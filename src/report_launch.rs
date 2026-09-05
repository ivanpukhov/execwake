use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use execwake::semantic_diff::SemanticDiff;
use execwake::storage::{SessionId, SessionPaths, SessionStore};
use rusqlite::{Connection, OpenFlags};

const INTERNAL_REPORT_COMMAND: &str = "__serve-report";
const INTERNAL_DIFF_REPORT_COMMAND: &str = "__serve-diff";
const REPORT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub fn serve_if_requested(arguments: &[OsString]) -> Option<io::Result<()>> {
    match arguments.get(1).map(OsString::as_os_str) {
        Some(command) if command == OsStr::new(INTERNAL_REPORT_COMMAND) => {
            Some(serve(&arguments[2..]))
        }
        Some(command) if command == OsStr::new(INTERNAL_DIFF_REPORT_COMMAND) => {
            Some(serve_diff(&arguments[2..]))
        }
        _ => None,
    }
}

pub fn present_diff(before: &Path, after: &Path, diff: &SemanticDiff) -> io::Result<()> {
    if !should_open_report() {
        return write_diff(diff);
    }

    let (mut server, url) = match start_diff_report_server(before, after) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("Report unavailable: {error}");
            return write_diff(diff);
        }
    };

    match open_browser(&url) {
        Ok(()) => {
            eprintln!("Report: {url}");
            Ok(())
        }
        Err(error) => {
            stop_child(&mut server);
            eprintln!("Report unavailable: {error}");
            write_diff(diff)
        }
    }
}

pub fn present(session: &SessionPaths) {
    if !should_open_report() {
        return;
    }

    let (mut server, url) = match start_report_server(session) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("Report unavailable: {error}");
            return;
        }
    };

    match open_browser(&url) {
        Ok(()) => eprintln!("Report: {url}"),
        Err(error) => {
            stop_child(&mut server);
            eprintln!("Report unavailable: {error}");
        }
    }
}

pub fn print_session_path(session: &SessionPaths) {
    eprintln!("Session: {}", session.database().display());
}

pub fn print_run_summary(session: &SessionPaths) -> io::Result<()> {
    let summary = load_run_summary(session)?;
    let stderr = io::stderr();
    let mut output = stderr.lock();
    write_run_summary(&mut output, &summary, session.database())
}

#[derive(Debug, Eq, PartialEq)]
struct RunSummary {
    collector_requested: String,
    collector_backend: Option<String>,
    collector_fallback_reason: Option<String>,
    categories: Vec<RunCategorySummary>,
}

#[derive(Debug, Eq, PartialEq)]
struct RunCategorySummary {
    label: &'static str,
    count: i64,
    coverage: String,
    lost_events: i64,
}

fn load_run_summary(session: &SessionPaths) -> io::Result<RunSummary> {
    let connection = Connection::open_with_flags(
        session.database(),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(database_error)?;
    let (collector_requested, collector_backend, collector_fallback_reason) = connection
        .query_row(
            "SELECT collector_requested, collector_backend, collector_fallback_reason
             FROM session WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(database_error)?;
    let counts = [
        (
            "Processes",
            connection
                .query_row("SELECT COUNT(*) FROM process", [], |row| row.get(0))
                .map_err(database_error)?,
            "processes",
        ),
        (
            "Filesystem events",
            event_count(&connection, "filesystem")?,
            "filesystem",
        ),
        (
            "Network events",
            event_count(&connection, "network")?,
            "network",
        ),
        (
            "Environment records",
            connection
                .query_row("SELECT COUNT(*) FROM environment_variable", [], |row| {
                    row.get(0)
                })
                .map_err(database_error)?,
            "environment",
        ),
    ];
    let mut categories = Vec::with_capacity(counts.len());
    for (label, count, category) in counts {
        let (coverage, lost_events) = connection
            .query_row(
                "SELECT state, lost_events FROM coverage WHERE category = ?1",
                [category],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(database_error)?;
        categories.push(RunCategorySummary {
            label,
            count,
            coverage,
            lost_events,
        });
    }

    Ok(RunSummary {
        collector_requested,
        collector_backend,
        collector_fallback_reason,
        categories,
    })
}

fn event_count(connection: &Connection, category: &str) -> io::Result<i64> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM event WHERE category = ?1",
            [category],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn write_run_summary(
    output: &mut impl Write,
    summary: &RunSummary,
    database: &Path,
) -> io::Result<()> {
    writeln!(output, "ExecWake session finalized")?;
    write!(output, "Collector: ")?;
    match summary.collector_backend.as_deref() {
        Some(backend) => write!(output, "{backend}")?,
        None => write!(output, "unavailable")?,
    }
    write!(output, " (requested: {}", summary.collector_requested)?;
    if let Some(reason) = summary.collector_fallback_reason.as_deref() {
        write!(output, "; fallback: {reason}")?;
    }
    writeln!(output, ")")?;
    for category in &summary.categories {
        if category.coverage == "unavailable" {
            writeln!(output, "{}: unavailable", category.label)?;
            continue;
        }
        write!(
            output,
            "{}: {} ({} coverage",
            category.label, category.count, category.coverage
        )?;
        if category.lost_events > 0 {
            write!(output, "; {} lost", category.lost_events)?;
        }
        writeln!(output, ")")?;
    }
    writeln!(output, "Session: {}", database.display())
}

fn database_error(error: rusqlite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn serve(arguments: &[OsString]) -> io::Result<()> {
    if arguments.len() != 1 {
        return Err(invalid_input("a session id is required"));
    }
    let value = arguments[0]
        .to_str()
        .ok_or_else(|| invalid_input("session id is not valid UTF-8"))?;
    let id = SessionId::parse(value).ok_or_else(|| invalid_input("session id is invalid"))?;
    let store = SessionStore::discover()?;
    let server = execwake::report::ReportServer::bind(store.paths(&id), REPORT_IDLE_TIMEOUT)?;
    let url = server.open_url();

    {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "{url}")?;
        output.flush()?;
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(server.run())
}

fn serve_diff(arguments: &[OsString]) -> io::Result<()> {
    if arguments.len() != 2 {
        return Err(invalid_input("two session paths are required"));
    }
    let server = execwake::report::ReportServer::bind_diff(
        PathBuf::from(&arguments[0]),
        PathBuf::from(&arguments[1]),
        REPORT_IDLE_TIMEOUT,
    )?;
    let url = server.open_url();

    {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "{url}")?;
        output.flush()?;
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(server.run())
}

fn write_diff(diff: &SemanticDiff) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, diff)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
    writeln!(output)
}

fn should_open_report() -> bool {
    let (stdin_is_terminal, stderr_is_terminal) = standard_stream_terminal_state();
    report_open_allowed(
        stdin_is_terminal,
        stderr_is_terminal,
        env::var_os("CI").is_some(),
        graphical_session_available(),
    )
}

#[cfg(unix)]
fn standard_stream_terminal_state() -> (bool, bool) {
    // isatty accepts any file descriptor value and does not access caller-owned memory.
    unsafe {
        (
            libc::isatty(libc::STDIN_FILENO) == 1,
            libc::isatty(libc::STDERR_FILENO) == 1,
        )
    }
}

#[cfg(not(unix))]
const fn standard_stream_terminal_state() -> (bool, bool) {
    (false, false)
}

fn report_open_allowed(
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
    ci: bool,
    graphical_session: bool,
) -> bool {
    stdin_is_terminal && stderr_is_terminal && !ci && graphical_session
}

#[cfg(any(target_os = "macos", windows))]
fn graphical_session_available() -> bool {
    true
}

#[cfg(all(unix, not(target_os = "macos")))]
fn graphical_session_available() -> bool {
    env::var_os("DISPLAY").is_some() || env::var_os("WAYLAND_DISPLAY").is_some()
}

#[cfg(not(any(unix, windows)))]
fn graphical_session_available() -> bool {
    false
}

fn start_report_server(session: &SessionPaths) -> io::Result<(Child, String)> {
    let child = Command::new(env::current_exe()?)
        .arg(INTERNAL_REPORT_COMMAND)
        .arg(session.id().as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    read_server_url(child, |value| validated_report_url(value, session.id()))
}

fn start_diff_report_server(before: &Path, after: &Path) -> io::Result<(Child, String)> {
    let child = Command::new(env::current_exe()?)
        .arg(INTERNAL_DIFF_REPORT_COMMAND)
        .arg(before)
        .arg(after)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    read_server_url(child, validated_diff_url)
}

fn read_server_url(
    mut child: Child,
    validate: impl FnOnce(&str) -> Option<String>,
) -> io::Result<(Child, String)> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "report server output is missing"))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });

    let line = match receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(line)) => line,
        Ok(Err(error)) => {
            stop_child(&mut child);
            let _ = reader.join();
            return Err(error);
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            stop_child(&mut child);
            let _ = reader.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "report server did not start in time",
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            stop_child(&mut child);
            let _ = reader.join();
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "report server stopped during startup",
            ));
        }
    };
    if reader.join().is_err() {
        stop_child(&mut child);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "report server output could not be read",
        ));
    }

    let url = line.trim_end_matches(|character| character == '\r' || character == '\n');
    let Some(url) = validate(url) else {
        stop_child(&mut child);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "report server returned an invalid address",
        ));
    };

    Ok((child, url))
}

fn validated_report_url(value: &str, id: &SessionId) -> Option<String> {
    validated_route_url(value, id.as_str())
}

fn validated_diff_url(value: &str) -> Option<String> {
    validated_route_url(value, "diff")
}

fn validated_route_url(value: &str, route_id: &str) -> Option<String> {
    let remainder = value.strip_prefix("http://127.0.0.1:")?;
    let (port, path) = remainder.split_once('/')?;
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    let token = path.strip_prefix(&format!("open/{route_id}?token="))?;
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }

    let normalized = format!("http://127.0.0.1:{port}/open/{route_id}?token={token}");
    (normalized == value).then_some(normalized)
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "macos")]
fn open_browser(url: &str) -> io::Result<()> {
    run_opener(Command::new("open").arg(url))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_browser(url: &str) -> io::Result<()> {
    run_opener(Command::new("xdg-open").arg(url))
}

#[cfg(windows)]
fn open_browser(url: &str) -> io::Result<()> {
    run_opener(Command::new("cmd.exe").args(["/C", "start", "", url]))
}

#[cfg(not(any(unix, windows)))]
fn open_browser(_url: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "opening a browser is not supported on this platform",
    ))
}

fn run_opener(command: &mut Command) -> io::Result<()> {
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "browser opener failed",
        ))
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        report_open_allowed, validated_diff_url, validated_report_url, write_run_summary,
        RunCategorySummary, RunSummary,
    };
    use execwake::storage::SessionId;

    #[test]
    fn validates_internal_report_urls() {
        let id = SessionId::parse("0123456789abcdef0123456789abcdef").expect("valid session id");
        let token = "a".repeat(64);
        let url = format!("http://127.0.0.1:7319/open/{}?token={token}", id.as_str());

        assert_eq!(validated_report_url(&url, &id), Some(url));
        assert!(validated_report_url("http://localhost:7319/open/x?token=a", &id).is_none());
        assert!(validated_report_url("http://127.0.0.1:0/open/x?token=a", &id).is_none());
        let diff_url = format!("http://127.0.0.1:7319/open/diff?token={token}");
        assert_eq!(validated_diff_url(&diff_url), Some(diff_url));
    }

    #[test]
    fn opens_reports_only_in_an_interactive_graphical_session() {
        assert!(report_open_allowed(true, true, false, true));
        assert!(!report_open_allowed(false, true, false, true));
        assert!(!report_open_allowed(true, false, false, true));
        assert!(!report_open_allowed(true, true, true, true));
        assert!(!report_open_allowed(true, true, false, false));
    }

    #[test]
    fn summary_distinguishes_partial_and_unavailable_coverage() {
        let summary = RunSummary {
            collector_requested: "auto".to_owned(),
            collector_backend: Some("ptrace".to_owned()),
            collector_fallback_reason: Some("permission_denied".to_owned()),
            categories: vec![
                RunCategorySummary {
                    label: "Processes",
                    count: 6,
                    coverage: "complete".to_owned(),
                    lost_events: 0,
                },
                RunCategorySummary {
                    label: "Filesystem events",
                    count: 412,
                    coverage: "partial".to_owned(),
                    lost_events: 3,
                },
                RunCategorySummary {
                    label: "Network events",
                    count: 0,
                    coverage: "unavailable".to_owned(),
                    lost_events: 0,
                },
            ],
        };
        let mut output = Vec::new();

        write_run_summary(&mut output, &summary, Path::new("/tmp/session.sqlite3"))
            .expect("the summary should be written");

        assert_eq!(
            String::from_utf8(output).expect("summary output should be UTF-8"),
            "ExecWake session finalized\n\
             Collector: ptrace (requested: auto; fallback: permission_denied)\n\
             Processes: 6 (complete coverage)\n\
             Filesystem events: 412 (partial coverage; 3 lost)\n\
             Network events: unavailable\n\
             Session: /tmp/session.sqlite3\n"
        );
    }
}
