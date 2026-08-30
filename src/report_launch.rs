use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use execwake::storage::{SessionId, SessionPaths, SessionStore};

const INTERNAL_REPORT_COMMAND: &str = "__serve-report";
const REPORT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub fn serve_if_requested(arguments: &[OsString]) -> Option<io::Result<()>> {
    (arguments.get(1).map(OsString::as_os_str) == Some(OsStr::new(INTERNAL_REPORT_COMMAND)))
        .then(|| serve(&arguments[2..]))
}

pub fn present(session: &SessionPaths) {
    if !should_open_report() {
        print_session_path(session);
        return;
    }

    let (mut server, url) = match start_report_server(session) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("Report unavailable: {error}");
            print_session_path(session);
            return;
        }
    };

    match open_browser(&url) {
        Ok(()) => eprintln!("Report: {url}"),
        Err(error) => {
            stop_child(&mut server);
            eprintln!("Report unavailable: {error}");
            print_session_path(session);
        }
    }
}

pub fn print_session_path(session: &SessionPaths) {
    eprintln!("Session: {}", session.database().display());
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

fn should_open_report() -> bool {
    report_open_allowed(
        atty::is(atty::Stream::Stdin),
        atty::is(atty::Stream::Stderr),
        env::var_os("CI").is_some(),
        graphical_session_available(),
    )
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
    let mut child = Command::new(env::current_exe()?)
        .arg(INTERNAL_REPORT_COMMAND)
        .arg(session.id().as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
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
    let Some(url) = validated_report_url(url, session.id()) else {
        stop_child(&mut child);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "report server returned an invalid address",
        ));
    };

    Ok((child, url))
}

fn validated_report_url(value: &str, id: &SessionId) -> Option<String> {
    let remainder = value.strip_prefix("http://127.0.0.1:")?;
    let (port, path) = remainder.split_once('/')?;
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    let token = path.strip_prefix(&format!("open/{}?token=", id.as_str()))?;
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }

    let normalized = format!("http://127.0.0.1:{port}/open/{}?token={token}", id.as_str());
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
    use super::{report_open_allowed, validated_report_url};
    use execwake::storage::SessionId;

    #[test]
    fn validates_internal_report_urls() {
        let id = SessionId::parse("0123456789abcdef0123456789abcdef").expect("valid session id");
        let token = "a".repeat(64);
        let url = format!("http://127.0.0.1:7319/open/{}?token={token}", id.as_str());

        assert_eq!(validated_report_url(&url, &id), Some(url));
        assert!(validated_report_url("http://localhost:7319/open/x?token=a", &id).is_none());
        assert!(validated_report_url("http://127.0.0.1:0/open/x?token=a", &id).is_none());
    }

    #[test]
    fn opens_reports_only_in_an_interactive_graphical_session() {
        assert!(report_open_allowed(true, true, false, true));
        assert!(!report_open_allowed(false, true, false, true));
        assert!(!report_open_allowed(true, false, false, true));
        assert!(!report_open_allowed(true, true, true, true));
        assert!(!report_open_allowed(true, true, false, false));
    }
}
