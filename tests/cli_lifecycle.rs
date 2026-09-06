#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use execwake::session::CollectorFallbackReason;
use rusqlite::Connection;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "execwake-cli-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("the test state directory should be created");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn passes_stdin_and_explicit_shell_pipelines() {
    let stdin_state = TestDirectory::new("stdin");
    let mut child = command(&stdin_state.0)
        .args(["run", "--collector", "ptrace", "--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the stdin run should start");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(b"input-through-execwake\n")
        .expect("stdin should be written");
    let output = child
        .wait_with_output()
        .expect("the stdin run should finish");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"input-through-execwake\n");
    assert_session_finalized(&session_path(&output));

    let pipeline_state = TestDirectory::new("pipeline");
    let output = run(
        &pipeline_state.0,
        &[
            "run",
            "--collector",
            "ptrace",
            "--",
            "/bin/sh",
            "-c",
            "printf pipeline | tr a-z A-Z",
        ],
    );

    assert!(output.status.success());
    assert_eq!(output.stdout, b"PIPELINE");
    assert_session_finalized(&session_path(&output));
}

#[test]
fn preserves_nonzero_and_crash_statuses() {
    let nonzero_state = TestDirectory::new("nonzero");
    let output = run(
        &nonzero_state.0,
        &[
            "run",
            "--collector",
            "ptrace",
            "--",
            "/bin/sh",
            "-c",
            "exit 23",
        ],
    );

    assert_eq!(output.status.code(), Some(23));
    assert_session_finalized(&session_path(&output));

    let crash_state = TestDirectory::new("crash");
    let output = run(
        &crash_state.0,
        &[
            "run",
            "--collector",
            "ptrace",
            "--",
            "/bin/sh",
            "-c",
            "kill -SEGV $$",
        ],
    );

    assert_eq!(output.status.signal(), Some(libc::SIGSEGV));
    assert_session_finalized(&session_path(&output));
}

#[test]
fn automatic_collector_records_a_consistent_decision() {
    let state = TestDirectory::new("auto");
    let output = run(&state.0, &["run", "--collector", "auto", "--", "/bin/true"]);

    assert!(
        output.status.success(),
        "automatic collection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = session_path(&output);
    let lifecycle = session_lifecycle(&path);
    assert_finalized(&path, &lifecycle);
    assert_eq!(lifecycle.requested, "auto");
    match lifecycle.backend.as_deref() {
        Some("ebpf") => assert_eq!(lifecycle.fallback, None),
        Some("ptrace") => {
            let fallback = lifecycle
                .fallback
                .as_deref()
                .and_then(CollectorFallbackReason::parse);
            assert!(fallback.is_some(), "ptrace fallback reason is missing");
        }
        backend => panic!("unexpected collector backend: {backend:?}"),
    }
    if let Ok(expected) = std::env::var("EXECWAKE_EXPECT_AUTO_FALLBACK") {
        assert_eq!(lifecycle.backend.as_deref(), Some("ptrace"));
        assert_eq!(lifecycle.fallback.as_deref(), Some(expected.as_str()));
    }
}

#[test]
fn writes_an_explicit_session_output_after_finalization() {
    let state = TestDirectory::new("output");
    let destination = state.0.join("saved.sqlite3");
    let destination_text = destination.to_string_lossy().into_owned();
    let output = run(
        &state.0,
        &[
            "run",
            "--collector",
            "ptrace",
            "--output",
            &destination_text,
            "--",
            "/bin/true",
        ],
    );

    assert!(
        output.status.success(),
        "session export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stored = session_path(&output);
    assert_ne!(stored, destination);
    assert_eq!(
        fs::read(&destination).expect("the saved session should be readable"),
        fs::read(&stored).expect("the stored session should be readable")
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!("Saved session: {}", destination.display())));
}

#[test]
fn collector_startup_failure_finalizes_the_session() {
    let Ok(expected) = std::env::var("EXECWAKE_EXPECT_EBPF_STARTUP_FAILURE") else {
        return;
    };
    let state = TestDirectory::new("collector-startup-failure");
    let output = run(&state.0, &["run", "--collector", "ebpf", "--", "/bin/true"]);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&expected), "unexpected error: {stderr}");
    let path = session_path(&output);
    let lifecycle = session_lifecycle(&path);
    assert_finalized(&path, &lifecycle);
    assert_eq!(lifecycle.requested, "ebpf");
    assert_eq!(lifecycle.backend, None);
    assert_eq!(lifecycle.fallback, None);
}

#[test]
fn ctrl_c_finalizes_the_session_and_stops_the_collector() {
    let state = TestDirectory::new("interrupt");
    let child = command(&state.0)
        .args(["run", "--collector", "ptrace", "--", "/bin/sleep", "30"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the interrupted run should start");
    let wrapper_pid = child.id();
    wait_for_process_record(&state.0);

    assert_eq!(
        unsafe { libc::kill(wrapper_pid as libc::pid_t, libc::SIGINT) },
        0
    );
    let output = child
        .wait_with_output()
        .expect("the interrupted run should finish");

    assert_eq!(output.status.signal(), Some(libc::SIGINT));
    assert_session_finalized(&session_path(&output));
}

#[test]
fn preserves_terminal_file_descriptors() {
    let state = TestDirectory::new("tty");
    let (master, slave) = pseudo_terminal();
    let stdin = slave
        .try_clone()
        .expect("the terminal stdin should be cloned");
    let stdout = slave
        .try_clone()
        .expect("the terminal stdout should be cloned");

    let status = command(&state.0)
        .env("CI", "1")
        .args([
            "run",
            "--collector",
            "ptrace",
            "--",
            "/bin/sh",
            "-c",
            "test -t 0 && test -t 1 && test -t 2",
        ])
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave))
        .status()
        .expect("the terminal run should finish");
    drop(master);

    assert!(status.success());
    let database = only_session_database(&state.0);
    assert_session_finalized(&database);
}

fn command(state_home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_execwake"));
    command
        .env("XDG_STATE_HOME", state_home)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    command
}

fn run(state_home: &Path, arguments: &[&str]) -> Output {
    command(state_home)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("execwake should run")
}

fn session_path(output: &Output) -> PathBuf {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("Session: "))
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("session path is missing from stderr: {stderr}"))
}

fn assert_session_finalized(path: &Path) {
    let lifecycle = session_lifecycle(path);
    assert_finalized(path, &lifecycle);
    assert_eq!(lifecycle.requested, "ptrace");
    assert_eq!(lifecycle.backend.as_deref(), Some("ptrace"));
    assert_eq!(lifecycle.fallback, None);
}

struct SessionLifecycle {
    state: String,
    finalized: i64,
    unfinished: i64,
    requested: String,
    backend: Option<String>,
    fallback: Option<String>,
}

fn session_lifecycle(path: &Path) -> SessionLifecycle {
    let connection = Connection::open(path).expect("the session database should open");
    connection
        .query_row(
            "SELECT state, finalized,
                    (SELECT COUNT(*) FROM process WHERE ended_at_ms IS NULL),
                    collector_requested, collector_backend,
                    collector_fallback_reason
             FROM session WHERE singleton = 1",
            [],
            |row| {
                Ok(SessionLifecycle {
                    state: row.get(0)?,
                    finalized: row.get(1)?,
                    unfinished: row.get(2)?,
                    requested: row.get(3)?,
                    backend: row.get(4)?,
                    fallback: row.get(5)?,
                })
            },
        )
        .expect("the session lifecycle should be readable")
}

fn assert_finalized(path: &Path, lifecycle: &SessionLifecycle) {
    assert_eq!(lifecycle.state, "finalized");
    assert_eq!(lifecycle.finalized, 1);
    assert_eq!(lifecycle.unfinished, 0);
    assert!(path.with_extension("finalized").is_file());
    assert!(!path.with_extension("lock").exists());
}

fn wait_for_process_record(state_home: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(database) = session_databases(state_home).into_iter().next() {
            if Connection::open(database)
                .and_then(|connection| {
                    connection.query_row("SELECT COUNT(*) FROM process", [], |row| {
                        row.get::<_, i64>(0)
                    })
                })
                .map_or(false, |count| count > 0)
            {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the collector did not record its root process");
}

fn only_session_database(state_home: &Path) -> PathBuf {
    let databases = session_databases(state_home);
    assert_eq!(databases.len(), 1);
    databases[0].clone()
}

fn session_databases(state_home: &Path) -> Vec<PathBuf> {
    let directory = state_home.join("execwake/sessions");
    let mut databases: Vec<_> = fs::read_dir(directory)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sqlite3"))
        .collect();
    databases.sort();
    databases
}

fn pseudo_terminal() -> (File, File) {
    let mut master = -1;
    let mut slave = -1;
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(result, 0, "a pseudo-terminal should be allocated");
    assert!(master >= 0 && slave >= 0);
    unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
}
