use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

#[cfg(target_os = "linux")]
use crate::collector::{Collector, PtraceCollector};
use crate::storage::{SessionOutcome, SessionPaths, SessionStore, StoreError};

#[derive(Debug)]
pub enum RunError {
    Store(StoreError),
    Signal(io::Error),
    Command { source: io::Error, session: PathBuf },
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Signal(error) => write!(formatter, "signal handling failed: {error}"),
            Self::Command { source, .. } => write!(formatter, "command failed: {source}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Signal(error) => Some(error),
            Self::Command { source, .. } => Some(source),
        }
    }
}

impl From<StoreError> for RunError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Debug)]
pub struct RunResult {
    pub session: SessionPaths,
    pub status: ExitStatus,
}

pub fn run(argv: Vec<OsString>) -> Result<RunResult, RunError> {
    let store = SessionStore::discover().map_err(StoreError::from)?;
    store.recover_interrupted()?;
    run_in_store(argv, &store)
}

fn run_in_store(argv: Vec<OsString>, store: &SessionStore) -> Result<RunResult, RunError> {
    let executable = argv
        .first()
        .expect("the CLI parser requires a command before running");
    let command_name = display_name(executable);
    let mut session = store.begin(&command_name, argv.len().saturating_sub(1))?;
    let forwarder = SignalForwarder::start().map_err(RunError::Signal)?;

    let mut command = Command::new(executable);
    command
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    #[cfg(target_os = "linux")]
    let mut collector = PtraceCollector::new(command_name);
    #[cfg(target_os = "linux")]
    if let Err(source) = collector.prepare(&mut command) {
        forwarder.stop();
        let session_path = session.paths().database().to_owned();
        session.finalize(SessionOutcome::without_status())?;
        return Err(RunError::Command {
            source,
            session: session_path,
        });
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(source) => {
            forwarder.stop();
            let session_path = session.paths().database().to_owned();
            session.finalize(SessionOutcome::without_status())?;
            return Err(RunError::Command {
                source,
                session: session_path,
            });
        }
    };
    forwarder.set_child(child.id());

    #[cfg(not(target_os = "linux"))]
    if let Err(error) = session.record_root_process(child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        forwarder.stop();
        session.finalize(SessionOutcome::without_status())?;
        return Err(error.into());
    }

    #[cfg(target_os = "linux")]
    let status_result = collector.collect(&mut child, &mut session);
    #[cfg(not(target_os = "linux"))]
    let status_result = child.wait();

    let status = match status_result {
        Ok(status) => status,
        Err(source) => {
            forwarder.stop();
            let session_path = session.paths().database().to_owned();
            session.finalize(SessionOutcome::without_status())?;
            return Err(RunError::Command {
                source,
                session: session_path,
            });
        }
    };
    forwarder.stop();
    let outcome = session_outcome(&status);
    let session = session.finalize(outcome)?;

    Ok(RunResult { session, status })
}

pub fn exit_with_status(status: ExitStatus) -> ! {
    if let Some(code) = status.code() {
        std::process::exit(code);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        if let Some(signal) = status.signal() {
            // Reset the handler before raising so the parent terminates like the child.
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            std::process::exit(128 + signal);
        }
    }

    std::process::exit(1)
}

fn session_outcome(status: &ExitStatus) -> SessionOutcome {
    if let Some(code) = status.code() {
        return SessionOutcome::exited(code);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        if let Some(signal) = status.signal() {
            return SessionOutcome::signaled(signal);
        }
    }

    SessionOutcome::without_status()
}

#[cfg(unix)]
struct SignalForwarder {
    child_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
    pending_signal: std::sync::Arc<std::sync::atomic::AtomicI32>,
    handle: signal_hook::iterator::Handle,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl SignalForwarder {
    fn start() -> io::Result<Self> {
        use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
        use signal_hook::iterator::Signals;

        let mut signals = Signals::new([SIGHUP, SIGINT, SIGQUIT, SIGTERM])?;
        let handle = signals.handle();
        let child_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let pending_signal = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(0));
        let thread_child_id = child_id.clone();
        let thread_pending_signal = pending_signal.clone();
        let thread = std::thread::spawn(move || {
            use std::sync::atomic::Ordering;

            for signal in signals.forever() {
                let child_id = thread_child_id.load(Ordering::Acquire);
                if child_id == 0 {
                    thread_pending_signal.store(signal, Ordering::Release);
                } else {
                    forward_signal(child_id, signal);
                }
            }
        });

        Ok(Self {
            child_id,
            pending_signal,
            handle,
            thread: Some(thread),
        })
    }

    fn set_child(&self, child_id: u32) {
        use std::sync::atomic::Ordering;

        self.child_id.store(child_id, Ordering::Release);
        let signal = self.pending_signal.swap(0, Ordering::AcqRel);
        if signal != 0 {
            forward_signal(child_id, signal);
        }
    }

    fn stop(mut self) {
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
fn forward_signal(child_id: u32, signal: i32) {
    // child_id comes directly from std::process::Child and fits the platform pid type.
    unsafe {
        libc::kill(child_id as libc::pid_t, signal);
    }
}

#[cfg(not(unix))]
struct SignalForwarder;

#[cfg(not(unix))]
impl SignalForwarder {
    fn start() -> io::Result<Self> {
        Ok(Self)
    }

    fn set_child(&self, _child_id: u32) {}

    fn stop(self) {}
}

fn display_name(executable: &OsStr) -> String {
    let name = Path::new(executable)
        .file_name()
        .unwrap_or(executable)
        .to_string_lossy();
    name.chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::run_in_store;
    use crate::storage::SessionStore;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            Self(
                std::env::temp_dir()
                    .join(format!("execwake-runner-{}-{nonce}", std::process::id())),
            )
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn returns_the_child_exit_code_and_finalizes_the_session() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let result = run_in_store(exit_command(7), &store).expect("the command should run");

        assert_eq!(result.status.code(), Some(7));
        assert!(result.session.finalized().exists());

        let connection =
            Connection::open(result.session.database()).expect("the database should open");
        let row = connection
            .query_row(
                "SELECT state, exit_code, (SELECT COUNT(*) FROM process),
                        (SELECT COUNT(*) FROM event)
                 FROM session WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .expect("the session row should exist");

        assert_eq!(row, ("finalized".to_owned(), 7, 1, 2));
    }

    #[cfg(unix)]
    #[test]
    fn records_signal_termination() {
        use std::os::unix::process::ExitStatusExt;

        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let result = run_in_store(
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("kill -TERM $$"),
            ],
            &store,
        )
        .expect("the command should run");

        assert_eq!(result.status.signal(), Some(libc::SIGTERM));
        let connection =
            Connection::open(result.session.database()).expect("the database should open");
        let signal = connection
            .query_row(
                "SELECT termination_signal FROM session WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("the signal should be stored");
        assert_eq!(signal, i64::from(libc::SIGTERM));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn records_descendants_with_session_local_identities() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let result = run_in_store(
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("(/bin/sh -c 'sleep 0.02 & wait') & wait"),
            ],
            &store,
        )
        .expect("the process tree should run");
        let connection =
            Connection::open(result.session.database()).expect("the database should open");
        let (processes, identities, children, execs) = connection
            .query_row(
                "SELECT COUNT(*), COUNT(DISTINCT process_id),
                        SUM(parent_process_id IS NOT NULL),
                        (SELECT COUNT(*) FROM event
                         WHERE category = 'process' AND operation = 'exec')
                 FROM process",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .expect("process records should exist");

        assert!(processes >= 3);
        assert_eq!(identities, processes);
        assert!(children >= 2);
        assert!(execs >= 2);
    }

    #[cfg(unix)]
    fn exit_command(code: u8) -> Vec<OsString> {
        vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(format!("exit {code}")),
        ]
    }

    #[cfg(windows)]
    fn exit_command(code: u8) -> Vec<OsString> {
        vec![
            OsString::from("cmd.exe"),
            OsString::from("/C"),
            OsString::from(format!("exit {code}")),
        ]
    }
}
