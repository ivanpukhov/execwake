use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::storage::{SessionOutcome, SessionPaths, SessionStore, StoreError};

#[derive(Debug)]
pub enum RunError {
    Store(StoreError),
    Command { source: io::Error, session: PathBuf },
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Command { source, .. } => write!(formatter, "command failed: {source}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
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

    let mut command = Command::new(executable);
    command
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(source) => {
            let session_path = session.paths().database().to_owned();
            session.finalize(SessionOutcome::without_status())?;
            return Err(RunError::Command {
                source,
                session: session_path,
            });
        }
    };
    session.record_root_process(child.id())?;

    let status = match child.wait() {
        Ok(status) => status,
        Err(source) => {
            let session_path = session.paths().database().to_owned();
            session.finalize(SessionOutcome::without_status())?;
            return Err(RunError::Command {
                source,
                session: session_path,
            });
        }
    };
    let outcome = status
        .code()
        .map_or_else(SessionOutcome::without_status, SessionOutcome::exited);
    let session = session.finalize(outcome)?;

    Ok(RunResult { session, status })
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
