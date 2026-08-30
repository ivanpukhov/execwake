use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

#[cfg(target_os = "linux")]
use crate::collector::{Collector, LinuxCollector};
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
    let mut collector = LinuxCollector::new(command_name);
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

        assert_eq!((row.0, row.1, row.2), ("finalized".to_owned(), 7, 1));
        assert!(row.3 >= 2);

        #[cfg(target_os = "linux")]
        if std::env::var_os("EXECWAKE_REQUIRE_EBPF").is_some() {
            let backend: String = connection
                .query_row(
                    "SELECT collector_backend FROM session WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("the collector backend should be stored");
            assert_eq!(backend, "ebpf");
        }
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

        let environment_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM environment_variable", [], |row| {
                row.get(0)
            })
            .expect("environment names should be counted");
        let environment_columns: Vec<String> = connection
            .prepare("PRAGMA table_info(environment_variable)")
            .expect("the environment schema should be readable")
            .query_map([], |row| row.get(1))
            .expect("the environment columns should be queried")
            .collect::<Result<_, _>>()
            .expect("the environment columns should be read");
        assert!(environment_count > 0);
        assert_eq!(environment_columns, ["name", "process_id", "evidence"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn records_successful_filesystem_operations() {
        use std::collections::HashSet;

        let directory = TestDirectory::new();
        fs::create_dir_all(&directory.0).expect("the test directory should be created");
        let work = directory.0.join("trace-work");
        fs::create_dir(&work).expect("the trace directory should be created");
        let store =
            SessionStore::at(directory.0.join("sessions")).expect("storage should be created");
        let result = run_in_store(
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from(
                    "cd \"$1\" && printf data > trace-created && cat trace-created >/dev/null \
                     && : > trace-created && mv trace-created trace-renamed \
                     && ln trace-renamed trace-linked && ln -s trace-renamed trace-symlink \
                     && printf temporary > trace-transient && rm trace-transient \
                     && rm trace-linked trace-symlink trace-renamed",
                ),
                OsString::from("fixture"),
                work.into_os_string(),
            ],
            &store,
        )
        .expect("the filesystem fixture should run");
        let connection =
            Connection::open(result.session.database()).expect("the database should open");
        let mut statement = connection
            .prepare(
                "SELECT DISTINCT operation FROM event
                 WHERE category = 'filesystem' AND target LIKE '%trace-%'",
            )
            .expect("the event query should prepare");
        let operations: HashSet<String> = statement
            .query_map([], |row| row.get(0))
            .expect("events should be queried")
            .collect::<Result<_, _>>()
            .expect("events should be read");

        for operation in [
            "create", "write", "read", "truncate", "rename", "link", "symlink", "unlink",
        ] {
            assert!(
                operations.contains(operation),
                "missing {operation}: {operations:?}"
            );
        }

        let transient = connection
            .query_row(
                "SELECT before_kind, after_kind FROM filesystem_delta
                 WHERE path LIKE '%trace-transient'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .expect("the create-delete state should be stored");
        assert_eq!(transient, ("absent".to_owned(), "absent".to_owned()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn records_socket_operations_without_application_protocol_labels() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let executable = std::env::current_exe().expect("the test executable should be known");
        let result = run_in_store(
            vec![
                executable.into_os_string(),
                OsString::from("--exact"),
                OsString::from("runner::tests::network_fixture_child"),
                OsString::from("--nocapture"),
                OsString::from("--test-threads=1"),
            ],
            &store,
        )
        .expect("the network fixture should run");
        let connection =
            Connection::open(result.session.database()).expect("the database should open");
        let mut statement = connection
            .prepare("SELECT operation, target FROM event WHERE category = 'network'")
            .expect("the event query should prepare");
        let events: Vec<(String, String)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("events should be queried")
            .collect::<Result<_, _>>()
            .expect("events should be read");

        for operation in ["bind", "listen", "connect"] {
            assert!(
                events.iter().any(|event| event.0 == operation),
                "missing {operation}: {events:?}"
            );
        }
        for target in ["tcp 127.0.0.1:", "udp 127.0.0.1:"] {
            assert!(
                events.iter().any(|event| event.1.starts_with(target)),
                "missing {target}: {events:?}"
            );
        }
        assert!(events.iter().all(|event| !event.1.contains("http")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn network_fixture_child() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream, UdpSocket};

        for bind_address in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(listener) = TcpListener::bind(bind_address) else {
                continue;
            };
            let address = listener
                .local_addr()
                .expect("the listener address should exist");
            let client = std::thread::spawn(move || {
                let mut stream = TcpStream::connect(address).expect("the client should connect");
                stream.write_all(b"x").expect("the client should write");
            });
            let (mut stream, _) = listener.accept().expect("the listener should accept");
            let mut byte = [0_u8; 1];
            stream
                .read_exact(&mut byte)
                .expect("the listener should read");
            client.join().expect("the client should finish");
        }

        for (receiver_address, sender_address) in
            [("127.0.0.1:0", "127.0.0.1:0"), ("[::1]:0", "[::1]:0")]
        {
            let Ok(receiver) = UdpSocket::bind(receiver_address) else {
                continue;
            };
            let sender = UdpSocket::bind(sender_address).expect("the sender should bind");
            sender
                .connect(
                    receiver
                        .local_addr()
                        .expect("the receiver address should exist"),
                )
                .expect("the sender should connect");
            sender.send(b"x").expect("the datagram should send");
            let mut byte = [0_u8; 1];
            receiver
                .recv(&mut byte)
                .expect("the datagram should arrive");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn records_dns_only_after_a_matching_response() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let executable = std::env::current_exe().expect("the test executable should be known");
        let result = run_in_store(
            vec![
                executable.into_os_string(),
                OsString::from("--ignored"),
                OsString::from("--exact"),
                OsString::from("runner::tests::dns_fixture_child"),
                OsString::from("--nocapture"),
                OsString::from("--test-threads=1"),
            ],
            &store,
        )
        .expect("the DNS fixture should run");
        let connection =
            Connection::open(result.session.database()).expect("the database should open");
        let correlation = connection
            .query_row(
                "SELECT hostname, address, evidence, confidence FROM dns_correlation",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .expect("the DNS correlation should exist");

        assert_eq!(
            correlation,
            (
                "fixture.test".to_owned(),
                "127.0.0.7".to_owned(),
                "observed".to_owned(),
                "high".to_owned(),
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn dns_fixture_child() {
        use std::net::UdpSocket;

        let server = UdpSocket::bind("127.0.0.1:0").expect("the DNS server should bind");
        let server_address = server
            .local_addr()
            .expect("the server address should exist");
        let server_thread = std::thread::spawn(move || {
            let mut query = [0_u8; 512];
            let (length, peer) = server
                .recv_from(&mut query)
                .expect("the server should receive a query");
            let response = dns_fixture_response(&query[..length]);
            server
                .send_to(&response, peer)
                .expect("the server should send a response");
        });
        let client = UdpSocket::bind("127.0.0.1:0").expect("the DNS client should bind");
        client
            .connect(server_address)
            .expect("the DNS client should connect");
        client
            .send(&dns_fixture_query())
            .expect("the DNS client should send a query");
        let mut response = [0_u8; 512];
        client
            .recv(&mut response)
            .expect("the DNS client should receive a response");
        server_thread.join().expect("the DNS server should finish");
    }

    #[cfg(target_os = "linux")]
    fn dns_fixture_query() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&[
            7, b'f', b'i', b'x', b't', b'u', b'r', b'e', 4, b't', b'e', b's', b't', 0,
        ]);
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet
    }

    #[cfg(target_os = "linux")]
    fn dns_fixture_response(query: &[u8]) -> Vec<u8> {
        let mut packet = query.to_vec();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0;
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 7]);
        packet
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
