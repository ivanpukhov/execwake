use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags};

use crate::session::CURRENT_SCHEMA_VERSION;

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Database(rusqlite::Error),
    InvalidInput(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "session storage error: {error}"),
            Self::Database(error) => write!(formatter, "session database error: {error}"),
            Self::InvalidInput(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionOutcome {
    pub exit_code: Option<i32>,
    pub termination_signal: Option<i32>,
}

impl SessionOutcome {
    pub const fn exited(exit_code: i32) -> Self {
        Self {
            exit_code: Some(exit_code),
            termination_signal: None,
        }
    }

    pub const fn signaled(signal: i32) -> Self {
        Self {
            exit_code: None,
            termination_signal: Some(signal),
        }
    }

    pub const fn without_status() -> Self {
        Self {
            exit_code: None,
            termination_signal: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0_u8; 16];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "random source unavailable"))?;

        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut value, "{byte:02x}").expect("writing to a string cannot fail");
        }

        Ok(Self(value))
    }

    pub fn parse(value: &str) -> Option<Self> {
        (value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPaths {
    id: SessionId,
    database: PathBuf,
    lock: PathBuf,
    finalized: PathBuf,
}

impl SessionPaths {
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn database(&self) -> &Path {
        &self.database
    }

    pub fn lock(&self) -> &Path {
        &self.lock
    }

    pub fn finalized(&self) -> &Path {
        &self.finalized
    }
}

#[derive(Clone, Debug)]
pub struct SessionStore {
    root: PathBuf,
}

impl SessionStore {
    pub fn discover() -> io::Result<Self> {
        Self::at(default_storage_root()?)
    }

    pub fn at(root: PathBuf) -> io::Result<Self> {
        if !root.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session storage path must be absolute",
            ));
        }

        ensure_private_directory(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn new_session_paths(&self) -> io::Result<SessionPaths> {
        for _ in 0..8 {
            let id = SessionId::generate()?;
            let paths = self.paths(&id);

            if !paths.database.exists() && !paths.lock.exists() && !paths.finalized.exists() {
                return Ok(paths);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique session id",
        ))
    }

    pub fn paths(&self, id: &SessionId) -> SessionPaths {
        let base = self.root.join(id.as_str());
        SessionPaths {
            id: id.clone(),
            database: base.with_extension("sqlite3"),
            lock: base.with_extension("lock"),
            finalized: base.with_extension("finalized"),
        }
    }

    pub fn begin(
        &self,
        command_name: &str,
        argument_count: usize,
    ) -> Result<ActiveSession, StoreError> {
        if command_name.is_empty() || command_name.chars().any(|character| character.is_control()) {
            return Err(StoreError::InvalidInput("invalid command name"));
        }

        let argument_count = i64::try_from(argument_count)
            .map_err(|_| StoreError::InvalidInput("argument count is too large"))?;
        let paths = self.new_session_paths()?;
        let lock_file = create_private_file(paths.lock())?;
        FileExt::try_lock_exclusive(&lock_file)?;
        create_private_file(paths.database())?;

        let result = initialize_database(&paths, command_name, argument_count);
        match result {
            Ok(connection) => Ok(ActiveSession {
                paths,
                connection,
                lock_file: Some(lock_file),
                finalized: false,
            }),
            Err(error) => {
                let _ = FileExt::unlock(&lock_file);
                drop(lock_file);
                let _ = fs::remove_file(paths.lock());
                let _ = fs::remove_file(paths.database());
                Err(error)
            }
        }
    }

    pub fn recover_interrupted(&self) -> Result<Vec<SessionPaths>, StoreError> {
        let mut recovered = Vec::new();

        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("lock") {
                continue;
            }

            let Some(id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(SessionId::parse)
            else {
                continue;
            };
            let paths = self.paths(&id);
            if recover_session(&paths)? {
                recovered.push(paths);
            }
        }

        Ok(recovered)
    }
}

pub struct ActiveSession {
    paths: SessionPaths,
    connection: Connection,
    lock_file: Option<File>,
    finalized: bool,
}

impl ActiveSession {
    pub fn paths(&self) -> &SessionPaths {
        &self.paths
    }

    pub fn record_root_process(&mut self, process_id: u32) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        let (command_name, started_at_ms) = transaction.query_row(
            "SELECT command_name, started_at_ms FROM session WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?;
        transaction.execute(
            "INSERT INTO process (
                 process_id, parent_process_id, executable, started_at_ms, evidence
             ) VALUES (?1, NULL, ?2, ?3, 'observed')",
            params![i64::from(process_id), command_name, started_at_ms],
        )?;
        transaction.execute(
            "INSERT INTO event (
                 category, operation, target, process_id, occurred_at_ms, evidence
             ) VALUES ('process', 'start', ?1, ?2, ?3, 'observed')",
            params![command_name, i64::from(process_id), started_at_ms],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn finalize(mut self, outcome: SessionOutcome) -> Result<SessionPaths, StoreError> {
        let ended_at_ms = unix_time_ms()?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE process
             SET ended_at_ms = ?1, exit_code = ?2, termination_signal = ?3
             WHERE parent_process_id IS NULL",
            params![ended_at_ms, outcome.exit_code, outcome.termination_signal],
        )?;
        transaction.execute(
            "INSERT INTO event (
                 category, operation, target, process_id, occurred_at_ms, evidence
             )
             SELECT 'process', 'exit', executable, process_id, ?1, 'observed'
             FROM process WHERE parent_process_id IS NULL",
            [ended_at_ms],
        )?;
        let updated = transaction.execute(
            "UPDATE session
             SET state = 'finalized', finalized = 1, ended_at_ms = ?1,
                 exit_code = ?2, termination_signal = ?3
             WHERE singleton = 1 AND state = 'running' AND finalized = 0",
            params![ended_at_ms, outcome.exit_code, outcome.termination_signal],
        )?;
        if updated != 1 {
            return Err(StoreError::InvalidInput("session is not running"));
        }
        transaction.commit()?;

        create_finalized_marker(self.paths.finalized())?;
        self.finalized = true;
        let lock_file = self
            .lock_file
            .take()
            .ok_or(StoreError::InvalidInput("session lock is missing"))?;
        FileExt::unlock(&lock_file)?;
        drop(lock_file);
        fs::remove_file(self.paths.lock())?;

        Ok(self.paths.clone())
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        if !self.finalized {
            if let Some(lock_file) = self.lock_file.as_ref() {
                let _ = FileExt::unlock(lock_file);
            }
        }
    }
}

fn initialize_database(
    paths: &SessionPaths,
    command_name: &str,
    argument_count: i64,
) -> Result<Connection, StoreError> {
    let mut connection = Connection::open_with_flags(
        paths.database(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.execute_batch(
        "PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         CREATE TABLE session (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             id TEXT NOT NULL,
             schema_version INTEGER NOT NULL,
             mode TEXT NOT NULL CHECK (mode = 'observe'),
             state TEXT NOT NULL CHECK (state IN ('running', 'finalized', 'interrupted')),
             finalized INTEGER NOT NULL CHECK (finalized IN (0, 1)),
             command_name TEXT NOT NULL,
             argument_count INTEGER NOT NULL CHECK (argument_count >= 0),
             started_at_ms INTEGER NOT NULL,
             ended_at_ms INTEGER,
             runner_pid INTEGER NOT NULL,
             exit_code INTEGER,
             termination_signal INTEGER,
             interruption TEXT
         );
         CREATE TABLE coverage (
             category TEXT PRIMARY KEY,
             state TEXT NOT NULL CHECK (state IN ('complete', 'partial', 'unavailable')),
             lost_events INTEGER NOT NULL CHECK (lost_events >= 0)
         );
         CREATE TABLE process (
             process_id INTEGER PRIMARY KEY,
             parent_process_id INTEGER REFERENCES process(process_id),
             executable TEXT NOT NULL,
             started_at_ms INTEGER NOT NULL,
             ended_at_ms INTEGER,
             exit_code INTEGER,
             termination_signal INTEGER,
             evidence TEXT NOT NULL CHECK (evidence IN ('observed', 'inferred', 'derived'))
         );
         CREATE TABLE event (
             event_id INTEGER PRIMARY KEY AUTOINCREMENT,
             category TEXT NOT NULL,
             operation TEXT NOT NULL,
             target TEXT NOT NULL,
             process_id INTEGER REFERENCES process(process_id),
             occurred_at_ms INTEGER NOT NULL,
             evidence TEXT NOT NULL CHECK (evidence IN ('observed', 'inferred', 'derived'))
         );",
    )?;

    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT INTO session (
             singleton, id, schema_version, mode, state, finalized,
             command_name, argument_count, started_at_ms, runner_pid
         ) VALUES (1, ?1, ?2, 'observe', 'running', 0, ?3, ?4, ?5, ?6)",
        params![
            paths.id().as_str(),
            i64::from(CURRENT_SCHEMA_VERSION),
            command_name,
            argument_count,
            unix_time_ms()?,
            i64::from(std::process::id()),
        ],
    )?;
    for (category, state) in [
        ("processes", "partial"),
        ("filesystem", "unavailable"),
        ("network", "unavailable"),
        ("environment", "unavailable"),
    ] {
        transaction.execute(
            "INSERT INTO coverage (category, state, lost_events) VALUES (?1, ?2, 0)",
            params![category, state],
        )?;
    }
    transaction.commit()?;

    Ok(connection)
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path)
}

fn open_private_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let file = options.open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        options.open(path)
    }
}

fn recover_session(paths: &SessionPaths) -> Result<bool, StoreError> {
    let lock_file = open_private_lock(paths.lock())?;
    match FileExt::try_lock_exclusive(&lock_file) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(error) => return Err(error.into()),
    }

    if !paths.database().is_file() {
        FileExt::unlock(&lock_file)?;
        drop(lock_file);
        fs::remove_file(paths.lock())?;
        return Ok(false);
    }

    let mut connection = Connection::open_with_flags(
        paths.database(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let transaction = connection.transaction()?;
    let (state, finalized) = transaction.query_row(
        "SELECT state, finalized FROM session WHERE singleton = 1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )?;

    let interrupted = state == "running" && finalized == 0;
    if interrupted {
        transaction.execute(
            "UPDATE session
             SET state = 'interrupted', finalized = 1, ended_at_ms = ?1,
                 exit_code = NULL, termination_signal = NULL,
                 interruption = 'runner exited before finalization'
             WHERE singleton = 1",
            [unix_time_ms()?],
        )?;
    }
    transaction.commit()?;

    if finalized == 1 || interrupted {
        create_finalized_marker(paths.finalized())?;
    }

    FileExt::unlock(&lock_file)?;
    drop(lock_file);
    fs::remove_file(paths.lock())?;

    Ok(interrupted)
}

fn create_finalized_marker(path: &Path) -> io::Result<()> {
    if path.exists() {
        return Ok(());
    }

    let marker = create_private_file(path)?;
    marker.sync_all()
}

fn unix_time_ms() -> Result<i64, StoreError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::InvalidInput("system clock is before the Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| StoreError::InvalidInput("system time is out of range"))
}

fn default_storage_root() -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        return absolute_environment_path("HOME")
            .map(|home| home.join("Library/Application Support/ExecWake/sessions"));
    }

    #[cfg(target_os = "windows")]
    {
        return absolute_environment_path("LOCALAPPDATA")
            .map(|root| root.join("ExecWake/sessions"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(root) = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
        {
            return Ok(root.join("execwake/sessions"));
        }

        return absolute_environment_path("HOME")
            .map(|home| home.join(".local/state/execwake/sessions"));
    }

    #[allow(unreachable_code)]
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no platform session storage directory is available",
    ))
}

fn absolute_environment_path(name: &str) -> io::Result<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{name} does not contain an absolute path"),
            )
        })
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
    }

    #[cfg(not(unix))]
    fs::create_dir_all(path)?;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session storage path is not a directory",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::{SessionId, SessionOutcome, SessionStore};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            Self(
                std::env::temp_dir()
                    .join(format!("execwake-storage-{}-{nonce}", std::process::id())),
            )
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn session_ids_are_fixed_lowercase_hex() {
        let id = SessionId::generate().expect("a session id should be generated");

        assert_eq!(id.as_str().len(), 32);
        assert_eq!(SessionId::parse(id.as_str()), Some(id));
        assert!(SessionId::parse("../outside").is_none());
        assert!(SessionId::parse("ABCDEF0123456789ABCDEF0123456789").is_none());
    }

    #[test]
    fn storage_requires_an_absolute_path() {
        assert!(SessionStore::at(PathBuf::from("sessions")).is_err());
    }

    #[test]
    fn storage_rejects_a_file_in_place_of_the_directory() {
        let directory = TestDirectory::new();
        fs::create_dir(&directory.0).expect("the test directory should be created");
        let file = directory.0.join("sessions");
        fs::write(&file, b"not a directory").expect("the test file should be created");

        assert!(SessionStore::at(file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn storage_rejects_a_symlink_in_place_of_the_directory() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        fs::create_dir(&directory.0).expect("the test directory should be created");
        let target = directory.0.join("target");
        let link = directory.0.join("sessions");
        fs::create_dir(&target).expect("the target directory should be created");
        symlink(target, &link).expect("the symlink should be created");

        assert!(SessionStore::at(link).is_err());
    }

    #[test]
    fn session_paths_stay_under_the_storage_root() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let paths = store
            .new_session_paths()
            .expect("session paths should be allocated");

        assert!(paths.database().starts_with(store.root()));
        assert!(paths.lock().starts_with(store.root()));
        assert!(paths.finalized().starts_with(store.root()));
    }

    #[cfg(unix)]
    #[test]
    fn storage_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let mode = fs::metadata(store.root())
            .expect("storage metadata should be available")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn sessions_are_finalized_in_sqlite_and_on_disk() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("printf", 2)
            .expect("a session should be started");
        let database = session.paths().database().to_owned();
        let marker = session.paths().finalized().to_owned();

        let paths = session
            .finalize(SessionOutcome::exited(7))
            .expect("the session should be finalized");

        assert_eq!(paths.database(), database);
        assert!(marker.exists());
        assert!(!paths.lock().exists());

        let connection = Connection::open(database).expect("the database should open");
        let row = connection
            .query_row(
                "SELECT state, finalized, command_name, argument_count, exit_code
                 FROM session WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .expect("the session row should exist");

        assert_eq!(row, ("finalized".to_owned(), 1, "printf".to_owned(), 2, 7));
    }

    #[cfg(unix)]
    #[test]
    fn session_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("printf", 0)
            .expect("a session should be started");

        for path in [session.paths().database(), session.paths().lock()] {
            let mode = fs::metadata(path)
                .expect("session metadata should be available")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn orphaned_running_sessions_are_recovered() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("sleep", 1)
            .expect("a session should be started");
        let database = session.paths().database().to_owned();
        let marker = session.paths().finalized().to_owned();
        drop(session);

        let recovered = store
            .recover_interrupted()
            .expect("the orphaned session should be recovered");

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].database(), database);
        assert!(marker.exists());
        assert!(!recovered[0].lock().exists());

        let connection = Connection::open(database).expect("the database should open");
        let row = connection
            .query_row(
                "SELECT state, finalized, interruption FROM session WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("the session row should exist");

        assert_eq!(
            row,
            (
                "interrupted".to_owned(),
                1,
                "runner exited before finalization".to_owned(),
            )
        );
    }

    #[test]
    fn active_sessions_are_not_recovered() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("sleep", 1)
            .expect("a session should be started");

        let recovered = store
            .recover_interrupted()
            .expect("recovery should inspect the store");

        assert!(recovered.is_empty());
        assert!(!session.paths().finalized().exists());
    }
}
