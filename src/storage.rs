use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
            let base = self.root.join(id.as_str());
            let paths = SessionPaths {
                id,
                database: base.with_extension("sqlite3"),
                lock: base.with_extension("lock"),
                finalized: base.with_extension("finalized"),
            };

            if !paths.database.exists() && !paths.lock.exists() && !paths.finalized.exists() {
                return Ok(paths);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique session id",
        ))
    }
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
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }

    #[cfg(not(unix))]
    fs::create_dir_all(path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{SessionId, SessionStore};

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
}
