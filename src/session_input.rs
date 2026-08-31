use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use rusqlite::limits::Limit;
use rusqlite::Connection;

use crate::limits::{MAX_SESSION_INPUT_BYTES, MAX_SQLITE_VALUE_BYTES, SQLITE_CACHE_KIB};

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

pub(crate) fn canonical_session_file(path: &Path) -> io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid_input("session input is not a regular file"));
    }
    if metadata.len() > MAX_SESSION_INPUT_BYTES {
        return Err(invalid_input("session input exceeds the size limit"));
    }

    let mut header = [0_u8; SQLITE_HEADER.len()];
    File::open(path)?.read_exact(&mut header).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            invalid_input("session input is not a SQLite database")
        } else {
            error
        }
    })?;
    if &header != SQLITE_HEADER {
        return Err(invalid_input("session input is not a SQLite database"));
    }
    fs::canonicalize(path)
}

pub(crate) fn configure_read_only(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "PRAGMA query_only = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA foreign_keys = ON;
         PRAGMA cell_size_check = ON;
         PRAGMA temp_store = FILE;
         PRAGMA mmap_size = 0;",
    )?;
    connection.pragma_update(None, "cache_size", -SQLITE_CACHE_KIB)?;

    connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_SQLITE_VALUE_BYTES);
    connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 64 * 1024);
    connection.set_limit(Limit::SQLITE_LIMIT_COLUMN, 128);
    connection.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 50);
    connection.set_limit(Limit::SQLITE_LIMIT_COMPOUND_SELECT, 10);
    connection.set_limit(Limit::SQLITE_LIMIT_VDBE_OP, 100_000);
    connection.set_limit(Limit::SQLITE_LIMIT_FUNCTION_ARG, 16);
    connection.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0);
    connection.set_limit(Limit::SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 1024);
    connection.set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 100);
    connection.set_limit(Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 0);
    connection.set_limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0);
    Ok(())
}

pub(crate) fn check_integrity(connection: &Connection) -> rusqlite::Result<bool> {
    connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .map(|result| result == "ok")
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::canonical_session_file;
    use crate::limits::MAX_SESSION_INPUT_BYTES;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("execwake-input-{}-{nonce}", std::process::id()));
            fs::create_dir_all(&path).expect("the test directory should be created");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_non_sqlite_and_oversized_inputs() {
        let directory = TestDirectory::new();
        let text = directory.0.join("text.sqlite3");
        File::create(&text)
            .expect("the text file should be created")
            .write_all(b"not a database")
            .expect("the text file should be written");
        assert!(canonical_session_file(&text).is_err());

        let oversized = directory.0.join("oversized.sqlite3");
        let file = File::create(&oversized).expect("the sparse file should be created");
        file.set_len(MAX_SESSION_INPUT_BYTES + 1)
            .expect("the sparse file should be sized");
        assert!(canonical_session_file(&oversized).is_err());
    }
}
