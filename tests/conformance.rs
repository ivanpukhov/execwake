#![cfg(feature = "conformance-fixture")]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct FixtureDirectory {
    path: PathBuf,
}

impl FixtureDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "execwake-conformance-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("fixture directory should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if self.path.parent() == Some(env::temp_dir().as_path())
            && self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("execwake-conformance-"))
                .unwrap_or(false)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[test]
fn produces_the_expected_local_side_effects() {
    let fixture = FixtureDirectory::new();
    fs::write(fixture.path().join("read.txt"), "fixture input\n")
        .expect("read fixture should be written");
    fs::write(fixture.path().join("modified.txt"), "before\n")
        .expect("modified fixture should be written");
    fs::write(fixture.path().join("rename-from.txt"), "rename me\n")
        .expect("rename fixture should be written");

    let output = Command::new(env!("CARGO_BIN_EXE_execwake-conformance"))
        .arg(fixture.path())
        .env("EXECWAKE_CONFORMANCE_FLAG", "present")
        .output()
        .expect("fixture should run");

    assert!(
        output.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(fixture.path().join("created.txt")).unwrap(),
        "created by root\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.path().join("modified.txt")).unwrap(),
        "before\nafter\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.path().join("renamed.txt")).unwrap(),
        "rename me\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.path().join("child.txt")).unwrap(),
        "created by child\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.path().join("grandchild.txt")).unwrap(),
        "created by grandchild\n"
    );
    assert!(!fixture.path().join("rename-from.txt").exists());
    assert!(!fixture.path().join("delete-me.txt").exists());
}
