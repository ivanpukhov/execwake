#![no_main]

use std::fs::{self, OpenOptions};
use std::io::Write;

use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 1024 * 1024;

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_INPUT_BYTES {
        return;
    }

    let directory = std::env::temp_dir().join(format!("execwake-fuzz-{}", std::process::id()));
    if fs::create_dir_all(&directory).is_err() {
        return;
    }
    let path = directory.join("session.sqlite3");
    let result = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .and_then(|mut file| file.write_all(input));
    if result.is_ok() {
        let _ = execwake::semantic_diff::SessionSnapshot::load(&path);
    }
    let _ = fs::remove_file(path);
});
