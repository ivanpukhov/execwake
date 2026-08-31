#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

const ENVIRONMENT_PROBES: [(&str, &str); 4] = [
    ("EXECWAKE_NODE_PARENT_PROBE", "parent-environment-value"),
    ("EXECWAKE_NODE_CHILD_PROBE", "child-environment-value"),
    ("EXECWAKE_NODE_ESM_PROBE", "esm-environment-value"),
    ("EXECWAKE_NODE_WORKER_PROBE", "worker-environment-value"),
];
const FORBIDDEN_PAYLOADS: [&str; 15] = [
    "parent-environment-value",
    "child-environment-value",
    "esm-environment-value",
    "worker-environment-value",
    "fetch-query-value",
    "fetch-fragment",
    "https-query-value",
    "https-fragment",
    "fetch-header-value",
    "https-header-value",
    "fetch-cookie-value",
    "https-cookie-value",
    "fetch-request-body-value",
    "https-request-body-value",
    "response-body-value",
];

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "execwake-node-enrichment-{}-{nonce}",
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
fn records_bounded_node_runtime_evidence_across_supported_module_paths() {
    if Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_or(true, |status| !status.success())
    {
        eprintln!("node executable is unavailable; skipping Node enrichment integration test");
        return;
    }

    let state = TestDirectory::new();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/node_enrichment/root.cjs");
    let mut command = Command::new(env!("CARGO_BIN_EXE_execwake"));
    command
        .env("XDG_STATE_HOME", &state.0)
        .env("CI", "1")
        .env("NODE_OPTIONS", "--no-warnings")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["run", "--node-enrichment", "--", "node"])
        .arg(fixture)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in ENVIRONMENT_PROBES {
        command.env(name, value);
    }
    let output = command.output().expect("the instrumented run should start");
    assert!(
        output.status.success(),
        "instrumented fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let database = session_path(&output.stderr);
    let connection = Connection::open(&database).expect("the session database should open");
    let mode: String = connection
        .query_row("SELECT mode FROM session WHERE singleton = 1", [], |row| {
            row.get(0)
        })
        .expect("the session mode should be readable");
    let coverage: (String, i64) = connection
        .query_row(
            "SELECT state, lost_events FROM coverage WHERE category = 'node_enrichment'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the enrichment coverage should be readable");
    assert_eq!(mode, "instrumented");
    assert_eq!(coverage.0, "partial");
    assert_eq!(coverage.1, 0);

    let environment_rows: Vec<(String, i64)> = connection
        .prepare(
            "SELECT environment_name, process_id FROM node_enrichment
             WHERE kind = 'environment' ORDER BY environment_name, process_id",
        )
        .expect("the environment query should prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("the environment evidence should be queried")
        .collect::<Result<_, _>>()
        .expect("the environment evidence should be read");
    let environment_names: BTreeSet<_> = environment_rows
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    for (name, _) in ENVIRONMENT_PROBES {
        assert!(
            environment_names.contains(name),
            "missing environment read: {name}"
        );
    }
    assert!(
        environment_rows
            .iter()
            .filter(|(name, _)| name == "EXECWAKE_NODE_WORKER_PROBE")
            .count()
            >= 2,
        "the worker preload should emit independently of the parent"
    );
    let mut process_ids_by_probe: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    for (name, process_id) in environment_rows {
        if ENVIRONMENT_PROBES
            .iter()
            .any(|(probe, _)| *probe == name.as_str())
        {
            process_ids_by_probe
                .entry(name)
                .or_default()
                .insert(process_id);
        }
    }
    let parent_process = *process_ids_by_probe["EXECWAKE_NODE_PARENT_PROBE"]
        .iter()
        .next()
        .expect("the parent process should be identified");
    let child_process = process_ids_by_probe["EXECWAKE_NODE_CHILD_PROBE"]
        .iter()
        .copied()
        .find(|process_id| *process_id != parent_process)
        .expect("the CommonJS child should emit from its own process");
    let esm_process = process_ids_by_probe["EXECWAKE_NODE_ESM_PROBE"]
        .iter()
        .copied()
        .find(|process_id| *process_id != parent_process)
        .expect("the ESM child should emit from its own process");
    assert_ne!(child_process, esm_process);
    assert!(process_ids_by_probe["EXECWAKE_NODE_WORKER_PROBE"].contains(&parent_process));

    let http_rows: Vec<(String, String, String, i64, i64)> = connection
        .prepare(
            "SELECT method, host, path, process_id, monotonic_ns
             FROM node_enrichment WHERE kind = 'http' ORDER BY enrichment_id",
        )
        .expect("the HTTP query should prepare")
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .expect("the HTTP evidence should be queried")
        .collect::<Result<_, _>>()
        .expect("the HTTP evidence should be read");
    let paths: BTreeSet<_> = http_rows.iter().map(|row| row.2.as_str()).collect();
    for path in [
        "/fetch/root",
        "/fetch/child",
        "/fetch/module",
        "/fetch/worker",
        "/secure",
    ] {
        assert!(paths.contains(path), "missing sanitized HTTP path: {path}");
    }
    assert!(http_rows.iter().all(|(method, host, path, _, monotonic)| {
        matches!(method.as_str(), "GET" | "POST")
            && (host == "127.0.0.1" || host.starts_with("127.0.0.1:"))
            && !path.contains('?')
            && !path.contains('#')
            && *monotonic > 0
    }));

    let application_protocol_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event
             WHERE category = 'network' AND operation IN ('http', 'GET', 'POST')",
            [],
            |row| row.get(0),
        )
        .expect("kernel network events should be queried");
    let kernel_socket_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event WHERE category = 'network'",
            [],
            |row| row.get(0),
        )
        .expect("kernel socket events should be queried");
    let internal_file_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event
             WHERE category = 'filesystem'
               AND (instr(target, '.node-events') > 0
                    OR instr(target, '.node-preload.cjs') > 0)",
            [],
            |row| row.get(0),
        )
        .expect("internal filesystem events should be queried");
    assert_eq!(application_protocol_events, 0);
    assert_eq!(internal_file_events, 0);
    assert!(kernel_socket_events > 0);
    drop(connection);

    assert!(!database.with_extension("node-events").exists());
    assert!(!database.with_extension("node-preload.cjs").exists());
    let bytes = fs::read(database).expect("the finalized session should be readable");
    for forbidden in FORBIDDEN_PAYLOADS {
        assert!(
            !contains(&bytes, forbidden.as_bytes()),
            "session contains forbidden payload: {forbidden}"
        );
    }
}

fn session_path(stderr: &[u8]) -> PathBuf {
    let stderr = String::from_utf8_lossy(stderr);
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("Session: "))
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("session path is missing from stderr: {stderr}"))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
