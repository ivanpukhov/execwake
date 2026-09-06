use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use execwake::behavior::{BehaviorCategory, BehaviorKey, BehaviorValue};
use execwake::collector::{CollectorEvent, CollectorSink, ProcessIdentity, ProcessRecord};
use execwake::semantic_diff::{
    compare_paths, BehaviorChange, BehaviorSide, CategoryCompatibility, ChangeStatus,
    CompatibilityIssue, FindingChange, FindingSnapshot, SemanticDiff,
};
use execwake::session::{CategoryCoverage, EvidenceKind, SessionCoverage};
use execwake::storage::{ActiveSession, SessionOutcome, SessionPaths, SessionStore};
use serde::Serialize;

const ROOT_PROCESS: ProcessIdentity = ProcessIdentity::new(1);
const GIT_PROCESS: ProcessIdentity = ProcessIdentity::new(2);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        Self(std::env::temp_dir().join(format!("execwake-{label}-{}-{nonce}", std::process::id())))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GoldenDiff {
    compatibility: Vec<GoldenCompatibility>,
    new: Vec<GoldenBehavior>,
    removed: Vec<GoldenBehavior>,
    changed: Vec<GoldenBehavior>,
    unchanged: Vec<GoldenBehavior>,
    findings: Vec<GoldenFindingChange>,
    what_changed: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GoldenCompatibility {
    category: BehaviorCategory,
    comparable: bool,
    issues: Vec<CompatibilityIssue>,
    before: Option<String>,
    after: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GoldenBehavior {
    category: BehaviorCategory,
    subject: String,
    process: Option<String>,
    before: Option<GoldenBehaviorSide>,
    after: Option<GoldenBehaviorSide>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GoldenBehaviorSide {
    value: BehaviorValue,
    evidence_event_ids: Vec<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GoldenFindingChange {
    status: ChangeStatus,
    before: Option<GoldenFinding>,
    after: Option<GoldenFinding>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GoldenFinding {
    rule_id: String,
    rule_version: u32,
    severity: String,
    process: String,
    subject: String,
    evidence_event_ids: Vec<i64>,
}

#[test]
fn npm_package_update_matches_the_golden_diff() {
    let directory = TestDirectory::new("npm-update");
    let store = SessionStore::at(directory.0.clone()).expect("session storage should be created");

    let mut before = begin_npm_session(&store, 41_001);
    record_event(
        &mut before,
        "filesystem",
        "read",
        "$WORKSPACE/package.json".to_owned(),
        ROOT_PROCESS,
        10,
    );
    record_event(
        &mut before,
        "network",
        "connect",
        "tcp 104.16.1.10:443".to_owned(),
        ROOT_PROCESS,
        20,
    );
    let before = finish(before);

    let mut after = begin_npm_session(&store, 52_001);
    record_event(
        &mut after,
        "filesystem",
        "read",
        "$WORKSPACE/package.json".to_owned(),
        ROOT_PROCESS,
        10,
    );
    record_event(
        &mut after,
        "network",
        "connect",
        "tcp 104.16.1.10:443".to_owned(),
        ROOT_PROCESS,
        20,
    );
    record_event(
        &mut after,
        "filesystem",
        "read",
        "$HOME/.gitconfig".to_owned(),
        ROOT_PROCESS,
        30,
    );
    record_event(
        &mut after,
        "network",
        "connect",
        "tcp 203.0.113.50:443".to_owned(),
        ROOT_PROCESS,
        40,
    );
    after
        .record_process(ProcessRecord {
            identity: GIT_PROCESS,
            operating_system_id: 52_002,
            start_time_ticks: Some(8_200),
            parent: Some(ROOT_PROCESS),
            executable: "/usr/bin/git".to_owned(),
            occurred_at_ms: 50,
            evidence: EvidenceKind::Observed,
        })
        .expect("the git process should be recorded");
    record_event(
        &mut after,
        "process",
        "exec",
        "/usr/bin/git".to_owned(),
        GIT_PROCESS,
        50,
    );
    let after = finish(after);

    let diff = compare(&before, &after);
    assert_golden(&diff, include_str!("golden/npm_package_update.json"));
}

#[test]
fn repeated_npm_run_matches_the_golden_diff() {
    let directory = TestDirectory::new("repeat-run");
    let store = SessionStore::at(directory.0.clone()).expect("session storage should be created");

    let before = record_repeat_session(&store, 61_001, 49_101);
    let after = record_repeat_session(&store, 72_001, 58_303);

    let diff = compare(&before, &after);
    assert_golden(&diff, include_str!("golden/repeat_run.json"));
}

#[test]
fn diff_exit_policy_is_exposed_by_the_command() {
    let directory = TestDirectory::new("exit-policy");
    let store = SessionStore::at(directory.0.clone()).expect("session storage should be created");
    let unchanged = record_repeat_session(&store, 81_001, 45_101);
    let mut changed = begin_npm_session(&store, 82_001);
    record_event(
        &mut changed,
        "filesystem",
        "read",
        "$HOME/.gitconfig".to_owned(),
        ROOT_PROCESS,
        10,
    );
    let changed = finish(changed);

    let same = diff_command(&unchanged, &unchanged);
    assert_eq!(same.status.code(), Some(0));

    let different = diff_command(&unchanged, &changed);
    assert_eq!(different.status.code(), Some(10));
    let document: serde_json::Value =
        serde_json::from_slice(&different.stdout).expect("stdout should contain the JSON diff");
    assert!(document["behavior"]
        .as_array()
        .expect("behavior should be an array")
        .iter()
        .any(|change| change["status"] != "UNCHANGED"));

    let connection = rusqlite::Connection::open(changed.database())
        .expect("the changed session should open for the fixture update");
    connection
        .execute(
            "UPDATE session SET collector_backend = 'ebpf' WHERE singleton = 1",
            [],
        )
        .expect("the fixture backend should change");
    drop(connection);

    let incomparable = diff_command(&unchanged, &changed);
    assert_eq!(incomparable.status.code(), Some(11));
}

fn diff_command(before: &SessionPaths, after: &SessionPaths) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_execwake"))
        .arg("diff")
        .arg("--json")
        .arg("--exit-code")
        .arg(before.database())
        .arg(after.database())
        .env("CI", "1")
        .output()
        .expect("the diff command should run")
}

fn begin_npm_session(store: &SessionStore, operating_system_id: u32) -> ActiveSession {
    let mut session = store.begin("npm", 3).expect("the npm session should start");
    session
        .set_backend("ptrace")
        .expect("the backend should be recorded");
    session
        .record_process(ProcessRecord {
            identity: ROOT_PROCESS,
            operating_system_id,
            start_time_ticks: Some(8_100),
            parent: None,
            executable: "/usr/bin/npm".to_owned(),
            occurred_at_ms: 0,
            evidence: EvidenceKind::Observed,
        })
        .expect("the npm process should be recorded");
    session
}

fn record_repeat_session(
    store: &SessionStore,
    operating_system_id: u32,
    ephemeral_port: u16,
) -> SessionPaths {
    let mut session = begin_npm_session(store, operating_system_id);
    let session_id = session.paths().id().as_str().to_owned();
    record_event(
        &mut session,
        "filesystem",
        "write",
        format!("$TMP/npm-{operating_system_id}/{session_id}"),
        ROOT_PROCESS,
        10,
    );
    record_event(
        &mut session,
        "network",
        "connect",
        format!("tcp 127.0.0.1:{ephemeral_port}"),
        ROOT_PROCESS,
        20,
    );
    finish(session)
}

fn record_event(
    session: &mut ActiveSession,
    category: &'static str,
    operation: &'static str,
    target: String,
    process: ProcessIdentity,
    occurred_at_ms: i64,
) {
    session
        .record_event(CollectorEvent {
            category,
            operation,
            target,
            process: Some(process),
            occurred_at_ms,
            evidence: EvidenceKind::Observed,
        })
        .expect("the event should be recorded");
}

fn finish(mut session: ActiveSession) -> SessionPaths {
    session
        .set_coverage(SessionCoverage {
            processes: CategoryCoverage::complete(),
            filesystem: CategoryCoverage::complete(),
            network: CategoryCoverage::complete(),
            environment: CategoryCoverage::complete(),
        })
        .expect("coverage should be recorded");
    session
        .finalize(SessionOutcome::exited(0))
        .expect("the session should finalize")
}

fn compare(before: &SessionPaths, after: &SessionPaths) -> SemanticDiff {
    compare_paths(before.database(), after.database()).expect("the sessions should compare")
}

fn assert_golden(diff: &SemanticDiff, expected: &str) {
    let projection = GoldenDiff {
        compatibility: diff
            .compatibility
            .iter()
            .map(golden_compatibility)
            .collect(),
        new: changes(diff, ChangeStatus::New),
        removed: changes(diff, ChangeStatus::Removed),
        changed: changes(diff, ChangeStatus::Changed),
        unchanged: changes(diff, ChangeStatus::Unchanged),
        findings: diff.findings.iter().map(golden_finding_change).collect(),
        what_changed: diff.what_changed.clone(),
    };
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&projection).expect("the golden diff should serialize")
    );
    assert_eq!(actual, expected);
}

fn changes(diff: &SemanticDiff, status: ChangeStatus) -> Vec<GoldenBehavior> {
    diff.behavior
        .iter()
        .filter(|change| change.status == status)
        .map(golden_behavior)
        .collect()
}

fn golden_compatibility(compatibility: &CategoryCompatibility) -> GoldenCompatibility {
    GoldenCompatibility {
        category: compatibility.category,
        comparable: compatibility.comparable,
        issues: compatibility.issues.clone(),
        before: compatibility
            .before
            .as_ref()
            .map(|coverage| format!("{}/{}", coverage.state, coverage.lost_events)),
        after: compatibility
            .after
            .as_ref()
            .map(|coverage| format!("{}/{}", coverage.state, coverage.lost_events)),
    }
}

fn golden_behavior(change: &BehaviorChange) -> GoldenBehavior {
    GoldenBehavior {
        category: change.key.category(),
        subject: change.key.subject().to_owned(),
        process: behavior_process(&change.key).map(str::to_owned),
        before: change.before.as_ref().map(golden_behavior_side),
        after: change.after.as_ref().map(golden_behavior_side),
    }
}

fn behavior_process(key: &BehaviorKey) -> Option<&str> {
    match key {
        BehaviorKey::Filesystem { process, .. }
        | BehaviorKey::Network { process, .. }
        | BehaviorKey::Environment { process, .. } => process.as_deref(),
        BehaviorKey::Process { role } => Some(role),
    }
}

fn golden_behavior_side(side: &BehaviorSide) -> GoldenBehaviorSide {
    GoldenBehaviorSide {
        value: side.value.clone(),
        evidence_event_ids: side.evidence_event_ids.clone(),
    }
}

fn golden_finding_change(change: &FindingChange) -> GoldenFindingChange {
    GoldenFindingChange {
        status: change.status,
        before: change.before.as_ref().map(golden_finding),
        after: change.after.as_ref().map(golden_finding),
    }
}

fn golden_finding(finding: &FindingSnapshot) -> GoldenFinding {
    GoldenFinding {
        rule_id: finding.rule_id.clone(),
        rule_version: finding.rule_version,
        severity: finding.severity.as_str().to_owned(),
        process: finding.process.clone(),
        subject: finding.subject.clone(),
        evidence_event_ids: finding.evidence_event_ids.clone(),
    }
}
