use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use crate::behavior::{
    BehaviorCategory, BehaviorEvent, BehaviorFact, BehaviorKey, BehaviorProcess, BehaviorSet,
    BehaviorValue,
};
use crate::findings::Severity;
use crate::session::CURRENT_SCHEMA_VERSION;

#[derive(Debug)]
pub enum DiffError {
    Io(io::Error),
    Database(rusqlite::Error),
    InvalidSession(String),
}

impl fmt::Display for DiffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "session input error: {error}"),
            Self::Database(error) => write!(formatter, "session database error: {error}"),
            Self::InvalidSession(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for DiffError {}

impl From<io::Error> for DiffError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for DiffError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub schema_version: u32,
    pub backend: Option<String>,
    pub privacy_profile: Option<String>,
    pub command_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSnapshot {
    pub state: String,
    pub lost_events: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    pub info: SessionInfo,
    pub coverage: BTreeMap<BehaviorCategory, CoverageSnapshot>,
    pub behavior: BehaviorSet,
    pub findings: Vec<FindingSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSnapshot {
    pub finding_id: i64,
    pub rule_id: String,
    pub rule_version: u32,
    pub severity: Severity,
    pub process: String,
    pub subject: String,
    pub evidence_event_ids: Vec<i64>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ChangeStatus {
    New,
    Removed,
    Changed,
    Unchanged,
}

impl ChangeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "NEW",
            Self::Removed => "REMOVED",
            Self::Changed => "CHANGED",
            Self::Unchanged => "UNCHANGED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorSide {
    pub value: BehaviorValue,
    pub evidence_event_ids: Vec<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorChange {
    pub status: ChangeStatus,
    pub key: BehaviorKey,
    pub before: Option<BehaviorSide>,
    pub after: Option<BehaviorSide>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingChange {
    pub status: ChangeStatus,
    pub before: Option<FindingSnapshot>,
    pub after: Option<FindingSnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityIssue {
    SchemaMismatch,
    UnsupportedSchema,
    BackendUnavailable,
    BackendMismatch,
    PrivacyProfileUnavailable,
    PrivacyProfileMismatch,
    CoverageUnavailable,
    CoverageMismatch,
    LostEvents,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryCompatibility {
    pub category: BehaviorCategory,
    pub comparable: bool,
    pub issues: Vec<CompatibilityIssue>,
    pub before: Option<CoverageSnapshot>,
    pub after: Option<CoverageSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticDiff {
    pub before: SessionInfo,
    pub after: SessionInfo,
    pub compatibility: Vec<CategoryCompatibility>,
    pub behavior: Vec<BehaviorChange>,
    pub findings: Vec<FindingChange>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindingKey {
    rule_id: String,
    rule_version: u32,
    process: String,
    subject: String,
}

pub fn compare_paths(before: &Path, after: &Path) -> Result<SemanticDiff, DiffError> {
    Ok(compare(
        SessionSnapshot::load(before)?,
        SessionSnapshot::load(after)?,
    ))
}

pub fn compare(before: SessionSnapshot, after: SessionSnapshot) -> SemanticDiff {
    let compatibility = compare_compatibility(&before, &after);
    let comparable: BTreeMap<_, _> = compatibility
        .iter()
        .map(|category| (category.category, category.comparable))
        .collect();
    let behavior = compare_behavior(&before.behavior.facts, &after.behavior.facts, &comparable);
    let findings = compare_findings(&before.findings, &after.findings, &comparable);

    SemanticDiff {
        before: before.info,
        after: after.info,
        compatibility,
        behavior,
        findings,
    }
}

impl SessionSnapshot {
    pub fn load(path: &Path) -> Result<Self, DiffError> {
        let database = canonical_regular_file(path)?;
        let connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        let (id, schema_version, state, finalized, command_name, runner_pid, backend) = connection
            .query_row(
                "SELECT id, schema_version, state, finalized, command_name, runner_pid,
                        collector_backend
                 FROM session WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )?;
        if finalized != 1 || !matches!(state.as_str(), "finalized" | "interrupted") {
            return Err(DiffError::InvalidSession(
                "session comparison requires finalized inputs".to_owned(),
            ));
        }
        let schema_version = u32::try_from(schema_version).map_err(|_| {
            DiffError::InvalidSession("session schema version is out of range".to_owned())
        })?;
        let privacy_profile = if table_has_column(&connection, "session", "privacy_profile")? {
            connection.query_row(
                "SELECT privacy_profile FROM session WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?
        } else {
            None
        };
        let info = SessionInfo {
            id: id.clone(),
            schema_version,
            backend,
            privacy_profile,
            command_name,
        };
        let coverage = load_coverage(&connection)?;

        if schema_version != CURRENT_SCHEMA_VERSION {
            return Ok(Self {
                info,
                coverage,
                behavior: BehaviorSet::default(),
                findings: Vec::new(),
            });
        }

        let processes = load_processes(&connection)?;
        let events = load_events(&connection)?;
        let behavior = BehaviorSet::build(&id, runner_pid, &processes, &events);
        let findings = load_findings(&connection, &behavior.process_roles)?;
        Ok(Self {
            info,
            coverage,
            behavior,
            findings,
        })
    }
}

fn canonical_regular_file(path: &Path) -> io::Result<PathBuf> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session input is not a regular file",
        ));
    }
    fs::canonicalize(path)
}

fn table_has_column(connection: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns.iter().any(|candidate| candidate == column))
}

fn load_coverage(
    connection: &Connection,
) -> rusqlite::Result<BTreeMap<BehaviorCategory, CoverageSnapshot>> {
    let mut statement = connection
        .prepare("SELECT category, state, lost_events FROM coverage ORDER BY category")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                CoverageSnapshot {
                    state: row.get(1)?,
                    lost_events: row.get(2)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(category, coverage)| {
            category_from_coverage_name(&category).map(|category| (category, coverage))
        })
        .collect())
}

fn load_processes(connection: &Connection) -> rusqlite::Result<Vec<BehaviorProcess>> {
    let mut statement = connection.prepare(
        "SELECT process_id, operating_system_id, parent_process_id, executable,
                exit_code, termination_signal, evidence
         FROM process ORDER BY process_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(BehaviorProcess {
                process_id: row.get(0)?,
                operating_system_id: row.get(1)?,
                parent_process_id: row.get(2)?,
                executable: row.get(3)?,
                exit_code: row.get(4)?,
                termination_signal: row.get(5)?,
                evidence: row.get(6)?,
            })
        })?
        .collect();
    rows
}

fn load_events(connection: &Connection) -> rusqlite::Result<Vec<BehaviorEvent>> {
    let mut statement = connection.prepare(
        "SELECT event_id, category, operation, target, process_id, evidence
         FROM event ORDER BY event_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(BehaviorEvent {
                event_id: row.get(0)?,
                category: row.get(1)?,
                operation: row.get(2)?,
                target: row.get(3)?,
                process_id: row.get(4)?,
                evidence: row.get(5)?,
            })
        })?
        .collect();
    rows
}

fn load_findings(
    connection: &Connection,
    process_roles: &BTreeMap<i64, String>,
) -> Result<Vec<FindingSnapshot>, DiffError> {
    let mut statement = connection.prepare(
        "SELECT finding_id, rule_id, rule_version, severity, process_id, subject
         FROM finding ORDER BY rule_id, rule_version, process_id, subject",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);

    let mut findings = Vec::new();
    for (finding_id, rule_id, rule_version, severity, process_id, subject) in rows {
        let Some(process) = process_roles.get(&process_id) else {
            return Err(DiffError::InvalidSession(
                "finding references an unknown process".to_owned(),
            ));
        };
        let severity = Severity::parse(&severity)
            .ok_or_else(|| DiffError::InvalidSession("finding severity is invalid".to_owned()))?;
        let rule_version = u32::try_from(rule_version).map_err(|_| {
            DiffError::InvalidSession("finding rule version is out of range".to_owned())
        })?;
        let mut evidence_statement = connection.prepare(
            "SELECT event_id FROM finding_evidence
             WHERE finding_id = ?1 ORDER BY event_id",
        )?;
        let evidence_event_ids = evidence_statement
            .query_map([finding_id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        findings.push(FindingSnapshot {
            finding_id,
            rule_id,
            rule_version,
            severity,
            process: process.clone(),
            subject,
            evidence_event_ids,
        });
    }
    findings.sort_by_key(finding_key);
    Ok(findings)
}

fn compare_compatibility(
    before: &SessionSnapshot,
    after: &SessionSnapshot,
) -> Vec<CategoryCompatibility> {
    BehaviorCategory::ALL
        .into_iter()
        .map(|category| {
            let mut issues = BTreeSet::new();
            if before.info.schema_version != after.info.schema_version {
                issues.insert(CompatibilityIssue::SchemaMismatch);
            }
            if before.info.schema_version != CURRENT_SCHEMA_VERSION
                || after.info.schema_version != CURRENT_SCHEMA_VERSION
            {
                issues.insert(CompatibilityIssue::UnsupportedSchema);
            }
            match (&before.info.backend, &after.info.backend) {
                (Some(left), Some(right)) if left == right => {}
                (Some(_), Some(_)) => {
                    issues.insert(CompatibilityIssue::BackendMismatch);
                }
                _ => {
                    issues.insert(CompatibilityIssue::BackendUnavailable);
                }
            }
            match (&before.info.privacy_profile, &after.info.privacy_profile) {
                (Some(left), Some(right)) if left == right => {}
                (Some(_), Some(_)) => {
                    issues.insert(CompatibilityIssue::PrivacyProfileMismatch);
                }
                _ => {
                    issues.insert(CompatibilityIssue::PrivacyProfileUnavailable);
                }
            }

            let left = before.coverage.get(&category).cloned();
            let right = after.coverage.get(&category).cloned();
            match (&left, &right) {
                (Some(left), Some(right)) => {
                    if left.state == "unavailable" || right.state == "unavailable" {
                        issues.insert(CompatibilityIssue::CoverageUnavailable);
                    }
                    if left.state != right.state {
                        issues.insert(CompatibilityIssue::CoverageMismatch);
                    }
                    if left.lost_events > 0 || right.lost_events > 0 {
                        issues.insert(CompatibilityIssue::LostEvents);
                    }
                }
                _ => {
                    issues.insert(CompatibilityIssue::CoverageUnavailable);
                }
            }
            CategoryCompatibility {
                category,
                comparable: issues.is_empty(),
                issues: issues.into_iter().collect(),
                before: left,
                after: right,
            }
        })
        .collect()
}

fn compare_behavior(
    before: &[BehaviorFact],
    after: &[BehaviorFact],
    comparable: &BTreeMap<BehaviorCategory, bool>,
) -> Vec<BehaviorChange> {
    let before: BTreeMap<_, _> = before.iter().map(|fact| (&fact.key, fact)).collect();
    let after: BTreeMap<_, _> = after.iter().map(|fact| (&fact.key, fact)).collect();
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
    keys.into_iter()
        .filter_map(|key| {
            let left = before.get(key).copied();
            let right = after.get(key).copied();
            let category_comparable = comparable.get(&key.category()).copied().unwrap_or(false);
            change_status(
                left.map(|fact| &fact.value),
                right.map(|fact| &fact.value),
                category_comparable,
            )
            .map(|status| BehaviorChange {
                status,
                key: key.clone(),
                before: left.map(behavior_side),
                after: right.map(behavior_side),
            })
        })
        .collect()
}

fn behavior_side(fact: &BehaviorFact) -> BehaviorSide {
    BehaviorSide {
        value: fact.value.clone(),
        evidence_event_ids: fact.evidence_event_ids.clone(),
    }
}

fn compare_findings(
    before: &[FindingSnapshot],
    after: &[FindingSnapshot],
    comparable: &BTreeMap<BehaviorCategory, bool>,
) -> Vec<FindingChange> {
    let before: BTreeMap<_, _> = before
        .iter()
        .map(|finding| (finding_key(finding), finding))
        .collect();
    let after: BTreeMap<_, _> = after
        .iter()
        .map(|finding| (finding_key(finding), finding))
        .collect();
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
    keys.into_iter()
        .filter_map(|key| {
            let left = before.get(&key).copied();
            let right = after.get(&key).copied();
            let category = finding_category(&key.rule_id);
            let category_comparable = comparable.get(&category).copied().unwrap_or(false);
            change_status(
                left.map(|finding| finding.severity),
                right.map(|finding| finding.severity),
                category_comparable,
            )
            .map(|status| FindingChange {
                status,
                before: left.cloned(),
                after: right.cloned(),
            })
        })
        .collect()
}

fn change_status<T: Eq>(
    before: Option<T>,
    after: Option<T>,
    category_comparable: bool,
) -> Option<ChangeStatus> {
    match (before, after) {
        (Some(left), Some(right)) if left == right => Some(ChangeStatus::Unchanged),
        (Some(_), Some(_)) => Some(ChangeStatus::Changed),
        (None, Some(_)) if category_comparable => Some(ChangeStatus::New),
        (Some(_), None) if category_comparable => Some(ChangeStatus::Removed),
        _ => None,
    }
}

fn finding_key(finding: &FindingSnapshot) -> FindingKey {
    FindingKey {
        rule_id: finding.rule_id.clone(),
        rule_version: finding.rule_version,
        process: finding.process.clone(),
        subject: finding.subject.clone(),
    }
}

fn finding_category(rule_id: &str) -> BehaviorCategory {
    if rule_id.starts_with("EW-FS-") {
        BehaviorCategory::Filesystem
    } else if rule_id.starts_with("EW-NET-") {
        BehaviorCategory::Network
    } else if rule_id.starts_with("EW-ENV-") {
        BehaviorCategory::Environment
    } else {
        BehaviorCategory::Process
    }
}

fn category_from_coverage_name(value: &str) -> Option<BehaviorCategory> {
    BehaviorCategory::ALL
        .into_iter()
        .find(|category| category.coverage_name() == value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::behavior::{
        BehaviorCategory, BehaviorFact, BehaviorKey, BehaviorSet, BehaviorValue,
    };

    use super::{
        compare, ChangeStatus, CompatibilityIssue, CoverageSnapshot, SessionInfo, SessionSnapshot,
    };

    fn fact(path: &str, operations: &[&str], event_id: i64) -> BehaviorFact {
        BehaviorFact {
            key: BehaviorKey::Filesystem {
                path: path.to_owned(),
                process: Some("root/npm".to_owned()),
            },
            value: BehaviorValue {
                operations: operations.iter().map(|value| (*value).to_owned()).collect(),
                evidence: vec!["observed".to_owned()],
                attributes: Vec::new(),
            },
            evidence_event_ids: vec![event_id],
        }
    }

    fn snapshot(
        backend: &str,
        filesystem: CoverageSnapshot,
        facts: Vec<BehaviorFact>,
    ) -> SessionSnapshot {
        let coverage = BehaviorCategory::ALL
            .into_iter()
            .map(|category| {
                let value = if category == BehaviorCategory::Filesystem {
                    filesystem.clone()
                } else {
                    CoverageSnapshot {
                        state: "complete".to_owned(),
                        lost_events: 0,
                    }
                };
                (category, value)
            })
            .collect::<BTreeMap<_, _>>();
        SessionSnapshot {
            info: SessionInfo {
                id: "session".to_owned(),
                schema_version: crate::session::CURRENT_SCHEMA_VERSION,
                backend: Some(backend.to_owned()),
                privacy_profile: Some("paths-v1".to_owned()),
                command_name: "npm".to_owned(),
            },
            coverage,
            behavior: BehaviorSet {
                facts,
                process_roles: BTreeMap::new(),
            },
            findings: Vec::new(),
        }
    }

    #[test]
    fn classifies_new_removed_changed_and_unchanged_facts() {
        let coverage = CoverageSnapshot {
            state: "partial".to_owned(),
            lost_events: 0,
        };
        let before = snapshot(
            "ptrace",
            coverage.clone(),
            vec![
                fact("$WORKSPACE/changed", &["read"], 1),
                fact("$WORKSPACE/removed", &["read"], 2),
                fact("$WORKSPACE/same", &["read"], 3),
            ],
        );
        let after = snapshot(
            "ptrace",
            coverage,
            vec![
                fact("$WORKSPACE/changed", &["read", "write"], 4),
                fact("$WORKSPACE/new", &["write"], 5),
                fact("$WORKSPACE/same", &["read"], 6),
            ],
        );

        let diff = compare(before, after);
        let statuses: BTreeMap<_, _> = diff
            .behavior
            .iter()
            .map(|change| (change.key.subject(), change.status))
            .collect();

        assert_eq!(statuses["$WORKSPACE/changed"], ChangeStatus::Changed);
        assert_eq!(statuses["$WORKSPACE/new"], ChangeStatus::New);
        assert_eq!(statuses["$WORKSPACE/removed"], ChangeStatus::Removed);
        assert_eq!(statuses["$WORKSPACE/same"], ChangeStatus::Unchanged);
    }

    #[test]
    fn suppresses_one_sided_facts_when_coverage_is_incomparable() {
        let before = snapshot(
            "ptrace",
            CoverageSnapshot {
                state: "partial".to_owned(),
                lost_events: 4,
            },
            vec![
                fact("$HOME/.npmrc", &["read"], 1),
                fact("$WORKSPACE/only-before", &["write"], 2),
            ],
        );
        let after = snapshot(
            "ebpf",
            CoverageSnapshot {
                state: "complete".to_owned(),
                lost_events: 0,
            },
            vec![
                fact("$HOME/.npmrc", &["read", "write"], 3),
                fact("$WORKSPACE/only-after", &["write"], 4),
            ],
        );

        let diff = compare(before, after);
        let filesystem = diff
            .compatibility
            .iter()
            .find(|entry| entry.category == BehaviorCategory::Filesystem)
            .expect("filesystem compatibility should exist");

        assert!(!filesystem.comparable);
        assert!(filesystem
            .issues
            .contains(&CompatibilityIssue::BackendMismatch));
        assert!(filesystem
            .issues
            .contains(&CompatibilityIssue::CoverageMismatch));
        assert!(filesystem.issues.contains(&CompatibilityIssue::LostEvents));
        assert_eq!(diff.behavior.len(), 1);
        assert_eq!(diff.behavior[0].status, ChangeStatus::Changed);
        assert_eq!(diff.behavior[0].key.subject(), "$HOME/.npmrc");
    }
}
