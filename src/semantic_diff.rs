use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use crate::behavior::{
    BehaviorCategory, BehaviorEvent, BehaviorFact, BehaviorKey, BehaviorProcess, BehaviorSet,
    BehaviorValue,
};
use crate::display_text::sanitize;
use crate::findings::Severity;
use crate::limits::{MAX_IMPORTED_EVENTS, MAX_IMPORTED_FINDINGS, MAX_IMPORTED_PROCESSES};
use crate::privacy::CURRENT_PRIVACY_PROFILE;
use crate::session::{
    supports_behavior_schema, CollectorBackend, CollectorFallbackReason, CollectorRequest,
    SessionMode, CURRENT_SCHEMA_VERSION,
};
use crate::session_input::{
    canonical_session_file, check_integrity, configure_read_only, optional_session_text,
};
use crate::storage::SessionId;

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
    pub requested_backend: Option<String>,
    pub backend: Option<String>,
    pub fallback_reason: Option<String>,
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
    UnsupportedPrivacyProfile,
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
    pub what_changed: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindingKey {
    rule_id: String,
    process: String,
    subject: String,
}

pub fn compare_paths(before: &Path, after: &Path) -> Result<SemanticDiff, DiffError> {
    Ok(compare(
        SessionSnapshot::load(before)?,
        SessionSnapshot::load(after)?,
    ))
}

pub fn write_json(diff: &SemanticDiff, output: &mut impl Write) -> io::Result<()> {
    serde_json::to_writer(&mut *output, diff)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
    writeln!(output)
}

pub fn compare(before: SessionSnapshot, after: SessionSnapshot) -> SemanticDiff {
    let compatibility = compare_compatibility(&before, &after);
    let comparable: BTreeMap<_, _> = compatibility
        .iter()
        .map(|category| (category.category, category.comparable))
        .collect();
    let behavior = compare_behavior(&before.behavior.facts, &after.behavior.facts, &comparable);
    let findings = compare_findings(&before.findings, &after.findings, &comparable);
    let what_changed = summarize_findings(&findings);

    SemanticDiff {
        before: before.info,
        after: after.info,
        compatibility,
        behavior,
        findings,
        what_changed,
    }
}

impl SessionSnapshot {
    pub fn load(path: &Path) -> Result<Self, DiffError> {
        let database = canonical_session_file(path)?;
        let connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_read_only(&connection)?;
        if !check_integrity(&connection)? {
            return Err(DiffError::InvalidSession(
                "session database is corrupt".to_owned(),
            ));
        }

        let (id, schema_version, mode, state, finalized, command_name, runner_pid) = connection
            .query_row(
                "SELECT id, schema_version, mode, state, finalized, command_name, runner_pid
                 FROM session WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )?;
        if SessionId::parse(&id).is_none() {
            return Err(DiffError::InvalidSession(
                "session id is invalid".to_owned(),
            ));
        }
        if SessionMode::parse(&mode).is_none() {
            return Err(DiffError::InvalidSession(
                "session mode is unsupported".to_owned(),
            ));
        }
        if finalized != 1 || !matches!(state.as_str(), "finalized" | "interrupted") {
            return Err(DiffError::InvalidSession(
                "session comparison requires finalized inputs".to_owned(),
            ));
        }
        let schema_version = u32::try_from(schema_version).map_err(|_| {
            DiffError::InvalidSession("session schema version is out of range".to_owned())
        })?;
        if schema_version == 0 || schema_version > CURRENT_SCHEMA_VERSION {
            return Err(DiffError::InvalidSession(
                "session schema version is unsupported".to_owned(),
            ));
        }
        let requested_backend = optional_session_text(&connection, "collector_requested")?;
        let backend = optional_session_text(&connection, "collector_backend")?;
        let fallback_reason = optional_session_text(&connection, "collector_fallback_reason")?;
        if schema_version >= 10 {
            let request = requested_backend
                .as_deref()
                .and_then(CollectorRequest::parse)
                .ok_or_else(|| {
                    DiffError::InvalidSession("collector request is invalid".to_owned())
                })?;
            let selected = match backend.as_deref() {
                Some(value) => Some(CollectorBackend::parse(value).ok_or_else(|| {
                    DiffError::InvalidSession("collector backend is invalid".to_owned())
                })?),
                None => None,
            };
            let fallback = match fallback_reason.as_deref() {
                Some(value) => {
                    let reason = CollectorFallbackReason::parse(value).ok_or_else(|| {
                        DiffError::InvalidSession("collector fallback reason is invalid".to_owned())
                    })?;
                    if !reason.is_valid_for_schema(schema_version) {
                        return Err(DiffError::InvalidSession(
                            "collector fallback reason is invalid".to_owned(),
                        ));
                    }
                    Some(reason)
                }
                None => None,
            };
            if fallback.is_some()
                && (request != CollectorRequest::Auto || selected != Some(CollectorBackend::Ptrace))
            {
                return Err(DiffError::InvalidSession(
                    "collector decision is inconsistent".to_owned(),
                ));
            }
        } else if supports_behavior_schema(schema_version)
            && matches!(backend.as_deref(), Some(value) if CollectorBackend::parse(value).is_none())
        {
            return Err(DiffError::InvalidSession(
                "collector backend is invalid".to_owned(),
            ));
        }
        let privacy_profile =
            optional_session_text(&connection, "privacy_profile")?.map(|value| sanitize(&value));
        let info = SessionInfo {
            id: id.clone(),
            schema_version,
            requested_backend: requested_backend.map(|value| sanitize(&value)),
            backend: backend.map(|value| sanitize(&value)),
            fallback_reason: fallback_reason.map(|value| sanitize(&value)),
            privacy_profile,
            command_name: sanitize(&command_name),
        };
        let coverage = load_coverage(&connection)?;

        if !supports_behavior_schema(schema_version) {
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

fn load_coverage(
    connection: &Connection,
) -> Result<BTreeMap<BehaviorCategory, CoverageSnapshot>, DiffError> {
    let mut statement = connection
        .prepare("SELECT category, state, lost_events FROM coverage ORDER BY category")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut coverage_by_category = BTreeMap::new();
    for (category, state, lost_events) in rows {
        let lost_events = u64::try_from(lost_events)
            .map_err(|_| DiffError::InvalidSession("session coverage is invalid".to_owned()))?;
        if !matches!(state.as_str(), "complete" | "partial" | "unavailable")
            || (lost_events > 0 && state != "partial")
        {
            return Err(DiffError::InvalidSession(
                "session coverage is invalid".to_owned(),
            ));
        }
        let Some(category) = category_from_coverage_name(&category) else {
            continue;
        };
        let coverage = CoverageSnapshot { state, lost_events };
        if coverage_by_category.insert(category, coverage).is_some() {
            return Err(DiffError::InvalidSession(
                "session coverage contains duplicate categories".to_owned(),
            ));
        }
    }
    Ok(coverage_by_category)
}

fn load_processes(connection: &Connection) -> rusqlite::Result<Vec<BehaviorProcess>> {
    let mut statement = connection.prepare(&format!(
        "SELECT process_id, operating_system_id, parent_process_id, executable,
                exit_code, termination_signal, evidence
         FROM process ORDER BY process_id LIMIT {}",
        MAX_IMPORTED_PROCESSES + 1
    ))?;
    let rows = statement
        .query_map([], |row| {
            Ok(BehaviorProcess {
                process_id: row.get(0)?,
                operating_system_id: row.get(1)?,
                parent_process_id: row.get(2)?,
                executable: sanitize(&row.get::<_, String>(3)?),
                exit_code: row.get(4)?,
                termination_signal: row.get(5)?,
                evidence: sanitize(&row.get::<_, String>(6)?),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() > MAX_IMPORTED_PROCESSES {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(rows)
}

fn load_events(connection: &Connection) -> rusqlite::Result<Vec<BehaviorEvent>> {
    let mut statement = connection.prepare(&format!(
        "SELECT event_id, category, operation, target, process_id, evidence
         FROM event ORDER BY event_id LIMIT {}",
        MAX_IMPORTED_EVENTS + 1
    ))?;
    let rows = statement
        .query_map([], |row| {
            Ok(BehaviorEvent {
                event_id: row.get(0)?,
                category: sanitize(&row.get::<_, String>(1)?),
                operation: sanitize(&row.get::<_, String>(2)?),
                target: sanitize(&row.get::<_, String>(3)?),
                process_id: row.get(4)?,
                evidence: sanitize(&row.get::<_, String>(5)?),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() > MAX_IMPORTED_EVENTS {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(rows)
}

fn load_findings(
    connection: &Connection,
    process_roles: &BTreeMap<i64, String>,
) -> Result<Vec<FindingSnapshot>, DiffError> {
    let mut statement = connection.prepare(&format!(
        "SELECT finding_id, rule_id, rule_version, severity, process_id, subject
         FROM finding ORDER BY rule_id, rule_version, process_id, subject LIMIT {}",
        MAX_IMPORTED_FINDINGS + 1
    ))?;
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
    if rows.len() > MAX_IMPORTED_FINDINGS {
        return Err(DiffError::InvalidSession(
            "session contains too many findings".to_owned(),
        ));
    }

    let mut findings = Vec::new();
    for (finding_id, rule_id, rule_version, severity, process_id, subject) in rows {
        if finding_id <= 0 || rule_id.is_empty() {
            return Err(DiffError::InvalidSession(
                "finding identity is invalid".to_owned(),
            ));
        }
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
        if rule_version == 0 {
            return Err(DiffError::InvalidSession(
                "finding rule version is invalid".to_owned(),
            ));
        }
        let mut evidence_statement = connection.prepare(&format!(
            "SELECT finding_evidence.event_id, event.process_id
             FROM finding_evidence
             LEFT JOIN event ON event.event_id = finding_evidence.event_id
             WHERE finding_evidence.finding_id = ?1
             ORDER BY finding_evidence.event_id LIMIT {}",
            MAX_IMPORTED_EVENTS + 1
        ))?;
        let evidence = evidence_statement
            .query_map([finding_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if evidence.is_empty()
            || evidence.len() > MAX_IMPORTED_EVENTS
            || evidence.iter().any(|(event_id, event_process)| {
                *event_id <= 0 || *event_process != Some(process_id)
            })
        {
            return Err(DiffError::InvalidSession(
                "finding evidence is invalid".to_owned(),
            ));
        }
        let evidence_event_ids = evidence.into_iter().map(|(event_id, _)| event_id).collect();
        findings.push(FindingSnapshot {
            finding_id,
            rule_id: sanitize(&rule_id),
            rule_version,
            severity,
            process: process.clone(),
            subject: sanitize(&subject),
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
            if !supports_behavior_schema(before.info.schema_version)
                || !supports_behavior_schema(after.info.schema_version)
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
                (Some(left), Some(right)) if left == right => {
                    if !supported_privacy_profile(left) {
                        issues.insert(CompatibilityIssue::UnsupportedPrivacyProfile);
                    }
                }
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

fn supported_privacy_profile(profile: &str) -> bool {
    matches!(profile, "paths-v1") || profile == CURRENT_PRIVACY_PROFILE
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
                left.map(|finding| (finding.rule_version, finding.severity)),
                right.map(|finding| (finding.rule_version, finding.severity)),
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
        process: finding.process.clone(),
        subject: finding.subject.clone(),
    }
}

fn summarize_findings(findings: &[FindingChange]) -> Vec<String> {
    let mut changes: Vec<_> = findings
        .iter()
        .filter(|change| change.status != ChangeStatus::Unchanged)
        .collect();
    changes.sort_by_key(|change| {
        let finding = change.after.as_ref().or(change.before.as_ref());
        (
            summary_status_order(change.status),
            finding.map_or(0, |finding| severity_order(finding.severity)),
            finding
                .map(|finding| finding.rule_id.clone())
                .unwrap_or_default(),
            finding
                .map(|finding| finding.process.clone())
                .unwrap_or_default(),
            finding
                .map(|finding| finding.subject.clone())
                .unwrap_or_default(),
        )
    });

    let summary: Vec<_> = changes.into_iter().map(summary_line).collect();
    if summary.is_empty() {
        vec!["No comparable finding changes.".to_owned()]
    } else {
        summary
    }
}

const fn summary_status_order(status: ChangeStatus) -> u8 {
    match status {
        ChangeStatus::New => 0,
        ChangeStatus::Changed => 1,
        ChangeStatus::Removed => 2,
        ChangeStatus::Unchanged => 3,
    }
}

const fn severity_order(severity: Severity) -> u8 {
    match severity {
        Severity::High => 0,
        Severity::Medium => 1,
        Severity::Low => 2,
    }
}

fn summary_line(change: &FindingChange) -> String {
    match change.status {
        ChangeStatus::New => {
            let finding = change
                .after
                .as_ref()
                .expect("a new finding has an after value");
            format!(
                "New {} finding: {}.",
                finding.severity.as_str(),
                finding_description(finding)
            )
        }
        ChangeStatus::Removed => {
            let finding = change
                .before
                .as_ref()
                .expect("a removed finding has a before value");
            format!(
                "Removed {} finding: {}.",
                finding.severity.as_str(),
                finding_description(finding)
            )
        }
        ChangeStatus::Changed => {
            let before = change
                .before
                .as_ref()
                .expect("a changed finding has a before value");
            let after = change
                .after
                .as_ref()
                .expect("a changed finding has an after value");
            format!(
                "Changed finding {} from rule version {} {} to version {} {}: {}.",
                after.rule_id,
                before.rule_version,
                before.severity.as_str(),
                after.rule_version,
                after.severity.as_str(),
                finding_description(after)
            )
        }
        ChangeStatus::Unchanged => "No comparable finding changes.".to_owned(),
    }
}

fn finding_description(finding: &FindingSnapshot) -> String {
    match finding.rule_id.as_str() {
        "EW-FS-001" => format!(
            "process {} accessed credential path {}",
            finding.process, finding.subject
        ),
        "EW-FS-002" => format!(
            "process {} accessed private configuration path {}",
            finding.process, finding.subject
        ),
        "EW-ENV-001" => format!(
            "process {} read credential environment name {}",
            finding.process, finding.subject
        ),
        "EW-NET-001" => format!(
            "process {} opened public listener {}",
            finding.process, finding.subject
        ),
        _ => format!(
            "process {} matched rule {} for {}",
            finding.process, finding.rule_id, finding.subject
        ),
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
    use std::fs;
    use std::io::{Seek, Write};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use crate::behavior::{
        BehaviorCategory, BehaviorFact, BehaviorKey, BehaviorSet, BehaviorValue,
    };
    use crate::findings::Severity;
    use crate::privacy::CURRENT_PRIVACY_PROFILE;
    use crate::session::SessionMode;
    use crate::storage::{SessionOutcome, SessionStore};

    use super::{
        compare, write_json, ChangeStatus, CompatibilityIssue, CoverageSnapshot, DiffError,
        FindingSnapshot, SessionInfo, SessionSnapshot,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            Self(std::env::temp_dir().join(format!("execwake-diff-{}-{nonce}", std::process::id())))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn loads_instrumented_sessions_without_mixing_enrichment_with_kernel_behavior() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin_in_mode("node", 0, SessionMode::Instrumented)
            .expect("an instrumented session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the instrumented session should finalize");

        let snapshot = SessionSnapshot::load(session.database())
            .expect("the instrumented session should load");

        assert!(snapshot.behavior.facts.is_empty());
        assert_eq!(snapshot.coverage.len(), BehaviorCategory::ALL.len());
    }

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
                requested_backend: Some("auto".to_owned()),
                backend: Some(backend.to_owned()),
                fallback_reason: None,
                privacy_profile: Some(CURRENT_PRIVACY_PROFILE.to_owned()),
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

    fn finding(rule_version: u32, severity: Severity) -> FindingSnapshot {
        FindingSnapshot {
            finding_id: i64::from(rule_version),
            rule_id: "EW-FS-001".to_owned(),
            rule_version,
            severity,
            process: "root/npm".to_owned(),
            subject: "$HOME/.ssh/id_ed25519".to_owned(),
            evidence_event_ids: vec![1],
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

    #[test]
    fn rejects_invalid_persisted_identity_and_coverage() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let invalid_id = store
            .begin("npm", 0)
            .expect("the first session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the first session should finalize");
        let connection =
            Connection::open(invalid_id.database()).expect("the first session should open");
        connection
            .execute("UPDATE session SET id = 'not-a-session-id'", [])
            .expect("the session id should be changed");
        drop(connection);

        assert!(matches!(
            SessionSnapshot::load(invalid_id.database()),
            Err(DiffError::InvalidSession(_))
        ));

        let invalid_coverage = store
            .begin("npm", 0)
            .expect("the second session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the second session should finalize");
        let connection =
            Connection::open(invalid_coverage.database()).expect("the second session should open");
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE coverage
                 SET state = 'complete', lost_events = 2
                 WHERE category = 'filesystem';",
            )
            .expect("the coverage should be changed");
        drop(connection);

        assert!(matches!(
            SessionSnapshot::load(invalid_coverage.database()),
            Err(DiffError::InvalidSession(_))
        ));

        let negative_loss = store
            .begin("npm", 0)
            .expect("the third session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the third session should finalize");
        let connection =
            Connection::open(negative_loss.database()).expect("the third session should open");
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE coverage
                 SET state = 'partial', lost_events = -1
                 WHERE category = 'filesystem';",
            )
            .expect("the lost event count should be changed");
        drop(connection);

        assert!(matches!(
            SessionSnapshot::load(negative_loss.database()),
            Err(DiffError::InvalidSession(_))
        ));
    }

    #[test]
    fn loads_older_schema_metadata_without_newer_columns() {
        let directory = TestDirectory::new();
        fs::create_dir_all(&directory.0).expect("the test directory should be created");
        let database = directory.0.join("old.sqlite3");
        let connection = Connection::open(&database).expect("the old session should open");
        connection
            .execute_batch(
                "CREATE TABLE session (
                     singleton INTEGER PRIMARY KEY,
                     id TEXT NOT NULL,
                     schema_version INTEGER NOT NULL,
                     mode TEXT NOT NULL,
                     state TEXT NOT NULL,
                     finalized INTEGER NOT NULL,
                     command_name TEXT NOT NULL,
                     runner_pid INTEGER NOT NULL
                 );
                 CREATE TABLE coverage (
                     category TEXT PRIMARY KEY,
                     state TEXT NOT NULL,
                     lost_events INTEGER NOT NULL
                 );
                 INSERT INTO session VALUES (
                     1, '0123456789abcdef0123456789abcdef', 1, 'observe',
                     'finalized', 1, 'npm', 100
                 );
                 INSERT INTO coverage VALUES
                     ('processes', 'partial', 0),
                     ('filesystem', 'unavailable', 0),
                     ('network', 'unavailable', 0),
                     ('environment', 'unavailable', 0);",
            )
            .expect("the old session should be created");
        drop(connection);

        let snapshot =
            SessionSnapshot::load(&database).expect("the old metadata should remain readable");

        assert_eq!(snapshot.info.schema_version, 1);
        assert_eq!(snapshot.info.backend, None);
        assert_eq!(snapshot.info.privacy_profile, None);
        assert!(snapshot.behavior.facts.is_empty());
        assert!(snapshot.findings.is_empty());

        let diff = compare(snapshot.clone(), snapshot);
        assert!(diff.compatibility.iter().all(|entry| {
            !entry.comparable
                && entry
                    .issues
                    .contains(&CompatibilityIssue::UnsupportedSchema)
        }));
    }

    #[test]
    fn loads_release_candidate_behavior_without_modifying_the_session() {
        use crate::session_input::test_support::rewrite_as_release_schema;

        for version in [9, 10] {
            let directory = TestDirectory::new();
            let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
            let session = store
                .begin("fixture", 0)
                .expect("a session should start")
                .finalize(SessionOutcome::exited(0))
                .expect("the session should finalize");
            rewrite_as_release_schema(session.database(), session.id().as_str(), version);
            let before = fs::read(session.database()).expect("the fixture should be readable");

            let snapshot = SessionSnapshot::load(session.database())
                .expect("the release candidate session should load");
            assert_eq!(snapshot.info.schema_version, version);
            assert_eq!(snapshot.info.backend.as_deref(), Some("ptrace"));
            assert!(!snapshot.behavior.facts.is_empty());
            let comparison = compare(snapshot.clone(), snapshot);
            assert!(comparison.compatibility.iter().all(|entry| !entry
                .issues
                .contains(&CompatibilityIssue::UnsupportedSchema)));

            let after = fs::read(session.database()).expect("the fixture should remain readable");
            assert_eq!(after, before);
        }
    }

    #[test]
    fn rejects_corrupt_and_future_session_inputs() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let future = store
            .begin("npm", 0)
            .expect("the future session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the future session should finalize");
        let connection = Connection::open(future.database()).expect("the session should open");
        connection
            .execute(
                "UPDATE session SET schema_version = ?1 WHERE singleton = 1",
                [i64::from(crate::session::CURRENT_SCHEMA_VERSION) + 1],
            )
            .expect("the schema version should be changed");
        drop(connection);

        assert!(matches!(
            SessionSnapshot::load(future.database()),
            Err(DiffError::InvalidSession(_))
        ));

        let corrupt = store
            .begin("npm", 0)
            .expect("the corrupt session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the corrupt session should finalize");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(corrupt.database())
            .expect("the session file should open");
        file.rewind()
            .expect("the session header should be selected");
        file.write_all(b"Not SQLite data")
            .expect("the session header should be corrupted");
        drop(file);

        assert!(SessionSnapshot::load(corrupt.database()).is_err());
    }

    #[test]
    fn rejects_an_unknown_privacy_profile_for_comparison() {
        let coverage = CoverageSnapshot {
            state: "complete".to_owned(),
            lost_events: 0,
        };
        let mut before = snapshot("ptrace", coverage.clone(), Vec::new());
        before.info.privacy_profile = Some("paths-future".to_owned());
        let mut after = snapshot("ptrace", coverage, Vec::new());
        after.info.privacy_profile = Some("paths-future".to_owned());

        let diff = compare(before, after);

        assert!(diff.compatibility.iter().all(|entry| {
            !entry.comparable
                && entry
                    .issues
                    .contains(&CompatibilityIssue::UnsupportedPrivacyProfile)
        }));
    }

    #[test]
    fn privacy_profile_changes_make_categories_incomparable() {
        let coverage = CoverageSnapshot {
            state: "complete".to_owned(),
            lost_events: 0,
        };
        let mut before = snapshot(
            "ptrace",
            coverage.clone(),
            vec![fact("$WORKSPACE/only-before", &["read"], 1)],
        );
        before.info.privacy_profile = Some("paths-v1".to_owned());
        let after = snapshot("ptrace", coverage, Vec::new());

        let diff = compare(before, after);

        assert!(diff.behavior.is_empty());
        assert!(diff.compatibility.iter().all(|entry| {
            !entry.comparable
                && entry
                    .issues
                    .contains(&CompatibilityIssue::PrivacyProfileMismatch)
        }));
    }

    #[test]
    fn summarizes_finding_changes_with_fixed_deterministic_templates() {
        let coverage = CoverageSnapshot {
            state: "partial".to_owned(),
            lost_events: 0,
        };
        let mut before = snapshot("ptrace", coverage.clone(), Vec::new());
        before.findings = vec![finding(1, Severity::Medium)];
        let mut after = snapshot("ptrace", coverage, Vec::new());
        after.findings = vec![finding(2, Severity::High)];

        let first = compare(before.clone(), after.clone());
        let second = compare(before, after);

        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].status, ChangeStatus::Changed);
        assert_eq!(
            first.what_changed,
            ["Changed finding EW-FS-001 from rule version 1 medium to version 2 high: process root/npm accessed credential path $HOME/.ssh/id_ed25519."]
        );
        assert_eq!(
            serde_json::to_vec(&first.what_changed).expect("summary should serialize"),
            serde_json::to_vec(&second.what_changed).expect("summary should serialize")
        );
    }

    #[test]
    fn writes_deterministic_machine_readable_output() {
        let coverage = CoverageSnapshot {
            state: "complete".to_owned(),
            lost_events: 0,
        };
        let before = snapshot("ptrace", coverage.clone(), Vec::new());
        let after = snapshot(
            "ptrace",
            coverage,
            vec![fact("$WORKSPACE/new", &["read"], 8)],
        );
        let diff = compare(before, after);
        let mut first = Vec::new();
        let mut second = Vec::new();

        write_json(&diff, &mut first).expect("the diff should serialize");
        write_json(&diff, &mut second).expect("the diff should serialize again");

        assert_eq!(first, second);
        assert_eq!(first.last(), Some(&b'\n'));
        assert!(!first.contains(&b'\r'));
        let parsed: serde_json::Value =
            serde_json::from_slice(&first).expect("the diff should be valid JSON");
        assert_eq!(parsed["behavior"][0]["status"], "NEW");
    }

    #[test]
    fn uses_a_neutral_summary_when_findings_do_not_change() {
        let coverage = CoverageSnapshot {
            state: "partial".to_owned(),
            lost_events: 0,
        };
        let before = snapshot("ptrace", coverage.clone(), Vec::new());
        let after = snapshot("ptrace", coverage, Vec::new());

        let diff = compare(before, after);

        assert_eq!(diff.what_changed, ["No comparable finding changes."]);
    }
}
