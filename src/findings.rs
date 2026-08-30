use std::collections::BTreeMap;

use crate::collector::ProcessIdentity;
use crate::privacy::is_valid_environment_name;
use crate::session::EvidenceKind;

const CREDENTIAL_PATH_RULE: &str = "EW-FS-001";
const PRIVATE_CONFIG_RULE: &str = "EW-FS-002";
const CREDENTIAL_ENV_RULE: &str = "EW-ENV-001";
const PUBLIC_LISTENER_RULE: &str = "EW-NET-001";
const RULE_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceReference {
    Event(i64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub rule_id: String,
    pub rule_version: u32,
    pub severity: Severity,
    pub process: ProcessIdentity,
    pub subject: String,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingEvent {
    pub event_id: i64,
    pub category: String,
    pub operation: String,
    pub target: String,
    pub process: Option<ProcessIdentity>,
    pub evidence: EvidenceKind,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindingKey {
    rule_id: &'static str,
    rule_version: u32,
    severity: Severity,
    process: ProcessIdentity,
    subject: String,
}

pub fn evaluate(events: impl IntoIterator<Item = FindingEvent>) -> Vec<Finding> {
    let mut matches: BTreeMap<FindingKey, Vec<EvidenceReference>> = BTreeMap::new();

    for event in events {
        if event.event_id <= 0 || event.evidence != EvidenceKind::Observed {
            continue;
        }
        let Some(process) = event.process else {
            continue;
        };

        if event.category == "filesystem" {
            for path in event.target.split(" → ") {
                if let Some((rule_id, severity)) = sensitive_path_rule(path) {
                    record_match(
                        &mut matches,
                        rule_id,
                        severity,
                        process,
                        path,
                        event.event_id,
                    );
                }
            }
        } else if event.category == "environment"
            && event.operation == "read"
            && sensitive_environment_name(&event.target)
        {
            record_match(
                &mut matches,
                CREDENTIAL_ENV_RULE,
                Severity::High,
                process,
                &event.target,
                event.event_id,
            );
        } else if event.category == "network"
            && event.operation == "listen"
            && public_listener(&event.target)
        {
            record_match(
                &mut matches,
                PUBLIC_LISTENER_RULE,
                Severity::Medium,
                process,
                &event.target,
                event.event_id,
            );
        }
    }

    matches
        .into_iter()
        .map(|(key, mut evidence)| {
            evidence.sort_unstable();
            evidence.dedup();
            Finding {
                rule_id: key.rule_id.to_owned(),
                rule_version: key.rule_version,
                severity: key.severity,
                process: key.process,
                subject: key.subject,
                evidence,
            }
        })
        .collect()
}

fn record_match(
    matches: &mut BTreeMap<FindingKey, Vec<EvidenceReference>>,
    rule_id: &'static str,
    severity: Severity,
    process: ProcessIdentity,
    subject: &str,
    event_id: i64,
) {
    matches
        .entry(FindingKey {
            rule_id,
            rule_version: RULE_VERSION,
            severity,
            process,
            subject: subject.to_owned(),
        })
        .or_default()
        .push(EvidenceReference::Event(event_id));
}

fn sensitive_path_rule(path: &str) -> Option<(&'static str, Severity)> {
    if credential_path(path) {
        Some((CREDENTIAL_PATH_RULE, Severity::High))
    } else if private_configuration_path(path) {
        Some((PRIVATE_CONFIG_RULE, Severity::Medium))
    } else {
        None
    }
}

fn credential_path(path: &str) -> bool {
    matches!(
        path,
        "$HOME/.aws/credentials"
            | "$HOME/.docker/config.json"
            | "$HOME/.kube/config"
            | "$HOME/.netrc"
            | "$HOME/.npmrc"
            | "$HOME/.config/gh/hosts.yml"
            | "$HOME/.config/gcloud/credentials.db"
    ) || path.strip_prefix("$HOME/.ssh/").map_or(false, |name| {
        name.starts_with("id_") && !name.ends_with(".pub")
    })
}

fn private_configuration_path(path: &str) -> bool {
    matches!(
        path,
        "$HOME/.gitconfig"
            | "$HOME/.ssh"
            | "$HOME/.ssh/authorized_keys"
            | "$HOME/.ssh/config"
            | "$HOME/.ssh/known_hosts"
    )
}

fn sensitive_environment_name(name: &str) -> bool {
    if !is_valid_environment_name(name) {
        return false;
    }

    matches!(
        name.to_ascii_uppercase().as_str(),
        "AWS_ACCESS_KEY_ID"
            | "AWS_SECRET_ACCESS_KEY"
            | "AWS_SESSION_TOKEN"
            | "GITHUB_TOKEN"
            | "GITLAB_TOKEN"
            | "GOOGLE_APPLICATION_CREDENTIALS"
            | "NPM_TOKEN"
            | "SSH_AUTH_SOCK"
    )
}

fn public_listener(target: &str) -> bool {
    target
        .split_once(' ')
        .map_or(false, |(transport, endpoint)| {
            transport == "tcp"
                && (endpoint.starts_with("0.0.0.0:") || endpoint.starts_with("[::]:"))
        })
}

#[cfg(test)]
mod tests {
    use crate::collector::ProcessIdentity;
    use crate::session::EvidenceKind;

    use super::{evaluate, EvidenceReference, FindingEvent, Severity};

    fn event(event_id: i64, category: &str, operation: &str, target: &str) -> FindingEvent {
        FindingEvent {
            event_id,
            category: category.to_owned(),
            operation: operation.to_owned(),
            target: target.to_owned(),
            process: Some(ProcessIdentity::new(4)),
            evidence: EvidenceKind::Observed,
        }
    }

    #[test]
    fn groups_sensitive_path_evidence_deterministically() {
        let first = event(8, "filesystem", "read", "$HOME/.ssh/id_ed25519");
        let second = event(3, "filesystem", "open", "$HOME/.ssh/id_ed25519");

        let findings = evaluate([first, second]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "EW-FS-001");
        assert_eq!(findings[0].rule_version, 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].process, ProcessIdentity::new(4));
        assert_eq!(
            findings[0].evidence,
            [EvidenceReference::Event(3), EvidenceReference::Event(8)]
        );
    }

    #[test]
    fn ignores_public_keys_and_inherited_environment_names() {
        let findings = evaluate([
            event(1, "filesystem", "read", "$HOME/.ssh/id_ed25519.pub"),
            event(2, "environment", "inherited", "GITHUB_TOKEN"),
        ]);

        assert!(findings.is_empty());
    }

    #[test]
    fn detects_observed_credential_names_without_values() {
        let findings = evaluate([event(1, "environment", "read", "github_token")]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "EW-ENV-001");
        assert_eq!(findings[0].subject, "github_token");
    }

    #[test]
    fn distinguishes_public_and_loopback_listeners() {
        let findings = evaluate([
            event(1, "network", "listen", "tcp 127.0.0.1:7319"),
            event(2, "network", "listen", "tcp 0.0.0.0:8080"),
        ]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "EW-NET-001");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].subject, "tcp 0.0.0.0:8080");
    }

    #[test]
    fn requires_observed_evidence_and_a_process_identity() {
        let mut inferred = event(1, "filesystem", "read", "$HOME/.npmrc");
        inferred.evidence = EvidenceKind::Inferred;
        let mut detached = event(2, "filesystem", "read", "$HOME/.npmrc");
        detached.process = None;

        assert!(evaluate([inferred, detached]).is_empty());
    }
}
