use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::privacy::is_valid_environment_name;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BehaviorCategory {
    Filesystem,
    Network,
    Process,
    Environment,
}

impl BehaviorCategory {
    pub const ALL: [Self; 4] = [
        Self::Filesystem,
        Self::Network,
        Self::Process,
        Self::Environment,
    ];

    pub const fn coverage_name(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Process => "processes",
            Self::Environment => "environment",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "category", rename_all = "lowercase")]
pub enum BehaviorKey {
    Filesystem {
        path: String,
        process: Option<String>,
    },
    Network {
        endpoint: String,
        process: Option<String>,
    },
    Process {
        role: String,
    },
    Environment {
        name: String,
        process: Option<String>,
    },
}

impl BehaviorKey {
    pub const fn category(&self) -> BehaviorCategory {
        match self {
            Self::Filesystem { .. } => BehaviorCategory::Filesystem,
            Self::Network { .. } => BehaviorCategory::Network,
            Self::Process { .. } => BehaviorCategory::Process,
            Self::Environment { .. } => BehaviorCategory::Environment,
        }
    }

    pub fn subject(&self) -> &str {
        match self {
            Self::Filesystem { path, .. } => path,
            Self::Network { endpoint, .. } => endpoint,
            Self::Process { role } => role,
            Self::Environment { name, .. } => name,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorValue {
    pub operations: Vec<String>,
    pub evidence: Vec<String>,
    pub attributes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorFact {
    pub key: BehaviorKey,
    pub value: BehaviorValue,
    pub evidence_event_ids: Vec<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BehaviorProcess {
    pub process_id: i64,
    pub operating_system_id: i64,
    pub parent_process_id: Option<i64>,
    pub executable: String,
    pub exit_code: Option<i64>,
    pub termination_signal: Option<i64>,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BehaviorEvent {
    pub event_id: i64,
    pub category: String,
    pub operation: String,
    pub target: String,
    pub process_id: Option<i64>,
    pub evidence: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BehaviorSet {
    pub facts: Vec<BehaviorFact>,
    pub process_roles: BTreeMap<i64, String>,
}

#[derive(Default)]
struct FactAccumulator {
    operations: BTreeSet<String>,
    evidence: BTreeSet<String>,
    attributes: BTreeSet<String>,
    evidence_event_ids: BTreeSet<i64>,
}

impl BehaviorSet {
    pub fn build(
        session_id: &str,
        runner_pid: i64,
        processes: &[BehaviorProcess],
        events: &[BehaviorEvent],
    ) -> Self {
        let normalizer = BehaviorNormalizer::new(session_id, runner_pid, processes);
        let process_roles = build_process_roles(processes, &normalizer);
        let mut facts: BTreeMap<BehaviorKey, FactAccumulator> = BTreeMap::new();

        for process in processes {
            let Some(role) = process_roles.get(&process.process_id) else {
                continue;
            };
            let fact = facts
                .entry(BehaviorKey::Process { role: role.clone() })
                .or_default();
            fact.operations.insert("spawn".to_owned());
            fact.evidence.insert(process.evidence.clone());
            fact.attributes.insert(format!(
                "executable:{}",
                normalizer.executable(&process.executable)
            ));
            if let Some(exit_code) = process.exit_code {
                fact.attributes.insert(format!("exit:{exit_code}"));
            }
            if let Some(signal) = process.termination_signal {
                fact.attributes.insert(format!("signal:{signal}"));
            }
        }

        for event in events {
            let process = event
                .process_id
                .and_then(|process_id| process_roles.get(&process_id).cloned());
            let key = match event.category.as_str() {
                "filesystem" => BehaviorKey::Filesystem {
                    path: normalizer.text(&event.target),
                    process,
                },
                "network" => BehaviorKey::Network {
                    endpoint: normalizer.network(&event.operation, &event.target),
                    process,
                },
                "environment" if is_valid_environment_name(&event.target) => {
                    BehaviorKey::Environment {
                        name: event.target.clone(),
                        process,
                    }
                }
                "process" => {
                    let Some(role) = process else {
                        continue;
                    };
                    let fact = facts.entry(BehaviorKey::Process { role }).or_default();
                    fact.operations.insert(event.operation.clone());
                    fact.evidence.insert(event.evidence.clone());
                    fact.attributes
                        .insert(format!("target:{}", normalizer.executable(&event.target)));
                    if event.event_id > 0 {
                        fact.evidence_event_ids.insert(event.event_id);
                    }
                    continue;
                }
                _ => continue,
            };

            let fact = facts.entry(key).or_default();
            fact.operations.insert(event.operation.clone());
            fact.evidence.insert(event.evidence.clone());
            if event.event_id > 0 {
                fact.evidence_event_ids.insert(event.event_id);
            }
        }

        Self {
            facts: facts
                .into_iter()
                .map(|(key, fact)| BehaviorFact {
                    key,
                    value: BehaviorValue {
                        operations: fact.operations.into_iter().collect(),
                        evidence: fact.evidence.into_iter().collect(),
                        attributes: fact.attributes.into_iter().collect(),
                    },
                    evidence_event_ids: fact.evidence_event_ids.into_iter().collect(),
                })
                .collect(),
            process_roles,
        }
    }
}

struct BehaviorNormalizer {
    session_id: String,
    process_ids: BTreeSet<String>,
}

impl BehaviorNormalizer {
    fn new(session_id: &str, runner_pid: i64, processes: &[BehaviorProcess]) -> Self {
        let mut process_ids = BTreeSet::new();
        if runner_pid >= 0 {
            process_ids.insert(runner_pid.to_string());
        }
        for process in processes {
            if process.operating_system_id >= 0 {
                process_ids.insert(process.operating_system_id.to_string());
            }
        }
        Self {
            session_id: session_id.to_owned(),
            process_ids,
        }
    }

    fn executable(&self, executable: &str) -> String {
        let normalized = self.text(executable);
        normalized
            .rsplit(['/', '\\'])
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or(&normalized)
            .to_owned()
    }

    fn network(&self, operation: &str, target: &str) -> String {
        let normalized = self.text(target);
        let Some((transport, endpoint)) = normalized.split_once(' ') else {
            return normalized;
        };
        let Some((host, port)) = endpoint.rsplit_once(':') else {
            return normalized;
        };
        let host = host.trim_matches(|character| character == '[' || character == ']');
        let loopback_or_wildcard = matches!(host, "127.0.0.1" | "::1" | "0.0.0.0" | "::");
        let ephemeral = port.parse::<u16>().map_or(false, |port| port >= 32_768);
        if loopback_or_wildcard
            && ephemeral
            && matches!(
                operation,
                "bind" | "connect" | "listen" | "receive" | "send"
            )
        {
            if host.contains(':') {
                format!("{transport} [{host}]:$EPHEMERAL")
            } else {
                format!("{transport} {host}:$EPHEMERAL")
            }
        } else {
            normalized
        }
    }

    fn text(&self, value: &str) -> String {
        let session_normalized = if self.session_id.is_empty() {
            value.to_owned()
        } else {
            value.replace(&self.session_id, "$SESSION")
        };
        replace_numeric_tokens(&session_normalized, &self.process_ids)
    }
}

fn replace_numeric_tokens(value: &str, replacements: &BTreeSet<String>) -> String {
    let mut output = String::with_capacity(value.len());
    let mut start = 0;
    let mut digits = None;

    for (index, character) in value.char_indices() {
        if character.is_ascii_digit() {
            digits.get_or_insert(index);
        } else if let Some(digit_start) = digits.take() {
            output.push_str(&value[start..digit_start]);
            let token = &value[digit_start..index];
            if replacements.contains(token) {
                output.push_str("$PID");
            } else {
                output.push_str(token);
            }
            start = index;
        }
    }

    if let Some(digit_start) = digits {
        output.push_str(&value[start..digit_start]);
        let token = &value[digit_start..];
        if replacements.contains(token) {
            output.push_str("$PID");
        } else {
            output.push_str(token);
        }
    } else {
        output.push_str(&value[start..]);
    }
    output
}

fn build_process_roles(
    processes: &[BehaviorProcess],
    normalizer: &BehaviorNormalizer,
) -> BTreeMap<i64, String> {
    let details: BTreeMap<_, _> = processes
        .iter()
        .map(|process| {
            (
                process.process_id,
                (
                    process.parent_process_id,
                    normalizer.executable(&process.executable),
                ),
            )
        })
        .collect();
    let mut roles = BTreeMap::new();
    let mut unresolved: BTreeSet<_> = details.keys().copied().collect();

    loop {
        let mut progress = false;
        let pending: Vec<_> = unresolved.iter().copied().collect();
        for process_id in pending {
            let (parent, executable) = &details[&process_id];
            let role = match parent {
                None => Some(format!("root/{executable}")),
                Some(parent) if !details.contains_key(parent) => Some(format!("root/{executable}")),
                Some(parent) => roles
                    .get(parent)
                    .map(|parent_role| format!("{parent_role}/{executable}")),
            };
            if let Some(role) = role {
                roles.insert(process_id, role);
                unresolved.remove(&process_id);
                progress = true;
            }
        }
        if unresolved.is_empty() || !progress {
            break;
        }
    }

    for process_id in unresolved {
        let executable = &details[&process_id].1;
        roles.insert(process_id, format!("orphan/{executable}"));
    }
    roles
}

#[cfg(test)]
mod tests {
    use super::{BehaviorEvent, BehaviorKey, BehaviorProcess, BehaviorSet};

    fn process(
        process_id: i64,
        operating_system_id: i64,
        parent_process_id: Option<i64>,
        executable: &str,
    ) -> BehaviorProcess {
        BehaviorProcess {
            process_id,
            operating_system_id,
            parent_process_id,
            executable: executable.to_owned(),
            exit_code: Some(0),
            termination_signal: None,
            evidence: "observed".to_owned(),
        }
    }

    fn event(
        event_id: i64,
        category: &str,
        operation: &str,
        target: &str,
        process_id: i64,
    ) -> BehaviorEvent {
        BehaviorEvent {
            event_id,
            category: category.to_owned(),
            operation: operation.to_owned(),
            target: target.to_owned(),
            process_id: Some(process_id),
            evidence: "observed".to_owned(),
        }
    }

    #[test]
    fn normalizes_process_identity_session_ids_and_ephemeral_ports() {
        let session_id = "0123456789abcdef0123456789abcdef";
        let set = BehaviorSet::build(
            session_id,
            700,
            &[
                process(10, 7_001, None, "/usr/bin/node"),
                process(11, 7_002, Some(10), "/workspace/node_modules/.bin/npm"),
            ],
            &[
                event(
                    1,
                    "filesystem",
                    "write",
                    &format!("$TMP/npm-7001/{session_id}"),
                    11,
                ),
                event(2, "network", "connect", "tcp 127.0.0.1:53001", 11),
            ],
        );

        assert_eq!(set.process_roles[&10], "root/node");
        assert_eq!(set.process_roles[&11], "root/node/npm");
        assert!(set.facts.iter().any(|fact| {
            matches!(
                &fact.key,
                BehaviorKey::Filesystem { path, process }
                    if path == "$TMP/npm-$PID/$SESSION"
                        && process.as_deref() == Some("root/node/npm")
            )
        }));
        assert!(set.facts.iter().any(|fact| {
            matches!(
                &fact.key,
                BehaviorKey::Network { endpoint, .. }
                    if endpoint == "tcp 127.0.0.1:$EPHEMERAL"
            )
        }));
    }

    #[test]
    fn merges_repeated_process_roles_without_operating_system_ids() {
        let set = BehaviorSet::build(
            "session",
            1,
            &[
                process(10, 101, None, "/usr/bin/node"),
                process(11, 102, Some(10), "/usr/bin/git"),
                process(12, 103, Some(10), "/usr/bin/git"),
            ],
            &[
                event(1, "process", "exec", "/usr/bin/git", 11),
                event(2, "process", "exec", "/usr/bin/git", 12),
            ],
        );

        let git_facts: Vec<_> = set
            .facts
            .iter()
            .filter(|fact| fact.key.subject() == "root/node/git")
            .collect();
        assert_eq!(git_facts.len(), 1);
        assert_eq!(git_facts[0].evidence_event_ids, [1, 2]);
    }

    #[test]
    fn rejects_environment_targets_that_could_contain_values() {
        let set = BehaviorSet::build(
            "session",
            1,
            &[process(10, 101, None, "node")],
            &[event(1, "environment", "read", "GITHUB_TOKEN=value", 10)],
        );

        assert!(!set
            .facts
            .iter()
            .any(|fact| matches!(fact.key, BehaviorKey::Environment { .. })));
    }
}
