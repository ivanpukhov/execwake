use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::privacy::{is_valid_environment_name, sanitize_http_url};
use crate::storage::{ActiveSession, SessionPaths};

pub(crate) const NODE_ENRICHMENT_EVIDENCE: &str = "observed";
const CONTROL_EVENT_FILE: &str = "EXECWAKE_NODE_EVENT_FILE";
const PRELOAD_SOURCE: &[u8] = include_bytes!("node_enrichment/preload.cjs");
const PROTOCOL_VERSION: u8 = 1;
const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 4 * 1024;
const MAX_CAPTURE_EVENTS: usize = 50_000;
const MAX_METHOD_BYTES: usize = 32;
const MAX_HOST_BYTES: usize = 1_024;
const MAX_PATH_BYTES: usize = 2_048;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NodeEnrichmentRecord {
    pub operating_system_id: u32,
    pub monotonic_ns: u64,
    pub fact: NodeEnrichmentFact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NodeEnrichmentFact {
    Http {
        method: String,
        host: String,
        path: String,
    },
    Environment {
        name: String,
    },
}

pub(crate) struct NodeEnrichmentCapture {
    event_file: File,
    event_path: PathBuf,
    preload_path: PathBuf,
}

impl NodeEnrichmentCapture {
    pub fn install(command: &mut Command, session: &SessionPaths) -> io::Result<Self> {
        let event_path = session.database().with_extension("node-events");
        let preload_path = session.database().with_extension("node-preload.cjs");
        let event_file = create_private_file(&event_path, true)?;
        let preload_result = (|| {
            let mut preload = create_private_file(&preload_path, false)?;
            preload.write_all(PRELOAD_SOURCE)?;
            preload.sync_all()
        })();
        if let Err(error) = preload_result {
            let _ = fs::remove_file(&event_path);
            return Err(error);
        }

        let preload = preload_path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Node preload path is not valid UTF-8",
            )
        })?;
        let node_options = append_node_options(env::var_os("NODE_OPTIONS"), preload)?;
        command
            .env("NODE_OPTIONS", node_options)
            .env(CONTROL_EVENT_FILE, &event_path);

        Ok(Self {
            event_file,
            event_path,
            preload_path,
        })
    }

    pub fn finish(mut self, session: &mut ActiveSession) {
        let (records, mut lost_events) = match self.read_records() {
            Ok(result) => result,
            Err(_) => {
                session.record_node_enrichment_loss(1);
                return;
            }
        };

        for record in records {
            if session.record_node_enrichment(record).is_err() {
                lost_events = lost_events.saturating_add(1);
            }
        }
        session.record_node_enrichment_loss(lost_events);
    }

    fn read_records(&mut self) -> io::Result<(Vec<NodeEnrichmentRecord>, u64)> {
        self.event_file.rewind()?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut self.event_file)
            .take(MAX_CAPTURE_BYTES + 1)
            .read_to_end(&mut bytes)?;

        let mut lost_events = u64::from(bytes.len() as u64 > MAX_CAPTURE_BYTES);
        bytes.truncate(MAX_CAPTURE_BYTES as usize);
        let complete_length = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        if complete_length != bytes.len() {
            lost_events = lost_events.saturating_add(1);
        }

        let mut records = Vec::new();
        for line in bytes[..complete_length].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_LINE_BYTES || records.len() >= MAX_CAPTURE_EVENTS {
                lost_events = lost_events.saturating_add(1);
                continue;
            }
            match serde_json::from_slice::<WireEvent>(line)
                .ok()
                .and_then(WireEvent::into_record)
            {
                Some(record) => records.push(record),
                None => lost_events = lost_events.saturating_add(1),
            }
        }
        Ok((records, lost_events))
    }
}

impl Drop for NodeEnrichmentCapture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.event_path);
        let _ = fs::remove_file(&self.preload_path);
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum WireEvent {
    Http {
        version: u8,
        pid: u32,
        #[serde(rename = "monotonicNs")]
        monotonic_ns: String,
        method: String,
        host: String,
        path: String,
    },
    Environment {
        version: u8,
        pid: u32,
        #[serde(rename = "monotonicNs")]
        monotonic_ns: String,
        name: String,
    },
}

impl WireEvent {
    fn into_record(self) -> Option<NodeEnrichmentRecord> {
        match self {
            Self::Http {
                version,
                pid,
                monotonic_ns,
                method,
                host,
                path,
            } if version == PROTOCOL_VERSION => {
                NodeEnrichmentRecord::http(pid, monotonic_ns.parse().ok()?, &method, &host, &path)
            }
            Self::Environment {
                version,
                pid,
                monotonic_ns,
                name,
            } if version == PROTOCOL_VERSION => {
                NodeEnrichmentRecord::environment(pid, monotonic_ns.parse().ok()?, &name)
            }
            Self::Http { .. } | Self::Environment { .. } => None,
        }
    }
}

fn create_private_file(path: &Path, read: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).append(read).read(read).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn append_node_options(existing: Option<OsString>, preload: &str) -> io::Result<OsString> {
    let existing = existing
        .map(|value| {
            value.into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NODE_OPTIONS is not valid UTF-8",
                )
            })
        })
        .transpose()?
        .unwrap_or_default();
    let escaped = preload.replace('\\', "\\\\").replace('"', "\\\"");
    let separator = if existing.is_empty() { "" } else { " " };
    Ok(format!("{existing}{separator}--require \"{escaped}\"").into())
}

impl NodeEnrichmentRecord {
    pub fn http(
        operating_system_id: u32,
        monotonic_ns: u64,
        method: &str,
        host: &str,
        path: &str,
    ) -> Option<Self> {
        let (method, host, path) = sanitize_http_fact(method, host, path)?;
        Some(Self {
            operating_system_id,
            monotonic_ns,
            fact: NodeEnrichmentFact::Http { method, host, path },
        })
    }

    pub fn environment(operating_system_id: u32, monotonic_ns: u64, name: &str) -> Option<Self> {
        (name.len() <= MAX_ENVIRONMENT_NAME_BYTES && is_valid_environment_name(name)).then(|| {
            Self {
                operating_system_id,
                monotonic_ns,
                fact: NodeEnrichmentFact::Environment {
                    name: name.to_owned(),
                },
            }
        })
    }
}

pub(crate) fn sanitize_http_fact(
    method: &str,
    host: &str,
    path: &str,
) -> Option<(String, String, String)> {
    let method = clean_method(method)?;
    let (host, path) = clean_host_and_path(host, path)?;
    Some((method, host, path))
}

fn clean_method(method: &str) -> Option<String> {
    (!method.is_empty()
        && method.len() <= MAX_METHOD_BYTES
        && method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)))
    .then(|| method.to_ascii_uppercase())
}

fn clean_host_and_path(host: &str, path: &str) -> Option<(String, String)> {
    if host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || host.contains('@')
        || path.len() > MAX_PATH_BYTES
    {
        return None;
    }
    let path = if path.starts_with('/') { path } else { "/" };
    let sanitized = sanitize_http_url(&format!("https://{host}{path}"))?;
    let remainder = sanitized.strip_prefix("https://")?;
    let boundary = remainder.find('/').unwrap_or(remainder.len());
    let clean_host = remainder[..boundary].to_ascii_lowercase();
    let clean_path = remainder.get(boundary..).unwrap_or("/");
    if clean_path.len() > MAX_PATH_BYTES {
        return None;
    }
    Some((clean_host, clean_path.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{NodeEnrichmentFact, NodeEnrichmentRecord, WireEvent};

    #[test]
    fn removes_url_secrets_before_creating_http_evidence() {
        let record = NodeEnrichmentRecord::http(
            7,
            11,
            "get",
            "Example.COM:443",
            "/install?token=secret#fragment",
        )
        .expect("the request should be accepted");

        assert_eq!(
            record.fact,
            NodeEnrichmentFact::Http {
                method: "GET".to_owned(),
                host: "example.com:443".to_owned(),
                path: "/install".to_owned(),
            }
        );
    }

    #[test]
    fn environment_evidence_has_no_value_field() {
        let record = NodeEnrichmentRecord::environment(7, 11, "GITHUB_TOKEN")
            .expect("the name should be accepted");

        assert_eq!(
            record.fact,
            NodeEnrichmentFact::Environment {
                name: "GITHUB_TOKEN".to_owned(),
            }
        );
        assert!(NodeEnrichmentRecord::environment(7, 11, "NAME=value").is_none());
    }

    #[test]
    fn parses_the_bounded_wire_format() {
        let event: WireEvent = serde_json::from_slice(
            br#"{"version":1,"pid":77,"monotonicNs":"101","kind":"environment","name":"HOME"}"#,
        )
        .expect("the wire event should parse");

        assert_eq!(
            event.into_record(),
            NodeEnrichmentRecord::environment(77, 101, "HOME")
        );
    }
}
