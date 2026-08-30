use std::io;
use std::process::{Child, Command, ExitStatus};

use crate::session::{EvidenceKind, SessionCoverage};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxCollector;

pub type SinkError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessIdentity(u64);

impl ProcessIdentity {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRecord {
    pub identity: ProcessIdentity,
    pub operating_system_id: u32,
    pub start_time_ticks: Option<u64>,
    pub parent: Option<ProcessIdentity>,
    pub executable: String,
    pub occurred_at_ms: i64,
    pub evidence: EvidenceKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessExecRecord {
    pub identity: ProcessIdentity,
    pub executable: String,
    pub occurred_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessExitRecord {
    pub identity: ProcessIdentity,
    pub occurred_at_ms: i64,
    pub exit_code: Option<i32>,
    pub termination_signal: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileStateKind {
    Absent,
    File,
    Directory,
    Symlink,
    Other,
    Unknown,
}

impl FileStateKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileState {
    pub kind: FileStateKind,
    pub size: Option<u64>,
    pub modified_at_ns: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDeltaRecord {
    pub path: String,
    pub before: FileState,
    pub after: FileState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsConfidence {
    High,
}

impl DnsConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCorrelationRecord {
    pub hostname: String,
    pub address: String,
    pub process: ProcessIdentity,
    pub occurred_at_ms: i64,
    pub evidence: EvidenceKind,
    pub confidence: DnsConfidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentVariableRecord {
    pub name: String,
    pub process: ProcessIdentity,
    pub evidence: EvidenceKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectorEvent {
    pub category: &'static str,
    pub operation: &'static str,
    pub target: String,
    pub process: Option<ProcessIdentity>,
    pub occurred_at_ms: i64,
    pub evidence: EvidenceKind,
}

pub trait CollectorSink {
    fn set_backend(&mut self, backend: &'static str) -> Result<(), SinkError>;
    fn record_process(&mut self, process: ProcessRecord) -> Result<(), SinkError>;
    fn record_process_exec(&mut self, process: ProcessExecRecord) -> Result<(), SinkError>;
    fn record_process_exit(&mut self, process: ProcessExitRecord) -> Result<(), SinkError>;
    fn record_file_delta(&mut self, delta: FileDeltaRecord) -> Result<(), SinkError>;
    fn record_dns_correlation(&mut self, dns: DnsCorrelationRecord) -> Result<(), SinkError>;
    fn record_environment_variable(
        &mut self,
        environment: EnvironmentVariableRecord,
    ) -> Result<(), SinkError>;
    fn record_event(&mut self, event: CollectorEvent) -> Result<(), SinkError>;
    fn set_coverage(&mut self, coverage: SessionCoverage) -> Result<(), SinkError>;
}

pub trait Collector {
    fn backend_name(&self) -> &'static str;
    fn prepare(&mut self, command: &mut Command) -> io::Result<()>;
    fn collect(
        &mut self,
        child: &mut Child,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<ExitStatus>;
}

#[cfg(test)]
mod tests {
    use super::ProcessIdentity;

    #[test]
    fn process_identity_is_session_local() {
        let identity = ProcessIdentity::new(12);

        assert_eq!(identity.get(), 12);
    }
}
