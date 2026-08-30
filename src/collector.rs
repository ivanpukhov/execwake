use std::io;
use std::process::{Child, Command, ExitStatus};

use crate::session::{EvidenceKind, SessionCoverage};

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
    pub parent: Option<ProcessIdentity>,
    pub executable: String,
    pub occurred_at_ms: i64,
    pub evidence: EvidenceKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessExitRecord {
    pub identity: ProcessIdentity,
    pub occurred_at_ms: i64,
    pub exit_code: Option<i32>,
    pub termination_signal: Option<i32>,
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
    fn record_process_exit(&mut self, process: ProcessExitRecord) -> Result<(), SinkError>;
    fn record_event(&mut self, event: CollectorEvent) -> Result<(), SinkError>;
    fn set_coverage(&mut self, coverage: SessionCoverage) -> Result<(), SinkError>;
}

pub trait Collector {
    fn backend_name(&self) -> &'static str;
    fn prepare(&mut self, command: &mut Command) -> io::Result<()>;
    fn collect(&mut self, child: Child, sink: &mut dyn CollectorSink) -> io::Result<ExitStatus>;
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
