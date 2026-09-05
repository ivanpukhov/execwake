use crate::privacy::is_valid_environment_name;

pub const CURRENT_SCHEMA_VERSION: u32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorRequest {
    Auto,
    Ebpf,
    Ptrace,
}

impl CollectorRequest {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ebpf => "ebpf",
            Self::Ptrace => "ptrace",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "ebpf" => Some(Self::Ebpf),
            "ptrace" => Some(Self::Ptrace),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorBackend {
    Ebpf,
    Ptrace,
}

impl CollectorBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ebpf => "ebpf",
            Self::Ptrace => "ptrace",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ebpf" => Some(Self::Ebpf),
            "ptrace" => Some(Self::Ptrace),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorFallbackReason {
    CgroupUnavailable,
    PermissionDenied,
    PlatformIncompatible,
    InitializationFailed,
}

impl CollectorFallbackReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupUnavailable => "cgroup_unavailable",
            Self::PermissionDenied => "permission_denied",
            Self::PlatformIncompatible => "platform_incompatible",
            Self::InitializationFailed => "initialization_failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "cgroup_unavailable" => Some(Self::CgroupUnavailable),
            "permission_denied" => Some(Self::PermissionDenied),
            "platform_incompatible" => Some(Self::PlatformIncompatible),
            "initialization_failed" => Some(Self::InitializationFailed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorDecision {
    pub requested: CollectorRequest,
    pub backend: CollectorBackend,
    pub fallback_reason: Option<CollectorFallbackReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMode {
    Observe,
    Instrumented,
}

impl SessionMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Instrumented => "instrumented",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "observe" => Some(Self::Observe),
            "instrumented" => Some(Self::Instrumented),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceKind {
    Observed,
    Inferred,
    Derived,
}

impl EvidenceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Inferred => "inferred",
            Self::Derived => "derived",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "observed" => Some(Self::Observed),
            "inferred" => Some(Self::Inferred),
            "derived" => Some(Self::Derived),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentRead {
    name: String,
    evidence: EvidenceKind,
}

impl EnvironmentRead {
    pub fn new(name: &str, evidence: EvidenceKind) -> Option<Self> {
        is_valid_environment_name(name).then(|| Self {
            name: name.to_owned(),
            evidence,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn evidence(&self) -> EvidenceKind {
        self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageState {
    Complete,
    Partial,
    Unavailable,
}

impl CoverageState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CategoryCoverage {
    state: CoverageState,
    lost_events: u64,
}

impl CategoryCoverage {
    pub const fn complete() -> Self {
        Self {
            state: CoverageState::Complete,
            lost_events: 0,
        }
    }

    pub const fn partial(lost_events: u64) -> Self {
        Self {
            state: CoverageState::Partial,
            lost_events,
        }
    }

    pub const fn unavailable() -> Self {
        Self {
            state: CoverageState::Unavailable,
            lost_events: 0,
        }
    }

    pub const fn state(self) -> CoverageState {
        self.state
    }

    pub const fn lost_events(self) -> u64 {
        self.lost_events
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCoverage {
    pub processes: CategoryCoverage,
    pub filesystem: CategoryCoverage,
    pub network: CategoryCoverage,
    pub environment: CategoryCoverage,
}

impl SessionCoverage {
    pub const fn unavailable() -> Self {
        Self {
            processes: CategoryCoverage::unavailable(),
            filesystem: CategoryCoverage::unavailable(),
            network: CategoryCoverage::unavailable(),
            environment: CategoryCoverage::unavailable(),
        }
    }

    pub const fn has_event_loss(self) -> bool {
        self.processes.lost_events() > 0
            || self.filesystem.lost_events() > 0
            || self.network.lost_events() > 0
            || self.environment.lost_events() > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionManifest {
    pub schema_version: u32,
    pub mode: SessionMode,
    pub collector: Option<CollectorDecision>,
    pub coverage: SessionCoverage,
}

impl SessionManifest {
    pub const fn new(coverage: SessionCoverage) -> Self {
        Self::with_mode(SessionMode::Observe, coverage)
    }

    pub const fn with_mode(mode: SessionMode, coverage: SessionCoverage) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            mode,
            collector: None,
            coverage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CategoryCoverage, CollectorBackend, CollectorFallbackReason, CollectorRequest,
        CoverageState, EnvironmentRead, EvidenceKind, SessionCoverage, SessionManifest,
        SessionMode, CURRENT_SCHEMA_VERSION,
    };

    #[test]
    fn environment_reads_store_only_valid_names() {
        let read = EnvironmentRead::new("GITHUB_TOKEN", EvidenceKind::Observed)
            .expect("a variable name should be accepted");

        assert_eq!(read.name(), "GITHUB_TOKEN");
        assert_eq!(read.evidence(), EvidenceKind::Observed);
        assert!(EnvironmentRead::new("GITHUB_TOKEN=secret", EvidenceKind::Observed).is_none());
    }

    #[test]
    fn new_sessions_are_explicitly_observe_only() {
        let manifest = SessionManifest::new(SessionCoverage::unavailable());

        assert_eq!(manifest.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(manifest.mode, SessionMode::Observe);
    }

    #[test]
    fn collector_decision_values_have_stable_storage_names() {
        assert_eq!(
            CollectorRequest::parse("auto"),
            Some(CollectorRequest::Auto)
        );
        assert_eq!(
            CollectorBackend::parse("ebpf"),
            Some(CollectorBackend::Ebpf)
        );
        assert_eq!(
            CollectorFallbackReason::parse("permission_denied"),
            Some(CollectorFallbackReason::PermissionDenied)
        );
        assert_eq!(CollectorRequest::parse("automatic"), None);
        assert_eq!(CollectorBackend::parse("strace"), None);
        assert_eq!(CollectorFallbackReason::parse("unknown error"), None);
    }

    #[test]
    fn instrumented_sessions_are_explicit_in_the_manifest() {
        let manifest =
            SessionManifest::with_mode(SessionMode::Instrumented, SessionCoverage::unavailable());

        assert_eq!(manifest.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(manifest.mode, SessionMode::Instrumented);
        assert_eq!(manifest.mode.as_str(), "instrumented");
        assert_eq!(SessionMode::parse("instrumented"), Some(manifest.mode));
    }

    #[test]
    fn unavailable_coverage_does_not_claim_event_loss() {
        let coverage = SessionCoverage::unavailable();

        assert_eq!(coverage.processes.state(), CoverageState::Unavailable);
        assert!(!coverage.has_event_loss());
    }

    #[test]
    fn lost_events_require_partial_coverage() {
        let coverage = CategoryCoverage::partial(3);

        assert_eq!(coverage.state(), CoverageState::Partial);
        assert_eq!(coverage.lost_events(), 3);
    }

    #[test]
    fn complete_coverage_cannot_include_lost_events() {
        let coverage = CategoryCoverage::complete();

        assert_eq!(coverage.state(), CoverageState::Complete);
        assert_eq!(coverage.lost_events(), 0);
    }
}
