use crate::privacy::is_valid_environment_name;

pub const CURRENT_SCHEMA_VERSION: u32 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMode {
    Observe,
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
    pub coverage: SessionCoverage,
}

impl SessionManifest {
    pub const fn new(coverage: SessionCoverage) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            mode: SessionMode::Observe,
            coverage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CategoryCoverage, CoverageState, EnvironmentRead, EvidenceKind, SessionCoverage,
        SessionManifest, SessionMode, CURRENT_SCHEMA_VERSION,
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
