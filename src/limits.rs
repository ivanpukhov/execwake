pub(crate) const REPORT_REQUEST_BYTES: usize = 16 * 1024;
pub(crate) const SQLITE_CACHE_KIB: i64 = 16 * 1024;
pub(crate) const MAX_SESSION_INPUT_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_SQLITE_VALUE_BYTES: i32 = 1024 * 1024;
pub(crate) const MAX_IMPORTED_EVENTS: usize = 1_000_000;
pub(crate) const MAX_IMPORTED_PROCESSES: usize = 100_000;
pub(crate) const MAX_IMPORTED_FINDINGS: usize = 100_000;
pub(crate) const MAX_DISPLAY_TEXT_BYTES: usize = 16 * 1024;
pub(crate) const REPORT_EVENT_PAGE_SIZE: usize = 500;
pub(crate) const REPORT_TIMELINE_EVENT_LIMIT: usize = 5_000;
pub(crate) const REPORT_PROCESS_LIMIT: usize = 2_048;
pub(crate) const REPORT_FINDING_LIMIT: usize = 1_024;
pub(crate) const REPORT_FINDING_EVIDENCE_LIMIT: usize = 128;

#[cfg(target_os = "linux")]
pub(crate) const MAX_LIVE_PROCESSES: usize = 1_024;
#[cfg(target_os = "linux")]
pub(crate) const MAX_FILE_SNAPSHOTS: usize = 100_000;
#[cfg(target_os = "linux")]
pub(crate) const MAX_SOCKETS_PER_PROCESS: usize = 512;
#[cfg(target_os = "linux")]
pub(crate) const MAX_DNS_QUERIES_PER_SOCKET: usize = 256;
#[cfg(target_os = "linux")]
pub(crate) const EBPF_BUFFER_PAGES: usize = 8;
#[cfg(target_os = "linux")]
pub(crate) const EBPF_READ_BATCH: usize = 64;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CaptureLimits {
    pub event_count: u64,
    pub session_bytes: u64,
    pub finalization_bytes: u64,
    pub text_bytes: usize,
}

impl CaptureLimits {
    pub const DEFAULT: Self = Self {
        event_count: 250_000,
        session_bytes: 256 * 1024 * 1024,
        finalization_bytes: 4 * 1024 * 1024,
        text_bytes: 32 * 1024,
    };
}

#[cfg(test)]
mod tests {
    use super::CaptureLimits;

    #[test]
    fn finalization_reserve_fits_inside_the_session_limit() {
        assert!(CaptureLimits::DEFAULT.finalization_bytes < CaptureLimits::DEFAULT.session_bytes);
    }
}
