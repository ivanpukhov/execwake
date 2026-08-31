pub(crate) const REPORT_REQUEST_BYTES: usize = 16 * 1024;
pub(crate) const SQLITE_CACHE_KIB: i64 = 16 * 1024;

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
