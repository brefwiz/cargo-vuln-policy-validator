use crate::domain::models::Violation;

pub trait Reporter {
    fn report(&self, violations: &[Violation]);

    /// Non-blocking notices: e.g. an exception whose review_by has passed
    /// but whose advisory isn't present in this consumer's Cargo.lock.
    /// Default is a no-op so existing reporters keep compiling.
    fn report_notices(&self, _notices: &[Violation]) {}
}

/// Determines which RUSTSEC ids actually affect *this* consumer, by
/// checking its own Cargo.lock — as opposed to `toml_ignores`, which mirror
/// the shared/central audit.toml and deny.toml ignore lists and read the
/// same for every consumer.
pub trait AdvisoryLockCheck {
    fn affected_ids(
        &self,
        lockfile_path: &str,
    ) -> anyhow::Result<std::collections::HashSet<String>>;
}
