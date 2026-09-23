use crate::ports::outbound::AdvisoryLockCheck;
use anyhow::{Context, Result};
use rustsec::Lockfile;
use rustsec::advisory::Informational;
use rustsec::database::Database;
use rustsec::report::{Report, Settings};
use std::collections::HashSet;
use std::path::Path;

/// Checks a consumer's own Cargo.lock against the real RustSec advisory
/// database — the same source `cargo audit` itself uses — to determine
/// which RUSTSEC ids genuinely affect this consumer (a covered crate is
/// present at an affected version), as opposed to what the shared/central
/// ignore lists merely mention.
pub struct RustsecAdvisories;

impl AdvisoryLockCheck for RustsecAdvisories {
    fn affected_ids(&self, lockfile_path: &str) -> Result<HashSet<String>> {
        if !Path::new(lockfile_path).is_file() {
            // Nothing to check against; report no affected ids rather than
            // erroring, so the policy-consistency checks (which don't need
            // a lockfile at all) keep working from any directory.
            return Ok(HashSet::new());
        }

        let lockfile = Lockfile::load(lockfile_path)
            .with_context(|| format!("failed to parse {lockfile_path}"))?;
        let db = Database::fetch().context("failed to fetch the RustSec advisory database")?;

        let settings = Settings {
            informational_warnings: vec![
                Informational::Unmaintained,
                Informational::Unsound,
                Informational::Notice,
            ],
            ..Settings::default()
        };

        let report = Report::generate(&db, &lockfile, &settings);

        let mut ids: HashSet<String> = report
            .vulnerabilities
            .list
            .iter()
            .map(|vulnerability| vulnerability.advisory.id.to_string())
            .collect();

        for warnings in report.warnings.values() {
            for warning in warnings {
                if let Some(advisory) = &warning.advisory {
                    ids.insert(advisory.id.to_string());
                }
            }
        }

        Ok(ids)
    }
}
