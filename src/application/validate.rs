use crate::{
    domain::service::PolicyService,
    ports::inbound::ExceptionRepository,
    ports::outbound::{AdvisoryLockCheck, Reporter},
};
use chrono::Utc;
use std::collections::HashSet;

/// Default location `cargo-vuln-policy-validator` is invoked from: the
/// consumer's own repo root, where its Cargo.lock lives.
const LOCKFILE_PATH: &str = "Cargo.lock";

pub struct ValidateUseCase<R: ExceptionRepository, P: Reporter, A: AdvisoryLockCheck> {
    pub repo: R,
    pub reporter: P,
    pub advisories: A,
}

impl<R: ExceptionRepository, P: Reporter, A: AdvisoryLockCheck> ValidateUseCase<R, P, A> {
    pub fn run(&self, audit: &str, deny: &str, allowlist: &str) -> anyhow::Result<()> {
        let exceptions = self.repo.load_exceptions(allowlist)?;
        let audit_ignores = self.repo.load_toml_ignores(audit)?;
        let deny_ignores = self.repo.load_toml_ignores(deny)?;

        let mut all = audit_ignores;
        all.extend(deny_ignores);

        // Only consult the consumer's Cargo.lock (which means fetching the
        // advisory database) when there is an expired exception to resolve
        // — the common case, where every review_by is still current, never
        // needs it.
        let today = Utc::now().date_naive();
        let has_expired = exceptions.iter().any(|exception| {
            exception
                .review_by
                .is_some_and(|review_by| review_by < today)
        });

        let affected_ids = if has_expired {
            self.advisories.affected_ids(LOCKFILE_PATH)?
        } else {
            HashSet::new()
        };

        let violations = PolicyService::validate(exceptions, all, &affected_ids);
        let (blocking, notices): (Vec<_>, Vec<_>) = violations
            .into_iter()
            .partition(|violation| violation.kind.is_blocking());

        if !notices.is_empty() {
            self.reporter.report_notices(&notices);
        }

        if blocking.is_empty() {
            println!("✅ Policy validation OK");
            Ok(())
        } else {
            self.reporter.report(&blocking);
            anyhow::bail!("policy validation failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ValidateUseCase;
    use crate::domain::models::{ExceptionRecord, SourceSpan, TomlIgnoreRecord, Violation};
    use crate::ports::inbound::ExceptionRepository;
    use crate::ports::outbound::{AdvisoryLockCheck, Reporter};
    use chrono::{Duration, Utc};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    fn span(path: &str, line: usize, column: usize) -> SourceSpan {
        SourceSpan::new(path, line, column)
    }

    fn exception(id: &str) -> ExceptionRecord {
        ExceptionRecord {
            id: id.to_string(),
            owner: "team-security".to_string(),
            review_by: Some(Utc::now().date_naive() + Duration::days(30)),
            reason: "temporary exception".to_string(),
            risk: "known".to_string(),
            impact: "low".to_string(),
            tracking: "SEC-123".to_string(),
            resolution: "upgrade planned".to_string(),
            id_span: span("exceptions.yaml", 3, 9),
            owner_span: Some(span("exceptions.yaml", 4, 12)),
            review_by_span: Some(span("exceptions.yaml", 5, 16)),
            reason_span: Some(span("exceptions.yaml", 6, 13)),
            risk_span: Some(span("exceptions.yaml", 7, 11)),
            impact_span: Some(span("exceptions.yaml", 8, 13)),
            tracking_span: Some(span("exceptions.yaml", 9, 15)),
            resolution_span: Some(span("exceptions.yaml", 10, 17)),
        }
    }

    struct StubRepo {
        exceptions: Vec<ExceptionRecord>,
        audit_ignores: Vec<TomlIgnoreRecord>,
        deny_ignores: Vec<TomlIgnoreRecord>,
    }

    impl ExceptionRepository for StubRepo {
        fn load_exceptions(&self, _path: &str) -> anyhow::Result<Vec<ExceptionRecord>> {
            Ok(self.exceptions.clone())
        }

        fn load_toml_ignores(&self, path: &str) -> anyhow::Result<Vec<TomlIgnoreRecord>> {
            match path {
                "audit.toml" => Ok(self.audit_ignores.clone()),
                "deny.toml" => Ok(self.deny_ignores.clone()),
                other => panic!("unexpected path: {other}"),
            }
        }
    }

    #[derive(Clone, Default)]
    struct RecordingReporter {
        violations: Arc<Mutex<Vec<Violation>>>,
        notices: Arc<Mutex<Vec<Violation>>>,
    }

    impl Reporter for RecordingReporter {
        fn report(&self, violations: &[Violation]) {
            self.violations
                .lock()
                .unwrap()
                .extend_from_slice(violations);
        }

        fn report_notices(&self, notices: &[Violation]) {
            self.notices.lock().unwrap().extend_from_slice(notices);
        }
    }

    #[derive(Clone, Default)]
    struct StubAdvisories {
        affected: HashSet<String>,
        calls: Arc<Mutex<u32>>,
    }

    impl StubAdvisories {
        fn affecting(ids: &[&str]) -> Self {
            Self {
                affected: ids.iter().map(|id| id.to_string()).collect(),
                calls: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl AdvisoryLockCheck for StubAdvisories {
        fn affected_ids(&self, _lockfile_path: &str) -> anyhow::Result<HashSet<String>> {
            *self.calls.lock().unwrap() += 1;
            Ok(self.affected.clone())
        }
    }

    #[test]
    fn succeeds_when_policy_validation_has_no_violations() {
        let id = "RUSTSEC-2024-0001";
        let reporter = RecordingReporter::default();
        let usecase = ValidateUseCase {
            repo: StubRepo {
                exceptions: vec![exception(id)],
                audit_ignores: vec![TomlIgnoreRecord {
                    id: id.to_string(),
                    source_span: span("audit.toml", 4, 4),
                    section: "advisories.ignore",
                }],
                deny_ignores: vec![],
            },
            reporter: reporter.clone(),
            advisories: StubAdvisories::default(),
        };

        let result = usecase.run("audit.toml", "deny.toml", "exceptions.yaml");

        assert!(result.is_ok());
        assert!(reporter.violations.lock().unwrap().is_empty());
    }

    #[test]
    fn does_not_consult_the_lock_when_nothing_is_expired() {
        let id = "RUSTSEC-2024-0001";
        let advisories = StubAdvisories::affecting(&[id]);
        let usecase = ValidateUseCase {
            repo: StubRepo {
                exceptions: vec![exception(id)],
                audit_ignores: vec![],
                deny_ignores: vec![],
            },
            reporter: RecordingReporter::default(),
            advisories: advisories.clone(),
        };

        let result = usecase.run("audit.toml", "deny.toml", "exceptions.yaml");

        assert!(result.is_ok());
        assert_eq!(*advisories.calls.lock().unwrap(), 0);
    }

    #[test]
    fn reports_and_fails_when_policy_validation_finds_violations() {
        let reporter = RecordingReporter::default();
        let usecase = ValidateUseCase {
            repo: StubRepo {
                exceptions: vec![],
                audit_ignores: vec![TomlIgnoreRecord {
                    id: "RUSTSEC-2024-9999".to_string(),
                    source_span: span("audit.toml", 4, 4),
                    section: "advisories.ignore",
                }],
                deny_ignores: vec![],
            },
            reporter: reporter.clone(),
            advisories: StubAdvisories::default(),
        };

        let result = usecase.run("audit.toml", "deny.toml", "exceptions.yaml");

        assert!(result.is_err());
        let violations = reporter.violations.lock().unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].id, "RUSTSEC-2024-9999");
        assert_eq!(
            violations[0].message,
            "ignore present in advisories.ignore but missing from allowlist"
        );
        assert_eq!(violations[0].primary_span.path, "audit.toml");
        assert_eq!(violations[0].primary_span.line, 4);
    }

    #[test]
    fn fails_when_an_expired_exception_advisory_is_present_in_the_lock() {
        let id = "RUSTSEC-2024-0001";
        let mut expired = exception(id);
        expired.review_by = Some(Utc::now().date_naive() - Duration::days(1));
        let reporter = RecordingReporter::default();
        let usecase = ValidateUseCase {
            repo: StubRepo {
                exceptions: vec![expired],
                audit_ignores: vec![TomlIgnoreRecord {
                    id: id.to_string(),
                    source_span: span("audit.toml", 4, 4),
                    section: "advisories.ignore",
                }],
                deny_ignores: vec![],
            },
            reporter: reporter.clone(),
            advisories: StubAdvisories::affecting(&[id]),
        };

        let result = usecase.run("audit.toml", "deny.toml", "exceptions.yaml");

        assert!(result.is_err());
        assert_eq!(reporter.violations.lock().unwrap().len(), 1);
        assert!(reporter.notices.lock().unwrap().is_empty());
    }

    #[test]
    fn succeeds_with_a_notice_when_an_expired_exception_advisory_is_absent_from_the_lock() {
        let id = "RUSTSEC-2024-0001";
        let mut expired = exception(id);
        expired.review_by = Some(Utc::now().date_naive() - Duration::days(1));
        let reporter = RecordingReporter::default();
        let usecase = ValidateUseCase {
            repo: StubRepo {
                exceptions: vec![expired],
                // The shared/central ignore list still mentions the id (as it
                // does for every consumer) — that alone must not block.
                audit_ignores: vec![TomlIgnoreRecord {
                    id: id.to_string(),
                    source_span: span("audit.toml", 4, 4),
                    section: "advisories.ignore",
                }],
                deny_ignores: vec![],
            },
            reporter: reporter.clone(),
            advisories: StubAdvisories::default(),
        };

        let result = usecase.run("audit.toml", "deny.toml", "exceptions.yaml");

        assert!(result.is_ok());
        assert!(reporter.violations.lock().unwrap().is_empty());
        let notices = reporter.notices.lock().unwrap();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].id, id);
    }
}
