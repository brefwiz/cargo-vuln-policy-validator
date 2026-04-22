use crate::{
    domain::service::PolicyService, ports::inbound::ExceptionRepository, ports::outbound::Reporter,
};

pub struct ValidateUseCase<R: ExceptionRepository, P: Reporter> {
    pub repo: R,
    pub reporter: P,
}

impl<R: ExceptionRepository, P: Reporter> ValidateUseCase<R, P> {
    pub fn run(&self, audit: &str, deny: &str, allowlist: &str) -> anyhow::Result<()> {
        let exceptions = self.repo.load_exceptions(allowlist)?;
        let audit_ignores = self.repo.load_toml_ignores(audit)?;
        let deny_ignores = self.repo.load_toml_ignores(deny)?;

        let mut all = audit_ignores;
        all.extend(deny_ignores);

        let violations = PolicyService::validate(exceptions, all);

        if violations.is_empty() {
            println!("✅ Policy validation OK");
            Ok(())
        } else {
            self.reporter.report(&violations);
            anyhow::bail!("policy validation failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ValidateUseCase;
    use crate::domain::models::{ExceptionRecord, SourceSpan, TomlIgnoreRecord, Violation};
    use crate::ports::inbound::ExceptionRepository;
    use crate::ports::outbound::Reporter;
    use chrono::{Duration, Utc};
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
    }

    impl Reporter for RecordingReporter {
        fn report(&self, violations: &[Violation]) {
            self.violations
                .lock()
                .unwrap()
                .extend_from_slice(violations);
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
        };

        let result = usecase.run("audit.toml", "deny.toml", "exceptions.yaml");

        assert!(result.is_ok());
        assert!(reporter.violations.lock().unwrap().is_empty());
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
}
