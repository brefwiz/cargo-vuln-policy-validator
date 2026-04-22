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
    use crate::domain::models::{Exception, TomlIgnore, Violation};
    use crate::ports::inbound::ExceptionRepository;
    use crate::ports::outbound::Reporter;
    use chrono::{Duration, Utc};
    use std::sync::{Arc, Mutex};

    fn exception(id: &str) -> Exception {
        Exception {
            id: id.to_string(),
            owner: "team-security".to_string(),
            review_by: Utc::now().date_naive() + Duration::days(30),
            reason: "temporary exception".to_string(),
            risk: "known".to_string(),
            impact: "low".to_string(),
            tracking: "SEC-123".to_string(),
            resolution: "upgrade planned".to_string(),
        }
    }

    struct StubRepo {
        exceptions: Vec<Exception>,
        audit_ignores: Vec<TomlIgnore>,
        deny_ignores: Vec<TomlIgnore>,
    }

    impl ExceptionRepository for StubRepo {
        fn load_exceptions(&self, _path: &str) -> anyhow::Result<Vec<Exception>> {
            Ok(self.exceptions.clone())
        }

        fn load_toml_ignores(&self, path: &str) -> anyhow::Result<Vec<TomlIgnore>> {
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
                audit_ignores: vec![TomlIgnore {
                    id: id.to_string(),
                    source: "audit.toml".to_string(),
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
                audit_ignores: vec![TomlIgnore {
                    id: "RUSTSEC-2024-9999".to_string(),
                    source: "audit.toml".to_string(),
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
            "present in TOML but missing from allowlist"
        );
    }
}
