use crate::domain::models::{Exception, TomlIgnore, Violation};
use chrono::Utc;
use std::collections::HashMap;
use tracing::info;

pub struct PolicyService;

impl PolicyService {
    pub fn validate(exceptions: Vec<Exception>, toml: Vec<TomlIgnore>) -> Vec<Violation> {
        info!("calling into the policy service",);
        let mut violations = Vec::new();
        let mut map = HashMap::new();

        for e in exceptions {
            map.insert(e.id.clone(), e.clone());
            info!(
                id = %e.id,
                owner = %e.owner,
                review_by = %e.review_by,
                "checking allowlist"
            );
        }

        // TOML → allowlist
        for t in &toml {
            info!(
                id = %t.id,
                source = %t.source,
            );
            if !map.contains_key(&t.id) {
                violations.push(Violation {
                    id: t.id.clone(),
                    message: "present in TOML but missing from allowlist".into(),
                    source: Some(t.source.clone()),
                });
            }
        }

        let today = Utc::now().date_naive();

        // allowlist → TOML + rule validation
        for (id, e) in &map {
            if e.review_by < today {
                violations.push(Violation {
                    id: id.clone(),
                    message: "review expired".into(),
                    source: None,
                });
            }

            if e.reason.trim().is_empty()
                || e.impact.trim().is_empty()
                || e.resolution.trim().is_empty()
                || e.owner.trim().is_empty()
                || e.reason.trim().is_empty()
                || e.risk.trim().is_empty()
                || e.impact.trim().is_empty()
                || e.tracking.trim().is_empty()
                || e.resolution.trim().is_empty()
            {
                violations.push(Violation {
                    id: id.clone(),
                    message: "missing required fields".into(),
                    source: None,
                });
            }
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyService;
    use crate::domain::models::{Exception, TomlIgnore};
    use chrono::{Duration, Utc};

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

    #[test]
    fn reports_toml_entries_missing_from_allowlist() {
        let violations = PolicyService::validate(
            vec![exception("RUSTSEC-2024-0001")],
            vec![TomlIgnore {
                id: "RUSTSEC-2024-9999".to_string(),
                source: "audit.toml".to_string(),
            }],
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].id, "RUSTSEC-2024-9999");
        assert_eq!(
            violations[0].message,
            "present in TOML but missing from allowlist"
        );
        assert_eq!(violations[0].source.as_deref(), Some("audit.toml"));
    }

    #[test]
    fn reports_expired_allowlist_entries() {
        let mut expired = exception("RUSTSEC-2024-0001");
        expired.review_by = Utc::now().date_naive() - Duration::days(1);

        let violations = PolicyService::validate(vec![expired], vec![]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].id, "RUSTSEC-2024-0001");
        assert_eq!(violations[0].message, "review expired");
    }

    #[test]
    fn reports_missing_required_fields() {
        let mut invalid = exception("RUSTSEC-2024-0001");
        invalid.owner = " ".to_string();

        let violations = PolicyService::validate(vec![invalid], vec![]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].id, "RUSTSEC-2024-0001");
        assert_eq!(violations[0].message, "missing required fields");
    }

    #[test]
    fn returns_no_violations_for_valid_matching_entries() {
        let id = "RUSTSEC-2024-0001";
        let violations = PolicyService::validate(
            vec![exception(id)],
            vec![TomlIgnore {
                id: id.to_string(),
                source: "deny.toml".to_string(),
            }],
        );

        assert!(violations.is_empty());
    }
}
