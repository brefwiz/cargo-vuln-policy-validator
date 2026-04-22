use crate::domain::models::{ExceptionRecord, TomlIgnoreRecord, Violation, ViolationKind};
use chrono::Utc;
use std::collections::HashMap;
use tracing::info;

pub struct PolicyService;

impl PolicyService {
    pub fn validate(
        exceptions: Vec<ExceptionRecord>,
        toml_ignores: Vec<TomlIgnoreRecord>,
    ) -> Vec<Violation> {
        info!("calling into the policy service");
        let mut violations = Vec::new();
        let exception_map = exceptions
            .into_iter()
            .map(|exception| (exception.id.clone(), exception))
            .collect::<HashMap<_, _>>();

        for exception in exception_map.values() {
            info!(
                id = %exception.id,
                owner = %exception.owner,
                review_by = ?exception.review_by,
                "checking allowlist"
            );
        }

        for ignore in &toml_ignores {
            info!(id = %ignore.id, section = %ignore.section, "checking ignore entry");
            if !exception_map.contains_key(&ignore.id) {
                violations.push(Violation {
                    id: ignore.id.clone(),
                    message: format!(
                        "ignore present in {} but missing from allowlist",
                        ignore.section
                    ),
                    kind: ViolationKind::TomlIgnoreMissingException,
                    field: None,
                    primary_span: ignore.source_span.clone(),
                    related_spans: Vec::new(),
                });
            }
        }

        let today = Utc::now().date_naive();

        for exception in exception_map.values() {
            if exception.review_by.is_none() {
                violations.push(missing_field_violation(exception, "review_by"));
            } else if exception
                .review_by
                .is_some_and(|review_by| review_by < today)
            {
                violations.push(Violation {
                    id: exception.id.clone(),
                    message: "review expired".into(),
                    kind: ViolationKind::ExceptionReviewExpired,
                    field: Some("review_by".to_string()),
                    primary_span: exception.missing_field_anchor("review_by"),
                    related_spans: Vec::new(),
                });
            }

            for field in [
                "owner",
                "reason",
                "risk",
                "impact",
                "tracking",
                "resolution",
            ] {
                if field_value(exception, field).trim().is_empty() {
                    violations.push(missing_field_violation(exception, field));
                }
            }
        }

        violations
    }
}

fn field_value<'a>(exception: &'a ExceptionRecord, field: &str) -> &'a str {
    match field {
        "owner" => &exception.owner,
        "reason" => &exception.reason,
        "risk" => &exception.risk,
        "impact" => &exception.impact,
        "tracking" => &exception.tracking,
        "resolution" => &exception.resolution,
        _ => "",
    }
}

fn missing_field_violation(exception: &ExceptionRecord, field: &str) -> Violation {
    let message = if exception.span_for(field).is_some() {
        format!("required field '{field}' is blank")
    } else {
        format!("required field '{field}' is missing")
    };

    Violation {
        id: exception.id.clone(),
        message,
        kind: ViolationKind::ExceptionFieldMissing,
        field: Some(field.to_string()),
        primary_span: exception.missing_field_anchor(field),
        related_spans: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyService;
    use crate::domain::models::{ExceptionRecord, SourceSpan, TomlIgnoreRecord, ViolationKind};
    use chrono::{Duration, Utc};

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

    #[test]
    fn reports_toml_entries_missing_from_allowlist() {
        let violations = PolicyService::validate(
            vec![exception("RUSTSEC-2024-0001")],
            vec![TomlIgnoreRecord {
                id: "RUSTSEC-2024-9999".to_string(),
                source_span: span("audit.toml", 4, 4),
                section: "advisories.ignore",
            }],
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].id, "RUSTSEC-2024-9999");
        assert_eq!(
            violations[0].message,
            "ignore present in advisories.ignore but missing from allowlist"
        );
        assert_eq!(
            violations[0].kind,
            ViolationKind::TomlIgnoreMissingException
        );
        assert_eq!(violations[0].primary_span.path, "audit.toml");
        assert_eq!(violations[0].primary_span.line, 4);
        assert_eq!(violations[0].primary_span.column, 4);
    }

    #[test]
    fn reports_expired_allowlist_entries_at_review_date() {
        let mut expired = exception("RUSTSEC-2024-0001");
        expired.review_by = Some(Utc::now().date_naive() - Duration::days(1));

        let violations = PolicyService::validate(vec![expired], vec![]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].id, "RUSTSEC-2024-0001");
        assert_eq!(violations[0].message, "review expired");
        assert_eq!(violations[0].kind, ViolationKind::ExceptionReviewExpired);
        assert_eq!(violations[0].primary_span.line, 5);
    }

    #[test]
    fn reports_blank_required_fields_at_their_field_location() {
        let mut invalid = exception("RUSTSEC-2024-0001");
        invalid.owner = " ".to_string();

        let violations = PolicyService::validate(vec![invalid], vec![]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].message, "required field 'owner' is blank");
        assert_eq!(violations[0].kind, ViolationKind::ExceptionFieldMissing);
        assert_eq!(violations[0].primary_span.line, 4);
    }

    #[test]
    fn reports_missing_required_fields_at_the_exception_id() {
        let mut invalid = exception("RUSTSEC-2024-0001");
        invalid.owner.clear();
        invalid.owner_span = None;

        let violations = PolicyService::validate(vec![invalid], vec![]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].message, "required field 'owner' is missing");
        assert_eq!(violations[0].primary_span.line, 3);
    }

    #[test]
    fn returns_no_violations_for_valid_matching_entries() {
        let id = "RUSTSEC-2024-0001";
        let violations = PolicyService::validate(
            vec![exception(id)],
            vec![TomlIgnoreRecord {
                id: id.to_string(),
                source_span: span("deny.toml", 4, 4),
                section: "advisories.ignore",
            }],
        );

        assert!(violations.is_empty());
    }
}
