use crate::domain::models::{
    ExceptionConfig, ExceptionRecord, IgnoreEntry, SourceSpan, TomlIgnoreRecord,
};
use crate::ports::inbound::ExceptionRepository;
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::fs;

pub struct FileRepo;

#[derive(Debug, Deserialize)]
struct AdvisoryFile {
    advisories: Option<Advisories>,
}

#[derive(Debug, Deserialize)]
struct Advisories {
    ignore: Option<Vec<IgnoreEntry>>,
}

#[derive(Debug, Default)]
struct ExceptionSpans {
    id: Option<SourceSpan>,
    owner: Option<SourceSpan>,
    review_by: Option<SourceSpan>,
    reason: Option<SourceSpan>,
    risk: Option<SourceSpan>,
    impact: Option<SourceSpan>,
    tracking: Option<SourceSpan>,
    resolution: Option<SourceSpan>,
}

impl ExceptionRepository for FileRepo {
    fn load_exceptions(&self, path: &str) -> Result<Vec<ExceptionRecord>> {
        let raw = fs::read_to_string(path)?;
        let parsed: ExceptionConfig = serde_yaml::from_str(&raw)?;
        let spans = locate_exception_spans(path, &raw);

        if spans.len() != parsed.exceptions.len() {
            bail!(
                "failed to locate all exception entries in {path}: parsed {}, located {}",
                parsed.exceptions.len(),
                spans.len()
            );
        }

        parsed
            .exceptions
            .into_iter()
            .zip(spans)
            .map(|(exception, spans)| {
                let id_span = spans
                    .id
                    .ok_or_else(|| anyhow!("missing source location for exception id in {path}"))?;

                Ok(ExceptionRecord {
                    id: exception.id,
                    owner: exception.owner,
                    review_by: exception.review_by,
                    reason: exception.reason,
                    risk: exception.risk,
                    impact: exception.impact,
                    tracking: exception.tracking,
                    resolution: exception.resolution,
                    id_span,
                    owner_span: spans.owner,
                    review_by_span: spans.review_by,
                    reason_span: spans.reason,
                    risk_span: spans.risk,
                    impact_span: spans.impact,
                    tracking_span: spans.tracking,
                    resolution_span: spans.resolution,
                })
            })
            .collect()
    }

    fn load_toml_ignores(&self, path: &str) -> Result<Vec<TomlIgnoreRecord>> {
        let raw = fs::read_to_string(path)?;
        let parsed: AdvisoryFile = toml::from_str(&raw)?;

        let expected_ids = parsed
            .advisories
            .and_then(|advisories| advisories.ignore)
            .unwrap_or_default()
            .into_iter()
            .map(|entry| match entry {
                IgnoreEntry::Simple(id) => id,
                IgnoreEntry::Detailed { id, .. } => id,
            })
            .collect::<Vec<_>>();

        let located = locate_toml_ignores(path, &raw);

        if located.len() != expected_ids.len() {
            bail!(
                "failed to locate all advisories.ignore entries in {path}: parsed {}, located {}",
                expected_ids.len(),
                located.len()
            );
        }

        Ok(expected_ids
            .into_iter()
            .zip(located)
            .map(|(id, source_span)| TomlIgnoreRecord {
                id,
                source_span,
                section: "advisories.ignore",
            })
            .collect())
    }
}

fn locate_exception_spans(path: &str, raw: &str) -> Vec<ExceptionSpans> {
    let mut results = Vec::new();
    let mut current: Option<ExceptionSpans> = None;

    for (index, line) in raw.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        if let Some(value) = trimmed.strip_prefix("- id:") {
            if let Some(record) = current.take() {
                results.push(record);
            }

            current = Some(ExceptionSpans {
                id: Some(SourceSpan::new(
                    path,
                    line_number,
                    yaml_value_column(indent, "- id:", value),
                )),
                ..ExceptionSpans::default()
            });
            continue;
        }

        let Some(record) = current.as_mut() else {
            continue;
        };

        for key in [
            "owner",
            "review_by",
            "reason",
            "risk",
            "impact",
            "tracking",
            "resolution",
        ] {
            let prefix = format!("{key}:");
            if let Some(value) = trimmed.strip_prefix(&prefix) {
                let span = Some(SourceSpan::new(
                    path,
                    line_number,
                    yaml_value_column(indent, &prefix, value),
                ));
                assign_exception_field_span(record, key, span);
                break;
            }
        }
    }

    if let Some(record) = current {
        results.push(record);
    }

    results
}

fn yaml_value_column(indent: usize, prefix: &str, value: &str) -> usize {
    let content_offset = value.chars().take_while(|ch| ch.is_whitespace()).count();
    indent + prefix.len() + content_offset + 1
}

fn assign_exception_field_span(record: &mut ExceptionSpans, field: &str, span: Option<SourceSpan>) {
    match field {
        "owner" => record.owner = span,
        "review_by" => record.review_by = span,
        "reason" => record.reason = span,
        "risk" => record.risk = span,
        "impact" => record.impact = span,
        "tracking" => record.tracking = span,
        "resolution" => record.resolution = span,
        _ => {}
    }
}

fn locate_toml_ignores(path: &str, raw: &str) -> Vec<SourceSpan> {
    let mut spans = Vec::new();
    let mut in_advisories = false;
    let mut in_ignore = false;

    for (index, line) in raw.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_advisories = trimmed == "[advisories]";
            if !in_advisories {
                in_ignore = false;
            }
            continue;
        }

        if !in_advisories {
            continue;
        }

        if !in_ignore {
            if let Some(eq_index) = line.find("ignore") {
                let after_key = &line[eq_index + "ignore".len()..];
                if let Some(array_index) = after_key.find('[') {
                    in_ignore = true;
                    let slice_start = eq_index + "ignore".len() + array_index + 1;
                    spans.extend(locate_toml_entries_in_slice(
                        path,
                        line_number,
                        line,
                        slice_start,
                    ));
                    if line[slice_start..].contains(']') {
                        in_ignore = false;
                    }
                }
            }
            continue;
        }

        spans.extend(locate_toml_entries_in_slice(path, line_number, line, 0));
        if line.contains(']') {
            in_ignore = false;
        }
    }

    spans
}

fn locate_toml_entries_in_slice(
    path: &str,
    line_number: usize,
    line: &str,
    start: usize,
) -> Vec<SourceSpan> {
    let mut spans = Vec::new();
    let slice = &line[start..];
    let bytes = slice.as_bytes();
    let mut offset = 0;

    while offset < bytes.len() {
        let remaining = &slice[offset..];
        let trimmed = remaining.trim_start();
        offset += remaining.len() - trimmed.len();

        if trimmed.is_empty() || trimmed.starts_with(']') || trimmed.starts_with('#') {
            break;
        }

        if let Some(rest) = trimmed.strip_prefix('"') {
            if let Some(end) = rest.find('"') {
                spans.push(SourceSpan::new(path, line_number, start + offset + 2));
                offset += end + 2;
                continue;
            }
            break;
        }

        if trimmed.starts_with('{') {
            let Some(close_brace) = trimmed.find('}') else {
                break;
            };
            let table = &trimmed[..=close_brace];

            if let Some(id_index) = table.find("id") {
                let id_slice = &table[id_index + 2..];
                if let Some(first_quote) = id_slice.find('"') {
                    let value_start = id_index + 2 + first_quote + 1;
                    if table[value_start + 1..].find('"').is_some() {
                        spans.push(SourceSpan::new(
                            path,
                            line_number,
                            start + offset + value_start + 1,
                        ));
                        offset += close_brace + 1;
                        continue;
                    }
                }
            }
            break;
        }

        let Some(next_char) = trimmed.chars().next() else {
            break;
        };
        offset += next_char.len_utf8();
    }

    spans
}

#[cfg(test)]
mod tests {
    use super::FileRepo;
    use crate::ports::inbound::ExceptionRepository;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("cargo-vuln-policy-validator-{name}-{nanos}"))
    }

    #[test]
    fn loads_exceptions_from_yaml_with_field_locations() {
        let path = temp_file_path("exceptions.yaml");
        let contents = r#"
exceptions:
  - id: RUSTSEC-2024-0001
    owner: team-security
    review_by: 2099-01-01
    reason: temporary exception
    risk: known
    impact: low
    tracking: SEC-123
    resolution: upgrade planned
"#;
        fs::write(&path, contents).unwrap();

        let repo = FileRepo;
        let exceptions = repo.load_exceptions(path.to_str().unwrap()).unwrap();

        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].id, "RUSTSEC-2024-0001");
        assert_eq!(exceptions[0].owner, "team-security");
        assert_eq!(exceptions[0].id_span.line, 3);
        assert_eq!(exceptions[0].owner_span.as_ref().unwrap().line, 4);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn keeps_missing_yaml_field_unset_for_validation() {
        let path = temp_file_path("exceptions.yaml");
        let contents = r#"
exceptions:
  - id: RUSTSEC-2024-0001
    review_by: 2099-01-01
    reason: temporary exception
    risk: known
    impact: low
    tracking: SEC-123
    resolution: upgrade planned
"#;
        fs::write(&path, contents).unwrap();

        let repo = FileRepo;
        let exceptions = repo.load_exceptions(path.to_str().unwrap()).unwrap();

        assert_eq!(exceptions[0].owner, "");
        assert!(exceptions[0].owner_span.is_none());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn loads_simple_and_detailed_toml_ignores_with_locations() {
        let path = temp_file_path("deny.toml");
        let contents = r#"
[advisories]
ignore = [
  "RUSTSEC-2024-0001",
  { id = "RUSTSEC-2024-0002" }
]
"#;
        fs::write(&path, contents).unwrap();

        let repo = FileRepo;
        let ignores = repo.load_toml_ignores(path.to_str().unwrap()).unwrap();

        assert_eq!(ignores.len(), 2);
        assert_eq!(ignores[0].id, "RUSTSEC-2024-0001");
        assert_eq!(ignores[1].id, "RUSTSEC-2024-0002");
        assert_eq!(ignores[0].source_span.path, path.to_str().unwrap());
        assert_eq!(ignores[0].source_span.line, 4);
        assert_eq!(ignores[0].source_span.column, 4);
        assert_eq!(ignores[1].source_span.line, 5);
        assert_eq!(ignores[1].source_span.column, 11);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn returns_empty_when_advisories_ignore_is_missing() {
        let path = temp_file_path("audit.toml");
        let contents = r#"
[advisories]
severity-threshold = "medium"
"#;
        fs::write(&path, contents).unwrap();

        let repo = FileRepo;
        let ignores = repo.load_toml_ignores(path.to_str().unwrap()).unwrap();

        assert!(ignores.is_empty());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ignores_unicode_comments_inside_ignore_array_without_panicking() {
        let path = temp_file_path("deny.toml");
        let contents = r#"
[advisories]
ignore = [
  "RUSTSEC-2024-0001",
  # rustls-webpki 0.101.7 via rustls 0.21 → aws-smithy-http-client 1.1.12.
  { id = "RUSTSEC-2024-0002" }
]
"#;
        fs::write(&path, contents).unwrap();

        let repo = FileRepo;
        let ignores = repo.load_toml_ignores(path.to_str().unwrap()).unwrap();

        assert_eq!(ignores.len(), 2);
        assert_eq!(ignores[0].id, "RUSTSEC-2024-0001");
        assert_eq!(ignores[1].id, "RUSTSEC-2024-0002");

        fs::remove_file(path).unwrap();
    }
}
