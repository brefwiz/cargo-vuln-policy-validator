use crate::domain::models::{Exception, ExceptionConfig, IgnoreEntry, TomlIgnore};
use crate::ports::inbound::ExceptionRepository;
use anyhow::Result;
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

impl ExceptionRepository for FileRepo {
    fn load_exceptions(&self, path: &str) -> Result<Vec<Exception>> {
        let raw = fs::read_to_string(path)?;
        let parsed: ExceptionConfig = serde_yaml::from_str(&raw)?;
        Ok(parsed.exceptions)
    }

    fn load_toml_ignores(&self, path: &str) -> Result<Vec<TomlIgnore>> {
        let raw = std::fs::read_to_string(path)?;
        let parsed: AdvisoryFile = toml::from_str(&raw)?;

        let mut results = Vec::new();

        if let Some(advisories) = parsed.advisories
            && let Some(ignore) = advisories.ignore
        {
            for entry in ignore {
                let id = match entry {
                    IgnoreEntry::Simple(id) => id,
                    IgnoreEntry::Detailed { id, .. } => id,
                };

                results.push(TomlIgnore {
                    id,
                    source: path.to_string(),
                });
            }
        }

        Ok(results)
    }
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
    fn loads_exceptions_from_yaml() {
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

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn loads_simple_and_detailed_toml_ignores() {
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
        assert_eq!(ignores[0].source, path.to_str().unwrap());
        assert_eq!(ignores[1].source, path.to_str().unwrap());

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
}
