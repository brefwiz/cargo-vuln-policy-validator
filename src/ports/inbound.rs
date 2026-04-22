use crate::domain::models::{ExceptionRecord, TomlIgnoreRecord};

pub trait ExceptionRepository {
    fn load_exceptions(&self, path: &str) -> anyhow::Result<Vec<ExceptionRecord>>;
    fn load_toml_ignores(&self, path: &str) -> anyhow::Result<Vec<TomlIgnoreRecord>>;
}
