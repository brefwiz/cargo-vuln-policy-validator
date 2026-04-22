use crate::domain::models::{Exception, TomlIgnore};

pub trait ExceptionRepository {
    fn load_exceptions(&self, path: &str) -> anyhow::Result<Vec<Exception>>;
    fn load_toml_ignores(&self, path: &str) -> anyhow::Result<Vec<TomlIgnore>>;
}
