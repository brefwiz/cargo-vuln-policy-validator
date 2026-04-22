use chrono::NaiveDate;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Exception {
    pub id: String,
    pub owner: String,
    pub review_by: NaiveDate,
    pub reason: String,
    pub risk: String,
    pub impact: String,
    pub tracking: String,
    pub resolution: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ExceptionConfig {
    pub exceptions: Vec<Exception>,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub id: String,
    pub message: String,
    pub source: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TomlIgnore {
    pub id: String,
    pub source: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum IgnoreEntry {
    Simple(String),
    Detailed { id: String },
}
