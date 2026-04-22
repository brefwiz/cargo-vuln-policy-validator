use chrono::NaiveDate;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpan {
    pub path: String,
    pub line: usize,
    pub column: usize,
}

impl SourceSpan {
    pub fn new(path: impl Into<String>, line: usize, column: usize) -> Self {
        Self {
            path: path.into(),
            line,
            column,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExceptionConfig {
    pub exceptions: Vec<ExceptionInput>,
}

#[derive(Debug, Deserialize)]
pub struct ExceptionInput {
    pub id: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub review_by: Option<NaiveDate>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub risk: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub tracking: String,
    #[serde(default)]
    pub resolution: String,
}

#[derive(Debug, Clone)]
pub struct ExceptionRecord {
    pub id: String,
    pub owner: String,
    pub review_by: Option<NaiveDate>,
    pub reason: String,
    pub risk: String,
    pub impact: String,
    pub tracking: String,
    pub resolution: String,
    pub id_span: SourceSpan,
    pub owner_span: Option<SourceSpan>,
    pub review_by_span: Option<SourceSpan>,
    pub reason_span: Option<SourceSpan>,
    pub risk_span: Option<SourceSpan>,
    pub impact_span: Option<SourceSpan>,
    pub tracking_span: Option<SourceSpan>,
    pub resolution_span: Option<SourceSpan>,
}

impl ExceptionRecord {
    pub fn span_for(&self, field: &str) -> Option<&SourceSpan> {
        match field {
            "id" => Some(&self.id_span),
            "owner" => self.owner_span.as_ref(),
            "review_by" => self.review_by_span.as_ref(),
            "reason" => self.reason_span.as_ref(),
            "risk" => self.risk_span.as_ref(),
            "impact" => self.impact_span.as_ref(),
            "tracking" => self.tracking_span.as_ref(),
            "resolution" => self.resolution_span.as_ref(),
            _ => None,
        }
    }

    pub fn missing_field_anchor(&self, field: &str) -> SourceSpan {
        self.span_for(field)
            .cloned()
            .unwrap_or_else(|| self.id_span.clone())
    }
}

#[derive(Debug, Clone)]
pub struct TomlIgnoreRecord {
    pub id: String,
    pub source_span: SourceSpan,
    pub section: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum IgnoreEntry {
    Simple(String),
    Detailed { id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    TomlIgnoreMissingException,
    ExceptionReviewExpired,
    ExceptionFieldMissing,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub id: String,
    pub message: String,
    pub kind: ViolationKind,
    pub field: Option<String>,
    pub primary_span: SourceSpan,
    pub related_spans: Vec<SourceSpan>,
}

impl Violation {
    pub fn edit_hint(&self) -> String {
        match self.kind {
            ViolationKind::TomlIgnoreMissingException => {
                "Edit this ignore entry or add a matching exception record.".to_string()
            }
            ViolationKind::ExceptionReviewExpired => {
                "Update the review_by date in this exception record.".to_string()
            }
            ViolationKind::ExceptionFieldMissing => format!(
                "Update the '{}' field in this exception record.",
                self.field.as_deref().unwrap_or("missing")
            ),
        }
    }
}
