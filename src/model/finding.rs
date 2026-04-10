use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
        }
    }
}

/// Represents a security finding from risk analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub impact: String,
    pub description: String,
    pub recommendation: String,
}

impl Finding {
    pub fn new(
        title: impl Into<String>,
        severity: Severity,
        impact: impl Into<String>,
        description: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            severity,
            impact: impact.into(),
            description: description.into(),
            recommendation: recommendation.into(),
        }
    }
}
