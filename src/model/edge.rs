use serde::{Deserialize, Serialize};

/// Represents a privilege escalation path between two principals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub source: String,
    pub destination: String,
    pub reason: String,
    pub short_reason: String,
}

impl Edge {
    pub fn new(
        source: impl Into<String>,
        destination: impl Into<String>,
        reason: impl Into<String>,
        short_reason: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            reason: reason.into(),
            short_reason: short_reason.into(),
        }
    }

    /// Returns a human-readable description: "source reason destination"
    pub fn describe(&self) -> String {
        format!("{} {} {}", self.source, self.reason, self.destination)
    }
}
