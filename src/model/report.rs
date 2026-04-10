use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::finding::Finding;

/// A report containing findings for an AWS account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub account_id: String,
    pub generated_at: DateTime<Utc>,
    pub findings: Vec<Finding>,
    pub description: String,
}

impl Report {
    pub fn new(account_id: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self {
            account_id: account_id.into(),
            generated_at: Utc::now(),
            findings,
            description: "IAM Recon analysis report".to_string(),
        }
    }
}
