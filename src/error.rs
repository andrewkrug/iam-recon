use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum IamReconError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("AWS SDK error: {0}")]
    AwsSdk(String),

    #[error("Invalid ARN: {0}")]
    InvalidArn(String),

    #[error("Graph version mismatch: stored={stored}, current={current}")]
    VersionMismatch { stored: String, current: String },

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, IamReconError>;

/// Helper to convert AWS SDK errors to IamReconError
pub fn aws_err(e: impl fmt::Display) -> IamReconError {
    IamReconError::AwsSdk(e.to_string())
}
