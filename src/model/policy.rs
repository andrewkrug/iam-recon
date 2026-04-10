use serde::{Deserialize, Serialize};

/// Represents an IAM policy (inline or managed).
/// For inline policies, `arn` is the principal's ARN.
/// For managed policies, `arn` is the policy's own ARN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub arn: String,
    pub name: String,
    pub policy_doc: serde_json::Value,
}

/// Lightweight reference to a Policy used in serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRef {
    pub arn: String,
    pub name: String,
}

impl Policy {
    pub fn new(
        arn: impl Into<String>,
        name: impl Into<String>,
        policy_doc: serde_json::Value,
    ) -> Self {
        Self {
            arn: arn.into(),
            name: name.into(),
            policy_doc,
        }
    }

    pub fn to_ref(&self) -> PolicyRef {
        PolicyRef {
            arn: self.arn.clone(),
            name: self.name.clone(),
        }
    }
}
