use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::policy::{Policy, PolicyRef};

/// Represents an IAM Group
#[derive(Debug, Clone)]
pub struct Group {
    pub arn: String,
    pub attached_policies: Vec<Arc<Policy>>,
}

/// Serialized form of a Group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupData {
    pub arn: String,
    pub attached_policies: Vec<PolicyRef>,
}

impl Group {
    pub fn new(arn: impl Into<String>, attached_policies: Vec<Arc<Policy>>) -> Self {
        let arn = arn.into();
        assert!(arn.contains("group/"), "Group ARN must contain 'group/'");
        Self {
            arn,
            attached_policies,
        }
    }

    pub fn to_data(&self) -> GroupData {
        GroupData {
            arn: self.arn.clone(),
            attached_policies: self.attached_policies.iter().map(|p| p.to_ref()).collect(),
        }
    }
}
