use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::group::Group;
use super::policy::{Policy, PolicyRef};
use crate::util::arns;

/// Represents an IAM User or Role
#[derive(Debug, Clone)]
pub struct Node {
    pub arn: String,
    pub id_value: String,
    pub attached_policies: Vec<Arc<Policy>>,
    pub group_memberships: Vec<Arc<Group>>,
    pub trust_policy: Option<serde_json::Value>,
    pub instance_profile: Option<Vec<String>>,
    pub active_password: bool,
    pub access_keys: u32,
    pub is_admin: bool,
    pub permissions_boundary: Option<Arc<Policy>>,
    pub has_mfa: bool,
    pub tags: HashMap<String, String>,
}

/// Serialized form of a Node (matches Python JSON format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeData {
    pub arn: String,
    pub id_value: String,
    pub attached_policies: Vec<PolicyRef>,
    pub group_memberships: Vec<String>,
    pub trust_policy: Option<serde_json::Value>,
    pub instance_profile: Option<Vec<String>>,
    pub active_password: bool,
    pub access_keys: u32,
    pub is_admin: bool,
    pub permissions_boundary: Option<PolicyRef>,
    pub has_mfa: bool,
    pub tags: HashMap<String, String>,
}

impl Node {
    /// Returns "user/Alice" or "role/Admin" style searchable name
    pub fn searchable_name(&self) -> &str {
        arns::get_searchable_name(&self.arn)
    }

    pub fn is_user(&self) -> bool {
        self.arn.contains(":user/")
    }

    pub fn is_role(&self) -> bool {
        self.arn.contains(":role/")
    }

    /// Get all policies for this principal including group policies
    pub fn all_policies(&self) -> Vec<&Policy> {
        let mut result: Vec<&Policy> = self.attached_policies.iter().map(|p| p.as_ref()).collect();
        for group in &self.group_memberships {
            for policy in &group.attached_policies {
                result.push(policy.as_ref());
            }
        }
        result
    }

    pub fn to_data(&self) -> NodeData {
        NodeData {
            arn: self.arn.clone(),
            id_value: self.id_value.clone(),
            attached_policies: self.attached_policies.iter().map(|p| p.to_ref()).collect(),
            group_memberships: self
                .group_memberships
                .iter()
                .map(|g| g.arn.clone())
                .collect(),
            trust_policy: self.trust_policy.clone(),
            instance_profile: self.instance_profile.clone(),
            active_password: self.active_password,
            access_keys: self.access_keys,
            is_admin: self.is_admin,
            permissions_boundary: self.permissions_boundary.as_ref().map(|p| p.to_ref()),
            has_mfa: self.has_mfa,
            tags: self.tags.clone(),
        }
    }
}
