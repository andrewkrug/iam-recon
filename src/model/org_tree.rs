use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::edge::Edge;

/// Represents an AWS Organization structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationTree {
    pub org_id: String,
    pub management_account_id: String,
    pub root_ous: Vec<OrganizationNode>,
    pub all_scps: Vec<ServiceControlPolicy>,
    pub accounts: Vec<String>,
    pub edge_list: Vec<Edge>,
    pub metadata: OrgMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMetadata {
    #[serde(alias = "pmapper_version")]
    pub iam_recon_version: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Represents an Organizational Unit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationNode {
    pub ou_id: String,
    pub ou_name: String,
    pub child_nodes: Vec<OrganizationNode>,
    pub accounts: Vec<OrganizationAccount>,
    pub scps: Vec<String>,
    pub tags: HashMap<String, String>,
}

/// Represents an AWS Account within an Organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationAccount {
    pub account_id: String,
    pub account_name: String,
    pub scps: Vec<String>,
    pub tags: HashMap<String, String>,
}

/// Represents a Service Control Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceControlPolicy {
    pub policy_id: String,
    pub arn: String,
    pub name: String,
    pub policy_doc: serde_json::Value,
}

impl OrganizationTree {
    /// Get SCPs applicable to a given account ID (walk the OU tree)
    pub fn get_scps_for_account(&self, account_id: &str) -> Vec<Vec<&ServiceControlPolicy>> {
        let mut result = Vec::new();
        let path = self.find_account_path(account_id);
        for scp_ids in path {
            let level_scps: Vec<&ServiceControlPolicy> = scp_ids
                .iter()
                .filter_map(|id| self.all_scps.iter().find(|s| &s.policy_id == id))
                .collect();
            if !level_scps.is_empty() {
                result.push(level_scps);
            }
        }
        result
    }

    fn find_account_path(&self, account_id: &str) -> Vec<Vec<String>> {
        for root in &self.root_ous {
            if let Some(path) = Self::find_in_ou(root, account_id) {
                return path;
            }
        }
        Vec::new()
    }

    fn find_in_ou(ou: &OrganizationNode, account_id: &str) -> Option<Vec<Vec<String>>> {
        // Check if account is directly in this OU
        for account in &ou.accounts {
            if account.account_id == account_id {
                let mut path = vec![ou.scps.clone()];
                // Add account-level SCPs
                if !account.scps.is_empty() {
                    path.push(account.scps.clone());
                }
                return Some(path);
            }
        }
        // Recurse into child OUs
        for child in &ou.child_nodes {
            if let Some(mut path) = Self::find_in_ou(child, account_id) {
                path.insert(0, ou.scps.clone());
                return Some(path);
            }
        }
        None
    }
}
