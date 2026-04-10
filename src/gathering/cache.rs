//! Local disk cache for AWS API responses.
//!
//! When `iam-recon graph create` runs, all AWS describe/list/get API responses are
//! serialized to a cache directory alongside the graph. This allows subsequent
//! queries, analysis, and visualization to work fully offline without AWS access.
//!
//! Cache layout:
//! ```text
//! <graph_root>/
//!   cache/
//!     caller_identity.json
//!     iam_authorization_details.json
//!     lambda_functions.json
//!     codebuild_projects.json
//!     cloudformation_stacks.json
//!     resource_policies.json
//!   policies/
//!     <sanitized_arn>.json          # One file per policy document
//!     _index.json                   # ARN -> filename mapping
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// Cached AWS API responses for offline operation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiCache {
    pub caller_identity: CallerIdentityCache,
    pub iam_authorization_details: serde_json::Value,
    pub lambda_functions: Vec<LambdaFunctionCache>,
    pub codebuild_projects: Vec<CodeBuildProjectCache>,
    pub cloudformation_stacks: Vec<CloudFormationStackCache>,
    pub resource_policies: Vec<ResourcePolicyCache>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallerIdentityCache {
    pub account_id: String,
    pub arn: String,
    pub user_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LambdaFunctionCache {
    pub function_arn: String,
    pub role_arn: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CodeBuildProjectCache {
    pub project_arn: String,
    pub service_role_arn: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CloudFormationStackCache {
    pub stack_arn: String,
    pub role_arn: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResourcePolicyCache {
    pub arn: String,
    pub name: String,
    pub service: String,
    pub policy_doc: serde_json::Value,
}

/// A single cached policy document with metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedPolicy {
    pub arn: String,
    pub name: String,
    /// "managed", "inline-user", "inline-role", "inline-group", "resource", "trust"
    pub policy_type: String,
    /// The principal or resource this policy is attached to
    pub attached_to: String,
    pub policy_document: serde_json::Value,
}

/// Index mapping ARNs to filenames in the policies/ directory
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyIndex {
    pub account_id: String,
    pub total_policies: usize,
    pub entries: Vec<PolicyIndexEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyIndexEntry {
    pub arn: String,
    pub name: String,
    pub policy_type: String,
    pub attached_to: String,
    pub filename: String,
}

impl ApiCache {
    pub fn cache_dir(graph_root: &Path) -> PathBuf {
        graph_root.join("cache")
    }

    pub fn policies_dir(graph_root: &Path) -> PathBuf {
        graph_root.join("policies")
    }

    pub fn save(&self, graph_root: &Path) -> Result<()> {
        let cache_dir = Self::cache_dir(graph_root);
        std::fs::create_dir_all(&cache_dir)?;

        std::fs::write(
            cache_dir.join("caller_identity.json"),
            serde_json::to_string_pretty(&self.caller_identity)?,
        )?;
        std::fs::write(
            cache_dir.join("iam_authorization_details.json"),
            serde_json::to_string_pretty(&self.iam_authorization_details)?,
        )?;
        std::fs::write(
            cache_dir.join("lambda_functions.json"),
            serde_json::to_string_pretty(&self.lambda_functions)?,
        )?;
        std::fs::write(
            cache_dir.join("codebuild_projects.json"),
            serde_json::to_string_pretty(&self.codebuild_projects)?,
        )?;
        std::fs::write(
            cache_dir.join("cloudformation_stacks.json"),
            serde_json::to_string_pretty(&self.cloudformation_stacks)?,
        )?;
        std::fs::write(
            cache_dir.join("resource_policies.json"),
            serde_json::to_string_pretty(&self.resource_policies)?,
        )?;

        tracing::info!("API cache saved to {}", cache_dir.display());
        Ok(())
    }

    pub fn load(graph_root: &Path) -> Result<Self> {
        let cache_dir = Self::cache_dir(graph_root);

        let caller_identity: CallerIdentityCache = serde_json::from_str(&std::fs::read_to_string(
            cache_dir.join("caller_identity.json"),
        )?)?;
        let iam_authorization_details: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(cache_dir.join("iam_authorization_details.json"))?,
        )?;
        let lambda_functions: Vec<LambdaFunctionCache> = serde_json::from_str(
            &std::fs::read_to_string(cache_dir.join("lambda_functions.json"))?,
        )?;
        let codebuild_projects: Vec<CodeBuildProjectCache> = serde_json::from_str(
            &std::fs::read_to_string(cache_dir.join("codebuild_projects.json"))?,
        )?;
        let cloudformation_stacks: Vec<CloudFormationStackCache> = serde_json::from_str(
            &std::fs::read_to_string(cache_dir.join("cloudformation_stacks.json"))?,
        )?;
        let resource_policies: Vec<ResourcePolicyCache> = serde_json::from_str(
            &std::fs::read_to_string(cache_dir.join("resource_policies.json"))?,
        )?;

        tracing::info!("API cache loaded from {}", cache_dir.display());
        Ok(Self {
            caller_identity,
            iam_authorization_details,
            lambda_functions,
            codebuild_projects,
            cloudformation_stacks,
            resource_policies,
        })
    }

    pub fn exists(graph_root: &Path) -> bool {
        Self::cache_dir(graph_root)
            .join("caller_identity.json")
            .exists()
    }
}

/// Save all policy documents from a graph to individual JSON files
pub fn save_policies(graph_root: &Path, policies: &[CachedPolicy]) -> Result<()> {
    let dir = ApiCache::policies_dir(graph_root);
    std::fs::create_dir_all(&dir)?;

    let mut index_entries = Vec::new();

    for (i, policy) in policies.iter().enumerate() {
        let filename = format!("{:04}_{}.json", i, sanitize_filename(&policy.name));

        let content = serde_json::json!({
            "arn": policy.arn,
            "name": policy.name,
            "type": policy.policy_type,
            "attached_to": policy.attached_to,
            "document": policy.policy_document,
        });

        std::fs::write(dir.join(&filename), serde_json::to_string_pretty(&content)?)?;

        index_entries.push(PolicyIndexEntry {
            arn: policy.arn.clone(),
            name: policy.name.clone(),
            policy_type: policy.policy_type.clone(),
            attached_to: policy.attached_to.clone(),
            filename,
        });
    }

    let index = PolicyIndex {
        account_id: policies
            .first()
            .map(|p| crate::util::arns::get_account_id(&p.arn).to_string())
            .unwrap_or_default(),
        total_policies: policies.len(),
        entries: index_entries,
    };

    std::fs::write(
        dir.join("_index.json"),
        serde_json::to_string_pretty(&index)?,
    )?;

    tracing::info!(
        "Saved {} policy documents to {}",
        policies.len(),
        dir.display()
    );
    Ok(())
}

/// Load the policy index from disk
pub fn load_policy_index(graph_root: &Path) -> Result<PolicyIndex> {
    let path = ApiCache::policies_dir(graph_root).join("_index.json");
    let content = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&content)?)
}

/// Load a single cached policy by filename
pub fn load_policy(graph_root: &Path, filename: &str) -> Result<serde_json::Value> {
    let path = ApiCache::policies_dir(graph_root).join(filename);
    let content = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&content)?)
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .chars()
        .take(60)
        .collect()
}
