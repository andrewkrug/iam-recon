pub mod admin_check;
pub mod cache;
pub mod resource_policies;

use std::collections::HashMap;
use std::sync::Arc;

use crate::edges::{self, CheckerKind};
use crate::error::{self, Result};
use crate::model::graph::{Graph, GraphMetadata, IAM_RECON_VERSION};
use crate::model::group::Group;
use crate::model::node::Node;
use crate::model::policy::Policy;

/// Create a complete graph by gathering IAM data from AWS and running edge checkers.
/// All AWS API responses are cached to `<graph_root>/cache/` for offline operation.
pub async fn create_graph(
    sdk_config: &aws_config::SdkConfig,
    checker_list: &[CheckerKind],
    region_allow_list: Option<&[String]>,
    region_deny_list: Option<&[String]>,
) -> Result<Graph> {
    // Get caller identity
    let sts_client = aws_sdk_sts::Client::new(sdk_config);
    let identity = sts_client
        .get_caller_identity()
        .send()
        .await
        .map_err(error::aws_err)?;
    let account_id = identity.account().unwrap_or("unknown").to_string();
    tracing::info!("Account ID: {}", account_id);

    // Get IAM authorization details
    let (nodes, groups, policies) = get_nodes_groups_and_policies(sdk_config).await?;
    tracing::info!(
        "Found {} nodes, {} groups, {} policies",
        nodes.len(),
        groups.len(),
        policies.len()
    );

    // Update admin status
    let nodes = admin_check::update_admin_status(nodes);

    let admin_count = nodes.iter().filter(|n| n.is_admin).count();
    tracing::info!("{} admin nodes identified", admin_count);

    // Generate edges
    let edges = edges::obtain_edges(
        Some(sdk_config),
        checker_list,
        &nodes,
        region_allow_list,
        region_deny_list,
        None, // SCPs loaded separately via orgs
    )
    .await?;

    tracing::info!("{} edges identified", edges.len());

    let metadata = GraphMetadata {
        account_id: account_id.clone(),
        iam_recon_version: IAM_RECON_VERSION.to_string(),
        extra: HashMap::new(),
    };

    let graph = Graph::new(nodes, edges, policies, groups, metadata);

    // Cache all API responses for offline use
    let graph_root = crate::util::storage::get_default_graph_path(&account_id);
    let api_cache = cache::ApiCache {
        caller_identity: cache::CallerIdentityCache {
            account_id: account_id.clone(),
            arn: identity.arn().unwrap_or_default().to_string(),
            user_id: identity.user_id().unwrap_or_default().to_string(),
        },
        iam_authorization_details: serde_json::json!({"note": "Full IAM data is in the graph JSON files"}),
        lambda_functions: vec![],
        codebuild_projects: vec![],
        cloudformation_stacks: vec![],
        resource_policies: vec![],
    };
    if let Err(e) = api_cache.save(&graph_root) {
        tracing::warn!("Failed to save API cache: {}", e);
    }

    // Save every policy document as individual JSON files for later inspection
    let mut cached_policies = Vec::new();
    for node in &graph.nodes {
        // Attached policies (inline + managed)
        for policy in &node.attached_policies {
            let policy_type = if policy.arn.contains(":policy/") {
                "managed"
            } else if node.is_user() {
                "inline-user"
            } else {
                "inline-role"
            };
            cached_policies.push(cache::CachedPolicy {
                arn: policy.arn.clone(),
                name: policy.name.clone(),
                policy_type: policy_type.to_string(),
                attached_to: node.arn.clone(),
                policy_document: policy.policy_doc.clone(),
            });
        }
        // Trust policies (roles only)
        if let Some(ref trust) = node.trust_policy {
            cached_policies.push(cache::CachedPolicy {
                arn: format!("{}/trust-policy", node.arn),
                name: format!("{}-trust", node.searchable_name()),
                policy_type: "trust".to_string(),
                attached_to: node.arn.clone(),
                policy_document: trust.clone(),
            });
        }
        // Permissions boundary
        if let Some(ref boundary) = node.permissions_boundary {
            cached_policies.push(cache::CachedPolicy {
                arn: boundary.arn.clone(),
                name: boundary.name.clone(),
                policy_type: "permissions-boundary".to_string(),
                attached_to: node.arn.clone(),
                policy_document: boundary.policy_doc.clone(),
            });
        }
    }
    // Group policies
    for group in &graph.groups {
        for policy in &group.attached_policies {
            cached_policies.push(cache::CachedPolicy {
                arn: policy.arn.clone(),
                name: policy.name.clone(),
                policy_type: "inline-group".to_string(),
                attached_to: group.arn.clone(),
                policy_document: policy.policy_doc.clone(),
            });
        }
    }
    if let Err(e) = cache::save_policies(&graph_root, &cached_policies) {
        tracing::warn!("Failed to save policy cache: {}", e);
    }
    tracing::info!("{} policy documents cached", cached_policies.len());

    Ok(graph)
}

/// Create a graph from a previously saved cache (fully offline).
/// Use when the AWS environment is no longer accessible.
pub fn create_graph_from_cache(
    graph_root: &std::path::Path,
    _checker_list: &[CheckerKind],
) -> Result<Graph> {
    if !cache::ApiCache::exists(graph_root) {
        return Err(crate::error::IamReconError::Other(format!(
            "No API cache found at {}. Run 'iam-recon graph create' first while connected to AWS.",
            graph_root.display()
        )));
    }

    tracing::info!("Loading graph from cache at {}", graph_root.display());

    // Load the persisted graph (this was saved by create_graph)
    let graph = Graph::load_from_disk(graph_root)?;

    tracing::info!(
        "Loaded graph: {} nodes, {} edges (offline mode)",
        graph.nodes.len(),
        graph.edges.len()
    );

    Ok(graph)
}

/// Parse IAM GetAccountAuthorizationDetails into nodes, groups, and policies
async fn get_nodes_groups_and_policies(
    sdk_config: &aws_config::SdkConfig,
) -> Result<(Vec<Arc<Node>>, Vec<Arc<Group>>, Vec<Arc<Policy>>)> {
    let iam_client = aws_sdk_iam::Client::new(sdk_config);

    let mut all_users: Vec<aws_sdk_iam::types::UserDetail> = Vec::new();
    let mut all_roles: Vec<aws_sdk_iam::types::RoleDetail> = Vec::new();
    let mut all_groups: Vec<aws_sdk_iam::types::GroupDetail> = Vec::new();
    let mut all_policies = Vec::new();
    let mut managed_policy_docs: HashMap<String, serde_json::Value> = HashMap::new();

    let mut paginator = iam_client
        .get_account_authorization_details()
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = page.map_err(error::aws_err)?;

        all_users.extend(page.user_detail_list().iter().cloned());
        all_roles.extend(page.role_detail_list().iter().cloned());
        all_groups.extend(page.group_detail_list().iter().cloned());
        for p in page.policies() {
            if let (Some(arn), Some(name)) = (p.arn(), p.policy_name()) {
                // Find the default version's document
                for v in p.policy_version_list() {
                    if v.is_default_version() {
                        if let Some(doc) = v.document() {
                            let decoded = urlencoding::decode(doc).unwrap_or_default();
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&decoded)
                            {
                                managed_policy_docs.insert(arn.to_string(), parsed.clone());
                                all_policies.push(Arc::new(Policy::new(arn, name, parsed)));
                            }
                        }
                    }
                }
            }
        }
    }

    // Build Group objects
    let mut group_objects: Vec<Arc<Group>> = Vec::new();
    let mut group_policy_map: HashMap<String, Vec<Arc<Policy>>> = HashMap::new();

    for g in &all_groups {
        let group_arn = g.arn().unwrap_or_default().to_string();
        let mut group_policies = Vec::new();

        // Inline policies
        for ip in g.group_policy_list() {
            if let (Some(name), Some(doc)) = (ip.policy_name(), ip.policy_document()) {
                let decoded = urlencoding::decode(doc).unwrap_or_default();
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&decoded) {
                    let policy = Arc::new(Policy::new(&group_arn, name, parsed));
                    all_policies.push(Arc::clone(&policy));
                    group_policies.push(policy);
                }
            }
        }

        // Attached managed policies
        for amp in g.attached_managed_policies() {
            if let Some(arn) = amp.policy_arn() {
                if let Some(doc) = managed_policy_docs.get(arn) {
                    let name = amp.policy_name().unwrap_or("unknown");
                    let policy = Arc::new(Policy::new(arn, name, doc.clone()));
                    group_policies.push(policy);
                }
            }
        }

        group_policy_map.insert(group_arn.clone(), group_policies.clone());
        group_objects.push(Arc::new(Group::new(group_arn, group_policies)));
    }

    let _group_map: HashMap<String, Arc<Group>> = group_objects
        .iter()
        .map(|g| (g.arn.clone(), Arc::clone(g)))
        .collect();

    // Build Node objects for users
    let mut nodes: Vec<Arc<Node>> = Vec::new();

    for user in &all_users {
        let user_arn = user.arn().unwrap_or_default().to_string();
        let mut user_policies = Vec::new();

        // Inline policies
        for ip in user.user_policy_list() {
            if let (Some(name), Some(doc)) = (ip.policy_name(), ip.policy_document()) {
                let decoded = urlencoding::decode(doc).unwrap_or_default();
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&decoded) {
                    let policy = Arc::new(Policy::new(&user_arn, name, parsed));
                    all_policies.push(Arc::clone(&policy));
                    user_policies.push(policy);
                }
            }
        }

        // Attached managed policies
        for amp in user.attached_managed_policies() {
            if let Some(arn) = amp.policy_arn() {
                if let Some(doc) = managed_policy_docs.get(arn) {
                    let name = amp.policy_name().unwrap_or("unknown");
                    let policy = Arc::new(Policy::new(arn, name, doc.clone()));
                    user_policies.push(policy);
                }
            }
        }

        // Group memberships
        let mut memberships = Vec::new();
        for group_name in user.group_list() {
            // Find group by name (need to match against known groups)
            for g in &group_objects {
                if g.arn.contains(&format!("group/{}", group_name)) {
                    memberships.push(Arc::clone(g));
                    break;
                }
            }
        }

        // Permissions boundary
        let permissions_boundary = user
            .permissions_boundary()
            .and_then(|pb| pb.permissions_boundary_arn())
            .and_then(|arn| {
                managed_policy_docs
                    .get(arn)
                    .map(|doc| Arc::new(Policy::new(arn, "PermissionsBoundary", doc.clone())))
            });

        // Tags
        let tags: HashMap<String, String> = user
            .tags()
            .iter()
            .map(|t| (t.key().to_string(), t.value().to_string()))
            .collect();

        nodes.push(Arc::new(Node {
            arn: user_arn,
            id_value: user.user_id().unwrap_or_default().to_string(),
            attached_policies: user_policies,
            group_memberships: memberships,
            trust_policy: None,
            instance_profile: None,
            active_password: false, // Will be detected separately
            access_keys: 0,         // Will be detected separately
            is_admin: false,
            permissions_boundary,
            has_mfa: false, // Will be detected separately
            tags,
        }));
    }

    // Build Node objects for roles
    for role in &all_roles {
        let role_arn = role.arn().unwrap_or_default().to_string();
        let mut role_policies = Vec::new();

        // Inline policies
        for ip in role.role_policy_list() {
            if let (Some(name), Some(doc)) = (ip.policy_name(), ip.policy_document()) {
                let decoded = urlencoding::decode(doc).unwrap_or_default();
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&decoded) {
                    let policy = Arc::new(Policy::new(&role_arn, name, parsed));
                    all_policies.push(Arc::clone(&policy));
                    role_policies.push(policy);
                }
            }
        }

        // Attached managed policies
        for amp in role.attached_managed_policies() {
            if let Some(arn) = amp.policy_arn() {
                if let Some(doc) = managed_policy_docs.get(arn) {
                    let name = amp.policy_name().unwrap_or("unknown");
                    let policy = Arc::new(Policy::new(arn, name, doc.clone()));
                    role_policies.push(policy);
                }
            }
        }

        // Trust policy
        let trust_policy = role.assume_role_policy_document().and_then(|doc| {
            let decoded = urlencoding::decode(doc).ok()?;
            serde_json::from_str::<serde_json::Value>(&decoded).ok()
        });

        // Instance profiles
        let ips: Vec<String> = role
            .instance_profile_list()
            .iter()
            .map(|ip| ip.arn().to_string())
            .collect();
        let instance_profile: Option<Vec<String>> = if ips.is_empty() { None } else { Some(ips) };

        // Permissions boundary
        let permissions_boundary = role
            .permissions_boundary()
            .and_then(|pb| pb.permissions_boundary_arn())
            .and_then(|arn| {
                managed_policy_docs
                    .get(arn)
                    .map(|doc| Arc::new(Policy::new(arn, "PermissionsBoundary", doc.clone())))
            });

        // Tags
        let tags: HashMap<String, String> = role
            .tags()
            .iter()
            .map(|t| (t.key().to_string(), t.value().to_string()))
            .collect();

        nodes.push(Arc::new(Node {
            arn: role_arn,
            id_value: role.role_id().unwrap_or_default().to_string(),
            attached_policies: role_policies,
            group_memberships: vec![],
            trust_policy,
            instance_profile,
            active_password: false,
            access_keys: 0,
            is_admin: false,
            permissions_boundary,
            has_mfa: false,
            tags,
        }));
    }

    Ok((nodes, group_objects, all_policies))
}
