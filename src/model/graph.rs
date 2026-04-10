use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::edge::Edge;
use super::group::{Group, GroupData};
use super::node::{Node, NodeData};
use super::policy::Policy;
use crate::error::{IamReconError, Result};

pub const IAM_RECON_VERSION: &str = "1.1.5";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMetadata {
    pub account_id: String,
    #[serde(alias = "pmapper_version")]
    pub iam_recon_version: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// The main graph container holding all IAM analysis data
pub struct Graph {
    pub nodes: Vec<Arc<Node>>,
    pub edges: Vec<Edge>,
    pub policies: Vec<Arc<Policy>>,
    pub groups: Vec<Arc<Group>>,
    pub metadata: GraphMetadata,
    // Lookup indexes
    node_by_arn: HashMap<String, Arc<Node>>,
    node_by_searchable_name: HashMap<String, Arc<Node>>,
}

impl Graph {
    pub fn new(
        nodes: Vec<Arc<Node>>,
        edges: Vec<Edge>,
        policies: Vec<Arc<Policy>>,
        groups: Vec<Arc<Group>>,
        metadata: GraphMetadata,
    ) -> Self {
        let mut node_by_arn = HashMap::new();
        let mut node_by_searchable_name = HashMap::new();
        for node in &nodes {
            node_by_arn.insert(node.arn.clone(), Arc::clone(node));
            node_by_searchable_name.insert(node.searchable_name().to_string(), Arc::clone(node));
        }
        Self {
            nodes,
            edges,
            policies,
            groups,
            metadata,
            node_by_arn,
            node_by_searchable_name,
        }
    }

    pub fn get_node_by_arn(&self, arn: &str) -> Option<&Arc<Node>> {
        self.node_by_arn.get(arn)
    }

    pub fn get_node_by_searchable_name(&self, name: &str) -> Option<&Arc<Node>> {
        self.node_by_searchable_name.get(name)
    }

    /// Get outbound edges from a given node
    pub fn get_outbound_edges(&self, node: &Node) -> Vec<&Edge> {
        self.edges.iter().filter(|e| e.source == node.arn).collect()
    }

    /// Get inbound edges to a given node
    pub fn get_inbound_edges(&self, node: &Node) -> Vec<&Edge> {
        self.edges
            .iter()
            .filter(|e| e.destination == node.arn)
            .collect()
    }

    /// Store graph as JSON files on disk (Python-compatible format)
    ///
    /// Directory layout:
    /// ```text
    /// root/
    ///   metadata.json
    ///   graph/
    ///     nodes.json
    ///     edges.json
    ///     policies.json
    ///     groups.json
    /// ```
    pub fn store_to_disk(&self, root: &Path) -> Result<()> {
        let graph_dir = root.join("graph");
        std::fs::create_dir_all(&graph_dir)?;

        // metadata.json
        let metadata_json = serde_json::to_string_pretty(&self.metadata)?;
        std::fs::write(root.join("metadata.json"), metadata_json)?;

        // nodes.json
        let nodes_data: Vec<NodeData> = self.nodes.iter().map(|n| n.to_data()).collect();
        let nodes_json = serde_json::to_string_pretty(&nodes_data)?;
        std::fs::write(graph_dir.join("nodes.json"), nodes_json)?;

        // edges.json
        let edges_json = serde_json::to_string_pretty(&self.edges)?;
        std::fs::write(graph_dir.join("edges.json"), edges_json)?;

        // policies.json
        let policies_json = serde_json::to_string_pretty(
            &self.policies.iter().map(|p| p.as_ref()).collect::<Vec<_>>(),
        )?;
        std::fs::write(graph_dir.join("policies.json"), policies_json)?;

        // groups.json
        let groups_data: Vec<GroupData> = self.groups.iter().map(|g| g.to_data()).collect();
        let groups_json = serde_json::to_string_pretty(&groups_data)?;
        std::fs::write(graph_dir.join("groups.json"), groups_json)?;

        Ok(())
    }

    /// Load graph from JSON files on disk
    pub fn load_from_disk(root: &Path) -> Result<Self> {
        let metadata_path = root.join("metadata.json");
        if !metadata_path.exists() {
            return Err(IamReconError::Other(format!(
                "No graph found at {}\n\nRun 'iam-recon graph create --profile <profile>' first to scan an AWS account.",
                root.display()
            )));
        }

        let graph_dir = root.join("graph");

        // Load metadata
        let metadata: GraphMetadata =
            serde_json::from_str(&std::fs::read_to_string(&metadata_path)?)?;

        // Version compatibility check (major.minor must match)
        let stored_parts: Vec<&str> = metadata.iam_recon_version.splitn(3, '.').collect();
        let current_parts: Vec<&str> = IAM_RECON_VERSION.splitn(3, '.').collect();
        if stored_parts.len() >= 2
            && current_parts.len() >= 2
            && (stored_parts[0] != current_parts[0] || stored_parts[1] != current_parts[1])
        {
            return Err(IamReconError::VersionMismatch {
                stored: metadata.iam_recon_version.clone(),
                current: IAM_RECON_VERSION.to_string(),
            });
        }

        // Load policies first (no dependencies)
        let policies_data: Vec<Policy> =
            serde_json::from_str(&std::fs::read_to_string(graph_dir.join("policies.json"))?)?;
        let policies: Vec<Arc<Policy>> = policies_data.into_iter().map(Arc::new).collect();

        // Build policy lookup
        let policy_map: HashMap<(String, String), Arc<Policy>> = policies
            .iter()
            .map(|p| ((p.arn.clone(), p.name.clone()), Arc::clone(p)))
            .collect();

        // Load groups and resolve policy references
        let groups_data: Vec<GroupData> =
            serde_json::from_str(&std::fs::read_to_string(graph_dir.join("groups.json"))?)?;
        let groups: Vec<Arc<Group>> = groups_data
            .into_iter()
            .map(|gd| {
                let attached = gd
                    .attached_policies
                    .iter()
                    .filter_map(|pr| policy_map.get(&(pr.arn.clone(), pr.name.clone())))
                    .cloned()
                    .collect();
                Arc::new(Group {
                    arn: gd.arn,
                    attached_policies: attached,
                })
            })
            .collect();

        // Build group lookup
        let group_map: HashMap<String, Arc<Group>> = groups
            .iter()
            .map(|g| (g.arn.clone(), Arc::clone(g)))
            .collect();

        // Load nodes and resolve references
        let nodes_data: Vec<NodeData> =
            serde_json::from_str(&std::fs::read_to_string(graph_dir.join("nodes.json"))?)?;
        let nodes: Vec<Arc<Node>> = nodes_data
            .into_iter()
            .map(|nd| {
                let attached_policies = nd
                    .attached_policies
                    .iter()
                    .filter_map(|pr| policy_map.get(&(pr.arn.clone(), pr.name.clone())))
                    .cloned()
                    .collect();
                let group_memberships = nd
                    .group_memberships
                    .iter()
                    .filter_map(|g_arn| group_map.get(g_arn))
                    .cloned()
                    .collect();
                let permissions_boundary = nd
                    .permissions_boundary
                    .as_ref()
                    .and_then(|pr| policy_map.get(&(pr.arn.clone(), pr.name.clone())))
                    .cloned();
                Arc::new(Node {
                    arn: nd.arn,
                    id_value: nd.id_value,
                    attached_policies,
                    group_memberships,
                    trust_policy: nd.trust_policy,
                    instance_profile: nd.instance_profile,
                    active_password: nd.active_password,
                    access_keys: nd.access_keys,
                    is_admin: nd.is_admin,
                    permissions_boundary,
                    has_mfa: nd.has_mfa,
                    tags: nd.tags,
                })
            })
            .collect();

        // Load edges
        let edges: Vec<Edge> =
            serde_json::from_str(&std::fs::read_to_string(graph_dir.join("edges.json"))?)?;

        Ok(Graph::new(nodes, edges, policies, groups, metadata))
    }
}
