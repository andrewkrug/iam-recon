//! Maps IAM privileges found on principals to known pathfinding.cloud escalation paths.

use std::collections::HashMap;
use std::sync::Arc;

use crate::model::finding::{Finding, Severity};
use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::policy_eval::authorization;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

use super::paths::{EscalationCategory, EscalationPath, ALL_PATHS};

/// Result of mapping a principal's permissions against pathfinding.cloud
#[derive(Debug, Clone)]
pub struct PathMatch {
    pub path: EscalationPath,
    pub node_arn: String,
    pub node_name: String,
    /// Which required permissions the principal actually has
    pub matched_permissions: Vec<String>,
    /// Whether ALL required permissions are present (full match)
    pub full_match: bool,
}

/// Maps graph principals to known pathfinding.cloud escalation paths.
pub struct PathfindingMapper;

impl PathfindingMapper {
    /// Check a single node against all pathfinding.cloud paths.
    /// Returns paths where the node has ALL required permissions.
    pub fn check_node(node: &Node) -> Vec<PathMatch> {
        let ctx = CaseInsensitiveMap::new();
        let mut matches = Vec::new();

        for path in ALL_PATHS.iter() {
            if path.permissions.is_empty() {
                continue;
            }

            let mut matched = Vec::new();
            let mut all_match = true;

            for perm in &path.permissions {
                // Split permission into service:action
                let authorized = authorization::local_check_authorization(node, perm, "*", &ctx);
                if authorized {
                    matched.push(perm.clone());
                } else {
                    all_match = false;
                }
            }

            if all_match && !matched.is_empty() {
                matches.push(PathMatch {
                    path: path.clone(),
                    node_arn: node.arn.clone(),
                    node_name: node.searchable_name().to_string(),
                    matched_permissions: matched,
                    full_match: true,
                });
            }
        }

        matches
    }

    /// Check all nodes in a graph and return all matches.
    pub fn check_graph(graph: &Graph) -> Vec<PathMatch> {
        let mut all_matches = Vec::new();
        for node in &graph.nodes {
            if node.is_admin {
                continue; // Admins trivially match everything
            }
            all_matches.extend(Self::check_node(node));
        }
        all_matches
    }

    /// Generate findings from pathfinding.cloud matches.
    pub fn generate_findings(graph: &Graph) -> Vec<Finding> {
        let matches = Self::check_graph(graph);
        let mut findings = Vec::new();

        // Group matches by node
        let mut by_node: HashMap<String, Vec<&PathMatch>> = HashMap::new();
        for m in &matches {
            by_node.entry(m.node_arn.clone()).or_default().push(m);
        }

        for (_node_arn, node_matches) in &by_node {
            let node_name = &node_matches[0].node_name;

            // Generate one finding per path match
            for m in node_matches {
                let severity = match m.path.category {
                    EscalationCategory::SelfEscalation => Severity::High,
                    EscalationCategory::PrincipalAccess => Severity::High,
                    EscalationCategory::NewPassrole => Severity::High,
                    EscalationCategory::ExistingPassrole => Severity::Medium,
                    EscalationCategory::CredentialAccess => Severity::Medium,
                };

                findings.push(Finding::new(
                    format!("[{}] {} — {}", m.path.id, node_name, m.path.name),
                    severity,
                    format!(
                        "{} has permissions for privilege escalation path {} ({})",
                        node_name, m.path.id, m.path.category
                    ),
                    format!(
                        "{}\n\nMatched permissions: {}\n\nPathfinding.cloud: {}",
                        m.path.description,
                        m.matched_permissions.join(", "),
                        m.path.url(),
                    ),
                    if m.path.recommendation.is_empty() {
                        format!(
                            "Restrict access to: {}. See {} for details.",
                            m.matched_permissions.join(", "),
                            m.path.url(),
                        )
                    } else {
                        format!("{}\n\nRef: {}", m.path.recommendation, m.path.url())
                    },
                ));
            }
        }

        findings
    }

    /// Print a summary of all pathfinding.cloud matches for a graph.
    pub fn print_report(graph: &Graph) {
        let matches = Self::check_graph(graph);

        if matches.is_empty() {
            println!("  No pathfinding.cloud escalation paths matched.");
            return;
        }

        // Group by category
        let mut by_category: HashMap<EscalationCategory, Vec<&PathMatch>> = HashMap::new();
        for m in &matches {
            by_category.entry(m.path.category).or_default().push(m);
        }

        let categories = [
            EscalationCategory::SelfEscalation,
            EscalationCategory::PrincipalAccess,
            EscalationCategory::NewPassrole,
            EscalationCategory::ExistingPassrole,
            EscalationCategory::CredentialAccess,
        ];

        println!(
            "  {} escalation paths matched across {} principals",
            matches.len(),
            matches
                .iter()
                .map(|m| &m.node_arn)
                .collect::<std::collections::HashSet<_>>()
                .len()
        );
        println!();

        for cat in &categories {
            if let Some(cat_matches) = by_category.get(cat) {
                println!("  [{}] ({} matches)", cat, cat_matches.len());
                for m in cat_matches {
                    println!("    {} — {} ({})", m.path.id, m.node_name, m.path.name);
                }
                println!();
            }
        }
    }

    /// Get the total number of bundled paths (for diagnostics).
    pub fn path_count() -> usize {
        ALL_PATHS.len()
    }
}
