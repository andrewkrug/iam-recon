use std::sync::Arc;

use crate::model::finding::{Finding, Severity};
use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::policy_eval::authorization;
use crate::policy_eval::resource_policy;
use crate::querying::presets::privesc;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Generate all findings for a graph
pub fn gen_all_findings(graph: &Graph) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(gen_privesc_findings(graph));
    findings.extend(gen_admin_users_without_mfa_finding(graph));
    findings.extend(gen_mfa_actions_findings(graph));
    findings.extend(gen_overprivileged_function_findings(graph));
    findings.extend(gen_overprivileged_instance_profile_findings(graph));
    findings.extend(gen_overprivileged_stack_findings(graph));
    findings.extend(gen_circular_access_finding(graph));
    // pathfinding.cloud — map dangerous privileges to known escalation paths
    findings.extend(crate::pathfinding::PathfindingMapper::generate_findings(
        graph,
    ));
    findings
}

/// Find non-admin nodes that can escalate to admin
fn gen_privesc_findings(graph: &Graph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for node in &graph.nodes {
        if node.is_admin {
            continue;
        }

        if let Some((can_esc, path)) = privesc::can_privesc(graph, node) {
            if can_esc {
                let hops = path.len();
                let dest = path
                    .last()
                    .map(|e| e.destination.clone())
                    .unwrap_or_default();

                findings.push(Finding::new(
                    format!(
                        "Privilege Escalation: {} -> {}",
                        node.searchable_name(),
                        dest
                    ),
                    Severity::High,
                    format!(
                        "{} can escalate to admin through {} hop(s)",
                        node.searchable_name(),
                        hops
                    ),
                    format!(
                        "Principal {} can reach admin principal {} through the following path:\n{}",
                        node.searchable_name(),
                        dest,
                        path.iter()
                            .map(|e| format!("  {}", e.describe()))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ),
                    "Review and restrict the permissions of the affected principals.",
                ));
            }
        }
    }

    findings
}

/// Find admin users without MFA
fn gen_admin_users_without_mfa_finding(graph: &Graph) -> Vec<Finding> {
    let mut findings = Vec::new();

    let admin_users_without_mfa: Vec<&Arc<Node>> = graph
        .nodes
        .iter()
        .filter(|n| {
            n.is_admin && n.is_user() && !n.has_mfa && (n.access_keys > 0 || n.active_password)
        })
        .collect();

    if !admin_users_without_mfa.is_empty() {
        let names: Vec<String> = admin_users_without_mfa
            .iter()
            .map(|n| n.searchable_name().to_string())
            .collect();

        findings.push(Finding::new(
            "Admin Users Without MFA",
            Severity::High,
            "Admin users without MFA can be compromised through credential theft",
            format!(
                "The following admin users do not have MFA enabled: {}",
                names.join(", ")
            ),
            "Enable MFA for all admin users.",
        ));
    }

    findings
}

/// Find admin users that can perform sensitive actions without MFA
fn gen_mfa_actions_findings(graph: &Graph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ctx = CaseInsensitiveMap::new();

    let sensitive_actions = [
        "iam:CreateUser",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
    ];

    for node in &graph.nodes {
        if !node.is_admin || !node.is_user() || !node.has_mfa {
            continue;
        }

        for action in &sensitive_actions {
            if authorization::local_check_authorization(node, action, "*", &ctx) {
                // Action allowed without MFA condition
                findings.push(Finding::new(
                    format!("No MFA Required for {}", action),
                    Severity::Medium,
                    format!(
                        "{} can call {} without MFA",
                        node.searchable_name(),
                        action
                    ),
                    format!(
                        "Admin user {} can perform the sensitive action {} without MFA verification.",
                        node.searchable_name(),
                        action
                    ),
                    format!(
                        "Add MFA condition to the policy granting {} to {}.",
                        action,
                        node.searchable_name()
                    ),
                ));
                break; // One finding per node
            }
        }
    }

    findings
}

/// Find Lambda execution roles with admin-level access
fn gen_overprivileged_function_findings(graph: &Graph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for node in &graph.nodes {
        if !node.is_role() || !node.is_admin {
            continue;
        }

        let trust_policy = match &node.trust_policy {
            Some(tp) => tp,
            None => continue,
        };

        if resource_policy::service_can_assume_role(trust_policy, "lambda.amazonaws.com") {
            findings.push(Finding::new(
                format!("Overprivileged Lambda Role: {}", node.searchable_name()),
                Severity::Medium,
                "Lambda function with admin access could be exploited",
                format!(
                    "Role {} is assumable by Lambda and has admin-level permissions.",
                    node.searchable_name()
                ),
                "Apply least-privilege permissions to Lambda execution roles.",
            ));
        }
    }

    findings
}

/// Find EC2 instance profiles with admin access
fn gen_overprivileged_instance_profile_findings(graph: &Graph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for node in &graph.nodes {
        if !node.is_role() || !node.is_admin {
            continue;
        }

        let trust_policy = match &node.trust_policy {
            Some(tp) => tp,
            None => continue,
        };

        let has_instance_profile = node
            .instance_profile
            .as_ref()
            .map_or(false, |ip| !ip.is_empty());

        if has_instance_profile
            && resource_policy::service_can_assume_role(trust_policy, "ec2.amazonaws.com")
        {
            findings.push(Finding::new(
                format!(
                    "Overprivileged Instance Profile: {}",
                    node.searchable_name()
                ),
                Severity::Medium,
                "EC2 instances with admin access could be exploited via SSRF or RCE",
                format!(
                    "Role {} has an instance profile and admin-level permissions.",
                    node.searchable_name()
                ),
                "Apply least-privilege permissions to EC2 instance roles.",
            ));
        }
    }

    findings
}

/// Find CloudFormation stack roles with admin access
fn gen_overprivileged_stack_findings(graph: &Graph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for node in &graph.nodes {
        if !node.is_role() || !node.is_admin {
            continue;
        }

        let trust_policy = match &node.trust_policy {
            Some(tp) => tp,
            None => continue,
        };

        if resource_policy::service_can_assume_role(trust_policy, "cloudformation.amazonaws.com") {
            findings.push(Finding::new(
                format!("Overprivileged Stack Role: {}", node.searchable_name()),
                Severity::Medium,
                "CloudFormation stack with admin role could be exploited",
                format!(
                    "Role {} is assumable by CloudFormation and has admin-level permissions.",
                    node.searchable_name()
                ),
                "Apply least-privilege permissions to CloudFormation stack roles.",
            ));
        }
    }

    findings
}

/// Find circular access patterns (A can reach B and B can reach A)
fn gen_circular_access_finding(graph: &Graph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut checked_pairs = std::collections::HashSet::new();

    for node_a in &graph.nodes {
        if node_a.is_admin {
            continue;
        }

        let outbound_a = graph.get_outbound_edges(node_a);
        for edge_ab in &outbound_a {
            if checked_pairs.contains(&(edge_ab.destination.clone(), node_a.arn.clone())) {
                continue;
            }

            let outbound_b = graph
                .get_node_by_arn(&edge_ab.destination)
                .map(|b| graph.get_outbound_edges(b))
                .unwrap_or_default();

            for edge_ba in &outbound_b {
                if edge_ba.destination == node_a.arn {
                    checked_pairs.insert((node_a.arn.clone(), edge_ab.destination.clone()));
                    findings.push(Finding::new(
                        format!(
                            "Circular Access: {} <-> {}",
                            node_a.searchable_name(),
                            edge_ab.destination
                        ),
                        Severity::Low,
                        "Circular privilege relationships may indicate misconfiguration",
                        format!(
                            "{} and {} can access each other, creating a circular relationship.",
                            node_a.searchable_name(),
                            edge_ab.destination
                        ),
                        "Review whether both directions of access are necessary.",
                    ));
                    break;
                }
            }
        }
    }

    findings
}
