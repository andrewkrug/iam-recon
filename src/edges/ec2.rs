use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::policy_eval::resource_policy;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Generate edges for EC2-based privilege escalation:
/// Source can launch an EC2 instance with destination role's instance profile.
pub fn generate_edges(nodes: &[Arc<Node>], scps: Option<&[Vec<&Policy>]>) -> Vec<Edge> {
    let mut edges = Vec::new();

    for dest in nodes {
        if !dest.is_role() {
            continue;
        }

        // Check if EC2 can assume this role
        let trust_policy = match &dest.trust_policy {
            Some(tp) => tp,
            None => continue,
        };
        if !resource_policy::service_can_assume_role(trust_policy, "ec2.amazonaws.com") {
            continue;
        }

        for source in nodes {
            if source.arn == dest.arn || source.is_admin {
                continue;
            }

            let mut pass_role_ctx = CaseInsensitiveMap::new();
            pass_role_ctx.insert_single("iam:PassedToService", "ec2.amazonaws.com");

            // Check iam:PassRole
            let (can_pass, _) = local_check_authorization_handling_mfa(
                source,
                "iam:PassRole",
                &dest.arn,
                &pass_role_ctx,
                scps,
            );
            if !can_pass {
                continue;
            }

            let empty_ctx = CaseInsensitiveMap::new();

            // Check ec2:RunInstances
            let (can_run, mfa_needed) = local_check_authorization_handling_mfa(
                source,
                "ec2:RunInstances",
                "*",
                &empty_ctx,
                scps,
            );

            if can_run {
                let reason = if mfa_needed {
                    format!(
                        "{} can launch EC2 instances with {} (MFA required)",
                        source.searchable_name(),
                        dest.searchable_name()
                    )
                } else {
                    format!(
                        "{} can launch EC2 instances with {}",
                        source.searchable_name(),
                        dest.searchable_name()
                    )
                };
                edges.push(Edge::new(&source.arn, &dest.arn, reason, "EC2"));
                continue;
            }

            // Alternative: create instance profile + associate
            let has_instance_profile = dest
                .instance_profile
                .as_ref()
                .map_or(false, |ip| !ip.is_empty());
            if !has_instance_profile {
                let (can_create_ip, _) = local_check_authorization_handling_mfa(
                    source,
                    "iam:CreateInstanceProfile",
                    "*",
                    &empty_ctx,
                    scps,
                );
                let (can_add_role, _) = local_check_authorization_handling_mfa(
                    source,
                    "iam:AddRoleToInstanceProfile",
                    "*",
                    &empty_ctx,
                    scps,
                );
                if can_create_ip && can_add_role {
                    let (can_run2, _) = local_check_authorization_handling_mfa(
                        source,
                        "ec2:RunInstances",
                        "*",
                        &empty_ctx,
                        scps,
                    );
                    if can_run2 {
                        edges.push(Edge::new(
                            &source.arn,
                            &dest.arn,
                            format!(
                                "{} can create an instance profile, attach {}, and launch an instance",
                                source.searchable_name(), dest.searchable_name()
                            ),
                            "EC2",
                        ));
                    }
                }
            }
        }
    }

    edges
}
