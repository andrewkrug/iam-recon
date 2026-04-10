use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::policy_eval::resource_policy;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

pub fn generate_edges(nodes: &[Arc<Node>], scps: Option<&[Vec<&Policy>]>) -> Vec<Edge> {
    let mut edges = Vec::new();

    for dest in nodes {
        if !dest.is_role() {
            continue;
        }
        let trust_policy = match &dest.trust_policy {
            Some(tp) => tp,
            None => continue,
        };
        if !resource_policy::service_can_assume_role(trust_policy, "ec2.amazonaws.com") {
            continue;
        }

        let has_instance_profile = dest
            .instance_profile
            .as_ref()
            .map_or(false, |ip| !ip.is_empty());
        if !has_instance_profile {
            continue;
        }

        for source in nodes {
            if source.arn == dest.arn || source.is_admin {
                continue;
            }

            let empty_ctx = CaseInsensitiveMap::new();

            // Check if source can create autoscaling group
            let (can_create_asg, _) = local_check_authorization_handling_mfa(
                source,
                "autoscaling:CreateAutoScalingGroup",
                "*",
                &empty_ctx,
                scps,
            );
            if !can_create_asg {
                continue;
            }

            // Check if source can create launch configuration
            let (can_create_lc, _) = local_check_authorization_handling_mfa(
                source,
                "autoscaling:CreateLaunchConfiguration",
                "*",
                &empty_ctx,
                scps,
            );

            // Check service linked role
            let (has_slr, _) = local_check_authorization_handling_mfa(
                source,
                "iam:CreateServiceLinkedRole",
                "*",
                &empty_ctx,
                scps,
            );

            if can_create_lc && has_slr {
                let mut pass_ctx = CaseInsensitiveMap::new();
                pass_ctx.insert_single("iam:PassedToService", "ec2.amazonaws.com");
                let (can_pass, _) = local_check_authorization_handling_mfa(
                    source,
                    "iam:PassRole",
                    &dest.arn,
                    &pass_ctx,
                    scps,
                );
                if can_pass {
                    edges.push(Edge::new(
                        &source.arn,
                        &dest.arn,
                        format!(
                            "{} can create an auto-scaling group with {}",
                            source.searchable_name(),
                            dest.searchable_name()
                        ),
                        "AutoScaling",
                    ));
                }
            }
        }
    }

    edges
}
