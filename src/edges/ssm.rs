use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::policy_eval::resource_policy;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Generate SSM-based edges.
/// If source can send commands or start sessions on instances running with dest role.
pub fn generate_edges(nodes: &[Arc<Node>], scps: Option<&[Vec<&Policy>]>) -> Vec<Edge> {
    let mut edges = Vec::new();
    let empty_ctx = CaseInsensitiveMap::new();

    for dest in nodes {
        if !dest.is_role() {
            continue;
        }

        let trust_policy = match &dest.trust_policy {
            Some(tp) => tp,
            None => continue,
        };

        // Dest role must be assumable by EC2 and have an instance profile
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

        // Check if dest role can create SSM control channel (i.e., SSM agent can run)
        let (can_ssm, _) = local_check_authorization_handling_mfa(
            dest,
            "ssmmessages:CreateControlChannel",
            "*",
            &empty_ctx,
            None,
        );
        if !can_ssm {
            continue;
        }

        for source in nodes {
            if source.arn == dest.arn || source.is_admin {
                continue;
            }

            // Check ssm:SendCommand
            let (can_send, _) = local_check_authorization_handling_mfa(
                source,
                "ssm:SendCommand",
                "*",
                &empty_ctx,
                scps,
            );
            if can_send {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can send SSM commands to instances with {}",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "SSM",
                ));
                continue;
            }

            // Check ssm:StartSession
            let (can_session, _) = local_check_authorization_handling_mfa(
                source,
                "ssm:StartSession",
                "*",
                &empty_ctx,
                scps,
            );
            if can_session {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can start SSM sessions on instances with {}",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "SSM",
                ));
            }
        }
    }

    edges
}
