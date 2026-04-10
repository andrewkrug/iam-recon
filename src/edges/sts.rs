use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::policy_eval::resource_policy::{self, ResourcePolicyEvalResult};
use crate::util::arns;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Generate edges for STS AssumeRole-based privilege escalation.
/// Checks both the trust policy (resource policy) and the source's identity policy.
pub fn generate_edges(nodes: &[Arc<Node>], scps: Option<&[Vec<&Policy>]>) -> Vec<Edge> {
    let mut edges = Vec::new();
    let ctx = CaseInsensitiveMap::new();

    for dest in nodes {
        // Only roles can be assumed
        if !dest.is_role() {
            continue;
        }

        let trust_policy = match &dest.trust_policy {
            Some(tp) => tp,
            None => continue,
        };

        let dest_account = arns::get_account_id(&dest.arn);

        for source in nodes {
            if source.arn == dest.arn {
                continue;
            }
            if source.is_admin {
                continue;
            }

            // Step 1: Evaluate the trust policy (resource policy)
            let rp_result = resource_policy::resource_policy_authorization(
                source,
                dest_account,
                trust_policy,
                "sts:AssumeRole",
                &dest.arn,
                &ctx,
            );

            match rp_result {
                ResourcePolicyEvalResult::DenyMatch => continue,
                ResourcePolicyEvalResult::NoMatch => continue,
                ResourcePolicyEvalResult::NodeMatch => {
                    // Trust policy explicitly allows this node
                    // Check for explicit deny in identity policy
                    let (can_assume, mfa_needed) = local_check_authorization_handling_mfa(
                        source,
                        "sts:AssumeRole",
                        &dest.arn,
                        &ctx,
                        scps,
                    );
                    // For NodeMatch, trust policy is sufficient even without identity policy allow
                    // but identity policy deny still blocks
                    if !has_explicit_deny(source, "sts:AssumeRole", &dest.arn, &ctx) {
                        let reason = if mfa_needed && can_assume {
                            format!(
                                "{} can assume {} (MFA required)",
                                source.searchable_name(),
                                dest.searchable_name()
                            )
                        } else {
                            format!(
                                "{} can assume {}",
                                source.searchable_name(),
                                dest.searchable_name()
                            )
                        };
                        edges.push(Edge::new(&source.arn, &dest.arn, reason, "STS"));
                    }
                }
                ResourcePolicyEvalResult::RootMatch
                | ResourcePolicyEvalResult::DiffAccountMatch => {
                    // Trust policy allows account root or cross-account
                    // Identity policy must also allow
                    let (can_assume, mfa_needed) = local_check_authorization_handling_mfa(
                        source,
                        "sts:AssumeRole",
                        &dest.arn,
                        &ctx,
                        scps,
                    );
                    if can_assume {
                        let reason = if mfa_needed {
                            format!(
                                "{} can assume {} (MFA required)",
                                source.searchable_name(),
                                dest.searchable_name()
                            )
                        } else {
                            format!(
                                "{} can assume {}",
                                source.searchable_name(),
                                dest.searchable_name()
                            )
                        };
                        edges.push(Edge::new(&source.arn, &dest.arn, reason, "STS"));
                    }
                }
                ResourcePolicyEvalResult::ServiceMatch => {
                    // Service principals can assume, not relevant for user→role edges
                }
            }
        }
    }

    edges
}

fn has_explicit_deny(
    node: &Node,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
) -> bool {
    use crate::policy_eval::statement_match;
    let ctx = crate::policy_eval::context_keys::prepare_condition_context(node, condition_keys);
    statement_match::has_matching_statement(node, "Deny", action, resource, &ctx)
}
