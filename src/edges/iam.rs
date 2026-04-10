use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Generate edges for IAM-based privilege escalation:
/// - CreateAccessKey / UpdateLoginProfile for users
/// - UpdateAssumeRolePolicy for roles
pub fn generate_edges(nodes: &[Arc<Node>], scps: Option<&[Vec<&Policy>]>) -> Vec<Edge> {
    let mut edges = Vec::new();
    let ctx = CaseInsensitiveMap::new();

    for source in nodes {
        if source.is_admin {
            continue;
        }

        for dest in nodes {
            if source.arn == dest.arn {
                continue;
            }

            if dest.is_user() {
                // Check if source can create access key for destination user
                let dest_arn = &dest.arn;
                let (can_create_key, mfa_create) = local_check_authorization_handling_mfa(
                    source,
                    "iam:CreateAccessKey",
                    dest_arn,
                    &ctx,
                    scps,
                );

                if can_create_key {
                    // If dest has 2 keys, also need DeleteAccessKey
                    if dest.access_keys >= 2 {
                        let (can_delete, _) = local_check_authorization_handling_mfa(
                            source,
                            "iam:DeleteAccessKey",
                            dest_arn,
                            &ctx,
                            scps,
                        );
                        if can_delete {
                            let reason = if mfa_create {
                                format!(
                                    "{} can create access keys for {} after deleting one (MFA required)",
                                    source.searchable_name(), dest.searchable_name()
                                )
                            } else {
                                format!(
                                    "{} can create access keys for {} after deleting one",
                                    source.searchable_name(),
                                    dest.searchable_name()
                                )
                            };
                            edges.push(Edge::new(&source.arn, &dest.arn, reason, "IAM"));
                        }
                    } else {
                        let reason = if mfa_create {
                            format!(
                                "{} can create access keys for {} (MFA required)",
                                source.searchable_name(),
                                dest.searchable_name()
                            )
                        } else {
                            format!(
                                "{} can create access keys for {}",
                                source.searchable_name(),
                                dest.searchable_name()
                            )
                        };
                        edges.push(Edge::new(&source.arn, &dest.arn, reason, "IAM"));
                    }
                    continue; // Already found an edge, skip login profile check
                }

                // Check UpdateLoginProfile or CreateLoginProfile
                let (can_update_login, mfa_login) = if dest.active_password {
                    local_check_authorization_handling_mfa(
                        source,
                        "iam:UpdateLoginProfile",
                        dest_arn,
                        &ctx,
                        scps,
                    )
                } else {
                    local_check_authorization_handling_mfa(
                        source,
                        "iam:CreateLoginProfile",
                        dest_arn,
                        &ctx,
                        scps,
                    )
                };

                if can_update_login {
                    let action = if dest.active_password {
                        "update the login profile for"
                    } else {
                        "create a login profile for"
                    };
                    let reason = if mfa_login {
                        format!(
                            "{} can {} {} (MFA required)",
                            source.searchable_name(),
                            action,
                            dest.searchable_name()
                        )
                    } else {
                        format!(
                            "{} can {} {}",
                            source.searchable_name(),
                            action,
                            dest.searchable_name()
                        )
                    };
                    edges.push(Edge::new(&source.arn, &dest.arn, reason, "IAM"));
                }
            } else if dest.is_role() {
                // Check if source can update the trust policy
                let (can_update_trust, mfa_trust) = local_check_authorization_handling_mfa(
                    source,
                    "iam:UpdateAssumeRolePolicy",
                    &dest.arn,
                    &ctx,
                    scps,
                );

                if can_update_trust {
                    let reason = if mfa_trust {
                        format!(
                            "{} can update the trust policy of {} (MFA required)",
                            source.searchable_name(),
                            dest.searchable_name()
                        )
                    } else {
                        format!(
                            "{} can update the trust policy of {}",
                            source.searchable_name(),
                            dest.searchable_name()
                        )
                    };
                    edges.push(Edge::new(&source.arn, &dest.arn, reason, "IAM"));
                }
            }
        }
    }

    edges
}
