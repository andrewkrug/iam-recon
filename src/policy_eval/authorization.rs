use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::context_keys;
use crate::policy_eval::resource_policy::{self, ResourcePolicyEvalResult};
use crate::policy_eval::statement_match;
use crate::util::arns;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Simple authorization check: can this node perform this action on this resource?
/// Does not consider resource policies, SCPs, or session policies.
pub fn local_check_authorization(
    node: &Node,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
) -> bool {
    let ctx = context_keys::prepare_condition_context(node, condition_keys);

    // Check for explicit deny first
    if statement_match::has_matching_statement(node, "Deny", action, resource, &ctx) {
        return false;
    }

    // Check permissions boundary
    if let Some(ref boundary) = node.permissions_boundary {
        if !statement_match::policy_has_matching_statement(
            boundary, "Allow", action, resource, &ctx,
        ) {
            return false;
        }
        if statement_match::policy_has_matching_statement(boundary, "Deny", action, resource, &ctx)
        {
            return false;
        }
    }

    // Check for allow
    statement_match::has_matching_statement(node, "Allow", action, resource, &ctx)
}

/// Full authorization check including resource policies, SCPs, and session policies.
/// Follows AWS IAM evaluation logic:
/// 1. Explicit Deny in any policy -> Deny
/// 2. SCP Deny -> Deny
/// 3. SCP must Allow (unless service-linked role)
/// 4. Resource policy Allow -> Allow (for same-account)
/// 5. Permissions boundary must Allow
/// 6. Session policy must Allow (if present)
/// 7. Identity policy must Allow
pub fn local_check_authorization_full(
    node: &Node,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
    resource_policy: Option<&serde_json::Value>,
    resource_owner: Option<&str>,
    scps: Option<&[Vec<&Policy>]>,
    session_policy: Option<&Policy>,
) -> bool {
    let ctx = context_keys::prepare_condition_context(node, condition_keys);
    let resource_account = resource_owner.unwrap_or_else(|| arns::get_account_id(resource));

    // Step 1: Check explicit Deny across all policies
    if statement_match::has_matching_statement(node, "Deny", action, resource, &ctx) {
        return false;
    }

    // Check session policy deny
    if let Some(sp) = session_policy {
        if statement_match::policy_has_matching_statement(sp, "Deny", action, resource, &ctx) {
            return false;
        }
    }

    // Check permission boundary deny
    if let Some(ref boundary) = node.permissions_boundary {
        if statement_match::policy_has_matching_statement(boundary, "Deny", action, resource, &ctx)
        {
            return false;
        }
    }

    // Step 2: SCP evaluation
    if let Some(scp_groups) = scps {
        // Service-linked roles are exempt from SCPs
        let is_service_linked = node.searchable_name().contains("AWSServiceRoleFor");

        if !is_service_linked {
            // Check SCP denies
            for group in scp_groups {
                for scp in group {
                    if statement_match::policy_has_matching_statement(
                        scp, "Deny", action, resource, &ctx,
                    ) {
                        return false;
                    }
                }
            }

            // Each SCP group must have at least one Allow
            for group in scp_groups {
                let any_allow = group.iter().any(|scp| {
                    statement_match::policy_has_matching_statement(
                        scp, "Allow", action, resource, &ctx,
                    )
                });
                if !any_allow {
                    return false;
                }
            }
        }
    }

    // Step 3: Resource policy evaluation
    if let Some(rp) = resource_policy {
        let rp_result = resource_policy::resource_policy_authorization(
            node,
            resource_account,
            rp,
            action,
            resource,
            &ctx,
        );

        match rp_result {
            ResourcePolicyEvalResult::DenyMatch => return false,
            ResourcePolicyEvalResult::NodeMatch => return true,
            ResourcePolicyEvalResult::ServiceMatch => return true,
            _ => {} // Continue to identity policy checks
        }
    }

    // Step 4: Permissions boundary must allow
    if let Some(ref boundary) = node.permissions_boundary {
        if !statement_match::policy_has_matching_statement(
            boundary, "Allow", action, resource, &ctx,
        ) {
            return false;
        }
    }

    // Step 5: Session policy must allow (if present)
    if let Some(sp) = session_policy {
        if !statement_match::policy_has_matching_statement(sp, "Allow", action, resource, &ctx) {
            return false;
        }
    }

    // Step 6: Identity policy must allow
    statement_match::has_matching_statement(node, "Allow", action, resource, &ctx)
}

/// Authorization check that also considers MFA.
/// Returns (authorized, needs_mfa):
/// - (true, false) = authorized without MFA
/// - (true, true) = authorized only with MFA
/// - (false, false) = not authorized
pub fn local_check_authorization_handling_mfa(
    node: &Node,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
    scps: Option<&[Vec<&Policy>]>,
) -> (bool, bool) {
    // Check without MFA first
    let without_mfa = local_check_authorization_full(
        node,
        action,
        resource,
        condition_keys,
        None,
        None,
        scps,
        None,
    );

    if without_mfa {
        return (true, false);
    }

    // Check with MFA
    if node.has_mfa && node.is_user() {
        let mfa_ctx = context_keys::prepare_mfa_context(node, condition_keys);
        let with_mfa = local_check_authorization_full(
            node, action, resource, &mfa_ctx, None, None, scps, None,
        );
        if with_mfa {
            return (true, true);
        }
    }

    (false, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn admin_node() -> Node {
        Node {
            arn: "arn:aws:iam::123456789012:user/Admin".into(),
            id_value: "AIDA00000000000000001".into(),
            attached_policies: vec![Arc::new(Policy::new(
                "arn:aws:iam::aws:policy/AdministratorAccess",
                "AdministratorAccess",
                serde_json::json!({
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }]
                }),
            ))],
            group_memberships: vec![],
            trust_policy: None,
            instance_profile: None,
            active_password: true,
            access_keys: 1,
            is_admin: true,
            permissions_boundary: None,
            has_mfa: true,
            tags: Default::default(),
        }
    }

    #[test]
    fn test_admin_allowed() {
        let node = admin_node();
        let ctx = CaseInsensitiveMap::new();
        assert!(local_check_authorization(
            &node,
            "iam:CreateUser",
            "*",
            &ctx
        ));
        assert!(local_check_authorization(
            &node,
            "s3:GetObject",
            "arn:aws:s3:::any-bucket/key",
            &ctx
        ));
    }

    #[test]
    fn test_explicit_deny_overrides() {
        let node = Node {
            arn: "arn:aws:iam::123456789012:user/Test".into(),
            id_value: "AIDA00000000000000002".into(),
            attached_policies: vec![
                Arc::new(Policy::new(
                    "p1",
                    "allow-all",
                    serde_json::json!({
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    }),
                )),
                Arc::new(Policy::new(
                    "p2",
                    "deny-delete",
                    serde_json::json!({
                        "Statement": [{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]
                    }),
                )),
            ],
            group_memberships: vec![],
            trust_policy: None,
            instance_profile: None,
            active_password: false,
            access_keys: 0,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: Default::default(),
        };
        let ctx = CaseInsensitiveMap::new();
        assert!(local_check_authorization(&node, "s3:GetObject", "*", &ctx));
        assert!(!local_check_authorization(
            &node,
            "s3:DeleteBucket",
            "*",
            &ctx
        ));
    }

    #[test]
    fn test_mfa_handling() {
        let node = Node {
            arn: "arn:aws:iam::123456789012:user/MfaUser".into(),
            id_value: "AIDA00000000000000003".into(),
            attached_policies: vec![Arc::new(Policy::new(
                "p1",
                "mfa-only",
                serde_json::json!({
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "iam:*",
                        "Resource": "*",
                        "Condition": {
                            "Bool": { "aws:MultiFactorAuthPresent": "true" }
                        }
                    }]
                }),
            ))],
            group_memberships: vec![],
            trust_policy: None,
            instance_profile: None,
            active_password: true,
            access_keys: 1,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: true,
            tags: Default::default(),
        };
        let ctx = CaseInsensitiveMap::new();
        let (auth, mfa_needed) =
            local_check_authorization_handling_mfa(&node, "iam:GetUser", "*", &ctx, None);
        assert!(auth);
        assert!(mfa_needed);
    }
}
