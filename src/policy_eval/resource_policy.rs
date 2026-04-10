use serde_json::Value;

use crate::model::node::Node;
use crate::policy_eval::condition;
use crate::policy_eval::wildcard;
use crate::util::arns;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Result of evaluating a resource-based policy (e.g., trust policy)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePolicyEvalResult {
    /// No matching statement found
    NoMatch,
    /// Explicit Deny found
    DenyMatch,
    /// Root account principal matched
    RootMatch,
    /// Specific node (user/role) matched
    NodeMatch,
    /// Different account principal matched
    DiffAccountMatch,
    /// Service principal matched (e.g., lambda.amazonaws.com)
    ServiceMatch,
}

/// Evaluate a resource-based policy (trust policy, bucket policy, etc.)
/// against a principal trying to perform an action.
pub fn resource_policy_authorization(
    node: &Node,
    account_id: &str,
    resource_policy: &Value,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
) -> ResourcePolicyEvalResult {
    let statements = match resource_policy.get("Statement") {
        Some(Value::Array(arr)) => arr.iter().collect::<Vec<_>>(),
        Some(stmt) => vec![stmt],
        None => return ResourcePolicyEvalResult::NoMatch,
    };

    // Collect matching statements
    let mut allow_matches = Vec::new();
    let mut has_deny = false;

    for stmt in &statements {
        let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");

        // Check action match
        if !action_matches_stmt(stmt, action) {
            continue;
        }

        // Check resource match (if present)
        if let Some(resources) = stmt.get("Resource") {
            let patterns = get_string_or_list(resources);
            if !patterns
                .iter()
                .any(|p| wildcard::resource_matches(p, resource))
            {
                continue;
            }
        }

        // Check condition
        if let Some(cond) = stmt.get("Condition") {
            if !condition::evaluate_condition_block(cond, condition_keys) {
                continue;
            }
        }

        // Check principal match
        let principal_match = principal_matches(stmt, node, account_id);
        if principal_match == PrincipalMatchResult::NoMatch {
            continue;
        }

        if effect.eq_ignore_ascii_case("Deny") {
            // Check if this deny targets our principal specifically
            if principal_match != PrincipalMatchResult::NoMatch {
                has_deny = true;
            }
        } else if effect.eq_ignore_ascii_case("Allow") {
            allow_matches.push(principal_match);
        }
    }

    if has_deny {
        return ResourcePolicyEvalResult::DenyMatch;
    }

    if allow_matches.is_empty() {
        return ResourcePolicyEvalResult::NoMatch;
    }

    // Return the most specific match
    for m in &allow_matches {
        if *m == PrincipalMatchResult::NodeMatch {
            return ResourcePolicyEvalResult::NodeMatch;
        }
    }
    for m in &allow_matches {
        if *m == PrincipalMatchResult::DiffAccountMatch {
            return ResourcePolicyEvalResult::DiffAccountMatch;
        }
    }
    for m in &allow_matches {
        if *m == PrincipalMatchResult::RootMatch {
            return ResourcePolicyEvalResult::RootMatch;
        }
    }
    for m in &allow_matches {
        if *m == PrincipalMatchResult::ServiceMatch {
            return ResourcePolicyEvalResult::ServiceMatch;
        }
    }
    for m in &allow_matches {
        if *m == PrincipalMatchResult::WildcardMatch {
            // Wildcard in same account = root match, cross-account requires identity policy too
            let node_account = arns::get_account_id(&node.arn);
            if node_account == account_id {
                return ResourcePolicyEvalResult::RootMatch;
            } else {
                return ResourcePolicyEvalResult::DiffAccountMatch;
            }
        }
    }

    ResourcePolicyEvalResult::NoMatch
}

/// Evaluate a trust policy to see if a service principal can assume a role
pub fn service_can_assume_role(trust_policy: &Value, service_principal: &str) -> bool {
    let statements = match trust_policy.get("Statement") {
        Some(Value::Array(arr)) => arr.iter().collect::<Vec<_>>(),
        Some(stmt) => vec![stmt],
        None => return false,
    };

    for stmt in statements {
        let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
        if !effect.eq_ignore_ascii_case("Allow") {
            continue;
        }

        // Check action is sts:AssumeRole
        if !action_matches_stmt(stmt, "sts:AssumeRole") {
            continue;
        }

        // Check Service principal
        if let Some(principal) = stmt.get("Principal") {
            let services = get_principal_services(principal);
            if services.iter().any(|s| *s == service_principal) {
                return true;
            }
        }
    }

    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrincipalMatchResult {
    NoMatch,
    WildcardMatch,
    RootMatch,
    NodeMatch,
    DiffAccountMatch,
    ServiceMatch,
}

fn principal_matches(stmt: &Value, node: &Node, resource_account_id: &str) -> PrincipalMatchResult {
    // Handle NotPrincipal
    if let Some(not_principal) = stmt.get("NotPrincipal") {
        let matches = check_principal_value(not_principal, node, resource_account_id);
        return if matches == PrincipalMatchResult::NoMatch {
            // NotPrincipal didn't match us, so the statement applies to us
            PrincipalMatchResult::NodeMatch
        } else {
            PrincipalMatchResult::NoMatch
        };
    }

    if let Some(principal) = stmt.get("Principal") {
        check_principal_value(principal, node, resource_account_id)
    } else {
        PrincipalMatchResult::NoMatch
    }
}

fn check_principal_value(
    principal: &Value,
    node: &Node,
    resource_account_id: &str,
) -> PrincipalMatchResult {
    let node_account = arns::get_account_id(&node.arn);

    match principal {
        Value::String(s) if s == "*" => PrincipalMatchResult::WildcardMatch,
        Value::Object(obj) => {
            // Check AWS principals
            if let Some(aws_principals) = obj.get("AWS") {
                let arns = get_string_or_list(aws_principals);
                for principal_arn in arns {
                    if principal_arn == "*" {
                        return PrincipalMatchResult::WildcardMatch;
                    }
                    // Check exact ARN match
                    if principal_arn == node.arn {
                        if node_account == resource_account_id {
                            return PrincipalMatchResult::NodeMatch;
                        } else {
                            return PrincipalMatchResult::DiffAccountMatch;
                        }
                    }
                    // Check account root match
                    if principal_arn.ends_with(":root")
                        && arns::get_account_id(principal_arn) == node_account
                    {
                        return PrincipalMatchResult::RootMatch;
                    }
                    // Check bare account ID (e.g., "000000000000" without arn: prefix)
                    if !principal_arn.contains(':') && principal_arn == node_account {
                        return PrincipalMatchResult::RootMatch;
                    }
                    // Check by user ID
                    if principal_arn == node.id_value {
                        return PrincipalMatchResult::NodeMatch;
                    }
                }
            }
            // Check Service principals
            if let Some(service_principals) = obj.get("Service") {
                let services = get_string_or_list(service_principals);
                if !services.is_empty() {
                    return PrincipalMatchResult::ServiceMatch;
                }
            }
            // Check Federated principals
            if let Some(federated) = obj.get("Federated") {
                let fed_arns = get_string_or_list(federated);
                if !fed_arns.is_empty() {
                    return PrincipalMatchResult::ServiceMatch;
                }
            }
            PrincipalMatchResult::NoMatch
        }
        _ => PrincipalMatchResult::NoMatch,
    }
}

fn action_matches_stmt(stmt: &Value, action: &str) -> bool {
    if let Some(actions) = stmt.get("Action") {
        let patterns = get_string_or_list(actions);
        patterns.iter().any(|p| wildcard::action_matches(p, action))
    } else if let Some(not_actions) = stmt.get("NotAction") {
        let patterns = get_string_or_list(not_actions);
        !patterns.iter().any(|p| wildcard::action_matches(p, action))
    } else {
        // No Action specified - match everything (common in trust policies)
        true
    }
}

fn get_string_or_list(value: &Value) -> Vec<&str> {
    match value {
        Value::String(s) => vec![s.as_str()],
        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => vec![],
    }
}

fn get_principal_services(principal: &Value) -> Vec<&str> {
    match principal {
        Value::Object(obj) => {
            if let Some(services) = obj.get("Service") {
                get_string_or_list(services)
            } else {
                vec![]
            }
        }
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node(arn: &str) -> Node {
        Node {
            arn: arn.to_string(),
            id_value: "AIDA00000000000000000".to_string(),
            attached_policies: vec![],
            group_memberships: vec![],
            trust_policy: None,
            instance_profile: None,
            active_password: false,
            access_keys: 0,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: Default::default(),
        }
    }

    #[test]
    fn test_trust_policy_same_account() {
        let trust = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
                "Action": "sts:AssumeRole"
            }]
        });
        let node = test_node("arn:aws:iam::123456789012:user/Alice");
        let ctx = CaseInsensitiveMap::new();
        let result = resource_policy_authorization(
            &node,
            "123456789012",
            &trust,
            "sts:AssumeRole",
            "*",
            &ctx,
        );
        assert_eq!(result, ResourcePolicyEvalResult::RootMatch);
    }

    #[test]
    fn test_trust_policy_specific_principal() {
        let trust = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::123456789012:user/Alice" },
                "Action": "sts:AssumeRole"
            }]
        });
        let node = test_node("arn:aws:iam::123456789012:user/Alice");
        let ctx = CaseInsensitiveMap::new();
        let result = resource_policy_authorization(
            &node,
            "123456789012",
            &trust,
            "sts:AssumeRole",
            "*",
            &ctx,
        );
        assert_eq!(result, ResourcePolicyEvalResult::NodeMatch);
    }

    #[test]
    fn test_trust_policy_deny() {
        let trust = serde_json::json!({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": { "AWS": "*" },
                    "Action": "sts:AssumeRole"
                },
                {
                    "Effect": "Deny",
                    "Principal": { "AWS": "arn:aws:iam::123456789012:user/Alice" },
                    "Action": "sts:AssumeRole"
                }
            ]
        });
        let node = test_node("arn:aws:iam::123456789012:user/Alice");
        let ctx = CaseInsensitiveMap::new();
        let result = resource_policy_authorization(
            &node,
            "123456789012",
            &trust,
            "sts:AssumeRole",
            "*",
            &ctx,
        );
        assert_eq!(result, ResourcePolicyEvalResult::DenyMatch);
    }

    #[test]
    fn test_service_can_assume() {
        let trust = serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "Service": "lambda.amazonaws.com" },
                "Action": "sts:AssumeRole"
            }]
        });
        assert!(service_can_assume_role(&trust, "lambda.amazonaws.com"));
        assert!(!service_can_assume_role(&trust, "ec2.amazonaws.com"));
    }
}
