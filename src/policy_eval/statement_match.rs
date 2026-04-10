use serde_json::Value;

use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::condition;
use crate::policy_eval::wildcard;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Check if a principal has any matching statement across all attached policies
/// (including group policies).
pub fn has_matching_statement(
    node: &Node,
    effect: &str,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
) -> bool {
    // Check principal's own policies
    for policy in &node.attached_policies {
        if policy_has_matching_statement(policy, effect, action, resource, condition_keys) {
            return true;
        }
    }
    // Check group policies (for users)
    for group in &node.group_memberships {
        for policy in &group.attached_policies {
            if policy_has_matching_statement(policy, effect, action, resource, condition_keys) {
                return true;
            }
        }
    }
    false
}

/// Check if a single policy document contains a matching statement.
pub fn policy_has_matching_statement(
    policy: &Policy,
    effect: &str,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
) -> bool {
    let statements = get_statements(&policy.policy_doc);
    for stmt in statements {
        if statement_matches(&stmt, effect, action, resource, condition_keys) {
            return true;
        }
    }
    false
}

/// Extract statements from a policy document, normalizing to always return a Vec
fn get_statements(policy_doc: &Value) -> Vec<&Value> {
    match policy_doc.get("Statement") {
        Some(Value::Array(arr)) => arr.iter().collect(),
        Some(stmt) => vec![stmt],
        None => vec![],
    }
}

/// Check if a single statement matches the given effect/action/resource/conditions
fn statement_matches(
    stmt: &Value,
    effect: &str,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
) -> bool {
    // Check Effect
    let stmt_effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
    if !stmt_effect.eq_ignore_ascii_case(effect) {
        return false;
    }

    // Check Action / NotAction
    if !action_matches(stmt, action) {
        return false;
    }

    // Check Resource / NotResource
    if !resource_matches(stmt, resource, condition_keys) {
        return false;
    }

    // Check Condition
    if let Some(cond) = stmt.get("Condition") {
        if !condition::evaluate_condition_block(cond, condition_keys) {
            return false;
        }
    }

    true
}

/// Check if the statement's Action/NotAction matches the given action
fn action_matches(stmt: &Value, action: &str) -> bool {
    if let Some(actions) = stmt.get("Action") {
        let patterns = get_string_or_list(actions);
        patterns.iter().any(|p| wildcard::action_matches(p, action))
    } else if let Some(not_actions) = stmt.get("NotAction") {
        let patterns = get_string_or_list(not_actions);
        !patterns.iter().any(|p| wildcard::action_matches(p, action))
    } else {
        false
    }
}

/// Check if the statement's Resource/NotResource matches the given resource
fn resource_matches(stmt: &Value, resource: &str, condition_keys: &CaseInsensitiveMap) -> bool {
    if let Some(resources) = stmt.get("Resource") {
        let patterns = get_string_or_list(resources);
        patterns.iter().any(|p| {
            let expanded = wildcard::expand_variables(p, condition_keys);
            wildcard::resource_matches(&expanded, resource)
        })
    } else if let Some(not_resources) = stmt.get("NotResource") {
        let patterns = get_string_or_list(not_resources);
        !patterns.iter().any(|p| {
            let expanded = wildcard::expand_variables(p, condition_keys);
            wildcard::resource_matches(&expanded, resource)
        })
    } else {
        // No Resource/NotResource specified = matches everything
        true
    }
}

/// Extract a string or list of strings from a JSON value
fn get_string_or_list(value: &Value) -> Vec<&str> {
    match value {
        Value::String(s) => vec![s.as_str()],
        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_policy(doc: Value) -> Policy {
        Policy::new("arn:aws:iam::123456789012:policy/test", "test", doc)
    }

    fn make_node(policies: Vec<Arc<Policy>>) -> Node {
        Node {
            arn: "arn:aws:iam::123456789012:user/TestUser".into(),
            id_value: "AIDA00000000000000000".into(),
            attached_policies: policies,
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
    fn test_simple_allow() {
        let policy = make_policy(serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }));
        let ctx = CaseInsensitiveMap::new();
        assert!(policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:GetObject",
            "*",
            &ctx
        ));
        assert!(!policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:PutObject",
            "*",
            &ctx
        ));
    }

    #[test]
    fn test_wildcard_action() {
        let policy = make_policy(serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }]
        }));
        let ctx = CaseInsensitiveMap::new();
        assert!(policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:GetObject",
            "*",
            &ctx
        ));
        assert!(policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:PutObject",
            "*",
            &ctx
        ));
        assert!(!policy_has_matching_statement(
            &policy,
            "Allow",
            "ec2:RunInstances",
            "*",
            &ctx
        ));
    }

    #[test]
    fn test_not_action() {
        let policy = make_policy(serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "NotAction": "iam:*",
                "Resource": "*"
            }]
        }));
        let ctx = CaseInsensitiveMap::new();
        assert!(policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:GetObject",
            "*",
            &ctx
        ));
        assert!(!policy_has_matching_statement(
            &policy,
            "Allow",
            "iam:GetUser",
            "*",
            &ctx
        ));
    }

    #[test]
    fn test_deny_statement() {
        let policy = make_policy(serde_json::json!({
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteBucket",
                "Resource": "*"
            }]
        }));
        let ctx = CaseInsensitiveMap::new();
        assert!(policy_has_matching_statement(
            &policy,
            "Deny",
            "s3:DeleteBucket",
            "*",
            &ctx
        ));
        assert!(!policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:DeleteBucket",
            "*",
            &ctx
        ));
    }

    #[test]
    fn test_has_matching_statement_with_node() {
        let policy = Arc::new(make_policy(serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        })));
        let node = make_node(vec![policy]);
        let ctx = CaseInsensitiveMap::new();
        assert!(has_matching_statement(
            &node,
            "Allow",
            "anything:anything",
            "*",
            &ctx
        ));
    }

    #[test]
    fn test_resource_specific() {
        let policy = make_policy(serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }));
        let ctx = CaseInsensitiveMap::new();
        assert!(policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:GetObject",
            "arn:aws:s3:::my-bucket/key",
            &ctx
        ));
        assert!(!policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:GetObject",
            "arn:aws:s3:::other-bucket/key",
            &ctx
        ));
    }

    #[test]
    fn test_condition_in_statement() {
        let policy = make_policy(serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "10.0.0.0/8"
                    }
                }
            }]
        }));
        let mut ctx = CaseInsensitiveMap::new();
        ctx.insert_single("aws:SourceIp", "10.0.1.5");
        assert!(policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:GetObject",
            "*",
            &ctx
        ));

        let mut ctx2 = CaseInsensitiveMap::new();
        ctx2.insert_single("aws:SourceIp", "192.168.1.1");
        assert!(!policy_has_matching_statement(
            &policy,
            "Allow",
            "s3:GetObject",
            "*",
            &ctx2
        ));
    }
}
