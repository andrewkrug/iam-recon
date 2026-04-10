use std::sync::Arc;

use crate::model::node::Node;
use crate::policy_eval::statement_match;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Check each node to see if it has admin-level permissions and return updated nodes.
/// A node is admin if it has Action:* and Resource:* Allow.
pub fn update_admin_status(nodes: Vec<Arc<Node>>) -> Vec<Arc<Node>> {
    let ctx = CaseInsensitiveMap::new();

    nodes
        .into_iter()
        .map(|node| {
            let is_admin = is_admin_check(&node, &ctx);
            if is_admin {
                // Create a new node with is_admin = true
                let mut new_node = (*node).clone();
                new_node.is_admin = true;
                Arc::new(new_node)
            } else {
                node
            }
        })
        .collect()
}

fn is_admin_check(node: &Node, ctx: &CaseInsensitiveMap) -> bool {
    // Check if any policy grants Action:* Resource:*
    statement_match::has_matching_statement(node, "Allow", "iam:PutRolePolicy", "*", ctx)
        && statement_match::has_matching_statement(node, "Allow", "s3:GetObject", "*", ctx)
        && statement_match::has_matching_statement(node, "Allow", "ec2:RunInstances", "*", ctx)
        && statement_match::has_matching_statement(node, "Allow", "lambda:InvokeFunction", "*", ctx)

    // The above is a heuristic check. The true check is Action:* Resource:*
    // but we use a broader check for safety. Let's use the simple approach:
    || has_star_star(node, ctx)
}

fn has_star_star(node: &Node, ctx: &CaseInsensitiveMap) -> bool {
    // Check for * action and * resource in any single statement
    for policy in node.all_policies() {
        if let Some(stmts) = policy.policy_doc.get("Statement") {
            let stmts = match stmts {
                serde_json::Value::Array(arr) => arr.iter().collect::<Vec<_>>(),
                other => vec![other],
            };
            for stmt in stmts {
                let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
                if !effect.eq_ignore_ascii_case("Allow") {
                    continue;
                }

                let action_star = match stmt.get("Action") {
                    Some(serde_json::Value::String(s)) => s == "*",
                    Some(serde_json::Value::Array(arr)) => {
                        arr.iter().any(|v| v.as_str() == Some("*"))
                    }
                    _ => false,
                };

                let resource_star = match stmt.get("Resource") {
                    Some(serde_json::Value::String(s)) => s == "*",
                    Some(serde_json::Value::Array(arr)) => {
                        arr.iter().any(|v| v.as_str() == Some("*"))
                    }
                    _ => false,
                };

                if action_star && resource_star {
                    // Check conditions don't restrict
                    if stmt.get("Condition").is_none() {
                        return true;
                    }
                    // Even with conditions, check if they match empty context
                    if crate::policy_eval::condition::evaluate_condition_block(
                        stmt.get("Condition").unwrap(),
                        ctx,
                    ) {
                        return true;
                    }
                }
            }
        }
    }
    false
}
