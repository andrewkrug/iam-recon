use chrono::Utc;

use crate::model::node::Node;
use crate::util::arns;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Infer standard AWS condition keys from a principal node
pub fn infer_condition_keys(node: &Node) -> CaseInsensitiveMap {
    let mut ctx = CaseInsensitiveMap::new();

    let now = Utc::now();
    ctx.insert_single("aws:CurrentTime", now.to_rfc3339());
    ctx.insert_single("aws:EpochTime", now.timestamp().to_string());
    ctx.insert_single("aws:SecureTransport", "true");

    ctx.insert_single("aws:userid", &node.id_value);
    ctx.insert_single("aws:PrincipalArn", &node.arn);

    let account_id = arns::get_account_id(&node.arn);
    ctx.insert_single("aws:PrincipalAccount", account_id);

    // For IAM users, set aws:username
    if node.is_user() {
        let searchable = node.searchable_name();
        if let Some(name) = searchable.strip_prefix("user/") {
            ctx.insert_single("aws:username", name);
        }
    }

    // Add principal tags
    for (key, value) in &node.tags {
        ctx.insert_single(format!("aws:PrincipalTag/{}", key), value);
    }

    ctx
}

/// Merge user-provided condition keys with inferred ones.
/// User-provided keys take precedence.
pub fn prepare_condition_context(
    node: &Node,
    user_keys: &CaseInsensitiveMap,
) -> CaseInsensitiveMap {
    let mut ctx = infer_condition_keys(node);
    // User-provided keys override inferred ones
    for (key, values) in user_keys.iter() {
        for value in values {
            ctx.insert_single(key, value);
        }
    }
    ctx
}

/// Prepare condition keys with MFA context
pub fn prepare_mfa_context(node: &Node, user_keys: &CaseInsensitiveMap) -> CaseInsensitiveMap {
    let mut ctx = prepare_condition_context(node, user_keys);
    ctx.insert_single("aws:MultiFactorAuthPresent", "true");
    ctx.insert_single("aws:MultiFactorAuthAge", "1");
    ctx
}
