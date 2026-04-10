use crate::error::{IamReconError, Result};
use crate::model::graph::Graph;
use crate::model::query_result::QueryResult;
use crate::querying::query_interface;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Parse and execute a natural language query.
/// Formats:
/// - "who can do <action> with <resource>"
/// - "can <principal> do <action> with <resource>"
/// - "can <principal> do <action> with <resource> when <key> is <value>"
pub fn execute_query(graph: &Graph, query: &str) -> Result<Vec<QueryResult>> {
    let query = query.trim().to_lowercase();

    if query.starts_with("who can do ") {
        parse_who_query(graph, &query)
    } else if query.starts_with("can ") {
        parse_can_query(graph, &query)
    } else if query.starts_with("preset ") {
        parse_preset_query(graph, &query)
    } else {
        Err(IamReconError::InvalidQuery(format!(
            "Unrecognized query format: {}. Use 'who can do <action> with <resource>' or 'can <principal> do <action> with <resource>'",
            query
        )))
    }
}

fn parse_who_query(graph: &Graph, query: &str) -> Result<Vec<QueryResult>> {
    // "who can do <action> with <resource>"
    let rest = query.strip_prefix("who can do ").unwrap();
    let (action, resource, condition_keys) = parse_action_resource_conditions(rest)?;

    let mut results = Vec::new();
    for node in &graph.nodes {
        let result = query_interface::search_authorization_for(
            graph,
            node,
            &action,
            &resource,
            &condition_keys,
        );
        if result.allowed {
            results.push(result);
        }
    }
    Ok(results)
}

fn parse_can_query(graph: &Graph, query: &str) -> Result<Vec<QueryResult>> {
    // "can <principal> do <action> with <resource>"
    let rest = query.strip_prefix("can ").unwrap();

    let do_pos = rest
        .find(" do ")
        .ok_or_else(|| IamReconError::InvalidQuery("Expected 'do' keyword".into()))?;

    let principal_name = &rest[..do_pos];
    let after_do = &rest[do_pos + 4..];

    let (action, resource, condition_keys) = parse_action_resource_conditions(after_do)?;

    // Handle wildcard principal
    if principal_name == "*" {
        let mut results = Vec::new();
        for node in &graph.nodes {
            let result = query_interface::search_authorization_for(
                graph,
                node,
                &action,
                &resource,
                &condition_keys,
            );
            results.push(result);
        }
        return Ok(results);
    }

    let node = graph
        .get_node_by_searchable_name(principal_name)
        .ok_or_else(|| IamReconError::NodeNotFound(principal_name.into()))?;

    let result =
        query_interface::search_authorization_for(graph, node, &action, &resource, &condition_keys);
    Ok(vec![result])
}

fn parse_preset_query(graph: &Graph, query: &str) -> Result<Vec<QueryResult>> {
    let rest = query.strip_prefix("preset ").unwrap().trim();
    let parts: Vec<&str> = rest.splitn(2, ' ').collect();
    let preset_name = parts[0];
    let _preset_arg = parts.get(1).unwrap_or(&"*");

    match preset_name {
        "privesc" => {
            let mut results = Vec::new();
            for node in &graph.nodes {
                if let Some((can_escalate, path)) = super::presets::privesc::can_privesc(graph, node) {
                    if can_escalate {
                        results.push(QueryResult::new_allowed(std::sync::Arc::clone(node), path));
                    }
                }
            }
            Ok(results)
        }
        _ => Err(IamReconError::InvalidQuery(format!(
            "Unknown preset: {}. Available: privesc, connected, wrongadmin, endgame, serviceaccess, clusters",
            preset_name
        ))),
    }
}

fn parse_action_resource_conditions(s: &str) -> Result<(String, String, CaseInsensitiveMap)> {
    let mut condition_keys = CaseInsensitiveMap::new();

    // Split on "when" for conditions
    let (action_resource, conditions) = if let Some(when_pos) = s.find(" when ") {
        (&s[..when_pos], Some(&s[when_pos + 6..]))
    } else {
        (s, None)
    };

    // Parse conditions
    if let Some(cond_str) = conditions {
        // "key is value and key2 is value2"
        for part in cond_str.split(" and ") {
            let part = part.trim();
            if let Some(is_pos) = part.find(" is ") {
                let key = part[..is_pos].trim();
                let value = part[is_pos + 4..].trim();
                condition_keys.insert_single(key, value);
            }
        }
    }

    // Split action and resource on "with"
    if let Some(with_pos) = action_resource.find(" with ") {
        let action = action_resource[..with_pos].trim().to_string();
        let resource = action_resource[with_pos + 6..].trim().to_string();
        Ok((action, resource, condition_keys))
    } else {
        // No resource specified, use "*"
        Ok((
            action_resource.trim().to_string(),
            "*".to_string(),
            condition_keys,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_action_resource() {
        let (action, resource, _) =
            parse_action_resource_conditions("s3:getobject with *").unwrap();
        assert_eq!(action, "s3:getobject");
        assert_eq!(resource, "*");
    }

    #[test]
    fn test_parse_with_conditions() {
        let (action, resource, ctx) =
            parse_action_resource_conditions("s3:getobject with * when aws:sourceip is 10.0.0.0/8")
                .unwrap();
        assert_eq!(action, "s3:getobject");
        assert_eq!(resource, "*");
        assert_eq!(ctx.get_first("aws:sourceip"), Some("10.0.0.0/8"));
    }
}
