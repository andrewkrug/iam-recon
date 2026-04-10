use std::sync::Arc;

use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::model::query_result::QueryResult;
use crate::policy_eval::authorization;
use crate::querying::search;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Search if a principal (or any reachable principal) can perform an action.
pub fn search_authorization_for(
    graph: &Graph,
    principal: &Arc<Node>,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
) -> QueryResult {
    // Check direct authorization
    if principal.is_admin
        || authorization::local_check_authorization(principal, action, resource, condition_keys)
    {
        return QueryResult::new_allowed(Arc::clone(principal), vec![]);
    }

    // Check reachable nodes
    let paths = search::get_search_list(graph, principal);
    for path in paths {
        if let Some(last_edge) = path.last() {
            if let Some(dest_node) = graph.get_node_by_arn(&last_edge.destination) {
                if dest_node.is_admin
                    || authorization::local_check_authorization(
                        dest_node,
                        action,
                        resource,
                        condition_keys,
                    )
                {
                    return QueryResult::new_allowed(Arc::clone(principal), path);
                }
            }
        }
    }

    QueryResult::new_denied(Arc::clone(principal))
}

/// Full authorization search including resource policies, SCPs, and session policies.
pub fn search_authorization_full(
    graph: &Graph,
    principal: &Arc<Node>,
    action: &str,
    resource: &str,
    condition_keys: &CaseInsensitiveMap,
    resource_policy: Option<&serde_json::Value>,
    resource_owner: Option<&str>,
    scps: Option<&[Vec<&Policy>]>,
    session_policy: Option<&Policy>,
) -> QueryResult {
    // Check direct authorization with full evaluation
    let direct = authorization::local_check_authorization_full(
        principal,
        action,
        resource,
        condition_keys,
        resource_policy,
        resource_owner,
        scps,
        session_policy,
    );

    if principal.is_admin || direct {
        // For admins with SCPs, still check SCP denials
        if principal.is_admin && scps.is_some() {
            if direct {
                return QueryResult::new_allowed(Arc::clone(principal), vec![]);
            }
        } else {
            return QueryResult::new_allowed(Arc::clone(principal), vec![]);
        }
    }

    // Check reachable nodes
    let paths = search::get_search_list(graph, principal);
    for path in paths {
        if let Some(last_edge) = path.last() {
            if let Some(dest_node) = graph.get_node_by_arn(&last_edge.destination) {
                let dest_auth = authorization::local_check_authorization_full(
                    dest_node,
                    action,
                    resource,
                    condition_keys,
                    resource_policy,
                    resource_owner,
                    scps,
                    session_policy,
                );
                if dest_auth {
                    return QueryResult::new_allowed(Arc::clone(principal), path);
                }
            }
        }
    }

    QueryResult::new_denied(Arc::clone(principal))
}
