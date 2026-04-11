//! Execute a parsed Query AST against a Graph.

use std::collections::HashSet;
use std::sync::Arc;

use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::model::query_result::QueryResult;
use crate::querying::query_interface;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

use super::ast::{BoolOp, Query};
use super::cypher;
use super::error::NlqError;
use super::fuzzy::FuzzyIndex;
use super::saved::SavedQueryStore;

pub struct ExecutionResult {
    pub results: Vec<QueryResult>,
    /// Informational messages (e.g., "Fuzzy-matched 'createuser' -> 'iam:CreateUser'")
    pub notes: Vec<String>,
    /// Pattern match nodes (for Cypher-style queries)
    pub pattern_matches: Vec<Arc<Node>>,
}

impl ExecutionResult {
    pub fn empty() -> Self {
        Self {
            results: vec![],
            notes: vec![],
            pattern_matches: vec![],
        }
    }
}

/// Execute a parsed Query against a graph.
pub fn execute(
    graph: &Graph,
    query: &Query,
    idx: &FuzzyIndex,
) -> Result<ExecutionResult, NlqError> {
    match query {
        Query::Who {
            action,
            resource,
            conditions,
        } => {
            let (action, resource, mut notes) = canonicalize(action, resource, idx);
            let ctx = build_ctx(conditions);
            let mut results = Vec::new();
            for node in &graph.nodes {
                let r = query_interface::search_authorization_for(
                    graph, node, &action, &resource, &ctx,
                );
                if r.allowed {
                    results.push(r);
                }
            }
            notes.push(format!("Matched {} principals", results.len()));
            Ok(ExecutionResult {
                results,
                notes,
                pattern_matches: vec![],
            })
        }
        Query::Can {
            principal,
            action,
            resource,
            conditions,
        } => {
            let (action, resource, mut notes) = canonicalize(action, resource, idx);
            let canonical_principal = idx.canonicalize_principal(principal);
            if canonical_principal != *principal {
                notes.push(format!(
                    "Canonicalized '{}' -> '{}'",
                    principal, canonical_principal
                ));
            }

            if canonical_principal == "*" {
                let ctx = build_ctx(conditions);
                let results: Vec<_> = graph
                    .nodes
                    .iter()
                    .map(|n| {
                        query_interface::search_authorization_for(
                            graph, n, &action, &resource, &ctx,
                        )
                    })
                    .collect();
                return Ok(ExecutionResult {
                    results,
                    notes,
                    pattern_matches: vec![],
                });
            }

            let node = graph
                .get_node_by_searchable_name(&canonical_principal)
                .ok_or_else(|| {
                    NlqError::Unknown(format!(
                        "Principal not found: {} (did you mean {:?}?)",
                        principal,
                        FuzzyIndex::top_matches(principal, &idx.principals, 3)
                            .iter()
                            .map(|m| m.value.as_str())
                            .collect::<Vec<_>>()
                    ))
                })?;
            let ctx = build_ctx(conditions);
            let r =
                query_interface::search_authorization_for(graph, node, &action, &resource, &ctx);
            Ok(ExecutionResult {
                results: vec![r],
                notes,
                pattern_matches: vec![],
            })
        }
        Query::Preset { name, arg } => execute_preset(graph, name, arg.as_deref()),
        Query::Bool { op, left, right } => execute_bool(graph, op, left, right, idx),
        Query::Pattern { text } => execute_pattern(graph, text),
        Query::Saved { name } => execute_saved(graph, name, idx),
        Query::What { principal } => execute_what(graph, principal, idx),
        Query::Compare { a, b } => execute_compare(graph, a, b, idx),
    }
}

fn canonicalize(action: &str, resource: &str, idx: &FuzzyIndex) -> (String, String, Vec<String>) {
    let mut notes = Vec::new();
    let canonical_action = idx.canonicalize_action(action);
    if canonical_action != action {
        notes.push(format!(
            "Fuzzy-matched action '{}' -> '{}'",
            action, canonical_action
        ));
    }
    (canonical_action, resource.to_string(), notes)
}

fn build_ctx(conditions: &std::collections::HashMap<String, String>) -> CaseInsensitiveMap {
    let mut ctx = CaseInsensitiveMap::new();
    for (k, v) in conditions {
        ctx.insert_single(k, v);
    }
    ctx
}

fn execute_preset(
    graph: &Graph,
    name: &str,
    _arg: Option<&str>,
) -> Result<ExecutionResult, NlqError> {
    use crate::querying::presets;
    match name {
        "privesc" => {
            let mut results = Vec::new();
            for node in &graph.nodes {
                if let Some((can, path)) = presets::privesc::can_privesc(graph, node) {
                    if can {
                        results.push(QueryResult::new_allowed(Arc::clone(node), path));
                    }
                }
            }
            Ok(ExecutionResult {
                notes: vec![format!("Found {} principals with escalation paths", results.len())],
                results, pattern_matches: vec![],
            })
        }
        "wrongadmin" => {
            let wa = presets::wrongadmin::compose_wrong_admin_list(graph);
            let results: Vec<QueryResult> = wa.iter()
                .map(|(node, _)| QueryResult::new_allowed(Arc::clone(node), vec![]))
                .collect();
            Ok(ExecutionResult {
                notes: vec![format!("{} anomalous admins", results.len())],
                results, pattern_matches: vec![],
            })
        }
        _ => Err(NlqError::Unknown(format!(
            "Unknown preset: {}. Try: privesc, wrongadmin, endgame, serviceaccess, clusters, connected",
            name
        ))),
    }
}

fn execute_bool(
    graph: &Graph,
    op: &BoolOp,
    left: &Query,
    right: &Query,
    idx: &FuzzyIndex,
) -> Result<ExecutionResult, NlqError> {
    let l = execute(graph, left, idx)?;
    let r = execute(graph, right, idx)?;

    let l_set: HashSet<String> = l
        .results
        .iter()
        .filter(|qr| qr.allowed)
        .map(|qr| qr.node.arn.clone())
        .collect();
    let r_set: HashSet<String> = r
        .results
        .iter()
        .filter(|qr| qr.allowed)
        .map(|qr| qr.node.arn.clone())
        .collect();

    let combined: HashSet<String> = match op {
        BoolOp::And => l_set.intersection(&r_set).cloned().collect(),
        BoolOp::Or => l_set.union(&r_set).cloned().collect(),
        BoolOp::Not => l_set.difference(&r_set).cloned().collect(),
    };

    // Preserve QueryResult details from the left side where possible
    let mut results: Vec<QueryResult> = l
        .results
        .into_iter()
        .filter(|qr| combined.contains(&qr.node.arn))
        .collect();
    // For OR, add any right-only results
    if matches!(op, BoolOp::Or) {
        for qr in r.results {
            if !results
                .iter()
                .any(|existing| existing.node.arn == qr.node.arn)
            {
                results.push(qr);
            }
        }
    }

    let op_name = match op {
        BoolOp::And => "AND",
        BoolOp::Or => "OR",
        BoolOp::Not => "BUT NOT",
    };
    let notes = vec![format!(
        "Combined with {}: {} results",
        op_name,
        results.len()
    )];
    Ok(ExecutionResult {
        results,
        notes,
        pattern_matches: vec![],
    })
}

fn execute_pattern(graph: &Graph, text: &str) -> Result<ExecutionResult, NlqError> {
    let matches = cypher::evaluate(graph, text)
        .map_err(|e| NlqError::Unknown(format!("Pattern parse error: {}", e)))?;
    let notes = vec![format!("Pattern matched {} nodes", matches.len())];
    Ok(ExecutionResult {
        results: vec![],
        notes,
        pattern_matches: matches,
    })
}

fn execute_saved(graph: &Graph, name: &str, idx: &FuzzyIndex) -> Result<ExecutionResult, NlqError> {
    let store = SavedQueryStore::load_default()?;
    let text = store.get(name).ok_or_else(|| {
        NlqError::Unknown(format!(
            "No saved query named '{}'. Use 'iam-recon query list' to see all.",
            name
        ))
    })?;
    let q = super::parser::parse(&text)?;
    execute(graph, &q, idx)
}

fn execute_what(
    graph: &Graph,
    principal: &str,
    idx: &FuzzyIndex,
) -> Result<ExecutionResult, NlqError> {
    let canonical = idx.canonicalize_principal(principal);
    let node = graph
        .get_node_by_searchable_name(&canonical)
        .ok_or_else(|| NlqError::Unknown(format!("Principal not found: {}", principal)))?;

    // "What can X do" → BFS reachable nodes, show target set
    use crate::querying::search;
    let paths = search::get_search_list(graph, node);
    let reachable: HashSet<String> = paths
        .iter()
        .filter_map(|p| p.last().map(|e| e.destination.clone()))
        .collect();

    let results: Vec<QueryResult> = graph
        .nodes
        .iter()
        .filter(|n| reachable.contains(&n.arn))
        .map(|n| QueryResult::new_allowed(Arc::clone(n), vec![]))
        .collect();

    let notes = vec![format!(
        "{} can reach {} principals (direct + transitive)",
        canonical,
        results.len()
    )];
    Ok(ExecutionResult {
        results,
        notes,
        pattern_matches: vec![],
    })
}

fn execute_compare(
    graph: &Graph,
    a: &str,
    b: &str,
    idx: &FuzzyIndex,
) -> Result<ExecutionResult, NlqError> {
    let canonical_a = idx.canonicalize_principal(a);
    let canonical_b = idx.canonicalize_principal(b);
    let node_a = graph
        .get_node_by_searchable_name(&canonical_a)
        .ok_or_else(|| NlqError::Unknown(format!("Not found: {}", a)))?;
    let node_b = graph
        .get_node_by_searchable_name(&canonical_b)
        .ok_or_else(|| NlqError::Unknown(format!("Not found: {}", b)))?;

    use crate::querying::search;
    let reach_a: HashSet<String> = search::get_search_list(graph, node_a)
        .iter()
        .filter_map(|p| p.last().map(|e| e.destination.clone()))
        .collect();
    let reach_b: HashSet<String> = search::get_search_list(graph, node_b)
        .iter()
        .filter_map(|p| p.last().map(|e| e.destination.clone()))
        .collect();

    let only_a: Vec<_> = reach_a.difference(&reach_b).collect();
    let only_b: Vec<_> = reach_b.difference(&reach_a).collect();
    let both: Vec<_> = reach_a.intersection(&reach_b).collect();

    let notes = vec![
        format!("{} reaches {} principals", canonical_a, reach_a.len()),
        format!("{} reaches {} principals", canonical_b, reach_b.len()),
        format!(
            "Shared: {} | Only {}: {} | Only {}: {}",
            both.len(),
            canonical_a,
            only_a.len(),
            canonical_b,
            only_b.len()
        ),
    ];
    Ok(ExecutionResult {
        results: vec![],
        notes,
        pattern_matches: vec![],
    })
}
