//! Mini-Cypher pattern matcher.
//!
//! Supports a tiny subset of Cypher for IAM graph queries:
//!   `match (a)-[*]->(b:admin)` — find nodes with ANY path to admin
//!   `match (a)-[:STS]->(b)`    — find A→B edges of a specific kind
//!   `match (a:user)-[*]->(b:admin)` — node labels filter by kind
//!
//! Node patterns:  `(variable)` or `(variable:label)` where label is
//!   `user`, `role`, `admin`, `privesc`
//!
//! Edge patterns:
//!   `-[]->` any edge
//!   `-[:STS]->` specific short_reason
//!   `-[*]->` any path of any length (transitive)

use std::sync::Arc;

use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::querying::presets::privesc;
use crate::querying::search;

/// Evaluate a pattern string and return matching destination nodes.
pub fn evaluate(graph: &Graph, pattern: &str) -> Result<Vec<Arc<Node>>, String> {
    let ast = parse_pattern(pattern)?;
    Ok(match_pattern(graph, &ast))
}

#[derive(Debug, Clone)]
struct PatternAst {
    src_label: Option<String>,
    edge: EdgeKind,
    dst_label: Option<String>,
}

#[derive(Debug, Clone)]
enum EdgeKind {
    /// Single edge, optionally filtered by short_reason
    Single(Option<String>),
    /// Transitive — any path length (BFS)
    Star,
}

fn parse_pattern(input: &str) -> Result<PatternAst, String> {
    // Strip whitespace and expect roughly:
    //   (a[:label])-[:kind|*]->(b[:label])
    let input = input.trim();
    // Split on ")-" to get source node and the rest
    let src_end = input
        .find(")-[")
        .ok_or("expected source node followed by '-[' like '(a)-['")?;
    let src = &input[..src_end + 1]; // includes closing ')'
    let after_edge_open = &input[src_end + 3..]; // skip past ")-["

    // Find the closing "]" of the edge part
    let edge_close = after_edge_open.find("]->").ok_or("expected ']->'")?;
    let edge_inner = &after_edge_open[..edge_close];
    let dst = after_edge_open[edge_close + 3..].trim();

    let src_label = parse_node_label(src)?;
    let dst_label = parse_node_label(dst)?;
    let edge = parse_edge_inner(edge_inner)?;

    Ok(PatternAst {
        src_label,
        edge,
        dst_label,
    })
}

fn parse_node_label(s: &str) -> Result<Option<String>, String> {
    let s = s.trim();
    let inner = s.trim_start_matches('(').trim_end_matches(')');
    if let Some(colon) = inner.find(':') {
        let label = inner[colon + 1..].trim().to_string();
        Ok(Some(label))
    } else {
        Ok(None)
    }
}

/// Parse the content between `[` and `]` of an edge pattern.
fn parse_edge_inner(inner: &str) -> Result<EdgeKind, String> {
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(EdgeKind::Single(None));
    }
    if inner == "*" {
        return Ok(EdgeKind::Star);
    }
    if let Some(rest) = inner.strip_prefix(':') {
        return Ok(EdgeKind::Single(Some(rest.to_string())));
    }
    Err(format!("unknown edge pattern: {}", inner))
}

fn match_pattern(graph: &Graph, ast: &PatternAst) -> Vec<Arc<Node>> {
    let sources: Vec<&Arc<Node>> = graph
        .nodes
        .iter()
        .filter(|n| matches_label(n, ast.src_label.as_deref(), graph))
        .collect();

    let mut results = Vec::new();

    for src in &sources {
        match &ast.edge {
            EdgeKind::Single(kind_filter) => {
                for edge in graph.get_outbound_edges(src) {
                    if let Some(kind) = kind_filter {
                        if !edge.short_reason.eq_ignore_ascii_case(kind) {
                            continue;
                        }
                    }
                    if let Some(dst) = graph.get_node_by_arn(&edge.destination) {
                        if matches_label(dst, ast.dst_label.as_deref(), graph) {
                            results.push(Arc::clone(dst));
                        }
                    }
                }
            }
            EdgeKind::Star => {
                let paths = search::get_search_list(graph, src);
                for path in paths {
                    if let Some(last) = path.last() {
                        if let Some(dst) = graph.get_node_by_arn(&last.destination) {
                            if matches_label(dst, ast.dst_label.as_deref(), graph) {
                                results.push(Arc::clone(dst));
                            }
                        }
                    }
                }
            }
        }
    }

    // Dedup by ARN
    results.sort_by(|a, b| a.arn.cmp(&b.arn));
    results.dedup_by(|a, b| a.arn == b.arn);
    results
}

fn matches_label(node: &Node, label: Option<&str>, graph: &Graph) -> bool {
    match label {
        None => true,
        Some("user") => node.is_user(),
        Some("role") => node.is_role(),
        Some("admin") => node.is_admin,
        Some("privesc") => privesc::can_privesc(graph, &Arc::new(node.clone()))
            .map(|(can, _)| can)
            .unwrap_or(false),
        Some(_) => false, // Unknown label = no match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_pattern() {
        let ast = parse_pattern("(a)-[:STS]->(b)").unwrap();
        assert_eq!(ast.src_label, None);
        assert_eq!(ast.dst_label, None);
        match ast.edge {
            EdgeKind::Single(Some(s)) => assert_eq!(s, "STS"),
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_star_pattern() {
        let ast = parse_pattern("(a)-[*]->(b:admin)").unwrap();
        assert_eq!(ast.dst_label, Some("admin".into()));
        assert!(matches!(ast.edge, EdgeKind::Star));
    }

    #[test]
    fn test_parse_with_labels() {
        let ast = parse_pattern("(a:user)-[]->(b:role)").unwrap();
        assert_eq!(ast.src_label, Some("user".into()));
        assert_eq!(ast.dst_label, Some("role".into()));
    }
}
