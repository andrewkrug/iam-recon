use std::collections::HashSet;
use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::graph::Graph;
use crate::model::node::Node;

/// BFS: find all reachable nodes and the edge paths to reach them.
/// Returns a list of edge paths (each path is a Vec<Edge>).
/// Admin nodes can reach all other nodes (short-circuit).
pub fn get_search_list(graph: &Graph, start: &Arc<Node>) -> Vec<Vec<Edge>> {
    if start.is_admin {
        // Admin can reach everything
        return graph
            .nodes
            .iter()
            .filter(|n| n.arn != start.arn)
            .map(|n| {
                vec![Edge::new(
                    &start.arn,
                    &n.arn,
                    format!("{} is an admin", start.searchable_name()),
                    "Admin",
                )]
            })
            .collect();
    }

    let mut result: Vec<Vec<Edge>> = Vec::new();
    let mut explored: HashSet<String> = HashSet::new();
    explored.insert(start.arn.clone());

    // Seed with direct outbound edges
    let direct_edges = graph.get_outbound_edges(start);
    for edge in direct_edges {
        if !explored.contains(&edge.destination) {
            result.push(vec![edge.clone()]);
        }
    }

    // BFS expansion
    let mut i = 0;
    while i < result.len() {
        let current_dest = result[i].last().unwrap().destination.clone();

        if explored.insert(current_dest.clone()) {
            // Get outbound edges from the current destination
            if let Some(current_node) = graph.get_node_by_arn(&current_dest) {
                if current_node.is_admin {
                    // Admin node can reach everything
                    for node in &graph.nodes {
                        if !explored.contains(&node.arn) && node.arn != current_dest {
                            let mut path = result[i].clone();
                            path.push(Edge::new(
                                &current_dest,
                                &node.arn,
                                format!("{} is an admin", current_node.searchable_name()),
                                "Admin",
                            ));
                            result.push(path);
                        }
                    }
                } else {
                    let outbound = graph.get_outbound_edges(current_node);
                    for edge in outbound {
                        if !explored.contains(&edge.destination) {
                            let mut path = result[i].clone();
                            path.push(edge.clone());
                            result.push(path);
                        }
                    }
                }
            }
        }
        i += 1;
    }

    result
}

/// Check if source can reach destination through any path
pub fn is_connected(
    graph: &Graph,
    source: &Arc<Node>,
    destination: &Arc<Node>,
) -> Option<Vec<Edge>> {
    if source.arn == destination.arn {
        return Some(vec![]);
    }

    let paths = get_search_list(graph, source);
    for path in paths {
        if let Some(last) = path.last() {
            if last.destination == destination.arn {
                return Some(path);
            }
        }
    }
    None
}
