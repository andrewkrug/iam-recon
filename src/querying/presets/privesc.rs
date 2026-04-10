use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::querying::search;

/// Check if a node can escalate to an admin principal.
pub fn can_privesc(graph: &Graph, node: &Arc<Node>) -> Option<(bool, Vec<Edge>)> {
    if node.is_admin {
        return Some((false, vec![]));
    }

    let paths = search::get_search_list(graph, node);
    for path in paths {
        if let Some(last_edge) = path.last() {
            if let Some(dest_node) = graph.get_node_by_arn(&last_edge.destination) {
                if dest_node.is_admin {
                    return Some((true, path));
                }
            }
        }
    }

    Some((false, vec![]))
}

pub fn print_privesc_results(graph: &Graph) {
    use crate::cli::colors as c;

    println!("{}", c::header("Privilege Escalation Paths"));

    let mut has_privesc = false;

    for node in &graph.nodes {
        if node.is_admin {
            println!(
                "  {} {}",
                c::node_name(node.searchable_name(), true, node.is_user()),
                c::bold_red("[ADMIN]")
            );
            continue;
        }

        if let Some((can_esc, path)) = can_privesc(graph, node) {
            if can_esc {
                has_privesc = true;
                println!(
                    "\n  {} {} can escalate to admin:",
                    c::bold_red(">>>"),
                    c::node_name(node.searchable_name(), false, node.is_user())
                );
                for edge in &path {
                    let src = edge.source.split(':').last().unwrap_or(&edge.source);
                    let dst = edge
                        .destination
                        .split(':')
                        .last()
                        .unwrap_or(&edge.destination);
                    println!(
                        "    {} {} {} {}",
                        c::cyan(src),
                        c::dim("->"),
                        c::edge_label(&edge.short_reason),
                        c::magenta(dst)
                    );
                }
            }
        }
    }

    if !has_privesc {
        println!("\n  {}", c::ok("No privilege escalation paths found."));
    }
    println!();
}
