use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::querying::search;

pub fn is_connected(
    graph: &Graph,
    source: &Arc<Node>,
    destination: &Arc<Node>,
) -> (bool, Vec<Edge>) {
    match search::is_connected(graph, source, destination) {
        Some(path) => (true, path),
        None => (false, vec![]),
    }
}

pub fn print_connected_results(graph: &Graph, source: &Arc<Node>, destination: &Arc<Node>) {
    use crate::cli::colors as c;

    let (connected, path) = is_connected(graph, source, destination);
    if connected {
        if path.is_empty() {
            println!(
                "  {} {} is the same as {}",
                c::ok("OK"),
                c::node_name(source.searchable_name(), source.is_admin, source.is_user()),
                c::node_name(
                    destination.searchable_name(),
                    destination.is_admin,
                    destination.is_user()
                )
            );
        } else {
            println!(
                "  {} {} -> {} through {} hop(s):",
                c::bold_green("CONNECTED"),
                c::node_name(source.searchable_name(), source.is_admin, source.is_user()),
                c::node_name(
                    destination.searchable_name(),
                    destination.is_admin,
                    destination.is_user()
                ),
                c::stat(path.len())
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
    } else {
        println!(
            "  {} {} cannot reach {}",
            c::bold_red("NOT CONNECTED"),
            c::node_name(source.searchable_name(), source.is_admin, source.is_user()),
            c::node_name(
                destination.searchable_name(),
                destination.is_admin,
                destination.is_user()
            )
        );
    }
}
