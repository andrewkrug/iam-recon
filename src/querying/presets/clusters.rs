use std::collections::HashMap;
use std::sync::Arc;

use crate::model::graph::Graph;
use crate::model::node::Node;

pub fn generate_clusters(graph: &Graph, tag_name: &str) -> HashMap<String, Vec<Arc<Node>>> {
    let mut clusters: HashMap<String, Vec<Arc<Node>>> = HashMap::new();
    for node in &graph.nodes {
        if let Some(value) = node.tags.get(tag_name) {
            clusters
                .entry(value.clone())
                .or_default()
                .push(Arc::clone(node));
        }
    }
    clusters
}

pub fn print_cluster_results(graph: &Graph, tag_name: &str) {
    use crate::cli::colors as c;

    let clusters = generate_clusters(graph, tag_name);

    println!("{}", c::header(&format!("Clusters by tag: {}", tag_name)));

    if clusters.is_empty() {
        println!("  {} No nodes found with tag '{}'", c::dim("--"), tag_name);
        println!();
        return;
    }

    for (value, nodes) in &clusters {
        println!(
            "\n  {} {}={} ({} nodes)",
            c::bold_yellow("*"),
            c::dim(tag_name),
            c::bold_white(value),
            c::stat(nodes.len())
        );
        for node in nodes {
            println!(
                "    {}",
                c::node_name(node.searchable_name(), node.is_admin, node.is_user())
            );
        }
    }
    println!();
}
