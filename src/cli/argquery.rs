use clap::Args;

use crate::model::graph::Graph;
use crate::querying::presets;
use crate::querying::query_interface;
use crate::util::case_insensitive_map::CaseInsensitiveMap;
use crate::util::storage;

#[derive(Args)]
pub struct ArgqueryArgs {
    /// Principal (searchable name, e.g., "user/Alice" or "role/Admin")
    #[arg(long, short)]
    pub principal: Option<String>,

    /// IAM action (e.g., "s3:GetObject")
    #[arg(long, short)]
    pub action: Option<String>,

    /// Resource ARN
    #[arg(long, short, default_value = "*")]
    pub resource: String,

    /// Preset query to run (privesc, connected, wrongadmin, endgame, serviceaccess, clusters)
    #[arg(long)]
    pub preset: Option<String>,

    /// For connected preset: destination principal
    #[arg(long)]
    pub destination: Option<String>,

    /// For clusters preset: tag name
    #[arg(long)]
    pub tag: Option<String>,

    /// Condition keys (key=value pairs)
    #[arg(long, short = 'c')]
    pub condition: Vec<String>,
}

pub fn handle(args: ArgqueryArgs, account: Option<&str>) -> anyhow::Result<()> {
    let account_id =
        account.ok_or_else(|| anyhow::anyhow!("--account required for offline mode"))?;
    let path = storage::get_default_graph_path(account_id);
    let graph = Graph::load_from_disk(&path)?;

    // Handle preset queries
    if let Some(preset) = &args.preset {
        match preset.as_str() {
            "privesc" => {
                if let Some(principal_name) = &args.principal {
                    if principal_name == "*" {
                        presets::privesc::print_privesc_results(&graph);
                    } else {
                        let node = graph
                            .get_node_by_searchable_name(principal_name)
                            .ok_or_else(|| anyhow::anyhow!("Node not found: {}", principal_name))?;
                        if let Some((can_esc, path)) = presets::privesc::can_privesc(&graph, node) {
                            if can_esc {
                                println!("  {} can escalate to admin:", node.searchable_name());
                                for edge in &path {
                                    println!("    {}", edge.describe());
                                }
                            } else {
                                println!("  {} cannot escalate to admin.", node.searchable_name());
                            }
                        }
                    }
                } else {
                    presets::privesc::print_privesc_results(&graph);
                }
            }
            "connected" => {
                let src_name = args
                    .principal
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--principal required for connected preset"))?;
                let dst_name = args.destination.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("--destination required for connected preset")
                })?;
                let src = graph
                    .get_node_by_searchable_name(src_name)
                    .ok_or_else(|| anyhow::anyhow!("Source not found: {}", src_name))?;
                let dst = graph
                    .get_node_by_searchable_name(dst_name)
                    .ok_or_else(|| anyhow::anyhow!("Destination not found: {}", dst_name))?;
                presets::connected::print_connected_results(&graph, src, dst);
            }
            "wrongadmin" => {
                presets::wrongadmin::print_wrong_admin_results(&graph);
            }
            "serviceaccess" => {
                presets::serviceaccess::print_service_access_results(&graph);
            }
            "clusters" => {
                let tag = args
                    .tag
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--tag required for clusters preset"))?;
                presets::clusters::print_cluster_results(&graph, tag);
            }
            "endgame" => {
                // Need resource policies which require loading separately
                presets::endgame::print_endgame_results(&graph, &[]);
            }
            other => {
                anyhow::bail!("Unknown preset: {}", other);
            }
        }
        return Ok(());
    }

    // Standard query
    let action = args
        .action
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--action required (or use --preset)"))?;

    let mut condition_keys = CaseInsensitiveMap::new();
    for cond in &args.condition {
        if let Some((key, value)) = cond.split_once('=') {
            condition_keys.insert_single(key, value);
        }
    }

    if let Some(principal_name) = &args.principal {
        if principal_name == "*" {
            for node in &graph.nodes {
                let result = query_interface::search_authorization_for(
                    &graph,
                    node,
                    action,
                    &args.resource,
                    &condition_keys,
                );
                if result.allowed {
                    result.print_result(action, &args.resource);
                }
            }
        } else {
            let node = graph
                .get_node_by_searchable_name(principal_name)
                .ok_or_else(|| anyhow::anyhow!("Node not found: {}", principal_name))?;
            let result = query_interface::search_authorization_for(
                &graph,
                node,
                action,
                &args.resource,
                &condition_keys,
            );
            result.print_result(action, &args.resource);
        }
    } else {
        // No principal = check all
        for node in &graph.nodes {
            let result = query_interface::search_authorization_for(
                &graph,
                node,
                action,
                &args.resource,
                &condition_keys,
            );
            if result.allowed {
                result.print_result(action, &args.resource);
            }
        }
    }

    Ok(())
}
