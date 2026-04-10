use clap::Args;

use crate::cli::colors as c;
use crate::model::graph::Graph;
use crate::pathfinding::PathfindingMapper;
use crate::util::storage;

#[derive(Args)]
pub struct PathfindingArgs {
    /// Show only a specific principal (searchable name)
    #[arg(long, short)]
    pub principal: Option<String>,

    /// Output format: text, json
    #[arg(long, short, default_value = "text")]
    pub format: String,
}

pub fn handle(args: PathfindingArgs, account: Option<&str>) -> anyhow::Result<()> {
    let account_id =
        account.ok_or_else(|| anyhow::anyhow!("--account required for offline mode"))?;
    let path = storage::get_default_graph_path(account_id);
    let graph = Graph::load_from_disk(&path)?;

    println!("{}", c::header("Pathfinding.cloud"));
    println!(
        "  {} {} known escalation paths bundled",
        c::dim("Database:"),
        c::stat(PathfindingMapper::path_count())
    );

    if let Some(principal_name) = &args.principal {
        let node = graph
            .get_node_by_searchable_name(principal_name)
            .ok_or_else(|| anyhow::anyhow!("Node not found: {}", principal_name))?;

        let matches = PathfindingMapper::check_node(node);
        if matches.is_empty() {
            println!(
                "\n  {} {} no known paths matched.\n",
                c::node_name(principal_name, node.is_admin, node.is_user()),
                c::dim("—")
            );
        } else {
            println!(
                "\n  {} {} {} paths matched:\n",
                c::node_name(principal_name, node.is_admin, node.is_user()),
                c::dim("—"),
                c::stat(matches.len())
            );
            for m in &matches {
                println!(
                    "  {} {} ({})",
                    c::bold_yellow(&format!("[{}]", m.path.id)),
                    c::bold_white(&m.path.name),
                    c::dim(&m.path.category.to_string())
                );
                println!(
                    "    {} {}",
                    c::dim("Permissions:"),
                    m.matched_permissions.join(", ")
                );
                println!("    {}", c::url(&m.path.url()));
                println!();
            }
        }
    } else {
        match args.format.as_str() {
            "json" => {
                let matches = PathfindingMapper::check_graph(&graph);
                let json = serde_json::to_string_pretty(
                    &matches
                        .iter()
                        .map(|m| {
                            serde_json::json!({
                                "path_id": m.path.id,
                                "path_name": m.path.name,
                                "category": m.path.category.to_string(),
                                "node_arn": m.node_arn,
                                "node_name": m.node_name,
                                "matched_permissions": m.matched_permissions,
                                "url": m.path.url(),
                            })
                        })
                        .collect::<Vec<_>>(),
                )?;
                println!("{}", json);
            }
            _ => {
                let matches = PathfindingMapper::check_graph(&graph);
                if matches.is_empty() {
                    println!("\n  {}\n", c::ok("No escalation paths matched."));
                } else {
                    let unique_nodes: std::collections::HashSet<&str> =
                        matches.iter().map(|m| m.node_arn.as_str()).collect();
                    println!(
                        "\n  {} matches across {} principals\n",
                        c::stat(matches.len()),
                        c::stat(unique_nodes.len())
                    );

                    for m in &matches {
                        let node = graph.get_node_by_arn(&m.node_arn);
                        let is_admin = node.map_or(false, |n| n.is_admin);
                        let is_user = node.map_or(false, |n| n.is_user());

                        println!(
                            "  {} {} {}",
                            c::bold_yellow(&format!("[{}]", m.path.id)),
                            c::node_name(&m.node_name, is_admin, is_user),
                            c::dim(&format!("({})", m.path.category))
                        );
                        println!("    {} {}", c::dim("Path:"), c::bold_white(&m.path.name));
                        println!(
                            "    {} {}",
                            c::dim("Perms:"),
                            m.matched_permissions.join(", ")
                        );
                        println!("    {}", c::url(&m.path.url()));
                        println!();
                    }
                }
            }
        }
    }

    Ok(())
}
