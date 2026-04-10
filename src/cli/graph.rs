use clap::{Args, Subcommand};

use crate::cli::colors as c;
use crate::edges::CheckerKind;
use crate::gathering;
use crate::model::graph::Graph;
use crate::util::storage;

#[derive(Args)]
pub struct GraphArgs {
    #[command(subcommand)]
    pub command: GraphCommand,
}

#[derive(Subcommand)]
pub enum GraphCommand {
    /// Create a new graph from AWS (caches all API responses for offline use)
    Create {
        /// Edge checkers to include (comma-separated, or 'all')
        #[arg(long, default_value = "all")]
        include_services: String,

        /// AWS regions to scan (comma-separated)
        #[arg(long)]
        region_allow_list: Option<String>,

        /// AWS regions to exclude (comma-separated)
        #[arg(long)]
        region_deny_list: Option<String>,
    },
    /// Display information about a stored graph
    Display,
    /// List stored graphs
    List,
    /// Refresh edges from cached data (no AWS access needed)
    Refresh {
        /// Edge checkers to include (comma-separated, or 'all')
        #[arg(long, default_value = "all")]
        include_services: String,
    },
}

pub async fn handle(
    args: GraphArgs,
    profile: Option<&str>,
    account: Option<&str>,
) -> anyhow::Result<()> {
    match args.command {
        GraphCommand::Create {
            include_services,
            region_allow_list,
            region_deny_list,
        } => {
            let checkers: Vec<CheckerKind> = if include_services == "all" {
                CheckerKind::all().to_vec()
            } else {
                include_services
                    .split(',')
                    .filter_map(|s| CheckerKind::from_name(s.trim()))
                    .collect()
            };

            let region_allow: Option<Vec<String>> =
                region_allow_list.map(|s| s.split(',').map(|r| r.trim().to_string()).collect());
            let region_deny: Option<Vec<String>> =
                region_deny_list.map(|s| s.split(',').map(|r| r.trim().to_string()).collect());

            let mut config_loader = aws_config::from_env();
            if let Some(p) = profile {
                config_loader = config_loader.profile_name(p);
            }
            let sdk_config = config_loader.load().await;

            let graph = gathering::create_graph(
                &sdk_config,
                &checkers,
                region_allow.as_deref(),
                region_deny.as_deref(),
            )
            .await?;

            let path = storage::get_default_graph_path(&graph.metadata.account_id);
            graph.store_to_disk(&path)?;

            println!(
                "\n  {} Graph stored at {}",
                c::ok("OK"),
                c::dim(&path.display().to_string())
            );
            println!(
                "  {} {} nodes, {} edges",
                c::dim("   "),
                c::stat(graph.nodes.len()),
                c::stat(graph.edges.len()),
            );
            println!(
                "  {}  API responses cached for offline queries\n",
                c::dim("   ")
            );
            Ok(())
        }
        GraphCommand::Display => {
            let account_id =
                account.ok_or_else(|| anyhow::anyhow!("--account required for offline mode"))?;
            let path = storage::get_default_graph_path(account_id);
            let graph = Graph::load_from_disk(&path)?;

            let users = graph.nodes.iter().filter(|n| n.is_user()).count();
            let roles = graph.nodes.iter().filter(|n| n.is_role()).count();
            let admins = graph.nodes.iter().filter(|n| n.is_admin).count();

            println!("{}", c::header("Graph Summary"));
            println!("{}", c::kv("Account:", &graph.metadata.account_id));
            println!("{}", c::kv("Version:", &graph.metadata.iam_recon_version));
            println!(
                "  {}  {} ({} users, {} roles, {} admins)",
                c::dim("Nodes:"),
                c::stat(graph.nodes.len()),
                c::stat(users),
                c::stat(roles),
                c::bold_red(&admins.to_string()),
            );
            println!("{}", c::kv("Edges:", &graph.edges.len().to_string()));
            println!("{}", c::kv("Policies:", &graph.policies.len().to_string()));
            println!("{}", c::kv("Groups:", &graph.groups.len().to_string()));
            println!();
            Ok(())
        }
        GraphCommand::Refresh { include_services } => {
            let account_id =
                account.ok_or_else(|| anyhow::anyhow!("--account required for refresh"))?;
            let path = storage::get_default_graph_path(account_id);

            let checkers: Vec<CheckerKind> = if include_services == "all" {
                CheckerKind::all().to_vec()
            } else {
                include_services
                    .split(',')
                    .filter_map(|s| CheckerKind::from_name(s.trim()))
                    .collect()
            };

            let graph = gathering::create_graph_from_cache(&path, &checkers)?;
            graph.store_to_disk(&path)?;

            println!("\n  {} Graph refreshed from cache (offline)", c::ok("OK"));
            println!(
                "  {} {} nodes, {} edges\n",
                c::dim("   "),
                c::stat(graph.nodes.len()),
                c::stat(graph.edges.len()),
            );
            Ok(())
        }
        GraphCommand::List => {
            let root = storage::get_storage_root();
            if !root.exists() {
                println!("\n  {} No graphs stored.\n", c::dim("--"));
                return Ok(());
            }
            println!("{}", c::header("Stored Graphs"));
            let mut found = false;
            for entry in std::fs::read_dir(&root)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let metadata_path = entry.path().join("metadata.json");
                    if metadata_path.exists() {
                        found = true;
                        println!("  {}", c::bold_cyan(&entry.file_name().to_string_lossy()));
                    }
                }
            }
            if !found {
                println!("  {}", c::dim("No graphs stored."));
            }
            println!();
            Ok(())
        }
    }
}
