pub mod analysis;
pub mod argquery;
pub mod colors;
pub mod completer;
pub mod graph;
pub mod orgs;
pub mod pathfinding_cmd;
pub mod policies_cmd;
pub mod query;
pub mod repl;
pub mod visualize;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "iam-recon",
    about = "AWS IAM privilege escalation and attack path mapper",
    version
)]
pub struct Cli {
    /// AWS CLI profile to use
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// AWS account ID (offline mode)
    #[arg(long, global = true)]
    pub account: Option<String>,

    /// Enable debug logging
    #[arg(long, global = true)]
    pub debug: bool,

    /// Launch interactive TUI dashboard
    #[arg(long, global = true)]
    pub tui: bool,

    /// Compact output for LLM/AI agent consumption (no color, minimal formatting, token-efficient)
    #[arg(long, global = true)]
    pub compact: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Build and manage the IAM graph
    Graph(graph::GraphArgs),
    /// AWS Organizations operations
    Orgs(orgs::OrgsArgs),
    /// Natural language queries
    Query(query::QueryArgs),
    /// Argument-based queries
    Argquery(argquery::ArgqueryArgs),
    /// Interactive query REPL
    Repl(repl::ReplArgs),
    /// Visualize the graph
    Visualize(visualize::VisualizeArgs),
    /// Run security analysis
    Analysis(analysis::AnalysisArgs),
    /// Map dangerous privileges to pathfinding.cloud escalation paths
    Pathfinding(pathfinding_cmd::PathfindingArgs),
    /// Browse cached IAM policy documents
    Policies(policies_cmd::PoliciesArgs),
}

pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    // Set compact mode globally before any output
    colors::set_compact(cli.compact);

    // TUI mode: launch full-screen dashboard. Account is optional — if not
    // provided or the graph doesn't exist, the TUI lands on the Create Graph
    // wizard so the user can pick a profile and scan.
    if cli.tui {
        return crate::tui::run_tui(cli.account.as_deref());
    }

    let command = cli
        .command
        .ok_or_else(|| anyhow::anyhow!("No subcommand provided. Use --help or --tui."))?;

    match command {
        Commands::Graph(args) => {
            graph::handle(args, cli.profile.as_deref(), cli.account.as_deref()).await
        }
        Commands::Orgs(args) => orgs::handle(args, cli.profile.as_deref()).await,
        Commands::Query(args) => query::handle(args, cli.account.as_deref()),
        Commands::Argquery(args) => argquery::handle(args, cli.account.as_deref()),
        Commands::Repl(args) => repl::handle(args, cli.account.as_deref()),
        Commands::Visualize(args) => visualize::handle(args, cli.account.as_deref()).await,
        Commands::Analysis(args) => analysis::handle(args, cli.account.as_deref()),
        Commands::Pathfinding(args) => pathfinding_cmd::handle(args, cli.account.as_deref()),
        Commands::Policies(args) => policies_cmd::handle(args, cli.account.as_deref()),
    }
}
