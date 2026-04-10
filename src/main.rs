#![allow(dead_code, unused_imports)]

use clap::Parser;

mod analysis;
mod cli;
mod edges;
mod error;
mod gathering;
mod model;
mod pathfinding;
mod policy_eval;
mod querying;
mod tui;
mod util;
mod visualization;

use cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .init();

    cli::dispatch(cli).await
}
