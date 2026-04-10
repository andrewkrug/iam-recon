use clap::Args;

use crate::cli::colors as c;
use crate::model::graph::Graph;
use crate::querying::query_actions;
use crate::util::storage;

#[derive(Args)]
pub struct QueryArgs {
    /// Natural language query
    pub query: Vec<String>,
}

pub fn handle(args: QueryArgs, account: Option<&str>) -> anyhow::Result<()> {
    let account_id =
        account.ok_or_else(|| anyhow::anyhow!("--account required for offline mode"))?;
    let path = storage::get_default_graph_path(account_id);
    let graph = Graph::load_from_disk(&path)?;

    let query_str = args.query.join(" ");
    let results = query_actions::execute_query(&graph, &query_str)?;

    for result in &results {
        result.print_result(&query_str, "*");
    }

    if results.is_empty() {
        println!("  {}", c::dim("No results found."));
    }

    Ok(())
}
