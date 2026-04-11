use clap::{Args, Subcommand};

use crate::cli::colors as c;
use crate::model::graph::Graph;
use crate::querying::nlq;
use crate::querying::nlq::llm::LlmProvider;
use crate::querying::nlq::saved::SavedQueryStore;
use crate::querying::nlq::templates::TEMPLATES;
use crate::util::storage;

#[derive(Args)]
pub struct QueryArgs {
    /// Natural-language query (or subcommand: save, list, run, delete, templates, builder)
    pub query: Vec<String>,

    /// Use an LLM backend to translate natural English to a canonical query.
    /// Values: openai, anthropic. Requires OPENAI_API_KEY or ANTHROPIC_API_KEY.
    #[arg(long)]
    pub llm: Option<String>,

    /// Show parser notes (fuzzy matches, canonicalizations) alongside results
    #[arg(long, short)]
    pub verbose: bool,

    #[command(subcommand)]
    pub sub: Option<QuerySub>,
}

#[derive(Subcommand)]
pub enum QuerySub {
    /// Save a query under a name for later use
    Save { name: String, query: Vec<String> },
    /// List saved queries
    List,
    /// Run a saved query by name
    Run { name: String },
    /// Delete a saved query
    Delete { name: String },
    /// Show question templates / example queries
    Templates,
}

pub fn handle(args: QueryArgs, account: Option<&str>) -> anyhow::Result<()> {
    // Handle non-graph-requiring subcommands first
    if let Some(ref sub) = args.sub {
        match sub {
            QuerySub::Save { name, query } => return handle_save(name, query),
            QuerySub::List => return handle_list(),
            QuerySub::Delete { name } => return handle_delete(name),
            QuerySub::Templates => return handle_templates(),
            QuerySub::Run { .. } => { /* falls through, needs graph */ }
        }
    }

    let account_id =
        account.ok_or_else(|| anyhow::anyhow!("--account required for offline mode"))?;
    let path = storage::get_default_graph_path(account_id);
    let graph = Graph::load_from_disk(&path)?;
    let idx = nlq::FuzzyIndex::from_graph(&graph);

    // `query run <name>` path — look up saved and execute
    if let Some(QuerySub::Run { name }) = &args.sub {
        let store = SavedQueryStore::load_default()?;
        let query_text = store.get(name).ok_or_else(|| {
            anyhow::anyhow!("No saved query named '{}'. Try: iam-recon query list", name)
        })?;
        println!("  {} {}", c::dim("running:"), c::bold_white(query_text));
        return run_query_string(&graph, &idx, query_text, args.verbose);
    }

    let query_str = args.query.join(" ");
    if query_str.trim().is_empty() {
        anyhow::bail!("empty query. Try 'iam-recon query templates' for examples");
    }

    // LLM translation mode
    if let Some(provider_str) = &args.llm {
        let provider = LlmProvider::parse(provider_str).ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown LLM provider: {}. Use: openai, anthropic",
                provider_str
            )
        })?;
        println!("  {} using {:?} to translate...", c::dim("[llm]"), provider);
        let hint = nlq::llm::build_schema_hint(&graph);
        let runtime = tokio::runtime::Runtime::new()?;
        let translated = runtime
            .block_on(async { nlq::llm::translate(provider, &query_str, Some(&hint)).await })
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("  {} {}", c::dim("translated:"), c::bold_white(&translated));
        return run_query_string(&graph, &idx, &translated, args.verbose);
    }

    run_query_string(&graph, &idx, &query_str, args.verbose)
}

fn run_query_string(
    graph: &Graph,
    idx: &nlq::FuzzyIndex,
    query_str: &str,
    verbose: bool,
) -> anyhow::Result<()> {
    let parsed = match nlq::parser::parse(query_str) {
        Ok(q) => q,
        Err(e) => {
            println!("{}", e.render());
            // Suggest action fuzzy matches if the error looks action-related
            let parts: Vec<&str> = query_str.split_whitespace().collect();
            for part in &parts {
                let matches = nlq::FuzzyIndex::top_matches(part, &idx.actions, 3);
                if !matches.is_empty() && matches[0].score > 0.6 {
                    println!(
                        "  {} Did you mean action: {}?",
                        c::dim("hint:"),
                        c::bold_white(matches[0].value)
                    );
                    break;
                }
            }
            anyhow::bail!("query parse failed");
        }
    };

    let result =
        nlq::executor::execute(graph, &parsed, idx).map_err(|e| anyhow::anyhow!("{}", e))?;

    if verbose {
        for note in &result.notes {
            println!("  {} {}", c::dim("[note]"), note);
        }
    }

    for qr in &result.results {
        qr.print_result(query_str, "*");
    }

    if !result.pattern_matches.is_empty() {
        println!("{}", c::header("Pattern matches"));
        for node in &result.pattern_matches {
            println!(
                "  {}",
                c::node_name(node.searchable_name(), node.is_admin, node.is_user())
            );
        }
    }

    if result.results.is_empty() && result.pattern_matches.is_empty() {
        println!("  {}", c::dim("No results found."));
    }

    Ok(())
}

fn handle_save(name: &str, query: &[String]) -> anyhow::Result<()> {
    if query.is_empty() {
        anyhow::bail!("expected query text after name");
    }
    let query_text = query.join(" ");
    let mut store = SavedQueryStore::load_default().map_err(|e| anyhow::anyhow!("{}", e))?;
    store.add(name, &query_text);
    store.save_default().map_err(|e| anyhow::anyhow!("{}", e))?;
    println!(
        "  {} Saved '{}' = {}",
        c::ok("OK"),
        c::bold_white(name),
        c::dim(&query_text)
    );
    Ok(())
}

fn handle_list() -> anyhow::Result<()> {
    let store = SavedQueryStore::load_default().map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("{}", c::header("Saved queries"));
    if store.queries.is_empty() {
        println!(
            "  {}",
            c::dim("No saved queries yet. Use 'iam-recon query save <name> <query>'")
        );
        return Ok(());
    }
    for (name, text) in store.list() {
        println!("  {} {}", c::bold_cyan(name), c::dim(text));
    }
    Ok(())
}

fn handle_delete(name: &str) -> anyhow::Result<()> {
    let mut store = SavedQueryStore::load_default().map_err(|e| anyhow::anyhow!("{}", e))?;
    if store.remove(name) {
        store.save_default().map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("  {} Deleted '{}'", c::ok("OK"), name);
    } else {
        println!("  {} No saved query named '{}'", c::dim("--"), name);
    }
    Ok(())
}

fn handle_templates() -> anyhow::Result<()> {
    println!("{}", c::header("Query templates"));
    println!(
        "  {}",
        c::dim("Copy and modify these for common questions:")
    );
    println!();
    for t in TEMPLATES {
        println!("  {} {}", c::bold_yellow("Q:"), c::bold_white(t.question));
        println!("  {} {}", c::dim("  →"), c::cyan(t.canonical));
        println!("  {}   {}", c::dim("   "), c::dim(t.description));
        println!();
    }
    Ok(())
}
