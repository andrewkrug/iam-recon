use clap::Args;

use crate::cli::colors as c;
use crate::cli::completer::{GraphCompleter, ReplHelper};
use crate::model::graph::Graph;
use crate::querying::nlq;
use crate::util::storage;

#[derive(Args)]
pub struct ReplArgs {}

pub fn handle(_args: ReplArgs, account: Option<&str>) -> anyhow::Result<()> {
    let account_id =
        account.ok_or_else(|| anyhow::anyhow!("--account required for offline mode"))?;
    let path = storage::get_default_graph_path(account_id);
    let graph = Graph::load_from_disk(&path)?;

    println!("{}", c::header("IAM Recon REPL"));
    println!("{}", c::kv("Account:", &graph.metadata.account_id));

    // Build completer from graph data
    let completer = GraphCompleter::from_graph(&graph);
    let n_principals = completer.principals.len();
    let n_actions = completer.actions.len();
    println!(
        "  {} Tab-completion loaded: {} principals, {} actions",
        c::dim("Tip:"),
        c::stat(n_principals),
        c::stat(n_actions)
    );
    println!(
        "  {} Type {} for usage, {} to quit.\n",
        c::dim("    "),
        c::bold_white("help"),
        c::bold_white("exit")
    );

    let helper = ReplHelper { completer };
    let config = rustyline::Config::builder()
        .completion_type(rustyline::CompletionType::List)
        .build();
    let mut rl = rustyline::Editor::with_config(config)?;
    rl.set_helper(Some(helper));

    loop {
        let prompt = if c::enabled() {
            "\x1b[36miam-recon>\x1b[0m ".to_string()
        } else {
            "iam-recon> ".to_string()
        };

        let readline = rl.readline(&prompt);
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if line == "exit" || line == "quit" {
                    break;
                }
                if line == "help" {
                    println!("  {} who can do <action> with <resource>", c::dim("*"));
                    println!(
                        "  {} can <principal> do <action> with <resource>",
                        c::dim("*")
                    );
                    println!(
                        "  {} can <principal> do <action> with <resource> when <key> is <value>",
                        c::dim("*")
                    );
                    println!("  {} preset privesc *", c::dim("*"));
                    println!("  {} exit", c::dim("*"));
                    println!();
                    println!(
                        "  {} Tab to complete, Right-arrow to accept hint\n",
                        c::dim("Tip:")
                    );
                    continue;
                }

                let _ = rl.add_history_entry(line);

                let idx = nlq::FuzzyIndex::from_graph(&graph);
                match nlq::parser::parse(line) {
                    Ok(parsed) => match nlq::executor::execute(&graph, &parsed, &idx) {
                        Ok(result) => {
                            for note in &result.notes {
                                println!("  {} {}", c::dim("[note]"), note);
                            }
                            for qr in &result.results {
                                qr.print_result(line, "*");
                            }
                            for node in &result.pattern_matches {
                                println!(
                                    "  {}",
                                    c::node_name(
                                        node.searchable_name(),
                                        node.is_admin,
                                        node.is_user()
                                    )
                                );
                            }
                            if result.results.is_empty() && result.pattern_matches.is_empty() {
                                println!("  {}", c::dim("No results."));
                            }
                        }
                        Err(e) => {
                            println!("  {} {}", c::bold_red("Error:"), e);
                        }
                    },
                    Err(e) => {
                        println!("{}", e.render());
                    }
                }
                println!();
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("{}", c::dim("Interrupted"));
                break;
            }
            Err(rustyline::error::ReadlineError::Eof) => break,
            Err(e) => {
                println!("{} {}", c::bold_red("Error:"), e);
                break;
            }
        }
    }

    Ok(())
}
