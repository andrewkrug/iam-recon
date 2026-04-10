use clap::Args;

use crate::cli::colors as c;
use crate::gathering::cache;
use crate::util::storage;

#[derive(Args)]
pub struct PoliciesArgs {
    /// Show a specific policy by name (substring match)
    #[arg(long, short)]
    pub name: Option<String>,

    /// Filter by type: managed, inline-user, inline-role, inline-group, trust, permissions-boundary
    #[arg(long, short = 't')]
    pub policy_type: Option<String>,

    /// Filter by attached principal (substring match on ARN)
    #[arg(long, short = 'a')]
    pub attached_to: Option<String>,

    /// Output format: text, json
    #[arg(long, short, default_value = "text")]
    pub format: String,

    /// Show full policy document (otherwise just summary)
    #[arg(long)]
    pub full: bool,
}

pub fn handle(args: PoliciesArgs, account: Option<&str>) -> anyhow::Result<()> {
    let account_id = account.ok_or_else(|| anyhow::anyhow!("--account required"))?;
    let graph_root = storage::get_default_graph_path(account_id);
    let index = cache::load_policy_index(&graph_root)?;

    // Filter
    let filtered: Vec<&cache::PolicyIndexEntry> = index
        .entries
        .iter()
        .filter(|e| {
            let name_ok = args
                .name
                .as_ref()
                .map_or(true, |n| e.name.to_lowercase().contains(&n.to_lowercase()));
            let type_ok = args.policy_type.as_ref().map_or(true, |t| {
                e.policy_type.to_lowercase().contains(&t.to_lowercase())
            });
            let attached_ok = args.attached_to.as_ref().map_or(true, |a| {
                e.attached_to.to_lowercase().contains(&a.to_lowercase())
            });
            name_ok && type_ok && attached_ok
        })
        .collect();

    if args.format == "json" {
        if args.full && filtered.len() == 1 {
            let doc = cache::load_policy(&graph_root, &filtered[0].filename)?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
        } else {
            let listing: Vec<serde_json::Value> = filtered
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "arn": e.arn, "name": e.name,
                        "type": e.policy_type, "attached_to": e.attached_to,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&listing)?);
        }
        return Ok(());
    }

    println!("{}", c::header("Cached Policies"));
    println!(
        "  {} {} policies stored  ({} matched filter)\n",
        c::dim("Account:"),
        c::stat(index.total_policies),
        c::stat(filtered.len())
    );

    if filtered.is_empty() {
        println!("  {}", c::dim("No policies match the filter."));
        return Ok(());
    }

    // If --full and single match, show the full document
    if args.full && filtered.len() == 1 {
        let entry = filtered[0];
        let doc = cache::load_policy(&graph_root, &entry.filename)?;
        println!(
            "  {} {}",
            c::bold_white(&entry.name),
            c::dim(&format!("({})", entry.policy_type))
        );
        println!("  {} {}", c::dim("ARN:"), entry.arn);
        println!("  {} {}\n", c::dim("Attached to:"), entry.attached_to);
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }

    // If --full with multiple matches, show each document
    if args.full {
        for entry in &filtered {
            let doc = cache::load_policy(&graph_root, &entry.filename)?;
            println!("{}", c::divider(&entry.name));
            println!(
                "  {} {} {} {}",
                c::dim("Type:"),
                c::yellow(&entry.policy_type),
                c::dim("Attached to:"),
                entry
                    .attached_to
                    .split(':')
                    .last()
                    .unwrap_or(&entry.attached_to)
            );
            println!(
                "{}\n",
                serde_json::to_string_pretty(&doc.get("document").unwrap_or(&doc))?
            );
        }
        return Ok(());
    }

    // Summary listing
    let type_colors = |t: &str| -> String {
        match t {
            "managed" => c::bold_cyan(t),
            "inline-user" | "inline-role" | "inline-group" => c::yellow(t),
            "trust" => c::magenta(t),
            "permissions-boundary" => c::bold_yellow(t),
            _ => c::gray(t),
        }
    };

    for entry in &filtered {
        let attached = entry
            .attached_to
            .split(':')
            .last()
            .unwrap_or(&entry.attached_to);
        println!(
            "  {} {} {}  {}",
            type_colors(&entry.policy_type),
            c::bold_white(&entry.name),
            c::dim("->"),
            c::gray(attached)
        );
    }
    println!(
        "\n  {} Use {} to see full document\n",
        c::dim("Tip:"),
        c::bold_white("--full")
    );

    Ok(())
}
