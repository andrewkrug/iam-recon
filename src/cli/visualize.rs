use clap::Args;

use crate::cli::colors as c;
use crate::model::graph::Graph;
use crate::util::storage;
use crate::visualization::{dot_writer, graphml_writer, interactive};

#[derive(Args)]
pub struct VisualizeArgs {
    /// Output format: dot, svg, png, pdf, graphml
    #[arg(long, short, default_value = "dot")]
    pub format: String,

    /// Output file path
    #[arg(long, short)]
    pub output: Option<String>,

    /// Only show privilege escalation paths
    #[arg(long)]
    pub privesc_only: bool,

    /// Include service nodes
    #[arg(long)]
    pub with_services: bool,

    /// Launch interactive browser-based visualization (awspx-inspired)
    #[arg(long)]
    pub interactive_viz: bool,
}

pub async fn handle(args: VisualizeArgs, account: Option<&str>) -> anyhow::Result<()> {
    let account_id =
        account.ok_or_else(|| anyhow::anyhow!("--account required for offline mode"))?;
    let path = storage::get_default_graph_path(account_id);
    let graph = Graph::load_from_disk(&path)?;

    if args.interactive_viz {
        interactive::server::serve_interactive(&graph).await?;
        return Ok(());
    }

    let output = args
        .output
        .unwrap_or_else(|| format!("iam_recon_graph.{}", args.format));

    match args.format.as_str() {
        "dot" => {
            let mut buf = Vec::new();
            if args.privesc_only {
                dot_writer::write_privesc_dot(&graph, &mut buf)?;
            } else {
                dot_writer::write_standard_dot(&graph, &mut buf, args.with_services)?;
            }
            std::fs::write(&output, buf)?;
            println!(
                "  {} DOT graph written to {}",
                c::ok("OK"),
                c::bold_white(&output)
            );
        }
        "svg" | "png" | "pdf" => {
            let mut dot_buf = Vec::new();
            if args.privesc_only {
                dot_writer::write_privesc_dot(&graph, &mut dot_buf)?;
            } else {
                dot_writer::write_standard_dot(&graph, &mut dot_buf, args.with_services)?;
            }
            let dot_str = String::from_utf8(dot_buf)?;
            dot_writer::render_dot(&dot_str, &output, &args.format)?;
            println!(
                "  {} {} rendered to {}",
                c::ok("OK"),
                c::bold_white(&args.format.to_uppercase()),
                c::bold_white(&output)
            );
        }
        "graphml" => {
            let mut buf = Vec::new();
            graphml_writer::write_standard_graphml(&graph, &mut buf)?;
            std::fs::write(&output, buf)?;
            println!(
                "  {} GraphML written to {}",
                c::ok("OK"),
                c::bold_white(&output)
            );
        }
        other => {
            anyhow::bail!(
                "Unknown format: {}. Supported: dot, svg, png, pdf, graphml",
                other
            );
        }
    }

    Ok(())
}
