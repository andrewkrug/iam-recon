use clap::Args;

use crate::analysis;
use crate::cli::colors as c;
use crate::model::finding::{Finding, Severity};
use crate::model::graph::Graph;
use crate::model::report::Report;
use crate::util::storage;

#[derive(Args)]
pub struct AnalysisArgs {
    /// Output format: text, json, csv, ocsf
    #[arg(long, short, default_value = "text")]
    pub format: String,

    /// Output file path (default: stdout)
    #[arg(long, short)]
    pub output: Option<String>,
}

pub fn handle(args: AnalysisArgs, account: Option<&str>) -> anyhow::Result<()> {
    let account_id =
        account.ok_or_else(|| anyhow::anyhow!("--account required for offline mode"))?;
    let path = storage::get_default_graph_path(account_id);
    let graph = Graph::load_from_disk(&path)?;

    let report = analysis::gen_report(&graph);

    let content = match args.format.as_str() {
        "json" => format_json(&report)?,
        "csv" => format_csv(&report),
        "ocsf" => format_ocsf(&report)?,
        _ => {
            print_text_report(&report);
            if let Some(output) = &args.output {
                let json = serde_json::to_string_pretty(&report)?;
                std::fs::write(output, &json)?;
                println!("\n  {} {}", c::ok("Saved"), c::dim(output));
            }
            return Ok(());
        }
    };

    if let Some(output) = &args.output {
        std::fs::write(output, &content)?;
        println!("{} {}", c::ok("Report written to"), output);
    } else {
        println!("{}", content);
    }

    Ok(())
}

// ── Text ──────────────────────────────────────────────────────────

fn print_text_report(report: &Report) {
    let high: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .collect();
    let medium: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .collect();
    let low: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .collect();

    println!("{}", c::header("IAM Recon Security Analysis"));
    println!("{}", c::kv("Account:", &report.account_id));
    println!(
        "{}",
        c::kv(
            "Generated:",
            &report
                .generated_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
        )
    );
    println!(
        "  {}  {} total  |  {} {}  {} {}  {} {}",
        c::dim("Findings:"),
        c::stat(report.findings.len()),
        c::stat(high.len()),
        c::bold_red("high"),
        c::stat(medium.len()),
        c::bold_yellow("medium"),
        c::stat(low.len()),
        c::blue("low"),
    );

    if report.findings.is_empty() {
        println!("\n  {}", c::ok("No findings."));
        return;
    }

    if !high.is_empty() {
        println!("\n{}", c::divider(&c::bold_red("HIGH")));
        for f in &high {
            print_finding(f);
        }
    }
    if !medium.is_empty() {
        println!("\n{}", c::divider(&c::bold_yellow("MEDIUM")));
        for f in &medium {
            print_finding(f);
        }
    }
    if !low.is_empty() {
        println!("\n{}", c::divider(&c::blue("LOW")));
        for f in &low {
            print_finding(f);
        }
    }
}

fn print_finding(f: &Finding) {
    println!();
    println!(
        "  {} {}",
        c::severity_badge(f.severity),
        c::bold_white(&f.title)
    );
    println!("  {} {}", c::dim("Impact:"), f.impact);

    for line in wrap_text(&f.description, 72) {
        if line.is_empty() {
            println!();
        } else {
            println!("  {}", c::gray(&line));
        }
    }

    if !f.recommendation.is_empty() {
        println!("  {}", c::dim("Recommendation:"));
        for line in wrap_text(&f.recommendation, 72) {
            if line.is_empty() {
                println!();
            } else {
                println!("  {}", c::green(&line));
            }
        }
    }
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let paragraph = paragraph.trim();
        if paragraph.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.len() + word.len() + 1 > width && !current.is_empty() {
                lines.push(current);
                current = String::new();
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    lines
}

// ── JSON ──────────────────────────────────────────────────────────

fn format_json(report: &Report) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

// ── CSV ───────────────────────────────────────────────────────────

fn format_csv(report: &Report) -> String {
    let mut csv = String::new();
    csv.push_str("severity,title,impact,description,recommendation\n");
    for f in &report.findings {
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            f.severity,
            csv_escape(&f.title),
            csv_escape(&f.impact),
            csv_escape(&f.description),
            csv_escape(&f.recommendation),
        ));
    }
    csv
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ── OCSF (Open Cybersecurity Schema Framework) ───────────────────

fn format_ocsf(report: &Report) -> anyhow::Result<String> {
    let ocsf_findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            serde_json::json!({
                "class_uid": 2001,
                "class_name": "Security Finding",
                "category_uid": 2,
                "category_name": "Findings",
                "activity_id": 1,
                "activity_name": "Create",
                "severity_id": ocsf_severity_id(f.severity),
                "severity": f.severity.to_string(),
                "status_id": 1,
                "status": "New",
                "time": report.generated_at.timestamp(),
                "message": f.title,
                "finding_info": {
                    "uid": format!("iam-recon-{}-{}", report.account_id, i + 1),
                    "title": f.title,
                    "desc": f.description,
                    "types": ["Privilege Escalation"],
                    "created_time": report.generated_at.timestamp(),
                    "modified_time": report.generated_at.timestamp(),
                    "product_uid": "iam-recon",
                    "data_sources": ["AWS IAM"],
                },
                "resources": [{
                    "uid": &report.account_id,
                    "type": "AWS Account",
                    "cloud": {
                        "provider": "AWS",
                        "account": { "uid": &report.account_id }
                    }
                }],
                "remediation": { "desc": f.recommendation },
                "impact": f.impact,
                "metadata": {
                    "version": "1.1.0",
                    "product": {
                        "name": "IAM Recon",
                        "vendor_name": "iam-recon",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "log_name": "iam-recon-analysis",
                }
            })
        })
        .collect();

    Ok(serde_json::to_string_pretty(&ocsf_findings)?)
}

fn ocsf_severity_id(s: Severity) -> u8 {
    match s {
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
    }
}
