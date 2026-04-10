pub mod findings;

use crate::model::graph::Graph;
use crate::model::report::Report;

/// Generate a complete analysis report for a graph
pub fn gen_report(graph: &Graph) -> Report {
    let findings = findings::gen_all_findings(graph);
    Report::new(&graph.metadata.account_id, findings)
}
