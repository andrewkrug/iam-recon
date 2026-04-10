use std::sync::Arc;

use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::policy_eval::statement_match;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

pub fn compose_wrong_admin_list(graph: &Graph) -> Vec<(Arc<Node>, Vec<String>)> {
    let mut result = Vec::new();
    let ctx = CaseInsensitiveMap::new();

    for node in &graph.nodes {
        if !node.is_admin {
            continue;
        }
        let has_admin_access_policy = node.attached_policies.iter().any(|p| {
            p.name == "AdministratorAccess" && p.arn.contains("aws:policy/AdministratorAccess")
        });
        if has_admin_access_policy {
            continue;
        }

        let mut reasons = Vec::new();
        for policy in node.all_policies() {
            if statement_match::policy_has_matching_statement(policy, "Allow", "*", "*", &ctx) {
                reasons.push(format!(
                    "Policy '{}' grants Action:* Resource:*",
                    policy.name
                ));
            }
        }
        if reasons.is_empty() {
            reasons.push("Admin status set but reason unclear".to_string());
        }
        result.push((Arc::clone(node), reasons));
    }

    result
}

pub fn print_wrong_admin_results(graph: &Graph) {
    use crate::cli::colors as c;

    let wrong_admins = compose_wrong_admin_list(graph);

    println!("{}", c::header("Wrong Admins"));

    if wrong_admins.is_empty() {
        println!(
            "  {}",
            c::ok("All admin nodes have AdministratorAccess policy.")
        );
        println!();
        return;
    }

    for (node, reasons) in &wrong_admins {
        println!(
            "\n  {} {} is admin without AdministratorAccess:",
            c::bold_yellow("!"),
            c::node_name(node.searchable_name(), true, node.is_user())
        );
        for reason in reasons {
            println!("    {} {}", c::dim("*"), reason);
        }
    }
    println!();
}
