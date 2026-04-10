use std::collections::HashMap;
use std::sync::Arc;

use crate::model::graph::Graph;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

pub fn compose_endgame_map(
    graph: &Graph,
    resource_policies: &[Policy],
) -> HashMap<String, Vec<Arc<Node>>> {
    let mut endgame_map: HashMap<String, Vec<Arc<Node>>> = HashMap::new();

    let modification_actions = [
        ("s3", "s3:PutBucketPolicy"),
        ("sns", "sns:AddPermission"),
        ("sqs", "sqs:AddPermission"),
        ("kms", "kms:PutKeyPolicy"),
        ("secretsmanager", "secretsmanager:PutResourcePolicy"),
    ];

    for policy in resource_policies {
        let service = if policy.arn.contains(":s3:") || policy.arn.starts_with("arn:aws:s3:") {
            "s3"
        } else if policy.arn.contains(":sns:") {
            "sns"
        } else if policy.arn.contains(":sqs:") {
            "sqs"
        } else if policy.arn.contains(":kms:") {
            "kms"
        } else if policy.arn.contains(":secretsmanager:") {
            "secretsmanager"
        } else {
            continue;
        };

        let modify_action = modification_actions
            .iter()
            .find(|(s, _)| *s == service)
            .map(|(_, a)| *a)
            .unwrap_or("*");

        let ctx = CaseInsensitiveMap::new();
        for node in &graph.nodes {
            if authorization::local_check_authorization(node, modify_action, &policy.arn, &ctx) {
                endgame_map
                    .entry(policy.arn.clone())
                    .or_default()
                    .push(Arc::clone(node));
            }
        }
    }

    endgame_map
}

pub fn print_endgame_results(graph: &Graph, resource_policies: &[Policy]) {
    use crate::cli::colors as c;

    let map = compose_endgame_map(graph, resource_policies);

    println!("{}", c::header("Endgame Exposure"));

    if map.is_empty() {
        println!("  {}", c::ok("No endgame exposure found."));
        println!();
        return;
    }

    for (resource_arn, nodes) in &map {
        println!(
            "\n  {} {}",
            c::bold_yellow("*"),
            c::bold_white(resource_arn)
        );
        for node in nodes {
            println!(
                "    {} can modify its resource policy",
                c::node_name(node.searchable_name(), node.is_admin, node.is_user())
            );
        }
    }
    println!();
}
