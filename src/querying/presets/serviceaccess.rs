use std::collections::HashMap;
use std::sync::Arc;

use crate::model::graph::Graph;
use crate::model::node::Node;

pub fn compose_service_access_map(graph: &Graph) -> HashMap<String, Vec<Arc<Node>>> {
    let mut service_map: HashMap<String, Vec<Arc<Node>>> = HashMap::new();

    for node in &graph.nodes {
        if !node.is_role() {
            continue;
        }
        let trust_policy = match &node.trust_policy {
            Some(tp) => tp,
            None => continue,
        };
        if let Some(statements) = trust_policy.get("Statement").and_then(|s| s.as_array()) {
            for stmt in statements {
                let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
                if !effect.eq_ignore_ascii_case("Allow") {
                    continue;
                }
                if let Some(principal) = stmt.get("Principal") {
                    if let Some(services) = principal.get("Service") {
                        let svc_list = match services {
                            serde_json::Value::String(s) => vec![s.as_str()],
                            serde_json::Value::Array(arr) => {
                                arr.iter().filter_map(|v| v.as_str()).collect()
                            }
                            _ => vec![],
                        };
                        for svc in svc_list {
                            service_map
                                .entry(svc.to_string())
                                .or_default()
                                .push(Arc::clone(node));
                        }
                    }
                }
            }
        }
    }

    service_map
}

pub fn print_service_access_results(graph: &Graph) {
    use crate::cli::colors as c;

    let map = compose_service_access_map(graph);

    println!("{}", c::header("Service Access Mapping"));

    if map.is_empty() {
        println!("  {}", c::dim("No service access mappings found."));
        println!();
        return;
    }

    let mut services: Vec<&String> = map.keys().collect();
    services.sort();

    for service in services {
        let roles = &map[service];
        println!(
            "\n  {} {} ({} roles)",
            c::bold_yellow("*"),
            c::bold_white(service),
            c::stat(roles.len())
        );
        for role in roles {
            println!(
                "    {}",
                c::node_name(role.searchable_name(), role.is_admin, role.is_user())
            );
        }
    }
    println!();
}
