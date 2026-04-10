use std::io::Write;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::edge::Edge;
use super::node::Node;

/// Result of an authorization query
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub allowed: bool,
    pub edge_list: Vec<Edge>,
    pub node: Arc<Node>,
}

/// JSON-serializable form of QueryResult
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResultData {
    pub allowed: bool,
    pub principal: String,
    pub edge_path: Vec<String>,
}

impl QueryResult {
    pub fn new_allowed(node: Arc<Node>, edge_list: Vec<Edge>) -> Self {
        Self {
            allowed: true,
            edge_list,
            node,
        }
    }

    pub fn new_denied(node: Arc<Node>) -> Self {
        Self {
            allowed: false,
            edge_list: Vec::new(),
            node,
        }
    }

    /// Print the result to stdout with colors
    pub fn print_result(&self, action: &str, resource: &str) {
        use crate::cli::colors as c;

        if c::compact() {
            // LLM-friendly: one line per result, no decoration
            if self.allowed {
                if self.edge_list.is_empty() {
                    println!(
                        "ALLOW {} {} {}",
                        self.node.searchable_name(),
                        action,
                        resource
                    );
                } else {
                    let path: Vec<String> = self
                        .edge_list
                        .iter()
                        .map(|e| {
                            format!(
                                "{}->{}[{}]",
                                e.source.split(':').last().unwrap_or(&e.source),
                                e.destination.split(':').last().unwrap_or(&e.destination),
                                e.short_reason
                            )
                        })
                        .collect();
                    println!(
                        "ALLOW {} {} {} via {}",
                        self.node.searchable_name(),
                        action,
                        resource,
                        path.join(",")
                    );
                }
            } else {
                println!(
                    "DENY {} {} {}",
                    self.node.searchable_name(),
                    action,
                    resource
                );
            }
            return;
        }

        let name = c::node_name(
            self.node.searchable_name(),
            self.node.is_admin,
            self.node.is_user(),
        );

        if self.allowed {
            if self.edge_list.is_empty() {
                println!(
                    "  {} {} can call {} with {}",
                    c::bold_green("ALLOW"),
                    name,
                    c::bold_white(action),
                    c::dim(resource)
                );
            } else {
                let final_node = &self.edge_list.last().unwrap().destination;
                println!(
                    "  {} {} can access {} through {} hop(s):",
                    c::bold_green("ALLOW"),
                    name,
                    c::bold_white(final_node.split(':').last().unwrap_or(final_node)),
                    c::stat(self.edge_list.len())
                );
                for edge in &self.edge_list {
                    let src = edge.source.split(':').last().unwrap_or(&edge.source);
                    let dst = edge
                        .destination
                        .split(':')
                        .last()
                        .unwrap_or(&edge.destination);
                    println!(
                        "    {} {} {} {}",
                        c::cyan(src),
                        c::dim("->"),
                        c::edge_label(&edge.short_reason),
                        c::magenta(dst)
                    );
                }
                println!(
                    "    {} {} can call {} with {}",
                    c::dim("...then"),
                    c::bold_white(final_node.split(':').last().unwrap_or(final_node)),
                    c::bold_white(action),
                    c::dim(resource)
                );
            }
        } else {
            println!(
                "  {} {} cannot call {} with {}",
                c::bold_red("DENY "),
                name,
                c::dim(action),
                c::dim(resource)
            );
        }
    }

    /// Write the result to a writer (plain text, no colors)
    pub fn write_result(
        &self,
        action: &str,
        resource: &str,
        w: &mut dyn Write,
    ) -> std::io::Result<()> {
        if self.allowed {
            if self.edge_list.is_empty() {
                writeln!(
                    w,
                    "{} can call {} with resource {}",
                    self.node.searchable_name(),
                    action,
                    resource
                )?;
            } else {
                let final_node = &self.edge_list.last().unwrap().destination;
                writeln!(
                    w,
                    "{} can access {} and then call {} with resource {}",
                    self.node.searchable_name(),
                    final_node,
                    action,
                    resource
                )?;
            }
        } else {
            writeln!(
                w,
                "{} cannot call {} with resource {}",
                self.node.searchable_name(),
                action,
                resource
            )?;
        }
        Ok(())
    }

    pub fn to_data(&self) -> QueryResultData {
        QueryResultData {
            allowed: self.allowed,
            principal: self.node.arn.clone(),
            edge_path: self.edge_list.iter().map(|e| e.describe()).collect(),
        }
    }
}
