//! Query AST.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Query {
    /// `who can do <action> with <resource> [when <conditions>]`
    Who {
        action: String,
        resource: String,
        conditions: HashMap<String, String>,
    },
    /// `can <principal> do <action> with <resource> [when <conditions>]`
    Can {
        principal: String,
        action: String,
        resource: String,
        conditions: HashMap<String, String>,
    },
    /// Run a named preset: `preset privesc`, `preset wrongadmin`, ...
    Preset { name: String, arg: Option<String> },
    /// Boolean combinator: `<q1> and <q2>`, `<q1> or <q2>`, `<q1> not <q2>`
    Bool {
        op: BoolOp,
        left: Box<Query>,
        right: Box<Query>,
    },
    /// Mini-Cypher pattern query: `match (a)-[*]->(b:admin)`
    Pattern { text: String },
    /// Run a saved query by name
    Saved { name: String },
    /// List a principal's permissions or reachable nodes
    What { principal: String },
    /// Compare two principals' capabilities
    Compare { a: String, b: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolOp {
    And,
    Or,
    Not, // interpreted as "in left but not right"
}

impl Query {
    /// Convert to the legacy string form for backward-compatible error messages.
    pub fn to_legacy_string(&self) -> String {
        match self {
            Query::Who {
                action, resource, ..
            } => {
                format!("who can do {} with {}", action, resource)
            }
            Query::Can {
                principal,
                action,
                resource,
                ..
            } => {
                format!("can {} do {} with {}", principal, action, resource)
            }
            Query::Preset { name, arg } => {
                if let Some(a) = arg {
                    format!("preset {} {}", name, a)
                } else {
                    format!("preset {}", name)
                }
            }
            Query::Bool { op, left, right } => format!(
                "({}) {} ({})",
                left.to_legacy_string(),
                match op {
                    BoolOp::And => "AND",
                    BoolOp::Or => "OR",
                    BoolOp::Not => "BUT NOT",
                },
                right.to_legacy_string(),
            ),
            Query::Pattern { text } => format!("match {}", text),
            Query::Saved { name } => format!("run {}", name),
            Query::What { principal } => format!("what can {} do", principal),
            Query::Compare { a, b } => format!("compare {} and {}", a, b),
        }
    }
}
