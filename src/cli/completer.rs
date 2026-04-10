//! Tab-completion and inline hints for the REPL and TUI, powered by graph data.

use std::sync::Arc;

use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::{Hint, Hinter};
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::model::graph::Graph;

/// Completion candidates extracted from a loaded graph.
pub struct GraphCompleter {
    /// Searchable names: "user/Alice", "role/Admin", etc.
    pub principals: Vec<String>,
    /// Full ARNs
    pub arns: Vec<String>,
    /// Policy names
    pub policy_names: Vec<String>,
    /// Account IDs seen
    pub account_ids: Vec<String>,
    /// Common IAM actions
    pub actions: Vec<String>,
    /// Preset names
    pub presets: Vec<String>,
    /// Query keywords
    pub keywords: Vec<String>,
}

impl GraphCompleter {
    pub fn from_graph(graph: &Graph) -> Self {
        let mut principals: Vec<String> = graph
            .nodes
            .iter()
            .map(|n| n.searchable_name().to_string())
            .collect();
        principals.sort();
        principals.dedup();

        let mut arns: Vec<String> = graph.nodes.iter().map(|n| n.arn.clone()).collect();
        arns.sort();

        let mut policy_names: Vec<String> = graph.policies.iter().map(|p| p.name.clone()).collect();
        policy_names.sort();
        policy_names.dedup();

        let mut account_ids = vec![graph.metadata.account_id.clone()];
        // Extract any other account IDs from ARNs
        for node in &graph.nodes {
            let acct = crate::util::arns::get_account_id(&node.arn).to_string();
            if !account_ids.contains(&acct) && !acct.is_empty() {
                account_ids.push(acct);
            }
        }

        // Common IAM actions seen in policies
        let mut actions = Vec::new();
        for policy in graph.policies.iter() {
            extract_actions(&policy.policy_doc, &mut actions);
        }
        for node in &graph.nodes {
            for policy in &node.attached_policies {
                extract_actions(&policy.policy_doc, &mut actions);
            }
        }
        actions.sort();
        actions.dedup();

        let presets = vec![
            "privesc".into(),
            "connected".into(),
            "wrongadmin".into(),
            "endgame".into(),
            "serviceaccess".into(),
            "clusters".into(),
        ];

        let keywords = vec![
            "who".into(),
            "can".into(),
            "do".into(),
            "with".into(),
            "when".into(),
            "is".into(),
            "and".into(),
            "preset".into(),
            "exit".into(),
            "quit".into(),
            "help".into(),
        ];

        Self {
            principals,
            arns,
            policy_names,
            account_ids,
            actions,
            presets,
            keywords,
        }
    }

    /// Get all completion candidates as a flat list (for TUI use)
    pub fn all_candidates(&self) -> Vec<&str> {
        let mut all: Vec<&str> = Vec::new();
        all.extend(self.principals.iter().map(|s| s.as_str()));
        all.extend(self.actions.iter().map(|s| s.as_str()));
        all.extend(self.presets.iter().map(|s| s.as_str()));
        all.extend(self.keywords.iter().map(|s| s.as_str()));
        all
    }

    /// Find completions for a partial word
    pub fn complete_word(&self, word: &str) -> Vec<String> {
        let lower = word.to_lowercase();
        let mut results = Vec::new();

        // Check each category
        for p in &self.principals {
            if p.to_lowercase().starts_with(&lower) {
                results.push(p.clone());
            }
        }
        for a in &self.actions {
            if a.to_lowercase().starts_with(&lower) {
                results.push(a.clone());
            }
        }
        for p in &self.presets {
            if p.starts_with(&lower) {
                results.push(p.clone());
            }
        }
        for k in &self.keywords {
            if k.starts_with(&lower) {
                results.push(k.clone());
            }
        }
        for a in &self.arns {
            if a.to_lowercase().starts_with(&lower) {
                results.push(a.clone());
            }
        }
        for a in &self.account_ids {
            if a.starts_with(&lower) {
                results.push(a.clone());
            }
        }
        for p in &self.policy_names {
            if p.to_lowercase().starts_with(&lower) {
                results.push(p.clone());
            }
        }

        results.sort();
        results.dedup();
        results
    }
}

fn extract_actions(doc: &serde_json::Value, out: &mut Vec<String>) {
    if let Some(stmts) = doc.get("Statement") {
        let stmts = match stmts {
            serde_json::Value::Array(arr) => arr.iter().collect::<Vec<_>>(),
            other => vec![other],
        };
        for stmt in stmts {
            for key in &["Action", "NotAction"] {
                if let Some(actions) = stmt.get(key) {
                    match actions {
                        serde_json::Value::String(s) if s != "*" => out.push(s.clone()),
                        serde_json::Value::Array(arr) => {
                            for v in arr {
                                if let Some(s) = v.as_str() {
                                    if s != "*" {
                                        out.push(s.to_string());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

// ─── Rustyline integration ──────────────────────────────────────

pub struct ReplHelper {
    pub completer: GraphCompleter,
}

impl Helper for ReplHelper {}
impl Validator for ReplHelper {}

impl Highlighter for ReplHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        // Dim gray hint text
        std::borrow::Cow::Owned(format!("\x1b[90m{}\x1b[0m", hint))
    }
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // Find the word being typed (go back from cursor to last space)
        let before = &line[..pos];
        let word_start = before.rfind(' ').map(|i| i + 1).unwrap_or(0);
        let word = &before[word_start..];

        if word.is_empty() {
            return Ok((pos, vec![]));
        }

        let completions = self.completer.complete_word(word);
        let pairs: Vec<Pair> = completions
            .into_iter()
            .map(|c| {
                let replacement = c[word.len()..].to_string();
                Pair {
                    display: c.clone(),
                    replacement,
                }
            })
            .collect();

        Ok((pos, pairs))
    }
}

impl Hinter for ReplHelper {
    type Hint = InlineHint;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<InlineHint> {
        let before = &line[..pos];
        let word_start = before.rfind(' ').map(|i| i + 1).unwrap_or(0);
        let word = &before[word_start..];

        if word.len() < 2 {
            return None;
        }

        // Find the best single completion to show as ghost text
        let completions = self.completer.complete_word(word);
        completions.first().map(|c| InlineHint {
            text: c[word.len()..].to_string(),
        })
    }
}

#[derive(Debug)]
pub struct InlineHint {
    text: String,
}

impl Hint for InlineHint {
    fn display(&self) -> &str {
        &self.text
    }

    fn completion(&self) -> Option<&str> {
        if self.text.is_empty() {
            None
        } else {
            Some(&self.text)
        }
    }
}
