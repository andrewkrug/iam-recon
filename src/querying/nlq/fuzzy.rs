//! Fuzzy matching for action and principal names using Levenshtein distance.

use strsim::normalized_levenshtein;

use crate::model::graph::Graph;

/// A fuzzy index of all candidate strings from the graph: principal names,
/// ARNs, policy names, actions seen in policies, and preset names.
#[derive(Debug, Clone)]
pub struct FuzzyIndex {
    pub principals: Vec<String>, // searchable names (user/alice, role/admin)
    pub principal_arns: Vec<String>, // full ARNs
    pub actions: Vec<String>,    // IAM actions seen in policies
    pub policies: Vec<String>,   // policy names
    pub presets: Vec<String>,
}

impl FuzzyIndex {
    pub fn from_graph(graph: &Graph) -> Self {
        let mut principals: Vec<String> = graph
            .nodes
            .iter()
            .map(|n| n.searchable_name().to_string())
            .collect();
        principals.sort();
        principals.dedup();

        let principal_arns: Vec<String> = graph.nodes.iter().map(|n| n.arn.clone()).collect();

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

        let mut policies: Vec<String> = graph.policies.iter().map(|p| p.name.clone()).collect();
        policies.sort();
        policies.dedup();

        let presets = vec![
            "privesc".into(),
            "connected".into(),
            "wrongadmin".into(),
            "endgame".into(),
            "serviceaccess".into(),
            "clusters".into(),
        ];

        Self {
            principals,
            principal_arns,
            actions,
            policies,
            presets,
        }
    }

    /// Find the best match among a haystack. Returns None if nothing is
    /// similar enough (>= 0.6 normalized similarity).
    pub fn best_match<'a>(needle: &str, haystack: &'a [String]) -> Option<&'a String> {
        let needle_lower = needle.to_lowercase();
        haystack
            .iter()
            .map(|h| (h, normalized_levenshtein(&needle_lower, &h.to_lowercase())))
            .filter(|(_, score)| *score >= 0.6)
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(h, _)| h)
    }

    /// Get the top N matches sorted by similarity.
    pub fn top_matches<'a>(needle: &str, haystack: &'a [String], n: usize) -> Vec<Match<'a>> {
        let needle_lower = needle.to_lowercase();
        let mut scored: Vec<Match<'a>> = haystack
            .iter()
            .map(|h| Match {
                value: h,
                score: normalized_levenshtein(&needle_lower, &h.to_lowercase()),
            })
            .filter(|m| m.score >= 0.4)
            .collect();
        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(n);
        scored
    }

    /// Try to canonicalize an action name (e.g. "createuser" -> "iam:CreateUser").
    /// Falls back to exact returned string if no match is found.
    pub fn canonicalize_action(&self, input: &str) -> String {
        // Exact (case-insensitive) match first
        if let Some(exact) = self.actions.iter().find(|a| a.eq_ignore_ascii_case(input)) {
            return exact.clone();
        }
        // Prefix match (e.g. "iam:cre" -> "iam:CreateUser")
        let lower = input.to_lowercase();
        let prefix_matches: Vec<&String> = self
            .actions
            .iter()
            .filter(|a| a.to_lowercase().starts_with(&lower))
            .collect();
        if prefix_matches.len() == 1 {
            return prefix_matches[0].clone();
        }
        // Substring match (e.g. "createuser" -> "iam:CreateUser")
        let substring_matches: Vec<&String> = self
            .actions
            .iter()
            .filter(|a| a.to_lowercase().contains(&lower))
            .collect();
        if substring_matches.len() == 1 {
            return substring_matches[0].clone();
        }
        // Fuzzy match (Levenshtein)
        if let Some(best) = Self::best_match(input, &self.actions) {
            return best.clone();
        }
        input.to_string()
    }

    /// Canonicalize a principal name: "alice" -> "user/alice", etc.
    pub fn canonicalize_principal(&self, input: &str) -> String {
        if input == "*" {
            return input.to_string();
        }
        // Exact match
        if self
            .principals
            .iter()
            .any(|p| p.eq_ignore_ascii_case(input))
        {
            return self
                .principals
                .iter()
                .find(|p| p.eq_ignore_ascii_case(input))
                .cloned()
                .unwrap_or_else(|| input.to_string());
        }
        // Strip prefix if present for matching
        let bare = input
            .trim_start_matches("user/")
            .trim_start_matches("role/");
        let with_user = format!("user/{}", bare);
        let with_role = format!("role/{}", bare);
        for candidate in &[with_user, with_role] {
            if let Some(hit) = self
                .principals
                .iter()
                .find(|p| p.eq_ignore_ascii_case(candidate))
            {
                return hit.clone();
            }
        }
        // Substring match (unique)
        let lower = input.to_lowercase();
        let hits: Vec<&String> = self
            .principals
            .iter()
            .filter(|p| p.to_lowercase().contains(&lower))
            .collect();
        if hits.len() == 1 {
            return hits[0].clone();
        }
        // Fuzzy
        if let Some(best) = Self::best_match(input, &self.principals) {
            return best.clone();
        }
        input.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct Match<'a> {
    pub value: &'a String,
    pub score: f64,
}

fn extract_actions(doc: &serde_json::Value, out: &mut Vec<String>) {
    let stmts = match doc.get("Statement") {
        Some(serde_json::Value::Array(a)) => a.clone(),
        Some(s) => vec![s.clone()],
        None => return,
    };
    for stmt in &stmts {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_best_match() {
        let haystack = vec!["iam:CreateUser".to_string(), "iam:DeleteUser".to_string()];
        let best = FuzzyIndex::best_match("createuser", &haystack);
        assert_eq!(best.map(|s| s.as_str()), Some("iam:CreateUser"));
    }

    #[test]
    fn test_typo() {
        let haystack = vec![
            "iam:CreateUser".to_string(),
            "iam:AttachRolePolicy".to_string(),
        ];
        // Typo: "creatuser" missing an 'e'
        let best = FuzzyIndex::best_match("iam:CreatUser", &haystack);
        assert_eq!(best.map(|s| s.as_str()), Some("iam:CreateUser"));
    }
}
