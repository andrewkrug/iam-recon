use std::collections::HashMap;
use std::sync::Mutex;

use regex::Regex;

/// Thread-safe cache for compiled regex patterns
static PATTERN_CACHE: std::sync::LazyLock<Mutex<HashMap<String, Regex>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Check if `value` matches the IAM wildcard `pattern`.
/// Supports `*` (any characters) and `?` (single character).
/// Matching is case-insensitive (per AWS IAM behavior).
pub fn matches(pattern: &str, value: &str) -> bool {
    let regex = compile_pattern(pattern);
    regex.is_match(value)
}

/// Check if an IAM action matches a pattern, with expansion.
/// Handles patterns like "iam:*", "s3:Get*", etc.
pub fn action_matches(pattern: &str, action: &str) -> bool {
    matches(pattern, action)
}

/// Check if an IAM resource ARN matches a pattern.
/// Handles patterns like "arn:aws:s3:::bucket/*", "*", etc.
pub fn resource_matches(pattern: &str, resource: &str) -> bool {
    matches(pattern, resource)
}

/// Expand variable references in a pattern using condition context.
/// E.g., "arn:aws:s3:::${aws:username}/*" with aws:username=Alice
/// becomes "arn:aws:s3:::Alice/*"
pub fn expand_variables(
    pattern: &str,
    context: &crate::util::case_insensitive_map::CaseInsensitiveMap,
) -> String {
    let mut result = pattern.to_string();
    // Find all ${...} patterns and replace with context values
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let replacement = context.get_first(var_name).unwrap_or(""); // If variable not found, replace with empty
            result = format!(
                "{}{}{}",
                &result[..start],
                replacement,
                &result[start + end + 1..]
            );
        } else {
            break;
        }
    }
    result
}

fn compile_pattern(pattern: &str) -> Regex {
    let mut cache = PATTERN_CACHE.lock().unwrap();
    if let Some(regex) = cache.get(pattern) {
        return regex.clone();
    }

    let regex_str = pattern_to_regex(pattern);
    let regex = Regex::new(&regex_str).unwrap_or_else(|_| {
        // Fallback: escape the whole thing for an exact match
        Regex::new(&format!("(?i)^{}$", regex::escape(pattern))).unwrap()
    });

    cache.insert(pattern.to_string(), regex.clone());
    regex
}

fn pattern_to_regex(pattern: &str) -> String {
    let mut regex = String::with_capacity(pattern.len() * 2 + 8);
    regex.push_str("(?i)^");

    for ch in pattern.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '$' | '^' | '+' | '{' | '}' | '[' | ']' | '(' | ')' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }

    regex.push('$');
    regex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches("iam:GetUser", "iam:GetUser"));
        assert!(matches("iam:GetUser", "IAM:GETUSER")); // case insensitive
    }

    #[test]
    fn test_star_wildcard() {
        assert!(matches("iam:*", "iam:GetUser"));
        assert!(matches("*", "anything"));
        assert!(matches("s3:Get*", "s3:GetObject"));
        assert!(!matches("s3:Get*", "s3:PutObject"));
    }

    #[test]
    fn test_question_wildcard() {
        assert!(matches("s3:Get?bject", "s3:GetObject"));
        assert!(!matches("s3:Get?bject", "s3:GetXXbject"));
    }

    #[test]
    fn test_arn_pattern() {
        assert!(matches(
            "arn:aws:s3:::my-bucket/*",
            "arn:aws:s3:::my-bucket/some/key"
        ));
        assert!(!matches(
            "arn:aws:s3:::my-bucket/*",
            "arn:aws:s3:::other-bucket/key"
        ));
    }

    #[test]
    fn test_special_chars() {
        assert!(matches("my.bucket", "my.bucket"));
        assert!(!matches("my.bucket", "myXbucket")); // . is escaped, not regex .
    }

    #[test]
    fn test_expand_variables() {
        let mut ctx = crate::util::case_insensitive_map::CaseInsensitiveMap::new();
        ctx.insert_single("aws:username", "Alice");
        let result = expand_variables("arn:aws:s3:::${aws:username}/*", &ctx);
        assert_eq!(result, "arn:aws:s3:::Alice/*");
    }
}
