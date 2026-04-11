//! Synonym normalization — rewrites common English phrasings into the canonical
//! keywords that the parser understands.
//!
//! Applied BEFORE lexing so the parser sees a stable token stream.

/// Normalize a query string:
/// - lowercases
/// - strips articles (a, the)
/// - maps verb/noun synonyms to canonical keywords
/// - merges multi-word phrases (e.g. "but not" → "but_not")
/// - dedupes consecutive identical tokens (e.g. "who who" → "who")
/// - collapses whitespace
pub fn normalize(input: &str) -> String {
    let lower = input.to_lowercase().replace('?', " ");
    let raw_words: Vec<String> = lower.split_whitespace().map(String::from).collect();

    // Step 1: Merge multi-word phrases BEFORE single-word mapping
    let merged = merge_phrases(&raw_words);

    // Step 2: Map single words via synonym table
    let mut mapped: Vec<String> = merged.iter().filter_map(|w| map_word(w)).collect();

    // Step 3: Dedupe consecutive identical tokens
    mapped.dedup();

    mapped.join(" ")
}

/// Merge multi-word phrases into canonical tokens.
fn merge_phrases(words: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(words.len());
    let mut i = 0;
    while i < words.len() {
        // "but not" → "but_not"
        if i + 1 < words.len() && words[i] == "but" && words[i + 1] == "not" {
            out.push("but_not".to_string());
            i += 2;
            continue;
        }
        // "show me" → drop both (combined with next word)
        if i + 1 < words.len() && words[i] == "show" && words[i + 1] == "me" {
            out.push("who".to_string());
            i += 2;
            continue;
        }
        // "tell me" → "who"
        if i + 1 < words.len() && words[i] == "tell" && words[i + 1] == "me" {
            out.push("who".to_string());
            i += 2;
            continue;
        }
        out.push(words[i].clone());
        i += 1;
    }
    out
}

/// Map a single lowercased word to its canonical form, or None to drop it.
fn map_word(w: &str) -> Option<String> {
    // Words to drop entirely (articles, fillers)
    const DROP: &[&str] = &["a", "an", "the", "some", "any", "please", "me", "us"];
    if DROP.contains(&w) {
        return None;
    }

    // Canonical keyword mapping
    let canonical = match w {
        // "who can do" — NOTE: "what" is NOT here because `what can X` has its own parse rule
        "which" | "show" | "find" | "list" | "display" | "give" | "tell" => "who",
        "principals" | "principal" | "users" | "roles" | "entities" | "identities" => "",
        "has" | "have" | "hold" | "holds" => "can",
        // verbs → "do" — NOTE: "run" is NOT here; it's reserved for `run <saved>`
        "perform" | "performs" | "execute" | "executes" | "invoke" | "invokes" | "call"
        | "calls" | "trigger" | "triggers" | "use" | "uses" | "make" | "makes" => "do",
        // "with resource"
        "on" | "against" | "for" | "to" | "at" => "with",
        // "when conditions"
        "if" | "given" | "where" => "when",
        // "and / or / except / but not"
        "plus" | "&" | "&&" => "and",
        "|" | "||" => "or",
        "except" | "minus" | "-" | "without" | "excluding" => "but_not",
        // "reach / assume" → special verbs
        "reach" | "access" | "become" => "reach",
        "assume" | "assumes" | "impersonate" => "assume",
        // "admin" is a keyword itself
        _ => return Some(w.to_string()),
    };

    if canonical.is_empty() {
        None
    } else {
        Some(canonical.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_who_variants() {
        assert_eq!(
            normalize("who can do iam:CreateUser"),
            "who can do iam:createuser"
        );
        assert_eq!(
            normalize("which principals can do iam:CreateUser"),
            "who can do iam:createuser"
        );
        assert_eq!(
            normalize("Show me who can invoke lambda:InvokeFunction"),
            "who can do lambda:invokefunction"
        );
        // "what" is preserved because `what can X` has its own parse rule
        assert_eq!(normalize("what can user/alice"), "what can user/alice");
    }

    #[test]
    fn test_normalize_verbs() {
        assert_eq!(
            normalize("who can perform s3:GetObject"),
            "who can do s3:getobject"
        );
        assert_eq!(
            normalize("who can invoke lambda on *"),
            "who can do lambda with *"
        );
    }

    #[test]
    fn test_normalize_drop_articles() {
        assert_eq!(
            normalize("who can do a thing with the bucket"),
            "who can do thing with bucket"
        );
    }

    #[test]
    fn test_normalize_but_not() {
        assert_eq!(
            normalize("who can do X but not who has admin"),
            "who can do x but_not who can admin"
        );
    }
}
