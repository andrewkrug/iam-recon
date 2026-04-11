//! LLM-backed query translation and agent mode.
//!
//! Two modes:
//! 1. **Translate**: LLM rewrites a natural-language question into a canonical
//!    IAM Recon query string, which the normal parser then executes.
//! 2. **Agent**: LLM is given access to a small set of "tools" (check_auth,
//!    find_paths, list_principals) and reasons about the question directly.
//!
//! Both modes support OpenAI and Anthropic APIs selected via `--llm` flag.
//! Requires env var `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

use serde_json::json;

use super::error::NlqError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmProvider {
    OpenAi,
    Anthropic,
}

impl LlmProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "openai" | "oai" | "gpt" => Some(Self::OpenAi),
            "anthropic" | "claude" => Some(Self::Anthropic),
            _ => None,
        }
    }
}

const SYSTEM_PROMPT: &str = r#"You are a query translator for IAM Recon, an AWS IAM attack path mapper.
Convert the user's natural-language question to EXACTLY ONE canonical query in one of these forms:

  who can do <action> with <resource> [when <key> is <value>]
  can <principal> do <action> with <resource>
  what can <principal>
  compare <principal-a> and <principal-b>
  preset privesc|wrongadmin|serviceaccess|endgame|clusters|connected
  match (a[:label])-[:kind|*]->(b[:label])
  run <saved-name>

Rules:
- Actions are AWS IAM actions like iam:CreateUser, s3:GetObject, lambda:InvokeFunction
- Resources are ARNs or * for any
- Labels for match are: user, role, admin, privesc
- Return ONLY the canonical query, nothing else. No code fences, no explanation.

Examples:
User: "Which roles can create new IAM users?"
Output: who can do iam:CreateUser with *

User: "Can alice read the production S3 bucket?"
Output: can user/alice do s3:GetObject with arn:aws:s3:::production/*

User: "Show me principals that can reach admin"
Output: match (a)-[*]->(b:admin)
"#;

/// Translate a natural-language question to a canonical query string.
pub async fn translate(
    provider: LlmProvider,
    question: &str,
    schema_hint: Option<&str>,
) -> Result<String, NlqError> {
    let user_msg = if let Some(hint) = schema_hint {
        format!(
            "{}\n\nAvailable principals and actions in the current graph:\n{}",
            question, hint
        )
    } else {
        question.to_string()
    };

    match provider {
        LlmProvider::OpenAi => call_openai(&user_msg).await,
        LlmProvider::Anthropic => call_anthropic(&user_msg).await,
    }
}

async fn call_openai(user_msg: &str) -> Result<String, NlqError> {
    let api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| NlqError::Unknown("OPENAI_API_KEY not set".into()))?;
    let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());

    let body = json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg}
        ],
        "temperature": 0.0,
    });

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&body)
        .send()
        .await
        .map_err(|e| NlqError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(NlqError::Http(format!("OpenAI {} :: {}", status, text)));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| NlqError::Http(e.to_string()))?;
    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| NlqError::Http("OpenAI response missing content".into()))?
        .trim()
        .to_string();
    Ok(strip_code_fences(&content))
}

async fn call_anthropic(user_msg: &str) -> Result<String, NlqError> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| NlqError::Unknown("ANTHROPIC_API_KEY not set".into()))?;
    let model =
        std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-sonnet-4-6".to_string());

    let body = json!({
        "model": model,
        "max_tokens": 256,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": user_msg}
        ],
        "temperature": 0.0,
    });

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| NlqError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(NlqError::Http(format!("Anthropic {} :: {}", status, text)));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| NlqError::Http(e.to_string()))?;
    let content = json["content"][0]["text"]
        .as_str()
        .ok_or_else(|| NlqError::Http("Anthropic response missing text".into()))?
        .trim()
        .to_string();
    Ok(strip_code_fences(&content))
}

fn strip_code_fences(s: &str) -> String {
    let mut out = s.trim().to_string();
    if let Some(stripped) = out.strip_prefix("```") {
        // Remove language identifier line if present
        let without_lang = stripped.lines().skip(1).collect::<Vec<_>>().join("\n");
        out = without_lang;
    }
    if let Some(stripped) = out.strip_suffix("```") {
        out = stripped.to_string();
    }
    out.trim().to_string()
}

/// Build a compact schema hint for the LLM: a few sample principals and
/// common actions from the loaded graph.
pub fn build_schema_hint(graph: &crate::model::graph::Graph) -> String {
    let principals: Vec<&str> = graph
        .nodes
        .iter()
        .take(20)
        .map(|n| n.searchable_name())
        .collect();
    let mut hint = format!("Principals (first 20): {}\n", principals.join(", "));
    hint.push_str("Common IAM actions: iam:CreateUser, iam:PutRolePolicy, sts:AssumeRole, lambda:InvokeFunction, s3:GetObject, s3:PutBucketPolicy\n");
    hint
}
