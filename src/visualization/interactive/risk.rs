//! IAM policy risk detection using `iam-rs` for parsing + custom rules for flagging
//! dangerous statements.
//!
//! Returned data is consumed by the interactive web UI to highlight statements
//! inside a policy JSON viewer.

use serde::Serialize;

/// Severity of a detected risk in a policy statement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// A single risk annotation on a statement within a policy
#[derive(Debug, Clone, Serialize)]
pub struct PolicyRisk {
    /// Index of the statement within the policy's Statement array
    pub statement_index: usize,
    /// The Sid (if present) for easier identification
    pub sid: Option<String>,
    pub level: RiskLevel,
    pub rule: String,
    pub description: String,
}

/// Analyze a policy JSON document and return a list of risk findings.
/// Uses iam-rs to parse the policy structure and custom heuristics to flag dangerous patterns.
pub fn analyze_policy(policy_doc: &serde_json::Value) -> Vec<PolicyRisk> {
    let mut risks = Vec::new();

    // Try to parse with iam-rs for validation
    let parsed: Result<iam_rs::IAMPolicy, _> = serde_json::from_value(policy_doc.clone());

    let statements = match &parsed {
        Ok(policy) => &policy.statement[..],
        Err(_) => {
            // Fall back to raw JSON walking if iam-rs can't parse
            return analyze_raw(policy_doc);
        }
    };

    for (idx, stmt) in statements.iter().enumerate() {
        let sid = stmt.sid.clone();
        let is_allow = matches!(stmt.effect, iam_rs::IAMEffect::Allow);

        let actions = extract_action_strings(&stmt.action);
        let not_actions = extract_action_strings(&stmt.not_action);
        let resources = extract_resource_strings(&stmt.resource);

        let has_star_action =
            actions.iter().any(|a| a == "*") || not_actions.iter().any(|a| a == "*");
        let has_star_resource = resources.iter().any(|r| r == "*");
        let has_condition = stmt.condition.is_some();

        // Rule 1: Action:* on Resource:* with Allow and no conditions → Critical (admin)
        if is_allow && has_star_action && has_star_resource && !has_condition {
            risks.push(PolicyRisk {
                statement_index: idx,
                sid: sid.clone(),
                level: RiskLevel::Critical,
                rule: "FullAdmin".into(),
                description:
                    "Grants full administrative access (Action:* on Resource:*) with no conditions"
                        .into(),
            });
        }

        // Rule 2: Action:* with Allow (even with specific resource) → High
        if is_allow && has_star_action && !has_star_resource && !has_condition {
            risks.push(PolicyRisk {
                statement_index: idx,
                sid: sid.clone(),
                level: RiskLevel::High,
                rule: "WildcardAction".into(),
                description: "Allows any action (*) on specific resources".into(),
            });
        }

        // Rule 3: NotAction with Allow → High (easy to accidentally over-grant)
        if is_allow && !not_actions.is_empty() {
            risks.push(PolicyRisk {
                statement_index: idx,
                sid: sid.clone(),
                level: RiskLevel::High,
                rule: "NotActionAllow".into(),
                description: "Allow + NotAction can unintentionally grant broad access".into(),
            });
        }

        // Rule 4: iam:PassRole without condition → High
        if is_allow
            && actions
                .iter()
                .any(|a| a.eq_ignore_ascii_case("iam:PassRole"))
            && !has_condition
        {
            risks.push(PolicyRisk {
                statement_index: idx,
                sid: sid.clone(),
                level: RiskLevel::High,
                rule: "UnscopedPassRole".into(),
                description: "iam:PassRole without iam:PassedToService condition is unscoped"
                    .into(),
            });
        }

        // Rule 5: Dangerous privilege-escalation actions from pathfinding.cloud paths
        let dangerous_actions = [
            (
                "iam:CreatePolicyVersion",
                "Allows creating a new version of an IAM policy (self-escalation)",
            ),
            (
                "iam:SetDefaultPolicyVersion",
                "Allows setting default policy version (self-escalation)",
            ),
            (
                "iam:PutUserPolicy",
                "Allows attaching inline policies to users (self-escalation)",
            ),
            (
                "iam:PutRolePolicy",
                "Allows attaching inline policies to roles (self-escalation)",
            ),
            (
                "iam:PutGroupPolicy",
                "Allows attaching inline policies to groups (self-escalation)",
            ),
            (
                "iam:AttachUserPolicy",
                "Allows attaching managed policies to users (self-escalation)",
            ),
            (
                "iam:AttachRolePolicy",
                "Allows attaching managed policies to roles (self-escalation)",
            ),
            (
                "iam:AttachGroupPolicy",
                "Allows attaching managed policies to groups (self-escalation)",
            ),
            (
                "iam:CreateAccessKey",
                "Allows creating access keys for other users (principal access)",
            ),
            (
                "iam:UpdateLoginProfile",
                "Allows changing another user's password",
            ),
            (
                "iam:CreateLoginProfile",
                "Allows setting a password for another user",
            ),
            (
                "iam:UpdateAssumeRolePolicy",
                "Allows modifying role trust policies",
            ),
            ("iam:AddUserToGroup", "Allows adding users to any group"),
            ("sts:AssumeRole", "Allows assuming other roles"),
        ];
        for (action, desc) in &dangerous_actions {
            if is_allow && actions.iter().any(|a| a.eq_ignore_ascii_case(action)) {
                risks.push(PolicyRisk {
                    statement_index: idx,
                    sid: sid.clone(),
                    level: RiskLevel::Medium,
                    rule: format!("Dangerous:{}", action),
                    description: (*desc).into(),
                });
            }
        }

        // Rule 6: Wildcard principal in trust policy = external/public
        if stmt.principal.is_some() {
            // Could extract principal detail but iam-rs structure is complex; rely on raw json fallback
        }

        // Rule 7: No condition on sensitive services at resource=*
        if is_allow && has_star_resource {
            for action in &actions {
                if action.starts_with("s3:")
                    || action.starts_with("kms:")
                    || action.starts_with("secretsmanager:")
                {
                    if !has_condition {
                        risks.push(PolicyRisk {
                            statement_index: idx,
                            sid: sid.clone(),
                            level: RiskLevel::Medium,
                            rule: "UnscopedSensitiveAction".into(),
                            description: format!("{} on Resource:* without conditions", action),
                        });
                        break;
                    }
                }
            }
        }
    }

    risks
}

/// Fallback analyzer if iam-rs can't parse the policy — walks the raw JSON
fn analyze_raw(doc: &serde_json::Value) -> Vec<PolicyRisk> {
    let mut risks = Vec::new();
    let statements = match doc.get("Statement") {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(s) => vec![s.clone()],
        None => return risks,
    };

    for (idx, stmt) in statements.iter().enumerate() {
        let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
        if !effect.eq_ignore_ascii_case("Allow") {
            continue;
        }
        let sid = stmt.get("Sid").and_then(|s| s.as_str()).map(String::from);

        let action_star = check_wildcard(stmt.get("Action"));
        let resource_star = check_wildcard(stmt.get("Resource"));
        let has_condition = stmt.get("Condition").is_some();

        if action_star && resource_star && !has_condition {
            risks.push(PolicyRisk {
                statement_index: idx,
                sid,
                level: RiskLevel::Critical,
                rule: "FullAdmin".into(),
                description:
                    "Grants full administrative access (Action:* on Resource:*) with no conditions"
                        .into(),
            });
        }
    }
    risks
}

fn check_wildcard(v: Option<&serde_json::Value>) -> bool {
    match v {
        Some(serde_json::Value::String(s)) => s == "*",
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some("*")),
        _ => false,
    }
}

fn extract_action_strings(action: &Option<iam_rs::IAMAction>) -> Vec<String> {
    match action {
        Some(a) => {
            // iam_rs::IAMAction is an enum; serialize to JSON and extract strings
            match serde_json::to_value(a) {
                Ok(serde_json::Value::String(s)) => vec![s],
                Ok(serde_json::Value::Array(arr)) => arr
                    .into_iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
                _ => vec![],
            }
        }
        None => vec![],
    }
}

fn extract_resource_strings(resource: &Option<iam_rs::IAMResource>) -> Vec<String> {
    match resource {
        Some(r) => match serde_json::to_value(r) {
            Ok(serde_json::Value::String(s)) => vec![s],
            Ok(serde_json::Value::Array(arr)) => arr
                .into_iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => vec![],
        },
        None => vec![],
    }
}
