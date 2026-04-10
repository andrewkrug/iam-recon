pub mod arn_ops;
pub mod binary_ops;
pub mod bool_ops;
pub mod date_ops;
pub mod ip_ops;
pub mod null_ops;
pub mod numeric_ops;
pub mod string_ops;

use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Evaluate a Condition block from an IAM policy statement.
///
/// A Condition block looks like:
/// ```json
/// {
///   "StringEquals": { "aws:PrincipalTag/team": "engineering" },
///   "IpAddress": { "aws:SourceIp": "10.0.0.0/8" }
/// }
/// ```
///
/// All top-level operators must match (AND). Within each operator,
/// all keys must match (AND). For each key, at least one value must match (OR).
pub fn evaluate_condition_block(
    condition: &serde_json::Value,
    context: &CaseInsensitiveMap,
) -> bool {
    let condition_obj = match condition.as_object() {
        Some(obj) => obj,
        None => return true, // No condition = always matches
    };

    // All operators must match (AND)
    for (operator, keys_values) in condition_obj {
        if !evaluate_operator(operator, keys_values, context) {
            return false;
        }
    }

    true
}

/// Evaluate a single condition operator (e.g., "StringEquals", "ForAnyValue:StringLike")
fn evaluate_operator(
    operator: &str,
    keys_values: &serde_json::Value,
    context: &CaseInsensitiveMap,
) -> bool {
    let kv_obj = match keys_values.as_object() {
        Some(obj) => obj,
        None => return false,
    };

    // Parse quantifier prefix
    let (quantifier, base_op) = parse_quantifier(operator);

    // Parse IfExists suffix
    let (core_op, if_exists) = parse_if_exists(base_op);

    // All keys within one operator must match (AND)
    for (cond_key, cond_values) in kv_obj {
        let policy_values = get_string_values(cond_values);
        let context_values = context.get(cond_key);

        match (context_values, if_exists) {
            (None, true) => continue, // IfExists: key absent = condition satisfied
            (None, false) => {
                // Null operator handles missing keys specially
                if core_op == "Null" {
                    if !null_ops::evaluate_null(None, &policy_values) {
                        return false;
                    }
                    continue;
                }
                // ForAllValues with empty set = vacuously true
                if quantifier == Quantifier::ForAllValues {
                    continue;
                }
                return false;
            }
            (Some(ctx_vals), _) => {
                let matched = match quantifier {
                    Quantifier::None => {
                        // Default: at least one context value must match at least one policy value
                        evaluate_single(core_op, ctx_vals, &policy_values)
                    }
                    Quantifier::ForAnyValue => {
                        // At least one context value satisfies the condition
                        ctx_vals.iter().any(|cv| {
                            evaluate_single(core_op, std::slice::from_ref(cv), &policy_values)
                        })
                    }
                    Quantifier::ForAllValues => {
                        // Every context value must satisfy the condition
                        ctx_vals.iter().all(|cv| {
                            evaluate_single(core_op, std::slice::from_ref(cv), &policy_values)
                        })
                    }
                };
                if !matched {
                    return false;
                }
            }
        }
    }

    true
}

#[derive(Debug, PartialEq)]
enum Quantifier {
    None,
    ForAnyValue,
    ForAllValues,
}

fn parse_quantifier(operator: &str) -> (Quantifier, &str) {
    if let Some(rest) = operator.strip_prefix("ForAnyValue:") {
        (Quantifier::ForAnyValue, rest)
    } else if let Some(rest) = operator.strip_prefix("ForAllValues:") {
        (Quantifier::ForAllValues, rest)
    } else {
        (Quantifier::None, operator)
    }
}

fn parse_if_exists(operator: &str) -> (&str, bool) {
    if let Some(core) = operator.strip_suffix("IfExists") {
        (core, true)
    } else {
        (operator, false)
    }
}

fn get_string_values(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Bool(b) => vec![b.to_string()],
        serde_json::Value::Number(n) => vec![n.to_string()],
        _ => vec![],
    }
}

/// Evaluate a condition for a single set of context values against policy values
fn evaluate_single(operator: &str, context_values: &[String], policy_values: &[String]) -> bool {
    match operator {
        "StringEquals" => {
            string_ops::evaluate(context_values, policy_values, string_ops::StringOp::Equals)
        }
        "StringNotEquals" => string_ops::evaluate(
            context_values,
            policy_values,
            string_ops::StringOp::NotEquals,
        ),
        "StringEqualsIgnoreCase" => string_ops::evaluate(
            context_values,
            policy_values,
            string_ops::StringOp::EqualsIgnoreCase,
        ),
        "StringNotEqualsIgnoreCase" => string_ops::evaluate(
            context_values,
            policy_values,
            string_ops::StringOp::NotEqualsIgnoreCase,
        ),
        "StringLike" => {
            string_ops::evaluate(context_values, policy_values, string_ops::StringOp::Like)
        }
        "StringNotLike" => {
            string_ops::evaluate(context_values, policy_values, string_ops::StringOp::NotLike)
        }

        "NumericEquals" => numeric_ops::evaluate(
            context_values,
            policy_values,
            numeric_ops::NumericOp::Equals,
        ),
        "NumericNotEquals" => numeric_ops::evaluate(
            context_values,
            policy_values,
            numeric_ops::NumericOp::NotEquals,
        ),
        "NumericLessThan" => numeric_ops::evaluate(
            context_values,
            policy_values,
            numeric_ops::NumericOp::LessThan,
        ),
        "NumericLessThanEquals" => numeric_ops::evaluate(
            context_values,
            policy_values,
            numeric_ops::NumericOp::LessThanEquals,
        ),
        "NumericGreaterThan" => numeric_ops::evaluate(
            context_values,
            policy_values,
            numeric_ops::NumericOp::GreaterThan,
        ),
        "NumericGreaterThanEquals" => numeric_ops::evaluate(
            context_values,
            policy_values,
            numeric_ops::NumericOp::GreaterThanEquals,
        ),

        "DateEquals" => date_ops::evaluate(context_values, policy_values, date_ops::DateOp::Equals),
        "DateNotEquals" => {
            date_ops::evaluate(context_values, policy_values, date_ops::DateOp::NotEquals)
        }
        "DateLessThan" => {
            date_ops::evaluate(context_values, policy_values, date_ops::DateOp::LessThan)
        }
        "DateLessThanEquals" => date_ops::evaluate(
            context_values,
            policy_values,
            date_ops::DateOp::LessThanEquals,
        ),
        "DateGreaterThan" => {
            date_ops::evaluate(context_values, policy_values, date_ops::DateOp::GreaterThan)
        }
        "DateGreaterThanEquals" => date_ops::evaluate(
            context_values,
            policy_values,
            date_ops::DateOp::GreaterThanEquals,
        ),

        "Bool" => bool_ops::evaluate(context_values, policy_values),
        "BinaryEquals" => binary_ops::evaluate(context_values, policy_values),

        "IpAddress" => ip_ops::evaluate(context_values, policy_values, false),
        "NotIpAddress" => ip_ops::evaluate(context_values, policy_values, true),

        "ArnEquals" => arn_ops::evaluate(context_values, policy_values, arn_ops::ArnOp::Equals),
        "ArnNotEquals" => {
            arn_ops::evaluate(context_values, policy_values, arn_ops::ArnOp::NotEquals)
        }
        "ArnLike" => arn_ops::evaluate(context_values, policy_values, arn_ops::ArnOp::Like),
        "ArnNotLike" => arn_ops::evaluate(context_values, policy_values, arn_ops::ArnOp::NotLike),

        "Null" => null_ops::evaluate_null(Some(context_values), policy_values),

        _ => {
            tracing::warn!("Unknown condition operator: {}", operator);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_equals_condition() {
        let condition = serde_json::json!({
            "StringEquals": {
                "aws:PrincipalTag/team": "engineering"
            }
        });
        let mut ctx = CaseInsensitiveMap::new();
        ctx.insert_single("aws:PrincipalTag/team", "engineering");
        assert!(evaluate_condition_block(&condition, &ctx));

        ctx = CaseInsensitiveMap::new();
        ctx.insert_single("aws:PrincipalTag/team", "marketing");
        assert!(!evaluate_condition_block(&condition, &ctx));
    }

    #[test]
    fn test_if_exists_missing_key() {
        let condition = serde_json::json!({
            "StringEqualsIfExists": {
                "aws:PrincipalTag/team": "engineering"
            }
        });
        let ctx = CaseInsensitiveMap::new();
        // Key is missing, IfExists means condition is satisfied
        assert!(evaluate_condition_block(&condition, &ctx));
    }

    #[test]
    fn test_for_any_value() {
        let condition = serde_json::json!({
            "ForAnyValue:StringEquals": {
                "aws:PrincipalTag/team": ["engineering", "platform"]
            }
        });
        let mut ctx = CaseInsensitiveMap::new();
        ctx.insert("aws:PrincipalTag/team", "engineering");
        ctx.insert("aws:PrincipalTag/team", "marketing");
        assert!(evaluate_condition_block(&condition, &ctx));
    }

    #[test]
    fn test_empty_condition_block() {
        let condition = serde_json::json!({});
        let ctx = CaseInsensitiveMap::new();
        assert!(evaluate_condition_block(&condition, &ctx));
    }
}
