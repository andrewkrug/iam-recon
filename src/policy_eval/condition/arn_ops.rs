use crate::policy_eval::wildcard;

#[derive(Debug, Clone, Copy)]
pub enum ArnOp {
    Equals,
    NotEquals,
    Like,
    NotLike,
}

pub fn evaluate(context_values: &[String], policy_values: &[String], op: ArnOp) -> bool {
    match op {
        ArnOp::Equals => {
            // AWS IAM: ArnEquals supports wildcards (same as ArnLike per PMapper behavior)
            context_values
                .iter()
                .any(|cv| policy_values.iter().any(|pv| wildcard::matches(pv, cv)))
        }
        ArnOp::NotEquals => context_values
            .iter()
            .any(|cv| policy_values.iter().all(|pv| !wildcard::matches(pv, cv))),
        ArnOp::Like => context_values
            .iter()
            .any(|cv| policy_values.iter().any(|pv| wildcard::matches(pv, cv))),
        ArnOp::NotLike => context_values
            .iter()
            .any(|cv| policy_values.iter().all(|pv| !wildcard::matches(pv, cv))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arn_equals() {
        assert!(evaluate(
            &["arn:aws:iam::123456789012:user/Alice".into()],
            &["arn:aws:iam::123456789012:user/Alice".into()],
            ArnOp::Equals,
        ));
    }

    #[test]
    fn test_arn_like_wildcard() {
        assert!(evaluate(
            &["arn:aws:iam::123456789012:user/Alice".into()],
            &["arn:aws:iam::123456789012:user/*".into()],
            ArnOp::Like,
        ));
    }

    #[test]
    fn test_arn_not_like() {
        assert!(evaluate(
            &["arn:aws:iam::123456789012:role/Admin".into()],
            &["arn:aws:iam::123456789012:user/*".into()],
            ArnOp::NotLike,
        ));
    }
}
