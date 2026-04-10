use crate::policy_eval::wildcard;

#[derive(Debug, Clone, Copy)]
pub enum StringOp {
    Equals,
    NotEquals,
    EqualsIgnoreCase,
    NotEqualsIgnoreCase,
    Like,
    NotLike,
}

pub fn evaluate(context_values: &[String], policy_values: &[String], op: StringOp) -> bool {
    match op {
        StringOp::Equals => context_values
            .iter()
            .any(|cv| policy_values.iter().any(|pv| cv == pv)),
        StringOp::NotEquals => context_values
            .iter()
            .any(|cv| policy_values.iter().all(|pv| cv != pv)),
        StringOp::EqualsIgnoreCase => context_values.iter().any(|cv| {
            policy_values
                .iter()
                .any(|pv| cv.to_lowercase() == pv.to_lowercase())
        }),
        StringOp::NotEqualsIgnoreCase => context_values.iter().any(|cv| {
            policy_values
                .iter()
                .all(|pv| cv.to_lowercase() != pv.to_lowercase())
        }),
        StringOp::Like => context_values
            .iter()
            .any(|cv| policy_values.iter().any(|pv| wildcard::matches(pv, cv))),
        StringOp::NotLike => context_values
            .iter()
            .any(|cv| policy_values.iter().all(|pv| !wildcard::matches(pv, cv))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_equals() {
        assert!(evaluate(&["foo".into()], &["foo".into()], StringOp::Equals));
        assert!(!evaluate(
            &["foo".into()],
            &["bar".into()],
            StringOp::Equals
        ));
    }

    #[test]
    fn test_string_like_wildcard() {
        assert!(evaluate(
            &["s3:GetObject".into()],
            &["s3:*".into()],
            StringOp::Like
        ));
        assert!(!evaluate(
            &["ec2:RunInstances".into()],
            &["s3:*".into()],
            StringOp::Like
        ));
    }

    #[test]
    fn test_string_not_equals() {
        assert!(evaluate(
            &["foo".into()],
            &["bar".into()],
            StringOp::NotEquals
        ));
        assert!(!evaluate(
            &["foo".into()],
            &["foo".into()],
            StringOp::NotEquals
        ));
    }

    #[test]
    fn test_ignore_case() {
        assert!(evaluate(
            &["FOO".into()],
            &["foo".into()],
            StringOp::EqualsIgnoreCase
        ));
        assert!(!evaluate(
            &["FOO".into()],
            &["bar".into()],
            StringOp::EqualsIgnoreCase
        ));
    }
}
