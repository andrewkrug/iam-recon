/// BinaryEquals: exact byte-for-byte comparison (case-sensitive)
pub fn evaluate(context_values: &[String], policy_values: &[String]) -> bool {
    context_values
        .iter()
        .any(|cv| policy_values.iter().any(|pv| cv == pv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_equals() {
        assert!(evaluate(&["abc".into()], &["abc".into()]));
        assert!(!evaluate(&["ABC".into()], &["abc".into()]));
    }
}
