/// Null condition: checks whether a context key is present or absent.
/// Policy value "true" means key should be absent (null).
/// Policy value "false" means key should be present (not null).
pub fn evaluate_null(context_values: Option<&[String]>, policy_values: &[String]) -> bool {
    let key_is_null = context_values.is_none() || context_values.map_or(true, |v| v.is_empty());

    policy_values.iter().any(|pv| {
        let expect_null = pv.eq_ignore_ascii_case("true");
        key_is_null == expect_null
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_key_absent() {
        // Key is absent, policy expects null (true) -> match
        assert!(evaluate_null(None, &["true".into()]));
        // Key is absent, policy expects not-null (false) -> no match
        assert!(!evaluate_null(None, &["false".into()]));
    }

    #[test]
    fn test_null_key_present() {
        let vals = vec!["some-value".into()];
        // Key is present, policy expects null (true) -> no match
        assert!(!evaluate_null(Some(&vals), &["true".into()]));
        // Key is present, policy expects not-null (false) -> match
        assert!(evaluate_null(Some(&vals), &["false".into()]));
    }
}
