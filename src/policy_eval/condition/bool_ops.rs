pub fn evaluate(context_values: &[String], policy_values: &[String]) -> bool {
    context_values.iter().any(|cv| {
        let cv_bool = cv.eq_ignore_ascii_case("true");
        policy_values.iter().any(|pv| {
            let pv_bool = pv.eq_ignore_ascii_case("true");
            cv_bool == pv_bool
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_match() {
        assert!(evaluate(&["true".into()], &["true".into()]));
        assert!(evaluate(&["True".into()], &["true".into()]));
        assert!(!evaluate(&["false".into()], &["true".into()]));
    }

    #[test]
    fn test_bool_false() {
        assert!(evaluate(&["false".into()], &["false".into()]));
        assert!(evaluate(&["anything".into()], &["false".into()]));
    }
}
