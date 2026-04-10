#[derive(Debug, Clone, Copy)]
pub enum NumericOp {
    Equals,
    NotEquals,
    LessThan,
    LessThanEquals,
    GreaterThan,
    GreaterThanEquals,
}

pub fn evaluate(context_values: &[String], policy_values: &[String], op: NumericOp) -> bool {
    context_values.iter().any(|cv| {
        let cv_num = match cv.parse::<f64>() {
            Ok(n) => n,
            Err(_) => return false,
        };
        policy_values.iter().any(|pv| {
            let pv_num = match pv.parse::<f64>() {
                Ok(n) => n,
                Err(_) => return false,
            };
            match op {
                NumericOp::Equals => (cv_num - pv_num).abs() < f64::EPSILON,
                NumericOp::NotEquals => (cv_num - pv_num).abs() >= f64::EPSILON,
                NumericOp::LessThan => cv_num < pv_num,
                NumericOp::LessThanEquals => cv_num <= pv_num,
                NumericOp::GreaterThan => cv_num > pv_num,
                NumericOp::GreaterThanEquals => cv_num >= pv_num,
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numeric_equals() {
        assert!(evaluate(&["42".into()], &["42".into()], NumericOp::Equals));
        assert!(!evaluate(&["42".into()], &["43".into()], NumericOp::Equals));
    }

    #[test]
    fn test_numeric_less_than() {
        assert!(evaluate(&["5".into()], &["10".into()], NumericOp::LessThan));
        assert!(!evaluate(
            &["10".into()],
            &["5".into()],
            NumericOp::LessThan
        ));
    }

    #[test]
    fn test_numeric_float() {
        assert!(evaluate(
            &["3.14".into()],
            &["3.14".into()],
            NumericOp::Equals
        ));
    }
}
