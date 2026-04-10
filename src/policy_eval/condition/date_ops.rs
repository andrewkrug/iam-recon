use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy)]
pub enum DateOp {
    Equals,
    NotEquals,
    LessThan,
    LessThanEquals,
    GreaterThan,
    GreaterThanEquals,
}

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    // Try epoch seconds first
    if let Ok(epoch) = s.parse::<f64>() {
        let secs = epoch as i64;
        let nsecs = ((epoch - secs as f64) * 1_000_000_000.0) as u32;
        return DateTime::from_timestamp(secs, nsecs);
    }
    // Try ISO 8601 / RFC 3339
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try common formats
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(dt.and_utc());
    }
    None
}

pub fn evaluate(context_values: &[String], policy_values: &[String], op: DateOp) -> bool {
    context_values.iter().any(|cv| {
        let cv_date = match parse_date(cv) {
            Some(d) => d,
            None => return false,
        };
        policy_values.iter().any(|pv| {
            let pv_date = match parse_date(pv) {
                Some(d) => d,
                None => return false,
            };
            match op {
                DateOp::Equals => cv_date == pv_date,
                DateOp::NotEquals => cv_date != pv_date,
                DateOp::LessThan => cv_date < pv_date,
                DateOp::LessThanEquals => cv_date <= pv_date,
                DateOp::GreaterThan => cv_date > pv_date,
                DateOp::GreaterThanEquals => cv_date >= pv_date,
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_equals_rfc3339() {
        assert!(evaluate(
            &["2023-01-01T00:00:00Z".into()],
            &["2023-01-01T00:00:00Z".into()],
            DateOp::Equals,
        ));
    }

    #[test]
    fn test_date_less_than() {
        assert!(evaluate(
            &["2022-01-01T00:00:00Z".into()],
            &["2023-01-01T00:00:00Z".into()],
            DateOp::LessThan,
        ));
    }

    #[test]
    fn test_date_epoch() {
        // 2023-01-01T00:00:00Z = 1672531200
        assert!(evaluate(
            &["1672531200".into()],
            &["2023-01-01T00:00:00Z".into()],
            DateOp::Equals,
        ));
    }
}
