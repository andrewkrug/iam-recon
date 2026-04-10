use ipnet::IpNet;
use std::net::IpAddr;

/// IpAddress / NotIpAddress condition evaluation.
/// Policy values are CIDR ranges. Context values are IP addresses.
pub fn evaluate(context_values: &[String], policy_values: &[String], negated: bool) -> bool {
    context_values.iter().any(|cv| {
        let ip: IpAddr = match cv.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        let contained = policy_values.iter().any(|pv| {
            // Try parsing as CIDR first, then as single IP
            let net: IpNet = if pv.contains('/') {
                match pv.parse() {
                    Ok(n) => n,
                    Err(_) => return false,
                }
            } else {
                match pv.parse::<IpAddr>() {
                    Ok(addr) => IpNet::from(addr),
                    Err(_) => return false,
                }
            };
            net.contains(&ip)
        });
        if negated {
            !contained
        } else {
            contained
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_cidr() {
        assert!(evaluate(
            &["10.0.1.5".into()],
            &["10.0.0.0/8".into()],
            false
        ));
        assert!(!evaluate(
            &["192.168.1.1".into()],
            &["10.0.0.0/8".into()],
            false
        ));
    }

    #[test]
    fn test_not_ip_address() {
        assert!(evaluate(
            &["192.168.1.1".into()],
            &["10.0.0.0/8".into()],
            true
        ));
        assert!(!evaluate(
            &["10.0.1.5".into()],
            &["10.0.0.0/8".into()],
            true
        ));
    }

    #[test]
    fn test_exact_ip() {
        assert!(evaluate(&["10.0.0.1".into()], &["10.0.0.1".into()], false));
    }
}
