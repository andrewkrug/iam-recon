/// ARN format: arn:partition:service:region:account-id:resource
/// Some ARNs use / or : as resource separator

/// Extract the partition from an ARN (e.g., "aws", "aws-cn", "aws-us-gov")
pub fn get_partition(arn: &str) -> &str {
    arn.splitn(6, ':').nth(1).unwrap_or("")
}

/// Extract the service from an ARN (e.g., "iam", "s3", "ec2")
pub fn get_service(arn: &str) -> &str {
    arn.splitn(6, ':').nth(2).unwrap_or("")
}

/// Extract the region from an ARN
pub fn get_region(arn: &str) -> &str {
    arn.splitn(6, ':').nth(3).unwrap_or("")
}

/// Extract the account ID from an ARN
pub fn get_account_id(arn: &str) -> &str {
    arn.splitn(6, ':').nth(4).unwrap_or("")
}

/// Extract the resource portion of an ARN (everything after the 5th colon)
pub fn get_resource(arn: &str) -> &str {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() >= 6 {
        parts[5]
    } else {
        ""
    }
}

/// Validate that a string looks like an ARN
pub fn validate_arn(arn: &str) -> bool {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    parts.len() >= 6 && parts[0] == "arn"
}

/// Get the "searchable name" from an IAM principal ARN
/// e.g., "arn:aws:iam::123456789012:user/Alice" -> "user/Alice"
///       "arn:aws:iam::123456789012:role/Admin" -> "role/Admin"
pub fn get_searchable_name(arn: &str) -> &str {
    let resource = get_resource(arn);
    // For IAM resources, the resource part is already "user/name" or "role/name"
    resource
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user_arn() {
        let arn = "arn:aws:iam::123456789012:user/Alice";
        assert_eq!(get_partition(arn), "aws");
        assert_eq!(get_service(arn), "iam");
        assert_eq!(get_region(arn), "");
        assert_eq!(get_account_id(arn), "123456789012");
        assert_eq!(get_resource(arn), "user/Alice");
    }

    #[test]
    fn test_parse_role_arn() {
        let arn = "arn:aws:iam::123456789012:role/Admin";
        assert_eq!(get_resource(arn), "role/Admin");
        assert_eq!(get_searchable_name(arn), "role/Admin");
    }

    #[test]
    fn test_parse_s3_arn() {
        let arn = "arn:aws:s3:::my-bucket/prefix/key";
        assert_eq!(get_service(arn), "s3");
        assert_eq!(get_resource(arn), "my-bucket/prefix/key");
    }

    #[test]
    fn test_validate_arn() {
        assert!(validate_arn("arn:aws:iam::123456789012:user/Alice"));
        assert!(!validate_arn("not-an-arn"));
        assert!(!validate_arn("arn:aws:iam"));
    }

    #[test]
    fn test_china_partition() {
        let arn = "arn:aws-cn:iam::123456789012:role/Test";
        assert_eq!(get_partition(arn), "aws-cn");
    }
}
