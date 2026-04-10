//! Parse AWS CLI / SDK shared configuration files to discover available profiles.
//!
//! Reads `~/.aws/config` and `~/.aws/credentials` and merges profile definitions
//! from both. Used by the TUI's "Create Graph" wizard to present a pick list.

use std::collections::BTreeMap;
use std::fs;

/// A single AWS profile discovered in the shared config files.
#[derive(Debug, Clone)]
pub struct AwsProfile {
    pub name: String,
    pub region: Option<String>,
    pub sso_start_url: Option<String>,
    pub role_arn: Option<String>,
    pub source_account_id: Option<String>,
    /// Whether ~/.aws/credentials contained an aws_access_key_id for this profile
    pub has_credentials: bool,
    /// Whether ~/.aws/config defined SSO settings for this profile
    pub uses_sso: bool,
}

/// List all profiles found in the user's shared AWS config files.
/// Profiles are sorted alphabetically with `default` always first.
pub fn list_profiles() -> Vec<AwsProfile> {
    let mut profiles: BTreeMap<String, AwsProfile> = BTreeMap::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return vec![],
    };

    // Parse ~/.aws/config
    let config_path = home.join(".aws/config");
    if let Ok(content) = fs::read_to_string(&config_path) {
        for (section, props) in parse_ini(&content) {
            let name = if section == "default" {
                "default".to_string()
            } else if let Some(rest) = section.strip_prefix("profile ") {
                rest.to_string()
            } else {
                continue;
            };

            let entry = profiles.entry(name.clone()).or_insert_with(|| AwsProfile {
                name: name.clone(),
                region: None,
                sso_start_url: None,
                role_arn: None,
                source_account_id: None,
                has_credentials: false,
                uses_sso: false,
            });
            entry.region = props.get("region").cloned();
            entry.sso_start_url = props.get("sso_start_url").cloned();
            entry.role_arn = props.get("role_arn").cloned();
            entry.source_account_id = props.get("sso_account_id").cloned();
            entry.uses_sso =
                props.contains_key("sso_start_url") || props.contains_key("sso_session");
        }
    }

    // Parse ~/.aws/credentials
    let creds_path = home.join(".aws/credentials");
    if let Ok(content) = fs::read_to_string(&creds_path) {
        for (section, props) in parse_ini(&content) {
            let name = section;
            let entry = profiles.entry(name.clone()).or_insert_with(|| AwsProfile {
                name: name.clone(),
                region: None,
                sso_start_url: None,
                role_arn: None,
                source_account_id: None,
                has_credentials: false,
                uses_sso: false,
            });
            entry.has_credentials = props.contains_key("aws_access_key_id");
        }
    }

    // Sort: default first, then alphabetical
    let mut sorted: Vec<AwsProfile> = profiles.into_values().collect();
    sorted.sort_by(|a, b| match (a.name.as_str(), b.name.as_str()) {
        ("default", _) => std::cmp::Ordering::Less,
        (_, "default") => std::cmp::Ordering::Greater,
        (x, y) => x.cmp(y),
    });
    sorted
}

/// Minimal INI parser for AWS shared config files.
/// Returns a list of (section_name, key_value_map) preserving order.
fn parse_ini(content: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut result = Vec::new();
    let mut current: Option<(String, BTreeMap<String, String>)> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(prev) = current.take() {
                result.push(prev);
            }
            let name = line[1..line.len() - 1].trim().to_string();
            current = Some((name, BTreeMap::new()));
        } else if let Some((_, props)) = current.as_mut() {
            if let Some((k, v)) = line.split_once('=') {
                props.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    if let Some(prev) = current.take() {
        result.push(prev);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ini() {
        let content = "[default]\nregion = us-east-1\n\n[profile dev]\nregion=us-west-2\nrole_arn = arn:aws:iam::123:role/Dev\n";
        let parsed = parse_ini(content);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "default");
        assert_eq!(parsed[0].1.get("region"), Some(&"us-east-1".to_string()));
        assert_eq!(parsed[1].0, "profile dev");
        assert_eq!(parsed[1].1.get("region"), Some(&"us-west-2".to_string()));
    }

    #[test]
    fn test_ini_comments() {
        let content = "# this is a comment\n[default]\n; also comment\nregion = us-east-1\n";
        let parsed = parse_ini(content);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1.get("region"), Some(&"us-east-1".to_string()));
    }
}
