use std::path::PathBuf;

/// Get the root storage directory for iam-recon data.
/// On Unix: ~/.local/share/iam-recon (XDG) or ~/.iam-recon as fallback
/// On macOS: ~/Library/Application Support/iam-recon or ~/.iam-recon
pub fn get_storage_root() -> PathBuf {
    if let Some(data_dir) = dirs::data_dir() {
        data_dir.join("iam-recon")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".iam-recon")
    }
}

/// Get the default graph storage path for a given account ID
pub fn get_default_graph_path(account_id: &str) -> PathBuf {
    get_storage_root().join(account_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_root_exists() {
        let root = get_storage_root();
        assert!(root.to_str().unwrap().contains("iam-recon"));
    }

    #[test]
    fn test_graph_path() {
        let path = get_default_graph_path("123456789012");
        assert!(path.to_str().unwrap().contains("123456789012"));
    }
}
