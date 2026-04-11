//! Persistent named queries stored in ~/.local/share/iam-recon/queries.json

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::error::NlqError;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedQueryStore {
    /// name -> query text
    pub queries: BTreeMap<String, String>,
}

impl SavedQueryStore {
    pub fn path() -> PathBuf {
        crate::util::storage::get_storage_root().join("queries.json")
    }

    pub fn load_default() -> Result<Self, NlqError> {
        let p = Self::path();
        if !p.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&p)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn save_default(&self) -> Result<(), NlqError> {
        let p = Self::path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&p, content)?;
        Ok(())
    }

    pub fn add(&mut self, name: impl Into<String>, query: impl Into<String>) {
        self.queries.insert(name.into(), query.into());
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.queries.remove(name).is_some()
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        self.queries.get(name)
    }

    pub fn list(&self) -> Vec<(&String, &String)> {
        self.queries.iter().collect()
    }
}
