use indexmap::IndexMap;
use std::fmt;
use unicase::UniCase;

/// A map with case-insensitive string keys, matching AWS IAM condition key behavior.
/// Preserves the original case of the first insertion for display purposes.
#[derive(Clone, Default)]
pub struct CaseInsensitiveMap {
    inner: IndexMap<UniCase<String>, (String, Vec<String>)>,
}

impl CaseInsensitiveMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let uc = UniCase::new(key.clone());
        self.inner
            .entry(uc)
            .or_insert_with(|| (key, Vec::new()))
            .1
            .push(value.into());
    }

    pub fn insert_single(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let uc = UniCase::new(key.clone());
        self.inner.insert(uc, (key, vec![value.into()]));
    }

    pub fn get(&self, key: &str) -> Option<&[String]> {
        let uc = UniCase::new(key.to_string());
        self.inner.get(&uc).map(|(_, v)| v.as_slice())
    }

    pub fn get_first(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.first().map(|s| s.as_str()))
    }

    pub fn contains_key(&self, key: &str) -> bool {
        let uc = UniCase::new(key.to_string());
        self.inner.contains_key(&uc)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.inner.values().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.inner.values().map(|(k, _)| k.as_str())
    }
}

impl fmt::Debug for CaseInsensitiveMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (k, v) in &self.inner {
            map.entry(&k.as_ref(), &v.1);
        }
        map.finish()
    }
}

impl From<std::collections::HashMap<String, String>> for CaseInsensitiveMap {
    fn from(map: std::collections::HashMap<String, String>) -> Self {
        let mut cim = Self::new();
        for (k, v) in map {
            cim.insert_single(k, v);
        }
        cim
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_insensitive_lookup() {
        let mut m = CaseInsensitiveMap::new();
        m.insert_single("aws:SourceIp", "10.0.0.1");
        assert_eq!(m.get_first("aws:sourceip"), Some("10.0.0.1"));
        assert_eq!(m.get_first("AWS:SOURCEIP"), Some("10.0.0.1"));
        assert_eq!(m.get_first("aws:SourceIp"), Some("10.0.0.1"));
    }

    #[test]
    fn test_multi_value() {
        let mut m = CaseInsensitiveMap::new();
        m.insert("aws:PrincipalTag/team", "engineering");
        m.insert("aws:PrincipalTag/team", "platform");
        let values = m.get("aws:principaltag/team").unwrap();
        assert_eq!(values.len(), 2);
    }
}
