//! Rich parse errors with source spans and suggestions.

use std::fmt;

#[derive(Debug, Clone)]
pub struct ParseError {
    pub source: String,
    pub position: usize,
    pub message: String,
    pub suggestions: Vec<String>,
}

impl ParseError {
    pub fn new(source: impl Into<String>, position: usize, message: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            position,
            message: message.into(),
            suggestions: vec![],
        }
    }

    pub fn with_suggestions(mut self, suggestions: Vec<String>) -> Self {
        self.suggestions = suggestions;
        self
    }

    /// Render as a multi-line, human-readable error showing the offending position.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("  error: {}\n", self.message));
        out.push_str(&format!("  > {}\n", self.source));
        let caret_pad = " ".repeat(self.position.min(self.source.len()));
        out.push_str(&format!("  > {}^\n", caret_pad));
        if !self.suggestions.is_empty() {
            out.push_str("\n  Did you mean?\n");
            for s in &self.suggestions {
                out.push_str(&format!("    {}\n", s));
            }
        }
        out
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

impl std::error::Error for ParseError {}

/// Top-level NLQ error enum used by executors.
#[derive(Debug)]
pub enum NlqError {
    Parse(ParseError),
    Unknown(String),
    IoError(std::io::Error),
    Json(serde_json::Error),
    Http(String),
}

impl fmt::Display for NlqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NlqError::Parse(e) => write!(f, "{}", e),
            NlqError::Unknown(s) => write!(f, "  error: {}", s),
            NlqError::IoError(e) => write!(f, "  io error: {}", e),
            NlqError::Json(e) => write!(f, "  json error: {}", e),
            NlqError::Http(s) => write!(f, "  http error: {}", s),
        }
    }
}

impl std::error::Error for NlqError {}

impl From<ParseError> for NlqError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}
impl From<std::io::Error> for NlqError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}
impl From<serde_json::Error> for NlqError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
