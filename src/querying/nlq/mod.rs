//! Natural language query engine for IAM Recon.
//!
//! Layers:
//! - `lexer`: tokenizes input after synonym normalization
//! - `parser`: recursive-descent parser producing an `ast::Query`
//! - `fuzzy`: Levenshtein-based matching for actions / principals
//! - `synonyms`: maps common English verbs to canonical keywords
//! - `executor`: runs a parsed AST against a `Graph`
//! - `ast`: query AST types (includes boolean combinators)
//! - `error`: rich parse errors with source spans and suggestions
//! - `templates`: pre-written canonical queries for the help menu
//! - `saved`: on-disk persistence of named queries
//! - `cypher`: mini-Cypher pattern queries (`match (a)-[:STS]->(b:admin)`)
//! - `llm`: optional LLM-backed translation via OpenAI/Anthropic APIs

pub mod ast;
pub mod cypher;
pub mod error;
pub mod executor;
pub mod fuzzy;
pub mod lexer;
pub mod llm;
pub mod parser;
pub mod saved;
pub mod synonyms;
pub mod templates;

pub use ast::{BoolOp, Query};
pub use error::{NlqError, ParseError};
pub use executor::{execute, ExecutionResult};
pub use fuzzy::{FuzzyIndex, Match};
