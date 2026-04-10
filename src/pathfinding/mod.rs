//! Pathfinding.cloud integration — maps dangerous IAM privileges to known
//! privilege escalation paths from Datadog's pathfinding.cloud database.
//!
//! The path data is fetched at build time from
//! <https://github.com/DataDog/pathfinding.cloud> and embedded in the binary.
//! No network access is needed at runtime.

pub mod mapper;
pub mod paths;

pub use mapper::PathfindingMapper;
pub use paths::{EscalationCategory, EscalationPath};
