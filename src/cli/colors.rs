//! Terminal colors with automatic TTY detection.
//! Colors render in interactive terminals but vanish when piped or redirected,
//! so output is always clean for copy-paste.

use std::io::IsTerminal;
use std::sync::{LazyLock, OnceLock};

static USE_COLOR: LazyLock<bool> = LazyLock::new(|| !compact() && std::io::stdout().is_terminal());

/// Global compact mode flag (set once from CLI)
static COMPACT_MODE: OnceLock<bool> = OnceLock::new();

pub fn set_compact(v: bool) {
    let _ = COMPACT_MODE.set(v);
}

pub fn compact() -> bool {
    COMPACT_MODE.get().copied().unwrap_or(false)
}

pub fn enabled() -> bool {
    *USE_COLOR
}

macro_rules! define_color {
    ($name:ident, $code:expr) => {
        pub fn $name(s: &str) -> String {
            if *USE_COLOR {
                format!("\x1b[{}m{}\x1b[0m", $code, s)
            } else {
                s.to_string()
            }
        }
    };
}

// Regular colors
define_color!(red, "31");
define_color!(green, "32");
define_color!(yellow, "33");
define_color!(blue, "34");
define_color!(magenta, "35");
define_color!(cyan, "36");
define_color!(white, "37");
define_color!(gray, "90");

// Bold variants
define_color!(bold, "1");
define_color!(bold_red, "1;31");
define_color!(bold_green, "1;32");
define_color!(bold_yellow, "1;33");
define_color!(bold_blue, "1;34");
define_color!(bold_magenta, "1;35");
define_color!(bold_cyan, "1;36");
define_color!(bold_white, "1;37");

// Dim
define_color!(dim, "2");

/// Severity badge: colored [HIGH] / [MEDIUM] / [LOW]
pub fn severity_badge(s: crate::model::finding::Severity) -> String {
    match s {
        crate::model::finding::Severity::High => bold_red("[HIGH]"),
        crate::model::finding::Severity::Medium => bold_yellow("[MEDIUM]"),
        crate::model::finding::Severity::Low => blue("[LOW]"),
    }
}

/// Section header with underline
pub fn header(title: &str) -> String {
    let line = "─".repeat(title.len() + 4);
    format!("\n{}\n  {}\n{}", dim(&line), bold_cyan(title), dim(&line))
}

/// Sub-section divider
pub fn divider(label: &str) -> String {
    let pad = 50usize.saturating_sub(label.len());
    format!("  {} {}", bold(label), dim(&"─".repeat(pad)))
}

/// Key-value pair
pub fn kv(key: &str, val: &str) -> String {
    format!("  {}  {}", dim(key), bold_white(val))
}

/// Stat counter (e.g., "42" in a summary line)
pub fn stat(n: usize) -> String {
    bold_cyan(&n.to_string())
}

/// Node name, colored by type
pub fn node_name(name: &str, is_admin: bool, is_user: bool) -> String {
    if is_admin {
        bold_red(name)
    } else if is_user {
        cyan(name)
    } else {
        magenta(name)
    }
}

/// Edge reason (the short_reason label)
pub fn edge_label(short_reason: &str) -> String {
    match short_reason {
        "IAM" => bold_red(short_reason),
        "STS" => bold_blue(short_reason),
        "Lambda" => bold_yellow(short_reason),
        "EC2" => bold_green(short_reason),
        "SSM" => yellow(short_reason),
        "CodeBuild" => magenta(short_reason),
        "CloudFormation" => cyan(short_reason),
        "SageMaker" => blue(short_reason),
        "AutoScaling" => green(short_reason),
        "Admin" => bold_red(short_reason),
        _ => white(short_reason),
    }
}

/// Success message
pub fn ok(s: &str) -> String {
    bold_green(s)
}

/// Warning message
pub fn warn(s: &str) -> String {
    bold_yellow(s)
}

/// Error/danger message
pub fn danger(s: &str) -> String {
    bold_red(s)
}

/// URL (underlined blue)
pub fn url(s: &str) -> String {
    if *USE_COLOR {
        format!("\x1b[4;34m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}
