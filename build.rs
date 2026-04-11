//! Build script: fetches pathfinding.cloud data and bundles it into the binary.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let paths_dir = out_dir.join("pathfinding_cloud");

    // Only re-fetch if not already present
    if !paths_dir.join("data/paths").exists() {
        println!("cargo:warning=Fetching pathfinding.cloud data from GitHub...");

        // Clone with depth 1 for speed
        let status = Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                "https://github.com/DataDog/pathfinding.cloud.git",
                paths_dir.to_str().unwrap(),
            ])
            .status();

        if let Ok(s) = status {
            if s.success() {
                // Sparse checkout just the data/paths directory
                let _ = Command::new("git")
                    .args(["sparse-checkout", "set", "data/paths"])
                    .current_dir(&paths_dir)
                    .status();
            }
        }

        // Fallback: if git clone failed, create empty dir so build doesn't break
        if !paths_dir.join("data/paths").exists() {
            println!("cargo:warning=Could not fetch pathfinding.cloud data, using empty dataset");
            fs::create_dir_all(paths_dir.join("data/paths")).unwrap();
        }
    }

    // Collect all YAML files into a single JSON bundle for include_str!
    let data_paths = paths_dir.join("data/paths");
    let mut all_paths = Vec::new();

    if data_paths.exists() {
        collect_yaml_files(&data_paths, &mut all_paths);
    }

    // Write as JSON array for the binary to include
    let json = serde_json::to_string(&all_paths).unwrap_or_else(|_| "[]".to_string());
    let bundle_path = out_dir.join("pathfinding_paths.json");
    fs::write(&bundle_path, json).unwrap();

    println!(
        "cargo:warning=Bundled {} pathfinding.cloud paths",
        all_paths.len()
    );
    println!("cargo:rerun-if-changed=build.rs");
}

fn collect_yaml_files(dir: &Path, results: &mut Vec<serde_json::Value>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_yaml_files(&path, results);
            } else if path
                .extension()
                .is_some_and(|e| e == "yaml" || e == "yml")
            {
                if let Ok(contents) = fs::read_to_string(&path) {
                    // Parse YAML to JSON value using a minimal parser
                    // We extract only the fields we need to keep the binary small
                    if let Some(parsed) = parse_path_yaml(&contents) {
                        results.push(parsed);
                    }
                }
            }
        }
    }
}

/// Minimal YAML parser for pathfinding.cloud path files.
/// Extracts only the fields we need: id, name, category, description,
/// required permissions, recommendation.
fn parse_path_yaml(yaml: &str) -> Option<serde_json::Value> {
    let mut id = String::new();
    let mut name = String::new();
    let mut category = String::new();
    let mut description = String::new();
    let mut recommendation = String::new();
    let mut permissions: Vec<String> = Vec::new();
    let mut services: Vec<String> = Vec::new();

    let mut in_description = false;
    let mut in_recommendation = false;
    let mut in_permissions = false;
    let mut in_required = false;
    let mut in_services = false;

    for line in yaml.lines() {
        let trimmed = line.trim();

        // Top-level field detection (no leading whitespace or minimal)
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_description = false;
            in_recommendation = false;
            in_permissions = false;
            in_required = false;
            in_services = false;

            if let Some(val) = trimmed.strip_prefix("id:") {
                id = val.trim().trim_matches('"').to_string();
            } else if let Some(val) = trimmed.strip_prefix("name:") {
                name = val.trim().trim_matches('"').to_string();
            } else if let Some(val) = trimmed.strip_prefix("category:") {
                category = val.trim().trim_matches('"').to_string();
            } else if trimmed == "description: |" || trimmed.starts_with("description:") {
                in_description = true;
                if let Some(val) = trimmed.strip_prefix("description:") {
                    let val = val.trim();
                    if val != "|" && !val.is_empty() {
                        description = val.to_string();
                        in_description = false;
                    }
                }
            } else if trimmed == "recommendation: |" || trimmed.starts_with("recommendation:") {
                in_recommendation = true;
                if let Some(val) = trimmed.strip_prefix("recommendation:") {
                    let val = val.trim();
                    if val != "|" && !val.is_empty() {
                        recommendation = val.trim_matches('\'').trim_matches('"').to_string();
                        in_recommendation = false;
                    }
                }
            } else if trimmed == "permissions:" {
                in_permissions = true;
            } else if trimmed == "services:" {
                in_services = true;
            }
            continue;
        }

        // Indented content
        if in_description && line.starts_with("  ") {
            if !description.is_empty() {
                description.push(' ');
            }
            description.push_str(trimmed);
        } else if in_recommendation && line.starts_with("  ") {
            if !recommendation.is_empty() {
                recommendation.push(' ');
            }
            recommendation.push_str(trimmed);
        } else if in_services && trimmed.starts_with("- ") {
            services.push(trimmed[2..].trim().to_string());
        } else if in_permissions {
            if trimmed == "required:" {
                in_required = true;
            } else if trimmed == "additional:" {
                in_required = false;
            } else if in_required {
                if let Some(perm) = trimmed.strip_prefix("- permission:") {
                    permissions.push(perm.trim().trim_matches('"').to_string());
                }
            }
        }
    }

    if id.is_empty() {
        return None;
    }

    Some(serde_json::json!({
        "id": id,
        "name": name,
        "category": category,
        "description": description,
        "recommendation": recommendation,
        "permissions": permissions,
        "services": services,
    }))
}
