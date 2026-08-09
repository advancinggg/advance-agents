//! T_S A8 — AC-13 enforcement: no first-party crate may directly depend on a
//! tracing/log/slog/log4rs/env_logger/fern crate.
//!
//! Round-3 Critical 1 fix: uses the `toml` crate for parsing rather than line-based
//! regex (regex missed `<crate>.workspace = true` dotted-key syntax). Round-6 W4 fix:
//! also asserts that `crates/event-bus`'s `[dependencies]` and `[build-dependencies]`
//! tables do NOT contain a `toml` key — sentinel against accidental promotion of the
//! dev-only dep into the production graph.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

const FORBIDDEN: &[&str] = &[
    "tracing",
    "tracing-subscriber",
    "tracing-core",
    "tracing-attributes",
    "tracing-futures",
    "log",
    "slog",
    "slog-stdlog",
    "slog-async",
    "slog-term",
    "log4rs",
    "env_logger",
    "fern",
];

const SKIP_DIRS: &[&str] = &["target", "node_modules", ".git", "dist", "fixtures"];
const MAX_DEPTH: usize = 6;

#[test]
fn no_first_party_crate_depends_on_tracing_or_log_subsystems() {
    let workspace_root = find_workspace_root();
    let mut tomls: Vec<PathBuf> = Vec::new();

    let workspace_cargo = workspace_root.join("Cargo.toml");
    if workspace_cargo.exists() {
        tomls.push(workspace_cargo);
    }
    walk_for_cargo_tomls(&workspace_root.join("crates"), 0, &mut tomls);

    let mut violations: Vec<(PathBuf, String, String)> = Vec::new();

    for toml_path in &tomls {
        let raw = fs::read_to_string(toml_path)
            .unwrap_or_else(|e| panic!("read {}: {}", toml_path.display(), e));
        let parsed: Value =
            toml::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {}", toml_path.display(), e));
        let deps = collect_dependency_names(&parsed);
        for (section, name) in deps {
            if FORBIDDEN.iter().any(|f| *f == name) {
                violations.push((toml_path.clone(), section, name));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "AC-13 violation — direct logging-crate dep found:\n{}",
        violations
            .iter()
            .map(|(p, s, n)| format!("  {} → [{}] {}", p.display(), s, n))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    // Round-6 W4 sentinel: event-bus's [dependencies] and [build-dependencies]
    // must NOT contain a `toml` key — the workspace-pinned `toml` is dev-only.
    let event_bus_toml = workspace_root.join("crates/event-bus/Cargo.toml");
    assert!(event_bus_toml.exists(), "event-bus Cargo.toml not found");
    let raw = fs::read_to_string(&event_bus_toml).expect("read event-bus Cargo.toml");
    let parsed: Value = toml::from_str(&raw).expect("parse event-bus Cargo.toml");
    for forbidden_section in &["dependencies", "build-dependencies"] {
        if let Some(table) = parsed.get(forbidden_section).and_then(|v| v.as_table()) {
            assert!(
                !table.contains_key("toml"),
                "Round-6 W4 sentinel — `toml` crate must not appear in event-bus [{}]; \
                 it is workspace-pinned as a dev-dep only.",
                forbidden_section,
            );
        }
    }
}

fn find_workspace_root() -> PathBuf {
    // Walk up from CARGO_MANIFEST_DIR (set by cargo at test compile time) until we
    // find a Cargo.toml containing [workspace]. Robust to future workspace
    // restructuring.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut current: PathBuf = PathBuf::from(manifest_dir);
    for _ in 0..16 {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(raw) = fs::read_to_string(&candidate) {
                if let Ok(parsed) = toml::from_str::<Value>(&raw) {
                    if parsed.get("workspace").is_some() {
                        return current;
                    }
                }
            }
        }
        if !current.pop() {
            break;
        }
    }
    panic!("workspace root (Cargo.toml with [workspace]) not found from {manifest_dir}");
}

fn walk_for_cargo_tomls(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth >= MAX_DEPTH {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(it) => it,
        Err(_) => return,
    };
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let file_type = entry.file_type().expect("file_type");
        if file_type.is_dir() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if SKIP_DIRS.iter().any(|s| *s == name_str) {
                continue;
            }
            walk_for_cargo_tomls(&path, depth + 1, out);
        } else if file_type.is_file() && entry.file_name() == "Cargo.toml" {
            out.push(path);
        }
    }
}

fn collect_dependency_names(parsed: &Value) -> BTreeSet<(String, String)> {
    let mut result = BTreeSet::new();

    let dep_section_names = ["dependencies", "dev-dependencies", "build-dependencies"];
    for section in &dep_section_names {
        if let Some(table) = parsed.get(section).and_then(|v| v.as_table()) {
            for key in table.keys() {
                result.insert((section.to_string(), key.to_string()));
            }
        }
    }

    // [workspace.dependencies]
    if let Some(workspace) = parsed.get("workspace").and_then(|v| v.as_table()) {
        if let Some(table) = workspace.get("dependencies").and_then(|v| v.as_table()) {
            for key in table.keys() {
                result.insert(("workspace.dependencies".to_string(), key.to_string()));
            }
        }
    }

    // [target.<cfg>.dependencies] / dev-dependencies / build-dependencies
    if let Some(target) = parsed.get("target").and_then(|v| v.as_table()) {
        for (cfg, cfg_value) in target {
            if let Some(cfg_table) = cfg_value.as_table() {
                for section in &dep_section_names {
                    if let Some(table) = cfg_table.get(*section).and_then(|v| v.as_table()) {
                        for key in table.keys() {
                            result.insert((format!("target.{cfg}.{section}"), key.to_string()));
                        }
                    }
                }
            }
        }
    }

    result
}
