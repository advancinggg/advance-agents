//! Feature audit — MODULE-001-AC-02 dependency-audit half (REQ-015).
//!
//! Parses the `[workspace.dependencies]` entries for `wasmtime` and `wasmtime-wasi`
//! from the workspace Cargo.toml (embedded via `include_str!` at test-compile time)
//! and asserts:
//!   - exact feature-set whitelist,
//!   - `default-features = false`,
//!   - absence of explicitly-forbidden features per REQ-015.
//!
//! Implementation choice: a line-oriented parser instead of the `toml` crate.
//! Adding `toml =0.8.23` would pull `toml_edit`, `winnow`, `serde_spanned`,
//! `toml_datetime`, `toml_write` into the workspace supply chain (5 net-new
//! transitive crates). Per the Slice A' exact-pin + minimize-surface discipline
//! (workspace Cargo.toml supply-chain follow-up bullet), dev-dep additions are
//! scrutinized; for a single test file's parsing needs zero new deps is preferred.
//! The parser enforces the project's one-dep-per-line `[workspace.dependencies]`
//! convention by panicking with a clear message if the target dep is split across
//! lines — steering any future reformatter toward preserving the convention or
//! explicitly picking the `toml` crate in a follow-up.
//!
//! Forbidden feature taxonomy verified against
//! `wasmtime-43.0.1/Cargo.toml` and `wasmtime-wasi-43.0.0/Cargo.toml`
//! (43.0.0 and 43.0.1 share an identical feature set; workspace pins 43.0.1):
//!
//!   wasmtime: `component-model-async`, `component-model-async-bytes`,
//!             `threads`, `gc`, `gc-drc`, `gc-null`, `stack-switching`
//!   wasmtime-wasi: `p0` (legacy alias for p1), `p1` (WASI preview1 — REQ-015 excludes),
//!                  `p3` (experimental tier that pulls Component Model async features)
//!
//! Fuel is NOT a Wasmtime Cargo feature — it is runtime-configured via
//! `wasmtime::Config::consume_fuel` per ARCH §8 Decision 16 Implication (i);
//! asserting its absence would be a no-op.

use std::collections::HashSet;

const WORKSPACE_CARGO_TOML: &str = include_str!("../../../Cargo.toml");

/// Find the single-line definition of the named dep inside `[workspace.dependencies]`.
/// Returns the entire line (including the dep name prefix). Panics with a helpful
/// message distinguishing three error modes: (a) dep not present, (b) dep present in
/// string-version form (not the expected `{ ... }` table form), (c) dep table form
/// spans multiple physical lines.
fn find_dep_line(dep: &str) -> &'static str {
    let mut in_workspace_deps = false;
    let mut saw_in_string_form = false;
    for line in WORKSPACE_CARGO_TOML.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_workspace_deps = trimmed == "[workspace.dependencies]";
            continue;
        }
        if !in_workspace_deps {
            continue;
        }
        // Exact name + '=' match to avoid `wasmtime` prefix-colliding with `wasmtime-wasi`.
        let prefix = format!("{dep} =");
        let alt_prefix = format!("{dep}=");
        if trimmed.starts_with(&prefix) || trimmed.starts_with(&alt_prefix) {
            let rest = trimmed
                .trim_start_matches(dep)
                .trim_start()
                .trim_start_matches('=')
                .trim_start();
            if rest.starts_with('{') && rest.contains('}') {
                return line;
            } else if rest.starts_with('{') {
                panic!(
                    "[workspace.dependencies] entry for `{dep}` spans multiple lines; \
                     Slice U feature_audit.rs requires the one-dep-per-line convention. \
                     Restore single-line form or swap the audit to the `toml` crate."
                );
            } else {
                saw_in_string_form = true; // e.g. `foo = "=1.2.3"`
            }
        }
    }
    if saw_in_string_form {
        panic!(
            "[workspace.dependencies].{dep} is in string-version form (expected `{{ ... }}` \
             table with explicit features array)"
        );
    } else {
        panic!("[workspace.dependencies].{dep} not found in workspace Cargo.toml");
    }
}

/// Extract the `features = [ ... ]` array contents from the single-line dep line.
/// Uses a leading-space prefix to avoid false-matching the substring inside
/// `default-features = [...]` (audit-fix R1 W3 — defensive against a future
/// reformat that switches the boolean form to per-feature-gate array form).
fn features_in_line(line: &str) -> HashSet<String> {
    let key = " features = [";
    let start = line
        .find(key)
        .unwrap_or_else(|| panic!("expected ` features = [` in {line:?}"))
        + key.len();
    let end_rel = line[start..]
        .find(']')
        .unwrap_or_else(|| panic!("unterminated `features = [` in {line:?}"));
    let body = &line[start..start + end_rel];
    body.split(',')
        .map(|s| s.trim().trim_matches('"'))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn default_features_is_false(line: &str) -> bool {
    line.contains("default-features = false")
}

#[test]
fn wasmtime_feature_whitelist_exact() {
    let line = find_dep_line("wasmtime");
    let actual = features_in_line(line);
    let expected: HashSet<String> = ["runtime", "component-model", "async", "cranelift"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        actual, expected,
        "wasmtime features must be exactly {expected:?}, got {actual:?}\n  line: {line}"
    );
    assert!(
        default_features_is_false(line),
        "wasmtime default-features must be false (REQ-015)\n  line: {line}"
    );
}

#[test]
fn wasmtime_wasi_feature_whitelist_exact() {
    let line = find_dep_line("wasmtime-wasi");
    let actual = features_in_line(line);
    let expected: HashSet<String> = ["p2"].iter().map(|s| s.to_string()).collect();
    assert_eq!(
        actual, expected,
        "wasmtime-wasi features must be exactly [\"p2\"], got {actual:?}\n  line: {line}"
    );
    assert!(
        default_features_is_false(line),
        "wasmtime-wasi default-features must be false (REQ-015)\n  line: {line}"
    );
}

#[test]
fn no_forbidden_wasmtime_features_enabled() {
    let forbidden = [
        "component-model-async",
        "component-model-async-bytes",
        "threads",
        "gc",
        "gc-drc",
        "gc-null",
        "stack-switching",
    ];
    let line = find_dep_line("wasmtime");
    let actual = features_in_line(line);
    for f in &forbidden {
        assert!(
            !actual.contains(*f),
            "forbidden wasmtime feature \"{f}\" enabled (REQ-015)\n  line: {line}"
        );
    }
}

#[test]
fn no_forbidden_wasmtime_wasi_features_enabled() {
    let forbidden = ["p0", "p1", "p3"];
    let line = find_dep_line("wasmtime-wasi");
    let actual = features_in_line(line);
    for f in &forbidden {
        assert!(
            !actual.contains(*f),
            "forbidden wasmtime-wasi feature \"{f}\" enabled (REQ-015)\n  line: {line}"
        );
    }
}
