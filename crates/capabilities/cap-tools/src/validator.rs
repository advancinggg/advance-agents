//! `tool-exports` Component-binary validator — MODULE-017 Slice B.
//!
//! Implements **structural-presence** validation: walks
//! `wasmparser::Payload::ComponentExportSection` entries on the given
//! binary, matches `ComponentExternalKind::Func` exports against the
//! `tool-exports` (`describe` / `execute`) and `runnable` (`run`) item
//! names. The matcher accepts both interface-mangled export names
//! (`advance:runtime/tool-exports@0.1.0#describe`, with or without
//! `@version`) and flat top-level names (`describe`), supporting both
//! the `wit_component::ComponentEncoder` canonical form AND the
//! `wit-bindgen` `export!` macro flat surface.
//!
//! ## What this is NOT
//!
//! - **NOT** full WIT signature equivalence. A binary that exports
//!   `describe()` with a wrong-shape signature will reach WASM
//!   instantiation; the trap during the actual `describe()` call surfaces
//!   as a [`ToolError`] in `LazyToolRegistry::load`. Full WIT equivalence
//!   is intentionally deferred (no Slice B AC depends on it).
//! - **NOT** a runtime instantiation path. This is a pure-bytes inspection
//!   step, suitable for cold-load gating (AC-29 point 2).
//!
//! ## Public surface discipline (round-3 + round-4 plan finding)
//!
//! `wasmparser` types (`Parser`, `Payload`, `ComponentExternalKind`, etc.)
//! stay private to this module. Only [`ValidationOutcome`] +
//! [`ToolError`] are public. Slice C+ can bump `wasmparser` without
//! breaking downstream consumers.

use wasmparser::{ComponentExternalKind, Parser, Payload};

use crate::registry::ToolError;

/// Outcome of validating a component binary against the `tool-exports`
/// contract. Three booleans + an [`ExportSource`] for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationOutcome {
    pub has_describe: bool,
    pub has_execute: bool,
    pub has_runnable: bool,
    pub source: ExportSource,
}

/// Which export-name shape provided each positive signal.
///
/// `Both` records a defensive case: the binary exports BOTH interface-
/// mangled (`advance:runtime/tool-exports#describe`) AND flat
/// top-level (`describe`) — treated as a single positive (logical OR).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportSource {
    None,
    Instance,
    TopLevel,
    Both,
}

impl ExportSource {
    fn merge(self, other: ExportSource) -> ExportSource {
        match (self, other) {
            (ExportSource::None, x) | (x, ExportSource::None) => x,
            (ExportSource::Instance, ExportSource::Instance) => ExportSource::Instance,
            (ExportSource::TopLevel, ExportSource::TopLevel) => ExportSource::TopLevel,
            _ => ExportSource::Both,
        }
    }
}

/// `tool-exports` interface name prefix. The wasmparser export name is
/// `advance:runtime/tool-exports@{semver}#{item}` for the
/// versioned mangled form (which `wit_component::ComponentEncoder` emits).
const TOOL_EXPORTS_PREFIX: &str = "advance:runtime/tool-exports";
const RUNNABLE_PREFIX: &str = "advance:runtime/runnable";

/// Validate a Component binary's exports against the `tool-exports` /
/// `runnable` mutual-exclusion rule.
///
/// **Success arm**: `has_describe && has_execute && !has_runnable` →
/// returns `Ok(ValidationOutcome)`.
///
/// **Error arms**:
/// - missing `describe` or `execute` → `ToolError::InvocationFailed("missing tool-exports: {detail}")`.
/// - both `tool-exports` and `runnable` exported → `ToolError::InvocationFailed("runnable + tool-exports mutual exclusion violated")`.
/// - binary parse failure → `ToolError::InvocationFailed("invalid wasm: {err}")`.
pub fn validate_tool_component(binary: &[u8]) -> Result<ValidationOutcome, ToolError> {
    let outcome = walk_component_exports(binary)
        .map_err(|e| ToolError::InvocationFailed(format!("invalid wasm: {e}")))?;
    // Order matters: a binary with `runnable` AND tool-exports is a mutual-
    // exclusion violation (the real conflict). A binary with `runnable` but
    // NO tool-exports is just a runnable component — fails the "missing
    // tool-exports" check below with a clearer message. This avoids
    // mis-reporting a plain runnable as a "mutual exclusion violation".
    let has_any_tool_export = outcome.has_describe || outcome.has_execute;
    if outcome.has_runnable && has_any_tool_export {
        return Err(ToolError::InvocationFailed(
            "runnable + tool-exports mutual exclusion violated".into(),
        ));
    }
    if !outcome.has_describe || !outcome.has_execute {
        let mut missing = Vec::new();
        if !outcome.has_describe {
            missing.push("describe");
        }
        if !outcome.has_execute {
            missing.push("execute");
        }
        return Err(ToolError::InvocationFailed(format!(
            "missing tool-exports: {}",
            missing.join(", ")
        )));
    }
    Ok(outcome)
}

/// Validate a Component binary's exports against the **`runnable`** side of the
/// `tool-exports` / `runnable` mutual-exclusion rule — the mirror of
/// [`validate_tool_component`], for the `submit-component` admission point
/// (MODULE-017 §2.7 AC-29 point 3; consumed by MODULE-005 cap-lifecycle).
///
/// **Success arm**: `has_runnable && !has_describe && !has_execute` →
/// returns `Ok(ValidationOutcome)`.
///
/// **Error arms** (ordered to mirror [`validate_tool_component`] — the
/// mutual-exclusion conflict is reported FIRST so a binary co-exporting
/// `tool-exports` + `runnable` is never mis-reported as a plain
/// "missing runnable export"):
/// - both `runnable` and `tool-exports` exported →
///   `ToolError::InvocationFailed("runnable + tool-exports mutual exclusion violated")`.
/// - no `runnable` export →
///   `ToolError::InvocationFailed("missing runnable export")`.
/// - binary parse failure → `ToolError::InvocationFailed("invalid wasm: {err}")`.
pub fn validate_runnable_component(binary: &[u8]) -> Result<ValidationOutcome, ToolError> {
    let outcome = walk_component_exports(binary)
        .map_err(|e| ToolError::InvocationFailed(format!("invalid wasm: {e}")))?;
    let has_any_tool_export = outcome.has_describe || outcome.has_execute;
    if outcome.has_runnable && has_any_tool_export {
        return Err(ToolError::InvocationFailed(
            "runnable + tool-exports mutual exclusion violated".into(),
        ));
    }
    if !outcome.has_runnable {
        return Err(ToolError::InvocationFailed(
            "missing runnable export".into(),
        ));
    }
    Ok(outcome)
}

fn walk_component_exports(
    binary: &[u8],
) -> Result<ValidationOutcome, wasmparser::BinaryReaderError> {
    let mut has_describe_instance = false;
    let mut has_describe_top = false;
    let mut has_execute_instance = false;
    let mut has_execute_top = false;
    let mut has_runnable_instance = false;
    let mut has_runnable_top = false;
    for payload in Parser::new(0).parse_all(binary) {
        let payload = payload?;
        if let Payload::ComponentExportSection(reader) = payload {
            for item in reader.into_iter_with_offsets() {
                let (_, export) = item?;
                if !matches!(export.kind, ComponentExternalKind::Func) {
                    continue;
                }
                let name = export.name.0;
                let class = classify_export_name(name);
                match class {
                    NameClass::InstanceDescribe => has_describe_instance = true,
                    NameClass::InstanceExecute => has_execute_instance = true,
                    NameClass::InstanceRunnableRun => has_runnable_instance = true,
                    NameClass::FlatDescribe => has_describe_top = true,
                    NameClass::FlatExecute => has_execute_top = true,
                    NameClass::FlatRun => has_runnable_top = true,
                    NameClass::Unrelated => {}
                }
            }
        }
    }
    let mut source = ExportSource::None;
    let describe_src = combine_source(has_describe_instance, has_describe_top);
    let execute_src = combine_source(has_execute_instance, has_execute_top);
    let runnable_src = combine_source(has_runnable_instance, has_runnable_top);
    source = source.merge(describe_src);
    source = source.merge(execute_src);
    source = source.merge(runnable_src);
    Ok(ValidationOutcome {
        has_describe: has_describe_instance || has_describe_top,
        has_execute: has_execute_instance || has_execute_top,
        has_runnable: has_runnable_instance || has_runnable_top,
        source,
    })
}

fn combine_source(instance: bool, top: bool) -> ExportSource {
    match (instance, top) {
        (false, false) => ExportSource::None,
        (true, false) => ExportSource::Instance,
        (false, true) => ExportSource::TopLevel,
        (true, true) => ExportSource::Both,
    }
}

enum NameClass {
    InstanceDescribe,
    InstanceExecute,
    InstanceRunnableRun,
    FlatDescribe,
    FlatExecute,
    FlatRun,
    Unrelated,
}

/// Classify an export name into one of the recognized categories.
///
/// Mangled form: `advance:runtime/tool-exports[@semver]#{item}` —
/// match by `starts_with(TOOL_EXPORTS_PREFIX)` AND the suffix-after-`#`
/// equals the canonical item name. `runnable` follows the same shape.
fn classify_export_name(name: &str) -> NameClass {
    if let Some(item) = item_after_hash(name, TOOL_EXPORTS_PREFIX) {
        match item {
            "describe" => return NameClass::InstanceDescribe,
            "execute" => return NameClass::InstanceExecute,
            _ => return NameClass::Unrelated,
        }
    }
    if let Some(item) = item_after_hash(name, RUNNABLE_PREFIX) {
        if item == "run" {
            return NameClass::InstanceRunnableRun;
        }
        return NameClass::Unrelated;
    }
    match name {
        "describe" => NameClass::FlatDescribe,
        "execute" => NameClass::FlatExecute,
        "run" => NameClass::FlatRun,
        _ => NameClass::Unrelated,
    }
}

/// Return `Some(item)` if `name` starts with `prefix` followed by
/// optional `@semver`, then `#item`. Otherwise `None`.
fn item_after_hash<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = name.strip_prefix(prefix)?;
    // After the prefix we expect either '@<version>#<item>' or '#<item>'.
    let after_version = match rest.strip_prefix('@') {
        Some(s) => {
            // skip until '#'
            let hash_idx = s.find('#')?;
            &s[hash_idx..]
        }
        None => rest,
    };
    after_version.strip_prefix('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_mangled_describe() {
        assert!(matches!(
            classify_export_name("advance:runtime/tool-exports@0.1.0#describe"),
            NameClass::InstanceDescribe
        ));
        assert!(matches!(
            classify_export_name("advance:runtime/tool-exports#describe"),
            NameClass::InstanceDescribe
        ));
    }

    #[test]
    fn classify_mangled_execute() {
        assert!(matches!(
            classify_export_name("advance:runtime/tool-exports@0.1.0#execute"),
            NameClass::InstanceExecute
        ));
    }

    #[test]
    fn classify_mangled_run() {
        assert!(matches!(
            classify_export_name("advance:runtime/runnable@0.1.0#run"),
            NameClass::InstanceRunnableRun
        ));
    }

    #[test]
    fn classify_flat() {
        assert!(matches!(
            classify_export_name("describe"),
            NameClass::FlatDescribe
        ));
        assert!(matches!(
            classify_export_name("execute"),
            NameClass::FlatExecute
        ));
        assert!(matches!(classify_export_name("run"), NameClass::FlatRun));
    }

    #[test]
    fn classify_unrelated() {
        assert!(matches!(
            classify_export_name("some-other-export"),
            NameClass::Unrelated
        ));
        assert!(matches!(
            classify_export_name("advance:runtime/tool-exports@0.1.0#unknown-item"),
            NameClass::Unrelated
        ));
    }

    #[test]
    fn validate_rejects_empty_binary() {
        let err = validate_tool_component(&[]).expect_err("must reject");
        match err {
            ToolError::InvocationFailed(msg) => assert!(msg.contains("invalid wasm")),
            _ => panic!("wrong arm"),
        }
    }
}
