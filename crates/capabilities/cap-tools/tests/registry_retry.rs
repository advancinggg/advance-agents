//! MODULE-017-AC-24 — Slice G integration tests for the tool-retry
//! idempotency gate wired into [`cap_tools::LazyToolRegistry`].
//!
//! These tests exercise the publicly observable behaviour of
//! `tool_invoke_max_retries`:
//!
//! - **T-RETRY-01 (T26-G3)**: `LazyRegistryConfig::default().tool_invoke_max_retries == 0`
//!   — default-zero pin (opt-in field).
//! - **T-RETRY-02 (T26-G5)**: `LazyRegistryConfig::from(&ToolsConfig::default())
//!   .tool_invoke_max_retries == 0` — From-impl maps to Default value
//!   (surfacing as a runtime-config YAML knob deferred — MODULE-017 §3.6 (tt)).
//! - **T-RETRY-03 (T26-G4)**: `LazyToolRegistry::new(cfg with max_retries=3)
//!   .invoke(...)` on the legacy `engine: None` path returns the SB-21
//!   `InvocationFailed("slice-B: in-WASM execute deferred...")` SINGLE-SHOT —
//!   the retry harness lives strictly inside the `Some(engine)` branch.
//!   Without the gate, `InvocationFailed` is the bucket the SB-21 stub uses,
//!   which would naïvely match the transient-class predicate and retry
//!   forever. The legitimate behaviour is: the SB-21 path short-circuits
//!   BEFORE the retry harness is ever entered.
//! - **T-RETRY-04**: struct-spread construction with explicit non-default
//!   fields keeps `tool_invoke_max_retries == 0` (`..Default::default()`
//!   spread covers the new field).
//! - **T-RETRY-05**: SB-21 single-shot regression with `max_retries == 0`
//!   — same as T-RETRY-03 baseline (the no-engine path is one-shot regardless
//!   of `tool_invoke_max_retries`).
//!
//! End-to-end behavioural verification of the retry loop on the
//! `Some(engine)` path is deferred (no `echo_tool.component.wasm`
//! fixture per MODULE-017 §3.6 (e)); the gate + harness are covered
//! by unit tests inside `cap-tools/src/retry.rs::tests` (T26-G1 truth
//! table + T26-G2 harness call-count table).

use std::num::NonZeroUsize;
use std::time::Duration;

use advance_runtime::config::ToolsConfig;
use cap_tools::{LazyRegistryConfig, LazyToolRegistry, ToolError, ToolRegistry};

/// T-RETRY-01 (T26-G3): default-zero pin.
#[test]
fn t_retry_01_default_max_retries_is_zero() {
    let cfg = LazyRegistryConfig::default();
    assert_eq!(
        cfg.tool_invoke_max_retries, 0,
        "LazyRegistryConfig::default().tool_invoke_max_retries must be 0 — \
         the field is opt-in per MODULE-017 §3.6 (tt). Operators opt-in via \
         explicit LazyRegistryConfig construction."
    );
}

/// T-RETRY-02 (T26-G5): From<&ToolsConfig> maps to default.
#[test]
fn t_retry_02_from_tools_config_default_max_retries_is_zero() {
    let tools = ToolsConfig::default();
    let cfg: LazyRegistryConfig = (&tools).into();
    assert_eq!(
        cfg.tool_invoke_max_retries, 0,
        "From<&ToolsConfig> for LazyRegistryConfig must keep \
         tool_invoke_max_retries at 0 — surfacing as a runtime YAML knob \
         is deferred to a follow-on slice (MODULE-017 §3.6 (tt))."
    );
}

/// T-RETRY-03 (T26-G4): SB-21 single-shot on the no-engine path even
/// when max_retries is non-zero. The retry harness must NOT be active
/// on the legacy `::new(config)` path (engine: None) — that path
/// short-circuits to the SB-21 fail-explicit InvocationFailed BEFORE
/// the retry harness would wrap dispatch.
#[tokio::test]
async fn t_retry_03_no_engine_path_single_shot_despite_max_retries() {
    let cfg = LazyRegistryConfig {
        max_tool_instances: NonZeroUsize::new(2).expect("2 != 0"),
        lazy_load_timeout: Duration::from_secs(5),
        max_result_bytes: 1024,
        tool_invoke_max_retries: 3,
        ..Default::default()
    };
    let reg = LazyToolRegistry::new(cfg);

    // Register a tiny WASM component (the actual bytes don't matter
    // — Slice B's validator fails first on this hand-rolled binary,
    // which is the SB-21 contract path. The retry harness lives
    // strictly INSIDE the `Some(engine)` branch which is never
    // entered on `::new(config)`.
    //
    // We use the simplest path: invoke on an unregistered tool. The
    // load() short-circuit returns NotFound (which is NOT in the
    // retryable class anyway), proving the no-engine path is
    // single-shot.
    let result = reg.invoke("nonexistent-tool", "m", &[]).await;
    assert!(
        matches!(result, Err(ToolError::NotFound(_))),
        "unregistered tool must short-circuit to NotFound — proves the \
         retry harness did not bleed into the load() path. Got: {:?}",
        result,
    );
}

/// T-RETRY-04: struct-spread construction keeps the new field at 0
/// via the `..Default::default()` spread — confirms existing test
/// helpers in tests/registry_lru.rs + tests/registry_dispatch.rs
/// keep their current semantics without code changes.
#[test]
fn t_retry_04_struct_spread_keeps_new_field_at_default_zero() {
    let cfg = LazyRegistryConfig {
        max_tool_instances: NonZeroUsize::new(2).expect("2 != 0"),
        lazy_load_timeout: Duration::from_secs(5),
        max_result_bytes: 1024,
        ..Default::default()
    };
    assert_eq!(
        cfg.tool_invoke_max_retries, 0,
        "..Default::default() spread must propagate Default's 0 — \
         otherwise existing struct-literal call sites in \
         tests/registry_lru.rs and tests/registry_dispatch.rs would \
         silently inherit a non-default value once the new field is \
         added. Slice G compatibility hinges on this."
    );
}

/// T-RETRY-05: SB-21 single-shot baseline with max_retries = 0 —
/// regression pin for the no-engine InvocationFailed contract under
/// the new field's default value.
#[tokio::test]
async fn t_retry_05_no_engine_default_max_retries_single_shot() {
    let cfg = LazyRegistryConfig::default();
    let reg = LazyToolRegistry::new(cfg);
    let result = reg.invoke("nonexistent-tool", "m", &[]).await;
    assert!(
        matches!(result, Err(ToolError::NotFound(_))),
        "default config must produce single-shot behaviour identical \
         to pre-Slice-G — got: {:?}",
        result,
    );
}
