//! MODULE-017 Slice C — `LazyToolRegistry` tool-invoke 主流程 external-
//! surface tests.
//!
//! Covers the externally-visible Slice C surface:
//!
//! - **SC-52**: legacy `::new(config)` path preserves Slice B behavior at
//!   the load/invoke boundary (unknown id → NotFound; the SB-21
//!   InvocationFailed-deferred behavior is verified by the integration
//!   suite in `tests/registry_lru.rs`).
//! - **Slice C additive `LazyRegistryConfig` fields**: defaults are sane
//!   and the `From<&ToolsConfig>` translation keeps additive fields at
//!   `Default`.
//! - **`MAX_TOOL_DESCRIPTION_BYTES`**: exposed as a `pub` constant for
//!   cross-crate reasoning (128 KiB aggregate cap closing the methods-
//!   vector DoS surface).
//!
//! In-WASM execute integration tests (SC-48 / SC-49 / SC-53 / SC-54 /
//! SC-56) — **landed in Slice V1-c (2026-05-30)** now that the real
//! `echo_tool.component.wasm` fixture is committed (built via wit-bindgen +
//! `wasm-tools component new` for `wasm32-unknown-unknown`; cargo-component
//! NOT required — MODULE-017 §3.6 (e) reconciled). They load the real
//! component through the engine-bearing `new_with_engine` path and exercise
//! `tool-exports.execute` end-to-end.

use std::num::NonZeroUsize;
use std::time::Duration;

use cap_tools::lazy_registry::MAX_TOOL_DESCRIPTION_BYTES;
use cap_tools::{LazyRegistryConfig, LazyToolRegistry, ToolError, ToolRegistry};

fn small_config() -> LazyRegistryConfig {
    LazyRegistryConfig {
        max_tool_instances: NonZeroUsize::new(2).expect("2 != 0"),
        lazy_load_timeout: Duration::from_secs(5),
        max_result_bytes: 1024,
        ..Default::default()
    }
}

/// SC-52: legacy `::new(config)` (no engine) — unknown tool id flows
/// through the load path and returns NotFound (preserves the original
/// NotFound contract before the engine-presence branching kicks in).
#[tokio::test]
async fn sc_52_legacy_invoke_unknown_id_not_found() {
    let reg = LazyToolRegistry::new(small_config());
    let err = reg
        .invoke("nope", "echo", b"hi")
        .await
        .expect_err("unknown tool id");
    match err {
        ToolError::NotFound(id) => assert_eq!(id, "nope"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

/// LazyRegistryConfig defaults — Slice C additive fields have sane values.
#[test]
fn slice_c_default_fields() {
    let cfg = LazyRegistryConfig::default();
    assert_eq!(cfg.tool_invoke_timeout, Duration::from_secs(5));
    assert_eq!(cfg.tool_fuel_per_call, None);
    assert_eq!(cfg.bring_up_describe_timeout, Duration::from_secs(2));
    // Original 3 fields unchanged.
    assert_eq!(cfg.max_tool_instances.get(), 20);
    assert_eq!(cfg.lazy_load_timeout, Duration::from_secs(30));
    assert_eq!(cfg.max_result_bytes, 16 * 1024 * 1024);
}

/// `From<&ToolsConfig>` plumbs all 6 fields (adversarial round 1 fix for
/// C4 — Slice C additive fields now operator-tunable). With a ToolsConfig
/// using its own defaults, the resulting LazyRegistryConfig matches the
/// LazyRegistryConfig::default() Slice C field values.
#[test]
fn from_tools_config_plumbs_all_six_fields() {
    use advance_runtime::config::ToolsConfig;
    let tools = ToolsConfig {
        max_tool_instances: 7,
        lazy_load_timeout_sec: 17,
        max_result_bytes: 8 * 1024,
        tool_invoke_timeout_sec: 11,
        tool_fuel_per_call: Some(123_456),
        bring_up_describe_timeout_sec: 3,
    };
    let cfg: LazyRegistryConfig = (&tools).into();
    // Original 3 fields translated.
    assert_eq!(cfg.max_tool_instances.get(), 7);
    assert_eq!(cfg.lazy_load_timeout, Duration::from_secs(17));
    assert_eq!(cfg.max_result_bytes, 8 * 1024);
    // Slice C additive fields are now plumbed through (adversarial fix C4).
    assert_eq!(cfg.tool_invoke_timeout, Duration::from_secs(11));
    assert_eq!(cfg.tool_fuel_per_call, Some(123_456));
    assert_eq!(cfg.bring_up_describe_timeout, Duration::from_secs(3));
}

/// Default ToolsConfig still maps to default Slice C LazyRegistryConfig
/// fields — the two default sets are kept in agreement.
#[test]
fn from_default_tools_config_matches_default_lazy_registry_config_for_slice_c() {
    use advance_runtime::config::ToolsConfig;
    let tools = ToolsConfig::default();
    let cfg: LazyRegistryConfig = (&tools).into();
    let defaults = LazyRegistryConfig::default();
    assert_eq!(cfg.tool_invoke_timeout, defaults.tool_invoke_timeout);
    assert_eq!(cfg.tool_fuel_per_call, defaults.tool_fuel_per_call);
    assert_eq!(
        cfg.bring_up_describe_timeout,
        defaults.bring_up_describe_timeout
    );
}

/// MAX_TOOL_DESCRIPTION_BYTES is the aggregate cap exposed for cross-crate
/// reasoning (round-5 Info finding #2 fix: closes the methods-vector DoS
/// surface).
#[test]
fn max_tool_description_bytes_cap_is_128k() {
    assert_eq!(MAX_TOOL_DESCRIPTION_BYTES, 128 * 1024);
}

// ─────────────────────────────────────────────────────────────────────
// In-WASM execute integration suite (SC-48/49/53/54/56) — Slice V1-c.
// Loads the committed real `echo_tool.component.wasm` through the
// engine-bearing `new_with_engine` path. `echo_tool.execute("echo", p)`
// returns `p` verbatim; the `echo` method declares no input/output schema,
// so the Slice-F JSON-Schema gate short-circuits and any byte payload
// round-trips.
// ─────────────────────────────────────────────────────────────────────

use advance_runtime::component_loader::{ComponentRuntime, ToolEngineHandle};
use advance_runtime::config::WasmConfig;

/// The committed real tool component (exports `advance:runtime/tool-exports`).
const ECHO_TOOL_WASM: &[u8] = include_bytes!("fixtures/echo_tool.component.wasm");

fn tool_engine() -> ToolEngineHandle {
    let cfg = WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    };
    ComponentRuntime::new(&cfg)
        .expect("construct ComponentRuntime")
        .tool_engine_handle()
}

fn engine_registry() -> LazyToolRegistry {
    LazyToolRegistry::new_with_engine(small_config(), tool_engine())
}

/// SC-48 — echo round-trip: `execute("echo", params)` returns params verbatim.
#[tokio::test]
async fn sc_48_in_wasm_echo_round_trip() {
    let reg = engine_registry();
    reg.register_binary("skill::echoer", ECHO_TOOL_WASM.to_vec())
        .await;
    let out = reg
        .invoke("skill::echoer", "echo", b"hello-l2")
        .await
        .expect("echo invoke");
    assert_eq!(out, b"hello-l2", "echo returns params unchanged");
}

/// SC-49 — empty + arbitrary binary payloads round-trip (no schema gate).
#[tokio::test]
async fn sc_49_in_wasm_echo_arbitrary_bytes() {
    let reg = engine_registry();
    reg.register_binary("t", ECHO_TOOL_WASM.to_vec()).await;
    assert_eq!(reg.invoke("t", "echo", b"").await.expect("empty"), b"");
    let bin = vec![0u8, 1, 2, 255, 254, 0, 42];
    assert_eq!(reg.invoke("t", "echo", &bin).await.expect("bin"), bin);
}

/// SC-53 — unknown method → guest `method-not-found` → `MethodNotFound`.
#[tokio::test]
async fn sc_53_unknown_method_is_method_not_found() {
    let reg = engine_registry();
    reg.register_binary("t", ECHO_TOOL_WASM.to_vec()).await;
    let err = reg
        .invoke("t", "nope", b"x")
        .await
        .expect_err("unknown method");
    match err {
        ToolError::MethodNotFound(m) => assert_eq!(m, "nope"),
        other => panic!("expected MethodNotFound, got {other:?}"),
    }
}

/// SC-54 — describe() surfaces the single `echo` method via list() once loaded.
#[tokio::test]
async fn sc_54_describe_surfaces_echo_method() {
    let reg = engine_registry();
    reg.register_binary("t", ECHO_TOOL_WASM.to_vec()).await;
    reg.load("t").await.expect("load"); // populate the cache with describe()
    let infos = reg.list().await;
    let echo = infos.iter().find(|i| i.id == "t").expect("listed");
    assert_eq!(echo.methods.len(), 1, "one method");
    assert_eq!(echo.methods[0].name, "echo");
}

/// SC-56 — result is bounded by `max_result_bytes` (small_config caps at 1024);
/// echoing a 2 KiB payload trips the output cap.
#[tokio::test]
async fn sc_56_result_exceeds_max_result_bytes() {
    let reg = engine_registry();
    reg.register_binary("t", ECHO_TOOL_WASM.to_vec()).await;
    let big = vec![7u8; 2048];
    let err = reg
        .invoke("t", "echo", &big)
        .await
        .expect_err("over max_result_bytes");
    assert!(
        matches!(err, ToolError::OutputValidationFailed(_)),
        "expected OutputValidationFailed, got {err:?}"
    );
}
