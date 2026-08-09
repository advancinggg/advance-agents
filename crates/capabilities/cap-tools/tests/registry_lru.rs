//! SB-06..SB-11 — `LazyToolRegistry` LRU + lazy + tool-exports validation
//! + failed-load hidden + mutual-exclusion.
//!
//! Tests use `wit_component::dummy_module` to synthesize Component binaries
//! that satisfy / violate the `tool-exports` contract. The dummy bodies
//! trap on call, but Slice B's validator + registry chain inspects exports
//! statically — actual invocation isn't required for the validator
//! verdict.

use std::num::NonZeroUsize;
use std::time::Duration;

use cap_tools::{LazyRegistryConfig, LazyToolRegistry, ToolError, ToolRegistry};
use wit_component::{embed_component_metadata, ComponentEncoder, StringEncoding};
use wit_parser::{ManglingAndAbi, Resolve};

// ────────────────────────────────────────────────────────────────────
// WIT fixtures
// ────────────────────────────────────────────────────────────────────

// Use the canonical `advance:runtime` package name so the dummy_module
// emits exports mangled exactly as the validator expects
// (`advance:runtime/tool-exports@0.1.0#describe`).
const WIT_TOOL_EXPORTS: &str = r#"
package advance:runtime@0.1.0;

interface tool-exports {
    record method-info {
        name: string,
    }
    record tool-description {
        description: string,
        methods: list<method-info>,
    }
    describe: func() -> tool-description;
    execute: func(method: string, params: list<u8>) -> result<list<u8>, string>;
}

world tool-world {
    export tool-exports;
}
"#;

const WIT_RUNNABLE: &str = r#"
package advance:runtime@0.1.0;

interface runnable {
    run: func();
}

world runnable-world {
    export runnable;
}
"#;

const WIT_TOOL_PLUS_RUNNABLE: &str = r#"
package advance:runtime@0.1.0;

interface tool-exports {
    record method-info {
        name: string,
    }
    record tool-description {
        description: string,
        methods: list<method-info>,
    }
    describe: func() -> tool-description;
    execute: func(method: string, params: list<u8>) -> result<list<u8>, string>;
}

interface runnable {
    run: func();
}

world both-world {
    export tool-exports;
    export runnable;
}
"#;

fn build_dummy_component(wit: &str, world: &str) -> Vec<u8> {
    let mut resolve = Resolve::default();
    let pkg = resolve.push_str("inline.wit", wit).expect("WIT parses");
    let world = resolve
        .select_world(&[pkg], Some(world))
        .expect("world found");
    let mut core = wit_component::dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut core, &resolve, world, StringEncoding::UTF8)
        .expect("embed metadata");
    ComponentEncoder::default()
        .validate(true)
        .module(&core)
        .expect("module accepted")
        .encode()
        .expect("component encoded")
}

fn small_cap_config() -> LazyRegistryConfig {
    LazyRegistryConfig {
        max_tool_instances: NonZeroUsize::new(2).expect("2 != 0"),
        lazy_load_timeout: Duration::from_secs(5),
        max_result_bytes: 1024,
        ..Default::default()
    }
}

// ────────────────────────────────────────────────────────────────────
// SB-06 — load validates tool-exports: first load returns
//         InvocationFailed (validator-specific); subsequent loads
//         and invoke short-circuit to NotFound (AC-12 hidden).
// ────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_06_load_validates_tool_exports() {
    let reg = LazyToolRegistry::new(small_cap_config());
    // Empty bytes — validator rejects.
    reg.register_binary("broken", vec![0, 0, 0, 0]).await;
    // First load — surfaces validator-specific error for diagnostic.
    let err = reg.load("broken").await.expect_err("must fail");
    match err {
        ToolError::InvocationFailed(msg) => assert!(msg.contains("invalid wasm")),
        other => panic!("expected InvocationFailed got {other:?}"),
    }
    // Second load — hidden, short-circuits via failed-map.
    let err2 = reg.load("broken").await.expect_err("must fail");
    assert!(matches!(err2, ToolError::NotFound(_)));
    // After failed load, invoke also short-circuits to NotFound.
    let invoke_err = reg.invoke("broken", "m", &[]).await.expect_err("must fail");
    assert!(matches!(invoke_err, ToolError::NotFound(_)));
}

// ────────────────────────────────────────────────────────────────────
// SB-07 — Binary exporting BOTH tool-exports and runnable rejected.
//         First load surfaces validator-specific InvocationFailed.
// ────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_07_runnable_co_export_rejected() {
    let reg = LazyToolRegistry::new(small_cap_config());
    let bytes = build_dummy_component(WIT_TOOL_PLUS_RUNNABLE, "both-world");
    reg.register_binary("hybrid", bytes).await;
    let err = reg.load("hybrid").await.expect_err("must fail");
    match err {
        ToolError::InvocationFailed(msg) => {
            assert!(msg.contains("runnable + tool-exports mutual exclusion"))
        }
        other => panic!("expected InvocationFailed got {other:?}"),
    }
    // Subsequent load — short-circuit to NotFound (hidden).
    let err2 = reg.load("hybrid").await.expect_err("must fail");
    assert!(matches!(err2, ToolError::NotFound(_)));
}

// ────────────────────────────────────────────────────────────────────
// SB-08 — Failed loads hidden from list-tools; valid tool still listed.
// ────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_08_failed_load_hidden_from_list() {
    let reg = LazyToolRegistry::new(small_cap_config());
    let valid = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    reg.register_binary("good", valid).await;
    reg.register_binary("bad", vec![0, 0, 0, 0]).await;
    // Trigger loads.
    let _ = reg.load("good").await.expect("good loads");
    let _ = reg.load("bad").await.expect_err("bad fails");
    let tools = reg.list().await;
    let ids: Vec<&str> = tools.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, vec!["good"], "bad should be hidden");
}

// ────────────────────────────────────────────────────────────────────
// SB-09 — Lazy first-load then cache.
// ────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_09_lazy_first_load_then_cache() {
    let reg = LazyToolRegistry::new(small_cap_config());
    let bytes = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    reg.register_binary("a", bytes).await;
    assert_eq!(reg.cache_len().await, 0);
    let _ = reg.load("a").await.expect("load ok");
    assert_eq!(reg.cache_len().await, 1);
    // Repeated load — still 1 entry.
    let _ = reg.load("a").await.expect("re-load ok");
    assert_eq!(reg.cache_len().await, 1);
}

// ────────────────────────────────────────────────────────────────────
// SB-10 — LRU evicts oldest at capacity; evicted tool re-loadable.
// ────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_10_lru_evicts_oldest_at_capacity() {
    let reg = LazyToolRegistry::new(small_cap_config()); // cap = 2
    let a = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    let b = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    let c = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    reg.register_binary("a", a).await;
    reg.register_binary("b", b).await;
    reg.register_binary("c", c).await;
    let _ = reg.load("a").await.unwrap();
    let _ = reg.load("b").await.unwrap();
    assert_eq!(reg.cache_len().await, 2);
    let _ = reg.load("c").await.unwrap();
    // Cap is 2 — one of {a, b} should have been evicted.
    assert_eq!(reg.cache_len().await, 2);
    // Re-load a: succeeds (registration retained), cache stays bounded at 2.
    let _ = reg.load("a").await.unwrap();
    assert_eq!(reg.cache_len().await, 2);
}

// ────────────────────────────────────────────────────────────────────
// SB-11 — LRU touches recency on `load` cache hit.
// ────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_11_lru_touches_recency_on_load() {
    let reg = LazyToolRegistry::new(small_cap_config()); // cap = 2
    let a = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    let b = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    let c = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    reg.register_binary("a", a).await;
    reg.register_binary("b", b).await;
    reg.register_binary("c", c).await;
    let _ = reg.load("a").await.unwrap();
    let _ = reg.load("b").await.unwrap();
    // Touch a — now MRU = a, b is LRU.
    let _ = reg.load("a").await.unwrap();
    // Load c — should evict b (the LRU).
    let _ = reg.load("c").await.unwrap();
    // a should still be cached.
    assert_eq!(reg.cache_len().await, 2);
    // Re-load a — cache hit (no new entry added).
    let _ = reg.load("a").await.unwrap();
    assert_eq!(reg.cache_len().await, 2);
}

// ────────────────────────────────────────────────────────────────────
// SB-18 — Validator: well-formed tool-exports binary passes.
// ────────────────────────────────────────────────────────────────────
#[test]
fn sb_18_validator_has_describe_and_execute() {
    let bytes = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    let outcome = cap_tools::validate_tool_component(&bytes).expect("valid");
    assert!(outcome.has_describe);
    assert!(outcome.has_execute);
    assert!(!outcome.has_runnable);
}

// ────────────────────────────────────────────────────────────────────
// SB-21 — Invoke against a validly-loaded tool returns the explicit
//         "in-WASM execute deferred" InvocationFailed, NOT a vacuous
//         Ok(empty). Locks the audit-round-4 W1 fail-explicit contract.
// ────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_21_invoke_after_successful_load_returns_explicit_deferred() {
    let reg = LazyToolRegistry::new(small_cap_config());
    let bytes = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    reg.register_binary("a", bytes).await;
    // First load succeeds (validator passes).
    let inst = reg.load("a").await.expect("load ok");
    assert_eq!(inst.tool_id, "a");
    // Invoke must NOT silently return Ok(empty) — it must surface the
    // typed "in-WASM execute deferred" InvocationFailed so callers can
    // distinguish "tool ran and returned nothing" from "Slice B's in-WASM
    // execute isn't wired yet".
    let err = reg
        .invoke("a", "some-method", b"params")
        .await
        .expect_err("must fail explicitly");
    match err {
        ToolError::InvocationFailed(msg) => {
            assert!(
                msg.contains("in-WASM execute deferred"),
                "expected deferred message, got: {msg}"
            );
        }
        other => panic!("expected InvocationFailed got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// SB-19 — Validator detects runnable export.
// ────────────────────────────────────────────────────────────────────
#[test]
fn sb_19_validator_runnable_export_detected() {
    let bytes = build_dummy_component(WIT_RUNNABLE, "runnable-world");
    let err = cap_tools::validate_tool_component(&bytes).expect_err("must fail");
    match err {
        ToolError::InvocationFailed(msg) => assert!(msg.contains("missing tool-exports")),
        other => panic!("expected InvocationFailed got {other:?}"),
    }
    // Confirm mutual-exclusion detection on the tool+runnable variant.
    let both = build_dummy_component(WIT_TOOL_PLUS_RUNNABLE, "both-world");
    let err = cap_tools::validate_tool_component(&both).expect_err("must fail");
    match err {
        ToolError::InvocationFailed(msg) => {
            assert!(msg.contains("runnable + tool-exports mutual exclusion"));
        }
        other => panic!("expected InvocationFailed got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// AC-29 — `validate_runnable_component` matcher (submit-component side,
// m017-slice-l). Mirror of SB-19; pins the four arms that MODULE-005
// cap-lifecycle's `admit_runnable_binary` + MODULE-017 §2.7 point 3 rely on.
// ────────────────────────────────────────────────────────────────────
#[test]
fn ac29_validate_runnable_component_matcher() {
    // Runnable component → Ok (has_runnable, no tool-exports).
    let runnable = build_dummy_component(WIT_RUNNABLE, "runnable-world");
    let outcome = cap_tools::validate_runnable_component(&runnable).expect("runnable accepted");
    assert!(outcome.has_runnable);
    assert!(!outcome.has_describe && !outcome.has_execute);

    // Tool-exports component (not runnable) → Err("missing runnable export").
    let tool = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    let err = cap_tools::validate_runnable_component(&tool).expect_err("tool rejected");
    match err {
        ToolError::InvocationFailed(msg) => assert!(
            msg.contains("missing runnable export"),
            "expected missing-runnable, got: {msg}"
        ),
        other => panic!("expected InvocationFailed got {other:?}"),
    }

    // Tool + runnable co-export → mutual-exclusion (reported FIRST).
    let both = build_dummy_component(WIT_TOOL_PLUS_RUNNABLE, "both-world");
    let err = cap_tools::validate_runnable_component(&both).expect_err("hybrid rejected");
    match err {
        ToolError::InvocationFailed(msg) => assert!(
            msg.contains("runnable + tool-exports mutual exclusion"),
            "expected mutual-exclusion, got: {msg}"
        ),
        other => panic!("expected InvocationFailed got {other:?}"),
    }

    // Non-component / unparseable bytes → Err("invalid wasm").
    let err = cap_tools::validate_runnable_component(&[0, 0, 0, 0]).expect_err("garbage rejected");
    match err {
        ToolError::InvocationFailed(msg) => assert!(
            msg.contains("invalid wasm"),
            "expected invalid-wasm, got: {msg}"
        ),
        other => panic!("expected InvocationFailed got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// AC-29 point 2 — ToolRegistry cold load rejects a NON-tool (runnable-only)
// component before caching, and accepts a tool-exports component. Witnesses
// the `bring_up_tool` validator gate that has enforced this since Slice B.
// ────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn ac29_cold_load_rejects_non_tool() {
    let reg = LazyToolRegistry::new(small_cap_config());
    // Runnable-only component is NOT a tool → cold load rejects it.
    let runnable = build_dummy_component(WIT_RUNNABLE, "runnable-world");
    reg.register_binary("runner", runnable).await;
    let err = reg
        .load("runner")
        .await
        .expect_err("runnable-only must not load as a tool");
    match err {
        ToolError::InvocationFailed(msg) => assert!(
            msg.contains("missing tool-exports"),
            "expected missing-tool-exports, got: {msg}"
        ),
        other => panic!("expected InvocationFailed got {other:?}"),
    }
    // A valid tool-exports component loads (no-engine path synthesizes an
    // empty description per Slice B).
    let tool = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    reg.register_binary("tool", tool).await;
    reg.load("tool")
        .await
        .expect("tool-exports component loads");
}
