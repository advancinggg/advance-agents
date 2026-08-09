//! Slice X — MODULE-001-AC-04 closure: WIT bindings validate + dispatch.
//!
//! Six tests covering both halves of AC-04's literal criterion:
//! - **Validate**: T36 — bindgen-generated types compile; the `_typecheck_call_methods`
//!   helper references every world-export's call-method to assert the bindgen surface
//!   exists at compile time.
//! - **Dispatch**: T37..T40 — full call chain from `ComponentRuntime::load_component` →
//!   `instantiate_advance_host_async` → `bindings.advance_runtime_*().call_*()`.
//!   Test fixtures use `wit_component::dummy_module` to generate stub guests that
//!   satisfy the WIT world; the dummies trap on call (`unreachable` body), so the
//!   test asserts the trap path — verifying the dispatch chain wires through bindgen
//!   correctly. Real Rust guest with non-trapping bodies is owned by the future
//!   AC-03 slice (cargo-component toolchain).
//! - **Validate (negative)**: T41 — empty component is rejected at
//!   `AdvanceHostPre::new` with `BindgenExportLookup` (the world's required exports
//!   are missing).

use advance_runtime::{
    config::WasmConfig,
    wit_bindings::{advance::runtime::types as wit_types, AdvanceHost, AdvanceHostPre},
    ComponentCtx, ComponentRuntime, InstantiateError,
};
use wit_component::{embed_component_metadata, ComponentEncoder, StringEncoding};
use wit_parser::{ManglingAndAbi, Resolve};

const WIT_PACKAGE: &str = include_str!("../wit/advance.wit");
const WIT_PACKAGE_PATH: &str = "advance.wit";

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn ctx() -> ComponentCtx {
    ComponentCtx::new("agent-test".into(), "trace-test".into(), Vec::new())
}

/// Build a Component implementing the `advance-host` world by wrapping a
/// `wit_component::dummy_module` (whose function bodies are `unreachable`)
/// via `wit_component::ComponentEncoder`. The resulting Component instantiates
/// cleanly; calling any exported method traps. Useful for verifying the
/// dispatch CHAIN works — the trap path proves Wasmtime delivered the call
/// through the bindgen-typed accessor down to the guest core module.
fn dummy_advance_host_component() -> Vec<u8> {
    let mut resolve = Resolve::default();
    let pkg = resolve
        .push_str(WIT_PACKAGE_PATH, WIT_PACKAGE)
        .expect("WIT parses");
    let world = resolve
        .select_world(&[pkg], Some("advance-host"))
        .expect("advance-host world exists");
    let mut core_bytes = wit_component::dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    // Embed the WIT metadata custom section so ComponentEncoder knows which
    // world to wrap. This is the canonical pattern from wit-component's own
    // tests + semver-check helper.
    embed_component_metadata(&mut core_bytes, &resolve, world, StringEncoding::UTF8)
        .expect("embed component metadata");
    ComponentEncoder::default()
        .validate(true)
        .module(&core_bytes)
        .expect("core module accepted")
        .encode()
        .expect("component encoded")
}

// =====================================================================
// T36 — WIT bindings compile + typed-shape validate
// =====================================================================
//
// Load-bearing compile-time typed-shape check. If the bindgen output drifts
// (signature change, missing method, gated `cfg`), `_typecheck_call_methods`
// (a never-executed helper) fails to compile and this test file refuses to
// build — providing a real type-shape regression gate.

// The presence of these three call paths inside `_typecheck_call_methods`
// asserts at compile time that every required guest-export method exists on
// the bindgen-generated `AdvanceHost` handle.
#[allow(dead_code)]
async fn _typecheck_call_methods(
    bindings: AdvanceHost,
    mut store: wasmtime::Store<ComponentCtx>,
    cfg: &wit_types::ComponentConfig,
    msg: &wit_types::Message,
    state: &[u8],
) {
    let _ = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, cfg)
        .await;
    let _ = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, msg, state)
        .await;
    let _ = bindings
        .advance_runtime_runnable()
        .call_run(&mut store, cfg)
        .await;
}

#[test]
fn module_001_t36_wit_bindings_compile_and_typed_shape_validates() {
    // Function-pointer typealias against the bindgen-generated
    // `AdvanceHostPre::<T>::new(InstancePre<T>) -> wasmtime::Result<AdvanceHostPre<T>>`.
    let _new_pre: fn(
        wasmtime::component::InstancePre<ComponentCtx>,
    ) -> wasmtime::Result<AdvanceHostPre<ComponentCtx>> = AdvanceHostPre::new;

    // World-handle accessor typealiases — assert the snake-cased
    // `advance_runtime_message_driven` / `advance_runtime_runnable` surface
    // exists with the expected return types (`&Guest` per interface).
    let _md_acc: for<'a> fn(
        &'a AdvanceHost,
    ) -> &'a advance_runtime::wit_bindings::message_driven::Guest =
        AdvanceHost::advance_runtime_message_driven;
    let _r_acc: for<'a> fn(&'a AdvanceHost) -> &'a advance_runtime::wit_bindings::runnable::Guest =
        AdvanceHost::advance_runtime_runnable;
}

// Helper: assert a wasmtime call result is a trap (Err) — avoids requiring
// `Debug` on the success type.
fn assert_trap<T, E: std::fmt::Debug>(result: Result<T, E>, ctx: &str) {
    match result {
        Ok(_) => panic!("{ctx}: expected trap, got Ok"),
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("unreachable") || msg.contains("Trap") || msg.contains("trap"),
                "{ctx}: expected unreachable/trap, got: {msg}"
            );
        }
    }
}

// =====================================================================
// T37..T40 — Dispatch chain (trap path via dummy_module)
// =====================================================================

#[tokio::test]
async fn module_001_t37_runnable_dispatch_chain_invokes_guest() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    let bytes = dummy_advance_host_component();
    let loaded = runtime.load_component(&bytes).expect("component loads");
    let (bindings, mut store) = match runtime.instantiate_advance_host_async(&loaded, ctx()).await {
        Ok(pair) => pair,
        Err(e) => panic!("instantiate failed: {e:?}"),
    };

    let cfg = wit_types::ComponentConfig {
        id: "test".into(),
        config_data: None,
        trigger_context: None,
    };
    let result = bindings
        .advance_runtime_runnable()
        .call_run(&mut store, &cfg)
        .await;
    assert_trap(result, "T37 runnable.run");
}

#[tokio::test]
async fn module_001_t38_message_driven_init_dispatch_chain_invokes_guest() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    let bytes = dummy_advance_host_component();
    let loaded = runtime.load_component(&bytes).expect("component loads");
    let (bindings, mut store) = match runtime.instantiate_advance_host_async(&loaded, ctx()).await {
        Ok(pair) => pair,
        Err(e) => panic!("instantiate failed: {e:?}"),
    };

    let cfg = wit_types::ComponentConfig {
        id: "test".into(),
        config_data: None,
        trigger_context: None,
    };
    let result = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await;
    assert_trap(result, "T38 message-driven.init");
}

#[tokio::test]
async fn module_001_t39_message_driven_handle_message_dispatch_chain_invokes_guest() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    let bytes = dummy_advance_host_component();
    let loaded = runtime.load_component(&bytes).expect("component loads");
    let (bindings, mut store) = match runtime.instantiate_advance_host_async(&loaded, ctx()).await {
        Ok(pair) => pair,
        Err(e) => panic!("instantiate failed: {e:?}"),
    };

    let msg = wit_types::Message {
        payload: Vec::new(),
    };
    let state: Vec<u8> = Vec::new();
    let result = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &state)
        .await;
    assert_trap(result, "T39 message-driven.handle-message");
}

#[tokio::test]
async fn module_001_t40_dispatch_chain_independent_per_instantiate() {
    // T40 verifies that two consecutive `instantiate_advance_host_async` calls
    // each produce independent (AdvanceHost, Store) pairs — the runtime does
    // not cache or share bindings handles across stores. Both calls trap
    // identically on the same fixture.
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    let bytes = dummy_advance_host_component();
    let loaded = runtime.load_component(&bytes).expect("component loads");

    let cfg = wit_types::ComponentConfig {
        id: "first".into(),
        config_data: None,
        trigger_context: None,
    };

    // First instantiate.
    let (b1, mut s1) = match runtime.instantiate_advance_host_async(&loaded, ctx()).await {
        Ok(pair) => pair,
        Err(e) => panic!("first instantiate failed: {e:?}"),
    };
    let r1 = b1.advance_runtime_runnable().call_run(&mut s1, &cfg).await;
    assert_trap(r1, "T40 first call");

    // Second instantiate — independent store + bindings.
    let (b2, mut s2) = match runtime.instantiate_advance_host_async(&loaded, ctx()).await {
        Ok(pair) => pair,
        Err(e) => panic!("second instantiate failed: {e:?}"),
    };
    let r2 = b2.advance_runtime_runnable().call_run(&mut s2, &cfg).await;
    assert_trap(r2, "T40 second call");
}

// =====================================================================
// T42 — Architectural guard: advance-host world has zero imports
// =====================================================================
//
// **Adversarial fix R1 (round-1 Critical #7)**: `instantiate_advance_host_async`
// constructs a bare `Linker<ComponentCtx>` and bypasses `CapabilityInjector`'s
// L0/L1/CircuitBreaker stack. This is safe TODAY only because the
// `advance-host` world has no host-fn imports — there is nothing to gate.
// If a future commit adds even one `import` clause to `crates/runtime/wit/advance.wit`,
// the dispatch path silently bypasses CapabilityInjector for the new import.
// This architectural test makes that regression LOUD: it parses the WIT,
// counts the world's imports, and asserts the count is zero. Any future
// addition to the world's import set forces the author to either (a) wire
// CapabilityInjector into `instantiate_advance_host_async`, or (b) ship a
// new `_with_capabilities_async` parallel API that does the wiring.

#[test]
fn module_001_t42_advance_host_world_has_zero_function_imports_arch_guard() {
    use wit_parser::WorldItem;

    let mut resolve = Resolve::default();
    let pkg = resolve
        .push_str(WIT_PACKAGE_PATH, WIT_PACKAGE)
        .expect("WIT parses");
    let world_id = resolve
        .select_world(&[pkg], Some("advance-host"))
        .expect("advance-host world exists");
    let world = &resolve.worlds[world_id];

    // Pure-type interface imports (e.g. `use types.{...}` shared records)
    // are SAFE — they require no host-fn registration. Only Function imports
    // and Interface imports that contain functions trigger the bypass.
    let mut function_imports: Vec<String> = Vec::new();
    for (key, item) in world.imports.iter() {
        match item {
            WorldItem::Function(_) => {
                function_imports.push(format!("{key:?} (top-level function)"));
            }
            WorldItem::Interface { id, .. } => {
                let iface = &resolve.interfaces[*id];
                if !iface.functions.is_empty() {
                    function_imports.push(format!(
                        "{key:?} (interface with {} functions)",
                        iface.functions.len()
                    ));
                }
            }
            WorldItem::Type { .. } => {
                // Type imports are harmless from a host-fn standpoint.
            }
        }
    }

    assert!(
        function_imports.is_empty(),
        "ARCH GUARD: advance-host world MUST have zero function-bearing imports because \
         ComponentRuntime::instantiate_advance_host_async bypasses CapabilityInjector \
         (L0/L1/CircuitBreaker). Adding host-fn imports here silently bypasses the \
         capability stack. Either: (a) wire CapabilityInjector into \
         instantiate_advance_host_async, OR (b) ship a parallel \
         `instantiate_advance_host_with_capabilities_async`. Found function imports: {:?}",
        function_imports
    );
}

// =====================================================================
// MODULE-009-T01 — Slice C architectural guard: agent-llm interface declared
// =====================================================================
//
// Slice C (2026-05-09) added `interface agent-llm` to advance.wit at the
// package level (NOT imported by `world advance-host`; T42 invariant must
// still hold). This test parses the WIT package, locates the `agent-llm`
// interface, and asserts the 3 functions (`generate`, `stream`, `poll-stream`)
// exist with the documented WIT signatures per MODULE-009 §1.4.1.
//
// Anchors MODULE-009-AC-01 (`agent-llm WIT exposes generate / stream /
// poll-stream`).

#[test]
fn module_009_t01_agent_llm_interface_declared_in_wit_package() {
    let mut resolve = Resolve::default();
    let pkg = resolve
        .push_str(WIT_PACKAGE_PATH, WIT_PACKAGE)
        .expect("WIT parses");

    // Find the agent-llm interface in the package's interface set.
    let pkg_data = &resolve.packages[pkg];
    let agent_llm_id = pkg_data
        .interfaces
        .get("agent-llm")
        .copied()
        .expect("agent-llm interface declared in advance.wit at package level");

    let iface = &resolve.interfaces[agent_llm_id];

    // Assert the 3 functions exist with the canonical names per §1.4.1.
    let fn_names: std::collections::BTreeSet<&str> =
        iface.functions.keys().map(|s| s.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> =
        ["generate", "poll-stream", "stream"].into_iter().collect();
    assert_eq!(
        fn_names, expected,
        "agent-llm must declare exactly {{generate, stream, poll-stream}}; got: {fn_names:?}"
    );

    // Assert each function returns `result<_, _>` (a TypeDefKind::Result) per
    // §1.4.1: generate → `result<llm-response, llm-error>`,
    // stream → `result<stream-handle, llm-error>`,
    // poll-stream → `result<stream-chunk, llm-error>`.
    // A regression that silently changes the return type (e.g. to `string`)
    // would not be caught by name-only assertion alone — this loop closes
    // that gap (audit-fix round 2 W1).
    use wit_parser::{Type, TypeDefKind};
    for name in ["generate", "stream", "poll-stream"] {
        let func = iface
            .functions
            .get(name)
            .expect("function present (asserted above)");
        let ret_ty = func
            .result
            .as_ref()
            .unwrap_or_else(|| panic!("agent-llm/{name} must return a result type, got no result"));
        let ret_id = match ret_ty {
            Type::Id(id) => *id,
            other => panic!("agent-llm/{name} return type must be a TypeId, got {other:?}"),
        };
        let kind = &resolve.types[ret_id].kind;
        assert!(
            matches!(kind, TypeDefKind::Result(_)),
            "agent-llm/{name} must return `result<_, _>`, got {kind:?}"
        );
    }
}

// =====================================================================
// T41 — Bindgen rejects component with no advance-host exports
// =====================================================================

#[tokio::test]
async fn module_001_t41_bindgen_rejects_component_with_no_exports() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    // Empty component — exports nothing; missing the required
    // `advance:runtime/message-driven` and `advance:runtime/runnable` exports
    // that the `advance-host` world demands.
    let bytes = wat::parse_str("(component)").expect("empty component WAT parses");
    let loaded = runtime.load_component(&bytes).expect("component loads");
    let result = runtime.instantiate_advance_host_async(&loaded, ctx()).await;
    let err = match result {
        Ok(_) => panic!("empty component must not satisfy advance-host world"),
        Err(e) => e,
    };
    assert!(
        matches!(err, InstantiateError::BindgenExportLookup(_)),
        "expected BindgenExportLookup, got: {err:?}"
    );
    let msg = format!("{err:?}");
    // The wasmtime error message names a missing world export.
    assert!(
        msg.contains("message-driven") || msg.contains("runnable") || msg.contains("export"),
        "expected error to mention missing export; got: {msg}"
    );
}
