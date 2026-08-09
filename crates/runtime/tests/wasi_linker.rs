//! WASI preview2 linker wiring — Slice V integration test.
//!
//! Verifies:
//!   1. A Component importing `wasi:random/random@0.2.6` instantiates successfully when
//!      `add_wasi_to_linker` populates the linker.
//!   2. The same Component FAILS to instantiate when WASI imports are NOT linked
//!      (proves the WASI binding is what makes the import resolve, not the
//!      runtime's host-function injection or some default-engine behavior).
//!
//! **Scope**: link-time import resolution + Component instantiation only. The actual
//! WASI host-function bodies (and `WasiView::ctx` getter inside them) are NOT exercised
//! here — that requires a driving WAT export that calls the imported WASI fn from
//! Wasm core code, deferred to a future slice (same posture as T25/T26 in §3.6).

use advance_runtime::capability_injector::{add_wasi_to_linker, ComponentCtx};
use advance_runtime::component_loader::ComponentRuntime;
use advance_runtime::config::WasmConfig;

fn wasm_cfg() -> WasmConfig {
    // Mirror the helper in tests/capability_injector.rs:26-32 — `WasmConfig` derives
    // Deserialize/Clone/Debug/PartialEq but NOT Default, so a struct-literal is the
    // canonical construction path. Workspace `wasmtime` features include "async"
    // (Slice L), so the engine has host-embedding async unconditionally — no
    // deprecated `wasmtime::Config::async_support` call needed.
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

/// Minimal WAT importing `wasi:random/random@0.2.6` — verified version against
/// wasmtime-wasi 43.0.0/.1 WIT deps (random.wit:1 declares `package wasi:random@0.2.6`).
const WASI_IMPORT_WAT: &str = r#"
(component
  (import "wasi:random/random@0.2.6" (instance $r
    (export "get-random-bytes" (func (param "len" u64) (result (list u8))))
  ))
)
"#;

#[test]
fn component_with_wasi_import_links_when_wasi_added() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let mut linker: wasmtime::component::Linker<ComponentCtx> =
        wasmtime::component::Linker::new(runtime.host_engine_handle().engine());
    add_wasi_to_linker(&mut linker).expect("add wasi");

    let bytes = wat::parse_str(WASI_IMPORT_WAT).expect("parse WAT");
    let component = runtime.load_component(&bytes).expect("load component");

    let ctx = ComponentCtx::new("agent_test".into(), "trace_test".into(), Vec::new());
    let mut store = wasmtime::Store::new(runtime.host_engine_handle().engine(), ctx);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt");
    let result = rt.block_on(async {
        linker
            .instantiate_async(&mut store, component.component())
            .await
    });
    assert!(
        result.is_ok(),
        "instantiate Component with WASI link: {result:?}"
    );
}

#[test]
fn component_with_wasi_import_fails_without_wasi() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let linker: wasmtime::component::Linker<ComponentCtx> =
        wasmtime::component::Linker::new(runtime.host_engine_handle().engine());
    // no add_wasi_to_linker — the import must remain unresolved.

    let bytes = wat::parse_str(WASI_IMPORT_WAT).expect("parse WAT");
    let component = runtime.load_component(&bytes).expect("load component");

    let ctx = ComponentCtx::new("agent_test".into(), "trace_test".into(), Vec::new());
    let mut store = wasmtime::Store::new(runtime.host_engine_handle().engine(), ctx);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt");
    let result = rt.block_on(async {
        linker
            .instantiate_async(&mut store, component.component())
            .await
    });
    let err = result.expect_err("instantiate must fail when wasi:random/random is not linked");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("wasi:random/random") || msg.contains("not found") || msg.contains("import"),
        "expected unresolved-import error mentioning wasi:random/random; got: {msg}"
    );
}
