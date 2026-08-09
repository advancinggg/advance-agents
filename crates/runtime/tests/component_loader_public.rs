//! Integration tests for the public component loader API (Slice T).

use advance_runtime::component_loader::{
    ComponentLoadError, ComponentRuntime, HostEngineHandle, LoadedComponent, ToolEngineHandle,
};
use advance_runtime::config::WasmConfig;

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

/// A minimal valid Component that exports nothing and imports nothing.
/// Serves as the smallest fixture `Component::from_binary` will accept.
fn minimal_component_wat() -> &'static str {
    "(component)"
}

#[test]
fn t22_valid_component_loads() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let bytes = wat::parse_str(minimal_component_wat()).expect("wat compile");
    let result = runtime.load_component(&bytes);
    assert!(result.is_ok(), "valid component must load: {result:?}");
}

#[test]
fn t22_valid_component_loads_on_tool_engine() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let bytes = wat::parse_str(minimal_component_wat()).expect("wat compile");
    let result = runtime.load_tool_component(&bytes);
    assert!(
        result.is_ok(),
        "valid component must load on tool engine: {result:?}"
    );
}

#[test]
fn load_component_rejects_empty_bytes() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let result = runtime.load_component(&[]);
    assert!(matches!(result, Err(ComponentLoadError::EmptyBinary)));
}

#[test]
fn load_tool_component_rejects_empty_bytes() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let result = runtime.load_tool_component(&[]);
    assert!(matches!(result, Err(ComponentLoadError::EmptyBinary)));
}

#[test]
fn load_component_rejects_malformed_bytes() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let malformed = [0xFFu8; 16];
    let result = runtime.load_component(&malformed);
    assert!(matches!(result, Err(ComponentLoadError::ComponentParse(_))));
}

#[test]
fn t28_host_engine_handle_clone_cheap() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let h1 = runtime.host_engine_handle();
    let h2 = h1.clone();
    // Handle is Clone and Engine is Arc-backed; both should resolve to engines.
    let _e1: &wasmtime::Engine = h1.engine();
    let _e2: &wasmtime::Engine = h2.engine();
    // Compile-time check that the types line up.
    let _: HostEngineHandle = h2;
}

#[test]
fn t28_tool_engine_handle_clone_cheap() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let h1 = runtime.tool_engine_handle();
    let h2 = h1.clone();
    let _e1: &wasmtime::Engine = h1.engine();
    let _e2: &wasmtime::Engine = h2.engine();
    let _: ToolEngineHandle = h2;
}

#[test]
fn loaded_component_clone_cheap() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let bytes = wat::parse_str(minimal_component_wat()).expect("wat compile");
    let c: LoadedComponent = runtime.load_component(&bytes).expect("load");
    let _c2: LoadedComponent = c.clone();
}
