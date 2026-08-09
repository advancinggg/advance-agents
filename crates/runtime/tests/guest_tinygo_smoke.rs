use advance_runtime::{config::WasmConfig, ComponentRuntime};

const COMPONENT_BYTES: &[u8] = include_bytes!("fixtures/guest-tinygo-smoke.component.wasm");
const TINYGO_VERSION: &str = include_str!("fixtures/guest-tinygo-smoke/tinygo-version.txt");

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

#[test]
fn module_001_t46_tinygo_smoke_byte_load_and_provenance() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    runtime
        .load_component(COMPONENT_BYTES)
        .expect("TinyGo guest component must be loadable — AC-03 'smoke test only' clause");

    assert!(
        TINYGO_VERSION.to_lowercase().contains("tinygo"),
        "tinygo-version.txt must name 'tinygo' as the producing toolchain; got: {TINYGO_VERSION}"
    );
}
