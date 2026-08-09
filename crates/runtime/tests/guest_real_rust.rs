use advance_runtime::{
    config::WasmConfig, wit_bindings::advance::runtime::types as wit_types, ComponentCtx,
    ComponentRuntime,
};
use wit_component::ComponentEncoder;

const CORE_MODULE_BYTES: &[u8] = include_bytes!("fixtures/guest-rust-minimal.core.wasm");

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

fn rust_guest_component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_MODULE_BYTES)
        .expect(
            "core module accepted by ComponentEncoder (wit-bindgen embeds component-type metadata)",
        )
        .encode()
        .expect("component encoded")
}

#[tokio::test]
async fn module_001_t43_rust_guest_init_happy_path() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    let component_bytes = rust_guest_component_bytes();
    let loaded = runtime
        .load_component(&component_bytes)
        .expect("guest component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_async(&loaded, ctx())
        .await
        .expect("instantiate");

    let cfg = wit_types::ComponentConfig {
        id: "test".into(),
        config_data: None,
        trigger_context: None,
    };
    let result = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("call_init succeeded");

    match result {
        Ok(bytes) => assert_eq!(
            bytes,
            vec![0xAD, 0x11, 0xCE, 0x01],
            "init sentinel mismatch"
        ),
        Err(e) => panic!("guest returned Err: {e}"),
    }
}

#[tokio::test]
async fn module_001_t44_rust_guest_handle_message_happy_path() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    let component_bytes = rust_guest_component_bytes();
    let loaded = runtime
        .load_component(&component_bytes)
        .expect("guest component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_async(&loaded, ctx())
        .await
        .expect("instantiate");

    let cfg = wit_types::ComponentConfig {
        id: "test".into(),
        config_data: None,
        trigger_context: None,
    };
    // Outer expect = the wasmtime call must succeed; the guest-level inner
    // Result is deliberately not asserted here (behavior-preserving lint fix).
    let _ = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("call_init succeeded");

    let msg = wit_types::Message {
        payload: b"hello".to_vec(),
    };
    let result = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &[])
        .await
        .expect("call_handle_message succeeded");

    match result {
        Ok(action_result) => {
            assert_eq!(
                action_result.new_state, b"hello",
                "echo-append new_state mismatch"
            );
            assert!(action_result.actions.is_empty(), "expected zero actions");
        }
        Err(e) => panic!("guest returned Err: {e}"),
    }
}

#[tokio::test]
async fn module_001_t45_rust_guest_run_happy_path() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("construct runtime");
    let component_bytes = rust_guest_component_bytes();
    let loaded = runtime
        .load_component(&component_bytes)
        .expect("guest component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_async(&loaded, ctx())
        .await
        .expect("instantiate");

    let cfg = wit_types::ComponentConfig {
        id: "test".into(),
        config_data: None,
        trigger_context: None,
    };
    let result = bindings
        .advance_runtime_runnable()
        .call_run(&mut store, &cfg)
        .await
        .expect("call_run succeeded");

    match result {
        Ok(run_result) => {
            assert!(
                matches!(run_result.status, wit_types::RunStatus::Completed),
                "expected Completed status"
            );
            assert_eq!(
                run_result.output,
                Some(vec![0xAD, 0x11, 0xCE, 0x02]),
                "run sentinel mismatch"
            );
        }
        Err(e) => panic!("guest returned Err: {e}"),
    }
}
