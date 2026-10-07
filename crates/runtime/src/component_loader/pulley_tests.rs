//! MODULE-001-AC-32 Pulley engine unit tests.

use super::*;
use crate::capability_injector::ComponentCtx;
use crate::wit_bindings::advance::runtime::types as wit_types;
use wit_component::ComponentEncoder;

const CORE_MODULE_BYTES: &[u8] =
    include_bytes!("../../tests/fixtures/guest-rust-minimal.core.wasm");

fn wasm_cfg_with_pages(max_pages: u32) -> WasmConfig {
    WasmConfig {
        max_memory_pages: max_pages,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn ctx() -> ComponentCtx {
    ComponentCtx::new("agent-pulley".into(), "trace-pulley".into(), Vec::new())
}

fn rust_guest_component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_MODULE_BYTES)
        .expect("core module accepted by ComponentEncoder")
        .encode()
        .expect("component encoded")
}

fn decode_le_i32(bytes: &[u8]) -> i32 {
    assert_eq!(bytes.len(), 4, "output must be 4 bytes (le-encoded i32)");
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    i32::from_le_bytes(arr)
}

async fn call_run_with_config_data(
    runtime: &ComponentRuntime,
    config_data: Option<Vec<u8>>,
) -> wit_types::RunResult {
    let loaded = runtime
        .load_component(&rust_guest_component_bytes())
        .expect("guest component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_async(&loaded, ctx())
        .await
        .expect("instantiate");
    let cfg = wit_types::ComponentConfig {
        id: "t-pulley".into(),
        config_data,
        trigger_context: None,
    };
    bindings
        .advance_runtime_runnable()
        .call_run(&mut store, &cfg)
        .await
        .expect("call_run returns")
        .expect("guest run ok")
}

fn todays_recipe(fuel: bool) -> wasmtime::Config {
    let mut c = wasmtime::Config::new();
    c.wasm_component_model(true);
    c.epoch_interruption(true);
    c.wasm_memory64(false);
    c.wasm_multi_memory(false);
    c.max_wasm_stack(256 * 1024);
    c.consume_fuel(fuel);
    c
}

fn sorted_debug_lines(s: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = s.lines().collect();
    lines.sort_unstable();
    lines
}

fn engine_debug(engine: &wasmtime::Engine) -> String {
    format!("{:#?}", engine.config())
}

#[test]
fn module_001_ac32_pulley_engines_target_pulley64() {
    let rt = ComponentRuntime::with_backend(&wasm_cfg_with_pages(256), WasmBackend::Pulley)
        .expect("pulley runtime");
    assert_eq!(rt.backend(), WasmBackend::Pulley);
    let report = rt.engine_report();
    assert!(report.host.is_pulley);
    assert!(report.tool.is_pulley);
    assert_eq!(report.host.target, Some(PULLEY_TARGET));
    assert_eq!(report.tool.target, Some(PULLEY_TARGET));
    assert!(rt.host_engine_handle().engine().is_pulley());
    assert!(rt.tool_engine_handle().engine().is_pulley());
}

#[test]
fn module_001_ac32_native_backend_builds_todays_engines() {
    for fuel in [false, true] {
        let cfg = WasmConfig {
            max_memory_pages: 256,
            epoch_interruption_ms: 100,
            fuel_enabled: fuel,
        };
        let via_new = ComponentRuntime::new(&cfg).expect("new");
        let via_native = ComponentRuntime::with_backend(&cfg, WasmBackend::Native).expect("native");
        for rt in [&via_new, &via_native] {
            assert_eq!(rt.backend(), WasmBackend::Native);
            let report = rt.engine_report();
            assert!(!report.host.is_pulley);
            assert!(!report.tool.is_pulley);
            assert_eq!(report.host.target, None);
            assert_eq!(report.tool.target, None);
            assert_eq!(report.host.memory_reservation, None);
            assert_eq!(report.tool.memory_reservation, None);
            assert_eq!(report.host.memory_reservation_for_growth, None);
            assert_eq!(report.tool.memory_reservation_for_growth, None);
        }
        let host_recipe = wasmtime::Engine::new(&todays_recipe(false)).expect("host recipe engine");
        let tool_recipe = wasmtime::Engine::new(&todays_recipe(fuel)).expect("tool recipe engine");
        assert_eq!(
            sorted_debug_lines(&engine_debug(via_new.host_engine_handle().engine())),
            sorted_debug_lines(&engine_debug(&host_recipe))
        );
        assert_eq!(
            sorted_debug_lines(&engine_debug(via_new.tool_engine_handle().engine())),
            sorted_debug_lines(&engine_debug(&tool_recipe))
        );
        assert_eq!(
            sorted_debug_lines(&engine_debug(via_new.host_engine_handle().engine())),
            sorted_debug_lines(&engine_debug(via_native.host_engine_handle().engine()))
        );
        assert_eq!(
            sorted_debug_lines(&engine_debug(via_new.tool_engine_handle().engine())),
            sorted_debug_lines(&engine_debug(via_native.tool_engine_handle().engine()))
        );
    }
}

#[test]
fn module_001_ac32_pulley_memory_reservation_is_the_configured_maximum() {
    let rt = ComponentRuntime::with_backend(&wasm_cfg_with_pages(256), WasmBackend::Pulley)
        .expect("pulley runtime");
    let report = rt.engine_report();
    assert_eq!(report.host.memory_reservation, Some(16_777_216));
    assert_eq!(report.tool.memory_reservation, Some(16_777_216));
    assert_eq!(report.host.memory_reservation_for_growth, Some(1_048_576));
    assert_eq!(report.tool.memory_reservation_for_growth, Some(1_048_576));
    for engine in [
        rt.host_engine_handle().engine(),
        rt.tool_engine_handle().engine(),
    ] {
        let dbg = format!("{:?}", engine.config());
        assert!(
            dbg.contains("memory_reservation: 16777216"),
            "missing reservation in {dbg}"
        );
        assert!(
            dbg.contains("memory_reservation_for_growth: 1048576"),
            "missing growth in {dbg}"
        );
        assert!(
            dbg.contains("memory_guard_size: 0"),
            "missing guard size in {dbg}"
        );
        assert!(
            dbg.contains("signals_based_traps: false"),
            "missing signals_based_traps in {dbg}"
        );
    }
}

#[test]
fn module_001_ac32_pulley_memory_reservation_is_capped_at_4_gib() {
    assert_eq!(pulley_memory_reservation(1), 65_536);
    assert_eq!(pulley_memory_reservation(65_536), 4_294_967_296);
    assert_eq!(pulley_memory_reservation(65_537), 4_294_967_296);
    assert_eq!(pulley_memory_reservation(1_048_576), 4_294_967_296);
    let rt = ComponentRuntime::with_backend(&wasm_cfg_with_pages(1_048_576), WasmBackend::Pulley)
        .expect("capped pulley runtime");
    let report = rt.engine_report();
    assert_eq!(report.host.memory_reservation, Some(4_294_967_296));
    assert_eq!(report.tool.memory_reservation, Some(4_294_967_296));
}

#[tokio::test]
async fn module_001_ac32_pulley_guest_runs_init_and_handle_message() {
    let runtime = ComponentRuntime::with_backend(&wasm_cfg_with_pages(256), WasmBackend::Pulley)
        .expect("pulley runtime");
    let loaded = runtime
        .load_component(&rust_guest_component_bytes())
        .expect("load");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_async(&loaded, ctx())
        .await
        .expect("instantiate");
    let cfg = wit_types::ComponentConfig {
        id: "t-pulley".into(),
        config_data: None,
        trigger_context: None,
    };
    let init = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("call_init")
        .expect("init ok");
    assert_eq!(init, vec![0xAD, 0x11, 0xCE, 0x01]);
    let msg = wit_types::Message {
        payload: b"pulley".to_vec(),
    };
    let action = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &init)
        .await
        .expect("call_handle_message")
        .expect("handle ok");
    let mut expected = vec![0xAD, 0x11, 0xCE, 0x01];
    expected.extend_from_slice(b"pulley");
    assert_eq!(action.new_state, expected);
}

#[tokio::test]
async fn module_001_ac32_pulley_memory_grows_to_the_configured_maximum() {
    let runtime = ComponentRuntime::with_backend(&wasm_cfg_with_pages(256), WasmBackend::Pulley)
        .expect("pulley runtime");
    let first = call_run_with_config_data(&runtime, Some(b"grow:0".to_vec())).await;
    let p = decode_le_i32(first.output.as_ref().expect("output"));
    assert!(p >= 1, "initial pages {p}");
    let grown =
        call_run_with_config_data(&runtime, Some(format!("grow:{}", 256 - p).into_bytes())).await;
    assert_eq!(decode_le_i32(grown.output.as_ref().expect("output")), p);
    let refused =
        call_run_with_config_data(&runtime, Some(format!("grow:{}", 257 - p).into_bytes())).await;
    assert_eq!(decode_le_i32(refused.output.as_ref().expect("output")), -1);
}

#[test]
fn module_001_ac32_pulley_epoch_yield_preempts_a_spinning_guest() {
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let _guest_thread = std::thread::Builder::new()
        .name("pulley-epoch-yield".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("guest tokio");
            rt.block_on(async move {
                let runtime =
                    ComponentRuntime::with_backend(&wasm_cfg_with_pages(256), WasmBackend::Pulley)
                        .expect("pulley runtime");
                let loaded = runtime
                    .load_component(&rust_guest_component_bytes())
                    .expect("load");
                let (bindings, mut store) = runtime
                    .instantiate_advance_host_async(&loaded, ctx())
                    .await
                    .expect("instantiate");
                let cfg = wit_types::ComponentConfig {
                    id: "t-pulley-loop".into(),
                    config_data: Some(b"loop".to_vec()),
                    trigger_context: None,
                };
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    bindings
                        .advance_runtime_runnable()
                        .call_run(&mut store, &cfg),
                )
                .await;
                let _ = tx.send(result.is_err());
            });
        })
        .expect("spawn");
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(true) => {}
        Ok(false) => panic!("tight-loop guest returned before the 3s timeout"),
        Err(_) => panic!("Pulley epoch yield not observed within 10 s"),
    }
}

#[test]
fn module_001_ac32_pulley_tool_engine_compiles_components() {
    let runtime = ComponentRuntime::with_backend(&wasm_cfg_with_pages(256), WasmBackend::Pulley)
        .expect("pulley runtime");
    runtime
        .load_tool_component(&rust_guest_component_bytes())
        .expect("tool engine compiles the minimal component");
}

#[cfg(target_os = "linux")]
fn overlapping_maps(text: &str, start: u64, end: u64) -> Vec<(u64, u64, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((range, rest)) = line.split_once(' ') else {
            continue;
        };
        let Some((a, b)) = range.split_once('-') else {
            continue;
        };
        let Ok(s) = u64::from_str_radix(a, 16) else {
            continue;
        };
        let Ok(e) = u64::from_str_radix(b, 16) else {
            continue;
        };
        if s < end && e > start {
            let perms = rest.split_whitespace().next().unwrap_or("").to_string();
            out.push((s, e, perms));
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn maps_for_image(loaded: &LoadedComponent) -> Vec<(u64, u64, String)> {
    let range = loaded.component().image_range();
    let start = range.start as usize as u64;
    let end = range.end as usize as u64;
    let text = std::fs::read_to_string("/proc/self/maps").expect("/proc/self/maps");
    overlapping_maps(&text, start, end)
}

#[cfg(target_os = "linux")]
#[test]
fn module_001_ac32_pulley_code_image_is_never_executable() {
    let runtime = ComponentRuntime::with_backend(&wasm_cfg_with_pages(256), WasmBackend::Pulley)
        .expect("pulley runtime");
    let bytes = rust_guest_component_bytes();
    let host = runtime.load_component(&bytes).expect("host load");
    let tool = runtime.load_tool_component(&bytes).expect("tool load");
    for loaded in [&host, &tool] {
        let maps = maps_for_image(loaded);
        assert!(!maps.is_empty(), "expected overlapping mappings");
        for (s, e, perms) in &maps {
            assert!(
                !perms.contains('x'),
                "pulley image {s:x}-{e:x} has exec perms {perms}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn module_001_ac32_native_code_image_is_executable_control() {
    let runtime = ComponentRuntime::new(&wasm_cfg_with_pages(256)).expect("native runtime");
    let loaded = runtime
        .load_component(&rust_guest_component_bytes())
        .expect("load");
    let maps = maps_for_image(&loaded);
    assert!(!maps.is_empty(), "expected overlapping mappings");
    assert!(
        maps.iter().any(|(_, _, perms)| perms.contains('x')),
        "native image should have an executable mapping, got {maps:?}"
    );
}
