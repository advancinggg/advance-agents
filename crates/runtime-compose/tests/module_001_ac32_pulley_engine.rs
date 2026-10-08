//! MODULE-001-AC-32 — `WasmEngine::Pulley` composes both engines on pulley64.

use std::sync::{Arc, Weak};

use advance_runtime::component_loader::{
    pulley_memory_reservation, PULLEY_MEMORY_RESERVATION_FOR_GROWTH, WASM_PAGE_BYTES,
};
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, FixtureInference, StubInferencePort, STUB_REPLY,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, post_msg, CapDecl, FixtureDriver, FixtureExtension, FixtureHome,
    FixtureHomeSpec,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, WasmEngine};

const PAGES: u32 = 768;

fn configured(engine: &wasmtime::Engine, tunable: &str) -> Option<u64> {
    let text = format!("{:?}", engine.config());
    let key = format!("{tunable}: ");
    let at = text.find(&key)? + key.len();
    text[at..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

fn turn_home() -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver: FixtureDriver::LlmNoErr,
        git: false,
        providers_yaml: Some(provider_yaml::llm_providers_block(&[
            provider_yaml::LOCAL_STUB,
        ])),
    })
    .expect("turn home")
}

fn set_pages(home: &FixtureHome, pages: u32) {
    let path = home.home().join(".advance/runtime-config.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read runtime-config");
    let from = "max_memory_pages: 1024";
    let to = format!("max_memory_pages: {pages}");
    assert!(
        yaml.contains(from),
        "runtime-config must contain {from:?} so this test can rewrite it"
    );
    std::fs::write(path, yaml.replace(from, &to)).expect("rewrite pages");
}

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_pulley_engines_compose_and_answer_a_turn() {
    let home = turn_home();
    set_pages(&home, PAGES);
    let stub = StubInferencePort::new(STUB_REPLY, 7, 3);
    let ext = FixtureExtension::new("fixture")
        .with_inference(FixtureInference::standard(Arc::clone(&stub)));
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_wasm_engine(WasmEngine::Pulley),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    assert_eq!(rt.health().wasm_engine, WasmEngine::Pulley);

    let runtime = probe
        .record()
        .component_runtime
        .as_ref()
        .and_then(Weak::upgrade)
        .expect("component runtime");
    let report = runtime.engine_report();
    assert!(report.host.is_pulley);
    assert!(report.tool.is_pulley);
    let reservation = pulley_memory_reservation(PAGES);
    assert_eq!(reservation, u64::from(PAGES) * WASM_PAGE_BYTES);
    assert_eq!(reservation, 50_331_648);
    assert_eq!(report.host.memory_reservation, Some(reservation));
    assert_eq!(report.tool.memory_reservation, Some(reservation));
    assert_eq!(
        report.host.memory_reservation_for_growth,
        Some(PULLEY_MEMORY_RESERVATION_FOR_GROWTH)
    );
    assert_eq!(
        report.tool.memory_reservation_for_growth,
        Some(PULLEY_MEMORY_RESERVATION_FOR_GROWTH)
    );
    for engine in [
        runtime.host_engine_handle().engine(),
        runtime.tool_engine_handle().engine(),
    ] {
        assert_eq!(configured(engine, "memory_reservation"), Some(reservation));
        assert_eq!(
            configured(engine, "memory_reservation_for_growth"),
            Some(PULLEY_MEMORY_RESERVATION_FOR_GROWTH)
        );
    }
    drop(runtime);

    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(addr, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    assert_eq!(stub.calls(), 1);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_default_options_build_native_engines() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs")],
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    assert_eq!(rt.health().wasm_engine, WasmEngine::Native);

    let runtime = probe
        .record()
        .component_runtime
        .as_ref()
        .and_then(Weak::upgrade)
        .expect("component runtime");
    let report = runtime.engine_report();
    assert!(!report.host.is_pulley);
    assert!(!report.tool.is_pulley);
    assert_eq!(report.host.target, None);
    assert_eq!(report.tool.target, None);
    assert_eq!(report.host.memory_reservation, None);
    assert_eq!(report.tool.memory_reservation, None);
    assert_eq!(report.host.memory_reservation_for_growth, None);
    assert_eq!(report.tool.memory_reservation_for_growth, None);
    assert!(!runtime.host_engine_handle().engine().is_pulley());
    assert!(!runtime.tool_engine_handle().engine().is_pulley());
    drop(runtime);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
