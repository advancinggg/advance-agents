//! SYS-AC-337: the embedded profile answers a turn under Pulley with no child
//! process. Own binary because the spawn counter and `/proc/self` are process-wide.

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::Platform;
use advance_runtime_compose::compose;
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, FixtureInference, StubInferencePort, LOCAL_STUB_ID, STUB_REPLY,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, client_message_turn, provider_cost, CapDecl, CostTotals, FixtureDriver,
    FixtureExtension, FixtureHome, FixtureHomeSpec, FIXTURE_ID, ROOT_MAILBOX,
};
use advance_runtime_compose::test_support::{
    proc_self, spawn_counter, ComposeProbe, MemoryComposeLog,
};
use advance_runtime_compose::{ClientApiEndpoint, HostPlatform, WasmEngine};

fn turn_home(driver: FixtureDriver) -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver,
        git: false,
        providers_yaml: Some(provider_yaml::llm_providers_block(&[
            provider_yaml::LOCAL_STUB,
        ])),
    }
}

async fn cost_after_turn(ep: &ClientApiEndpoint, tok: &str) -> CostTotals {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let c = provider_cost(ep, tok, LOCAL_STUB_ID).await.expect("costs");
        if c.request_count >= 1 || Instant::now() > deadline {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_337_j83_embedded_pulley_turn_spawns_no_child() {
    let spawns = spawn_counter::snapshot();
    let baseline = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();

    let home = FixtureHome::new(turn_home(FixtureDriver::HelloLlm)).expect("home");
    let stub = StubInferencePort::new(STUB_REPLY, 7, 3);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::default());
    let opts = home.embedded_options(HostPlatform::Ios, Arc::new(log), probe.clone());
    let ext = FixtureExtension::new(FIXTURE_ID)
        .with_inference(FixtureInference::standard(stub.clone()))
        .arc();
    let rt = tokio::time::timeout(Duration::from_secs(180), compose(opts, vec![ext]))
        .await
        .expect("compose in time")
        .expect("compose");
    assert_eq!(rt.health().wasm_engine, WasmEngine::Pulley);

    let ep = rt.client_api().expect("loopback Client API");
    let token = ep
        .api
        .upgrade()
        .expect("ClientApi alive")
        .mint_in_process_session(Platform::Ios)
        .token;
    let turn = client_message_turn(
        &ep,
        &token,
        ROOT_MAILBOX,
        "hello from Pulley",
        Duration::from_secs(120),
    )
    .await
    .expect("turn");
    assert_eq!(turn.reply_state, "replied", "message {}", turn.message_id);
    let cost = cost_after_turn(&ep, &token).await;
    assert_eq!(
        (cost.tokens_in, cost.tokens_out, cost.request_count),
        (7, 3, 1),
        "{cost:?}"
    );
    assert_eq!(stub.calls(), 1);
    let d = spawn_counter::snapshot().since(&spawns);
    assert_eq!((d.admitted_total(), d.refused_total()), (0, 0), "{d:?}");
    if let Some(kids) = proc_self::child_pids() {
        assert!(kids.is_empty(), "children: {kids:?}");
    }

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    let d = spawn_counter::snapshot().since(&spawns);
    assert_eq!((d.admitted_total(), d.refused_total()), (0, 0), "{d:?}");
    if let Some(kids) = proc_self::child_pids() {
        assert!(kids.is_empty(), "children: {kids:?}");
    }
}
