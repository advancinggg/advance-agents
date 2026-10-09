//! MODULE-001-T113 (2) — the embedded profile's Pulley turn in its own binary.

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::Platform;
use advance_runtime::component_loader::{
    pulley_memory_reservation, PULLEY_MEMORY_RESERVATION_FOR_GROWTH, PULLEY_TARGET,
};
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, FixtureInference, StubInferencePort, LOCAL_STUB_ID, STUB_REPLY,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, client_message_turn, provider_cost, warm_up, CapDecl, CostTotals,
    FixtureDriver, FixtureExtension, FixtureHome, FixtureHomeSpec, FIXTURE_ID, ROOT_MAILBOX,
};
use advance_runtime_compose::test_support::{
    proc_self, spawn_counter, ComposeProbe, MemoryComposeLog,
};
use advance_runtime_compose::{
    compose, Admission, ClientApiEndpoint, ClientApiOptions, HostPlatform, InstanceGuard,
    ProcessPolicy, WasmEngine,
};

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
async fn module_001_ac32_t113_2_embedded_pulley_turn_no_exec_memory_no_child() {
    #[cfg(target_os = "linux")]
    let s0 = proc_self::read_self_maps().expect("maps before compose");
    let spawns = spawn_counter::snapshot();
    let baseline = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();

    let home = FixtureHome::new(turn_home(FixtureDriver::HelloLlm)).expect("home");
    home.set_max_memory_pages(PAGES).expect("pages");
    let stub = StubInferencePort::new(STUB_REPLY, 7, 3);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::default());
    let opts = home.embedded_options(HostPlatform::Ios, Arc::new(log), probe.clone());
    assert_eq!(opts.wasm_engine, WasmEngine::Pulley);
    assert_eq!(opts.processes, ProcessPolicy::Forbid);
    assert_eq!(opts.instance, InstanceGuard::ProcessLocal);
    assert!(opts.hot_reload);
    assert!(matches!(
        opts.client_api,
        ClientApiOptions::Loopback {
            write_discovery: false,
            admission: Admission::InProcessOnly,
            ..
        }
    ));
    let ext = FixtureExtension::new(FIXTURE_ID)
        .with_inference(FixtureInference::standard(stub.clone()))
        .arc();
    let rt = tokio::time::timeout(Duration::from_secs(180), compose(opts, vec![ext]))
        .await
        .expect("compose in time")
        .expect("compose");

    {
        let cr = probe
            .record()
            .component_runtime
            .and_then(|w| w.upgrade())
            .expect("runtime recorded");
        let r = cr.engine_report();
        let reservation = u64::from(PAGES) * 65_536;
        assert_eq!(reservation, pulley_memory_reservation(PAGES));
        for (s, engine) in [
            (r.host, cr.host_engine_handle().engine().clone()),
            (r.tool, cr.tool_engine_handle().engine().clone()),
        ] {
            assert!(s.is_pulley && engine.is_pulley() && s.target == Some(PULLEY_TARGET));
            assert_eq!(
                (
                    s.memory_reservation,
                    configured(&engine, "memory_reservation")
                ),
                (Some(reservation), Some(reservation))
            );
            assert_eq!(
                (
                    s.memory_reservation_for_growth,
                    configured(&engine, "memory_reservation_for_growth")
                ),
                (
                    Some(PULLEY_MEMORY_RESERVATION_FOR_GROWTH),
                    Some(PULLEY_MEMORY_RESERVATION_FOR_GROWTH)
                )
            );
        }
    }
    assert_eq!(rt.health().wasm_engine, WasmEngine::Pulley);

    let ep = rt.client_api().expect("loopback Client API");
    let token = ep
        .api
        .upgrade()
        .expect("ClientApi alive")
        .mint_in_process_session(Platform::Ios)
        .token;
    warm_up(&ep, &token).await.expect("warm-up");
    assert_eq!(
        provider_cost(&ep, &token, LOCAL_STUB_ID)
            .await
            .expect("costs")
            .request_count,
        0
    );
    #[cfg(target_os = "linux")]
    let s1 = proc_self::read_self_maps().expect("maps before the turn");
    let turn = client_message_turn(
        &ep,
        &token,
        ROOT_MAILBOX,
        "hello pulley",
        Duration::from_secs(120),
    )
    .await
    .expect("turn");
    #[cfg(target_os = "linux")]
    let s2 = proc_self::read_self_maps().expect("maps after the turn");

    assert_eq!(
        (turn.delivery_state.as_str(), turn.reply_state.as_str()),
        ("delivered", "replied"),
        "message {} after {} polls",
        turn.message_id,
        turn.polls
    );
    let cost = cost_after_turn(&ep, &token).await;
    assert_eq!(
        (cost.tokens_in, cost.tokens_out, cost.request_count),
        (7, 3, 1),
        "{cost:?}"
    );
    assert!(cost.cost_usd > 0.0, "{cost:?}");
    assert_eq!(stub.calls(), 1);
    assert_eq!(stub.requests()[0].provider_id, LOCAL_STUB_ID);
    let d = spawn_counter::snapshot().since(&spawns);
    assert_eq!((d.admitted_total(), d.refused_total()), (0, 0), "{d:?}");
    #[cfg(target_os = "linux")]
    {
        // Strict on purpose: no executable mapping may appear during the turn, file-backed
        // ones included. The turn talks to an IP-literal loopback address (no DNS, no NSS),
        // so it never reaches the dynamic loader; a shared object loaded here is a change to
        // look at, not noise. The check since compose below allows file-backed mappings.
        let during = proc_self::new_executable(&s1, &s2);
        assert!(
            during.is_empty(),
            "executable mappings appeared during the turn: {during:#?}"
        );
        let anon: Vec<_> = proc_self::new_executable(&s0, &s2)
            .into_iter()
            .filter(|m| !m.file_backed())
            .collect();
        assert!(
            anon.is_empty(),
            "non-file executable memory since compose: {anon:#?}"
        );
    }
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
