//! MODULE-001-T112 callback-order binary. It starts with the client-families
//! pre-bind witness; the remaining order legs follow.

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime_compose::compose;
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, FixtureInference, StubInferencePort,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, ext_probe_core, CapDecl, FixtureCall, FixtureDriver, FixtureExtension,
    FixtureFamilies, FixtureHome, FixtureHomeSpec, FIXTURE_ID, FIXTURE_TWO_ID,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};

#[path = "support/source_scan.rs"]
mod source_scan;

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_a_client_families_runs_before_bind() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let fixture = FixtureExtension::new(FIXTURE_ID).with_families(FixtureFamilies::standard());
    let rec = fixture.record();
    let two = FixtureExtension::new(FIXTURE_TWO_ID)
        .with_families(FixtureFamilies::standard_with_label(FIXTURE_TWO_ID))
        .sharing(&rec);
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![fixture.arc(), two.arc()],
    )
    .await
    .expect("compose");

    let family_calls: Vec<_> = rec
        .calls()
        .into_iter()
        .filter(|call| call.phase == "client_families")
        .collect();
    assert_eq!(
        family_calls
            .iter()
            .map(|call| call.extension)
            .collect::<Vec<_>>(),
        [FIXTURE_ID, FIXTURE_TWO_ID]
    );
    assert!(
        family_calls.iter().all(|call| !call.discovery_present),
        "{family_calls:?}"
    );
    assert!(home.home().join(".runtime/client-api").exists());

    let ep = rt.client_api().expect("client api");
    {
        let api = ep.api.upgrade().expect("client api alive");
        let table = api.route_table();
        assert!(
            table
                .iter()
                .any(|row| row.path == "/client/fixture/status" && !row.templated),
            "{table:?}"
        );
        assert!(
            table
                .iter()
                .any(|row| row.path == "/client/fixture-two/status" && !row.templated),
            "{table:?}"
        );
        let stats = api.extension_budget_stats();
        assert_eq!(stats.len(), 2, "{stats:?}");
        assert_eq!(stats[0].extension, FIXTURE_ID);
        assert_eq!(stats[0].labels, vec!["fixture".to_owned()]);
        assert_eq!(stats[1].extension, FIXTURE_TWO_ID);
        assert_eq!(stats[1].labels, vec!["fixture-two".to_owned()]);
    }
    drop(ep);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

const PHASES: &[&str] = &[
    "capabilities",
    "inference",
    "host_functions",
    "tools",
    "client_families",
    "on_started",
];

fn phases_of<'a>(calls: &'a [FixtureCall], extension: &str) -> Vec<&'a str> {
    calls
        .iter()
        .filter(|call| call.extension == extension)
        .map(|call| call.phase)
        .collect()
}

fn assert_phase_major(calls: &[FixtureCall], phases: &[&str]) {
    let mut prev_end = 0usize;
    for phase in phases {
        let idxs: Vec<usize> = calls
            .iter()
            .enumerate()
            .filter(|(_, call)| call.phase == *phase)
            .map(|(index, _)| index)
            .collect();
        assert!(
            !idxs.is_empty(),
            "missing phase {phase} in {:?}",
            calls
                .iter()
                .map(|call| (call.extension, call.phase))
                .collect::<Vec<_>>()
        );
        let start = *idxs.iter().min().expect("idxs");
        let end = *idxs.iter().max().expect("idxs");
        assert!(
            start >= prev_end,
            "phase {phase} is not after the previous phase: {:?}",
            calls
                .iter()
                .map(|call| (call.extension, call.phase))
                .collect::<Vec<_>>()
        );
        prev_end = end + 1;
    }
}

async fn wait_phase(
    rec: &advance_runtime_compose::test_support::fixture::FixtureRecord,
    phase: &str,
    n: usize,
) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let got = rec
            .calls()
            .into_iter()
            .filter(|call| call.phase == phase)
            .count();
        if got >= n {
            return;
        }
        if Instant::now() >= deadline {
            panic!("wanted {n} {phase} calls, got {got}: {:?}", rec.calls());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn once_and_after(src: &str, previous: usize, marker: &str) -> usize {
    let matches: Vec<usize> = src.match_indices(marker).map(|(index, _)| index).collect();
    assert_eq!(
        matches.len(),
        1,
        "marker {marker:?} occurs {} times",
        matches.len()
    );
    let at = matches[0];
    assert!(
        at >= previous,
        "marker {marker:?} at {at} is before the previous marker ending at {previous}"
    );
    at + marker.len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_callback_order_capabilities_to_on_started() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![
            CapDecl::Granted("fs"),
            CapDecl::Granted("llm"),
            CapDecl::Granted("tools"),
            CapDecl::Granted("fixture.probe"),
        ],
        driver: FixtureDriver::Core(ext_probe_core()),
        git: true,
        providers_yaml: Some(provider_yaml::llm_providers_block(&[
            provider_yaml::LOCAL_STUB,
        ])),
    })
    .expect("home");
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let fixture = FixtureExtension::standard()
        .with_families(FixtureFamilies::standard())
        .with_inference(FixtureInference::standard(stub));
    let rec = fixture.record();
    let two = FixtureExtension::new(FIXTURE_TWO_ID)
        .with_families(FixtureFamilies::standard_with_label(FIXTURE_TWO_ID))
        .sharing(&rec);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![fixture.arc(), two.arc()],
    )
    .await
    .expect("compose");
    wait_phase(&rec, "on_started", 2).await;
    let calls = rec.calls();
    assert_eq!(phases_of(&calls, FIXTURE_ID), PHASES);
    assert_eq!(phases_of(&calls, FIXTURE_TWO_ID), PHASES);
    assert_phase_major(&calls, PHASES);
    for call in calls.iter().filter(|call| call.phase != "on_started") {
        assert!(
            !call.discovery_present,
            "pre-bind call saw discovery: {call:?}"
        );
    }
    let base = rt.client_api().expect("client api").base_url.clone();
    let started: Vec<_> = calls
        .iter()
        .filter(|call| call.phase == "on_started")
        .collect();
    assert_eq!(started.len(), 2, "{started:?}");
    for call in started {
        assert!(call.discovery_present, "{call:?}");
        assert_eq!(
            call.client_api_base.as_deref(),
            Some(base.as_str()),
            "{call:?}"
        );
    }
    rt.shutdown().await.expect("shutdown");
    let hooks = rec
        .hooks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(hooks, [FIXTURE_TWO_ID, FIXTURE_ID], "{hooks:?}");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_callback_order_skips_inference_without_llm_and_tools_without_tools() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs")],
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home");
    let fixture = FixtureExtension::standard();
    let rec = fixture.record();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![fixture.arc()],
    )
    .await
    .expect("compose");
    wait_phase(&rec, "on_started", 1).await;
    assert_eq!(
        rec.phases(),
        [
            "capabilities",
            "host_functions",
            "client_families",
            "on_started"
        ]
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[test]
fn module_001_ac31_callback_sites_follow_composition_order() {
    let src = source_scan::src_dir();
    let wiring = source_scan::strip_comments(
        &std::fs::read_to_string(src.join("wiring.rs")).expect("wiring.rs"),
    );
    let compose = source_scan::strip_comments(
        &std::fs::read_to_string(src.join("compose.rs")).expect("compose.rs"),
    );
    let daemon = source_scan::strip_comments(
        &std::fs::read_to_string(src.join("daemon/mod.rs")).expect("daemon/mod.rs"),
    );

    let mut at = 0;
    for marker in [
        ".secret_plan(",
        "build_pack_wiring(",
        "EventBus::new(",
        ".install_contexts(",
        "if declares_llm {",
        "run_inference_phase(",
        "let gateway = build_llm_gateway_with(",
        "register_agent_llm_with_turn_cost(",
        "run_host_functions(",
        "builder.build(cap_grant.grant_check.clone())",
        "crate::data_wiring::register_data_tool_with_log(",
        "run_tools(",
        "run_client_families(",
        "bind_runtime(",
        "bind_local_factory(",
    ] {
        at = once_and_after(&wiring, at, marker);
    }

    let mut at = 0;
    for marker in [
        "ExtensionSet::prepare(",
        "compose_graph(",
        "spawn_on_started(",
        "let supervisor = tokio::spawn(",
    ] {
        at = once_and_after(&compose, at, marker);
    }

    let fn_at = daemon
        .find("fn try_spawn_agent_loop(")
        .expect("try_spawn_agent_loop");
    let body_start = fn_at
        + daemon[fn_at..]
            .find('{')
            .expect("try_spawn_agent_loop body");
    let mut depth = 0i32;
    let mut body_end = body_start;
    for (index, ch) in daemon[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    body_end = body_start + index + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let list = "ToolRegistry::list";
    let mut n = 0usize;
    let mut from = 0;
    while let Some(rel) = daemon[from..].find(list) {
        let abs = from + rel;
        assert!(
            abs >= body_start && abs < body_end,
            "ToolRegistry::list at {abs} is outside try_spawn_agent_loop"
        );
        n += 1;
        from = abs + list.len();
    }
    assert!(
        n >= 1,
        "ToolRegistry::list never appears in try_spawn_agent_loop"
    );
}
