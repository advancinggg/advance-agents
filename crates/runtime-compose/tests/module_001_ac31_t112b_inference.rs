//! MODULE-001-T112 (b) — claimed-entry turns, hub scan, mesh dispatch, and
//! inference-port containment.

use std::sync::Weak;
use std::time::{Duration, Instant};

use advance_runtime_compose::daemon::DEFAULT_MSG_AGENT_ID;
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, stub_profile, DropFlag, FixtureInference, StubInferencePort, StubMeshDispatch,
    STUB_MESH_PANIC, STUB_PORT_PANIC, STUB_PROFILE_ID,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, FixtureExtension, Http,
};
use advance_runtime_compose::test_support::{MemoryComposeLog, TEARDOWN_ORDER};
use advance_runtime_compose::{log_keys, ComposeLogLine, LogStream};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

#[path = "support/t112b.rs"]
mod t112b;
use t112b::{
    all_events, api, append_runtime_config, compose_with, deltas_ws, events, home, jsonl_contains,
    msg, provider, provider_id, restart_required_count, run_id, subsequence, wait_events,
    CREATE_LOCAL_TWO, POLL, WAIT,
};

fn inference_once(phases: &[&str]) {
    assert_eq!(
        phases.iter().filter(|phase| **phase == "inference").count(),
        1,
        "{phases:?}"
    );
}

fn expected_stub_cost() -> f64 {
    7.0 * 2.0 / 1_000_000.0 + 5.0 * 4.0 / 1_000_000.0
}

fn line_for<'a>(log: &'a MemoryComposeLog, key: &str) -> ComposeLogLine {
    log.lines()
        .into_iter()
        .find(|line| line.key == key)
        .unwrap_or_else(|| panic!("missing log key {key}"))
}

fn no_ext_keys(log: &MemoryComposeLog) {
    let keys: Vec<_> = log
        .lines()
        .into_iter()
        .filter(|line| line.key.starts_with("ext."))
        .map(|line| line.key)
        .collect();
    assert!(keys.is_empty(), "{keys:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112b_claimed_entry_turn_profile_hold_budget_preflight_and_admin() {
    let home = home(
        &["fs", "llm"],
        &[
            provider_yaml::LOCAL_STUB,
            provider_yaml::LOCAL_FREE,
            provider_yaml::CLOUD_A,
        ],
    );
    append_runtime_config(&home, "run-budget:\n  default-cost-limit-usd: 0.00001\n");
    let stub = StubInferencePort::new("stub-pong", 7, 5);
    let mesh = StubMeshDispatch::new("mesh-pong");
    let flag = DropFlag::default();
    let ext = FixtureExtension::new("fixture").with_inference(
        FixtureInference::new()
            .claim("local-stub", stub.clone())
            .profile(STUB_PROFILE_ID, stub_profile())
            .hold(&flag)
            .mesh_dispatch(mesh.clone()),
    );
    let rec = ext.record();
    let (result, log, probe, baseline) = compose_with(&home, vec![ext.arc()]).await;
    let rt = result.expect("compose");
    inference_once(&rec.phases());

    {
        let probe_rec = probe.record();
        let vlm = probe_rec.vlm_catalog.as_ref().expect("vlm catalog");
        let gateway = probe_rec.gateway_catalog.as_ref().expect("gateway catalog");
        assert!(Weak::ptr_eq(vlm, gateway));
        let catalog = vlm.upgrade().expect("catalog alive");
        assert!(catalog.get(STUB_PROFILE_ID).is_some());
    }

    let (status, body) = msg(&probe, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    assert_eq!(stub.calls(), 1);
    let request = stub.requests().pop().expect("recorded chat");
    assert_eq!(request.provider_id, "local-stub");
    assert_eq!(request.model, "stub-model");
    assert_eq!(request.messages.last(), Some(&("user".into(), "hi".into())));
    let requests = wait_events(
        home.home(),
        "llm.request",
        |event| provider_id(event) == Some("local-stub") && run_id(event).is_some(),
        1,
        WAIT,
    )
    .await;
    assert_eq!(requests.len(), 1);
    let run = run_id(&requests[0]).expect("run_id").to_owned();
    let responses = wait_events(
        home.home(),
        "llm.response",
        |event| provider(event) == Some("local-stub"),
        1,
        WAIT,
    )
    .await;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["payload"]["input_tokens"], 7);
    assert_eq!(responses[0]["payload"]["output_tokens"], 5);
    let cost = responses[0]["payload"]["cost_usd"]
        .as_f64()
        .expect("cost_usd");
    assert!(
        (cost - expected_stub_cost()).abs() < 1e-12,
        "{cost} vs {}",
        expected_stub_cost()
    );
    assert_eq!(run_id(&responses[0]), Some(run.as_str()));

    let (status, body) = msg(&probe, "llm:hi").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("llm-err:"), "{body}");
    assert!(body.contains("BudgetExceeded"), "{body}");
    assert_eq!(stub.calls(), 1);
    let with_run: Vec<_> = events(home.home(), "llm.request")
        .into_iter()
        .filter(|event| provider_id(event) == Some("local-stub") && run_id(event).is_some())
        .collect();
    assert_eq!(with_run.len(), 1, "{with_run:?}");

    let (addr, tok) = api(&rt);
    let preflight = Http::post(addr, "/client/providers/local-stub:preflight")
        .session(&tok)
        .idempotency_key("k-pf")
        .send()
        .await;
    assert_eq!(preflight.body["data"]["ok"], true, "{:?}", preflight.body);
    assert!(
        preflight.body["data"]["reason"].is_null(),
        "{:?}",
        preflight.body
    );
    assert_eq!(stub.calls(), 2);
    let last = stub.requests().pop().expect("preflight chat");
    assert_eq!(last.messages, vec![("user".into(), "ping".into())]);
    assert_eq!(last.max_tokens, Some(16));
    let without_run = wait_events(
        home.home(),
        "llm.request",
        |event| provider_id(event) == Some("local-stub") && run_id(event).is_none(),
        1,
        WAIT,
    )
    .await;
    assert_eq!(without_run.len(), 1);

    let unclaimed = Http::post(addr, "/client/providers/local-free:preflight")
        .session(&tok)
        .idempotency_key("k-pf-free")
        .send()
        .await;
    assert_eq!(unclaimed.body["data"]["ok"], false, "{:?}", unclaimed.body);
    assert_eq!(
        unclaimed.body["data"]["reason"],
        "unsupported-backend-class"
    );

    let created = Http::post(addr, "/client/providers")
        .session(&tok)
        .idempotency_key("k-c2")
        .json(serde_json::from_str(CREATE_LOCAL_TWO).expect("create body"))
        .await;
    assert!(created.body.get("data").is_some(), "{:?}", created.body);
    assert_eq!(restart_required_count(&created), 1, "{:?}", created.body);

    let updated = Http::post(addr, "/client/providers/cloud-a:update")
        .session(&tok)
        .idempotency_key("k-u1")
        .json(json!({ "backend_class": "local" }))
        .await;
    assert!(updated.body.get("data").is_some(), "{:?}", updated.body);
    assert_eq!(restart_required_count(&updated), 1, "{:?}", updated.body);

    assert!(!flag.dropped());
    rt.shutdown().await.expect("shutdown");
    assert!(flag.dropped());
    let steps = probe.record().step_names();
    assert!(
        subsequence(
            &steps,
            &[
                "ingress.claimed_preflight",
                "holds.drop_graph",
                "holds.extension_holds",
            ]
        ),
        "{steps:?} vs {TEARDOWN_ORDER:?}"
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    no_ext_keys(&log);
    assert_eq!(log.count(log_keys::COMPOSE_CLAIMED_PREFLIGHT_OVERRUN), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112b_claimed_turn_teed_frames_pass_the_hub_scan() {
    let home = home(
        &["fs", "llm"],
        &[provider_yaml::LOCAL_STUB_PLAIN, provider_yaml::CLOUD_A],
    );
    let stub = StubInferencePort::new("here AKIAABCDEFGHIJKLMNOP done", 3, 3);
    let gate = stub.hold_next_call();
    let ext = FixtureExtension::new("fixture")
        .with_inference(FixtureInference::new().claim("local-stub", stub.clone()));
    let (result, _log, probe, baseline) = compose_with(&home, vec![ext.arc()]).await;
    let rt = result.expect("compose");
    let (addr, tok) = api(&rt);
    let sent = Http::post(addr, "/client/messages")
        .session(&tok)
        .idempotency_key("k-m1")
        .json(json!({
            "to": DEFAULT_MSG_AGENT_ID,
            "payload": "llm:hi"
        }))
        .await;
    let message_id = sent.body["data"]["message_id"]
        .as_str()
        .unwrap_or_else(|| panic!("message_id: {:?}", sent.body))
        .to_owned();
    assert!(!message_id.is_empty(), "{:?}", sent.body);

    gate.entered().await;
    let deadline = Instant::now() + WAIT;
    let stream_key = loop {
        let status = Http::get(addr, format!("/client/messages/{message_id}"))
            .session(&tok)
            .send()
            .await;
        if let Some(key) = status.body["data"]["stream_key"].as_str() {
            if !key.is_empty() {
                break key.to_owned();
            }
        }
        assert!(
            Instant::now() < deadline,
            "stream_key missing: {:?}",
            status.body
        );
        tokio::time::sleep(POLL).await;
    };

    let mut ws = deltas_ws(addr, &tok).await;
    ws.send(Message::Text(
        json!({ "stream_key": stream_key }).to_string().into(),
    ))
    .await
    .expect("subscribe");
    gate.release();
    let bound = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = bound.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("no terminal delta page within 10s");
        }
        let frame = tokio::time::timeout(remaining, async {
            loop {
                match ws.next().await {
                    Some(Ok(Message::Text(text))) => return Some(text.to_string()),
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = ws.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => return None,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return None,
                }
            }
        })
        .await
        .ok()
        .flatten();
        let Some(text) = frame else {
            break;
        };
        assert!(!text.contains("AKIA"), "{text}");
        let envelope: Value = serde_json::from_str(&text).expect("delta json");
        if envelope.pointer("/data/terminal").is_some()
            && !envelope.pointer("/data/terminal").unwrap().is_null()
        {
            break;
        }
    }

    let responses = wait_events(
        home.home(),
        "llm.response",
        |event| provider(event) == Some("local-stub"),
        1,
        WAIT,
    )
    .await;
    assert_eq!(responses.len(), 1);
    assert_eq!(stub.calls(), 1);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112b_mesh_dispatch_serves_mesh_remote_turns_and_contains_panics() {
    let home = home(
        &["fs", "llm"],
        &[provider_yaml::MESH_STUB, provider_yaml::CLOUD_A],
    );
    let mesh = StubMeshDispatch::new("mesh-pong");
    let ext = FixtureExtension::new("fixture")
        .with_inference(FixtureInference::new().mesh_dispatch(mesh.clone()));
    let (result, log, probe, baseline) = compose_with(&home, vec![ext.arc()]).await;
    let rt = result.expect("compose");

    let (status, body) = msg(&probe, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:mesh-pong"), "{body}");
    assert_eq!(mesh.targets(), ["dev-1"]);
    let responses = wait_events(
        home.home(),
        "llm.response",
        |event| provider(event) == Some("mesh-stub"),
        1,
        WAIT,
    )
    .await;
    assert_eq!(responses.len(), 1);

    mesh.panic_next_call();
    let (status, body) = msg(&probe, "llm:hi").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("llm-err:"), "{body}");
    assert!(body.contains("ProviderError"), "{body}");
    assert!(!body.contains(STUB_MESH_PANIC), "{body}");
    assert_eq!(log.count(log_keys::EXT_MESH_DISPATCH_PANICKED), 1);
    let line = line_for(&log, log_keys::EXT_MESH_DISPATCH_PANICKED);
    assert_eq!(line.stream, LogStream::Stderr);
    assert_eq!(
        line.text,
        "advance: WARN extension fixture mesh dispatch panicked in dispatch_chat; the call answered a typed error"
    );
    let errors = wait_events(
        home.home(),
        "llm.error",
        |event| {
            event.pointer("/payload/model").and_then(Value::as_str) == Some("mesh-model")
                && event.pointer("/payload/error_type").and_then(Value::as_str)
                    == Some("provider-error")
        },
        1,
        WAIT,
    )
    .await;
    assert_eq!(errors.len(), 1);
    assert!(events(home.home(), "llm.request")
        .iter()
        .all(
            |event| event.pointer("/payload/model").and_then(Value::as_str) != Some("cloud-model")
        ));
    assert!(!jsonl_contains(home.home(), STUB_MESH_PANIC));
    for event in all_events(home.home()) {
        let line = event.to_string();
        assert!(!line.contains(STUB_MESH_PANIC), "{line}");
    }

    let (status, body) = msg(&probe, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:mesh-pong"), "{body}");
    assert_eq!(mesh.calls(), 3);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112e_inference_port_panic_mid_turn_is_contained() {
    let home = home(
        &["fs", "llm"],
        &[provider_yaml::LOCAL_STUB_PLAIN, provider_yaml::CLOUD_A],
    );
    let stub = StubInferencePort::new("stub-pong", 1, 1);
    let ext = FixtureExtension::new("fixture")
        .with_inference(FixtureInference::new().claim("local-stub", stub.clone()));
    let (result, log, probe, baseline) = compose_with(&home, vec![ext.arc()]).await;
    let rt = result.expect("compose");

    stub.panic_next_call();
    let (status, body) = msg(&probe, "llm:hi").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("llm-err:"), "{body}");
    assert!(body.contains("ProviderError"), "{body}");
    assert!(body.contains("provider error"), "{body}");
    assert!(!body.contains(STUB_PORT_PANIC), "{body}");

    assert_eq!(log.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);
    let line = line_for(&log, log_keys::EXT_INFERENCE_PORT_PANICKED);
    assert_eq!(line.stream, LogStream::Stderr);
    assert_eq!(
        line.text,
        "advance: WARN extension fixture inference port local-stub panicked in chat; the call answered a typed error"
    );

    let errors = wait_events(
        home.home(),
        "llm.error",
        |event| {
            event.pointer("/payload/model").and_then(Value::as_str) == Some("stub-model")
                && event.pointer("/payload/error_type").and_then(Value::as_str)
                    == Some("provider-error")
        },
        1,
        WAIT,
    )
    .await;
    assert_eq!(errors.len(), 1);
    assert!(events(home.home(), "llm.request")
        .iter()
        .all(
            |event| event.pointer("/payload/model").and_then(Value::as_str) != Some("cloud-model")
        ));
    assert!(!jsonl_contains(home.home(), STUB_PORT_PANIC));
    for event in all_events(home.home()) {
        let line = event.to_string();
        assert!(!line.contains(STUB_PORT_PANIC), "{line}");
    }

    let (status, body) = msg(&probe, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    assert_eq!(stub.calls(), 2);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
