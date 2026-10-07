//! MODULE-020-T29 production-composition witnesses and the D5 llm-deltas row.

#[path = "support/t29.rs"]
mod t29;

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::{
    ClientApi, ClientApiConfig, ClientErrorCode, ClientRequest, ClientSession, Platform, Principal,
    Scope, UnboundHistoryReadPort,
};
use advance_event_bus::{EventBus, EventBusConfig, EventFilter};
use advance_runtime_compose::agent_config::KNOWN_CAPABILITIES;
use advance_runtime_compose::client_api_adapters::UnboundHistoryAdapter;
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, FixtureInference, StubInferencePort,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, mint_session_with, post_msg, CapDecl, FixtureDriver,
    FixtureExtension, FixtureHomeSpec, Http, FIXTURE_ID,
};
use advance_runtime_compose::test_support::ComposeProbe;
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, LlmDeltaEvent, LlmDeltaFrame, LlmTerminalReason};
use cap_grant::ChannelApprovalRequest;
use cap_http::DefaultLeakDetector;
use chrono::{TimeZone, Utc};
use serde_json::{json, Value};
use t29::{
    api, compose_home, deltas_ws, error_code, error_message, events_ws, grant_snapshot, has_data,
    home, next_json, park, publish_deltas, query, read_port, registry_specs, send_message,
    session_run, stable_compare, syntactic_revision, try_next_json, warning_codes, write_skill,
    ws_send, WsFrame, POLL, WAIT,
};

static SERIAL: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn granted(caps: &[&'static str]) -> Vec<CapDecl> {
    caps.iter().copied().map(CapDecl::Granted).collect()
}

fn turn_home() -> advance_runtime_compose::test_support::fixture::FixtureHome {
    home(FixtureHomeSpec {
        capabilities: granted(&["fs", "llm"]),
        driver: FixtureDriver::LlmNoErr,
        git: false,
        providers_yaml: Some(provider_yaml::llm_providers_block(&[
            provider_yaml::LOCAL_STUB,
        ])),
    })
}

fn msg_addr(probe: &ComposeProbe) -> std::net::SocketAddr {
    probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound")
}

fn event_keys(event: &Value) -> Vec<&str> {
    event
        .get("data")
        .and_then(Value::as_object)
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

fn find_round_completed<'a>(events: &'a [Value], run: &str) -> Option<&'a Value> {
    events.iter().find(|event| {
        event.get("event_type").and_then(Value::as_str) == Some("run.round_completed")
            && event.get("run_id").and_then(Value::as_str) == Some(run)
    })
}

fn frame_has_round(frame: &Value, run: &str) -> bool {
    frame
        .pointer("/data/events")
        .and_then(Value::as_array)
        .is_some_and(|events| find_round_completed(events, run).is_some())
}

async fn drain_events_ws(ws: &mut t29::WsClient, frames: &mut Vec<Value>) {
    loop {
        match try_next_json(ws, Duration::from_millis(20)).await {
            WsFrame::Json(frame) => frames.push(frame),
            WsFrame::Timeout | WsFrame::Closed => break,
        }
    }
}

async fn session_run_keeping_ws(
    addr: std::net::SocketAddr,
    tok: &str,
    root: &str,
    ws: &mut t29::WsClient,
    frames: &mut Vec<Value>,
) -> (String, String) {
    let deadline = Instant::now() + WAIT;
    loop {
        drain_events_ws(ws, frames).await;
        let resp = Http::get(addr, "/client/runs").session(tok).send().await;
        assert_eq!(resp.status, 200, "{:?}", resp.body);
        let runs = resp
            .body
            .pointer("/data/runs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(run) = runs
            .iter()
            .find(|run| run.get("controller_agent").and_then(Value::as_str) == Some(root))
        {
            let run_id = run
                .get("run_id")
                .and_then(Value::as_str)
                .expect("run_id")
                .to_owned();
            let task_id = run
                .get("task_id")
                .and_then(Value::as_str)
                .expect("task_id")
                .to_owned();
            return (run_id, task_id);
        }
        if Instant::now() >= deadline {
            panic!("session run for {root} not listed within {WAIT:?}: {runs:?}");
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn poll_events_for_turn(addr: std::net::SocketAddr, tok: &str, run: &str) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let resp = Http::get(addr, "/client/events?event_type=run.round_completed")
            .session(tok)
            .send()
            .await;
        assert_eq!(resp.status, 200, "{:?}", resp.body);
        assert!(has_data(&resp.body), "{:?}", resp.body);
        let events = resp
            .body
            .pointer("/data/events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(event) = find_round_completed(&events, run) {
            return event.clone();
        }
        if Instant::now() >= deadline {
            panic!("run.round_completed for {run} missing within {WAIT:?}: {events:?}");
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn poll_turn_row(
    read: &Arc<dyn advance_event_bus::ObservabilityReadApi>,
    run: &str,
    root: &str,
) -> advance_event_bus::ReadEvent {
    let deadline = Instant::now() + WAIT;
    loop {
        let rows = read
            .query(
                &EventFilter {
                    event_type_prefix: Some("run.round_completed".into()),
                    run_id: Some(run.to_owned()),
                    ..EventFilter::default()
                },
                10,
            )
            .await
            .expect("query");
        if let Some(turn) = rows.into_iter().next() {
            assert_eq!(turn.event.task_id.as_deref(), Some(root), "{turn:?}");
            assert!(
                !turn.event.trace_id.is_empty(),
                "empty trace_id on {}",
                turn.event.id
            );
            return turn;
        }
        if Instant::now() >= deadline {
            panic!("run.round_completed row missing within {WAIT:?}");
        }
        tokio::time::sleep(POLL).await;
    }
}

fn assert_unwired(resp: &advance_runtime_compose::test_support::fixture::HttpResponse) {
    assert_eq!(resp.status, 503, "{:?}", resp.body);
    assert_eq!(error_code(&resp.body), "module_unavailable");
    assert_eq!(error_message(&resp.body), "provider not wired");
}

fn empty_tools() -> Value {
    json!({"wasm": [], "mcp": [], "skills": []})
}

fn empty_grants() -> Value {
    json!({"requests": []})
}

fn history_filter(run: Option<&str>) -> EventFilter {
    EventFilter {
        run_id: run.map(str::to_owned),
        ..EventFilter::default()
    }
}

fn grant_mutations(root: &str, grant_id: &str) -> Vec<(String, Value, String)> {
    let rev = syntactic_revision();
    vec![
        (
            "/client/grants/pending/t29-req:approve".into(),
            json!({ "decision_revision": rev.clone() }),
            "t29-1".into(),
        ),
        (
            "/client/grants/pending/t29-req:deny".into(),
            json!({ "decision_revision": rev.clone(), "reason": "t29" }),
            "t29-2".into(),
        ),
        (
            "/client/grants/pending/t29-req:narrow".into(),
            json!({
                "decision_revision": rev,
                "params": [{ "key": "k", "value": "v" }]
            }),
            "t29-3".into(),
        ),
        (
            format!("/client/grants/{grant_id}:revoke"),
            json!({}),
            "t29-4".into(),
        ),
        (
            "/client/presets/supervised:apply".into(),
            json!({ "target_agent_id": root }),
            "t29-5".into(),
        ),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_020_ac18_t29_a_fs_llm_turn_home_read_views_answer_data() {
    let _serial = SERIAL.lock().await;
    let home = turn_home();
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let (rt, _log, probe, baseline) = compose_home(
        &home,
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_inference(FixtureInference::standard(stub))
            .arc()],
    )
    .await;
    let rt = rt.expect("compose");
    let ep = rt.client_api().expect("client api");
    let (addr, tok) = api(&rt);
    let root = rt.root_agent_id().to_owned();
    let read = read_port(&probe);

    let seed = Http::get(
        addr,
        "/client/events/stream?event_type=run.round_completed&limit=0",
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(seed.status, 200, "{:?}", seed.body);
    let stream_id = seed
        .body
        .pointer("/data/cursor/stream_id")
        .and_then(Value::as_str)
        .expect("stream_id")
        .to_owned();
    let last_event_id = seed
        .body
        .pointer("/data/cursor/last_event_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    assert!(!stream_id.is_empty(), "{:?}", seed.body);
    let (mut events_sock, ws_seed) = events_ws(addr, &tok, "?event_type=run.round_completed").await;
    assert!(
        has_data(&ws_seed) || ws_seed.get("error").is_none(),
        "{ws_seed}"
    );
    let mut ws_frames = Vec::new();

    let (status, body) = post_msg(msg_addr(&probe), "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");

    let (run, task) =
        session_run_keeping_ws(addr, &tok, &root, &mut events_sock, &mut ws_frames).await;
    let turn = poll_turn_row(&read, &run, &root).await;
    drain_events_ws(&mut events_sock, &mut ws_frames).await;
    let projected = poll_events_for_turn(addr, &tok, &run).await;
    drain_events_ws(&mut events_sock, &mut ws_frames).await;
    assert_eq!(
        projected.get("event_type").and_then(Value::as_str),
        Some("run.round_completed")
    );
    assert_eq!(
        projected.get("run_id").and_then(Value::as_str),
        Some(run.as_str())
    );
    assert_eq!(
        projected.get("trace_id").and_then(Value::as_str),
        Some(turn.event.trace_id.as_str())
    );
    assert_eq!(
        projected.get("agent_id").and_then(Value::as_str),
        Some(root.as_str())
    );
    let stamped = projected
        .get("timestamp")
        .and_then(Value::as_str)
        .expect("timestamp");
    let parsed = chrono::DateTime::parse_from_rfc3339(stamped)
        .expect("rfc3339")
        .with_timezone(&Utc);
    assert_eq!(parsed, turn.event.timestamp);
    let allowed = ["iteration", "token_used", "cost_usd", "decision"];
    for key in event_keys(&projected) {
        assert!(allowed.contains(&key), "unexpected data key {key}");
    }

    // One Client API allows a single in-flight event-stream read. The WS pump
    // holds that slot, so HTTP resume runs only after the socket is closed.
    let ws_deadline = Instant::now() + WAIT;
    let mut saw_ws = ws_frames.iter().any(|frame| frame_has_round(frame, &run));
    while !saw_ws && Instant::now() < ws_deadline {
        match try_next_json(&mut events_sock, Duration::from_secs(2)).await {
            WsFrame::Json(frame) => {
                if frame_has_round(&frame, &run) {
                    saw_ws = true;
                }
                ws_frames.push(frame);
            }
            WsFrame::Timeout => {}
            WsFrame::Closed => break,
        }
    }
    assert!(saw_ws, "events WS missed the turn; frames={ws_frames:?}");
    let _ = events_sock.close(None).await;

    let deadline = Instant::now() + WAIT;
    let mut resumed = None;
    while Instant::now() < deadline {
        let path = query(
            "/client/events/stream",
            &[
                ("stream_id", stream_id.as_str()),
                ("last_event_id", last_event_id.as_str()),
                ("event_type", "run.round_completed"),
                ("limit", "64"),
            ],
        );
        let resp = Http::get(addr, path).session(&tok).send().await;
        if resp.status == 429 {
            tokio::time::sleep(POLL).await;
            continue;
        }
        assert_eq!(resp.status, 200, "{:?}", resp.body);
        let events = resp
            .body
            .pointer("/data/events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if find_round_completed(&events, &run).is_some() {
            resumed = Some(resp.body.clone());
            break;
        }
        tokio::time::sleep(POLL).await;
    }
    assert!(resumed.is_some(), "stream resume missed the turn");

    let run_history = stable_compare(
        &read,
        history_filter(Some(&run)),
        None,
        addr,
        &tok,
        &format!("/client/runs/{run}/history"),
    )
    .await;
    let entries = run_history
        .get("entries")
        .and_then(Value::as_array)
        .expect("entries");
    assert!(!entries.is_empty());
    assert!(entries.len() <= 100);
    assert!(
        entries
            .iter()
            .any(|entry| entry.get("event_id").and_then(Value::as_str)
                == Some(turn.event.id.as_str())),
        "{entries:?}"
    );

    let task_history = stable_compare(
        &read,
        history_filter(None),
        Some(&task),
        addr,
        &tok,
        &format!("/client/tasks/{task}/history"),
    )
    .await;
    let task_entries = task_history
        .get("entries")
        .and_then(Value::as_array)
        .expect("entries");
    assert!(!task_entries.is_empty());
    assert!(task_entries.iter().any(|entry| {
        entry.get("event_id").and_then(Value::as_str) == Some(turn.event.id.as_str())
    }));

    let first_id = entries[0]
        .get("event_id")
        .and_then(Value::as_str)
        .expect("event_id");
    let skipped = Http::get(
        addr,
        query(
            &format!("/client/runs/{run}/history"),
            &[("cursor", first_id)],
        ),
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(skipped.status, 200, "{:?}", skipped.body);
    assert_eq!(
        skipped.body.pointer("/data/entries"),
        Some(&json!(entries[1..].to_vec()))
    );
    for path in [
        format!("/client/runs/{run}/history"),
        format!("/client/tasks/{task}/history"),
    ] {
        let unknown = Http::get(addr, query(&path, &[("cursor", "t29-no-such-event")]))
            .session(&tok)
            .send()
            .await;
        assert_eq!(unknown.status, 404, "{path} {:?}", unknown.body);
        assert_eq!(error_code(&unknown.body), "not_found");
        assert_eq!(error_message(&unknown.body), "resource not found");
    }

    let pending = Http::get(addr, "/client/grants/pending")
        .session(&tok)
        .send()
        .await;
    assert_eq!(pending.status, 200, "{:?}", pending.body);
    assert_eq!(pending.body.get("data"), Some(&empty_grants()));
    assert!(
        warning_codes(&pending.body).is_empty(),
        "{:?}",
        pending.body
    );

    mint_session_with(&ep, vec![Scope::ReadRuns], None);
    let forbidden = Http::get(addr, "/client/grants/pending")
        .session(&tok)
        .send()
        .await;
    assert_eq!(forbidden.status, 403, "{:?}", forbidden.body);
    assert_eq!(error_code(&forbidden.body), "forbidden");
    mint_session(&ep);

    assert!(probe.record().grant_approval_intake.is_none());
    let s0 = grant_snapshot(&probe, &root);
    assert!(!s0.is_empty(), "fs/llm grants");
    let grant_id = s0[0].id.to_string();
    for (path, body, key) in grant_mutations(&root, &grant_id) {
        let first = Http::post(addr, &path)
            .session(&tok)
            .idempotency_key(&key)
            .json(body.clone())
            .await;
        assert_unwired(&first);
        assert!(
            !warning_codes(&first.body).contains(&"idempotent_replay"),
            "{path}"
        );
        let replay = Http::post(addr, &path)
            .session(&tok)
            .idempotency_key(&key)
            .json(body)
            .await;
        assert_unwired(&replay);
        assert!(
            !warning_codes(&replay.body).contains(&"idempotent_replay"),
            "replay {path}"
        );
    }
    let keyless = Http::post(addr, "/client/grants/pending/t29-req:approve")
        .session(&tok)
        .json(json!({ "decision_revision": syntactic_revision() }))
        .await;
    assert_eq!(keyless.status, 400, "{:?}", keyless.body);
    assert_eq!(error_code(&keyless.body), "idempotency_required");
    assert_eq!(grant_snapshot(&probe, &root), s0);

    let tools = Http::get(addr, "/client/tools").session(&tok).send().await;
    assert_eq!(tools.status, 200, "{:?}", tools.body);
    assert_eq!(tools.body.get("data"), Some(&empty_tools()));

    let rec = probe.record();
    let mut caps: Vec<String> = KNOWN_CAPABILITIES.iter().map(|s| (*s).to_owned()).collect();
    caps.extend(["web".into(), "data".into()]);
    if let Some(req) = rec.root_request_set.as_ref() {
        for name in req {
            if !caps.iter().any(|cap| cap == name) {
                caps.push(name.clone());
            }
        }
    }
    let cap_refs: Vec<&str> = caps.iter().map(String::as_str).collect();
    let specs = registry_specs(&probe, &cap_refs);
    for banned in [
        "tool-invoke",
        "list-tools",
        "submit-component",
        "component-status",
        "kill-component",
        "list-components",
    ] {
        assert!(
            specs.iter().all(|(_, name)| name != banned),
            "{banned} in {specs:?}"
        );
    }
    assert!(
        specs
            .iter()
            .any(|(cap, name)| cap == "lifecycle" && name == "spawn-child"),
        "{specs:?}"
    );
    assert!(specs.iter().any(|(cap, _)| cap == "fs"), "{specs:?}");
    assert_eq!(
        rec.root_request_set.as_deref(),
        Some(["fs".to_owned(), "llm".to_owned()].as_slice())
    );

    drop(read);
    drop(rec);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_020_ac18_t29_a_plain_composition_without_extension_answers_the_same_views() {
    let _serial = SERIAL.lock().await;
    let home = home(FixtureHomeSpec {
        capabilities: granted(&["fs", "llm"]),
        driver: FixtureDriver::Minimal,
        git: false,
        providers_yaml: Some("llm-providers: []".into()),
    });
    let (rt, _log, probe, baseline) = compose_home(&home, vec![]).await;
    let rt = rt.expect("compose");
    let (addr, tok) = api(&rt);
    let root = rt.root_agent_id().to_owned();
    let read = read_port(&probe);

    send_message(addr, &tok, "t29-m1", "t29").await;
    let (run, task) = session_run(addr, &tok, &root).await;
    let turn = poll_turn_row(&read, &run, &root).await;
    let projected = poll_events_for_turn(addr, &tok, &run).await;
    assert_eq!(
        projected.get("run_id").and_then(Value::as_str),
        Some(run.as_str())
    );
    assert_eq!(
        projected.get("trace_id").and_then(Value::as_str),
        Some(turn.event.trace_id.as_str())
    );

    let run_history = stable_compare(
        &read,
        history_filter(Some(&run)),
        None,
        addr,
        &tok,
        &format!("/client/runs/{run}/history"),
    )
    .await;
    assert!(run_history
        .get("entries")
        .and_then(Value::as_array)
        .is_some_and(|entries| !entries.is_empty()));
    stable_compare(
        &read,
        history_filter(None),
        Some(&task),
        addr,
        &tok,
        &format!("/client/tasks/{task}/history"),
    )
    .await;

    let pending = Http::get(addr, "/client/grants/pending")
        .session(&tok)
        .send()
        .await;
    assert_eq!(pending.body.get("data"), Some(&empty_grants()));
    let tools = Http::get(addr, "/client/tools").session(&tok).send().await;
    assert_eq!(tools.body.get("data"), Some(&empty_tools()));

    let rec = probe.record();
    assert_eq!(
        rec.root_request_set.as_deref(),
        Some(["fs".to_owned(), "llm".to_owned()].as_slice())
    );
    drop(read);
    drop(rec);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_020_ac18_t29_b_no_driver_tools_view_and_read_families() {
    let _serial = SERIAL.lock().await;
    let home = home(FixtureHomeSpec {
        capabilities: granted(&["fs", "llm"]),
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    });
    let (rt, _log, probe, baseline) = compose_home(&home, vec![]).await;
    let rt = rt.expect("compose");
    assert!(!rt.health().agent_loop_up);
    let (addr, tok) = api(&rt);

    let tools = Http::get(addr, "/client/tools").session(&tok).send().await;
    assert_eq!(tools.status, 200, "{:?}", tools.body);
    assert_eq!(tools.body.get("data"), Some(&empty_tools()));
    let events = Http::get(addr, "/client/events").session(&tok).send().await;
    assert_eq!(events.status, 200, "{:?}", events.body);
    assert!(has_data(&events.body), "{:?}", events.body);
    let history = Http::get(addr, "/client/runs/x/history")
        .session(&tok)
        .send()
        .await;
    assert_eq!(history.status, 200, "{:?}", history.body);
    assert_eq!(history.body.get("data"), Some(&json!({"entries": []})));
    let pending = Http::get(addr, "/client/grants/pending")
        .session(&tok)
        .send()
        .await;
    assert_eq!(pending.body.get("data"), Some(&empty_grants()));
    assert!(probe.record().late_tools.is_none());

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_020_ac18_bind_time_tools_view_follows_the_skills_rule() {
    let _serial = SERIAL.lock().await;
    for (caps, expect_skill) in [
        (&["fs", "llm", "skills"][..], true),
        (&["fs", "llm"][..], false),
    ] {
        let home = home(FixtureHomeSpec {
            capabilities: granted(caps),
            driver: FixtureDriver::None,
            git: false,
            providers_yaml: None,
        });
        write_skill(&home, "echo-skill", 3);
        let (rt, _log, probe, baseline) = compose_home(&home, vec![]).await;
        let rt = rt.expect("compose");
        let (addr, tok) = api(&rt);
        let tools = Http::get(addr, "/client/tools").session(&tok).send().await;
        assert_eq!(tools.status, 200, "{:?}", tools.body);
        let data = tools.body.get("data").expect("data");
        assert_eq!(data.get("wasm"), Some(&json!([])));
        assert_eq!(data.get("mcp"), Some(&json!([])));
        if expect_skill {
            assert_eq!(
                data.get("skills"),
                Some(&json!([{
                    "skill_id": "echo-skill",
                    "version": 3,
                    "provenance": "imported",
                    "trust_level": "trusted"
                }]))
            );
        } else {
            assert_eq!(data.get("skills"), Some(&json!([])));
        }
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_020_ac18_t29_c_grant_without_lifecycle_never_lists_empty_while_a_request_is_parked()
{
    let _serial = SERIAL.lock().await;
    let home = home(FixtureHomeSpec {
        capabilities: granted(&["fs", "llm", "grant"]),
        driver: FixtureDriver::Minimal,
        git: false,
        providers_yaml: None,
    });
    let (rt, _log, probe, baseline) = compose_home(&home, vec![]).await;
    let rt = rt.expect("compose");
    let (addr, tok) = api(&rt);
    let root = rt.root_agent_id().to_owned();
    assert_eq!(
        park(
            &probe,
            ChannelApprovalRequest {
                request_id: "t29-c".into(),
                caller: root.clone(),
                capability: "fs".into(),
                params: None,
                ttl: cap_grant::GrantTtl::Once,
                justification: Some("t29".into()),
            }
        ),
        1
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let pending = Http::get(addr, "/client/grants/pending")
            .session(&tok)
            .send()
            .await;
        assert_ne!(pending.status, 200, "{:?}", pending.body);
        assert_unwired(&pending);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let grant_id = grant_snapshot(&probe, &root)
        .first()
        .map(|g| g.id.to_string())
        .unwrap_or_else(|| "g1".into());
    for (i, (path, body, _)) in grant_mutations(&root, &grant_id).into_iter().enumerate() {
        let key = format!("t29-c{}", i + 1);
        let resp = Http::post(addr, path)
            .session(&tok)
            .idempotency_key(&key)
            .json(body)
            .await;
        assert_unwired(&resp);
    }
    let events = Http::get(addr, "/client/events").session(&tok).send().await;
    assert_eq!(events.status, 200, "{:?}", events.body);
    let tools = Http::get(addr, "/client/tools").session(&tok).send().await;
    assert_eq!(tools.status, 200, "{:?}", tools.body);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_020_ac18_t29_d_lifecycle_grant_tools_home_keeps_the_bound_views_and_the_late_tools_install(
) {
    let _serial = SERIAL.lock().await;
    let home = home(FixtureHomeSpec {
        capabilities: granted(&["fs", "llm", "lifecycle", "grant", "tools"]),
        driver: FixtureDriver::Minimal,
        git: false,
        providers_yaml: None,
    });
    let (rt, _log, probe, baseline) = compose_home(&home, vec![]).await;
    let rt = rt.expect("compose");
    let (addr, tok) = api(&rt);
    let root = rt.root_agent_id().to_owned();

    let late = probe.record().late_tools.clone();
    let late = late.expect("late install ran");
    assert!(late.iter().any(|name| name == "data"), "{late:?}");
    let tools = Http::get(addr, "/client/tools").session(&tok).send().await;
    assert_eq!(tools.status, 200, "{:?}", tools.body);
    let wasm: Vec<String> = tools
        .body
        .pointer("/data/wasm")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("name").and_then(Value::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(wasm, late);
    assert_eq!(tools.body.pointer("/data/mcp"), Some(&json!([])));
    assert_eq!(tools.body.pointer("/data/skills"), Some(&json!([])));

    send_message(addr, &tok, "t29-d-m1", "t29").await;
    let (run, _task) = session_run(addr, &tok, &root).await;
    let deadline = Instant::now() + WAIT;
    let mut history = None;
    let mut bound_rejected = None;
    while Instant::now() < deadline {
        let resp = Http::get(addr, format!("/client/runs/{run}/history"))
            .session(&tok)
            .send()
            .await;
        if resp.status == 422 {
            // The bound adapter is installed: ordinary run.* events have
            // carriers but fail the history-schema redactor. The unbound
            // port would have answered 200 with params: [].
            assert_eq!(
                error_code(&resp.body),
                "projection_rejected",
                "{:?}",
                resp.body
            );
            assert_eq!(
                error_message(&resp.body),
                "bound observation projection rejected",
                "{:?}",
                resp.body
            );
            bound_rejected = Some(resp.body);
            break;
        }
        assert_eq!(resp.status, 200, "{:?}", resp.body);
        let entries = resp
            .body
            .pointer("/data/entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !entries.is_empty() {
            history = Some(entries);
            break;
        }
        tokio::time::sleep(POLL).await;
    }
    if let Some(entries) = history {
        for entry in &entries {
            let keys: Vec<&str> = entry
                .get("params")
                .and_then(Value::as_array)
                .map(|params| {
                    params
                        .iter()
                        .filter_map(|param| param.get("key").and_then(Value::as_str))
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(keys, ["api_key", "event_type", "id", "run_id"], "{entry}");
        }
    } else {
        bound_rejected.expect("bound history");
    }

    assert_eq!(
        park(
            &probe,
            ChannelApprovalRequest {
                request_id: "t29-d".into(),
                caller: root.clone(),
                capability: "fs".into(),
                params: None,
                ttl: cap_grant::GrantTtl::Once,
                justification: Some("t29".into()),
            }
        ),
        1
    );
    let pending = Http::get(addr, "/client/grants/pending")
        .session(&tok)
        .send()
        .await;
    assert_eq!(pending.status, 200, "{:?}", pending.body);
    let requests = pending
        .body
        .pointer("/data/requests")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(
        requests[0].get("request_id").and_then(Value::as_str),
        Some("t29-d")
    );
    assert!(
        requests[0]
            .get("decision_revision")
            .and_then(Value::as_str)
            .is_some_and(|rev| !rev.is_empty()),
        "{requests:?}"
    );

    let projected = poll_events_for_turn(addr, &tok, &run).await;
    assert_eq!(
        projected.get("event_type").and_then(Value::as_str),
        Some("run.round_completed")
    );

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_t111_2_d5_llm_deltas_pages_carry_a_resume_cursor_without_lifecycle() {
    let _serial = SERIAL.lock().await;
    let home = home(FixtureHomeSpec {
        capabilities: granted(&["fs", "llm"]),
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    });
    let (rt, _log, probe, baseline) = compose_home(&home, vec![]).await;
    let rt = rt.expect("compose");
    let (addr, tok) = api(&rt);
    let root = rt.root_agent_id().to_owned();
    let mut ws1 = deltas_ws(addr, &tok).await;
    ws_send(
        &mut ws1,
        json!({"stream_key": "t111-d5", "from_cursor": "not-a-sealed-token"}),
    )
    .await;
    let err = next_json(&mut ws1, Duration::from_secs(10)).await;
    assert_eq!(error_code(&err), "not_found", "{err}");

    let agent: std::sync::Arc<str> = root.as_str().into();
    let key: std::sync::Arc<str> = "t111-d5".into();
    // Publish before the subscribe frame so the first noteworthy page is the
    // stream itself (not the pre-admit absent page).
    publish_deltas(
        &probe,
        vec![
            LlmDeltaEvent {
                agent_id: Arc::clone(&agent),
                stream_key: Arc::clone(&key),
                frame: LlmDeltaFrame::Begin {
                    run_id: None,
                    task_id: None,
                },
            },
            LlmDeltaEvent {
                agent_id: Arc::clone(&agent),
                stream_key: Arc::clone(&key),
                frame: LlmDeltaFrame::Delta {
                    seq: 0,
                    text: "hello from t111-d5".into(),
                },
            },
            LlmDeltaEvent {
                agent_id: Arc::clone(&agent),
                stream_key: Arc::clone(&key),
                frame: LlmDeltaFrame::Delta {
                    seq: 1,
                    text: "more t111-d5 text".into(),
                },
            },
            LlmDeltaEvent {
                agent_id: agent,
                stream_key: key,
                frame: LlmDeltaFrame::Terminal {
                    seq: 2,
                    reason: LlmTerminalReason::Completed,
                    usage: None,
                },
            },
        ],
    );
    ws_send(&mut ws1, json!({"stream_key": "t111-d5"})).await;

    let deadline = Instant::now() + WAIT;
    let mut first_cursor = None;
    let mut last_seq = None;
    let mut saw_terminal = false;
    let mut pages = Vec::new();
    while Instant::now() < deadline {
        let page = next_json(&mut ws1, Duration::from_secs(2)).await;
        pages.push(page.clone());
        if !error_code(&page).is_empty() {
            panic!("unexpected error page {page}");
        }
        let deltas = page
            .pointer("/data/deltas")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !deltas.is_empty() {
            let cursor = page
                .pointer("/data/cursor")
                .and_then(Value::as_str)
                .expect("cursor on a page with deltas");
            assert!(!cursor.is_empty(), "{page}");
            if first_cursor.is_none() {
                first_cursor = Some(cursor.to_owned());
                last_seq = page.pointer("/data/to_seq").and_then(Value::as_u64);
            }
        }
        if page.pointer("/data/terminal").is_some() {
            saw_terminal = true;
            if first_cursor.is_some() {
                break;
            }
        }
        if page.pointer("/data/absent") == Some(&Value::Bool(true)) && first_cursor.is_some() {
            break;
        }
    }
    assert!(saw_terminal, "terminal page missing; pages={pages:?}");
    let cursor = first_cursor.unwrap_or_else(|| panic!("resume cursor; pages={pages:?}"));
    let seq_at_c = last_seq.expect("seq at c");

    let mut ws2 = deltas_ws(addr, &tok).await;
    ws_send(
        &mut ws2,
        json!({"stream_key": "t111-d5", "from_cursor": cursor}),
    )
    .await;
    let next = next_json(&mut ws2, Duration::from_secs(10)).await;
    assert_eq!(error_code(&next), "", "{next}");
    let from_seq = next.pointer("/data/from_seq").and_then(Value::as_u64);
    let terminal = next.pointer("/data/terminal").is_some();
    let absent = next.pointer("/data/absent") == Some(&Value::Bool(true));
    assert!(
        from_seq.is_some_and(|seq| seq > seq_at_c) || terminal || absent,
        "{next}"
    );

    let _ = ws1.close(None).await;
    let _ = ws2.close(None).await;
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

fn insert_session(api: &ClientApi) {
    api.sessions().insert(
        "tok".into(),
        ClientSession {
            session_id: "session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_020_ac18_unbound_history_adapter_serves_the_bound_window_over_a_real_event_bus() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = EventBusConfig::new(
        tmp.path().join("events-jsonl"),
        tmp.path().join("events.db"),
    );
    config.websocket_addr = "127.0.0.1:0".parse().unwrap();
    let bus = EventBus::new(config).await.expect("EventBus");
    let read = bus.read_api().expect("read API");
    let start = Utc.with_ymd_and_hms(2026, 10, 3, 12, 0, 0).unwrap();
    for i in 0..130 {
        let mut event = Event::observability("run.progress", "agent", json!({}), None);
        event.id = format!("E{i}");
        event.run_id = Some("r-1".into());
        event.task_id = Some(if i <= 9 || i >= 120 { "t-1" } else { "t-2" }.into());
        event.timestamp = start + chrono::Duration::milliseconds(i as i64);
        bus.emit(event);
    }
    let deadline = Instant::now() + WAIT;
    loop {
        let rows = read
            .query(
                &EventFilter {
                    run_id: Some("r-1".into()),
                    ..EventFilter::default()
                },
                1000,
            )
            .await
            .expect("query");
        if rows.len() >= 130 {
            break;
        }
        if Instant::now() >= deadline {
            panic!("indexed {} / 130", rows.len());
        }
        tokio::time::sleep(POLL).await;
    }

    let adapter = UnboundHistoryAdapter::new(Arc::clone(&read)).expect("adapter");
    let api = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(Arc::new(adapter) as Arc<dyn UnboundHistoryReadPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);

    let run = api.handle(ClientRequest::get("/client/runs/r-1/history").with_session("tok"));
    assert!(run.is_ok(), "{:?}", run.error);
    let entries = run
        .data
        .as_ref()
        .and_then(|data| data.get("entries"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(entries.len(), 100, "{entries:?}");
    let ids: Vec<&str> = entries
        .iter()
        .filter_map(|entry| entry.get("event_id").and_then(Value::as_str))
        .collect();
    let expected: Vec<String> = (30..130).rev().map(|i| format!("E{i}")).collect();
    assert_eq!(ids, expected.iter().map(String::as_str).collect::<Vec<_>>());
    for entry in &entries {
        assert_eq!(entry.get("params"), Some(&json!([])));
    }

    let task = api.handle(ClientRequest::get("/client/tasks/t-1/history").with_session("tok"));
    let task_ids: Vec<&str> = task
        .data
        .as_ref()
        .and_then(|data| data.get("entries"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("event_id").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let expected_task: Vec<String> = (120..130).rev().map(|i| format!("E{i}")).collect();
    assert_eq!(
        task_ids,
        expected_task.iter().map(String::as_str).collect::<Vec<_>>()
    );

    let mut cursor = ClientRequest::get("/client/tasks/t-1/history").with_session("tok");
    cursor.body = json!({"cursor": "E125"});
    let after = api.handle(cursor);
    let after_ids: Vec<&str> = after
        .data
        .as_ref()
        .and_then(|data| data.get("entries"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("event_id").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let expected_after: Vec<String> = (120..125).rev().map(|i| format!("E{i}")).collect();
    assert_eq!(
        after_ids,
        expected_after
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );

    let mut unknown = ClientRequest::get("/client/tasks/t-1/history").with_session("tok");
    unknown.body = json!({"cursor": "E5"});
    let missing = api.handle(unknown);
    assert_eq!(missing.error_code(), Some(ClientErrorCode::NotFound));

    drop(api);
    drop(read);
    bus.shutdown().await;
}
