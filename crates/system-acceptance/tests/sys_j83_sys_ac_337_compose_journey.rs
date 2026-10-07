//! SYS-AC-337: production-compose journey legs (the extension family through the standard
//! gates, a turn on the extension's inference backend, the read families, shutdown then a
//! second compose) and the SYS-J-83 journey that runs them in one composition.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime_compose::compose;
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, FixtureInference, StubInferencePort,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_browser_session, mint_session, post_msg, CapDecl, FixtureDriver,
    FixtureExtension, FixtureFamilies, FixtureHome, FixtureHomeSpec, Http, FIXTURE_ID,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use serde_json::{json, Value};

const POLL: Duration = Duration::from_millis(10);
const WAIT: Duration = Duration::from_secs(5);
const READ_WAIT: Duration = Duration::from_secs(10);

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
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
    .expect("home")
}

fn error_code(body: &Value) -> &str {
    body.pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn has_data(body: &Value) -> bool {
    !body.get("data").is_none_or(Value::is_null)
}

fn events(home: &Path, ty: &str) -> Vec<Value> {
    let dir = home.join(".runtime/events/jsonl");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries {
        let path = entry.expect("jsonl entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read jsonl");
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("jsonl line in {}: {error}: {line}", path.display())
            });
            if event.get("event_type").and_then(Value::as_str) == Some(ty) {
                out.push(event);
            }
        }
    }
    out
}

async fn wait_events(
    home: &Path,
    ty: &str,
    pred: impl Fn(&Value) -> bool,
    n: usize,
    budget: Duration,
) -> Vec<Value> {
    let deadline = Instant::now() + budget;
    loop {
        let matched: Vec<Value> = events(home, ty).into_iter().filter(&pred).collect();
        if matched.len() >= n {
            return matched;
        }
        if Instant::now() >= deadline {
            panic!(
                "wait_events {ty} wanted {n} within {budget:?}, got {}: {matched:?}",
                matched.len()
            );
        }
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_337_j83_turn_routed_to_extension_inference_backend() {
    let home = turn_home();
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_inference(FixtureInference::standard(Arc::clone(&stub)))
            .arc()],
    )
    .await
    .expect("compose");

    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(addr, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    assert_eq!(stub.calls(), 1);
    let request = stub.requests().pop().expect("recorded chat");
    assert_eq!(request.provider_id, "local-stub");

    let requests = wait_events(
        home.home(),
        "llm.request",
        |event| {
            event
                .pointer("/payload/provider_id")
                .and_then(Value::as_str)
                == Some("local-stub")
        },
        1,
        WAIT,
    )
    .await;
    assert_eq!(requests.len(), 1, "{requests:?}");
    let responses = wait_events(
        home.home(),
        "llm.response",
        |event| event.pointer("/payload/provider").and_then(Value::as_str) == Some("local-stub"),
        1,
        WAIT,
    )
    .await;
    assert_eq!(responses.len(), 1, "{responses:?}");
    assert_eq!(responses[0]["payload"]["input_tokens"], 7);
    assert_eq!(responses[0]["payload"]["output_tokens"], 3);
    let cost = responses[0]["payload"]["cost_usd"]
        .as_f64()
        .expect("cost_usd");
    assert!(cost > 0.0, "{cost}");

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_337_fixture_family_answers_through_standard_gates() {
    let home = turn_home();
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_families(FixtureFamilies::standard())
            .with_inference(FixtureInference::standard(stub))
            .arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let origin = ep.base_url.clone();
    let (tok, _csrf) = mint_browser_session(&ep);

    let none = Http::get(addr, "/client/fixture/items").send().await;
    assert_eq!(none.status, 401, "{:?}", none.body);
    assert_eq!(error_code(&none.body), "unauthenticated");

    let items = Http::get(addr, "/client/fixture/items")
        .session(&tok)
        .send()
        .await;
    assert_eq!(items.status, 200, "{:?}", items.body);
    assert!(has_data(&items.body), "{:?}", items.body);

    let no_key = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .json(json!({}))
        .await;
    assert_eq!(no_key.status, 400, "{:?}", no_key.body);
    assert_eq!(error_code(&no_key.body), "idempotency_required");

    let created = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .idempotency_key("k-1")
        .json(json!({"name": "n"}))
        .await;
    assert_eq!(created.status, 200, "{:?}", created.body);
    assert!(has_data(&created.body), "{:?}", created.body);

    let no_csrf = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .origin(&origin)
        .idempotency_key("k-csrf")
        .json(json!({}))
        .await;
    assert_eq!(no_csrf.status, 403, "{:?}", no_csrf.body);
    assert_eq!(error_code(&no_csrf.body), "csrf_required");

    drop(ep);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_337_shutdown_then_second_compose_in_process() {
    let home = turn_home();

    async fn one_turn(home: &FixtureHome) {
        let stub = StubInferencePort::new("stub-pong", 7, 3);
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let rt = compose(
            home.options(Arc::new(log), Arc::clone(&probe)),
            vec![FixtureExtension::new(FIXTURE_ID)
                .with_inference(FixtureInference::standard(stub))
                .arc()],
        )
        .await
        .expect("compose");
        let addr = probe
            .record()
            .listener("post_msg")
            .expect("POST /msg is bound");
        let (status, body) = post_msg(addr, "llm:hi").await;
        assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }

    one_turn(&home).await;
    one_turn(&home).await;
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn query(path: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = String::from(path);
    out.push('?');
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(&enc(v));
    }
    out
}

async fn session_run(addr: SocketAddr, tok: &str, root: &str) -> (String, String) {
    let deadline = Instant::now() + READ_WAIT;
    loop {
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
            panic!("session run for {root} not listed within {READ_WAIT:?}: {runs:?}");
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn poll_round_completed(addr: SocketAddr, tok: &str, run: &str) -> Value {
    let deadline = Instant::now() + READ_WAIT;
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
        if let Some(event) = events.iter().find(|event| {
            event.get("event_type").and_then(Value::as_str) == Some("run.round_completed")
                && event.get("run_id").and_then(Value::as_str) == Some(run)
        }) {
            return event.clone();
        }
        if Instant::now() >= deadline {
            panic!("run.round_completed for {run} missing within {READ_WAIT:?}: {events:?}");
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn assert_history(addr: SocketAddr, tok: &str, path: &str) {
    let deadline = Instant::now() + READ_WAIT;
    loop {
        let resp = Http::get(addr, path).session(tok).send().await;
        assert_eq!(resp.status, 200, "{path} {:?}", resp.body);
        assert!(has_data(&resp.body), "{path} {:?}", resp.body);
        let data = resp.body.get("data").expect("data");
        assert!(data.get("next_cursor").is_none(), "next_cursor: {data}");
        let entries = data
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !entries.is_empty() {
            let mut saw_turn = false;
            for entry in &entries {
                assert_eq!(entry.get("params"), Some(&json!([])), "{entry}");
                assert_eq!(
                    entry.get("summary").and_then(Value::as_str),
                    Some("observability event"),
                    "{entry}"
                );
                let occurred = entry
                    .get("occurred_at")
                    .and_then(Value::as_str)
                    .expect("occurred_at");
                chrono::DateTime::parse_from_rfc3339(occurred)
                    .unwrap_or_else(|error| panic!("rfc3339 {occurred}: {error}"));
                if entry.get("kind").and_then(Value::as_str) == Some("run.round_completed") {
                    saw_turn = true;
                }
            }
            assert!(saw_turn, "{path} {entries:?}");
            return;
        }
        if Instant::now() >= deadline {
            panic!("{path} empty within {READ_WAIT:?}: {:?}", resp.body);
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn assert_read_families(addr: SocketAddr, tok: &str, run: &str, task: &str) {
    let _ = poll_round_completed(addr, tok, run).await;
    assert_history(addr, tok, &format!("/client/runs/{run}/history")).await;
    assert_history(addr, tok, &format!("/client/tasks/{task}/history")).await;
    for path in [
        format!("/client/runs/{run}/history"),
        format!("/client/tasks/{task}/history"),
    ] {
        let unknown = Http::get(addr, query(&path, &[("cursor", "no-such")]))
            .session(tok)
            .send()
            .await;
        assert_eq!(unknown.status, 404, "{path} {:?}", unknown.body);
        assert_eq!(error_code(&unknown.body), "not_found");
    }
    let pending = Http::get(addr, "/client/grants/pending")
        .session(tok)
        .send()
        .await;
    assert_eq!(pending.status, 200, "{:?}", pending.body);
    assert_eq!(pending.body.get("data"), Some(&json!({"requests": []})));
    let tools = Http::get(addr, "/client/tools").session(tok).send().await;
    assert_eq!(tools.status, 200, "{:?}", tools.body);
    assert_eq!(
        tools.body.get("data"),
        Some(&json!({"wasm": [], "mcp": [], "skills": []}))
    );
}

async fn resume_seed(addr: SocketAddr, tok: &str, stream_id: &str, last_event_id: &str, run: &str) {
    let deadline = Instant::now() + READ_WAIT;
    loop {
        let path = query(
            "/client/events/stream",
            &[
                ("stream_id", stream_id),
                ("last_event_id", last_event_id),
                ("event_type", "run.round_completed"),
                ("limit", "64"),
            ],
        );
        let resp = Http::get(addr, path).session(tok).send().await;
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
        if events.iter().any(|event| {
            event.get("event_type").and_then(Value::as_str) == Some("run.round_completed")
                && event.get("run_id").and_then(Value::as_str) == Some(run)
        }) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("stream resume missed {run} within {READ_WAIT:?}: {events:?}");
        }
        tokio::time::sleep(POLL).await;
    }
}

fn seed_cursor(body: &Value) -> (String, String) {
    let stream_id = body
        .pointer("/data/cursor/stream_id")
        .and_then(Value::as_str)
        .expect("stream_id")
        .to_owned();
    let last_event_id = body
        .pointer("/data/cursor/last_event_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    assert!(!stream_id.is_empty(), "{body}");
    (stream_id, last_event_id)
}

async fn assert_standard_gates(addr: SocketAddr, origin: &str, tok: &str) {
    let none = Http::get(addr, "/client/fixture/items").send().await;
    assert_eq!(none.status, 401, "{:?}", none.body);
    assert_eq!(error_code(&none.body), "unauthenticated");

    let items = Http::get(addr, "/client/fixture/items")
        .session(tok)
        .send()
        .await;
    assert_eq!(items.status, 200, "{:?}", items.body);
    assert!(has_data(&items.body), "{:?}", items.body);

    let no_key = Http::post(addr, "/client/fixture/items:create")
        .session(tok)
        .json(json!({}))
        .await;
    assert_eq!(no_key.status, 400, "{:?}", no_key.body);
    assert_eq!(error_code(&no_key.body), "idempotency_required");

    let created = Http::post(addr, "/client/fixture/items:create")
        .session(tok)
        .idempotency_key("k-1")
        .json(json!({"name": "n"}))
        .await;
    assert_eq!(created.status, 200, "{:?}", created.body);
    assert!(has_data(&created.body), "{:?}", created.body);

    let no_csrf = Http::post(addr, "/client/fixture/items:create")
        .session(tok)
        .origin(origin)
        .idempotency_key("k-csrf")
        .json(json!({}))
        .await;
    assert_eq!(no_csrf.status, 403, "{:?}", no_csrf.body);
    assert_eq!(error_code(&no_csrf.body), "csrf_required");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_337_read_families_answer_data_on_fs_llm_home() {
    let home = turn_home();
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_inference(FixtureInference::standard(stub))
            .arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let tok = mint_session(&ep);
    let root = rt.root_agent_id().to_owned();

    let seed = Http::get(
        addr,
        "/client/events/stream?event_type=run.round_completed&limit=0",
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(seed.status, 200, "{:?}", seed.body);
    let (stream_id, last_event_id) = seed_cursor(&seed.body);

    let post_addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(post_addr, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");

    let (run, task) = session_run(addr, &tok, &root).await;
    let _ = poll_round_completed(addr, &tok, &run).await;
    resume_seed(addr, &tok, &stream_id, &last_event_id, &run).await;
    assert_read_families(addr, &tok, &run, &task).await;

    drop(ep);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_337_journey_production_compose_fs_llm_home() {
    let home = turn_home();
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_families(FixtureFamilies::standard())
            .with_inference(FixtureInference::standard(Arc::clone(&stub)))
            .arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let origin = ep.base_url.clone();
    let (browser_tok, _csrf) = mint_browser_session(&ep);
    let root = rt.root_agent_id().to_owned();

    assert_standard_gates(addr, &origin, &browser_tok).await;
    let tok = mint_session(&ep);

    let seed = Http::get(
        addr,
        "/client/events/stream?event_type=run.round_completed&limit=0",
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(seed.status, 200, "{:?}", seed.body);
    let (stream_id, last_event_id) = seed_cursor(&seed.body);

    let post_addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(post_addr, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    assert_eq!(stub.calls(), 1);

    let (run, task) = session_run(addr, &tok, &root).await;
    let _ = poll_round_completed(addr, &tok, &run).await;
    resume_seed(addr, &tok, &stream_id, &last_event_id, &run).await;
    assert_read_families(addr, &tok, &run, &task).await;

    drop(ep);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;

    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_inference(FixtureInference::standard(stub))
            .arc()],
    )
    .await
    .expect("compose");
    let post_addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(post_addr, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
