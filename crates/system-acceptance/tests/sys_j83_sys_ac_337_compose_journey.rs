//! SYS-AC-337: production-compose journey legs (the extension family through the standard
//! gates, a turn on the extension's inference backend, shutdown then a second compose).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime_compose::compose;
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, FixtureInference, StubInferencePort,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_browser_session, post_msg, CapDecl, FixtureDriver, FixtureExtension,
    FixtureFamilies, FixtureHome, FixtureHomeSpec, Http, FIXTURE_ID,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use serde_json::{json, Value};

const POLL: Duration = Duration::from_millis(10);
const WAIT: Duration = Duration::from_secs(5);

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
