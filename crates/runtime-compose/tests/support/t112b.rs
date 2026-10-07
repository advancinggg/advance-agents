//! Shared helpers of the MODULE-001-T112 (b) inference witnesses.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::CLIENT_WS_PROTOCOL;
use advance_runtime_compose::test_support::fixture::inference::provider_yaml;
use advance_runtime_compose::test_support::fixture::{
    mint_session, post_msg, CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec, HttpResponse,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, ComposeError, ComposeExtension, ComposedRuntime};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;

pub const POLL: Duration = Duration::from_millis(10);
pub const WAIT: Duration = Duration::from_secs(5);

pub const CREATE_LOCAL_TWO: &str = r#"{"provider_id":"local-two","backend_class":"local","model_aliases":{"default":"m2"},"cost":{"input_per_mtoken":0.01,"output_per_mtoken":0.01},"rate_limit":{"requests_per_minute":100,"tokens_per_minute":100000}}"#;

pub type WsClient = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

pub fn home(caps: &'static [&'static str], providers: &[&str]) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver: FixtureDriver::LlmNoErr,
        git: false,
        providers_yaml: Some(provider_yaml::llm_providers_block(providers)),
    })
    .expect("home")
}

pub fn append_runtime_config(home: &FixtureHome, yaml: &str) {
    let path = home.home().join(".advance/runtime-config.yaml");
    let mut text = std::fs::read_to_string(&path).expect("runtime-config");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(yaml);
    std::fs::write(path, text).expect("append runtime-config");
}

pub async fn compose_with(
    home: &FixtureHome,
    exts: Vec<Arc<dyn ComposeExtension>>,
) -> (
    Result<ComposedRuntime, ComposeError>,
    MemoryComposeLog,
    Arc<ComposeProbe>,
    usize,
) {
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let result = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        exts,
    )
    .await;
    (result, log, probe, baseline)
}

pub fn msg_addr(probe: &ComposeProbe) -> SocketAddr {
    probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound")
}

pub fn api(rt: &ComposedRuntime) -> (SocketAddr, String) {
    let endpoint = rt.client_api().expect("client api");
    let token = mint_session(&endpoint);
    (endpoint.socket_addr, token)
}

pub async fn msg(probe: &ComposeProbe, payload: &str) -> (u16, String) {
    post_msg(msg_addr(probe), payload).await
}

pub fn all_events(home: &Path) -> Vec<Value> {
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
            out.push(serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("jsonl line in {}: {error}: {line}", path.display())
            }));
        }
    }
    out
}

pub fn events(home: &Path, ty: &str) -> Vec<Value> {
    all_events(home)
        .into_iter()
        .filter(|event| event.get("event_type").and_then(Value::as_str) == Some(ty))
        .collect()
}

pub async fn wait_events(
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

pub fn jsonl_contains(home: &Path, needle: &str) -> bool {
    let dir = home.join(".runtime/events/jsonl");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    for entry in entries {
        let path = entry.expect("jsonl entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read jsonl");
        if text.contains(needle) {
            return true;
        }
    }
    false
}

pub async fn deltas_ws(addr: SocketAddr, token: &str) -> WsClient {
    let mut request = format!("ws://{addr}/client/llm/deltas/stream")
        .into_client_request()
        .expect("WebSocket request");
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}")
            .parse()
            .expect("protocol header"),
    );
    request.headers_mut().insert(
        ORIGIN,
        format!("http://{addr}").parse().expect("origin header"),
    );
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the Client API");
    let (mut ws, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("WebSocket handshake");
    let seed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return text.to_string(),
                Some(Ok(Message::Ping(payload))) => {
                    let _ = ws.send(Message::Pong(payload)).await;
                }
                other => panic!("unexpected frame before the seed: {other:?}"),
            }
        }
    })
    .await
    .expect("the seed frame arrives");
    let envelope: Value = serde_json::from_str(&seed).expect("seed json");
    assert_eq!(
        envelope.pointer("/data/subscribed"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    ws
}

pub fn restart_required_count(resp: &HttpResponse) -> usize {
    resp.body
        .get("warnings")
        .and_then(Value::as_array)
        .map(|warnings| {
            warnings
                .iter()
                .filter(|warning| {
                    warning.get("code").and_then(Value::as_str) == Some("restart_required")
                })
                .count()
        })
        .unwrap_or(0)
}

pub fn subsequence(haystack: &[&str], needle: &[&str]) -> bool {
    let mut rest = haystack;
    for wanted in needle {
        match rest.iter().position(|got| got == wanted) {
            Some(index) => rest = &rest[index + 1..],
            None => return false,
        }
    }
    true
}

pub fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

pub fn run_id(event: &Value) -> Option<&str> {
    event
        .get("run_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

pub fn provider_id(event: &Value) -> Option<&str> {
    event
        .pointer("/payload/provider_id")
        .and_then(Value::as_str)
}

pub fn provider(event: &Value) -> Option<&str> {
    event.pointer("/payload/provider").and_then(Value::as_str)
}
