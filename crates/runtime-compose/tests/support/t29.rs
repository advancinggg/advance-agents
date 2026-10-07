//! Shared helpers of the MODULE-020-T29 read-view witnesses.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::CLIENT_WS_PROTOCOL;
use advance_event_bus::{EventFilter, ObservabilityReadApi, ReadEvent};
use advance_runtime_compose::test_support::fixture::{mint_session, Http};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, ComposeError, ComposeExtension, ComposedRuntime};
use advance_shared_types::traits::{LlmDeltaEvent, LlmDeltaSink};
use cap_grant::{ChannelApprovalPort, ChannelApprovalRequest, Grant};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;

use advance_runtime_compose::test_support::fixture::{FixtureHome, FixtureHomeSpec};

pub const POLL: Duration = Duration::from_millis(10);
pub const WAIT: Duration = Duration::from_secs(10);

pub type WsClient = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

pub fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

pub async fn compose_home(
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

pub fn api(rt: &ComposedRuntime) -> (SocketAddr, String) {
    let endpoint = rt.client_api().expect("client api");
    let token = mint_session(&endpoint);
    (endpoint.socket_addr, token)
}

pub fn enc(s: &str) -> String {
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

pub fn query(path: &str, pairs: &[(&str, &str)]) -> String {
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

pub fn error_code(body: &Value) -> &str {
    body.pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("")
}

pub fn error_message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

pub fn has_data(body: &Value) -> bool {
    !body.get("data").is_none_or(Value::is_null)
}

pub fn warning_codes(body: &Value) -> Vec<&str> {
    body.get("warnings")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|warning| warning.get("code").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

pub async fn session_run(addr: SocketAddr, tok: &str, root: &str) -> (String, String) {
    let deadline = Instant::now() + WAIT;
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
            panic!("session run for {root} not listed within {WAIT:?}: {runs:?}");
        }
        tokio::time::sleep(POLL).await;
    }
}

pub fn read_port(probe: &ComposeProbe) -> Arc<dyn ObservabilityReadApi> {
    let bus = probe
        .record()
        .event_bus
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .expect("event bus");
    let read = bus.read_api().expect("production read API");
    drop(bus);
    read
}

pub fn history_oracle(rows: &[ReadEvent], task: Option<&str>) -> Vec<Value> {
    rows.iter()
        .filter(|row| task.is_none_or(|expected| row.event.task_id.as_deref() == Some(expected)))
        .map(|row| {
            json!({
                "event_id": row.event.id,
                "occurred_at": row.event.timestamp.to_rfc3339(),
                "kind": row.event.event_type,
                "summary": "observability event",
                "params": [],
            })
        })
        .collect()
}

pub async fn stable_compare(
    read: &Arc<dyn ObservabilityReadApi>,
    filter: EventFilter,
    task: Option<&str>,
    addr: SocketAddr,
    tok: &str,
    path: &str,
) -> Value {
    for _ in 0..20 {
        let first = history_oracle(&read.query(&filter, 100).await.expect("oracle query"), task);
        let resp = Http::get(addr, path).session(tok).send().await;
        let second = history_oracle(&read.query(&filter, 100).await.expect("oracle query"), task);
        if first == second {
            assert_eq!(resp.status, 200, "{path} {:?}", resp.body);
            assert!(has_data(&resp.body), "{path} {:?}", resp.body);
            let data = resp.body.get("data").cloned().expect("data");
            assert_eq!(
                data.get("entries").cloned().unwrap_or(Value::Null),
                json!(first),
                "{path} {data}"
            );
            assert!(
                data.get("next_cursor").is_none(),
                "next_cursor present: {data}"
            );
            let keys: Vec<&str> = data
                .as_object()
                .map(|object| object.keys().map(String::as_str).collect())
                .unwrap_or_default();
            assert_eq!(keys, vec!["entries"], "{data}");
            return data;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("history oracle did not settle within 20 attempts for {path}");
}

pub fn syntactic_revision() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode([0x5a; 185])
}

pub fn grant_snapshot(probe: &ComposeProbe, root: &str) -> Vec<Grant> {
    let store = probe
        .record()
        .grant_store
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .expect("grant store");
    let mut grants = store.list_by_grantee(root);
    drop(store);
    grants.sort_by(|a, b| format!("{:?}", a.id).cmp(&format!("{:?}", b.id)));
    grants
}

pub fn park(probe: &ComposeProbe, req: ChannelApprovalRequest) -> usize {
    let intake = probe
        .record()
        .grant_approval_intake
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .expect("grant approval intake");
    ChannelApprovalPort::request_approval(&*intake, req).expect("park");
    let n = intake.list_pending().len();
    drop(intake);
    n
}

pub fn registry_specs(probe: &ComposeProbe, caps: &[&str]) -> Vec<(String, String)> {
    let registry = probe
        .record()
        .host_registry
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .expect("host registry");
    let mut specs = Vec::new();
    for cap in caps {
        for spec in registry.lookup(cap) {
            specs.push((spec.capability, spec.name));
        }
    }
    drop(registry);
    specs
}

pub fn publish_deltas(probe: &ComposeProbe, events: Vec<LlmDeltaEvent>) {
    let hub = probe
        .record()
        .llm_delta_hub
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .expect("llm delta hub");
    for event in events {
        LlmDeltaSink::publish(&*hub, event);
    }
    drop(hub);
}

pub async fn send_message(addr: SocketAddr, tok: &str, key: &str, payload: &str) -> Value {
    let resp = Http::post(addr, "/client/messages")
        .session(tok)
        .idempotency_key(key)
        .json(json!({
            "to": format!("agent:{}", cap_lifecycle::identity::ROOT_HANDLE),
            "payload": payload,
        }))
        .await;
    assert_eq!(resp.status, 200, "{:?}", resp.body);
    let data = resp.body.get("data").cloned().expect("data");
    assert_eq!(
        data.get("delivery_state").and_then(Value::as_str),
        Some("delivered"),
        "{data}"
    );
    data
}

pub fn write_skill(home: &FixtureHome, id: &str, version: u32) {
    let dir = home.home().join(".agent/.agent/skills").join(id);
    std::fs::create_dir_all(&dir).expect("skill dir");
    std::fs::write(dir.join("SKILL.md"), "# Echo\n").expect("skill md");
    std::fs::write(
        dir.join(".meta.yaml"),
        format!("skill_id: {id}\nversion: {version}\nprovenance: Imported\ntrust_level: Trusted\n"),
    )
    .expect("meta");
}

async fn ws_handshake(addr: SocketAddr, token: &str, path: &str) -> WsClient {
    let mut request = format!("ws://{addr}{path}")
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
    let (ws, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("WebSocket handshake");
    ws
}

pub enum WsFrame {
    Json(Value),
    Timeout,
    Closed,
}

/// Read the next JSON envelope, answering pings. A Close / reset / end of
/// stream is `Closed` (the events pump drops the TCP socket without a Close
/// frame when a poll returns an error). A timeout is `Timeout`.
pub async fn try_next_json(ws: &mut WsClient, timeout: Duration) -> WsFrame {
    match tokio::time::timeout(timeout, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    return Ok(serde_json::from_str::<Value>(&text).expect("json"));
                }
                Some(Ok(Message::Ping(payload))) => {
                    let _ = ws.send(Message::Pong(payload)).await;
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return Err(()),
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    {
        Ok(Ok(value)) => WsFrame::Json(value),
        Ok(Err(())) => WsFrame::Closed,
        Err(_) => WsFrame::Timeout,
    }
}

pub async fn next_json(ws: &mut WsClient, timeout: Duration) -> Value {
    match try_next_json(ws, timeout).await {
        WsFrame::Json(value) => value,
        WsFrame::Timeout => panic!("json frame timed out after {timeout:?}"),
        WsFrame::Closed => panic!("socket closed before a json frame"),
    }
}

pub async fn events_ws(addr: SocketAddr, tok: &str, query: &str) -> (WsClient, Value) {
    let mut ws = ws_handshake(addr, tok, &format!("/client/events/stream{query}")).await;
    let seed = next_json(&mut ws, Duration::from_secs(10)).await;
    (ws, seed)
}

pub async fn deltas_ws(addr: SocketAddr, tok: &str) -> WsClient {
    let mut ws = ws_handshake(addr, tok, "/client/llm/deltas/stream").await;
    let seed = next_json(&mut ws, Duration::from_secs(10)).await;
    assert_eq!(
        seed.pointer("/data/subscribed"),
        Some(&Value::Bool(true)),
        "{seed}"
    );
    ws
}

pub async fn ws_send(ws: &mut WsClient, body: Value) {
    ws.send(Message::Text(body.to_string().into()))
        .await
        .expect("send");
}

pub fn home(spec: FixtureHomeSpec) -> FixtureHome {
    FixtureHome::new(spec).expect("home")
}
