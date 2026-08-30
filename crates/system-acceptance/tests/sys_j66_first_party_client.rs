//! SYS-J-66 — first-party Client API / console witness (SYS-AC-268..271).
//!
//! One wired journey at daemon / first-party-client altitude. Along ledger
//! flips (MODULE-020-AC-03/06/07/08) are out of this OSS tree.
//!
//! J66-T268  — SYS-AC-268: successful lists for runs / tree / grants / tools
//! J66-T268d — devices: versioned envelope only (not a list pass)
//! J66-T269a — SYS-AC-269 + AC-08: POST message → delivered + replied
//! J66-T269b — SYS-AC-269 + AC-07: pause settle / resume(manual) / cancel settle
//! J66-T269c — POST /client/runs → unknown_route
//! J66-T270  — SYS-AC-270 + AC-06: cursor resume + events history + run history
//! J66-T271  — SYS-AC-271 + AC-03: live assets + console-shaped HTTP/WS

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use advance_client_api::{
    ClientEnvelope, ClientEventPage, ClientSession, Platform, Principal, Scope, API_VERSION,
    CLIENT_WS_PROTOCOL,
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const HELLO_LLM: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const AGENT: &str = "agent:default";
const TOKEN: &str = "j66-operator-token";
const CSRF: &str = "j66-csrf";
const ECHO_TOOL: &str = "echo_tool";

type Sock = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct ClientHttp {
    addr: SocketAddr,
    origin: String,
    idem: std::sync::atomic::AtomicU64,
}

impl ClientHttp {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            origin: format!("http://{addr}"),
            idem: std::sync::atomic::AtomicU64::new(1),
        }
    }

    async fn raw(
        &self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> (u16, String, String) {
        let mut stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("tcp connect");
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.addr
        );
        for (name, value) in extra_headers {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = body {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
            req.push_str("\r\n");
            req.push_str(body);
        } else {
            req.push_str("\r\n");
        }
        stream.write_all(req.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let text = String::from_utf8_lossy(&buf).into_owned();
        let (head, rest) = text.split_once("\r\n\r\n").expect("header/body");
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, head.to_string(), rest.to_string())
    }

    async fn envelope(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        mutation: bool,
    ) -> ClientEnvelope<Value> {
        let authorization = format!("Bearer {TOKEN}");
        let idem = format!(
            "j66-idem-{}",
            self.idem.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        let body_text = body.map(|v| v.to_string());
        let mut headers = vec![
            ("x-advance-api-version", API_VERSION),
            ("authorization", authorization.as_str()),
            ("origin", self.origin.as_str()),
        ];
        if mutation {
            headers.push(("x-csrf-token", CSRF));
            headers.push(("idempotency-key", idem.as_str()));
        }
        if body_text.is_some() {
            headers.push(("content-type", "application/json"));
        }
        let (_status, _head, resp) = self.raw(method, path, &headers, body_text.as_deref()).await;
        serde_json::from_str(&resp).unwrap_or_else(|e| {
            panic!("ClientEnvelope parse failed for {method} {path}: {e}; body={resp}")
        })
    }

    async fn ok(&self, method: &str, path: &str, body: Option<Value>, mutation: bool) -> Value {
        let env = self.envelope(method, path, body, mutation).await;
        assert!(env.is_ok(), "{method} {path} errored: {:?}", env.error);
        env.data.expect("data")
    }
}

fn install_operator(api: &advance_client_api::ClientApi) {
    api.sessions().insert(
        TOKEN.to_string(),
        ClientSession {
            session_id: "j66-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some(CSRF.into()),
            expires_at: u64::MAX,
        },
        0,
    );
}

async fn connect_events(port: u16, origin: &str) -> Sock {
    // Same drain-window retry as console_reconnect_e2e: the single stream slot
    // can still be held while a just-closed websocket_loop exits.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut request = format!("ws://127.0.0.1:{port}/client/events/stream")
            .into_client_request()
            .unwrap();
        let protocols = format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{TOKEN}");
        request
            .headers_mut()
            .insert(SEC_WEBSOCKET_PROTOCOL, protocols.parse().unwrap());
        request
            .headers_mut()
            .insert(ORIGIN, origin.parse().unwrap());
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => return socket,
            Err(tokio_tungstenite::tungstenite::Error::Http(resp))
                if resp.status() == 429 && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => panic!("events ws connect: {e:?}"),
        }
    }
}

async fn next_text(socket: &mut Sock, timeout: Duration) -> Option<String> {
    tokio::time::timeout(timeout, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Text(t))) => return Some(t.to_string()),
                Some(Ok(Message::Ping(b))) => {
                    if socket.send(Message::Pong(b)).await.is_err() {
                        return None;
                    }
                }
                Some(Ok(Message::Close(_))) | None => return None,
                Some(Ok(_)) => {}
                Some(Err(_)) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn read_event_page(socket: &mut Sock, timeout: Duration) -> Option<ClientEventPage> {
    let text = next_text(socket, timeout).await?;
    let envelope: ClientEnvelope<Value> = serde_json::from_str(&text).unwrap();
    assert!(
        envelope.is_ok(),
        "event frame errored: {:?}",
        envelope.error
    );
    Some(serde_json::from_value(envelope.data.unwrap()).unwrap())
}

async fn read_seed(socket: &mut Sock) -> ClientEventPage {
    let page = read_event_page(socket, Duration::from_secs(5))
        .await
        .expect("seed frame");
    page
}

async fn send_frame(socket: &mut Sock, body: Value) {
    socket
        .send(Message::Text(body.to_string().into()))
        .await
        .expect("send frame");
}

async fn drain_events_until<F>(
    socket: &mut Sock,
    overall: Duration,
    mut done: F,
    require_done: bool,
) -> (Vec<Value>, Option<Value>)
where
    F: FnMut(&[Value]) -> bool,
{
    let deadline = Instant::now() + overall;
    let mut events = Vec::new();
    let mut cursor = None;
    let mut quiet_rounds = 0u8;
    let mut satisfied = false;
    while Instant::now() < deadline {
        if done(&events) {
            satisfied = true;
        }
        let remain = deadline.saturating_duration_since(Instant::now());
        match read_event_page(socket, remain.min(Duration::from_secs(1))).await {
            Some(page) => {
                quiet_rounds = 0;
                if let Some(c) = page.cursor {
                    cursor = Some(serde_json::to_value(c).unwrap());
                }
                for ev in page.events {
                    events.push(serde_json::to_value(ev).unwrap());
                }
            }
            None => {
                if events.is_empty() {
                    continue;
                }
                if require_done && !satisfied {
                    continue;
                }
                quiet_rounds += 1;
                if quiet_rounds >= 2 {
                    break;
                }
            }
        }
    }
    (events, cursor)
}

async fn drain_events(socket: &mut Sock, overall: Duration) -> (Vec<Value>, Option<Value>) {
    drain_events_until(socket, overall, |_| false, false).await
}

fn event_type_is(events: &[Value], event_type: &str) -> bool {
    events.iter().any(|e| e["event_type"] == event_type)
}

fn rfc3339_eq(left: &Value, right: &Value) -> bool {
    let left = left.as_str().unwrap_or("");
    let right = right.as_str().unwrap_or("");
    match (
        chrono::DateTime::parse_from_rfc3339(left),
        chrono::DateTime::parse_from_rfc3339(right),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => left == right,
    }
}

fn projected_row_matches_live(event: &Value, live: &Value) -> bool {
    event["event_type"] == live["event_type"]
        && rfc3339_eq(&event["timestamp"], &live["timestamp"])
        && event["run_id"] == live["run_id"]
        && event["trace_id"] == live["trace_id"]
        && event["agent_id"] == live["agent_id"]
        && event["data"] == live["data"]
}

fn history_matches_live(entry: &Value, live: &Value) -> bool {
    entry["kind"] == live["event_type"]
        && rfc3339_eq(&entry["occurred_at"], &live["timestamp"])
        && entry.get("id").is_none()
        && entry.get("event_id").is_some()
}

async fn wait_client_events(
    http: &ClientHttp,
    run_id: Option<&str>,
    event_type: Option<&str>,
    live: Option<&Value>,
) -> Value {
    let run_id = run_id.map(str::to_owned);
    let event_type = event_type.map(str::to_owned);
    let live = live.cloned();
    wait_json(
        || {
            let http = http;
            let run_id = run_id.clone();
            let event_type = event_type.clone();
            let live = live.clone();
            async move {
                let mut path = format!("/client/events?agent_id={AGENT}&limit=64");
                if let Some(rid) = run_id.as_ref() {
                    path.push_str("&run_id=");
                    path.push_str(rid);
                }
                if let Some(et) = event_type.as_ref() {
                    path.push_str("&event_type=");
                    path.push_str(et);
                }
                let env = http.envelope("GET", &path, None, false).await;
                let data = env.data?;
                let evs = data.get("events").and_then(|v| v.as_array())?;
                let type_ok = match event_type.as_deref() {
                    Some(et) => evs.iter().any(|e| e["event_type"] == et),
                    None => !evs.is_empty(),
                };
                let live_ok = match live.as_ref() {
                    Some(live) => evs.iter().any(|e| projected_row_matches_live(e, live)),
                    None => true,
                };
                if type_ok && live_ok {
                    Some(data)
                } else {
                    None
                }
            }
        },
        "GET /client/events projected page",
    )
    .await
}

async fn wait_history_kind(http: &ClientHttp, run_id: &str, live: &Value) -> Value {
    let run_id = run_id.to_owned();
    let live = live.clone();
    wait_json(
        || {
            let http = http;
            let run_id = run_id.clone();
            let live = live.clone();
            async move {
                let env = http
                    .envelope(
                        "GET",
                        &format!("/client/runs/{run_id}/history"),
                        None,
                        false,
                    )
                    .await;
                let data = env.data?;
                let entries = data.get("entries").and_then(|v| v.as_array())?;
                let bound = entries.iter().all(|e| {
                    e.get("event_id").is_some() && e.get("kind").is_some() && e.get("id").is_none()
                });
                if bound && entries.iter().any(|e| history_matches_live(e, &live)) {
                    Some(data)
                } else {
                    None
                }
            }
        },
        "GET /client/runs/{id}/history projected kind",
    )
    .await
}

async fn wait_json<F, Fut>(mut probe: F, what: &str) -> Value
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<Value>>,
{
    let start = Instant::now();
    loop {
        if let Some(v) = probe().await {
            return v;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_j66_first_party_client_journey() {
    let mut sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Tools])
        .agent_id(AGENT)
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("j66-turn-1", 7, 9),
            ScriptedResponse::ok_chat("j66-turn-2", 7, 9),
            ScriptedResponse::ok_chat("j66-turn-3", 7, 9),
        ]))
        .with_first_party_client()
        .build(HELLO_LLM)
        .await;

    assert!(
        sut.run_manager().is_some(),
        "first-party axis must retain RunManager"
    );
    let server = sut.client_api_server().expect("first-party Client API");
    install_operator(server.api().as_ref());
    let addr = server.local_addr();
    let http = ClientHttp::new(addr);
    let origin = http.origin.clone();
    let port = addr.port();

    // ── J66-T271: live-served console assets + console-shaped headers ──
    let (app_status, _, app_js) = http.raw("GET", "/app.js", &[], None).await;
    assert_eq!(app_status, 200, "live GET /app.js");
    assert!(app_js.contains("/client/runs"), "console lists runs");
    assert!(
        app_js.contains("/client/messages"),
        "console sends messages"
    );
    assert!(app_js.contains("/client/tools"), "console lists tools");
    assert!(
        app_js.contains("requestEnvelope"),
        "devices must use a non-throwing envelope reader"
    );
    assert!(
        app_js.contains("\"manual\"") || app_js.contains("reason: \"manual\""),
        "resume uses reason manual"
    );
    assert!(
        app_js.contains("connectDashboard();") && app_js.contains("Promise.allSettled"),
        "login must connect the dashboard even if list refreshes fail"
    );
    let (idx_status, _, idx) = http.raw("GET", "/index.html", &[], None).await;
    assert_eq!(idx_status, 200, "live GET /index.html");
    assert!(idx.contains("id=\"runs\"") || idx.contains("id=\"run-list\""));
    let (query_status, _, query_body) = http.raw("GET", "/query", &[], None).await;
    assert!(
        query_status != 200 || !query_body.contains("\"api_version\""),
        "internal /query is not a Client API surface; got {query_status} {query_body}"
    );
    let (q2_status, _, _) = http.raw("GET", "/query/events", &[], None).await;
    assert_ne!(q2_status, 200, "GET /query/events is not live-served");

    // ── J66-T268: successful lists (not devices) ──
    let runs = http.ok("GET", "/client/runs", None, false).await;
    assert!(runs.get("runs").and_then(|v| v.as_array()).is_some());
    let tree = http.ok("GET", "/client/runs/tree", None, false).await;
    let nodes = tree["nodes"].as_array().expect("tree.nodes");
    assert!(
        nodes.iter().any(|n| n["id"] == AGENT),
        "tree must contain {AGENT}: {tree}"
    );
    let grants = http.ok("GET", "/client/grants/pending", None, false).await;
    assert!(
        grants.get("requests").and_then(|v| v.as_array()).is_some(),
        "grants.requests must be an array: {grants}"
    );
    let tools = http.ok("GET", "/client/tools", None, false).await;
    let wasm = tools["wasm"].as_array().expect("tools.wasm");
    assert!(
        wasm.iter().any(|t| t["name"] == ECHO_TOOL),
        "tools must include seeded {ECHO_TOOL}: {tools}"
    );
    assert!(
        wasm.iter()
            .all(|t| t["name"] != "wasmtool" && t["name"] != "mcptool"),
        "synthetic assembler names must not be the tools witness: {tools}"
    );

    // ── J66-T268d: devices is a versioned envelope, not a list pass ──
    let devices = http.envelope("GET", "/client/devices", None, false).await;
    assert_eq!(devices.api_version, API_VERSION);
    assert!(
        devices.error.is_some(),
        "OSS must not privately mint a devices list"
    );
    assert!(
        devices.data.is_none(),
        "devices data must stay absent on OSS"
    );

    // ── J66-T269c: run creation is not POST /client/runs ──
    let created = http
        .envelope("POST", "/client/runs", Some(json!({})), true)
        .await;
    assert_eq!(
        created.error.as_ref().map(|e| e.code.as_str()),
        Some("unknown_route")
    );

    // ── Live event stream (console-shaped) ──
    let mut ws = connect_events(port, &origin).await;
    let seed = read_seed(&mut ws).await;
    assert!(seed.events.is_empty(), "seed must be empty-join");
    send_frame(&mut ws, json!({ "agent_id": AGENT, "limit": 16 })).await;

    // ── J66-T269a: messaging + fulfill → replied ──
    let ack = http
        .ok(
            "POST",
            "/client/messages",
            Some(json!({ "to": AGENT, "payload": "hello-j66-1" })),
            true,
        )
        .await;
    assert_eq!(ack["delivery_state"], "delivered");
    let message_id = ack["message_id"].as_str().expect("message_id").to_string();
    sut.run_turn().await;
    let status = wait_json(
        || {
            let http = &http;
            let message_id = message_id.clone();
            async move {
                let env = http
                    .envelope(
                        "GET",
                        &format!("/client/messages/{message_id}"),
                        None,
                        false,
                    )
                    .await;
                let data = env.data?;
                if data["delivery_state"] == "delivered" && data["reply_state"] == "replied" {
                    Some(data)
                } else {
                    None
                }
            }
        },
        "message replied",
    )
    .await;
    assert_eq!(status["reply_state"], "replied");
    assert_eq!(status["delivery_state"], "delivered");

    let run_list = wait_json(
        || {
            let http = &http;
            async move {
                let data = http.ok("GET", "/client/runs", None, false).await;
                data["runs"].as_array().and_then(|runs| {
                    runs.iter()
                        .find(|r| r["controller_agent"] == AGENT)
                        .cloned()
                })
            }
        },
        "run appears",
    )
    .await;
    let run_id = run_list["run_id"].as_str().expect("run_id").to_string();
    assert_eq!(run_list["status"], "active");

    let (first_events, first_cursor) = drain_events(&mut ws, Duration::from_secs(8)).await;
    assert!(
        !first_events.is_empty(),
        "first turn must project at least one client event"
    );
    let live_event = first_events
        .iter()
        .find(|e| e["event_type"].as_str().is_some() && e["timestamp"].as_str().is_some())
        .cloned()
        .expect("live projected event");
    let cursor = first_cursor.expect("cursor after first-turn events");

    // ── T270 disconnect window: close, then settle pause (new projected events) ──
    ws.close(None).await.ok();
    drop(ws);

    let paused = http
        .ok(
            "POST",
            &format!("/client/runs/{run_id}:pause"),
            Some(json!({})),
            true,
        )
        .await;
    assert_eq!(paused["run_id"], run_id);

    let ack2 = http
        .ok(
            "POST",
            "/client/messages",
            Some(json!({ "to": AGENT, "payload": "hello-j66-2" })),
            true,
        )
        .await;
    assert_eq!(ack2["delivery_state"], "delivered");
    sut.run_turn().await;
    let after_pause = wait_json(
        || {
            let http = &http;
            let run_id = run_id.clone();
            async move {
                let data = http.ok("GET", "/client/runs", None, false).await;
                data["runs"].as_array().and_then(|runs| {
                    runs.iter()
                        .find(|r| r["run_id"] == run_id && r["status"] == "paused")
                        .cloned()
                })
            }
        },
        "run paused after complete_round",
    )
    .await;
    assert_eq!(after_pause["status"], "paused");

    // ── J66-T270: reconnect with filter + cursor; no pre-cursor redelivery ──
    let mut ws2 = connect_events(port, &origin).await;
    let _ = read_seed(&mut ws2).await;
    send_frame(
        &mut ws2,
        json!({
            "agent_id": AGENT,
            "stream_id": cursor["stream_id"],
            "last_event_id": cursor["last_event_id"],
            "limit": 16
        }),
    )
    .await;
    let (resume_events, _) = drain_events_until(
        &mut ws2,
        Duration::from_secs(15),
        |evs| event_type_is(evs, "run.paused"),
        true,
    )
    .await;
    assert_eq!(
        resume_events
            .iter()
            .filter(|e| e["event_type"] == "run.paused")
            .count(),
        1,
        "disconnect-window run.paused must arrive exactly once: {resume_events:?}"
    );
    let paused_live = resume_events
        .iter()
        .find(|e| e["event_type"] == "run.paused")
        .cloned()
        .expect("live run.paused");
    for ev in &resume_events {
        assert!(
            !first_events
                .iter()
                .any(|pre| projected_row_matches_live(ev, pre)),
            "pre-cursor projected row redelivered: {ev}"
        );
        if let Some(agent) = ev["agent_id"].as_str() {
            assert_eq!(agent, AGENT);
        }
    }
    ws2.close(None).await.ok();

    let events_hist = wait_client_events(&http, None, None, Some(&live_event)).await;
    assert!(
        events_hist["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| projected_row_matches_live(e, &live_event)),
        "GET /client/events must include the live projected row: live={live_event} {events_hist}"
    );
    let first_hist = wait_history_kind(&http, &run_id, &live_event).await;
    assert!(
        first_hist["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| history_matches_live(e, &live_event)),
        "bound run history must contain the first-turn live row: {first_hist}"
    );
    let paused_hist =
        wait_client_events(&http, Some(&run_id), Some("run.paused"), Some(&paused_live)).await;
    assert!(
        paused_hist["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| projected_row_matches_live(e, &paused_live)),
        "GET /client/events must project the live run.paused row: {paused_hist}"
    );
    let run_hist = wait_history_kind(&http, &run_id, &paused_live).await;
    assert!(
        run_hist["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| history_matches_live(e, &paused_live)),
        "bound run history must contain the live run.paused row: {run_hist}"
    );

    // ── J66-T269b: resume(manual) then cancel + settle ──
    let resumed = http
        .ok(
            "POST",
            &format!("/client/runs/{run_id}:resume"),
            Some(json!({ "reason": "manual" })),
            true,
        )
        .await;
    assert_eq!(resumed["status"], "active");
    let resumed_hist = wait_client_events(&http, Some(&run_id), Some("run.resumed"), None).await;
    let resumed_live = resumed_hist["events"]
        .as_array()
        .and_then(|evs| evs.iter().find(|e| e["event_type"] == "run.resumed"))
        .cloned()
        .expect("projected run.resumed");
    let _ = wait_history_kind(&http, &run_id, &resumed_live).await;
    let _ = http
        .ok(
            "POST",
            &format!("/client/runs/{run_id}:cancel"),
            Some(json!({})),
            true,
        )
        .await;
    let ack3 = http
        .ok(
            "POST",
            "/client/messages",
            Some(json!({ "to": AGENT, "payload": "hello-j66-3" })),
            true,
        )
        .await;
    assert_eq!(ack3["delivery_state"], "delivered");
    sut.run_turn().await;
    let cancelled = wait_json(
        || {
            let http = &http;
            let run_id = run_id.clone();
            async move {
                let data = http.ok("GET", "/client/runs", None, false).await;
                data["runs"].as_array().and_then(|runs| {
                    runs.iter()
                        .find(|r| r["run_id"] == run_id && r["status"] == "cancelled")
                        .cloned()
                })
            }
        },
        "run cancelled after complete_round",
    )
    .await;
    assert_eq!(cancelled["status"], "cancelled");
    let cancelled_hist =
        wait_client_events(&http, Some(&run_id), Some("run.cancelled"), None).await;
    let cancelled_live = cancelled_hist["events"]
        .as_array()
        .and_then(|evs| evs.iter().find(|e| e["event_type"] == "run.cancelled"))
        .cloned()
        .expect("projected run.cancelled");
    let _ = wait_history_kind(&http, &run_id, &cancelled_live).await;

    sut.shutdown_event_bus().await;
}
