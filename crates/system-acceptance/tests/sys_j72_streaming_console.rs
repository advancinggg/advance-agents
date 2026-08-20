//! SYS-J-72 — live console token-delta streaming (SYS-AC-306/307/308) plus
//! MODULE-009-AC-30 live-hub / hold witnesses.

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::{
    ClientEnvelope, ClientSession, LlmDeltaWirePage, Platform, Principal, Scope, CLIENT_WS_PROTOCOL,
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use system_acceptance::llm_loopback::{ScriptedResponse, SseEvent, SseGate};
use system_acceptance::{Cap, LlmMode, SystemUnderTest};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const STREAM_CORE: &[u8] = include_bytes!("fixtures/guest-rust-llm-stream.core.wasm");
const ABANDON_CORE: &[u8] = include_bytes!("fixtures/guest-rust-llm-stream-abandon.core.wasm");

const TOKEN: &str = "j72-operator-token";
const CLEAN: &str = "hello streaming world";
/// First incremental page wait: < SseGate's 1500 ms abandon, with slack for
/// poll-stream → tee publish → hub generation → WS page.
const FIRST_PAGE: Duration = Duration::from_millis(1400);
/// Undotted Bearer token matching `bearer_token` (`Bearer\s+eyJ[A-Za-z0-9_-]+`).
const SECRET: &str = "Bearer eyJhbGciOiJIUzI1NiJ9secretpayload42";
const SECRET_A: &str = "Bearer ey";
const SECRET_B: &str = "JhbGciOiJIUzI1NiJ9secretpayload42";

type Sock = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn openai_delta(content: &str) -> SseEvent {
    SseEvent {
        event: None,
        data: json!({
            "choices": [{
                "index": 0,
                "delta": { "content": content },
                "finish_reason": Value::Null
            }]
        })
        .to_string(),
    }
}

fn openai_finish() -> SseEvent {
    SseEvent {
        event: None,
        data: json!({
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 7, "completion_tokens": 9 }
        })
        .to_string(),
    }
}

fn openai_done() -> SseEvent {
    SseEvent {
        event: None,
        data: "[DONE]".to_string(),
    }
}

fn clean_events() -> Vec<SseEvent> {
    let mut events: Vec<SseEvent> = CLEAN.split_inclusive(' ').map(openai_delta).collect();
    events.push(openai_finish());
    events.push(openai_done());
    events
}

fn hold_events() -> Vec<SseEvent> {
    vec![
        openai_delta(SECRET_A),
        openai_delta(SECRET_B),
        openai_finish(),
        openai_done(),
    ]
}

fn install_operator(api: &advance_client_api::ClientApi) {
    api.sessions().insert(
        TOKEN.to_string(),
        ClientSession {
            session_id: "j72-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("j72-csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );
}

async fn try_connect_delta(
    port: u16,
    origin: &str,
) -> Result<Sock, tokio_tungstenite::tungstenite::Error> {
    let mut request = format!("ws://127.0.0.1:{port}/client/llm/deltas/stream")
        .into_client_request()
        .unwrap();
    let protocols = format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{TOKEN}");
    request
        .headers_mut()
        .insert(SEC_WEBSOCKET_PROTOCOL, protocols.parse().unwrap());
    request
        .headers_mut()
        .insert(ORIGIN, origin.parse().unwrap());
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(socket, _)| socket)
}

async fn connect_delta(port: u16, origin: &str) -> Sock {
    try_connect_delta(port, origin).await.expect("ws connect")
}

fn upgrade_status(err: &tokio_tungstenite::tungstenite::Error) -> Option<u16> {
    match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => Some(resp.status().as_u16()),
        _ => None,
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

async fn read_delta_seed(socket: &mut Sock) {
    let text = next_text(socket, Duration::from_secs(5))
        .await
        .expect("seed frame");
    let envelope: ClientEnvelope<Value> = serde_json::from_str(&text).unwrap();
    assert!(envelope.is_ok(), "seed errored: {:?}", envelope.error);
    assert_eq!(envelope.data.unwrap()["subscribed"], json!(true));
}

async fn send_frame(socket: &mut Sock, body: Value) {
    socket
        .send(Message::Text(body.to_string().into()))
        .await
        .expect("send frame");
}

async fn read_delta_wire_page(socket: &mut Sock, timeout: Duration) -> Option<LlmDeltaWirePage> {
    let text = next_text(socket, timeout).await?;
    let envelope: ClientEnvelope<Value> = serde_json::from_str(&text).unwrap();
    assert!(
        envelope.is_ok(),
        "delta frame errored: {:?}",
        envelope.error
    );
    Some(serde_json::from_value(envelope.data.unwrap()).unwrap())
}

async fn drain_until_close(socket: &mut Sock, overall: Duration) -> (bool, bool) {
    let deadline = Instant::now() + overall;
    let mut saw_close = false;
    let mut text_after_close = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match tokio::time::timeout(deadline - now, socket.next()).await {
            Err(_) | Ok(None) => break,
            Ok(Some(Ok(Message::Text(_)))) => {
                if saw_close {
                    text_after_close = true;
                }
            }
            Ok(Some(Ok(Message::Close(_)))) => saw_close = true,
            Ok(Some(Ok(Message::Ping(b)))) => {
                let _ = socket.send(Message::Pong(b)).await;
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) => break,
        }
    }
    (saw_close, text_after_close)
}

fn decoded_chunks(events: &[SseEvent]) -> Vec<String> {
    let mut out = Vec::new();
    for ev in events {
        if ev.data == "[DONE]" {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(&ev.data) {
            if let Some(c) = v
                .pointer("/choices/0/delta/content")
                .and_then(|x| x.as_str())
            {
                out.push(c.to_string());
            }
        }
    }
    out
}

fn decoded_contents(events: &[SseEvent]) -> String {
    decoded_chunks(events).concat()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t119_notwired_without_tee_axis() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            CLEAN, 7, 9,
        )]))
        .build(STREAM_CORE)
        .await;
    assert!(!sut.llm_gateway().expect("loopback").delta_sink().is_wired());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t119_live_and_sys_ac_306() {
    let gate = SseGate::new();
    let events = clean_events();
    let n_events = events.len();
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::sse(
            200,
            events.clone(),
        )
        .with_gate(gate.clone())]))
        .with_delta_tee()
        .with_reply_capture()
        .build(STREAM_CORE)
        .await;
    assert!(sut.llm_gateway().unwrap().delta_sink().is_wired());
    let server = sut.client_api_server().expect("client api");
    install_operator(server.api().as_ref());
    let origin = format!("http://{}", server.local_addr());
    let port = server.local_addr().port();
    let sink = sut.capturing_sink().expect("capturing sink");
    sut.inject_message("j72", CLEAN.as_bytes()).await;

    let ((), first_concat) = tokio::join!(sut.run_turns(1), async {
        let key = sink
            .wait_begin_key(Duration::from_secs(5))
            .await
            .expect("Begin stream_key");
        let mut ws = connect_delta(port, &origin).await;
        read_delta_seed(&mut ws).await;
        send_frame(&mut ws, json!({ "stream_key": key })).await;
        gate.release(1);
        let page = read_delta_wire_page(&mut ws, FIRST_PAGE)
            .await
            .expect("first incremental page");
        assert!(
            !page.absent && !page.deltas.is_empty() && page.terminal.is_none(),
            "first page must be in-flight content, not absent or terminal"
        );
        let first: String = page.deltas.iter().map(|d| d.text.as_str()).collect();
        assert!(
            CLEAN.starts_with(&first) && first != CLEAN,
            "first incremental page must be a strict prefix of the scripted text, got {first:?}"
        );
        gate.release(n_events); // remaining events + EOF
        let mut concat = first;
        let mut saw_terminal = false;
        while let Some(p) = read_delta_wire_page(&mut ws, Duration::from_secs(5)).await {
            for d in &p.deltas {
                concat.push_str(&d.text);
            }
            if p.terminal.is_some() {
                saw_terminal = true;
                break;
            }
        }
        assert!(saw_terminal, "terminal marker");
        concat
    });

    let recorded = sink.recorded_delta_texts();
    let scripted_chunks = decoded_chunks(&events);
    let scripted = scripted_chunks.concat();
    assert_eq!(recorded, scripted_chunks);
    assert_eq!(recorded.concat(), scripted);
    assert_eq!(first_concat, scripted);
    let replies = sut.delivered_replies();
    assert_eq!(replies, vec![recorded.concat().into_bytes()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t119_hold_redact_split_kills_prescan_tee() {
    let gate = SseGate::new();
    let events = hold_events();
    let n_events = events.len();
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::sse(
            200,
            events.clone(),
        )
        .with_gate(gate.clone())]))
        .with_delta_tee()
        .with_reply_capture()
        .build(STREAM_CORE)
        .await;
    let sink = sut.capturing_sink().expect("capturing sink");
    sut.inject_message("j72", b"hold").await;

    tokio::join!(sut.run_turns(1), async {
        let _key = sink
            .wait_begin_key(Duration::from_secs(5))
            .await
            .expect("Begin");
        gate.release(n_events + 1);
    });

    assert_eq!(gate.events_emitted(), n_events);
    let recorded = sink.recorded_delta_texts();
    assert!(
        recorded.iter().any(|t| !t.is_empty()),
        "Redact finish must emit at least one non-empty post-scan Delta (empty-vs-empty fails)"
    );
    let sink_concat = recorded.concat();
    assert!(
        !sink_concat.is_empty() && sink_concat.contains("[REDACTED]"),
        "hold must emit [REDACTED], not empty concat; got {sink_concat:?}"
    );
    let replies = sut.delivered_replies();
    assert_eq!(replies, vec![sink_concat.clone().into_bytes()]);
    let decoded = decoded_contents(&events);
    assert!(
        decoded.contains(SECRET),
        "scripted content must contain SECRET"
    );
    assert!(
        !sink_concat.contains(SECRET),
        "sink must not contain raw secret"
    );
    assert!(
        !String::from_utf8_lossy(&replies[0]).contains(SECRET),
        "guest payload must not contain raw secret"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_307a_revocation_cuts_mid_stream() {
    let gate = SseGate::new();
    let events = clean_events();
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::sse(
            200, events,
        )
        .with_gate(gate.clone())]))
        .with_delta_tee()
        .build(STREAM_CORE)
        .await;
    let server = sut.client_api_server().expect("client api");
    install_operator(server.api().as_ref());
    let origin = format!("http://{}", server.local_addr());
    let port = server.local_addr().port();
    let sink = sut.capturing_sink().expect("capturing sink");
    sut.inject_message("j72", CLEAN.as_bytes()).await;

    tokio::join!(sut.run_turns(1), async {
        let key = sink
            .wait_begin_key(Duration::from_secs(5))
            .await
            .expect("Begin");
        let mut ws = connect_delta(port, &origin).await;
        read_delta_seed(&mut ws).await;
        send_frame(&mut ws, json!({ "stream_key": key })).await;
        gate.release(1);
        let page = read_delta_wire_page(&mut ws, FIRST_PAGE)
            .await
            .expect("live page");
        assert!(!page.absent && !page.deltas.is_empty() && page.terminal.is_none());
        assert!(
            !sink.recorded_delta_texts().is_empty(),
            "page must come from poll_live tee"
        );
        let revoked_at = Instant::now();
        server.api().sessions().revoke(TOKEN);
        let (saw_close, text_after) = drain_until_close(&mut ws, Duration::from_secs(15)).await;
        assert!(saw_close, "revocation must close the socket");
        assert!(
            revoked_at.elapsed() <= Duration::from_secs(15),
            "cut within 15 s"
        );
        assert!(!text_after, "no delta after close");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if sut
                .pump_exits()
                .iter()
                .any(|e| *e == advance_client_api::DeltaPumpExit::AuthFailureImmediate)
            {
                break;
            }
            if Instant::now() >= deadline {
                panic!("expected AuthFailureImmediate, got {:?}", sut.pump_exits());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_307b_fifth_subscriber_is_429() {
    let gate = SseGate::new();
    let events = clean_events();
    let n_events = events.len();
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::sse(
            200, events,
        )
        .with_gate(gate.clone())]))
        .with_delta_tee()
        .build(STREAM_CORE)
        .await;
    let server = sut.client_api_server().expect("client api");
    install_operator(server.api().as_ref());
    let origin = format!("http://{}", server.local_addr());
    let port = server.local_addr().port();
    let sink = sut.capturing_sink().expect("capturing sink");
    sut.inject_message("j72", CLEAN.as_bytes()).await;

    tokio::join!(sut.run_turns(1), async {
        let key = sink
            .wait_begin_key(Duration::from_secs(5))
            .await
            .expect("Begin");
        let mut socks = Vec::new();
        for _ in 0..4 {
            let mut ws = connect_delta(port, &origin).await;
            read_delta_seed(&mut ws).await;
            send_frame(&mut ws, json!({ "stream_key": key })).await;
            socks.push(ws);
        }
        gate.release(1);
        let mut first_pages = Vec::new();
        for (i, ws) in socks.iter_mut().enumerate() {
            let page = read_delta_wire_page(ws, FIRST_PAGE)
                .await
                .unwrap_or_else(|| panic!("incumbent {i} first page"));
            assert!(
                !page.absent && !page.deltas.is_empty() && page.terminal.is_none(),
                "incumbent {i} must receive in-flight content before 429, got {page:?}"
            );
            let first: String = page.deltas.iter().map(|d| d.text.as_str()).collect();
            assert!(
                CLEAN.starts_with(&first) && first != CLEAN,
                "incumbent {i} first page must be a strict prefix of the script, got {first:?}"
            );
            first_pages.push(first);
        }
        match try_connect_delta(port, &origin).await {
            Err(err) => assert_eq!(
                upgrade_status(&err),
                Some(429),
                "5th subscriber must 429 at upgrade"
            ),
            Ok(_) => panic!("the 5th subscriber must be refused"),
        }
        gate.release(n_events);
        for (i, ws) in socks.iter_mut().enumerate() {
            let page = read_delta_wire_page(ws, Duration::from_secs(5))
                .await
                .unwrap_or_else(|| panic!("incumbent {i} must stay live after 429"));
            assert!(
                !page.absent && !page.deltas.is_empty(),
                "incumbent {i} must keep receiving content after 429, got {page:?}"
            );
            let later: String = page.deltas.iter().map(|d| d.text.as_str()).collect();
            assert!(
                !later.is_empty() && !later.starts_with(&first_pages[i]),
                "incumbent {i} post-429 page must be new script bytes, got {later:?}"
            );
            let acc = format!("{}{}", first_pages[i], later);
            assert!(
                acc.len() > first_pages[i].len() && (CLEAN.starts_with(&acc) || acc == CLEAN),
                "incumbent {i} pages must be a continuation of the script, got {acc:?}"
            );
        }
        drop(socks);
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_308_unconsumed_reap_exactly_once() {
    let gate = SseGate::new();
    let events = clean_events();
    let bus_dir = tempfile::tempdir().expect("bus dir");
    let bus = Arc::new(
        advance_event_bus::EventBus::new_synchronous_for_tests(
            advance_event_bus::EventBusConfig::new(
                bus_dir.path().join("jsonl"),
                bus_dir.path().join("events.db"),
            ),
        )
        .expect("event bus"),
    );
    let rm = Arc::new(advance_run_manager::RunManager::new(
        bus.clone() as Arc<dyn advance_shared_types::traits::EventBusEmit>
    ));
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::sse(
            200, events,
        )
        .with_gate(gate.clone())]))
        .with_delta_tee()
        .grant_run_session(rm.clone(), advance_run_manager::RunConfig::default())
        .budget(Arc::new(rm.budget()))
        .build(ABANDON_CORE)
        .await;
    let server = sut.client_api_server().expect("client api");
    install_operator(server.api().as_ref());
    let origin = format!("http://{}", server.local_addr());
    let port = server.local_addr().port();
    let sink = sut.capturing_sink().expect("capturing sink");
    sut.inject_message("j72", CLEAN.as_bytes()).await;

    tokio::join!(sut.run_turns(1), async {
        let key = sink
            .wait_begin_key(Duration::from_secs(5))
            .await
            .expect("Begin");
        let mut ws = connect_delta(port, &origin).await;
        read_delta_seed(&mut ws).await;
        send_frame(&mut ws, json!({ "stream_key": key })).await;
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut saw_reaped = false;
        while Instant::now() < deadline {
            if let Some(page) = read_delta_wire_page(&mut ws, Duration::from_secs(2)).await {
                if page.terminal.as_ref().map(|t| t.reason.as_str()) == Some("reaped") {
                    saw_reaped = true;
                    break;
                }
            }
        }
        assert!(saw_reaped, "console Terminal(reaped)");
        assert_eq!(
            gate.events_emitted(),
            0,
            "abandon guest must leave the gated body unconsumed"
        );
    });

    let runs = rm.list_runs();
    assert!(!runs.is_empty(), "run ledger has a run");
    let snap = rm
        .budget_state_snapshot(&runs[0].id)
        .expect("budget snapshot");
    assert!(
        snap.token_used > 0 || snap.cost_usd > 0.0,
        "exactly-once commit must be visible, got {snap:?}"
    );
    sut.llm_stream_reaper()
        .expect("tee retains reaper")
        .reap_agent(sut.agent_id());
    let snap2 = rm
        .budget_state_snapshot(&runs[0].id)
        .expect("budget snapshot after second reap");
    assert_eq!(snap2.token_used, snap.token_used);
    assert_eq!(snap2.cost_usd, snap.cost_usd);
}
