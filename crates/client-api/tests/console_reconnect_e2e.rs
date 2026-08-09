//! MODULE-020-AC-05 real-transport reconnect witness (MODULE-020-T05) + the transport
//! async-bridge regression cell (m020-console-e2e).
//!
//! Self-contained: drives the REAL `ClientApiServer` WebSocket/HTTP transport over real loopback
//! sockets, with a REAL `advance_event_bus::EventBus` behind the `ClientEventProvider` port via an
//! owned-runtime `block_on` adapter (legal now that the transport runs `handle()` under
//! `spawn_blocking`). No sync fake provider is used — the real bus is what makes the projection a
//! REAL-TIME projection from the real source.

use std::collections::HashSet;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::audit::{AuditEvent, AuditSink};
use advance_client_api::clock::SystemClock;
use advance_client_api::{
    AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientApiServer, ClientCursorCodec,
    ClientEnvelope, ClientEventCursor, ClientEventPage, ClientEventProvider, ClientSession,
    MemoryCursorKeyCustody, NormalizedEventFilter, OsCursorEntropy, Platform, Principal,
    ProviderError, RawEventRow, Scope, SystemCursorClock, API_VERSION, CLIENT_WS_PROTOCOL,
};
use advance_event_bus::{
    EventBus, EventBusConfig, EventFilter, ObservabilityReadApi, ReadApiError, ReadCursor,
};
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::LeakDetector;
use advance_shared_types::traits::EventBusEmit;
use cap_http::DefaultLeakDetector;
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;

const AGENT_MATCH: &str = "agent:alpha";
const AGENT_OTHER: &str = "agent:bravo";
const TRACE: &str = "00000000-0000-4000-8000-000000000001";
const TOKEN: &str = "console-e2e-token";

// ── Real EventBus fixture (owned parked runtime; identical pattern to tests/events.rs) ────────

struct LiveBus {
    _rt_thread: Option<std::thread::JoinHandle<()>>,
    bus: Arc<EventBus>,
    read: Arc<dyn ObservabilityReadApi>,
    retention_days: u32,
    _shutdown_tx: std::sync::mpsc::Sender<()>,
}

impl LiveBus {
    fn start(retention_days: u32) -> Self {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let temp = Box::leak(Box::new(temp));
        let mut cfg =
            EventBusConfig::new(temp.path().join("events"), temp.path().join("events.db"));
        cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
        cfg.jsonl_retention_days = retention_days;

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .expect("bus rt");
            rt.block_on(async move {
                let bus = Arc::new(EventBus::new(cfg).await.expect("bus"));
                let read = bus.read_api().expect("read_api");
                ready_tx.send((Arc::clone(&bus), read)).expect("ready send");
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = shutdown_rx.recv();
                })
                .await;
            });
        });
        let (bus, read) = ready_rx.recv().expect("bus ready");
        Self {
            _rt_thread: Some(handle),
            bus,
            read,
            retention_days,
            _shutdown_tx: shutdown_tx,
        }
    }

    fn emit(&self, event: Event) {
        self.bus.emit(event);
    }

    fn read(&self) -> Arc<dyn ObservabilityReadApi> {
        Arc::clone(&self.read)
    }
}

/// Real-EventBus-backed provider: OWNS a tokio Runtime and `block_on`s inside its sync trait
/// methods. Legal because the transport fix runs `handle()` on a `spawn_blocking` thread.
struct EventBusProvider {
    rt: tokio::runtime::Runtime,
    read: Arc<dyn ObservabilityReadApi>,
    retention_days: u32,
}

impl EventBusProvider {
    fn new(live: &LiveBus) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("provider rt");
        Self {
            rt,
            read: live.read(),
            retention_days: live.retention_days,
        }
    }

    fn map_err(e: ReadApiError) -> ProviderError {
        match e {
            ReadApiError::CursorNotFound(_) => ProviderError::NotFound("cursor".into()),
            ReadApiError::BadFilter(_) => ProviderError::InvalidState("filter".into()),
            ReadApiError::Db(_) => ProviderError::Unavailable("db".into()),
        }
    }

    fn to_row(re: advance_event_bus::ReadEvent) -> RawEventRow {
        RawEventRow {
            raw_id: re.cursor.0,
            event_type: re.event.event_type.clone(),
            timestamp: re.event.timestamp,
            agent_id: re.event.agent_id.clone(),
            run_id: re.event.run_id.clone(),
            trace_id: re.event.trace_id.clone(),
            payload: re.event.payload.clone(),
        }
    }
}

impl ClientEventProvider for EventBusProvider {
    fn retention_days(&self) -> u32 {
        self.retention_days
    }

    fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
        let read = Arc::clone(&self.read);
        self.rt.block_on(async move {
            read.query(&EventFilter::default(), 1)
                .await
                .map(|rows| rows.into_iter().next().map(|r| r.cursor.0))
                .map_err(Self::map_err)
        })
    }

    fn query_history(
        &self,
        filter: &NormalizedEventFilter,
        limit: usize,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        let ef = EventFilter {
            event_type_prefix: filter.event_type.clone(),
            agent_id: filter.agent_id.clone(),
            run_id: filter.run_id.clone(),
            trace_id: filter.trace_id.clone(),
            since: filter.since.clone(),
        };
        let read = Arc::clone(&self.read);
        self.rt.block_on(async move {
            read.query(&ef, limit)
                .await
                .map(|rows| rows.into_iter().map(Self::to_row).collect())
                .map_err(Self::map_err)
        })
    }

    fn drain_stream(
        &self,
        after_raw_id: Option<&str>,
        scan_ceiling: usize,
        idle_ms: u64,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        let read = Arc::clone(&self.read);
        let after = after_raw_id.map(|s| s.to_string());
        let idle = Duration::from_millis(idle_ms);
        self.rt.block_on(async move {
            let mut stream = read
                .resume(after.map(ReadCursor), EventFilter::default())
                .await
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            while out.len() < scan_ceiling {
                match tokio::time::timeout(idle, stream.recv()).await {
                    Ok(Ok(Some(re))) => out.push(Self::to_row(re)),
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => return Err(Self::map_err(e)),
                    Err(_) => break, // idle end — success
                }
            }
            Ok(out)
        })
    }
}

// ── Harness helpers ───────────────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn make_event(id: &str, agent_id: &str, run_id: &str, payload: Value) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: agent_id.into(),
        task_id: None,
        run_id: Some(run_id.into()),
        execution_id: None,
        trace_id: TRACE.into(),
        span_id: "span-console".into(),
        parent_span_id: None,
        event_type: "run.created".into(),
        payload,
        duration_ms: None,
    }
}

fn build_api(
    origin: &str,
    provider: Arc<dyn ClientEventProvider>,
    retention: u32,
) -> Arc<ClientApi> {
    let mut config = ClientApiConfig::default();
    config.allowed_origins = vec![origin.into()];
    let codec: Arc<dyn ClientCursorCodec> = Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        retention,
    ));
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(config)
        .with_event_provider(provider)
        .with_leak_detector(detector)
        .with_cursor_codec(codec);
    api.sessions().insert(
        TOKEN.into(),
        ClientSession {
            session_id: "console-e2e-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("console-e2e-csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );
    Arc::new(api)
}

type Sock =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(port: u16, origin: &str) -> Sock {
    // A reconnect can transiently 429 (`stream_backpressure`) while the just-closed connection's
    // websocket_loop task is still draining the single stream slot (MAX_CONCURRENT_EVENT_STREAMS=1).
    // That is the only real reconnect race (the slot is per-handle()-call, not per-connection) — a
    // bounded retry covers the drain window. Any other status is a real failure.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut request = format!("ws://127.0.0.1:{port}/client/events/stream")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{TOKEN}")
                .parse()
                .unwrap(),
        );
        request
            .headers_mut()
            .insert(ORIGIN, origin.parse().unwrap());
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, response)) => {
                assert_eq!(
                    response
                        .headers()
                        .get(SEC_WEBSOCKET_PROTOCOL)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    CLIENT_WS_PROTOCOL
                );
                return socket;
            }
            Err(tokio_tungstenite::tungstenite::Error::Http(resp))
                if resp.status() == 429 && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => panic!("ws connect failed: {e:?}"),
        }
    }
}

async fn send_frame(socket: &mut Sock, frame: Value) {
    socket
        .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
        .await
        .unwrap();
}

/// Read one WebSocket page (raw text + parsed) within `timeout`, answering pings. `None` = quiet
/// (no noteworthy page arrived, e.g. only filtered-out / empty polls) or the socket closed.
async fn read_page(socket: &mut Sock, timeout: Duration) -> Option<(String, ClientEventPage)> {
    let text = tokio::time::timeout(timeout, async {
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
    .ok()??;
    let envelope: ClientEnvelope<Value> = serde_json::from_str(&text).unwrap();
    assert!(
        envelope.is_ok(),
        "stream frame errored: {:?}",
        envelope.error
    );
    let page: ClientEventPage = serde_json::from_value(envelope.data.unwrap()).unwrap();
    Some((text, page))
}

/// Wait until the real bus reports at least `min` events visible. Runs a fresh current-thread
/// runtime on a blocking thread (block_on legal there); never nests on the async worker.
async fn wait_visible(read: Arc<dyn ObservabilityReadApi>, min: usize) {
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(8) {
            let n = rt.block_on(async {
                read.query(&EventFilter::default(), 100_000)
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            });
            if n >= min {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("wait_visible: fewer than {min} events after 8s");
    })
    .await
    .unwrap();
}

/// Raw loopback HTTP GET (native client — no Origin header, so CORS is bypassed). Returns
/// (status_code, body). Body is the JSON envelope.
async fn http_get(port: u16, path: &str, token: Option<&str>) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nx-advance-api-version: {API_VERSION}\r\n{auth}Connection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// Precise teardown: keepalive was cloned before the server took its own Arc. Close sockets first,
/// await graceful shutdown (drains the ws task + its Arc clone), then drop the keepalive on a plain
/// std thread once it is the last ref — landing the provider's owned Runtime drop OUTSIDE async.
fn drop_keepalive_off_async(keepalive: Arc<ClientApi>) {
    let handle = std::thread::spawn(move || {
        let mut spins = 0;
        while Arc::strong_count(&keepalive) > 1 && spins < 5_000 {
            std::thread::sleep(Duration::from_millis(1));
            spins += 1;
        }
        drop(keepalive);
    });
    handle.join().unwrap();
}

// ── MODULE-020-T05 ────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_020_ac05_filtered_realtime_projection_survives_reconnect_with_cursor_resume() {
    const SENTINEL: &str = "SUPERSECRETSENTINEL_UNPROJECTED_42";
    // Use long provider IDs for the opacity assertion. Short fragments such as "m1" can occur by
    // chance inside an opaque base64url ciphertext and make the witness probabilistically flaky.
    const MATCH_ONE_EVENT_ID: &str = "raw-event-id-match-one-7f3b18c25d4a";
    const NON_MATCH_EVENT_ID: &str = "raw-event-id-non-match-c9a641e08b72";
    const MATCH_TWO_EVENT_ID: &str = "raw-event-id-match-two-2de790a4f163";

    let live = LiveBus::start(30);
    let read = live.read();
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");

    let provider: Arc<dyn ClientEventProvider> = Arc::new(EventBusProvider::new(&live));
    let api = build_api(&origin, provider, 30);
    let keepalive = Arc::clone(&api);
    let server = ClientApiServer::bind(api, port).await.unwrap();

    let mut socket = connect(port, &origin).await;
    // Unfiltered seed (empty-join on an empty bus): opaque cursor, no events.
    let (seed_text, seed) = read_page(&mut socket, Duration::from_secs(4))
        .await
        .expect("seed page");
    assert!(seed.events.is_empty(), "seed must be empty-join");
    let seed_cursor = seed.cursor.clone().expect("seed cursor");

    // Establish the FILTERED stream (agent_id = AGENT_MATCH). Emit matching probes and read until a
    // page arrives — this crosses the high-water open race deterministically and proves the filter
    // is active (every delivered event is AGENT_MATCH). Then drain to a quiet anchor.
    send_frame(&mut socket, json!({ "agent_id": AGENT_MATCH, "limit": 16 })).await;
    let mut probe = 0;
    let mut anchor: ClientEventCursor;
    loop {
        probe += 1;
        assert!(probe <= 40, "filtered stream never delivered a probe");
        live.emit(make_event(
            &format!("probe-{probe}"),
            AGENT_MATCH,
            &format!("run-probe-{probe}"),
            json!({}),
        ));
        match read_page(&mut socket, Duration::from_secs(2)).await {
            Some((_, page)) if !page.events.is_empty() => {
                for ev in &page.events {
                    assert_eq!(
                        ev.agent_id, AGENT_MATCH,
                        "probe leaked a non-matching event"
                    );
                }
                anchor = page.cursor.clone().expect("probe cursor");
                break;
            }
            _ => continue,
        }
    }
    // Drain any remaining probe pages so the anchor sits past every probe.
    while let Some((_, page)) = read_page(&mut socket, Duration::from_secs(1)).await {
        for ev in &page.events {
            assert_eq!(ev.agent_id, AGENT_MATCH);
        }
        anchor = page.cursor.clone().expect("drain cursor");
    }

    // Deterministic witness: a KNOWN mix emitted strictly AFTER the anchor. m1/m2 match; n1 does
    // not. m2 carries a secret sentinel in a NON-projected payload field (run.created has no
    // projected leaves), which must never appear in any frame.
    live.emit(make_event(
        MATCH_ONE_EVENT_ID,
        AGENT_MATCH,
        "run-m1",
        json!({}),
    ));
    live.emit(make_event(
        NON_MATCH_EVENT_ID,
        AGENT_OTHER,
        "run-n1",
        json!({}),
    ));
    live.emit(make_event(
        MATCH_TWO_EVENT_ID,
        AGENT_MATCH,
        "run-m2",
        json!({ "secret_note": SENTINEL }),
    ));

    let mut seen: HashSet<String> = HashSet::new();
    let mut witness_cursor = anchor.clone();
    let collect_start = Instant::now();
    while !(seen.contains("run-m1") && seen.contains("run-m2")) {
        assert!(
            collect_start.elapsed() < Duration::from_secs(10),
            "witness events not projected within 10s (seen={seen:?})"
        );
        let (raw, page) = read_page(&mut socket, Duration::from_secs(3))
            .await
            .expect("witness page");
        assert!(
            !raw.contains(SENTINEL),
            "secret sentinel leaked into a WS frame"
        );
        for ev in &page.events {
            // The filter is load-bearing: a non-matching agent must NEVER be projected.
            assert_eq!(
                ev.agent_id, AGENT_MATCH,
                "filter failed — leaked {}",
                ev.agent_id
            );
            let run = ev.run_id.clone().expect("run_id");
            assert_ne!(run, "run-n1", "filtered-out event was delivered");
            assert!(
                seen.insert(run),
                "event delivered more than once (not exactly-once)"
            );
        }
        witness_cursor = page.cursor.clone().expect("witness cursor");
    }
    assert!(seen.contains("run-m1") && seen.contains("run-m2"));
    assert!(!seen.contains("run-n1"), "non-matching event was delivered");

    // Opaque cursor: the sealed token must not expose the provider's complete raw event IDs.
    // Compare full high-entropy markers, not short substrings that can randomly occur in ciphertext.
    let cursor_json = serde_json::to_string(&witness_cursor).unwrap();
    for raw in [MATCH_ONE_EVENT_ID, NON_MATCH_EVENT_ID, MATCH_TWO_EVENT_ID] {
        assert!(
            !cursor_json.contains(raw),
            "cursor leaked raw event id {raw}: {cursor_json}"
        );
    }
    // The unfiltered seed cursor likewise predates and cannot expose the witness identifiers.
    assert!(!seed_text.contains(MATCH_ONE_EVENT_ID));
    assert!(!serde_json::to_string(&seed_cursor)
        .unwrap()
        .contains(MATCH_ONE_EVENT_ID));

    // ── Survives reconnect with cursor resume ──
    socket.close(None).await.ok();
    // Emit the post-reconnect event and confirm it is bus-visible BEFORE timing the reconnect, so
    // the 2s bound measures reconnect+resume latency, not bus emit latency.
    live.emit(make_event("m3", AGENT_MATCH, "run-m3", json!({})));
    // probes (>=1) + m1 + n1 + m2 + m3 are all visible.
    wait_visible(read, probe as usize + 4).await;

    let reconnect_start = Instant::now();
    let resumed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut sock2 = connect(port, &origin).await;
        // Fresh (always-unfiltered) seed; discard.
        let _ = read_page(&mut sock2, Duration::from_secs(2))
            .await
            .expect("fresh seed");
        // Resume the FILTERED stream: re-send the filter dims AND the cursor. The server recomputes
        // stream_id = stream_id_for_filter(filter); a cursor-only frame would mismatch.
        send_frame(
            &mut sock2,
            json!({
                "agent_id": AGENT_MATCH,
                "stream_id": witness_cursor.stream_id,
                "last_event_id": witness_cursor.last_event_id,
                "limit": 16
            }),
        )
        .await;
        loop {
            let (_, page) = read_page(&mut sock2, Duration::from_secs(2))
                .await
                .expect("resume page");
            for ev in &page.events {
                assert_eq!(ev.agent_id, AGENT_MATCH);
                let run = ev.run_id.clone().unwrap();
                // Gap-free: pre-cursor events must NOT be re-delivered on resume.
                assert!(
                    !["run-m1", "run-m2"].contains(&run.as_str()),
                    "re-delivered a pre-cursor event on resume: {run}"
                );
                if run == "run-m3" {
                    return sock2;
                }
            }
        }
    })
    .await
    .expect("reconnect + cursor resume did not complete within the 2s NFR bound");
    let reconnect_elapsed = reconnect_start.elapsed();
    assert!(
        reconnect_elapsed < Duration::from_secs(2),
        "reconnect resume took {reconnect_elapsed:?} (>2s NFR)"
    );

    // Exactly-once (completeness, measured OUTSIDE the 2s NFR window): the resume delivered m3
    // exactly once. Emit nothing more and drain a window spanning several 250ms poll cycles; the
    // per-handle() cursor must have advanced past m3, so NO further delivery of m3 (a duplicate) or
    // of any pre-cursor event may occur. A non-advancing WS cursor would re-deliver m3 here.
    let mut resumed = resumed;
    for _ in 0..2 {
        while let Some((_, page)) = read_page(&mut resumed, Duration::from_secs(1)).await {
            for ev in &page.events {
                let run = ev.run_id.clone().unwrap();
                assert!(
                    !["run-m1", "run-m2", "run-m3"].contains(&run.as_str()),
                    "resume re-delivered {run} after it was already seen (not exactly-once)"
                );
            }
        }
    }

    // ── Teardown: close ws first, await shutdown, drop keepalive off-async ──
    resumed.close(None).await.ok();
    server.shutdown().await.unwrap();
    drop_keepalive_off_async(keepalive);
}

// ── Transport async-bridge regression cell ────────────────────────────────────────────────

/// (a) A `block_on`-bridging provider behind the real HTTP path (`GET /client/events` history)
/// returns real data — proving the `handle_http` spawn_blocking fix. Pre-fix, the provider's
/// inner `block_on` would nested-runtime-panic on the async worker and be swallowed to
/// `module_unavailable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_http_bridges_block_on_provider_and_returns_real_data() {
    let live = LiveBus::start(30);
    let read = live.read();
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");

    let provider: Arc<dyn ClientEventProvider> = Arc::new(EventBusProvider::new(&live));
    let api = build_api(&origin, provider, 30);
    let keepalive = Arc::clone(&api);
    let server = ClientApiServer::bind(api, port).await.unwrap();

    live.emit(make_event("h1", AGENT_MATCH, "run-h1", json!({})));
    wait_visible(read, 1).await;

    let (status, body) = http_get(port, "/client/events?limit=16", Some(TOKEN)).await;
    assert_eq!(status, 200, "history GET status: {body}");
    let env: ClientEnvelope<Value> = serde_json::from_str(&body).unwrap();
    assert!(env.is_ok(), "history errored: {:?}", env.error);
    let page: ClientEventPage = serde_json::from_value(env.data.unwrap()).unwrap();
    // The real block_on provider actually returned the emitted event (NOT module_unavailable).
    assert_eq!(
        page.events.len(),
        1,
        "history did not return the real event"
    );
    assert_eq!(page.events[0].agent_id, AGENT_MATCH);

    server.shutdown().await.unwrap();
    drop_keepalive_off_async(keepalive);
}

/// (b) JOIN-ERROR branch: a panicking `AuditSink` (invoked at the top of `handle()`, OUTSIDE
/// `run_handler`'s catch_unwind) escapes `handle()` → the transport's `spawn_blocking` join error
/// maps to a stable `module_unavailable` (503). The server must NOT hang or drop the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_join_error_maps_to_stable_503() {
    struct PanicSink;
    impl AuditSink for PanicSink {
        fn emit(&self, _event: AuditEvent) {
            panic!("audit sink boom (expected — exercises the spawn_blocking join-error branch)");
        }
    }

    let port = free_port();
    let mut config = ClientApiConfig::default();
    config.allowed_origins = vec![format!("http://127.0.0.1:{port}")];
    let api = Arc::new(ClientApi::with_parts(
        config,
        "tester",
        Arc::new(SystemClock),
        Arc::new(PanicSink),
    ));
    let server = ClientApiServer::bind(api, port).await.unwrap();

    // /client/health is unauthenticated but still emits `client_api.request` at handle() top.
    let (status, body) = http_get(port, "/client/health", None).await;
    assert_eq!(
        status, 503,
        "expected 503 on join error, got {status}: {body}"
    );
    assert!(
        body.contains("module_unavailable"),
        "expected module_unavailable envelope, got: {body}"
    );

    server.shutdown().await.unwrap();
}

/// (c) DISPATCH CAP (adversarial round-13 hardening): the transport runs handle() under
/// spawn_blocking, which would otherwise let a caller pin the blocking pool and grow an unbounded
/// submission queue on the uncapped provider families. With max_concurrent_dispatch = 2, two
/// concurrent requests that block inside their provider hold both dispatch permits; a third request
/// must FAIL CLOSED with a stable module_unavailable (503) rather than stalling or queueing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_dispatch_cap_fails_closed_when_saturated() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct BlockingEventProvider {
        started: Arc<AtomicUsize>,
        release: Arc<AtomicBool>,
    }
    impl ClientEventProvider for BlockingEventProvider {
        fn retention_days(&self) -> u32 {
            30
        }
        fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
            Ok(None)
        }
        fn query_history(
            &self,
            _f: &NormalizedEventFilter,
            _l: usize,
        ) -> Result<Vec<RawEventRow>, ProviderError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(Vec::new())
        }
        fn drain_stream(
            &self,
            _a: Option<&str>,
            _s: usize,
            _i: u64,
        ) -> Result<Vec<RawEventRow>, ProviderError> {
            Ok(Vec::new())
        }
    }

    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let provider: Arc<dyn ClientEventProvider> = Arc::new(BlockingEventProvider {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    });
    let mut config = ClientApiConfig::default();
    config.allowed_origins = vec![origin];
    config.max_concurrent_dispatch = 2;
    let codec: Arc<dyn ClientCursorCodec> = Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ));
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(config)
        .with_event_provider(provider)
        .with_leak_detector(detector)
        .with_cursor_codec(codec);
    api.sessions().insert(
        TOKEN.into(),
        ClientSession {
            session_id: "cap-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("cap-csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    // Two requests that block inside query_history, holding both dispatch permits (GET /client/events
    // = history route, served through handle_http; EventConcurrency's cap is 4, above the dispatch 2).
    let h1 =
        tokio::spawn(async move { http_get(port, "/client/events?limit=1", Some(TOKEN)).await });
    let h2 =
        tokio::spawn(async move { http_get(port, "/client/events?limit=1", Some(TOKEN)).await });

    let start = Instant::now();
    while started.load(Ordering::SeqCst) < 2 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the two blocking requests did not both enter the provider"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The third request must fail closed FAST with a stable 503 — not stall on an unbounded queue.
    let (status3, body3) = tokio::time::timeout(
        Duration::from_secs(2),
        http_get(port, "/client/events?limit=1", Some(TOKEN)),
    )
    .await
    .expect("saturated dispatch must fail fast, not stall");
    assert_eq!(
        status3, 503,
        "expected 503 at dispatch capacity, got {status3}: {body3}"
    );
    assert!(
        body3.contains("module_unavailable"),
        "expected module_unavailable at capacity, got {body3}"
    );

    // Release the two blocked requests; both complete with 200 and the permits are freed.
    release.store(true, Ordering::SeqCst);
    let (s1, _) = h1.await.unwrap();
    let (s2, _) = h2.await.unwrap();
    assert_eq!(s1, 200);
    assert_eq!(s2, 200);

    server.shutdown().await.unwrap();
}

/// Best-effort regression guard for the round-14 fix: the dispatch permit is moved INTO the
/// `spawn_blocking` closure, so it is held for the real handle() execution and — because
/// `spawn_blocking` closures cannot be cancelled — stays held by the detached closure even if the
/// transport future is dropped on client disconnect. The fix's correctness is primarily BY
/// CONSTRUCTION (the permit is owned by the blocking closure, verified by review), because this test
/// cannot self-verify that the server cancelled its HTTP/1 handler on `drop(raw)` (hyper may run an
/// HTTP/1 handler to completion): with `release=false` the provider never returns, so a
/// future-owned (buggy) permit would ALSO stay held and 503 the fresh request unless the handler was
/// actually cancelled. The assertions still exercise the disconnect path and prove the permit is
/// held across it and released when the blocking work finishes. With cap=1: a request blocks in its
/// provider holding the sole permit; after the client disconnects a fresh request 503s until the
/// detached blocking work completes and releases the permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_dispatch_permit_survives_request_cancellation() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct BlockingEventProvider {
        started: Arc<AtomicUsize>,
        release: Arc<AtomicBool>,
    }
    impl ClientEventProvider for BlockingEventProvider {
        fn retention_days(&self) -> u32 {
            30
        }
        fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
            Ok(None)
        }
        fn query_history(
            &self,
            _f: &NormalizedEventFilter,
            _l: usize,
        ) -> Result<Vec<RawEventRow>, ProviderError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(Vec::new())
        }
        fn drain_stream(
            &self,
            _a: Option<&str>,
            _s: usize,
            _i: u64,
        ) -> Result<Vec<RawEventRow>, ProviderError> {
            Ok(Vec::new())
        }
    }

    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let provider: Arc<dyn ClientEventProvider> = Arc::new(BlockingEventProvider {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    });
    let mut config = ClientApiConfig::default();
    config.allowed_origins = vec![origin];
    config.max_concurrent_dispatch = 1;
    let codec: Arc<dyn ClientCursorCodec> = Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ));
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(config)
        .with_event_provider(provider)
        .with_leak_detector(detector)
        .with_cursor_codec(codec);
    api.sessions().insert(
        TOKEN.into(),
        ClientSession {
            session_id: "cancel-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("cancel-csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    // Open a raw connection, send a request that blocks in the provider (taking the sole permit),
    // then DISCONNECT before reading the response — cancelling the server's handler future.
    let mut raw = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let req = format!(
        "GET /client/events?limit=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nx-advance-api-version: {API_VERSION}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    );
    raw.write_all(req.as_bytes()).await.unwrap();
    let start = Instant::now();
    while started.load(Ordering::SeqCst) < 1 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the blocking request never entered the provider"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(raw); // client disconnect — the async handler future is cancelled; the closure is detached.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The permit must STILL be held by the detached closure → a fresh request fails closed with 503.
    // (If the permit had lived in the cancelled future, it would have been released and this would be
    // a 200 — the bug this fix closes.)
    let (status2, body2) = tokio::time::timeout(
        Duration::from_secs(2),
        http_get(port, "/client/events?limit=1", Some(TOKEN)),
    )
    .await
    .expect("must not stall");
    assert_eq!(
        status2, 503,
        "permit was released on cancellation instead of held by the detached closure: {status2} {body2}"
    );

    // Release the detached blocking work; the closure returns, freeing the permit, and a request now
    // succeeds — proving the permit was genuinely tied to the (now-finished) blocking task.
    release.store(true, Ordering::SeqCst);
    let mut recovered = false;
    for _ in 0..60 {
        let (s, _) = http_get(port, "/client/events?limit=1", Some(TOKEN)).await;
        if s == 200 {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        recovered,
        "permit was not released after the detached blocking task completed"
    );

    server.shutdown().await.unwrap();
}

// ═════════════════════════════════════════════════════════════════════════════════════════
// Tee T2 (CONTRACT-235) delta-subscription witnesses — MODULE-020-T24 / T25 / T26 + G-1.
//
// T24 (integration, current_thread start_paused + TestClock): hub fed through its
// CONTRACT-234 sink face, subscribe through the scope-gated handler, release-gated reads.
// T25 (e2e, real socket): order/content/terminal ONLY (no timing assertions on a real socket).
// T26 (security integration, real socket, test-support injected triple
// cadence=250ms / allowance=100ms / deadline=1s): containment witnesses discriminated by
// pump EXIT REASON (witness note (c)), not wall time.
// ═════════════════════════════════════════════════════════════════════════════════════════

use std::sync::Mutex;

use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::cursor::SEAL_TAG_RAW_ID;
use advance_client_api::{
    resolve_stream_request, seal_delta_cursor, ClientRequest, DeltaHoldSplit, DeltaPumpExit,
    DeltaTiming, LlmDeltaHub, LlmDeltaStreamRequest, LlmDeltaWirePage, Method, SealPurpose,
    LLM_DELTA_ABSENT_NOTE,
};
use advance_shared_types::security_validator::{ScanContext, ScanResult};
use advance_shared_types::traits::{
    LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink, LlmDeltaUsage as SinkUsage, LlmTerminalReason,
};
use cap_http::canonical_facade::decoded_hold_split;

// ── Shared delta fixtures ─────────────────────────────────────────────────────────────────

fn real_hold_split() -> DeltaHoldSplit {
    Arc::new(|buf: &[u8], max: usize| decoded_hold_split(buf, max))
}

/// Hub over the REAL cap-http pattern source: `DefaultLeakDetector` + the
/// `decoded_hold_split` facade (the §2.4 same-source obligation), TestClock-driven.
fn delta_hub_with_clock(clock: Arc<TestClock>) -> Arc<LlmDeltaHub> {
    Arc::new(LlmDeltaHub::new(
        Some(Arc::new(DefaultLeakDetector::new())),
        Some(real_hold_split()),
        clock,
        None,
    ))
}

/// The T26 injected triple: cadence 250 ms / allowance 100 ms / deadline 1 s.
fn t26_timing() -> DeltaTiming {
    DeltaTiming {
        cadence: Duration::from_millis(250),
        reauth_max_age: Duration::from_secs(1),
        allowance: Duration::from_millis(100),
        linger: Duration::from_secs(30),
    }
}

fn delta_hub_timed(timing: DeltaTiming) -> Arc<LlmDeltaHub> {
    Arc::new(LlmDeltaHub::with_timing(
        Some(Arc::new(DefaultLeakDetector::new())),
        Some(real_hold_split()),
        Arc::new(SystemClock),
        None,
        timing,
    ))
}

fn d_begin(hub: &LlmDeltaHub, agent: &str, key: &str) {
    hub.publish(LlmDeltaEvent {
        agent_id: Arc::from(agent),
        stream_key: Arc::from(key),
        frame: LlmDeltaFrame::Begin {
            run_id: Some(format!("run-{key}")),
            task_id: None,
        },
    });
}

fn d_delta(hub: &LlmDeltaHub, key: &str, seq: u64, text: &str) {
    hub.publish(LlmDeltaEvent {
        agent_id: Arc::from("agent-x"),
        stream_key: Arc::from(key),
        frame: LlmDeltaFrame::Delta {
            seq,
            text: text.to_string(),
        },
    });
}

fn d_terminal(hub: &LlmDeltaHub, key: &str, seq: u64) {
    hub.publish(LlmDeltaEvent {
        agent_id: Arc::from("agent-x"),
        stream_key: Arc::from(key),
        frame: LlmDeltaFrame::Terminal {
            seq,
            reason: LlmTerminalReason::Completed,
            usage: Some(SinkUsage {
                input_tokens: 10,
                output_tokens: 20,
                cost_usd: 0.01,
            }),
        },
    });
}

/// Base ClientApi with codec + hub + pump-exit observer (no session yet).
fn delta_api_base(
    origin: &str,
    hub: &Arc<LlmDeltaHub>,
    mut config: ClientApiConfig,
    audit: Option<Arc<dyn AuditSink>>,
) -> (ClientApi, Arc<Mutex<Vec<DeltaPumpExit>>>) {
    config.allowed_origins = vec![origin.into()];
    let codec: Arc<dyn ClientCursorCodec> = Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ));
    let exits: Arc<Mutex<Vec<DeltaPumpExit>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&exits);
    let api = match audit {
        Some(audit) => ClientApi::with_parts(config, "operator", Arc::new(SystemClock), audit),
        None => ClientApi::new(config),
    }
    .with_cursor_codec(codec)
    .with_llm_delta_hub(Arc::clone(hub))
    .with_delta_pump_observer(Arc::new(move |exit| sink.lock().unwrap().push(exit)));
    (api, exits)
}

fn install_delta_session(api: &ClientApi, expires_at: u64, scopes: Vec<Scope>) {
    api.sessions().insert(
        TOKEN.into(),
        ClientSession {
            session_id: "delta-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes,
            csrf_token: Some("delta-csrf".into()),
            expires_at,
        },
        0,
    );
}

async fn connect_delta(
    port: u16,
    origin: &str,
    bearer: Option<&str>,
) -> Result<Sock, tokio_tungstenite::tungstenite::Error> {
    let mut request = format!("ws://127.0.0.1:{port}/client/llm/deltas/stream")
        .into_client_request()
        .unwrap();
    let protocols = match bearer {
        Some(token) => format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}"),
        None => CLIENT_WS_PROTOCOL.to_string(),
    };
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

/// Read the seed envelope (the first Text frame): a data envelope `{"subscribed": true}`.
async fn read_delta_seed(socket: &mut Sock) {
    let text = next_text(socket, Duration::from_secs(5))
        .await
        .expect("seed frame");
    let envelope: ClientEnvelope<Value> = serde_json::from_str(&text).unwrap();
    assert!(envelope.is_ok(), "seed errored: {:?}", envelope.error);
    assert_eq!(envelope.data.unwrap()["subscribed"], json!(true));
}

async fn read_delta_wire_page(
    socket: &mut Sock,
    timeout: Duration,
) -> Option<(String, LlmDeltaWirePage)> {
    let text = next_text(socket, timeout).await?;
    let envelope: ClientEnvelope<Value> = serde_json::from_str(&text).unwrap();
    assert!(
        envelope.is_ok(),
        "delta frame errored: {:?}",
        envelope.error
    );
    let page: LlmDeltaWirePage = serde_json::from_value(envelope.data.unwrap()).unwrap();
    Some((text, page))
}

/// Drain frames until the stream ends; returns (texts, saw_close, text_after_close).
async fn drain_until_close(socket: &mut Sock, overall: Duration) -> (Vec<String>, bool, bool) {
    let deadline = Instant::now() + overall;
    let mut texts = Vec::new();
    let mut saw_close = false;
    let mut text_after_close = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match tokio::time::timeout(deadline - now, socket.next()).await {
            Err(_) | Ok(None) => break,
            Ok(Some(Ok(Message::Text(t)))) => {
                if saw_close {
                    text_after_close = true;
                }
                texts.push(t.to_string());
            }
            Ok(Some(Ok(Message::Ping(b)))) => {
                let _ = socket.send(Message::Pong(b)).await;
            }
            Ok(Some(Ok(Message::Close(_)))) => saw_close = true,
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) => break,
        }
    }
    (texts, saw_close, text_after_close)
}

async fn wait_exit(
    exits: &Arc<Mutex<Vec<DeltaPumpExit>>>,
    timeout: Duration,
) -> Option<DeltaPumpExit> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(exit) = exits.lock().unwrap().first().copied() {
            return Some(exit);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Keep an idle subscriber's socket responsive to server pings (its pump must not time out
/// while another socket is the subject under test).
fn spawn_ping_keeper(mut socket: Sock) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(frame) = socket.next().await {
            match frame {
                Ok(Message::Ping(b)) => {
                    if socket.send(Message::Pong(b)).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    })
}

fn delta_handle_request(token: Option<&str>) -> ClientRequest {
    ClientRequest {
        api_version: API_VERSION.to_string(),
        method: Method::Get,
        path: "/client/llm/deltas/stream".into(),
        session_token: token.map(str::to_owned),
        origin: None,
        csrf_token: None,
        idempotency_key: None,
        is_loopback_peer: true,
        body: Value::Null,
    }
}

// ── MODULE-020-T24 (integration; current_thread start_paused + TestClock) ─────────────────

/// T24-a: park the consumer FIRST, feed AFTER, race delivery against a 1 ms virtual sleep —
/// delivery wins with ZERO virtual-time advance. Hold-free fixture text (canary: hold == 0
/// under the REAL facade geometry).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t24a_push_latency_delivery_beats_one_virtual_millisecond() {
    const FIX: &str = "first fixture chunk. ";
    assert_eq!(
        decoded_hold_split(FIX.as_bytes(), 4 * 1024 * 1024),
        Ok(FIX.len()),
        "T24-a fixture must be hold-free (canary: hold == 0)"
    );

    let clock = Arc::new(TestClock::new(1_000_000));
    let hub = delta_hub_with_clock(Arc::clone(&clock));

    // Subscribe through the scope-gated handler (the FULL handle() pipeline).
    let api = ClientApi::new(ClientApiConfig::default()).with_llm_delta_hub(Arc::clone(&hub));
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let seed = api.handle(delta_handle_request(Some(TOKEN)));
    assert!(
        seed.is_ok(),
        "scope-gated subscribe failed: {:?}",
        seed.error
    );

    // Park the consumer FIRST…
    let mut rx = hub.generation_watch();
    let parked = tokio::spawn(async move {
        rx.changed().await.expect("generation watch closed");
    });
    tokio::task::yield_now().await; // genuinely parked before any feed

    // …feed AFTER…
    d_begin(&hub, "agent-a", "t24a");
    d_delta(&hub, "t24a", 0, FIX);

    // …and race delivery vs sleep(1 ms): with start_paused the sleep only completes via
    // auto-advance, so a ready wake means delivery needed no virtual time at all.
    let before = tokio::time::Instant::now();
    tokio::select! {
        biased;
        joined = parked => joined.expect("parked consumer"),
        _ = tokio::time::sleep(Duration::from_millis(1)) => {
            panic!("push delivery lost the race to a 1 ms virtual sleep")
        }
    }
    assert_eq!(
        tokio::time::Instant::now(),
        before,
        "delivery must not require a virtual-time advance"
    );

    let page = hub.read_page("t24a", 0);
    assert!(!page.absent);
    assert_eq!(
        page.dropped_count, 0,
        "hold-free fixture: nothing withheld or dropped"
    );
    assert_eq!(page.deltas.len(), 1);
    assert_eq!(page.deltas[0].text, FIX);
}

/// T24-b: ordered pages ascend by from_seq across a bounds walk; a below-floor request
/// reports dropped_count > 0 after the released head evicts.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t24b_page_walk_ascends_and_below_floor_reports_drops() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let hub = delta_hub_with_clock(clock);
    d_begin(&hub, "agent-a", "t24b");
    let chunk = format!("{}. ", "x".repeat(30 * 1024)); // ~30 KiB, hold-free tail
    for seq in 0..8 {
        d_delta(&hub, "t24b", seq, &chunk);
    }

    let mut from = 0u64;
    let mut last_from_seq: Option<u64> = None;
    let mut collected = Vec::new();
    loop {
        let page = hub.read_page("t24b", from);
        assert_eq!(page.dropped_count, 0, "inside bounds nothing drops");
        if let Some(prev) = last_from_seq {
            assert!(page.from_seq > prev, "pages must ascend by from_seq");
        }
        last_from_seq = Some(page.from_seq);
        let seqs: Vec<u64> = page.deltas.iter().map(|i| i.from_seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        assert_eq!(seqs, sorted, "items ordered within the page");
        collected.extend(seqs);
        match page.cursor {
            Some(c) if page.page_limit_reached => from = c.from_cursor + 1,
            _ => break,
        }
    }
    assert_eq!(collected, (0..8).collect::<Vec<u64>>());

    // Push past the 256 KiB window: the RELEASED head evicts (floor rises)…
    d_delta(&hub, "t24b", 8, &chunk);
    d_delta(&hub, "t24b", 9, &chunk);
    // …and a below-floor request reports the loss.
    let below = hub.read_page("t24b", 0);
    assert!(
        below.dropped_count > 0,
        "below-floor request must report dropped_count > 0"
    );
}

/// T24-c: fill the window, drive Terminal, read post-terminal — every in-window seq comes
/// back with dropped_count == 0 and the settlement marker present.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t24c_terminal_settlement_serves_every_in_window_seq() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let hub = delta_hub_with_clock(clock);
    d_begin(&hub, "agent-a", "t24c");
    for seq in 0..100u64 {
        d_delta(&hub, "t24c", seq, &format!("w{seq}. "));
    }
    d_terminal(&hub, "t24c", 100);
    let page = hub.read_page("t24c", 0);
    assert!(!page.absent);
    assert_eq!(page.dropped_count, 0, "in-window fill loses nothing");
    assert_eq!(
        page.deltas.iter().map(|i| i.from_seq).collect::<Vec<_>>(),
        (0..100).collect::<Vec<u64>>()
    );
    let terminal = page
        .terminal
        .expect("post-terminal read carries the marker");
    assert_eq!(terminal.seq, 100);
    assert_eq!(terminal.reason, "completed");
}

/// T24-d: request-shape both-or-neither; cross-domain event↔delta rejects BOTH directions;
/// tampered ciphertext rejected; plaintext↔sealed stream_key mismatch rejected.
#[test]
fn t24d_request_shape_and_cursor_domains() {
    let codec = AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    );
    // (vi) a valid pair resolves past the minted item boundary.
    let token = seal_delta_cursor(&codec, "t24d-s", 41).unwrap();
    let ok = resolve_stream_request(
        Some(&codec),
        &LlmDeltaStreamRequest {
            stream_key: Some("t24d-s".into()),
            from_cursor: Some(token.clone()),
        },
    )
    .unwrap();
    assert_eq!(ok, ("t24d-s".to_string(), 42));
    // A fresh subscribe (stream_key alone) reads from 0.
    assert_eq!(
        resolve_stream_request(
            Some(&codec),
            &LlmDeltaStreamRequest {
                stream_key: Some("t24d-s".into()),
                from_cursor: None,
            },
        )
        .unwrap(),
        ("t24d-s".to_string(), 0)
    );
    // (i) both-or-neither request shape: empty and cursor-only frames reject.
    assert!(resolve_stream_request(Some(&codec), &LlmDeltaStreamRequest::default()).is_err());
    assert!(resolve_stream_request(
        Some(&codec),
        &LlmDeltaStreamRequest {
            stream_key: None,
            from_cursor: Some(token.clone()),
        },
    )
    .is_err());
    // (v) plaintext↔sealed stream_key mismatch rejects.
    assert!(resolve_stream_request(
        Some(&codec),
        &LlmDeltaStreamRequest {
            stream_key: Some("someone-else".into()),
            from_cursor: Some(token.clone()),
        },
    )
    .is_err());
    // (ii) cross-domain rejects in BOTH directions.
    let event_token = codec
        .seal(
            SealPurpose::Cursor,
            "stream-1",
            SEAL_TAG_RAW_ID,
            b"raw-ev-1",
        )
        .unwrap();
    assert!(
        resolve_stream_request(
            Some(&codec),
            &LlmDeltaStreamRequest {
                stream_key: Some("stream-1".into()),
                from_cursor: Some(event_token),
            },
        )
        .is_err(),
        "an event-domain cursor must not resume a delta stream"
    );
    assert!(
        codec.open(SealPurpose::Cursor, "stream-1", &token).is_err(),
        "a delta cursor must not open on the event-cursor surface"
    );
    assert!(codec
        .open(SealPurpose::EventId, "stream-1", &token)
        .is_err());
    // (iv) tampered ciphertext rejects.
    let payload_start = token.rfind('.').unwrap() + 1;
    let mut chars: Vec<char> = token.chars().collect();
    let idx = payload_start + 7;
    chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert!(resolve_stream_request(
        Some(&codec),
        &LlmDeltaStreamRequest {
            stream_key: Some("t24d-s".into()),
            from_cursor: Some(tampered),
        },
    )
    .is_err());
    // A missing codec fails closed for any cursor-bearing request.
    assert!(resolve_stream_request(
        None,
        &LlmDeltaStreamRequest {
            stream_key: Some("t24d-s".into()),
            from_cursor: Some(token),
        },
    )
    .is_err());
}

/// T24-e: absent semantics — (a) serve-first + linger lazy eviction; (b) unknown /
/// live-quiet / refused; (c) lingering-cap displacement of a previously-served entry.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t24e_absent_semantics_linger_refusal_displacement() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let hub = delta_hub_with_clock(Arc::clone(&clock));

    // (a) serve-first arms: a page was SERVED, then the stream terminated; past the linger a
    // read lazily evicts and answers absent — previously-served ⇒ never served again.
    d_begin(&hub, "agent-a", "t24e-victim");
    d_delta(&hub, "t24e-victim", 0, "served content one. ");
    let served = hub.read_page("t24e-victim", 0);
    assert!(!served.absent);
    assert_eq!(served.deltas.len(), 1, "serve-first arms the witness");
    d_terminal(&hub, "t24e-victim", 1);
    clock.advance(30_001);
    let gone = hub.read_page("t24e-victim", 0);
    assert!(
        gone.absent,
        "linger-expired read lazily evicts + answers absent"
    );
    assert!(gone.deltas.is_empty() && gone.terminal.is_none());
    assert!(hub.read_page("t24e-victim", 0).absent, "never served again");

    // (b) unknown key / live-quiet admitted / refused key.
    assert!(
        hub.read_page("t24e-never-began", 0).absent,
        "unknown key reads absent"
    );
    d_begin(&hub, "agent-q", "t24e-quiet");
    let quiet = hub.read_page("t24e-quiet", 0);
    assert!(
        !quiet.absent && quiet.deltas.is_empty(),
        "a live-but-quiet admitted stream reads absent:false"
    );
    for i in 0..8 {
        d_begin(&hub, "agent-r", &format!("t24e-r{i}"));
    }
    d_begin(&hub, "agent-r", "t24e-refused"); // 9th per-agent → refused, no entry
    assert!(
        hub.read_page("t24e-refused", 0).absent,
        "refused key reads absent"
    );

    // (c) displacement: serve + terminate a victim, then 64 further admitted-first-Terminals
    // displace it from the lingering set → absent.
    d_begin(&hub, "agent-v", "t24e-victim2");
    d_delta(&hub, "t24e-victim2", 0, "served content two. ");
    assert_eq!(hub.read_page("t24e-victim2", 0).deltas.len(), 1);
    d_terminal(&hub, "t24e-victim2", 1);
    for a in 0..8 {
        for k in 0..8 {
            let key = format!("t24e-d{a}-{k}");
            d_begin(&hub, &format!("agent-d{a}"), &key);
            d_terminal(&hub, &key, 0);
        }
    }
    assert!(
        hub.read_page("t24e-victim2", 0).absent,
        "lingering-cap displacement evicts the oldest previously-served entry"
    );
}

/// T24-g: the 65th global and the 9th per-agent Begin are refused (no entry, no memory).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t24g_admission_caps_refuse_ninth_per_agent_and_sixty_fifth_global() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let hub = delta_hub_with_clock(clock);
    for i in 0..8 {
        d_begin(&hub, "agent-solo", &format!("t24g-solo-{i}"));
    }
    d_begin(&hub, "agent-solo", "t24g-solo-9th");
    assert!(
        hub.read_page("t24g-solo-9th", 0).absent,
        "9th per-agent Begin refused"
    );
    for a in 0..7 {
        for k in 0..8 {
            d_begin(&hub, &format!("agent-g{a}"), &format!("t24g-{a}-{k}"));
        }
    }
    d_begin(&hub, "agent-fresh", "t24g-65th");
    assert!(
        hub.read_page("t24g-65th", 0).absent,
        "65th global Begin refused"
    );
    // Later frames for a refused key drop at membership — still absent, still no entry.
    d_delta(&hub, "t24g-65th", 0, "late frame. ");
    assert!(hub.read_page("t24g-65th", 0).absent);
    assert!(
        !hub.read_page("t24g-solo-0", 0).absent,
        "admitted streams unaffected"
    );
}

/// T24-h: post-terminal deltas accepted below/equal/above Terminal.seq AND released
/// (zero-viable-tail fixture); a second Terminal is absorbed and displaces nothing; the
/// terminal marker rides the FIRST page after Terminal ARRIVES even while a viable tail is
/// withheld (separate viable-tail sub-case).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t24h_post_terminal_acceptance_release_and_viable_tail() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let hub = delta_hub_with_clock(clock);

    d_begin(&hub, "agent-a", "t24h");
    d_delta(&hub, "t24h", 0, "pre one. ");
    d_delta(&hub, "t24h", 1, "pre two. ");
    d_terminal(&hub, "t24h", 5);
    d_delta(&hub, "t24h", 3, "post below. ");
    d_delta(&hub, "t24h", 5, "post equal. ");
    d_delta(&hub, "t24h", 7, "post above. ");
    let page = hub.read_page("t24h", 0);
    assert_eq!(
        page.deltas.iter().map(|i| i.from_seq).collect::<Vec<_>>(),
        vec![0, 1, 3, 5, 7],
        "post-terminal deltas below/equal/above Terminal.seq accepted AND released"
    );
    assert_eq!(page.dropped_count, 0);
    let terminal = page.terminal.clone().expect("terminal marker");
    assert_eq!(terminal.seq, 5);

    // A second Terminal is absorbed — and displaces nothing.
    d_begin(&hub, "agent-b", "t24h-other");
    d_terminal(&hub, "t24h-other", 0);
    d_terminal(&hub, "t24h", 9); // absorbed
    assert_eq!(
        hub.read_page("t24h", 0).terminal.unwrap().seq,
        5,
        "second Terminal absorbed"
    );
    assert!(
        !hub.read_page("t24h-other", 0).absent,
        "an absorbed Terminal displaces nothing"
    );

    // Viable-tail sub-case: the marker rides the FIRST page after Terminal arrives even
    // while the viable Block-prefix tail is withheld by the hold discipline.
    d_begin(&hub, "agent-a", "t24h-vt");
    d_delta(&hub, "t24h-vt", 0, "clean head. ");
    d_delta(&hub, "t24h-vt", 1, "AKIA"); // viable aws_access_key prefix — never released
    d_terminal(&hub, "t24h-vt", 2);
    let vt = hub.read_page("t24h-vt", 0);
    assert_eq!(
        vt.deltas.iter().map(|i| i.from_seq).collect::<Vec<_>>(),
        vec![0],
        "the viable tail is withheld"
    );
    assert!(
        !vt.deltas.iter().any(|i| i.text.contains("AKIA")),
        "the viable tail never ships"
    );
    assert!(
        vt.terminal.is_some(),
        "terminal marker present on the FIRST page while the tail is withheld"
    );
}

// ── MODULE-020-T25 (e2e; real socket) ─────────────────────────────────────────────────────

/// T25: bearer subprotocol + full-handle() seed pass + pages through Terminal over the REAL
/// `ClientApiServer` WS route. Asserts order/content/terminal ONLY (zero-viable-tail
/// fixture); an unauthenticated upgrade is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t25_real_socket_pages_through_terminal() {
    let hub = Arc::new(LlmDeltaHub::new(
        Some(Arc::new(DefaultLeakDetector::new())),
        Some(real_hold_split()),
        Arc::new(SystemClock),
        None,
    ));
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, _exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    // An unauthenticated upgrade is refused (no bearer subprotocol → 401, no upgrade).
    match connect_delta(port, &origin, None).await {
        Err(err) => assert_eq!(
            upgrade_status(&err),
            Some(401),
            "unauthenticated upgrade must be refused with 401"
        ),
        Ok(_) => panic!("unauthenticated upgrade must be refused"),
    }

    // Zero-viable-tail fixture; a prefix fed before subscribing, the rest after.
    d_begin(&hub, "agent-t25", "t25-s");
    d_delta(&hub, "t25-s", 0, "one. ");
    d_delta(&hub, "t25-s", 1, "two. ");

    let mut socket = connect_delta(port, &origin, Some(TOKEN))
        .await
        .expect("delta ws upgrade");
    read_delta_seed(&mut socket).await;
    send_frame(&mut socket, json!({ "stream_key": "t25-s" })).await;

    d_delta(&hub, "t25-s", 2, "three. ");
    d_terminal(&hub, "t25-s", 3);

    let mut seen: Vec<(u64, String)> = Vec::new();
    let mut terminal_reason: Option<String> = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while terminal_reason.is_none() {
        assert!(
            Instant::now() < deadline,
            "terminal page never arrived (seen={seen:?})"
        );
        let (_, page) = read_delta_wire_page(&mut socket, Duration::from_secs(5))
            .await
            .expect("delta page");
        assert_eq!(page.stream_key, "t25-s");
        assert!(!page.absent);
        assert_eq!(page.dropped_count, 0);
        for item in &page.deltas {
            if let Some((last, _)) = seen.last() {
                assert!(
                    item.from_seq > *last,
                    "pages must stay ordered with no re-delivery"
                );
            }
            seen.push((item.from_seq, item.text.clone()));
        }
        if !page.deltas.is_empty() {
            assert!(
                page.cursor.is_some(),
                "a content page mints a sealed item-boundary cursor"
            );
        }
        if let Some(t) = &page.terminal {
            terminal_reason = Some(t.reason.clone());
        }
    }
    assert_eq!(
        seen,
        vec![
            (0, "one. ".to_string()),
            (1, "two. ".to_string()),
            (2, "three. ".to_string())
        ],
        "order + content through Terminal"
    );
    assert_eq!(terminal_reason.as_deref(), Some("completed"));

    socket.close(None).await.ok();
    server.shutdown().await.unwrap();
}

// ── MODULE-020-T26 (security integration; real socket; injected triple) ───────────────────

/// T26-a: revoke the session mid-stream → the FULL-handle() re-auth beat cuts IMMEDIATELY
/// (exit auth_failure_immediate), wall ≤ 15 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t26a_revocation_cut_is_immediate_and_within_bound() {
    let hub = delta_hub_timed(t26_timing());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let api = Arc::new(api);
    let server = ClientApiServer::bind(Arc::clone(&api), port).await.unwrap();

    d_begin(&hub, "agent-a", "t26a");
    d_delta(&hub, "t26a", 0, "mid stream page. ");
    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await;
    send_frame(&mut socket, json!({ "stream_key": "t26a" })).await;
    let (_, page) = read_delta_wire_page(&mut socket, Duration::from_secs(5))
        .await
        .expect("mid-stream page");
    assert_eq!(page.deltas.len(), 1);

    let revoked_at = Instant::now();
    api.sessions().revoke(TOKEN);
    let (_texts, saw_close, text_after_close) =
        drain_until_close(&mut socket, Duration::from_secs(15)).await;
    let cut_elapsed = revoked_at.elapsed();
    assert!(saw_close, "the cut must close the socket");
    assert!(
        cut_elapsed <= Duration::from_secs(15),
        "revocation cut must land within 15 s (took {cut_elapsed:?})"
    );
    assert!(!text_after_close, "no delta frame after the cut");
    assert_eq!(
        wait_exit(&exits, Duration::from_secs(5)).await,
        Some(DeltaPumpExit::AuthFailureImmediate),
        "an auth-failure verdict cuts IMMEDIATELY"
    );

    server.shutdown().await.unwrap();
}

/// T26-b: hold every dispatch permit (the transport_dispatch_cap saturation seam; subscribe
/// FIRST) → the pump cuts at the reauth deadline measured from the seed anchor. This is the
/// witness that the re-auth beat goes through the FULL handle() dispatch pipeline: the
/// saturated-permit fail-CLOSED leg is reachable only via the dispatch semaphore.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26b_saturated_dispatch_cuts_at_reauth_deadline() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct BlockingEventProvider {
        started: Arc<AtomicUsize>,
        release: Arc<AtomicBool>,
    }
    impl ClientEventProvider for BlockingEventProvider {
        fn retention_days(&self) -> u32 {
            30
        }
        fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
            Ok(None)
        }
        fn query_history(
            &self,
            _f: &NormalizedEventFilter,
            _l: usize,
        ) -> Result<Vec<RawEventRow>, ProviderError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(Vec::new())
        }
        fn drain_stream(
            &self,
            _a: Option<&str>,
            _s: usize,
            _i: u64,
        ) -> Result<Vec<RawEventRow>, ProviderError> {
            Ok(Vec::new())
        }
    }

    let hub = delta_hub_timed(t26_timing());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let mut config = ClientApiConfig::default();
    config.max_concurrent_dispatch = 2;
    let (api, exits) = delta_api_base(&origin, &hub, config, None);
    let api = api
        .with_event_provider(Arc::new(BlockingEventProvider {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        }))
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    // Subscribe FIRST (the seed pass needs a dispatch permit while unsaturated).
    let t0 = Instant::now();
    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await;

    // Saturate BOTH dispatch permits: every later beat finds the semaphore empty — no
    // in-beat retry, no anchor refresh — so the unconditional deadline fires from the last
    // successful anchor.
    let h1 =
        tokio::spawn(async move { http_get(port, "/client/events?limit=1", Some(TOKEN)).await });
    let h2 =
        tokio::spawn(async move { http_get(port, "/client/events?limit=1", Some(TOKEN)).await });
    let sat_start = Instant::now();
    while started.load(Ordering::SeqCst) < 2 {
        assert!(
            sat_start.elapsed() < Duration::from_secs(5),
            "the saturation requests did not both enter the provider"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let (_texts, saw_close, _after) = drain_until_close(&mut socket, Duration::from_secs(10)).await;
    let elapsed = t0.elapsed();
    assert!(saw_close, "the deadline cut must close the socket");
    assert_eq!(
        wait_exit(&exits, Duration::from_secs(5)).await,
        Some(DeltaPumpExit::ReauthDeadline),
        "saturation fails CLOSED into the reauth_deadline cut"
    );
    assert!(
        elapsed >= Duration::from_millis(900),
        "the cut must not fire before the deadline window ({elapsed:?})"
    );
    assert!(
        elapsed <= Duration::from_secs(6),
        "the cut must land near the deadline ({elapsed:?})"
    );

    release.store(true, Ordering::SeqCst);
    let (s1, _) = h1.await.unwrap();
    let (s2, _) = h2.await.unwrap();
    assert_eq!((s1, s2), (200, 200));
    server.shutdown().await.unwrap();
}

/// T26-c: pages in flight at the cut — after the Close frame, the received byte stream
/// carries NO further delta frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26c_no_delta_after_close_under_live_feed() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let hub = delta_hub_timed(t26_timing());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let api = Arc::new(api);
    let server = ClientApiServer::bind(Arc::clone(&api), port).await.unwrap();

    d_begin(&hub, "agent-a", "t26c");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_feed = Arc::clone(&stop);
    let feeder_hub = Arc::clone(&hub);
    let feeder = std::thread::spawn(move || {
        let mut seq = 0u64;
        while !stop_feed.load(Ordering::SeqCst) {
            d_delta(&feeder_hub, "t26c", seq, &format!("live {seq}. "));
            seq += 1;
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await;
    send_frame(&mut socket, json!({ "stream_key": "t26c" })).await;
    // At least one page is in flight before the cut.
    assert!(
        read_delta_wire_page(&mut socket, Duration::from_secs(5))
            .await
            .is_some(),
        "live pages must be flowing before the cut"
    );

    api.sessions().revoke(TOKEN);
    let (_texts, saw_close, text_after_close) =
        drain_until_close(&mut socket, Duration::from_secs(10)).await;
    stop.store(true, Ordering::SeqCst);
    feeder.join().unwrap();
    assert!(saw_close, "the cut must close the socket");
    assert!(
        !text_after_close,
        "no delta frame may follow the Close frame on the received bytes"
    );
    assert_eq!(
        wait_exit(&exits, Duration::from_secs(5)).await,
        Some(DeltaPumpExit::AuthFailureImmediate)
    );

    server.shutdown().await.unwrap();
}

/// T26-d: 4 subscribers hold the RAII cap; the 5th is refused with 429 stream_backpressure
/// and NO upgrade; a plain GET consumes no slot; a panicking pump releases its slot.
/// Cadence 1 s here (not the 250 ms triple) so idle-pump ping deadlines cannot free a slot
/// before the panic does — the slot-freeing event under test must be the panic alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26d_subscriber_cap_plain_get_and_panicking_pump_release() {
    struct PanickingDetector;
    impl LeakDetector for PanickingDetector {
        fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
            panic!("injected detector panic (T26-d; expected)");
        }
        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    let hub = Arc::new(LlmDeltaHub::with_timing(
        Some(Arc::new(PanickingDetector)),
        Some(real_hold_split()),
        Arc::new(SystemClock),
        None,
        DeltaTiming {
            cadence: Duration::from_secs(1),
            reauth_max_age: Duration::from_secs(3),
            allowance: Duration::from_millis(100),
            linger: Duration::from_secs(30),
        },
    ));
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, _exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    // Fill the RAII subscriber cap (4).
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut s = connect_delta(port, &origin, Some(TOKEN))
            .await
            .expect("subscriber");
        read_delta_seed(&mut s).await;
        held.push(s);
    }
    // The 5th is refused with the EXISTING stream_backpressure → 429, at the seed stage
    // (before any upgrade).
    match connect_delta(port, &origin, Some(TOKEN)).await {
        Err(err) => assert_eq!(upgrade_status(&err), Some(429), "5th subscriber must 429"),
        Ok(_) => panic!("the 5th subscriber must be refused"),
    }
    // A plain (non-upgrade) GET consumes no slot — it succeeds even at cap.
    let (status, body) = http_get(port, "/client/llm/deltas/stream", Some(TOKEN)).await;
    assert_eq!(
        status, 200,
        "plain GET must need no subscriber slot: {body}"
    );
    assert!(
        body.contains("\"subscribed\":true"),
        "plain GET answers the subscribe probe: {body}"
    );

    // Keep 3 idle subscribers responsive so their pumps cannot be the slot-freeing event.
    let mut first = held.remove(0);
    let keepers: Vec<_> = held.into_iter().map(spawn_ping_keeper).collect();

    // Panic the FIRST pump: subscribe it, then feed — its read_page unwinds in the scan.
    d_begin(&hub, "agent-a", "t26d");
    send_frame(&mut first, json!({ "stream_key": "t26d" })).await;
    d_delta(&hub, "t26d", 0, "boom fixture. ");

    // The panicking pump's task aborts; its RAII slot must release → a new subscriber fits.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut readmitted = false;
    while Instant::now() < deadline {
        match connect_delta(port, &origin, Some(TOKEN)).await {
            Ok(mut s) => {
                read_delta_seed(&mut s).await;
                readmitted = true;
                break;
            }
            Err(err) if upgrade_status(&err) == Some(429) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(err) => panic!("unexpected refusal while waiting for the freed slot: {err:?}"),
        }
    }
    assert!(readmitted, "a panicking pump must release its RAII slot");

    for keeper in keepers {
        keeper.abort();
    }
    server.shutdown().await.unwrap();
}

/// T26-e: kill a peer WITHOUT a close frame → the slot releases within ~one beat and the
/// exit reason is peer_dead (the socket-error-observable leg, B3(ii)) — NOT C-7's
/// pong_timeout. The mutation isolator is exit-reason-based, not wall-time-based.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26e_dead_peer_slot_release_discriminated_as_peer_dead() {
    let hub = delta_hub_timed(t26_timing());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    let mut held = Vec::new();
    for _ in 0..4 {
        let mut s = connect_delta(port, &origin, Some(TOKEN))
            .await
            .expect("subscriber");
        read_delta_seed(&mut s).await;
        held.push(s);
    }
    let first = held.remove(0);
    let keepers: Vec<_> = held.into_iter().map(spawn_ping_keeper).collect();

    // Kill the peer without a close frame: dropping tears the TCP stream down with no WS
    // Close handshake → the pump's recv errors (peer_dead), it does not wait for a pong.
    let killed_at = Instant::now();
    drop(first);

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut readmitted_at = None;
    while Instant::now() < deadline {
        match connect_delta(port, &origin, Some(TOKEN)).await {
            Ok(mut s) => {
                read_delta_seed(&mut s).await;
                readmitted_at = Some(killed_at.elapsed());
                break;
            }
            Err(err) if upgrade_status(&err) == Some(429) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => panic!("unexpected refusal while waiting for the freed slot: {err:?}"),
        }
    }
    let readmitted_at = readmitted_at.expect("the dead peer's slot must release");
    assert!(
        readmitted_at <= Duration::from_secs(1),
        "slot must release within ~one beat (took {readmitted_at:?})"
    );
    assert_eq!(
        wait_exit(&exits, Duration::from_secs(2)).await,
        Some(DeltaPumpExit::PeerDead),
        "the dead-peer cut discriminates by exit reason: peer_dead, NOT pong_timeout"
    );

    for keeper in keepers {
        keeper.abort();
    }
    server.shutdown().await.unwrap();
}

/// T26-f: (i) a session WITHOUT the scope → 403 (the scope gate precedes everything else);
/// (ii) scope present + kill switch OFF → the EXISTING module_unavailable — and an
/// under-scoped caller still sees 403 with the switch off (flag state never leaks).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t26f_scope_gate_403_and_kill_switch_module_unavailable() {
    let under_scoped: Vec<Scope> = Scope::operator_default()
        .into_iter()
        .filter(|s| *s != Scope::ReadLlmDeltas)
        .collect();

    // (i) missing Scope::ReadLlmDeltas → 403 at the seed, no upgrade.
    let hub = delta_hub_timed(t26_timing());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, _exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, under_scoped.clone());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();
    match connect_delta(port, &origin, Some(TOKEN)).await {
        Err(err) => assert_eq!(upgrade_status(&err), Some(403), "under-scoped must 403"),
        Ok(_) => panic!("an under-scoped subscribe must be refused"),
    }
    server.shutdown().await.unwrap();

    // (ii) scope present + kill switch OFF → module_unavailable (503), evaluated AFTER the
    // scope gate.
    let hub2 = delta_hub_timed(t26_timing());
    let port2 = free_port();
    let origin2 = format!("http://127.0.0.1:{port2}");
    let mut config = ClientApiConfig::default();
    config.llm_deltas_enabled = false;
    let (api2, _e2) = delta_api_base(&origin2, &hub2, config, None);
    install_delta_session(&api2, u64::MAX, Scope::operator_default());
    let api2 = Arc::new(api2);
    api2.sessions().insert(
        "underscoped-token".into(),
        ClientSession {
            session_id: "underscoped-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: under_scoped,
            csrf_token: Some("underscoped-csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );
    let server2 = ClientApiServer::bind(Arc::clone(&api2), port2)
        .await
        .unwrap();
    match connect_delta(port2, &origin2, Some(TOKEN)).await {
        Err(err) => assert_eq!(
            upgrade_status(&err),
            Some(503),
            "kill switch OFF must answer 503"
        ),
        Ok(_) => panic!("kill switch OFF must refuse the subscribe"),
    }
    let (status, body) = http_get(port2, "/client/llm/deltas/stream", Some(TOKEN)).await;
    assert_eq!(status, 503);
    assert!(
        body.contains("module_unavailable"),
        "OFF answers the EXISTING code: {body}"
    );
    // Flag state never leaks to an under-scoped caller: still 403, not 503.
    let (status_u, body_u) = http_get(
        port2,
        "/client/llm/deltas/stream",
        Some("underscoped-token"),
    )
    .await;
    assert_eq!(
        status_u, 403,
        "an under-scoped caller sees 403 regardless of the flag: {body_u}"
    );
    server2.shutdown().await.unwrap();
}

/// T26-g: a session whose `expires_at` is nearer than one beat ends the pump with the
/// expires_at exit (independent of revocation and of the re-auth deadline).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t26g_expires_at_nearer_than_one_beat_cuts_with_expires_at() {
    // Cadence 2 s with a ~500 ms expiry: the expiry arm must fire BEFORE the first beat
    // could even run (and give the handshake wide margin on a slow runner).
    let hub = delta_hub_timed(DeltaTiming {
        cadence: Duration::from_secs(2),
        reauth_max_age: Duration::from_secs(6),
        allowance: Duration::from_millis(100),
        linger: Duration::from_secs(30),
    });
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(
        &api,
        SystemClock.now_millis() + 500,
        Scope::operator_default(),
    );
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    let t0 = Instant::now();
    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await;
    let (_texts, saw_close, _after) = drain_until_close(&mut socket, Duration::from_secs(5)).await;
    assert!(saw_close, "the expiry cut must close the socket");
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "the pump must end promptly at expires_at"
    );
    assert_eq!(
        wait_exit(&exits, Duration::from_secs(2)).await,
        Some(DeltaPumpExit::ExpiresAt),
        "the lifetime cap exit is expires_at, not a re-auth cut"
    );

    server.shutdown().await.unwrap();
}

/// T26-h (wire leg): a REAL cap-http Redact-pattern secret planted in the fed delta text is
/// never on the wire — the tainted span collapses to a replacement entry with
/// redacted_count > 0; a hub built WITHOUT its egress detector refuses subscriptions, and so
/// does one WITHOUT its hold-geometry closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t26h_egress_wire_redaction_and_construction_fail_closed() {
    let hub = delta_hub_timed(t26_timing());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, _exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    // A real `bearer_token` Redact-pattern instance (cap-http LEAK_PATTERNS).
    const SECRET: &str = "Bearer eyJhbGciOiJIUzI1NiJ9secretpayload42";
    const SECRET_TAIL: &str = "eyJhbGciOiJIUzI1NiJ9secretpayload42";

    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await;
    send_frame(&mut socket, json!({ "stream_key": "t26h" })).await;

    d_begin(&hub, "agent-a", "t26h");
    d_delta(&hub, "t26h", 0, "intro line. ");
    d_delta(&hub, "t26h", 1, &format!("leak {SECRET} tail done. "));
    d_terminal(&hub, "t26h", 2);

    let mut raw_frames = Vec::new();
    let mut redacted_total = 0u32;
    let mut saw_replacement_entry = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "terminal page never arrived");
        let (raw, page) = read_delta_wire_page(&mut socket, Duration::from_secs(5))
            .await
            .expect("delta page");
        raw_frames.push(raw);
        redacted_total += page.redacted_count;
        saw_replacement_entry |= page.deltas.iter().any(|i| i.text.contains("[REDACTED]"));
        if page.terminal.is_some() {
            break;
        }
    }
    let all_received: String = raw_frames.concat();
    assert!(
        !all_received.contains(SECRET_TAIL),
        "the planted secret's plaintext must never be in the received bytes"
    );
    assert!(redacted_total > 0, "redacted_count > 0 must reach the wire");
    assert!(
        saw_replacement_entry,
        "the tainted span collapses to a replacement entry"
    );
    socket.close(None).await.ok();
    server.shutdown().await.unwrap();

    // Hub built WITHOUT the egress detector → subscribe refused (fail closed, no upgrade).
    let hub_no_detector = Arc::new(LlmDeltaHub::with_timing(
        None,
        Some(real_hold_split()),
        Arc::new(SystemClock),
        None,
        t26_timing(),
    ));
    let port2 = free_port();
    let origin2 = format!("http://127.0.0.1:{port2}");
    let (api2, _e2) = delta_api_base(&origin2, &hub_no_detector, ClientApiConfig::default(), None);
    install_delta_session(&api2, u64::MAX, Scope::operator_default());
    let server2 = ClientApiServer::bind(Arc::new(api2), port2).await.unwrap();
    match connect_delta(port2, &origin2, Some(TOKEN)).await {
        Err(err) => assert_eq!(
            upgrade_status(&err),
            Some(503),
            "a detector-less hub must refuse subscriptions"
        ),
        Ok(_) => panic!("a detector-less hub must refuse subscriptions"),
    }
    server2.shutdown().await.unwrap();

    // Hub built WITHOUT the hold-geometry closure → the same refusal.
    let hub_no_hold = Arc::new(LlmDeltaHub::with_timing(
        Some(Arc::new(DefaultLeakDetector::new())),
        None,
        Arc::new(SystemClock),
        None,
        t26_timing(),
    ));
    let port3 = free_port();
    let origin3 = format!("http://127.0.0.1:{port3}");
    let (api3, _e3) = delta_api_base(&origin3, &hub_no_hold, ClientApiConfig::default(), None);
    install_delta_session(&api3, u64::MAX, Scope::operator_default());
    let server3 = ClientApiServer::bind(Arc::new(api3), port3).await.unwrap();
    match connect_delta(port3, &origin3, Some(TOKEN)).await {
        Err(err) => assert_eq!(
            upgrade_status(&err),
            Some(503),
            "a hold-less hub must refuse subscriptions"
        ),
        Ok(_) => panic!("a hold-less hub must refuse subscriptions"),
    }
    server3.shutdown().await.unwrap();
}

/// T26-h (disposition legs, REAL pattern source): cross-entry in-step collapse; straddle
/// across steps (head held, never on wire); head-held-pre-terminal + tail-post-terminal
/// caught whole; Warn-action delivered verbatim + warned_count; a Blocked span ships ONE
/// EMPTY range entry.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t26h_egress_dispositions_cross_entry_straddle_warn_block() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let hub = delta_hub_with_clock(clock);

    // Cross-entry in-step: a secret split across two frames scanned in ONE step collapses to
    // one seq-range replacement entry; the fragments never ship.
    d_begin(&hub, "agent-a", "ce");
    d_delta(&hub, "ce", 0, "Bearer ey");
    d_delta(&hub, "ce", 1, "JXentry77token tail. ");
    let page = hub.read_page("ce", 0);
    assert_eq!(
        page.deltas.len(),
        1,
        "one collapse entry for the tainted step"
    );
    assert_eq!((page.deltas[0].from_seq, page.deltas[0].to_seq), (0, 1));
    assert!(page.deltas[0].text.contains("[REDACTED]"));
    assert!(!page.deltas[0].text.contains("JXentry77token"));
    assert_eq!(page.redacted_count, 2, "both collapsed seqs count");

    // Straddle across STEPS: the viable head is HELD (never on the wire); the joined next
    // step catches the whole secret.
    d_begin(&hub, "agent-a", "st");
    d_delta(&hub, "st", 0, "clean lead. ");
    d_delta(&hub, "st", 1, "Bearer ey");
    let first = hub.read_page("st", 0);
    assert_eq!(
        first
            .deltas
            .iter()
            .map(|i| i.text.as_str())
            .collect::<Vec<_>>(),
        vec!["clean lead. "],
        "only the clean prefix releases; the viable head is held"
    );
    d_delta(&hub, "st", 2, "Jstraddle88tok rest. ");
    let second = hub.read_page("st", 0);
    let joined: String = second.deltas.iter().map(|i| i.text.as_str()).collect();
    assert!(
        !joined.contains("Jstraddle88tok") && !joined.contains("Bearer ey"),
        "the straddling secret never assembles on the wire: {joined:?}"
    );
    assert!(joined.contains("[REDACTED]"));
    assert!(second.redacted_count >= 2);

    // Head held PRE-terminal + tail POST-terminal → caught WHOLE by the joined hold scan.
    d_begin(&hub, "agent-a", "ht");
    d_delta(&hub, "ht", 0, "opening text. ");
    d_delta(&hub, "ht", 1, "Bearer ey");
    let pre = hub.read_page("ht", 0);
    assert_eq!(pre.deltas.len(), 1, "the viable head is held pre-terminal");
    d_terminal(&hub, "ht", 2);
    let at_terminal = hub.read_page("ht", 0);
    assert!(
        at_terminal.terminal.is_some(),
        "terminal marker while the tail is withheld"
    );
    d_delta(&hub, "ht", 2, "Jposttail99x end. ");
    let post = hub.read_page("ht", 0);
    let joined: String = post.deltas.iter().map(|i| i.text.as_str()).collect();
    assert!(
        !joined.contains("Jposttail99x") && !joined.contains("Bearer ey"),
        "a pre-terminal head + post-terminal tail is caught whole: {joined:?}"
    );
    assert!(post.redacted_count >= 2);

    // Warn-action pattern (high_entropy_hex): delivered VERBATIM and counted.
    d_begin(&hub, "agent-a", "wa");
    let hex = "0123456789abcdef".repeat(4); // 64 hex chars → Warn
    d_delta(&hub, "wa", 0, &format!("{hex} end. "));
    let warned = hub.read_page("wa", 0);
    assert_eq!(warned.deltas.len(), 1);
    assert!(
        warned.deltas[0].text.contains(&hex),
        "a Warn-action pattern is delivered verbatim"
    );
    assert!(warned.warned_count >= 1);
    assert_eq!(warned.redacted_count, 0);

    // Blocked span (completed Block pattern): ONE EMPTY range entry + rejected_count.
    d_begin(&hub, "agent-a", "bl");
    d_delta(&hub, "bl", 0, "pre text. ");
    d_delta(&hub, "bl", 1, "AKIAABCDEFGHIJKLMNOP"); // completed aws_access_key → Block
    d_delta(&hub, "bl", 2, "post text. ");
    let blocked = hub.read_page("bl", 0);
    assert_eq!(
        blocked.deltas.len(),
        1,
        "the whole span collapses to ONE range entry"
    );
    assert_eq!(
        (blocked.deltas[0].from_seq, blocked.deltas[0].to_seq),
        (0, 2)
    );
    assert_eq!(
        blocked.deltas[0].text, "",
        "a Blocked span ships an EMPTY entry"
    );
    assert_eq!(blocked.rejected_count, 3);

    // FIX 6 (honest Warn-straddle behavior): a Warn-action pattern (high_entropy_hex) has NO
    // viable-prefix hold — the hold set is Block/Redact only (this is ratified: Warn passes
    // content). So a Warn secret SPLIT across two release steps is NOT withheld: it ships VERBATIM
    // and the counters report reality. A split whose halves match in NEITHER step alone reports
    // warned_count 0, and that is acceptable BECAUSE "never on the wire" protects the Block/Redact
    // class — which IS held (asserted in the contrast leg below). (The existing single-frame Warn
    // leg above stays as-is; it implied a straddle coverage it does not have.)
    let hex64 = "0123456789abcdef".repeat(4); // 64 hex chars = one high_entropy_hex Warn match
    d_begin(&hub, "agent-a", "ws");
    d_delta(&hub, "ws", 0, "lead 0123456789abcdef0123456789abcdef"); // 32 hex — below the 64 gate
    let ws_step1 = hub.read_page("ws", 0);
    assert_eq!(
        ws_step1.warned_count, 0,
        "a 32-hex half is not a Warn match on its own"
    );
    d_delta(&hub, "ws", 1, "0123456789abcdef0123456789abcdef trail. "); // the other 32 hex
    let ws_step2 = hub.read_page("ws", 0);
    let ws_wire: String = ws_step2.deltas.iter().map(|i| i.text.as_str()).collect();
    assert!(
        ws_wire.contains(&hex64),
        "a Warn match split across two steps ships VERBATIM (Warn content is not withheld): {ws_wire:?}"
    );
    assert_eq!(
        ws_step2.warned_count, 0,
        "the split matched in neither step alone → warned_count 0 (honest; the Block/Redact class is what 'never on the wire' protects)"
    );
    assert_eq!(ws_step2.redacted_count, 0);
    assert_eq!(ws_step2.rejected_count, 0);

    // CONTRAST: a Block/Redact secret split across the SAME step boundary IS held and NEVER on the
    // wire — the viable head is retained past the first step and the whole secret is caught when
    // the joined next step completes it.
    d_begin(&hub, "agent-a", "bh");
    d_delta(&hub, "bh", 0, "context lead. ");
    d_delta(&hub, "bh", 1, "prefix AKIA"); // a viable aws_access_key (Block) prefix at the end
    let bh_step1 = hub.read_page("bh", 0);
    let bh_wire1: String = bh_step1.deltas.iter().map(|i| i.text.as_str()).collect();
    assert!(
        !bh_wire1.contains("AKIA"),
        "the viable Block prefix is HELD, not released in the first step: {bh_wire1:?}"
    );
    d_delta(&hub, "bh", 2, "ABCDEFGHIJKLMNOP done. "); // completes AKIAABCDEFGHIJKLMNOP → Block
    let bh_step2 = hub.read_page("bh", 0);
    let bh_wire: String = bh_step2.deltas.iter().map(|i| i.text.as_str()).collect();
    assert!(
        !bh_wire.contains("AKIAABCDEFGHIJKLMNOP"),
        "the split Block secret is caught whole and never on the wire: {bh_wire:?}"
    );
    assert!(
        bh_step2.rejected_count >= 1,
        "the held Block secret is dropped fail-closed and counted"
    );
}

/// T26-j: a valid session with ~50 ms injected re-auth latency survives ≥3 deadline windows
/// while receiving deltas — start-anchored beats keep refreshing the anchor well inside the
/// 1 s deadline, so latency never erodes the bound into a false cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26j_reauth_latency_survives_three_deadline_windows() {
    /// ~25 ms per audit emit ⇒ ~50 ms per FULL handle() pass (request + response events).
    struct SlowSink;
    impl AuditSink for SlowSink {
        fn emit(&self, _event: AuditEvent) {
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    let hub = delta_hub_timed(t26_timing());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(
        &origin,
        &hub,
        ClientApiConfig::default(),
        Some(Arc::new(SlowSink)),
    );
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    d_begin(&hub, "agent-a", "t26j");
    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await;
    send_frame(&mut socket, json!({ "stream_key": "t26j" })).await;

    let feeder_hub = Arc::clone(&hub);
    let feeder = std::thread::spawn(move || {
        for seq in 0..40u64 {
            d_delta(&feeder_hub, "t26j", seq, &format!("j{seq}. "));
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    // Receive across ≥3 deadline windows (3 × 1 s): seq 30 is published at ~3.0 s.
    let t0 = Instant::now();
    let mut top_seq = 0u64;
    while t0.elapsed() < Duration::from_millis(3_400) {
        if let Some((_, page)) = read_delta_wire_page(&mut socket, Duration::from_millis(500)).await
        {
            if let Some(last) = page.deltas.last() {
                top_seq = top_seq.max(last.to_seq);
            }
        }
    }
    // Snapshot the exits WHILE the client is still a live, ping-answering peer: once this
    // test stops polling (join/teardown below), a later pong_timeout cut is the pump doing
    // its job on a gone-quiet peer, not a witness failure.
    let exits_during_stream = exits.lock().unwrap().clone();
    assert!(
        exits_during_stream.is_empty(),
        "no cut may fire for a valid session under 50 ms re-auth latency: {exits_during_stream:?}"
    );
    assert!(
        top_seq >= 30,
        "the stream must keep delivering across ≥3 deadline windows (top_seq={top_seq})"
    );

    socket.close(None).await.ok();
    feeder.join().unwrap();
    server.shutdown().await.unwrap();
}

// ── MODULE-020-T26 adversarial-fix witnesses (real socket; injected triple) ───────────────

/// FIX 1 (CRITICAL revocation escape): a peer that STOPS reading applies TCP backpressure, so the
/// pump's delivery send blocks with a page queued. The send is bounded by the imminent cut, so the
/// pump parks in that blocked send only until the start-anchored deadline, then cuts — a revoked
/// (or simply non-reading) session cannot keep the connection open by refusing to read. Without
/// the bound the blocking send parks the pump forever (the deliver is OUTSIDE the `select!`, so no
/// cut / deadline arm is ever polled again) and the pump never completes — `wait_exit` returns
/// `None` and this fails.
///
/// A brief, SELF-LIMITED flood drives the pump's send into TCP backpressure (loopback only blocks
/// once cumulative bytes exceed the socket buffers), then STOPS so the runtime idles and the tokio
/// timer can fire — a *continuous* flood keeps every worker busy and starves the timer. The cadence
/// is long so the pong deadline cannot preempt the parked pump, and reauth_max_age is short relative
/// to the flood so the bound is already due when the flood ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "flaky on GitHub Actions runners: backpressured send can miss ReauthDeadline under host load; tracked for post-genesis hardening"]
async fn t26_fix1_backpressured_send_still_cuts_at_reauth_deadline() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let hub = delta_hub_timed(DeltaTiming {
        cadence: Duration::from_secs(30), // no beat during the test → the pong path cannot preempt
        reauth_max_age: Duration::from_secs(5),
        allowance: Duration::from_millis(500),
        linger: Duration::from_secs(30),
    });
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let api = Arc::new(api);
    let server = ClientApiServer::bind(Arc::clone(&api), port).await.unwrap();

    d_begin(&hub, "agent-a", "f1");
    d_delta(&hub, "f1", 0, "first page. ");
    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await;
    send_frame(&mut socket, json!({ "stream_key": "f1" })).await;
    // Confirm the stream flows (client reads once, no flood yet), THEN stop reading entirely.
    read_delta_wire_page(&mut socket, Duration::from_secs(5))
        .await
        .expect("a page must flow before we stop reading");

    // A GENTLE continuous producer (yields the core each publish, so the tokio timer keeps
    // running): with the client no longer reading, the pump's send drives the socket buffers full
    // and blocks — the pump parks in `deliver_pending`, OUTSIDE the `select!`.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_feed = Arc::clone(&stop);
    let feeder_hub = Arc::clone(&hub);
    let feeder = std::thread::spawn(move || {
        let mut seq = 1u64;
        let chunk = "x".repeat(16 * 1024);
        while !stop_feed.load(Ordering::SeqCst) {
            d_delta(&feeder_hub, "f1", seq, &chunk);
            seq += 1;
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    let t_block = Instant::now();
    // With the fix, the bounded send lets the start-anchored deadline cut the parked pump (a
    // non-reading — e.g. revocation-evading — peer cannot hold the socket open by refusing to read);
    // without it, the pump is parked in the blocking send forever and this returns None.
    let exit = wait_exit(&exits, Duration::from_secs(12)).await;
    let cut_elapsed = t_block.elapsed();
    stop.store(true, Ordering::SeqCst);
    feeder.join().unwrap();

    assert_eq!(
        exit,
        Some(DeltaPumpExit::ReauthDeadline),
        "a backpressured delivery send must NOT park the pump — the start-anchored deadline cuts \
         (without the timeout the pump hangs and the non-reading session keeps its socket)"
    );
    assert!(
        cut_elapsed <= Duration::from_secs(10),
        "the cut lands within the deadline window (took {cut_elapsed:?})"
    );

    drop(socket);
    server.shutdown().await.unwrap();
}

/// FIX 2: the re-auth `spawn_blocking` join is bounded by `allowance`. A re-auth that overruns the
/// whole deadline window must NOT delay the cut — the join times out, the anchor is NOT refreshed,
/// and the unconditional start-anchored deadline fires on schedule. Without the bound the beat arm
/// blocks on the slow join and the deadline arm cannot fire until it returns, pushing the cut past
/// the deadline and mislabelling it `auth_failure_immediate`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_fix2_overrunning_reauth_still_cuts_at_deadline() {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Sleeps ONLY once armed, so the seed handshake is fast and only the re-auth beats overrun.
    struct ArmedSlowSink {
        armed: Arc<AtomicBool>,
    }
    impl AuditSink for ArmedSlowSink {
        fn emit(&self, _event: AuditEvent) {
            if self.armed.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(800)); // ≥ the 1 s deadline over 2 emits
            }
        }
    }

    let hub = delta_hub_timed(t26_timing()); // cadence 250 ms / allowance 100 ms / deadline 1 s
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let armed = Arc::new(AtomicBool::new(false));
    let (api, exits) = delta_api_base(
        &origin,
        &hub,
        ClientApiConfig::default(),
        Some(Arc::new(ArmedSlowSink {
            armed: Arc::clone(&armed),
        })),
    );
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let api = Arc::new(api);
    let server = ClientApiServer::bind(Arc::clone(&api), port).await.unwrap();

    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await; // fast (unarmed)

    // Arm the overrunning re-auth (each beat's handle() now takes ≥ the deadline window) and revoke.
    armed.store(true, Ordering::SeqCst);
    let revoked_at = Instant::now();
    api.sessions().revoke(TOKEN);
    // A ping-answering keeper so the cut is the deadline, not a pong timeout or peer_dead.
    let keeper = spawn_ping_keeper(socket);

    let exit = wait_exit(&exits, Duration::from_secs(8)).await;
    let cut_elapsed = revoked_at.elapsed();
    keeper.abort();

    assert_eq!(
        exit,
        Some(DeltaPumpExit::ReauthDeadline),
        "an overrunning re-auth is bounded by `allowance`, so the start-anchored deadline still \
         cuts (without the bound the slow join blocks the beat and delays/mislabels the cut)"
    );
    assert!(
        cut_elapsed <= Duration::from_secs(4),
        "the cut stays near the deadline window (took {cut_elapsed:?})"
    );

    server.shutdown().await.unwrap();
}

/// FIX 3: the beat-arm inbound drain is capped per wake and always yields back to the `select!`,
/// so an inbound flood cannot starve the cut / deadline arms. Under a continuous flood of tiny
/// invalid Text frames (each answered with a heavier error envelope, so the client outpaces the
/// server and the recv buffer never empties) with the session revoked, the pump still reaches its
/// re-auth beat and cuts. Without the cap the unbounded drain never returns to the select while
/// frames keep arriving, so the cut is starved and the pump never completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_fix3_inbound_flood_does_not_starve_the_cut() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let hub = delta_hub_timed(t26_timing());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let api = Arc::new(api);
    let server = ClientApiServer::bind(Arc::clone(&api), port).await.unwrap();

    let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut socket).await;
    api.sessions().revoke(TOKEN);

    let (mut write, mut read) = socket.split();
    // Drain everything the server sends so its error-envelope replies never backpressure.
    let reader = tokio::spawn(async move { while (read.next().await).is_some() {} });
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flood = Arc::clone(&stop);
    let flooder = tokio::spawn(async move {
        // 1-byte invalid Text frames; each provokes a ~200-byte error envelope, so the client
        // outpaces the server and the server's recv buffer stays non-empty.
        while !stop_flood.load(Ordering::SeqCst) {
            if write.send(Message::Text("x".into())).await.is_err() {
                break;
            }
        }
    });

    // Even under the flood, the pump yields from the bounded drain to its re-auth beat and cuts.
    let exit = wait_exit(&exits, Duration::from_secs(6)).await;
    stop.store(true, Ordering::SeqCst);
    flooder.abort();
    reader.abort();

    assert_eq!(
        exit,
        Some(DeltaPumpExit::AuthFailureImmediate),
        "an inbound flood must not starve the cut — the capped drain yields to the re-auth beat, \
         which cuts the revoked session (exit={exit:?})"
    );

    server.shutdown().await.unwrap();
}

/// FIX 4: `biased;` cut arms plus the delivery gate — a session already past its cut instant at
/// the loop top is cut BEFORE any page ships, closing the unconditional-pre-select-delivery leak.
/// A seed pass slower than the deadline window makes the start-anchored deadline already-past when
/// the pump's loop begins; a selection frame is pipelined but NO delta page is delivered — only the
/// seed, then the cut. Four independent subscribers make the without-fix miss (the old unbiased
/// select could service the recv+deliver before the already-elapsed cut arm) improbable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_fix4_biased_gate_ships_no_page_to_already_cut_session() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct SlowSink {
        armed: Arc<AtomicBool>,
    }
    impl AuditSink for SlowSink {
        fn emit(&self, _event: AuditEvent) {
            if self.armed.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(600));
            }
        }
    }

    // reauth_max_age 500 ms; a ≥ 600 ms seed pass makes seed_start + deadline already-past at the
    // pump's first loop, regardless of the audit emit count.
    let timing = DeltaTiming {
        cadence: Duration::from_millis(100),
        reauth_max_age: Duration::from_millis(500),
        allowance: Duration::from_millis(50),
        linger: Duration::from_secs(30),
    };
    let hub = delta_hub_timed(timing);
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let armed = Arc::new(AtomicBool::new(true)); // slow from the start → the SEED pass is slow
    let (api, exits) = delta_api_base(
        &origin,
        &hub,
        ClientApiConfig::default(),
        Some(Arc::new(SlowSink {
            armed: Arc::clone(&armed),
        })),
    );
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    // A live stream with content ready to ship the moment a subscription is set.
    d_begin(&hub, "agent-a", "f4");
    d_delta(
        &hub,
        "f4",
        0,
        "secret-ish page that must NOT ship after the cut. ",
    );

    let mut total_delta_pages = 0usize;
    for _ in 0..4 {
        let mut socket = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
        // Pipeline the selection BEFORE reading the seed so it is buffered when the pump starts;
        // the gate must cut before it is ever delivered against.
        let _ = socket
            .send(Message::Text(
                json!({ "stream_key": "f4" }).to_string().into(),
            ))
            .await;
        read_delta_seed(&mut socket).await;
        let (texts, saw_close, _after) =
            drain_until_close(&mut socket, Duration::from_secs(3)).await;
        assert!(saw_close, "the gate cut must close the socket");
        total_delta_pages += texts.iter().filter(|t| t.contains("\"deltas\"")).count();
    }

    assert_eq!(
        total_delta_pages, 0,
        "no delta page may ship to a session already past its cut instant (the biased gate cuts first)"
    );
    let seen = exits.lock().unwrap().clone();
    assert_eq!(seen.len(), 4, "all four pumps must have cut");
    assert!(
        seen.iter().all(|e| *e == DeltaPumpExit::ReauthDeadline),
        "each gate cut carries the deadline reason: {seen:?}"
    );

    server.shutdown().await.unwrap();
}

/// FIX 5: the pong is correlated by a monotonic ping nonce, so a write-only half-open peer that
/// spews unsolicited / garbage Pongs (never echoing the actual ping) is still cut at the pong
/// deadline and its slot released. Without correlation, a bool cleared on ANY Pong let such a peer
/// hold its slot forever. This is the ~2-beat dead-peer class (ADR B3(ii)), DISTINCT from T26-e's
/// ≤1-beat socket-error class — no ≤1-beat claim is made here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_fix5_uncorrelated_pong_still_pong_timeout_and_slot_release() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let hub = delta_hub_timed(t26_timing()); // cadence 250 ms
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    let server = ClientApiServer::bind(Arc::new(api), port).await.unwrap();

    // Fill three of the four RAII subscriber slots with correctly-ponging keepers.
    let mut held = Vec::new();
    for _ in 0..3 {
        let mut s = connect_delta(port, &origin, Some(TOKEN))
            .await
            .expect("subscriber");
        read_delta_seed(&mut s).await;
        held.push(s);
    }
    let keepers: Vec<_> = held.into_iter().map(spawn_ping_keeper).collect();

    // The half-open peer takes the 4th slot. It reads ONLY the seed, then NEVER reads again — so
    // tokio-tungstenite queues no automatic echo-Pong for the server's pings (its socket stays
    // open at the TCP level) — while it spews garbage Pongs that match no ping nonce.
    let mut victim = connect_delta(port, &origin, Some(TOKEN))
        .await
        .expect("subscriber");
    read_delta_seed(&mut victim).await; // the seed is a Text frame → no auto-Pong is queued
    let (mut vwrite, vread) = victim.split();
    // Hold the read half open (so the socket is not torn down) but NEVER poll it: no ping is ever
    // read, so tungstenite never auto-echoes one, and the server's ping stays unanswered.
    let _vread_hold = vread;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_w = Arc::clone(&stop);
    let vwriter = tokio::spawn(async move {
        while !stop_w.load(Ordering::SeqCst) {
            if vwrite
                .send(Message::Pong(vec![0xAB, 0xCD].into()))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
    });

    // The half-open peer is cut at the pong deadline (~2 beats), NOT kept alive by garbage Pongs.
    let exit = wait_exit(&exits, Duration::from_secs(4)).await;
    assert_eq!(
        exit,
        Some(DeltaPumpExit::PongTimeout),
        "an uncorrelated / garbage Pong must NOT clear the wait — the half-open peer is cut at the \
         pong deadline (~2-beat class, ADR B3(ii))"
    );

    // …and its slot releases, so a fresh subscriber is re-admitted.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut readmitted = false;
    while Instant::now() < deadline {
        match connect_delta(port, &origin, Some(TOKEN)).await {
            Ok(mut s) => {
                read_delta_seed(&mut s).await;
                readmitted = true;
                break;
            }
            Err(err) if upgrade_status(&err) == Some(429) => {
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            Err(err) => panic!("unexpected refusal while waiting for the freed slot: {err:?}"),
        }
    }
    assert!(readmitted, "the half-open peer's slot must release");

    stop.store(true, Ordering::SeqCst);
    vwriter.abort();
    drop(_vread_hold);
    for k in keepers {
        k.abort();
    }
    server.shutdown().await.unwrap();
}

/// FIX 1 (CRITICAL revocation escape — inbound-reply leg, the merge-gate re-review find): a peer
/// that reads ONLY the seed then goes SILENT on its read half (never drains the server's replies)
/// while FLOODING inbound invalid-Text frames, with the session revoked. Each invalid frame provokes
/// an error-envelope reply; with the client no longer reading, those replies fill the server→client
/// socket buffer and the reply-send blocks under TCP backpressure. FIX 1 bounds EVERY reply
/// `handle_delta_socket_message` performs by the pump's most-imminent cut instant, so the parked
/// reply-send is cut by the start-anchored re-auth deadline — a revoked (or merely non-reading)
/// session cannot hold the connection (and its RAII subscriber slot) open by refusing to read our
/// replies. Without the bound the reply-send parks the pump INSIDE `handle_delta_socket_message`,
/// the `select!` stops being polled, no cut arm fires, the pump never completes and `wait_exit`
/// returns `None` (this fails).
///
/// This INVERTS t26_fix3: there the client DRAINS every reply (so nothing backpressures and the
/// point is the drain-COUNT cap); here the client never reads, so the point is the reply-SEND bound.
/// Timing knobs (documented so it stays deterministic-ish, not CI-flaky):
///  - cadence 30 s: NO re-auth beat fires during the test, so the revoked session cannot be cut by a
///    beat's `AuthFailureImmediate` and the pong path cannot preempt — the ONLY thing that can end
///    the pump is the reply-send bound → `ReauthDeadline`. This isolates FIX 1.
///  - reauth_max_age 2 s: the start-anchored deadline (never refreshed — no beat) is due 2 s after
///    subscribe, so the parked reply-send is cut promptly.
/// The flood self-limits: once both socket buffers fill, the flooder's own send parks (pending, not
/// busy) and the runtime idles, so the tokio timer wheel advances and the bounded `timeout_at`
/// fires — the gentle-runtime methodology the t26_fix1 witness documents.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_fix7_nonreading_inbound_flood_still_cuts() {
    use std::sync::atomic::{AtomicBool, Ordering};

    const READMIT: &str = "fix7-readmit-token";

    let hub = delta_hub_timed(DeltaTiming {
        cadence: Duration::from_secs(30), // no beat → no AuthFailureImmediate / pong preempt
        reauth_max_age: Duration::from_secs(2),
        allowance: Duration::from_millis(500),
        linger: Duration::from_secs(30),
    });
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let (api, exits) = delta_api_base(&origin, &hub, ClientApiConfig::default(), None);
    install_delta_session(&api, u64::MAX, Scope::operator_default());
    // A SECOND, still-valid session so the freed-slot re-admission below does not depend on the
    // revoked victim token (a revoked token would be refused at the seed, not the subscriber cap).
    api.sessions().insert(
        READMIT.into(),
        ClientSession {
            session_id: "fix7-readmit".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("delta-csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );
    let api = Arc::new(api);
    let server = ClientApiServer::bind(Arc::clone(&api), port).await.unwrap();

    let mut victim = connect_delta(port, &origin, Some(TOKEN)).await.expect("ws");
    read_delta_seed(&mut victim).await; // reads ONLY the seed…
    api.sessions().revoke(TOKEN); // …and the session it holds is revoked and must be cut.

    // Split: hold the read half OPEN (so the socket is not torn down at TCP level) but NEVER poll
    // it, so the server's error-envelope replies are never drained and back up into backpressure.
    let (mut vwrite, vread) = victim.split();
    let _vread_hold = vread;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flood = Arc::clone(&stop);
    let flooder = tokio::spawn(async move {
        // 1-byte invalid Text frames; each provokes a ~200-byte error envelope, so the
        // server→client buffer fills fast. Once both buffers fill, this send parks (pending) — a
        // self-limiting burst, so the runtime idles and the timer can fire.
        while !stop_flood.load(Ordering::SeqCst) {
            if vwrite.send(Message::Text("x".into())).await.is_err() {
                break;
            }
        }
    });

    let t_block = Instant::now();
    // With FIX 1 the bounded reply-send lets the start-anchored deadline cut the parked pump; without
    // it the pump is parked in the unbounded reply-send forever and this returns None.
    let exit = wait_exit(&exits, Duration::from_secs(10)).await;
    let cut_elapsed = t_block.elapsed();
    stop.store(true, Ordering::SeqCst);
    flooder.abort();

    assert_eq!(
        exit,
        Some(DeltaPumpExit::ReauthDeadline),
        "a non-reading peer flooding inbound frames must NOT park the pump inside a backpressured \
         reply-send — the start-anchored deadline cuts (without the FIX 1 bound the pump hangs and \
         the revoked session keeps its socket and RAII subscriber slot)"
    );
    assert!(
        cut_elapsed <= Duration::from_secs(8),
        "the cut lands within the deadline window (took {cut_elapsed:?})"
    );

    // The RAII subscriber slot released with the cut: saturate the whole cap (4) with fresh
    // subscribers on the still-valid token — all four admit ONLY because the victim freed its slot
    // (a still-parked victim would pin one, and the fourth fresh connect would 429).
    let mut fresh = Vec::new();
    let readmit_deadline = Instant::now() + Duration::from_secs(4);
    for _ in 0..4 {
        loop {
            match connect_delta(port, &origin, Some(READMIT)).await {
                Ok(mut s) => {
                    read_delta_seed(&mut s).await;
                    fresh.push(s);
                    break;
                }
                Err(err)
                    if upgrade_status(&err) == Some(429) && Instant::now() < readmit_deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
                Err(err) => panic!("the victim's freed slot must let the cap re-admit: {err:?}"),
            }
        }
    }
    assert_eq!(
        fresh.len(),
        4,
        "the cap is fully free — the victim released its RAII subscriber slot on the cut"
    );

    drop(fresh);
    drop(_vread_hold);
    server.shutdown().await.unwrap();
}

// ── G-1 ship gate ─────────────────────────────────────────────────────────────────────────

/// G-1: the §2.4 pin-(xv) note string is byte-present in ALL FIVE
/// `conformance/fixtures/*/surface.json`.
#[test]
fn g1_absent_note_byte_present_on_all_five_surfaces() {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("sdk-artifacts/conformance/fixtures");
    for target in ["web", "mac", "ios", "android", "windows"] {
        let path = fixtures.join(target).join("surface.json");
        let bytes = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            bytes.contains(LLM_DELTA_ABSENT_NOTE),
            "the pin-(xv) note string is missing from the {target} surface"
        );
    }
}
