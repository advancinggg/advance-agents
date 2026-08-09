//! CONTRACT-191 client event stream + historical query witnesses (CE-T01–CE-T32).
//!
//! All tests serialize via OnceLock+Mutex. Live EventBus fixtures keep a dedicated time-enabled
//! runtime alive; static fixtures poll-for-visibility or shutdown before leaving the runtime.
//! Every path drives `ClientApi::handle()` — no mock ReadApi.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use advance_client_api::audit::{AuditEvent, AuditSink, RecordingSink};
use advance_client_api::clock::SystemClock;
use advance_client_api::{
    stream_id_for_filter, AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientCursorCodec,
    ClientErrorCode, ClientEventPage, ClientEventProvider, ClientRequest, ClientSession,
    MemoryCursorKeyCustody, NormalizedEventFilter, OpenedSeal, OsCursorEntropy, Platform,
    Principal, ProviderError, RawEventRow, Scope, SealPurpose, SystemCursorClock, API_VERSION,
};
use advance_event_bus::{
    EventBus, EventBusConfig, EventFilter, ObservabilityReadApi, ReadApiError, ReadCursor,
};
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::LeakDetector;
use advance_shared_types::traits::EventBusEmit;
use cap_http::DefaultLeakDetector;
use chrono::Utc;
use serde_json::{json, Value};

// ── Serialization lock ────────────────────────────────────────────────────────────────────

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let m = LOCK.get_or_init(|| Mutex::new(()));
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

// ── Live EventBus fixture ─────────────────────────────────────────────────────────────────

struct LiveBus {
    /// Keep the runtime + bus alive for the whole test (live path).
    _rt_thread: Option<std::thread::JoinHandle<()>>,
    bus: Arc<EventBus>,
    read: Arc<dyn ObservabilityReadApi>,
    retention_days: u32,
    #[allow(dead_code)]
    /// Shutdown channel for static fixtures that want to tear down cleanly.
    shutdown_tx: Option<std::sync::mpsc::Sender<()>>,
}

impl LiveBus {
    fn start(retention_days: u32) -> Self {
        let temp = tempfile::TempDir::new().expect("tempdir");
        // Leak tempdir so the bus can keep using paths for the process lifetime of the test.
        let temp = Box::leak(Box::new(temp));
        let jsonl = temp.path().join("events");
        let db = temp.path().join("events.db");
        let mut cfg = EventBusConfig::new(jsonl, db);
        cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
        cfg.jsonl_retention_days = retention_days;

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .expect("rt");
            rt.block_on(async move {
                let bus = EventBus::new(cfg).await.expect("bus");
                let bus = Arc::new(bus);
                let read = bus.read_api().expect("read_api");
                ready_tx.send((Arc::clone(&bus), read)).expect("ready send");
                // Park until shutdown signal (or test process end).
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = shutdown_rx.recv();
                })
                .await;
                // Best-effort: drop Arc bus on runtime exit (may still be held by adapter).
            });
        });

        let (bus, read) = ready_rx.recv().expect("bus ready");
        Self {
            _rt_thread: Some(handle),
            bus,
            read,
            retention_days,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn emit(&self, event: Event) {
        self.bus.emit(event);
    }

    fn wait_count(&self, min: usize, timeout: Duration) {
        let start = std::time::Instant::now();
        let read = Arc::clone(&self.read);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        while start.elapsed() < timeout {
            let n = rt.block_on(async {
                read.query(&EventFilter::default(), 10_000)
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            });
            if n >= min {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("wait_count: expected >= {min} within {timeout:?}");
    }
}

// ── Real EventBus-backed provider adapter ─────────────────────────────────────────────────

struct EventBusProvider {
    rt: tokio::runtime::Runtime,
    read: Arc<dyn ObservabilityReadApi>,
    retention_days: u32,
    /// Optional park barrier for CE-T21/T32 (before block_on drain).
    park: Mutex<Option<Arc<std::sync::Barrier>>>,
    /// Optional park after latest_raw returns None (CE-T32).
    park_after_latest_none: Mutex<Option<Arc<std::sync::Barrier>>>,
    /// Call counters for CE-T04/T10.
    calls: Arc<Mutex<ProviderCallCounts>>,
    fail_latest: bool,
}

#[derive(Default, Clone, Debug)]
struct ProviderCallCounts {
    latest: usize,
    history: usize,
    drain: usize,
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
            read: Arc::clone(&live.read),
            retention_days: live.retention_days,
            park: Mutex::new(None),
            park_after_latest_none: Mutex::new(None),
            calls: Arc::new(Mutex::new(ProviderCallCounts::default())),
            fail_latest: false,
        }
    }

    fn with_fail_latest(mut self) -> Self {
        self.fail_latest = true;
        self
    }

    fn call_counts(&self) -> Arc<Mutex<ProviderCallCounts>> {
        Arc::clone(&self.calls)
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
        self.calls.lock().unwrap().latest += 1;
        if self.fail_latest {
            return Err(ProviderError::Unavailable("injected".into()));
        }
        if let Some(b) = self.park.lock().unwrap().clone() {
            b.wait();
        }
        let read = Arc::clone(&self.read);
        let result = self.rt.block_on(async move {
            read.query(&EventFilter::default(), 1)
                .await
                .map(|rows| rows.into_iter().next().map(|r| r.cursor.0))
                .map_err(Self::map_err)
        });
        if let Ok(None) = &result {
            if let Some(b) = self.park_after_latest_none.lock().unwrap().clone() {
                b.wait();
            }
        }
        result
    }

    fn query_history(
        &self,
        filter: &NormalizedEventFilter,
        limit: usize,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        self.calls.lock().unwrap().history += 1;
        if let Some(b) = self.park.lock().unwrap().clone() {
            b.wait();
        }
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
        self.calls.lock().unwrap().drain += 1;
        if let Some(b) = self.park.lock().unwrap().clone() {
            b.wait();
        }
        let read = Arc::clone(&self.read);
        let after = after_raw_id.map(|s| s.to_string());
        let idle = Duration::from_millis(idle_ms);
        self.rt.block_on(async move {
            let cursor = after.map(ReadCursor);
            let mut stream = read
                .resume(cursor, EventFilter::default())
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

// ── API fixture ───────────────────────────────────────────────────────────────────────────

fn make_codec(retention_days: u32) -> Arc<dyn ClientCursorCodec> {
    let custody = Arc::new(MemoryCursorKeyCustody::new_for_tests());
    Arc::new(AeadClientCursorCodec::new(
        custody,
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        retention_days,
    ))
}

fn login(api: &ClientApi) -> String {
    let r = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "platform": "mac" }),
    ));
    assert!(r.is_ok(), "login: {:?}", r.error);
    r.data.unwrap()["token"].as_str().unwrap().to_string()
}

fn build_api(
    provider: Arc<dyn ClientEventProvider>,
    retention_days: u32,
    cfg: ClientApiConfig,
    audit: Arc<dyn AuditSink>,
) -> ClientApi {
    let codec = make_codec(retention_days);
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    ClientApi::with_parts(cfg, "tester", Arc::new(SystemClock), audit)
        .with_event_provider(provider)
        .with_leak_detector(detector)
        .with_cursor_codec(codec)
}

fn get_events(
    api: &ClientApi,
    token: &str,
    body: Value,
) -> advance_client_api::ClientEnvelope<Value> {
    let mut req = ClientRequest::get("/client/events").with_session(token);
    req.body = body;
    api.handle(req)
}

fn get_stream(
    api: &ClientApi,
    token: &str,
    body: Value,
) -> advance_client_api::ClientEnvelope<Value> {
    let mut req = ClientRequest::get("/client/events/stream").with_session(token);
    req.body = body;
    api.handle(req)
}

fn page_of(env: &advance_client_api::ClientEnvelope<Value>) -> ClientEventPage {
    assert!(env.is_ok(), "expected ok: {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("page")
}

fn make_event(id: &str, event_type: &str, payload: Value) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "agent-a".into(),
        task_id: None,
        run_id: Some("run-1".into()),
        execution_id: None,
        trace_id: "00000000-0000-4000-8000-000000000001".into(),
        span_id: "span-1".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload,
        duration_ms: None,
    }
}

// ── CE-T01: exact accepted stream event projects ──────────────────────────────────────────

#[test]
fn ce_t01_accepted_stream_projects_allowed_leaves() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    // Empty-join first, then emit.
    let provider = Arc::new(EventBusProvider::new(&live));
    let api = build_api(
        provider,
        30,
        ClientApiConfig::default(),
        Arc::new(RecordingSink::new()),
    );
    let token = login(&api);

    let first = get_stream(&api, &token, Value::Null);
    let p0 = page_of(&first);
    assert!(p0.events.is_empty());
    let cursor = p0.cursor.expect("cursor");
    assert!(cursor.last_event_id.is_some());

    live.emit(make_event(
        "e1",
        "run.round_completed",
        json!({
            "iteration": 3,
            "token_used": 100,
            "cost_usd": 0.01,
            "decision": "continue-allowed",
            "secret_internal": "should-not-project",
            "prompt": "LEAK"
        }),
    ));
    live.wait_count(1, Duration::from_secs(3));

    let resume = get_stream(
        &api,
        &token,
        json!({
            "stream_id": cursor.stream_id,
            "last_event_id": cursor.last_event_id,
            "limit": 8
        }),
    );
    let page = page_of(&resume);
    assert_eq!(page.events.len(), 1);
    let ev = &page.events[0];
    assert_eq!(ev.event_type, "run.round_completed");
    assert!(ev.event_id.starts_with("c1."));
    // Sealed AEAD base64url may coincidentally contain the substring "e1"; require the raw
    // id is not a JSON string field value and event_id is not equal to the raw id.
    assert_ne!(ev.event_id, "e1");
    assert!(ev.data.contains_key("iteration"));
    assert!(!ev.data.contains_key("secret_internal"));
    assert!(!ev.data.contains_key("prompt"));
    let ser = serde_json::to_string(&page).unwrap();
    assert!(!ser.contains("LEAK"));
    assert!(!ser.contains("\"event_id\":\"e1\""));
    assert!(!ser.contains("\"e1\""));
}

// ── CE-T02: unknown + blocked omitted; no secret leak ─────────────────────────────────────

#[test]
fn ce_t02_unknown_and_blocked_omitted() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let sink = Arc::new(RecordingSink::new());
    let api = build_api(provider, 30, ClientApiConfig::default(), sink.clone());
    let token = login(&api);

    let first = page_of(&get_stream(&api, &token, Value::Null));
    let cur = first.cursor.unwrap();

    // Unknown taxonomy type.
    live.emit(make_event("u1", "task.created", json!({})));
    // Blocked payload string (64-hex credential-like → CONTRACT-112 Warned).
    let secret = "a".repeat(64);
    live.emit(make_event(
        "b1",
        "orchestration.await_started",
        json!({
            "session_id": secret,
            "mode": "all-of",
            "targets": 1
        }),
    ));
    // Valid event after.
    live.emit(make_event("ok1", "run.created", json!({})));
    live.wait_count(3, Duration::from_secs(3));

    let page = page_of(&get_stream(
        &api,
        &token,
        json!({
            "stream_id": cur.stream_id,
            "last_event_id": cur.last_event_id,
            "limit": 16
        }),
    ));
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].event_type, "run.created");
    assert!(page.rejected_count >= 1);
    let ser = serde_json::to_string(&page).unwrap();
    assert!(!ser.contains(&secret));
    for a in sink.events() {
        let s = format!("{a:?}");
        assert!(!s.contains(&secret));
    }
}

// ── CE-T05: missing ReadEvents forbidden ──────────────────────────────────────────────────

#[test]
fn ce_t05_missing_read_events_forbidden() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let api = build_api(
        provider,
        30,
        ClientApiConfig::default(),
        Arc::new(RecordingSink::new()),
    );
    // Insert under-scoped session directly.
    let now = 1_700_000_000_000u64;
    let token = "tok_underscope";
    api.sessions().insert(
        token.into(),
        ClientSession {
            session_id: "s1".into(),
            principal: Principal::operator("tester"),
            platform: Platform::Mac,
            scopes: vec![Scope::ReadRuns], // no ReadEvents
            csrf_token: None,
            expires_at: now + 3_600_000,
        },
        now,
    );
    // Need clock fixed — SystemClock session may expire; use far future expires.
    // SessionStore get_valid uses now from handle's clock — SystemClock is real now.
    // Re-insert with far future.
    let far = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 86_400_000;
    api.sessions().insert(
        token.into(),
        ClientSession {
            session_id: "s1".into(),
            principal: Principal::operator("tester"),
            platform: Platform::Mac,
            scopes: vec![Scope::ReadRuns],
            csrf_token: None,
            expires_at: far,
        },
        far - 1000,
    );

    let env = get_stream(&api, token, Value::Null);
    assert_eq!(env.error_code(), Some(ClientErrorCode::Forbidden));
}

// ── CE-T09: quiet stream ends within idle ─────────────────────────────────────────────────

#[test]
fn ce_t09_quiet_stream_idle() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let mut cfg = ClientApiConfig::default();
    cfg.event_stream_recv_idle_ms = 250;
    let api = build_api(provider, 30, cfg, Arc::new(RecordingSink::new()));
    let token = login(&api);

    let start = std::time::Instant::now();
    let page = page_of(&get_stream(&api, &token, Value::Null));
    let elapsed = start.elapsed();
    assert!(page.events.is_empty());
    assert!(page.cursor.unwrap().last_event_id.is_some());
    assert!(
        elapsed < Duration::from_millis(350),
        "quiet stream took {elapsed:?}"
    );

    // Config rejects idle < 50.
    let mut bad = ClientApiConfig::default();
    bad.event_stream_recv_idle_ms = 10;
    let live2 = LiveBus::start(30);
    let p2 = Arc::new(EventBusProvider::new(&live2));
    let api2 = build_api(p2, 30, bad, Arc::new(RecordingSink::new()));
    let tok2 = login(&api2);
    let env = get_stream(&api2, &tok2, Value::Null);
    assert_eq!(env.error_code(), Some(ClientErrorCode::ModuleUnavailable));
    assert_eq!(env.error.as_ref().unwrap().message, "event config invalid");
}

// ── CE-T10: missing provider/detector/codec ───────────────────────────────────────────────

#[test]
fn ce_t10_missing_slots() {
    let _g = test_lock();
    // Missing all three.
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "tester",
        Arc::new(SystemClock),
        Arc::new(RecordingSink::new()),
    );
    let token = login(&api);
    let env = get_stream(&api, &token, Value::Null);
    assert_eq!(env.error_code(), Some(ClientErrorCode::ModuleUnavailable));
    assert_eq!(
        env.error.as_ref().unwrap().message,
        "event provider not wired"
    );

    // Provider only — detector missing next.
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "tester",
        Arc::new(SystemClock),
        Arc::new(RecordingSink::new()),
    )
    .with_event_provider(provider);
    let token = login(&api);
    let env = get_stream(&api, &token, Value::Null);
    assert_eq!(
        env.error.as_ref().unwrap().message,
        "event leak detector not wired"
    );

    // Provider + detector, no codec.
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let det: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "tester",
        Arc::new(SystemClock),
        Arc::new(RecordingSink::new()),
    )
    .with_event_provider(provider)
    .with_leak_detector(det);
    let token = login(&api);
    let env = get_stream(&api, &token, Value::Null);
    assert_eq!(
        env.error.as_ref().unwrap().message,
        "event cursor codec not wired"
    );
}

// ── CE-T11: schema drift components present ───────────────────────────────────────────────

#[test]
fn ce_t11_schema_eight_dtos() {
    let _g = test_lock();
    let art = advance_client_api::schema::generate_schema_artifact();
    let comps = &art.schema["components"];
    for name in [
        "ClientEventPriority",
        "ClientScalar",
        "ClientEvent",
        "ClientEventCursor",
        "ClientEventFilter",
        "ClientEventsRequest",
        "ClientEventStreamRequest",
        "ClientEventPage",
    ] {
        assert!(comps.get(name).is_some(), "missing {name}");
    }
    // Priority wire literals.
    assert_eq!(
        serde_json::to_value(advance_client_api::ClientEventPriority::Normal).unwrap(),
        json!("normal")
    );
    assert_eq!(
        serde_json::to_value(advance_client_api::ClientEventPriority::Low).unwrap(),
        json!("low")
    );
    // Untagged scalar.
    assert_eq!(
        serde_json::to_value(advance_client_api::ClientScalar::Bool(true)).unwrap(),
        json!(true)
    );
    assert_eq!(
        serde_json::to_value(advance_client_api::ClientScalar::Unsigned(7)).unwrap(),
        json!(7)
    );
    assert_eq!(
        serde_json::to_value(advance_client_api::ClientScalar::Signed(-3)).unwrap(),
        json!(-3)
    );
    assert_eq!(
        serde_json::to_value(advance_client_api::ClientScalar::String("x".into())).unwrap(),
        json!("x")
    );
}

// ── CE-T16: invalid filters ───────────────────────────────────────────────────────────────

#[test]
fn ce_t16_invalid_filters() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let calls = provider.call_counts();
    let api = build_api(
        provider,
        30,
        ClientApiConfig::default(),
        Arc::new(RecordingSink::new()),
    );
    let token = login(&api);

    for body in [
        json!({"since": "not-a-date"}),
        json!({"event_type": "task.created"}),
        json!({"event_type": ""}),
        json!({"agent_id": ""}),
        json!({"run_id": ""}),
        json!({"trace_id": ""}),
        json!({"agent_id": "a".repeat(300)}),
    ] {
        let before = calls.lock().unwrap().clone();
        let env = get_history_or_stream_both(&api, &token, body.clone());
        for e in env {
            assert_eq!(e.error_code(), Some(ClientErrorCode::InvalidState));
            assert_eq!(e.error.as_ref().unwrap().message, "invalid event filter");
        }
        let after = calls.lock().unwrap().clone();
        assert_eq!(before.latest, after.latest, "no provider on bad filter");
        assert_eq!(before.history, after.history);
        assert_eq!(before.drain, after.drain);
    }
}

fn get_history_or_stream_both(
    api: &ClientApi,
    token: &str,
    body: Value,
) -> Vec<advance_client_api::ClientEnvelope<Value>> {
    vec![
        get_events(api, token, body.clone()),
        get_stream(api, token, body),
    ]
}

// ── CE-T17: limits ────────────────────────────────────────────────────────────────────────

#[test]
fn ce_t17_limits() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    for i in 0..5 {
        live.emit(make_event(&format!("h{i}"), "run.created", json!({})));
    }
    live.wait_count(5, Duration::from_secs(3));

    let provider = Arc::new(EventBusProvider::new(&live));
    let calls = provider.call_counts();
    let mut cfg = ClientApiConfig::default();
    cfg.max_event_buffer = 8;
    let api = build_api(provider, 30, cfg, Arc::new(RecordingSink::new()));
    let token = login(&api);

    // History limit 0 — no provider query.
    let before = calls.lock().unwrap().history;
    let p = page_of(&get_events(&api, &token, json!({"limit": 0})));
    assert!(p.events.is_empty());
    assert_eq!(calls.lock().unwrap().history, before);

    // History null defaults 64 (asks provider for 64 window).
    let p = page_of(&get_events(&api, &token, Value::Null));
    assert!(p.events.len() <= 64);
    assert!(p.events.len() >= 1);

    // Stream limit 0 fresh — query+seal, no drain.
    let before_d = calls.lock().unwrap().drain;
    let p = page_of(&get_stream(&api, &token, json!({"limit": 0})));
    assert!(p.events.is_empty());
    assert!(p.cursor.as_ref().unwrap().last_event_id.is_some());
    assert_eq!(calls.lock().unwrap().drain, before_d);

    // Stream null with max_event_buffer=8 → cap 8.
    let p = page_of(&get_stream(&api, &token, Value::Null));
    assert!(p.events.len() <= 8);
}

// ── CE-T26: Null-first body + incomplete cursor ───────────────────────────────────────────

#[test]
fn ce_t26_null_body_and_incomplete_cursor() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let mut cfg = ClientApiConfig::default();
    cfg.max_event_buffer = 8;
    let api = build_api(provider, 30, cfg, Arc::new(RecordingSink::new()));
    let token = login(&api);

    // (a) true Null success
    assert!(get_events(&api, &token, Value::Null).is_ok());
    assert!(get_stream(&api, &token, Value::Null).is_ok());
    assert!(get_events(&api, &token, json!({})).is_ok());
    assert!(get_stream(&api, &token, json!({})).is_ok());

    // (b) bad body types
    for bad in [json!([]), json!("x"), json!(1), json!(true)] {
        let e = get_events(&api, &token, bad.clone());
        assert_eq!(e.error.as_ref().unwrap().message, "invalid event filter");
        let e = get_stream(&api, &token, bad);
        assert_eq!(e.error.as_ref().unwrap().message, "invalid event filter");
    }
    let e = get_stream(&api, &token, json!({"unknown_field": 1}));
    assert_eq!(e.error.as_ref().unwrap().message, "invalid event filter");

    // (c) incomplete cursor
    let e = get_stream(&api, &token, json!({"stream_id": "ces1.abc"}));
    assert_eq!(
        e.error.as_ref().unwrap().message,
        "event stream cursor incomplete"
    );
    let e = get_stream(&api, &token, json!({"last_event_id": "c1.k1.xxx"}));
    assert_eq!(
        e.error.as_ref().unwrap().message,
        "event stream cursor incomplete"
    );

    // (d) multi-fault: empty agent wins over XOR cursor
    let e = get_stream(&api, &token, json!({"agent_id": "", "stream_id": "ces1.x"}));
    assert_eq!(e.error.as_ref().unwrap().message, "invalid event filter");
}

// ── CE-T30: filter rebinding ──────────────────────────────────────────────────────────────

#[test]
fn ce_t30_filter_rebinding() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let api = build_api(
        provider,
        30,
        ClientApiConfig::default(),
        Arc::new(RecordingSink::new()),
    );
    let token = login(&api);

    let p = page_of(&get_stream(
        &api,
        &token,
        json!({"event_type": "run.created"}),
    ));
    let cur = p.cursor.unwrap();
    let tok = cur.last_event_id.unwrap();

    // (1) token from A, filter B, stream_id stays H(A)
    let e = get_stream(
        &api,
        &token,
        json!({
            "event_type": "run.paused",
            "stream_id": cur.stream_id,
            "last_event_id": tok,
        }),
    );
    assert_eq!(
        e.error.as_ref().unwrap().message,
        "event stream does not match filter"
    );

    // (2) stream_id=H(B), token from A → not_found
    let sid_b = stream_id_for_filter(&NormalizedEventFilter {
        event_type: Some("run.paused".into()),
        ..Default::default()
    });
    let e = get_stream(
        &api,
        &token,
        json!({
            "event_type": "run.paused",
            "stream_id": sid_b,
            "last_event_id": tok,
        }),
    );
    assert_eq!(e.error_code(), Some(ClientErrorCode::NotFound));
    assert_eq!(e.error.as_ref().unwrap().message, "event cursor not found");

    // (3) last_event_id without stream_id
    let e = get_stream(&api, &token, json!({"last_event_id": tok}));
    assert_eq!(
        e.error.as_ref().unwrap().message,
        "event stream cursor incomplete"
    );
}

// ── CE-T31: high-water / empty-join / bypass / fail-closed ────────────────────────────────

#[test]
fn ce_t31_high_water_and_empty_join() {
    let _g = test_lock();

    // Case A: high-water
    {
        let live = LiveBus::start(30);
        for i in 0..25 {
            live.emit(make_event(&format!("seed{i}"), "run.created", json!({})));
        }
        live.wait_count(25, Duration::from_secs(5));
        let provider = Arc::new(EventBusProvider::new(&live));
        let api = build_api(
            provider,
            30,
            ClientApiConfig::default(),
            Arc::new(RecordingSink::new()),
        );
        let token = login(&api);
        let p = page_of(&get_stream(&api, &token, json!({"limit": 8})));
        assert!(
            p.events.is_empty(),
            "high-water must not replay retained rows"
        );
        let cur = p.cursor.unwrap();
        assert!(cur.last_event_id.is_some());

        live.emit(make_event("post", "run.paused", json!({})));
        live.wait_count(26, Duration::from_secs(3));
        let p2 = page_of(&get_stream(
            &api,
            &token,
            json!({
                "stream_id": cur.stream_id,
                "last_event_id": cur.last_event_id,
                "limit": 8
            }),
        ));
        assert_eq!(p2.events.len(), 1);
        assert_eq!(p2.events[0].event_type, "run.paused");
    }

    // Case B: stream_id only on pre-seeded bus
    {
        let live = LiveBus::start(30);
        live.emit(make_event("s", "run.created", json!({})));
        live.wait_count(1, Duration::from_secs(3));
        let provider = Arc::new(EventBusProvider::new(&live));
        let api = build_api(
            provider,
            30,
            ClientApiConfig::default(),
            Arc::new(RecordingSink::new()),
        );
        let token = login(&api);
        let sid = stream_id_for_filter(&NormalizedEventFilter::default());
        let e = get_stream(&api, &token, json!({"stream_id": sid}));
        assert_eq!(
            e.error.as_ref().unwrap().message,
            "event stream cursor incomplete"
        );
    }

    // Case C: empty-join
    {
        let live = LiveBus::start(30);
        let provider = Arc::new(EventBusProvider::new(&live));
        let api = build_api(
            provider,
            30,
            ClientApiConfig::default(),
            Arc::new(RecordingSink::new()),
        );
        let token = login(&api);
        let p = page_of(&get_stream(&api, &token, Value::Null));
        let cur = p.cursor.unwrap();
        assert!(cur.last_event_id.is_some(), "must seal watermark");

        live.emit(make_event("new1", "run.created", json!({})));
        live.wait_count(1, Duration::from_secs(3));
        let p2 = page_of(&get_stream(
            &api,
            &token,
            json!({
                "stream_id": cur.stream_id,
                "last_event_id": cur.last_event_id,
                "limit": 8
            }),
        ));
        assert_eq!(p2.events.len(), 1);
    }

    // Case D: failing latest_raw_event_id
    {
        let live = LiveBus::start(30);
        let provider = Arc::new(EventBusProvider::new(&live).with_fail_latest());
        let api = build_api(
            provider,
            30,
            ClientApiConfig::default(),
            Arc::new(RecordingSink::new()),
        );
        let token = login(&api);
        let e = get_stream(&api, &token, Value::Null);
        assert_eq!(e.error_code(), Some(ClientErrorCode::ModuleUnavailable));
        assert_eq!(
            e.error.as_ref().unwrap().message,
            "event provider unavailable"
        );
    }
}

// ── CE-T04: cursor not_found uniform ──────────────────────────────────────────────────────

#[test]
fn ce_t04_cursor_not_found_uniform() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let calls = provider.call_counts();
    let api = build_api(
        provider,
        30,
        ClientApiConfig::default(),
        Arc::new(RecordingSink::new()),
    );
    let token = login(&api);
    let sid = stream_id_for_filter(&NormalizedEventFilter::default());

    let before = calls.lock().unwrap().clone();
    for tok in [
        "not-a-token",
        "c1.k1.",
        "c2.k1.aaa",
        "c1.BAD.aaa",
        &format!("c1.k1.{}", "A".repeat(600)),
        "c1.unknownkey.YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE",
    ] {
        let e = get_stream(
            &api,
            &token,
            json!({"stream_id": sid, "last_event_id": tok}),
        );
        assert_eq!(
            e.error.as_ref().map(|x| x.message.as_str()),
            Some("event cursor not found"),
            "tok={tok}"
        );
    }
    let after = calls.lock().unwrap().clone();
    assert_eq!(before.drain, after.drain, "token failure: zero drain");
    assert_eq!(before.history, after.history);
    // latest may or may not be called depending on path — resume path should not call latest.
    assert_eq!(before.latest, after.latest);
}

// ── CE-T06: history type filter + order ───────────────────────────────────────────────────

#[test]
fn ce_t06_history_type_filter_and_order() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    // Mixed traffic: many run.created + decoys.
    for i in 0..10 {
        live.emit(make_event(&format!("d{i}"), "task.created", json!({})));
        live.emit(make_event(&format!("r{i}"), "run.created", json!({})));
    }
    live.wait_count(20, Duration::from_secs(5));

    let provider = Arc::new(EventBusProvider::new(&live));
    let api = build_api(
        provider,
        30,
        ClientApiConfig::default(),
        Arc::new(RecordingSink::new()),
    );
    let token = login(&api);
    let p = page_of(&get_events(
        &api,
        &token,
        json!({"event_type": "run.created", "limit": 64}),
    ));
    assert!(!p.events.is_empty());
    assert!(p.events.iter().all(|e| e.event_type == "run.created"));
    // Most-recent-first: timestamps non-increasing.
    for w in p.events.windows(2) {
        assert!(w[0].timestamp >= w[1].timestamp);
    }
}

// ── CE-T07: event_id cannot open as cursor ────────────────────────────────────────────────

#[test]
fn ce_t07_event_id_not_cursor() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    live.emit(make_event("x1", "run.created", json!({})));
    live.wait_count(1, Duration::from_secs(3));

    let provider = Arc::new(EventBusProvider::new(&live));
    let codec = make_codec(30);
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "tester",
        Arc::new(SystemClock),
        Arc::new(RecordingSink::new()),
    )
    .with_event_provider(provider)
    .with_leak_detector(Arc::new(DefaultLeakDetector::new()))
    .with_cursor_codec(Arc::clone(&codec));
    let token = login(&api);

    // History delivers sealed event_id.
    let p = page_of(&get_events(
        &api,
        &token,
        json!({"event_type": "run.created"}),
    ));
    assert!(!p.events.is_empty());
    let eid = &p.events[0].event_id;

    let sid = stream_id_for_filter(&NormalizedEventFilter::default());
    let e = get_stream(
        &api,
        &token,
        json!({"stream_id": sid, "last_event_id": eid}),
    );
    assert_eq!(e.error.as_ref().unwrap().message, "event cursor not found");

    // Direct open with Cursor purpose fails (domain mismatch).
    let opened = codec.open(SealPurpose::Cursor, &sid, eid);
    assert!(opened.is_err());
}

// ── CE-T08: Low drop under tiny cap ───────────────────────────────────────────────────────

#[test]
fn ce_t08_low_drop_tiny_cap() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let sink = Arc::new(RecordingSink::new());
    let mut cfg = ClientApiConfig::default();
    cfg.max_event_buffer = 1; // delivery cap 1
    let api = build_api(provider, 30, cfg, sink.clone());
    let token = login(&api);
    let cur = page_of(&get_stream(&api, &token, Value::Null))
        .cursor
        .unwrap();

    // Fill ahead: many Low progress ticks then a terminal Normal so drain must drop Lows or page.
    for i in 0..8 {
        live.emit(make_event(
            &format!("low{i}"),
            "orchestration.await_progress",
            json!({"session_id": "sess1", "target": "agent:a"}),
        ));
    }
    live.emit(make_event("norm1", "run.completed", json!({})));
    live.wait_count(9, Duration::from_secs(3));

    let p = page_of(&get_stream(
        &api,
        &token,
        json!({
            "stream_id": cur.stream_id,
            "last_event_id": cur.last_event_id,
            "limit": 1
        }),
    ));
    assert!(p.cursor.as_ref().unwrap().last_event_id.is_some());
    // Soft pressure path: either dropped Lows or deferred Normal after a full page.
    assert!(
        p.dropped_count > 0
            || p.response_limit_reached
            || p.events.iter().any(|e| e.event_type == "run.completed"),
        "expected Low-drop / response-limit / Normal delivery; page={:?}",
        p
    );
    if p.dropped_count > 0 {
        assert!(
            sink.events()
                .iter()
                .any(|e| e.kind == "client_api.stream_backpressure"),
            "soft drop must emit one stream_backpressure audit; got {:?}",
            sink.events().iter().map(|e| &e.kind).collect::<Vec<_>>()
        );
    }

    // History still sees Low (independent of stream drops).
    let h = page_of(&get_events(
        &api,
        &token,
        json!({"event_type": "orchestration.await_progress"}),
    ));
    assert!(
        h.events
            .iter()
            .any(|e| e.event_type == "orchestration.await_progress"),
        "history must still project Low events"
    );
}

// ── CE-T14: Normal pages without drop ─────────────────────────────────────────────────────

#[test]
fn ce_t14_normal_pages() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let mut cfg = ClientApiConfig::default();
    cfg.max_event_buffer = 2;
    let api = build_api(provider, 30, cfg, Arc::new(RecordingSink::new()));
    let token = login(&api);
    let mut cur = page_of(&get_stream(&api, &token, Value::Null))
        .cursor
        .unwrap();

    for i in 0..5 {
        live.emit(make_event(&format!("n{i}"), "run.created", json!({})));
    }
    live.wait_count(5, Duration::from_secs(3));

    let mut seen = 0;
    for _ in 0..10 {
        let p = page_of(&get_stream(
            &api,
            &token,
            json!({
                "stream_id": cur.stream_id,
                "last_event_id": cur.last_event_id,
                "limit": 2
            }),
        ));
        seen += p.events.len();
        cur = p.cursor.unwrap();
        if p.events.is_empty() && !p.raw_limit_reached {
            break;
        }
    }
    assert_eq!(seen, 5, "all Normal events delivered across pages");
    assert_eq!(
        page_of(&get_stream(
            &api,
            &token,
            json!({
                "stream_id": cur.stream_id,
                "last_event_id": cur.last_event_id,
                "limit": 2
            }),
        ))
        .dropped_count,
        0
    );
}

// ── CE-T18: non-object payload → empty data ───────────────────────────────────────────────

#[test]
fn ce_t18_non_object_payload() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let api = build_api(
        provider,
        30,
        ClientApiConfig::default(),
        Arc::new(RecordingSink::new()),
    );
    let token = login(&api);
    let cur = page_of(&get_stream(&api, &token, Value::Null))
        .cursor
        .unwrap();
    live.emit(make_event("arr", "run.created", json!(["not", "object"])));
    live.wait_count(1, Duration::from_secs(3));
    let p = page_of(&get_stream(
        &api,
        &token,
        json!({
            "stream_id": cur.stream_id,
            "last_event_id": cur.last_event_id,
            "limit": 4
        }),
    ));
    assert_eq!(p.events.len(), 1);
    assert!(p.events[0].data.is_empty());
}

// ── CE-T20: 29-row table ──────────────────────────────────────────────────────────────────

#[test]
fn ce_t20_table_has_29() {
    let _g = test_lock();
    let lits = advance_client_api::projection::accepted_event_literals();
    assert_eq!(lits.len(), 29);
    assert!(lits.contains(&"orchestration.await_progress"));
    assert!(!lits.contains(&"task.created"));
}

// ── CE-T25: codec seal/open roundtrip ─────────────────────────────────────────────────────

#[test]
fn ce_t25_codec_roundtrip() {
    let _g = test_lock();
    let codec = make_codec(30);
    let sid = "ces1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let sealed = codec
        .seal(
            SealPurpose::Cursor,
            sid,
            advance_client_api::cursor::SEAL_TAG_EMPTY_JOIN,
            advance_client_api::cursor::EMPTY_JOIN_WATERMARK_BODY.as_bytes(),
        )
        .unwrap();
    assert!(sealed.starts_with("c1."));
    match codec.open(SealPurpose::Cursor, sid, &sealed).unwrap() {
        OpenedSeal::EmptyJoin => {}
        other => panic!("expected EmptyJoin, got {other:?}"),
    }
    let sealed2 = codec
        .seal(SealPurpose::Cursor, sid, 0x02, b"raw-id-1")
        .unwrap();
    match codec.open(SealPurpose::Cursor, sid, &sealed2).unwrap() {
        OpenedSeal::RawId(id) => assert_eq!(id, "raw-id-1"),
        other => panic!("expected RawId, got {other:?}"),
    }
    // Event-id domain mismatch.
    let eid = codec
        .seal(SealPurpose::EventId, sid, 0x02, b"raw-id-1")
        .unwrap();
    assert!(codec.open(SealPurpose::Cursor, sid, &eid).is_err());
}

// ── CE-T28: raw_limit alone no backpressure audit ─────────────────────────────────────────

#[test]
fn ce_t28_raw_limit_no_pressure_audit() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    for i in 0..70 {
        live.emit(make_event(&format!("f{i}"), "run.created", json!({})));
    }
    live.wait_count(70, Duration::from_secs(8));
    let provider = Arc::new(EventBusProvider::new(&live));
    let sink = Arc::new(RecordingSink::new());
    let api = build_api(provider, 30, ClientApiConfig::default(), sink.clone());
    let token = login(&api);
    let p = page_of(&get_events(
        &api,
        &token,
        json!({"event_type": "run.created", "limit": 64}),
    ));
    assert!(p.raw_limit_reached, "64-window full");
    assert_eq!(p.dropped_count, 0);
    // raw_limit alone must not emit stream_backpressure success audit.
    let pressure = sink
        .events()
        .into_iter()
        .filter(|e| e.kind == "client_api.stream_backpressure")
        .count();
    // Capacity denials would be on error path; success pressure only if response_limit.
    if !p.response_limit_reached {
        assert_eq!(pressure, 0, "raw_limit alone must not audit pressure");
    }
}

// ── Operator default includes ReadEvents ──────────────────────────────────────────────────

#[test]
fn ce_scope_operator_default_includes_read_events() {
    let _g = test_lock();
    assert!(Scope::operator_default().contains(&Scope::ReadEvents));
}

// Silence unused import warnings in sparse CI.
#[allow(dead_code)]
fn _keep() {
    let _ = API_VERSION;
    let _ = AuditEvent::new("k", "r", "f", "m");
}

// ── Security regression (adversarial R35 fixes) ───────────────────────────────────────────

#[test]
fn ce_security_history_agent_post_filter() {
    let _g = test_lock();
    let live = LiveBus::start(30);
    let provider = Arc::new(EventBusProvider::new(&live));
    let api = build_api(
        provider,
        30,
        ClientApiConfig::default(),
        Arc::new(RecordingSink::new()),
    );
    let token = login(&api);
    live.emit(make_event("h1", "run.completed", json!({})));
    live.wait_count(1, Duration::from_secs(3));
    let h = page_of(&get_events(
        &api,
        &token,
        json!({"event_type": "run.completed", "agent_id": "no-such-agent"}),
    ));
    assert!(h.events.is_empty(), "history must post-filter agent_id");
}
