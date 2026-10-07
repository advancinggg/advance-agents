//! MODULE-001-AC-31 (a) client-api integration tests for extension families
//! (RouteBook → wrap → install → handle / transport).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use advance_client_api::clock::{SystemClock, TestClock};
use advance_client_api::families::{
    ExtensionRouteEvent, ExtensionRouteHooks, ExtensionServiceParts, FamilyBudget,
    NoExtensionRouteHooks, ResponseScan, RouteBook, RouteOptions,
};
use advance_client_api::{
    AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientApiServer, ClientErrorCode,
    ClientRequest, ClientSession, Clock, ExtensionRouteGate, HandlerCtx, HandlerSpec,
    MemoryCursorKeyCustody, Method, NoopSink, OsCursorEntropy, Platform, Principal, Scope,
    SystemCursorClock, API_VERSION,
};
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use serde_json::json;

struct StubDetector;

impl LeakDetector for StubDetector {
    fn scan(&self, text: &str, _context: ScanContext) -> ScanResult {
        if text.contains("AKIA") {
            ScanResult::Blocked { findings: vec![] }
        } else if text.contains("Bearer ") {
            ScanResult::Redacted {
                redacted: "[REDACTED]".into(),
                findings: vec![],
            }
        } else {
            ScanResult::Clean
        }
    }
    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

#[derive(Default)]
struct RecordingHooks {
    events: Mutex<Vec<ExtensionRouteEvent>>,
}

impl ExtensionRouteHooks for RecordingHooks {
    fn event(&self, event: &ExtensionRouteEvent) {
        self.events.lock().expect("hooks").push(event.clone());
    }
}

fn parts() -> ExtensionServiceParts {
    ExtensionServiceParts {
        leak_detector: Arc::new(StubDetector),
        clock: Arc::new(SystemClock),
        cursor_codec: Arc::new(AeadClientCursorCodec::new(
            Arc::new(MemoryCursorKeyCustody::new_for_tests()),
            Arc::new(SystemCursorClock),
            Arc::new(OsCursorEntropy),
            30,
        )),
    }
}

fn book_with(
    cfg: &ClientApiConfig,
    gate: ExtensionRouteGate,
    hooks: Arc<dyn ExtensionRouteHooks>,
) -> RouteBook {
    RouteBook::new(cfg, parts(), gate, hooks)
}

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>, csrf: Option<&str>, now: u64) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: format!("sess-{token}"),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes,
            csrf_token: csrf.map(str::to_string),
            expires_at: u64::MAX,
        },
        now,
    );
}

fn origin_cfg() -> ClientApiConfig {
    let mut cfg = ClientApiConfig::default();
    cfg.allowed_origins = vec!["http://127.0.0.1:1".into()];
    cfg
}

fn read_ok() -> HandlerSpec {
    HandlerSpec::read(true, |_| Ok(json!({ "ok": true }))).with_scopes(vec![Scope::ReadInventory])
}

#[test]
fn module_001_ac31_install_registers_exact_and_templated() {
    let gate = ExtensionRouteGate::new();
    let mut book = book_with(
        &ClientApiConfig::default(),
        gate,
        Arc::new(NoExtensionRouteHooks),
    );
    {
        let mut r = book.registrar("ext");
        r.route(Method::Get, "/client/ext/items", read_ok())
            .unwrap();
        r.route_templated(
            Method::Get,
            "/client/ext/items/{item_id}",
            HandlerSpec::read(true, |ctx| {
                Ok(json!({ "item_id": ctx.path_param("item_id")? }))
            })
            .with_scopes(vec![Scope::ReadInventory]),
        )
        .unwrap();
        r.route(
            Method::Post,
            "/client/ext/items:create",
            HandlerSpec::mutation(true, |_| Ok(json!({ "created": 1 })))
                .with_scopes(vec![Scope::WriteEntities]),
        )
        .unwrap();
    }
    let families = book.finish().unwrap();
    let report = families.report().to_vec();
    assert_eq!(report.len(), 3);
    assert_eq!(report[0].path, "/client/ext/items");
    assert!(!report[0].templated);
    assert_eq!(report[1].path, "/client/ext/items/{item_id}");
    assert!(report[1].templated);
    let mut api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(SystemClock),
        Arc::new(NoopSink),
    );
    let oss = api.route_table();
    families.install(&mut api);
    let table = api.route_table();
    for e in &oss {
        assert!(
            table.iter().any(|t| t == e),
            "OSS route missing after install: {} {:?}",
            e.path,
            e.method
        );
    }
    assert!(table
        .iter()
        .any(|t| t.path == "/client/ext/items" && !t.templated));
    assert!(table
        .iter()
        .any(|t| t.path == "/client/ext/items/{item_id}" && t.templated));
    assert_eq!(api.extension_route_report(), report);
}

#[test]
fn module_001_ac31_installed_routes_run_gate_chain_in_process() {
    let cfg = origin_cfg();
    let mut book = book_with(
        &cfg,
        ExtensionRouteGate::new(),
        Arc::new(NoExtensionRouteHooks),
    );
    {
        let mut r = book.registrar("ext");
        r.route(Method::Get, "/client/ext/items", read_ok())
            .unwrap();
        r.route(
            Method::Post,
            "/client/ext/items:create",
            HandlerSpec::mutation(true, |_| Ok(json!({ "created": 1 })))
                .with_scopes(vec![Scope::WriteEntities]),
        )
        .unwrap();
    }
    let families = book.finish().unwrap();
    let mut api = ClientApi::with_parts(cfg, "operator", Arc::new(SystemClock), Arc::new(NoopSink));
    families.install(&mut api);

    let env = api.handle(ClientRequest::get("/client/ext/items"));
    assert_eq!(env.error.unwrap().code, ClientErrorCode::Unauthenticated);

    mint(&api, "low", vec![Scope::ReadRuns], None, 0);
    let env = api.handle(ClientRequest::get("/client/ext/items").with_session("low"));
    assert_eq!(env.error.unwrap().code, ClientErrorCode::Forbidden);

    mint(&api, "op", Scope::operator_default(), Some("csrf"), 0);
    let env = api.handle(
        ClientRequest::post("/client/ext/items:create", json!({}))
            .with_session("op")
            .with_origin("http://127.0.0.1:1"),
    );
    assert_eq!(
        env.error.unwrap().code,
        ClientErrorCode::IdempotencyRequired
    );

    let env = api.handle(
        ClientRequest::post("/client/ext/items:create", json!({}))
            .with_session("op")
            .with_origin("http://127.0.0.1:1")
            .with_idempotency_key("k1"),
    );
    assert_eq!(env.error.unwrap().code, ClientErrorCode::CsrfRequired);

    let env = api.handle(
        ClientRequest::post("/client/ext/items:create", json!({}))
            .with_session("op")
            .with_origin("http://127.0.0.1:1")
            .with_csrf("csrf")
            .with_idempotency_key("k1"),
    );
    assert!(env.is_ok(), "{env:?}");
    assert_eq!(env.data.unwrap()["created"], json!(1));
}

#[test]
fn module_001_ac31_blocked_mutation_success_is_committed_not_reexecuted() {
    let count = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&count);
    let cfg = origin_cfg();
    let mut book = book_with(
        &cfg,
        ExtensionRouteGate::new(),
        Arc::new(NoExtensionRouteHooks),
    );
    {
        let mut r = book.registrar("ext");
        r.route(
            Method::Post,
            "/client/ext/items:create",
            HandlerSpec::mutation(true, move |_| {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "note": "key AKIAABCDEFGHIJKLMNOP" }))
            })
            .with_scopes(vec![Scope::WriteEntities]),
        )
        .unwrap();
    }
    let families = book.finish().unwrap();
    let mut api = ClientApi::with_parts(cfg, "operator", Arc::new(SystemClock), Arc::new(NoopSink));
    families.install(&mut api);
    mint(&api, "op", Scope::operator_default(), Some("csrf"), 0);
    let req = ClientRequest::post("/client/ext/items:create", json!({}))
        .with_session("op")
        .with_origin("http://127.0.0.1:1")
        .with_csrf("csrf")
        .with_idempotency_key("k");
    let env = api.handle(req.clone());
    assert_eq!(env.error.unwrap().code, ClientErrorCode::ProjectionRejected);
    let env = api.handle(req);
    assert_eq!(env.error.unwrap().code, ClientErrorCode::ProjectionRejected);
    assert!(env.warnings.iter().any(|w| w.code == "idempotent_replay"));
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn module_001_ac31_closing_answers_module_unavailable_before_auth_and_replay() {
    let count = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&count);
    let cfg = origin_cfg();
    let gate = ExtensionRouteGate::new();
    let mut book = book_with(&cfg, gate.clone(), Arc::new(NoExtensionRouteHooks));
    {
        let mut r = book.registrar("ext");
        r.route(Method::Get, "/client/ext/items", read_ok())
            .unwrap();
        r.route(
            Method::Post,
            "/client/ext/items:create",
            HandlerSpec::mutation(true, move |_| {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "created": 1 }))
            })
            .with_scopes(vec![Scope::WriteEntities]),
        )
        .unwrap();
    }
    let families = book.finish().unwrap();
    let spec = families
        .wrapped_spec(Method::Get, "/client/ext/items")
        .expect("wrapped GET");
    let mut api = ClientApi::with_parts(cfg, "operator", Arc::new(SystemClock), Arc::new(NoopSink));
    families.install(&mut api);
    mint(&api, "op", Scope::operator_default(), Some("csrf"), 0);
    let env = api.handle(
        ClientRequest::post("/client/ext/items:create", json!({}))
            .with_session("op")
            .with_origin("http://127.0.0.1:1")
            .with_csrf("csrf")
            .with_idempotency_key("k1"),
    );
    assert!(env.is_ok());
    assert_eq!(count.load(Ordering::SeqCst), 1);

    gate.close();
    let env = api.handle(ClientRequest::get("/client/ext/items"));
    let err = env.error.unwrap();
    assert_eq!(err.code, ClientErrorCode::ModuleUnavailable);
    assert_eq!(err.message, "provider unavailable");

    let env = api.handle(
        ClientRequest::post("/client/ext/items:create", json!({}))
            .with_session("op")
            .with_origin("http://127.0.0.1:1")
            .with_csrf("csrf")
            .with_idempotency_key("k1"),
    );
    assert_eq!(env.error.unwrap().code, ClientErrorCode::ModuleUnavailable);

    let env = api.handle(ClientRequest::get("/client/ext/nope"));
    assert_eq!(env.error.unwrap().code, ClientErrorCode::UnknownRoute);

    let env = api.handle(ClientRequest::get("/client/health"));
    assert!(env.is_ok());

    let ctx = HandlerCtx {
        request_id: "t".into(),
        principal: None,
        scopes: vec![],
        body: serde_json::Value::Null,
        path_params: vec![],
        mutation: None,
        is_loopback_peer: true,
    };
    let err = match spec.invoke_for_test(&ctx) {
        Err(e) => e,
        Ok(_) => panic!("closed gate must refuse the wrapped handler"),
    };
    assert_eq!(err.code, ClientErrorCode::ModuleUnavailable);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn module_001_ac31_route_panic_contained_in_process() {
    let hooks = Arc::new(RecordingHooks::default());
    let mut book = book_with(
        &ClientApiConfig::default(),
        ExtensionRouteGate::new(),
        Arc::clone(&hooks) as Arc<dyn ExtensionRouteHooks>,
    );
    {
        let mut r = book.registrar("ext");
        r.route(Method::Get, "/client/ext/items", read_ok())
            .unwrap();
        r.route(
            Method::Get,
            "/client/ext/panic",
            HandlerSpec::read(true, |_| panic!("fixture route panic"))
                .with_scopes(vec![Scope::ReadInventory]),
        )
        .unwrap();
    }
    let families = book.finish().unwrap();
    let mut api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(SystemClock),
        Arc::new(NoopSink),
    );
    families.install(&mut api);
    mint(&api, "tok", vec![Scope::ReadInventory], None, 0);

    let env = api.handle(ClientRequest::get("/client/ext/panic").with_session("tok"));
    let err = env.error.unwrap();
    assert_eq!(err.code, ClientErrorCode::ModuleUnavailable);
    assert_eq!(err.message, "provider unavailable");
    let events = hooks.events.lock().unwrap().clone();
    let panics: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ExtensionRouteEvent::HandlerPanicked { .. }))
        .collect();
    assert_eq!(panics.len(), 1);
    assert_eq!(
        panics[0],
        &ExtensionRouteEvent::HandlerPanicked {
            extension: "ext",
            method: Method::Get,
            route: "/client/ext/panic".into(),
        }
    );

    let env = api.handle(ClientRequest::get("/client/ext/items").with_session("tok"));
    assert!(env.is_ok());
    let env = api.handle(ClientRequest::get("/client/ext/panic").with_session("tok"));
    assert_eq!(env.error.unwrap().code, ClientErrorCode::ModuleUnavailable);
    let panics = hooks
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, ExtensionRouteEvent::HandlerPanicked { .. }))
        .count();
    assert_eq!(panics, 2);
}

#[test]
fn module_001_ac31_extension_idempotency_store_isolated() {
    let clock = Arc::new(TestClock::new(1_000));
    let cfg = origin_cfg();
    let mut book = book_with(
        &cfg,
        ExtensionRouteGate::new(),
        Arc::new(NoExtensionRouteHooks),
    );
    {
        let mut r = book.registrar("ext");
        r.set_budget(FamilyBudget::new(16, 2)).unwrap();
        r.route(
            Method::Post,
            "/client/ext/items:create",
            HandlerSpec::mutation(true, |_| Ok(json!({ "ok": true })))
                .with_scopes(vec![Scope::WriteEntities]),
        )
        .unwrap();
    }
    let families = book.finish().unwrap();
    let mut api = ClientApi::with_parts(
        cfg,
        "operator",
        Arc::clone(&clock) as Arc<dyn advance_client_api::Clock>,
        Arc::new(NoopSink),
    );
    families.install(&mut api);
    mint(
        &api,
        "op",
        Scope::operator_default(),
        Some("csrf"),
        clock.now_millis(),
    );
    let n0 = api.idempotency().len();
    for i in 1..=3 {
        clock.advance(1);
        let env = api.handle(
            ClientRequest::post("/client/ext/items:create", json!({ "i": i }))
                .with_session("op")
                .with_origin("http://127.0.0.1:1")
                .with_csrf("csrf")
                .with_idempotency_key(format!("e{i}")),
        );
        assert!(env.is_ok(), "e{i}: {env:?}");
    }
    assert_eq!(api.idempotency().len(), n0);
    let stats = api.extension_budget_stats();
    assert_eq!(stats[0].idempotency_cap, 2);
    assert_eq!(stats[0].idempotency_records, 2);

    clock.advance(1);
    let replay = api.handle(
        ClientRequest::post("/client/ext/items:create", json!({ "i": 3 }))
            .with_session("op")
            .with_origin("http://127.0.0.1:1")
            .with_csrf("csrf")
            .with_idempotency_key("e3"),
    );
    assert!(replay
        .warnings
        .iter()
        .any(|w| w.code == "idempotent_replay"));

    clock.advance(1);
    let first = api.handle(
        ClientRequest::post("/client/ext/items:create", json!({ "i": 1 }))
            .with_session("op")
            .with_origin("http://127.0.0.1:1")
            .with_csrf("csrf")
            .with_idempotency_key("e1"),
    );
    assert!(!first.warnings.iter().any(|w| w.code == "idempotent_replay"));
}

#[test]
fn module_001_ac31_scan_opt_out_is_recorded_and_logged() {
    let hooks = Arc::new(RecordingHooks::default());
    let mut book = book_with(
        &ClientApiConfig::default(),
        ExtensionRouteGate::new(),
        Arc::clone(&hooks) as Arc<dyn ExtensionRouteHooks>,
    );
    {
        let mut r = book.registrar("ext");
        r.route_with(
            Method::Get,
            "/client/ext/raw",
            HandlerSpec::read(true, |_| {
                Ok(json!({ "note": "Bearer eyJhbGciOiJIUzI1NiJ9.x" }))
            })
            .with_scopes(vec![Scope::ReadInventory]),
            RouteOptions::skip_response_scan("fixture: raw echo for the scan opt-out witness"),
        )
        .unwrap();
        r.route(Method::Get, "/client/ext/items", read_ok())
            .unwrap();
    }
    let families = book.finish().unwrap();
    assert!(families.report().iter().any(|i| {
        i.path == "/client/ext/raw"
            && matches!(
                i.response_scan,
                ResponseScan::OptOut {
                    reason: "fixture: raw echo for the scan opt-out witness"
                }
            )
    }));
    let mut api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(SystemClock),
        Arc::new(NoopSink),
    );
    families.install(&mut api);
    let events = hooks.events.lock().unwrap().clone();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, ExtensionRouteEvent::ScanOptOut { .. }))
            .count(),
        1
    );
}

fn http_get(addr: SocketAddr, path: &str, token: Option<&str>) -> u16 {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nx-advance-api-version: {API_VERSION}\r\n{auth}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

type HoldGate = Arc<(Mutex<bool>, Condvar)>;

fn hold_handler(
    released: HoldGate,
    holding: Arc<AtomicUsize>,
) -> impl Fn(&HandlerCtx) -> Result<serde_json::Value, advance_client_api::ClientError>
       + Send
       + Sync
       + 'static {
    move |_ctx: &HandlerCtx| {
        holding.fetch_add(1, Ordering::SeqCst);
        let (lock, cvar) = &*released;
        let guard = lock.lock().unwrap();
        let _ = cvar
            .wait_timeout_while(guard, Duration::from_secs(30), |r| !*r)
            .unwrap();
        holding.fetch_sub(1, Ordering::SeqCst);
        Ok(json!({ "held": true }))
    }
}

fn release(gate: &HoldGate) {
    let (lock, cvar) = &**gate;
    *lock.lock().unwrap() = true;
    cvar.notify_all();
}

async fn bind_isolated_server(
    hold_ext: impl Fn(&HandlerCtx) -> Result<serde_json::Value, advance_client_api::ClientError>
        + Send
        + Sync
        + 'static,
    hold_oss: impl Fn(&HandlerCtx) -> Result<serde_json::Value, advance_client_api::ClientError>
        + Send
        + Sync
        + 'static,
) -> (ClientApiServer, SocketAddr) {
    let mut cfg = ClientApiConfig::default();
    cfg.max_concurrent_dispatch = 1;
    let mut book = book_with(
        &cfg,
        ExtensionRouteGate::new(),
        Arc::new(NoExtensionRouteHooks),
    );
    {
        let mut r = book.registrar("ext");
        r.set_budget(FamilyBudget::new(1, 8)).unwrap();
        r.route(
            Method::Get,
            "/client/ext/hold",
            HandlerSpec::read(true, hold_ext).with_scopes(vec![Scope::ReadInventory]),
        )
        .unwrap();
        r.route(Method::Get, "/client/ext/items", read_ok())
            .unwrap();
    }
    let families = book.finish().unwrap();
    let mut api = ClientApi::with_parts(cfg, "operator", Arc::new(SystemClock), Arc::new(NoopSink));
    families.install(&mut api);
    api.register(
        Method::Get,
        "/client/oss-hold",
        HandlerSpec::read(false, hold_oss),
    );
    mint(&api, "tok", vec![Scope::ReadInventory], None, 0);
    let server = ClientApiServer::bind(Arc::new(api), 0).await.expect("bind");
    let addr = server.local_addr();
    (server, addr)
}

fn wait_holding(holding: &AtomicUsize, label: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while holding.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "{label} hold never started"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_extension_dispatch_pool_isolated_over_transport() {
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let holding = Arc::new(AtomicUsize::new(0));
    let (server, addr) = bind_isolated_server(
        hold_handler(Arc::clone(&released), Arc::clone(&holding)),
        hold_handler(Arc::clone(&released), Arc::clone(&holding)),
    )
    .await;
    let h = std::thread::spawn(move || http_get(addr, "/client/ext/hold", Some("tok")));
    wait_holding(&holding, "ext");
    assert_eq!(http_get(addr, "/client/ext/items", Some("tok")), 503);
    assert_eq!(http_get(addr, "/client/health", None), 200);
    release(&released);
    assert_eq!(h.join().unwrap(), 200);
    drop(server);

    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let holding = Arc::new(AtomicUsize::new(0));
    let (server, addr) = bind_isolated_server(
        hold_handler(Arc::clone(&released), Arc::clone(&holding)),
        hold_handler(Arc::clone(&released), Arc::clone(&holding)),
    )
    .await;
    let h = std::thread::spawn(move || http_get(addr, "/client/oss-hold", None));
    wait_holding(&holding, "oss");
    assert_eq!(http_get(addr, "/client/health", None), 503);
    assert_eq!(http_get(addr, "/client/ext/items", Some("tok")), 200);
    release(&released);
    assert_eq!(h.join().unwrap(), 200);
    drop(server);
}

async fn bind_ext_hold_server(
    hold: impl Fn(&HandlerCtx) -> Result<serde_json::Value, advance_client_api::ClientError>
        + Send
        + Sync
        + 'static,
) -> (ClientApiServer, SocketAddr) {
    let cfg = ClientApiConfig::default();
    let mut book = book_with(
        &cfg,
        ExtensionRouteGate::new(),
        Arc::new(NoExtensionRouteHooks),
    );
    {
        let mut r = book.registrar("ext");
        r.set_budget(FamilyBudget::new(1, 8)).unwrap();
        r.route(
            Method::Get,
            "/client/ext/hold",
            HandlerSpec::read(true, hold).with_scopes(vec![Scope::ReadInventory]),
        )
        .unwrap();
    }
    let families = book.finish().unwrap();
    let mut api = ClientApi::with_parts(cfg, "operator", Arc::new(SystemClock), Arc::new(NoopSink));
    families.install(&mut api);
    mint(&api, "tok", vec![Scope::ReadInventory], None, 0);
    let server = ClientApiServer::bind(Arc::new(api), 0).await.expect("bind");
    let addr = server.local_addr();
    (server, addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_shutdown_ingress_drains_extension_pools() {
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let holding = Arc::new(AtomicUsize::new(0));
    let (server, addr) =
        bind_ext_hold_server(hold_handler(Arc::clone(&released), Arc::clone(&holding))).await;
    let h = std::thread::spawn(move || http_get(addr, "/client/ext/hold", Some("tok")));
    wait_holding(&holding, "ext-drain");
    let ingress = server.shutdown_ingress(Duration::from_millis(200)).await;
    assert!(
        !ingress.drained,
        "a held extension dispatch must miss the 200 ms drain"
    );
    release(&released);
    let _ = h.join();

    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let holding = Arc::new(AtomicUsize::new(0));
    let (server, addr) =
        bind_ext_hold_server(hold_handler(Arc::clone(&released), Arc::clone(&holding))).await;
    let h = std::thread::spawn(move || http_get(addr, "/client/ext/hold", Some("tok")));
    wait_holding(&holding, "ext-drain-release");
    release(&released);
    assert_eq!(h.join().unwrap(), 200);
    let ingress = server.shutdown_ingress(Duration::from_millis(200)).await;
    assert!(
        ingress.drained,
        "the extension pool drains when no request is in flight"
    );
}
