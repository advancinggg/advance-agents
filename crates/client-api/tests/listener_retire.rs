//! MODULE-001-AC-32 — `ClientApiServer::retire` hands the `ClientApi` to a new listener;
//! `shutdown_unbound` drains and closes the extension pools of an API with no listener.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use advance_client_api::clock::SystemClock;
use advance_client_api::families::{
    ExtensionServiceParts, FamilyBudget, NoExtensionRouteHooks, RouteBook,
};
use advance_client_api::{
    AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientApiServer, ClientCursorCodec,
    ClientEventProvider, ClientSession, ExtensionRouteGate, HandlerCtx, HandlerSpec,
    MemoryCursorKeyCustody, Method, NoopSink, NormalizedEventFilter, OsCursorEntropy, Platform,
    Principal, ProviderError, RawEventRow, Scope, SystemCursorClock, API_VERSION,
    CLIENT_WS_PROTOCOL,
};
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use cap_http::DefaultLeakDetector;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;

const TOKEN: &str = "listener-retire-token";

type Sock =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct EmptyEvents;

impl ClientEventProvider for EmptyEvents {
    fn retention_days(&self) -> u32 {
        30
    }
    fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
        Ok(None)
    }
    fn query_history(
        &self,
        _filter: &NormalizedEventFilter,
        _limit: usize,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        Ok(Vec::new())
    }
    fn drain_stream(
        &self,
        _after: Option<&str>,
        _max: usize,
        _idle_ms: u64,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        Ok(Vec::new())
    }
}

struct StubDetector;

impl LeakDetector for StubDetector {
    fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

fn codec() -> Arc<dyn ClientCursorCodec> {
    Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ))
}

fn origin_of(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: format!("sess-{token}"),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes,
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

fn http_exchange(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    (status, body)
}

fn http_get(addr: SocketAddr, path: &str, token: Option<&str>) -> u16 {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nx-advance-api-version: {API_VERSION}\r\n{auth}Connection: close\r\n\r\n"
    );
    http_exchange(addr, &request).0
}

fn parts() -> ExtensionServiceParts {
    ExtensionServiceParts {
        leak_detector: Arc::new(StubDetector),
        clock: Arc::new(SystemClock),
        cursor_codec: codec(),
    }
}

async fn bind_ext_server(
    hold: impl Fn(&HandlerCtx) -> Result<serde_json::Value, advance_client_api::ClientError>
        + Send
        + Sync
        + 'static,
) -> (ClientApiServer, SocketAddr) {
    let cfg = ClientApiConfig::default();
    let mut book = RouteBook::new(
        &cfg,
        parts(),
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
    mint(&api, "tok", vec![Scope::ReadInventory]);
    let server = ClientApiServer::bind(Arc::new(api), 0).await.expect("bind");
    let addr = server.local_addr();
    (server, addr)
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

fn wait_holding(holding: &AtomicUsize, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while holding.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "{label} hold never started");
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn connect_ws(addr: SocketAddr, path: &str) -> Sock {
    let mut request = format!("ws://{addr}{path}").into_client_request().unwrap();
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{TOKEN}")
            .parse()
            .unwrap(),
    );
    request
        .headers_mut()
        .insert(ORIGIN, origin_of(addr).parse().unwrap());
    let (socket, _response) = tokio_tungstenite::connect_async(request)
        .await
        .unwrap_or_else(|e| panic!("ws connect {path}: {e:?}"));
    socket
}

async fn next_text(socket: &mut Sock) -> String {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("frame within 5s")
            .expect("stream open")
            .expect("frame");
        match frame {
            Message::Text(text) => return text.to_string(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected a text frame, got {other:?}"),
        }
    }
}

async fn expect_closed(socket: &mut Sock, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, socket.next()).await {
            Err(_) => panic!("{what}: no Close / end of stream within 2s"),
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_retire_hands_the_api_to_a_new_listener() {
    let mut api = ClientApi::new(ClientApiConfig::default());
    api.register(
        Method::Get,
        "/client/whoami",
        HandlerSpec::read(true, |ctx| {
            Ok(json!({
                "id": ctx.principal.as_ref().map(|p| p.id.clone()).unwrap_or_default()
            }))
        }),
    );
    let api = Arc::new(api);
    let original = Arc::clone(&api);
    let server = ClientApiServer::bind(api, 0).await.expect("bind");
    let addr = server.local_addr();

    let body = json!({ "platform": "mac" }).to_string();
    let request = format!(
        "POST /client/session/login HTTP/1.1\r\nHost: 127.0.0.1\r\nx-advance-api-version: {API_VERSION}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, login_body) = http_exchange(addr, &request);
    assert_eq!(status, 200, "login: {login_body}");
    let login: Value = serde_json::from_str(&login_body).expect("login json");
    let token = login["data"]["token"]
        .as_str()
        .expect("login token")
        .to_string();

    let retired = server.retire(Duration::from_secs(5)).await;
    assert!(
        Arc::ptr_eq(&retired.api, &original),
        "retire hands back the same ClientApi"
    );
    assert!(retired.drained, "idle listener drained");
    assert!(retired.ws_joined, "no WebSocket tasks left");
    assert_eq!(retired.local_addr, addr);
    assert!(
        TcpStream::connect(addr).is_err(),
        "retired listener no longer accepts"
    );

    let server = ClientApiServer::bind(retired.api, addr.port())
        .await
        .expect("rebind previous port");
    assert_eq!(server.local_addr(), addr);
    let (status, who) = {
        let request = format!(
            "GET /client/whoami HTTP/1.1\r\nHost: 127.0.0.1\r\nx-advance-api-version: {API_VERSION}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        );
        http_exchange(server.local_addr(), &request)
    };
    assert_eq!(status, 200, "old token after rebind: {who}");
    let who: Value = serde_json::from_str(&who).expect("whoami json");
    assert!(!who["data"]["id"].as_str().unwrap_or("").is_empty());
    server.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_retire_closes_this_listeners_websockets() {
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let server = ClientApiServer::bind_local_factory(0, move |addr| {
        let mut config = ClientApiConfig::default();
        config.allowed_origins = vec![origin_of(addr)];
        let api = ClientApi::new(config)
            .with_event_provider(Arc::new(EmptyEvents))
            .with_leak_detector(detector)
            .with_cursor_codec(codec());
        mint(&api, TOKEN, Scope::operator_default());
        Arc::new(api)
    })
    .await
    .expect("bind");
    let addr = server.local_addr();

    let mut events = connect_ws(addr, "/client/events/stream").await;
    let seed = next_text(&mut events).await;
    assert!(seed.contains("\"data\""), "events seed: {seed}");

    let retired = server.retire(Duration::from_secs(5)).await;
    assert!(retired.ws_joined, "WebSocket tasks joined");
    expect_closed(&mut events, "events").await;
    drop(retired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_retire_keeps_extension_pools_open() {
    let (server, addr) = bind_ext_server(|_| Ok(json!({ "ok": true }))).await;
    let port = addr.port();
    let retired = server.retire(Duration::from_secs(5)).await;
    assert!(retired.drained);
    let server = ClientApiServer::bind(retired.api, port)
        .await
        .expect("rebind");
    assert_eq!(
        http_get(server.local_addr(), "/client/ext/hold", Some("tok")),
        200
    );
    server.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_shutdown_unbound_drains_and_closes_extension_pools() {
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let holding = Arc::new(AtomicUsize::new(0));
    let (server, addr) =
        bind_ext_server(hold_handler(Arc::clone(&released), Arc::clone(&holding))).await;
    let api = server.api();
    let h = std::thread::spawn(move || http_get(addr, "/client/ext/hold", Some("tok")));
    wait_holding(&holding, "ext-unbound");
    let ingress =
        ClientApiServer::shutdown_unbound(Arc::clone(&api), Duration::from_millis(200)).await;
    assert!(
        !ingress.drained,
        "a held extension dispatch must miss the 200 ms drain"
    );
    release(&released);
    let _ = h.join();
    assert_eq!(
        http_get(addr, "/client/ext/hold", Some("tok")),
        503,
        "closed pool fails closed"
    );
    drop(ingress);
    server.shutdown().await.expect("shutdown held");

    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let holding = Arc::new(AtomicUsize::new(0));
    let (server, _addr) =
        bind_ext_server(hold_handler(Arc::clone(&released), Arc::clone(&holding))).await;
    let api = server.api();
    let ingress = ClientApiServer::shutdown_unbound(api, Duration::from_millis(200)).await;
    assert!(
        ingress.drained,
        "the extension pool drains when no request is in flight"
    );
    drop(ingress);
    server.shutdown().await.expect("shutdown idle");
}
