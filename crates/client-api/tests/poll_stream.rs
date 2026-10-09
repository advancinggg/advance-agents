//! MODULE-001-AC-33: registrar rules for `poll_stream`, the OSS WebSocket routes unchanged when
//! a poll stream is installed, and a POST to a poll-stream path.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use advance_client_api::clock::SystemClock;
use advance_client_api::families::{
    ExtensionServiceParts, NoExtensionRouteHooks, PollEmit, PollStreamDefect, PollStreamSpec,
    RouteBook, RouteRefusalReason,
};
use advance_client_api::{
    AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientApiServer, ClientCursorCodec,
    ClientEventProvider, ClientSession, DuplicateOf, HandlerSpec, LlmDeltaHub,
    MemoryCursorKeyCustody, Method, NoopSink, NormalizedEventFilter, OsCursorEntropy, Platform,
    Principal, ProviderError, RawEventRow, Scope, SystemCursorClock, API_VERSION,
    CLIENT_WS_PROTOCOL,
};
use advance_shared_types::security_validator::LeakDetector;
use cap_http::canonical_facade::decoded_hold_split;
use cap_http::DefaultLeakDetector;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;

const TOKEN: &str = "poll-stream-token";

struct StubDetector;

impl LeakDetector for StubDetector {
    fn scan(
        &self,
        _text: &str,
        _context: advance_shared_types::security_validator::ScanContext,
    ) -> advance_shared_types::security_validator::ScanResult {
        advance_shared_types::security_validator::ScanResult::Clean
    }
    fn scan_headers(
        &self,
        _headers: &[(String, String)],
    ) -> advance_shared_types::security_validator::ScanResult {
        advance_shared_types::security_validator::ScanResult::Clean
    }
}

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

fn book() -> RouteBook {
    RouteBook::new(
        &ClientApiConfig::default(),
        parts(),
        advance_client_api::ExtensionRouteGate::new(),
        Arc::new(NoExtensionRouteHooks),
    )
}

fn read_feed() -> HandlerSpec {
    HandlerSpec::read(true, |_| Ok(json!({ "items": [], "cursor": "c0" })))
        .with_scopes(vec![Scope::ReadInventory])
}

fn spec(handler: HandlerSpec) -> PollStreamSpec {
    PollStreamSpec::new(handler, "/cursor", PollEmit::NonEmptyArrayAt("/items"))
}

fn codec() -> Arc<dyn ClientCursorCodec> {
    Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ))
}

fn delta_hub() -> Arc<LlmDeltaHub> {
    let hold_split = Arc::new(|buf: &[u8], max: usize| decoded_hold_split(buf, max));
    Arc::new(LlmDeltaHub::new(
        Some(Arc::new(DefaultLeakDetector::new())),
        Some(hold_split),
        Arc::new(SystemClock),
        None,
    ))
}

fn mint(api: &ClientApi) {
    api.sessions().insert(
        TOKEN.to_string(),
        ClientSession {
            session_id: "poll-stream-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

#[test]
fn module_001_ac33_poll_stream_registrar_rules() {
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        let err = r
            .poll_stream("/client/ext/feed/{id}", spec(read_feed()))
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::PollStream(PollStreamDefect::TemplatedPath)
        );
        assert_eq!(err.reason.to_string(), "poll stream: templated path");
    }
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        let err = r
            .poll_stream(
                "/client/ext/feed",
                PollStreamSpec::new(read_feed(), "cursor", PollEmit::NonEmptyArrayAt("/items")),
            )
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::PollStream(PollStreamDefect::InvalidCursorPointer)
        );
    }
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        let err = r
            .poll_stream(
                "/client/ext/feed",
                PollStreamSpec::new(read_feed(), "/", PollEmit::NonEmptyArrayAt("/items")),
            )
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::PollStream(PollStreamDefect::InvalidCursorPointer)
        );
    }
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        let err = r
            .poll_stream(
                "/client/ext/feed",
                PollStreamSpec::new(read_feed(), "/a~x", PollEmit::NonEmptyArrayAt("/items")),
            )
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::PollStream(PollStreamDefect::InvalidCursorPointer)
        );
    }
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        let err = r
            .poll_stream(
                "/client/ext/feed",
                PollStreamSpec::new(
                    read_feed(),
                    TOO_LONG_CURSOR,
                    PollEmit::NonEmptyArrayAt("/items"),
                ),
            )
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::PollStream(PollStreamDefect::InvalidCursorPointer)
        );
    }
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        let err = r
            .poll_stream(
                "/client/ext/feed",
                PollStreamSpec::new(read_feed(), "/cursor", PollEmit::NonEmptyArrayAt("items")),
            )
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::PollStream(PollStreamDefect::InvalidEmitPointer)
        );
        assert_eq!(err.reason.to_string(), "poll stream: invalid emit pointer");
    }
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        let handler =
            HandlerSpec::mutation(true, |_| Ok(json!({}))).with_scopes(vec![Scope::WriteEntities]);
        let err = r
            .poll_stream("/client/ext/feed", spec(handler))
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::PollStream(PollStreamDefect::HandlerNotRead)
        );
    }
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        let err = r
            .poll_stream("/client/events/feed", spec(read_feed()))
            .unwrap_err();
        assert!(
            matches!(err.reason, RouteRefusalReason::ReservedLabel { ref label } if label == "events")
        );
    }
    {
        let mut book = book();
        let mut r = book.registrar("ext");
        r.route(Method::Get, "/client/ext/feed", read_feed())
            .unwrap();
        let err = r
            .poll_stream("/client/ext/feed", spec(read_feed()))
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::DuplicateRoute {
                shape: "/client/ext/feed".into(),
                of: DuplicateOf::Extension("ext"),
            }
        );
    }
    {
        let mut book = book();
        {
            let mut r = book.registrar("ext");
            r.poll_stream("/client/ext/feed", spec(read_feed()))
                .unwrap();
        }
        let families = book.finish().unwrap();
        let report = families.report();
        assert_eq!(report.len(), 1);
        assert!(report[0].poll_stream);
        assert_eq!(report[0].path, "/client/ext/feed");
        assert_eq!(report[0].method, Method::Get);
        let mut api = ClientApi::with_parts(
            ClientApiConfig::default(),
            "operator",
            Arc::new(SystemClock),
            Arc::new(NoopSink),
        );
        families.install(&mut api);
        mint(&api);
        let env = api
            .handle(advance_client_api::ClientRequest::get("/client/ext/feed").with_session(TOKEN));
        assert!(env.is_ok(), "{:?}", env.error_code());
        let data = env.data.expect("data");
        assert_eq!(data["cursor"], "c0");
        assert_eq!(data["items"], json!([]));
    }
}

/// 129-byte pointer (`/` + 128 `a`s); the poll-stream limit is 128 bytes.
const TOO_LONG_CURSOR: &str = concat!(
    "/",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_events_and_delta_ws_unchanged_with_a_poll_stream() {
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let server = ClientApiServer::bind_local_factory(0, move |addr| {
        let mut cfg = ClientApiConfig::default();
        cfg.allowed_origins = vec![format!("http://{addr}")];
        let mut book = RouteBook::new(
            &cfg,
            parts(),
            advance_client_api::ExtensionRouteGate::new(),
            Arc::new(NoExtensionRouteHooks),
        );
        {
            let mut r = book.registrar("ext");
            r.poll_stream("/client/ext/feed", spec(read_feed()))
                .unwrap();
        }
        let families = book.finish().unwrap();
        let mut api = ClientApi::new(cfg)
            .with_event_provider(Arc::new(EmptyEvents))
            .with_leak_detector(Arc::clone(&detector))
            .with_cursor_codec(codec())
            .with_llm_delta_hub(delta_hub());
        families.install(&mut api);
        mint(&api);
        Arc::new(api)
    })
    .await
    .expect("bind");
    let addr = server.local_addr();
    let origin = format!("http://{addr}");

    let events = connect_ws(addr, &origin, "/client/events/stream")
        .await
        .expect("events ws");
    let (mut events, _) = events;
    let seed = next_text(&mut events).await;
    assert!(seed.contains("\"data\""), "events seed: {seed}");
    let env: advance_client_api::ClientEnvelope<Value> =
        serde_json::from_str(&seed).expect("events envelope");
    assert!(env.is_ok());
    assert_eq!(env.api_version, API_VERSION);

    let deltas = connect_ws(addr, &origin, "/client/llm/deltas/stream")
        .await
        .expect("delta ws");
    let (mut deltas, _) = deltas;
    let seed = next_text(&mut deltas).await;
    assert!(seed.contains("\"data\""), "delta seed: {seed}");
    let env: advance_client_api::ClientEnvelope<Value> =
        serde_json::from_str(&seed).expect("delta envelope");
    assert!(env.is_ok());

    let feed = connect_ws(addr, &origin, "/client/ext/feed")
        .await
        .expect("poll stream ws");
    let (mut feed, _) = feed;
    let seed = next_text(&mut feed).await;
    let env: advance_client_api::ClientEnvelope<Value> =
        serde_json::from_str(&seed).expect("feed envelope");
    assert!(env.is_ok(), "{:?}", env.error);
    let data = env.data.expect("feed seed data");
    assert_eq!(data["cursor"], "c0");
    assert_eq!(data["items"], json!([]));
}

type Sock =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_ws(
    addr: std::net::SocketAddr,
    origin: &str,
    path: &str,
) -> Result<(Sock, u16), WsError> {
    let mut request = format!("ws://{addr}{path}").into_client_request().unwrap();
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{TOKEN}")
            .parse()
            .unwrap(),
    );
    request
        .headers_mut()
        .insert(ORIGIN, origin.parse().unwrap());
    let (socket, response) = tokio_tungstenite::connect_async(request).await?;
    Ok((socket, response.status().as_u16()))
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

/// One raw HTTP/1.1 request with an empty body; `(status, JSON body or Null)`. Reads exactly the
/// response's `Content-Length`, so a kept-alive connection does not hold the test.
async fn raw_http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
) -> (u16, Value) {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    let (head_end, body_len) = tokio::time::timeout(Duration::from_secs(10), async {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&response[..end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse::<usize>().expect("content-length"))
                    .unwrap_or(0);
                if response.len() >= end + 4 + len {
                    return (end, len);
                }
            }
            let n = stream.read(&mut chunk).await.expect("read response");
            assert!(n > 0, "connection closed mid-response: {response:?}");
            response.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .expect("response within 10s");
    let status_line = String::from_utf8_lossy(&response[..head_end]).into_owned();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .expect("status code");
    let body = &response[head_end + 4..head_end + 4 + body_len];
    (status, serde_json::from_slice(body).unwrap_or(Value::Null))
}

/// A POST that carries the WebSocket upgrade headers is not a poll-stream request: the stream's
/// read never runs for it and it is answered as the same POST without those headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_post_with_upgrade_headers_never_runs_the_poll_read() {
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&reads);
    let server = ClientApiServer::bind_local_factory(0, move |addr| {
        let mut cfg = ClientApiConfig::default();
        cfg.allowed_origins = vec![format!("http://{addr}")];
        let mut book = RouteBook::new(
            &cfg,
            parts(),
            advance_client_api::ExtensionRouteGate::new(),
            Arc::new(NoExtensionRouteHooks),
        );
        {
            let mut r = book.registrar("ext");
            let read = HandlerSpec::read(true, move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "items": [], "cursor": "c0" }))
            })
            .with_scopes(vec![Scope::ReadInventory]);
            r.poll_stream("/client/ext/feed", spec(read)).unwrap();
        }
        let families = book.finish().unwrap();
        let mut api =
            ClientApi::with_parts(cfg, "operator", Arc::new(SystemClock), Arc::new(NoopSink));
        families.install(&mut api);
        mint(&api);
        Arc::new(api)
    })
    .await
    .expect("bind");
    let addr = server.local_addr();
    let origin = format!("http://{addr}");
    let session = [
        ("Origin", origin.clone()),
        ("Authorization", format!("Bearer {TOKEN}")),
    ];
    let upgrade = [
        ("Origin", origin.clone()),
        ("Authorization", format!("Bearer {TOKEN}")),
        ("Upgrade", "websocket".to_string()),
        ("Connection", "Upgrade".to_string()),
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==".to_string()),
        ("Sec-WebSocket-Version", "13".to_string()),
        (
            "Sec-WebSocket-Protocol",
            format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{TOKEN}"),
        ),
    ];

    let (plain_status, plain) = raw_http(addr, "POST", "/client/ext/feed", &session).await;
    let (status, body) = raw_http(addr, "POST", "/client/ext/feed", &upgrade).await;
    assert_eq!(
        reads.load(Ordering::SeqCst),
        0,
        "the poll read ran for a POST (answered {status}: {body})"
    );
    assert_eq!(plain_status, 404, "{plain}");
    assert_eq!(
        plain.pointer("/error/code"),
        Some(&json!("unknown_route")),
        "{plain}"
    );
    assert_eq!(status, plain_status, "{body}");
    assert_eq!(body.pointer("/error"), plain.pointer("/error"), "{body}");

    // The GET upgrade on the same path still seeds the stream with one read.
    let (mut feed, switched) = connect_ws(addr, &origin, "/client/ext/feed")
        .await
        .expect("poll stream ws");
    assert_eq!(switched, 101);
    let seed: Value = serde_json::from_str(&next_text(&mut feed).await).expect("seed json");
    assert_eq!(seed.pointer("/data/cursor"), Some(&json!("c0")), "{seed}");
    assert!(reads.load(Ordering::SeqCst) >= 1);
}
