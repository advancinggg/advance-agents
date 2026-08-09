//! T25a-k — real `ReqwestHttpExecutor` end-to-end against a loopback `axum` mock
//! server (Slice E). No real network, no API key.
//!
//! SSRF-vs-loopback bridge: the chain's `DefaultSsrfGuard` blocks 127.0.0.1, so we map
//! `api.example.com` → a PUBLIC IP via `MockResolver` (SSRF passes) while the executor's
//! reqwest client carries a `.resolve()` DNS override → `127.0.0.1:PORT` (real TCP to the
//! mock server). `Allowlist::matches` is host-only/port-agnostic, so `"api.example.com"`
//! matches `http://api.example.com:PORT/...`.
//!
//! Witnessing what reached the wire uses a side-channel `Recorder` (NOT response-body
//! reflection) so reflected credentials never trip the chain's step-8 inbound leak scan.

use advance_shared_types::security_validator::{
    Allowlist, CredentialBinding, CredentialPosition, HttpCapability, HttpError, HttpMethod,
    HttpRequest, HttpSecurityChain, LeakDetector, RedirectRejectReason, SsrfGuard,
    TransportErrorKind,
};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use cap_http::rate_limit::{AlwaysAllow, RateLimiter};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, HttpExecutor, MockResolver,
    ReqwestExecutorConfig, ReqwestHttpExecutor,
};
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

// ─── Mock server harness ─────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<RecordedReq>>>);

#[derive(Clone)]
struct RecordedReq {
    path: String,
    method: String,
    headers: Vec<(String, String)>,
    #[allow(dead_code)]
    body: Vec<u8>,
}

fn record(rec: &Recorder, path: &str, method: &Method, headers: &HeaderMap, body: &Bytes) {
    rec.0.lock().unwrap().push(RecordedReq {
        path: path.to_string(),
        method: method.to_string(),
        headers: headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: body.to_vec(),
    });
}

async fn get_handler() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        "hello-get",
    )
}

async fn echo_handler(
    State(rec): State<Recorder>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&rec, "/echo", &method, &headers, &body);
    "echo-ok"
}

async fn final_handler(
    State(rec): State<Recorder>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&rec, "/final", &method, &headers, &body);
    "final-ok"
}

async fn redirect_handler(
    State(rec): State<Recorder>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&rec, "/redirect", &method, &headers, &body);
    // absolute-path Location → executor follows (path+query sourced wholly from Location).
    (
        StatusCode::FOUND,
        [(header::LOCATION, HeaderValue::from_static("/final"))],
    )
}

async fn redirect_evil_handler() -> impl IntoResponse {
    // absolute URL to a NON-allowlisted host → redirect_check rejects (AllowlistBlocked).
    (
        StatusCode::FOUND,
        [(
            header::LOCATION,
            HeaderValue::from_static("http://evil.example.com/pwn"),
        )],
    )
}

async fn redirect_relative_handler() -> impl IntoResponse {
    // query-only Location → executor MUST refuse (would let url::Url::join preserve the
    // injected base path/query). Maps to ExecutorError::Transport.
    (
        StatusCode::FOUND,
        [(header::LOCATION, HeaderValue::from_static("?leftover=1"))],
    )
}

async fn redirect_network_handler() -> impl IntoResponse {
    // network-path Location (`//host`) → executor MUST refuse outright (a bare `/`-prefixed
    // reference that silently changes host). Maps to ExecutorError::Transport WITHOUT calling
    // redirect_check — the executor itself rejects it, not just the allowlist.
    (
        StatusCode::FOUND,
        [(
            header::LOCATION,
            HeaderValue::from_static("//evil.example.com/pwn"),
        )],
    )
}

async fn redirect_backslash_handler() -> impl IntoResponse {
    // Backslash network-path EQUIVALENT — WHATWG `url::Url::join` normalizes `/\host` into the
    // authority (silent host change). Must be rejected by the origin check, NOT just the `//`
    // literal-prefix guard (round-6 diff W1 hardening).
    (
        StatusCode::FOUND,
        [(
            header::LOCATION,
            HeaderValue::from_static("/\\evil.example.com/pwn"),
        )],
    )
}

async fn huge_handler() -> impl IntoResponse {
    // Body far larger than T25k's small max_response_bytes cap → executor rejects → Transport.
    "a".repeat(4096)
}

async fn slow_handler() -> impl IntoResponse {
    tokio::time::sleep(Duration::from_secs(2)).await;
    "slow-done"
}

async fn leak_handler() -> impl IntoResponse {
    // Body carries a BUILTIN leak pattern (openai key) → step-8 inbound scan blocks.
    "leak: sk-proj-abcdefghijklmnop1234ABCD"
}

/// Bind a loopback server on an ephemeral port; serve in a background task.
/// Returns the bound addr, the server task handle, and the request recorder.
async fn start_mock_server() -> (SocketAddr, tokio::task::JoinHandle<()>, Recorder) {
    let rec = Recorder::default();
    let app = Router::new()
        .route("/get", get(get_handler))
        .route("/echo", get(echo_handler).post(echo_handler))
        .route("/final", get(final_handler).post(final_handler))
        .route("/redirect", get(redirect_handler).post(redirect_handler))
        .route("/redirect-evil", get(redirect_evil_handler))
        .route("/redirect-relative", get(redirect_relative_handler))
        .route("/redirect-network", get(redirect_network_handler))
        .route("/redirect-backslash", get(redirect_backslash_handler))
        .route("/huge", get(huge_handler))
        .route("/slow", get(slow_handler))
        .route("/leak", get(leak_handler))
        .with_state(rec.clone());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle, rec)
}

// ─── Chain wiring ────────────────────────────────────────────────────────────

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn store(secrets: &[(&str, &str)]) -> Arc<SecretStore> {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let master = Zeroizing::new([0xab; 32]);
    let s = SecretStore::new(master, storage);
    for (name, value) in secrets {
        s.store(name, value).unwrap();
    }
    Arc::new(s)
}

struct TraceCollector(Mutex<Vec<&'static str>>);
impl TraceCollector {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }
    fn snapshot(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
}

/// Build a chain whose executor is the REAL `ReqwestHttpExecutor`, DNS-overriding
/// `api.example.com` → `127.0.0.1:port` while SSRF sees the public IP `8.8.8.8`.
fn build_chain(
    port: u16,
    secrets: &[(&str, &str)],
    timeout: Duration,
    tracer: Option<Arc<TraceCollector>>,
) -> DefaultHttpSecurityChain {
    let leak: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn RateLimiter> = Arc::new(AlwaysAllow);
    let exec: Arc<dyn HttpExecutor> =
        Arc::new(ReqwestHttpExecutor::from_config(ReqwestExecutorConfig {
            timeout,
            dns_overrides: vec![(
                "api.example.com".to_string(),
                SocketAddr::from(([127, 0, 0, 1], port)),
            )],
            max_redirects: 10,
            ..Default::default()
        }));
    let chain = DefaultHttpSecurityChain::new(store(secrets), leak, ssrf, rl, exec);
    match tracer {
        Some(t) => {
            let t2 = Arc::clone(&t);
            chain.with_step_tracer(Arc::new(move |name| t2.0.lock().unwrap().push(name)))
        }
        None => chain,
    }
}

fn cap(allowlist: &[&str], creds: Vec<CredentialBinding>) -> HttpCapability {
    HttpCapability {
        allowlist: Allowlist {
            patterns: allowlist.iter().map(|s| s.to_string()).collect(),
        },
        credentials: creds,
        component_id: "test".to_string(),
    }
}

fn url(port: u16, path: &str) -> String {
    format!("http://api.example.com:{}{}", port, path)
}

fn get_req(port: u16, path: &str) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: url(port, path),
        headers: vec![],
        body: vec![],
    }
}

// ─── T25a — real GET round-trip ──────────────────────────────────────────────

#[tokio::test]
async fn t25a_real_get_round_trip() {
    let (addr, _h, _rec) = start_mock_server().await;
    let chain = build_chain(addr.port(), &[], Duration::from_secs(5), None);
    let resp = chain
        .execute(
            "agent-1",
            get_req(addr.port(), "/get"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(String::from_utf8_lossy(&resp.body), "hello-get");
    assert!(
        resp.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("application/json")),
        "headers: {:?}",
        resp.headers
    );
}

// ─── T25b — real POST + injected BearerToken present on the wire (hop 1) ──────

#[tokio::test]
async fn t25b_real_post_injected_bearer_on_wire() {
    let (addr, _h, rec) = start_mock_server().await;
    let chain = build_chain(
        addr.port(),
        &[("api_key", "secret-bearer-xyz")],
        Duration::from_secs(5),
        None,
    );
    let req = HttpRequest {
        method: HttpMethod::Post,
        url: url(addr.port(), "/echo"),
        headers: vec![],
        body: b"request-body-123".to_vec(),
    };
    let mut c = cap(&["api.example.com"], vec![]);
    c.credentials.push(CredentialBinding {
        position: CredentialPosition::BearerToken,
        secret_name: "api_key".to_string(),
    });
    let resp = chain.execute("agent-1", req, &c).await.unwrap();
    assert_eq!(resp.status, 200);

    let recs = rec.0.lock().unwrap();
    let echo = recs
        .iter()
        .find(|r| r.path == "/echo")
        .expect("server saw /echo");
    assert_eq!(echo.method, "POST");
    let auth = echo
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str());
    assert_eq!(
        auth,
        Some("Bearer secret-bearer-xyz"),
        "injected Bearer token must reach the wire; headers: {:?}",
        echo.headers
    );
    assert_eq!(
        echo.body, b"request-body-123",
        "request body must be delivered"
    );
}

// ─── T25c — redirect to allowlisted target followed (clean GET) ──────────────

#[tokio::test]
async fn t25c_redirect_followed() {
    let (addr, _h, rec) = start_mock_server().await;
    let chain = build_chain(addr.port(), &[], Duration::from_secs(5), None);
    let resp = chain
        .execute(
            "agent-1",
            get_req(addr.port(), "/redirect"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(String::from_utf8_lossy(&resp.body), "final-ok");
    let recs = rec.0.lock().unwrap();
    assert!(
        recs.iter().any(|r| r.path == "/final"),
        "redirect target /final must be hit"
    );
}

// ─── T25d — redirect to non-allowlisted host rejected ────────────────────────

#[tokio::test]
async fn t25d_redirect_non_allowlisted_rejected() {
    let (addr, _h, rec) = start_mock_server().await;
    let chain = build_chain(addr.port(), &[], Duration::from_secs(5), None);
    let err = chain
        .execute(
            "agent-1",
            get_req(addr.port(), "/redirect-evil"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            HttpError::RedirectRejected {
                reason: RedirectRejectReason::AllowlistBlocked,
                ..
            }
        ),
        "got: {:?}",
        err
    );
    // The executor must NOT have connected to evil (no recorded request for it).
    let recs = rec.0.lock().unwrap();
    assert!(recs.iter().all(|r| r.path != "/pwn"));
}

// ─── T25e — redirect carries NONE of the original creds/headers (zero-carry) ──

#[tokio::test]
async fn t25e_redirect_zero_carry() {
    let (addr, _h, rec) = start_mock_server().await;
    let chain = build_chain(
        addr.port(),
        &[("api_key", "sek-bearer-val"), ("xkey", "sek-custom-val")],
        Duration::from_secs(5),
        None,
    );
    let mut c = cap(&["api.example.com"], vec![]);
    c.credentials.push(CredentialBinding {
        position: CredentialPosition::BearerToken,
        secret_name: "api_key".to_string(),
    });
    c.credentials.push(CredentialBinding {
        position: CredentialPosition::CustomHeader {
            key: "X-Api-Key".to_string(),
        },
        secret_name: "xkey".to_string(),
    });
    let resp = chain
        .execute("agent-1", get_req(addr.port(), "/redirect"), &c)
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&resp.body), "final-ok");

    let recs = rec.0.lock().unwrap();
    let final_req = recs
        .iter()
        .find(|r| r.path == "/final")
        .expect("redirect reached /final");
    // Zero-carry: NONE of the original creds/headers reach the redirect target. We check
    // specific-header absence (reqwest/axum still add transport headers like host).
    assert!(
        !final_req
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("authorization")),
        "redirect hop must NOT carry Authorization: {:?}",
        final_req.headers
    );
    assert!(
        !final_req
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("x-api-key")),
        "redirect hop must NOT carry the CustomHeader credential: {:?}",
        final_req.headers
    );
    assert_eq!(final_req.method, "GET", "redirect hop must be a clean GET");
}

// ─── T25f — request timeout → Transport(Timeout) ─────────────────────────────

#[tokio::test]
async fn t25f_timeout_maps_to_transport_timeout() {
    let (addr, _h, _rec) = start_mock_server().await;
    let chain = build_chain(addr.port(), &[], Duration::from_millis(150), None);
    let err = chain
        .execute(
            "agent-1",
            get_req(addr.port(), "/slow"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Transport(TransportErrorKind::Timeout)),
        "got: {:?}",
        err
    );
}

// ─── T25g — transport error (connection refused) → Transport ─────────────────

#[tokio::test]
async fn t25g_connection_refused_maps_to_transport() {
    // Bind then drop to obtain a free loopback port nothing is listening on.
    let free_port = {
        let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let chain = build_chain(free_port, &[], Duration::from_secs(3), None);
    let err = chain
        .execute(
            "agent-1",
            get_req(free_port, "/get"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap_err();
    // Any transport kind (refused → Other, or timeout-under-load → Timeout); both Transport(_).
    assert!(matches!(err, HttpError::Transport(_)), "got: {:?}", err);
}

// ─── T25h — full 10-step chain trace + inbound-leak over the real executor ────

#[tokio::test]
async fn t25h_full_chain_trace_and_inbound_leak() {
    let (addr, _h, _rec) = start_mock_server().await;

    // (a) direct GET /get → the chain runs all 10 steps in order.
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(
        addr.port(),
        &[],
        Duration::from_secs(5),
        Some(Arc::clone(&tracer)),
    );
    let resp = chain
        .execute(
            "agent-1",
            get_req(addr.port(), "/get"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(
        tracer.snapshot(),
        vec![
            "allowlist",
            "outbound_leak_scan",
            "substitute_placeholders",
            "inject_credentials",
            "ssrf_check",
            "rate_limit",
            "execute",
            "inbound_leak_scan",
            "redact_error_message",
            "return",
        ]
    );

    // (b) direct GET /leak → step-8 inbound scan blocks on the real response bytes.
    let chain2 = build_chain(addr.port(), &[], Duration::from_secs(5), None);
    let err = chain2
        .execute(
            "agent-1",
            get_req(addr.port(), "/leak"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpError::InboundLeakBlocked(_)),
        "got: {:?}",
        err
    );
}

// ─── T25i — credential-preserving (relative/query-only) Location rejected ─────

#[tokio::test]
async fn t25i_relative_location_rejected() {
    let (addr, _h, rec) = start_mock_server().await;
    let chain = build_chain(addr.port(), &[], Duration::from_secs(5), None);
    let err = chain
        .execute(
            "agent-1",
            get_req(addr.port(), "/redirect-relative"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap_err();
    // Query-only Location is refused (would let url::Url::join preserve injected base
    // path/query) → ExecutorError::Transport → HttpError::Transport(_).
    assert!(matches!(err, HttpError::Transport(_)), "got: {:?}", err);
    // The executor must NOT have followed to a target that preserves the base path.
    let recs = rec.0.lock().unwrap();
    assert!(recs.iter().all(|r| r.path != "/final"));
}

// ─── T25j — network-path (`//host`) Location rejected outright ────────────────

#[tokio::test]
async fn t25j_network_path_location_rejected() {
    let (addr, _h, rec) = start_mock_server().await;
    let chain = build_chain(addr.port(), &[], Duration::from_secs(5), None);
    // BOTH the `//host` literal form AND the `/\host` backslash form (which WHATWG
    // `url::Url::join` normalizes into the authority) silently change host. The origin check
    // rejects BOTH → `ExecutorError::Transport`, WITHOUT calling redirect_check (the executor
    // itself rejects them, not just the allowlist). Round-5 + round-6 diff W1 hardening.
    for path in ["/redirect-network", "/redirect-backslash"] {
        let err = chain
            .execute(
                "agent-1",
                get_req(addr.port(), path),
                &cap(&["api.example.com"], vec![]),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, HttpError::Transport(_)),
            "{} → got: {:?}",
            path,
            err
        );
    }
    // The executor must never have connected to the off-host target.
    let recs = rec.0.lock().unwrap();
    assert!(recs.iter().all(|r| r.path != "/pwn"));
}

// ─── T25k — oversized response body rejected (memory bound) ───────────────────

#[tokio::test]
async fn t25k_oversized_response_body_rejected() {
    let (addr, _h, _rec) = start_mock_server().await;
    // Tiny cap (1 KiB); `/huge` returns 4 KiB → executor refuses to buffer it → Transport.
    let leak: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn RateLimiter> = Arc::new(AlwaysAllow);
    let exec: Arc<dyn HttpExecutor> =
        Arc::new(ReqwestHttpExecutor::from_config(ReqwestExecutorConfig {
            timeout: Duration::from_secs(5),
            dns_overrides: vec![(
                "api.example.com".to_string(),
                SocketAddr::from(([127, 0, 0, 1], addr.port())),
            )],
            max_redirects: 10,
            max_response_bytes: 1024,
        }));
    let chain = DefaultHttpSecurityChain::new(store(&[]), leak, ssrf, rl, exec);
    let err = chain
        .execute(
            "agent-1",
            get_req(addr.port(), "/huge"),
            &cap(&["api.example.com"], vec![]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::Transport(_)), "got: {:?}", err);
}

// ─── T25l — connect-time SSRF resolver blocks a DNS-rebinding host ────────────

#[tokio::test]
async fn t25l_connect_time_ssrf_resolver_blocks_rebind() {
    // DISCRIMINATING rebinding test: the mock server IS listening on 127.0.0.1:PORT, so if
    // the SsrfDnsResolver were absent the request would SUCCEED (200). The chain's hostname
    // SSRF guard is fooled (MockResolver "localhost"→8.8.8.8, step 5 passes), but the
    // executor's SsrfDnsResolver re-resolves "localhost"→127.0.0.1 (loopback, forbidden) and
    // refuses the connection → Transport (round-9 Critical; round-11 W2 made this assertion
    // discriminating). No `.resolve()` override for "localhost" → the SsrfDnsResolver is
    // consulted (a static override would bypass it).
    let (addr, _h, _rec) = start_mock_server().await;
    let leak: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("localhost", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn RateLimiter> = Arc::new(AlwaysAllow);
    let exec: Arc<dyn HttpExecutor> =
        Arc::new(ReqwestHttpExecutor::with_timeout(Duration::from_secs(5)));
    let chain = DefaultHttpSecurityChain::new(store(&[]), leak, ssrf, rl, exec);
    let req = HttpRequest {
        method: HttpMethod::Get,
        url: format!("http://localhost:{}/get", addr.port()),
        headers: vec![],
        body: vec![],
    };
    let err = chain
        .execute("agent-1", req, &cap(&["localhost"], vec![]))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::Transport(_)), "got: {:?}", err);
}

// ─── T25m — executor blocks an IP-literal forbidden host (resolver bypass) ────

#[tokio::test]
async fn t25m_executor_blocks_ip_literal_host() {
    // IP-LITERAL hosts bypass the SsrfDnsResolver (hyper-util short-circuits DNS for literals),
    // so the executor-layer literal check is the backstop (round-11 adversarial W1).
    // DISCRIMINATING: the mock server IS up on 127.0.0.1:PORT, so without the check the request
    // would SUCCEED. The chain's SSRF guard is fooled (MockResolver maps the literal STRING
    // "127.0.0.1"→8.8.8.8, step 5 passes), but the executor sees the literal loopback host and
    // refuses → Transport.
    let (addr, _h, _rec) = start_mock_server().await;
    let leak: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("127.0.0.1", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn RateLimiter> = Arc::new(AlwaysAllow);
    let exec: Arc<dyn HttpExecutor> =
        Arc::new(ReqwestHttpExecutor::with_timeout(Duration::from_secs(5)));
    let chain = DefaultHttpSecurityChain::new(store(&[]), leak, ssrf, rl, exec);
    let req = HttpRequest {
        method: HttpMethod::Get,
        url: format!("http://127.0.0.1:{}/get", addr.port()),
        headers: vec![],
        body: vec![],
    };
    let err = chain
        .execute("agent-1", req, &cap(&["127.0.0.1"], vec![]))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::Transport(_)), "got: {:?}", err);
}

// ─────────────────────────────────────────────────────────────────────────────
// S3 — ReqwestHttpExecutor streaming transport (CONTRACT-233 executor seam).
// Raw-TCP chunked server (not axum) so the test controls WHEN each body chunk
// hits the wire — the live-fed proof needs head + chunk-1 to arrive while the
// server is still holding chunk-2 back.
// ─────────────────────────────────────────────────────────────────────────────

use cap_http::executor::HttpStreamExecutor;
use cap_http::ExecutorError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct AllowAllRedirect;

#[async_trait::async_trait]
impl advance_shared_types::security_validator::RedirectCheck for AllowAllRedirect {
    async fn check(
        &self,
        _target_url: &str,
        _target_headers: &[(String, String)],
    ) -> Result<(), RedirectRejectReason> {
        Ok(())
    }
}

/// Serve ONE connection with a manual HTTP/1.1 chunked response. Each entry is
/// (delay-before-writing-ms, chunk bytes). Returns the bound address.
async fn spawn_chunked_server(chunks: Vec<(u64, Vec<u8>)>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Drain the request head.
        let mut buf = [0u8; 4096];
        let mut req = Vec::new();
        loop {
            let n = sock.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            req.extend_from_slice(&buf[..n]);
            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        sock.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();
        for (delay_ms, chunk) in chunks {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            let hdr = format!("{:x}\r\n", chunk.len());
            sock.write_all(hdr.as_bytes()).await.unwrap();
            sock.write_all(&chunk).await.unwrap();
            sock.write_all(b"\r\n").await.unwrap();
            sock.flush().await.unwrap();
        }
        sock.write_all(b"0\r\n\r\n").await.unwrap();
        sock.flush().await.unwrap();
        // Keep the socket open briefly so the client observes clean EOF.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    addr
}

fn stream_executor_for(
    addr: SocketAddr,
    timeout: Duration,
    max_bytes: usize,
) -> ReqwestHttpExecutor {
    ReqwestHttpExecutor::from_config(ReqwestExecutorConfig {
        timeout,
        dns_overrides: vec![("api.stream.test".to_string(), addr)],
        max_redirects: 10,
        max_response_bytes: max_bytes,
    })
}

fn stream_req(addr: SocketAddr) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: format!("http://api.stream.test:{}/sse", addr.port()),
        headers: vec![],
        body: vec![],
    }
}

/// Live-fed proof: the head + first chunk arrive while the server is still
/// holding the second chunk back — a buffer-then-replay implementation would
/// block until the full body (≥ 600 ms) before yielding anything.
#[tokio::test]
async fn s3_reqwest_stream_live_fed_head_before_body_complete() {
    let addr = spawn_chunked_server(vec![
        (0, b"first-chunk".to_vec()),
        (600, b"second-chunk".to_vec()),
    ])
    .await;
    let exec = stream_executor_for(addr, Duration::from_secs(5), 1024 * 1024);
    let started = std::time::Instant::now();
    let (head, mut wire) = exec
        .execute_stream(&stream_req(addr), Arc::new(AllowAllRedirect))
        .await
        .unwrap();
    assert_eq!(head.status, 200);
    let first = wire.next().await.expect("first chunk").expect("ok");
    let elapsed_first = started.elapsed();
    assert_eq!(first, b"first-chunk");
    assert!(
        elapsed_first < Duration::from_millis(450),
        "first chunk must be pollable BEFORE the upstream terminal \
         (live-fed, not buffer-then-replay); took {elapsed_first:?}"
    );
    let second = wire.next().await.expect("second chunk").expect("ok");
    assert_eq!(second, b"second-chunk");
    assert!(wire.next().await.is_none(), "clean EOF after final chunk");
    assert!(wire.next().await.is_none(), "terminal is absorbing");
}

/// Per-frame idle timeout: a stalled upstream (no chunk within the idle
/// window) terminates enum-coded — never a hang.
#[tokio::test]
async fn s3_reqwest_stream_idle_timeout_enum_coded() {
    let addr = spawn_chunked_server(vec![
        (0, b"one".to_vec()),
        (10_000, b"never-arrives".to_vec()),
    ])
    .await;
    let exec = stream_executor_for(addr, Duration::from_millis(400), 1024 * 1024);
    let (_head, mut wire) = exec
        .execute_stream(&stream_req(addr), Arc::new(AllowAllRedirect))
        .await
        .unwrap();
    assert_eq!(wire.next().await.unwrap().unwrap(), b"one");
    let started = std::time::Instant::now();
    match wire.next().await {
        Some(Err(ExecutorError::Timeout)) => {}
        other => panic!("stalled upstream must yield enum-coded Timeout, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "idle timeout must fire at ~the configured window, not hang"
    );
    assert!(wire.next().await.is_none(), "terminal is absorbing");
}

/// Cumulative wire cap: a body exceeding max_response_bytes terminates
/// enum-coded mid-stream (same rationale as the buffered 8 MiB cap).
#[tokio::test]
async fn s3_reqwest_stream_cumulative_cap_enum_coded() {
    let addr = spawn_chunked_server(vec![(0, vec![b'a'; 6]), (0, vec![b'b'; 6])]).await;
    let exec = stream_executor_for(addr, Duration::from_secs(5), 8);
    let (_head, mut wire) = exec
        .execute_stream(&stream_req(addr), Arc::new(AllowAllRedirect))
        .await
        .unwrap();
    assert_eq!(wire.next().await.unwrap().unwrap(), vec![b'a'; 6]);
    match wire.next().await {
        Some(Err(ExecutorError::Transport)) => {}
        other => panic!("cap breach must yield enum-coded Transport, got {other:?}"),
    }
    assert!(wire.next().await.is_none(), "terminal is absorbing");
}

/// Streaming uses the same real reqwest redirect walk as the buffered path.
/// Prove its POST is rewritten to a clean GET with no caller headers/body;
/// checking only mock-fixture revalidation would not witness bytes on wire.
#[tokio::test]
async fn s3_reqwest_stream_redirect_zero_carry_on_wire() {
    let (addr, _h, rec) = start_mock_server().await;
    let exec = ReqwestHttpExecutor::from_config(ReqwestExecutorConfig {
        timeout: Duration::from_secs(5),
        dns_overrides: vec![("api.example.com".to_string(), addr)],
        max_redirects: 10,
        ..Default::default()
    });
    let request = HttpRequest {
        method: HttpMethod::Post,
        url: url(addr.port(), "/redirect"),
        headers: vec![
            (
                "Authorization".to_string(),
                "Bearer must-not-carry".to_string(),
            ),
            ("X-Api-Key".to_string(), "must-not-carry".to_string()),
            ("X-Caller-Marker".to_string(), "must-not-carry".to_string()),
        ],
        body: b"must-not-carry-body".to_vec(),
    };

    let (head, mut wire) = exec
        .execute_stream(&request, Arc::new(AllowAllRedirect))
        .await
        .unwrap();
    assert_eq!(head.status, 200);
    let mut response_body = Vec::new();
    while let Some(chunk) = wire.next().await {
        response_body.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(response_body, b"final-ok");

    let recs = rec.0.lock().unwrap();
    let initial_req = recs
        .iter()
        .find(|record| record.path == "/redirect")
        .expect("streaming initial request reached /redirect");
    assert_eq!(initial_req.method, "POST");
    assert_eq!(initial_req.body, b"must-not-carry-body");
    for (name, value) in [
        ("authorization", "Bearer must-not-carry"),
        ("x-api-key", "must-not-carry"),
        ("x-caller-marker", "must-not-carry"),
    ] {
        assert!(
            initial_req
                .headers
                .iter()
                .any(|(actual_name, actual_value)| {
                    actual_name.eq_ignore_ascii_case(name) && actual_value == value
                }),
            "initial POST must carry {name}"
        );
    }
    let final_req = recs
        .iter()
        .find(|record| record.path == "/final")
        .expect("streaming redirect reached /final");
    for forbidden in ["authorization", "x-api-key", "x-caller-marker"] {
        assert!(
            !final_req
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(forbidden)),
            "streaming redirect must not carry {forbidden}: {:?}",
            final_req.headers
        );
    }
    assert_eq!(final_req.method, "GET", "redirect hop must be a clean GET");
    assert!(
        final_req.body.is_empty(),
        "redirect hop must not carry the original request body"
    );
}
