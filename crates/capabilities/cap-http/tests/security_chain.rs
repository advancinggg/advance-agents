//! T06a-i + T12a-g + T14a-d — HttpSecurityChain integration tests
//! (AC-06 + AC-12 + AC-14). Use `MockHttpExecutor` + `MockResolver`.

use advance_shared_types::security_validator::{
    Allowlist, CidrClass, CredentialBinding, CredentialPosition, HttpCapability, HttpError,
    HttpMethod, HttpRequest, HttpResponse, HttpSecurityChain, RedirectRejectReason,
    SecretResolutionReason,
};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, HttpExecutor,
    MockHttpExecutor, MockResolver,
};
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

// AlwaysAllow / AlwaysDeny are private to rate_limit.rs's pub-but-not-re-exported
// path. Re-import via the crate-internal path.
mod private_helpers {
    pub use cap_http::rate_limit::{AlwaysAllow, AlwaysDeny};
}

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

fn cap_with_allowlist(patterns: &[&str]) -> HttpCapability {
    HttpCapability {
        allowlist: Allowlist {
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
        },
        credentials: vec![],
        component_id: "test-component".to_string(),
    }
}

fn ok_response(body: &[u8]) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: body.to_vec(),
    }
}

struct TraceCollector(Mutex<Vec<&'static str>>);

impl TraceCollector {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }
    fn record(&self, name: &'static str) {
        self.0.lock().unwrap().push(name);
    }
    fn snapshot(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
}

fn build_chain(
    secret_store: Arc<SecretStore>,
    leak_detector: Arc<dyn advance_shared_types::security_validator::LeakDetector>,
    ssrf_guard: Arc<dyn advance_shared_types::security_validator::SsrfGuard>,
    rate_limiter: Arc<dyn cap_http::rate_limit::RateLimiter>,
    executor: Arc<dyn HttpExecutor>,
    tracer: Arc<TraceCollector>,
) -> DefaultHttpSecurityChain {
    let trace_arc = Arc::clone(&tracer);
    let trace_fn: Arc<dyn Fn(&'static str) + Send + Sync> = Arc::new(move |name| {
        trace_arc.record(name);
    });
    DefaultHttpSecurityChain::new(
        secret_store,
        leak_detector,
        ssrf_guard,
        rate_limiter,
        executor,
    )
    .with_step_tracer(trace_fn)
}

// ─── T06a — happy path 10-step trace ─────────────────────────────────────

#[tokio::test]
async fn t06a_happy_path_10_step_trace() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec =
        MockHttpExecutor::new().with_response("https://api.example.com/", ok_response(b"hello"));
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());

    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));
    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    assert_eq!(resp.status, 200);

    let trace = tracer.snapshot();
    assert_eq!(
        trace,
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
}

// ─── T06b — step 1 short-circuit (allowlist) ─────────────────────────────

#[tokio::test]
async fn t06b_step_1_short_circuit() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://evil.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(err, HttpError::AllowlistBlocked(_)));
    let trace = tracer.snapshot();
    assert_eq!(trace, vec!["allowlist"]);
}

// ─── T06c — step 2 short-circuit (outbound leak) ──────────────────────────

#[tokio::test]
async fn t06c_step_2_short_circuit() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    // Use a known leak pattern from BUILTIN_PATTERNS — `sk-proj-` openai key.
    let req = HttpRequest {
        method: HttpMethod::Post,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: b"raw leak: sk-proj-abcdefghijklmnop1234ABCD".to_vec(),
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(err, HttpError::LeakBlocked(_)));
    let trace = tracer.snapshot();
    assert_eq!(trace, vec!["allowlist", "outbound_leak_scan"]);
}

// ─── T06d — step 5 short-circuit (SSRF) ──────────────────────────────────

#[tokio::test]
async fn t06d_step_5_short_circuit() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("127.0.0.1")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(err, HttpError::SsrfBlocked(CidrClass::Loopback)));
    let trace = tracer.snapshot();
    assert_eq!(
        trace,
        vec![
            "allowlist",
            "outbound_leak_scan",
            "substitute_placeholders",
            "inject_credentials",
            "ssrf_check",
        ]
    );
}

// ─── T06e — step 6 short-circuit (rate limit) ────────────────────────────

#[tokio::test]
async fn t06e_step_6_short_circuit() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysDeny(500));
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(
        err,
        HttpError::RateLimited {
            retry_after_ms: 500
        }
    ));
    let trace = tracer.snapshot();
    assert_eq!(
        trace,
        vec![
            "allowlist",
            "outbound_leak_scan",
            "substitute_placeholders",
            "inject_credentials",
            "ssrf_check",
            "rate_limit",
        ]
    );
}

// ─── T06f — step 8 inbound body block ─────────────────────────────────────

#[tokio::test]
async fn t06f_step_8_inbound_body_block() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    // Response body carries a Block-action leak pattern (sk-proj key).
    let leaky_body = b"benign prefix sk-proj-abcdefghijklmnop1234ABCD trailer";
    let resp = HttpResponse {
        status: 200,
        headers: vec![],
        body: leaky_body.to_vec(),
    };
    let exec = MockHttpExecutor::new().with_response("https://api.example.com/", resp);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(err, HttpError::InboundLeakBlocked(_)));
    let trace = tracer.snapshot();
    assert_eq!(
        trace,
        vec![
            "allowlist",
            "outbound_leak_scan",
            "substitute_placeholders",
            "inject_credentials",
            "ssrf_check",
            "rate_limit",
            "execute",
            "inbound_leak_scan",
        ]
    );
}

// ─── T06g — step 9 redact_error_message — 2xx no-op ───────────────────────

#[tokio::test]
async fn t06g_step_9_2xx_no_op() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let resp = ok_response(b"hello");
    let exec = MockHttpExecutor::new().with_response("https://api.example.com/", resp);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello");
    // Tracer captures all 10 steps INCLUDING redact_error_message even on 2xx.
    let trace = tracer.snapshot();
    assert!(trace.contains(&"redact_error_message"), "trace={:?}", trace);
    assert!(trace.contains(&"return"), "trace={:?}", trace);
}

// ─── T06h — step 9 5xx redact (response headers) ─────────────────────────

#[tokio::test]
async fn t06h_step_9_5xx_redact_headers() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    // 500 response with a Redact-action leak pattern in header value.
    // basic_auth_header is a Redact pattern matching "Basic <base64>".
    let resp = HttpResponse {
        status: 500,
        headers: vec![(
            "X-Debug".to_string(),
            "Authorization: Basic dXNlcjpwYXNz".to_string(),
        )],
        body: b"benign error body".to_vec(),
    };
    let exec = MockHttpExecutor::new().with_response("https://api.example.com/", resp);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    assert_eq!(resp.status, 500);
    // Redacted form substituted into response headers.
    let header = resp
        .headers
        .iter()
        .find(|(n, _)| n == "X-Debug")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert!(
        header.contains("[REDACTED]"),
        "header value should be redacted: {}",
        header
    );
    let trace = tracer.snapshot();
    assert!(trace.contains(&"redact_error_message"));
    assert!(trace.contains(&"return"));
}

// ─── T06i — step 9 4xx Block (response headers) ──────────────────────────

#[tokio::test]
async fn t06i_step_9_4xx_block_headers() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    // 401 response with a Block-action pattern in header value.
    let resp = HttpResponse {
        status: 401,
        headers: vec![(
            "X-Debug-Token".to_string(),
            "sk-proj-abcdefghijklmnop1234ABCD".to_string(),
        )],
        body: b"Unauthorized".to_vec(),
    };
    let exec = MockHttpExecutor::new().with_response("https://api.example.com/", resp);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(err, HttpError::InboundLeakBlocked(_)));
    let trace = tracer.snapshot();
    let last = trace.last().unwrap();
    assert!(
        *last == "redact_error_message" || *last == "inbound_leak_scan",
        "trace ends at step 9 area, got {:?}",
        trace
    );
}

// ─── Adversarial R1 regression — step 9 scans 2xx response headers ──────

#[tokio::test]
async fn adv_step_9_2xx_response_headers_scanned() {
    // Adversarial R1 fix regression lock: step 9 now scans response headers
    // on ALL status codes, not just 4xx/5xx. A 200 OK with a credential
    // pattern in a custom header should be REDACTED (or BLOCKED). Pre-fix,
    // the 4xx/5xx gate let 2xx responses leak credentials in headers.
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let resp = HttpResponse {
        status: 200,
        headers: vec![
            (
                "Authorization".to_string(),
                "Basic dXNlcjpwYXNz".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: b"{\"ok\":true}".to_vec(),
    };
    let exec = MockHttpExecutor::new().with_response("https://api.example.com/", resp);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    let auth = resp
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("Authorization"))
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert_eq!(
        auth, "[REDACTED]",
        "Authorization in 2xx response must be redacted (R5 adversarial fix)"
    );
}

// ─── R3-C1 regression — step 9 redacts name-anchored Authorization: Basic ──

#[tokio::test]
async fn r3_c1_step_9_redacts_authorization_basic_header() {
    // R3 audit fix: outer scan_headers detects `Authorization: Basic ...`
    // (name-anchored auth_header_basic pattern). Pre-fix, the inner per-value
    // rescan saw only the value (`Basic dXNlcjpwYXNz`) without the `Authorization:`
    // prefix, so the regex didn't match and the redaction silently failed.
    // Post-fix, per-header rescan rebuilds `name: value` so the same pattern
    // matches and the value is replaced with [REDACTED].
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let resp = HttpResponse {
        status: 500,
        headers: vec![
            (
                "Authorization".to_string(),
                "Basic dXNlcjpwYXNz".to_string(),
            ),
            ("Content-Type".to_string(), "text/plain".to_string()),
        ],
        body: b"benign".to_vec(),
    };
    let exec = MockHttpExecutor::new().with_response("https://api.example.com/", resp);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    let auth = resp
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("Authorization"))
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert_eq!(
        auth, "[REDACTED]",
        "Authorization value must be redacted at step 9, got {:?}",
        auth
    );
    // Non-sensitive Content-Type passes through untouched.
    let ct = resp
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("Content-Type"))
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert_eq!(ct, "text/plain");
}

// ─── AC-20 criterion examples — Set-Cookie (200), WWW-Authenticate (5xx),
//     clean-response-unchanged. These witness the EXACT §1.5 AC-20 examples
//     ("200-OK Set-Cookie/auth tokens, 5xx WWW-Authenticate values ... a clean
//     response is returned unchanged"), beyond the Authorization-header cases. ──

/// Shared helper: run a single GET through the real chain against a canned
/// response, returning the post-step-9 response headers.
async fn run_with_response(resp: HttpResponse) -> Vec<(String, String)> {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = MockHttpExecutor::new().with_response("https://api.example.com/", resp);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, tracer);
    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    chain.execute("agent-1", req, &cap).await.unwrap().headers
}

fn header_val<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("header {name} missing"))
}

/// AC-20 — a 200-OK `Set-Cookie` carrying an auth token (Bearer JWT) is scrubbed
/// (step 9 scans headers on 2xx, not just error codes).
#[tokio::test]
async fn ac20_200_set_cookie_auth_token_redacted() {
    let resp = HttpResponse {
        status: 200,
        headers: vec![
            (
                "Set-Cookie".to_string(),
                "sess=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: b"{\"ok\":true}".to_vec(),
    };
    let headers = run_with_response(resp).await;
    assert_eq!(
        header_val(&headers, "Set-Cookie"),
        "[REDACTED]",
        "200-OK Set-Cookie auth token must be scrubbed at step 9"
    );
    assert_eq!(header_val(&headers, "Content-Type"), "application/json");
}

/// AC-20 — a 5xx `WWW-Authenticate` value carrying a token is scrubbed.
#[tokio::test]
async fn ac20_5xx_www_authenticate_redacted() {
    let resp = HttpResponse {
        status: 503,
        headers: vec![(
            "WWW-Authenticate".to_string(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJlcnIiOiJ4In0".to_string(),
        )],
        body: b"unavailable".to_vec(),
    };
    let headers = run_with_response(resp).await;
    assert_eq!(
        header_val(&headers, "WWW-Authenticate"),
        "[REDACTED]",
        "5xx WWW-Authenticate token must be scrubbed at step 9"
    );
}

/// AC-20 — a clean response (no credential patterns in headers) is returned with
/// its headers UNCHANGED (no false redaction).
#[tokio::test]
async fn ac20_clean_response_headers_unchanged() {
    let resp = HttpResponse {
        status: 200,
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Request-Id".to_string(), "req-abc-12345".to_string()),
        ],
        body: b"{\"ok\":true}".to_vec(),
    };
    let headers = run_with_response(resp).await;
    assert_eq!(header_val(&headers, "Content-Type"), "application/json");
    assert_eq!(
        header_val(&headers, "X-Request-Id"),
        "req-abc-12345",
        "clean response headers must be returned unchanged (no false redaction)"
    );
}

// ─── T12a — redirect to allowlisted public IP ────────────────────────────

#[tokio::test]
async fn t12a_redirect_to_allowlisted_public_ip() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new()
        .with("api.example.com", vec![ip("8.8.8.8")])
        .with("api2.example.com", vec![ip("9.9.9.9")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = MockHttpExecutor::new()
        .with_redirect(
            "https://api.example.com/",
            "https://api2.example.com/v1/x",
            vec![],
        )
        .with_response("https://api2.example.com/", ok_response(b"final"));
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com", "api2.example.com"]);
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    assert_eq!(resp.body, b"final");
}

// ─── T12b — redirect to non-allowlisted host → AllowlistBlocked ──────────

#[tokio::test]
async fn t12b_redirect_to_non_allowlisted_host() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new()
        .with("api.example.com", vec![ip("8.8.8.8")])
        .with("evil.com", vec![ip("9.9.9.9")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = MockHttpExecutor::new().with_redirect(
        "https://api.example.com/",
        "https://evil.com/x",
        vec![],
    );
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(
        err,
        HttpError::RedirectRejected {
            reason: RedirectRejectReason::AllowlistBlocked,
            ..
        }
    ));
}

// ─── T12c — redirect to private IP (DNS rebinding) → SsrfBlocked ────────

#[tokio::test]
async fn t12c_redirect_to_private_ip() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new()
        .with("api.example.com", vec![ip("8.8.8.8")])
        .with("rebind.example.com", vec![ip("127.0.0.1")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = MockHttpExecutor::new().with_redirect(
        "https://api.example.com/",
        "https://rebind.example.com/x",
        vec![],
    );
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com", "rebind.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(
        err,
        HttpError::RedirectRejected {
            reason: RedirectRejectReason::SsrfBlocked,
            ..
        }
    ));
}

// ─── T12d — redirect URL with leak pattern → LeakBlocked ─────────────────

#[tokio::test]
async fn t12d_redirect_url_with_leak_pattern() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    // Redirect target URL contains a known leak pattern.
    let exec = MockHttpExecutor::new().with_redirect(
        "https://api.example.com/",
        "https://api.example.com/?token=sk-proj-abcdefghijklmnop1234ABCD",
        vec![],
    );
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(
        err,
        HttpError::RedirectRejected {
            reason: RedirectRejectReason::LeakBlocked,
            ..
        }
    ));
}

// ─── T12e — redirect headers with leak pattern → HeaderLeakBlocked ───────

#[tokio::test]
async fn t12e_redirect_headers_with_leak_pattern() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = MockHttpExecutor::new().with_redirect(
        "https://api.example.com/",
        "https://api.example.com/v2/",
        vec![(
            "X-Custom".to_string(),
            "sk-proj-abcdefghijklmnop1234ABCD".to_string(),
        )],
    );
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(
        err,
        HttpError::RedirectRejected {
            reason: RedirectRejectReason::HeaderLeakBlocked,
            ..
        }
    ));
}

// ─── T12f — redirect does NOT re-inject credentials ──────────────────────

#[tokio::test]
async fn t12f_redirect_no_credential_reinjection() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new()
        .with("api.example.com", vec![ip("8.8.8.8")])
        .with("api2.example.com", vec![ip("9.9.9.9")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = MockHttpExecutor::new()
        .with_redirect(
            "https://api.example.com/",
            "https://api2.example.com/x",
            vec![],
        )
        .with_response("https://api2.example.com/", ok_response(b"final"));
    // Hold concrete Arc<MockHttpExecutor> for post-run inspection; clone for
    // chain consumption (Arc<MockHttpExecutor> coerces to Arc<dyn HttpExecutor>
    // because MockHttpExecutor: HttpExecutor).
    let exec_concrete: Arc<MockHttpExecutor> = Arc::new(exec);
    let exec_arc: Arc<dyn HttpExecutor> = exec_concrete.clone();
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(
        store(&[("api_key", "secret-bearer-value")]),
        leak,
        ssrf,
        rl,
        exec_arc,
        Arc::clone(&tracer),
    );

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let mut cap = cap_with_allowlist(&["api.example.com", "api2.example.com"]);
    cap.credentials.push(CredentialBinding {
        position: CredentialPosition::BearerToken,
        secret_name: "api_key".to_string(),
    });
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    assert_eq!(resp.body, b"final");

    // Inspect MockHttpExecutor's recorded_requests — the SECOND request (the
    // redirect target) MUST NOT carry the Bearer token.
    let recorded = exec_concrete.recorded_requests.lock().unwrap();
    assert_eq!(
        recorded.len(),
        2,
        "should record 2 requests (initial + redirect)"
    );
    let (_, redirect_headers) = &recorded[1];
    let auth = redirect_headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("authorization"));
    assert!(
        auth.is_none(),
        "redirect target MUST NOT carry Authorization header: {:?}",
        redirect_headers
    );
}

// ─── T12g — first-seen redirect host (cache cold) → resolves async ──────

#[tokio::test]
async fn t12g_first_seen_redirect_cold_cache() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    // Both initial host AND redirect target host are pre-mapped.
    let resolver = MockResolver::new()
        .with("api.example.com", vec![ip("8.8.8.8")])
        .with("api2.example.com", vec![ip("9.9.9.9")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = MockHttpExecutor::new()
        .with_redirect(
            "https://api.example.com/",
            "https://api2.example.com/x",
            vec![],
        )
        .with_response("https://api2.example.com/", ok_response(b"final"));
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com", "api2.example.com"]);
    // First request to api.example.com → cache populated for api.example.com.
    // Redirect to api2.example.com → CACHE COLD for that host. Should resolve
    // async (NOT auto-reject).
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    assert_eq!(resp.body, b"final");
}

// ─── T14a — outbound leak scan precedes injection (placeholder safe) ────

#[tokio::test]
async fn t14a_outbound_scan_before_injection() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec =
        MockHttpExecutor::new().with_response("https://api.example.com/", ok_response(b"ok"));
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());

    // SecretStore has the Slack-style xoxb token. Body has the placeholder.
    // Step 2 (outbound scan) sees the LITERAL `{my_token}` placeholder, NOT
    // the resolved xoxb value → does NOT trigger leak detector. After step 3
    // substitutes, the body has the actual Slack token but step 2's scan
    // already passed.
    let chain = build_chain(
        store(&[("my_token", "xoxb-slack-bot-token-1234")]),
        leak,
        ssrf,
        rl,
        exec_arc,
        Arc::clone(&tracer),
    );

    let req = HttpRequest {
        method: HttpMethod::Post,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: b"slack: {my_token}".to_vec(),
    };
    // Capability binding for `my_token` is REQUIRED for step 3 placeholder
    // substitution per the R5 capability-scope rule. Use CustomHeader as a
    // dummy injection target — step 4 will set X-Test-Token but T14a is
    // about step 2 ordering, not step 4 behavior.
    let mut cap = cap_with_allowlist(&["api.example.com"]);
    cap.credentials.push(CredentialBinding {
        position: CredentialPosition::CustomHeader {
            key: "X-Test-Token".to_string(),
        },
        secret_name: "my_token".to_string(),
    });
    let resp = chain.execute("agent-1", req, &cap).await.unwrap();
    assert_eq!(resp.status, 200);
    let trace = tracer.snapshot();
    // Confirm step ordering: step 2 (outbound_leak_scan) preceded step 3
    // (substitute_placeholders).
    let scan_idx = trace
        .iter()
        .position(|s| *s == "outbound_leak_scan")
        .unwrap();
    let sub_idx = trace
        .iter()
        .position(|s| *s == "substitute_placeholders")
        .unwrap();
    assert!(scan_idx < sub_idx);
}

// ─── T14b — pre-resolved leak in raw input still blocked ─────────────────

#[tokio::test]
async fn t14b_pre_resolved_leak_in_raw_input_blocked() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = MockHttpExecutor::new();
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Post,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        // Body is `Vec<u8>`. Step 2 must scan it via from_utf8_lossy and see
        // the raw text, NOT a Debug `[u8; N]` numeric form.
        body: b"raw token sk-proj-abcdefghijklmnop1234ABCD".to_vec(),
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(err, HttpError::LeakBlocked(_)));
}

// ─── T14c — step 2 scans URL + headers + body separately ─────────────────

#[tokio::test]
async fn t14c_step_2_separate_url_headers_body_scans() {
    // 3 sub-asserts: leak in URL, in headers, in body — all should LeakBlock.
    for (label, req) in [
        (
            "url",
            HttpRequest {
                method: HttpMethod::Get,
                url: "https://api.example.com/?key=sk-proj-abcdefghijklmnop1234ABCD".to_string(),
                headers: vec![],
                body: vec![],
            },
        ),
        (
            "headers",
            HttpRequest {
                method: HttpMethod::Get,
                url: "https://api.example.com/x".to_string(),
                headers: vec![(
                    "X-Custom".to_string(),
                    "sk-proj-abcdefghijklmnop1234ABCD".to_string(),
                )],
                body: vec![],
            },
        ),
        (
            "body",
            HttpRequest {
                method: HttpMethod::Post,
                url: "https://api.example.com/x".to_string(),
                headers: vec![],
                body: b"sk-proj-abcdefghijklmnop1234ABCD".to_vec(),
            },
        ),
    ] {
        let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
            Arc::new(DefaultLeakDetector::new());
        let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
        let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
            Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
        let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
        let exec_arc: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
        let tracer = Arc::new(TraceCollector::new());
        let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, tracer);
        let cap = cap_with_allowlist(&["api.example.com"]);
        let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
        assert!(
            matches!(err, HttpError::LeakBlocked(_)),
            "{} surface should LeakBlock",
            label
        );
    }
}

// ─── R3-W2 regression — pre-step-1 InvalidUrl emission ──────────────────

#[tokio::test]
async fn r3_w2_invalid_url_pre_step_1() {
    // R3 audit fix: malformed URL caught BEFORE step 1 → HttpError::InvalidUrl
    // (NOT AllowlistBlocked). Tracer captures NO entries because the guard
    // fires before step 1's tracer.
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new();
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        // Missing scheme — url::Url::parse rejects "no base URL" for relative
        // strings.
        url: "no-scheme-url-just-text".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    match err {
        HttpError::InvalidUrl(_) => {} // expected
        other => panic!("expected InvalidUrl, got {:?}", other),
    }
    let trace = tracer.snapshot();
    assert!(
        trace.is_empty(),
        "tracer should be empty pre-step-1, got {:?}",
        trace
    );
}

// ─── T14d — step 3 substitute_placeholders missing-secret ───────────────

#[tokio::test]
async fn t14d_step_3_substitute_missing_secret() {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(store(&[]), leak, ssrf, rl, exec_arc, Arc::clone(&tracer));

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/{missing_token}/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(matches!(
        err,
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(_))
    ));
    let trace = tracer.snapshot();
    // Tracer captures steps 1-3 only.
    assert_eq!(
        trace,
        vec!["allowlist", "outbound_leak_scan", "substitute_placeholders"]
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// T26–T28 + S3 supporting tests — CONTRACT-233 HttpStreamingChain
// (ADR 2026-07-22 slice S3; MODULE-012 §2.9 streaming scan contract, AC-21).
// ─────────────────────────────────────────────────────────────────────────────

use advance_shared_types::security_validator::{
    HttpBodyStream, HttpResponseHead, HttpStreamingChain,
};
use cap_http::executor::HttpStreamExecutor;
use cap_http::MAX_HOLD_BYTES;

/// Build a chain over a shared MockHttpExecutor wired for BOTH the buffered
/// (`HttpExecutor`) and streaming (`HttpStreamExecutor`) seams.
fn build_streaming_chain(
    exec: Arc<MockHttpExecutor>,
    tracer: Arc<TraceCollector>,
) -> DefaultHttpSecurityChain {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    build_chain(
        store(&[]),
        leak,
        ssrf,
        rl,
        exec.clone() as Arc<dyn HttpExecutor>,
        tracer,
    )
    .with_stream_executor(exec as Arc<dyn HttpStreamExecutor>)
}

fn stream_head() -> HttpResponseHead {
    HttpResponseHead {
        status: 200,
        headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
    }
}

fn get_req() -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/stream".to_string(),
        headers: vec![],
        body: vec![],
    }
}

/// A well-formed anthropic-style key (10-byte prefix + 96 suffix chars ≥ the
/// regex's {90,} floor). Test fixture only — matches the LEAK_PATTERNS shape.
fn anthropic_key() -> String {
    format!("sk-ant-api{}", "a".repeat(96))
}

async fn drain(body: &mut Box<dyn HttpBodyStream>) -> (Vec<u8>, Option<HttpError>) {
    let mut emitted = Vec::new();
    let mut err = None;
    while let Some(r) = body.next_chunk().await {
        match r {
            Ok(c) => emitted.extend_from_slice(&c),
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    (emitted, err)
}

// ─── T26 — boundary-split secret across chunks is caught (rejoin-then-lossy) ──

#[tokio::test]
async fn t26_boundary_split_secret_two_chunks_blocked() {
    let key = anthropic_key();
    // Split INSIDE the key: neither chunk alone satisfies the {90,} floor.
    let (a, b) = key.as_bytes().split_at(50);
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![[b"data: ", a].concat(), b.to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    // Audit round 1: Block-pattern prefixes are HELD too — not one byte of the
    // forming key may emit before the terminal.
    assert_eq!(
        emitted,
        b"data: ",
        "no partial Block-pattern credential bytes may emit, got {:?}",
        String::from_utf8_lossy(&emitted)
    );
    match err.expect("boundary-split key must terminate the stream") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "anthropic_api_key"),
                "expected the anthropic_api_key finding, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
    // Terminal is absorbing.
    assert!(body.next_chunk().await.is_none());
}

#[tokio::test]
async fn t26_boundary_split_secret_three_chunks_blocked() {
    let key = anthropic_key();
    let bytes = key.as_bytes();
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![
            [b"data: ", &bytes[..30]].concat(),
            bytes[30..60].to_vec(),
            bytes[60..].to_vec(),
        ],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert_eq!(
        emitted, b"data: ",
        "no partial Block-pattern credential bytes may emit across a 3-way split"
    );
    assert!(
        matches!(err, Some(HttpError::InboundLeakBlocked(_))),
        "three-way split must still be caught, got {err:?}"
    );
}

/// Audit round 1 (dual-model Critical): a Block pattern with an UNBOUNDED
/// interior before its required suffix (`pem_private_key`'s `[A-Z ]*`) defeats
/// any finite overlap window — chunk 1 can push the `-----BEGIN ` start out of
/// the window before `PRIVATE KEY-----` arrives. The Block/Redact viability
/// hold is what catches it: the open interior stays a viable in-progress
/// match, is withheld, and the completed match Block-terminates.
#[tokio::test]
async fn t26_pem_unbounded_interior_split_blocked_and_held() {
    let mut chunk1 = b"log: -----BEGIN ".to_vec();
    chunk1.extend_from_slice(&vec![b' '; 150]); // interior wider than W=99
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![chunk1, b"PRIVATE KEY-----".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert_eq!(
        emitted,
        b"log: ",
        "the open pem interior must be held, got {:?}",
        String::from_utf8_lossy(&emitted)
    );
    match err.expect("unbounded-interior pem split must terminate the stream") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings.iter().any(|f| f.pattern_name == "pem_private_key"),
                "expected the pem_private_key finding, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
}

/// Audit round 1 (dual-model Critical): invisible-codepoint inflation must not
/// defeat the hold — the viability feed is canonical (invisible-stripped +
/// per-char NFKC), so `B` + ZWSP-flood + `earer eyJ` is still a viable
/// in-progress bearer prefix and is withheld from the first letter.
#[tokio::test]
async fn t27_invisible_inflated_prefix_still_held() {
    let mut chunk1 = b"x ".to_vec();
    chunk1.extend_from_slice("B".as_bytes());
    for _ in 0..40 {
        chunk1.extend_from_slice("\u{200B}".as_bytes());
    }
    chunk1.extend_from_slice(b"earer ey");
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![chunk1, b"Jtok.en.sig".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert_eq!(
        emitted,
        b"x ",
        "the invisible-inflated forming credential must be held, got {:?}",
        String::from_utf8_lossy(&emitted)
    );
    assert!(
        matches!(err, Some(HttpError::InboundLeakBlocked(_))),
        "completed match must Block, got {err:?}"
    );
}

/// Audit round 1: an upstream drip-feeding tiny chunks while a hold stays
/// viable does re-scan work quadratic in the hold length — the cumulative
/// re-scan budget fails CLOSED enum-coded long before the CPU burns.
#[tokio::test]
async fn t27_tiny_chunk_drip_feed_scan_budget_fails_closed() {
    let mut chunks = vec![b"x Bearer".to_vec()];
    // 12k one-byte whitespace chunks: hold grows by 1 per round, re-scan debt
    // grows by the hold length per round (~72M total) and must trip the
    // 32 MiB budget well before the 256 KiB hold cap is anywhere close.
    for _ in 0..12_000 {
        chunks.push(b" ".to_vec());
    }
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        chunks,
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert_eq!(emitted, b"x ", "nothing of the held region may emit");
    match err.expect("drip-feed must fail closed on the scan budget") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "stream_scan_budget"),
                "expected the synthetic stream_scan_budget Block, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
}

/// The multi-byte-split discriminator: a 3-byte ZWSP (U+200B, E2 80 8B) sits
/// INSIDE the key and is split across the chunk boundary. Rejoin-then-lossy
/// reconstitutes the ZWSP, `canonical_scan_text` strips it, and the key
/// matches. A decode-then-concatenate implementation lossy-decodes each side
/// separately, shattering the ZWSP into U+FFFD replacement chars that the
/// canonicalizer does NOT strip — the key would evade the match.
#[tokio::test]
async fn t26_zwsp_split_inside_key_still_blocked() {
    let key = anthropic_key();
    let bytes = key.as_bytes();
    let zwsp = "\u{200B}".as_bytes(); // [0xE2, 0x80, 0x8B]
                                      // chunk1 = "data: " + key[..8] + ZWSP[0..2]; chunk2 = ZWSP[2..] + key[8..]
    let chunk1 = [b"data: " as &[u8], &bytes[..8], &zwsp[..2]].concat();
    let chunk2 = [&zwsp[2..], &bytes[8..]].concat();
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![chunk1, chunk2],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (_emitted, err) = drain(&mut body).await;
    match err.expect("ZWSP-split key must still be caught (rejoin-then-lossy)") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "anthropic_api_key"),
                "expected anthropic_api_key despite the split invisible, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
}

// ─── T27 — greedy hold never emits a partial credential ──────────────────────

#[tokio::test]
async fn t27_greedy_hold_no_partial_credential_emitted() {
    // chunk1 ends mid-bearer ("Bearer ey" — a viable in-progress match below
    // the min-match floor); chunk2 completes the token → Redact fires on the
    // rejoined text → wire-layer degrade to Block.
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![b"hello Bearer ey".to_vec(), b"Jabc.def.ghi".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    // The viable in-progress suffix was withheld: nothing of the credential —
    // not even the "Bearer" literal — reached the consumer.
    assert_eq!(
        emitted,
        b"hello ",
        "only the pre-hold prefix may emit; got {:?}",
        String::from_utf8_lossy(&emitted)
    );
    assert!(
        matches!(err, Some(HttpError::InboundLeakBlocked(_))),
        "completed greedy match must Block (wire-layer degrade), got {err:?}"
    );
}

#[tokio::test]
async fn t27_eof_resolves_hold_and_flushes() {
    // The in-progress prefix never completes; EOF resolves the hold and the
    // withheld bytes (which are NOT a credential) flush as the final chunk.
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![b"hello Bearer ey".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert!(err.is_none(), "clean EOF, got {err:?}");
    assert_eq!(
        emitted, b"hello Bearer ey",
        "EOF must flush the resolved hold"
    );
}

#[tokio::test]
async fn t27_hold_cap_crossing_fails_closed() {
    // "Bearer" followed by an endless whitespace flood stays a viable
    // in-progress match (`\s+` is unbounded) without ever completing — the
    // hold grows past MAX_HOLD_BYTES and MUST fail CLOSED enum-coded.
    let mut chunks = vec![b"x Bearer".to_vec()];
    let flood = vec![b' '; 64 * 1024];
    for _ in 0..5 {
        chunks.push(flood.clone());
    }
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        chunks,
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert_eq!(emitted, b"x ", "nothing of the held region may emit");
    match err.expect("hold-cap crossing must fail closed") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "stream_hold_overflow"),
                "expected the synthetic stream_hold_overflow Block, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
    let _ = MAX_HOLD_BYTES; // pinned public constant (256 KiB)
}

/// Audit round 3: an EMIT-heavy drip-feed of tiny invisible-dense chunks pins
/// the retained overlap near its 8 KiB cap (canonical projection stays below
/// the window, so the canonical trim never fires) while nothing is held — the
/// round-1 held-only re-scan budget did NOT cover this, so per-round overlap
/// re-strip work was quadratic in the round count. The debt/credit ledger
/// (round 5) charges the re-processed overlap against credit earned by the
/// 3-byte frames (≈8193 debt vs 384 credit per round) and MUST fail CLOSED
/// enum-coded.
#[tokio::test]
async fn t27_emit_heavy_invisible_drip_feed_scan_budget_fails_closed() {
    // Each chunk = one ZWSP (3 bytes). ZWSP is stripped by the canonical feed,
    // so it scans Clean and emits (nothing held) but accumulates in overlap.
    // ~8 KiB overlap × enough rounds crosses the 32 MiB re-scan budget.
    let zwsp = "\u{200B}".as_bytes().to_vec();
    let chunks = vec![zwsp; 12_000];
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        chunks,
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (_emitted, err) = drain(&mut body).await;
    match err.expect("emit-heavy invisible drip-feed must fail closed on the scan budget") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "stream_scan_budget"),
                "expected the synthetic stream_scan_budget Block, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
}

/// AUDIT ROUND 5 (Critical, end-to-end): a credential whose completed match the
/// DETECTOR misses (whole-string NFKC composes `a` + U+0301 into `á`, so
/// `bearer_token`'s `[A-Za-z0-9_-]+` never matches) must still never reach the
/// consumer — the per-chunk viability hold now reports `Matched` and holds,
/// and EOF fail-closes instead of flushing. Before the fix the entire chunk,
/// JWT and all, was emitted.
#[tokio::test]
async fn t27_detector_blind_completed_match_never_emitted() {
    let payload = "data: Bearer eyJa\u{0301}hbGciOiJIUzI1NiJ9.body.signature";
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![payload.as_bytes().to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    let seen = String::from_utf8_lossy(&emitted);
    assert!(
        !seen.contains("hbGciOiJIUzI1NiJ9"),
        "credential payload must never be emitted, got {seen:?}"
    );
    assert!(
        !seen.contains("Bearer"),
        "the held region starts at the `Bearer` literal, got {seen:?}"
    );
    match err.expect("a detector-blind completed match must fail CLOSED at EOF") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "stream_hold_unresolved_match"),
                "expected the synthetic stream_hold_unresolved_match Block, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
}

/// AUDIT ROUND 5 — zero-progress (empty-frame) flood. Empty HTTP/2 DATA frames
/// cost 0 wire bytes, so `max_response_bytes` never trips; only the ledger's
/// fixed allowance bounds them (they earn 0 credit). Must fail CLOSED.
#[tokio::test]
async fn t27_empty_frame_flood_fails_closed() {
    // A benign chunk first, then a flood of zero-length frames. Bounded by
    // MAX_CONSECUTIVE_EMPTY_CHUNKS (audit round 6) rather than by the byte
    // ledger — see the leading-flood sibling below for why the ledger alone
    // was not enough.
    let mut chunks = vec![vec![b'x'; 200]];
    chunks.extend(std::iter::repeat(Vec::new()).take(4_000));
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        chunks,
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (_emitted, err) = drain(&mut body).await;
    match err.expect("an empty-frame flood must fail closed on the ledger") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "stream_scan_budget"),
                "expected the synthetic stream_scan_budget Block, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
}

/// AUDIT ROUND 6 — the LEADING empty-frame flood: zero-length frames from the
/// very first frame, so `overlap` and `held` are both empty and the byte
/// ledger charges only ~1/round (33.5 M rounds — effectively the 300 s
/// deadline). This is the shape the round-5 witness accidentally avoided by
/// pre-filling the belt; only `MAX_CONSECUTIVE_EMPTY_CHUNKS` bounds it.
#[tokio::test]
async fn t27_leading_empty_frame_flood_fails_closed() {
    let chunks: Vec<Vec<u8>> = std::iter::repeat(Vec::new()).take(4_000).collect();
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        chunks,
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert!(emitted.is_empty(), "nothing to emit from empty frames");
    match err.expect("a leading empty-frame flood must fail closed") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "stream_scan_budget"),
                "expected the synthetic stream_scan_budget Block, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
}

/// A `LeakDetector` that never reports anything. Used to make the HOLD the
/// only guard, so a test can witness the "self-contained hold" property
/// directly instead of accidentally witnessing the detector (audit round 7: the
/// previous version of the test below used a plain-ASCII `AKIA…` payload that
/// `DefaultLeakDetector` blocks outright at the per-chunk scan, so it passed
/// with the round-6 fix fully reverted — fake-green).
struct BlindDetector;

impl advance_shared_types::security_validator::LeakDetector for BlindDetector {
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

fn build_blind_detector_chain(exec: Arc<MockHttpExecutor>) -> DefaultHttpSecurityChain {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(BlindDetector);
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    build_chain(
        store(&[]),
        leak,
        ssrf,
        rl,
        exec.clone() as Arc<dyn HttpExecutor>,
        Arc::new(TraceCollector::new()),
    )
    .with_stream_executor(exec as Arc<dyn HttpStreamExecutor>)
}

#[tokio::test]
async fn s3_weak_detector_head_still_fails_closed() {
    let head = HttpResponseHead {
        status: 200,
        headers: vec![("X-Debug".to_string(), "AKIAIOSFODNN7EXAMPLE".to_string())],
    };
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        head,
        vec![b"never".to_vec()],
    ));
    let chain = build_blind_detector_chain(exec);
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .expect_err("the crate-static head baseline must survive blind injection");
    assert!(matches!(err, HttpError::InboundLeakBlocked(_)));
}

/// AUDIT ROUND 6/7 (Critical, end-to-end) — the hold must block a COMPLETED
/// credential ON ITS OWN, with the detector contributing nothing. This is the
/// direct witness for the "self-contained hold" property: with `BlindDetector`
/// every scan returns Clean, so the ONLY thing standing between the credential
/// and the consumer is the viability hold plus the non-short-circuiting EOF
/// sweep. Revert either and the credential is emitted.
///
/// The payload also exercises the round-6 shape: a merely-viable
/// `anthropic_api_key` prefix at index 0 (it needs `{90,}`) hides a COMPLETE
/// `aws_access_key` at index 10 from the split-point walk's short-circuit.
#[tokio::test]
async fn t27_hold_blocks_completed_match_without_detector_help() {
    let payload = b"sk-ant-apiAKIA0123456789ABCDEF";
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![payload.to_vec()],
    ));
    let chain = build_blind_detector_chain(exec);
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    let seen = String::from_utf8_lossy(&emitted);
    assert!(
        !seen.contains("AKIA"),
        "the completed AWS key must never be emitted even with a blind detector, got {seen:?}"
    );
    match err.expect("the hold alone must fail CLOSED at EOF") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings
                    .iter()
                    .any(|f| f.pattern_name == "stream_hold_unresolved_match"),
                "expected stream_hold_unresolved_match, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
}

/// Control for the witness above: with the SAME blind detector, credential-free
/// content flows through untouched. Without this, "blocks everything" would
/// also pass.
#[tokio::test]
async fn t27_blind_detector_clean_stream_flows() {
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![
            b"hello ".to_vec(),
            b"ordinary ".to_vec(),
            b"content".to_vec(),
        ],
    ));
    let chain = build_blind_detector_chain(exec);
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert!(err.is_none(), "clean content must not be cut, got {err:?}");
    assert_eq!(emitted, b"hello ordinary content");
}

/// AUDIT ROUND 5 — availability counterpart: a LEGITIMATE finely-chunked clean
/// stream (1 byte per frame, the worst realistic shape) must NOT be cut. Under
/// the round-3 flat charge this tripped at ~332 K rounds; the ledger grants
/// 128 credit per wire byte against ~100 debt, so it nets negative forever.
///
/// AUDIT ROUND 6: the frame count MUST exceed the round-3 trip point or the
/// test does not discriminate — at the original 60,000 frames it passed under
/// the flat charge, the excess-only charge AND the ledger, pinning nothing
/// about the credit term. 400,000 frames fails under the flat charge and
/// passes only with credit.
#[tokio::test]
async fn t27_clean_one_byte_frames_are_never_cut() {
    let chunks: Vec<Vec<u8>> = (0..400_000u32)
        .map(|i| vec![b'a' + (i % 26) as u8])
        .collect();
    let expected: Vec<u8> = chunks.iter().flatten().copied().collect();
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        chunks,
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert!(
        err.is_none(),
        "a clean 1-byte-per-frame stream must never fail closed, got {err:?}"
    );
    assert_eq!(
        emitted, expected,
        "concat(emitted) == body on a clean stream"
    );
}

// ─── T28 — wire-layer Redact→Block sanctioned divergence ─────────────────────

#[tokio::test]
async fn t28_redact_degrades_to_block_never_passthrough() {
    // A COMPLETE Redact-pattern match inside one chunk: the buffered path
    // would splice [REDACTED]; the wire layer cannot splice into live frames,
    // so the stream terminates enum-coded and NO partially-redacted frame is
    // ever emitted (never pass-through).
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![b"data: Bearer eyJhbGciOiJIUzI1NiJ9.x.y tail".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert!(
        emitted.is_empty(),
        "no frame (redacted or raw) may emit before the Block, got {:?}",
        String::from_utf8_lossy(&emitted)
    );
    match err.expect("wire-layer Redact must degrade to Block") {
        HttpError::InboundLeakBlocked(findings) => {
            assert!(
                findings.iter().any(|f| f.pattern_name == "bearer_token"),
                "expected the bearer_token finding, got {findings:?}"
            );
        }
        other => panic!("expected InboundLeakBlocked, got {other:?}"),
    }
    assert!(body.next_chunk().await.is_none(), "terminal is absorbing");
}

// ─── S3 supporting: clean-stream reconstruction, begin gating, head scan,
//     fail-closed unwired seam, streaming redirects, buffered totality ────────

#[tokio::test]
async fn s3_clean_stream_concat_equals_body() {
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![
            b"hello ".to_vec(),
            b"streaming ".to_vec(),
            b"world!".to_vec(),
        ],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    assert_eq!(head.status, 200);
    let (emitted, err) = drain(&mut body).await;
    assert!(err.is_none());
    assert_eq!(emitted, b"hello streaming world!");
}

#[tokio::test]
async fn s3_begin_site_gating_allowlist_and_no_executor_call() {
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![b"x".to_vec()],
    ));
    let chain = build_streaming_chain(exec.clone(), Arc::new(TraceCollector::new()));
    // Allowlist does NOT include the target → step-1 reject at begin.
    let cap = cap_with_allowlist(&["other.example.com"]);
    let err = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::AllowlistBlocked(_)));
    assert!(
        exec.recorded_requests.lock().unwrap().is_empty(),
        "executor must not be dialed on a begin-site reject"
    );
}

#[tokio::test]
async fn s3_unwired_stream_executor_fails_closed() {
    // A chain WITHOUT with_stream_executor fails CLOSED as its FIRST
    // operation. No trace entry or injected outbound collaborator may run:
    // the unwired chain has not accepted the streaming-only composition
    // precondition, and the shared HttpExecutor never grants a streaming path.
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);
    let exec = Arc::new(
        MockHttpExecutor::new().with_response("https://api.example.com/", ok_response(b"x")),
    );
    let tracer = Arc::new(TraceCollector::new());
    let chain = build_chain(
        store(&[]),
        leak,
        ssrf,
        rl,
        exec.clone() as Arc<dyn HttpExecutor>,
        tracer.clone(),
    );
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        HttpError::Transport(advance_shared_types::security_validator::TransportErrorKind::Other)
    ));
    assert!(
        tracer.snapshot().is_empty(),
        "unwired execute_streaming must fail before the first outbound step"
    );
    assert!(
        exec.recorded_requests.lock().unwrap().is_empty(),
        "unwired execute_streaming must not invoke either executor seam"
    );
}

#[tokio::test]
async fn s3_head_scan_blocks_at_begin() {
    // Head carries a Block-pattern credential in a header value → begin-site
    // Err, no body stream handed out.
    let head = HttpResponseHead {
        status: 200,
        headers: vec![("X-Debug".to_string(), anthropic_key())],
    };
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        head,
        vec![b"never".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::InboundLeakBlocked(_)));
}

/// AUDIT ROUND 7 (Critical regression pin) — a Redact match SPANNING the
/// synthesized `name: value\n` join, accompanied by an ordinary self-contained
/// Redact DECOY. The round-6 guard asked "did anything get redacted?", which
/// the decoy answers `true`, so the spanning credential rode out in the head.
/// Round 8 removed the salvage attempt entirely — EVERY Redacted head now
/// fails CLOSED — so this fixture is kept as the documented exploit witness
/// for the round-7 bypass rather than as an independent discriminator.
#[tokio::test]
async fn s3_head_scan_spanning_match_with_decoy_fails_closed() {
    let head = HttpResponseHead {
        status: 200,
        headers: vec![
            // The span: `Authorization: Basic` ends header A; `\s+` then eats
            // the synthesized `\n` and `[A-Za-z0-9+/=]+` is satisfied by the
            // `X` that begins header B's NAME — so the match exists only across
            // the join and no single header reproduces it. (B's value is never
            // reached by the match; the round-7 comment claiming otherwise was
            // corrected in round 8.)
            ("X-A".to_string(), "Authorization: Basic".to_string()),
            ("X-B".to_string(), "QUJDREVGRw==".to_string()),
            // The decoy: matches on its own line, so the round-6 existential
            // check was satisfied here.
            (
                "Proxy-Authorization".to_string(),
                "Basic QUJDREVGRw==".to_string(),
            ),
        ],
    };
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        head,
        vec![b"body".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .expect_err("a head whose flagged span survives remediation must fail CLOSED");
    assert!(
        matches!(err, HttpError::InboundLeakBlocked(_)),
        "expected InboundLeakBlocked, got {err:?}"
    );
}

#[tokio::test]
async fn s3_head_scan_redact_degrades_to_block() {
    // AUDIT ROUND 8: a Redact-pattern header no longer yields a redacted head —
    // it fails CLOSED, §2.9 term 5's Redact→Block applied to the head. Rounds 6
    // and 7 tried to salvage such a head by rewriting values and proving the
    // rewrite worked; both proofs were defeatable (see the anchor-deletion
    // witness below), so the proof obligation was removed rather than patched.
    let head = HttpResponseHead {
        status: 200,
        headers: vec![
            ("Content-Type".to_string(), "text/event-stream".to_string()),
            (
                "Authorization".to_string(),
                "Basic QWxhZGRpbjpvcGVu".to_string(),
            ),
        ],
    };
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        head,
        vec![b"ok".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .expect_err("a Redacted head must fail CLOSED on the streaming path");
    assert!(
        matches!(err, HttpError::InboundLeakBlocked(_)),
        "expected InboundLeakBlocked, got {err:?}"
    );
}

/// AUDIT ROUND 9 — the head-PASSTHROUGH property. Round 8 deleted the only
/// test that ever read a returned head's headers while newly asserting "the
/// head is either returned AS RECEIVED or the call fails CLOSED — the scan
/// never rewrites it". Nothing pinned that: a regression silently rewriting or
/// dropping head headers on the Ok path would have passed the whole suite.
#[tokio::test]
async fn s3_head_returned_verbatim_on_clean_input() {
    let head = HttpResponseHead {
        status: 207,
        headers: vec![
            ("Content-Type".to_string(), "text/event-stream".to_string()),
            ("X-Trace".to_string(), "abc-123".to_string()),
            ("Cache-Control".to_string(), "no-store".to_string()),
        ],
    };
    let expected = head.headers.clone();
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        head,
        vec![b"ok".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .expect("a clean head must not be blocked");
    assert_eq!(head.status, 207, "status passes through unchanged");
    assert_eq!(
        head.headers, expected,
        "a clean head must be returned VERBATIM — no rewriting, no dropping"
    );
    let (emitted, err) = drain(&mut body).await;
    assert!(err.is_none());
    assert_eq!(emitted, b"ok");
}

/// AUDIT ROUND 9 — the EOF sweep budget is adequate for a LARGE candidate-dense
/// hold. The sweep is non-short-circuiting, so its allowance
/// (`16 × n × matchers + 1 MiB`) was tuned by argument with no witness; if it
/// were too small a legitimate stream would fail closed with a synthetic
/// budget terminal. Here `-----BEGIN ` + a long `[A-Z ]*` run keeps `pem_private_key`
/// viable so the whole region is HELD to EOF, then must flush cleanly.
#[tokio::test]
async fn t27_large_candidate_dense_hold_sweeps_within_budget() {
    let mut payload = b"-----BEGIN ".to_vec();
    payload.extend(std::iter::repeat(b'A').take(160 * 1024));
    let expected = payload.clone();
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![payload],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let (_head, mut body) = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert!(
        err.is_none(),
        "a 160-KiB viable-but-unmatched hold must sweep within budget, got {err:?}"
    );
    assert_eq!(emitted, expected, "EOF flushes the whole unmatched hold");
}

/// AUDIT ROUND 8 (Critical regression pin) — the ANCHOR-DELETION exploit that
/// defeated round 7's "re-scan the mutated head" verification. `Bearer` (the
/// match's anchor) sits in H1's VALUE while the JWT payload sits in H2's NAME.
/// Redacting H1 deletes the anchor, so the re-scan reported Clean and the head
/// shipped with the credential intact — and the audit event said "remediated".
/// Under Redact→Block this must fail CLOSED, and nothing may be returned.
#[tokio::test]
async fn s3_head_scan_anchor_deletion_exploit_fails_closed() {
    let head = HttpResponseHead {
        status: 200,
        headers: vec![
            // Anchor lives here; redacting this value used to erase the match.
            (
                "X-A".to_string(),
                "Authorization: Basic QUJD Bearer".to_string(),
            ),
            // Payload lives in the NAME, which value-only remediation cannot
            // rewrite. `bearer_token` matches across the synthesized join.
            ("eyJhbGciOiJIUzI1NiJ9-QUJDRUZH".to_string(), "1".to_string()),
        ],
    };
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        head,
        vec![b"body".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .expect_err("anchor-deletion must not be salvageable — fail CLOSED");
    assert!(
        matches!(err, HttpError::InboundLeakBlocked(_)),
        "expected InboundLeakBlocked, got {err:?}"
    );
}

#[tokio::test]
async fn s3_streaming_redirect_revalidated_and_rejectable() {
    // Redirect → Stream on the streaming path: the per-hop redirect_check
    // re-runs allowlist; a target OUTSIDE the cap allowlist is rejected.
    let exec = Arc::new(
        MockHttpExecutor::new()
            .with_redirect(
                "https://api.example.com/",
                "https://evil.example.net/steal",
                vec![],
            )
            .with_stream("https://evil.example.net/", stream_head(), vec![]),
    );
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let err = chain
        .execute_streaming("agent-1", get_req(), &cap)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        HttpError::RedirectRejected {
            reason: RedirectRejectReason::AllowlistBlocked,
            ..
        }
    ));
}

#[tokio::test]
async fn s3_streaming_redirect_followed_when_allowed() {
    let exec = Arc::new(
        MockHttpExecutor::new()
            .with_redirect(
                "https://api.example.com/start",
                "https://api.example.com/moved",
                vec![],
            )
            .with_stream(
                "https://api.example.com/moved",
                stream_head(),
                vec![b"moved-body".to_vec()],
            ),
    );
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/start".to_string(),
        headers: vec![],
        body: vec![],
    };
    let (_head, mut body) = chain.execute_streaming("agent-1", req, &cap).await.unwrap();
    let (emitted, err) = drain(&mut body).await;
    assert!(err.is_none());
    assert_eq!(emitted, b"moved-body");
}

#[tokio::test]
async fn s3_buffered_execute_on_stream_fixture_is_total() {
    // The buffered path over a Stream fixture = head + concatenated chunks
    // (fixture enum totality).
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/",
        stream_head(),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
    ));
    let chain = build_streaming_chain(exec, Arc::new(TraceCollector::new()));
    let cap = cap_with_allowlist(&["api.example.com"]);
    let resp = chain.execute("agent-1", get_req(), &cap).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"abc");
}
