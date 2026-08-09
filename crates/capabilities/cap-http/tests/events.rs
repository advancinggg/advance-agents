//! Phase-3 kickoff (2026-06-06) — MODULE-019-AC-22: `DefaultHttpSecurityChain`
//! emits redacted observability events when an `EventBus` is wired via
//! `with_event_bus`. The security-load-bearing test is `t_redaction_*`: no
//! secret / URL-path / query / userinfo substring may appear in ANY payload.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{
    Allowlist, CredentialBinding, CredentialPosition, HttpBodyStream, HttpCapability, HttpError,
    HttpMethod, HttpRequest, HttpResponse, HttpResponseHead, HttpSecurityChain, HttpStreamingChain,
};
use advance_shared_types::traits::EventBusEmit;
use cap_http::executor::HttpStreamExecutor;
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, HttpExecutor,
    MockHttpExecutor, MockResolver,
};
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use zeroize::Zeroizing;

mod private_helpers {
    pub use cap_http::rate_limit::{AlwaysAllow, AlwaysDeny};
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Recording `EventBusEmit` — captures every emitted `Event`.
#[derive(Default)]
struct RecordingEmitter(Mutex<Vec<Event>>);
impl EventBusEmit for RecordingEmitter {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}
impl RecordingEmitter {
    fn snapshot(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }
    fn types(&self) -> Vec<String> {
        self.snapshot().into_iter().map(|e| e.event_type).collect()
    }
    fn has(&self, t: &str) -> bool {
        self.types().iter().any(|x| x == t)
    }
    /// One payload for the named event type (first match).
    fn payload_of(&self, t: &str) -> Option<serde_json::Value> {
        self.snapshot()
            .into_iter()
            .find(|e| e.event_type == t)
            .map(|e| e.payload)
    }
    /// Serialize EVERY emitted event (type + payload + all fields) into one
    /// string for substring-leak assertions.
    fn all_serialized(&self) -> String {
        serde_json::to_string(&self.snapshot()).unwrap()
    }
}

fn store(secrets: &[(&str, &str)]) -> Arc<SecretStore> {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let s = SecretStore::new(Zeroizing::new([0xab; 32]), storage);
    for (name, value) in secrets {
        s.store(name, value).unwrap();
    }
    Arc::new(s)
}

fn cap_allow(patterns: &[&str]) -> HttpCapability {
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
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: body.to_vec(),
    }
}

fn get(url: &str) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: url.to_string(),
        headers: vec![],
        body: vec![],
    }
}

/// Build a chain wired with the recording bus + a public-IP resolver for
/// `api.example.com` (so SSRF passes on the happy paths).
fn chain_with_bus(
    secret_store: Arc<SecretStore>,
    executor: Arc<dyn HttpExecutor>,
    rate_limiter: Arc<dyn cap_http::rate_limit::RateLimiter>,
    resolver_ip: &str,
    bus: Arc<RecordingEmitter>,
) -> DefaultHttpSecurityChain {
    let resolver = MockResolver::new().with("api.example.com", vec![ip(resolver_ip)]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    DefaultHttpSecurityChain::new(secret_store, leak, ssrf, rate_limiter, executor)
        .with_event_bus(bus)
}

fn streaming_chain_with_bus(
    executor: Arc<MockHttpExecutor>,
    bus: Arc<RecordingEmitter>,
) -> DefaultHttpSecurityChain {
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    DefaultHttpSecurityChain::new(
        store(&[]),
        leak,
        ssrf,
        Arc::new(private_helpers::AlwaysAllow),
        executor.clone() as Arc<dyn HttpExecutor>,
    )
    .with_event_bus(bus)
    .with_stream_executor(executor as Arc<dyn HttpStreamExecutor>)
}

async fn drain_stream(body: &mut Box<dyn HttpBodyStream>) -> (Vec<u8>, Option<HttpError>) {
    let mut emitted = Vec::new();
    while let Some(chunk) = body.next_chunk().await {
        match chunk {
            Ok(chunk) => emitted.extend_from_slice(&chunk),
            Err(err) => return (emitted, Some(err)),
        }
    }
    (emitted, None)
}

#[tokio::test]
async fn t_happy_emits_request_and_response() {
    let bus = Arc::new(RecordingEmitter::default());
    let exec: Arc<dyn HttpExecutor> = Arc::new(
        MockHttpExecutor::new().with_response("https://api.example.com/x", ok_response(b"hello")),
    );
    let chain = chain_with_bus(
        store(&[]),
        exec,
        Arc::new(private_helpers::AlwaysAllow),
        "8.8.8.8",
        bus.clone(),
    );
    let resp = chain
        .execute(
            "agent-1",
            get("https://api.example.com/x"),
            &cap_allow(&["api.example.com"]),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    assert!(bus.has("http.request"), "types: {:?}", bus.types());
    assert!(bus.has("http.response"), "types: {:?}", bus.types());
    let req = bus.payload_of("http.request").unwrap();
    assert_eq!(req["host"], "api.example.com");
    assert_eq!(req["scheme"], "https");
    assert_eq!(req["method"], "get");
    // http.request must NOT carry a path key.
    assert!(req.get("path").is_none() && req.get("url").is_none());
    let resp_p = bus.payload_of("http.response").unwrap();
    assert_eq!(resp_p["status"], 200);
    assert_eq!(resp_p["host"], "api.example.com");
}

#[tokio::test]
async fn t_allowlist_block_emits_http_blocked() {
    let bus = Arc::new(RecordingEmitter::default());
    let exec: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    let chain = chain_with_bus(
        store(&[]),
        exec,
        Arc::new(private_helpers::AlwaysAllow),
        "8.8.8.8",
        bus.clone(),
    );
    // Host not in the allowlist → AllowlistBlocked.
    let err = chain
        .execute(
            "a",
            get("https://evil.example.org/x"),
            &cap_allow(&["api.example.com"]),
        )
        .await;
    assert!(err.is_err());
    assert!(bus.has("http.blocked"));
    assert_eq!(
        bus.payload_of("http.blocked").unwrap()["reason"],
        "allowlist"
    );
    // The blocked event must NOT carry the full URL / path.
    assert!(!bus.all_serialized().contains("/x"));
}

#[tokio::test]
async fn t_rate_limited_emits_http_blocked() {
    let bus = Arc::new(RecordingEmitter::default());
    let exec: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    let chain = chain_with_bus(
        store(&[]),
        exec,
        Arc::new(private_helpers::AlwaysDeny(500)),
        "8.8.8.8",
        bus.clone(),
    );
    let err = chain
        .execute(
            "a",
            get("https://api.example.com/x"),
            &cap_allow(&["api.example.com"]),
        )
        .await;
    assert!(err.is_err());
    assert!(bus.has("http.blocked"));
    let p = bus.payload_of("http.blocked").unwrap();
    assert_eq!(p["reason"], "rate-limited");
    assert_eq!(p["retry_after_ms"], 500);
}

#[tokio::test]
async fn t_ssrf_emits_security_ssrf_blocked() {
    let bus = Arc::new(RecordingEmitter::default());
    let exec: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new());
    // Resolver returns a private IP → DefaultSsrfGuard blocks.
    let chain = chain_with_bus(
        store(&[]),
        exec,
        Arc::new(private_helpers::AlwaysAllow),
        "10.0.0.1",
        bus.clone(),
    );
    let err = chain
        .execute(
            "a",
            get("https://api.example.com/x"),
            &cap_allow(&["api.example.com"]),
        )
        .await;
    assert!(err.is_err());
    assert!(bus.has("security.ssrf_blocked"), "types: {:?}", bus.types());
    let p = bus.payload_of("security.ssrf_blocked").unwrap();
    assert_eq!(p["host"], "api.example.com");
    assert!(p.get("cidr_class").is_some());
}

#[tokio::test]
async fn t_inbound_leak_emits_security_leak_detected() {
    let bus = Arc::new(RecordingEmitter::default());
    // Response body carries a block-class credential pattern (AWS access key id).
    let exec: Arc<dyn HttpExecutor> = Arc::new(MockHttpExecutor::new().with_response(
        "https://api.example.com/x",
        ok_response(b"AKIAIOSFODNN7EXAMPLE"),
    ));
    let chain = chain_with_bus(
        store(&[]),
        exec,
        Arc::new(private_helpers::AlwaysAllow),
        "8.8.8.8",
        bus.clone(),
    );
    let err = chain
        .execute(
            "a",
            get("https://api.example.com/x"),
            &cap_allow(&["api.example.com"]),
        )
        .await;
    assert!(err.is_err());
    assert!(
        bus.has("security.leak_detected"),
        "types: {:?}",
        bus.types()
    );
    let p = bus.payload_of("security.leak_detected").unwrap();
    assert_eq!(p["scan_context"], "http_inbound");
    assert!(p["finding_count"].as_u64().unwrap() >= 1);
    // The matched secret must NOT be in any payload (count only).
    assert!(!bus.all_serialized().contains("AKIAIOSFODNN7EXAMPLE"));
}

#[tokio::test]
async fn t_stream_warn_body_and_head_pass_silently() {
    let bus = Arc::new(RecordingEmitter::default());
    let digest = "a".repeat(64);
    let expected_headers = vec![
        ("Content-Type".to_string(), "text/event-stream".to_string()),
        ("X-Digest".to_string(), digest),
    ];
    let exec = Arc::new(MockHttpExecutor::new().with_stream(
        "https://api.example.com/x",
        HttpResponseHead {
            status: 206,
            headers: expected_headers.clone(),
        },
        vec![vec![b'a'; 32], vec![b'a'; 32]],
    ));
    let chain = streaming_chain_with_bus(exec, bus.clone());

    let (head, mut body) = chain
        .execute_streaming(
            "a",
            get("https://api.example.com/x"),
            &cap_allow(&["api.example.com"]),
        )
        .await
        .expect("Warned head content must pass");
    let (emitted, err) = drain_stream(&mut body).await;

    assert!(err.is_none(), "Warned body content must pass: {err:?}");
    assert_eq!(head.status, 206);
    assert_eq!(head.headers, expected_headers, "Warned head is verbatim");
    assert_eq!(emitted, vec![b'a'; 64], "Warned body is verbatim");
    assert!(
        !bus.has("security.leak_detected"),
        "Warn is deliberately silent; types: {:?}",
        bus.types()
    );
}

#[tokio::test]
async fn t_stream_body_block_and_redact_emit_security_leak_detected() {
    for (action, payload) in [
        ("block", b"AKIAIOSFODNN7EXAMPLE".to_vec()),
        ("redact", b"Authorization: Basic QUJDREVGRw==".to_vec()),
    ] {
        let bus = Arc::new(RecordingEmitter::default());
        let exec = Arc::new(MockHttpExecutor::new().with_stream(
            "https://api.example.com/x",
            HttpResponseHead {
                status: 200,
                headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
            },
            vec![payload.clone()],
        ));
        let chain = streaming_chain_with_bus(exec, bus.clone());
        let (_head, mut body) = chain
            .execute_streaming(
                "a",
                get("https://api.example.com/x"),
                &cap_allow(&["api.example.com"]),
            )
            .await
            .expect("clean head must hand out the scanning body");
        let (_emitted, err) = drain_stream(&mut body).await;

        assert!(
            matches!(err, Some(HttpError::InboundLeakBlocked(_))),
            "{action} body must terminate"
        );
        let leak_events = bus
            .types()
            .into_iter()
            .filter(|event_type| event_type == "security.leak_detected")
            .count();
        assert_eq!(leak_events, 1, "{action} body emits one terminal event");
        assert!(
            !bus.all_serialized()
                .contains(String::from_utf8_lossy(&payload).as_ref()),
            "{action} matched bytes must not enter event payloads"
        );
    }
}

#[tokio::test]
async fn t_stream_head_block_and_redact_emit_security_leak_detected() {
    for (action, headers, secret) in [
        (
            "block",
            vec![("X-Debug".to_string(), "AKIAIOSFODNN7EXAMPLE".to_string())],
            "AKIAIOSFODNN7EXAMPLE",
        ),
        (
            "redact",
            vec![(
                "Authorization".to_string(),
                "Basic QUJDREVGRw==".to_string(),
            )],
            "QUJDREVGRw==",
        ),
    ] {
        let bus = Arc::new(RecordingEmitter::default());
        let exec = Arc::new(MockHttpExecutor::new().with_stream(
            "https://api.example.com/x",
            HttpResponseHead {
                status: 200,
                headers,
            },
            vec![b"never".to_vec()],
        ));
        let chain = streaming_chain_with_bus(exec, bus.clone());
        let err = chain
            .execute_streaming(
                "a",
                get("https://api.example.com/x"),
                &cap_allow(&["api.example.com"]),
            )
            .await
            .expect_err("terminal head finding must not hand out a body");

        assert!(
            matches!(err, HttpError::InboundLeakBlocked(_)),
            "{action} head must terminate"
        );
        let leak_events = bus
            .types()
            .into_iter()
            .filter(|event_type| event_type == "security.leak_detected")
            .count();
        assert_eq!(leak_events, 1, "{action} head emits one terminal event");
        assert!(
            !bus.all_serialized().contains(secret),
            "{action} matched bytes must not enter event payloads"
        );
    }
}

#[tokio::test]
async fn t_secret_injected_emits_and_redacts() {
    // BearerToken injection works through the full chain (UrlPath is shadowed by
    // step-3 placeholder scanning — a documented cap-http limitation; see
    // tests/credential_injection.rs for direct UrlPath coverage). The secret
    // lands in the Authorization header (never a URL/payload), so the redaction
    // assertion (no secret value in any emitted payload) is exact.
    let bus = Arc::new(RecordingEmitter::default());
    let secret = "BEARER-SECRET-9999";
    let exec: Arc<dyn HttpExecutor> = Arc::new(
        MockHttpExecutor::new()
            .with_response("https://api.example.com/x", ok_response(b"{\"ok\":true}")),
    );
    let mut cap = cap_allow(&["api.example.com"]);
    cap.credentials.push(CredentialBinding {
        position: CredentialPosition::BearerToken,
        secret_name: "bot_token".to_string(),
    });
    let chain = chain_with_bus(
        store(&[("bot_token", secret)]),
        exec,
        Arc::new(private_helpers::AlwaysAllow),
        "8.8.8.8",
        bus.clone(),
    );
    let resp = chain
        .execute("a", get("https://api.example.com/x"), &cap)
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    // secret.injected fired with a binding COUNT, never the secret.
    assert!(bus.has("secret.injected"), "types: {:?}", bus.types());
    let p = bus.payload_of("secret.injected").unwrap();
    assert_eq!(p["host"], "api.example.com");
    assert_eq!(p["credential_bindings"], 1);

    // REDACTION (security-load-bearing): the injected Bearer secret must NOT
    // appear in ANY emitted payload (it lives only in the request header).
    let dump = bus.all_serialized();
    assert!(!dump.contains(secret), "secret leaked: {dump}");
    assert!(
        !dump.contains("Authorization"),
        "auth header leaked: {dump}"
    );
}

#[tokio::test]
async fn t_url_path_token_redacted_in_http_request() {
    // The Telegram-style case: the bot token rides in the URL PATH (no injection).
    // http.request must emit host/scheme/method ONLY — never the token-bearing path.
    let bus = Arc::new(RecordingEmitter::default());
    let token = "BOTTOKEN-PATH-7777";
    let url = format!("https://api.example.com/bot{token}/sendMessage");
    let exec: Arc<dyn HttpExecutor> =
        Arc::new(MockHttpExecutor::new().with_response(&url, ok_response(b"ok")));
    let chain = chain_with_bus(
        store(&[]),
        exec,
        Arc::new(private_helpers::AlwaysAllow),
        "8.8.8.8",
        bus.clone(),
    );
    let resp = chain
        .execute("a", get(&url), &cap_allow(&["api.example.com"]))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    let req = bus.payload_of("http.request").unwrap();
    assert_eq!(req["host"], "api.example.com");
    assert!(req.get("path").is_none() && req.get("url").is_none() && req.get("query").is_none());
    let dump = bus.all_serialized();
    assert!(!dump.contains(token), "url-path token leaked: {dump}");
    assert!(!dump.contains("/bot"), "url path leaked: {dump}");
    assert!(!dump.contains("sendMessage"), "url path leaked: {dump}");
}

#[tokio::test]
async fn t_no_event_bus_no_emit() {
    // Same happy call but WITHOUT with_event_bus → the recording bus (not wired)
    // captures nothing; assert the chain still works and the un-wired bus is empty.
    let bus = Arc::new(RecordingEmitter::default());
    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let exec: Arc<dyn HttpExecutor> = Arc::new(
        MockHttpExecutor::new().with_response("https://api.example.com/x", ok_response(b"hi")),
    );
    // NO .with_event_bus(...)
    let chain = DefaultHttpSecurityChain::new(
        store(&[]),
        leak,
        ssrf,
        Arc::new(private_helpers::AlwaysAllow),
        exec,
    );
    let resp = chain
        .execute(
            "a",
            get("https://api.example.com/x"),
            &cap_allow(&["api.example.com"]),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        bus.snapshot().is_empty(),
        "un-wired bus must capture nothing"
    );
}
