//! Track-E shared test-local real-wiring support (system-acceptance, 2026-06-04).
//!
//! Builders that wire the **real** production cap-* security components for the
//! security-chain journeys (SYS-J-17/18/19/28/30/58), mocking ONLY the external
//! peer (a local axum HTTP backend / the `HttpExecutor` network-egress leg / an
//! MCP server / a subprocess) — never a security/transport/validation module.
//! This is the Track-H "test-local real wiring" pattern; it touches NO harness
//! `src/lib.rs` / `src/llm_loopback.rs`.
//!
//! Included by each `tests/sys_jNN_*.rs` via `#[path = "e_support/mod.rs"] mod e_support;`.
//! A `mod.rs` under `tests/` is NOT compiled as its own test binary (only top-level
//! `tests/*.rs` are), so this is a shared module, not a journey.

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_shared_types::security_validator::{LeakDetector, SsrfGuard};
use cap_http::rate_limit::{AlwaysAllow, AlwaysDeny, RateLimiter};
use cap_http::{
    DefaultLeakDetector, DefaultSsrfGuard, HttpExecutor, MockResolver, ReqwestExecutorConfig,
    ReqwestHttpExecutor,
};
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use zeroize::Zeroizing;

// ── credential test vectors (match cap-http `DefaultLeakDetector` patterns) ──
/// Block-class (Critical) — OpenAI project key. `scan` → `ScanResult::Blocked`.
pub const SECRET_OPENAI: &str = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA";
/// Block-class (Critical) — AWS access key id. `AKIA` + 16 upper-alnum.
pub const SECRET_AWS: &str = "AKIAIOSFODNN7EXAMPLE";
/// Block-class (Critical) — PEM private-key header.
pub const SECRET_PEM: &str = "-----BEGIN PRIVATE KEY-----";
/// Redact-class (High) — Bearer JWT. `scan` → `ScanResult::Redacted`.
pub const SECRET_BEARER_JWT: &str = "Bearer eyJhbGciOiJIUzI1NiJ9";
/// Redact-class (High) — Authorization Basic header line.
pub const SECRET_AUTH_BASIC: &str = "Authorization: Basic dXNlcjpwYXNz";

/// A non-routable RFC1918 address the SSRF guard rejects (PrivateIpv4 CIDR).
pub const PRIVATE_IP: &str = "10.0.0.1";
/// A public address the SSRF guard accepts.
pub const PUBLIC_IP: &str = "8.8.8.8";

pub fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip parse")
}

/// Minimal standard-base64 decoder (no external crate — keeps the zero-Cargo-edit
/// posture). Used to verify the `BasicAuth` credential position substituted the
/// real `username:secret` on the wire (SYS-AC-208).
pub fn b64_decode(input: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let val = |c: u8| -> Option<u32> { A.iter().position(|&x| x == c).map(|p| p as u32) };
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = match val(c) {
            Some(v) => v,
            None => continue,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8 & 0xFF);
        }
    }
    out
}

// ───────────────────────── secret store ─────────────────────────

/// A real `cap_secrets::SecretStore` (3-layer AES-GCM) seeded with `entries`.
pub fn secret_store(entries: &[(&str, &str)]) -> Arc<SecretStore> {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let master = Zeroizing::new([0x11u8; 32]);
    let store = SecretStore::new(master, storage);
    for (name, value) in entries {
        store.store(name, value).expect("seed secret");
    }
    Arc::new(store)
}

/// A real `cap_secrets::SecretStore` with no secrets (chains with no credential bindings).
pub fn empty_secret_store() -> Arc<SecretStore> {
    secret_store(&[])
}

// ───────────────────────── chain collaborators ─────────────────────────

/// The real production leak detector (Aho-Corasick + regex; the 8-pattern table).
pub fn leak() -> Arc<dyn LeakDetector> {
    Arc::new(DefaultLeakDetector::new())
}

/// A real `DefaultSsrfGuard` whose resolver maps each `(host, ip)` deterministically
/// (no live DNS). Map a host to [`PUBLIC_IP`] so SSRF passes, or to [`PRIVATE_IP`] so
/// it is rejected with `SsrfBlocked`.
pub fn ssrf_guard(mappings: &[(&str, &str)]) -> Arc<dyn SsrfGuard> {
    let mut resolver = MockResolver::new();
    for (host, addr) in mappings {
        resolver = resolver.with(host, vec![ip(addr)]);
    }
    Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)))
}

/// Rate limiter that always allows (the egress is never throttled).
pub fn rate_allow() -> Arc<dyn RateLimiter> {
    Arc::new(AlwaysAllow)
}

/// Rate limiter that always denies with `retry_after_ms` (witnesses `RateLimited`).
pub fn rate_deny(retry_after_ms: u64) -> Arc<dyn RateLimiter> {
    Arc::new(AlwaysDeny(retry_after_ms))
}

/// The real reqwest-backed executor with `dns_overrides` bridging a `host → 127.0.0.1:port`
/// loopback (the proven `llm_loopback.rs` seam). The executor performs a REAL TCP request;
/// it is the network-egress leg (the external boundary) — every cap-http security step runs
/// on the real `DefaultHttpSecurityChain` in front of it.
pub fn reqwest_executor(dns_overrides: &[(String, SocketAddr)]) -> Arc<dyn HttpExecutor> {
    Arc::new(ReqwestHttpExecutor::from_config(ReqwestExecutorConfig {
        timeout: Duration::from_secs(5),
        dns_overrides: dns_overrides.to_vec(),
        max_redirects: 5,
        ..Default::default()
    }))
}

/// A step-tracer that records each cap-http chain step name in order. Pass
/// `tracer.callback()` to `DefaultHttpSecurityChain::with_step_tracer` and read
/// `tracer.steps()` after.
#[derive(Clone, Default)]
pub struct StepTracer(Arc<Mutex<Vec<&'static str>>>);

impl StepTracer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn callback(&self) -> Arc<dyn Fn(&'static str) + Send + Sync> {
        let inner = self.0.clone();
        Arc::new(move |name: &'static str| inner.lock().unwrap().push(name))
    }
    pub fn steps(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
    /// How many full chain passes reached step 7 (`execute`). The cap-http step
    /// name for the execute step is the literal `"execute"` (see
    /// `cap-http/src/security_chain.rs` `STEP_EXECUTE`).
    pub fn execute_count(&self) -> usize {
        self.steps().iter().filter(|s| **s == "execute").count()
    }
}

// ───────────────────────── local axum HTTP backend (external peer) ─────────────────────────

/// One inbound request the backend observed (URL path + headers + body) — the
/// post-chain wire form (proves credential injection reached the network leg).
#[derive(Clone, Debug)]
pub struct RecordedReq {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A scripted backend response.
#[derive(Clone)]
pub struct BackendResp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl BackendResp {
    pub fn ok_json(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
        }
    }
    pub fn ok_text(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: body.as_bytes().to_vec(),
        }
    }
    pub fn status_text(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: body.as_bytes().to_vec(),
        }
    }
    pub fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            headers: vec![("location".into(), location.to_string())],
            body: Vec::new(),
        }
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }
}

type Responder = Arc<dyn Fn(usize, &RecordedReq) -> BackendResp + Send + Sync>;

#[derive(Clone)]
struct BackendState {
    recorder: Arc<Mutex<Vec<RecordedReq>>>,
    responder: Responder,
}

/// A booted local axum backend on an ephemeral loopback port. The `host` is a
/// synthetic hostname the chain's SSRF resolver maps to a PUBLIC ip while the
/// executor's `dns_overrides` route the TCP to this loopback port.
pub struct Backend {
    pub host: String,
    pub port: u16,
    recorder: Arc<Mutex<Vec<RecordedReq>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Backend {
    /// Spawn a backend whose response is computed per request by `responder`
    /// (`(call_index, request) -> BackendResp`). `host` is the synthetic hostname
    /// the test uses in its URLs / allowlist / SSRF mapping.
    pub async fn spawn(
        host: &str,
        responder: impl Fn(usize, &RecordedReq) -> BackendResp + Send + Sync + 'static,
    ) -> Self {
        let recorder: Arc<Mutex<Vec<RecordedReq>>> = Arc::new(Mutex::new(Vec::new()));
        let state = BackendState {
            recorder: recorder.clone(),
            responder: Arc::new(responder),
        };
        let app = axum::Router::new().fallback(handler).with_state(state);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind backend");
        let port = listener.local_addr().expect("local_addr").port();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            host: host.to_string(),
            port,
            recorder,
            task,
        }
    }

    /// Spawn a backend that returns the same `resp` for every request.
    pub async fn fixed(host: &str, resp: BackendResp) -> Self {
        Self::spawn(host, move |_, _| resp.clone()).await
    }

    /// The `dns_overrides` entry routing `host` → this backend's loopback port.
    pub fn dns_override(&self) -> (String, SocketAddr) {
        (
            self.host.clone(),
            SocketAddr::from(([127, 0, 0, 1], self.port)),
        )
    }

    /// All requests the backend has observed.
    pub fn recorded(&self) -> Vec<RecordedReq> {
        self.recorder.lock().unwrap().clone()
    }

    /// The most recent observed request, if any.
    pub fn last(&self) -> Option<RecordedReq> {
        self.recorder.lock().unwrap().last().cloned()
    }
}

async fn handler(
    axum::extract::State(state): axum::extract::State<BackendState>,
    req: axum::extract::Request,
) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    // Record path AND query so the QueryParam / UrlPath credential positions are
    // observable on the wire (SYS-AC-208).
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let rec = RecordedReq {
        path: path.clone(),
        headers,
        body: bytes,
    };
    let call_index = {
        let mut guard = state.recorder.lock().unwrap();
        let idx = guard.len();
        guard.push(rec.clone());
        idx
    };
    let resp = (state.responder)(call_index, &rec);
    let mut builder = axum::response::Response::builder().status(resp.status);
    for (k, v) in resp.headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(resp.body))
        .expect("build response")
}
