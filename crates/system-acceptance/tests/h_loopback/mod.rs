//! Track H shared test helper — a **scriptable** deterministic LLM loopback for the
//! run-manager / budget / LLM-resilience system-acceptance witnesses.
//!
//! This replicates the proven `crates/system-acceptance/src/llm_loopback.rs` chain
//! wiring (real `cap_llm::LlmGateway` + real `cap_http::DefaultHttpSecurityChain`
//! 10-step chain reaching a 127.0.0.1 axum mock via the `dns_overrides` seam, with
//! production SSRF intact), with TWO differences that make the resilience journeys
//! witnessable WITHOUT editing the HF-owned harness (`src/lib.rs` / `src/llm_loopback.rs`):
//!
//!  1. **Scriptable FIFO backend** — instead of a single canned 200 body, the mock
//!     serves a queue of `(status, body)` responses in order across successive
//!     requests (the LAST scripted response repeats once the queue drains). This lets
//!     a journey script `429-then-200` (retry), repeated `401` (non-retryable), or
//!     `invalid-then-valid` structured-output bodies. The mock returns the SCRIPTED
//!     HTTP status (never a hard 200) — the REAL OpenAI adapter maps it
//!     (429→RateLimited retryable, 5xx→retryable ProviderError, 4xx→non-retryable,
//!     200→parse), so every retry/terminal path runs through real product code.
//!  2. **Parameterized collaborators** — `build_real_gateway` takes the caller's
//!     `run_budget` / `repetition_guard` / `event_bus`, so a journey passes a REAL
//!     `advance_run_manager::InMemoryRunBudget` / `RepetitionGuard` and a capturing
//!     bus and WITNESSES the gateway's emitted `llm.*` events + budget/repetition
//!     decisions (the shipped harness routes the gateway bus to a private sink).
//!
//! Only the external LLM provider is mocked (the loopback axum server) — the sole
//! allowed mock under the witness-floor.

#![allow(dead_code)] // included into 5 test binaries; each uses a subset.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider};
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{HttpSecurityChain, LeakDetector, SsrfGuard};
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck, RunBudget};
use cap_http::rate_limit::{AlwaysAllow, RateLimiter};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, HttpExecutor, MockResolver,
    ReqwestExecutorConfig, ReqwestHttpExecutor,
};
use cap_llm::LlmGateway;
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use zeroize::Zeroizing;

/// Provider hostname the gateway dials (mapped to a PUBLIC ip for SSRF, and to
/// 127.0.0.1:<port> by the executor DNS override). MUST be a hostname — a literal
/// 127.0.0.1 URL is blocked by SSRF BEFORE the override applies.
pub const PROVIDER_HOST: &str = "harness-llm.test";
/// Secret name the provider config's `api-key-secret` references (seeded in the store).
pub const API_KEY_SECRET: &str = "harness-llm-api-key";

// ─────────────────────────────────────────────────────────────────────────────
// 1. Scriptable backend
// ─────────────────────────────────────────────────────────────────────────────

/// One scripted upstream HTTP response.
#[derive(Clone, Debug)]
pub struct ScriptedResponse {
    pub status: u16,
    /// Raw JSON body the mock returns (the real OpenAI adapter parses it).
    pub body: String,
}

impl ScriptedResponse {
    /// A 200 with a well-formed OpenAI chat-completion envelope whose assistant
    /// `message.content` is `content_text` and whose `usage` carries the token
    /// counts (mandatory — a missing `usage` makes the adapter return a
    /// non-retryable `ProviderError("invalid response shape")`).
    pub fn ok_chat(content_text: &str, prompt_tokens: u64, completion_tokens: u64) -> Self {
        let body = serde_json::to_string(&serde_json::json!({
            "choices": [{"message": {"content": content_text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
            "model": "harness-llm-mock",
        }))
        .expect("ok_chat body serializes");
        Self { status: 200, body }
    }

    /// A bare `(status, body)` pair (e.g. `err(429, "{\"error\":\"slow down\"}")`).
    pub fn err(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_string(),
        }
    }
}

/// One inbound request the loopback mock observed.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub path: String,
    /// Lowercased header name → value.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Records the inbound requests the mock received.
#[derive(Clone, Default)]
pub struct Recorder(Arc<Mutex<Vec<RecordedRequest>>>);

impl Recorder {
    fn push(&self, r: RecordedRequest) {
        self.0.lock().unwrap().push(r);
    }
    /// All requests observed, in arrival order.
    pub fn snapshot(&self) -> Vec<RecordedRequest> {
        self.0.lock().unwrap().clone()
    }
    /// Number of `/v1/chat/completions` requests observed (witnesses retry count).
    pub fn chat_request_count(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == "/v1/chat/completions")
            .count()
    }
    /// `authorization` header on the most recent request (credential-injection witness).
    pub fn last_authorization(&self) -> Option<String> {
        self.0.lock().unwrap().last().and_then(|r| {
            r.headers
                .iter()
                .find(|(n, _)| n == "authorization")
                .map(|(_, v)| v.clone())
        })
    }
}

#[derive(Clone)]
struct MockState {
    chat: Arc<Mutex<VecDeque<ScriptedResponse>>>,
    last_chat: Arc<Mutex<ScriptedResponse>>,
    recorder: Recorder,
}

/// A booted scriptable loopback server (axum on an ephemeral 127.0.0.1 port).
pub struct LoopbackServer {
    port: u16,
    recorder: Recorder,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        // A bare JoinHandle detaches (does NOT cancel) on drop; abort so teardown
        // is deterministic across many servers in one runtime.
        self.task.abort();
    }
}

impl LoopbackServer {
    /// Bind 127.0.0.1:0, spawn axum, serve `chat_responses` in FIFO order (the last
    /// repeats once drained). A drained empty queue with no last → falls back to a
    /// 500 so a mis-scripted test fails loudly rather than hanging.
    pub async fn start(chat_responses: Vec<ScriptedResponse>) -> Self {
        let recorder = Recorder::default();
        let last = chat_responses
            .last()
            .cloned()
            .unwrap_or_else(|| ScriptedResponse::err(500, r#"{"error":"loopback: empty script"}"#));
        let state = MockState {
            chat: Arc::new(Mutex::new(VecDeque::from(chat_responses))),
            last_chat: Arc::new(Mutex::new(last)),
            recorder: recorder.clone(),
        };
        let app = axum::Router::new()
            .route("/v1/chat/completions", axum::routing::post(chat_handler))
            .route("/v1/embeddings", axum::routing::post(embed_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock");
        let port = listener.local_addr().expect("local_addr").port();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            port,
            recorder,
            task,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn recorder(&self) -> Recorder {
        self.recorder.clone()
    }
}

async fn chat_handler(
    axum::extract::State(state): axum::extract::State<MockState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    state.recorder.push(RecordedRequest {
        path: "/v1/chat/completions".to_string(),
        headers: headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: body.to_vec(),
    });
    // Pop the next scripted response (per-REQUEST); replay the last once drained.
    let resp = {
        let mut q = state.chat.lock().unwrap();
        match q.pop_front() {
            Some(r) => {
                *state.last_chat.lock().unwrap() = r.clone();
                r
            }
            None => state.last_chat.lock().unwrap().clone(),
        }
    };
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::from_u16(resp.status).unwrap_or(axum::http::StatusCode::OK),
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        resp.body,
    )
        .into_response()
}

async fn embed_handler(
    axum::extract::State(_state): axum::extract::State<MockState>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        r#"{"data":[{"embedding":[0.1,0.2]}]}"#.to_string(),
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Real cap-http chain + cap-llm gateway builder (parameterized)
// ─────────────────────────────────────────────────────────────────────────────

/// The collaborators a journey supplies so it can WITNESS gateway side-effects.
/// Pass REAL product impls: `Arc::new(run_manager.budget())`,
/// `Arc::new(RepetitionGuard::new(..))`, and a `CapturingBus` (or real EventBus).
pub struct GatewayDeps {
    pub run_budget: Arc<dyn RunBudget>,
    pub repetition_guard: Arc<dyn RepetitionGuardCheck>,
    pub event_bus: Arc<dyn EventBusEmit>,
    /// Gateway default agent id (used by `chat()` / `chat_for_run()`).
    pub default_agent_id: String,
}

/// Build the REAL gateway: `DefaultHttpSecurityChain` (10-step) + DefaultLeakDetector
/// + DefaultSsrfGuard(MockResolver→public ip) + ReqwestHttpExecutor(dns_override→
/// 127.0.0.1:provider_port) + AlwaysAllow + seeded SecretStore + InlineConfigProvider,
/// wired to the caller's `deps`. `provider_port` is the `LoopbackServer`'s port.
pub fn build_real_gateway(provider_port: u16, deps: GatewayDeps) -> Arc<LlmGateway> {
    build_real_gateway_with_overrides(provider_port, deps, None)
}

/// As [`build_real_gateway`] but with optional §1.4.3c agent-tier retry
/// overrides (small-witness 2026-06-11, SYS-AC-129). `with_retry_overrides`
/// consumes the gateway BY VALUE, so it is applied here on the owned
/// `LlmGateway` BEFORE `Arc::new` — post-Arc chaining would not compile.
pub fn build_real_gateway_with_overrides(
    provider_port: u16,
    deps: GatewayDeps,
    retry_overrides: Option<cap_llm::PartialRetry>,
) -> Arc<LlmGateway> {
    let leak: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with(PROVIDER_HOST, vec![public_ip()]);
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn RateLimiter> = Arc::new(AlwaysAllow);
    let exec: Arc<dyn HttpExecutor> =
        Arc::new(ReqwestHttpExecutor::from_config(ReqwestExecutorConfig {
            timeout: Duration::from_secs(5),
            dns_overrides: vec![(
                PROVIDER_HOST.to_string(),
                SocketAddr::from(([127, 0, 0, 1], provider_port)),
            )],
            max_redirects: 5,
            ..Default::default()
        }));
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(DefaultHttpSecurityChain::new(
        secret_store(),
        leak,
        ssrf,
        rl,
        exec,
    ));

    let cfg_provider: Arc<dyn RuntimeConfigProvider> = Arc::new(InlineConfigProvider::new(
        loopback_runtime_config(provider_port),
    ));

    let mut gateway = LlmGateway::new(
        cfg_provider,
        chain,
        deps.run_budget,
        deps.event_bus,
        deps.repetition_guard,
        deps.default_agent_id,
    );
    if let Some(overrides) = retry_overrides {
        gateway = gateway.with_retry_overrides(overrides);
    }
    Arc::new(gateway)
}

/// Boot a scriptable backend AND the wired real gateway together.
pub struct LoopbackHarness {
    pub gateway: Arc<LlmGateway>,
    pub server: LoopbackServer,
}

/// Convenience: start the scriptable backend, then build the gateway pointed at it.
pub async fn boot(chat_responses: Vec<ScriptedResponse>, deps: GatewayDeps) -> LoopbackHarness {
    let server = LoopbackServer::start(chat_responses).await;
    let gateway = build_real_gateway(server.port(), deps);
    LoopbackHarness { gateway, server }
}

/// Small-witness 2026-06-11 (SYS-AC-129): [`boot`] with agent-tier retry overrides.
pub async fn boot_with_retry_overrides(
    chat_responses: Vec<ScriptedResponse>,
    deps: GatewayDeps,
    retry_overrides: cap_llm::PartialRetry,
) -> LoopbackHarness {
    let server = LoopbackServer::start(chat_responses).await;
    let gateway = build_real_gateway_with_overrides(server.port(), deps, Some(retry_overrides));
    LoopbackHarness { gateway, server }
}

fn public_ip() -> IpAddr {
    "8.8.8.8".parse().unwrap()
}

fn secret_store() -> Arc<SecretStore> {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let master = Zeroizing::new([0xab_u8; 32]);
    let s = SecretStore::new(master, storage);
    s.store(API_KEY_SECRET, "test-secret-value").unwrap();
    Arc::new(s)
}

/// In-memory `RuntimeConfig` whose single provider points at the loopback host:port.
/// `http://` is fine because this is constructed in-memory, NOT loaded through
/// `validate_config` (which would reject an http-non-localhost endpoint).
fn loopback_runtime_config(realport: u16) -> RuntimeConfig {
    let yaml = format!(
        r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai
    endpoint: http://{host}:{port}
    api-key-secret: {secret}
    model-aliases:
      default: gpt-4o-mini
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#,
        host = PROVIDER_HOST,
        port = realport,
        secret = API_KEY_SECRET,
    );
    serde_yml::from_str(&yaml).expect("loopback runtime config deserializes")
}

struct InlineConfigProvider {
    cfg: RwLock<Arc<RuntimeConfig>>,
}
impl InlineConfigProvider {
    fn new(cfg: RuntimeConfig) -> Self {
        Self {
            cfg: RwLock::new(Arc::new(cfg)),
        }
    }
}
impl RuntimeConfigProvider for InlineConfigProvider {
    fn current(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.cfg.read().unwrap())
    }
    fn subscribe(&self) -> tokio::sync::mpsc::Receiver<Arc<RuntimeConfig>> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }
    fn last_error(&self) -> Option<String> {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Witnessing collaborators (real-API; CapturingBus is an EventBusEmit sink,
//    the same seam the shipped src/llm_loopback.rs CollectorBus uses — NOT a
//    product mock).
// ─────────────────────────────────────────────────────────────────────────────

/// A synchronous capturing `EventBusEmit` sink. Witnesses the gateway's emitted
/// `llm.*` events (and the run-manager's `run.*` events when used as its bus).
#[derive(Clone, Default)]
pub struct CapturingBus(Arc<Mutex<Vec<Event>>>);

impl CapturingBus {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }
    /// Events whose `event_type` equals `name` (e.g. `cap_llm::LLM_RETRY`).
    pub fn events_named(&self, name: &str) -> Vec<Event> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == name)
            .cloned()
            .collect()
    }
    /// Count of events of `name`.
    pub fn count(&self, name: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == name)
            .count()
    }
    /// The `event_type` sequence in emit order (for sequence assertions).
    pub fn event_type_sequence(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }
}

impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}
