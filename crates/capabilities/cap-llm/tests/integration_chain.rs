//! Cross-crate integration tests for MODULE-009 Slice B-2.
//!
//! Verify the gateway end-to-end against the REAL `cap_http::DefaultHttpSecurityChain`
//! + `cap_http::executor::MockHttpExecutor` to satisfy:
//! - **AC-08** (HttpSecurityChain integration): full 10-step routing.
//! - **AC-13** (embed integration test): embed flow end-to-end.
//!
//! These tests pair with the in-crate Layer-2 tests (T76-T87 + T87a) that use
//! `MockHttpSecurityChain` for fast unit coverage. Layer-3 tests here verify
//! real-chain wiring works.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::event::Event;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::security_validator::{HttpResponse, HttpSecurityChain, SsrfGuard};
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck, RunBudget};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, HttpExecutor,
    MockHttpExecutor, MockResolver,
};
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmGateway, LlmGatewayInternal};
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

// `cap_http::rate_limit::AlwaysAllow` is published — we re-declare a thin
// local wrapper here since the trait sig uses `Result<(), u64>` (retry-after
// ms) per `cap_http/rate_limit.rs:RateLimiter`.

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

const FIXTURE_RUNTIME_CONFIG_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt4o: gpt-4o-2024-08-06
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

circuit-breakers: []

secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY

users: []

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

fn fixture_runtime_config() -> RuntimeConfig {
    serde_yml::from_str(FIXTURE_RUNTIME_CONFIG_YAML).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn make_secret_store() -> Arc<SecretStore> {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let master = Zeroizing::new([0xab_u8; 32]);
    let s = SecretStore::new(master, storage);
    s.store("openai-api-key", "test-secret-value").unwrap();
    Arc::new(s)
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
    fn subscribe(&self) -> mpsc::Receiver<Arc<RuntimeConfig>> {
        let (_tx, rx) = mpsc::channel(1);
        rx
    }
    fn last_error(&self) -> Option<String> {
        None
    }
}

#[derive(Default)]
struct AllowAllBudget;

impl RunBudget for AllowAllBudget {
    fn check(&self, _run_id: &str, _t: u64, _c: f64) -> BudgetDecision {
        BudgetDecision::Allow
    }
    fn commit(&self, _run_id: &str, _t: u64, _c: f64) {}
}

#[derive(Default)]
struct CollectorBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for CollectorBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

// Trivial AlwaysAllow rate limiter matching cap_http's RateLimiter trait sig
// (`Result<(), u64>` — Err carries retry-after-ms).
struct AlwaysAllowRl;

impl cap_http::rate_limit::RateLimiter for AlwaysAllowRl {
    fn check(&self, _agent_id: &str, _host: &str) -> Result<(), u64> {
        Ok(())
    }
}

struct StepTracer(Mutex<Vec<&'static str>>);

impl StepTracer {
    fn new() -> Self {
        Self(Mutex::new(vec![]))
    }
    fn snapshot(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
}

fn build_real_chain(
    executor: Arc<dyn HttpExecutor>,
    tracer: Option<Arc<StepTracer>>,
) -> Arc<dyn HttpSecurityChain> {
    let leak: Arc<dyn advance_shared_types::security_validator::LeakDetector> =
        Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.openai.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(AlwaysAllowRl);
    let chain = DefaultHttpSecurityChain::new(make_secret_store(), leak, ssrf, rl, executor);
    let chain = if let Some(t) = tracer {
        let trace_arc = Arc::clone(&t);
        let trace_fn: Arc<dyn Fn(&'static str) + Send + Sync> = Arc::new(move |name| {
            trace_arc.0.lock().unwrap().push(name);
        });
        chain.with_step_tracer(trace_fn)
    } else {
        chain
    };
    Arc::new(chain)
}

/// Slice D inline no-op RepetitionGuard — integration tests outside the
/// cap-llm crate cannot reach the `pub(crate)` MockRepetitionGuard in
/// `test_support/`. All `record_*` methods return `Pass` so integration
/// tests verify the chain-side behaviour without exercising the guard.
struct InlineNoOpRepetitionGuard;
impl RepetitionGuardCheck for InlineNoOpRepetitionGuard {
    fn record_tool_call(&self, _agent_id: &str, _sig: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(&self, _agent_id: &str, _output_hash: OutputHash) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
}

fn build_gateway(chain: Arc<dyn HttpSecurityChain>) -> (Arc<LlmGateway>, Arc<CollectorBus>) {
    let cfg_provider: Arc<dyn RuntimeConfigProvider> =
        Arc::new(InlineConfigProvider::new(fixture_runtime_config()));
    let budget: Arc<dyn RunBudget> = Arc::new(AllowAllBudget);
    let bus = Arc::new(CollectorBus::default());
    let rep_guard: Arc<dyn RepetitionGuardCheck> = Arc::new(InlineNoOpRepetitionGuard);
    let gateway = Arc::new(LlmGateway::new(
        cfg_provider,
        chain,
        budget,
        Arc::clone(&bus) as Arc<dyn EventBusEmit>,
        rep_guard,
        "test-agent".into(),
    ));
    (gateway, bus)
}

fn ok_chat_response_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        "model": "gpt-4o-mini",
    }))
    .unwrap()
}

fn ok_embed_response_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "data": [{"embedding": [0.1, 0.2]}],
    }))
    .unwrap()
}

fn ok_response(body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

/// MODULE-009-T88 — embed end-to-end through real DefaultHttpSecurityChain.
#[tokio::test]
async fn t88_embed_through_real_chain() {
    let exec = MockHttpExecutor::new().with_response(
        "https://api.openai.com/v1/embeddings",
        ok_response(ok_embed_response_body()),
    );
    let chain = build_real_chain(Arc::new(exec), None);
    let (gateway, _) = build_gateway(chain);
    let v = gateway.embed("hello").await.unwrap();
    assert_eq!(v.len(), 2);
}

/// MODULE-009-T89 — generate end-to-end through real DefaultHttpSecurityChain.
#[tokio::test]
async fn t89_generate_through_real_chain() {
    let exec = MockHttpExecutor::new().with_response(
        "https://api.openai.com/v1/chat/completions",
        ok_response(ok_chat_response_body()),
    );
    let chain = build_real_chain(Arc::new(exec), None);
    let (gateway, _) = build_gateway(chain);
    let resp = gateway
        .chat(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams::default(),
        )
        .await
        .unwrap();
    assert_eq!(resp.text, "hello");
    assert_eq!(resp.input_tokens, 1);
    assert_eq!(resp.output_tokens, 1);
}

/// MODULE-009-T90 — generate through real chain whose step_tracer records the
/// canonical 10-step trace via cap-http's STEP_* constant strings (lowercase
/// per cap-http/security_chain.rs:29-38).
#[tokio::test]
async fn t90_generate_real_chain_step_trace() {
    let exec = MockHttpExecutor::new().with_response(
        "https://api.openai.com/v1/chat/completions",
        ok_response(ok_chat_response_body()),
    );
    let tracer = Arc::new(StepTracer::new());
    let chain = build_real_chain(Arc::new(exec), Some(Arc::clone(&tracer)));
    let (gateway, _) = build_gateway(chain);
    gateway
        .chat(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams::default(),
        )
        .await
        .unwrap();
    let trace = tracer.snapshot();
    // cap-http's actual step strings (lowercase, snake_case).
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
