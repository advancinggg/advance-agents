//! Deterministic LLM loopback seam — a mock LLM backend reachable through the REAL
//! `cap_llm::LlmGateway` + `cap_http::DefaultHttpSecurityChain` (all 10 chain steps:
//! allowlist, leak-scan, secret-injection, SSRF, rate-limit, execute, …).
//!
//! The SSRF-vs-loopback bridge (the seam, with ZERO cap-http edits): the chain's
//! `DefaultSsrfGuard` blocks 127.0.0.1, so we map the provider **hostname**
//! `harness-llm.test` → a PUBLIC IP via `MockResolver` (the SSRF guard passes) while the
//! REAL `ReqwestHttpExecutor` carries a `.resolve()` DNS override → `127.0.0.1:<realport>`
//! (real TCP to the loopback axum mock). The endpoint MUST be a hostname (not a literal
//! `127.0.0.1` URL — those are blocked before the override). The gateway reads its provider
//! config from an in-memory `RuntimeConfigProvider` (bypassing `validate_config`, which
//! would reject an http-non-localhost endpoint).
//!
//! Proven pattern: `cap-http/tests/reqwest_executor.rs` (T25) +
//! `cap-llm/tests/integration_chain.rs`.
//!
//! HF-2 resilience knobs (2026-06-04) — folds the `tests/h_loopback/mod.rs` capabilities
//! into the shipped harness so resilience journeys witness through `SystemUnderTest`:
//!  1. **Scriptable FIFO backend** ([`ScriptedResponse`]) — instead of a single canned 200,
//!     the mock serves a queue of `(status, body)` responses in order (the LAST scripted
//!     response repeats once the queue drains), so a journey can script `429-then-200`
//!     (retry), `401` (non-retryable), or `invalid-then-valid` structured-output bodies. The
//!     mock returns the SCRIPTED HTTP status — the REAL OpenAI adapter does the mapping
//!     (429→RateLimited retryable, 5xx→retryable, 4xx→non-retryable, 200→parse).
//!  2. **Parameterized collaborators** — [`LoopbackLlm::start`] takes the caller's
//!     `Option<Arc<dyn RunBudget>>` / `Option<Arc<dyn RepetitionGuardCheck>>` (defaulting to
//!     the private `AllowAllBudget` / `NoOpRepetitionGuard` here when `None`) and the harness
//!     `Arc<dyn EventBusEmit>`, so the gateway's emitted `llm.*` events + budget/repetition
//!     decisions surface through the harness's normal `events()` / `events_from_db()`.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::response::IntoResponse;

use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::security_validator::{HttpSecurityChain, LeakDetector, SsrfGuard};
use advance_shared_types::traits::{
    EventBusEmit, HttpStreamingChain, LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink,
    RepetitionGuardCheck, RunBudget,
};
use cap_http::rate_limit::{AlwaysAllow, RateLimiter};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, HttpExecutor, MockResolver,
    ReqwestExecutorConfig, ReqwestHttpExecutor,
};
use cap_llm::LlmGateway;
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use zeroize::Zeroizing;

/// The provider hostname the gateway dials (mapped to loopback by the executor's DNS
/// override; mapped to a public IP by the chain's SSRF resolver).
const PROVIDER_HOST: &str = "harness-llm.test";
/// The secret name the provider's `api-key-secret` references (seeded in the store).
pub const API_KEY_SECRET: &str = "harness-llm-api-key";

/// Distinct cloud-mock reply so a silent local→cloud fallback is observable.
pub const CLOUD_FALLBACK_SENTINEL: &str = "CLOUD-FALLBACK-SENTINEL";

/// Harness-only CONTRACT-234 wrapper: forwards every frame to an inner
/// [`advance_client_api::LlmDeltaHub`] and records `event.stream_key` on
/// `Begin` plus guest-visible `Delta` texts. Gateway holds this as
/// `dyn LlmDeltaSink`; Client API holds the inner hub.
pub struct CapturingDeltaSink {
    inner: Arc<advance_client_api::LlmDeltaHub>,
    begins: Mutex<Vec<String>>,
    deltas: Mutex<Vec<String>>,
    begin_notify: tokio::sync::Notify,
}

impl CapturingDeltaSink {
    pub fn new(inner: Arc<advance_client_api::LlmDeltaHub>) -> Self {
        Self {
            inner,
            begins: Mutex::new(Vec::new()),
            deltas: Mutex::new(Vec::new()),
            begin_notify: tokio::sync::Notify::new(),
        }
    }

    pub fn inner_hub(&self) -> Arc<advance_client_api::LlmDeltaHub> {
        Arc::clone(&self.inner)
    }

    pub fn captured_stream_keys(&self) -> Vec<String> {
        self.begins.lock().expect("capturing begins").clone()
    }

    pub fn recorded_delta_texts(&self) -> Vec<String> {
        self.deltas.lock().expect("capturing deltas").clone()
    }

    pub async fn wait_begin_key(&self, timeout: Duration) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(key) = self
                .begins
                .lock()
                .expect("capturing begins")
                .first()
                .cloned()
            {
                return Some(key);
            }
            // Subscribe *then* re-check so a Begin published in the gap
            // cannot be lost (`notify_waiters` only wakes already-enabled waiters).
            let notified = self.begin_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(key) = self
                .begins
                .lock()
                .expect("capturing begins")
                .first()
                .cloned()
            {
                return Some(key);
            }
            match tokio::time::timeout_at(deadline, notified).await {
                Ok(()) => {}
                Err(_) => {
                    return self
                        .begins
                        .lock()
                        .expect("capturing begins")
                        .first()
                        .cloned();
                }
            }
        }
    }
}

impl LlmDeltaSink for CapturingDeltaSink {
    fn publish(&self, event: LlmDeltaEvent) {
        match &event.frame {
            LlmDeltaFrame::Begin { .. } => {
                self.begins
                    .lock()
                    .expect("capturing begins")
                    .push(event.stream_key.to_string());
                self.begin_notify.notify_waiters();
            }
            LlmDeltaFrame::Delta { text, .. } => {
                self.deltas
                    .lock()
                    .expect("capturing deltas")
                    .push(text.clone());
            }
            LlmDeltaFrame::Terminal { .. } => {}
        }
        self.inner.publish(event);
    }

    fn is_wired(&self) -> bool {
        true
    }
}

/// A single-200 convenience script: the assistant text the mock returns plus token counts.
/// Retained for back-compat (`.llm(LlmMode::Loopback(LoopbackScript::reply(..)))`); for
/// multi-response / error / retry scripting use [`ScriptedResponse`] +
/// `LlmMode::LoopbackScripted`.
#[derive(Clone, Debug)]
pub struct LoopbackScript {
    pub reply_text: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

impl LoopbackScript {
    /// A canned reply with `1/1` token counts.
    pub fn reply(text: &str) -> Self {
        Self {
            reply_text: text.to_string(),
            prompt_tokens: 1,
            completion_tokens: 1,
        }
    }
}

/// One SSE event the loopback serializes VERBATIM (grok-repass Item 2a).
/// `event` becomes an optional `event:` line (CR/LF in the name is rejected
/// eagerly at [`LoopbackLlm::start`] — it would break SSE framing); `data`
/// is written as one `data:` line per LF-separated line of the string,
/// followed by the blank-line terminator. A CR anywhere in `data` is also
/// rejected eagerly (it would frame differently than declared on a
/// spec-conforming parser; use [`ScriptedBody::Raw`] for malformed wire
/// bytes). Nothing is synthesized around it: no automatic
/// usage frame, no automatic `[DONE]` — absence is scriptable, which is the
/// point (dishonest-SSE fault vocabulary for fail-closed witnesses).
#[derive(Clone, Debug)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Scripted body vocabulary (grok-repass Item 2a).
#[derive(Clone, Debug)]
pub enum ScriptedBody {
    /// The historical raw-JSON-string shape. Non-streaming requests get it
    /// byte-identical as `application/json`; streaming requests get the
    /// synthesized OpenAI SSE built by `build_openai_sse` (byte-exact deltas
    /// per Item 2d).
    Json(String),
    /// Serialized verbatim as `text/event-stream` — see [`SseEvent`].
    Sse(Vec<SseEvent>),
    /// Written byte-for-byte as `text/event-stream` (malformed-wire faults).
    Raw(String),
}

/// One scripted upstream HTTP response the loopback mock serves (HF-2).
///
/// grok-repass Item 2 NOTE — recorded harness-API break: `body` is now the
/// [`ScriptedBody`] vocabulary, not a bare `String`. The former promise that
/// this type is API-identical to `tests/h_loopback/mod.rs`'s
/// `ScriptedResponse` (import-swap migration) no longer holds; that file
/// keeps its own independent `(status, body: String)` type. This crate is
/// `publish = false` and every in-repo construction site goes through the
/// constructors below, whose signatures are unchanged.
#[derive(Clone, Debug)]
pub struct ScriptedResponse {
    pub status: u16,
    /// Scripted body (see [`ScriptedBody`]).
    pub body: ScriptedBody,
    /// Optional per-event gate (Item 2b), honoured ONLY by `Sse` bodies —
    /// enforced eagerly at enqueue (a gate on a Json/Raw body would be a
    /// silently-ignored no-op, i.e. a witness that cannot fail). The REPLAY
    /// path never gates: once the FIFO drains, a replayed entry is served
    /// immediately regardless of its gate (round-7 structural close of the
    /// spent-gate replay hang).
    pub gate: Option<SseGate>,
}

impl ScriptedResponse {
    /// A 200 with a well-formed OpenAI chat-completion envelope whose assistant
    /// `message.content` is `content_text` and whose `usage` carries the token counts
    /// (mandatory — a missing `usage` makes the adapter return a non-retryable
    /// `ProviderError("invalid response shape")`).
    pub fn ok_chat(content_text: &str, prompt_tokens: u64, completion_tokens: u64) -> Self {
        let body = serde_json::to_string(&serde_json::json!({
            "choices": [{"message": {"content": content_text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
            "model": "harness-llm-mock",
        }))
        .expect("ok_chat body serializes");
        Self {
            status: 200,
            body: ScriptedBody::Json(body),
            gate: None,
        }
    }

    /// A bare `(status, body)` pair (e.g. `err(429, "{\"error\":\"slow down\"}")`).
    pub fn err(status: u16, body: &str) -> Self {
        Self {
            status,
            body: ScriptedBody::Json(body.to_string()),
            gate: None,
        }
    }

    /// A verbatim SSE script (Item 2a) — the mock serves exactly these
    /// events and nothing else.
    pub fn sse(status: u16, events: Vec<SseEvent>) -> Self {
        Self {
            status,
            body: ScriptedBody::Sse(events),
            gate: None,
        }
    }

    /// A byte-for-byte raw body served as `text/event-stream` (Item 2a).
    pub fn raw(status: u16, body: &str) -> Self {
        Self {
            status,
            body: ScriptedBody::Raw(body.to_string()),
            gate: None,
        }
    }

    /// Attach a per-event [`SseGate`] (Item 2b). Only legal on `Sse` bodies —
    /// validated eagerly at [`LoopbackLlm::start`].
    pub fn with_gate(mut self, gate: SseGate) -> Self {
        self.gate = Some(gate);
        self
    }
}

/// Per-event serving gate for `ScriptedBody::Sse` (grok-repass Item 2b) —
/// mirrors cap-http's `StreamGate` Semaphore precedent. The handler awaits
/// one permit per event PLUS one for the terminal EOF, so
/// `release(events + 1)` drains a script exactly.
///
/// Two out-of-band observability channels make gate witnesses able to FAIL
/// (rounds 6–7): `events_emitted()` is bumped after each successful acquire
/// and BEFORE the event is handed to the transport — after a client has read
/// k events the counter is exactly k, a timing-free equality; `timed_out()`
/// is published BEFORE the handler abandons the body on a bounded-acquire
/// expiry (the abandonment itself produces a clean EOF that is
/// byte-indistinguishable from a scripted truncation fault — which is why
/// the signal must be out-of-band and why no wire-visible sentinel exists).
#[derive(Clone, Debug)]
pub struct SseGate {
    sem: Arc<tokio::sync::Semaphore>,
    emitted: Arc<AtomicUsize>,
    timed_out: Arc<Mutex<Option<usize>>>,
}

impl SseGate {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            sem: Arc::new(tokio::sync::Semaphore::new(0)),
            emitted: Arc::new(AtomicUsize::new(0)),
            timed_out: Arc::new(Mutex::new(None)),
        }
    }

    /// Release `n` serves (each event consumes one; the EOF after the last
    /// event consumes one more — same arithmetic as `StreamGate::release`).
    pub fn release(&self, n: usize) {
        self.sem.add_permits(n);
    }

    /// Ungate entirely.
    pub fn open(&self) {
        self.sem.add_permits(1 << 20);
    }

    /// How many events the handler has committed to the transport. With
    /// EXACTLY k permits released, after a client has observed k events this
    /// reads exactly k, with no timing: the bump is after the acquire (so
    /// the counter cannot exceed the permits released) and before the write
    /// (so a client that has seen event k has causally seen bump k). With
    /// more permits outstanding only the lower bound holds — the handler may
    /// have run ahead of what the client has read.
    pub fn events_emitted(&self) -> usize {
        self.emitted.load(Ordering::SeqCst)
    }

    /// `Some(index)` if the handler's bounded acquire expired while waiting
    /// to serve the event at `index` (`index == events.len()` means the
    /// terminal EOF permit). Published BEFORE the body is abandoned, so a
    /// test that has drained the (clean-looking) EOF reads a settled value.
    pub fn timed_out(&self) -> Option<usize> {
        *self.timed_out.lock().unwrap()
    }
}

/// Bounded-acquire ceiling for gated serving (Item 2b). A failure bound,
/// NEVER a synchronization primitive — releases still gate all progress.
/// The client-side bound that actually applies (audit round 2, verified
/// against cap-http source): on the STREAMING path the executor replaces the
/// per-request total with its 300 s stream deadline, but it REUSES its
/// configured timeout — the loopback's 5 s — as the PER-PULL idle window
/// (`ReqwestChunkStream { idle: self.timeout }`, budget =
/// `idle.min(deadline - now)`). So the binding constraint on a gated frame
/// is that 5 s per-frame idle window, clamped by the 300 s deadline.
/// 1500 ms sits far under both, so the handler always times out first and
/// `timed_out()` is readable deterministically.
const SSE_GATE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Serialize one [`SseEvent`] to its wire form.
fn serialize_sse_event(ev: &SseEvent) -> String {
    let mut out = String::new();
    if let Some(name) = &ev.event {
        out.push_str("event: ");
        out.push_str(name);
        out.push('\n');
    }
    for line in ev.data.split('\n') {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out
}

/// Gated SSE serving (Item 2b): the body is a stream that awaits one gate
/// permit per frame plus one for the terminal EOF. On acquire expiry the
/// timeout index is published FIRST, then the body is abandoned (clean EOF
/// on the wire; the out-of-band flag is the honest signal).
fn serve_gated_sse(
    status: axum::http::StatusCode,
    frames: Vec<String>,
    gate: SseGate,
) -> axum::response::Response {
    let stream = futures::stream::unfold(
        (frames.into_iter(), 0usize, gate),
        |(mut frames, idx, gate)| async move {
            match frames.next() {
                Some(frame) => {
                    let acquire = Arc::clone(&gate.sem).acquire_owned();
                    match tokio::time::timeout(SSE_GATE_TIMEOUT, acquire).await {
                        Ok(Ok(permit)) => {
                            permit.forget();
                            // AFTER acquire, BEFORE the write reaches the
                            // transport (2b ordering — both bounds).
                            gate.emitted.fetch_add(1, Ordering::SeqCst);
                            Some((
                                Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(frame)),
                                (frames, idx + 1, gate),
                            ))
                        }
                        _ => {
                            // Publish BEFORE abandoning the body (L2-T9).
                            *gate.timed_out.lock().unwrap() = Some(idx);
                            None
                        }
                    }
                }
                None => {
                    // Terminal EOF permit (the events + 1 arithmetic).
                    let acquire = Arc::clone(&gate.sem).acquire_owned();
                    match tokio::time::timeout(SSE_GATE_TIMEOUT, acquire).await {
                        Ok(Ok(permit)) => permit.forget(),
                        _ => *gate.timed_out.lock().unwrap() = Some(idx),
                    }
                    None
                }
            }
        },
    );
    axum::response::Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .body(axum::body::Body::from_stream(stream))
        .expect("gated sse response builds")
}

/// Records the inbound HTTP requests the loopback mock received, so a journey can witness
/// what the REAL cap-http chain put on the wire (e.g. the injected credential).
#[derive(Clone, Default)]
pub struct Recorder(Arc<Mutex<Vec<RecordedRequest>>>);

/// One request the loopback mock observed.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub path: String,
    /// Lowercased header name → value.
    pub headers: Vec<(String, String)>,
    /// Backbone Step 2 (2026-06-07): the raw request BODY (the JSON the real
    /// OpenAI adapter serialized — `{"model":..,"messages":[..]}`). Captured so a
    /// journey can witness WHAT reached the LLM, e.g. the host-assembled
    /// `# Available Tools` section prepended by the generate seam (SYS-AC-010).
    pub body: String,
}

impl Recorder {
    fn push(&self, req: RecordedRequest) {
        self.0.lock().unwrap().push(req);
    }
    fn snapshot(&self) -> Vec<RecordedRequest> {
        self.0.lock().unwrap().clone()
    }
}

/// A booted loopback LLM: the real gateway + the background axum mock server.
pub struct LoopbackLlm {
    pub gateway: Arc<LlmGateway>,
    pub provider_host: String,
    recorder: Recorder,
    mock: tokio::task::JoinHandle<()>,
    /// Wave-16 Lane 2 (SYS-AC-005): the CONCRETE provider-config handle retained
    /// (in ADDITION to the `Arc<dyn RuntimeConfigProvider>` coercion moved into the
    /// gateway — a `dyn` cannot call `.set`) so the SUT can switch the configured
    /// provider in-run via [`Self::switch_provider`]; the gateway re-reads it per call.
    cfg_provider: Arc<InlineConfigProvider>,
    /// The loopback server's ephemeral port — reused when `switch_provider` rebuilds
    /// the config so the endpoint host:port (DNS-mapped) stays constant across a switch.
    realport: u16,
    /// Concrete chain (impls HttpSecurityChain + HttpStreamingChain).
    chain: Arc<DefaultHttpSecurityChain>,
    decoded_detector: Arc<dyn LeakDetector>,
    /// SYS-J-72 opt-in tee wrapper. `None` on the historical `start()` path.
    tee_sink: Option<Arc<CapturingDeltaSink>>,
}

impl Drop for LoopbackLlm {
    fn drop(&mut self) {
        // A bare JoinHandle detaches (does NOT cancel) on drop; abort the loopback
        // server task so teardown is deterministic even when many loopback SUTs are
        // built within one runtime (bounded ephemeral-port + task accumulation).
        self.mock.abort();
    }
}

impl LoopbackLlm {
    /// All requests the loopback mock received (e.g. to witness credential injection).
    pub fn recorded_requests(&self) -> Vec<RecordedRequest> {
        self.recorder.snapshot()
    }

    /// Backbone Step 2 — the BODY of the most recent `/v1/chat/completions` request
    /// the mock saw (the JSON the real OpenAI adapter put on the wire). Used to
    /// witness that the host-assembled layered context (e.g. the merged
    /// `# Available Tools` section) reached the LLM (SYS-AC-010). `None` if no chat
    /// request was recorded.
    pub fn last_chat_request_body(&self) -> Option<String> {
        self.recorder
            .snapshot()
            .into_iter()
            .rev()
            .find(|r| r.path == "/v1/chat/completions")
            .map(|r| r.body)
    }

    /// Backbone Step 4 — EVERY `/v1/chat/completions` request body the mock saw, in
    /// arrival order (one per turn that dialed `generate`). The multi-turn witness
    /// (SYS-AC-004) inspects each turn's outbound body to prove no provider session
    /// id is present on either request and that each turn carried its own prompt.
    pub fn all_chat_request_bodies(&self) -> Vec<String> {
        self.recorder
            .snapshot()
            .into_iter()
            .filter(|r| r.path == "/v1/chat/completions")
            .map(|r| r.body)
            .collect()
    }

    /// The `Authorization` header value the mock saw on the most recent request, if any
    /// — i.e. what the REAL cap-http chain's credential-injection step put on the wire.
    pub fn recorded_authorization(&self) -> Option<String> {
        self.recorder.snapshot().last().and_then(|r| {
            r.headers
                .iter()
                .find(|(n, _)| n == "authorization")
                .map(|(_, v)| v.clone())
        })
    }

    /// How many `/v1/chat/completions` requests the loopback mock observed — i.e. the
    /// number of upstream ATTEMPTS (a scripted `429`/`4xx`/`5xx` counts as an attempt, which
    /// is exactly what a retry witness wants: `429-then-200` ⇒ 2). Because the FIFO replays
    /// its last response once drained, this count is ALSO the over-call guard: assert it to
    /// prove the gateway dialed the provider EXACTLY N times (the replay would otherwise serve
    /// an unexpected extra call a silent 200). HF-2.
    pub fn chat_request_count(&self) -> usize {
        self.recorder
            .snapshot()
            .iter()
            .filter(|r| r.path == "/v1/chat/completions")
            .count()
    }

    /// Wave-16 Lane 2 (SYS-AC-005): switch the CONFIGURED LLM provider in-run. Builds
    /// a NEW provider config ENTRY (distinct `id` + `model-aliases.default`) on the
    /// SAME loopback endpoint host:port + the SAME seeded `api-key-secret`, kept
    /// OpenAI-wire (any non-`anthropic` id → `OpenAiAdapter` → `/v1/chat/completions`,
    /// the only route the loopback serves), and SETs it on the live `InlineConfigProvider`
    /// the gateway re-reads per call. The next `generate` resolves the new provider, so the
    /// outbound `/v1/chat/completions` body's `model` becomes `default_model` — the observable
    /// proof the configured provider genuinely switched, while local recall is unaffected.
    pub fn switch_provider(&self, provider_id: &str, default_model: &str) {
        self.cfg_provider.set(loopback_runtime_config_with(
            provider_id,
            default_model,
            self.realport,
        ));
    }

    /// grok-repass Item 2: the REAL `DefaultHttpSecurityChain` the loopback
    /// gateway streams through, exposed so SSE fault witnesses drive
    /// `HttpStreamingChain::execute_streaming` over the loopback's real TCP.
    /// This is the sanctioned consumption point — `WireChunkStream` bytes are
    /// PRE-scan and must only be read through this chain's scanning wrapper.
    pub fn streaming_chain(&self) -> Arc<dyn HttpStreamingChain> {
        Arc::clone(&self.chain) as Arc<dyn HttpStreamingChain>
    }

    pub fn security_chain(&self) -> Arc<dyn HttpSecurityChain> {
        Arc::clone(&self.chain) as Arc<dyn HttpSecurityChain>
    }

    pub fn decoded_detector(&self) -> Arc<dyn LeakDetector> {
        Arc::clone(&self.decoded_detector)
    }

    pub fn realport(&self) -> u16 {
        self.realport
    }

    pub fn replace_runtime_config(&self, cfg: RuntimeConfig) {
        self.cfg_provider.set(cfg);
    }

    pub fn config_provider(&self) -> Arc<dyn RuntimeConfigProvider> {
        self.cfg_provider.clone()
    }

    /// SYS-J-72: the capturing tee wrapper, if `start_with_tee` was used.
    pub fn capturing_sink(&self) -> Option<Arc<CapturingDeltaSink>> {
        self.tee_sink.clone()
    }

    /// The loopback's chat-completions URL. The hostname is DNS-mapped to
    /// `127.0.0.1:realport` by the executor override (`realport` itself is
    /// private; this is the supported way to address the mock directly).
    pub fn chat_completions_url(&self) -> String {
        format!(
            "http://{}:{}/v1/chat/completions",
            PROVIDER_HOST, self.realport
        )
    }
}

impl LoopbackLlm {
    /// Start the loopback mock + build the real gateway pointed at it.
    ///
    /// `responses` is the FIFO script the mock serves (the last response replays once the
    /// queue drains). `budget` / `repetition` default to the private `AllowAllBudget` /
    /// `NoOpRepetitionGuard` when `None` (back-compat path). `event_bus` is the harness sink
    /// the gateway emits `llm.*` events into; `default_agent_id` is the gateway's fallback
    /// caller id for trait-surface calls (`chat`/`embed` without a run id).
    pub async fn start(
        responses: Vec<ScriptedResponse>,
        budget: Option<Arc<dyn RunBudget>>,
        repetition: Option<Arc<dyn RepetitionGuardCheck>>,
        event_bus: Arc<dyn EventBusEmit>,
        default_agent_id: String,
    ) -> Self {
        Self::start_inner(
            responses,
            budget,
            repetition,
            event_bus,
            default_agent_id,
            None,
            ChainKind::Historical,
        )
        .await
    }

    /// Like [`Self::start`], but tees post-scan frames into `hub` via
    /// [`CapturingDeltaSink`]. Keeps `.with_live_streaming`.
    pub async fn start_with_tee(
        responses: Vec<ScriptedResponse>,
        budget: Option<Arc<dyn RunBudget>>,
        repetition: Option<Arc<dyn RepetitionGuardCheck>>,
        event_bus: Arc<dyn EventBusEmit>,
        default_agent_id: String,
        hub: Arc<advance_client_api::LlmDeltaHub>,
    ) -> Self {
        Self::start_inner(
            responses,
            budget,
            repetition,
            event_bus,
            default_agent_id,
            Some(hub),
            ChainKind::Historical,
        )
        .await
    }

    /// Production `DefaultSsrfGuard::new()` (live forbidden table). YAML
    /// `endpoint` is `origin` verbatim. Chain bus attached.
    pub async fn start_production_ssrf(
        origin: String,
        responses: Vec<ScriptedResponse>,
        budget: Option<Arc<dyn RunBudget>>,
        repetition: Option<Arc<dyn RepetitionGuardCheck>>,
        event_bus: Arc<dyn EventBusEmit>,
        default_agent_id: String,
    ) -> Self {
        Self::start_inner(
            responses,
            budget,
            repetition,
            event_bus,
            default_agent_id,
            None,
            ChainKind::Production { origin },
        )
        .await
    }

    /// Chain step 5 fooled (`mapped_host` → 8.8.8.8). No DNS override.
    /// YAML endpoint `http://{mapped_host}:{realport}`. Chain bus attached.
    pub async fn start_fooled_ssrf(
        mapped_host: String,
        responses: Vec<ScriptedResponse>,
        budget: Option<Arc<dyn RunBudget>>,
        repetition: Option<Arc<dyn RepetitionGuardCheck>>,
        event_bus: Arc<dyn EventBusEmit>,
        default_agent_id: String,
    ) -> Self {
        Self::start_inner(
            responses,
            budget,
            repetition,
            event_bus,
            default_agent_id,
            None,
            ChainKind::Fooled { mapped_host },
        )
        .await
    }

    async fn start_inner(
        responses: Vec<ScriptedResponse>,
        budget: Option<Arc<dyn RunBudget>>,
        repetition: Option<Arc<dyn RepetitionGuardCheck>>,
        event_bus: Arc<dyn EventBusEmit>,
        default_agent_id: String,
        tee_hub: Option<Arc<advance_client_api::LlmDeltaHub>>,
        kind: ChainKind,
    ) -> Self {
        // 1. Loopback axum mock on an ephemeral port. The chat handler RECORDS the inbound
        //    request headers (credential-injection witness) and serves the scripted FIFO.
        let recorder = Recorder::default();
        // A non-empty script is required. An empty `responses` is a wiring mistake (the
        // builder's `LlmMode::Loopback` always supplies one; only `LlmMode::LoopbackScripted(vec![])`
        // can reach here). Fail LOUDLY rather than serving a confusing replayed 500 that a
        // resilience journey could mistake for a real provider fault (adversarial R6 / witness floor).
        assert!(
            !responses.is_empty(),
            "LoopbackLlm requires a non-empty response script — pass at least one ScriptedResponse"
        );
        // Item 2c — eager script validation: a mis-scripted entry fails
        // LOUDLY at enqueue, naming the offending index, instead of
        // surfacing as a confusing wire-level artifact mid-journey.
        for (i, r) in responses.iter().enumerate() {
            match &r.body {
                ScriptedBody::Sse(events) => {
                    for (j, ev) in events.iter().enumerate() {
                        if let Some(name) = &ev.event {
                            assert!(
                                !name.contains('\r') && !name.contains('\n'),
                                "ScriptedResponse[{i}] event[{j}]: SseEvent.event name contains CR/LF, which breaks SSE framing"
                            );
                        }
                        // Audit rounds 4-5: LF in data is legal (it becomes
                        // one data: line per line), but ANY CR (bare or in a
                        // CRLF pair) reaches the wire inside a data: line,
                        // and a spec-conforming SSE parser terminates lines
                        // on CR — the script would frame differently than it
                        // declares. Same hazard class as CR/LF in the event
                        // name; scripts wanting malformed wire bytes use
                        // ScriptedBody::Raw.
                        assert!(
                            !ev.data.contains('\r'),
                            "ScriptedResponse[{i}] event[{j}]: SseEvent.data contains a CR, which breaks SSE framing - use ScriptedBody::Raw for malformed wire bytes"
                        );
                    }
                }
                ScriptedBody::Json(_) | ScriptedBody::Raw(_) => {
                    assert!(
                        r.gate.is_none(),
                        "ScriptedResponse[{i}]: a gate on a non-Sse body would be a silently-ignored no-op — gates are honoured only by ScriptedBody::Sse"
                    );
                }
            }
        }
        // The last scripted response replays once the queue drains, so a single-script,
        // multi-call journey (e.g. the repetition smoke) keeps getting the same reply. The
        // replay deliberately serves any EXTRA call a 200 rather than erroring; a journey that
        // needs an exact upstream-call count must assert `chat_request_count()` (the over-call
        // guard) — see its doc.
        let last = responses
            .last()
            .cloned()
            .expect("non-empty script (asserted above)");
        let state = MockState {
            recorder: recorder.clone(),
            chat: Arc::new(Mutex::new(VecDeque::from(responses))),
            last_chat: Arc::new(Mutex::new(last)),
        };
        let app = axum::Router::new()
            .route("/v1/chat/completions", axum::routing::post(chat_handler))
            .route("/v1/embeddings", axum::routing::post(embed_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock");
        let addr = listener.local_addr().expect("local_addr");
        let mock = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let realport = addr.port();

        // 2. Real chain. Historical: MockResolver + DNS override (SSRF sees a public
        //    IP; TCP lands on loopback). Production/Fooled: no DNS override.
        let leak: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
        let rl: Arc<dyn RateLimiter> = Arc::new(AlwaysAllow);
        let (ssrf, dns_overrides, yaml_endpoint, provider_host, attach_bus): (
            Arc<dyn SsrfGuard>,
            Vec<(String, SocketAddr)>,
            String,
            String,
            bool,
        ) = match &kind {
            ChainKind::Historical => {
                let resolver = MockResolver::new().with(PROVIDER_HOST, vec![public_ip()]);
                (
                    Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver))),
                    vec![(
                        PROVIDER_HOST.to_string(),
                        SocketAddr::from(([127, 0, 0, 1], realport)),
                    )],
                    format!("http://{PROVIDER_HOST}:{realport}"),
                    PROVIDER_HOST.to_string(),
                    false,
                )
            }
            ChainKind::Production { origin } => (
                Arc::new(DefaultSsrfGuard::new()),
                Vec::new(),
                loopback_origin_with_mock_port(origin, realport),
                origin.clone(),
                true,
            ),
            ChainKind::Fooled { mapped_host } => {
                let resolver = MockResolver::new().with(mapped_host.as_str(), vec![public_ip()]);
                (
                    Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver))),
                    Vec::new(),
                    format!("http://{mapped_host}:{realport}"),
                    mapped_host.clone(),
                    true,
                )
            }
        };
        let reqwest_exec = Arc::new(ReqwestHttpExecutor::from_config(ReqwestExecutorConfig {
            timeout: Duration::from_secs(5),
            dns_overrides,
            max_redirects: 5,
            ..Default::default()
        }));
        let exec: Arc<dyn HttpExecutor> = reqwest_exec.clone();
        let stream_exec: Arc<dyn cap_http::executor::HttpStreamExecutor> = reqwest_exec.clone();
        let leak_gateway: Arc<dyn LeakDetector> = leak.clone();
        let mut built = DefaultHttpSecurityChain::new(secret_store(), leak, ssrf, rl, exec)
            .with_stream_executor(stream_exec);
        if attach_bus {
            built = built.with_event_bus(event_bus.clone());
        }
        let chain = Arc::new(built);

        let cfg_provider = Arc::new(InlineConfigProvider::new(loopback_runtime_config_endpoint(
            "openai",
            "gpt-4o-mini",
            &yaml_endpoint,
        )));
        let cfg_provider_dyn: Arc<dyn RuntimeConfigProvider> = cfg_provider.clone();
        let budget: Arc<dyn RunBudget> = budget.unwrap_or_else(|| Arc::new(AllowAllBudget));
        let rep_guard: Arc<dyn RepetitionGuardCheck> =
            repetition.unwrap_or_else(|| Arc::new(NoOpRepetitionGuard));
        let streaming_chain: Arc<dyn HttpStreamingChain> = chain.clone();
        let tee_sink = tee_hub.map(|hub| Arc::new(CapturingDeltaSink::new(hub)));
        let mut gateway = LlmGateway::new(
            cfg_provider_dyn,
            chain.clone(),
            budget,
            event_bus,
            rep_guard,
            default_agent_id,
        )
        .with_live_streaming(streaming_chain, leak_gateway.clone());
        if let Some(sink) = tee_sink.as_ref() {
            gateway = gateway.with_delta_sink(sink.clone() as Arc<dyn LlmDeltaSink>);
        }
        let gateway = Arc::new(gateway);

        LoopbackLlm {
            gateway,
            provider_host,
            recorder,
            mock,
            cfg_provider,
            realport,
            chain,
            decoded_detector: leak_gateway,
            tee_sink,
        }
    }
}

enum ChainKind {
    Historical,
    Production { origin: String },
    Fooled { mapped_host: String },
}

/// `http://127.0.0.1` / `http://localhost` (no port) would dial `:80`, so the
/// in-process mock recorder could never observe a bypass. Append the bound
/// mock port. RFC1918 `https://10.0.0.1` is left verbatim.
fn loopback_origin_with_mock_port(origin: &str, realport: u16) -> String {
    let trimmed = origin.trim().trim_end_matches('/');
    if trimmed == "http://127.0.0.1" || trimmed == "http://localhost" {
        format!("{trimmed}:{realport}")
    } else {
        origin.to_string()
    }
}

#[derive(Clone)]
struct MockState {
    recorder: Recorder,
    /// FIFO of scripted chat responses (served in order; drains to `last_chat`).
    chat: Arc<Mutex<VecDeque<ScriptedResponse>>>,
    /// The most-recently-served chat response, replayed once the queue is empty.
    last_chat: Arc<Mutex<ScriptedResponse>>,
}

async fn chat_handler(
    axum::extract::State(state): axum::extract::State<MockState>,
    headers: axum::http::HeaderMap,
    // Backbone Step 2: the body-consuming extractor (`String`) MUST be the LAST
    // handler arg (after the non-consuming `State`/`HeaderMap`) per axum extractor
    // ordering. Captures the JSON request body (the serialized chat messages).
    body: String,
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
        body: body.clone(),
    });
    // Pop the next scripted response; once drained, replay the last one served.
    // The replay flag is load-bearing: a replayed Sse entry NEVER gates (its
    // permits were spent when it was first served; honouring a spent gate on
    // replay would hang the handler — round-7 structural fix).
    let (resp, from_replay) = {
        let mut q = state.chat.lock().unwrap();
        match q.pop_front() {
            Some(r) => {
                *state.last_chat.lock().unwrap() = r.clone();
                (r, false)
            }
            None => (state.last_chat.lock().unwrap().clone(), true),
        }
    };
    let status = axum::http::StatusCode::from_u16(resp.status)
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    match resp.body {
        ScriptedBody::Json(scripted_body) => {
            // S4: robust stream detection (parsed) for gated SSE. Falls back
            // to contains for malformed.
            let is_stream = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                v.get("stream").and_then(|s| s.as_bool()) == Some(true)
            } else {
                body.contains("\"stream\":true") || body.contains("\"stream\": true")
            };
            if is_stream {
                let content = extract_content_from_scripted(&scripted_body)
                    .unwrap_or_else(|| "ok".to_string());
                let p = extract_usage_prompt(&scripted_body).unwrap_or(7);
                let c = extract_usage_completion(&scripted_body).unwrap_or(9);
                let sse_body = build_openai_sse(&content, p, c, "harness-llm-mock");
                (
                    status,
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    sse_body,
                )
                    .into_response()
            } else {
                (
                    status,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    scripted_body,
                )
                    .into_response()
            }
        }
        ScriptedBody::Sse(events) => {
            let frames: Vec<String> = events.iter().map(serialize_sse_event).collect();
            let gate = if from_replay { None } else { resp.gate.clone() };
            match gate {
                Some(gate) => serve_gated_sse(status, frames, gate),
                None => (
                    status,
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    frames.concat(),
                )
                    .into_response(),
            }
        }
        ScriptedBody::Raw(raw) => (
            status,
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            raw,
        )
            .into_response(),
    }
}

/// Extract assistant content from a canned ScriptedResponse body (ok_chat shape).
fn extract_content_from_scripted(body: &str) -> Option<String> {
    // Minimal parse: look for "content":"..." in the choices[0].message
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            if let Some(first) = choices.get(0) {
                if let Some(msg) = first.get("message") {
                    if let Some(s) = msg.get("content").and_then(|x| x.as_str()) {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    None
}

fn extract_usage_prompt(body: &str) -> Option<u64> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(u) = v
            .get("usage")
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(|x| x.as_u64())
        {
            return Some(u);
        }
    }
    None
}
fn extract_usage_completion(body: &str) -> Option<u64> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(u) = v
            .get("usage")
            .and_then(|u| u.get("completion_tokens"))
            .and_then(|x| x.as_u64())
        {
            return Some(u);
        }
    }
    None
}

/// Build OpenAI-compatible SSE body for a streaming scripted response (real TCP SSE for live path).
/// Emits incremental content deltas then a final with finish_reason + usage, then [DONE].
///
/// grok-repass Item 2d: deltas are byte-exact — `split_inclusive(' ')`
/// segments carry their trailing space, so `concat(deltas) == text`
/// byte-for-byte including multi-line text, runs of spaces and fenced code
/// blocks (the historical `split_whitespace` + space-re-prefix synthesis
/// collapsed every whitespace run to a single space). Deliberate, pinned
/// consequence: newline-separated text with no spaces yields ONE delta where
/// the old splitter yielded two — there is genuinely no space boundary.
fn build_openai_sse(text: &str, prompt_tokens: u64, completion_tokens: u64, model: &str) -> String {
    let mut out = String::new();
    for part in text.split_inclusive(' ') {
        let frame = serde_json::json!({
            "id": "chatcmpl-s4",
            "object": "chat.completion.chunk",
            "created": 1u64,
            "model": model,
            "choices": [ { "index": 0, "delta": { "content": part }, "finish_reason": null } ]
        });
        out.push_str(&format!("data: {}\n\n", frame));
    }
    // Terminal frame with usage (adapter folds LWW).
    let fin = serde_json::json!({
        "id": "chatcmpl-s4",
        "object": "chat.completion.chunk",
        "created": 1u64,
        "model": model,
        "choices": [ { "index": 0, "delta": {}, "finish_reason": "stop" } ],
        "usage": { "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens }
    });
    out.push_str(&format!("data: {}\n\n", fin));
    out.push_str("data: [DONE]\n\n");
    out
}

async fn embed_handler(
    axum::extract::State(_state): axum::extract::State<MockState>,
) -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        r#"{"data":[{"embedding":[0.1,0.2]}]}"#.to_string(),
    )
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
/// `validate_config` (which would reject an http-non-localhost endpoint). The
/// default `("openai","gpt-4o-mini")` config is byte-identical to the pre-Wave-16
/// `loopback_runtime_config`. Wave-16 Lane 2 (SYS-AC-005): `provider_id` +
/// `default_model` are parameterized so `LoopbackLlm::switch_provider` can mint a
/// genuinely DIFFERENT provider ENTRY on the SAME endpoint host + secret.
fn loopback_runtime_config_with(
    provider_id: &str,
    default_model: &str,
    realport: u16,
) -> RuntimeConfig {
    loopback_runtime_config_endpoint(
        provider_id,
        default_model,
        &format!("http://{PROVIDER_HOST}:{realport}"),
    )
}

/// In-memory config whose single provider uses `endpoint` verbatim.
pub fn loopback_runtime_config_endpoint(
    provider_id: &str,
    default_model: &str,
    endpoint: &str,
) -> RuntimeConfig {
    let yaml = format!(
        r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: {id}
    endpoint: {endpoint}
    api-key-secret: {secret}
    model-aliases:
      default: {model}
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
        id = provider_id,
        model = default_model,
        endpoint = endpoint,
        secret = API_KEY_SECRET,
    );
    serde_yml::from_str(&yaml).expect("loopback runtime config deserializes")
}

/// Two-provider in-memory config: local first (optional sidecar command),
/// cloud-http second at `http://harness-llm.test:{cloud_port}`.
pub fn local_sidecar_runtime_config(
    sidecar_command: Option<&str>,
    cloud_port: u16,
) -> RuntimeConfig {
    let local_block = match sidecar_command {
        Some(cmd) => format!(
            r#"
  - id: local
    endpoint: ""
    api-key-secret: {secret}
    model-aliases:
      default: llama
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
    backend-class: local
    sidecar:
      command: {cmd}
"#,
            secret = API_KEY_SECRET,
            cmd = cmd,
        ),
        None => format!(
            r#"
  - id: local
    endpoint: ""
    api-key-secret: {secret}
    model-aliases:
      default: llama
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
    backend-class: local
"#,
            secret = API_KEY_SECRET,
        ),
    };
    let yaml = format!(
        r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
{local}
  - id: openai
    endpoint: http://{host}:{port}
    api-key-secret: {secret}
    model-aliases:
      gpt-4o-mini: gpt-4o-mini
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
    backend-class: cloud-http

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
        local = local_block,
        host = PROVIDER_HOST,
        port = cloud_port,
        secret = API_KEY_SECRET,
    );
    serde_yml::from_str(&yaml).expect("local sidecar runtime config deserializes")
}

/// In-memory [`RuntimeConfigProvider`] (SUT config swaps).
pub struct InlineConfigProvider {
    cfg: RwLock<Arc<RuntimeConfig>>,
}
impl InlineConfigProvider {
    pub fn new(cfg: RuntimeConfig) -> Self {
        Self {
            cfg: RwLock::new(Arc::new(cfg)),
        }
    }

    /// Wave-16 Lane 2 (SYS-AC-005): hot-swap the live config. The gateway reads
    /// `current()` per call, so the next `generate` observes the new config (the
    /// `MODULE-009-T85` per-call-poll contract). Used by `LoopbackLlm::switch_provider`.
    pub fn set(&self, cfg: RuntimeConfig) {
        *self.cfg.write().unwrap() = Arc::new(cfg);
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

/// Default run-budget when `.budget()` is unset — always allows (back-compat).
#[derive(Default)]
pub(crate) struct AllowAllBudget;
impl RunBudget for AllowAllBudget {
    fn check(&self, _run_id: &str, _t: u64, _c: f64) -> BudgetDecision {
        BudgetDecision::Allow
    }
    fn commit(&self, _run_id: &str, _t: u64, _c: f64) {}
}

/// grok-repass Item 2d (L2-T5): byte-exactness pins for `build_openai_sse`.
/// `concat(deltas) == input` byte-for-byte is the mock-layer half of the
/// `concat(deltas) == done-text` obligation. The multi-line / multi-space /
/// whitespace-only inputs FAIL under the historical `split_whitespace`
/// synthesis (which collapsed all whitespace runs to single spaces) — the
/// red half of this item's red→green witness.
#[cfg(test)]
mod sse_delta_pins {
    use super::build_openai_sse;

    fn deltas_of(sse: &str) -> Vec<String> {
        sse.lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter(|d| *d != "[DONE]")
            .filter_map(|d| serde_json::from_str::<serde_json::Value>(d).ok())
            .filter_map(|v| {
                v["choices"][0]["delta"]["content"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect()
    }

    fn concat_of(text: &str) -> (String, usize) {
        let deltas = deltas_of(&build_openai_sse(text, 7, 9, "m"));
        (deltas.concat(), deltas.len())
    }

    #[test]
    fn t_l2t5_single_space_prose_concat_exact() {
        let (concat, n) = concat_of("alpha beta gamma delta");
        assert_eq!(concat, "alpha beta gamma delta");
        assert!(n >= 2, "multi-word text still yields multiple deltas");
    }

    #[test]
    fn t_l2t5_consecutive_spaces_concat_exact() {
        let (concat, _) = concat_of("a  b");
        assert_eq!(concat, "a  b", "double space must survive byte-for-byte");
    }

    #[test]
    fn t_l2t5_multiline_concat_exact() {
        let text = "line one\nline two";
        let (concat, _) = concat_of(text);
        assert_eq!(concat, text, "newlines must survive byte-for-byte");
    }

    #[test]
    fn t_l2t5_fenced_code_block_concat_exact() {
        let text = "```rust\nfn main() {\n    println!(\"hi\");\n}\n```";
        let (concat, _) = concat_of(text);
        assert_eq!(concat, text, "code block must survive byte-for-byte");
    }

    #[test]
    fn t_l2t5_whitespace_only_input_yields_nonempty_deltas() {
        let (concat, n) = concat_of(" ");
        assert_eq!(concat, " ");
        assert!(
            n > 0,
            "whitespace-only input is content, not nothing (deliberate change)"
        );
    }

    /// The REAL regression surface of the splitter change: newline-separated
    /// text with no spaces drops from 2 deltas (split_whitespace) to 1
    /// (split_inclusive on the space byte). Deliberate and pinned — the text
    /// genuinely has no space boundary, and byte-exact concat is the property
    /// that matters.
    #[test]
    fn t_l2t5_newline_separated_no_space_is_one_delta() {
        let text = "a\nb";
        let (concat, n) = concat_of(text);
        assert_eq!(concat, text);
        assert_eq!(
            n, 1,
            "no space boundary: one delta (deliberate 2-to-1 change)"
        );
    }

    /// Trailing space: concat-only pin — the delta COUNT is unchanged by the
    /// splitter switch for this shape (both yield 2), so no count assertion.
    #[test]
    fn t_l2t5_trailing_space_concat_exact() {
        let (concat, _) = concat_of("alpha beta ");
        assert_eq!(concat, "alpha beta ");
    }

    /// CONTROL: empty input yields zero deltas under BOTH splitters (also the
    /// `.unwrap_or_default()` empty-content feed shape in cap-llm's mock).
    #[test]
    fn t_l2t5_empty_input_yields_no_deltas() {
        let (concat, n) = concat_of("");
        assert_eq!(concat, "");
        assert_eq!(n, 0);
    }
}

/// Default repetition guard when `.repetition()` is unset — never trips (back-compat).
pub(crate) struct NoOpRepetitionGuard;
impl RepetitionGuardCheck for NoOpRepetitionGuard {
    fn record_tool_call(&self, _agent_id: &str, _sig: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(&self, _agent_id: &str, _output_hash: OutputHash) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
}
