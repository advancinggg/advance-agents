//! /dev Phase-2 Step-3 — SYS-AC-001 channel reply round-trip witness (SYS-J-01).
//!
//! External message posted to a channel adapter → a reply delivered back out the
//! SAME adapter, correlated to the originating conversation. Wired end-to-end over
//! the REAL module chain; only the external Telegram peer is doubled:
//!   POST /hooks (Telegram update) → `TelegramVerifier` → `enqueue_event`
//!     → `poll_host_pump` pump → `Message`(origin) → `serve` turn (counter guest)
//!     → `DaemonOutboundSink`/`ChannelEgress` → `HttpEgress` → REAL `DefaultHttpSecurityChain`
//!       (allowlist + SSRF + leak + method/CRLF) → recording `HttpExecutor`.
//!
//! The witness asserts the recorded outbound `sendMessage` request targets the
//! preset Telegram host AND carries the inbound `chat_id` — the reply is
//! correlated to the originating conversation. A second test drives ONE
//! subscription / TWO conversations and asserts the replies fan to the two
//! distinct `chat_id`s (the ADR-mandated fan-out test). The chain is REAL (not a
//! CapturingChain shortcut); only the executor + DNS resolver are doubled — the
//! witness-floor pattern (real full chain, only the external peer doubled).

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::ComponentRuntime;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind, MessageOrigin};
use advance_shared_types::security_validator::{
    HttpRequest, HttpResponse, HttpSecurityChain, LeakDetector, RedirectCheck, SsrfGuard,
};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};

use advance_cli::agent_loop::{build_agent_loop, WasmMessageHandler};
use advance_cli::channel_egress::{ChannelEgress, DaemonOutboundSink};
use advance_cli::reply::ReplyRegistry;

use advance_messaging::{MailboxStore, OutboundActionSink};
use advance_scheduler::hook::{MessageHandler, TurnObserver};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};

use cap_channel::{
    AdapterType, ChannelConfig, HttpEgress, HttpMethod, OutboundConfig, OutboundTransport,
    SubscriptionId, SubscriptionManager, TelegramVerifier, TransportSupervisor,
};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultRateLimiter, DefaultSsrfGuard,
    ExecutorError, HttpExecutor, MockResolver, RateLimiter,
};
use cap_secrets::{InMemorySecretStorage, SecretStore};
use zeroize::Zeroizing;

const COUNTER_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-counter.core.wasm");
const TG_SECRET: &str = "tg-secret-token";
const TG_URL: &str = "https://api.telegram.org/bot123/sendMessage";

struct NullBus;
impl EventBusEmit for NullBus {
    fn emit(&self, _e: Event) {}
}
struct AllowAllGrant;
impl GrantCheck for AllowAllGrant {
    fn check(&self, _a: &str, _c: &str, _f: &str, _p: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

/// Records every outbound request the REAL chain forwards, returns a canned 200.
/// (The chain runs SSRF/allowlist/leak BEFORE this; the executor is the external
/// peer double.)
struct RecordingExecutor {
    sent: Arc<Mutex<Vec<HttpRequest>>>,
}
#[async_trait::async_trait]
impl HttpExecutor for RecordingExecutor {
    async fn execute(
        &self,
        req: &HttpRequest,
        _redirect: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        self.sent.lock().unwrap().push(req.clone());
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: b"{\"ok\":true}".to_vec(),
        })
    }
}

/// Notifies on each serve turn boundary.
struct TurnSignal {
    tx: tokio::sync::mpsc::UnboundedSender<()>,
}
impl TurnObserver for TurnSignal {
    fn on_turn_complete(&self, _a: &str) {
        let _ = self.tx.send(());
    }
}

/// Build the REAL chain with a recording executor + a MockResolver that resolves
/// the Telegram host to a public IP (so the real SSRF guard passes; no network).
fn recording_chain(sent: Arc<Mutex<Vec<HttpRequest>>>) -> Arc<dyn HttpSecurityChain> {
    let secret_store = Arc::new(SecretStore::new(
        Zeroizing::new([0u8; 32]),
        Arc::new(InMemorySecretStorage::new()),
    ));
    let leak: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let resolver = MockResolver::new().with("api.telegram.org", vec!["8.8.8.8".parse().unwrap()]);
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn RateLimiter> = Arc::new(DefaultRateLimiter::new());
    let exec: Arc<dyn HttpExecutor> = Arc::new(RecordingExecutor { sent });
    Arc::new(DefaultHttpSecurityChain::new(
        secret_store,
        leak,
        ssrf,
        rl,
        exec,
    ))
}

fn runtime() -> Arc<ComponentRuntime> {
    Arc::new(
        ComponentRuntime::new(&WasmConfig {
            max_memory_pages: 256,
            epoch_interruption_ms: 100,
            fuel_enabled: false,
        })
        .expect("runtime"),
    )
}

fn counter_handler(rt: Arc<ComponentRuntime>, agent: &str) -> Arc<dyn MessageHandler> {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let inj = Arc::new(CapabilityInjector::new(
        registry,
        Arc::new(AllowAllGrant),
        Arc::new(DefaultCircuitBreakerBus::new()),
    ));
    let component =
        build_agent::encode_core_to_component(COUNTER_CORE).expect("encode counter core");
    let loaded = rt.load_component(&component).expect("load");
    Arc::new(WasmMessageHandler::new(
        rt,
        loaded,
        inj,
        vec![],
        agent.to_string(),
        "trace-ch".into(),
    ))
}

/// Telegram update JSON for `(chat_id, from_id)`.
fn tg_update(chat_id: i64, from_id: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "update_id": 1,
        "message": {
            "message_id": 7,
            "date": 1_700_000_000u64,
            "chat": { "id": chat_id, "type": "private" },
            "from": { "id": from_id, "is_bot": false, "first_name": "U" },
            "text": "hello bot"
        }
    }))
    .unwrap()
}

/// Drain one event from the host pump and build the inbound `Message` (the daemon
/// pump's job): copy the whole `channel.*` bag into `MessageOrigin.channel_metadata`.
fn pump_one(mgr: &SubscriptionManager, sub_id: &SubscriptionId, agent: &str) -> Option<Message> {
    let raw = mgr.poll_host_pump(sub_id).ok()??;
    let meta: HashMap<String, String> = raw
        .metadata
        .iter()
        .map(|p| (p.key.clone(), p.value.clone()))
        .collect();
    let origin = MessageOrigin {
        message_id: "in".into(),
        original_channel: meta.get("channel.adapter").cloned().unwrap_or_default(),
        original_sender: meta.get("channel.sender_id").cloned().unwrap_or_default(),
        adapter_id: agent.to_string(),
        channel_metadata: meta,
        received_at: advance_shared_types::chrono::Utc::now(),
        context: None,
    };
    Some(Message {
        id: "in".into(),
        kind: MessageKind::User,
        from: "user:alice".into(),
        to: agent.into(),
        payload: raw.data,
        context: None,
        timestamp: SystemTime::now(),
        origin: Some(origin),
    })
}

/// Wire the full channel stack (manager + recording chain + egress + supervisor +
/// serve loop) and return the moving parts the test drives.
struct ChannelHarness {
    manager: Arc<SubscriptionManager>,
    supervisor: Arc<TransportSupervisor>,
    sub_id: SubscriptionId,
    store: Arc<MailboxStore>,
    sent: Arc<Mutex<Vec<HttpRequest>>>,
    turn_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
    _serve_task: tokio::task::JoinHandle<()>,
    agent: String,
}

fn wire(agent: &str) -> ChannelHarness {
    let manager = Arc::new(SubscriptionManager::new());
    let sub_id = manager
        .subscribe_host_pump(
            agent,
            ChannelConfig {
                adapter_type: AdapterType::Telegram,
                params: vec![],
                outbound: Some(OutboundConfig {
                    method: HttpMethod::Post,
                    url_template: TG_URL.into(),
                    headers: vec![("Content-Type".into(), "application/json".into())],
                }),
            },
        )
        .unwrap();

    let supervisor = Arc::new(TransportSupervisor::new(manager.clone()));
    supervisor
        .register_webhook(
            "tg",
            sub_id.clone(),
            AdapterType::Telegram,
            Arc::new(TelegramVerifier::new(TG_SECRET)),
        )
        .unwrap();

    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport: Arc<dyn OutboundTransport> =
        Arc::new(HttpEgress::new(recording_chain(sent.clone())));

    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let sink: Arc<dyn OutboundActionSink> = Arc::new(DaemonOutboundSink::with_channel(
        Arc::new(ReplyRegistry::new()),
        ChannelEgress::new(transport, manager.clone()),
    ));
    let (tx, turn_rx) = tokio::sync::mpsc::unbounded_channel();
    let observer: Arc<dyn TurnObserver> = Arc::new(TurnSignal { tx });

    let handler = counter_handler(runtime(), agent);
    let driver = build_agent_loop(store.clone(), handler, Arc::new(NullBus), Some(sink))
        .with_turn_observer(observer);
    let cfg = ComponentConfig {
        id: agent.into(),
        config_data: None,
        trigger_context: None,
    };
    let instance = WasmInstance::new(ComponentId::new("ch-inst".into()).unwrap());
    let agent_owned = agent.to_string();
    let serve_task = tokio::spawn(async move { driver.serve(&agent_owned, cfg, instance).await });

    ChannelHarness {
        manager,
        supervisor,
        sub_id,
        store,
        sent,
        turn_rx,
        _serve_task: serve_task,
        agent: agent.to_string(),
    }
}

impl ChannelHarness {
    /// Post a Telegram update, drive the pump, and wait for the turn's egress.
    async fn deliver_update_and_await_turn(&mut self, chat_id: i64, from_id: i64) {
        let headers = vec![(
            "X-Telegram-Bot-Api-Secret-Token".to_string(),
            TG_SECRET.to_string(),
        )];
        let resp = self
            .supervisor
            .dispatch_inbound("tg", &headers, &tg_update(chat_id, from_id));
        assert_eq!(resp.status, 200, "verified inbound enqueues");
        // Pump → Message → mailbox (wakes serve).
        let msg =
            pump_one(&self.manager, &self.sub_id, &self.agent).expect("pump builds a message");
        self.store
            .get_or_create(&self.agent)
            .unwrap()
            .deliver(msg)
            .unwrap();
        // Wait for the serve turn (which egresses the reply) to complete.
        tokio::time::timeout(Duration::from_secs(15), self.turn_rx.recv())
            .await
            .expect("turn completed within 15s")
            .expect("observer open");
    }
}

fn body_chat_id(req: &HttpRequest) -> String {
    let v: serde_json::Value = serde_json::from_slice(&req.body).expect("telegram body is JSON");
    v["chat_id"].as_str().unwrap_or_default().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn external_message_yields_reply_back_out_same_adapter_correlated() {
    let mut h = wire("agent:default");
    h.deliver_update_and_await_turn(98765, 4242).await;

    let sent = h.sent.lock().unwrap().clone();
    assert_eq!(
        sent.len(),
        1,
        "exactly one outbound reply through the real chain"
    );
    let req = &sent[0];
    // Reply delivered back out the SAME adapter (preset Telegram host), correlated
    // to the originating conversation (chat_id).
    assert_eq!(req.url, TG_URL, "host stays the preset Telegram endpoint");
    assert_eq!(
        body_chat_id(req),
        "98765",
        "reply correlated to the inbound chat_id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_subscription_two_conversations_fan_out_to_correct_chats() {
    // The ADR-mandated test: one subscription fans replies to many conversations.
    let mut h = wire("agent:default");
    h.deliver_update_and_await_turn(98765, 4242).await;
    h.deliver_update_and_await_turn(11111, 5555).await;

    let sent = h.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 2, "two replies, one per inbound conversation");
    let chats: Vec<String> = sent.iter().map(body_chat_id).collect();
    assert_eq!(
        chats,
        vec!["98765".to_string(), "11111".to_string()],
        "each reply fans to its own conversation's chat_id (no cross-talk)"
    );
    // Both went out the same preset host.
    for req in &sent {
        assert_eq!(req.url, TG_URL);
    }
}
