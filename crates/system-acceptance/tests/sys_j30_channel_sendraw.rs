//! SYS-J-30 — a channel `send-raw` outbound passes through the cap-http security chain
//! exactly once before the network; oversize is rejected; chain-rejection lowers to a
//! channel error; and notify-channel validates the `user:` recipient prefix.
//! Chain: MODULE-006 (messaging/notify) → MODULE-016 (channel) → MODULE-012 (cap-http).
//!
//! Witnessed test-local against the REAL `cap_channel::OutboundDispatcher` + REAL
//! `cap_http::DefaultHttpSecurityChain` (all real security steps). The network-egress leg
//! (step 7 `HttpExecutor`) is a recording `MockHttpExecutor` double — the adapter preset
//! pins an `https://` allowlist with no TLS-loopback knob, so the executor (the external
//! boundary) is doubled while every MODULE-012 security step runs real. SYS-AC-097 drives
//! the REAL `advance_messaging::MailboxDispatcherImpl::notify_channel`. No security module
//! is mocked.
//!
//! In-scope SYS-AC: 094 (lifecycle-harvest 2026-06-12), 095, 096, 097, 224.
//!
//! SYS-AC-094 (`channel.raw_sent`) — witnessed below since lifecycle-harvest:
//! the guest send-raw path's `HttpEgress` is bus-wired via the new
//! `OutboundDispatcher::new_with_event_bus`, so a successful chain pass emits
//! the redacted `channel.raw_sent` (`{adapter, body_bytes}`; the emit point is
//! the Phase-3 `HttpEgress::send` code, MODULE-016-AC-12).
//!
//! **SYS-AC-094 fidelity disclosure (user-approved at the plan gate)**: in
//! production the mailbox→send-raw hop is the WASM adapter guest's job — it
//! drains its mailbox and calls `channel-host::send-raw`. The harness has no
//! adapter guest, so the 094 test performs that hop as the guest stand-in (the
//! same host-fn-driving stand-in every passed SYS-AC uses): real
//! `MailboxDispatcherImpl::notify_channel` → real `ChannelDelivery` envelope in
//! the adapter's real mailbox → the test pops the envelope and drives the real
//! registered `send-raw` WIT handler with its body → real dispatcher → real
//! chain → recording executor + captured `channel.raw_sent`. Both product legs
//! are real; the join is the guest contract, exercised by the stand-in.

#[path = "e_support/mod.rs"]
mod e_support;

use std::sync::Arc;

use advance_messaging::{MailboxDispatcherImpl, MailboxStore};
use advance_runtime::host_registry::{HostCallContext, HostRegistry, InMemoryHostRegistry};
use advance_shared_types::agent_tree::{AgentKind, AgentTreeReader, Capability};
use advance_shared_types::mailbox::NotifyError;
use advance_shared_types::security_validator::{HttpResponse, HttpSecurityChain};
use cap_channel::{
    register_channel_host, AdapterType, ChannelConfig, ChannelHostBundle,
    HttpMethod as ChannelHttpMethod, OutboundConfig, OutboundDispatcher, SubscriptionId,
    SubscriptionManager, CHANNEL_HOST_NAMESPACE,
};
use cap_http::{DefaultHttpSecurityChain, MockHttpExecutor};
use e_support::*;
use wasmtime::component::Val;

const AGENT: &str = "agent:track-e";
const TELEGRAM_URL: &str = "https://api.telegram.org/bot123/sendMessage";

/// Wire a real channel host: real `OutboundDispatcher` over `chain`, registered into a real
/// `InMemoryHostRegistry`, with a Telegram-adapter subscription owned by `AGENT` (the
/// Telegram preset allowlist pins `https://api.telegram.org/`, matching `TELEGRAM_URL`).
fn build_channel(chain: Arc<dyn HttpSecurityChain>) -> (Arc<dyn HostRegistry>, SubscriptionId) {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let manager = Arc::new(SubscriptionManager::new());
    let outbound = Arc::new(OutboundDispatcher::new(chain, manager.clone()));
    register_channel_host(
        &*registry,
        ChannelHostBundle {
            manager: manager.clone(),
            outbound,
        },
    );
    let sub_id = manager
        .subscribe(
            AGENT.to_string(),
            ChannelConfig {
                adapter_type: AdapterType::Telegram,
                params: Vec::new(),
                outbound: Some(OutboundConfig {
                    method: ChannelHttpMethod::Post,
                    url_template: TELEGRAM_URL.into(),
                    headers: Vec::new(),
                }),
            },
        )
        .expect("subscribe");
    (registry, sub_id)
}

/// Drive the registered `send-raw` host fn (the only public caller of the outbound
/// dispatcher) as `AGENT`. Returns the host-level result `Vec<Val>`.
async fn drive_send_raw(
    registry: &Arc<dyn HostRegistry>,
    sub_id: &SubscriptionId,
    payload: &[u8],
) -> Vec<Val> {
    let spec = registry
        .lookup("channel")
        .into_iter()
        .find(|s| s.namespace == CHANNEL_HOST_NAMESPACE && s.name == "send-raw")
        .expect("send-raw handler registered");
    let ctx = HostCallContext {
        agent_id: AGENT.to_string(),
        trace_id: "trace-e30".into(),
        turn_id: None,
        capability: "channel".into(),
        function: format!("{CHANNEL_HOST_NAMESPACE}::send-raw"),
        run_id: None,
        iteration: None,
    };
    let params = vec![
        Val::String(sub_id.0.clone()),
        Val::List(payload.iter().map(|b| Val::U8(*b)).collect()),
    ];
    spec.handler
        .call(ctx, params, 0)
        .await
        .expect("host-level ok (WIT result encodes channel-error)")
}

fn is_wit_ok(vals: &[Val]) -> bool {
    matches!(vals.first(), Some(Val::Result(Ok(_))))
}

/// The WIT `channel-error` variant name from a `result::err`, if any.
fn wit_err_variant(vals: &[Val]) -> Option<String> {
    match vals.first() {
        Some(Val::Result(Err(Some(boxed)))) => match boxed.as_ref() {
            Val::Variant(name, _) => Some(name.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn ok_200() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_095_send_raw_passes_chain_exactly_once_before_network() {
    let mock =
        Arc::new(MockHttpExecutor::new().with_response("https://api.telegram.org", ok_200()));
    let tracer = StepTracer::new();
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(
        DefaultHttpSecurityChain::new(
            empty_secret_store(),
            leak(),
            ssrf_guard(&[("api.telegram.org", PUBLIC_IP)]),
            rate_allow(),
            mock.clone(),
        )
        .with_step_tracer(tracer.callback()),
    );
    let (registry, sub_id) = build_channel(chain);

    let result = drive_send_raw(&registry, &sub_id, b"hello-reply").await;
    assert!(is_wit_ok(&result), "send-raw succeeded, got {result:?}");
    assert_eq!(
        tracer.execute_count(),
        1,
        "the chain ran its full step sequence exactly once before the network"
    );
    assert_eq!(
        mock.recorded_requests.lock().unwrap().len(),
        1,
        "exactly one post-chain request reached the network-egress leg"
    );
    // The payload reached the network-egress leg unchanged (no leak, allowlisted).
    let (url, _headers) = mock.recorded_requests.lock().unwrap()[0].clone();
    assert!(
        url.starts_with("https://api.telegram.org/"),
        "outbound URL: {url}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_096_oversize_send_raw_rejected_no_outbound() {
    let mock =
        Arc::new(MockHttpExecutor::new().with_response("https://api.telegram.org", ok_200()));
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("api.telegram.org", PUBLIC_IP)]),
        rate_allow(),
        mock.clone(),
    ));
    let (registry, sub_id) = build_channel(chain);

    // 64 KiB + 1 byte → rejected at the WIT lift (MAX_SEND_RAW_BYTES = 65536), before dispatch.
    let payload = vec![b'a'; 65_536 + 1];
    let result = drive_send_raw(&registry, &sub_id, &payload).await;
    assert_eq!(
        wit_err_variant(&result).as_deref(),
        Some("invalid-config"),
        "oversize send-raw is rejected with invalid-config, got {result:?}"
    );
    assert!(
        mock.recorded_requests.lock().unwrap().is_empty(),
        "no outbound HTTP request was issued for the oversize payload"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_224_chain_rejection_lowers_to_connection_failed_no_outbound() {
    // The chain rejects the outbound at step 2 (outbound leak scan) because the payload
    // carries a credential pattern → OutboundBlocked → lowered to channel-error::connection-failed.
    let mock =
        Arc::new(MockHttpExecutor::new().with_response("https://api.telegram.org", ok_200()));
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("api.telegram.org", PUBLIC_IP)]),
        rate_allow(),
        mock.clone(),
    ));
    let (registry, sub_id) = build_channel(chain);

    let payload = format!("leaking {SECRET_OPENAI} in the body").into_bytes();
    let result = drive_send_raw(&registry, &sub_id, &payload).await;
    assert_eq!(
        wit_err_variant(&result).as_deref(),
        Some("connection-failed"),
        "chain rejection lowers to channel-error::connection-failed, got {result:?}"
    );
    assert!(
        mock.recorded_requests.lock().unwrap().is_empty(),
        "no outbound HTTP request reached the network (chain blocked at step 2)"
    );
}

// ── SYS-AC-097: notify-channel user:-prefix validation (real messaging dispatcher) ──

struct NoTree;
impl AgentTreeReader for NoTree {
    fn parent_of(&self, _: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, _: &str) -> bool {
        true
    }
    fn agent_kind(&self, _: &str) -> Option<AgentKind> {
        None
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        Vec::new()
    }
}

fn notify_dispatcher() -> MailboxDispatcherImpl {
    let store = Arc::new(MailboxStore::new(std::num::NonZeroUsize::new(64).unwrap()));
    MailboxDispatcherImpl::new(store, Arc::new(NoTree))
}

#[tokio::test]
async fn sys_ac_097_notify_channel_requires_user_prefix() {
    let d = notify_dispatcher();

    // A non-`user:`-prefixed recipient id is rejected up-front (before delivery).
    let bad = d
        .notify_channel(AGENT, "telegram", "not-a-user-id", b"hi".to_vec(), None)
        .await
        .expect_err("non-user: recipient rejected");
    match bad {
        NotifyError::InvalidTarget(msg) => assert_eq!(msg, "user_id_invalid", "got {msg:?}"),
        other => panic!("expected InvalidTarget(user_id_invalid), got {other:?}"),
    }

    // A valid `user:`-prefixed recipient passes the prefix gate and only fails later at
    // channel resolution — proving the `user:` prefix is the specific discriminating gate
    // (not a blanket rejection).
    let good_prefix = d
        .notify_channel(AGENT, "telegram", "user:alice", b"hi".to_vec(), None)
        .await
        .expect_err("unknown channel rejected after the prefix gate");
    match good_prefix {
        NotifyError::InvalidTarget(msg) => assert_eq!(msg, "channel_unknown", "got {msg:?}"),
        other => panic!("expected InvalidTarget(channel_unknown), got {other:?}"),
    }
}

// ── SYS-AC-094 — lifecycle-harvest 2026-06-12 ───────────────────────────────
// notify-channel → ChannelDelivery in the adapter mailbox → send-raw (guest
// stand-in hop; see the module-header disclosure) → chain → delivered, with
// the redacted `channel.raw_sent` captured from the bus-wired dispatcher.

struct RecordingBus(std::sync::Mutex<Vec<advance_shared_types::event::Event>>);
impl advance_shared_types::traits::EventBusEmit for RecordingBus {
    fn emit(&self, e: advance_shared_types::event::Event) {
        self.0.lock().unwrap().push(e);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_094_notify_channel_to_send_raw_emits_raw_sent() {
    use advance_messaging::{MessageTrace, StaticChannelAdapterRegistry};
    use advance_shared_types::mailbox::ChannelDelivery;

    const ADAPTER: &str = "agent:tg-adapter";

    // ── Leg 1 (real M006): notify-channel → ChannelDelivery in the adapter
    //    mailbox. Real MailboxDispatcherImpl + real StaticChannelAdapterRegistry.
    let store = Arc::new(MailboxStore::new(std::num::NonZeroUsize::new(64).unwrap()));
    let mut reg = StaticChannelAdapterRegistry::new();
    reg.insert("telegram", ADAPTER)
        .expect("register telegram adapter");
    let dispatcher = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(NoTree),
        Arc::new(MessageTrace::new()),
        Arc::new(reg),
    );
    let user_payload = b"hello from the agent".to_vec();
    dispatcher
        .notify_channel(AGENT, "telegram", "user:alice", user_payload.clone(), None)
        .await
        .expect("notify-channel delivers to the adapter mailbox");

    let mailbox = store.get(ADAPTER).expect("adapter mailbox exists");
    let msg = mailbox.poll().expect("ChannelDelivery enqueued");
    let delivery: ChannelDelivery = serde_json::from_slice(&msg.payload).expect("envelope decodes");
    assert_eq!(delivery.channel_id, "telegram");
    assert_eq!(delivery.user_id, "user:alice");
    assert_eq!(delivery.body, user_payload);

    // ── Leg 2 (real M016→M012): the adapter guest stand-in drives the REAL
    //    registered send-raw WIT handler with the delivery body, through a
    //    bus-wired dispatcher → real chain → recording executor.
    let mock =
        Arc::new(MockHttpExecutor::new().with_response("https://api.telegram.org", ok_200()));
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("api.telegram.org", PUBLIC_IP)]),
        rate_allow(),
        mock.clone(),
    ));
    let bus = Arc::new(RecordingBus(std::sync::Mutex::new(Vec::new())));
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let manager = Arc::new(SubscriptionManager::new());
    let outbound = Arc::new(OutboundDispatcher::new_with_event_bus(
        chain,
        manager.clone(),
        bus.clone(),
    ));
    register_channel_host(
        &*registry,
        ChannelHostBundle {
            manager: manager.clone(),
            outbound,
        },
    );
    let sub_id = manager
        .subscribe(
            AGENT.to_string(),
            ChannelConfig {
                adapter_type: AdapterType::Telegram,
                params: Vec::new(),
                outbound: Some(OutboundConfig {
                    method: ChannelHttpMethod::Post,
                    url_template: TELEGRAM_URL.into(),
                    headers: Vec::new(),
                }),
            },
        )
        .expect("subscribe");

    let result = drive_send_raw(&registry, &sub_id, &delivery.body).await;
    assert!(is_wit_ok(&result), "send-raw delivered, got {result:?}");
    assert_eq!(
        mock.recorded_requests.lock().unwrap().len(),
        1,
        "the message went out via the chain's network-egress leg"
    );

    // ── Observable: channel.raw_sent, redacted ({adapter, body_bytes} only).
    let events = bus.0.lock().unwrap();
    let raw_sent: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "channel.raw_sent")
        .collect();
    assert_eq!(
        raw_sent.len(),
        1,
        "exactly one channel.raw_sent: {events:?}"
    );
    let e = raw_sent[0];
    assert_eq!(e.payload["adapter"], "telegram");
    assert_eq!(e.payload["body_bytes"], delivery.body.len());
    let dump = serde_json::to_string(&e.payload).unwrap();
    assert!(!dump.contains("hello from the agent"), "no body in payload");
    assert!(!dump.contains("api.telegram.org"), "no target in payload");
    assert!(!dump.contains("user:alice"), "no recipient in payload");
}
