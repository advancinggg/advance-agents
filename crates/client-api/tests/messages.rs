//! MODULE-020-AC-08 witness (e2e cell — BUILT + HELD): messaging controls send a user message to an
//! agent and surface delivery/reply state through the Client API.
//!
//! Drives `ClientApi::handle()` end-to-end (POST /client/messages, GET /client/messages/{id}) against
//! a REAL MODULE-006 `MailboxDispatcherImpl`: the message lands in the target's REAL mailbox with the
//! correct from/origin, a trace is recorded so the recipient's reply routes back, and recipient-only
//! reply authz is exercised on the REAL dispatcher. Raw `MsgError` never leaks — it is projected
//! operation-scoped to a stable client code. Module-altitude in-process witness; the system-altitude
//! e2e is Wave-25, so §3.4 keeps AC-08 `untested` (build-and-hold, §3.6).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_client_api::{
    ClientApi, ClientApiConfig, ClientErrorCode, ClientMessageAck, ClientMessageStatus,
    ClientRequest, ClientSession, MessagingProvider, Platform, Principal, ProviderError, Scope,
};

use advance_messaging::{
    EmptyChannelAdapterRegistry, MailboxDispatcher, MailboxDispatcherImpl, MailboxStore,
    MessageTrace, MsgError, DEFAULT_CAPACITY,
};
use advance_shared_types::agent_tree::{AgentKind, AgentTreeReader, Capability};
use advance_shared_types::chrono::Utc;
use advance_shared_types::mailbox::{Message, MessageKind, MessageOrigin};

// ── TestTree (copied from messaging's own tests/common) — supervisor with two adjacent children ──

struct TestTree {
    parents: HashMap<String, Option<String>>,
}
impl TestTree {
    fn new() -> Self {
        Self {
            parents: HashMap::new(),
        }
    }
    fn add_root(mut self, id: &str) -> Self {
        self.parents.insert(id.to_string(), None);
        self
    }
    fn add_child(mut self, id: &str, parent: &str) -> Self {
        self.parents
            .insert(id.to_string(), Some(parent.to_string()));
        self
    }
}
impl AgentTreeReader for TestTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        self.parents.get(agent_id).cloned().flatten()
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        self.parents.contains_key(agent_id)
    }
    fn children_of(&self, _: &str) -> Vec<String> {
        unimplemented!()
    }
    fn siblings_of(&self, _: &str) -> Vec<String> {
        unimplemented!()
    }
    fn agent_kind(&self, _: &str) -> Option<AgentKind> {
        unimplemented!()
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        unimplemented!()
    }
}

// ── Real-provider adapter (production wiring is Wave-25 cli; the witness supplies it) ──

const ADAPTER_ID: &str = "agent:console-adapter";

fn map_deliver_err(e: MsgError) -> ProviderError {
    match e {
        MsgError::InvalidTarget(_) => ProviderError::NotFound("target".into()),
        MsgError::InvalidPayload(_) => ProviderError::TooLarge("payload".into()),
        MsgError::MailboxFull => ProviderError::Unavailable("mailbox_full".into()),
        MsgError::CircuitBreakerOpen(_) => ProviderError::Unavailable("breaker".into()),
        MsgError::CapabilityDenied(_) => ProviderError::NotAuthorized("capability".into()),
    }
}
/// reply(): only InvalidTarget("reply_not_authorized") is an authz denial; every other InvalidTarget
/// is a not-found.
fn map_reply_err(e: MsgError) -> ProviderError {
    match e {
        MsgError::InvalidTarget(s) if s == "reply_not_authorized" => {
            ProviderError::NotAuthorized("reply".into())
        }
        MsgError::InvalidTarget(_) => ProviderError::NotFound("reply_target".into()),
        MsgError::InvalidPayload(_) => ProviderError::TooLarge("payload".into()),
        MsgError::MailboxFull => ProviderError::Unavailable("mailbox_full".into()),
        MsgError::CircuitBreakerOpen(_) => ProviderError::Unavailable("breaker".into()),
        MsgError::CapabilityDenied(_) => ProviderError::NotAuthorized("capability".into()),
    }
}

struct SentState {
    to: String,
    replied: bool,
}

struct DispatcherMessaging {
    rt: Arc<tokio::runtime::Runtime>,
    dispatcher: Arc<MailboxDispatcherImpl>,
    store: Arc<MailboxStore>,
    counter: AtomicU64,
    sent: Mutex<HashMap<String, SentState>>,
}
impl DispatcherMessaging {
    /// Drain the client-adapter mailbox, marking sent messages replied by their reply's in_reply_to.
    fn drain_replies(&self) {
        if let Some(mb) = self.store.get(ADAPTER_ID) {
            while let Some(msg) = mb.poll() {
                if let Some(irt) = msg.context.as_ref().and_then(|c| c.in_reply_to.clone()) {
                    if let Some(st) = self.sent.lock().unwrap().get_mut(&irt) {
                        st.replied = true;
                    }
                }
            }
        }
    }
}
impl MessagingProvider for DispatcherMessaging {
    fn send(&self, to: &str, payload: &[u8]) -> Result<ClientMessageAck, ProviderError> {
        let message_id = format!("cmsg-{}", self.counter.fetch_add(1, Ordering::SeqCst));
        let msg = Message {
            id: message_id.clone(),
            kind: MessageKind::User,
            from: ADAPTER_ID.to_string(),
            to: to.to_string(),
            payload: payload.to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        self.rt
            .block_on(self.dispatcher.deliver(to, msg))
            .map_err(map_deliver_err)?;
        // Record the trace so the recipient's reply(to_message_id) routes back to the client-adapter.
        let origin = MessageOrigin {
            message_id: message_id.clone(),
            original_channel: "client".to_string(),
            original_sender: "user:operator".to_string(),
            adapter_id: ADAPTER_ID.to_string(),
            channel_metadata: HashMap::new(),
            received_at: Utc::now(),
            context: None,
        };
        self.dispatcher
            .trace()
            .record(&message_id, origin, to)
            .map_err(map_deliver_err)?;
        self.sent.lock().unwrap().insert(
            message_id.clone(),
            SentState {
                to: to.to_string(),
                replied: false,
            },
        );
        Ok(ClientMessageAck {
            message_id,
            to: to.to_string(),
            delivery_state: "delivered".to_string(),
        })
    }
    fn message_status(&self, message_id: &str) -> Result<ClientMessageStatus, ProviderError> {
        self.drain_replies();
        let sent = self.sent.lock().unwrap();
        let st = sent
            .get(message_id)
            .ok_or_else(|| ProviderError::NotFound("message".into()))?;
        Ok(ClientMessageStatus {
            message_id: message_id.to_string(),
            to: st.to.clone(),
            from: ADAPTER_ID.to_string(),
            delivery_state: "delivered".to_string(),
            reply_state: if st.replied { "replied" } else { "none" }.to_string(),
            stream_key: None,
        })
    }
}

// ── Scaffolding ──

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>) {
    let session = ClientSession {
        session_id: format!("sess-{token}"),
        principal: Principal {
            id: "operator".to_string(),
            os_user: "op".to_string(),
        },
        platform: Platform::Mac,
        scopes,
        csrf_token: None,
        expires_at: u64::MAX,
    };
    api.sessions().insert(token.to_string(), session, 0);
}

struct Fixture {
    api: ClientApi,
    store: Arc<MailboxStore>,
    dispatcher: Arc<MailboxDispatcherImpl>,
    rt: Arc<tokio::runtime::Runtime>,
}

fn fixture() -> Fixture {
    // console-adapter and worker are SIBLINGS under supervisor → adjacent for validate_routing.
    let tree = TestTree::new()
        .add_root("agent:supervisor")
        .add_child(ADAPTER_ID, "agent:supervisor")
        .add_child("agent:worker", "agent:supervisor");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let trace = Arc::new(MessageTrace::new());
    let dispatcher = Arc::new(MailboxDispatcherImpl::new_full(
        Arc::clone(&store),
        Arc::new(tree),
        trace,
        Arc::new(EmptyChannelAdapterRegistry),
    ));
    let rt = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime"),
    );
    let adapter = DispatcherMessaging {
        rt: Arc::clone(&rt),
        dispatcher: Arc::clone(&dispatcher),
        store: Arc::clone(&store),
        counter: AtomicU64::new(0),
        sent: Mutex::new(HashMap::new()),
    };
    let api = ClientApi::new(ClientApiConfig::default()).with_messaging_provider(Arc::new(adapter));
    mint(&api, "tok", vec![Scope::SendMessages, Scope::ReadMessages]);
    Fixture {
        api,
        store,
        dispatcher,
        rt,
    }
}

fn send(
    api: &ClientApi,
    to: &str,
    payload: &str,
    key: &str,
) -> advance_client_api::ClientEnvelope<serde_json::Value> {
    api.handle(
        ClientRequest::post(
            "/client/messages",
            serde_json::json!({ "to": to, "payload": payload }),
        )
        .with_session("tok")
        .with_idempotency_key(key),
    )
}

// ── T08 ──

#[test]
fn t08_send_delivers_and_surfaces_reply_state() {
    let fx = fixture();

    // T08a deliver: the message lands in the target's REAL mailbox with correct from/payload.
    let ack_env = send(&fx.api, "agent:worker", "hello", "k-send");
    assert!(ack_env.is_ok(), "send ok: {:?}", ack_env.error);
    let ack: ClientMessageAck = serde_json::from_value(ack_env.data.clone().unwrap()).unwrap();
    assert_eq!(ack.to, "agent:worker");
    assert_eq!(ack.delivery_state, "delivered");
    let message_id = ack.message_id.clone();

    let worker_mb = fx
        .store
        .get("agent:worker")
        .expect("target mailbox created by deliver");
    assert_eq!(worker_mb.depth(), 1);
    let got = worker_mb.poll().expect("delivered message present");
    assert_eq!(
        got.from, ADAPTER_ID,
        "delivered with the client-adapter as sender"
    );
    assert_eq!(got.to, "agent:worker");
    assert_eq!(got.payload, b"hello");

    // T08b status: before any reply → delivered / none.
    let st0 = get_status(&fx.api, &message_id);
    assert_eq!(st0.delivery_state, "delivered");
    assert_eq!(st0.reply_state, "none");

    // Recipient replies on the REAL dispatcher → routes back to the client-adapter (trace-driven).
    fx.rt
        .block_on(
            fx.dispatcher
                .reply("agent:worker", &message_id, b"ack".to_vec()),
        )
        .expect("authorized reply");

    // T08b status: after the reply → delivered / replied (surfaced through GET message).
    let st1 = get_status(&fx.api, &message_id);
    assert_eq!(
        st1.reply_state, "replied",
        "reply state surfaced through the Client API"
    );
}

fn get_status(api: &ClientApi, message_id: &str) -> ClientMessageStatus {
    let env = api
        .handle(ClientRequest::get(format!("/client/messages/{message_id}")).with_session("tok"));
    assert!(env.is_ok(), "status ok: {:?}", env.error);
    serde_json::from_value(env.data.unwrap()).unwrap()
}

#[test]
fn t08c_recipient_only_reply_authz() {
    let fx = fixture();
    let ack: ClientMessageAck =
        serde_json::from_value(send(&fx.api, "agent:worker", "hi", "k").data.unwrap()).unwrap();

    // A non-recipient (the console-adapter, which is NOT the delivered-to recipient) attempting a
    // reply → REAL InvalidTarget("reply_not_authorized") on the dispatcher, which the adapter
    // projects to the stable reply_not_authorized client code (raw MsgError never leaks).
    let err = fx
        .rt
        .block_on(
            fx.dispatcher
                .reply(ADAPTER_ID, &ack.message_id, b"x".to_vec()),
        )
        .expect_err("non-recipient reply is rejected");
    assert_eq!(err, MsgError::InvalidTarget("reply_not_authorized".into()));
    let projected = map_reply_err(err).into_client_error();
    assert_eq!(projected.code, ClientErrorCode::ReplyNotAuthorized);
}

#[test]
fn t08d_unknown_agent_and_oversize_project_to_stable_codes() {
    let fx = fixture();

    // Unknown target agent → deliver's validate_routing InvalidTarget("unknown_target") →
    // projected to not_found (raw MsgError never leaks).
    let env = send(&fx.api, "agent:ghost", "hi", "k1");
    assert_eq!(env.error_code(), Some(ClientErrorCode::NotFound));

    // Oversize payload → rejected as request_too_large (the s1 body-size gate fires before the
    // provider; the adapter's InvalidPayload→TooLarge mapping is the same client code).
    let big = "x".repeat(2 * 1024 * 1024);
    let env = send(&fx.api, "agent:worker", &big, "k2");
    assert_eq!(env.error_code(), Some(ClientErrorCode::RequestTooLarge));

    // The adapter's own oversize mapping is exercised directly too.
    let projected =
        map_deliver_err(MsgError::InvalidPayload("payload_too_large".into())).into_client_error();
    assert_eq!(projected.code, ClientErrorCode::RequestTooLarge);
}

#[test]
fn t08e_idempotent_replay_does_not_double_deliver() {
    let fx = fixture();
    let first = send(&fx.api, "agent:worker", "hello", "same-key");
    assert!(first.is_ok());
    // Replay with the SAME idempotency key → the handler does NOT run again (exactly-once).
    let replay = send(&fx.api, "agent:worker", "hello", "same-key");
    assert!(replay
        .warnings
        .iter()
        .any(|w| w.code == "idempotent_replay"));

    // The target mailbox depth stays 1 — the replay did NOT deliver a second copy.
    let worker_mb = fx.store.get("agent:worker").expect("mailbox");
    assert_eq!(worker_mb.depth(), 1, "replay must not double-deliver");
}

#[test]
fn t08_send_scope_and_absent_provider() {
    let fx = fixture();
    // Under-scoped session (no SendMessages) → forbidden.
    mint(&fx.api, "tok-ro", vec![Scope::ReadMessages]);
    let env = fx.api.handle(
        ClientRequest::post(
            "/client/messages",
            serde_json::json!({ "to": "agent:worker", "payload": "x" }),
        )
        .with_session("tok-ro")
        .with_idempotency_key("k"),
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::Forbidden));

    // Absent messaging provider → module_unavailable.
    let bare = ClientApi::new(ClientApiConfig::default());
    mint(&bare, "tok", vec![Scope::SendMessages]);
    let env = bare.handle(
        ClientRequest::post(
            "/client/messages",
            serde_json::json!({ "to": "agent:worker", "payload": "x" }),
        )
        .with_session("tok")
        .with_idempotency_key("k"),
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::ModuleUnavailable));
}
