//! Wave-19 Lane-2 — `AgentIdBridge` dispatcher-integration witnesses (TB-IDB-02).
//!
//! These drive the REAL `MailboxDispatcherImpl::deliver_notify` over a BARE-keyed
//! `TestTree` whose node is `default-agent` (so the colon target `agent:default`
//! MISSES `agent_exists` — the production residual). With the bridge wired, a
//! `notify_agent`/`notify_channel` to the colon form resolves to the bare
//! membership key + the canonical mailbox key and DELIVERS; without it, the
//! colon target returns `target_unknown` (the bridge is LOAD-BEARING — the
//! anti-fake-green discriminator). The malformed/non-member cases still reject,
//! so `is_safe_id`'s safety property is preserved.
//!
//! The STRONG witness (over the REAL `cap-lifecycle::AgentTreeStore`) lives in
//! `crates/system-acceptance/tests/id_bridge_notify.rs`.

mod common;

use std::sync::Arc;

use advance_messaging::{
    AgentIdBridge, ChannelAdapterRegistry, ChannelDelivery, EmptyChannelAdapterRegistry,
    MailboxDispatcher, MailboxDispatcherImpl, MailboxStore, MessageTrace, NotifyError,
    DEFAULT_CAPACITY,
};
use advance_shared_types::mailbox::Message;

use crate::common::{static_registry, TestTree};

/// Build a dispatcher over the given bare-keyed tree + optional registry, with an
/// OPTIONAL id-bridge. `bridge_pairs` empty → no bridge wired (`None`, the
/// byte-identical default).
fn dispatcher(
    tree: TestTree,
    registry_pairs: &[(&str, &str)],
    bridge_pairs: &[(&str, &str)],
) -> (Arc<MailboxStore>, MailboxDispatcherImpl) {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let registry: Arc<dyn ChannelAdapterRegistry> = if registry_pairs.is_empty() {
        Arc::new(EmptyChannelAdapterRegistry)
    } else {
        Arc::new(static_registry(registry_pairs))
    };
    let mut d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        registry,
    );
    if !bridge_pairs.is_empty() {
        let owned: Vec<(String, String)> = bridge_pairs
            .iter()
            .map(|(m, b)| (m.to_string(), b.to_string()))
            .collect();
        d = d.with_id_bridge(Arc::new(AgentIdBridge::from_pairs(owned)));
    }
    (store, d)
}

async fn recv(store: &MailboxStore, agent: &str) -> Message {
    store.get(agent).expect("mailbox exists").recv().await
}

// TB-IDB-02a — bridge-on: a colon `notify_agent` target resolves to the bare
// tree node + the canonical mailbox key and DELIVERS, where the bare tree alone
// would miss. Pins both halves: membership (bare key) + mailbox keying (canonical).
#[tokio::test]
async fn tb_idb_02a_bridge_delivers_via_alias() {
    // PRODUCTION-shaped: the tree node is BARE `default-agent`.
    let tree = TestTree::new().add_root("default-agent");
    let (store, d) = dispatcher(tree, &[], &[("agent:default", "default-agent")]);

    d.notify_agent("system", "agent:default", vec![7], None)
        .await
        .expect("bridge resolves agent:default -> default-agent membership; delivers");

    // The message lands under the CANONICAL mailbox key (the serve-loop poll key),
    // NOT the bare tree key.
    let msg = recv(&store, "agent:default").await;
    assert_eq!(msg.from, "system");
    assert_eq!(msg.to, "agent:default", "msg.to == canonical mailbox key");
    assert_eq!(msg.payload, vec![7]);
    // And NOT under the bare key (no orphan / double mailbox).
    assert!(
        store.get("default-agent").is_none(),
        "delivery must NOT create a bare-keyed mailbox"
    );
}

// TB-IDB-02b — anti-fake-green: WITHOUT the bridge, the same colon target against
// the same bare tree returns `target_unknown` and delivers nothing. Proves the
// bridge is LOAD-BEARING (not a no-op).
#[tokio::test]
async fn tb_idb_02b_no_bridge_target_unknown() {
    let tree = TestTree::new().add_root("default-agent");
    let (store, d) = dispatcher(tree, &[], &[]); // no bridge

    let err = d
        .notify_agent("system", "agent:default", vec![7], None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::InvalidTarget("target_unknown".into()));
    assert!(store.get("agent:default").is_none());
    assert!(store.get("default-agent").is_none());
}

// TB-IDB-02c — safety preserved: a multi-colon (is_safe_id-malformed) target is
// rejected at the is_safe_id gate BEFORE the bridge; a syntactically-valid but
// NON-member colon target (the `agent:default-agent` orphan-key trap) resolves to
// None → bare `agent_exists` miss → target_unknown. Neither delivers anything.
#[tokio::test]
async fn tb_idb_02c_malformed_and_nonmember_reject() {
    let tree = TestTree::new().add_root("default-agent");
    let (store, d) = dispatcher(tree, &[], &[("agent:default", "default-agent")]);

    // multi-colon → is_safe_id rejects first → invalid_id.
    let e1 = d
        .notify_agent("system", "agent:a:b", vec![1], None)
        .await
        .unwrap_err();
    assert_eq!(e1, NotifyError::InvalidTarget("invalid_id".into()));

    // is_safe_id-valid but NOT a bridge member; its bare strip (`default-agent`)
    // WOULD match the tree, but the no-strip-fallback design means it is NOT
    // bridged → bare tree miss on `agent:default-agent` → target_unknown (no
    // orphan delivery to `default-agent`).
    let e2 = d
        .notify_agent("system", "agent:default-agent", vec![2], None)
        .await
        .unwrap_err();
    assert_eq!(e2, NotifyError::InvalidTarget("target_unknown".into()));

    assert!(store.get("agent:default-agent").is_none());
    assert!(store.get("default-agent").is_none());
    assert!(store.get("agent:default").is_none());
}

// TB-IDB-02d — notify_channel through the bridge: a registered channel resolves
// to a colon adapter id, which the bridge maps to a bare adapter tree node →
// real `ChannelDelivery` envelope delivered to the adapter's canonical mailbox.
#[tokio::test]
async fn tb_idb_02d_notify_channel_via_alias() {
    // Bare adapter tree node; registry maps the channel to its COLON adapter id.
    let tree = TestTree::new().add_root("chan-adapter");
    let (store, d) = dispatcher(
        tree,
        &[("slack", "agent:chan-adapter")],
        &[("agent:chan-adapter", "chan-adapter")],
    );

    d.notify_channel("system", "slack", "user:bob", b"hello-chan".to_vec(), None)
        .await
        .expect("registered channel + bridge resolves the adapter -> delivers");

    let msg = recv(&store, "agent:chan-adapter").await;
    let env: ChannelDelivery =
        serde_json::from_slice(&msg.payload).expect("ChannelDelivery envelope");
    assert_eq!(env.channel_id, "slack");
    assert_eq!(env.user_id, "user:bob");
    assert_eq!(env.body, b"hello-chan".to_vec());
}

// TB-IDB-02e — notify_channel anti-fake-green: registered channel but NO bridge →
// the colon adapter misses the bare tree → target_unknown (NOT channel_unknown,
// which is the distinct unregistered-channel branch). Nothing delivered.
#[tokio::test]
async fn tb_idb_02e_notify_channel_no_bridge_target_unknown() {
    let tree = TestTree::new().add_root("chan-adapter");
    let (store, d) = dispatcher(tree, &[("slack", "agent:chan-adapter")], &[]); // no bridge

    let err = d
        .notify_channel("system", "slack", "user:bob", b"x".to_vec(), None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::InvalidTarget("target_unknown".into()));
    assert!(store.get("agent:chan-adapter").is_none());
}
