//! Wave-19 Lane-2 — the STRONG `AgentIdBridge` witness over the REAL
//! `cap-lifecycle::AgentTreeStore` (TB-IDB-03/04/05).
//!
//! Unlike the messaging-crate stub-tree witnesses (`crates/messaging/tests/
//! id_bridge.rs`, which use a generic string-keyed `TestTree`), this drives the
//! REAL production `AgentTreeStore` — bare-keyed, with `agent_exists` gated on
//! `validate_agent_id` (charset `[A-Za-z0-9_-]`, colon-REJECTING). That is the
//! production tree TYPE the §3.6 AC-02 residual is about. With the bridge wired,
//! a colon `notify_agent`/`notify_channel` target resolves to the bare tree node
//! + the canonical mailbox key and DELIVERS; without it, the real tree's
//! `agent_exists(colon)` is false → `target_unknown`. The bridge is therefore
//! LOAD-BEARING against the genuine production keying — not a permissive stub.
//!
//! This is a BUILD-ONLY witness for the AgentIdBridge building block; it does
//! NOT flip MODULE-006-AC-02 (the bridge is not wired into the production cli
//! composition root in this lane — see MODULE-006 §3.6 AC-02 row / §3.8 (k)).

use std::sync::Arc;

use advance_messaging::{
    AgentIdBridge, ChannelAdapterRegistry, ChannelDelivery, EmptyChannelAdapterRegistry,
    MailboxDispatcher, MailboxDispatcherImpl, MailboxStore, MessageTrace, NotifyError,
    StaticChannelAdapterRegistry, DEFAULT_CAPACITY,
};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use cap_lifecycle::AgentTreeStore;
use tempfile::TempDir;

const ROOT_BARE: &str = "default-agent";
const ROOT_COLON: &str = "agent:default";
const ADAPTER_BARE: &str = "chan-adapter";
const ADAPTER_COLON: &str = "agent:chan-adapter";
const CHANNEL: &str = "slack";

fn node(id: &str, kind: AgentKind, parent: Option<&str>, ws: std::path::PathBuf) -> AgentNode {
    AgentNode {
        id: AgentId(id.into()),
        kind,
        parent: parent.map(|p| AgentId(p.into())),
        workspace_path: ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    }
}

/// Build a REAL bare-keyed `AgentTreeStore` (root `default-agent` + a child
/// adapter `chan-adapter`) + a `MailboxDispatcherImpl`. When `wire_bridge`, the
/// dispatcher carries the colon/bare `AgentIdBridge` for both ids; when
/// `register_channel`, the static registry maps `slack → agent:chan-adapter`.
/// Returns the `TempDir` (must be held for the test's lifetime — the tree
/// canonicalizes against it) + the shared store + the dispatcher.
fn build(
    wire_bridge: bool,
    register_channel: bool,
) -> (TempDir, Arc<MailboxStore>, MailboxDispatcherImpl) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();

    let root_ws = tree.workspace_root().join(ROOT_BARE);
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(node(ROOT_BARE, AgentKind::Root, None, root_ws))
        .unwrap();

    let adapter_ws = tree
        .workspace_root()
        .join(format!("{ROOT_BARE}/{ADAPTER_BARE}"));
    std::fs::create_dir_all(&adapter_ws).unwrap();
    tree.insert_child(
        &AgentId(ROOT_BARE.into()),
        node(ADAPTER_BARE, AgentKind::Child, Some(ROOT_BARE), adapter_ws),
    )
    .unwrap();

    // Sanity: the REAL tree rejects the colon forms (the production residual).
    assert!(tree.contains(&AgentId(ROOT_BARE.into())));
    assert!(!tree.contains(&AgentId(ROOT_COLON.into())));

    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let registry: Arc<dyn ChannelAdapterRegistry> = if register_channel {
        let mut r = StaticChannelAdapterRegistry::new();
        r.insert(CHANNEL, ADAPTER_COLON).unwrap();
        Arc::new(r)
    } else {
        Arc::new(EmptyChannelAdapterRegistry)
    };

    let mut d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        registry,
    );
    if wire_bridge {
        let bridge = AgentIdBridge::from_pairs([
            (ROOT_COLON.to_string(), ROOT_BARE.to_string()),
            (ADAPTER_COLON.to_string(), ADAPTER_BARE.to_string()),
        ]);
        d = d.with_id_bridge(Arc::new(bridge));
    }
    (tmp, store, d)
}

// TB-IDB-03 — notify_agent through the REAL bare-keyed AgentTreeStore: the bridge
// resolves `agent:default` → membership `default-agent` + canonical mailbox key
// `agent:default`, and DELIVERS. Anti-fake-green: the same call against the same
// REAL tree WITHOUT the bridge returns `target_unknown`.
#[tokio::test(flavor = "multi_thread")]
async fn tb_idb_03_real_tree_notify_agent() {
    // bridge ON → delivers.
    let (_tmp, store, d) = build(true, false);
    d.notify_agent("system", ROOT_COLON, b"hi".to_vec(), None)
        .await
        .expect("bridge resolves agent:default against the REAL bare tree; delivers");
    let mb = store.get(ROOT_COLON).expect("canonical mailbox exists");
    let msg = mb.recv().await;
    assert_eq!(msg.from, "system");
    assert_eq!(msg.to, ROOT_COLON);
    assert_eq!(msg.payload, b"hi".to_vec());
    assert!(
        store.get(ROOT_BARE).is_none(),
        "no orphan bare-keyed mailbox"
    );

    // bridge OFF → the REAL tree's validate_agent_id rejects the colon →
    // agent_exists is false → target_unknown (the production residual).
    let (_tmp2, store2, d2) = build(false, false);
    let err = d2
        .notify_agent("system", ROOT_COLON, b"hi".to_vec(), None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::InvalidTarget("target_unknown".into()));
    assert!(store2.get(ROOT_COLON).is_none());
    assert!(store2.get(ROOT_BARE).is_none());
}

// TB-IDB-04 — notify_channel through the REAL tree: a REGISTERED channel resolves
// to the colon adapter id, which the bridge maps to the bare adapter tree node →
// a real ChannelDelivery envelope lands in the adapter's canonical mailbox.
// Anti-fake-green: registered channel but NO bridge → `target_unknown` (NOT
// `channel_unknown`, which is the distinct unregistered branch).
#[tokio::test(flavor = "multi_thread")]
async fn tb_idb_04_real_tree_notify_channel() {
    // bridge ON + channel registered → delivers the envelope.
    let (_tmp, store, d) = build(true, true);
    d.notify_channel("system", CHANNEL, "user:bob", b"hello-chan".to_vec(), None)
        .await
        .expect("registered channel + bridge resolves adapter against the REAL tree; delivers");
    let mb = store.get(ADAPTER_COLON).expect("adapter mailbox exists");
    let msg = mb.recv().await;
    let env: ChannelDelivery =
        serde_json::from_slice(&msg.payload).expect("ChannelDelivery envelope");
    assert_eq!(env.channel_id, CHANNEL);
    assert_eq!(env.user_id, "user:bob");
    assert_eq!(env.body, b"hello-chan".to_vec());

    // bridge OFF + channel registered → resolution succeeds (channel known) but
    // the colon adapter misses the REAL bare tree → target_unknown.
    let (_tmp2, store2, d2) = build(false, true);
    let err = d2
        .notify_channel("system", CHANNEL, "user:bob", b"x".to_vec(), None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::InvalidTarget("target_unknown".into()));
    assert!(store2.get(ADAPTER_COLON).is_none());
}

// TB-IDB-05 — safety preserved on the REAL tree: a multi-colon (is_safe_id-
// malformed) target rejects at the is_safe_id gate; a syntactically-valid but
// NON-member colon target (`agent:default-agent`, the orphan-key trap) resolves
// to None → REAL bare tree miss → target_unknown. Neither delivers anything.
#[tokio::test(flavor = "multi_thread")]
async fn tb_idb_05_real_tree_malformed_and_nonmember_reject() {
    let (_tmp, store, d) = build(true, false);

    let e1 = d
        .notify_agent("system", "agent:a:b", b"1".to_vec(), None)
        .await
        .unwrap_err();
    assert_eq!(e1, NotifyError::InvalidTarget("invalid_id".into()));

    // `agent:default-agent` is is_safe_id-valid (body `default-agent`) and its
    // strip WOULD match the bare root, but the no-strip-fallback design means it
    // is NOT a bridge member → REAL tree miss → target_unknown (no orphan).
    let e2 = d
        .notify_agent("system", "agent:default-agent", b"2".to_vec(), None)
        .await
        .unwrap_err();
    assert_eq!(e2, NotifyError::InvalidTarget("target_unknown".into()));

    assert!(store.get("agent:default-agent").is_none());
    assert!(store.get(ROOT_BARE).is_none());
    assert!(store.get(ROOT_COLON).is_none());
}
