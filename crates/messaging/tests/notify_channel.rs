//! AC-14 (REQ-182) notify-channel routing + notify_agent behavior.
//! T-B25..T-B32. notify_agent is hierarchy-bypassing (notify ≠ send);
//! notify_channel wraps a `ChannelDelivery` envelope and routes to the
//! channel-adapter agent mailbox (Message.origin == None — no spoof).

mod common;

use std::sync::Arc;

use advance_messaging::{
    ChannelDelivery, EmptyChannelAdapterRegistry, MailboxDispatcher, MailboxDispatcherImpl,
    MailboxStore, MessageTrace, NotifyError, DEFAULT_CAPACITY,
};
use advance_shared_types::mailbox::{Message, MessageKind};

use crate::common::{static_registry, TestTree};

fn dispatcher(
    tree: TestTree,
    registry_pairs: &[(&str, &str)],
) -> (Arc<MailboxStore>, MailboxDispatcherImpl) {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let registry: Arc<dyn advance_messaging::ChannelAdapterRegistry> = if registry_pairs.is_empty()
    {
        Arc::new(EmptyChannelAdapterRegistry)
    } else {
        Arc::new(static_registry(registry_pairs))
    };
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        registry,
    );
    (store, d)
}

async fn recv(store: &MailboxStore, agent: &str) -> Message {
    store.get(agent).expect("mailbox exists").recv().await
}

// T-B25 — notify_agent delivers (from=system). Also pins the AC-15
// cron/daemon hierarchy-bypass MECHANISM (infra; AC-15 not claimed,
// REQ-032).
#[tokio::test]
async fn t_b25_notify_agent_system_delivers() {
    let tree = TestTree::new().add_root("agent:research");
    let (store, d) = dispatcher(tree, &[]);
    d.notify_agent("system", "agent:research", vec![1], None)
        .await
        .unwrap();
    let msg = recv(&store, "agent:research").await;
    assert_eq!(msg.from, "system");
    assert!(matches!(msg.kind, MessageKind::System));
}

// T-B26 — notify_agent bypasses hierarchy (from=agent:unrelated, no
// parent/child/sibling relation with target).
#[tokio::test]
async fn t_b26_notify_agent_bypasses_hierarchy() {
    let tree = TestTree::new()
        .add_root("agent:unrelated")
        .add_root("agent:research");
    let (store, d) = dispatcher(tree, &[]);
    d.notify_agent("agent:unrelated", "agent:research", vec![2], None)
        .await
        .unwrap();
    let msg = recv(&store, "agent:research").await;
    assert_eq!(msg.from, "agent:unrelated");
    assert!(matches!(msg.kind, MessageKind::Agent));
}

// T-B27 — from=user:alice bypass pinned (notify is uniform across caller
// kinds; classified MessageKind::User).
#[tokio::test]
async fn t_b27_notify_agent_user_sender() {
    let tree = TestTree::new().add_root("agent:research");
    let (store, d) = dispatcher(tree, &[]);
    d.notify_agent("user:alice", "agent:research", vec![3], None)
        .await
        .unwrap();
    let msg = recv(&store, "agent:research").await;
    assert_eq!(msg.from, "user:alice");
    assert!(matches!(msg.kind, MessageKind::User));
}

// T-B28 — unknown target → InvalidTarget("target_unknown").
#[tokio::test]
async fn t_b28_notify_agent_unknown_target() {
    let tree = TestTree::new();
    let (_store, d) = dispatcher(tree, &[]);
    let err = d
        .notify_agent("system", "agent:ghost", vec![1], None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::InvalidTarget("target_unknown".into()));
}

// T-B29 — mailbox full (100 Agent msgs fill the regular queue) →
// NotifyError::MailboxFull.
#[tokio::test]
async fn t_b29_notify_agent_mailbox_full() {
    let tree = TestTree::new()
        .add_root("agent:src")
        .add_root("agent:research");
    let (_store, d) = dispatcher(tree, &[]);
    for _ in 0..100 {
        d.notify_agent("agent:src", "agent:research", vec![0], None)
            .await
            .unwrap();
    }
    let err = d
        .notify_agent("agent:src", "agent:research", vec![0], None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::MailboxFull);
}

// T-B30 — notify_channel unknown channel (empty registry) →
// InvalidTarget("channel_unknown").
#[tokio::test]
async fn t_b30_notify_channel_unknown_channel() {
    let tree = TestTree::new();
    let (_store, d) = dispatcher(tree, &[]);
    let err = d
        .notify_channel("agent:research", "telegram", "user:alice", vec![1], None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::InvalidTarget("channel_unknown".into()));
}

// T-B31 — notify_channel routes to adapter; decode the delivered payload as
// ChannelDelivery, assert channel_id/user_id/body round-trip + origin==None
// + to==adapter.
#[tokio::test]
async fn t_b31_notify_channel_routes_to_adapter() {
    let tree = TestTree::new().add_root("agent:adapter-tg");
    let (store, d) = dispatcher(tree, &[("telegram", "agent:adapter-tg")]);
    d.notify_channel(
        "agent:research",
        "telegram",
        "user:alice",
        vec![5, 6, 7],
        None,
    )
    .await
    .unwrap();
    let msg = recv(&store, "agent:adapter-tg").await;
    assert_eq!(msg.to, "agent:adapter-tg");
    assert_eq!(msg.from, "agent:research");
    assert!(msg.origin.is_none(), "notify_channel must not forge origin");
    let env: ChannelDelivery =
        serde_json::from_slice(&msg.payload).expect("payload is a ChannelDelivery");
    assert_eq!(env.channel_id, "telegram");
    assert_eq!(env.user_id, "user:alice");
    assert_eq!(env.body, vec![5, 6, 7]);
}

// T-B32 — notify_channel empty channel_id / non-safe user_id →
// channel_id_empty / user_id_invalid.
#[tokio::test]
async fn t_b32_notify_channel_arg_validation() {
    let tree = TestTree::new().add_root("agent:adapter-tg");
    let (_store, d) = dispatcher(tree, &[("telegram", "agent:adapter-tg")]);

    let empty_chan = d
        .notify_channel("agent:research", "", "user:alice", vec![1], None)
        .await
        .unwrap_err();
    assert_eq!(
        empty_chan,
        NotifyError::InvalidTarget("channel_id_empty".into())
    );

    let bad_user = d
        .notify_channel(
            "agent:research",
            "telegram",
            "user:alice\nspoof",
            vec![1],
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        bad_user,
        NotifyError::InvalidTarget("user_id_invalid".into())
    );
}

// T-B42 — notify_channel rejects a non-`user:` (agent:/system) user_id —
// enforces the documented unified-recipient contract.
#[tokio::test]
async fn t_b42_notify_channel_requires_user_prefix() {
    let tree = TestTree::new().add_root("agent:adapter-tg");
    let (_store, d) = dispatcher(tree, &[("telegram", "agent:adapter-tg")]);
    for bad in ["agent:bob", "system"] {
        let err = d
            .notify_channel("agent:research", "telegram", bad, vec![1], None)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            NotifyError::InvalidTarget("user_id_invalid".into()),
            "user_id {bad:?} must be rejected (not user:-prefixed)"
        );
    }
}

// T-B43 — notify_channel raw fast-path pre-cap: one byte over
// MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES → clear payload_too_large BEFORE the
// encode; a payload at exactly the cap passes the pre-cap and delivers
// (Adversarial r2 fix).
#[tokio::test]
async fn t_b43_notify_channel_payload_cap() {
    use advance_messaging::MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES;
    let tree = TestTree::new().add_root("agent:adapter-tg");
    let (store, d) = dispatcher(tree, &[("telegram", "agent:adapter-tg")]);

    let too_big = vec![0u8; MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES + 1];
    let err = d
        .notify_channel("agent:research", "telegram", "user:alice", too_big, None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::InvalidTarget("payload_too_large".into()));

    let at_cap = vec![7u8; MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES];
    d.notify_channel("agent:research", "telegram", "user:alice", at_cap, None)
        .await
        .expect("payload at exactly the notify-channel cap must be accepted");
    assert!(store.get("agent:adapter-tg").is_some());
}

// T-B45 — envelope-size invariant proof under WORST case (Adversarial r2):
// all-0xFF body at exactly the pre-cap + maximal-length channel_id/user_id
// must still produce an encoded envelope ≤ MAX_PAYLOAD_BYTES (the r1
// off-by-one would have exceeded it). Independently re-encode the same
// ChannelDelivery and assert the byte length.
#[tokio::test]
async fn t_b45_envelope_size_invariant_worst_case() {
    use advance_messaging::{ChannelDelivery, MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES};
    // Maximal-length ids: channel_id 256 bytes; user_id "user:" + 251 = 256.
    let channel_id = "c".repeat(256);
    let user_id = format!("user:{}", "a".repeat(251));
    assert_eq!(channel_id.len(), 256);
    assert_eq!(user_id.len(), 256);
    // Worst-case body: every byte 0xFF (encodes as "255" = 3 chars + comma).
    let body = vec![0xFFu8; MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES];
    let envelope = serde_json::to_vec(&ChannelDelivery {
        channel_id: channel_id.clone(),
        user_id: user_id.clone(),
        body,
    })
    .expect("encode");
    assert!(
        envelope.len() <= MAX_PAYLOAD_BYTES,
        "worst-case envelope {} must be ≤ MAX_PAYLOAD_BYTES {} (r1 off-by-one would exceed it)",
        envelope.len(),
        MAX_PAYLOAD_BYTES
    );

    // And a registered-adapter notify_channel with max ids + at-cap body
    // delivers (post-encode exact check does NOT spuriously reject a valid
    // bounded payload).
    let tree = TestTree::new().add_root("agent:adapter-x");
    let (store, d) = dispatcher(tree, &[(channel_id.as_str(), "agent:adapter-x")]);
    d.notify_channel(
        "agent:research",
        &channel_id,
        &user_id,
        vec![0xFFu8; MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES],
        None,
    )
    .await
    .expect("max-id + at-cap worst-case body must deliver (invariant holds)");
    assert!(store.get("agent:adapter-x").is_some());
}
