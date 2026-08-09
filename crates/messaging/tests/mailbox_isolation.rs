//! MODULE-006-AC-16 (REQ-026) — Mailbox facet of agent specialization.
//!
//! AC-16: "every agent instance is endowed with its own bounded mailbox keyed
//! on its tree identity (agent_id); messages addressed to an agent enqueue only
//! into that agent's mailbox, and a non-agent component receives a mailbox only
//! via the notify-agent adapter path (PRD §3.7)."
//!
//! Drives the PRODUCTION `MailboxDispatcherImpl` over a real `AgentTreeReader`
//! (`common::TestTree`) + real `MailboxStore` — NOT raw
//! `MailboxStore::get_or_create` (which would create a mailbox for ANY string,
//! bypassing the agent-identity gate). Three facets:
//!   (a) two-agent isolation — a message to agent:a enqueues ONLY into agent:a;
//!   (b) the dispatcher gates mailbox access on tree identity (`agent_exists`),
//!       so a non-agent target gets NO mailbox via `deliver` (the discriminator
//!       vs raw `get_or_create`);
//!   (c) a non-agent ("non-hierarchy") component reaches a tree-registered
//!       adapter ONLY via the hierarchy-bypassing `notify_agent` path, not via
//!       the hierarchy-validated `deliver`.
//!
//! Witnesses MODULE-006-AC-16 (T-W17-16).

mod common;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::SystemTime;

use advance_messaging::{
    MailboxDispatcher, MailboxDispatcherImpl, MailboxStore, MsgError, NotifyError,
};
use advance_shared_types::mailbox::{Message, MessageKind};

use crate::common::TestTree;

fn msg(from: &str, to: &str, payload: &[u8]) -> Message {
    Message {
        id: format!("{from}->{to}"),
        kind: MessageKind::Auto,
        from: from.to_string(),
        to: to.to_string(),
        payload: payload.to_vec(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

/// T-W17-16a — two-agent mailbox isolation: a message addressed to agent:a
/// enqueues ONLY into agent:a's mailbox; agent:b's mailbox holds only its own.
/// No cross-leak — each agent's mailbox is keyed on its own agent_id.
#[tokio::test]
async fn ac16_two_agent_mailbox_isolation_no_leak() {
    let tree = Arc::new(
        TestTree::new()
            .add_root("agent:parent")
            .add_child("agent:a", "agent:parent")
            .add_child("agent:b", "agent:parent"),
    );
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let dispatcher = MailboxDispatcherImpl::new(store.clone(), tree.clone());

    // parent → a (payload AAA), parent → b (payload BBB). Both hierarchy-valid.
    dispatcher
        .deliver("agent:a", msg("agent:parent", "agent:a", b"AAA"))
        .await
        .expect("parent → a delivers");
    dispatcher
        .deliver("agent:b", msg("agent:parent", "agent:b", b"BBB"))
        .await
        .expect("parent → b delivers");

    // Each mailbox holds EXACTLY its own one message — no cross-leak.
    let mb_a = store.get("agent:a").expect("agent:a mailbox exists");
    let mb_b = store.get("agent:b").expect("agent:b mailbox exists");
    assert_eq!(mb_a.depth(), 1, "agent:a holds exactly its own 1 message");
    assert_eq!(mb_b.depth(), 1, "agent:b holds exactly its own 1 message");

    let a_msg = mb_a.poll().expect("agent:a has a message");
    assert_eq!(
        a_msg.payload, b"AAA",
        "agent:a mailbox holds ONLY its own AAA (no leak from agent:b)"
    );
    let b_msg = mb_b.poll().expect("agent:b has a message");
    assert_eq!(
        b_msg.payload, b"BBB",
        "agent:b mailbox holds ONLY its own BBB (no leak from agent:a)"
    );

    // Both drained — neither ever received the other's message.
    assert!(mb_a.poll().is_none(), "agent:a had exactly one message");
    assert!(mb_b.poll().is_none(), "agent:b had exactly one message");
}

/// T-W17-16b — the dispatcher gates mailbox access on tree identity. A target
/// NOT in the agent tree is REJECTED by `deliver` and receives NO mailbox —
/// the discriminator vs raw `MailboxStore::get_or_create`, which creates a
/// mailbox for ANY string. ("every agent instance is endowed with its own
/// mailbox keyed on its tree identity" — non-members get none via the
/// dispatcher; the identity gate is the dispatcher's, not the store's.)
#[tokio::test]
async fn ac16_dispatcher_gates_mailbox_on_tree_identity() {
    let tree = Arc::new(TestTree::new().add_root("agent:real"));
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let dispatcher = MailboxDispatcherImpl::new(store.clone(), tree.clone());

    // deliver to a target NOT in the tree → rejected; no mailbox lazily created.
    let err = dispatcher
        .deliver("agent:ghost", msg("agent:real", "agent:ghost", b"X"))
        .await
        .expect_err("non-tree target rejected by the agent-identity gate");
    assert!(matches!(err, MsgError::InvalidTarget(_)), "got {err:?}");
    assert!(
        store.get("agent:ghost").is_none(),
        "the dispatcher must NOT lazy-create a mailbox for a non-agent target"
    );

    // Contrast: raw MailboxStore::get_or_create WOULD create a mailbox for any
    // string — proving the agent-identity GATE is the dispatcher's, not the
    // store's. (This is exactly why the witness drives the dispatcher.)
    let _ = store
        .get_or_create("agent:ungated")
        .expect("raw store creates a mailbox for any id");
    assert!(
        store.get("agent:ungated").is_some(),
        "raw get_or_create has no agent-identity gate (the dispatcher supplies it)"
    );
}

/// T-W17-16c — a non-agent ("non-hierarchy") component reaches a tree-registered
/// agent ONLY via the notify-agent adapter path (hierarchy bypass), NOT via the
/// hierarchy-validated `deliver` (PRD §3.7). The canonical non-agent sender form
/// `system` (per the MODULE-006 id grammar) is rejected by `deliver`
/// (`no_adjacency` — it has no hierarchy position) but accepted by `notify_agent`.
#[tokio::test]
async fn ac16_nonagent_sender_reaches_agent_only_via_notify_agent() {
    let tree = Arc::new(TestTree::new().add_root("agent:adapter"));
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let dispatcher = MailboxDispatcherImpl::new(store.clone(), tree.clone());

    // `deliver` from the non-hierarchy "system" sender → rejected: deliver
    // enforces parent↔child / sibling↔sibling, and a system/cron component has
    // no hierarchy position relative to the adapter.
    let err = dispatcher
        .deliver(
            "agent:adapter",
            msg("system", "agent:adapter", b"viaDeliver"),
        )
        .await
        .expect_err("hierarchy-validated deliver rejects a non-hierarchy sender");
    assert!(matches!(err, MsgError::InvalidTarget(_)), "got {err:?}");
    // The rejected deliver did NOT enqueue anything.
    if let Some(mb) = store.get("agent:adapter") {
        assert_eq!(mb.depth(), 0, "rejected deliver must not enqueue");
    }

    // `notify_agent` (hierarchy-bypassing) from the SAME "system" sender → OK:
    // the adapter receives the message via the notify-agent path only.
    dispatcher
        .notify_agent("system", "agent:adapter", b"viaNotify".to_vec(), None)
        .await
        .expect("notify_agent reaches the tree-registered adapter (hierarchy bypass)");

    let mb = store
        .get("agent:adapter")
        .expect("adapter mailbox exists after notify");
    let got = mb.poll().expect("adapter received the notify message");
    assert_eq!(
        got.payload, b"viaNotify",
        "the adapter received ONLY the notify-agent message (deliver was rejected)"
    );
    assert!(
        mb.poll().is_none(),
        "exactly one message — the rejected deliver attempt did not enqueue"
    );

    // Sanity: notify_agent still gates on tree identity — a non-existent target
    // is rejected (the notify path is not an unconditional mailbox factory).
    let nerr = dispatcher
        .notify_agent("system", "agent:missing", b"x".to_vec(), None)
        .await
        .expect_err("notify_agent rejects a non-tree target");
    assert!(
        matches!(nerr, NotifyError::InvalidTarget(_)),
        "got {nerr:?}"
    );
}
