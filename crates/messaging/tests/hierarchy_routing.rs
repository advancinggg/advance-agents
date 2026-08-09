//! AC-04 (REQ-028) — `validate_routing` enforces adjacent-level whitelist
//! (parent↔child, sibling↔sibling, cross-level rejected). Plus slice-A
//! defense-in-depth: self-send rejection + user-sender existence-check.

mod common;

use advance_messaging::{validate_routing, MsgError};

use crate::common::TestTree;

fn assert_invalid(result: Result<(), MsgError>) {
    match result {
        Err(MsgError::InvalidTarget(_)) => {}
        other => panic!("expected InvalidTarget, got {other:?}"),
    }
}

// T-A04 — child → parent
#[test]
fn t_a04_child_to_parent_ok() {
    let tree = TestTree::new()
        .add_root("agent:root")
        .add_child("agent:child", "agent:root");
    validate_routing(&tree, "agent:child", "agent:root").expect("child → parent allowed");
}

// T-A05 — parent → child
#[test]
fn t_a05_parent_to_child_ok() {
    let tree = TestTree::new()
        .add_root("agent:root")
        .add_child("agent:child", "agent:root");
    validate_routing(&tree, "agent:root", "agent:child").expect("parent → child allowed");
}

// T-A06 — sibling → sibling
#[test]
fn t_a06_sibling_to_sibling_ok() {
    let tree = TestTree::new()
        .add_root("agent:parent")
        .add_child("agent:a", "agent:parent")
        .add_child("agent:b", "agent:parent");
    validate_routing(&tree, "agent:a", "agent:b").expect("sibling → sibling allowed");
}

// T-A07 — grand-uncle (cross-level) rejected.
//
// Topology:
//   root
//   ├── uncle      (parent_of(uncle) == root)
//   └── parent     (parent_of(parent) == root)
//        └── grandchild  (parent_of(grandchild) == parent)
// from=grandchild, to=uncle: grandchild's parent is `parent`; uncle's parent
// is root. Not parent/child (uncle != parent of grandchild; grandchild != child
// of uncle). Not siblings (different parents). Reject.
#[test]
fn t_a07_cross_level_rejected() {
    let tree = TestTree::new()
        .add_root("agent:root")
        .add_child("agent:uncle", "agent:root")
        .add_child("agent:parent", "agent:root")
        .add_child("agent:grandchild", "agent:parent");
    assert_invalid(validate_routing(&tree, "agent:grandchild", "agent:uncle"));
}

// T-A08 — user:* → existing agent (user bypass).
#[test]
fn t_a08_user_to_existing_agent_ok() {
    let tree = TestTree::new().add_root("agent:root");
    validate_routing(&tree, "user:alice", "agent:root").expect("user → existing agent");
}

// T-A09 — user:* → unknown agent (R2/R3 tightening: agent_exists check applies).
#[test]
fn t_a09_user_to_unknown_rejected() {
    let tree = TestTree::new().add_root("agent:root");
    assert_invalid(validate_routing(
        &tree,
        "user:alice",
        "agent:does-not-exist",
    ));
}

// T-A10 — self-send rejected (slice-A defense-in-depth).
#[test]
fn t_a10_self_send_rejected() {
    let tree = TestTree::new().add_root("agent:root");
    assert_invalid(validate_routing(&tree, "agent:root", "agent:root"));
}

// T-A11 — from/to both unknown.
#[test]
fn t_a11_unknown_to_unknown_rejected() {
    let tree = TestTree::new();
    assert_invalid(validate_routing(&tree, "agent:ghost1", "agent:ghost2"));
}

// AUDIT R8 W3 fix — exercise the composed dispatcher path so a regression
// that wires `MailboxDispatcherImpl::deliver` without `validate_routing`
// is caught by slice-A tests.
#[tokio::test]
async fn t_a11b_dispatcher_composed_path_enforces_routing() {
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::time::SystemTime;

    use advance_messaging::{MailboxDispatcher, MailboxDispatcherImpl, MailboxStore, MsgError};
    use advance_shared_types::mailbox::{Message, MessageKind};

    let tree = Arc::new(
        TestTree::new()
            .add_root("agent:root")
            .add_child("agent:child", "agent:root"),
    );
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(4).unwrap()));
    let dispatcher = MailboxDispatcherImpl::new(store.clone(), tree.clone());

    // Cross-level (root → grandchild that doesn't exist) → InvalidTarget via
    // hierarchy validation BEFORE any mailbox creation.
    let msg = Message {
        id: "x1".to_string(),
        kind: MessageKind::Auto,
        from: "agent:root".to_string(),
        to: "agent:nope".to_string(),
        payload: vec![],
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    };
    let err = dispatcher
        .deliver("agent:nope", msg)
        .await
        .expect_err("hierarchy gate must reject unknown target before lazy-create");
    match err {
        MsgError::InvalidTarget(_) => {}
        other => panic!("expected InvalidTarget, got {other:?}"),
    }
    // No mailbox should have been lazily created for the rejected target.
    assert!(
        store.get("agent:nope").is_none(),
        "rejected target must NOT lazy-create a mailbox"
    );

    // Valid route (parent → child) succeeds and lazy-creates the target mailbox.
    let ok_msg = Message {
        id: "ok1".to_string(),
        kind: MessageKind::Auto,
        from: "agent:root".to_string(),
        to: "agent:child".to_string(),
        payload: vec![],
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    };
    dispatcher
        .deliver("agent:child", ok_msg)
        .await
        .expect("parent → child route ok");
    assert!(
        store.get("agent:child").is_some(),
        "valid route lazy-creates the target mailbox"
    );
}
