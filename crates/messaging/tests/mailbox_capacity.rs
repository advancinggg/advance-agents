//! AC-03 (REQ-024) — `Mailbox` bounded; over-capacity → `MsgError::MailboxFull`.

mod common;

use std::num::NonZeroUsize;
use std::time::SystemTime;

use advance_messaging::{Mailbox, MsgError};
use advance_shared_types::mailbox::{Message, MessageKind};

fn make_msg(id: &str, kind: MessageKind) -> Message {
    Message {
        id: id.to_string(),
        kind,
        from: "agent:src".to_string(),
        to: "agent:dst".to_string(),
        payload: Vec::new(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

// T-A01 — fill to capacity then reject 101st.
#[tokio::test]
async fn t_a01_over_capacity_rejected() {
    let cap = NonZeroUsize::new(100).unwrap();
    let mb = Mailbox::new(cap);
    for i in 0..100 {
        let m = make_msg(&format!("m{i}"), MessageKind::Auto);
        mb.deliver(m).expect("under capacity should accept");
    }
    let m101 = make_msg("m100", MessageKind::Auto);
    let err = mb.deliver(m101).expect_err("101st must reject");
    assert_eq!(err, MsgError::MailboxFull);
    assert_eq!(mb.depth(), 100);
}

// T-A02 — combined cap across high_priority + queue.
#[tokio::test]
async fn t_a02_combined_capacity_across_queues() {
    let cap = NonZeroUsize::new(4).unwrap();
    let mb = Mailbox::new(cap);
    // Fill 2 high-priority + 2 normal = 4/4.
    mb.deliver(make_msg("u1", MessageKind::User)).unwrap();
    mb.deliver(make_msg("c1", MessageKind::Control)).unwrap();
    mb.deliver(make_msg("a1", MessageKind::Auto)).unwrap();
    mb.deliver(make_msg("a2", MessageKind::Auto)).unwrap();
    assert_eq!(mb.depth(), 4);
    // Next User must also be rejected — combined cap rules.
    let err = mb
        .deliver(make_msg("u2", MessageKind::User))
        .expect_err("combined-cap reject");
    assert_eq!(err, MsgError::MailboxFull);
}

// T-A03 — round-trip with depth decrement via DepthGuard commit.
#[tokio::test]
async fn t_a03_round_trip_with_depth_decrement() {
    let cap = NonZeroUsize::new(8).unwrap();
    let mb = Mailbox::new(cap);
    let original = make_msg("rt-1", MessageKind::Auto);
    mb.deliver(original.clone()).unwrap();
    assert_eq!(mb.depth(), 1);
    let received = mb.recv().await;
    assert_eq!(received.id, "rt-1");
    assert_eq!(mb.depth(), 0);
}

// AUDIT R8 W4 fix — exercise the non-AC-bearing sync surface so a future
// slice cannot silently regress poll/freeze/unfreeze/is_frozen/depth.
#[tokio::test]
async fn t_a03b_poll_prefers_high_priority() {
    let mb = Mailbox::new(NonZeroUsize::new(4).unwrap());
    mb.deliver(make_msg("a1", MessageKind::Auto)).unwrap();
    mb.deliver(make_msg("u1", MessageKind::User)).unwrap();
    assert_eq!(mb.depth(), 2);
    // poll() is sync non-blocking; must return user (high priority) first.
    let m1 = mb.poll().expect("poll returns the user message first");
    assert_eq!(m1.id, "u1");
    let m2 = mb.poll().expect("poll then returns the auto message");
    assert_eq!(m2.id, "a1");
    assert!(mb.poll().is_none(), "poll returns None on empty");
    assert_eq!(mb.depth(), 0);
}

#[tokio::test]
async fn t_a03c_freeze_toggle_observable() {
    let mb = Mailbox::new(NonZeroUsize::new(4).unwrap());
    assert!(!mb.is_frozen(), "fresh mailbox starts unfrozen");
    mb.freeze();
    assert!(mb.is_frozen(), "freeze() toggles to true");
    mb.unfreeze();
    assert!(!mb.is_frozen(), "unfreeze() toggles back to false");
    // Slice A scope: freeze is observable-only — deliver still succeeds while frozen.
    mb.freeze();
    mb.deliver(make_msg("f1", MessageKind::Auto))
        .expect("slice-A deliver does NOT consult frozen flag");
}
