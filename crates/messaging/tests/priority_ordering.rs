//! AC-10 (REQ-045) — `User` + `Control` messages are prioritized over
//! `Auto` (separate high-priority queue). FIFO within high-priority.

mod common;

use std::num::NonZeroUsize;
use std::time::SystemTime;

use advance_messaging::Mailbox;
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

// T-A12 — Auto, Auto, User → recv order: User, Auto, Auto.
#[tokio::test]
async fn t_a12_user_jumps_auto_queue() {
    let mb = Mailbox::new(NonZeroUsize::new(8).unwrap());
    mb.deliver(make_msg("a1", MessageKind::Auto)).unwrap();
    mb.deliver(make_msg("a2", MessageKind::Auto)).unwrap();
    mb.deliver(make_msg("u1", MessageKind::User)).unwrap();
    assert_eq!(mb.recv().await.id, "u1");
    assert_eq!(mb.recv().await.id, "a1");
    assert_eq!(mb.recv().await.id, "a2");
}

// T-A13 — Auto, Control, Auto → recv order: Control, Auto, Auto.
#[tokio::test]
async fn t_a13_control_jumps_auto_queue() {
    let mb = Mailbox::new(NonZeroUsize::new(8).unwrap());
    mb.deliver(make_msg("a1", MessageKind::Auto)).unwrap();
    mb.deliver(make_msg("c1", MessageKind::Control)).unwrap();
    mb.deliver(make_msg("a2", MessageKind::Auto)).unwrap();
    assert_eq!(mb.recv().await.id, "c1");
    assert_eq!(mb.recv().await.id, "a1");
    assert_eq!(mb.recv().await.id, "a2");
}

// T-A14 — FIFO within high_priority: Control then User → Control, User.
#[tokio::test]
async fn t_a14_fifo_within_high_priority() {
    let mb = Mailbox::new(NonZeroUsize::new(8).unwrap());
    mb.deliver(make_msg("c1", MessageKind::Control)).unwrap();
    mb.deliver(make_msg("u1", MessageKind::User)).unwrap();
    assert_eq!(mb.recv().await.id, "c1");
    assert_eq!(mb.recv().await.id, "u1");
}
