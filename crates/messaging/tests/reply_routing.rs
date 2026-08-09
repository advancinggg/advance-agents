//! AC-06 (REQ-202) reply routing + AC-07 (REQ-175) context inheritance.
//! T-B14..T-B24. `reply()` routes back to `origin.adapter_id`, is
//! recipient-bound (`from == recipient`), inherits the original context
//! verbatim with a fresh `in_reply_to`, and carries the genuine
//! `MessageOrigin` through (§2.3 "passed through on reply").

mod common;

use std::sync::Arc;

use advance_messaging::{
    EmptyChannelAdapterRegistry, MailboxDispatcher, MailboxDispatcherImpl, MailboxStore,
    MessageTrace, MsgError, DEFAULT_CAPACITY, MAX_PAYLOAD_BYTES,
};
use advance_shared_types::mailbox::{Message, MessageKind};

use crate::common::{full_context, make_origin, make_origin_full, TestTree};

fn dispatcher_with_tree(
    tree: TestTree,
) -> (Arc<MailboxStore>, Arc<MessageTrace>, MailboxDispatcherImpl) {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let trace = Arc::new(MessageTrace::new());
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        trace.clone(),
        Arc::new(EmptyChannelAdapterRegistry),
    );
    (store, trace, d)
}

async fn recv(store: &MailboxStore, agent: &str) -> Message {
    store.get(agent).expect("mailbox exists").recv().await
}

// T-B14 — reply delivers to origin.adapter_id (to/from/kind=Agent).
#[tokio::test]
async fn t_b14_reply_delivers_to_adapter() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (store, _trace, d) = dispatcher_with_tree(tree);
    d.trace()
        .record(
            "m1",
            make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap();
    d.reply("agent:bob", "m1", vec![1, 2, 3]).await.unwrap();
    let msg = recv(&store, "agent:adapter-tg").await;
    assert_eq!(msg.to, "agent:adapter-tg");
    assert_eq!(msg.from, "agent:bob");
    assert!(matches!(msg.kind, MessageKind::Agent));
    assert_eq!(msg.payload, vec![1, 2, 3]);
}

// T-B15 — genuine MessageOrigin carried through; channel_metadata +
// original_* byte-identical (AC-06 "delivered to original channel" routing
// data preserved).
#[tokio::test]
async fn t_b15_origin_passthrough() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (store, _trace, d) = dispatcher_with_tree(tree);
    let origin = make_origin_full(
        "m1",
        "agent:adapter-tg",
        &[("thread_id", "t-99"), ("msg_ref", "r-7")],
        None,
    );
    d.trace().record("m1", origin.clone(), "agent:bob").unwrap();
    d.reply("agent:bob", "m1", vec![9]).await.unwrap();
    let msg = recv(&store, "agent:adapter-tg").await;
    let got = msg.origin.expect("origin carried through");
    assert_eq!(got.adapter_id, origin.adapter_id);
    assert_eq!(got.original_channel, origin.original_channel);
    assert_eq!(got.original_sender, origin.original_sender);
    assert_eq!(got.channel_metadata, origin.channel_metadata);
    assert_eq!(
        got.channel_metadata.get("thread_id").map(String::as_str),
        Some("t-99")
    );
}

// T-B16 — trace miss → InvalidTarget("trace_miss").
#[tokio::test]
async fn t_b16_trace_miss() {
    let tree = TestTree::new().add_root("agent:bob");
    let (_store, _trace, d) = dispatcher_with_tree(tree);
    let err = d.reply("agent:bob", "ghost", vec![1]).await.unwrap_err();
    assert_eq!(err, MsgError::InvalidTarget("trace_miss".into()));
}

// T-B17 — wrong replier (from != recipient) → reply_not_authorized.
#[tokio::test]
async fn t_b17_wrong_replier_rejected() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob")
        .add_root("agent:mallory");
    let (_store, _trace, d) = dispatcher_with_tree(tree);
    d.trace()
        .record(
            "m1",
            make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap();
    let err = d.reply("agent:mallory", "m1", vec![1]).await.unwrap_err();
    assert_eq!(err, MsgError::InvalidTarget("reply_not_authorized".into()));
}

// T-B18 — correct recipient → ok (explicit positive authorization).
#[tokio::test]
async fn t_b18_correct_recipient_ok() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (store, _trace, d) = dispatcher_with_tree(tree);
    d.trace()
        .record(
            "m1",
            make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap();
    d.reply("agent:bob", "m1", vec![7]).await.unwrap();
    assert_eq!(recv(&store, "agent:adapter-tg").await.payload, vec![7]);
}

// T-B19 — AC-07: inherits task_id / run_id / execution_id.
#[tokio::test]
async fn t_b19_inherits_task_run_execution() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (store, _trace, d) = dispatcher_with_tree(tree);
    d.trace()
        .record(
            "m1",
            make_origin_full("m1", "agent:adapter-tg", &[], Some(full_context())),
            "agent:bob",
        )
        .unwrap();
    d.reply("agent:bob", "m1", vec![1]).await.unwrap();
    let ctx = recv(&store, "agent:adapter-tg").await.context.expect("ctx");
    assert_eq!(ctx.task_id.as_deref(), Some("task-1"));
    assert_eq!(ctx.run_id.as_deref(), Some("run-1"));
    assert_eq!(ctx.execution_id.as_deref(), Some("exec-1"));
}

// T-B20 — AC-07: inherits trace_id + correlation_id.
#[tokio::test]
async fn t_b20_inherits_trace_and_correlation() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (store, _trace, d) = dispatcher_with_tree(tree);
    d.trace()
        .record(
            "m1",
            make_origin_full("m1", "agent:adapter-tg", &[], Some(full_context())),
            "agent:bob",
        )
        .unwrap();
    d.reply("agent:bob", "m1", vec![1]).await.unwrap();
    let ctx = recv(&store, "agent:adapter-tg").await.context.expect("ctx");
    assert_eq!(ctx.trace_id.as_deref(), Some("trace-1"));
    assert_eq!(ctx.correlation_id.as_deref(), Some("corr-1"));
}

// T-B21 — AC-07: in_reply_to stamped fresh, overwriting the inherited
// "old-irt" value.
#[tokio::test]
async fn t_b21_in_reply_to_stamped_fresh() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (store, _trace, d) = dispatcher_with_tree(tree);
    d.trace()
        .record(
            "m1",
            make_origin_full("m1", "agent:adapter-tg", &[], Some(full_context())),
            "agent:bob",
        )
        .unwrap();
    d.reply("agent:bob", "m1", vec![1]).await.unwrap();
    let ctx = recv(&store, "agent:adapter-tg").await.context.expect("ctx");
    assert_eq!(
        ctx.in_reply_to.as_deref(),
        Some("m1"),
        "in_reply_to overwritten with the replied-to id, not the inherited old-irt"
    );
}

// T-B22 — invalid `from` → InvalidTarget("invalid_id").
#[tokio::test]
async fn t_b22_invalid_from_rejected() {
    let tree = TestTree::new().add_root("agent:adapter-tg");
    let (_store, _trace, d) = dispatcher_with_tree(tree);
    let err = d.reply("user:", "m1", vec![1]).await.unwrap_err();
    assert_eq!(err, MsgError::InvalidTarget("invalid_id".into()));
}

// T-B23 — adapter not in tree → InvalidTarget("adapter_unknown").
#[tokio::test]
async fn t_b23_adapter_not_in_tree() {
    // Tree has bob but NOT agent:adapter-tg.
    let tree = TestTree::new().add_root("agent:bob");
    let (_store, _trace, d) = dispatcher_with_tree(tree);
    d.trace()
        .record(
            "m1",
            make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap();
    let err = d.reply("agent:bob", "m1", vec![1]).await.unwrap_err();
    assert_eq!(err, MsgError::InvalidTarget("adapter_unknown".into()));
}

// T-B24 — payload > MAX_PAYLOAD_BYTES → InvalidPayload("payload_too_large").
#[tokio::test]
async fn t_b24_payload_cap() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (_store, _trace, d) = dispatcher_with_tree(tree);
    d.trace()
        .record(
            "m1",
            make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap();
    let big = vec![0u8; MAX_PAYLOAD_BYTES + 1];
    let err = d.reply("agent:bob", "m1", big).await.unwrap_err();
    assert_eq!(err, MsgError::InvalidPayload("payload_too_large".into()));
}
