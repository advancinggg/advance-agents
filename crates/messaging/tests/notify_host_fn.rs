//! notify-agent host-fn slice (2026-06-13) — crate-test witness band TN-01..TN-08
//! for `NotifyAgentHandler` + `register_notify_host_fns`. Mirrors the
//! `reply-tracker/tests/host_fn_handler.rs` + `notify_channel.rs` (T-B28/T-B29) +
//! `circuit_breaker_gate.rs` (T-C04) precedents. TN-09 (the `encode_notify_error`
//! variant-spelling drift guard) lives in-crate in `src/host_fn.rs` because
//! `encode_notify_error` is `pub(crate)` and the `identity-unknown` arm is
//! unreachable through the dispatcher.
//!
//! `wasmtime::component::Val` has no `PartialEq`, so all Val assertions use
//! `matches!` / nested destructuring, never `==`.

mod common;

use std::sync::Arc;

use advance_messaging::{
    register_notify_host_fns, MailboxDispatcher, MailboxDispatcherImpl, MailboxStore,
    NotifyAgentHandler, DEFAULT_CAPACITY, NOTIFY_CAPABILITY, NOTIFY_NAMESPACE,
};
use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::mailbox::MessageKind;
use wasmtime::component::Val;

use crate::common::{make_mock_cb_bus, TestTree};

// ─── Fixtures ──────────────────────────────────────────────────────────

fn test_ctx(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "tr-notify-test".to_string(),
        turn_id: None,
        capability: NOTIFY_CAPABILITY.to_string(),
        function: format!("{NOTIFY_NAMESPACE}::notify-agent"),
        run_id: None,
        iteration: None,
    }
}

/// Build a plain dispatcher (no CB bus) over a fresh store seeded by `tree`.
/// Returns the store (for delivery inspection) + the dispatcher as a trait
/// object (what the handler holds).
fn plain_dispatcher(tree: TestTree) -> (Arc<MailboxStore>, Arc<dyn MailboxDispatcher>) {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let dispatcher: Arc<dyn MailboxDispatcher> =
        Arc::new(MailboxDispatcherImpl::new(store.clone(), Arc::new(tree)));
    (store, dispatcher)
}

fn payload_list(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().map(|b| Val::U8(*b)).collect())
}

/// Assert a Val is `Result(Err(Some(Variant(case, payload))))` with the expected
/// case-name and optional String payload.
fn assert_err_variant(val: &Val, case: &str, payload: Option<&str>) {
    match val {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(got_case, got_payload) => {
                assert_eq!(got_case, case, "variant case-name mismatch");
                match (got_payload.as_deref(), payload) {
                    (None, None) => {}
                    (Some(Val::String(s)), Some(exp)) => assert_eq!(s.as_str(), exp),
                    (got, exp) => panic!("{case}: payload mismatch got={got:?} expected={exp:?}"),
                }
            }
            other => panic!("expected Variant({case}), got {other:?}"),
        },
        other => panic!("expected Result(Err(Some(Variant))), got {other:?}"),
    }
}

// ════════════════════════════════════════════════════════════════════════
// TN-01..TN-08
// ════════════════════════════════════════════════════════════════════════

/// TN-01 — Delivery: `ctx.agent_id="system"`, real dispatcher seeded with the
/// target. Handler returns Ok-unit AND the target mailbox got exactly one
/// `Message` (from="system", kind=System, payload round-trips, origin=None).
#[tokio::test]
async fn tn01_notify_agent_delivers_to_target() {
    let tree = TestTree::new().add_root("agent:research");
    let (store, dispatcher) = plain_dispatcher(tree);
    let handler = NotifyAgentHandler::new(dispatcher);

    let result = handler
        .call(
            test_ctx("system"),
            vec![
                Val::String("agent:research".into()),
                payload_list(&[1, 2, 3]),
                Val::Option(None),
            ],
            1,
        )
        .await
        .expect("handler returned Err");

    assert_eq!(result.len(), 1);
    assert!(
        matches!(result[0], Val::Result(Ok(None))),
        "expected Ok-unit, got {:?}",
        result[0]
    );

    let mb = store.get("agent:research").expect("target mailbox exists");
    let msg = mb.poll().expect("exactly one message queued");
    assert_eq!(msg.from, "system");
    assert!(matches!(msg.kind, MessageKind::System));
    assert_eq!(msg.payload, vec![1, 2, 3]);
    assert!(msg.origin.is_none(), "notify must not forge origin");
    assert!(mb.poll().is_none(), "only one message must be queued");
}

/// TN-02 — unknown target: a WELL-FORMED-but-absent id (`agent:ghost`) passes
/// `is_safe_id` then fails `tree.agent_exists` → `invalid-target("target_unknown")`.
/// No mailbox is created (agent_exists check precedes get_or_create). Mirrors T-B28.
#[tokio::test]
async fn tn02_notify_agent_unknown_target() {
    let tree = TestTree::new(); // agent:ghost NOT present
    let (store, dispatcher) = plain_dispatcher(tree);
    let handler = NotifyAgentHandler::new(dispatcher);

    let result = handler
        .call(
            test_ctx("system"),
            vec![
                Val::String("agent:ghost".into()),
                payload_list(&[1]),
                Val::Option(None),
            ],
            1,
        )
        .await
        .expect("handler returned Err");

    assert_err_variant(&result[0], "invalid-target", Some("target_unknown"));
    assert!(
        store.get("agent:ghost").is_none(),
        "no mailbox must be created for an unknown target"
    );
}

/// TN-03 — over-capacity: fill the target to cap (100) via the dispatcher
/// directly, then the handler call (the 101st) returns `mailbox-full`. Robust
/// no-101st-delivery witness: drain via an unbounded `while let` and assert
/// exactly 100 queued. Default single-threaded `#[tokio::test]` keeps `poll()`'s
/// `try_lock` uncontended (no early `None`).
#[tokio::test]
async fn tn03_notify_agent_mailbox_full() {
    let tree = TestTree::new().add_root("agent:research");
    let (store, dispatcher) = plain_dispatcher(tree);

    for _ in 0..100 {
        dispatcher
            .notify_agent("system", "agent:research", vec![0], None)
            .await
            .expect("fill must succeed below cap");
    }

    let handler = NotifyAgentHandler::new(Arc::clone(&dispatcher));
    let result = handler
        .call(
            test_ctx("system"),
            vec![
                Val::String("agent:research".into()),
                payload_list(&[0]),
                Val::Option(None),
            ],
            1,
        )
        .await
        .expect("handler returned Err");

    assert_err_variant(&result[0], "mailbox-full", None);

    let mb = store.get("agent:research").expect("mailbox exists");
    let mut count = 0usize;
    while mb.poll().is_some() {
        count += 1;
    }
    assert_eq!(
        count, 100,
        "exactly 100 must be queued; the 101st must not have enqueued"
    );
}

/// TN-04 — open breaker: target IN tree, breaker OPEN for it (the CB gate runs
/// BEFORE `tree.agent_exists`). Returns `capability-denied("breaker_open")`, and
/// the bus's operator reason must NOT leak (PII discipline, mirror T-C04). No
/// delivery.
#[tokio::test]
async fn tn04_notify_agent_breaker_open() {
    let tree = TestTree::new().add_root("agent:research");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(
        MailboxDispatcherImpl::new(store.clone(), Arc::new(tree))
            .with_circuit_breaker_bus(make_mock_cb_bus(&[("agent:research", "pii_secret_reason")])),
    );
    let handler = NotifyAgentHandler::new(dispatcher);

    let result = handler
        .call(
            test_ctx("system"),
            vec![
                Val::String("agent:research".into()),
                payload_list(&[1]),
                Val::Option(None),
            ],
            1,
        )
        .await
        .expect("handler returned Err");

    // capability-denied("breaker_open"), and the bus's PII reason must not leak.
    match &result[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, Some(payload)) => {
                assert_eq!(case, "capability-denied");
                match payload.as_ref() {
                    Val::String(s) => {
                        assert_eq!(s, "breaker_open");
                        assert_ne!(
                            s, "pii_secret_reason",
                            "bus operator reason must not leak (PII discipline)"
                        );
                    }
                    other => panic!("expected String payload, got {other:?}"),
                }
            }
            other => panic!("expected Variant(capability-denied, Some), got {other:?}"),
        },
        other => panic!("expected Result(Err(Some)), got {other:?}"),
    }

    assert!(
        store
            .get("agent:research")
            .map(|mb| mb.poll().is_none())
            .unwrap_or(true),
        "no message must be delivered when the breaker is open"
    );
}

/// TN-05 — registration: a fresh registry holding only notify → `lookup` returns
/// exactly one spec with the pinned name/namespace/capability/idempotent. (A real
/// composition root also calling `register_reply_tracker_host_fns` yields 3 specs
/// under "messaging", non-colliding by distinct namespace — a HANDOFF item.)
#[test]
fn tn05_register_notify_host_fns_one_spec() {
    let reg = InMemoryHostRegistry::new();
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let dispatcher: Arc<dyn MailboxDispatcher> =
        Arc::new(MailboxDispatcherImpl::new(store, Arc::new(TestTree::new())));

    register_notify_host_fns(&reg, dispatcher);

    let specs = reg.lookup(NOTIFY_CAPABILITY);
    assert_eq!(specs.len(), 1, "exactly one notify-agent spec");
    let spec = &specs[0];
    assert_eq!(spec.name, "notify-agent");
    assert_eq!(spec.namespace, NOTIFY_NAMESPACE);
    assert_eq!(spec.capability, NOTIFY_CAPABILITY);
    assert!(
        !spec.idempotent,
        "notify-agent is state-modifying (enqueues a message) → idempotent=false"
    );
}

/// TN-06 — message-context round-trip: pass an `option<message-context>` record
/// with all 3 WIT fields; assert the delivered `Message.context` carries them and
/// the 3 runtime-internal fields default to None.
#[tokio::test]
async fn tn06_notify_agent_message_context_round_trip() {
    let tree = TestTree::new().add_root("agent:research");
    let (store, dispatcher) = plain_dispatcher(tree);
    let handler = NotifyAgentHandler::new(dispatcher);

    let context = Val::Option(Some(Box::new(Val::Record(vec![
        (
            "task-id".into(),
            Val::Option(Some(Box::new(Val::String("task-1".into())))),
        ),
        (
            "run-id".into(),
            Val::Option(Some(Box::new(Val::String("run-1".into())))),
        ),
        (
            "execution-id".into(),
            Val::Option(Some(Box::new(Val::String("exec-1".into())))),
        ),
    ]))));

    let result = handler
        .call(
            test_ctx("system"),
            vec![
                Val::String("agent:research".into()),
                payload_list(&[9]),
                context,
            ],
            1,
        )
        .await
        .expect("handler returned Err");

    assert!(matches!(result[0], Val::Result(Ok(None))));

    let mb = store.get("agent:research").expect("mailbox exists");
    let msg = mb.poll().expect("one message");
    let ctx = msg.context.expect("context present");
    assert_eq!(ctx.task_id.as_deref(), Some("task-1"));
    assert_eq!(ctx.run_id.as_deref(), Some("run-1"));
    assert_eq!(ctx.execution_id.as_deref(), Some("exec-1"));
    assert_eq!(ctx.trace_id, None);
    assert_eq!(ctx.in_reply_to, None);
    assert_eq!(ctx.correlation_id, None);
}

/// TN-07 — decode-fail: (a) a wrong-type first param and (b) EMPTY params (the
/// arity guard) both → `invalid-target("decode-failed:...")` with NO delivery and
/// NO panic.
#[tokio::test]
async fn tn07_notify_agent_decode_fail() {
    let tree = TestTree::new().add_root("agent:research");
    let (store, dispatcher) = plain_dispatcher(tree);
    let handler = NotifyAgentHandler::new(dispatcher);

    // (a) wrong-type first param (arity is 3, decode of agent-id fails).
    let result_a = handler
        .call(
            test_ctx("system"),
            vec![Val::S32(42), payload_list(&[]), Val::Option(None)],
            1,
        )
        .await
        .expect("handler returned Err");
    assert_decode_failed(&result_a[0]);

    // (b) empty params — exercises the `params.len() != 3` arity guard (no panic).
    let result_b = handler
        .call(test_ctx("system"), vec![], 1)
        .await
        .expect("handler returned Err");
    assert_decode_failed(&result_b[0]);

    assert!(
        store.get("agent:research").is_none(),
        "decode failures must not deliver"
    );
}

fn assert_decode_failed(val: &Val) {
    match val {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, Some(payload)) => {
                assert_eq!(case, "invalid-target");
                match payload.as_ref() {
                    Val::String(s) => {
                        assert!(s.starts_with("decode-failed:"), "unexpected msg: {s:?}")
                    }
                    other => panic!("expected String payload, got {other:?}"),
                }
            }
            other => panic!("expected Variant(invalid-target, Some), got {other:?}"),
        },
        other => panic!("expected Result(Err(Some)), got {other:?}"),
    }
}

/// TN-08 — pin the capability + namespace strings (pitfall 5). A future rename is
/// then a deliberate test edit that doubles as the cli-linker sync point.
#[test]
fn tn08_pinned_capability_and_namespace() {
    assert_eq!(NOTIFY_CAPABILITY, "messaging");
    assert_eq!(NOTIFY_NAMESPACE, "advance:runtime/notify@0.1.0");
}
