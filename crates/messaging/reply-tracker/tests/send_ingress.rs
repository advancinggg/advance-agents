// await-leg B-3 (2026-06-22) — production `send` ingress witnesses.
//
// Proves the WASM `send` host-fn routes a child→parent reply into the parked
// parent's await session via MODULE-007 `on_reply` THROUGH THE PRODUCT INGRESS:
// the prod-REGISTERED `SendHandler` is looked up from a `HostRegistry`
// (`register_send_host_fn` → `lookup` → clone → drive) — NOT a harness `on_reply`
// call, NOT the channel-reply path (`cli/src/reply.rs` / `messaging/src/trace.rs`).
// Also proves a non-reply `send` falls back to genuine M006 mailbox delivery.
//
// Build-lane witness: proves the `send`→`on_reply` MECHANISM only; flips ZERO
// acceptance criteria. await-leg B-4a (2026-06-22) added `"messaging"` to
// `KNOWN_CAPABILITIES` (the guest-driven path is now reachable), but shipped agents
// stay dormant (no shipped guest imports `agent-messaging`). The AC `untested→passed`
// + SYS-AC flips are held for Wave-11 B-4b.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;

use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::{register_send_host_fn, AwaitSessionManagerImpl, ManagerOptions};
use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitResult, AwaitSessionStatus,
    OrchestrationError, ReplyStatus, TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use wasmtime::component::Val;

/// The witness reply payload the child `send`s; the resolved parent await must
/// carry it verbatim (proving the bytes flowed through the ingress to `on_reply`).
const SEND_PAYLOAD: &[u8] = &[0x5E, 0x4D, 0xB3, 0x01];

// ─── Fixtures ──────────────────────────────────────────────────────────

/// Always-Ok dispatcher (slot dispatch succeeds → the parent session stays Open,
/// awaiting the reply). Mirrors the `OkDispatcher` in `host_fn_handler.rs`.
struct OkDispatcher;
#[async_trait]
impl MailboxDispatcher for OkDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(&self, _f: &str, _i: &str, _p: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _f: &str,
        _t: &str,
        _p: Vec<u8>,
        _c: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

/// Records every `deliver(target, payload)` so the mailbox-fallback path
/// (no matching await slot) is observable.
#[derive(Default)]
struct RecordingDispatcher {
    delivered: StdMutex<Vec<(String, Vec<u8>)>>,
}
#[async_trait]
impl MailboxDispatcher for RecordingDispatcher {
    async fn deliver(&self, target: &str, msg: Message) -> Result<(), MsgError> {
        self.delivered
            .lock()
            .unwrap()
            .push((target.to_string(), msg.payload));
        Ok(())
    }
    async fn reply(&self, _f: &str, _i: &str, _p: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _f: &str,
        _t: &str,
        _p: Vec<u8>,
        _c: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

fn make_manager(dispatcher: Arc<dyn MailboxDispatcher>) -> Arc<AwaitSessionManagerImpl> {
    Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ))
}

fn test_ctx(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "tr-b3-test".to_string(),
        turn_id: None,
        capability: "messaging".to_string(),
        function: "agent-messaging::send".to_string(),
        run_id: None,
        iteration: None,
    }
}

fn agent_req(target: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![],
        correlation_id: correlation_id.to_string(),
        context: None,
    })
}

fn allof_options() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

async fn wait_for_session_count(manager: &AwaitSessionManagerImpl, expected: usize) {
    for _ in 0..200 {
        if manager.session_count_for_test().await == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!(
        "wait_for_session_count: expected {expected} sessions, got {}",
        manager.session_count_for_test().await
    );
}

/// Pull the prod-REGISTERED `send` handler out of the registry (lookup→clone) and
/// assert it is wired under the canonical capability/namespace/name — this is the
/// "drive the prod-registered fn" discipline (no harness `on_reply`).
fn registered_send_handler(manager: Arc<AwaitSessionManagerImpl>) -> Arc<dyn HostFunctionHandler> {
    let registry = InMemoryHostRegistry::new();
    register_send_host_fn(&registry, manager);
    let spec = registry
        .lookup("messaging")
        .into_iter()
        .find(|s| s.name == "send")
        .expect("`send` registered under capability `messaging`");
    assert_eq!(spec.namespace, "advance:runtime/agent-messaging@0.1.0");
    assert!(
        !spec.idempotent,
        "send is state-modifying → idempotent=false"
    );
    spec.handler
}

fn send_params(target: &str, payload: &[u8]) -> Vec<Val> {
    vec![
        Val::String(target.to_string()),
        Val::List(payload.iter().map(|b| Val::U8(*b)).collect()),
        Val::Option(None),
    ]
}

// ════════════════════════════════════════════════════════════════════════
// Witnesses
// ════════════════════════════════════════════════════════════════════════

/// T-B3-route: a child's `send(target=parent)` reaches the parked parent's
/// `on_reply` through the production ingress (registered SendHandler →
/// `handle_send` → `try_route_reply` → `on_reply`), resolving the await with the
/// sent payload. No harness `on_reply` call; no channel-reply path.
#[tokio::test]
async fn t_b3_route_reaches_on_reply() {
    let manager = make_manager(Arc::new(OkDispatcher));

    // Parent parks awaiting a reply from `agent:child`.
    let m = Arc::clone(&manager);
    let parent = tokio::spawn(async move {
        m.start_with_run(
            "parent",
            None,
            vec![agent_req("agent:child", "corr-1")],
            allof_options(),
        )
        .await
    });
    wait_for_session_count(&manager, 1).await;

    // Drive the prod-REGISTERED send handler as the child agent.
    let handler = registered_send_handler(Arc::clone(&manager));
    let out = handler
        .call(
            test_ctx("child"),
            send_params("agent:parent", SEND_PAYLOAD),
            1,
        )
        .await
        .expect("send handler returned Err");
    assert!(
        matches!(out[0], Val::Result(Ok(None))),
        "send should lower to result<_, msg-error>::Ok, got {:?}",
        out[0]
    );

    // The parked parent resolves with the routed reply — proves the bytes reached
    // `on_reply` via the product ingress.
    let result: Result<AwaitResult, OrchestrationError> =
        tokio::time::timeout(Duration::from_secs(2), parent)
            .await
            .expect("parent await did not resolve within 2s")
            .expect("parent task panicked");
    let await_result = result.expect("await should resolve Ok (reply routed)");
    assert_eq!(await_result.status, AwaitSessionStatus::Completed);
    assert_eq!(await_result.replies.len(), 1);
    assert_eq!(await_result.replies[0].source, "agent:child");
    assert_eq!(await_result.replies[0].payload, SEND_PAYLOAD);
    assert!(matches!(
        await_result.replies[0].status,
        ReplyStatus::Completed
    ));

    // Session consumed by the resolution.
    wait_for_session_count(&manager, 0).await;
}

/// T-B3-nomatch: a `send` to a target with NO open awaiting slot falls back to
/// genuine M006 mailbox delivery (no `on_reply` route, no silent drop).
#[tokio::test]
async fn t_b3_nomatch_falls_back_to_mailbox() {
    let dispatcher = Arc::new(RecordingDispatcher::default());
    let dyn_disp: Arc<dyn MailboxDispatcher> = dispatcher.clone();
    let manager = make_manager(dyn_disp);

    let handler = registered_send_handler(Arc::clone(&manager));
    let out = handler
        .call(
            test_ctx("child"),
            send_params("agent:nobody", SEND_PAYLOAD),
            1,
        )
        .await
        .expect("send handler returned Err");
    assert!(
        matches!(out[0], Val::Result(Ok(None))),
        "send should return Ok on the mailbox-fallback path"
    );

    let delivered = dispatcher.delivered.lock().unwrap();
    assert_eq!(
        delivered.len(),
        1,
        "expected exactly 1 mailbox delivery (no await slot matched → no on_reply route)"
    );
    assert_eq!(delivered[0].0, "agent:nobody");
    assert_eq!(delivered[0].1, SEND_PAYLOAD);
}

/// T-B3-malformed-target: a `send` to a non-`is_safe_id` target returns a WIT
/// `msg-error::invalid-target` (and never reaches `on_reply` or the dispatcher).
#[tokio::test]
async fn t_b3_invalid_target_msg_error() {
    let dispatcher = Arc::new(RecordingDispatcher::default());
    let dyn_disp: Arc<dyn MailboxDispatcher> = dispatcher.clone();
    let manager = make_manager(dyn_disp);

    let handler = registered_send_handler(Arc::clone(&manager));
    // Multi-colon / spaces fail `is_safe_id`.
    let out = handler
        .call(
            test_ctx("child"),
            send_params("not a:valid:id", SEND_PAYLOAD),
            1,
        )
        .await
        .expect("send handler returned Err");
    match &out[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, _) => assert_eq!(case, "invalid-target"),
            other => panic!("expected Variant(invalid-target, ..), got {other:?}"),
        },
        other => panic!("expected Result(Err(..)), got {other:?}"),
    }
    assert_eq!(
        dispatcher.delivered.lock().unwrap().len(),
        0,
        "a malformed target must not reach the dispatcher"
    );
}
