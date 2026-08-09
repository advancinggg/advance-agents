//! Per-slot dispatch via [`advance_messaging::MailboxDispatcher`] (CONTRACT-051).
//!
//! For each [`AwaitRequest::AgentRequest`] slot, build a `Message` envelope and
//! invoke `dispatcher.deliver(target, msg)`. `target` is the canonical agent id
//! (`agent:<name>`) — `AgentAwaitRequest.target` must already be in this form;
//! the dispatch layer does NOT add another prefix. `MailboxDispatcherImpl::
//! deliver` validates the target via `is_safe_id`; raw names like `"t1"` would
//! be rejected with `MsgError::InvalidTarget`.
//!
//! For each [`AwaitRequest::ComponentFinished`] slot, return `Ok(())` without
//! invoking the dispatcher — component completion resolution lands via the
//! `run.completed` event subscriber (slice C).
//!
//! AC-09 deadlock triage (some-but-not-all-cycle case): slots whose index is
//! in the `deadlock_slots` set are NOT delivered (the dispatcher is not
//! invoked for them); they yield `DispatchSlotError::Deadlock(target)` so the
//! manager records the canonical per-slot `ReplyStatus::Failed("deadlock:
//! {target}")` via the existing per-slot dispatch-error recording path.

use std::collections::HashSet;
use std::time::SystemTime;

use advance_messaging::{is_safe_id, MailboxDispatcher};
use advance_shared_types::await_session::{AwaitRequest, SessionId};
use advance_shared_types::mailbox::{Message, MessageContext, MessageKind};

use crate::error::{classify_dispatch, DispatchSlotError};

/// Run per-slot dispatch for an entire AwaitRequest list. Returns one
/// `Result<(), DispatchSlotError>` per slot, in the same order as `requests`.
///
/// - `AgentRequest`: build `Message`, call `deliver(target, msg)`. Errors map
///   via [`classify_dispatch`].
/// - `ComponentFinished`: no dispatcher call; returns `Ok(())` (resolution
///   deferred to a later slice's run.completed subscriber).
///
/// `caller` is the bare caller name (e.g. `"researcher"`); the prefix
/// `agent:` is added when building `Message.from`.
///
/// `deadlock_slots` are slot indices the AC-09 admission gate flagged as
/// cyclic in the some-but-not-all-cycle case: those slots are NOT delivered
/// (the dispatcher is not invoked) and yield
/// `Err(DispatchSlotError::Deadlock(target))`.
pub async fn dispatch_slots(
    dispatcher: &dyn MailboxDispatcher,
    caller: &str,
    requests: &[AwaitRequest],
    session_id: &SessionId,
    deadlock_slots: &HashSet<usize>,
) -> Vec<Result<(), DispatchSlotError>> {
    let mut results = Vec::with_capacity(requests.len());
    for (slot_idx, req) in requests.iter().enumerate() {
        match req {
            AwaitRequest::AgentRequest(agent_req) => {
                // AC-09 some-but-not-all-cycle: skip dispatch for cyclic
                // slots; record the canonical per-slot deadlock failure.
                if deadlock_slots.contains(&slot_idx) {
                    results.push(Err(DispatchSlotError::Deadlock(agent_req.target.clone())));
                    continue;
                }
                // Adversarial round 1 W7 fix: fast-fail invalid targets
                // BEFORE Message allocation + deliver invocation. The
                // dispatcher's `validate_routing` rejects these too, but
                // pre-validation here saves the cost of building the
                // Message envelope (payload Vec clone + MessageContext
                // construction) for every bad slot in a burn-throughput
                // attack.
                if !is_safe_id(&agent_req.target) {
                    results.push(Err(DispatchSlotError::InvalidTarget(
                        agent_req.target.clone(),
                    )));
                    continue;
                }
                let msg = Message {
                    id: format!("session:{}:slot:{}", session_id.0, slot_idx),
                    kind: MessageKind::Agent,
                    from: format!("agent:{caller}"),
                    to: agent_req.target.clone(),
                    payload: agent_req.payload.clone(),
                    context: Some(MessageContext {
                        task_id: agent_req.context.as_ref().and_then(|c| c.task_id.clone()),
                        run_id: agent_req.context.as_ref().and_then(|c| c.run_id.clone()),
                        execution_id: agent_req
                            .context
                            .as_ref()
                            .and_then(|c| c.execution_id.clone()),
                        trace_id: agent_req.context.as_ref().and_then(|c| c.trace_id.clone()),
                        in_reply_to: Some(format!("session:{}:slot:{}", session_id.0, slot_idx)),
                        correlation_id: Some(agent_req.correlation_id.clone()),
                    }),
                    timestamp: SystemTime::now(),
                    origin: None,
                };
                let r = dispatcher
                    .deliver(&agent_req.target, msg)
                    .await
                    .map_err(|e| classify_dispatch(e, &agent_req.target));
                results.push(r);
            }
            AwaitRequest::ComponentFinished(_component_req) => {
                // Slice A: component completion resolves via a later slice's
                // run.completed event subscriber; no MailboxDispatcher call
                // here. Returning Ok(()) marks the slot as "dispatch-skipped"
                // (it will remain unresolved until that later-slice path fills
                // ReplyResult via on_reply / equivalent).
                results.push(Ok(()));
            }
        }
    }
    results
}
