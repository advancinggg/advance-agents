//! AC-13 keep-losers detach (`keep_losers=true`) — rule-2 observable half.
//!
//! Wave-24 (2026-07-09, lane `m007-keeplosers`, MINIMAL BUILD-AND-HOLD). This
//! module materializes a **detached loser** [`ReplyResult`] for a pending
//! (never-replied) non-winner slot when an `(AnyOf, keep_losers=true)` session
//! resolves on its winner — the **observable half** of **AC-13 rule 2 / PRD §9.2 rule 1**. Prior
//! to this, `AwaitSession::snapshot_replies`'s `_ =>` arm silently DROPPED
//! pending (`None`) slots, so a loser that had not yet replied when the winner
//! won simply vanished from `AwaitResult.replies`, contradicting "keep losers".
//!
//! Detached-loser envelope (AC-13 rule 2 / PRD §9.2 rule 1 of the `detached` contract):
//! - `status = ReplyStatus::Cancelled` — the canonical any-of-loser status,
//!   projected to the WIT `detached` reply-status (`host_fn.rs`
//!   `rust_reply_status_to_wit`).
//! - `task_id` = **substitute-or-clear**: the originating
//!   `AgentAwaitRequest.context.task_id` when present (substitute), else `None`
//!   (clear → unattributed fire-and-forget). `ComponentFinished` slots carry no
//!   context, so `task_id = None`.
//! - `source` = the awaited target (`AgentRequest.target` / `component:{id}`),
//!   mirroring [`super::session::AwaitSession::fill_unresolved_as_timed_out`].
//! - `slot` preserved in-place so the WIT encoder recovers the correlation-id
//!   by index; empty `payload`; `received_at` = the caller-supplied timestamp.
//!
//! **HELD (AC-13 stays `untested`)**: AC-13 rule 2 / PRD rule 1 run-id/reply-to clearing has
//! real production readers (`dispatcher.reply` → `emit_delivery_event`; turn admission) but
//! **no production clearing writer** and **no proven detached-loser locus** on the real late-send
//! path (`SendHandler → handle_send`); `ReplyResult` still carries neither `run_id` nor
//! `in_reply_to`. Production AC-13 rule 4 / PRD rule 4 is also unrealized (late `send` aliases a
//! later OPEN same-source slot or NoMatch→mailbox; orphan `reply_late` is AC-17-only). And
//! rule 3 (detached cost attribution) has NO in-crate cost source, so the full
//! PRD §9.2 4-rule conjunction is not witnessed this lane. See MODULE-007 §3.6.
//!
//! `#![forbid(unsafe_code)]` (crate-wide) upheld — this module is pure data.

use advance_shared_types::await_session::{AwaitRequest, ReplyResult, ReplyStatus};
use chrono::{DateTime, Utc};

/// Build the detached-loser [`ReplyResult`] for a pending (never-replied)
/// non-winner slot, per AC-13 rule 2 / PRD §9.2 rule 1 (observable half). `req` is the
/// originating `AwaitRequest` for this slot (`None` only if the slot index is
/// somehow out of the `expected` vector — defensively yields an empty source +
/// cleared task-id rather than panicking).
pub(crate) fn materialize_detached_loser(
    req: Option<&AwaitRequest>,
    slot: u32,
    now: DateTime<Utc>,
) -> ReplyResult {
    let (source, task_id) = match req {
        // AgentRequest: substitute the awaited task-id if the request context
        // carried one, else clear (AC-13 rule 2 / PRD §9.2 rule 1). Symmetric with the winner's AC-13 rule (1)
        // rule-1 preservation via `await_request_task_id` at the on_reply chokepoint.
        Some(AwaitRequest::AgentRequest(r)) => (
            r.target.clone(),
            r.context.as_ref().and_then(|c| c.task_id.clone()),
        ),
        // ComponentFinished has no context → task-id cleared; source is the
        // `component:{id}` form (mirrors fill_unresolved_as_timed_out).
        Some(AwaitRequest::ComponentFinished(r)) => (format!("component:{}", r.component_id), None),
        None => (String::new(), None),
    };
    ReplyResult {
        slot,
        source,
        payload: Vec::new(),
        status: ReplyStatus::Cancelled, // → WIT `detached`
        received_at: now,
        task_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::await_session::{AgentAwaitRequest, ComponentAwaitRequest};
    use advance_shared_types::mailbox::MessageContext;

    fn ctx(task_id: Option<&str>) -> MessageContext {
        MessageContext {
            task_id: task_id.map(str::to_string),
            run_id: Some("run-should-not-appear".to_string()),
            execution_id: None,
            trace_id: None,
            in_reply_to: Some("irt-should-not-appear".to_string()),
            correlation_id: Some("corr".to_string()),
        }
    }

    fn agent_req(target: &str, context: Option<MessageContext>) -> AwaitRequest {
        AwaitRequest::AgentRequest(AgentAwaitRequest {
            target: target.to_string(),
            payload: Vec::new(),
            correlation_id: "corr".to_string(),
            context,
        })
    }

    // AgentRequest with an explicit context task-id → SUBSTITUTE (AC-13 rule 2 / PRD §9.2 rule 1).
    #[test]
    fn materialize_agent_substitutes_task_id() {
        let req = agent_req("agent:t2", Some(ctx(Some("task-x"))));
        let now = chrono::Utc::now();
        let r = materialize_detached_loser(Some(&req), 1, now);
        assert_eq!(r.slot, 1);
        assert_eq!(r.source, "agent:t2");
        assert!(matches!(r.status, ReplyStatus::Cancelled));
        assert_eq!(r.task_id.as_deref(), Some("task-x")); // substituted
        assert!(r.payload.is_empty());
        assert_eq!(r.received_at, now);
    }

    // AgentRequest whose context carries NO task-id → CLEAR (None).
    #[test]
    fn materialize_agent_clears_task_id_when_context_has_none() {
        let req = agent_req("agent:t3", Some(ctx(None)));
        let r = materialize_detached_loser(Some(&req), 2, chrono::Utc::now());
        assert_eq!(r.source, "agent:t3");
        assert!(matches!(r.status, ReplyStatus::Cancelled));
        assert_eq!(r.task_id, None); // cleared
    }

    // AgentRequest with NO context at all → CLEAR (None).
    #[test]
    fn materialize_agent_clears_task_id_when_context_absent() {
        let req = agent_req("agent:t4", None);
        let r = materialize_detached_loser(Some(&req), 0, chrono::Utc::now());
        assert_eq!(r.task_id, None);
        assert!(matches!(r.status, ReplyStatus::Cancelled));
    }

    // ComponentFinished → source `component:{id}`, task-id cleared (no context).
    #[test]
    fn materialize_component_uses_component_source_and_clears_task_id() {
        let req = AwaitRequest::ComponentFinished(ComponentAwaitRequest {
            component_id: "comp-x".to_string(),
            correlation_id: "corr".to_string(),
        });
        let r = materialize_detached_loser(Some(&req), 3, chrono::Utc::now());
        assert_eq!(r.source, "component:comp-x");
        assert_eq!(r.task_id, None);
        assert!(matches!(r.status, ReplyStatus::Cancelled));
    }

    // Defensive: a slot index with no matching `expected` entry → empty source,
    // cleared task-id (never panics).
    #[test]
    fn materialize_none_slot_is_defensive_empty() {
        let r = materialize_detached_loser(None, 7, chrono::Utc::now());
        assert_eq!(r.slot, 7);
        assert_eq!(r.source, "");
        assert_eq!(r.task_id, None);
        assert!(matches!(r.status, ReplyStatus::Cancelled));
    }
}
