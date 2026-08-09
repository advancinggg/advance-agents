//! Event-builder helpers for all 11 PRD §15.3.4A run.* event types.
//!
//! Slice A shipped 4 helpers (`run.created`, `run.reused`,
//! `run.round_completed`, `run.completed`). Slice B adds 7 more
//! (`run.suspended`, `run.resumed`, `run.paused`, `run.failed`,
//! `run.cancelled`, `run.interrupted`, `run.repetition_detected`) AND
//! amends two Slice A payloads to PRD-compliant shapes:
//! - `run.reused` payload gains `status` field (PRD line 5305).
//! - `run.round_completed` payload becomes `{iteration, token_used,
//!   cost_usd, decision}` (replacing Slice A's `blocked: bool` per PRD
//!   line 5308).
//!
//! Per §3.6 known-gap, `trace_id` / `span_id` are per-emit UUID v4
//! placeholders; a future slice plumbs the chain-level trace_id from
//! M001 / M005.

use advance_shared_types::event::Event;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

/// `run.round_completed.payload.decision` wire-format constants. PRD
/// §15.3.4A line 5308 illustrates Rust enum rendering
/// (`continue-allowed` / `blocked("halted: ...")` / `blocked("cancelled:
/// ...")`); Slice B picks the colon-separated JSON wire encoding that
/// preserves the (variant, reason) pair losslessly without escape-quote
/// noise.
pub const DECISION_CONTINUE_ALLOWED: &str = "continue-allowed";
pub const DECISION_BLOCKED_ROUNDS_EXCEEDED: &str = "blocked:rounds-exceeded";
pub const DECISION_BLOCKED_CANCEL_PENDING: &str = "blocked:cancel-pending";

fn base_event(
    event_type: &str,
    run_id: Option<&str>,
    task_id: Option<&str>,
    agent_id: &str,
    payload: serde_json::Value,
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: task_id.map(|t| t.to_string()),
        run_id: run_id.map(|r| r.to_string()),
        execution_id: None,
        trace_id: Uuid::new_v4().to_string(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload,
        duration_ms: None,
    }
}

pub(crate) fn run_created_event(run_id: &str, task_id: &str, controller_agent: &str) -> Event {
    base_event(
        "run.created",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({
            "task_id": task_id,
            "controller_agent": controller_agent,
        }),
    )
}

/// Slice B amendment: payload gains `status` field (PRD §15.3.4A line
/// 5305: `agent_id, task_id, run_id, status`).
pub(crate) fn run_reused_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    status: &str,
) -> Event {
    base_event(
        "run.reused",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({
            "task_id": task_id,
            "controller_agent": controller_agent,
            "status": status,
        }),
    )
}

/// Slice B amendment: payload is `{iteration, token_used, cost_usd,
/// decision}` per PRD §15.3.4A line 5308. The Slice A `blocked: bool` +
/// optional reason payload is replaced entirely.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_round_completed_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    iteration: u32,
    token_used: u64,
    cost_usd: f64,
    decision: &str,
    // Stage-F obs SLICE 1: optional handle-message chain `trace_id` +
    // chain-root `parent_span_id`. `None` LEAVES `base_event`'s fresh-v4
    // `trace_id` + `None` parent intact (override invariant — never an empty
    // string, so the `assert_uuid_v4` tripwire on `run.*` events stays green).
    trace_id: Option<&str>,
    parent_span_id: Option<&str>,
) -> Event {
    let mut event = base_event(
        "run.round_completed",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({
            "iteration": iteration,
            "token_used": token_used,
            "cost_usd": cost_usd,
            "decision": decision,
        }),
    );
    // Override ONLY trace_id + parent_span_id (NEVER span_id — stays fresh-v4).
    if let Some(t) = trace_id {
        event.trace_id = t.to_string();
    }
    if let Some(p) = parent_span_id {
        event.parent_span_id = Some(p.to_string());
    }
    event
}

pub(crate) fn run_completed_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    outcome: &str,
) -> Event {
    base_event(
        "run.completed",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({
            "outcome": outcome,
        }),
    )
}

// -- Slice B new helpers --

pub(crate) fn run_suspended_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    root_await_session_id: &str,
) -> Event {
    base_event(
        "run.suspended",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({
            "root_await_session_id": root_await_session_id,
        }),
    )
}

pub(crate) fn run_resumed_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    reason: &str,
) -> Event {
    base_event(
        "run.resumed",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({ "reason": reason }),
    )
}

pub(crate) fn run_paused_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    reason: &str,
) -> Event {
    base_event(
        "run.paused",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({ "reason": reason }),
    )
}

pub(crate) fn run_failed_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    reason: &str,
) -> Event {
    base_event(
        "run.failed",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({ "reason": reason }),
    )
}

pub(crate) fn run_cancelled_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    reason: &str,
) -> Event {
    base_event(
        "run.cancelled",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({ "reason": reason }),
    )
}

pub(crate) fn run_interrupted_event(
    run_id: &str,
    task_id: &str,
    controller_agent: &str,
    reason: &str,
) -> Event {
    base_event(
        "run.interrupted",
        Some(run_id),
        Some(task_id),
        controller_agent,
        json!({ "reason": reason }),
    )
}

/// Slice B `run.repetition_detected` builder. `run_id` + `task_id` are
/// optional: when the `AgentRunResolver` cannot uniquely map the
/// triggering `agent_id` to a live Run (no resolver configured, no
/// match, OR ambiguous-multi), both Event-level fields are `None` and
/// serde-emit them as `null`. Payload carries
/// `{detection_type, details, repeat_count, action_taken}` (4 fields;
/// `run_id` and `agent_id` are NOT duplicated in payload per the Slice
/// B wire-format pattern rule).
pub(crate) fn run_repetition_detected_event(
    run_id: Option<&str>,
    task_id: Option<&str>,
    agent_id: &str,
    detection_type: &str,
    details: &str,
    repeat_count: u32,
    action_taken: &str,
) -> Event {
    base_event(
        "run.repetition_detected",
        run_id,
        task_id,
        agent_id,
        json!({
            "detection_type": detection_type,
            "details": details,
            "repeat_count": repeat_count,
            "action_taken": action_taken,
        }),
    )
}
