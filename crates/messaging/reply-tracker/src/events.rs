//! Slice E (2026-05-24) — `orchestration.*` event builder for the one event
//! variant emittable in-boundary this slice.
//!
//! Per MODULE-007 §3.6: of the 7 `orchestration.*` event variants listed under
//! AC-17 (`await_started`, `await_progress`, `await_satisfied`,
//! `await_idle_timeout`, `await_session_closed`, `reply_late`,
//! `deadlock_rejected`), **3 were in-boundary** as of Wave-15 (now ALL 7 —
//! see the Wave-20 note below) for `reply-tracker`:
//! `await_progress` (slice-E, via `HeartbeatHandler` + a fresh
//! `HostCallContext.trace_id`), plus `deadlock_rejected` + `await_idle_timeout`
//! (Wave-15 Lane A, 2026-06-24). The two Wave-15 events are emitted from the
//! manager admission / idle-monitor async paths where NO `HostCallContext`
//! exists, so they carry an **empty `trace_id`** + a session-stable envelope
//! (caller `agent_id` + `caller_run_id` + `SessionId`) — the established
//! `advance_shared_types::event::Event::observability()` precedent. This is
//! PRD §15.2-consistent: §15.2 forbids *conflating* `trace_id` (observability
//! chain) with `run_id` (business wave) across an await span that crosses
//! multiple traces; an empty `trace_id` claims no trace correlation, so it
//! conflates nothing (NOT the stored session-stable surrogate §15.2 forbids —
//! that would be a fresh trace_id captured at admission and reused stale). See
//! MODULE-007 §3.8 Implementation Notes (intentional drift). **Wave-20 Lane
//! `messagingabi` (2026-06-27): the remaining 4 (`await_started`,
//! `await_satisfied`, `await_session_closed`, `reply_late`) are NOW built
//! in-boundary** (builders below + emit sites in `manager.rs`), reusing the same
//! session-stable empty-`trace_id` envelope. All 7 `orchestration.*` events now
//! emit; AC-17 flips `untested→passed` at SUMMARY (witnessed in
//! `tests/orchestration_events.rs` + `tests/deadlock_detection.rs` via an
//! in-memory `RecordingEmitter`).
//!
//! `await_progress` IS in-boundary because the emit happens at the
//! `HeartbeatHandler` call boundary where `HostCallContext.trace_id` is
//! fresh per WIT call. AC-12 (whose criterion is specifically the
//! `await_progress` emit + RESET conjunction) is closed by the slice-B
//! in-boundary RESET-half + slice-E EMIT-half together. **As of Wave-20 all 7
//! `orchestration.*` events emit in-boundary** (`await_progress` + the Wave-15
//! `deadlock_rejected`/`await_idle_timeout` + the 4 Wave-20 events below);
//! AC-17 flips at SUMMARY.
//!
//! Envelope rules mirror `crates/capabilities/cap-tools/src/events.rs`
//! (MODULE-019 cap-tools precedent):
//! - `id` / `span_id` = fresh `Uuid::new_v4().to_string()` per event.
//! - `timestamp` = `Utc::now()`.
//! - `agent_id` = `ctx.agent_id`.
//! - `trace_id` = `ctx.trace_id` (HostCallContext.trace_id is `String`,
//!                NOT `Option`; no fallback chain).
//! - `run_id` = `ctx.run_id` (passed through verbatim).
//! - `task_id` / `execution_id` / `parent_span_id` = None.
//! - `duration_ms` = None (heartbeat is a point-in-time event, not a
//!                   spanned operation).
//!
//! ## PII discipline (MODULE-007 §2.9)
//!
//! Payload carries only structurally-typed fields:
//! - `session_id` = UUID v4 (`SessionId.0`, opaque),
//! - `target` = canonical `agent:<name>` form,
//! - `progress` = WIT-provided string passed through verbatim per PRD §9.2
//!   (agents are themselves the trust boundary for their own progress
//!   content; reply-tracker does NOT redact, matching cap-tools
//!   `tool.invoke` precedent which passes `tool_id` / `method` through
//!   unredacted).

use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::await_session::SessionId;
use advance_shared_types::event::Event;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

/// `orchestration.await_progress` event_type constant.
///
/// **Invariant**: byte-identical to
/// `advance_event_bus::taxonomy::orchestration::AWAIT_PROGRESS` (asserted by
/// the `tests/orchestration_events.rs::t17z_event_type_constant_byte_parity`
/// test under the `advance-event-bus` dev-dep — production code defines this
/// const LOCALLY to avoid the event-bus heavy deps).
pub const AWAIT_PROGRESS: &str = "orchestration.await_progress";

/// Build an `orchestration.await_progress` event from a `HostCallContext`
/// captured at `HeartbeatHandler` entry + per-session fields.
///
/// Payload schema per PRD §15.3.4B:
/// ```json
/// { "session_id": "<uuid>", "target": "agent:<name>", "progress": "<string-or-null>" }
/// ```
///
/// # Arguments
/// - `ctx`: caller context (provides agent_id / trace_id / run_id envelope).
/// - `session_id`: the AwaitSession whose idle clock was just reset
///   (returned by `AwaitSessionManagerImpl::heartbeat_for_target`).
/// - `target`: the caller agent id (canonical `agent:<name>` form per PRD
///   §15.3.4B `target` field — the agent reporting progress IS the target
///   of an outer await-session; from-target heartbeat semantics).
/// - `progress`: the WIT-provided progress string (None → JSON `null`).
pub fn build_await_progress_event(
    ctx: &HostCallContext,
    session_id: &SessionId,
    target: &str,
    progress: Option<&str>,
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: ctx.agent_id.clone(),
        task_id: None,
        run_id: ctx.run_id.clone(),
        execution_id: None,
        trace_id: ctx.trace_id.clone(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: AWAIT_PROGRESS.to_string(),
        payload: json!({
            "session_id": session_id.0,
            "target": target,
            "progress": progress,
        }),
        duration_ms: None,
    }
}

/// `orchestration.deadlock_rejected` event_type constant.
///
/// **Invariant**: byte-identical to
/// `advance_event_bus::taxonomy::orchestration::DEADLOCK_REJECTED` (asserted by
/// `tests/orchestration_events.rs` under the `advance-event-bus` dev-dep —
/// production code defines this const LOCALLY to avoid the event-bus heavy
/// deps, mirroring `AWAIT_PROGRESS`).
pub const DEADLOCK_REJECTED: &str = "orchestration.deadlock_rejected";

/// `orchestration.await_idle_timeout` event_type constant.
///
/// **Invariant**: byte-identical to
/// `advance_event_bus::taxonomy::orchestration::AWAIT_IDLE_TIMEOUT`.
pub const AWAIT_IDLE_TIMEOUT: &str = "orchestration.await_idle_timeout";

/// Build an `orchestration.deadlock_rejected` event for the AC-09
/// some-but-not-all-cycle admission triage (SYS-AC-169).
///
/// Emitted from `AwaitSessionManagerImpl::start_with_run_inner` where NO
/// `HostCallContext` exists, so `trace_id` is **empty** + the envelope is
/// session-stable (caller `agent_id` + `caller_run_id`). See the module doc.
///
/// Payload schema per PRD §15.3.4B `deadlock_rejected`:
/// ```json
/// { "requester": "<bare caller>", "targets": ["agent:<name>", ...], "cycle": ["<caller>", ..., "<target>"] }
/// ```
///
/// # Arguments
/// - `requester`: the awaiting caller (bare agent name).
/// - `run_id`: the caller's run id (`None` when unavailable — e.g. the
///   trait `start()` path delegates `caller_run_id=None`).
/// - `targets`: the canonical `agent:<name>` cyclic targets that were rejected.
/// - `cycle`: a representative detected cycle path (`[caller, …, target]`).
pub fn build_deadlock_rejected_event(
    requester: &str,
    run_id: Option<&str>,
    targets: &[String],
    cycle: &[String],
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: requester.to_string(),
        task_id: None,
        run_id: run_id.map(|s| s.to_string()),
        execution_id: None,
        trace_id: String::new(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: DEADLOCK_REJECTED.to_string(),
        payload: json!({
            "requester": requester,
            "targets": targets,
            "cycle": cycle,
        }),
        duration_ms: None,
    }
}

/// Build an `orchestration.await_idle_timeout` event for the AC-10
/// `TimeoutPolicy::ReturnPartial` idle resolution (SYS-AC-252).
///
/// Emitted from `idle::resolve_idle` (the per-session idle monitor) where NO
/// `HostCallContext` exists, so `trace_id` is **empty** + the envelope is
/// session-stable (caller `agent_id` from `session.agent_id` + `caller_run_id`
/// from the session). See the module doc.
///
/// Payload schema per PRD §15.3.4B `await_idle_timeout`:
/// ```json
/// { "session_id": "<uuid>", "target": "<first timed-out slot source>", "idle_seconds": <u32> }
/// ```
///
/// # Arguments
/// - `agent_id`: the session's caller (bare agent name).
/// - `run_id`: the caller's run id (`None` when unavailable).
/// - `session_id`: the timed-out session.
/// - `target`: the first timed-out slot's source (`agent:<name>` or
///   `component:<id>`), or the caller when no slot source is available.
/// - `idle_seconds`: the effective idle-timeout threshold that elapsed.
pub fn build_idle_timeout_event(
    agent_id: &str,
    run_id: Option<&str>,
    session_id: &SessionId,
    target: &str,
    idle_seconds: u32,
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: run_id.map(|s| s.to_string()),
        execution_id: None,
        trace_id: String::new(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: AWAIT_IDLE_TIMEOUT.to_string(),
        payload: json!({
            "session_id": session_id.0,
            "target": target,
            "idle_seconds": idle_seconds,
        }),
        duration_ms: None,
    }
}

// ---------------------------------------------------------------------------
// Wave-20 Lane `messagingabi` (2026-06-27) — the 4 remaining orchestration.*
// events, closing AC-17 (all 7). All four are emitted from the reply-tracker
// manager terminals where NO `HostCallContext` exists, so they carry an
// **empty `trace_id`** + a session-stable envelope (caller `agent_id` +
// `caller_run_id` + `SessionId`) — identical envelope discipline to
// `build_deadlock_rejected_event` / `build_idle_timeout_event` above. These four
// emits need only fields already in manager scope (NO `agent_tree` consulted).
// (W24 `perchild-daemon-2`: the await-deadlock-direction ADR
// [docs/adr/2026-06-10-await-deadlock-direction-adjudication.md]'s "production
// `ManagerOptions` must not wire `agent_tree`" landmine is SUPERSEDED after the
// `forms_cycle` direction fix landed
// — `build_await_messaging_chain` now wires `agent_tree` on the messaging/per-child
// path, SYS-AC-280; these four events remain `agent_tree`-independent regardless.)
// ---------------------------------------------------------------------------

/// `orchestration.await_started` event_type constant.
///
/// **Invariant**: byte-identical to
/// `advance_event_bus::taxonomy::orchestration::AWAIT_STARTED`.
pub const AWAIT_STARTED: &str = "orchestration.await_started";

/// `orchestration.await_satisfied` event_type constant.
///
/// **Invariant**: byte-identical to
/// `advance_event_bus::taxonomy::orchestration::AWAIT_SATISFIED`.
pub const AWAIT_SATISFIED: &str = "orchestration.await_satisfied";

/// `orchestration.await_session_closed` event_type constant.
///
/// **Invariant**: byte-identical to
/// `advance_event_bus::taxonomy::orchestration::AWAIT_SESSION_CLOSED`.
pub const AWAIT_SESSION_CLOSED: &str = "orchestration.await_session_closed";

/// `orchestration.reply_late` event_type constant.
///
/// **Invariant**: byte-identical to
/// `advance_event_bus::taxonomy::orchestration::REPLY_LATE`.
pub const REPLY_LATE: &str = "orchestration.reply_late";

/// Build an `orchestration.await_started` event at admission-success.
///
/// Emitted once per admitted session in
/// `AwaitSessionManagerImpl::start_with_run_inner` after the session is
/// inserted and the deadlock gate has passed.
///
/// Payload: `{ "session_id": "<uuid>", "mode": "all-of"|"any-of", "targets": <usize> }`.
///
/// # Arguments
/// - `agent_id`: the awaiting caller (bare agent name).
/// - `run_id`: the caller's run id (`None` when unavailable).
/// - `session_id`: the freshly-admitted session.
/// - `mode`: the await mode in canonical kebab form (`"all-of"` / `"any-of"`).
/// - `target_count`: number of awaited slots (`expected.len()`).
pub fn build_await_started_event(
    agent_id: &str,
    run_id: Option<&str>,
    session_id: &SessionId,
    mode: &str,
    target_count: usize,
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: run_id.map(|s| s.to_string()),
        execution_id: None,
        trace_id: String::new(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: AWAIT_STARTED.to_string(),
        payload: json!({
            "session_id": session_id.0,
            "mode": mode,
            "targets": target_count,
        }),
        duration_ms: None,
    }
}

/// Build an `orchestration.await_satisfied` event at a `Completed` resolution.
///
/// **Emitted exactly once per session that resolves `Completed`, INSIDE the
/// owning `sessions.remove` success block** (keyed on the remove succeeding),
/// NOT at the `AwaitResult` build point — this is the exactly-once guard for
/// the early-resolve / `on_reply` race (an early-resolve terminal builds its
/// `AwaitResult` before its conditional remove, so emitting at the build point
/// would double-fire when a concurrent `on_reply` already removed+resolved the
/// session). Only the `Completed` terminal emits this; `FailedDispatch`,
/// idle-timeout, and close have their own events.
///
/// Payload: `{ "session_id": "<uuid>", "mode": "all-of"|"any-of", "replies": <usize> }`.
pub fn build_await_satisfied_event(
    agent_id: &str,
    run_id: Option<&str>,
    session_id: &SessionId,
    mode: &str,
    reply_count: usize,
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: run_id.map(|s| s.to_string()),
        execution_id: None,
        trace_id: String::new(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: AWAIT_SATISFIED.to_string(),
        payload: json!({
            "session_id": session_id.0,
            "mode": mode,
            "replies": reply_count,
        }),
        duration_ms: None,
    }
}

/// Build an `orchestration.await_session_closed` event for the `close()`
/// cascade (cancel-run / pause-run / parent cascade).
///
/// Emitted once per `close()` after the session is removed. `reason` is a
/// host-internal string (not guest-controlled at this surface).
///
/// Payload: `{ "session_id": "<uuid>", "reason": "<string>" }`.
pub fn build_await_session_closed_event(
    agent_id: &str,
    run_id: Option<&str>,
    session_id: &SessionId,
    reason: &str,
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: run_id.map(|s| s.to_string()),
        execution_id: None,
        trace_id: String::new(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: AWAIT_SESSION_CLOSED.to_string(),
        payload: json!({
            "session_id": session_id.0,
            "reason": reason,
        }),
        duration_ms: None,
    }
}

/// Build an `orchestration.reply_late` event for a reply that arrived for an
/// already-resolved / closed session on the direct `on_reply` orphan branch (AC-17 event path; NOT production AC-13 rule 4 / PRD rule 4 for child `send` — that path aliases later OPEN same-source or NoMatch→mailbox. PRD §9.2 rule 4 intent: the loser reply is
/// recorded as `reply_late` and NOT routed back to the parent AwaitSession).
///
/// Emitted at the `on_reply` orphan / session-miss (`None`) branch. The caller
/// MUST pass a **sanitized** `source` (the branch precedes source validation,
/// so `reply.source` is caller-controlled there — sanitized via
/// `sanitize_for_error` to bound log-amplification).
///
/// Payload: `{ "session_id": "<uuid>", "source": "<sanitized>", "slot": <u32> }`.
/// The envelope `agent_id` carries the (sanitized) responding source — the
/// awaiting caller is unknown at this branch (the session is already gone).
pub fn build_reply_late_event(
    source_sanitized: &str,
    run_id: Option<&str>,
    session_id: &SessionId,
    slot: u32,
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: source_sanitized.to_string(),
        task_id: None,
        run_id: run_id.map(|s| s.to_string()),
        execution_id: None,
        trace_id: String::new(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: REPLY_LATE.to_string(),
        payload: json!({
            "session_id": session_id.0,
            "source": source_sanitized,
            "slot": slot,
        }),
        duration_ms: None,
    }
}

/// Build the production CONTRACT-216 late-reply outcome for a detached
/// keep-losers turn.  Unlike [`build_reply_late_event`], this path starts at
/// `messaging.send` after the await session has already been removed, so the
/// only remaining correlation key available to MODULE-006 is the trusted,
/// host-stamped turn id.  Await turn ids have the fixed
/// `session:<session-id>:slot:<slot>` shape; parsing it here is observability
/// only and never authorizes routing.
pub fn build_detached_reply_late_event(
    source_sanitized: &str,
    target: &str,
    turn_id: &str,
) -> Event {
    let parsed = turn_id
        .strip_prefix("session:")
        .and_then(|rest| rest.rsplit_once(":slot:"))
        .and_then(|(session_id, slot)| slot.parse::<u32>().ok().map(|slot| (session_id, slot)));
    let (session_id, slot) = parsed
        .map(|(session_id, slot)| (Some(session_id), Some(slot)))
        .unwrap_or((None, None));
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: source_sanitized.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: String::new(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: REPLY_LATE.to_string(),
        payload: json!({
            "session_id": session_id,
            "source": source_sanitized,
            "target": target,
            "slot": slot,
            "turn_id": turn_id,
            "outcome": "dropped",
        }),
        duration_ms: None,
    }
}
