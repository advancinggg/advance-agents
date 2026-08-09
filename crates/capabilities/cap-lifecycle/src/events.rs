//! Decomposition observability events (CONTRACT-180 `EventBusEmit` payloads).
//!
//! Builder helpers for the two PRD §15.3.4 / §9.5 `task.*` decomposition events
//! emitted from the `agent-lifecycle` WIT dispatch (`wit_impl.rs`). Mirrors the
//! `cap-grant/src/events.rs` builder pattern: a `new_event`-style constructor
//! (uuid-v4 `id`, `Utc::now()` timestamp, empty `trace_id`/`span_id`,
//! `parent_span_id: None`) — the same library-emitter correlation gap the
//! cap-grant `authz.checked` precedent accepts; full trace correlation is a
//! MODULE-019 concern. Unlike the generic `Event::observability` constructor,
//! these set `task_id: Some(..)` (decomposition is always task-scoped).
//!
//! `event_type` uses the canonical taxonomy string literals directly rather
//! than importing the `event-bus` crate's taxonomy consts — avoiding a new
//! Cargo edge. Both literals are locked against PRD §15.3 by
//! `event-bus/tests/taxonomy_coverage.rs`, so they cannot silently drift.
//!
//! Payload vocabulary is the kebab WIT/persistence taxonomy — matching
//! `wit_impl::lift_decomposition_plan`'s strategy tags and
//! `wit_impl::lift_subtask_status`'s status tags — pinned by the hand-written
//! [`strategy_tag`] / [`status_tag`] matches below, NOT the serde `Serialize`
//! forms (`DecompositionStrategy` is `snake_case` → would render
//! `delegate_single` with an underscore).
//!
//! # Payload trust model (emit-site hygiene)
//!
//! The emit-site guarantee here is **no secret inlining**: these builders never
//! place API keys, credentials, or host-side secrets into a payload (only the
//! strategy tag, a count, and the agent's own `assignees` / `subtask_id` /
//! status — the same task metadata already persisted to the decomposition YAML
//! and surfaced by `get-decomposition`). The `agent_id` is the call-frame
//! caller (`ctx.agent_id`), never a guest param.
//!
//! What this site does NOT guarantee, by design, is charset/length scrubbing:
//! `assignee` / `subtask_id` / `task_id` are guest-authored and length-capped
//! but NOT charset-restricted, so a payload string may legitimately contain
//! arbitrary UTF-8 (incl. control chars). Per the `shared-types::event::Event`
//! Implementer Invariants (§"`id` format" / §"Bounded field lengths"), the
//! downstream **EventBus implementer (MODULE-019) MUST sanitize or reject**
//! control chars / null bytes and enforce per-event size caps before persisting
//! to SQL / rendering in logs. This is the same trust split every emitter relies
//! on (e.g. cap-grant emits the guest-supplied `grantee` / `capability`); it is
//! not a per-emitter responsibility to re-implement that gate.

use advance_shared_types::agent_tree::AgentKind;
use advance_shared_types::event::Event;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::decomposition::{DecompositionStrategy, SubtaskStatus};

/// Canonical taxonomy event-type literal (PRD §15.3.4; locked by
/// `event-bus/tests/taxonomy_coverage.rs`).
const EVT_TASK_DECOMPOSED: &str = "task.decomposed";
/// Canonical taxonomy event-type literal (PRD §15.3.4; locked by
/// `event-bus/tests/taxonomy_coverage.rs`).
const EVT_TASK_SUBTASK_UPDATED: &str = "task.subtask_updated";
/// Canonical taxonomy event-type literal (PRD §15.3.5; locked by
/// `event-bus/tests/taxonomy_coverage.rs`).
const EVT_LIFECYCLE_TERMINATE_CHILD: &str = "lifecycle.terminate_child";
/// Canonical taxonomy event-type literal (PRD §15.3.5; locked by
/// `event-bus/tests/taxonomy_coverage.rs`).
const EVT_LIFECYCLE_TERMINATE_AGENT: &str = "lifecycle.terminate_agent";

/// Host-authoritative `reason` vocabulary for the `lifecycle.terminate_*`
/// payloads (MODULE-005-AC-28). The WIT surface carries no reason param —
/// the dispatch arm pins the value from the op that drove the removal.
pub const TERMINATE_REASON_CHILD: &str = "terminate-child";
pub const TERMINATE_REASON_AGENT: &str = "terminate-agent";
pub const TERMINATE_REASON_CASCADE: &str = "cascade";

/// Kebab kind tag for the `lifecycle.terminate_agent` `agent_kind` payload
/// field (PRD §15.3.5: `child|sub`; `root` is unreachable in practice —
/// terminate ops on Root are rejected before any removal — but the match is
/// exhaustive so a future caller cannot panic the emitter).
pub fn kind_tag(k: &AgentKind) -> &'static str {
    match k {
        AgentKind::Root => "root",
        AgentKind::Child => "child",
        AgentKind::Sub => "sub",
    }
}

/// Bare kebab family tag for the `task.decomposed` `strategy` payload field.
/// Matches the tags `lift_decomposition_plan` consumes (NOT serde snake_case);
/// the data-carrying `DelegateSingle(_)` inner target is dropped — the payload
/// field is a family tag per PRD §15.3.4.
pub fn strategy_tag(s: &DecompositionStrategy) -> &'static str {
    match s {
        DecompositionStrategy::SelfExecute => "self-execute",
        DecompositionStrategy::Decompose => "decompose",
        DecompositionStrategy::DelegateSingle(_) => "delegate-single",
    }
}

/// Kebab status tag for the `old_status` / `new_status` payload fields.
/// Matches `lift_subtask_status` + the `#[serde(rename_all = "kebab-case")]`
/// persisted form.
pub fn status_tag(s: SubtaskStatus) -> &'static str {
    match s {
        SubtaskStatus::Pending => "pending",
        SubtaskStatus::InProgress => "in-progress",
        SubtaskStatus::Completed => "completed",
        SubtaskStatus::Failed => "failed",
        SubtaskStatus::Skipped => "skipped",
    }
}

fn new_event(agent_id: &str, task_id: &str, event_type: &str, payload: serde_json::Value) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: Some(task_id.to_string()),
        run_id: None,
        execution_id: None,
        trace_id: String::new(),
        span_id: String::new(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload,
        duration_ms: None,
    }
}

/// `task.decomposed` — emitted on a successful `submit-decomposition`.
/// Payload (PRD §15.3.4): `strategy`, `subtask_count`, `assignees`.
pub fn task_decomposed_event(
    agent_id: &str,
    task_id: &str,
    strategy: &DecompositionStrategy,
    subtask_count: usize,
    assignees: &[String],
) -> Event {
    new_event(
        agent_id,
        task_id,
        EVT_TASK_DECOMPOSED,
        json!({
            "strategy": strategy_tag(strategy),
            "subtask_count": subtask_count,
            "assignees": assignees,
        }),
    )
}

fn new_lifecycle_event(agent_id: &str, event_type: &str, payload: serde_json::Value) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: String::new(),
        span_id: String::new(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload,
        duration_ms: None,
    }
}

/// `lifecycle.terminate_child` — emitted once, for the named child root, on a
/// successful `terminate-child` (MODULE-005-AC-28). Payload (PRD §15.3.5):
/// `initiator`, `child_id`, `reason`. No workspace paths, no node metadata.
pub fn lifecycle_terminate_child_event(initiator: &str, child_id: &str, reason: &str) -> Event {
    new_lifecycle_event(
        initiator,
        EVT_LIFECYCLE_TERMINATE_CHILD,
        json!({
            "initiator": initiator,
            "child_id": child_id,
            "reason": reason,
        }),
    )
}

/// `lifecycle.terminate_agent` — emitted per removed agent (the direct target
/// of `terminate-agent`, and every cascade-removed descendant of either
/// terminate op) on success (MODULE-005-AC-28). Payload (PRD §15.3.5):
/// `initiator`, `agent_id`, `agent_kind` (`child|sub`), `reason`.
pub fn lifecycle_terminate_agent_event(
    initiator: &str,
    agent_id: &str,
    agent_kind: &AgentKind,
    reason: &str,
) -> Event {
    new_lifecycle_event(
        initiator,
        EVT_LIFECYCLE_TERMINATE_AGENT,
        json!({
            "initiator": initiator,
            "agent_id": agent_id,
            "agent_kind": kind_tag(agent_kind),
            "reason": reason,
        }),
    )
}

/// `task.subtask_updated` — emitted on a successful `update-subtask-status`.
/// Payload (PRD §15.3.4): `subtask_id`, `old_status`, `new_status`.
pub fn task_subtask_updated_event(
    agent_id: &str,
    task_id: &str,
    subtask_id: &str,
    old_status: SubtaskStatus,
    new_status: SubtaskStatus,
) -> Event {
    new_event(
        agent_id,
        task_id,
        EVT_TASK_SUBTASK_UPDATED,
        json!({
            "subtask_id": subtask_id,
            "old_status": status_tag(old_status),
            "new_status": status_tag(new_status),
        }),
    )
}
