//! T-S-B AC-03 coverage tests + Slice D AC-20 PRD §15.3 alignment tests.
//!
//! T18: ALL_EVENT_TYPES contains ≥130 entries; no duplicates.
//! T19: ≥22 distinct top-level prefixes (categories) covered.
//! T71 (Slice D): every canonical PRD §15.3 event is in ALL_EVENT_TYPES (subset);
//!                CANONICAL_PRD_15_3_EVENTS has exactly 130 unique entries.
//! T72 (Slice D): every entry in ALL_EVENT_TYPES is canonical PRD §15.3 OR a
//!                documented `extensions::*` member OR matches a documented
//!                dynamic-prefix exemption (no leftover).

use std::collections::HashSet;

use advance_event_bus::taxonomy::{category_count, ALL_EVENT_TYPES};

/// MODULE-019-T18 — at least 130 entries (post-Slice-D), no duplicates.
#[test]
fn t18_all_event_types_at_least_130_no_duplicates() {
    let len = ALL_EVENT_TYPES.len();
    assert!(
        len >= 130,
        "expected ≥130 event types, got {len}: {:?}",
        ALL_EVENT_TYPES
    );

    let unique: HashSet<&&str> = ALL_EVENT_TYPES.iter().collect();
    assert_eq!(
        unique.len(),
        len,
        "duplicate entries in ALL_EVENT_TYPES (got {} unique of {} total)",
        unique.len(),
        len
    );
}

/// MODULE-019-T19 — at least 22 distinct top-level prefixes (categories).
#[test]
fn t19_at_least_22_top_level_categories() {
    let count = category_count();
    assert!(
        count >= 22,
        "expected ≥22 distinct top-level categories, got {count}"
    );
}

/// Sanity: the original Slice A 5-seed constants are still present in the aggregate.
#[test]
fn t_slice_a_seed_event_types_in_aggregate() {
    use advance_event_bus::taxonomy;
    assert!(ALL_EVENT_TYPES.contains(&taxonomy::RUNTIME_STARTED));
    assert!(ALL_EVENT_TYPES.contains(&taxonomy::FS_READ_ENTRY));
    assert!(ALL_EVENT_TYPES.contains(&taxonomy::LLM_RESPONSE));
    assert!(ALL_EVENT_TYPES.contains(&taxonomy::COMPONENT_SPAWNED));
    assert!(ALL_EVENT_TYPES.contains(&taxonomy::TASK_CREATED));
}

// ─────────────────────────────────────────────────────────────────────────
// Slice D — AC-20 set-arithmetic alignment proofs (T71 + T72).
//
// Single source of truth for PRD §15.3 alignment. Both T71 (subset) and T72
// (no-leftover) consume `CANONICAL_PRD_15_3_EVENTS` and `KNOWN_EXTENSIONS`.
// Adding a PRD event to taxonomy.rs requires adding it to
// `CANONICAL_PRD_15_3_EVENTS` AND bumping the strict equality assertion in
// T71 — intentional friction so taxonomy drift is impossible to merge silently.
// ─────────────────────────────────────────────────────────────────────────

/// Canonical PRD §15.3 event names — exactly 130 entries verbatim from PRD.
const CANONICAL_PRD_15_3_EVENTS: &[&str] = &[
    // Cat 1 runtime (4)
    "runtime.started",
    "runtime.shutdown",
    "runtime.schema_reloaded",
    "runtime.index_rebuild",
    // Cat 2 channel + identity (4)
    "channel.subscribe",
    "channel.raw_received",
    "channel.raw_sent",
    "identity.resolved",
    // Cat 3 msg + mailbox (5)
    "msg.received",
    "msg.sent",
    "msg.replied",
    "msg.routed",
    "mailbox.delivery_slow",
    // Cat 4 task (6)
    "task.created",
    "task.routed",
    "task.completed",
    "task.archived",
    "task.decomposed",
    "task.subtask_updated",
    // Cat 5 run (11)
    "run.created",
    "run.reused",
    "run.suspended",
    "run.resumed",
    "run.round_completed",
    "run.paused",
    "run.completed",
    "run.failed",
    "run.cancelled",
    "run.interrupted",
    "run.repetition_detected",
    // Cat 6 orchestration (7)
    "orchestration.await_started",
    "orchestration.await_progress",
    "orchestration.await_satisfied",
    "orchestration.await_idle_timeout",
    "orchestration.await_session_closed",
    "orchestration.reply_late",
    "orchestration.deadlock_rejected",
    // Cat 7 auto + auto.bootstrap (10)
    "auto.iteration_started",
    "auto.iteration_completed",
    "auto.iteration_kept",
    "auto.iteration_discarded",
    "auto.iteration_crashed",
    "auto.degraded",
    "auto.halted",
    "auto.bootstrap.spawned",
    "auto.bootstrap.skipped",
    "auto.bootstrap.conflict",
    // Cat 8 llm (5)
    "llm.task_route",
    "llm.request",
    "llm.response",
    "llm.error",
    "llm.retry",
    // Cat 9 context (1)
    "context.assembled",
    // Cat 10 recall (5)
    "recall.query",
    "recall.dense_hits",
    "recall.sparse_hits",
    "recall.propagation",
    "recall.final",
    // Cat 11 fs + meta (7)
    "fs.read",
    "fs.write",
    "fs.delete",
    "fs.list",
    "fs.scan",
    "fs.history",
    "meta.updated",
    // Cat 12 http (3)
    "http.request",
    "http.response",
    "http.blocked",
    // Cat 13 secret (2)
    "secret.checked",
    "secret.injected",
    // Cat 14 security (4)
    "security.leak_detected",
    "security.ssrf_blocked",
    "security.capability_denied",
    "security.injection_detected",
    // Cat 15 memory + l6 (7)
    "memory.remember",
    "memory.recall",
    "memory.forget",
    "memory.recall_at",
    "memory.rollback",
    "memory.l6_consolidation_due",
    "memory.l6_completed",
    // Cat 16 post (4)
    "post.started",
    "post.description",
    "post.knowledge",
    "post.summary",
    // Cat 17 component + lifecycle (9)
    "component.loaded",
    "component.started",
    "component.finished",
    "component.error",
    "component.spawned",
    "lifecycle.init_workspace",
    "lifecycle.rollback_child",
    "lifecycle.terminate_child",
    "lifecycle.terminate_agent",
    // Cat 18 trigger (1)
    "trigger.fired",
    // Cat 19 tool (5)
    "tool.invoke",
    "tool.result",
    "tool.error",
    "tool.retry",
    "tool.load_failed",
    // Cat 20 skill (9)
    "skill.draft_created",
    "skill.draft_updated",
    "skill.activated",
    "skill.rolled_back",
    "skill.deleted",
    "skill.loaded",
    "skill.tool_invoked",
    "skill.candidate_generated",
    "skill.candidate_resolved",
    // Cat 21 git (3)
    "git.commit",
    "git.checkpoint",
    "git.rollback",
    // Cat 22 authz + grant + preset + resolver (9)
    "authz.checked",
    "grant.issued",
    "grant.revoked",
    "grant.consumed",
    "grant.expired",
    "grant.delegated",
    "grant.narrowed",
    "preset.applied",
    "resolver.invoked",
    // Cat 23 mcp (6)
    "mcp.server_started",
    "mcp.server_died",
    "mcp.tool_invoked",
    "mcp.tool_error",
    "mcp.prompt_fetched",
    "mcp.resource_read",
    // Cat 24 circuit_breaker (3)
    "circuit_breaker.opened",
    "circuit_breaker.closed",
    "circuit_breaker.half_open",
];

/// Documented non-PRD operational events (mirror of `taxonomy::extensions::*`).
/// `RUNTIME_DEGRADED_PREFIX` is handled separately via dynamic-prefix exemption.
const KNOWN_EXTENSIONS: &[&str] = &[
    "runtime.warning",
    "runtime.config_reloaded",
    "fs.read.entry",
];

/// Events whose concrete strings are formed at the call site (not enumerated in
/// `ALL_EVENT_TYPES`); T72 prefix-exempts them.
const EXTENSION_DYNAMIC_PREFIXES: &[&str] = &["runtime.degraded."];

/// MODULE-019-T71 — subset proof: every canonical PRD §15.3 event is in
/// `ALL_EVENT_TYPES`. Failure means a canonical event was dropped or renamed
/// out of taxonomy.rs.
#[test]
fn t71_canonical_prd_15_3_events_present() {
    let registry: HashSet<&&str> = ALL_EVENT_TYPES.iter().collect();
    let mut missing: Vec<&str> = CANONICAL_PRD_15_3_EVENTS
        .iter()
        .filter(|e| !registry.contains(e))
        .copied()
        .collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "ALL_EVENT_TYPES is missing canonical PRD §15.3 events: {missing:?}"
    );
    assert_eq!(
        CANONICAL_PRD_15_3_EVENTS.len(),
        130,
        "PRD §15.3 canonical list expected exactly 130 entries; got {}. \
         If you intentionally added/removed a PRD event, update this number AND \
         the §1.3.0 example column in MODULE-019.",
        CANONICAL_PRD_15_3_EVENTS.len()
    );

    // Uniqueness — guard against the duplicate-plus-omission case slipping past
    // the length check. Without this, `len() == 130` is satisfiable with a
    // duplicate + missing entry (the subset check above would also pass since
    // all 130 unique values would still be in the registry).
    let unique: HashSet<&&str> = CANONICAL_PRD_15_3_EVENTS.iter().collect();
    assert_eq!(
        unique.len(),
        CANONICAL_PRD_15_3_EVENTS.len(),
        "duplicate entries in CANONICAL_PRD_15_3_EVENTS: {} unique vs {} total",
        unique.len(),
        CANONICAL_PRD_15_3_EVENTS.len()
    );
}

/// MODULE-019-T72 — no-leftover proof: every entry in `ALL_EVENT_TYPES` is
/// EITHER canonical PRD §15.3 OR a documented `extensions::*` member OR matches
/// a documented dynamic-prefix exemption. Together with T71 this proves set
/// equality `ALL_EVENT_TYPES == canonical ∪ extensions` for the static-registry
/// layer. Adding any new event_type without categorising it correctly fails this
/// test.
#[test]
fn t72_no_leftover_outside_canonical_or_extensions() {
    let canonical: HashSet<&&str> = CANONICAL_PRD_15_3_EVENTS.iter().collect();
    let extensions: HashSet<&&str> = KNOWN_EXTENSIONS.iter().collect();

    let mut leftover: Vec<&str> = Vec::new();
    for entry in ALL_EVENT_TYPES {
        if canonical.contains(&entry) || extensions.contains(&entry) {
            continue;
        }
        if EXTENSION_DYNAMIC_PREFIXES
            .iter()
            .any(|p| entry.starts_with(p))
        {
            continue;
        }
        leftover.push(entry);
    }
    leftover.sort();
    assert!(
        leftover.is_empty(),
        "ALL_EVENT_TYPES contains entries outside canonical PRD §15.3 + documented \
         extensions + dynamic-prefix exemptions: {leftover:?}. Either add to PRD \
         (canonical), document as `extensions::*`, or remove."
    );
}
