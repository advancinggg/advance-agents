//! Event-type taxonomy constants (MODULE-019 §1.3.0) + Trigger Bus whitelist (§1.3.2a).
//!
//! Slice D rewrite: every constant herein is named verbatim per PRD §15.3 canonical
//! event taxonomy. Non-PRD operational events live in `extensions::` with explicit
//! "NOT in PRD §15.3" doc comments. Coverage tests T71/T72 lock the alignment.
//!
//! Canonical entries: 130 across 22 PRD-aligned sub-modules (31 distinct top-level
//! prefixes). Enumerated extensions: 3. `runtime.degraded.{reason}` is documented as a
//! dynamic prefix via `extensions::RUNTIME_DEGRADED_PREFIX` but is NOT a fixed-string
//! entry in `ALL_EVENT_TYPES` — concrete strings are runtime-formed.
//!
//! `TRIGGER_BUS_WHITELIST` is preserved at exactly 12 entries per PRD §15.4
//! (regression-locked by `whitelist_has_12_entries`).

// ─────────────────────────────────────────────────────────────────────────
// Cat 1 — runtime.* (PRD §15.3.1 / MODULE-001, 002).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.1 — runtime.* events. 4 canonical events.
pub mod runtime {
    pub const STARTED: &str = "runtime.started";
    pub const SHUTDOWN: &str = "runtime.shutdown";
    pub const SCHEMA_RELOADED: &str = "runtime.schema_reloaded";
    pub const INDEX_REBUILD: &str = "runtime.index_rebuild";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 2 — channel.* + identity.* (PRD §15.3.2 / MODULE-016).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.2 — channel.* events. 3 canonical events.
pub mod channel {
    pub const SUBSCRIBE: &str = "channel.subscribe";
    pub const RAW_RECEIVED: &str = "channel.raw_received";
    pub const RAW_SENT: &str = "channel.raw_sent";
}

/// PRD §15.3.2 — identity.* namespace (separate prefix under same PRD section).
pub mod identity {
    pub const RESOLVED: &str = "identity.resolved";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 3 — msg.* + mailbox.* (PRD §15.3.3 / MODULE-006).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.3 — msg.* events. 4 canonical events.
pub mod msg {
    pub const RECEIVED: &str = "msg.received";
    pub const SENT: &str = "msg.sent";
    pub const REPLIED: &str = "msg.replied";
    pub const ROUTED: &str = "msg.routed";
}

/// PRD §15.3.3 — mailbox.* namespace (delivery-latency SLO breach).
pub mod mailbox {
    pub const DELIVERY_SLOW: &str = "mailbox.delivery_slow";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 4 — task.* (PRD §15.3.4 / MODULE-005, 008).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.4 — task.* events. 6 canonical events.
pub mod task {
    pub const CREATED: &str = "task.created";
    pub const ROUTED: &str = "task.routed";
    pub const COMPLETED: &str = "task.completed";
    pub const ARCHIVED: &str = "task.archived";
    pub const DECOMPOSED: &str = "task.decomposed";
    pub const SUBTASK_UPDATED: &str = "task.subtask_updated";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 5 — run.* (PRD §15.3.4A / MODULE-008).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.4A — run.* events. 11 canonical events per MODULE-008 AC-17.
pub mod run {
    pub const CREATED: &str = "run.created";
    pub const REUSED: &str = "run.reused";
    pub const SUSPENDED: &str = "run.suspended";
    pub const RESUMED: &str = "run.resumed";
    pub const ROUND_COMPLETED: &str = "run.round_completed";
    pub const PAUSED: &str = "run.paused";
    pub const COMPLETED: &str = "run.completed";
    pub const FAILED: &str = "run.failed";
    pub const CANCELLED: &str = "run.cancelled";
    pub const INTERRUPTED: &str = "run.interrupted";
    pub const REPETITION_DETECTED: &str = "run.repetition_detected";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 6 — orchestration.* (PRD §15.3.4B / MODULE-005, 007).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.4B — orchestration.* events. 7 canonical events.
pub mod orchestration {
    pub const AWAIT_STARTED: &str = "orchestration.await_started";
    pub const AWAIT_PROGRESS: &str = "orchestration.await_progress";
    pub const AWAIT_SATISFIED: &str = "orchestration.await_satisfied";
    pub const AWAIT_IDLE_TIMEOUT: &str = "orchestration.await_idle_timeout";
    pub const AWAIT_SESSION_CLOSED: &str = "orchestration.await_session_closed";
    pub const REPLY_LATE: &str = "orchestration.reply_late";
    pub const DEADLOCK_REJECTED: &str = "orchestration.deadlock_rejected";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 7 — auto.* + auto.bootstrap.* (PRD §15.3.4C + §15.3.21 / MODULE-015).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.4C — auto.* events. 7 canonical events.
pub mod auto {
    pub const ITERATION_STARTED: &str = "auto.iteration_started";
    pub const ITERATION_COMPLETED: &str = "auto.iteration_completed";
    pub const ITERATION_KEPT: &str = "auto.iteration_kept";
    pub const ITERATION_DISCARDED: &str = "auto.iteration_discarded";
    pub const ITERATION_CRASHED: &str = "auto.iteration_crashed";
    pub const DEGRADED: &str = "auto.degraded";
    pub const HALTED: &str = "auto.halted";

    /// PRD §15.3.21 — auto.bootstrap.* sub-namespace. 3 canonical events.
    pub mod bootstrap {
        pub const SPAWNED: &str = "auto.bootstrap.spawned";
        pub const SKIPPED: &str = "auto.bootstrap.skipped";
        pub const CONFLICT: &str = "auto.bootstrap.conflict";
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 8 — llm.* (PRD §15.3.5 / MODULE-009).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.5 — llm.* events. 5 canonical events.
pub mod llm {
    pub const TASK_ROUTE: &str = "llm.task_route";
    pub const REQUEST: &str = "llm.request";
    pub const RESPONSE: &str = "llm.response";
    pub const ERROR: &str = "llm.error";
    pub const RETRY: &str = "llm.retry";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 9 — context.* (PRD §15.3.6 / MODULE-010).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.6 — context.* events. 1 canonical event.
pub mod context {
    pub const ASSEMBLED: &str = "context.assembled";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 10 — recall.* (PRD §15.3.7 / MODULE-004, 010, 011).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.7 — recall.* events. 5 canonical events.
pub mod recall {
    pub const QUERY: &str = "recall.query";
    pub const DENSE_HITS: &str = "recall.dense_hits";
    pub const SPARSE_HITS: &str = "recall.sparse_hits";
    pub const PROPAGATION: &str = "recall.propagation";
    pub const FINAL: &str = "recall.final";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 11 — fs.* + meta.* (PRD §15.3.8 / MODULE-002).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.8 — fs.* events. 6 canonical events.
pub mod fs {
    pub const READ: &str = "fs.read";
    pub const WRITE: &str = "fs.write";
    pub const DELETE: &str = "fs.delete";
    pub const LIST: &str = "fs.list";
    pub const SCAN: &str = "fs.scan";
    pub const HISTORY: &str = "fs.history";
}

/// PRD §15.3.8 — meta.* namespace (metadata mutation events;
/// emitted by cap-fs `update-scope` / `update-entry-meta` / runtime auto-maintenance).
pub mod meta {
    pub const UPDATED: &str = "meta.updated";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 12 — http.* (PRD §15.3.9 / MODULE-009, 012, 016, 017).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.9 — http.* events. 3 canonical events.
pub mod http {
    pub const REQUEST: &str = "http.request";
    pub const RESPONSE: &str = "http.response";
    pub const BLOCKED: &str = "http.blocked";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 13 — secret.* (PRD §15.3.10 / MODULE-012).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.10 — secret.* events. 2 canonical events.
pub mod secret {
    pub const CHECKED: &str = "secret.checked";
    pub const INJECTED: &str = "secret.injected";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 14 — security.* (PRD §15.3.11 / MODULE-012, 001).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.11 — security.* events. 4 canonical events.
pub mod security {
    pub const LEAK_DETECTED: &str = "security.leak_detected";
    pub const SSRF_BLOCKED: &str = "security.ssrf_blocked";
    pub const CAPABILITY_DENIED: &str = "security.capability_denied";
    pub const INJECTION_DETECTED: &str = "security.injection_detected";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 15 — memory.* (PRD §15.3.12 + §15.3.22 / MODULE-011).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.12 + §15.3.22 — memory.* events. 7 canonical events.
pub mod memory {
    pub const REMEMBER: &str = "memory.remember";
    pub const RECALL: &str = "memory.recall";
    pub const FORGET: &str = "memory.forget";
    pub const RECALL_AT: &str = "memory.recall_at";
    pub const ROLLBACK: &str = "memory.rollback";
    /// PRD §15.3.22 — under memory.* namespace.
    pub const L6_CONSOLIDATION_DUE: &str = "memory.l6_consolidation_due";
    pub const L6_COMPLETED: &str = "memory.l6_completed";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 16 — post.* (PRD §15.3.13 / MODULE-011).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.13 — post.* events. 4 canonical events.
pub mod post {
    pub const STARTED: &str = "post.started";
    pub const DESCRIPTION: &str = "post.description";
    pub const KNOWLEDGE: &str = "post.knowledge";
    pub const SUMMARY: &str = "post.summary";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 17 — component.* + lifecycle.* (PRD §15.3.14 / MODULE-014, 005).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.14 — component.* events. 5 canonical events.
pub mod component {
    pub const LOADED: &str = "component.loaded";
    pub const STARTED: &str = "component.started";
    pub const FINISHED: &str = "component.finished";
    pub const ERROR: &str = "component.error";
    pub const SPAWNED: &str = "component.spawned";
}

/// PRD §15.3.14 — lifecycle.* namespace. 4 canonical events.
pub mod lifecycle {
    pub const INIT_WORKSPACE: &str = "lifecycle.init_workspace";
    pub const ROLLBACK_CHILD: &str = "lifecycle.rollback_child";
    pub const TERMINATE_CHILD: &str = "lifecycle.terminate_child";
    pub const TERMINATE_AGENT: &str = "lifecycle.terminate_agent";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 18 — trigger.* (PRD §15.3.15 / MODULE-014).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.15 — trigger.* events. 1 canonical event.
pub mod trigger {
    pub const FIRED: &str = "trigger.fired";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 19 — tool.* (PRD §15.3.16 / MODULE-017).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.16 — tool.* events. 5 canonical events.
pub mod tool {
    pub const INVOKE: &str = "tool.invoke";
    pub const RESULT: &str = "tool.result";
    pub const ERROR: &str = "tool.error";
    pub const RETRY: &str = "tool.retry";
    pub const LOAD_FAILED: &str = "tool.load_failed";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 20 — skill.* (PRD §15.3.16B / MODULE-017).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.16B — skill.* events. 9 canonical events.
pub mod skill {
    pub const DRAFT_CREATED: &str = "skill.draft_created";
    pub const DRAFT_UPDATED: &str = "skill.draft_updated";
    pub const ACTIVATED: &str = "skill.activated";
    pub const ROLLED_BACK: &str = "skill.rolled_back";
    pub const DELETED: &str = "skill.deleted";
    pub const LOADED: &str = "skill.loaded";
    pub const TOOL_INVOKED: &str = "skill.tool_invoked";
    pub const CANDIDATE_GENERATED: &str = "skill.candidate_generated";
    pub const CANDIDATE_RESOLVED: &str = "skill.candidate_resolved";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 21 — git.* (PRD §15.3.17 / MODULE-003).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.17 — git.* events. 3 canonical events.
pub mod git {
    pub const COMMIT: &str = "git.commit";
    pub const CHECKPOINT: &str = "git.checkpoint";
    pub const ROLLBACK: &str = "git.rollback";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 22 — authz.* + grant.* + preset.* + resolver.* (PRD §15.3.18 / MODULE-013).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.18 — authz.* events. 1 canonical event.
pub mod authz {
    pub const CHECKED: &str = "authz.checked";
}

/// PRD §15.3.18 — grant.* namespace. 6 canonical events.
pub mod grant {
    pub const ISSUED: &str = "grant.issued";
    pub const REVOKED: &str = "grant.revoked";
    pub const CONSUMED: &str = "grant.consumed";
    pub const EXPIRED: &str = "grant.expired";
    pub const DELEGATED: &str = "grant.delegated";
    pub const NARROWED: &str = "grant.narrowed";
}

/// PRD §15.3.18 — preset.* namespace. 1 canonical event.
pub mod preset {
    pub const APPLIED: &str = "preset.applied";
}

/// PRD §15.3.18 — resolver.* namespace. 1 canonical event.
pub mod resolver {
    pub const INVOKED: &str = "resolver.invoked";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 23 — mcp.* (PRD §15.3.19 / MODULE-017).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.19 — mcp.* events. 6 canonical events.
pub mod mcp {
    pub const SERVER_STARTED: &str = "mcp.server_started";
    pub const SERVER_DIED: &str = "mcp.server_died";
    pub const TOOL_INVOKED: &str = "mcp.tool_invoked";
    pub const TOOL_ERROR: &str = "mcp.tool_error";
    pub const PROMPT_FETCHED: &str = "mcp.prompt_fetched";
    pub const RESOURCE_READ: &str = "mcp.resource_read";
}

// ─────────────────────────────────────────────────────────────────────────
// Cat 24 — circuit_breaker.* (PRD §15.3.20 / MODULE-001).
// ─────────────────────────────────────────────────────────────────────────

/// PRD §15.3.20 — circuit_breaker.* events. 3 canonical events.
pub mod circuit_breaker {
    pub const OPENED: &str = "circuit_breaker.opened";
    pub const CLOSED: &str = "circuit_breaker.closed";
    pub const HALF_OPEN: &str = "circuit_breaker.half_open";
}

// ─────────────────────────────────────────────────────────────────────────
// M019/M001 operational extensions — events emitted by M019/M001 internal
// subsystems that are NOT enumerated in PRD §15.3.
// ─────────────────────────────────────────────────────────────────────────

/// M019/M001 operational extensions — events emitted by internal subsystems that are
/// NOT enumerated in PRD §15.3.
///
/// **NOT in PRD §15.3.** These events exist for operational observability of
/// internal failure modes and don't belong in any of the canonical 22 primary +
/// 4 sub-section categories. Subscribers should treat them as informational and
/// not depend on stable schema. They are exempted from the canonical-PRD coverage
/// test (T71) and explicitly recognised by the no-leftover test (T72).
pub mod extensions {
    /// Emitted by `sweeper.rs` on retention IO failure / symlink rejection /
    /// retention_overflow. Slice C item-12 placeholder, formalized in Slice D
    /// as an explicit non-PRD operational extension.
    pub const RUNTIME_WARNING: &str = "runtime.warning";

    /// Emitted by `MODULE-001 RuntimeConfigWatcher` on
    /// `/.advance/runtime-config.yaml` hot-reload (per MODULE-001 §10.2 event
    /// table). PRD §15.3.1 enumerates `runtime.schema_reloaded`
    /// (meta-schema reload, owned by MODULE-002) but NOT
    /// `runtime.config_reloaded` (runtime-config reload, owned by MODULE-001) —
    /// they are distinct events. The MODULE-001 bootstrap slice that wires
    /// emission references this constant.
    pub const RUNTIME_CONFIG_RELOADED: &str = "runtime.config_reloaded";

    /// Dynamic prefix for cap-fs atomic-rollback failure events
    /// (e.g., `runtime.degraded.fs_write_meta_rollback_failed`). Concrete
    /// strings are formed at the call site via
    /// `format!("runtime.degraded.{reason}")`. Because the suffix is dynamic,
    /// the prefix is registered as a **non-string-enumerated extension** —
    /// `RUNTIME_DEGRADED_PREFIX` itself is NOT included in `ALL_EVENT_TYPES`.
    /// T72's "leftover" check exempts any event_type starting with this prefix.
    pub const RUNTIME_DEGRADED_PREFIX: &str = "runtime.degraded.";

    /// `fs.read.entry` — Slice A seed for the host-fn entry/exit instrumentation
    /// marker referenced by PRD §15.6 (host-fn entry/exit emission concept; not
    /// a canonical event in §15.3). Kept here for back-compat with the
    /// `seed_event_type_constants_match_canonical_strings` regression test that
    /// was shipped in Slice A. The paired `fs.read.exit` is NOT introduced —
    /// no live emit, no enumeration source-of-truth.
    pub const FS_READ_ENTRY: &str = "fs.read.entry";
}

// ─────────────────────────────────────────────────────────────────────────
// 12-event Trigger Bus whitelist (MODULE-019 §1.3.2a / PRD §15.4).
// Locked by `whitelist_has_12_entries` regression test.
//
// Slice E (m019-slice-e, 2026-05-15): `TRIGGER_BUS_WHITELIST` is now a
// `pub use` re-export of `advance_scheduler::trigger_bus::WHITELIST` —
// single source of truth for the 12-event slice. Scheduler's own
// `whitelist_has_12_entries` test (trigger_bus.rs:1159) locks length from
// the provider side; this crate's `whitelist_has_12_entries` test
// (tests/taxonomy.rs:14) continues to lock via `.len()` against the
// re-exported slice. Previously the slice was duplicated as a literal here
// — Codex Round 2 W3 flagged the dual-truth hazard; closed by re-export.
// ─────────────────────────────────────────────────────────────────────────

pub use advance_scheduler::trigger_bus::WHITELIST as TRIGGER_BUS_WHITELIST;

// ─────────────────────────────────────────────────────────────────────────
// Aggregate: every event type known to the runtime.
// ─────────────────────────────────────────────────────────────────────────

/// All event types declared in this taxonomy. Used by AC-03 (≥130 post-Slice-D)
/// and AC-20 (canonical PRD §15.3 coverage + no-leftover) coverage tests.
///
/// Stable ordering: by PRD §15.3 sub-section then by declaration order within
/// section. `extensions::*` appear last.
///
/// **NOTE on `runtime.degraded.{reason}`**: this dynamic-prefix family is documented
/// at `extensions::RUNTIME_DEGRADED_PREFIX` but NOT included here — concrete strings
/// are runtime-formed (`format!("runtime.degraded.{reason}")` at the cap-fs call
/// site). T72 prefix-exempts events whose `event_type` starts with this prefix.
pub const ALL_EVENT_TYPES: &[&str] = &[
    // Cat 1 runtime (4)
    runtime::STARTED,
    runtime::SHUTDOWN,
    runtime::SCHEMA_RELOADED,
    runtime::INDEX_REBUILD,
    // Cat 2 channel + identity (4)
    channel::SUBSCRIBE,
    channel::RAW_RECEIVED,
    channel::RAW_SENT,
    identity::RESOLVED,
    // Cat 3 msg + mailbox (5)
    msg::RECEIVED,
    msg::SENT,
    msg::REPLIED,
    msg::ROUTED,
    mailbox::DELIVERY_SLOW,
    // Cat 4 task (6)
    task::CREATED,
    task::ROUTED,
    task::COMPLETED,
    task::ARCHIVED,
    task::DECOMPOSED,
    task::SUBTASK_UPDATED,
    // Cat 5 run (11)
    run::CREATED,
    run::REUSED,
    run::SUSPENDED,
    run::RESUMED,
    run::ROUND_COMPLETED,
    run::PAUSED,
    run::COMPLETED,
    run::FAILED,
    run::CANCELLED,
    run::INTERRUPTED,
    run::REPETITION_DETECTED,
    // Cat 6 orchestration (7)
    orchestration::AWAIT_STARTED,
    orchestration::AWAIT_PROGRESS,
    orchestration::AWAIT_SATISFIED,
    orchestration::AWAIT_IDLE_TIMEOUT,
    orchestration::AWAIT_SESSION_CLOSED,
    orchestration::REPLY_LATE,
    orchestration::DEADLOCK_REJECTED,
    // Cat 7 auto + auto.bootstrap (10)
    auto::ITERATION_STARTED,
    auto::ITERATION_COMPLETED,
    auto::ITERATION_KEPT,
    auto::ITERATION_DISCARDED,
    auto::ITERATION_CRASHED,
    auto::DEGRADED,
    auto::HALTED,
    auto::bootstrap::SPAWNED,
    auto::bootstrap::SKIPPED,
    auto::bootstrap::CONFLICT,
    // Cat 8 llm (5)
    llm::TASK_ROUTE,
    llm::REQUEST,
    llm::RESPONSE,
    llm::ERROR,
    llm::RETRY,
    // Cat 9 context (1)
    context::ASSEMBLED,
    // Cat 10 recall (5)
    recall::QUERY,
    recall::DENSE_HITS,
    recall::SPARSE_HITS,
    recall::PROPAGATION,
    recall::FINAL,
    // Cat 11 fs + meta (7)
    fs::READ,
    fs::WRITE,
    fs::DELETE,
    fs::LIST,
    fs::SCAN,
    fs::HISTORY,
    meta::UPDATED,
    // Cat 12 http (3)
    http::REQUEST,
    http::RESPONSE,
    http::BLOCKED,
    // Cat 13 secret (2)
    secret::CHECKED,
    secret::INJECTED,
    // Cat 14 security (4)
    security::LEAK_DETECTED,
    security::SSRF_BLOCKED,
    security::CAPABILITY_DENIED,
    security::INJECTION_DETECTED,
    // Cat 15 memory + l6 (7)
    memory::REMEMBER,
    memory::RECALL,
    memory::FORGET,
    memory::RECALL_AT,
    memory::ROLLBACK,
    memory::L6_CONSOLIDATION_DUE,
    memory::L6_COMPLETED,
    // Cat 16 post (4)
    post::STARTED,
    post::DESCRIPTION,
    post::KNOWLEDGE,
    post::SUMMARY,
    // Cat 17 component + lifecycle (9)
    component::LOADED,
    component::STARTED,
    component::FINISHED,
    component::ERROR,
    component::SPAWNED,
    lifecycle::INIT_WORKSPACE,
    lifecycle::ROLLBACK_CHILD,
    lifecycle::TERMINATE_CHILD,
    lifecycle::TERMINATE_AGENT,
    // Cat 18 trigger (1)
    trigger::FIRED,
    // Cat 19 tool (5)
    tool::INVOKE,
    tool::RESULT,
    tool::ERROR,
    tool::RETRY,
    tool::LOAD_FAILED,
    // Cat 20 skill (9)
    skill::DRAFT_CREATED,
    skill::DRAFT_UPDATED,
    skill::ACTIVATED,
    skill::ROLLED_BACK,
    skill::DELETED,
    skill::LOADED,
    skill::TOOL_INVOKED,
    skill::CANDIDATE_GENERATED,
    skill::CANDIDATE_RESOLVED,
    // Cat 21 git (3)
    git::COMMIT,
    git::CHECKPOINT,
    git::ROLLBACK,
    // Cat 22 authz + grant + preset + resolver (9)
    authz::CHECKED,
    grant::ISSUED,
    grant::REVOKED,
    grant::CONSUMED,
    grant::EXPIRED,
    grant::DELEGATED,
    grant::NARROWED,
    preset::APPLIED,
    resolver::INVOKED,
    // Cat 23 mcp (6)
    mcp::SERVER_STARTED,
    mcp::SERVER_DIED,
    mcp::TOOL_INVOKED,
    mcp::TOOL_ERROR,
    mcp::PROMPT_FETCHED,
    mcp::RESOURCE_READ,
    // Cat 24 circuit_breaker (3)
    circuit_breaker::OPENED,
    circuit_breaker::CLOSED,
    circuit_breaker::HALF_OPEN,
    // Total canonical: 130
    // M019/M001 operational extensions (NOT in PRD §15.3) — 3 enumerated entries
    extensions::RUNTIME_WARNING,
    extensions::RUNTIME_CONFIG_RELOADED,
    extensions::FS_READ_ENTRY,
    // NOTE: extensions::RUNTIME_DEGRADED_PREFIX is intentionally NOT enumerated —
    // concrete strings are dynamic (`runtime.degraded.{reason}`); T72 prefix-exempts.
];

// Slice-A seed re-exports — declared AFTER sub-modules so all referenced constants
// are in scope. These exist only for back-compat with the
// `seed_event_type_constants_match_canonical_strings` Slice-A regression test.

pub const RUNTIME_STARTED: &str = runtime::STARTED;
pub const LLM_RESPONSE: &str = llm::RESPONSE;
pub const COMPONENT_SPAWNED: &str = component::SPAWNED;
pub const TASK_CREATED: &str = task::CREATED;
/// `fs.read.entry` — Slice A seed for the host-fn entry/exit instrumentation marker
/// per PRD §15.6 host-fn entry/exit emission concept. NOT enumerated in PRD §15.3 by
/// design. Aliased through `extensions::FS_READ_ENTRY` to surface the non-canonical
/// classification at the type system / docs level.
pub const FS_READ_ENTRY: &str = extensions::FS_READ_ENTRY;

/// Number of distinct top-level categories represented in `ALL_EVENT_TYPES`.
/// Used by AC-03 / T19 coverage test.
pub fn category_count() -> usize {
    use std::collections::BTreeSet;
    let mut prefixes = BTreeSet::new();
    for ev in ALL_EVENT_TYPES {
        if let Some(prefix) = ev.split('.').next() {
            prefixes.insert(prefix.to_string());
        }
    }
    prefixes.len()
}
