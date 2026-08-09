//! MODULE-007 await-orchestration canonical dependency-inversion surface.
//!
//! Canonical source: `docs/modules/MODULE-007-await-orchestration.md` §2.3
//! (AwaitSessionRef + OrchestrationError + AwaitTreeSummary + SessionSummary)
//! and §2.3 head amendment for `SessionId` newtype (landed by /dev Slice AC
//! v2).
//!
//! Verbatim hoist — if the owner module's declaration changes, run
//! `/spec MODULE-007` and re-hoist via a follow-on /dev slice.
//!
//! # Security posture
//!
//! - **`SessionId` validation**: the `pub String` tuple field accepts any
//!   byte sequence via `#[serde(transparent)]`. Callers MUST validate
//!   against `^[A-Za-z0-9_-]{1,64}$` before HashMap-keying to prevent
//!   session-id confusables, control-char injection into log lines, and
//!   unbounded-key-insertion DoS. Typed constructors (`TryFrom<&str>`)
//!   deferred to MODULE-007 concrete-impl.
//! - **Error payload PII policy**: [`OrchestrationError`] all 9 variants
//!   carry `String` payloads flowing into operator logs / EventBus JSONL
//!   / WebSocket broadcast. Implementers MUST NOT embed user prompts,
//!   API-key fragments, session tokens, or filesystem paths. Reason strings
//!   SHOULD be short invariant identifiers (e.g. `"deadlock-detected"`,
//!   `"idle-timeout"`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Await-session identifier. Canonical declaration: MODULE-007 §2.3 head
/// (landed by /dev Slice AC v2). Newtype-over-String symmetric with
/// [`crate::agent_tree::AgentId`] + Slice I `CapabilityId`. Wire format is
/// `#[serde(transparent)]` bare string; `#[derive(Hash, PartialEq, Eq)]`
/// enables HashMap-key usage (MODULE-007 §1.3.2:95-97). Backing string
/// format (UUID v4 / ULID / opaque) is a MODULE-007 concrete-impl choice.
///
/// # Implementer Invariants
///
/// 1. **Bounded length** (recommended ≤ 64 bytes).
/// 2. **Charset**: validate against `^[A-Za-z0-9_-]{1,64}$` before use.
/// 3. **Public field**: the `.0` is public per narrow v2 scope; helper
///    impls deferred to MODULE-007 concrete-impl slice.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

/// MODULE-007 §2.3:381-401 — orchestration error surface. 9 variants all
/// carrying `String` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrchestrationError {
    /// Caller lacks `await-replies` or `heartbeat` capability.
    CapabilityDenied(String),
    /// Target agent does not exist, or hierarchy rules forbid the await.
    InvalidTarget(String),
    /// Awaiting this target would create a cycle in the active AwaitSession
    /// graph (PRD §9.2 deadlock prevention).
    DeadlockDetected(String),
    /// Caller's concurrent open sessions exceeds the per-agent cap.
    SessionLimitExceeded(String),
    /// Session closed before the slot completed (cascade close, pause, cancel).
    SessionClosed(String),
    /// Idle timeout reached while waiting for reply / heartbeat.
    IdleTimeoutExceeded(String),
    /// Session id or slot index not found.
    NotFound(String),
    /// Invalid AwaitOptions / AwaitRequest (empty requests list, bad mode combo).
    InvalidRequest(String),
    /// Downstream dependency failure (MODULE-006 deliver, MODULE-019 emit).
    Downstream(String),
}

/// MODULE-007 §2.3:323-331 — per-session projection summary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSummary {
    pub session_id: String,
    pub parent_session_id: Option<String>,
    pub agent_id: String,
    pub mode: String,
    pub expected: u32,
    pub received: u32,
    pub status: String,
}

/// MODULE-007 §2.3:316-321 — aggregate tree summary for run-status output.
///
/// **Implementer Invariants**: bounded `sessions.len()` (recommended ≤ 100
/// per MODULE-007 depth cap); `depth` saturates at `u32::MAX`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwaitTreeSummary {
    pub depth: u32,
    pub total_sessions: u32,
    pub pending_replies: u32,
    pub sessions: Vec<SessionSummary>,
}

/// Await-session read-only query surface. MODULE-007 §2.3 (partial extract:
/// 3 methods used across MODULE-006/008).
///
/// Mixed-async: `exists` / `walk_tree` sync; `close` async (persists state
/// changes + emits event bus notifications).
///
/// # Implementer Invariants
///
/// 1. **Read-only on `exists` / `walk_tree`**: no mutation inside these
///    queries; they must be safe to call from hot paths.
/// 2. **`close` idempotent**: multiple calls with the same `SessionId` MUST
///    yield the same terminal state (closed) without re-emitting cascade
///    events.
/// 3. **No on_reply re-entry**: implementer must not invoke reply callbacks
///    while holding the session lock; dispatch via a channel.
/// 4. **Bounded walk_tree output**: honor MODULE-007 depth cap
///    (recommended ≤ 100 sessions per walk).
#[async_trait]
pub trait AwaitSessionRef: Send + Sync {
    fn exists(&self, session_id: &SessionId) -> bool;
    /// Walks the session tree rooted at `session_id`. Returns `None` when
    /// the session does not exist (per MODULE-007 §2.3:319 canonical form).
    fn walk_tree(&self, session_id: &SessionId) -> Option<AwaitTreeSummary>;
    async fn close(&self, session_id: &SessionId, reason: &str) -> Result<(), OrchestrationError>;
}

// ─────────────────────────────────────────────────────────────────
// Slice m007-A (2026-05-18) canonical mirrors. Aligned with
// MODULE-007 §2.3:344-446 (rewritten in DOCS-phase 2026-05-18 to
// adopt the tuple-variant AwaitRequest, AwaitOptions field rename
// `timeout_policy` → `on_idle_timeout`, and AwaitSessionStatus
// FailedDispatch variant).
//
// **WIT-vs-Rust asymmetries** (6 bullets, canonical-by-design — see
// MODULE-007 §2.3 doc-comment block for the full taxonomy):
//   1. AwaitRequest: tuple-variant wrapping AgentAwaitRequest /
//      ComponentAwaitRequest (matches WIT shape).
//   2. AwaitOptions field rename: timeout_policy → on_idle_timeout.
//   3. AwaitResult: WIT 2-field vs Rust 5-field.
//   4. ReplyResult: WIT 4-field vs Rust 6-field (Wave-20 added the host-internal
//      `task_id`; Wave-23 wit-widening exposed it as the guest-visible WIT
//      `reply-result.task-id` — round-trip landed).
//   5. ReplyStatus: WIT 5-variant vs Rust 4-variant; WIT
//      `success(list<u8>)` splits to Rust `Completed` +
//      `ReplyResult.payload`; WIT `detached` → Rust `Cancelled`.
//   6. OrchestrationError: WIT 6-variant vs Rust 9-variant; the 3
//      Rust-only variants (NotFound, InvalidRequest, Downstream)
//      project to WIT `invalid-target("internal:{kind}:{msg}")` at
//      the host-fn boundary (rule documented now, applied by slice-B
//      host-fn handler).
//
// # Implementer invariants
//   - `AwaitMode` / `TimeoutPolicy` derive Hash so they can key into
//     capability-config tables.
//   - `ReplyStatus::Failed(String)` carries an "invariant identifier"
//     reason (PII discipline; see this file's security posture note).
//   - `received_at` / `ended_at` use `chrono::DateTime<chrono::Utc>` —
//     existing shared-types convention (event.rs / cost.rs).
//   - `AgentAwaitRequest.target` is the canonical `agent:<name>`
//     form per `crates/messaging/src/id_validation.rs::is_safe_id`
//     (must satisfy the grammar `^agent:[A-Za-z0-9_-]+$`).
// ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AwaitMode {
    AllOf,
    AnyOf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeoutPolicy {
    ReturnPartial,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwaitOptions {
    pub mode: AwaitMode,
    /// `None` → runtime default (600 s; see `MAX_IDLE_TIMEOUT_DEFAULT_SEC`
    /// in reply-tracker manager).
    pub idle_timeout_secs: Option<u32>,
    /// Slice-A rewrite: field renamed from `timeout_policy` to match the
    /// WIT `on-idle-timeout` field name.
    pub on_idle_timeout: TimeoutPolicy,
    pub keep_losers: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAwaitRequest {
    /// Canonical agent id (`agent:<name>` form per id_validation::is_safe_id).
    pub target: String,
    pub payload: Vec<u8>,
    pub correlation_id: String,
    pub context: Option<crate::mailbox::MessageContext>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentAwaitRequest {
    pub component_id: String,
    pub correlation_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AwaitRequest {
    AgentRequest(AgentAwaitRequest),
    ComponentFinished(ComponentAwaitRequest),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AwaitSessionStatus {
    /// all-of: every slot Completed. any-of: at least one slot Completed.
    Completed,
    /// TimeoutPolicy::ReturnPartial fired with at least one slot Completed.
    PartialTimeout,
    /// TimeoutPolicy::Fail fired; treated as an error in the caller.
    FailedTimeout,
    /// Session closed by pause-run / cancel-run / parent cascade.
    Cancelled,
    /// **Slice m007-A addition**: all-failed-dispatch fast path — every
    /// slot landed in `ReplyStatus::Failed(...)` at admission's dispatch
    /// loop. Per PRD §9.2 the slice returns `Ok(AwaitResult)` rather
    /// than `Err`; `FailedDispatch` surfaces this case explicitly so
    /// `Completed` is not overloaded.
    FailedDispatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplyStatus {
    /// Agent returned a reply through cap-messaging reply() or component
    /// completed cleanly.
    Completed,
    /// Per-slot idle timeout elapsed before reply arrived (partial-return
    /// mode).
    TimedOut,
    /// Cascade close / parent cancel-run / pause-run. Also used as the
    /// projection target for WIT `detached` in the slice-A loser-omission
    /// path (slice C introduces a richer detach projection).
    Cancelled,
    /// Component-finished with component error OR dispatch-time error.
    /// Payload-empty; reason carried here as an invariant identifier
    /// string (PII discipline).
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyResult {
    /// Slot index in the originating AwaitRequest vector.
    pub slot: u32,
    /// Agent id that produced the reply (`agent:<name>`), or
    /// `component:<id>` for ComponentFinished.
    pub source: String,
    /// Reply payload bytes (empty for ComponentFinished — whose result
    /// lives in the component's output-dir/result.bin and is read by the
    /// caller directly).
    pub payload: Vec<u8>,
    /// Outcome status for this slot — mirrors PRD §9.2 reply-status
    /// variants with the asymmetry documented above.
    pub status: ReplyStatus,
    pub received_at: chrono::DateTime<chrono::Utc>,
    /// AC-13 (keep-losers §9.2 rule 1, Wave-20): the task-id under which this
    /// reply's slot was awaited, preserved (for the winner) from the originating
    /// `AgentAwaitRequest.context.task_id` at the `on_reply` chokepoint. `None`
    /// when the request carried no task-id. Wave-23 wit-widening exposed this field
    /// as the guest-visible WIT `reply-result.task-id: option<string>` (the WIT
    /// `reply-result` record is now 4-field `{correlation-id, target, task-id,
    /// status}`; the coordinated 4-fixture rebuild amortized the prebuilt-`.core.wasm`
    /// ABI hazard). See MODULE-007 §3.6/§3.7. Additive `Option<String>`;
    /// `#[serde(default)]` keeps an old-format payload (no `task-id`)
    /// deserializable despite `deny_unknown_fields` (which only rejects EXTRA
    /// fields, not absent defaulted ones).
    #[serde(default)]
    pub task_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwaitResult {
    pub session_id: String,
    pub mode: AwaitMode,
    /// One ReplyResult per slot in the originating AwaitRequest vector.
    /// Losers (any-of mode, `keep_losers=false`) are OMITTED per MODULE-007
    /// §2.3 — the Vec contains only resolved slots (Completed/Failed
    /// /TimedOut/Cancelled).
    pub replies: Vec<ReplyResult>,
    pub status: AwaitSessionStatus,
    pub ended_at: chrono::DateTime<chrono::Utc>,
}
