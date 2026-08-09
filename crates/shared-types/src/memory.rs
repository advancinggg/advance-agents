//! MODULE-011 memory-system canonical dependency-inversion surface.
//!
//! Canonical source: `docs/modules/MODULE-011-memory-system.md` §2.3
//! (PostProcessorHook + PostProcessorError + L6RunnableSpec + L6Handler +
//! L6Context + L6Cursor + L6Outcome + L6Error) and §2.3 head amendment for
//! `KnowledgeHealthSnapshot` (landed by /dev Slice AC v2).
//!
//! Verbatim hoist — if the owner module's declaration changes, run
//! `/spec MODULE-011` and re-hoist via a follow-on /dev slice.
//!
//! # Security posture
//!
//! - **`L6Context.lease_token` leak surface**: [`L6Context`] ships a
//!   **manual** `impl Debug` that redacts `lease_token` to `<redacted>`
//!   (Slice AC v2 adversarial-fix R3 replaced the derived Debug). Any
//!   `{:?}` formatting is now safe to route into logs / EventBus JSONL.
//!   Downstream wrapper structs that re-derive Debug around L6Context
//!   inherit the safe impl. Serde Serialize/Deserialize still emit
//!   `lease_token` in JSON because handler → scheduler persistence calls
//!   require wire transport — callers writing L6Context JSON to
//!   persistent storage MUST scrub the `lease_token` field at the JSON
//!   layer.
//! - **`L6RunnableSpec` Debug redaction posture**: [`L6RunnableSpec`] ships
//!   a manual `impl Debug` redacting `handler: Arc<dyn L6Handler>` to
//!   `<L6Handler>`. Future field additions MUST preserve this redaction
//!   (or explicitly justify a new leak-safe rendering). Concrete-impl types
//!   that wrap `L6RunnableSpec` MUST NOT add a derived Debug that forces
//!   the supertrait `L6Handler: Debug` — that would leak internal handler
//!   state.
//! - **`L6Handler::handle` by-value ctx retention**: `handle(&self, ctx)`
//!   takes `L6Context` by value. Implementers MUST drop `ctx` at or before
//!   the first `.await` point after lease release. Retaining `ctx` inside
//!   handler state (e.g. `self.inner.lock().await.last_ctx = Some(ctx)`)
//!   keeps `lease_token` live past handler return — racing the scheduler's
//!   lease-rotation logic.
//! - **Error payload PII policy**: [`L6Error`] and [`PostProcessorError`]
//!   `String` payloads are operator-facing and serialized through MODULE-019
//!   EventBus; same PII/secret exclusion rule as [`crate::mailbox::MsgError`].

use crate::mailbox::{ActionResult, Message};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

/// Knowledge-health counter snapshot. Canonical declaration: MODULE-011 §2.3
/// head (landed by /dev Slice AC v2). Emitted in the `memory.l6_completed`
/// event payload (§1.3.6 step 5c; PRD §15.3.22; MODULE-011-AC-35) and
/// returned inside [`L6Outcome::health_snapshot`]. All fields are u32
/// counters computed via a single O(N) scan of `knowledge.jsonl` after the
/// step 5b commit.
///
/// **Implementer Invariants**: computation MUST be O(N) single-scan (no
/// re-reads); bounded values (counter fields saturate at `u32::MAX` rather
/// than overflow). Field evolution beyond these 10 counters is a MODULE-011
/// concrete-impl choice.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeHealthSnapshot {
    pub total_active: u32,
    pub active: u32,
    pub contested: u32,
    pub orphaned: u32,
    pub forgotten: u32,
    pub superseded: u32,
    pub partial_stale: u32,
    pub zero_access_30d: u32,
    pub clusters_total: u32,
    pub clusters_contested: u32,
}

/// MODULE-011 §2.3:503-516 — post-processor pipeline error surface. 5 variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostProcessorError {
    /// Light-model LLM call failed after retries (cools down per
    /// §2.10 `memory.post_processor.llm_failure_cooldown_sec`).
    LlmFailure(String),
    /// SQLite / filesystem write failed (MODULE-002/004).
    StorageError(String),
    /// Per-agent memory limit reached (REQ-097).
    LimitExceeded,
    /// Serialization / schema validation failed on the extracted entries.
    Invalid(String),
    /// Post-processor is in cool-down after repeated LLM failures;
    /// re-schedule after cooldown elapses.
    CooldownActive,
}

/// MODULE-011 §2.3:537-540 — L6 lease cursor. Tracks the `last_knowledge_id`
/// watermark for incremental L6 consolidation. `None` on first run or after
/// rollback-memory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L6Cursor {
    pub last_knowledge_id: Option<String>,
    pub last_completed_at: SystemTime,
}

/// MODULE-011 §2.3:526-535 — L6 handler invocation context. Carries the
/// lease token (acquired by the scheduler); handler passes it back on every
/// persistence call so the scheduler can detect lease loss.
///
/// **Debug posture**: this struct ships `#[derive(Clone, PartialEq, Eq,
/// Serialize, Deserialize)]` but provides a **manual** `impl Debug` that
/// redacts `lease_token` to `<redacted>` — defense-in-depth against
/// accidental `{:?}` logging in emit paths. See [`L6RunnableSpec`] for the
/// same pattern applied to trait-object fields. Implementers MUST NOT
/// override this with a derived Debug that would expose the token.
///
/// **Implementer Invariants**: `agent_id` / `lease_token` whitelist-validated
/// (recommended ≤ 64 bytes each); `triggered_at` monotonically increasing
/// per agent (scheduler emits in order).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L6Context {
    pub agent_id: String,
    pub triggered_at: SystemTime,
    /// Since-when cursor from `.agent/memory/_knowledge_cursor.yaml`.
    pub cursor: Option<L6Cursor>,
    /// Lease token (acquired by the scheduler); handler passes it back on
    /// every persistence call so the scheduler can detect lease loss.
    pub lease_token: String,
}

impl fmt::Debug for L6Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L6Context")
            .field("agent_id", &self.agent_id)
            .field("triggered_at", &self.triggered_at)
            .field("cursor", &self.cursor)
            .field("lease_token", &"<redacted>")
            .finish()
    }
}

/// MODULE-011 §2.3:542-549 — L6 handler return record. Counters drive the
/// `memory.l6_completed` event payload (§1.3.6 step 5c).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L6Outcome {
    pub entries_written: u32,
    pub syntheses_written: u32,
    pub knowledge_map_updated: bool,
    pub cluster_deltas: u32,
    /// Snapshot emitted in `memory.l6_completed` payload (§1.3.6 step 5c).
    pub health_snapshot: KnowledgeHealthSnapshot,
}

/// MODULE-011 §2.3:551-560 — L6 handler error surface. 5 variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum L6Error {
    LlmFailure(String),
    StorageError(String),
    /// Lease expired mid-flight; caller MUST abort writes and let the
    /// scheduler re-lease on the next trigger firing.
    LeaseLost,
    BudgetExhausted,
    /// Git commit failure; handler retains state in-memory and retries next trigger.
    GitCommitFailed(String),
}

/// CONTRACT-102 — L6 consolidation handler trait. MODULE-011 §2.3:518-524.
/// Invoked by MODULE-014 scheduler when the `memory.l6_consolidation_due`
/// trigger event fires for a given agent.
///
/// # Implementer Invariants
///
/// 1. **Idempotent**: scheduler retries on failure after clearing the lease
///    (see MODULE-011 §2.10 `memory.l6.lease_timeout_min`). A successful
///    handle must leave the knowledge store in a state where re-running is
///    safe (no double-count).
/// 2. **Long-running OK**: the handler is a background runnable — no
///    sub-second-latency requirement. But MUST respect `L6Context.lease_token`
///    and return [`L6Error::LeaseLost`] promptly on lease expiry to avoid
///    wasted work.
/// 3. **No host-fn re-entry**: do not call `llm.generate` / `fs.write` /
///    other host functions that themselves dispatch to MODULE-011. All I/O
///    goes through the MODULE-002 / MODULE-004 / MODULE-009 surfaces.
/// 4. **No Debug**: L6Handler does NOT require `Debug` — this is why
///    [`L6RunnableSpec`] provides a manual `impl Debug` that redacts the
///    handler field.
#[async_trait]
pub trait L6Handler: Send + Sync {
    async fn handle(&self, ctx: L6Context) -> Result<L6Outcome, L6Error>;
}

/// CONTRACT-102 — L6 scheduler registration struct. Canonical source:
/// MODULE-011 §2.3:490-494. **NOT a trait** — this is a data struct carrying
/// the handler reference that MODULE-014 scheduler reads from the shared-types
/// registry at boot.
///
/// **Serde posture**: does NOT derive `Serialize` / `Deserialize` because
/// `handler: Arc<dyn L6Handler>` is a trait object (not serializable). A
/// future slice needing registration-table persistence should split into
/// `L6RunnableSpecMeta` (serializable) + `L6RunnableSpec { meta, handler }`.
///
/// **Debug posture**: `L6Handler: Send + Sync` has no `Debug` super-trait,
/// so derived `Debug` would not compile. Manual `impl Debug` redacts the
/// handler to `<L6Handler>` — MODULE-011 concrete-impl slice may replace
/// this with a richer impl if needed.
///
/// **Clone posture**: `#[derive(Clone)]` works because `Arc<T>` is always
/// `Clone` (trait-object or not) and the two `String` fields are `Clone`.
#[derive(Clone)]
pub struct L6RunnableSpec {
    pub component_id: String,
    pub trigger_event: String,
    pub handler: Arc<dyn L6Handler>,
}

impl fmt::Debug for L6RunnableSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L6RunnableSpec")
            .field("component_id", &self.component_id)
            .field("trigger_event", &self.trigger_event)
            .field("handler", &"<L6Handler>")
            .finish()
    }
}

/// CONTRACT-103 — post-processor hook trait. MODULE-011 §2.3:482-488.
/// Invoked by MODULE-014 agent-loop driver after each `handle-message`.
///
/// # Implementer Invariants
///
/// 1. **Idempotent**: the hook MAY be retried after transient failures
///    (MODULE-014 retry policy); implementers must ensure re-invocation
///    does not double-write.
/// 2. **Failure does not roll back the turn**: `PostProcessorError` is
///    reported to MODULE-019 event bus but the turn itself remains
///    committed. The agent state has already advanced.
/// 3. **Bounded execution time**: soft cap per MODULE-011 §2.10
///    `memory.post_processor.max_duration_sec`.
/// 4. **No secrets in error strings**: variant payloads are operator-facing
///    and MUST NOT contain user PII or API-key fragments.
#[async_trait]
pub trait PostProcessorHook: Send + Sync {
    async fn run(
        &self,
        agent_id: &str,
        msg: &Message,
        result: &ActionResult,
    ) -> Result<(), PostProcessorError>;
}
