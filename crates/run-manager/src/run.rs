//! `Run` data model + `RunManager` API (Slice A).
//!
//! See MODULE-008 §1.3.1 + §1.3.2 + Slice A plan §5.3 / §5.4.

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use advance_shared_types::agent_tree::{AgentId, AgentTreeSnapshotData};
use advance_shared_types::await_session::{AwaitSessionRef, OrchestrationError, SessionId};
use advance_shared_types::mailbox::{RunCompletionSink, RunInterruptSink};
use advance_shared_types::run::{
    RoundAdvancer, RoundDecision, RoundResult, RunError, TaskRunStatus,
};
use advance_shared_types::traits::{AgentTreeSnapshot, CostTrackerQuery, EventBusEmit};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::budget::InMemoryRunBudget;
use crate::persist::RunPersister;
use crate::repetition_guard::{AgentRunResolver, RepetitionAction, RepetitionGuard};
use crate::wit_types::{RepetitionGuardConfig, WitRunState};

/// Hard byte-cap on caller-supplied free-form strings flowing into Event
/// payloads and `TaskRunStatus::Failed/Cancelled` reasons. Bounds emit-site
/// amplification of log/SQLite/WebSocket pressure. Byte-based (not char-
/// based) to keep the invariant honest for multi-byte UTF-8 input —
/// truncation respects char boundaries via `floor_char_boundary` semantics.
/// (Closes adversarial round-3 Warning #4.)
const MAX_REASON_LEN_BYTES: usize = 256;

fn truncate_reason(s: String) -> String {
    // Slice B adversarial round 2 W3 fix: strip ASCII control characters
    // (except space + tab) from caller-supplied reason strings BEFORE
    // length-truncation. Reasons flow into TaskRunStatus::Failed/Cancelled
    // → Debug-formatted into RunError messages → operator logs. Control
    // chars (newlines, NUL, etc.) embedded in reasons would forge log
    // entries when downstream consumers log RunError without escaping.
    let stripped: String = s
        .chars()
        .map(|c| {
            // Strip C0/C1 controls except space (U+0020) and tab (U+0009).
            // Tab is allowed because operators may indent multi-field reasons.
            if c == '\t' || c == ' ' || !c.is_control() {
                c
            } else {
                '_'
            }
        })
        .collect();
    if stripped.len() <= MAX_REASON_LEN_BYTES {
        return stripped;
    }
    let mut cut = MAX_REASON_LEN_BYTES;
    while cut > 0 && !stripped.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(cut + 16);
    out.push_str(&stripped[..cut]);
    out.push_str("…[truncated]");
    out
}

/// Hard upper bound on the number of Run rows stored per `RunStore`. New
/// `ensure_run` calls past this cap are rejected with
/// `RunError::PermissionDenied("run-store-cap-reached")`. Bounds the
/// unbounded-`runs`-HashMap memory-DoS surfaced by adversarial round-3.
/// 100_000 is a generous bound for realistic multi-tenant workloads in
/// a single process; a future slice with persistence (AC-15) should
/// rely on disk-backed storage + per-tenant quota instead.
pub const MAX_RUNS_PER_STORE: usize = 100_000;
use crate::events;
use crate::identifier::{
    validate_agent_id, validate_run_id, validate_session_id, validate_task_id,
};
use crate::store::RunStore;

const RESUME_REASONS: &[&str] = &["await_complete", "manual"];
const DESCENDANT_CASCADE_RETRY_LIMIT: usize = 2;
const DESCENDANT_CASCADE_SCAN_LIMIT: usize = 2;
/// grok-repass Item 1 — total dispatch attempts for a `cancel_run` whose
/// TOCTOU recheck keeps observing a still-live run (attempt 0 + 2 retries).
/// On exhaustion `cancel_run` returns `InvalidState("cancel-run-raced")`
/// instead of silently dropping the operator's cancel.
const CANCEL_RACE_RETRY_LIMIT: usize = 3;

/// Newtype over `String` used as the Run identifier. Wire format is a plain
/// string (transparent serde). Borrow<str> + AsRef<str> for ergonomic
/// lookups inside `HashMap<RunId, Run>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(pub(crate) String);

impl RunId {
    pub fn new_random() -> Self {
        Self(format!("run-{}", Uuid::new_v4()))
    }

    /// Construct a `RunId` from a caller-supplied string. Validates against
    /// the `validate_run_id` whitelist (alphanumeric + `_-`, max 64). Returns
    /// `Err` on invalid input; callers MUST handle the error rather than
    /// silently accept arbitrary input (closes the unvalidated-`from_string`
    /// trust-boundary gap surfaced by the adversarial review).
    pub fn from_string(s: String) -> Result<Self, &'static str> {
        validate_run_id(&s)?;
        Ok(Self(s))
    }

    /// Test-only escape hatch — bypasses validation. Compiled only when the
    /// `__test-util` feature is enabled.
    #[cfg(feature = "__test-util")]
    pub fn from_string_unchecked(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RunId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for RunId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Per-run budget state (MODULE-008 §1.3.1 — Slice A extension).
///
/// Canonical 5 fields preserved (`token_used`, `token_limit`, `cost_usd`,
/// `cost_limit`, `rounds_limit`). Slice A adds 3 fields for the
/// reservation-on-check / clamp-on-commit atomicity model:
/// `token_reserved` / `cost_reserved` (in-flight headroom held between
/// `RunBudget::check` and `RunBudget::commit`), `rounds_used` (advanced by
/// `RunManager::complete_round`; consumed by the rounds gate in
/// `RunBudget::check`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BudgetState {
    pub token_used: u64,
    pub token_reserved: u64,
    pub token_limit: Option<u64>,
    pub cost_usd: f64,
    pub cost_reserved: f64,
    pub cost_limit: Option<f64>,
    pub rounds_used: u32,
    pub rounds_limit: Option<u32>,
}

impl BudgetState {
    pub fn from_config(cfg: &RunConfig) -> Self {
        Self {
            token_used: 0,
            token_reserved: 0,
            token_limit: cfg.token_limit,
            cost_usd: 0.0,
            cost_reserved: 0.0,
            cost_limit: cfg.cost_usd_limit,
            rounds_used: 0,
            rounds_limit: cfg.rounds_limit,
        }
    }
}

/// RunConfig — Slice A canonical fields (`token_limit` / `cost_usd_limit` /
/// `rounds_limit`) extended in Slice C with the WIT-shape `retry_overrides`
/// and `repetition_guard` sub-records per PRD §9.5.1.
///
/// Auto-mode is NOT a config field — Auto Runs are identified by `task_id`
/// prefix `auto:` per REQ-069 (see `is_auto_mode`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RunConfig {
    pub token_limit: Option<u64>,
    pub cost_usd_limit: Option<f64>,
    pub rounds_limit: Option<u32>,
    /// Slice C — WIT `run-config.retry-overrides`. Per-run override of the
    /// runtime / agent-config retry defaults. Stored on `Run` for runtime
    /// inspection via `RunManager::retry_overrides`.
    #[serde(default)]
    pub retry_overrides: Option<crate::retry::RetryConfig>,
    /// Slice C — WIT `run-config.repetition-guard`. Per-run override of the
    /// repetition-guard defaults. Stored on `Run` and consulted by the
    /// `build_repetition_guard_from_config` builder.
    #[serde(default)]
    pub repetition_guard: Option<crate::wit_types::RepetitionGuardConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run {
    pub id: RunId,
    pub task_id: String,
    pub controller_agent: String,
    pub status: TaskRunStatus,
    pub root_await: Option<String>,
    pub budget: BudgetState,
    pub iteration: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Slice B — operator-requested pause that's waiting for the next
    /// `complete_round` to settle the Active → Paused transition (branch (b)
    /// of MODULE-008 §1.3.3). `None` when no pause is pending.
    #[serde(default)]
    pub pause_pending: Option<String>,
    /// Slice B — operator-requested cancel waiting for the next
    /// `complete_round` to settle the Active → Cancelled transition
    /// (branch (b) of MODULE-008 §1.3.3). Cancel SUPERSEDES pause; if both
    /// were set, only this field is checked at settle time.
    #[serde(default)]
    pub cancel_pending: Option<String>,
    /// Slice C — RUN-level override storage for AC-13 (PRD §9.5.1
    /// `run-config.retry-overrides`). Carries per-run overrides set at
    /// `ensure_run` time; read by `RunManager::retry_overrides` accessor.
    #[serde(default)]
    pub retry_overrides: Option<crate::retry::RetryConfig>,
    /// Slice C — RUN-level override storage for AC-13 (PRD §9.5.1
    /// `run-config.repetition-guard`). Carries per-run overrides set at
    /// `ensure_run` time; read by `RunManager::repetition_guard_overrides`
    /// accessor + consulted by `build_repetition_guard_from_config`.
    #[serde(default)]
    pub repetition_guard: Option<crate::wit_types::RepetitionGuardConfig>,
}

impl Run {
    pub fn new(task_id: &str, controller_agent: &str, cfg: RunConfig, now: DateTime<Utc>) -> Self {
        Self {
            id: RunId::new_random(),
            task_id: task_id.to_string(),
            controller_agent: controller_agent.to_string(),
            status: TaskRunStatus::Active,
            root_await: None,
            budget: BudgetState::from_config(&cfg),
            iteration: 0,
            created_at: now,
            updated_at: now,
            pause_pending: None,
            cancel_pending: None,
            retry_overrides: cfg.retry_overrides,
            repetition_guard: cfg.repetition_guard,
        }
    }
}

/// Predicate: a Run in Active / Suspended / Paused is "live" per
/// MODULE-008 §1.3.1.
pub(crate) fn is_live_status(s: &TaskRunStatus) -> bool {
    matches!(
        s,
        TaskRunStatus::Active | TaskRunStatus::Suspended | TaskRunStatus::Paused
    )
}

/// Render a `TaskRunStatus` as the lower-cased discriminant string used in
/// the `run.reused` PRD §15.3.4A payload `status` field.
pub(crate) fn task_run_status_label(s: &TaskRunStatus) -> &'static str {
    match s {
        TaskRunStatus::Active => "active",
        TaskRunStatus::Suspended => "suspended",
        TaskRunStatus::Paused => "paused",
        TaskRunStatus::Completed => "completed",
        TaskRunStatus::Failed(_) => "failed",
        TaskRunStatus::Cancelled(_) => "cancelled",
    }
}

/// MODULE-008 `RunManager` — owns the in-memory Run store + emits the full
/// 11-event PRD §15.3.4A lifecycle via the injected `EventBusEmit` trait
/// (Slice A: 4 events; Slice B: 7 more + 2 payload amendments). Slice B
/// additionally holds an optional `Arc<dyn AwaitSessionRef>` for
/// pause/cancel-branch-(a) and crash-recovery flows.
pub struct RunManager {
    pub(crate) store: Arc<RwLock<RunStore>>,
    pub(crate) event_bus: Arc<dyn EventBusEmit>,
    pub(crate) await_session_ref: Option<Arc<dyn AwaitSessionRef>>,
    /// Slice C — optional disk persistence layer (CONTRACT-070 §2.5 +
    /// AC-15). When `Some`, every state mutation persists the affected
    /// `Run` to disk; when `None`, RunManager is in-memory-only (preserves
    /// Slice A/B behavior).
    pub(crate) persister: Option<Arc<RunPersister>>,
    /// Slice C — optional `RoundAdvancer` impl (CONTRACT-141 provided by
    /// MODULE-015 AutoLoopDriver). Required when complete_round is called
    /// on an Auto-task-id Run (else returns PermissionDenied per AC-14).
    pub(crate) round_advancer: Option<Arc<dyn RoundAdvancer>>,
    /// Slice C — optional `CostTrackerQuery` impl (CONTRACT-181 provided
    /// by MODULE-019 CostTracker). When wired, propagates into every
    /// `InMemoryRunBudget` returned by `RunManager::budget()` so the
    /// cost gate consults `max(local, tracker)` per AC-16.
    pub(crate) cost_tracker: Option<Arc<dyn CostTrackerQuery>>,
    /// Wave-12 Lane B — optional `RunInterruptSink` impl (CONTRACT-182,
    /// provided by MODULE-006 `MailboxRunInterruptSink`). When wired,
    /// `recover_on_startup` pushes a synthesized `Message::RunInterrupted`
    /// into the recovered run's controller mailbox AFTER emitting
    /// `run.interrupted`. `None` ⇒ event-only (byte-identical to the
    /// pre-Wave-12 path).
    pub(crate) run_interrupt_sink: Option<Arc<dyn RunInterruptSink>>,
    /// Wave-19 Lane 3 — optional `RunCompletionSink` impl (CONTRACT-184,
    /// provided by MODULE-007 reply-tracker `ComponentResolutionSink`). When
    /// wired, `complete_run` fires it AFTER emitting `run.completed` so the
    /// provider resolves the matching `await-replies` `ComponentFinished` slot
    /// status-only. `None` ⇒ no-op (byte-identical to the pre-Wave-19 path).
    pub(crate) run_completion_sink: Option<Arc<dyn RunCompletionSink>>,
    /// Wave-21 — optional MODULE-005 tree snapshot used by run-id pause/cancel
    /// settlement to close descendant await sessions before forcing those
    /// descendant runs to `Cancelled`. `None` keeps root-only behavior.
    pub(crate) agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
    /// Wave-21 — agent ids whose run creation is permanently blocked because
    /// the agent is being terminated. `ensure_run` holds read guards across
    /// the store mutation so a blocker insertion cannot race between the
    /// check and a new live row.
    pub(crate) run_creation_terminated_agents: RwLock<HashSet<String>>,
    /// Wave-21 — scoped run-creation blockers for active descendant
    /// pause/cancel cascades. Counts allow overlapping root cascades to block
    /// the same descendant agent until every active cascade exits.
    pub(crate) run_creation_scoped_block_counts: RwLock<HashMap<String, usize>>,
}

struct ScopedRunCreationBlock<'a> {
    manager: &'a RunManager,
    agent_ids: Vec<String>,
}

impl<'a> ScopedRunCreationBlock<'a> {
    fn new(manager: &'a RunManager) -> Self {
        Self {
            manager,
            agent_ids: Vec::new(),
        }
    }

    fn add_agents(&mut self, agent_ids: &[String]) {
        if agent_ids.is_empty() {
            return;
        }
        let mut scoped = self
            .manager
            .run_creation_scoped_block_counts
            .write()
            .unwrap();
        for agent_id in agent_ids {
            if self.agent_ids.iter().any(|existing| existing == agent_id) {
                continue;
            }
            *scoped.entry(agent_id.clone()).or_insert(0) += 1;
            self.agent_ids.push(agent_id.clone());
        }
    }
}

impl Drop for ScopedRunCreationBlock<'_> {
    fn drop(&mut self) {
        if self.agent_ids.is_empty() {
            return;
        }
        let mut scoped = self
            .manager
            .run_creation_scoped_block_counts
            .write()
            .unwrap();
        for agent_id in &self.agent_ids {
            let remove = match scoped.get_mut(agent_id) {
                Some(count) if *count <= 1 => true,
                Some(count) => {
                    *count -= 1;
                    false
                }
                None => false,
            };
            if remove {
                scoped.remove(agent_id);
            }
        }
    }
}

impl RunManager {
    pub fn new(event_bus: Arc<dyn EventBusEmit>) -> Self {
        Self {
            store: Arc::new(RwLock::new(RunStore::new())),
            event_bus,
            await_session_ref: None,
            persister: None,
            round_advancer: None,
            cost_tracker: None,
            run_interrupt_sink: None,
            run_completion_sink: None,
            agent_tree: None,
            run_creation_terminated_agents: RwLock::new(HashSet::new()),
            run_creation_scoped_block_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Slice B convenience: builds the manager already wrapped in `Arc<Self>`
    /// so callers can chain `build_repetition_guard` without an explicit
    /// `Arc::new` step. Existing `RunManager::new` semantics unchanged.
    pub fn new_arc(event_bus: Arc<dyn EventBusEmit>) -> Arc<Self> {
        Arc::new(Self::new(event_bus))
    }

    /// Slice B builder: install the M007 session-state accessor needed by
    /// `pause_run` / `cancel_run` branch (a) AND by `recover_on_startup`.
    /// Slice A constructions continue to work without this builder; methods
    /// that REQUIRE the accessor return `PermissionDenied` when it's
    /// absent. (`AwaitSessionRef` is shared-types-hoisted from MODULE-007.)
    pub fn with_await_session_ref(mut self, ar: Arc<dyn AwaitSessionRef>) -> Self {
        self.await_session_ref = Some(ar);
        self
    }

    /// Slice C builder — wire the disk-persistence layer rooted at
    /// `state_dir`. When wired, every state mutation persists the affected
    /// `Run` to disk; `recover_from_disk` / `cold_start_recovery` become
    /// usable. The directory MUST already exist (caller responsibility).
    pub fn with_state_dir(mut self, state_dir: PathBuf) -> Self {
        self.persister = Some(Arc::new(RunPersister::new(state_dir)));
        self
    }

    /// Slice C builder — wire the M015 [`RoundAdvancer`] trait impl
    /// (CONTRACT-141). Required for Auto-mode `complete_round` per AC-14;
    /// Normal-mode `complete_round` does not consult it.
    pub fn with_round_advancer(mut self, ra: Arc<dyn RoundAdvancer>) -> Self {
        self.round_advancer = Some(ra);
        self
    }

    /// Slice C builder — wire the M019 [`CostTrackerQuery`] trait impl
    /// (CONTRACT-181). When wired, every `InMemoryRunBudget` returned by
    /// `RunManager::budget()` consults `max(local, tracker)` at the cost
    /// gate per AC-16.
    pub fn with_cost_tracker(mut self, ct: Arc<dyn CostTrackerQuery>) -> Self {
        self.cost_tracker = Some(ct);
        self
    }

    /// Wave-12 Lane B builder — wire the MODULE-006 [`RunInterruptSink`]
    /// (CONTRACT-182). When wired, `recover_on_startup` delivers a synthesized
    /// `Message::RunInterrupted` into each recovered run's controller mailbox
    /// after emitting `run.interrupted` (best-effort). Optional: without it,
    /// recovery is event-only (every existing caller/test is byte-identical).
    pub fn with_run_interrupt_sink(mut self, sink: Arc<dyn RunInterruptSink>) -> Self {
        self.run_interrupt_sink = Some(sink);
        self
    }

    /// Wave-19 Lane 3 builder — wire the MODULE-007 [`RunCompletionSink`]
    /// (CONTRACT-184). When wired, `complete_run` fires the sink after emitting
    /// `run.completed` so the provider (reply-tracker `ComponentResolutionSink`)
    /// resolves the matching `ComponentFinished` await slot status-only.
    /// Optional: without it, completion is event-only (every existing
    /// caller/test is byte-identical).
    pub fn with_run_completion_sink(mut self, sink: Arc<dyn RunCompletionSink>) -> Self {
        self.run_completion_sink = Some(sink);
        self
    }

    /// Wave-21 builder — wire the MODULE-005 [`AgentTreeSnapshot`] so run-id
    /// pause/cancel settlements can walk descendants and close their await
    /// sessions before terminal cancellation. Optional: without it, existing
    /// root-run behavior is unchanged.
    pub fn with_agent_tree(mut self, tree: Arc<dyn AgentTreeSnapshot>) -> Self {
        self.agent_tree = Some(tree);
        self
    }

    /// Best-effort persist (intermediate states): logs failures via eprintln
    /// and returns Ok. Used for non-terminal mutations (pause_pending /
    /// cancel_pending intermediates) where the next state mutation will
    /// retry persistence. The disk and memory may diverge transiently —
    /// acceptable per the §3.10 best-effort persistence contract.
    fn persist_best_effort(&self, run: &Run) {
        if let Some(persister) = self.persister.as_ref() {
            if let Err(e) = persister.persist(run) {
                eprintln!(
                    "RunManager::persist_best_effort failed for run_id={}: {:?}",
                    run.id, e
                );
            }
        }
    }

    /// Strict persist — returns Err on persistence failure. Used at TERMINAL
    /// transitions (complete_run / fail_run / cancel_run terminal flip) and
    /// at ensure_run-create where memory/disk divergence would corrupt the
    /// crash-recovery contract (closes audit R2 fail-open Warning). The
    /// caller is responsible for rolling back any in-memory state change
    /// before propagating the error to keep memory + disk consistent.
    fn persist_strict(&self, run: &Run) -> Result<(), RunError> {
        if let Some(persister) = self.persister.as_ref() {
            persister.persist(run)?;
        }
        Ok(())
    }

    fn persist_snapshot_best_effort(&self, run_id: &str) {
        if self.persister.is_none() {
            return;
        }
        let snapshot = {
            let store = self.store.read().unwrap();
            store.get(run_id).cloned()
        };
        if let Some(run) = snapshot {
            self.persist_best_effort(&run);
        }
    }

    fn post_order_descendant_agents(
        snapshot: &AgentTreeSnapshotData,
        root_agent: &str,
    ) -> Result<Vec<String>, RunError> {
        fn visit(
            snapshot: &AgentTreeSnapshotData,
            root: &AgentId,
            current: &AgentId,
            visiting: &mut HashSet<AgentId>,
            visited: &mut HashSet<AgentId>,
            out: &mut Vec<String>,
            depth: usize,
            max_depth: usize,
        ) -> Result<(), RunError> {
            if depth > max_depth {
                return Err(RunError::InvalidState(
                    "agent-tree-cycle-in-descendant-cascade".into(),
                ));
            }
            if visited.contains(current) {
                return Ok(());
            }
            if !visiting.insert(current.clone()) {
                return Err(RunError::InvalidState(
                    "agent-tree-cycle-in-descendant-cascade".into(),
                ));
            }
            if let Some(children) = snapshot.children_of.get(current) {
                for child in children {
                    if child == root {
                        return Err(RunError::InvalidState(
                            "agent-tree-cycle-in-descendant-cascade".into(),
                        ));
                    }
                    visit(
                        snapshot,
                        root,
                        child,
                        visiting,
                        visited,
                        out,
                        depth.saturating_add(1),
                        max_depth,
                    )?;
                }
            }
            visiting.remove(current);
            visited.insert(current.clone());
            if current != root {
                out.push(current.0.clone());
            }
            Ok(())
        }

        let root = AgentId(root_agent.to_string());
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        let mut out = Vec::new();
        visit(
            snapshot,
            &root,
            &root,
            &mut visiting,
            &mut visited,
            &mut out,
            0,
            snapshot.nodes.len().saturating_add(1),
        )?;
        Ok(out)
    }

    fn live_run_ids_for_agent(&self, agent_id: &str) -> Vec<RunId> {
        let store = self.store.read().unwrap();
        Self::live_run_ids_for_agent_in_store(&store, agent_id)
    }

    fn live_run_ids_for_agent_in_store(store: &RunStore, agent_id: &str) -> Vec<RunId> {
        let mut run_ids: Vec<RunId> = store
            .iter()
            .filter(|run| run.controller_agent == agent_id && is_live_status(&run.status))
            .map(|run| run.id.clone())
            .collect();
        run_ids.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        run_ids
    }

    fn live_run_ids_for_agents(&self, agent_ids: &[String]) -> Vec<RunId> {
        let store = self.store.read().unwrap();
        Self::live_run_ids_for_agents_in_store(&store, agent_ids)
    }

    fn live_run_ids_for_agents_in_store(store: &RunStore, agent_ids: &[String]) -> Vec<RunId> {
        let mut out = Vec::new();
        for agent_id in agent_ids {
            out.extend(Self::live_run_ids_for_agent_in_store(store, agent_id));
        }
        out
    }

    fn block_run_creation_for_terminated_agent(&self, agent_id: &str) {
        self.run_creation_terminated_agents
            .write()
            .unwrap()
            .insert(agent_id.to_string());
    }

    fn blocked_agent_error(agent_id: &str) -> RunError {
        RunError::PermissionDenied(format!(
            "run-creation-blocked-for-terminating-agent: {agent_id}"
        ))
    }

    fn descendant_agents_for_run(&self, root_run_id: &RunId) -> Result<Vec<String>, RunError> {
        let Some(tree) = self.agent_tree.as_ref() else {
            return Ok(Vec::new());
        };
        let root_agent = {
            let store = self.store.read().unwrap();
            let run = store
                .get(root_run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(root_run_id.to_string()))?;
            run.controller_agent.clone()
        };
        let snapshot = tree.snapshot();
        Self::post_order_descendant_agents(&snapshot, &root_agent)
    }

    fn descendant_run_ids_for_run(&self, root_run_id: &RunId) -> Result<Vec<RunId>, RunError> {
        let descendant_agents = self.descendant_agents_for_run(root_run_id)?;
        Ok(self.live_run_ids_for_agents(&descendant_agents))
    }

    fn preflight_descendant_cascade_for_agent_in_store(
        &self,
        _store: &RunStore,
        root_agent: &str,
    ) -> Result<(), RunError> {
        let Some(tree) = self.agent_tree.as_ref() else {
            return Ok(());
        };
        let snapshot = tree.snapshot();
        let _ = Self::post_order_descendant_agents(&snapshot, root_agent)?;
        Ok(())
    }

    fn preflight_descendant_cascade_for_run(&self, root_run_id: &RunId) -> Result<(), RunError> {
        let _ = self.descendant_agents_for_run(root_run_id)?;
        Ok(())
    }

    async fn cascade_descendants_for_run(
        &self,
        root_run_id: &RunId,
        reason: &str,
    ) -> Result<(), RunError> {
        let mut creation_block = ScopedRunCreationBlock::new(self);
        let mut last_error: Option<RunError> = None;
        for _ in 0..=DESCENDANT_CASCADE_SCAN_LIMIT {
            let descendant_agents = self.descendant_agents_for_run(root_run_id)?;
            creation_block.add_agents(&descendant_agents);
            let descendant_run_ids = self.live_run_ids_for_agents(&descendant_agents);
            if descendant_run_ids.is_empty() {
                return Ok(());
            }

            last_error = None;
            for run_id in descendant_run_ids {
                if let Err(e) = self.cancel_descendant_run(&run_id, reason).await {
                    if last_error.is_none() {
                        last_error = Some(e);
                    }
                }
            }
        }
        if let Some(err) = last_error {
            return Err(err);
        }
        if self.descendant_run_ids_for_run(root_run_id)?.is_empty() {
            Ok(())
        } else {
            Err(RunError::InvalidState("descendant-cascade-raced".into()))
        }
    }

    async fn cancel_descendant_run(&self, run_id: &RunId, reason: &str) -> Result<(), RunError> {
        let mut retries = 0usize;
        loop {
            let root_await_snapshot = {
                let store = self.store.read().unwrap();
                let Some(run) = store.get(run_id.as_ref()) else {
                    return Ok(());
                };
                if !is_live_status(&run.status) {
                    return Ok(());
                }
                run.root_await.clone()
            };

            if let Some(sid_str) = root_await_snapshot.as_deref() {
                let ar = self.await_session_ref.as_ref().ok_or_else(|| {
                    RunError::PermissionDenied("await-session-ref-not-configured".into())
                })?;
                let sid = SessionId(sid_str.to_string());
                if let Err(e) = ar.close(&sid, reason).await {
                    match e {
                        OrchestrationError::NotFound(_) | OrchestrationError::SessionClosed(_) => {
                            eprintln!(
                                "descendant cascade: AwaitSessionRef::close found session already terminal for run_id={}: {:?}",
                                run_id, e
                            );
                        }
                        other => {
                            eprintln!(
                                "descendant cascade: AwaitSessionRef::close failed for run_id={}: {:?}",
                                run_id, other
                            );
                            return Err(RunError::InvalidState(
                                "descendant-cascade-await-close-failed".into(),
                            ));
                        }
                    }
                }
            }

            let step = {
                let mut store = self.store.write().unwrap();
                let Some(run) = store.get_mut(run_id.as_ref()) else {
                    return Ok(());
                };
                if !is_live_status(&run.status) {
                    return Ok(());
                }
                if run.root_await != root_await_snapshot && run.root_await.is_some() {
                    if retries < DESCENDANT_CASCADE_RETRY_LIMIT {
                        None
                    } else {
                        return Err(RunError::InvalidState("descendant-cascade-raced".into()));
                    }
                } else {
                    run.status = TaskRunStatus::Cancelled(reason.to_string());
                    run.root_await = None;
                    run.pause_pending = None;
                    run.cancel_pending = None;
                    run.budget.token_reserved = 0;
                    run.budget.cost_reserved = 0.0;
                    run.updated_at = Utc::now();
                    let task_id = run.task_id.clone();
                    let controller_agent = run.controller_agent.clone();
                    let run_id_str = run.id.0.clone();
                    store.drop_live_by_task(&task_id);
                    Some(events::run_cancelled_event(
                        &run_id_str,
                        &task_id,
                        &controller_agent,
                        reason,
                    ))
                }
            };

            if let Some(evt) = step {
                self.persist_snapshot_best_effort(run_id.as_ref());
                self.event_bus.emit(evt);
                return Ok(());
            }
            retries = retries.saturating_add(1);
        }
    }

    /// Returns a fresh `InMemoryRunBudget` handle bound to this manager's
    /// store. Both share the same `Arc<RwLock<RunStore>>` so budget
    /// mutations and Run-state mutations serialize on a single lock.
    /// Slice C — propagates the manager-held `cost_tracker` into the
    /// returned budget so AC-16's `max(local, tracker)` fail-safe is
    /// honored by every consumer that obtains a budget handle via this
    /// factory.
    pub fn budget(&self) -> InMemoryRunBudget {
        InMemoryRunBudget::new_with_cost_tracker(
            Arc::clone(&self.store),
            self.cost_tracker.as_ref().map(Arc::clone),
            self.persister.as_ref().map(Arc::clone),
        )
    }

    /// Slice C accessor — read the `controller_agent` of the live Run for
    /// `task_id`, if any. Used by `AgentRunWitImpl::ensure_run` to enforce
    /// cross-agent task-id collision authz (closes adversarial R2 Critical:
    /// any caller could otherwise hijack another agent's live run by
    /// guessing the task_id). Returns `None` if no live run for that
    /// task_id exists.
    pub fn task_owner_if_live(&self, task_id: &str) -> Option<String> {
        let store = self.store.read().unwrap();
        store
            .find_live_by_task(task_id)
            .map(|r| r.controller_agent.clone())
    }

    /// Slice C accessor — read the `controller_agent` of a Run by run_id.
    /// Used by `AgentRunWitImpl::assert_caller_owns` to enforce ownership
    /// on every WIT mutating method (closes audit R1 adversarial Critical
    /// "any WIT caller can control another agent's run"). Returns `None`
    /// for unknown run_id.
    pub fn controller_agent_of(&self, run_id: &str) -> Option<String> {
        let store = self.store.read().unwrap();
        store.get(run_id).map(|r| r.controller_agent.clone())
    }

    /// Slice C accessor (AC-13) — read the per-run `RetryConfig` override
    /// stored on the `Run` row. Returns `None` for unknown run_id or for
    /// runs created without `retry_overrides` in their config. Used by
    /// integration tests + future M009 cross-crate consumption (the
    /// cross-crate read path is deferred to a future shared-types trait).
    pub fn retry_overrides(&self, run_id: &RunId) -> Option<crate::retry::RetryConfig> {
        let store = self.store.read().unwrap();
        store
            .get(run_id.as_ref())
            .and_then(|r| r.retry_overrides.clone())
    }

    /// Slice C accessor (AC-13) — read the per-run `RepetitionGuardConfig`
    /// override stored on the `Run` row. Used by integration tests + the
    /// `build_repetition_guard_from_config` internal flow.
    pub fn repetition_guard_overrides(&self, run_id: &RunId) -> Option<RepetitionGuardConfig> {
        let store = self.store.read().unwrap();
        store
            .get(run_id.as_ref())
            .and_then(|r| r.repetition_guard.clone())
    }

    /// Slice C (AC-13) — construct a `RepetitionGuard` from a
    /// `RepetitionGuardConfig` (typically obtained via
    /// `repetition_guard_overrides`). Honors `cfg.enabled=Some(false)` via
    /// `RepetitionGuard::with_enabled(false)`; resolves window/threshold/
    /// action via the config's `apply_defaults()` mapping.
    pub fn build_repetition_guard_from_config(
        self: &Arc<Self>,
        cfg: &RepetitionGuardConfig,
    ) -> RepetitionGuard {
        let defaults = cfg.apply_defaults();
        let action = RepetitionGuardConfig::action_to_repetition_action(&defaults.action)
            .unwrap_or(RepetitionAction::WarnThenTerminate);
        let g = RepetitionGuard::new(
            defaults.window_size as usize,
            defaults.repeat_threshold as usize,
            action,
        )
        .with_enabled(defaults.enabled)
        .with_event_bus(Arc::clone(&self.event_bus))
        .with_run_resolver(Arc::clone(self) as Arc<dyn AgentRunResolver>);
        g
    }

    /// Slice C (AC-18) — return the WIT-shape `run-state` per PRD §9.5.1.
    /// `await_tree` is populated ONLY when `status==Suspended` AND the
    /// `AwaitSessionRef` is wired AND `root_await` parses as a valid
    /// `SessionId`. Fail-closed semantics: any of these conditions being
    /// false yields `await_tree=None` (NOT an Err).
    pub fn run_status(&self, run_id: &RunId) -> Result<WitRunState, RunError> {
        let store = self.store.read().unwrap();
        let run = store
            .get(run_id.as_ref())
            .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
        let await_tree = match (
            &run.status,
            &run.root_await,
            self.await_session_ref.as_ref(),
        ) {
            (TaskRunStatus::Suspended, Some(sid_str), Some(walker)) => {
                if crate::identifier::validate_session_id(sid_str).is_ok() {
                    walker.walk_tree(&SessionId(sid_str.clone()))
                } else {
                    eprintln!(
                        "run_status: Suspended Run {} has invalid root_await (len={}) — fail-closed await_tree=None",
                        run_id,
                        sid_str.len()
                    );
                    None
                }
            }
            _ => None,
        };
        Ok(WitRunState {
            task_id: run.task_id.clone(),
            controller_agent: run.controller_agent.clone(),
            status: run.status.clone(),
            iteration: run.iteration,
            root_await: run.root_await.clone(),
            await_tree,
            token_used: run.budget.token_used,
            token_limit: run.budget.token_limit,
            cost_usd: run.budget.cost_usd,
            cost_usd_limit: run.budget.cost_limit,
            rounds_limit: run.budget.rounds_limit,
        })
    }

    /// `ensure_run` (MODULE-008 §1.3.2). Single write-locked critical
    /// section: lookup live-by-task; reuse-if-present or insert new. Event
    /// emission happens AFTER releasing the lock. Validates the supplied
    /// `RunConfig` to reject non-finite `cost_usd_limit` (closes
    /// adversarial round-2 Critical — NaN/Inf in limits would permanently
    /// fail-open the cost gate).
    pub fn ensure_run(
        &self,
        task_id: &str,
        controller_agent: &str,
        cfg: RunConfig,
    ) -> Result<RunId, RunError> {
        // Slice C — strict-mode opt-in: when called via `ensure_run_strict`,
        // the existing live run's controller_agent MUST match. The
        // wrapper below preserves the agent-blind contract for direct
        // Rust callers (test infrastructure) while exposing the strict
        // variant for AgentRunWitImpl.
        self.ensure_run_inner(task_id, controller_agent, cfg, false)
    }

    /// Slice C — strict variant that atomically combines the cross-agent
    /// authz check with the create/reuse decision under a single
    /// `store.write()` critical section. Closes the TOCTOU race
    /// surfaced by adversarial R4 (the WIT-layer authz pre-check and
    /// the RunManager-layer insert ran in separate lock spans).
    pub fn ensure_run_strict(
        &self,
        task_id: &str,
        controller_agent: &str,
        cfg: RunConfig,
    ) -> Result<RunId, RunError> {
        self.ensure_run_inner(task_id, controller_agent, cfg, true)
    }

    fn ensure_run_inner(
        &self,
        task_id: &str,
        controller_agent: &str,
        cfg: RunConfig,
        strict_agent_check: bool,
    ) -> Result<RunId, RunError> {
        validate_task_id(task_id)
            .map_err(|e| RunError::PermissionDenied(format!("invalid-task-id: {e}")))?;
        validate_agent_id(controller_agent)
            .map_err(|e| RunError::PermissionDenied(format!("invalid-controller-agent: {e}")))?;
        // Slice C — when a persister is wired, pre-validate task_id against
        // the persister-side filter BEFORE store.insert. This keeps
        // memory/disk consistent (no in-memory Run row that the persister
        // would later refuse).
        if self.persister.is_some() {
            RunPersister::validate_path_safe(task_id)
                .map_err(|e| RunError::PermissionDenied(format!("persist-unsafe-task-id: {e}")))?;
        }
        if let Some(limit) = cfg.cost_usd_limit {
            if !limit.is_finite() || limit < 0.0 {
                return Err(RunError::PermissionDenied(format!(
                    "invalid-cost-usd-limit: {limit}"
                )));
            }
        }

        let run_creation_terminated_block = self.run_creation_terminated_agents.read().unwrap();
        let run_creation_scoped_block = self.run_creation_scoped_block_counts.read().unwrap();
        if run_creation_terminated_block.contains(controller_agent)
            || run_creation_scoped_block
                .get(controller_agent)
                .copied()
                .unwrap_or(0)
                > 0
        {
            return Err(Self::blocked_agent_error(controller_agent));
        }

        let (id, event, new_run_snapshot) = {
            let mut store = self.store.write().unwrap();
            if let Some(existing) = store.find_live_by_task(task_id) {
                // Slice C — strict-mode cross-agent authz inside the
                // write-lock critical section (closes adversarial R4
                // Critical: WIT-layer pre-check was non-atomic with the
                // RunManager-layer reuse decision; concurrent callers
                // could race past the check).
                if strict_agent_check && existing.controller_agent != controller_agent {
                    return Err(RunError::PermissionDenied(
                        "task-owned-by-different-agent".into(),
                    ));
                }
                let existing_id = existing.id.clone();
                let existing_status = task_run_status_label(&existing.status);
                let evt = events::run_reused_event(
                    existing_id.as_ref(),
                    task_id,
                    controller_agent,
                    existing_status,
                );
                (existing_id, evt, None)
            } else {
                // Cap enforcement: refuse to grow the store past MAX_RUNS_PER_STORE.
                if store.runs_len() >= MAX_RUNS_PER_STORE {
                    return Err(RunError::PermissionDenied(format!(
                        "run-store-cap-reached: {MAX_RUNS_PER_STORE}"
                    )));
                }
                let run = Run::new(task_id, controller_agent, cfg, Utc::now());
                let new_id = run.id.clone();
                let snapshot = run.clone();
                store.insert(run);
                let evt = events::run_created_event(new_id.as_ref(), task_id, controller_agent);
                (new_id, evt, Some(snapshot))
            }
        };
        if let Some(run) = new_run_snapshot.as_ref() {
            // Strict persist on initial create — memory/disk consistency
            // contract requires us to roll back the in-memory insert if
            // the disk write fails (closes audit R2 fail-open Warning).
            if let Err(e) = self.persist_strict(run) {
                let mut store = self.store.write().unwrap();
                store.drop_live_by_task(&run.task_id);
                store.remove(run.id.as_ref());
                return Err(e);
            }
        }
        drop(run_creation_scoped_block);
        drop(run_creation_terminated_block);
        self.event_bus.emit(event);
        Ok(id)
    }

    /// `complete_round` — advances `rounds_used` + `iteration` then settles
    /// pause/cancel-pending state under the same write-lock critical section.
    /// Emits `run.round_completed` AFTER lock drop, then `run.paused` /
    /// `run.cancelled` if the settle applies. Slice B payload: PRD §15.3.4A
    /// `{iteration, token_used, cost_usd, decision}` where `decision` is one
    /// of `continue-allowed` / `blocked:rounds-exceeded` /
    /// `blocked:cancel-pending`.
    pub async fn complete_round(
        &self,
        run_id: &RunId,
        result: RoundResult,
    ) -> Result<RoundDecision, RunError> {
        // Stage-F obs SLICE 1: the legacy entry point delegates with no chain
        // trace — `run.round_completed` keeps `base_event`'s fresh-v4 trace +
        // `parent_span_id: None` (preserves the assert_uuid_v4 tripwire + every
        // existing caller byte-identically).
        self.complete_round_with_trace(run_id, result, None, None)
            .await
    }

    /// Stage-F obs SLICE 1 — `complete_round` with the handle-message chain
    /// `trace_id` + chain-root `parent_span_id` threaded onto the
    /// `run.round_completed` event (the SYS-AC-138 chain child). Additive: the
    /// cli `handle_message` per-turn caller passes
    /// `(msg.context.trace_id, Some(chain_root_span_id(msg.id)))`; all other
    /// callers use the delegating [`Self::complete_round`] (`None, None`).
    ///
    /// **Override invariant:** `trace_id: None` LEAVES `base_event`'s fresh-v4
    /// trace intact (never an empty string) and `parent_span_id: None` leaves the
    /// base `None` — so `run.created` / `run.reused` and the v4 tripwire are
    /// unaffected (run.* conflation guard: only the per-turn `run.round_completed`
    /// joins the chain, never the run-lifecycle events; Event invariant 4).
    pub async fn complete_round_with_trace(
        &self,
        run_id: &RunId,
        result: RoundResult,
        trace_id: Option<String>,
        parent_span_id: Option<String>,
    ) -> Result<RoundDecision, RunError> {
        // Slice C AC-14 — Auto-mode dispatch by task_id prefix. We need
        // the task_id BEFORE entering the per-round mutation block so the
        // Auto-mode branch can short-circuit out of all event/counter
        // side-effects. Read-lock briefly to inspect status + task_id.
        let (task_id_snapshot, status_snapshot, has_pending_descendant_cascade) = {
            let store = self.store.read().unwrap();
            let run = store
                .get(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            (
                run.task_id.clone(),
                run.status.clone(),
                run.pause_pending.is_some() || run.cancel_pending.is_some(),
            )
        };
        if !matches!(status_snapshot, TaskRunStatus::Active) {
            return Err(RunError::InvalidState(format!(
                "complete-round-on-non-active: {:?}",
                status_snapshot
            )));
        }
        if crate::identifier::is_auto_mode(&task_id_snapshot) {
            // Auto-mode complete_round — buffer-only per PRD §4.7.7 + A.24.
            // (i) Require round_advancer wired.
            let advancer = self.round_advancer.as_ref().ok_or_else(|| {
                RunError::PermissionDenied("auto-mode-requires-round-advancer".into())
            })?;
            // (ii) Hand off to RoundAdvancer; observe but DO NOT propagate
            // the decision value (PRD A.24 invariant: agent unaware →
            // continue-allowed). Errors from the advancer DO propagate via `?`
            // — these represent infrastructure failures (M015 buffer write
            // error, etc.) that the agent must observe to retry the call;
            // the PRD "unaware" guarantee is about decision values, not
            // RunError surface (documented in MODULE-008 §3.10).
            let _m015_decision = advancer.on_complete_round(run_id.as_ref(), result).await?;
            // (iii) Re-validate Active status under the write lock to defend
            // against TOCTOU race: between the read-lock drop above and now,
            // a concurrent `complete_run` / `cancel_run` (Suspended branch)
            // could have terminal-flipped this Run. We don't mutate state in
            // Auto-mode, but a terminal-flipped Run should surface as
            // InvalidState rather than silently returning ContinueAllowed
            // for a Run that no longer exists.
            {
                let store = self.store.read().unwrap();
                let run = store
                    .get(run_id.as_ref())
                    .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
                if !matches!(run.status, TaskRunStatus::Active) {
                    return Err(RunError::InvalidState(format!(
                        "complete-round-raced-from-active: now {:?}",
                        run.status
                    )));
                }
            }
            // (iv) Always return ContinueAllowed (agent unaware per PRD
            // line 871 + A.24 line 6254).
            return Ok(RoundDecision::ContinueAllowed);
        }
        if has_pending_descendant_cascade {
            self.preflight_descendant_cascade_for_run(run_id)?;
        }
        // Normal mode — existing Slice A/B logic unchanged below.
        let round_event: advance_shared_types::event::Event;
        let mut settle_event: Option<advance_shared_types::event::Event> = None;
        let mut descendant_cascade_reason: Option<String> = None;
        let outcome: RoundDecision;
        let _ = result; // Normal mode discards the result body per Slice A.
        {
            let mut store = self.store.write().unwrap();
            let (pending_descendant_cascade, root_agent_for_preflight) = {
                let run = store
                    .get_mut(run_id.as_ref())
                    .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
                if !matches!(run.status, TaskRunStatus::Active) {
                    return Err(RunError::InvalidState(format!(
                        "complete-round-on-non-active: {:?}",
                        run.status
                    )));
                }
                (
                    run.pause_pending.is_some() || run.cancel_pending.is_some(),
                    run.controller_agent.clone(),
                )
            };
            if pending_descendant_cascade {
                self.preflight_descendant_cascade_for_agent_in_store(
                    &store,
                    &root_agent_for_preflight,
                )?;
            }
            let run = store
                .get_mut(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            run.budget.rounds_used = run.budget.rounds_used.saturating_add(1);
            run.iteration = run.budget.rounds_used;
            run.updated_at = Utc::now();
            let rounds_blocked = run
                .budget
                .rounds_limit
                .map(|limit| run.budget.rounds_used > limit)
                .unwrap_or(false);

            // Decide the per-round decision string per PRD §15.3.4A line 5308.
            // Priority: rounds_blocked > cancel_pending > continue-allowed
            // (pause_pending does NOT change the decision; the round itself
            // succeeded — pause settles AFTER the emit).
            let decision_label: &'static str = if rounds_blocked {
                events::DECISION_BLOCKED_ROUNDS_EXCEEDED
            } else if run.cancel_pending.is_some() {
                events::DECISION_BLOCKED_CANCEL_PENDING
            } else {
                events::DECISION_CONTINUE_ALLOWED
            };

            round_event = events::run_round_completed_event(
                run.id.0.as_str(),
                &run.task_id,
                &run.controller_agent,
                run.iteration,
                run.budget.token_used,
                run.budget.cost_usd,
                decision_label,
                // Stage-F obs SLICE 1: thread the chain trace + chain-root parent
                // span onto ONLY this per-turn event (None -> keep base_event v4).
                trace_id.as_deref(),
                parent_span_id.as_deref(),
            );

            // Cancel-pending takes precedence over pause-pending.
            if let Some(cancel_reason) = run.cancel_pending.take() {
                let cancel_reason = truncate_reason(cancel_reason);
                run.status = TaskRunStatus::Cancelled(cancel_reason.clone());
                run.pause_pending = None;
                run.budget.token_reserved = 0;
                run.budget.cost_reserved = 0.0;
                let task_id = run.task_id.clone();
                let controller_agent = run.controller_agent.clone();
                let run_id_str = run.id.0.clone();
                store.drop_live_by_task(&task_id);
                settle_event = Some(events::run_cancelled_event(
                    &run_id_str,
                    &task_id,
                    &controller_agent,
                    &cancel_reason,
                ));
                descendant_cascade_reason = Some(cancel_reason.clone());
                outcome = RoundDecision::Blocked("cancel-pending".into());
            } else if let Some(pause_reason) = run.pause_pending.take() {
                let pause_reason = truncate_reason(pause_reason);
                run.status = TaskRunStatus::Paused;
                let run_id_str = run.id.0.clone();
                let task_id = run.task_id.clone();
                let controller_agent = run.controller_agent.clone();
                settle_event = Some(events::run_paused_event(
                    &run_id_str,
                    &task_id,
                    &controller_agent,
                    &pause_reason,
                ));
                descendant_cascade_reason = Some(pause_reason.clone());
                outcome = if rounds_blocked {
                    RoundDecision::Blocked("rounds-exceeded".into())
                } else {
                    RoundDecision::ContinueAllowed
                };
            } else if rounds_blocked {
                outcome = RoundDecision::Blocked("rounds-exceeded".into());
            } else {
                outcome = RoundDecision::ContinueAllowed;
            }
        } // ← write lock dropped here
          // Slice C — persist after lock drop, before emit (matches Slice B
          // lock-drop-before-emit invariant; persistence ordering is captured
          // implicitly because complete_round always mutates Run state).
        self.persist_snapshot_best_effort(run_id.as_ref());
        self.event_bus.emit(round_event);
        if let Some(evt) = settle_event {
            self.event_bus.emit(evt);
        }
        if let Some(reason) = descendant_cascade_reason {
            self.cascade_descendants_for_run(run_id, &reason).await?;
        }
        Ok(outcome)
    }

    /// `complete_run` — Active → Completed terminal flip. Emits
    /// `run.completed` AFTER releasing the lock. **Drains any outstanding
    /// budget reservation** to close the reservation-leak-DoS surface
    /// surfaced by the adversarial review.
    pub fn complete_run(&self, run_id: &RunId, outcome: String) -> Result<(), RunError> {
        let outcome = truncate_reason(outcome);
        let snapshot = {
            let mut store = self.store.write().unwrap();
            let run = store
                .get_mut(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            if !matches!(run.status, TaskRunStatus::Active) {
                return Err(RunError::InvalidState(format!(
                    "complete-run-on-non-active: {:?}",
                    run.status
                )));
            }
            run.status = TaskRunStatus::Completed;
            run.updated_at = Utc::now();
            // Drain reservations — terminal transition releases any
            // outstanding check-but-not-committed headroom.
            run.budget.token_reserved = 0;
            run.budget.cost_reserved = 0.0;
            // Slice B adv-round-2 Info #8: terminal-state hygiene —
            // clear pause/cancel pending flags so the Completed Run does
            // not carry stale operator-intent state. Matches fail_run.
            run.pause_pending = None;
            run.cancel_pending = None;
            let task_id = run.task_id.clone();
            let controller_agent = run.controller_agent.clone();
            let run_id_str = run.id.0.clone();
            store.drop_live_by_task(&task_id);
            (run_id_str, task_id, controller_agent)
        };
        let (run_id_str, task_id, controller_agent) = snapshot;
        let evt = events::run_completed_event(&run_id_str, &task_id, &controller_agent, &outcome);
        self.persist_snapshot_best_effort(&run_id_str);
        self.event_bus.emit(evt);
        // Wave-19 Lane 3 (CONTRACT-184): after the `run.completed` emit, fire the
        // optional RunCompletionSink so the MODULE-007 provider resolves the
        // matching `ComponentFinished` await slot status-only. Best-effort —
        // `Err` is logged and never blocks completion. `None` ⇒ byte-identical.
        if let Some(sink) = self.run_completion_sink.as_ref() {
            if let Err(e) =
                sink.on_run_completed(&controller_agent, &run_id_str, &task_id, &outcome)
            {
                eprintln!(
                    "RunManager::complete_run: RunCompletionSink returned non-fatal error for run_id={run_id_str}: {e:?}"
                );
            }
        }
        Ok(())
    }

    /// `fail_run` — Active → Failed(reason). Slice B amends to emit
    /// `run.failed` AFTER lock drop (Slice A had no emit; that gap is closed
    /// here as part of the 11-event lifecycle). Drains reservations on
    /// terminal transition.
    pub fn fail_run(&self, run_id: &RunId, reason: String) -> Result<(), RunError> {
        let reason = truncate_reason(reason);
        let snapshot = {
            let mut store = self.store.write().unwrap();
            let run = store
                .get_mut(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            if !matches!(run.status, TaskRunStatus::Active) {
                return Err(RunError::InvalidState(format!(
                    "fail-run-on-non-active: {:?}",
                    run.status
                )));
            }
            run.status = TaskRunStatus::Failed(reason.clone());
            run.updated_at = Utc::now();
            run.pause_pending = None;
            run.cancel_pending = None;
            run.budget.token_reserved = 0;
            run.budget.cost_reserved = 0.0;
            let task_id = run.task_id.clone();
            let controller_agent = run.controller_agent.clone();
            let run_id_str = run.id.0.clone();
            store.drop_live_by_task(&task_id);
            (run_id_str, task_id, controller_agent)
        };
        let (run_id_str, task_id, controller_agent) = snapshot;
        let evt = events::run_failed_event(&run_id_str, &task_id, &controller_agent, &reason);
        self.persist_snapshot_best_effort(&run_id_str);
        self.event_bus.emit(evt);
        Ok(())
    }

    /// `pause_run` (MODULE-008 §1.3.3, Slice B). Branch (a) Suspended →
    /// closes the AwaitSession then flips status to Paused. Branch (b)
    /// Active → sets `pause_pending`; the next `complete_round` settles
    /// the transition.
    pub async fn pause_run(&self, run_id: &RunId, reason: String) -> Result<(), RunError> {
        let reason = truncate_reason(reason);
        // Phase 1: read current state, decide branch.
        let (status_snapshot, root_await_snapshot) = {
            let store = self.store.read().unwrap();
            let run = store
                .get(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            (run.status.clone(), run.root_await.clone())
        };
        match status_snapshot {
            TaskRunStatus::Suspended => {
                self.preflight_descendant_cascade_for_run(run_id)?;
                let ar = self.await_session_ref.as_ref().ok_or_else(|| {
                    RunError::PermissionDenied("await-session-ref-not-configured".into())
                })?;
                if let Some(sid_str) = root_await_snapshot.as_deref() {
                    let sid = SessionId(sid_str.to_string());
                    if let Err(e) = ar.close(&sid, &reason).await {
                        // Non-fatal — close is idempotent per AwaitSessionRef invariant 2.
                        eprintln!(
                            "pause_run: AwaitSessionRef::close returned non-fatal error: {:?}",
                            e
                        );
                    }
                } else {
                    eprintln!(
                        "pause_run: Suspended Run {} has root_await=None — skipping close",
                        run_id
                    );
                }
                let evt_opt = {
                    let mut store = self.store.write().unwrap();
                    let run = store
                        .get_mut(run_id.as_ref())
                        .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
                    // Slice B TOCTOU double-recheck (matches recovery.rs
                    // invariant): re-verify BOTH `status == Suspended` AND
                    // `root_await == captured_snapshot` before mutating. The
                    // root_await comparison catches the
                    // Suspended(sid1) → resume_run → suspend_run(sid2)
                    // re-entry race where Phase 1's snapshot already closed
                    // sid1; without the root_await check, Phase 2 would
                    // clear sid2 from root_await while sid2 stays alive in
                    // M007 (orphaned-session leak per adv round 4).
                    let status_matches = matches!(run.status, TaskRunStatus::Suspended);
                    let root_matches = run.root_await == root_await_snapshot;
                    if !status_matches || !root_matches {
                        eprintln!(
                            "pause_run: branch (a) raced — Run {} status={:?} root_await={:?} (snapshot expected Suspended + {:?}); dropping pause",
                            run_id, run.status, run.root_await, root_await_snapshot
                        );
                        None
                    } else {
                        run.status = TaskRunStatus::Paused;
                        // Slice B adv-round-2 W1: AwaitSession was just
                        // closed via ar.close(...) above, root_await is
                        // stale. Clear it. Without this, Paused→Active
                        // (resume_run) followed by pause_run(Active) would
                        // hit the active-with-root-await invariant check.
                        run.root_await = None;
                        run.pause_pending = None;
                        run.updated_at = Utc::now();
                        Some(events::run_paused_event(
                            run.id.0.as_str(),
                            &run.task_id,
                            &run.controller_agent,
                            &reason,
                        ))
                    }
                };
                if let Some(evt) = evt_opt {
                    self.persist_snapshot_best_effort(run_id.as_ref());
                    self.event_bus.emit(evt);
                    self.cascade_descendants_for_run(run_id, &reason).await?;
                }
                Ok(())
            }
            TaskRunStatus::Paused => {
                self.cascade_descendants_for_run(run_id, &reason).await?;
                Ok(())
            }
            TaskRunStatus::Active => {
                let mut store = self.store.write().unwrap();
                let run = store
                    .get_mut(run_id.as_ref())
                    .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
                // Slice B TOCTOU recheck: status_snapshot was Active; if the
                // Run has since transitioned, surface as InvalidState rather
                // than poisoning a non-Active row with pause_pending.
                if !matches!(run.status, TaskRunStatus::Active) {
                    return Err(RunError::InvalidState(format!(
                        "pause-run-raced-from-active: now {:?}",
                        run.status
                    )));
                }
                if run.cancel_pending.is_some() {
                    return Err(RunError::InvalidState("cancel-pending-already-set".into()));
                }
                if root_await_snapshot.is_some() {
                    // Slice B fail-closed: Active + root_await=Some is a
                    // state-machine invariant violation; surface as an error
                    // rather than silently coercing.
                    eprintln!(
                        "pause_run: Active Run {} has root_await={:?} — invariant violation",
                        run_id, run.root_await
                    );
                    return Err(RunError::InvalidState(
                        "active-with-root-await-invariant-violation".into(),
                    ));
                }
                if let Some(existing) = &run.pause_pending {
                    // First-write-wins; eprintln logs the silently-dropped
                    // second reason for ops recovery.
                    eprintln!(
                        "pause_run: pause_pending already set (existing reason={:?}); ignoring new reason={:?} for run_id={}",
                        existing, reason, run_id
                    );
                    return Ok(());
                }
                run.pause_pending = Some(reason);
                run.updated_at = Utc::now();
                drop(store);
                self.persist_snapshot_best_effort(run_id.as_ref());
                Ok(())
            }
            other => Err(RunError::InvalidState(format!("pause-run-on-{:?}", other))),
        }
    }

    /// `cancel_run` (MODULE-008 §1.3.3, Slice B). Branch (a)
    /// Suspended/Paused → closes the AwaitSession (Paused has no session)
    /// then flips status to Cancelled. Branch (b) Active → sets
    /// `cancel_pending`; the next `complete_round` settles the transition.
    /// Cancel SUPERSEDES pause: if `pause_pending` was set, it's cleared.
    ///
    /// grok-repass Item 1 (lost-cancel): the Suspended/Paused TOCTOU
    /// recheck-failure legs used to log and return `Ok(())`, silently
    /// dropping the operator's cancel while the run stayed live. Now a
    /// raced-but-still-live recheck in the Suspended/Paused arms carries the
    /// `(status, root_await)` pair it observed under the write lock into the
    /// next attempt and re-dispatches into the branch documented for that
    /// state, bounded at [`CANCEL_RACE_RETRY_LIMIT`] attempts. (The Active
    /// arm's own recheck does NOT carry forward — it surfaces its
    /// pre-existing `cancel-run-raced-from-active` error, unchanged by this
    /// lane; see the in-arm note.) Carry-forward, NOT re-snapshot:
    /// a retry's seed status is live by construction, so a retry can never
    /// enter the terminal top-level arms — attempt 0 is the only
    /// fresh-snapshot dispatch and stays byte-identical for un-raced calls.
    /// A recheck that observes a TERMINAL status keeps today's behaviour
    /// verbatim (log, no mutation, `Ok`): a cancel racing a normal
    /// completion never flips a terminal run. On exhaustion the loss is
    /// surfaced as `InvalidState("cancel-run-raced")` instead of dropped;
    /// note an exhausted call may by then have closed up to
    /// [`CANCEL_RACE_RETRY_LIMIT`] then-current await sessions (one per
    /// Suspended attempt; the close-before-recheck ordering is pre-existing
    /// at attempt 0 — the loop multiplies it by the bound, and in a
    /// status-only flap a closed session can still be the one installed on
    /// the now-live row) — both flap shapes and their close counts are
    /// pinned by the cancel_toctou exhaustion witnesses.
    pub async fn cancel_run(&self, run_id: &RunId, reason: String) -> Result<(), RunError> {
        /// Write-lock recheck outcome, computed inside the critical section
        /// so the carried pair is exactly what the lock observed.
        enum CancelRecheck {
            Settled(advance_shared_types::event::Event),
            RacedTerminal,
            RacedLive(TaskRunStatus, Option<String>),
        }

        let reason = truncate_reason(reason);
        let (mut status_snapshot, mut root_await_snapshot) = {
            let store = self.store.read().unwrap();
            let run = store
                .get(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            (run.status.clone(), run.root_await.clone())
        };
        for _attempt in 0..CANCEL_RACE_RETRY_LIMIT {
            match status_snapshot.clone() {
                TaskRunStatus::Suspended => {
                    self.preflight_descendant_cascade_for_run(run_id)?;
                    let ar = self.await_session_ref.as_ref().ok_or_else(|| {
                        RunError::PermissionDenied("await-session-ref-not-configured".into())
                    })?;
                    if let Some(sid_str) = root_await_snapshot.as_deref() {
                        let sid = SessionId(sid_str.to_string());
                        if let Err(e) = ar.close(&sid, &reason).await {
                            eprintln!(
                                "cancel_run: AwaitSessionRef::close returned non-fatal error: {:?}",
                                e
                            );
                        }
                    } else {
                        eprintln!(
                            "cancel_run: Suspended Run {} has root_await=None — skipping close",
                            run_id
                        );
                    }
                    let outcome = {
                        let mut store = self.store.write().unwrap();
                        let run = store
                            .get_mut(run_id.as_ref())
                            .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
                        // Slice B TOCTOU recheck (same rationale as pause_run).
                        // Slice B adv-round-4: full double-recheck (status +
                        // root_await match) — same orphan-session concern as
                        // pause_run branch (a).
                        let status_matches = matches!(run.status, TaskRunStatus::Suspended);
                        let root_matches = run.root_await == root_await_snapshot;
                        if !status_matches || !root_matches {
                            if is_live_status(&run.status) {
                                // Audit round 1: every raced attempt logs its
                                // observed pair, so an exhausted cancel has a
                                // per-attempt trail to diagnose from.
                                eprintln!(
                                    "cancel_run: branch (a) raced — Run {} status={:?} root_await={:?} (snapshot expected Suspended + {:?}); retrying dispatch on the observed state",
                                    run_id, run.status, run.root_await, root_await_snapshot
                                );
                                CancelRecheck::RacedLive(run.status.clone(), run.root_await.clone())
                            } else {
                                eprintln!(
                                    "cancel_run: branch (a) raced to terminal — Run {} status={:?} (snapshot expected Suspended + root_await {:?}); cancel is moot",
                                    run_id, run.status, root_await_snapshot
                                );
                                CancelRecheck::RacedTerminal
                            }
                        } else {
                            run.status = TaskRunStatus::Cancelled(reason.clone());
                            run.root_await = None;
                            run.pause_pending = None;
                            run.cancel_pending = None;
                            run.budget.token_reserved = 0;
                            run.budget.cost_reserved = 0.0;
                            run.updated_at = Utc::now();
                            let task_id = run.task_id.clone();
                            let controller_agent = run.controller_agent.clone();
                            let run_id_str = run.id.0.clone();
                            store.drop_live_by_task(&task_id);
                            CancelRecheck::Settled(events::run_cancelled_event(
                                &run_id_str,
                                &task_id,
                                &controller_agent,
                                &reason,
                            ))
                        }
                    };
                    match outcome {
                        CancelRecheck::Settled(evt) => {
                            self.persist_snapshot_best_effort(run_id.as_ref());
                            self.event_bus.emit(evt);
                            self.cascade_descendants_for_run(run_id, &reason).await?;
                            return Ok(());
                        }
                        CancelRecheck::RacedTerminal => return Ok(()),
                        CancelRecheck::RacedLive(status, root_await) => {
                            status_snapshot = status;
                            root_await_snapshot = root_await;
                        }
                    }
                }
                TaskRunStatus::Paused => {
                    self.preflight_descendant_cascade_for_run(run_id)?;
                    let outcome = {
                        let mut store = self.store.write().unwrap();
                        let run = store
                            .get_mut(run_id.as_ref())
                            .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
                        // Slice B TOCTOU recheck — Paused branch. The raced
                        // leg additionally captures root_await so a
                        // carry-forward into the Suspended arm dispatches on
                        // the pair that arm's conjunction recheck will
                        // re-validate (without it, a Paused→Suspended race
                        // would exhaust instead of settling).
                        if !matches!(run.status, TaskRunStatus::Paused) {
                            if is_live_status(&run.status) {
                                eprintln!(
                                    "cancel_run: Paused branch raced — Run {} now status={:?} root_await={:?}; retrying dispatch on the observed state",
                                    run_id, run.status, run.root_await
                                );
                                CancelRecheck::RacedLive(run.status.clone(), run.root_await.clone())
                            } else {
                                eprintln!(
                                    "cancel_run: Paused branch raced to terminal — Run {} status={:?}; cancel is moot",
                                    run_id, run.status
                                );
                                CancelRecheck::RacedTerminal
                            }
                        } else {
                            run.status = TaskRunStatus::Cancelled(reason.clone());
                            run.pause_pending = None;
                            run.cancel_pending = None;
                            run.budget.token_reserved = 0;
                            run.budget.cost_reserved = 0.0;
                            run.updated_at = Utc::now();
                            let task_id = run.task_id.clone();
                            let controller_agent = run.controller_agent.clone();
                            let run_id_str = run.id.0.clone();
                            store.drop_live_by_task(&task_id);
                            CancelRecheck::Settled(events::run_cancelled_event(
                                &run_id_str,
                                &task_id,
                                &controller_agent,
                                &reason,
                            ))
                        }
                    };
                    match outcome {
                        CancelRecheck::Settled(evt) => {
                            self.persist_snapshot_best_effort(run_id.as_ref());
                            self.event_bus.emit(evt);
                            self.cascade_descendants_for_run(run_id, &reason).await?;
                            return Ok(());
                        }
                        CancelRecheck::RacedTerminal => return Ok(()),
                        CancelRecheck::RacedLive(status, root_await) => {
                            status_snapshot = status;
                            root_await_snapshot = root_await;
                        }
                    }
                }
                TaskRunStatus::Cancelled(_) => {
                    self.cascade_descendants_for_run(run_id, &reason).await?;
                    return Ok(());
                }
                TaskRunStatus::Active => {
                    let mut store = self.store.write().unwrap();
                    let run = store
                        .get_mut(run_id.as_ref())
                        .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
                    // Slice B TOCTOU recheck. Audit round 2: this leg exits
                    // the retry loop early with its own pre-existing error
                    // string (the error payload carries the observed status
                    // in-band); log the same diagnostic shape as the other
                    // raced legs so no raced outcome is silent. NOTE (audit
                    // rounds 3-4): this leg is structurally unreachable by
                    // the cancel_toctou tree-injection witnesses — the
                    // injector fires only inside tree.snapshot(), and this
                    // arm consults no tree between its dispatch snapshot and
                    // the write lock — so the log line is exercised only by
                    // production races: the enumerated-but-unwitnessed
                    // outcome the plan discloses.
                    if !matches!(run.status, TaskRunStatus::Active) {
                        eprintln!(
                            "cancel_run: Active branch raced — Run {} now status={:?} root_await={:?}; surfacing cancel-run-raced-from-active",
                            run_id, run.status, run.root_await
                        );
                        return Err(RunError::InvalidState(format!(
                            "cancel-run-raced-from-active: now {:?}",
                            run.status
                        )));
                    }
                    if let Some(existing) = &run.cancel_pending {
                        eprintln!(
                            "cancel_run: cancel_pending already set (existing reason={:?}); ignoring new reason={:?} for run_id={}",
                            existing, reason, run_id
                        );
                        return Ok(());
                    }
                    // Cancel SUPERSEDES pause: clear any pending pause.
                    run.pause_pending = None;
                    run.cancel_pending = Some(reason.clone());
                    run.updated_at = Utc::now();
                    drop(store);
                    self.persist_snapshot_best_effort(run_id.as_ref());
                    return Ok(());
                }
                other => return Err(RunError::InvalidState(format!("cancel-run-on-{:?}", other))),
            }
        }
        // Audit round 1: the exhaustion outcome is the one an operator most
        // needs to diagnose — say so in the log (the per-attempt observed
        // pairs were logged by the raced legs above).
        eprintln!(
            "cancel_run: Run {} still live after {} dispatch attempts; surfacing cancel-run-raced instead of dropping the cancel",
            run_id, CANCEL_RACE_RETRY_LIMIT
        );
        Err(RunError::InvalidState("cancel-run-raced".into()))
    }

    /// Forced, agent-keyed run cancel (Stage B2 — the SYS-AC-156 product half).
    /// Resolves the agent's single live run via [`AgentRunResolver::resolve`] and applies an
    /// IMMEDIATE `*→Cancelled` settle (forced, unlike [`Self::cancel_run`]'s cooperative
    /// branch-(b) which only arms `cancel_pending` on Active and leaves `status == Active`).
    ///
    /// SYNC by design (NOT async): the cascade adapter's `RunCascade::cancel_run`
    /// (cap-lifecycle) is a sync trait method, so a sync method here lets it call us directly —
    /// no `tokio::spawn`, no fire-and-forget — and observe `status != Active` the instant this
    /// returns. That synchronous post-state is exactly what the SYS-AC-156 criterion needs; an
    /// `async` signature would force the sync trait to `spawn` (re-introducing the race) or
    /// `block_on` (panic inside the runtime). The forced settle does no `.await`.
    ///
    /// - **0 live runs** → clean no-op `Ok(())`.
    /// - **exactly 1 live run** → force-settle it to `Cancelled(reason)` (mirrors the
    ///   Suspended/Paused settle in [`Self::cancel_run`], applied directly to Active): clears
    ///   `pause_pending`/`cancel_pending`, zeroes budget reservations, drops the `live_by_task`
    ///   reverse-index entry, emits `run.cancelled`. Idempotent: a run already terminal
    ///   (`Cancelled`/`Completed`/`Failed`) is a no-op `Ok`.
    /// - **>1 live runs (ambiguous)** → `Err(InvalidState("cancel-run-for-agent-ambiguous: ..."))`
    ///   — surfaced, NOT a silent no-op (mirrors `resolve`'s fail-honest ambiguity contract). In
    ///   the cascade contract 1 agent == 1 run, so this is not hit in production.
    ///
    /// Mode-blind (like `cancel_run`/`pause_run`): a forced admin terminate does not consult
    /// `RoundAdvancer`. Suspended residual: a `Suspended` run is still flipped synchronously,
    /// but its M007 await-session cannot be `.await`-closed from this sync method, so it is
    /// logged (same accepted surface as `resume_run` "manual"-from-Suspended); not reachable in
    /// the Active cascade case.
    pub fn cancel_run_for_agent(&self, agent_id: &str, reason: String) -> Result<(), RunError> {
        let reason = truncate_reason(reason);
        // Primary resolution: resolve() returns the single live run, or fail-honest
        // (None, None) for BOTH 0-live AND >1-live (ambiguous).
        let (run_id_opt, _task_id) = self.resolve(agent_id);
        let run_id = match run_id_opt {
            Some(run_id) => run_id,
            None => {
                // Disambiguate 0 (clean no-op) from >1 (surface, don't silently no-op) using
                // resolve()'s exact predicate (controller_agent match + live status).
                let live = {
                    let store = self.store.read().unwrap();
                    store
                        .iter()
                        .filter(|r| r.controller_agent == agent_id && is_live_status(&r.status))
                        .count()
                };
                if live == 0 {
                    return Ok(());
                }
                return Err(RunError::InvalidState(format!(
                    "cancel-run-for-agent-ambiguous: agent {agent_id:?} has {live} live runs; refusing forced cancel"
                )));
            }
        };

        let _ = self.force_cancel_run_by_id_sync(&run_id, &reason)?;
        Ok(())
    }

    fn force_cancel_run_by_id_sync(&self, run_id: &str, reason: &str) -> Result<bool, RunError> {
        // Forced immediate settle under a single store.write() critical section.
        let evt_opt = {
            let mut store = self.store.write().unwrap();
            let run = match store.get_mut(run_id) {
                Some(run) => run,
                None => return Ok(false), // raced away between scan and the write lock
            };
            // Idempotent: already terminal → nothing to force.
            if matches!(
                run.status,
                TaskRunStatus::Cancelled(_) | TaskRunStatus::Completed | TaskRunStatus::Failed(_)
            ) {
                return Ok(false);
            }
            // Suspended residual: a sync method cannot AwaitSessionRef::close(..).await; log the
            // possibly-orphaned M007 session (same accepted surface as resume_run "manual").
            if matches!(run.status, TaskRunStatus::Suspended) && run.root_await.is_some() {
                eprintln!(
                    "cancel_run_for_agent: forcing Suspended Run {} → Cancelled without awaiting \
                     M007 session close (root_await={:?}); session may be left live (same accepted \
                     surface as resume_run \"manual\")",
                    run_id, run.root_await
                );
            }
            run.status = TaskRunStatus::Cancelled(reason.to_string());
            run.root_await = None;
            run.pause_pending = None;
            run.cancel_pending = None;
            run.budget.token_reserved = 0;
            run.budget.cost_reserved = 0.0;
            run.updated_at = Utc::now();
            let task_id = run.task_id.clone();
            let controller_agent = run.controller_agent.clone();
            let run_id_str = run.id.0.clone();
            store.drop_live_by_task(&task_id);
            Some(events::run_cancelled_event(
                &run_id_str,
                &task_id,
                &controller_agent,
                reason,
            ))
        };
        if let Some(evt) = evt_opt {
            self.persist_snapshot_best_effort(run_id);
            self.event_bus.emit(evt);
            return Ok(true);
        }
        Ok(false)
    }

    /// Forced terminate-cascade helper: cancel every live run currently owned by
    /// `agent_id`, with bounded rescans so runs created during the cascade are
    /// picked up before the sync terminate adapter returns.
    pub fn cancel_all_runs_for_agent(
        &self,
        agent_id: &str,
        reason: String,
    ) -> Result<(), RunError> {
        self.block_run_creation_for_terminated_agent(agent_id);
        let reason = truncate_reason(reason);
        for _ in 0..=DESCENDANT_CASCADE_SCAN_LIMIT {
            let run_ids = self.live_run_ids_for_agent(agent_id);
            if run_ids.is_empty() {
                return Ok(());
            }
            for run_id in run_ids {
                let _ = self.force_cancel_run_by_id_sync(run_id.as_ref(), &reason)?;
            }
        }
        let live = self.live_run_ids_for_agent(agent_id).len();
        if live == 0 {
            return Ok(());
        }
        Err(RunError::InvalidState(format!(
            "cancel-all-runs-for-agent-raced: agent {agent_id:?} still has {live} live runs"
        )))
    }

    /// `resume_run` (MODULE-008 §1.3.3, Slice B). Dispatch:
    /// Paused → Active (admin "manual resume" path);
    /// Suspended → Active (M007 await-completion path).
    /// Reason whitelist enforced against `{await_complete, manual}` per
    /// PRD §15.3.4A line 5307.
    pub fn resume_run(&self, run_id: &RunId, reason: String) -> Result<(), RunError> {
        let reason = truncate_reason(reason);
        if !RESUME_REASONS.contains(&reason.as_str()) {
            return Err(RunError::PermissionDenied(format!(
                "invalid-resume-reason: {reason}"
            )));
        }
        let evt = {
            let mut store = self.store.write().unwrap();
            let run = store
                .get_mut(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            match run.status {
                TaskRunStatus::Paused => {
                    run.status = TaskRunStatus::Active;
                    run.pause_pending = None;
                    run.updated_at = Utc::now();
                }
                TaskRunStatus::Suspended => {
                    if reason == "manual" {
                        // Slice B adv-round-2 W2: "manual" resume from Suspended
                        // is an operator-override that bypasses M007's normal
                        // await-completion path. The agent's await-replies
                        // fiber may still be parked on the M007 session, and
                        // M008 has no async-fn surface here to call
                        // AwaitSessionRef::close. Log the orphaned-session
                        // surface for ops; production callers SHOULD use the
                        // pause_run(Suspended)+resume_run(Paused, "manual")
                        // chain to close the session cleanly.
                        eprintln!(
                            "resume_run: \"manual\" from Suspended on Run {} leaves M007 session (root_await={:?}) live; prefer pause_run+resume_run for clean shutdown",
                            run_id, run.root_await
                        );
                    }
                    run.status = TaskRunStatus::Active;
                    run.root_await = None;
                    run.updated_at = Utc::now();
                }
                ref other => {
                    return Err(RunError::InvalidState(format!("resume-run-on-{:?}", other)));
                }
            }
            events::run_resumed_event(
                run.id.0.as_str(),
                &run.task_id,
                &run.controller_agent,
                &reason,
            )
        };
        self.persist_snapshot_best_effort(run_id.as_ref());
        self.event_bus.emit(evt);
        Ok(())
    }

    /// `resume_run_if_suspended` (Backbone Step 4b, 2026-06-08) — the
    /// **atomic await-completion resume**. Transitions Suspended → Active (clears
    /// `root_await`, emits `run.resumed`) ONLY if the run is STILL `Suspended`,
    /// under a single `store.write()` critical section. Returns `Ok(true)` if it
    /// resumed, `Ok(false)` if the run had already left `Suspended` (a no-op).
    ///
    /// This is the await-replies driver's resume entry point. Unlike
    /// [`Self::resume_run`] (which ALSO accepts `Paused → Active`, the operator
    /// "manual resume" path), this method NEVER touches a non-Suspended run — so a
    /// child reply resolving `Ok` concurrently with an operator
    /// `pause_run`/`cancel_run` (branch-(a)) cannot clobber the operator's
    /// Paused/Cancelled transition back to Active (closing the resume-vs-pause
    /// race surfaced by the Step-4b diff audit). Reason is whitelisted to
    /// `await_complete` (the only valid await-completion reason).
    pub fn resume_run_if_suspended(
        &self,
        run_id: &RunId,
        reason: String,
    ) -> Result<bool, RunError> {
        let reason = truncate_reason(reason);
        if reason != "await_complete" {
            return Err(RunError::PermissionDenied(format!(
                "invalid-await-resume-reason: {reason}"
            )));
        }
        let evt = {
            let mut store = self.store.write().unwrap();
            let run = store
                .get_mut(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            // Atomic guard: only resume from Suspended. Any other status (Active /
            // Paused / Cancelled / Completed / Failed) → no-op (the operator
            // pause/cancel — or a prior resume — owns the current state).
            if !matches!(run.status, TaskRunStatus::Suspended) {
                return Ok(false);
            }
            run.status = TaskRunStatus::Active;
            run.root_await = None;
            run.updated_at = Utc::now();
            events::run_resumed_event(
                run.id.0.as_str(),
                &run.task_id,
                &run.controller_agent,
                &reason,
            )
        };
        self.persist_snapshot_best_effort(run_id.as_ref());
        self.event_bus.emit(evt);
        Ok(true)
    }

    /// `suspend_run` (MODULE-008 §1.3.3, Slice B). Active → Suspended,
    /// stores `root_await=Some(session_id)`. Validates `session_id`
    /// charset against `^[A-Za-z0-9_-]{1,64}$`.
    pub fn suspend_run(&self, run_id: &RunId, session_id: &str) -> Result<(), RunError> {
        validate_session_id(session_id)
            .map_err(|e| RunError::PermissionDenied(format!("invalid-session-id: {e}")))?;
        let evt = {
            let mut store = self.store.write().unwrap();
            let run = store
                .get_mut(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            if !matches!(run.status, TaskRunStatus::Active) {
                return Err(RunError::InvalidState(format!(
                    "suspend-run-on-{:?}",
                    run.status
                )));
            }
            run.status = TaskRunStatus::Suspended;
            run.root_await = Some(session_id.to_string());
            run.updated_at = Utc::now();
            events::run_suspended_event(
                run.id.0.as_str(),
                &run.task_id,
                &run.controller_agent,
                session_id,
            )
        };
        self.persist_snapshot_best_effort(run_id.as_ref());
        self.event_bus.emit(evt);
        Ok(())
    }

    /// Slice B convenience — construct a `RepetitionGuard` pre-wired with
    /// this manager's `EventBusEmit` AND `AgentRunResolver` impl (the
    /// manager itself), so the guard can emit `run.repetition_detected`
    /// events with `Event.run_id` populated via `agent_id → run_id`
    /// resolution. `with_context_assembler` / `with_prompt_injection_helpers`
    /// can be added afterwards by the caller via further builder calls.
    pub fn build_repetition_guard(
        self: &Arc<Self>,
        window_size: usize,
        repeat_threshold: usize,
        action: RepetitionAction,
    ) -> RepetitionGuard {
        RepetitionGuard::new(window_size, repeat_threshold, action)
            .with_event_bus(Arc::clone(&self.event_bus))
            .with_run_resolver(Arc::clone(self) as Arc<dyn AgentRunResolver>)
    }

    /// Read-only snapshot of every run in the store (owned `Run` clones). Additive production
    /// read accessor backing the MODULE-020 client-api `GET /client/runs` projection (m020-s2),
    /// over the existing `pub(crate)` `store.iter()`. Ordering follows the store's internal map
    /// iteration (non-deterministic); any ordering/pagination/filtering is the client-api layer's
    /// concern (the HTTP transport applies the cursor/limit/status query parameters — Wave-25).
    /// This adds no CONTRACT-070 `agent-run` WIT method and no CONTRACT-071 `RunStateSync` change —
    /// it is a host-side Rust accessor only (`modified_contracts: []`).
    pub fn list_runs(&self) -> Vec<Run> {
        let store = self.store.read().unwrap();
        store.iter().cloned().collect()
    }

    /// Test-setup helper — install arbitrary `TaskRunStatus` on a run row.
    /// Compiled only when the `__test-util` feature is enabled (Cargo
    /// feature-gating closes the production-callable trust-boundary
    /// surfaced by the adversarial review). Integration tests under
    /// `crates/run-manager/tests/` enable the feature via the crate's own
    /// `dev-dependencies` entry (see `Cargo.toml`); production consumers
    /// of `advance-run-manager` never compile this method.
    ///
    /// Contract:
    /// - Live target statuses (Active / Suspended / Paused): preserve (or
    ///   create) the `live_by_task` reverse-index entry.
    /// - Terminal target statuses (Completed / Failed / Cancelled): remove
    ///   the `live_by_task` reverse-index entry.
    #[cfg(feature = "__test-util")]
    pub fn with_status_for_test(
        &self,
        run_id: &RunId,
        status: TaskRunStatus,
    ) -> Result<(), RunError> {
        let mut store = self.store.write().unwrap();
        let live = is_live_status(&status);
        let (task_id, id_str) = {
            let run = store
                .get_mut(run_id.as_ref())
                .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
            run.status = status;
            run.updated_at = Utc::now();
            // Match the production-path terminal-transition contract: drain
            // outstanding budget reservations when installing a terminal
            // status. Without this, tests that flip Active → Failed/Cancelled
            // via with_status_for_test silently bypass the reservation-drain
            // logic in complete_run/fail_run, hiding regressions in that
            // contract. (Closes adversarial round-2 Warning #4.)
            if !live {
                run.budget.token_reserved = 0;
                run.budget.cost_reserved = 0.0;
            }
            (run.task_id.clone(), run.id.0.clone())
        };
        if live {
            store.ensure_live(&task_id, run_id);
        } else {
            store.drop_live_by_run(&id_str);
        }
        Ok(())
    }

    /// Test-helper accessor for the per-run `BudgetState` snapshot.
    /// Gated by `__test-util`; read-only but feature-gated for surface
    /// minimization.
    #[cfg(feature = "__test-util")]
    pub fn budget_state_snapshot(&self, run_id: &RunId) -> Option<BudgetState> {
        let store = self.store.read().unwrap();
        store.get(run_id.as_ref()).map(|r| r.budget.clone())
    }

    /// Test-helper accessor for a Run snapshot (deep clone).
    #[cfg(feature = "__test-util")]
    pub fn snapshot_run_for_test(&self, run_id: &RunId) -> Option<Run> {
        let store = self.store.read().unwrap();
        store.get(run_id.as_ref()).cloned()
    }

    /// Test-helper: current TaskRunStatus snapshot.
    #[cfg(feature = "__test-util")]
    pub fn snapshot_status_for_test(&self, run_id: &RunId) -> Option<TaskRunStatus> {
        self.snapshot_run_for_test(run_id).map(|r| r.status)
    }

    /// Test-helper: number of runs in the store.
    #[cfg(feature = "__test-util")]
    pub fn store_len_for_test(&self) -> usize {
        let store = self.store.read().unwrap();
        store.runs_len()
    }

    /// Test-helper (Slice B): snapshot `pause_pending` field of a run.
    /// Returns `None` if the run doesn't exist, else `Some(pause_pending_value)`.
    #[cfg(feature = "__test-util")]
    pub fn snapshot_pause_pending_for_test(&self, run_id: &RunId) -> Option<Option<String>> {
        let store = self.store.read().unwrap();
        store.get(run_id.as_ref()).map(|r| r.pause_pending.clone())
    }

    /// Test-helper (Slice B): snapshot `cancel_pending` field of a run.
    #[cfg(feature = "__test-util")]
    pub fn snapshot_cancel_pending_for_test(&self, run_id: &RunId) -> Option<Option<String>> {
        let store = self.store.read().unwrap();
        store.get(run_id.as_ref()).map(|r| r.cancel_pending.clone())
    }

    /// Test-helper (Slice B): directly install `root_await` on a run row
    /// (does NOT validate charset — recovery tests deliberately install
    /// invalid values to exercise the validation-at-recovery path).
    #[cfg(feature = "__test-util")]
    pub fn with_root_await_for_test(
        &self,
        run_id: &RunId,
        root_await: Option<String>,
    ) -> Result<(), RunError> {
        let mut store = self.store.write().unwrap();
        let run = store
            .get_mut(run_id.as_ref())
            .ok_or_else(|| RunError::NotFound(run_id.to_string()))?;
        run.root_await = root_await;
        run.updated_at = Utc::now();
        Ok(())
    }
}

/// Slice B blanket impl: `RunManager` itself implements `AgentRunResolver`
/// (the M008-internal trait declared in `repetition_guard.rs`). The
/// resolver walks the store for live Runs whose `controller_agent ==
/// agent_id`. Fail-honest under ambiguity (multiple matches → `(None,
/// None)`). Lock-order invariant: callers MUST NOT hold any other
/// RunManager-side lock when invoking `resolve` (it acquires
/// `store.read()`; the documented call site
/// `RepetitionGuard::decide_locked` holds `per_agent.write()` only).
impl AgentRunResolver for RunManager {
    fn resolve(&self, agent_id: &str) -> (Option<String>, Option<String>) {
        let store = self.store.read().unwrap();
        let mut matches: Vec<(String, String)> = Vec::new();
        for run in store.iter() {
            if run.controller_agent == agent_id && is_live_status(&run.status) {
                matches.push((run.id.as_ref().to_string(), run.task_id.clone()));
            }
        }
        match matches.len() {
            0 => (None, None),
            1 => {
                let (rid, tid) = matches.into_iter().next().unwrap();
                (Some(rid), Some(tid))
            }
            n => {
                eprintln!(
                    "AgentRunResolver: agent_id={:?} ambiguous ({} live runs); run_id omitted",
                    agent_id, n
                );
                (None, None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T21 — exhaustive `match` on TaskRunStatus covers all 6 variants
    /// (compile-time check; no `_` wildcard).
    #[test]
    fn task_run_status_six_variant_exhaustive_match() {
        fn classify(s: &TaskRunStatus) -> &'static str {
            match s {
                TaskRunStatus::Active => "active",
                TaskRunStatus::Suspended => "suspended",
                TaskRunStatus::Paused => "paused",
                TaskRunStatus::Completed => "completed",
                TaskRunStatus::Failed(_) => "failed",
                TaskRunStatus::Cancelled(_) => "cancelled",
            }
        }
        assert_eq!(classify(&TaskRunStatus::Active), "active");
        assert_eq!(classify(&TaskRunStatus::Suspended), "suspended");
        assert_eq!(classify(&TaskRunStatus::Paused), "paused");
        assert_eq!(classify(&TaskRunStatus::Completed), "completed");
        assert_eq!(classify(&TaskRunStatus::Failed("x".into())), "failed");
        assert_eq!(classify(&TaskRunStatus::Cancelled("x".into())), "cancelled");
    }
}
