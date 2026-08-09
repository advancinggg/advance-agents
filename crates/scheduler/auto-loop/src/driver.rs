//! CONTRACT-140 `AutoLoopDriver` trait + slice-A/B `DefaultAutoLoopDriver`.
//!
//! Slice A shipped a structural skeleton: `on_tick` / `on_component_event`
//! record-only, `start`/`stop`/`status` lifecycle, inherent
//! `checkpoint_iteration`/`checkpoint_baseline`/`rollback_iteration`
//! methods. Slice B extends the driver via a **builder pattern**: the
//! slice-A `new(checkpoint, rollback)` signature is preserved verbatim, and
//! optional dependencies (evaluator resolver, cost tracker, fail-fast
//! monitor, results writer) attach via additive `with_*` methods. New
//! inherent methods (`transition_status`, `record_complete_cycle_request`,
//! `handle_manual_cancel`, `check_per_iteration_budget`,
//! `auto_namespace_task_id`, `evaluator_id_for`) wire the slice-B primitives
//! into a per-agent surface the future integrated §4.7.7 loop can call.
//!
//! `on_tick` / `on_component_event` remain record-only this slice — the
//! integrated iteration loop (checkpoint → evaluate → keep/discard →
//! rollback → results-write → round-advance) is deferred.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use advance_scheduler::{ComponentEvent, SchedulerExtension, SchedulerTick};
use advance_shared_types::run::{MetricSample, RoundDecision};
use advance_shared_types::traits::CostTrackerQuery;
use async_trait::async_trait;

use crate::auto_bootstrap::{
    report_to_event_payloads, AutoBootstrapApplier, AutoBootstrapApplierError,
    AutoBootstrapCoordinationError, AutoBootstrapEventSink, MAX_BOOTSTRAP_ENTRIES,
};
use crate::budget::{check_budget, BudgetStatus};
use crate::checkpoint::IterationCheckpoint;
use crate::config::{AutoLoopConfig, Op, Role, SuccessCriteria};
use crate::error::{AutoError, AutoLoopError};
use crate::evaluator::EvaluatorResolver;
use crate::event_sink::{
    AutoIterationEventPayload, AutoIterationEventSink, DegradeReason, HaltReason, NotifySink,
};
use crate::fail_fast::{FailFastMetric, FailFastMonitor, FailFastOutcome};
use crate::results::{IterationResult, IterationStatus, ResultsWriter};
use crate::rollback::IterationRollback;
use crate::round_advancer::AutoStateReader;
use crate::skill_tracker::SkillRollback;
use crate::state::{AutoState, AutoStatus, Transition};
use advance_shared_types::capability::BudgetDecision;

/// CONTRACT-140 (MODULE-015 §2.3): the auto-loop driver trait. Supertrait
/// `SchedulerExtension` (CONTRACT-133) so it plugs into MODULE-014's
/// scheduler. Signature verbatim from §2.3.
#[async_trait]
pub trait AutoLoopDriver: SchedulerExtension {
    async fn start(&self, agent_id: &str, config: AutoLoopConfig) -> Result<(), AutoError>;
    async fn stop(&self, agent_id: &str) -> Result<(), AutoError>;
    async fn status(&self, agent_id: &str) -> Option<AutoStatus>;
}

/// PRD §4.7.3 `completion-summary` record. Local Rust mirror of the WIT
/// shape — the integrated-loop slice may hoist this to shared-types when
/// the M008 RoundAdvancer integration lands. Slice B uses the canonical
/// `advance_shared_types::run::MetricSample` for `final_metrics` so no
/// translation is needed at the wiring boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct CompletionSummary {
    pub outcome: String,
    pub final_metrics: Vec<MetricSample>,
}

/// Outcome of one iteration's close (`run.round_completed { decision }`
/// equivalent). Completed/Cancelled are terminal; Continue is the normal
/// keep/discard/crash arm. All `decision` fields use the canonical
/// `advance_shared_types::run::RoundDecision` so the integrated-loop slice
/// can forward directly to MODULE-008's RoundAdvancer without translation.
#[derive(Clone, Debug, PartialEq)]
pub enum IterationOutcome {
    Completed {
        summary: String,
        decision: RoundDecision,
    },
    Cancelled {
        reason: String,
        decision: RoundDecision,
    },
    Continue {
        status: IterationStatus,
        decision: RoundDecision,
    },
}

/// Stage-D input to [`DefaultAutoLoopDriver::close_iteration`]. The evaluated
/// primary/guardrail readings are passed IN (the driver has no
/// workspace/metric-reader handle); the SUT/harvest binding that reads the
/// configured `metric_source` after the evaluator finishes is a separate
/// install point (MODULE-015 §2.7 / §3.6). All caller-supplied free text
/// (`crash_reason` / `summary`) should be pre-sanitized + length-bounded by the
/// caller (reuse `round_advancer::sanitize_for_audit` for agent-emitted text).
#[derive(Clone, Debug, PartialEq)]
pub struct IterationCloseCtx {
    pub agent_id: String,
    pub run_id: Option<String>,
    pub iteration: u32,
    /// On-disk checkpoint label for the results row (e.g. `auto-iter-{n}`).
    pub checkpoint_label: String,
    /// Observed primary-objective metric reading (`None` if unavailable — a
    /// non-crash close with no primary reading is treated as a discard).
    pub primary_metric: Option<f64>,
    /// All metric readings to record in the `results.jsonl` row.
    pub metrics: BTreeMap<String, f64>,
    /// `true` if a guardrail failed OR the iteration crashed / timed-out /
    /// hit fail-fast — forces the crash arm (rollback, no previous_best update).
    pub crashed: bool,
    /// Optional crash reason (pre-sanitized) for the `auto.iteration_crashed`
    /// event.
    pub crash_reason: Option<String>,
    /// Optional summary (pre-sanitized) for the results row.
    pub summary: Option<String>,
    pub cost_usd: f64,
    pub wall_time_sec: u64,
}

/// The primary objective's comparison operator, if a `role: primary` objective
/// exists in the criteria.
fn primary_op(criteria: &SuccessCriteria) -> Option<Op> {
    criteria
        .objectives
        .iter()
        .find(|o| o.role == Role::Primary)
        .map(|o| o.predicate.op)
}

/// Whether `new` is an improvement over `prev` under the primary predicate's
/// direction. First iteration (`prev` is `None`) → always an improvement (it
/// becomes the baseline). A non-finite `new` is never an improvement. `None`
/// op (no primary objective — should not happen post-validation) → not an
/// improvement (conservative discard).
fn primary_is_improvement(op: Option<Op>, new: f64, prev: Option<f64>) -> bool {
    let Some(prev) = prev else {
        return new.is_finite();
    };
    if !new.is_finite() {
        return false;
    }
    match op {
        Some(Op::Lt) => new < prev,
        Some(Op::Le) => new <= prev,
        Some(Op::Gt) => new > prev,
        Some(Op::Ge) => new >= prev,
        // Adversarial-r10 I8: RELATIVE tolerance (matching fail_fast's Op::Eq) —
        // an absolute `f64::EPSILON` made "Eq improvement" effectively
        // exact-equality, so any metric magnitude ≫ 1 could never keep past the
        // baseline (a silent always-discard dead-end for `op: eq` primaries).
        Some(Op::Eq) => {
            let scale = new.abs().max(prev.abs()).max(1.0);
            (new - prev).abs() <= crate::fail_fast::EQ_RELATIVE_TOLERANCE * scale
        }
        None => false,
    }
}

/// Stage-D crate-internal bridge to MODULE-008's `RunBudget` for the
/// `AutoStateReader::budget_decision` query. The cli provides a concrete impl
/// wrapping the M008 surface (harvest install point); when absent, the driver's
/// `AutoStateReader` impl derives a fail-CLOSED decision from safety-valve
/// state. Mirrors the dependency-inversion pattern used for the other M015
/// seams.
pub trait RunBudgetSource: Send + Sync {
    /// Mirror of [`AutoStateReader::budget_decision`] — the real M008 budget
    /// gate. `Deny(reason)` → the advancer emits `Blocked(reason)`.
    fn budget_decision(&self, run_id: &str, agent_id: &str) -> BudgetDecision;
}

/// Slice-A/B concrete provider of CONTRACT-140 + CONTRACT-133.
///
/// Slice-A constructor `new(checkpoint, rollback)` preserved VERBATIM
/// (slice-A test fixtures call this with positional args). Slice-B
/// dependencies attach via additive `with_*` builders — all `Option<...>`
/// and `None`-by-default, so the slice-A behaviour is unchanged unless a
/// builder explicitly opts in.
pub struct DefaultAutoLoopDriver {
    name: String,
    #[allow(dead_code)] // exercised by inherent checkpoint_* methods (AC-10) + slice B loop
    checkpoint: Arc<dyn IterationCheckpoint>,
    #[allow(dead_code)] // exercised by inherent rollback_iteration (AC-11) + slice B loop
    rollback: Arc<dyn IterationRollback>,
    state: Mutex<HashMap<String, AutoState>>,
    tick_count: AtomicU64,
    event_count: AtomicU64,
    // Slice B builders — all None-by-default, opt-in via with_* methods.
    evaluator_resolver: Option<Arc<dyn EvaluatorResolver>>,
    cost_tracker: Option<Arc<dyn CostTrackerQuery>>,
    fail_fast_monitor: Option<Arc<dyn FailFastMonitor>>,
    results_writer: Option<Arc<ResultsWriter>>,
    // Slice D builders (AC-22 coordination surface) — None-by-default.
    auto_bootstrap_applier: Option<Arc<dyn AutoBootstrapApplier>>,
    auto_bootstrap_event_sink: Option<Arc<dyn AutoBootstrapEventSink>>,
    // Stage-D integrated-loop seams — all None/empty-by-default (additive).
    iteration_event_sink: Option<Arc<dyn AutoIterationEventSink>>,
    notify_sink: Option<Arc<dyn NotifySink>>,
    /// Real (restoring) skill-rollback. NEVER a fail-open Noop/recording in
    /// production: `close_iteration`'s discard arm fails-CLOSED when skill
    /// restoration is needed but this is unset (a recording double is used
    /// only in tests). See MODULE-015 §3.6 / §3.8 note 10.
    ///
    /// Wave-18 Lane 2: a `OnceLock` (was `Option`) so the cli composition can
    /// LATE-BIND the production `SkillPersistenceRollbackBridge` via
    /// `set_skill_rollback(&self, ..)` AFTER the driver Arc is built — the
    /// skills coordinator (whose Arc the bridge wraps) is constructed after
    /// `build_auto_loop_driver`. First-set-wins; unset preserves the
    /// fail-closed `SkillRollbackUnwired` behavior byte-equivalently.
    skill_rollback: OnceLock<Arc<dyn SkillRollback>>,
    /// Optional bridge to MODULE-008's `RunBudget` for `budget_decision`. When
    /// absent, the `AutoStateReader::budget_decision` impl derives a
    /// fail-CLOSED decision from safety-valve state.
    run_budget_source: Option<Arc<dyn RunBudgetSource>>,
    /// `run_id → agent_id` (populated by `register_run` from the cli Auto-mode
    /// start path; read by `AutoStateReader::agent_id_for_run`).
    run_agent_map: Mutex<HashMap<String, String>>,
    /// `component_id → agent_id` (populated by `register_component`; read by
    /// `on_component_event` to resolve the owning session).
    component_agent_map: Mutex<HashMap<String, String>>,
    /// Per-agent skill-pre-state trackers (drained on discard/crash via
    /// `apply_discard`; cleared on keep).
    skill_trackers: Mutex<HashMap<String, crate::skill_tracker::SkillTracker>>,
}

impl DefaultAutoLoopDriver {
    /// Slice-A constructor, signature unchanged. New slice-B fields are
    /// initialized to None; opt-in via builder methods.
    pub fn new(
        checkpoint: Arc<dyn IterationCheckpoint>,
        rollback: Arc<dyn IterationRollback>,
    ) -> Self {
        Self {
            name: "auto-loop".to_string(),
            checkpoint,
            rollback,
            state: Mutex::new(HashMap::new()),
            tick_count: AtomicU64::new(0),
            event_count: AtomicU64::new(0),
            evaluator_resolver: None,
            cost_tracker: None,
            fail_fast_monitor: None,
            results_writer: None,
            auto_bootstrap_applier: None,
            auto_bootstrap_event_sink: None,
            iteration_event_sink: None,
            notify_sink: None,
            skill_rollback: OnceLock::new(),
            run_budget_source: None,
            run_agent_map: Mutex::new(HashMap::new()),
            component_agent_map: Mutex::new(HashMap::new()),
            skill_trackers: Mutex::new(HashMap::new()),
        }
    }

    /// Slice-B builder: attach an evaluator resolver (foundation for AC-08/-09).
    /// The slice-B `handle_manual_cancel` test (`tests/state_machine.rs (o)`)
    /// attaches a `RecordingEvaluatorResolver` to verify the AC-19 invariant
    /// that the manual-cancel path never invokes the resolver.
    pub fn with_evaluator_resolver(mut self, r: Arc<dyn EvaluatorResolver>) -> Self {
        self.evaluator_resolver = Some(r);
        self
    }

    /// Slice-B builder: attach a cost tracker (canonical CONTRACT-181).
    /// Drives `check_per_iteration_budget` foundation for AC-13/AC-23.
    pub fn with_cost_tracker(mut self, c: Arc<dyn CostTrackerQuery>) -> Self {
        self.cost_tracker = Some(c);
        self
    }

    /// Slice-B builder: attach a fail-fast monitor (foundation for AC-14).
    pub fn with_fail_fast_monitor(mut self, f: Arc<dyn FailFastMonitor>) -> Self {
        self.fail_fast_monitor = Some(f);
        self
    }

    /// Slice-B builder: attach a results.jsonl writer (foundation for AC-15).
    pub fn with_results_writer(mut self, w: Arc<ResultsWriter>) -> Self {
        self.results_writer = Some(w);
        self
    }

    /// Slice-D builder: attach an auto-bootstrap applier (AC-22 — M005-bound
    /// in production, abstracted via the [`AutoBootstrapApplier`] trait).
    pub fn with_auto_bootstrap_applier(mut self, a: Arc<dyn AutoBootstrapApplier>) -> Self {
        self.auto_bootstrap_applier = Some(a);
        self
    }

    /// Slice-D builder: attach an auto-bootstrap event sink (AC-22 — M019-bound
    /// in production, abstracted via the [`AutoBootstrapEventSink`] trait).
    pub fn with_auto_bootstrap_event_sink(mut self, s: Arc<dyn AutoBootstrapEventSink>) -> Self {
        self.auto_bootstrap_event_sink = Some(s);
        self
    }

    // ─── Stage-D integrated-loop builders + seams ─────────────────────────

    /// Stage-D builder: attach the 7-event `auto.*` lifecycle sink (M019-bound
    /// in production via a cli adapter; abstract here).
    pub fn with_iteration_event_sink(mut self, s: Arc<dyn AutoIterationEventSink>) -> Self {
        self.iteration_event_sink = Some(s);
        self
    }

    /// Stage-D builder: attach the degrade/halt notify sink (event-agnostic;
    /// cli binds it to cap-channel egress / dispatcher).
    pub fn with_notify_sink(mut self, s: Arc<dyn NotifySink>) -> Self {
        self.notify_sink = Some(s);
        self
    }

    /// Stage-D builder: attach a REAL (restoring) skill-rollback (the m017-e
    /// cap-skills impl). NEVER pass a fail-open Noop/recording impl in
    /// production — `close_iteration` fails-CLOSED without one when skill
    /// restoration is needed. First-set-wins (`OnceLock`); a second call is a
    /// no-op (no current caller sets it twice).
    pub fn with_skill_rollback(self, r: Arc<dyn SkillRollback>) -> Self {
        let _ = self.skill_rollback.set(r);
        self
    }

    /// Wave-18 Lane 2 LATE-BIND: attach the production `SkillRollback` to an
    /// already-constructed (and `Arc`-shared) driver. Used by the cli
    /// `wire_capabilities` skills arm, which builds the
    /// `SkillPersistenceRollbackBridge` only AFTER `build_auto_loop_driver`
    /// returns (the bridge wraps the skills coordinator built later in the
    /// wiring sequence). First-set-wins; a redundant set is ignored.
    pub fn set_skill_rollback(&self, r: Arc<dyn SkillRollback>) {
        let _ = self.skill_rollback.set(r);
    }

    /// Stage-D builder: attach a `RunBudget` source for `budget_decision`
    /// (the cli's MODULE-008 bridge). Absent → fail-CLOSED safety-valve
    /// derivation.
    pub fn with_run_budget_source(mut self, s: Arc<dyn RunBudgetSource>) -> Self {
        self.run_budget_source = Some(s);
        self
    }

    /// Register the `run_id → agent_id` mapping for an auto Run (called from
    /// the cli Auto-mode start path after `RunManager` mints the Run). The
    /// `AutoLoopRoundAdvancer` resolves the agent via this map. Adversarial-r10
    /// W1: fail-CLOSED with [`AutoLoopError::AtCapacity`] at the
    /// [`MAX_AUTO_ID_MAPPINGS`] ceiling (re-registering an existing `run_id`
    /// updates in place and never trips the cap).
    pub fn register_run(&self, run_id: &str, agent_id: &str) -> Result<(), AutoLoopError> {
        let mut guard = self
            .run_agent_map
            .lock()
            .expect("auto-loop run_agent_map mutex poisoned in register_run");
        if !guard.contains_key(run_id) && guard.len() >= MAX_AUTO_ID_MAPPINGS {
            return Err(AutoLoopError::AtCapacity(
                "run-mappings",
                MAX_AUTO_ID_MAPPINGS,
            ));
        }
        guard.insert(run_id.to_string(), agent_id.to_string());
        Ok(())
    }

    /// Register the `component_id → agent_id` mapping for an iteration's
    /// evaluator/agent component, so `on_component_event` (and the harvest's
    /// Finished→read-metric→close binding) can resolve the owning session.
    /// Adversarial-r10 W1: fail-CLOSED at the [`MAX_AUTO_ID_MAPPINGS`] ceiling.
    pub fn register_component(
        &self,
        component_id: &str,
        agent_id: &str,
    ) -> Result<(), AutoLoopError> {
        let mut guard = self
            .component_agent_map
            .lock()
            .expect("auto-loop component_agent_map mutex poisoned in register_component");
        if !guard.contains_key(component_id) && guard.len() >= MAX_AUTO_ID_MAPPINGS {
            return Err(AutoLoopError::AtCapacity(
                "component-mappings",
                MAX_AUTO_ID_MAPPINGS,
            ));
        }
        guard.insert(component_id.to_string(), agent_id.to_string());
        Ok(())
    }

    /// Resolve a `component_id` to its owning auto-session `agent_id`
    /// (registered via [`Self::register_component`]). The harvest's
    /// Finished→read-metric→close binding uses this to route a finished
    /// evaluator component back to its session; `on_component_event` uses it to
    /// resolve the session for a `ComponentEvent::Failed` crash signal.
    pub fn agent_for_component(&self, component_id: &str) -> Option<String> {
        self.component_agent_map
            .lock()
            .expect("auto-loop component_agent_map mutex poisoned in agent_for_component")
            .get(component_id)
            .cloned()
    }

    /// Record a skill pre-activation snapshot for the current iteration (the
    /// SUT/harvest cap-skills bridge calls this when a skill activates). On
    /// discard/crash `close_iteration` restores via these; on keep it clears.
    pub fn record_skill_pre_activation(
        &self,
        agent_id: &str,
        skill_id: &str,
        prev_version: Option<u32>,
    ) {
        // Adversarial-r11 W1': gate on session-existence. A skill activates
        // DURING a live session's iteration, so a pre-state for a non-session is
        // meaningless — and recording one unconditionally is the 4th map (the
        // W1 cap missed) that an attacker-influenced caller could grow without
        // bound via synthesized agent_ids. Gating here caps `skill_trackers`
        // cardinality at the live-session count (itself capped at
        // MAX_AUTO_SESSIONS), so no separate map cap is needed. No-op (like the
        // close paths) when the agent has no live session.
        {
            let state = self
                .state
                .lock()
                .expect("auto-loop state mutex poisoned in record_skill_pre_activation (gate)");
            if !state.contains_key(agent_id) {
                return;
            }
        }
        let mut guard = self
            .skill_trackers
            .lock()
            .expect("auto-loop skill_trackers mutex poisoned in record_skill_pre_activation");
        guard
            .entry(agent_id.to_string())
            .or_default()
            .record_pre_activation(skill_id, prev_version);
    }

    /// Dedicated LLM-error ingress (Stage-D, AC-24 part b). Increments the
    /// agent's `consecutive_llm_errors`. The SUT/harvest cap-llm bridge calls
    /// this on each observed `llm.error` event — this is NOT inferred from
    /// `ComponentEvent::Failed` (a component crash, not an llm error). Returns
    /// the new streak count (`0` if the agent has no live session).
    pub fn record_llm_error(&self, agent_id: &str) -> u32 {
        let mut guard = self
            .state
            .lock()
            .expect("auto-loop state mutex poisoned in record_llm_error");
        match guard.get_mut(agent_id) {
            Some(s) => {
                s.consecutive_llm_errors = s.consecutive_llm_errors.saturating_add(1);
                s.consecutive_llm_errors
            }
            None => 0,
        }
    }

    /// Dedicated progress / llm-recovery ingress (Stage-D, AC-24 part c).
    /// Resets `consecutive_llm_errors` to 0 (LLM recovered) and, when the
    /// session is Degraded, transitions back to Active (clearing the cadence
    /// throttle). Returns the resulting status (`None` if no live session).
    pub fn record_progress(&self, agent_id: &str) -> Option<AutoStatus> {
        let mut guard = self
            .state
            .lock()
            .expect("auto-loop state mutex poisoned in record_progress");
        let s = guard.get_mut(agent_id)?;
        s.consecutive_llm_errors = 0;
        s.consecutive_no_progress = 0;
        if s.status == AutoStatus::Degraded {
            // Degraded → Active via ProgressDetected; clear the throttle.
            if let Ok(next) = s.status.transition(Transition::ProgressDetected) {
                s.status = next;
                s.degraded_backoff_until_ms = None;
                s.cadence_skip = 0;
            }
        }
        Some(s.status)
    }

    /// Stage-D §4.7.7 iteration start: checkpoint the iteration, reset the
    /// per-iteration wall-time budget anchor, and emit `auto.iteration_started`.
    pub async fn iteration_start(
        &self,
        agent_id: &str,
        run_id: Option<String>,
        iteration: u32,
    ) -> Result<(), AutoLoopError> {
        // Adversarial-r10 I6: verify the session exists AND is actively
        // iterating BEFORE creating the on-disk git checkpoint / emitting the
        // Started event — so a call for an unknown / terminal agent_id cannot
        // create a checkpoint tag or spurious lifecycle event for a non-session.
        {
            let guard = self
                .state
                .lock()
                .expect("auto-loop state mutex poisoned in iteration_start (check)");
            match guard.get(agent_id) {
                None => return Err(AutoLoopError::NotStarted(agent_id.to_string())),
                Some(st) if !matches!(st.status, AutoStatus::Active | AutoStatus::Degraded) => {
                    return Err(AutoLoopError::NotIterating(agent_id.to_string(), st.status));
                }
                Some(_) => {}
            }
        }
        self.checkpoint
            .checkpoint_iteration(agent_id, iteration)
            .await?;
        {
            let mut guard = self
                .state
                .lock()
                .expect("auto-loop state mutex poisoned in iteration_start");
            if let Some(st) = guard.get_mut(agent_id) {
                st.per_iter_budget_start = Instant::now();
            }
        }
        if let Some(sink) = self.iteration_event_sink.as_ref() {
            let _ = sink
                .emit(AutoIterationEventPayload::Started {
                    agent_id: agent_id.to_string(),
                    run_id,
                    iteration,
                })
                .await;
        }
        Ok(())
    }

    /// Stage-D §4.7.7 iteration-close orchestrator. Composes the ready
    /// primitives: decide keep/discard/crash (compare the supplied primary
    /// reading against `AutoState.previous_best`; honor the crash flag) →
    /// rollback on discard/crash → skill `apply_discard` (fail-CLOSED) →
    /// `ResultsWriter.append` → emit `auto.iteration_{kept,discarded,crashed}`
    /// + `auto.iteration_completed` → update `previous_best` / accumulators +
    /// record `last_iteration_status`.
    ///
    /// **Std-Mutex discipline**: the decision (phase 1) + write-back (phase 3)
    /// are short sync critical sections; ALL `.await` side effects (phase 2:
    /// rollback / skill apply_discard / results append / sink emit) happen with
    /// the state lock RELEASED — never held across an `.await`.
    pub async fn close_iteration(
        &self,
        ctx: IterationCloseCtx,
    ) -> Result<IterationOutcome, AutoLoopError> {
        // Audit-r7 W4 fix: sanitize + length-bound the caller-supplied free text
        // HERE (defense-in-depth), not relying on the caller's pre-sanitization.
        // `crash_reason` flows into the `auto.iteration_crashed` event; `summary`
        // is persisted to results.jsonl. Strip control / bidi-override chars
        // (reusing the round-advancer audit sanitizer) and cap the length so a
        // hostile/buggy close caller cannot inject log-lines or write unbounded
        // payloads into the event bus / results file.
        let ctx = IterationCloseCtx {
            crash_reason: ctx.crash_reason.map(|r| {
                truncate_at_char_boundary(
                    &crate::round_advancer::sanitize_for_audit(&r),
                    MAX_DECISION_REASON_BYTES,
                )
            }),
            summary: ctx.summary.map(|s| {
                truncate_at_char_boundary(
                    &crate::round_advancer::sanitize_for_audit(&s),
                    MAX_RESULTS_SUMMARY_BYTES,
                )
            }),
            ..ctx
        };
        // ── Phase 1: decide under the state lock (sync) + claim the
        //    single-writer close-in-progress flag (adversarial-r11 W2'). ──────
        let new_best: Option<f64>;
        let status: IterationStatus = {
            let mut guard = self
                .state
                .lock()
                .expect("auto-loop state mutex poisoned in close_iteration (decide)");
            let Some(st) = guard.get_mut(&ctx.agent_id) else {
                return Err(AutoLoopError::NotStarted(ctx.agent_id.clone()));
            };
            // Adversarial-r10 W2: terminal-state guard. Only an ACTIVELY-iterating
            // session (Active/Degraded) may close an iteration. A stale/duplicate
            // close on a Halted/Completed/Cancelled session must NOT re-roll-back,
            // re-emit, or mutate the terminal session's accumulators.
            if !matches!(st.status, AutoStatus::Active | AutoStatus::Degraded) {
                return Err(AutoLoopError::NotIterating(ctx.agent_id.clone(), st.status));
            }
            // Adversarial-r11 W2': enforce single-writer. A second concurrent
            // close for this agent is rejected, so the phase-1→phase-3
            // read-modify-write (previous_best / iteration / accumulators) below
            // cannot be interleaved + lost across the lock-released phase-2.
            if st.close_in_progress {
                return Err(AutoLoopError::ConcurrentClose(ctx.agent_id.clone()));
            }
            st.close_in_progress = true;
            if ctx.crashed {
                new_best = st.previous_best;
                IterationStatus::Crash
            } else {
                match ctx.primary_metric {
                    // No primary reading + not crashed → cannot prove
                    // improvement → discard (conservative).
                    None => {
                        new_best = st.previous_best;
                        IterationStatus::Discard
                    }
                    Some(m) => {
                        let op = primary_op(&st.criteria);
                        if primary_is_improvement(op, m, st.previous_best) {
                            new_best = Some(m);
                            IterationStatus::Keep
                        } else {
                            new_best = st.previous_best;
                            IterationStatus::Discard
                        }
                    }
                }
            }
        };

        // Phases 2+3 run inside an async block whose Result is captured so the
        // close-in-progress flag is ALWAYS cleared afterwards (on success OR on
        // any `?` early-exit), preventing a permanently-locked session.
        let result: Result<IterationOutcome, AutoLoopError> = async {
            // ── Phase 2: async side effects with the lock RELEASED ───────────
            match status {
                IterationStatus::Discard | IterationStatus::Crash => {
                    self.rollback
                        .rollback_iteration(&ctx.agent_id, ctx.iteration)
                        .await?;
                    self.apply_skill_discard(&ctx.agent_id).await?;
                }
                IterationStatus::Keep => {
                    self.clear_skill_tracker(&ctx.agent_id);
                }
            }

            if let Some(writer) = self.results_writer.as_ref() {
                let row = IterationResult {
                    iter: ctx.iteration,
                    checkpoint: ctx.checkpoint_label.clone(),
                    metric: ctx.metrics.clone(),
                    status,
                    cost_usd: ctx.cost_usd,
                    wall_time_sec: ctx.wall_time_sec,
                    summary: ctx.summary.clone(),
                };
                writer.append(&row).await?;
            }

            self.emit_iteration_events(&ctx, status).await;

            // ── Phase 3: write-back under the lock (sync) ────────────────────
            {
                let mut guard = self
                    .state
                    .lock()
                    .expect("auto-loop state mutex poisoned in close_iteration (write-back)");
                if let Some(st) = guard.get_mut(&ctx.agent_id) {
                    st.last_iteration_status = Some(status);
                    st.iteration = ctx.iteration;
                    // Accumulate cross-iteration cost. Audit-r7 W3 fix: only add a
                    // NON-NEGATIVE, finite cost. A negative (or NaN/Inf) cost is
                    // ignored so a buggy/hostile close caller can never LOWER
                    // total_cost_usd and slip the run back under the safety-valve
                    // cost cap (fail-CLOSED: cost only ever monotonically rises).
                    if ctx.cost_usd.is_finite() && ctx.cost_usd >= 0.0 {
                        st.total_cost_usd += ctx.cost_usd;
                    }
                    match status {
                        IterationStatus::Keep => {
                            // Adversarial-r10 W3: re-evaluate against the CURRENT
                            // previous_best (it may have advanced during the
                            // lock-released phase-2 via a concurrent close), and
                            // update only if this iteration's metric is STILL an
                            // improvement — a monotonic compare-and-set so a
                            // concurrent better keep is never clobbered by this
                            // (now-stale) phase-1 snapshot. Falls back to `new_best`
                            // if the metric is absent (shouldn't happen on Keep).
                            match ctx.primary_metric {
                                Some(m)
                                    if primary_is_improvement(
                                        primary_op(&st.criteria),
                                        m,
                                        st.previous_best,
                                    ) =>
                                {
                                    st.previous_best = Some(m);
                                }
                                None => st.previous_best = new_best,
                                _ => { /* a concurrent close already kept a >= value */ }
                            }
                            st.consecutive_no_progress = 0;
                        }
                        IterationStatus::Discard | IterationStatus::Crash => {
                            st.consecutive_no_progress =
                                st.consecutive_no_progress.saturating_add(1);
                        }
                    }
                }
            }

            Ok(IterationOutcome::Continue {
                status,
                decision: RoundDecision::ContinueAllowed,
            })
        }
        .await;

        // Adversarial-r11 W2': ALWAYS release the single-writer flag — on the
        // success path AND on any phase-2 `?` error — so a failed close (e.g.
        // SkillRollbackUnwired / rollback IO error) never permanently wedges the
        // session into ConcurrentClose.
        {
            let mut guard = self
                .state
                .lock()
                .expect("auto-loop state mutex poisoned in close_iteration (release flag)");
            if let Some(st) = guard.get_mut(&ctx.agent_id) {
                st.close_in_progress = false;
            }
        }
        result
    }

    /// Discard/crash skill restoration (fail-CLOSED). Takes the agent's
    /// `SkillTracker` OUT of the map (so no std-Mutex is held across the async
    /// `apply_discard`), then: empty tracker → `Ok` (nothing activated this
    /// iteration); non-empty + no real `SkillRollback` wired →
    /// `SkillRollbackUnwired` (a no-op write side would leak mutations); else
    /// drain via `apply_discard`, restoring any un-drained remainder on error.
    async fn apply_skill_discard(&self, agent_id: &str) -> Result<(), AutoLoopError> {
        let mut tracker = {
            let mut guard = self
                .skill_trackers
                .lock()
                .expect("auto-loop skill_trackers mutex poisoned in apply_skill_discard");
            match guard.remove(agent_id) {
                Some(t) => t,
                None => return Ok(()),
            }
        };
        if tracker.is_empty() {
            return Ok(());
        }
        let Some(rollback) = self.skill_rollback.get() else {
            // Fail-CLOSED: skills were activated but no restoring rollback is
            // wired. Put the tracker back for inspection/retry.
            self.skill_trackers
                .lock()
                .expect("auto-loop skill_trackers mutex poisoned in apply_skill_discard (restore)")
                .insert(agent_id.to_string(), tracker);
            return Err(AutoLoopError::SkillRollbackUnwired(agent_id.to_string()));
        };
        match tracker.apply_discard(agent_id, rollback.as_ref()).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Partial drain: stash the remaining un-restored pre-states.
                self.skill_trackers
                    .lock()
                    .expect(
                        "auto-loop skill_trackers mutex poisoned in apply_skill_discard (partial)",
                    )
                    .insert(agent_id.to_string(), tracker);
                Err(AutoLoopError::from(e))
            }
        }
    }

    /// Keep-path skill bookkeeping: drop the agent's recorded pre-states (the
    /// iteration is kept, so its skill mutations stand). Audit-r7 W1 fix: REMOVE
    /// the per-agent entry rather than just `clear()`-ing it, so a kept session
    /// leaves no residual map entry (the next `record_skill_pre_activation`
    /// re-creates it lazily). Prevents slow growth across kept iterations.
    fn clear_skill_tracker(&self, agent_id: &str) {
        self.skill_trackers
            .lock()
            .expect("auto-loop skill_trackers mutex poisoned in clear_skill_tracker")
            .remove(agent_id);
    }

    /// Emit the per-status `auto.iteration_{kept,discarded,crashed}` event then
    /// `auto.iteration_completed`. Best-effort observability — sink errors do
    /// NOT fail the iteration close (the close already mutated git/results).
    async fn emit_iteration_events(&self, ctx: &IterationCloseCtx, status: IterationStatus) {
        let Some(sink) = self.iteration_event_sink.as_ref() else {
            return;
        };
        let per_status = match status {
            IterationStatus::Keep => AutoIterationEventPayload::Kept {
                agent_id: ctx.agent_id.clone(),
                run_id: ctx.run_id.clone(),
                iteration: ctx.iteration,
                metric: ctx.primary_metric,
            },
            IterationStatus::Discard => AutoIterationEventPayload::Discarded {
                agent_id: ctx.agent_id.clone(),
                run_id: ctx.run_id.clone(),
                iteration: ctx.iteration,
                metric: ctx.primary_metric,
            },
            IterationStatus::Crash => AutoIterationEventPayload::Crashed {
                agent_id: ctx.agent_id.clone(),
                run_id: ctx.run_id.clone(),
                iteration: ctx.iteration,
                reason: ctx.crash_reason.clone().unwrap_or_default(),
            },
        };
        let _ = sink.emit(per_status).await;
        let _ = sink
            .emit(AutoIterationEventPayload::Completed {
                agent_id: ctx.agent_id.clone(),
                run_id: ctx.run_id.clone(),
                iteration: ctx.iteration,
                status,
            })
            .await;
    }

    /// Stage-D scheduler-cadence pass over ALL live sessions (called from
    /// `on_tick`, `now_ms` from `SchedulerTick`). Per session, fires the
    /// safety-valve (Halted) / no-progress + llm-error (Degraded) detectors and
    /// honors the reduced-cadence throttle while Degraded. Decisions are made
    /// under the state lock (sync); the resulting `auto.degraded`/`auto.halted`
    /// emits + notify calls happen with the lock RELEASED.
    pub async fn run_cadence_pass(&self, now_ms: u64) {
        // (payload, optional notify message)
        let mut emissions: Vec<(AutoIterationEventPayload, Option<String>)> = Vec::new();
        {
            let mut guard = self
                .state
                .lock()
                .expect("auto-loop state mutex poisoned in run_cadence_pass");
            for (agent_id, st) in guard.iter_mut() {
                if matches!(st.status, AutoStatus::Completed | AutoStatus::Cancelled) {
                    continue;
                }
                // Lazily anchor the whole-run wall-clock start.
                if st.started_at_ms.is_none() {
                    st.started_at_ms = Some(now_ms);
                }
                let sv = st.criteria.safety_valve_or_default();

                // 1) Safety valve → Halted (HIGHEST priority; from Active OR
                //    Degraded). Audit-r7 W2 fix: checked BEFORE the reduced-cadence
                //    throttle skip so a hard-limit breach (iterations/cost/wall-time)
                //    Halts immediately even while a Degraded session is inside its
                //    backoff window (the throttle must NEVER delay a hard stop).
                let elapsed_sec = st
                    .started_at_ms
                    .map(|s| now_ms.saturating_sub(s) / 1000)
                    .unwrap_or(0);
                let halt = if st.iteration >= sv.max_iterations() {
                    Some(HaltReason::MaxIterations)
                } else if st.total_cost_usd > sv.max_cost_usd() {
                    Some(HaltReason::MaxCostUsd)
                } else if elapsed_sec >= sv.max_wall_time_sec() {
                    Some(HaltReason::MaxWallTime)
                } else {
                    None
                };
                if let Some(reason) = halt {
                    if let Ok(next) = st.status.transition(Transition::SafetyValve) {
                        st.status = next;
                        emissions.push((
                            AutoIterationEventPayload::Halted {
                                agent_id: agent_id.clone(),
                                reason,
                            },
                            Some(format!("auto-loop halted: {}", reason.as_str())),
                        ));
                    }
                    continue;
                }

                // 2) Reduced cadence: while Degraded + inside the backoff window,
                //    SKIP this session's degrade-detector work (observable via
                //    cadence_skip). Runs AFTER the hard safety-valve check above.
                if st.status == AutoStatus::Degraded {
                    if let Some(until) = st.degraded_backoff_until_ms {
                        if now_ms < until {
                            st.cadence_skip = st.cadence_skip.saturating_add(1);
                            continue;
                        }
                    }
                }

                // 3) No-progress → Degraded + reduced cadence (only from Active).
                if st.status == AutoStatus::Active
                    && st.consecutive_no_progress >= sv.no_progress_limit()
                {
                    if let Ok(next) = st.status.transition(Transition::NoProgressLimit) {
                        st.status = next;
                        // Reduced cadence window = the backoff base (default 60s).
                        st.degraded_backoff_until_ms = Some(
                            now_ms.saturating_add(sv.llm_backoff_base_sec().saturating_mul(1000)),
                        );
                        st.cadence_skip = 0;
                        emissions.push((
                            AutoIterationEventPayload::Degraded {
                                agent_id: agent_id.clone(),
                                reason: DegradeReason::NoProgress,
                            },
                            Some(format!(
                                "auto-loop degraded: {} consecutive no-progress rounds (reduced cadence)",
                                st.consecutive_no_progress
                            )),
                        ));
                    }
                    continue;
                }

                // 4) LLM errors → Degraded + exponential backoff (only from Active).
                if st.status == AutoStatus::Active
                    && st.consecutive_llm_errors >= sv.llm_errors_limit()
                {
                    if let Ok(next) = st.status.transition(Transition::LlmErrorLimit) {
                        st.status = next;
                        st.degraded_backoff_until_ms =
                            Some(sv.backoff_until_ms(now_ms, st.consecutive_llm_errors));
                        st.cadence_skip = 0;
                        emissions.push((
                            AutoIterationEventPayload::Degraded {
                                agent_id: agent_id.clone(),
                                reason: DegradeReason::LlmErrors,
                            },
                            Some(format!(
                                "auto-loop degraded: {} consecutive LLM errors (exponential backoff)",
                                st.consecutive_llm_errors
                            )),
                        ));
                    }
                }
            }
        } // lock released

        for (payload, notify_msg) in emissions {
            let agent_id = payload.agent_id().to_string();
            if let Some(sink) = self.iteration_event_sink.as_ref() {
                let _ = sink.emit(payload).await;
            }
            if let (Some(ns), Some(msg)) = (self.notify_sink.as_ref(), notify_msg) {
                let _ = ns.notify(&agent_id, &msg).await;
            }
        }
    }

    /// Test/observation accessor: ticks delivered to this driver so far.
    pub fn tick_count(&self) -> u64 {
        self.tick_count.load(Ordering::Relaxed)
    }

    /// Test/observation accessor: component events delivered so far.
    pub fn event_count(&self) -> u64 {
        self.event_count.load(Ordering::Relaxed)
    }

    /// Test/observation accessor: count of `on_tick` passes skipped for
    /// `agent_id` while Degraded (reduced cadence). `None` if no live session.
    pub fn cadence_skip(&self, agent_id: &str) -> Option<u32> {
        self.state
            .lock()
            .expect("auto-loop state mutex poisoned in cadence_skip")
            .get(agent_id)
            .map(|s| s.cadence_skip)
    }

    /// Test/observation accessor: the reduced-cadence backoff deadline (epoch
    /// ms) for `agent_id`, or `None` if not throttled / no live session.
    pub fn degraded_backoff_until_ms(&self, agent_id: &str) -> Option<u64> {
        self.state
            .lock()
            .expect("auto-loop state mutex poisoned in degraded_backoff_until_ms")
            .get(agent_id)
            .and_then(|s| s.degraded_backoff_until_ms)
    }

    /// Inherent per-iteration checkpoint (AC-10 secondary / slice-B loop).
    pub async fn checkpoint_iteration(&self, agent_id: &str, n: u32) -> Result<(), AutoLoopError> {
        self.checkpoint.checkpoint_iteration(agent_id, n).await
    }

    /// Inherent baseline checkpoint (AC-10 / slice-B loop start).
    pub async fn checkpoint_baseline(&self, agent_id: &str) -> Result<(), AutoLoopError> {
        self.checkpoint.checkpoint_baseline(agent_id).await
    }

    /// Inherent per-iteration rollback (AC-11 / slice-B discard path).
    pub async fn rollback_iteration(&self, agent_id: &str, n: u32) -> Result<(), AutoLoopError> {
        self.rollback.rollback_iteration(agent_id, n).await
    }

    // ─── Slice-B inherent surface ─────────────────────────────────────────

    /// PRD §4.7.2 auto namespace task-id format (`auto:{agent-id}`).
    /// **Trust boundary**: `agent_id` validation (ASCII, no shell-meta, no
    /// embedded colons) is upstream (MODULE-005 agent-lifecycle at
    /// creation-time per CONTRACT-041). This helper does NOT re-validate.
    pub fn auto_namespace_task_id(&self, agent_id: &str) -> String {
        format!("auto:{agent_id}")
    }

    /// PRD §4.7.4 evaluator-id override format (`auto-eval:{agent-id}:iter-{n}`).
    /// Same agent_id trust boundary as `auto_namespace_task_id`.
    pub fn evaluator_id_for(&self, agent_id: &str, iteration: u32) -> String {
        crate::evaluator::evaluator_id(agent_id, iteration)
    }

    /// Apply a state-machine transition under the single Mutex critical
    /// section. Returns the new status, or `AutoLoopError::NotStarted` if
    /// the agent has no live `AutoState`, or `AutoLoopError::InvalidTransition`
    /// if the §1.3.5 table rejects the (from, trigger) pair (e.g., transitioning
    /// out of a terminal state).
    pub fn transition_status(
        &self,
        agent_id: &str,
        trigger: Transition,
    ) -> Result<AutoStatus, AutoLoopError> {
        let mut guard = self
            .state
            .lock()
            .expect("auto-loop state mutex poisoned in transition_status");
        let Some(auto_state) = guard.get_mut(agent_id) else {
            return Err(AutoLoopError::NotStarted(agent_id.to_string()));
        };
        let next = auto_state.status.transition(trigger)?;
        auto_state.status = next;
        Ok(next)
    }

    /// PRD §4.7.7 step 1 (foundation for AC-03 / AC-20 — verification deferred):
    /// records the complete-cycle request inside `AutoState.complete_cycle_request`
    /// WITHOUT transitioning. The integrated-loop slice reads this at
    /// iteration_end, runs the evaluator + applies keep/discard, computes
    /// final_status, composes the decision via `compose_complete_cycle_decision`,
    /// AND THEN transitions to Completed. complete-cycle is ORTHOGONAL to
    /// keep/discard.
    pub fn record_complete_cycle_request(
        &self,
        agent_id: &str,
        completion_summary: CompletionSummary,
    ) -> Result<(), AutoLoopError> {
        let mut guard = self
            .state
            .lock()
            .expect("auto-loop state mutex poisoned in record_complete_cycle_request");
        let Some(auto_state) = guard.get_mut(agent_id) else {
            return Err(AutoLoopError::NotStarted(agent_id.to_string()));
        };
        auto_state.complete_cycle_request = Some(completion_summary);
        Ok(())
    }

    /// PRD §4.7.7 cancel block (AC-19): direct transition to Cancelled
    /// without invoking the evaluator path. "不运行 evaluator，不读 metric."
    /// The other cancel-path pieces (rollback + emit run.round_completed +
    /// write results.jsonl) are integrated-loop responsibility — slice B
    /// only verifies the no-evaluator-call invariant.
    pub fn handle_manual_cancel(
        &self,
        agent_id: &str,
        reason: &str,
    ) -> Result<IterationOutcome, AutoLoopError> {
        let next = self.transition_status(agent_id, Transition::ManualCancel)?;
        debug_assert_eq!(next, AutoStatus::Cancelled);
        Ok(IterationOutcome::Cancelled {
            reason: reason.to_string(),
            decision: compose_cancel_decision(reason),
        })
    }

    /// Driver-level orchestrator for per-iteration budget check (foundation
    /// for AC-13/AC-23 — verification deferred). Reads per-session
    /// `per_iteration_budget` from `AutoState.criteria`, fetches `RunCost`
    /// from `cost_tracker.query_iteration(run_id, iteration)`, then calls the
    /// pure `check_budget` function. Returns `BudgetStatus::Ok` on missing
    /// session, missing budget, or missing cost_tracker (defense-in-depth —
    /// these are not error conditions, they're "nothing to check").
    pub fn check_per_iteration_budget(
        &self,
        agent_id: &str,
        run_id: &str,
        iteration: u32,
        started_at: Instant,
        now: Instant,
    ) -> BudgetStatus {
        let guard = self
            .state
            .lock()
            .expect("auto-loop state mutex poisoned in check_per_iteration_budget");
        let Some(auto_state) = guard.get(agent_id) else {
            return BudgetStatus::Ok;
        };
        let budget = auto_state.criteria.per_iteration_budget.as_ref();
        let cost = self
            .cost_tracker
            .as_ref()
            .and_then(|c| c.query_iteration(run_id, iteration));
        check_budget(budget, cost.as_ref(), started_at, now)
    }

    /// Convenience: forward to the configured fail-fast monitor (foundation
    /// for AC-14 — verification deferred). Returns Pass if no monitor.
    pub fn check_fail_fast(&self, metrics: &[FailFastMetric]) -> FailFastOutcome {
        let Some(monitor) = self.fail_fast_monitor.as_ref() else {
            return FailFastOutcome::Pass;
        };
        monitor.check_iteration(metrics)
    }

    /// Convenience: forward to the configured results writer (foundation
    /// for AC-15 — verification deferred). Returns Ok if no writer.
    pub async fn write_iteration_result(
        &self,
        result: &IterationResult,
    ) -> Result<(), AutoLoopError> {
        let Some(writer) = self.results_writer.as_ref() else {
            return Ok(());
        };
        writer.append(result).await
    }

    /// Slice-D AC-22 coordination method: consult the `auto.bootstrap` config at
    /// Auto-mode init, delegate to the configured [`AutoBootstrapApplier`], and
    /// emit the resulting `auto.bootstrap.{spawned,skipped,conflict}` events via
    /// the configured [`AutoBootstrapEventSink`].
    ///
    /// Does NOT modify the CONTRACT-140 `start()` signature — this is an
    /// additive inherent method. Its invocation at startup (the `start →
    /// checkpoint_baseline → consult_auto_bootstrap → iteration loop` sequence)
    /// is integrated-loop deferred (MODULE-015 §3.6).
    ///
    /// Workflow:
    /// 1. **Empty `raw_yaml`** (nothing to consult): `Ok(())` regardless of
    ///    wiring (passive observer). **Non-empty + missing applier or sink** →
    ///    `NotConfigured` (fail-CLOSED — a wiring bug must not silently swallow
    ///    the bootstrap intent).
    /// 2. Call `applier.apply`. On `Dispatch { msg, partial }`, emit the partial
    ///    events first (observability), THEN surface `ApplierFailed`. On the Ok
    ///    path, enforce the [`MAX_BOOTSTRAP_ENTRIES`] cap (fail-CLOSED).
    /// 3. Translate via `report_to_event_payloads` (parent root agent_id +
    ///    per-field 1024-byte truncation).
    /// 4. Emit each payload in `report.entries` order; sink failures DO NOT
    ///    short-circuit — aggregate into `SinkFailures`.
    pub async fn consult_auto_bootstrap(
        &self,
        parent_agent_id: &str,
        raw_yaml: &str,
    ) -> Result<(), AutoLoopError> {
        let applier = self.auto_bootstrap_applier.as_ref();
        let sink = self.auto_bootstrap_event_sink.as_ref();

        // Step 1: empty-config short-circuit + partial-wiring fail-CLOSED.
        if raw_yaml.trim().is_empty() {
            // Nothing to consult — passive observer regardless of wiring.
            return Ok(());
        }
        let (Some(applier), Some(sink)) = (applier, sink) else {
            return Err(AutoLoopError::AutoBootstrap(
                AutoBootstrapCoordinationError::NotConfigured {
                    applier_present: applier.is_some(),
                    sink_present: sink.is_some(),
                },
            ));
        };

        // Step 2: apply, with the Dispatch-with-partial observability path.
        let report = match applier.apply(parent_agent_id, raw_yaml).await {
            Ok(report) => {
                if report.entries.len() > MAX_BOOTSTRAP_ENTRIES {
                    return Err(AutoLoopError::AutoBootstrap(
                        AutoBootstrapCoordinationError::ReportTooLarge {
                            received: report.entries.len(),
                            limit: MAX_BOOTSTRAP_ENTRIES,
                        },
                    ));
                }
                report
            }
            Err(AutoBootstrapApplierError::Dispatch { msg, partial }) => {
                // Emit the landed-partial events for observability, then
                // surface the dispatch fault. Sink failures here are
                // best-effort (the dispatch fault dominates the return).
                //
                // Apply the SAME MAX_BOOTSTRAP_ENTRIES cap as the Ok-path
                // (audit R3 fix): `partial` is adapter-controlled, so a
                // buggy/hostile adapter returning an over-cap partial must
                // NOT cause unbounded emission. M005's parser caps at 64
                // upstream, so this guard only trips on a contract-violating
                // adapter.
                if partial.entries.len() <= MAX_BOOTSTRAP_ENTRIES {
                    let _ = self
                        .emit_payloads(parent_agent_id, &partial, sink.as_ref())
                        .await;
                    return Err(AutoLoopError::AutoBootstrap(
                        AutoBootstrapCoordinationError::ApplierFailed(
                            AutoBootstrapApplierError::Dispatch { msg, partial },
                        ),
                    ));
                }
                // Over-cap partial (adversarial Info #4): skip emission AND
                // bound the partial carried in the propagated error so a
                // hostile adapter can't push an unbounded Vec up the error
                // channel into any caller that logs/walks it. The dispatch
                // fault still surfaces with the first MAX_BOOTSTRAP_ENTRIES
                // entries retained for diagnostics.
                let bounded = crate::auto_bootstrap::M015BootstrapReport {
                    entries: partial
                        .entries
                        .into_iter()
                        .take(MAX_BOOTSTRAP_ENTRIES)
                        .collect(),
                };
                return Err(AutoLoopError::AutoBootstrap(
                    AutoBootstrapCoordinationError::ApplierFailed(
                        AutoBootstrapApplierError::Dispatch {
                            msg,
                            partial: bounded,
                        },
                    ),
                ));
            }
            Err(other) => {
                return Err(AutoLoopError::AutoBootstrap(
                    AutoBootstrapCoordinationError::ApplierFailed(other),
                ));
            }
        };

        // Steps 3+4: translate + emit (no short-circuit; aggregate failures).
        match self
            .emit_payloads(parent_agent_id, &report, sink.as_ref())
            .await
        {
            Ok(()) => Ok(()),
            Err(failures) => Err(AutoLoopError::AutoBootstrap(
                AutoBootstrapCoordinationError::SinkFailures(failures),
            )),
        }
    }

    /// Translate `report` → payloads and emit each in `report.entries` order.
    /// Sink failures DO NOT short-circuit: every payload is delivered;
    /// accumulated `(index, error)` pairs are returned as `Err`.
    ///
    /// **Truncation records — integrated-loop-deferred (NOT silently lost):**
    /// `report_to_event_payloads` sanitizes + length-caps every field and
    /// returns a `Vec<TruncationRecord>` describing any field that was cut.
    /// The slice-D coordination path intentionally does NOT emit
    /// `auto.bootstrap.field_truncated` events for them — M015 has no event
    /// channel for that yet (the integrated-loop slice, which wires the M019
    /// `EventBusEmit` sink, owns surfacing them; see
    /// [`crate::auto_bootstrap::TruncationRecord`]). The records are bound to
    /// `truncations` here (not `_`-discarded) and `debug_assert`-checked to
    /// keep the deferral explicit; in release builds they are dropped
    /// pending that wiring. After sanitization the emitted fields are
    /// audit-safe regardless, so deferring `field_truncated` does not leave an
    /// injection surface — only a (deferred) audit-completeness signal.
    async fn emit_payloads(
        &self,
        parent_agent_id: &str,
        report: &crate::auto_bootstrap::M015BootstrapReport,
        sink: &dyn AutoBootstrapEventSink,
    ) -> Result<(), Vec<(usize, crate::auto_bootstrap::AutoBootstrapSinkError)>> {
        let (payloads, truncations) = report_to_event_payloads(report, parent_agent_id);
        // Explicit deferral (adversarial slice-D W2): field_truncated emission
        // is integrated-loop-owned. Binding `truncations` (vs `_`) documents
        // that the records exist and are deliberately not yet emitted.
        debug_assert!(
            truncations.iter().all(|t| t.truncated_byte_len <= 1024),
            "TruncationRecord must respect MAX_CONFIG_STRING_LEN"
        );
        let _field_truncated_deferred = truncations;
        let mut failures = Vec::new();
        for (i, payload) in payloads.into_iter().enumerate() {
            if let Err(e) = sink.emit(payload).await {
                failures.push((i, e));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
}

/// Maximum bytes of caller-supplied `outcome` / `reason` text embedded
/// into a `RoundDecision::Blocked(String)` by the compose-* helpers.
/// Adversarial Round-1 Warning fix: cap unbounded caller text before it
/// flows into the event bus, audit logs, and `run.round_completed`
/// emissions. `RoundDecision` rustdoc in `advance_shared_types::run`
/// recommends ≤ 256 bytes for `Blocked.reason` and forbids PII; the
/// integrated-loop slice MUST add a separate PII redaction pass before
/// emission, but this slice unilaterally caps length so a hostile caller
/// can't OOM downstream consumers.
pub const MAX_DECISION_REASON_BYTES: usize = 256;

/// Adversarial-r10 W1: max concurrent live auto sessions per driver. `start`
/// rejects with [`AutoLoopError::AtCapacity`] at this ceiling so an
/// attacker-influenced caller minting unbounded distinct `agent_id`s cannot
/// grow the `state` map without bound (fail-CLOSED DoS guard; matches the
/// crate's capped-everything posture — MAX_OBJECTIVES / MAX_TRACKED_SKILLS / …).
pub const MAX_AUTO_SESSIONS: usize = 1024;

/// Adversarial-r10 W1: max entries in the `run_id→agent_id` /
/// `component_id→agent_id` index maps. `register_run` / `register_component`
/// reject at this ceiling. Generous (a live agent has few runs/components), but
/// bounds the one-never-stopped-agent-mints-infinite-ids residual vector.
pub const MAX_AUTO_ID_MAPPINGS: usize = 8192;

/// Max bytes of caller-supplied `summary` text persisted into the
/// `results.jsonl` row by `close_iteration` (audit-r7 W4). Larger than
/// [`MAX_DECISION_REASON_BYTES`] because the results file tolerates more, but
/// still bounded so a hostile/buggy close caller cannot write an unbounded line.
pub const MAX_RESULTS_SUMMARY_BYTES: usize = 1024;

/// Truncate `s` to at most `max_bytes` UTF-8 bytes, splitting on a
/// character boundary. If truncation occurs, an ellipsis marker (`…`,
/// 3 bytes UTF-8) replaces the trailing slot so consumers can see that
/// the string was cut. Returns `s` unchanged if shorter than `max_bytes`.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Leave room for the ellipsis marker.
    let ellipsis = "…";
    let target = max_bytes.saturating_sub(ellipsis.len());
    let mut end = target;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + ellipsis.len());
    out.push_str(&s[..end]);
    out.push_str(ellipsis);
    out
}

/// Pure helper (foundation for AC-20 — verification deferred): compose the
/// `run.round_completed` decision text for the complete-cycle terminal
/// path per PRD §4.7.7 line 934 verbatim:
/// `decision: blocked("completed: {outcome}, final_status: {status}")`.
///
/// `summary.outcome` is truncated to [`MAX_DECISION_REASON_BYTES`] minus
/// the framing text length (adversarial Round-1 Warning fix) — the
/// resulting string is bounded.
pub fn compose_complete_cycle_decision(
    summary: &CompletionSummary,
    final_status: IterationStatus,
) -> RoundDecision {
    let framing_len = "completed: , final_status: ".len() + final_status.as_str().len();
    let outcome_budget = MAX_DECISION_REASON_BYTES.saturating_sub(framing_len);
    let outcome = truncate_at_char_boundary(&summary.outcome, outcome_budget);
    RoundDecision::Blocked(format!(
        "completed: {}, final_status: {}",
        outcome,
        final_status.as_str()
    ))
}

/// Pure helper for the manual-cancel path's decision text (PRD §4.7.7
/// cancel block): `decision: blocked("cancelled: {reason}")`.
///
/// `reason` is truncated to [`MAX_DECISION_REASON_BYTES`] minus the
/// framing text length (adversarial Round-1 Warning fix).
pub fn compose_cancel_decision(reason: &str) -> RoundDecision {
    let framing_len = "cancelled: ".len();
    let reason_budget = MAX_DECISION_REASON_BYTES.saturating_sub(framing_len);
    let reason = truncate_at_char_boundary(reason, reason_budget);
    RoundDecision::Blocked(format!("cancelled: {reason}"))
}

#[async_trait]
impl SchedulerExtension for DefaultAutoLoopDriver {
    fn name(&self) -> &str {
        &self.name
    }

    async fn on_tick(&self, tick: SchedulerTick) {
        self.tick_count.fetch_add(1, Ordering::Relaxed);
        // Stage-D: scheduler-cadence detectors (safety-valve → Halted;
        // no-progress / llm-error → Degraded + reduced cadence) over all live
        // sessions. Pure-sync decision under the lock; emits with the lock
        // released. Idempotent: detectors gate on `status == Active` before
        // firing the entry transition, and the Degraded throttle skips
        // per-session work, so re-firing while already Degraded does not occur.
        self.run_cadence_pass(tick.now_ms).await;
    }

    async fn on_component_event(&self, _event: ComponentEvent) {
        // Stage-D: `ComponentEvent::Finished` is the close trigger and
        // `Failed` is the iteration-CRASH signal (NOT an llm-error — those use
        // the dedicated `record_llm_error` ingress). The full
        // Finished→read-`metric_source`→`close_iteration` (and Failed→close-as-crash)
        // binding needs a metric reader + workspace handle the driver does not
        // hold, so it is a harvest/SUT install point (MODULE-015 §2.7 / §3.6);
        // `agent_for_component` is the resolver that binding uses. This slice
        // records the event count.
        self.event_count.fetch_add(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl AutoLoopDriver for DefaultAutoLoopDriver {
    /// Pure-synchronous, single-lock, no `.await`, no git → race-free by
    /// construction. Validate, then ONE atomic check-and-insert critical
    /// section. Slice-B: passes the validated config to AutoState::new so
    /// per-session policy isolation is preserved.
    async fn start(&self, agent_id: &str, config: AutoLoopConfig) -> Result<(), AutoError> {
        // Validate first (AC-04 / AC-05 / AC-06 / AC-07 admission-time).
        // No state mutation on Err.
        config.validate()?;

        let mut guard = self
            .state
            .lock()
            .expect("auto-loop state mutex poisoned in start");
        if guard.contains_key(agent_id) {
            return Err(AutoLoopError::AlreadyStarted(agent_id.to_string()));
        }
        // Adversarial-r10 W1: fail-CLOSED at the session ceiling (a new agent,
        // not a re-start, would grow the map past MAX_AUTO_SESSIONS).
        if guard.len() >= MAX_AUTO_SESSIONS {
            return Err(AutoLoopError::AtCapacity("sessions", MAX_AUTO_SESSIONS));
        }
        guard.insert(agent_id.to_string(), AutoState::new(agent_id, config));
        Ok(())
    }

    async fn stop(&self, agent_id: &str) -> Result<(), AutoError> {
        // Audit-r7 W1 fix: purge ALL per-agent state so a stopped/restarted
        // agent inherits no stale mappings and the auxiliary maps cannot grow
        // unbounded in a long-lived daemon. `state` + `skill_trackers` are keyed
        // by agent_id; `run_agent_map` / `component_agent_map` are keyed by
        // run_id / component_id, so purge every entry whose VALUE is this agent.
        self.state
            .lock()
            .expect("auto-loop state mutex poisoned in stop")
            .remove(agent_id);
        self.skill_trackers
            .lock()
            .expect("auto-loop skill_trackers mutex poisoned in stop")
            .remove(agent_id);
        self.run_agent_map
            .lock()
            .expect("auto-loop run_agent_map mutex poisoned in stop")
            .retain(|_, owner| owner != agent_id);
        self.component_agent_map
            .lock()
            .expect("auto-loop component_agent_map mutex poisoned in stop")
            .retain(|_, owner| owner != agent_id);
        Ok(())
    }

    async fn status(&self, agent_id: &str) -> Option<AutoStatus> {
        let guard = self
            .state
            .lock()
            .expect("auto-loop state mutex poisoned in status");
        guard.get(agent_id).map(|s| s.status)
    }
}

/// Stage-D: the production [`AutoStateReader`] (the deferred slice-C bridge).
/// Makes `AutoLoopRoundAdvancer::new(Arc<driver as dyn AutoStateReader>)`
/// constructible. All methods are sync + read-only over the std-Mutex state;
/// none hold a lock across an `.await` (the trait methods are not async).
#[async_trait]
impl AutoStateReader for DefaultAutoLoopDriver {
    fn agent_id_for_run(&self, run_id: &str) -> Option<String> {
        // Lock poison → None → the advancer fail-CLOSES to InvalidState.
        self.run_agent_map.lock().ok()?.get(run_id).cloned()
    }

    fn complete_cycle_request(&self, agent_id: &str) -> Option<CompletionSummary> {
        let guard = self.state.lock().ok()?;
        guard
            .get(agent_id)
            .and_then(|s| s.complete_cycle_request.clone())
    }

    fn last_iteration_status(&self, agent_id: &str) -> Option<IterationStatus> {
        let guard = self.state.lock().ok()?;
        guard.get(agent_id).and_then(|s| s.last_iteration_status)
    }

    fn budget_decision(&self, run_id: &str, agent_id: &str) -> BudgetDecision {
        // (a) A wired RunBudgetSource (the real M008 bridge) wins.
        if let Some(src) = self.run_budget_source.as_ref() {
            return src.budget_decision(run_id, agent_id);
        }
        // (b) Fail-CLOSED safety-valve derivation when no source is wired.
        //     NEVER `Allow` for an unknown / over-limit / non-continuable run.
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(_) => {
                return BudgetDecision::Deny("auto-loop: state lock poisoned".to_string());
            }
        };
        let Some(st) = guard.get(agent_id) else {
            return BudgetDecision::Deny(
                "auto-loop: no live session for agent (budget indeterminate)".to_string(),
            );
        };
        let sv = st.criteria.safety_valve_or_default();
        if st.iteration >= sv.max_iterations() {
            return BudgetDecision::Deny(format!(
                "safety-valve: max_iterations {} reached",
                sv.max_iterations()
            ));
        }
        if st.total_cost_usd > sv.max_cost_usd() {
            return BudgetDecision::Deny(format!(
                "safety-valve: max_cost_usd {} exceeded",
                sv.max_cost_usd()
            ));
        }
        if matches!(
            st.status,
            AutoStatus::Halted | AutoStatus::Completed | AutoStatus::Cancelled
        ) {
            return BudgetDecision::Deny(format!(
                "auto-loop: status {:?} is not continuable",
                st.status
            ));
        }
        BudgetDecision::Allow
    }
}
