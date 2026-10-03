//! Per-iteration crash coordinator (cli composition root) — the SYS-AC-201/202
//! product seam.
//!
//! [`run_guarded_iteration`] is the per-iteration crash-DECISION coordinator that
//! the production scheduler tick-loop (a harvest install point) calls after each
//! agent turn. It composes the BUILT MODULE-015 auto-loop primitives with **zero
//! edits to the auto-loop crate src** — every primitive is already `pub`-re-exported
//! from `advance_scheduler_auto_loop`:
//!
//! - **Budget branch (SYS-AC-202)** — PRODUCT-decided crash. The coordinator computes
//!   [`BudgetStatus::Breach`] itself from a REAL `CostTrackerQuery` reading via
//!   `driver.check_per_iteration_budget`, maps it through the `pub`
//!   `budget_breach_to_fail_fast_trigger`, sets `IterationCloseCtx { crashed: true,
//!   crash_reason }`, and calls `close_iteration`. There is NO caller-set `crashed`
//!   flag — this closes the deferred "breach→crash CAUSATION is harness-stitched"
//!   gap (SYSTEM-ACCEPTANCE.md §3 row 202) at the product level.
//! - **Guardrail branch (SYS-AC-201)** — for each `Role::Guardrail` objective whose
//!   `metric_source` is a `Component { output_key }` evaluator output, the coordinator
//!   reads via the [`ComponentMetricReader`] trait → `predicate_breached` → crash.
//!   A read error is fail-CLOSED (crash) — an unreadable guardrail metric must NOT
//!   silently pass (matching `predicate_breached`'s NaN fail-CLOSED + the crate's
//!   `SkillRollbackUnwired` posture).
//! - **No breach** → a normal keep/discard `close_iteration`.
//!
//! **Witness-floor (Wave-14 Lane B, 2026-06-24):** the CONCRETE evaluator-executing
//! [`ComponentMetricReader`] — a real runnable-component binary run → output JSON — is
//! now BUILT: [`crate::evaluator_reader::ExecutingComponentMetricReader`]. The SYS-AC-201
//! e2e witness drives THIS coordinator's guardrail branch with that REAL reader over a
//! committed evaluator fixture (no hand-fed value). **Still a harvest install point (NOT
//! built):** the PRODUCTION tick-loop caller of this coordinator — the production auto
//! loop does not yet execute evaluator components on its own; the reader is witness-driven
//! (the SYS-AC-202/098/101/109 "drive-prod-fn, no-production-caller-yet" precedent; see
//! MODULE-015 §3.6 install-point (b) + §3.8 note 11). The unit tests below still drive the
//! guardrail branch with a `ComponentMetricReader` DOUBLE — legitimate product-unit-testing
//! of the coordinator logic, distinct from the SYS-AC-201 system-acceptance witness.
//!
//! File/Event-source guardrail objectives are out of this satellite's 201 scope (their
//! `FileMetricReader`/`EventMetricReader` readers are also harvest-deferred); the
//! coordinator evaluates only `Component`-source guardrails.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use advance_run_manager::{RunId, RunManager};
use advance_scheduler_auto_loop::config::{MetricSource, Role, SuccessCriteria};
use advance_scheduler_auto_loop::{
    budget_breach_to_fail_fast_trigger, compose_complete_cycle_decision, predicate_breached,
    sanitize_for_audit, AutoLoopError, AutoStateReader, BudgetStatus, CompletionSummary,
    ComponentMetricReader, DefaultAutoLoopDriver, DefaultFailFastMonitor, EvaluatedMetric,
    FailFastMetric, FailFastOutcome, FileMetricReader, InvalidTransition, IterationCloseCtx,
    IterationOutcome, Transition,
};
use advance_shared_types::run::{RoundDecision, RunError, TaskRunStatus};

/// Per-iteration inputs the coordinator needs alongside the driver, the session
/// `criteria`, and the metric reader. The future tick-loop caller fills these from
/// the iteration it just ran (the primary-objective reading, the cost/wall-time
/// accumulators, the on-disk checkpoint label, etc.).
#[derive(Clone, Debug)]
pub struct GuardedIterationInputs {
    pub agent_id: String,
    /// The auto Run id — the **RunManager-minted `RunId` string** (`run-{uuid}`, the
    /// colon-free cost-tracker + run-settle key validated by `validate_run_id`), NOT the
    /// `auto:{agent-id}` TASK id (`validate_task_id` permits `:`, but `validate_run_id`
    /// forbids it — the `auto:` namespacing lives on `task_id`). Both the per-iteration
    /// budget cost reading AND [`AutoTickCoordinator`]'s `complete_run` settle key on it.
    pub run_id: String,
    pub iteration: u32,
    /// On-disk checkpoint label for the results row (e.g. `auto-iter-{n}`).
    pub checkpoint_label: String,
    /// Observed primary-objective metric reading (`None` on a non-crash close →
    /// treated as a discard by `close_iteration`).
    pub primary_metric: Option<f64>,
    /// All metric readings to record in the `results.jsonl` row.
    pub metrics: BTreeMap<String, f64>,
    pub cost_usd: f64,
    pub wall_time_sec: u64,
    /// Optional caller summary for the results row (pre-sanitized; `close_iteration`
    /// re-sanitizes + length-bounds defensively).
    pub summary: Option<String>,
    /// Per-iteration wall-time anchor (set at `iteration_start`) + the current
    /// instant — the per-iteration budget wall-time check compares these.
    pub started_at: Instant,
    pub now: Instant,
}

/// Wave-22 (audit-r1): a threshold-source (File/Component) `fail_fast` metric is
/// UNDER-SPECIFIED when it has no predicate, OR a predicate with no threshold.
/// Either way `predicate_breached` returns `false` (see `fail_fast.rs`), so the
/// metric would silently PASS — the fail_fast branch treats this as fail-CLOSED.
fn threshold_source_underspecified(metric: &FailFastMetric) -> bool {
    match &metric.predicate {
        None => true,
        Some(p) => p.threshold.is_none(),
    }
}

/// Run one auto-mode iteration's guarded close. Decides crash from a REAL
/// per-iteration-budget breach (SYS-AC-202) or a guardrail Component-metric breach
/// (SYS-AC-201), else delegates to the normal keep/discard close. Returns the
/// `close_iteration` outcome (always `IterationOutcome::Continue { status, .. }`).
///
/// Budget is checked BEFORE the guardrail branch (mirroring `check_budget`'s
/// tokens>cost>walltime short-circuit), so a budget breach reason wins when both fire.
///
/// **PRECONDITION (trust contract).** This coordinator trusts its caller — the
/// scheduler tick-loop (a harvest install point). `criteria` MUST be the same
/// `AutoLoopConfig` the session was `start`ed with, and `inputs.run_id` /
/// `inputs.iteration` / `inputs.started_at` / `inputs.now` MUST be the iteration's
/// real facts. The budget CONFIG is driver-authoritative — `check_per_iteration_budget`
/// reads `AutoState.criteria.per_iteration_budget` + the wired `CostTrackerQuery`
/// internally — but the guardrail objectives + the per-iteration facts are
/// caller-supplied because `AutoState.criteria` is private to the driver (keeping the
/// auto-loop crate src untouched — MODULE-015 §3.8 note 11). A caller passing
/// stale/relaxed `criteria` or a wrong `run_id`/`iteration` is a caller bug, not an
/// attacker vector: the tick-loop already owns the loop, so no privilege boundary is
/// crossed.
pub async fn run_guarded_iteration(
    driver: &DefaultAutoLoopDriver,
    criteria: &SuccessCriteria,
    reader: &dyn ComponentMetricReader,
    inputs: GuardedIterationInputs,
) -> Result<IterationOutcome, AutoLoopError> {
    // Wave-22: delegate to the File-reader-aware variant with NO File reader
    // wired — a File-source `fail_fast` metric would FAIL-CLOSE for this caller
    // (no reader in the call). Every pre-Wave-22 caller carries `fail_fast: None`,
    // so the fail_fast branch is a true no-op for them (zero blast radius); this
    // signature is UNCHANGED.
    run_guarded_iteration_with_file_reader(driver, criteria, reader, None, inputs).await
}

/// Wave-22 (autoloop-integ) — the File-reader-aware guarded-iteration close
/// (AC-14 / REQ-078). Identical to [`run_guarded_iteration`]'s budget(1) +
/// Component-guardrail(2) crash branches, PLUS a `criteria.fail_fast` branch(3)
/// evaluated by the real `DefaultFailFastMonitor::check_with_readings` over the
/// RESOLVED subset, which on `Trigger` drives the same `close_crashed` crash path,
/// **SUPERSEDING the production-inert `FailFastMonitor::check_iteration` `Pass`
/// stub**. Precedence: budget → guardrail → fail_fast (a budget/guardrail reason
/// wins if both fire).
///
/// **Uniform fail-CLOSED posture (audit-r2 Claude-Diff-W1/W2)** — a `fail_fast`
/// metric that cannot be soundly evaluated NEVER silently fail-OPENs a safety
/// control; it is a fail-CLOSED `Trigger`:
/// - **File** — read via `file_reader`; if `file_reader` is `None` (the deferred
///   caller wired no reader), fail-CLOSED (the caller must use this
///   `_with_file_reader` variant with a real reader). **Component** — read via
///   `reader`. **Event** — presence-based reader unbuilt (a disclosed harvest
///   deferral) → fail-CLOSED.
/// - An under-specified threshold source (File/Component with NO predicate, OR a
///   predicate lacking a threshold — `predicate_breached` returns false, which
///   would silently Pass) → fail-CLOSED.
///
/// NOTE (Wave-22): unlike its pre-Wave-22 self, this fn is NO LONGER
/// `fail_fast`-agnostic. It stays inert for a `fail_fast: None` criteria (every
/// existing caller of the [`run_guarded_iteration`] shim carries `fail_fast: None`).
pub async fn run_guarded_iteration_with_file_reader(
    driver: &DefaultAutoLoopDriver,
    criteria: &SuccessCriteria,
    reader: &dyn ComponentMetricReader,
    file_reader: Option<&dyn FileMetricReader>,
    inputs: GuardedIterationInputs,
) -> Result<IterationOutcome, AutoLoopError> {
    // ── 1) Per-iteration BUDGET branch (SYS-AC-202) — product-decided crash. ──
    if let BudgetStatus::Breach(breach) = driver.check_per_iteration_budget(
        &inputs.agent_id,
        &inputs.run_id,
        inputs.iteration,
        inputs.started_at,
        inputs.now,
    ) {
        let reason = match budget_breach_to_fail_fast_trigger(&breach) {
            FailFastOutcome::Trigger { reason } => reason,
            // `budget_breach_to_fail_fast_trigger` is total over `BudgetBreach` and
            // always returns `Trigger`; this keeps the match exhaustive.
            FailFastOutcome::Pass => "fail-fast: per-iteration budget breach".to_string(),
        };
        return close_crashed(driver, &inputs, reason).await;
    }

    // ── 2) GUARDRAIL branch (SYS-AC-201) — Component-source guardrail objectives. ──
    for obj in &criteria.objectives {
        if obj.role != Role::Guardrail {
            continue;
        }
        let MetricSource::Component { output_key } = &obj.metric_source else {
            // File/Event guardrail sources need the File/Event readers (harvest);
            // out of this satellite's 201 scope.
            continue;
        };
        match reader.read_component_metric(output_key) {
            Ok(observed) => {
                if predicate_breached(&obj.predicate, observed) {
                    let reason = format!(
                        "guardrail breach: objective '{}' metric {observed} breached predicate (op={:?}, threshold={:?})",
                        obj.name, obj.predicate.op, obj.predicate.threshold
                    );
                    return close_crashed(driver, &inputs, reason).await;
                }
            }
            Err(e) => {
                // Fail-CLOSED: an unreadable guardrail metric must NOT silently pass.
                let reason = format!(
                    "guardrail metric read failed: objective '{}' (output_key={output_key}): {e}",
                    obj.name
                );
                return close_crashed(driver, &inputs, reason).await;
            }
        }
    }

    // ── 3) FAIL-FAST branch (AC-14 / REQ-078, Wave-22) — `criteria.fail_fast`
    //    File+Component metrics via the real `check_with_readings`, superseding
    //    the production-inert `check_iteration` `Pass` stub. ──
    if let Some(metrics) = criteria.fail_fast.as_ref() {
        // Resolve each `fail_fast` metric to a reading in lockstep; every
        // `resolved.push` is paired with a `readings.push`, so `check_with_readings`
        // always sees `resolved.len() == readings.len()` (no short-readings
        // fail-CLOSE). A source that cannot be soundly evaluated NEVER silently
        // fail-OPENs a safety control — it is a fail-CLOSED `Trigger` (uniform for
        // Event [reader unbuilt], File-with-no-`file_reader` [caller wired none],
        // and an under-specified threshold source) — audit-r2 Claude-Diff-W1/W2.
        let mut resolved: Vec<FailFastMetric> = Vec::new();
        let mut readings: Vec<EvaluatedMetric> = Vec::new();
        for metric in metrics {
            match &metric.metric_source {
                MetricSource::File { path, key } => {
                    // A threshold source needs a predicate WITH a threshold; a
                    // missing predicate OR a predicate lacking a threshold makes
                    // the metric meaningless (`predicate_breached` returns false
                    // on a None threshold), so it would silently PASS → fail-CLOSED
                    // (audit-r1 Codex-Diff-W3).
                    if threshold_source_underspecified(metric) {
                        return close_crashed(
                            driver,
                            &inputs,
                            format!("fail-fast: File metric '{path}' lacks a predicate+threshold"),
                        )
                        .await;
                    }
                    // No File reader wired in this call → FAIL-CLOSED (audit-r2
                    // Claude-Diff-W1: a File `fail_fast` safety control must NOT be
                    // silently skipped; the caller must use `_with_file_reader` with
                    // a real reader). Uniform with the Event/under-specified posture.
                    let Some(fr) = file_reader else {
                        return close_crashed(
                            driver,
                            &inputs,
                            format!(
                                "fail-fast: File metric '{path}' has no wired file reader in this call — fail-closed"
                            ),
                        )
                        .await;
                    };
                    match fr.read_file_metric(path, key) {
                        Ok(v) => {
                            resolved.push(metric.clone());
                            readings.push(EvaluatedMetric::Value(v));
                        }
                        // Fail-CLOSED: an unreadable fail_fast metric must NOT pass.
                        Err(e) => {
                            return close_crashed(
                                driver,
                                &inputs,
                                format!("fail-fast: File metric read failed '{path}': {e}"),
                            )
                            .await;
                        }
                    }
                }
                MetricSource::Component { output_key } => {
                    if threshold_source_underspecified(metric) {
                        return close_crashed(
                            driver,
                            &inputs,
                            format!(
                                "fail-fast: Component metric '{output_key}' lacks a predicate+threshold"
                            ),
                        )
                        .await;
                    }
                    match reader.read_component_metric(output_key) {
                        Ok(v) => {
                            resolved.push(metric.clone());
                            readings.push(EvaluatedMetric::Value(v));
                        }
                        Err(e) => {
                            return close_crashed(
                                driver,
                                &inputs,
                                format!(
                                    "fail-fast: Component metric read failed '{output_key}': {e}"
                                ),
                            )
                            .await;
                        }
                    }
                }
                // Event-source (presence-based) periodic fail_fast reader is
                // unbuilt (a disclosed Wave-22 harvest deferral). It is FAIL-CLOSED
                // rather than silently skipped so an admitted Event fail_fast
                // metric can never silently fail-OPEN a safety-abort control.
                MetricSource::Event { .. } => {
                    return close_crashed(
                        driver,
                        &inputs,
                        "fail-fast: Event-source fail_fast reader not yet built (deferred) — fail-closed"
                            .to_string(),
                    )
                    .await;
                }
            }
        }
        if !resolved.is_empty() {
            if let FailFastOutcome::Trigger { reason } =
                DefaultFailFastMonitor::check_with_readings(&resolved, &readings)
            {
                return close_crashed(driver, &inputs, format!("fail-fast: {reason}")).await;
            }
        }
    }

    // ── 4) No breach → normal keep/discard close. ──
    driver
        .close_iteration(IterationCloseCtx {
            agent_id: inputs.agent_id,
            run_id: Some(inputs.run_id),
            iteration: inputs.iteration,
            checkpoint_label: inputs.checkpoint_label,
            primary_metric: inputs.primary_metric,
            metrics: inputs.metrics,
            crashed: false,
            crash_reason: None,
            summary: inputs.summary,
            cost_usd: inputs.cost_usd,
            wall_time_sec: inputs.wall_time_sec,
        })
        .await
}

/// Build a crash `IterationCloseCtx` from `inputs` + `reason` and close it. The
/// `close_iteration` crash arm rolls back, appends a `status:crash` results row, and
/// emits `auto.iteration_crashed` carrying `reason`.
async fn close_crashed(
    driver: &DefaultAutoLoopDriver,
    inputs: &GuardedIterationInputs,
    reason: String,
) -> Result<IterationOutcome, AutoLoopError> {
    driver
        .close_iteration(IterationCloseCtx {
            agent_id: inputs.agent_id.clone(),
            run_id: Some(inputs.run_id.clone()),
            iteration: inputs.iteration,
            checkpoint_label: inputs.checkpoint_label.clone(),
            primary_metric: inputs.primary_metric,
            metrics: inputs.metrics.clone(),
            crashed: true,
            crash_reason: Some(reason),
            summary: inputs.summary.clone(),
            cost_usd: inputs.cost_usd,
            wall_time_sec: inputs.wall_time_sec,
        })
        .await
}

// ─── Wave-6 Lane C: auto-mode terminal-settle coordinator (183/185) ───────────────
//
// The EXTERNAL consumer of the advancer's terminal decision that
// `RunManager::complete_round`'s auto branch observes-but-discards
// (`let _m015_decision = …`; the auto branch stays buffer-only per PRD A.24 — the
// agent always sees `ContinueAllowed`). NOTHING in production read that decision; this
// coordinator is that missing bridge. It composes the per-iteration crash close
// (`run_guarded_iteration`, 201/202) with the terminal RUN settlement:
//
// - **183 (completion)** — on a recorded complete-cycle request the coordinator
//   pre-checks the Run is `Active`, then drives the driver `Active→Completed`
//   (`Transition::CompleteCycle`, DRIVER-FIRST — validates both preconditions before the
//   irreversible `RunManager::complete_run` → `run.completed`).
// - **185 (cancel)** — `DefaultAutoLoopDriver::handle_manual_cancel` (driver `→Cancelled`)
//   THEN `RunManager::cancel_run_for_agent` → `run.cancelled`.
//
// **Atomicity caveat.** The driver `AutoStatus` and the RunManager Run status are two
// DECOUPLED state machines (no shared lock). The pre-check + driver-first ordering NARROW
// — but do not eliminate — a cross-lock half-settle window: a CONCURRENT flip by an
// independent actor (operator pause/cancel, M007 await-suspend, or a `>1`-live-run cancel)
// between the read and the settle surfaces as a LOUD `AutoTickError`, never a silent
// half-state. That residual is only reachable once the harvest's wired tick-loop shares a
// Run another actor can move off `Active`; true atomicity would need a run-manager src
// change, out of this satellite's scope.
//
// `complete_round` itself stays buffer-only (NOT settled here — that would violate A.24);
// run-manager src is UNCHANGED (the two settle methods already exist + are `pub`). The
// SYS-AC-183/185 e2e witnesses on a real wired daemon are a MODULE-015 harvest hand-off.

/// Error from the [`AutoTickCoordinator`] terminal-settle path.
#[derive(Debug)]
pub enum AutoTickError {
    /// The per-iteration guarded close (`run_guarded_iteration`) failed.
    Close(AutoLoopError),
    /// A driver-side terminal transition (`CompleteCycle`/`ManualCancel`) failed for a
    /// reason OTHER than an idempotent already-terminal state — e.g. the session is
    /// `Degraded`/`Halted` (`CompleteCycle` is `Active`-only) or `NotStarted`. The Run
    /// is NOT settled (fail-CLOSED, no half-settle).
    Driver(AutoLoopError),
    /// The run-manager settle (`complete_run`/`cancel_run_for_agent`) failed.
    Settle(RunError),
    /// `run_id` failed `validate_run_id` (must be the RunManager-minted `run-{uuid}`,
    /// not the `auto:` task id), or a required driver slot was missing.
    BadInput(&'static str),
}

impl std::fmt::Display for AutoTickError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoTickError::Close(e) => write!(f, "auto-tick close failed: {e}"),
            AutoTickError::Driver(e) => write!(f, "auto-tick driver settle failed: {e}"),
            AutoTickError::Settle(e) => write!(f, "auto-tick run settle failed: {e:?}"),
            AutoTickError::BadInput(m) => write!(f, "auto-tick bad input: {m}"),
        }
    }
}

impl std::error::Error for AutoTickError {}

/// Outcome of the per-turn terminal-settle routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalSettle {
    /// No complete-cycle request → the Run continues (settle is a no-op).
    Continued,
    /// A complete-cycle request settled the Run `Active→Completed` (183).
    Completed,
    /// The driver was already terminal → idempotent no-op (no `complete_run`).
    AlreadySettled,
}

/// The auto-mode tick coordinator — owns the `DefaultAutoLoopDriver` + the `RunManager`
/// and routes the per-turn terminal decision to RUN settlement (183/185). The future
/// production scheduler tick-loop (a harvest install point) drives it once per turn.
pub struct AutoTickCoordinator {
    driver: Arc<DefaultAutoLoopDriver>,
    run_manager: Arc<RunManager>,
}

impl AutoTickCoordinator {
    pub fn new(driver: Arc<DefaultAutoLoopDriver>, run_manager: Arc<RunManager>) -> Self {
        Self {
            driver,
            run_manager,
        }
    }

    /// Run one guarded iteration close (crash decision — 201/202) THEN route the
    /// terminal complete-cycle decision to settle the Run (183). `inputs.run_id` MUST be
    /// the RunManager-minted `RunId` string. Returns the per-iteration close outcome +
    /// the terminal-settle result.
    pub async fn run_iteration(
        &self,
        criteria: &SuccessCriteria,
        reader: &dyn ComponentMetricReader,
        inputs: GuardedIterationInputs,
    ) -> Result<(IterationOutcome, TerminalSettle), AutoTickError> {
        let agent_id = inputs.agent_id.clone();
        let run_id = inputs.run_id.clone();
        let close = run_guarded_iteration(&self.driver, criteria, reader, inputs)
            .await
            .map_err(AutoTickError::Close)?;
        let settle = self.settle_completed(&agent_id, &run_id).await?;
        Ok((close, settle))
    }

    /// Route the advancer's terminal complete-cycle decision to settle the Run (183).
    /// DRIVER-FIRST + fail-CLOSED 3-way match (symmetric with [`Self::cancel`]) so a
    /// `Degraded`/`Halted` session never leaves a settled Run with a non-terminal driver.
    pub async fn settle_completed(
        &self,
        agent_id: &str,
        run_id: &str,
    ) -> Result<TerminalSettle, AutoTickError> {
        // No complete-cycle request → the Run continues; nothing to settle.
        let Some(summary) = self.driver.complete_cycle_request(agent_id) else {
            return Ok(TerminalSettle::Continued);
        };
        // Fail-CLOSED if the integrated loop forgot to record last_iteration_status
        // (mirrors the advancer's InvalidState posture — never compose `final_status:keep`
        // for an unknown outcome).
        let Some(status) = self.driver.last_iteration_status(agent_id) else {
            return Err(AutoTickError::BadInput(
                "missing last_iteration_status for complete-cycle settle",
            ));
        };
        let rid = RunId::from_string(run_id.to_string()).map_err(AutoTickError::BadInput)?;

        // Run-Active PRE-CHECK before the irreversible driver transition. The driver
        // `AutoStatus` and the RunManager Run status are TWO decoupled state machines —
        // an operator pause/cancel or an M007 await-suspend can move the Run off `Active`
        // independently of the driver. Checking here means a Run already off `Active`
        // fails-CLOSED WITHOUT a driver-terminal / Run-unsettled half-state. This NARROWS
        // (does NOT eliminate) the cross-lock window: a CONCURRENT flip between this read
        // and `complete_run` below is a TOCTOU narrowed to microseconds and surfaces as a
        // loud `Err`, never a silent half-settle. Full reachability is gated on the
        // harvest's wired shared-Run tick-loop (the driver mutex + the Run store lock have
        // no shared critical section — true atomicity would need a run-manager src change,
        // out of this satellite's scope).
        match self
            .run_manager
            .run_status(&rid)
            .map_err(AutoTickError::Settle)?
            .status
        {
            TaskRunStatus::Active => {}
            // Already Completed → idempotent (a prior settle handled both sides; the
            // un-cleared `complete_cycle_request` flag would otherwise re-trigger).
            TaskRunStatus::Completed => return Ok(TerminalSettle::AlreadySettled),
            // Suspended / Paused / Cancelled / Failed → moved off Active by an independent
            // path; refuse BEFORE touching the driver (no half-settle), loud `Err`.
            _ => {
                return Err(AutoTickError::BadInput(
                    "run is not Active (settled/suspended/paused/cancelled by another path) — \
                     complete-cycle settle refused",
                ))
            }
        }

        // Sanitize the agent-emitted outcome (control / ANSI / bidi) BEFORE it flows into
        // the `run.completed` outcome (the advancer applies the same pass; `complete_run`
        // additionally length-bounds via `truncate_reason`).
        let sanitized = CompletionSummary {
            outcome: sanitize_for_audit(&summary.outcome),
            final_metrics: summary.final_metrics,
        };
        let reason = match compose_complete_cycle_decision(&sanitized, status) {
            RoundDecision::Blocked(r) => r,
            // `compose_complete_cycle_decision` is total → always `Blocked`; this keeps
            // the match exhaustive without an unreachable!().
            RoundDecision::ContinueAllowed => "completed".to_string(),
        };

        // ── DRIVER-FIRST: `CompleteCycle` is `Active`-only (state.rs) — validates the
        //    driver precondition; the Run-Active pre-check above validated the Run side. ──
        match self
            .driver
            .transition_status(agent_id, Transition::CompleteCycle)
        {
            // Active → Completed: the loop stops; proceed to settle the Run.
            Ok(_completed) => {}
            // Already terminal → idempotent no-op; do NOT re-settle the Run.
            Err(AutoLoopError::InvalidTransition(InvalidTransition::TerminalState(_))) => {
                return Ok(TerminalSettle::AlreadySettled);
            }
            // Degraded/Halted (IllegalTransition), NotStarted, or any other transition
            // error → fail-CLOSED, settle NOTHING (a degraded/halted session cannot
            // cleanly complete per the state machine; surface the anomaly loudly).
            Err(e) => return Err(AutoTickError::Driver(e)),
        }

        // The driver reached Completed from Active + the pre-check saw the Run Active →
        // `complete_run` settles it (barring the microsecond TOCTOU above, which fails loud).
        self.run_manager
            .complete_run(&rid, reason)
            .map_err(AutoTickError::Settle)?;
        Ok(TerminalSettle::Completed)
    }

    /// Settle an auto manual-cancel (185): transition the driver to `Cancelled` THEN
    /// force the Run to `Cancelled` via the existing `cancel_run_for_agent` →
    /// `run.cancelled`. DRIVER-FIRST, symmetric with [`Self::settle_completed`].
    /// Idempotent on an already-terminal driver (`TerminalState`): still runs the
    /// run-side cancel (itself a no-op on a terminal Run — `cancel_run_for_agent` is
    /// idempotent on a terminal/0-live agent).
    ///
    /// **Precondition (the auto 1-agent-1-run contract).** `agent_id` MUST equal the
    /// Run's `controller_agent` (the `cancel_run_for_agent` resolution key), and the
    /// agent must control exactly ONE live Run. `cancel_run_for_agent` returns
    /// `Err(InvalidState("…ambiguous…"))` if the agent has `>1` live Run; the auto
    /// contract precludes that (one `auto:{agent}` Run per agent), so it is unreachable
    /// in production. If it ever fires, this returns `AutoTickError::Settle` with the
    /// driver already `Cancelled` and the Run(s) unsettled — a LOUD failure (never a
    /// silent half-settle), and the same decoupled-state-machine residual documented on
    /// [`Self::settle_completed`].
    pub fn cancel(&self, agent_id: &str, reason: &str) -> Result<(), AutoTickError> {
        match self.driver.handle_manual_cancel(agent_id, reason) {
            Ok(_) => {}
            // Already terminal → idempotent; still attempt the run-side cancel.
            Err(AutoLoopError::InvalidTransition(InvalidTransition::TerminalState(_))) => {}
            // NotStarted (no live auto session) or any other driver error → fail-CLOSED.
            Err(e) => return Err(AutoTickError::Driver(e)),
        }
        self.run_manager
            .cancel_run_for_agent(agent_id, reason.to_string())
            .map_err(AutoTickError::Settle)?;
        Ok(())
    }
}
