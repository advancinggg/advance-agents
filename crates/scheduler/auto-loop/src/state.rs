//! Per-agent Auto state + formal 5-state machine (MODULE-015 §2.5 / §1.3.5 /
//! AC-12 / AC-19).
//!
//! Slice B ships the full 5-state transition machine per PRD §4.7.5 verbatim:
//!
//! ```text
//! Active
//!   ├── NoProgressLimit → Degraded
//!   ├── LlmErrorLimit   → Degraded
//!   ├── SafetyValve     → Halted
//!   ├── CompleteCycle   → Completed (terminal)
//!   └── ManualCancel    → Cancelled (terminal)
//!
//! Degraded
//!   ├── ProgressDetected → Active
//!   ├── LlmRecovered     → Active (reset consecutive_llm_errors)
//!   ├── SafetyValve      → Halted
//!   ├── ManualResume     → Active
//!   └── ManualCancel     → Cancelled (terminal)
//!
//! Halted (recoverable, non-terminal)
//!   ├── ManualResume → Active
//!   └── ManualCancel → Cancelled (terminal)
//!
//! Terminal: Completed, Cancelled (reject ALL triggers)
//! ```
//!
//! The enum carries `#[non_exhaustive]` so future variant additions are
//! non-breaking at the SemVer level (defense in depth for the public
//! re-export at lib.rs).

use std::time::Instant;

use crate::config::SuccessCriteria;

/// Auto run lifecycle status. Terminal states (Completed, Cancelled) reject
/// all transitions. `#[non_exhaustive]` so future variants don't break
/// downstream exhaustive matches.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AutoStatus {
    Active,
    Degraded,
    Halted,
    Completed,
    Cancelled,
}

/// Transition triggers per PRD §4.7.5 / MODULE-015 §1.3.5.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transition {
    /// N consecutive no-progress rounds (Active → Degraded).
    NoProgressLimit,
    /// M consecutive LLM errors, default 3 (Active → Degraded).
    LlmErrorLimit,
    /// Safety valve triggered (Active|Degraded → Halted).
    SafetyValve,
    /// Agent returned complete-cycle (Active → Completed terminal).
    CompleteCycle,
    /// Manual cancel received (any non-terminal → Cancelled terminal).
    ManualCancel,
    /// Degraded → Active when progress observed.
    ProgressDetected,
    /// Degraded → Active when LLM recovers (resets consecutive_llm_errors).
    LlmRecovered,
    /// Halted/Degraded → Active on manual resume (budget restored).
    ManualResume,
}

/// Transition rejection reason. `TerminalState` distinguishes "the state
/// machine is in a terminal absorbing state" (Completed / Cancelled —
/// any trigger rejected) from `IllegalTransition` (non-terminal but the
/// specific (from, trigger) pair isn't in the §1.3.5 table).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidTransition {
    #[error("auto run is in terminal state `{0:?}` — all transitions rejected")]
    TerminalState(AutoStatus),
    #[error("illegal transition: {from:?} on {trigger:?}")]
    IllegalTransition {
        from: AutoStatus,
        trigger: Transition,
    },
}

impl AutoStatus {
    /// Apply the §1.3.5 transition table verbatim. Returns the new
    /// `AutoStatus` on success; `InvalidTransition` otherwise.
    ///
    /// Note: this is a pure function over `(self, trigger)` — no
    /// observability of cause-effect predicate state (consecutive counters,
    /// budget readings). Callers are responsible for inferring the trigger
    /// from observed conditions.
    pub fn transition(self, trigger: Transition) -> Result<AutoStatus, InvalidTransition> {
        use AutoStatus::*;
        use Transition::*;
        // Terminal states reject ALL triggers first.
        if matches!(self, Completed | Cancelled) {
            return Err(InvalidTransition::TerminalState(self));
        }
        let next = match (self, trigger) {
            // Active outbound (5 triggers).
            (Active, NoProgressLimit) => Degraded,
            (Active, LlmErrorLimit) => Degraded,
            (Active, SafetyValve) => Halted,
            (Active, CompleteCycle) => Completed,
            (Active, ManualCancel) => Cancelled,
            // Degraded outbound (5 triggers).
            (Degraded, ProgressDetected) => Active,
            (Degraded, LlmRecovered) => Active,
            (Degraded, SafetyValve) => Halted,
            (Degraded, ManualResume) => Active,
            (Degraded, ManualCancel) => Cancelled,
            // Halted outbound (2 triggers — non-terminal recoverable).
            (Halted, ManualResume) => Active,
            (Halted, ManualCancel) => Cancelled,
            // Anything else is illegal per the §1.3.5 table.
            _ => {
                return Err(InvalidTransition::IllegalTransition {
                    from: self,
                    trigger,
                })
            }
        };
        Ok(next)
    }
}

/// In-memory per-agent auto-session state. Slice B extends the slice-A
/// shape with per-session config + counters + budget timestamp + cost
/// accumulator + complete-cycle request flag. `skill_pre_states` (AC-18) is
/// NOT included this slice — deferred to the AC-18 slice (cross with M017).
/// `previous_best` stays `Option<f64>` (slice-A simplification — MODULE-015
/// §2.5 lists `Option<MetricValue>` as the final shape; promotion is
/// deferred — see MODULE-015 §3.8 note 4).
///
/// Not serde-derived because `Instant` is not `Serialize` (matches slice-A).
#[derive(Clone, Debug)]
pub struct AutoState {
    pub agent_id: String,
    pub status: AutoStatus,
    pub iteration: u32,
    pub previous_best: Option<f64>,
    /// Slice B: per-session config snapshot. Lets the driver's inherent
    /// methods read per-agent `per_iteration_budget` / `fail_fast` without
    /// re-validating or threading config around.
    pub criteria: SuccessCriteria,
    /// Slice B: count of consecutive iterations without progress
    /// (Active → Degraded threshold).
    pub consecutive_no_progress: u32,
    /// Slice B: count of consecutive LLM errors (Active → Degraded
    /// threshold; default M=3 per PRD §4.7.5).
    pub consecutive_llm_errors: u32,
    /// Slice B: per-iteration wall-time anchor. Initialized at AutoState::new
    /// to `Instant::now()`; the integrated-loop slice resets this on each
    /// `auto.iteration_started` event so `now - per_iter_budget_start` gives
    /// the current iteration's elapsed time.
    pub per_iter_budget_start: Instant,
    /// Slice B: accumulator for cross-iteration cost (separate from the per-
    /// iteration cost the CostTrackerQuery returns).
    pub total_cost_usd: f64,
    /// Slice B: complete-cycle request recorded by
    /// `record_complete_cycle_request`. Per PRD §4.7.7 step 1, this is set
    /// WITHOUT transitioning state — the integrated loop reads it at
    /// iteration_end, runs the evaluator + applies keep/discard, then
    /// transitions to Completed.
    pub complete_cycle_request: Option<crate::driver::CompletionSummary>,
    /// Stage-D: the most recent iteration's keep/discard/crash status, set by
    /// `close_iteration` just before the round advances. Read by
    /// `AutoStateReader::last_iteration_status` so the complete-cycle decision
    /// composes the REAL terminal status (fail-CLOSED `None` → `InvalidState`
    /// in the advancer when a complete-cycle request exists).
    pub last_iteration_status: Option<crate::results::IterationStatus>,
    /// Stage-D: reduced-cadence backoff deadline (epoch ms, from
    /// `SchedulerTick.now_ms`). While set and in the future, `on_tick` SKIPS
    /// this session's per-tick work (observable reduced cadence). Set on
    /// Degraded entry; cleared on recovery.
    pub degraded_backoff_until_ms: Option<u64>,
    /// Stage-D: count of consecutive `on_tick` calls skipped while Degraded
    /// (observability for the reduced-cadence AC-24 assertion — work-count vs
    /// tick-count). Reset on recovery.
    pub cadence_skip: u32,
    /// Stage-D: whole-run wall-clock start (epoch ms from `SchedulerTick.now_ms`),
    /// set lazily on the first `on_tick` that observes this session. Used by the
    /// safety-valve `max_wall_time_hours` Halted detector. (Distinct from
    /// `per_iter_budget_start`, which is the per-ITERATION `Instant` anchor.)
    pub started_at_ms: Option<u64>,
    /// Stage-D adversarial-r11 W2': single-writer mutual-exclusion flag for
    /// `close_iteration`. Set in phase-1 and cleared after phase-3 (or on any
    /// error exit). A second concurrent `close_iteration` for the same agent
    /// sees it set and is rejected with `ConcurrentClose` — this enforces the
    /// design's single-writer-per-agent invariant across the lock-released
    /// phase-2 `.await`s, protecting the phase-1→phase-3 read-modify-write of
    /// `previous_best` / `iteration` / `consecutive_no_progress` from a
    /// lost-update / valve-weakening regression.
    pub close_in_progress: bool,
}

impl AutoState {
    /// Two-parameter constructor (slice-B shape): captures the validated
    /// success_criteria for per-session policy isolation.
    pub fn new(agent_id: &str, criteria: SuccessCriteria) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            status: AutoStatus::Active,
            iteration: 0,
            previous_best: None,
            criteria,
            consecutive_no_progress: 0,
            consecutive_llm_errors: 0,
            per_iter_budget_start: Instant::now(),
            total_cost_usd: 0.0,
            complete_cycle_request: None,
            last_iteration_status: None,
            degraded_backoff_until_ms: None,
            cadence_skip: 0,
            started_at_ms: None,
            close_in_progress: false,
        }
    }
}
