//! Slice-local error enum for MODULE-015 auto-mode.
//!
//! CONTRACT-140 §2.3 names the error type `AutoError`; the alias keeps the
//! trait signature verbatim while the concrete enum is `AutoLoopError`
//! (mirrors the `AutoLoopConfig = SuccessCriteria` aliasing decision —
//! see `config.rs` + MODULE-015 §3.8 note 3).

use advance_git::{CheckpointError, RollbackError};

use crate::auto_bootstrap::AutoBootstrapCoordinationError;
use crate::evaluator::ConstraintViolation;
use crate::metric::MetricRoleSourceError;
use crate::skill_tracker::SkillTrackerError;
use crate::state::{AutoStatus, InvalidTransition};

/// Errors surfaced by the auto-loop crate (config parse/validate,
/// scheduler-layer checkpoint/rollback orchestration, session lifecycle,
/// state-machine transitions, evaluator constraint surface, role-source
/// matrix violations, missing-session lookups).
#[derive(Debug, thiserror::Error)]
pub enum AutoLoopError {
    #[error("success_criteria parse error: {0}")]
    Parse(String),

    #[error("success_criteria has no primary objective (exactly one required)")]
    MissingPrimary,

    #[error("success_criteria has {0} primary objectives (exactly one required)")]
    MultiplePrimary(usize),

    #[error("metric_source type=component requires a top-level `evaluator` ref")]
    MissingEvaluator,

    #[error("success_criteria has {0} objectives (max 64)")]
    TooManyObjectives(usize),

    /// Stage-D: a cost limit (`safety_valve.max_cost_usd` or
    /// `per_iteration_budget.max_cost_usd`) is non-finite (`NaN`/`Inf`).
    /// Rejected at admission (`validate()`) because a non-finite limit would
    /// fail-OPEN the `observed > limit` budget comparison. The `&'static str`
    /// names the offending field.
    #[error("non-finite cost limit: {0}")]
    NonFiniteCostLimit(&'static str),

    #[error("auto session for agent `{0}` already started")]
    AlreadyStarted(String),

    /// Stage-D adversarial-r10 W1: a per-driver capacity cap was hit (the
    /// `{0}` map — sessions / run-mappings / component-mappings — is at its
    /// `{1}` ceiling). Fail-CLOSED DoS guard: an attacker-influenced caller
    /// minting unbounded distinct agent/run/component ids cannot grow the
    /// in-memory maps without bound.
    #[error("auto-loop: {0} at capacity ({1})")]
    AtCapacity(&'static str, usize),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),

    #[error("rollback error: {0}")]
    Rollback(#[from] RollbackError),

    /// The `spawn_blocking` worker carrying the synchronous
    /// `NamedCheckpoint::create` libgit2 call failed to join.
    #[error("checkpoint task join error: {0}")]
    CheckpointJoin(String),

    /// Slice-B: role × metric_source matrix violation (AC-06/AC-07) surfaced
    /// from `SuccessCriteria::validate()` via `metric::validate_role_source_matrix`.
    #[error("role/source matrix violation: {0}")]
    RoleSource(#[from] MetricRoleSourceError),

    /// Slice-B: evaluator Pack component constraint surface violation
    /// (foundation for AC-08/AC-09) — surfaced from
    /// `evaluator::validate_constraint_surface`. AC-08/AC-09 verification
    /// is deferred this slice; the error variant lands as foundation.
    #[error("evaluator constraint surface violation: {0}")]
    EvaluatorConstraint(#[from] ConstraintViolation),

    /// Slice-B: state-machine transition rejected (AC-12) — surfaced from
    /// `AutoStatus::transition` via `DefaultAutoLoopDriver::transition_status`.
    #[error("invalid state transition: {0}")]
    InvalidTransition(#[from] InvalidTransition),

    /// Slice-B: agent_id has no live AutoState in the driver's HashMap.
    /// Returned by `transition_status` / `record_complete_cycle_request` /
    /// `handle_manual_cancel` when the session was never started or already
    /// stopped. NOT returned by `check_per_iteration_budget` (which returns
    /// `BudgetStatus::Ok` on missing session — defense-in-depth).
    #[error("auto session for agent `{0}` not started")]
    NotStarted(String),

    /// Stage-D adversarial-r10 W2: `close_iteration` / `iteration_start` was
    /// called on a session that is NOT actively iterating (status `{1:?}` —
    /// Halted/Completed/Cancelled). Rejected fail-CLOSED so a stale/duplicate
    /// `Finished` event after a session terminates cannot re-roll-back the
    /// workspace, double-emit `auto.iteration_*` / results rows, or mutate a
    /// terminal session's accumulators.
    #[error(
        "auto session for agent `{0}` is not iterating (status {1:?}) — iteration op rejected"
    )]
    NotIterating(String, AutoStatus),

    /// Stage-D adversarial-r11 W2': a second `close_iteration` for `{0}` was
    /// invoked while one is already in progress. The design is single-writer
    /// per agent; this fail-CLOSED rejection enforces it across the
    /// lock-released async phase, preventing a phase-1→phase-3 lost-update /
    /// `iteration` regression that would weaken the safety valves.
    #[error("auto session for agent `{0}`: a close_iteration is already in progress (concurrent close rejected)")]
    ConcurrentClose(String),

    /// Slice-B: I/O failure inside `ResultsWriter` (file open / write /
    /// flush / create_dir_all / JSON serialize). Distinct from `Parse`
    /// (which is for `success_criteria` YAML parse errors) so observability
    /// + operators can tell results.jsonl write failure from config parse
    /// failure — audit Round-2 fix.
    #[error("results.jsonl write error: {0}")]
    ResultsIo(String),

    /// Slice-D: auto-bootstrap coordination failure (AC-22) surfaced from
    /// `DefaultAutoLoopDriver::consult_auto_bootstrap` — wraps applier/sink/
    /// wiring errors. See `crate::auto_bootstrap::AutoBootstrapCoordinationError`.
    #[error("auto-bootstrap coordination error: {0}")]
    AutoBootstrap(#[from] AutoBootstrapCoordinationError),

    /// Stage-D: a discarded/crashed iteration's `close_iteration` needed to
    /// restore skill state (the per-agent `SkillTracker` had recorded
    /// pre-activations) but NO real `SkillRollback` was wired. Fail-CLOSED — a
    /// no-op write side would silently leak the discarded iteration's skill
    /// mutations (AC-18/AC-21). The `String` is the agent_id.
    #[error("auto session for agent `{0}`: skill restoration needed on discard but no SkillRollback wired (fail-closed)")]
    SkillRollbackUnwired(String),

    /// Stage-D: the wired `SkillRollback` impl failed during `apply_discard`.
    #[error("skill rollback error: {0}")]
    SkillTracker(#[from] SkillTrackerError),
}

/// CONTRACT-140 §2.3 declares the trait error as `AutoError`. Spec-faithful
/// alias so `trait AutoLoopDriver { ... -> Result<(), AutoError> }` matches
/// the doc verbatim without introducing a second enum.
pub type AutoError = AutoLoopError;
