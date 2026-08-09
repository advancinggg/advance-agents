//! MODULE-015 `auto-mode` — slices A + B + C + D.
//!
//! Nested sub-crate at `crates/scheduler/auto-loop/` per MODULE-015 §3.2.
//!
//! - Slice C added `skill_tracker` (SkillPreState) + `round_advancer`
//!   (CONTRACT-141 `AutoLoopRoundAdvancer`).
//! - Slice D added `auto_bootstrap` (AC-22 coordination surface:
//!   [`auto_bootstrap::AutoBootstrapApplier`] + [`auto_bootstrap::AutoBootstrapEventSink`]
//!   + [`auto_bootstrap::report_to_event_payloads`]) and
//!   [`budget::budget_breach_to_fail_fast_trigger`] (AC-23 fail-fast bridge).
//!   See MODULE-015 §3.8 note 9 for the slice-D M015-side-closure vs
//!   cross-module-deferred split.
//!
//! Slice A shipped the foundation:
//! - CONTRACT-140 [`AutoLoopDriver`] trait (`start`/`stop`/`status`) +
//!   [`DefaultAutoLoopDriver`] (also a CONTRACT-133
//!   [`advance_scheduler::SchedulerExtension`]).
//! - `success_criteria` parser ([`SuccessCriteria::parse_yaml`], the
//!   `auto-loop:`-wrapped snake_case config) + admission validation
//!   (exactly-one-primary AC-04, evaluator-if-component AC-05).
//! - Scheduler-layer checkpoint/rollback **primitives**
//!   ([`IterationCheckpoint`] / [`IterationRollback`] + inherent
//!   `DefaultAutoLoopDriver` methods, hyphen tag labels, `.agent/**`
//!   exclusion inherited from MODULE-003 CONTRACT-021).
//!
//! Slice B extends the crate with independent primitives:
//! - **5 new modules** ([`evaluator`], [`metric`], [`fail_fast`], [`results`],
//!   [`budget`]) shipping the constraint-surface validator, role × source
//!   matrix validator + high-fanout filter rule (AC-06/AC-07), fail-fast
//!   monitor, results.jsonl writer, and stateless per-iteration budget
//!   check (over canonical CONTRACT-181 `CostTrackerQuery`).
//! - **Formal 5-state machine** in [`state`] with `#[non_exhaustive]`
//!   [`AutoStatus`] + [`Transition`] table per PRD §4.7.5 verbatim (AC-12 +
//!   AC-19).
//! - **Driver builder pattern** preserving slice-A
//!   [`DefaultAutoLoopDriver::new`] signature verbatim; new dependencies
//!   attach via additive `with_*` methods.
//! - **Additive `SuccessCriteria` widening** with `per_iteration_budget`
//!   (PRD §4.7.8) and `fail_fast` (PRD §4.7.9) — both `Option<...>` + serde
//!   defaults so pre-slice-B configs parse unchanged.
//! - **Canonical shared-types consumption**:
//!   [`advance_shared_types::traits::CostTrackerQuery`] (CONTRACT-181),
//!   [`advance_shared_types::cost::RunCost`],
//!   [`advance_shared_types::run::MetricSample`],
//!   [`advance_shared_types::run::RoundDecision`],
//!   [`advance_shared_types::capability::CapRequest`] — no
//!   locally-invented duplicates.
//!
//! In-scope ACs verified by slice B: AC-06, AC-07, AC-12, AC-19. Primitives
//! ship as foundation for AC-02 / AC-03 / AC-08 / AC-09 / AC-13 / AC-14 /
//! AC-15 / AC-20 / AC-23 but AC verification is deferred to the coordinated
//! integrated §4.7.7 iteration-close loop slice. See MODULE-015 §3.8 notes
//! 4 + 5 for the deferred-verification rationale + role × source matrix
//! permissiveness design choice (PRD §4.7.4 vs §4.7.9 contradiction).
//!
//! Registration with MODULE-014's scheduler uses the additive
//! `Scheduler::register_extension` + `dispatch_tick`/`dispatch_component_event`
//! fan-out.

pub mod auto_bootstrap;
pub mod budget;
pub mod checkpoint;
pub mod config;
pub mod driver;
pub mod error;
pub mod evaluator;
pub mod event_sink;
pub mod fail_fast;
pub mod metric;
pub mod results;
pub mod rollback;
pub mod round_advancer;
pub mod skill_tracker;
pub mod state;

pub use auto_bootstrap::{
    report_to_event_payloads, AutoBootstrapApplier, AutoBootstrapApplierError,
    AutoBootstrapCoordinationError, AutoBootstrapEventSink, AutoBootstrapSinkError,
    BootstrapEventPayload, ConflictKind, M015BootstrapEntry, M015BootstrapOutcome,
    M015BootstrapReport, SkippedKind, TruncationRecord, MAX_BOOTSTRAP_ENTRIES,
};
pub use budget::{
    budget_breach_to_fail_fast_trigger, check_budget, BudgetBreach, BudgetStatus,
    PerIterationBudget,
};
pub use checkpoint::{
    iteration_label, DefaultIterationCheckpoint, IterationCheckpoint, BASELINE_LABEL,
};
pub use config::{
    AutoLoopConfig, AutoLoopDoc, MetricSource, Objective, Op, Predicate, Role, SafetyValve,
    SuccessCriteria, BACKOFF_EXP_CAP, DEFAULT_LLM_BACKOFF_BASE_SEC, DEFAULT_LLM_BACKOFF_MAX_SEC,
    DEFAULT_LLM_ERRORS_LIMIT, DEFAULT_MAX_COST_USD, DEFAULT_MAX_ITERATIONS,
    DEFAULT_MAX_WALL_TIME_HOURS, DEFAULT_NO_PROGRESS_LIMIT, MAX_CONFIG_STRING_LEN, MAX_OBJECTIVES,
};
pub use driver::{
    compose_cancel_decision, compose_complete_cycle_decision, AutoLoopDriver, CompletionSummary,
    DefaultAutoLoopDriver, IterationCloseCtx, IterationOutcome, RunBudgetSource,
};
pub use error::{AutoError, AutoLoopError};
pub use evaluator::{
    evaluator_id, validate_constraint_surface, ConstraintViolation, EvaluatorManifest,
    EvaluatorResolveError, EvaluatorResolver, EvaluatorSpec, NoopEvaluatorResolver,
};
pub use event_sink::{
    AutoEventSinkError, AutoIterationEventPayload, AutoIterationEventSink, DegradeReason,
    HaltReason, NoopAutoIterationEventSink, NoopNotifySink, NotifySink, NotifySinkError,
};
pub use fail_fast::{
    predicate_breached, DefaultFailFastMonitor, EvaluatedMetric, FailFastMetric, FailFastMonitor,
    FailFastOutcome,
};
pub use metric::{
    matrix_view, validate_role_source, validate_role_source_matrix, ComponentMetricReader,
    DefaultFileMetricReader, EventMetricReader, FileMetricReader, MetricReadError,
    MetricRoleSourceError, HIGH_FANOUT_EVENT_TYPES,
};
pub use results::{sanitize_for_serialization, IterationResult, IterationStatus, ResultsWriter};
pub use rollback::{DefaultIterationRollback, IterationRollback};
pub use round_advancer::{sanitize_for_audit, AutoLoopRoundAdvancer, AutoStateReader};
pub use skill_tracker::{
    NoopSkillRollback, SkillPreState, SkillRollback, SkillTracker, SkillTrackerError,
};
pub use state::{AutoState, AutoStatus, InvalidTransition, Transition};
