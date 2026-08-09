//! MODULE-008 run-manager — Slice A + Slice B.
//!
//! Slice A delivered the in-memory Run state machine + the 4 lifecycle
//! events (created / reused / round_completed / completed) + the
//! `InMemoryRunBudget` impl + the `RepetitionGuard` impl with action
//! policies wired (inject path None-skipped).
//!
//! Slice B adds:
//! - Lifecycle methods: [`RunManager::pause_run`] / [`RunManager::cancel_run`]
//!   branches (a) Suspended + (b) Active; [`RunManager::resume_run`] dispatch
//!   for Paused→Active manual AND Suspended→Active await_complete;
//!   [`RunManager::suspend_run`] for the M007 entry point.
//! - Crash recovery via [`RecoveryReport`] + [`RunManager::recover_on_startup`]
//!   which takes an `Arc<dyn AwaitSessionRef>` as a per-call parameter
//!   (NOT via the `with_await_session_ref` builder used by pause/cancel
//!   branch (a)). Returns a `RecoveryReport` value with 4 counters.
//! - 7 additional event types (`run.suspended`, `run.resumed`, `run.paused`,
//!   `run.failed`, `run.cancelled`, `run.interrupted`, `run.repetition_detected`)
//!   + payload amendments for `run.reused` (+ `status`) and
//!   `run.round_completed` (PRD shape).
//! - WarnThenTerminate Tier 3 inject wiring in [`RepetitionGuard`] via
//!   `with_context_assembler` + `with_prompt_injection_helpers` builders;
//!   Severity::Critical short-circuit defense-in-depth.
//! - [`AgentRunResolver`] trait + [`RunManager`] blanket impl + the
//!   [`RunManager::build_repetition_guard`] convenience for production
//!   wiring; fail-honest ambiguity (multiple live runs sharing a controller
//!   → `(None, None)` instead of a heuristic winner).
//!
//! See `docs/modules/MODULE-008-run-manager.md` §3.8 Implementation Notes
//! (Slice A + Slice B sub-sections) for the architectural rationale.

pub mod budget;
mod events;
mod identifier;
pub mod persist;
pub mod recovery;
pub mod repetition_guard;
pub mod retry;
pub mod run;
mod store;
pub mod wit_impl;
pub mod wit_types;

pub use budget::InMemoryRunBudget;
pub use persist::RunPersister;
pub use recovery::RecoveryReport;
pub use repetition_guard::{
    is_retryable_repetition_decision, is_terminate_decision, AgentRunResolver, RepetitionAction,
    RepetitionGuard,
};
pub use retry::RetryConfig;
pub use run::{BudgetState, Run, RunConfig, RunId, RunManager};
pub use wit_impl::AgentRunWitImpl;
pub use wit_types::{RepetitionGuardConfig, WitRunConfig, WitRunError, WitRunState};

// AC-11 — re-export the shared-types constant for ergonomic access from
// run-manager consumers (the canonical declaration is co-located with
// `RepetitionDecision` in shared-types to avoid a compile-time edge
// MODULE-009 → MODULE-008).
pub use advance_shared_types::repetition::REPETITION_TERMINATED_TAG;
