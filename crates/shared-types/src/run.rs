//! MODULE-008 run-manager + MODULE-015 auto-mode canonical
//! dependency-inversion surface.
//!
//! Canonical source: `docs/modules/MODULE-008-run-manager.md` §2.3
//! (RoundResult + MetricSample + RoundDecision + RunError + TaskRunStatus)
//! and `docs/modules/MODULE-015-auto-mode.md` §2.3 (RoundAdvancer).
//!
//! `BudgetDecision` is NOT re-declared here — it lives in
//! [`crate::capability`] from Slice J.
//!
//! Verbatim hoist — if either owner's declaration changes, run
//! `/spec MODULE-008` / `/spec MODULE-015` and re-hoist via a follow-on
//! /dev slice.
//!
//! # Security posture
//!
//! - **Error payload PII policy**: [`RunError`] all 5 variants carry
//!   `String` payloads that serialize through MODULE-019 EventBus and
//!   into operator logs. Implementers MUST NOT embed user content,
//!   run-budget internals, API-key fragments, or agent-private state.
//!   Reason strings SHOULD be short invariant identifiers
//!   (e.g. `"run-not-found"`, `"budget-exceeded-tokens"`).
//! - **`MetricSample.value: String` unbounded**: consumers cap at ≤ 256
//!   bytes per value. `MetricSample.name` SHOULD be a stable identifier
//!   shape (snake_case) to prevent log-line injection via newlines /
//!   control chars.
//! - **Status/decision enum String payloads**: [`RoundDecision::Blocked`],
//!   [`TaskRunStatus::Failed`], [`TaskRunStatus::Cancelled`] carry
//!   operator-facing `String` reasons. Same no-PII / no-secrets /
//!   no-user-input rule as [`RunError`] — keep payloads to short
//!   invariant identifiers (e.g. `"budget-exhausted"`, `"user-cancelled"`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// MODULE-008 §2.3:547-550 — per-metric sample.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricSample {
    pub name: String,
    pub value: String,
}

/// MODULE-008 §2.3:539-545 — round-completion record. `summary` is the
/// optional round-level narrative; `metrics` is a bounded list of per-metric
/// samples.
///
/// **Implementer Invariants**: bounded `summary` length (recommended
/// ≤ 4096 bytes); `metrics.len()` capped (recommended ≤ 64).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundResult {
    pub summary: Option<String>,
    pub metrics: Vec<MetricSample>,
}

/// MODULE-008 §2.3:552-555 — round-advancement decision. 2-variant:
/// continue the run or block with a reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoundDecision {
    ContinueAllowed,
    Blocked(String),
}

/// MODULE-008 §2.3:557-565 — run-manager error surface. 5 variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunError {
    NotFound(String),
    AlreadyExists(String),
    /// e.g. complete-round on a Completed run, resume-run on an Active run.
    InvalidState(String),
    BudgetExceeded(String),
    PermissionDenied(String),
}

/// MODULE-008 §2.3:567-574 — task-run lifecycle state machine.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskRunStatus {
    Active,
    /// Agent is inside await-replies (root AwaitSession open).
    Suspended,
    Paused,
    Completed,
    Failed(String),
    Cancelled(String),
}

/// CONTRACT-141 — round-advancement trait. MODULE-015 §2.3:291-300.
/// Implemented by MODULE-015; consumed by MODULE-008 complete-round handler.
///
/// # Implementer Invariants
///
/// 1. **Stateless across runs**: no per-run state stored inside the impl;
///    all state reads go through MODULE-008's run row.
/// 2. **Reads RunBudget**: invokes `RunBudget::check` before emitting
///    `ContinueAllowed`; Deny → `Blocked`.
/// 3. **No state mutation outside the run row**: advancement records only
///    the round result; it does not spawn new runs or mutate agent tree.
/// 4. **Bounded execution time**: soft cap per MODULE-015 policy (auto-mode
///    iteration close).
#[async_trait]
pub trait RoundAdvancer: Send + Sync {
    async fn on_complete_round(
        &self,
        run_id: &str,
        result: RoundResult,
    ) -> Result<RoundDecision, RunError>;
}
