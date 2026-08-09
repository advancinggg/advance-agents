//! Rust mirror of WIT records / variants per PRD §9.5.1 verbatim.
//!
//! Slice C — closes AC-12 + AC-13 type-shape half. The corresponding host
//! function dispatcher lives in [`crate::wit_impl::AgentRunWitImpl`]. WIT
//! Val encoding/decoding into the wasmtime ComponentLinker via
//! `HostRegistry::register_agent_run` is deferred to a future M001 /
//! runtime integration slice (see MODULE-008 §3.6).
//!
//! Auto-mode discrimination is NOT a config-level field — it is identified
//! by `task_id.starts_with("auto:")` per REQ-069 (see
//! [`crate::identifier::is_auto_mode`]).

use advance_shared_types::await_session::AwaitTreeSummary;
use advance_shared_types::run::{RunError, TaskRunStatus};
use serde::{Deserialize, Serialize};

// Re-export the shared-types `RoundResult` / `RoundDecision` / `MetricSample`
// — these already match the WIT shape verbatim (Slice AC v2 hoist; see
// MODULE-001 §2.3). M008 consumers receive these via the existing
// `crates/shared-types` dep; this re-export is purely ergonomic.
pub use advance_shared_types::run::{
    MetricSample as WitMetricSample, RoundDecision as WitRoundDecision,
    RoundResult as WitRoundResult,
};

use crate::repetition_guard::RepetitionAction;
use crate::retry::RetryConfig;
use crate::run::RunConfig;

/// Rust mirror of WIT `repetition-guard-config` per PRD §9.5.1 lines
/// 3225-3230. All four fields are `Option<...>`; `None` means "use
/// canonical default per WIT comments".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepetitionGuardConfig {
    pub enabled: Option<bool>,
    pub window_size: Option<u32>,
    pub repeat_threshold: Option<u32>,
    pub action: Option<String>,
}

/// Canonical defaults resolved from a [`RepetitionGuardConfig`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepetitionGuardConfigDefaults {
    pub enabled: bool,
    pub window_size: u32,
    pub repeat_threshold: u32,
    pub action: String,
}

impl RepetitionGuardConfig {
    /// Resolve all four fields against the canonical PRD §9.5.1 defaults.
    pub fn apply_defaults(&self) -> RepetitionGuardConfigDefaults {
        RepetitionGuardConfigDefaults {
            enabled: self.enabled.unwrap_or(true),
            window_size: self.window_size.unwrap_or(10),
            repeat_threshold: self.repeat_threshold.unwrap_or(3),
            action: self
                .action
                .as_deref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "warn-then-terminate".to_string()),
        }
    }

    /// Map the WIT action string to the Rust [`RepetitionAction`] enum.
    /// Returns `None` for unrecognized strings.
    pub fn action_to_repetition_action(s: &str) -> Option<RepetitionAction> {
        match s {
            "warn-only" => Some(RepetitionAction::WarnOnly),
            "terminate" => Some(RepetitionAction::Terminate),
            "warn-then-terminate" => Some(RepetitionAction::WarnThenTerminate),
            _ => None,
        }
    }
}

/// Rust mirror of WIT `run-config` per PRD §9.5.1 lines 3217-3223. NOTE:
/// **No `mode` field** — Auto-mode is identified by `task_id` prefix
/// `auto:` per REQ-069.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitRunConfig {
    pub token_limit: Option<u64>,
    pub cost_usd_limit: Option<f64>,
    pub rounds_limit: Option<u32>,
    pub retry_overrides: Option<RetryConfig>,
    pub repetition_guard: Option<RepetitionGuardConfig>,
}

impl From<WitRunConfig> for RunConfig {
    fn from(wit: WitRunConfig) -> Self {
        RunConfig {
            token_limit: wit.token_limit,
            cost_usd_limit: wit.cost_usd_limit,
            rounds_limit: wit.rounds_limit,
            retry_overrides: wit.retry_overrides,
            repetition_guard: wit.repetition_guard,
        }
    }
}

impl From<RunConfig> for WitRunConfig {
    fn from(cfg: RunConfig) -> Self {
        WitRunConfig {
            token_limit: cfg.token_limit,
            cost_usd_limit: cfg.cost_usd_limit,
            rounds_limit: cfg.rounds_limit,
            retry_overrides: cfg.retry_overrides,
            repetition_guard: cfg.repetition_guard,
        }
    }
}

/// Rust mirror of WIT `run-state` per PRD §9.5.1 lines 3256-3268.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitRunState {
    pub task_id: String,
    pub controller_agent: String,
    pub status: TaskRunStatus,
    pub iteration: u32,
    pub root_await: Option<String>,
    pub await_tree: Option<AwaitTreeSummary>,
    pub token_used: u64,
    pub token_limit: Option<u64>,
    pub cost_usd: f64,
    pub cost_usd_limit: Option<f64>,
    pub rounds_limit: Option<u32>,
}

/// Rust mirror of WIT `run-error` variant per PRD §9.5.1 lines 3296-3302.
/// Bidirectional [`From<RunError>`] / [`From<WitRunError>`] for the
/// `AgentRunWitImpl` boundary mapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitRunError {
    NotFound(String),
    AlreadyExists(String),
    InvalidState(String),
    BudgetExceeded(String),
    PermissionDenied(String),
}

impl From<RunError> for WitRunError {
    fn from(e: RunError) -> Self {
        match e {
            RunError::NotFound(s) => WitRunError::NotFound(s),
            RunError::AlreadyExists(s) => WitRunError::AlreadyExists(s),
            RunError::InvalidState(s) => WitRunError::InvalidState(s),
            RunError::BudgetExceeded(s) => WitRunError::BudgetExceeded(s),
            RunError::PermissionDenied(s) => WitRunError::PermissionDenied(s),
        }
    }
}

impl From<WitRunError> for RunError {
    fn from(e: WitRunError) -> Self {
        match e {
            WitRunError::NotFound(s) => RunError::NotFound(s),
            WitRunError::AlreadyExists(s) => RunError::AlreadyExists(s),
            WitRunError::InvalidState(s) => RunError::InvalidState(s),
            WitRunError::BudgetExceeded(s) => RunError::BudgetExceeded(s),
            WitRunError::PermissionDenied(s) => RunError::PermissionDenied(s),
        }
    }
}
