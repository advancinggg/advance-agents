//! `RetryConfig` Rust mirror of WIT `retry-config` per PRD §9.5.1.
//!
//! Slice C — closes AC-13's retry-overrides field shape. The actual retry
//! classifier + backoff machinery lives in MODULE-009 cap-llm; this module
//! ships the parser surface + canonical defaults that M008 stores on the
//! `Run` row for future M009 consumption via a yet-to-be-defined
//! shared-types trait (see MODULE-008 §3.6 known-gap).
//!
//! Defaults per PRD §9.5.1 lines 3232-3239:
//! - `llm_max_retries`: 3
//! - `llm_base_delay_ms`: 1000
//! - `llm_max_delay_ms`: 30000
//! - `tool_max_retries`: 2 (idempotent methods only)
//! - `tool_base_delay_ms`: 500
//! - `tool_max_delay_ms`: 10000
//!
//! Bounded validators:
//! - max-retries ≤ 10 (anti misconfig-DoS)
//! - delays ≤ 300_000 ms (5 minutes)

use serde::{Deserialize, Serialize};

/// Rust mirror of WIT `retry-config` per PRD §9.5.1. All six fields are
/// `Option<u32>`; `None` means "use canonical default per WIT comments".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    pub llm_max_retries: Option<u32>,
    pub llm_base_delay_ms: Option<u32>,
    pub llm_max_delay_ms: Option<u32>,
    pub tool_max_retries: Option<u32>,
    pub tool_base_delay_ms: Option<u32>,
    pub tool_max_delay_ms: Option<u32>,
}

/// Canonical defaults resolved from a [`RetryConfig`]. All six fields are
/// `u32` (no Option) because every field has a documented default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryConfigDefaults {
    pub llm_max_retries: u32,
    pub llm_base_delay_ms: u32,
    pub llm_max_delay_ms: u32,
    pub tool_max_retries: u32,
    pub tool_base_delay_ms: u32,
    pub tool_max_delay_ms: u32,
}

/// Hard cap on max-retries (anti misconfig-DoS).
pub const MAX_RETRIES_CAP: u32 = 10;
/// Hard cap on delay-ms fields (5 minutes).
pub const MAX_DELAY_MS_CAP: u32 = 300_000;

impl RetryConfig {
    /// Resolve all six fields against the canonical PRD §9.5.1 defaults,
    /// clamping each one to the documented validator bounds.
    pub fn apply_defaults(&self) -> RetryConfigDefaults {
        RetryConfigDefaults {
            llm_max_retries: clamp_retries(self.llm_max_retries.unwrap_or(3)),
            llm_base_delay_ms: clamp_delay(self.llm_base_delay_ms.unwrap_or(1000)),
            llm_max_delay_ms: clamp_delay(self.llm_max_delay_ms.unwrap_or(30_000)),
            tool_max_retries: clamp_retries(self.tool_max_retries.unwrap_or(2)),
            tool_base_delay_ms: clamp_delay(self.tool_base_delay_ms.unwrap_or(500)),
            tool_max_delay_ms: clamp_delay(self.tool_max_delay_ms.unwrap_or(10_000)),
        }
    }
}

fn clamp_retries(n: u32) -> u32 {
    n.min(MAX_RETRIES_CAP)
}

fn clamp_delay(n: u32) -> u32 {
    n.min(MAX_DELAY_MS_CAP)
}
