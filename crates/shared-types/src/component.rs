//! Shared component-primitive types used by CONTRACT-002 (`CircuitBreakerBus`)
//! and future callers across the workspace.
//!
//! Per MODULE-001 §3.2 and PRD §3.1, the component primitive has five execution
//! modes. This enum is the canonical representation shared by:
//! - MODULE-001 circuit-breaker bus (scope: component-type)
//! - MODULE-014 scheduler (dispatch routing)
//! - MODULE-010 context engine (Tier 2 Available Delegates — future)

use serde::{Deserialize, Serialize};

/// The five execution modes of the PRD §3.1 component primitive.
///
/// Used by [`CircuitBreakerBus::is_open_component_type`] (CONTRACT-002) and by
/// downstream scheduling / dispatch paths. Target-string encoding for
/// `BreakerScope::ComponentType` breakers MUST use [`ComponentType::as_str`]
/// to ensure stable cross-consumer matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ComponentType {
    Agent,
    Cron,
    Watcher,
    Daemon,
    Task,
}

impl ComponentType {
    /// Canonical lowercase string identifier. Used as the `target` field in
    /// `CircuitBreaker { scope: BreakerScope::ComponentType, target, ... }`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ComponentType::Agent => "agent",
            ComponentType::Cron => "cron",
            ComponentType::Watcher => "watcher",
            ComponentType::Daemon => "daemon",
            ComponentType::Task => "task",
        }
    }
}
