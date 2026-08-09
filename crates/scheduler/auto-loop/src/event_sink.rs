//! Stage-D abstract event/notify sinks for the integrated §4.7.7 loop.
//!
//! The auto-loop crate has NO `advance-event-bus` / `advance-messaging`
//! dependency (crate-boundary discipline — see MODULE-015 §3.8 note 10). The
//! integrated loop emits the 7 `auto.*` lifecycle events + degrade/halt
//! notifications through these abstract crate-internal traits, mirroring the
//! existing [`crate::auto_bootstrap::AutoBootstrapEventSink`] precedent. The
//! CONCRETE bindings (M019 EventBus emit; cap-channel egress / dispatcher for
//! notify) live cli-side in `auto_wiring.rs`.
//!
//! `async fn emit`/`notify` are declared for call-chain composition +
//! forward-compat; the production adapters are typically trivial
//! `async fn { self.bus.emit(ev); Ok(()) }`-style wrappers.

use async_trait::async_trait;

use crate::results::IterationStatus;

/// The 7 `auto.*` lifecycle event-type strings (mirrors
/// `advance-event-bus` `taxonomy::auto::*`; held as literals so this crate
/// stays free of the event-bus dependency). The cli adapter forwards
/// [`AutoIterationEventPayload::event_type`] verbatim to `EventBusEmit`.
pub mod event_type {
    pub const ITERATION_STARTED: &str = "auto.iteration_started";
    pub const ITERATION_COMPLETED: &str = "auto.iteration_completed";
    pub const ITERATION_KEPT: &str = "auto.iteration_kept";
    pub const ITERATION_DISCARDED: &str = "auto.iteration_discarded";
    pub const ITERATION_CRASHED: &str = "auto.iteration_crashed";
    pub const DEGRADED: &str = "auto.degraded";
    pub const HALTED: &str = "auto.halted";
}

/// Why a session entered Degraded / Halted — carried on the degrade/halt
/// payloads so the sink + notify message can name the trigger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DegradeReason {
    /// N consecutive no-progress rounds (Active → Degraded).
    NoProgress,
    /// M consecutive LLM errors (Active → Degraded + exponential backoff).
    LlmErrors,
}

impl DegradeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DegradeReason::NoProgress => "no-progress-limit",
            DegradeReason::LlmErrors => "llm-error-limit",
        }
    }
}

/// Why a session was Halted (safety-valve hard limit breached).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HaltReason {
    MaxIterations,
    MaxCostUsd,
    MaxWallTime,
}

impl HaltReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            HaltReason::MaxIterations => "safety-valve: max_iterations",
            HaltReason::MaxCostUsd => "safety-valve: max_cost_usd",
            HaltReason::MaxWallTime => "safety-valve: max_wall_time",
        }
    }
}

/// One `auto.*` lifecycle event the integrated loop emits. The `agent_id` is
/// the auto-session agent; `run_id` is the auto Run (when known). Per-iteration
/// variants carry `iteration`; keep/discard carry the observed primary
/// `metric`; crash/degrade/halt carry a human-readable `reason`.
///
/// All caller-supplied free text (`reason`) is expected to be bounded +
/// sanitized by the loop before construction (the loop reuses
/// `round_advancer::sanitize_for_audit` for any agent-emitted text), so a sink
/// adapter may forward fields without re-sanitizing.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum AutoIterationEventPayload {
    Started {
        agent_id: String,
        run_id: Option<String>,
        iteration: u32,
    },
    Kept {
        agent_id: String,
        run_id: Option<String>,
        iteration: u32,
        metric: Option<f64>,
    },
    Discarded {
        agent_id: String,
        run_id: Option<String>,
        iteration: u32,
        metric: Option<f64>,
    },
    Crashed {
        agent_id: String,
        run_id: Option<String>,
        iteration: u32,
        reason: String,
    },
    Completed {
        agent_id: String,
        run_id: Option<String>,
        iteration: u32,
        status: IterationStatus,
    },
    Degraded {
        agent_id: String,
        reason: DegradeReason,
    },
    Halted {
        agent_id: String,
        reason: HaltReason,
    },
}

impl AutoIterationEventPayload {
    /// The `auto.*` event-type string for this payload (for the cli EventBus
    /// adapter). Stable mapping to [`event_type`].
    pub fn event_type(&self) -> &'static str {
        match self {
            AutoIterationEventPayload::Started { .. } => event_type::ITERATION_STARTED,
            AutoIterationEventPayload::Kept { .. } => event_type::ITERATION_KEPT,
            AutoIterationEventPayload::Discarded { .. } => event_type::ITERATION_DISCARDED,
            AutoIterationEventPayload::Crashed { .. } => event_type::ITERATION_CRASHED,
            AutoIterationEventPayload::Completed { .. } => event_type::ITERATION_COMPLETED,
            AutoIterationEventPayload::Degraded { .. } => event_type::DEGRADED,
            AutoIterationEventPayload::Halted { .. } => event_type::HALTED,
        }
    }

    /// The auto-session agent id this event concerns.
    pub fn agent_id(&self) -> &str {
        match self {
            AutoIterationEventPayload::Started { agent_id, .. }
            | AutoIterationEventPayload::Kept { agent_id, .. }
            | AutoIterationEventPayload::Discarded { agent_id, .. }
            | AutoIterationEventPayload::Crashed { agent_id, .. }
            | AutoIterationEventPayload::Completed { agent_id, .. }
            | AutoIterationEventPayload::Degraded { agent_id, .. }
            | AutoIterationEventPayload::Halted { agent_id, .. } => agent_id,
        }
    }
}

/// Error surfaced by an [`AutoIterationEventSink`]. Transient — the loop's
/// emission path does NOT retry (production wiring may).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AutoEventSinkError {
    #[error("auto-iteration event sink emit failed: {0}")]
    EmitFailed(String),
}

/// Emit surface for the 7 `auto.*` lifecycle events (M019-side,
/// dependency-inverted). Mirrors [`crate::auto_bootstrap::AutoBootstrapEventSink`].
#[async_trait]
pub trait AutoIterationEventSink: Send + Sync {
    async fn emit(&self, payload: AutoIterationEventPayload) -> Result<(), AutoEventSinkError>;
}

/// Error surfaced by a [`NotifySink`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NotifySinkError {
    #[error("notify sink failed: {0}")]
    NotifyFailed(String),
}

/// Event-AGNOSTIC notification surface for degrade/halt user notifications
/// (SYS-J-62 row 257). Deliberately carries only a notify INTENT (agent +
/// message), NOT a hard-coded event type — the concrete binding (cap-channel
/// OUTBOUND egress emitting `channel.raw_sent`, the mailbox dispatcher, etc.)
/// is a cli/SUT concern. The satellite does NOT decide which event the SUT
/// emits; the harvest routes this through cap-channel egress so
/// `channel.raw_sent` is witnessed (the mailbox dispatcher's `notify_channel`
/// emits `msg.received`, a different event — see MODULE-015 §3.8 note 10).
#[async_trait]
pub trait NotifySink: Send + Sync {
    async fn notify(&self, agent_id: &str, message: &str) -> Result<(), NotifySinkError>;
}

/// No-op [`AutoIterationEventSink`] (returns `Ok`). Used as the driver default
/// when no sink is wired — events are simply not observed (safe; emission is
/// best-effort observability, not a correctness gate).
pub struct NoopAutoIterationEventSink;

#[async_trait]
impl AutoIterationEventSink for NoopAutoIterationEventSink {
    async fn emit(&self, _payload: AutoIterationEventPayload) -> Result<(), AutoEventSinkError> {
        Ok(())
    }
}

/// No-op [`NotifySink`] (returns `Ok`). Driver default when no notify sink is
/// wired — degrade/halt notifications are not delivered (observability only).
pub struct NoopNotifySink;

#[async_trait]
impl NotifySink for NoopNotifySink {
    async fn notify(&self, _agent_id: &str, _message: &str) -> Result<(), NotifySinkError> {
        Ok(())
    }
}
