//! CircuitBreakerBus (CONTRACT-002) — runtime policy layer for scoped breakers.
//!
//! Per MODULE-001 §1.4.4, breakers operate at three scopes (capability /
//! component-type / agent) × four consumer-side execution layers (block new
//! dispatch / surface error / handle running instances / freeze mailbox old
//! messages). This module owns the state container, transition rules,
//! admin-bypass helper, and event subscription. Consumer-side enforcement
//! (MODULE-006 mailbox freeze, MODULE-014 scheduler block, MODULE-013 grant
//! deny) queries this bus and acts on the returned state.
//!
//! `is_open_*` filters `BreakerState::Open` only — a `HalfOpen` breaker allows
//! a single probe (§1.4.4 line 449-450) and thus returns `None` from queries.
//! Consumers that need probe-dispensing semantics manage that state themselves.

use std::sync::{Arc, Mutex, RwLock};

use advance_shared_types::ComponentType;
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Scope of a circuit breaker. Mirrors the three runtime-config YAML values
/// `capability | component-type | agent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BreakerScope {
    Capability,
    ComponentType,
    Agent,
}

/// Transition state. `Open` blocks new dispatch; `Closed` allows normal flow;
/// `HalfOpen` allows a single probe before the next consumer decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    Open,
    Closed,
    HalfOpen,
}

/// Admin operations that bypass circuit-breaker state unconditionally.
/// Per spec §1.4.4 pseudocode (line 519). Variant names match the runtime-level
/// identifier; MODULE-006's WIT admin messages (e.g. `terminate-child`) are a
/// separate name-space surfaced to message layer consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminOp {
    TerminateAgent,
    CancelRun,
    Rollback,
}

/// A single breaker entry stored by the bus.
///
/// **Target-string encoding**: when `scope == BreakerScope::ComponentType`,
/// `target` MUST equal [`ComponentType::as_str()`] return value (one of
/// `"agent" | "cron" | "watcher" | "daemon" | "task"`). Other scopes use the
/// domain-native identifier (capability name or agent id).
#[derive(Clone, Debug, PartialEq)]
pub struct CircuitBreaker {
    pub scope: BreakerScope,
    pub target: String,
    pub state: BreakerState,
    pub kill_existing: bool,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Slice AE (2026-05-09): config → bus type bridges
// ---------------------------------------------------------------------------

impl From<crate::config::CircuitBreakerScope> for BreakerScope {
    fn from(v: crate::config::CircuitBreakerScope) -> Self {
        match v {
            crate::config::CircuitBreakerScope::Capability => BreakerScope::Capability,
            crate::config::CircuitBreakerScope::ComponentType => BreakerScope::ComponentType,
            crate::config::CircuitBreakerScope::Agent => BreakerScope::Agent,
        }
    }
}

impl From<crate::config::CircuitBreakerState> for BreakerState {
    fn from(v: crate::config::CircuitBreakerState) -> Self {
        match v {
            crate::config::CircuitBreakerState::Open => BreakerState::Open,
            crate::config::CircuitBreakerState::Closed => BreakerState::Closed,
            crate::config::CircuitBreakerState::HalfOpen => BreakerState::HalfOpen,
        }
    }
}

impl CircuitBreaker {
    /// Slice AE — build a runtime `CircuitBreaker` from a parsed YAML
    /// `CircuitBreakerSpec`. Resolves the optional fields:
    /// `kill_existing: Option<bool>` → `bool` via `unwrap_or(false)`,
    /// `reason: Option<String>` → `String` via the literal fallback
    /// `"<configured at startup>"`.
    pub fn from_config_spec(spec: &crate::config::CircuitBreakerSpec) -> Self {
        Self {
            scope: spec.scope.clone().into(),
            target: spec.target.clone(),
            state: spec.state.clone().into(),
            kill_existing: spec.kill_existing.unwrap_or(false),
            reason: spec
                .reason
                .clone()
                .unwrap_or_else(|| "<configured at startup>".to_string()),
        }
    }
}

/// Maximum length of a breaker `reason` string. Guards against memory-amplification
/// attacks where a malicious opener writes a huge string that gets cloned into
/// every subscriber's event (adversarial R6 finding).
pub const MAX_REASON_LEN: usize = 512;

/// Maximum length of a breaker `target` string. Guards against unbounded target
/// strings consuming memory during fan-out.
pub const MAX_TARGET_LEN: usize = 256;

/// Event emitted when a breaker state transition occurs.
///
/// Carries `kill_existing` so consumers implementing the §1.4.4 4-layer execution
/// semantics (MODULE-006 mailbox handling, MODULE-014 scheduler, MODULE-005 agent
/// termination) can act on the policy without re-querying the bus — closes the
/// TOCTOU window between event receipt and query.
#[derive(Clone, Debug, PartialEq)]
pub struct BreakerEvent {
    pub scope: BreakerScope,
    pub target: String,
    pub new_state: BreakerState,
    pub reason: String,
    pub kill_existing: bool,
    pub timestamp: DateTime<Utc>,
}

/// Errors produced by bus operations.
#[derive(Debug)]
pub enum BreakerError {
    NotFound {
        scope: BreakerScope,
        target: String,
    },
    InvalidTransition {
        from: BreakerState,
        to: BreakerState,
    },
    InvalidTarget {
        reason: String,
    },
    /// Returned when the caller lacks admin privileges required to mutate
    /// breaker state (spec §1.7 line 951). Not enforced by
    /// `DefaultCircuitBreakerBus` itself — admin-check is consumer-side
    /// (MODULE-013 grant-manager), but the variant is defined here so
    /// callers can match on it uniformly.
    PermissionDenied {
        op: String,
    },
}

impl std::fmt::Display for BreakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BreakerError::NotFound { scope, target } => {
                write!(f, "breaker not found: scope={scope:?}, target={target:?}")
            }
            BreakerError::InvalidTransition { from, to } => {
                write!(f, "invalid breaker transition: {from:?} -> {to:?}")
            }
            BreakerError::InvalidTarget { reason } => {
                write!(f, "invalid breaker target: {reason}")
            }
            BreakerError::PermissionDenied { op } => {
                write!(f, "permission denied for breaker operation: {op}")
            }
        }
    }
}

impl std::error::Error for BreakerError {}

// ---------------------------------------------------------------------------
// Trait (CONTRACT-002, verbatim from MODULE-001 §2.3 line 687-696)
// ---------------------------------------------------------------------------

/// CONTRACT-002: runtime policy layer for querying and mutating circuit
/// breakers at capability / component-type / agent scope.
/// CONTRACT-002 execution permit (D4, m021-s7-core Δ8).
///
/// Evidence that a breaker check RAN and did not refuse, minted only by
/// [`CircuitBreakerBus::acquire_execution_permit_for`]. Holding one means the check
/// happened before the effect, in that order.
///
/// **NO UNFORGEABILITY IS CLAIMED, and the reason is concrete.**
/// `DefaultCircuitBreakerBus::new()` is `pub` and starts with an EMPTY breaker list, so
/// any crate can build a permissive bus and obtain a permit from it; an out-of-crate
/// `impl CircuitBreakerBus` can do the same. CONTRACT-002's trust model is
/// composition-based — you trust the bus you wired, not the token.
///
/// So this is an ORDERING/HOLDING mechanism: it makes "the effect ran without consulting
/// the breaker" unrepresentable in a function signature. It is deliberately weaker than
/// the D4 `GrantMutationToken`, which sits behind a crate boundary with no public
/// constructor. Recording that difference matters more than the token itself: the
/// failure mode this lane exists to remove is a type whose NAME implies a guarantee its
/// CONSTRUCTION does not provide.
#[derive(Debug)]
pub struct ExecutionPermit {
    _scope: PermitScope,
}

#[derive(Debug)]
struct PermitScope;

impl ExecutionPermit {
    /// Crate-private mint. Callers obtain permits only from a bus.
    pub(crate) fn new() -> Self {
        Self {
            _scope: PermitScope,
        }
    }
}

pub trait CircuitBreakerBus: Send + Sync {
    fn is_open_capability(&self, cap: &str) -> Option<String>;
    fn is_open_component_type(&self, kind: ComponentType) -> Option<String>;
    fn is_open_agent(&self, agent_id: &str) -> Option<String>;
    fn open(&self, spec: CircuitBreaker) -> Result<(), BreakerError>;
    fn close(&self, scope: BreakerScope, target: &str) -> Result<(), BreakerError>;
    fn half_open(&self, scope: BreakerScope, target: &str) -> Result<(), BreakerError>;
    fn subscribe(&self) -> mpsc::UnboundedReceiver<BreakerEvent>;

    /// D4: consult the breaker for a capability and, if it is CLOSED, mint an
    /// [`ExecutionPermit`].
    ///
    /// The default body FAILS CLOSED — it returns `Err` with the breaker's own reason
    /// whenever the breaker is open. It is a provided method so existing implementors
    /// keep compiling, and it is written in terms of `is_open_capability`, so an
    /// implementor cannot accidentally get a permissive permit path by not overriding it:
    /// whatever their `is_open_capability` says is what this returns.
    fn acquire_execution_permit_for(&self, cap: &str) -> Result<ExecutionPermit, String> {
        match self.is_open_capability(cap) {
            Some(reason) => Err(reason),
            None => Ok(ExecutionPermit::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// DefaultCircuitBreakerBus — concrete in-memory implementation
// ---------------------------------------------------------------------------

struct Inner {
    breakers: RwLock<Vec<CircuitBreaker>>,
    subscribers: Mutex<Vec<mpsc::UnboundedSender<BreakerEvent>>>,
}

/// In-memory `CircuitBreakerBus` implementation. Construction via
/// [`DefaultCircuitBreakerBus::new`]; persistence to `runtime-config.yaml` and
/// EventBus emission are deferred to the bootstrap slice.
pub struct DefaultCircuitBreakerBus {
    inner: Arc<Inner>,
}

impl Default for DefaultCircuitBreakerBus {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCircuitBreakerBus {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                breakers: RwLock::new(Vec::new()),
                subscribers: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Admin control messages bypass breaker state unconditionally. Consumers
    /// should call this first; if `true`, skip `is_open_*` entirely.
    /// Per §1.4.4 line 429-430.
    pub fn is_admin_op(op: &AdminOp) -> bool {
        // Exhaustive match — if a new AdminOp variant is added, the compiler
        // forces us to decide whether it should bypass the breaker.
        match op {
            AdminOp::TerminateAgent | AdminOp::CancelRun | AdminOp::Rollback => true,
        }
    }

    /// Helper: send a `BreakerEvent` to all live subscribers. Runs OUTSIDE the
    /// breakers write-lock scope — callers must release it before invoking.
    /// Closed senders are pruned opportunistically.
    fn emit(&self, event: BreakerEvent) {
        let mut subs = self
            .inner
            .subscribers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        subs.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

impl CircuitBreakerBus for DefaultCircuitBreakerBus {
    fn is_open_capability(&self, cap: &str) -> Option<String> {
        let guard = self
            .inner
            .breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .find(|b| {
                b.scope == BreakerScope::Capability
                    && b.target == cap
                    && b.state == BreakerState::Open
            })
            .map(|b| b.reason.clone())
    }

    fn is_open_component_type(&self, kind: ComponentType) -> Option<String> {
        let guard = self
            .inner
            .breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .find(|b| {
                b.scope == BreakerScope::ComponentType
                    && b.target == kind.as_str()
                    && b.state == BreakerState::Open
            })
            .map(|b| b.reason.clone())
    }

    fn is_open_agent(&self, agent_id: &str) -> Option<String> {
        let guard = self
            .inner
            .breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .find(|b| {
                b.scope == BreakerScope::Agent
                    && b.target == agent_id
                    && b.state == BreakerState::Open
            })
            .map(|b| b.reason.clone())
    }

    fn open(&self, spec: CircuitBreaker) -> Result<(), BreakerError> {
        if spec.target.trim().is_empty() {
            return Err(BreakerError::InvalidTarget {
                reason: "target must be non-empty".to_string(),
            });
        }
        if spec.target.len() > MAX_TARGET_LEN {
            return Err(BreakerError::InvalidTarget {
                reason: format!("target exceeds MAX_TARGET_LEN ({MAX_TARGET_LEN} bytes)"),
            });
        }
        if spec.reason.len() > MAX_REASON_LEN {
            return Err(BreakerError::InvalidTarget {
                reason: format!("reason exceeds MAX_REASON_LEN ({MAX_REASON_LEN} bytes)"),
            });
        }
        // Reject ANSI escape / control / BIDI chars in reason — it's fanned out to
        // subscribers and may be rendered in operator logs/TTYs (R7 Info finding).
        if spec.reason.chars().any(|c| {
            c.is_control()
                || ('\u{200B}'..='\u{200F}').contains(&c)
                || ('\u{202A}'..='\u{202E}').contains(&c)
                || ('\u{2060}'..='\u{2064}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
                || c == '\u{FEFF}'
        }) {
            return Err(BreakerError::InvalidTarget {
                reason: "reason contains control, zero-width, or BIDI-override characters"
                    .to_string(),
            });
        }
        // Target charset: ASCII alphanumeric + `-_.:/` — covers capability names,
        // agent IDs, and component-type identifiers. This is an allow-list, which
        // defeats the entire class of Unicode Cf-based bypasses (SOFT HYPHEN,
        // ARABIC LETTER MARK, BIDI overrides, zero-width joins, BOM, etc.) as
        // well as whitespace-padding silent-bypass attacks (R8 finding).
        if !spec
            .target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
        {
            return Err(BreakerError::InvalidTarget {
                reason: "target must be ASCII alphanumeric + [-_.:/] only".to_string(),
            });
        }
        // For ComponentType-scoped breakers, target MUST be one of the canonical
        // ComponentType::as_str() values — otherwise is_open_component_type()
        // will silently never match and the breaker becomes a no-op.
        if spec.scope == BreakerScope::ComponentType
            && !matches!(
                spec.target.as_str(),
                "agent" | "cron" | "watcher" | "daemon" | "task"
            )
        {
            return Err(BreakerError::InvalidTarget {
                reason: format!(
                    "ComponentType target must be one of agent|cron|watcher|daemon|task (got: {:?})",
                    spec.target
                ),
            });
        }
        if spec.state != BreakerState::Open {
            return Err(BreakerError::InvalidTransition {
                from: spec.state,
                to: BreakerState::Open,
            });
        }
        let event = BreakerEvent {
            scope: spec.scope,
            target: spec.target.clone(),
            new_state: BreakerState::Open,
            reason: spec.reason.clone(),
            kill_existing: spec.kill_existing,
            timestamp: Utc::now(),
        };
        {
            let mut w = self
                .inner
                .breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(i) = w
                .iter()
                .position(|b| b.scope == spec.scope && b.target == spec.target)
            {
                w[i] = spec;
            } else {
                w.push(spec);
            }
        }
        self.emit(event);
        Ok(())
    }

    fn close(&self, scope: BreakerScope, target: &str) -> Result<(), BreakerError> {
        let event;
        {
            let mut w = self
                .inner
                .breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            match w
                .iter()
                .position(|b| b.scope == scope && b.target == target)
            {
                Some(i) => {
                    let removed = w.remove(i);
                    event = BreakerEvent {
                        scope,
                        target: target.to_string(),
                        new_state: BreakerState::Closed,
                        // Carry the original reason (audit trail).
                        reason: removed.reason,
                        kill_existing: removed.kill_existing,
                        timestamp: Utc::now(),
                    };
                }
                None => {
                    return Err(BreakerError::NotFound {
                        scope,
                        target: target.to_string(),
                    });
                }
            }
        }
        self.emit(event);
        Ok(())
    }

    fn half_open(&self, scope: BreakerScope, target: &str) -> Result<(), BreakerError> {
        let event;
        {
            let mut w = self
                .inner
                .breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            match w
                .iter_mut()
                .find(|b| b.scope == scope && b.target == target)
            {
                Some(b) => {
                    b.state = BreakerState::HalfOpen;
                    event = BreakerEvent {
                        scope,
                        target: target.to_string(),
                        new_state: BreakerState::HalfOpen,
                        reason: b.reason.clone(),
                        kill_existing: b.kill_existing,
                        timestamp: Utc::now(),
                    };
                }
                None => {
                    return Err(BreakerError::NotFound {
                        scope,
                        target: target.to_string(),
                    });
                }
            }
        }
        self.emit(event);
        Ok(())
    }

    fn subscribe(&self) -> mpsc::UnboundedReceiver<BreakerEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut subs = self
            .inner
            .subscribers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        subs.retain(|s| !s.is_closed());
        subs.push(tx);
        rx
    }
}
