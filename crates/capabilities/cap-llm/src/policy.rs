//! Per-agent LLM policy port (lane agent-llm-policy, 2026-09-16).
//!
//! An agent's territory may pin the provider it talks to, the model it asks for by default,
//! and a hard placement constraint (`<workspace>/.agent/config.yaml` `llm:` block, parsed by
//! the cli). The gateway consults an [`AgentLlmPolicySource`] on every request BEFORE
//! placement:
//!
//! - `provider` narrows the candidate provider list to that one id. An id that is not in the
//!   live `llm-providers` list FAILS CLOSED (`LlmError::ModelNotAvailable`) — the gateway never
//!   silently falls back to the first configured provider for a pinned agent.
//! - `model` is the agent's default model hint; an explicit per-call `ChatParams.model` wins.
//! - `constraint` is appended to the request's hard placement constraints
//!   (`always-local` / `never-cloud` / `device:<id>`).
//!
//! Every field is optional. A source that answers `None` (the [`NotWiredAgentLlmPolicy`]
//! default, and every agent without an `llm:` block) leaves the request byte-identical to the
//! pre-lane behaviour; the only observable difference is the `llm.request` payload's
//! `policy_source` key (`"default"` vs `"agent"`).

use crate::placement::UserHardConstraint;

/// Bound on a `device:<id>` id (`^[A-Za-z0-9_.:-]{1,128}$`).
pub const MAX_DEVICE_ID_LEN: usize = 128;

/// The resolved policy for one agent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentLlmPolicy {
    /// An `llm-providers[].id` the agent is pinned to.
    pub provider: Option<String>,
    /// The agent's default model hint (an alias key or a literal model id).
    pub model: Option<String>,
    /// A hard placement constraint applied to every request of the agent.
    pub constraint: Option<UserHardConstraint>,
}

impl AgentLlmPolicy {
    /// `true` when no field is set (the block is present but empty — equivalent to absent).
    pub fn is_empty(&self) -> bool {
        self.provider.is_none() && self.model.is_none() && self.constraint.is_none()
    }
}

/// Where a request's provider/model/constraint came from — carried on the request context and
/// emitted in the `llm.request` payload as `policy_source`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LlmPolicySource {
    /// No agent policy field applied (today's behaviour).
    #[default]
    Default,
    /// At least one field of the agent's `llm:` policy applied.
    Agent,
}

impl LlmPolicySource {
    /// The wire spelling used in the `llm.request` payload.
    pub fn as_str(self) -> &'static str {
        match self {
            LlmPolicySource::Default => "default",
            LlmPolicySource::Agent => "agent",
        }
    }
}

/// The per-agent policy port the gateway consults. Implementations must be cheap per call
/// (the cli adapter stats the agent's config file and re-reads only on an mtime change).
pub trait AgentLlmPolicySource: Send + Sync {
    /// The policy for `agent_id` (the BARE cap agent id the host-fn context carries), or `None`
    /// when the agent has no valid policy.
    fn policy_for(&self, agent_id: &str) -> Option<AgentLlmPolicy>;
}

/// The default source: no agent has a policy. Byte-identical to the pre-lane gateway.
pub struct NotWiredAgentLlmPolicy;

impl AgentLlmPolicySource for NotWiredAgentLlmPolicy {
    fn policy_for(&self, _agent_id: &str) -> Option<AgentLlmPolicy> {
        None
    }
}

/// Why a constraint string failed [`parse_constraint`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstraintParseError {
    /// Not one of `always-local` / `never-cloud` / `device:<id>`.
    UnknownConstraint(String),
    /// `device:` with an empty, over-long, or badly-charset id.
    InvalidDeviceId(String),
}

impl std::fmt::Display for ConstraintParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConstraintParseError::UnknownConstraint(s) => write!(
                f,
                "unknown llm constraint {s:?} (expected always-local | never-cloud | device:<id>)"
            ),
            ConstraintParseError::InvalidDeviceId(s) => {
                write!(f, "invalid device id in llm constraint {s:?}")
            }
        }
    }
}

impl std::error::Error for ConstraintParseError {}

/// Is `id` a well-formed `device:<id>` id (`^[A-Za-z0-9_.:-]{1,128}$`)?
pub fn is_valid_device_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_DEVICE_ID_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

/// Parse the `llm.constraint` grammar: `always-local` | `never-cloud` | `device:<id>`.
/// Exact, case-sensitive, no surrounding whitespace.
pub fn parse_constraint(s: &str) -> Result<UserHardConstraint, ConstraintParseError> {
    match s {
        "always-local" => Ok(UserHardConstraint::AlwaysLocal),
        "never-cloud" => Ok(UserHardConstraint::NeverCloud),
        _ => match s.strip_prefix("device:") {
            Some(id) if is_valid_device_id(id) => Ok(UserHardConstraint::DevicePin(id.to_string())),
            Some(_) => Err(ConstraintParseError::InvalidDeviceId(s.to_string())),
            None => Err(ConstraintParseError::UnknownConstraint(s.to_string())),
        },
    }
}

/// Render a constraint back to its grammar spelling (the inverse of [`parse_constraint`]).
pub fn constraint_to_string(c: &UserHardConstraint) -> String {
    match c {
        UserHardConstraint::AlwaysLocal => "always-local".to_string(),
        UserHardConstraint::NeverCloud => "never-cloud".to_string(),
        UserHardConstraint::DevicePin(id) => format!("device:{id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constraint_grammar_table() {
        assert_eq!(
            parse_constraint("always-local"),
            Ok(UserHardConstraint::AlwaysLocal)
        );
        assert_eq!(
            parse_constraint("never-cloud"),
            Ok(UserHardConstraint::NeverCloud)
        );
        assert_eq!(
            parse_constraint("device:mac-studio.local:1"),
            Ok(UserHardConstraint::DevicePin("mac-studio.local:1".into()))
        );
        for bad in [
            "",
            "always_local",
            "Always-Local",
            " always-local",
            "never-cloud ",
            "cloud-only",
            "device",
            "device:",
            "device: mac",
            "device:mac studio",
            "device:mac/1",
        ] {
            assert!(parse_constraint(bad).is_err(), "{bad:?}");
        }
        assert!(parse_constraint(&format!("device:{}", "x".repeat(MAX_DEVICE_ID_LEN))).is_ok());
        assert!(matches!(
            parse_constraint(&format!("device:{}", "x".repeat(MAX_DEVICE_ID_LEN + 1))),
            Err(ConstraintParseError::InvalidDeviceId(_))
        ));
        assert!(matches!(
            parse_constraint("gpu-only"),
            Err(ConstraintParseError::UnknownConstraint(_))
        ));
    }

    #[test]
    fn constraint_round_trips() {
        for s in ["always-local", "never-cloud", "device:phone"] {
            assert_eq!(constraint_to_string(&parse_constraint(s).unwrap()), s);
        }
    }

    #[test]
    fn not_wired_source_answers_none() {
        assert!(NotWiredAgentLlmPolicy.policy_for("any").is_none());
        assert!(AgentLlmPolicy::default().is_empty());
        assert_eq!(LlmPolicySource::default(), LlmPolicySource::Default);
        assert_eq!(LlmPolicySource::Default.as_str(), "default");
        assert_eq!(LlmPolicySource::Agent.as_str(), "agent");
    }
}
