//! AC-15 caller-dependency policy abstraction (cap-secrets-internal).
//!
//! `CallerDependencyPolicy` answers: "given a `HostCallContext` describing
//! the caller, has that caller DECLARED a dependency on this secret name?"
//! The policy is consulted by [`crate::host_fn::GatedSecretExistsHandler`]
//! **before** the storage probe, so undeclared secret names never reach
//! `InMemorySecretStorage::exists` (§3.6 timing-side-channel defense
//! depth — locked by `tests/dep_check.rs::T15e`).
//!
//! PRODUCTION wiring (Wave-18 Lane-3, MODULE-012-AC-15): the cli composition
//! root builds a [`DeclaredDependencyPolicy`] from the `secrets.dependencies`
//! config map (`<bare-agent-id> → [secret-name]`) and registers the gated
//! handler via [`crate::host_fn::register_agent_secrets_with_policy`] when that
//! map is non-empty, else the permissive
//! [`crate::host_fn::register_agent_secrets`] (operator-opt-in; an absent map
//! reproduces the pre-Wave-18 default-permissive behaviour byte-identically).
//! The policy keys on the already-populated `HostCallContext.agent_id` (the
//! production-stamped bare cap id, e.g. `default-agent`) — NOT per-call
//! `CapParams`. A future MODULE-001 slice that threads each caller's
//! *self-declared* `CapParams` list through `CapabilityInjector::inject` would
//! let an agent narrow its OWN allowlist at call time; the operator-config
//! basis shipped here is the trusted-operator complement (see MODULE-012 §3.6).

use std::collections::{HashMap, HashSet};

use advance_runtime::host_registry::HostCallContext;

/// Caller-side dependency policy consulted by [`crate::host_fn::GatedSecretExistsHandler`].
///
/// Implementations MUST be deterministic (same `(ctx, name)` → same answer)
/// and side-effect-free. Send + Sync + 'static is required so the policy
/// can live inside an `Arc<dyn CallerDependencyPolicy>` field on the handler.
pub trait CallerDependencyPolicy: Send + Sync + 'static {
    /// Returns `true` if the caller identified by `ctx` has DECLARED a
    /// dependency on the secret named `name`. Returns `false` otherwise
    /// (fail-closed for unknown callers / undeclared names).
    fn permits(&self, ctx: &HostCallContext, name: &str) -> bool;
}

/// Permissive default — every caller can probe every secret.
///
/// Backwards-compatible with Slice A semantics (the existing
/// [`crate::host_fn::SecretExistsHandler`] is structurally equivalent to a
/// `GatedSecretExistsHandler` wrapping this policy). Used as the
/// drop-in default for callsites that don't yet have a real declared-secret
/// list to plumb.
pub struct AllowAllCallerDependencyPolicy;

impl CallerDependencyPolicy for AllowAllCallerDependencyPolicy {
    fn permits(&self, _ctx: &HostCallContext, _name: &str) -> bool {
        true
    }
}

/// Declarative allowlist keyed by `HostCallContext.agent_id`.
///
/// Lookup is O(1): HashMap-by-agent_id + HashSet-by-secret-name. Unknown
/// `agent_id` → deny (fail-closed). Production constructs this from the
/// `secrets.dependencies` config map at boot (Wave-18 Lane-3, keyed on the
/// bare production-stamped `HostCallContext.agent_id`); a future MODULE-001
/// slice may additionally thread per-call `CapParams` through `HostCallContext`
/// at WASM Store construction time for agent-self-declared narrowing.
pub struct DeclaredDependencyPolicy {
    by_agent: HashMap<String, HashSet<String>>,
}

impl DeclaredDependencyPolicy {
    /// Build from a fully-populated map.
    pub fn new(by_agent: HashMap<String, HashSet<String>>) -> Self {
        Self { by_agent }
    }

    /// Convenience builder for the single-caller case.
    pub fn for_agent(agent_id: impl Into<String>, allowed: Vec<String>) -> Self {
        let mut by_agent = HashMap::new();
        by_agent.insert(agent_id.into(), allowed.into_iter().collect());
        Self { by_agent }
    }
}

impl CallerDependencyPolicy for DeclaredDependencyPolicy {
    fn permits(&self, ctx: &HostCallContext, name: &str) -> bool {
        self.by_agent
            .get(ctx.agent_id.as_str())
            .map(|allowed| allowed.contains(name))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_for(agent_id: &str) -> HostCallContext {
        HostCallContext {
            agent_id: agent_id.into(),
            trace_id: "test-trace".into(),
            turn_id: None,
            capability: "secrets".into(),
            function: "advance:runtime/agent-secrets::secret-exists".into(),
            run_id: None,
            iteration: None,
        }
    }

    // T15a: AllowAll permits any (ctx, name) — locks the permissive
    // default's Slice-A backwards-compat invariant.
    #[test]
    fn t15a_allow_all_permits_any_caller_and_name() {
        let policy = AllowAllCallerDependencyPolicy;
        assert!(policy.permits(&ctx_for("any-agent"), "k"));
        assert!(policy.permits(&ctx_for(""), ""));
        assert!(policy.permits(&ctx_for("agent-b"), "another-secret"));
    }

    // T15b: DeclaredDependencyPolicy accepts the declared name, rejects
    // everything else, and fails closed on unknown agent_id.
    #[test]
    fn t15b_declared_policy_admits_only_allowlisted_pairs() {
        let policy = DeclaredDependencyPolicy::for_agent("agent-a", vec!["allowed".into()]);

        assert!(policy.permits(&ctx_for("agent-a"), "allowed"));
        assert!(
            !policy.permits(&ctx_for("agent-a"), "other"),
            "declared agent should still reject non-allowlisted name"
        );
        assert!(
            !policy.permits(&ctx_for("agent-b"), "allowed"),
            "unknown agent_id must fail closed (HashMap::get returns None)"
        );
    }
}
