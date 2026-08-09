//! `SecretExistsHandler` + `GatedSecretExistsHandler`:
//! implementations of MODULE-001's `HostFunctionHandler` trait.
//!
//! Both return `Val::Result(Ok(Some(Box::new(Val::Bool(_)))))` on the
//! happy path, matching Wasmtime 43's tuple-form `Val::Result(Result<
//! Option<Box<Val>>, Option<Box<Val>>>)` encoding for the WIT type
//! `result<bool, secret-error>` declared in MODULE-012 §2.3.
//!
//! - `SecretExistsHandler` (Slice A): permissive — every caller can
//!   probe every secret. Wired by the cli composition root
//!   (`register_secrets_capability` → `register_agent_secrets`) when no
//!   `secrets.dependencies` are configured (the operator-opt-in default).
//! - `GatedSecretExistsHandler` (m012-slice-e): consults a
//!   `CallerDependencyPolicy` BEFORE the storage probe and returns
//!   `Val::Result(Err(Some(Box::new(Val::Variant("permission-denied",
//!   Some(Box::new(Val::String(reason))))))))` on the rejected path.
//!   PRODUCTION-wired (Wave-18 Lane-3, MODULE-012-AC-15): the cli
//!   composition root builds a `DeclaredDependencyPolicy` from the
//!   `secrets.dependencies` config map (keyed on the bare
//!   `HostCallContext.agent_id`) and registers this handler via
//!   `register_agent_secrets_with_policy` whenever that map is non-empty.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use wasmtime::component::Val;

use crate::caller_dep::CallerDependencyPolicy;
use crate::error::sanitize_identifier;
use crate::store::SecretStore;

/// Maximum length (UTF-8 bytes) accepted by `secret-exists` for the
/// `name` parameter. Bounds a compromised WASM guest from invoking the
/// handler with multi-megabyte strings that would cause an unbounded
/// clone + HashMap hash on every call (DoS defense). 512 bytes is an
/// order-of-magnitude larger than any plausible secret-name convention
/// and matches the `HostFunctionSpec` string-length ceilings in
/// MODULE-001 (`MAX_SPEC_STRING_LEN = 256`).
pub const MAX_SECRET_NAME_BYTES: usize = 512;

/// Slice A permissive handler — `_ctx` is intentionally ignored.
///
/// Continues to back `register_agent_secrets` for the operator-opt-in
/// default wiring (cli `register_secrets_capability` selects it when no
/// `secrets.dependencies` are configured). For the caller-dependency-gated
/// variant, use [`GatedSecretExistsHandler`] +
/// [`register_agent_secrets_with_policy`].
pub struct SecretExistsHandler {
    pub store: Arc<SecretStore>,
}

impl HostFunctionHandler for SecretExistsHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let name = parse_secret_exists_params(&params, results_len)?;
            let exists = store
                .exists(&name)
                .map_err(|e| HostCallError::HandlerError(format!("{e}")))?;
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::Bool(exists)))))])
        })
    }
}

/// m012-slice-e gated handler — consults `CallerDependencyPolicy::permits`
/// BEFORE invoking `SecretStore::exists`.
///
/// On reject, returns the WIT `secret-error::permission-denied(string)`
/// variant inside the outer `result<bool, secret-error>::Err` arm. The
/// reason string includes the `sanitize_identifier`-cleaned secret name
/// (printable ASCII only, max 128 chars — defangs log-injection on
/// attacker-controllable inputs). The reject path NEVER touches the
/// `SecretStore` — `tests/dep_check.rs::T15e` proves this causally
/// via a `SpyingSecretStorage` wrapper (timing-side-channel defense
/// depth — see MODULE-012 §3.6 "Timing side channel on `secret-exists`").
pub struct GatedSecretExistsHandler {
    pub store: Arc<SecretStore>,
    pub policy: Arc<dyn CallerDependencyPolicy>,
}

impl GatedSecretExistsHandler {
    /// Build a gated handler with the given store + policy.
    pub fn new(store: Arc<SecretStore>, policy: Arc<dyn CallerDependencyPolicy>) -> Self {
        Self { store, policy }
    }
}

impl HostFunctionHandler for GatedSecretExistsHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let policy = Arc::clone(&self.policy);
        Box::pin(async move {
            // Shared parse: results_len + single Val::String + MAX_SECRET_NAME_BYTES.
            let name = parse_secret_exists_params(&params, results_len)?;

            // AC-15 dep-check: caller must have a DECLARED dependency on `name`.
            // Reject by returning the WIT secret-error::permission-denied
            // variant. The reason string includes the sanitize_identifier-
            // cleaned name so log aggregators don't see attacker-controllable
            // control codepoints. CRITICAL: the policy check fires BEFORE
            // `store.exists(&name)` — undeclared names never reach storage,
            // narrowing the §3.6 timing-side-channel oracle.
            if !policy.permits(&ctx, &name) {
                let sanitized = sanitize_identifier(&name);
                let reason = format!("secret '{sanitized}' not declared by caller");
                return Ok(vec![Val::Result(Err(Some(Box::new(Val::Variant(
                    "permission-denied".to_string(),
                    Some(Box::new(Val::String(reason))),
                )))))]);
            }

            let exists = store
                .exists(&name)
                .map_err(|e| HostCallError::HandlerError(format!("{e}")))?;
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::Bool(exists)))))])
        })
    }
}

/// Register the `agent-secrets::secret-exists` host function into the
/// given `HostRegistry` under capability `"secrets"` — **permissive**
/// (Slice-A behavior). Every caller can probe every secret.
///
/// AC-16 is waived in Slice A (production `component_loader` does not
/// yet route through `CapabilityInjector::inject`), so this function
/// is shipped as a library primitive ready for the MODULE-001 wire-up.
pub fn register_agent_secrets(registry: &dyn HostRegistry, store: Arc<SecretStore>) {
    registry.register(HostFunctionSpec {
        capability: "secrets".to_string(),
        namespace: "advance:runtime/agent-secrets@0.1.0".to_string(),
        name: "secret-exists".to_string(),
        handler: Arc::new(SecretExistsHandler { store }),
        idempotent: true,
    });
}

/// Register the `agent-secrets::secret-exists` host function with a
/// caller-dependency policy — **gated** (m012-slice-e behavior).
/// Calls that fail `policy.permits(ctx, name)` return the WIT
/// `permission-denied(string)` variant; calls that pass proceed to the
/// storage probe identically to [`register_agent_secrets`].
///
/// PRODUCTION-wired (Wave-18 Lane-3): the cli composition root
/// (`register_secrets_capability`) calls this with a `DeclaredDependencyPolicy`
/// built from the `secrets.dependencies` config map — see MODULE-012 §3.6.
pub fn register_agent_secrets_with_policy(
    registry: &dyn HostRegistry,
    store: Arc<SecretStore>,
    policy: Arc<dyn CallerDependencyPolicy>,
) {
    registry.register(HostFunctionSpec {
        capability: "secrets".to_string(),
        namespace: "advance:runtime/agent-secrets@0.1.0".to_string(),
        name: "secret-exists".to_string(),
        handler: Arc::new(GatedSecretExistsHandler { store, policy }),
        idempotent: true,
    });
}

/// Shared parse + bounds-check for both handler implementations. Validates
/// (a) results_len == 1; (b) exactly one `Val::String` parameter; (c) the
/// string length is ≤ `MAX_SECRET_NAME_BYTES`. Returns the owned String on
/// success.
///
/// Error-message strings are preserved character-for-character so the
/// existing `test_handler_rejects_oversized_name` assertions continue to
/// hold after this refactor.
fn parse_secret_exists_params(params: &[Val], results_len: usize) -> Result<String, HostCallError> {
    if results_len != 1 {
        return Err(HostCallError::HandlerError(format!(
            "expected results_len == 1 for secret-exists, got {results_len}"
        )));
    }
    match params {
        [Val::String(s)] => {
            if s.len() > MAX_SECRET_NAME_BYTES {
                return Err(HostCallError::HandlerError(format!(
                    "secret name exceeds MAX_SECRET_NAME_BYTES ({MAX_SECRET_NAME_BYTES})"
                )));
            }
            Ok(s.clone())
        }
        _ => Err(HostCallError::HandlerError(
            "expected single Val::String parameter".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{InMemorySecretStorage, SecretStorage};
    use zeroize::Zeroizing;

    fn make_store() -> Arc<SecretStore> {
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let store = SecretStore::new(Zeroizing::new([0xab; 32]), storage);
        store.store("existing_key", "v").unwrap();
        Arc::new(store)
    }

    fn test_ctx() -> HostCallContext {
        HostCallContext {
            agent_id: "test-agent".into(),
            trace_id: "test-trace".into(),
            turn_id: None,
            capability: "secrets".into(),
            function: "advance:runtime/agent-secrets::secret-exists".into(),
            run_id: None,
            iteration: None,
        }
    }

    // T01: handler-level unit test — bool-only Val shape.
    #[tokio::test]
    async fn t01_handler_returns_bool_only_shape() {
        let handler = SecretExistsHandler {
            store: make_store(),
        };

        // Case A: existing key → Ok(Some(Bool(true)))
        let out = handler
            .call(test_ctx(), vec![Val::String("existing_key".into())], 1)
            .await
            .expect("handler call should succeed");
        assert_eq!(out.len(), 1);
        match &out[0] {
            Val::Result(Ok(Some(inner))) => match inner.as_ref() {
                Val::Bool(b) => assert!(*b, "existing key → Bool(true)"),
                other => panic!("expected Val::Bool, got {other:?}"),
            },
            other => panic!("expected Val::Result(Ok(Some(_))), got {other:?}"),
        }

        // Case B: absent key → Ok(Some(Bool(false)))
        let out = handler
            .call(test_ctx(), vec![Val::String("absent_key".into())], 1)
            .await
            .expect("handler call should succeed");
        assert_eq!(out.len(), 1);
        match &out[0] {
            Val::Result(Ok(Some(inner))) => match inner.as_ref() {
                Val::Bool(b) => assert!(!*b, "absent key → Bool(false)"),
                other => panic!("expected Val::Bool, got {other:?}"),
            },
            other => panic!("expected Val::Result(Ok(Some(_))), got {other:?}"),
        }
    }

    // DoS-defense regression: unbounded name parameter rejected.
    #[tokio::test]
    async fn test_handler_rejects_oversized_name() {
        let handler = SecretExistsHandler {
            store: make_store(),
        };
        let big = "x".repeat(MAX_SECRET_NAME_BYTES + 1);
        let err = handler
            .call(test_ctx(), vec![Val::String(big)], 1)
            .await
            .expect_err("should reject oversized name");
        let msg = format!("{err}");
        assert!(
            msg.contains("MAX_SECRET_NAME_BYTES"),
            "expected MAX_SECRET_NAME_BYTES error, got {msg}"
        );
    }

    // Register the spec and look it up via HostRegistry. Verifies the
    // library-side of AC-16 without touching production
    // component_loader (which is waived in this slice).
    #[test]
    fn test_register_agent_secrets_lookup() {
        use advance_runtime::host_registry::InMemoryHostRegistry;

        let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
        register_agent_secrets(&*registry, make_store());

        let specs = registry.lookup("secrets");
        assert!(
            !specs.is_empty(),
            "registry should have at least one spec under 'secrets'"
        );
        let spec = &specs[0];
        assert_eq!(spec.namespace, "advance:runtime/agent-secrets@0.1.0");
        assert_eq!(spec.name, "secret-exists");
        assert_eq!(spec.capability, "secrets");
        assert!(spec.idempotent);
    }
}
