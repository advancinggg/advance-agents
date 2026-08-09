//! T15c..T15g — m012-slice-e AC-15 integration tests for
//! `GatedSecretExistsHandler` + `CallerDependencyPolicy`.
//!
//! T15a/T15b cover the policy impls directly (inline in
//! `cap-secrets/src/caller_dep.rs#[cfg(test)]`). This file covers the
//! handler-level shape: Val tree encoding (Ok-arm + permission-denied
//! Err-arm), sanitization defense on the reject reason string, the
//! fail-closed unknown-agent path, and the causal proof that the policy
//! check fires BEFORE the storage probe (via the `SpyingSecretStorage`
//! wrapper — see MODULE-012 §3.6 timing-side-channel defense depth).

use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use cap_secrets::{
    DeclaredDependencyPolicy, GatedSecretExistsHandler, InMemorySecretStorage, SecretStorage,
    SecretStore, StorageError, StoredSecret,
};
use wasmtime::component::Val;
use zeroize::Zeroizing;

/// Storage wrapper that records each `exists(name)` invocation into a
/// shared log. Delegates put/get/exists to the inner `InMemorySecretStorage`.
/// Used by T15e to PROVE causally that the policy check fires BEFORE
/// `SecretStore::exists` — undeclared names must never appear in `exists_log`.
struct SpyingSecretStorage {
    inner: InMemorySecretStorage,
    exists_log: Arc<Mutex<Vec<String>>>,
}

impl SpyingSecretStorage {
    fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let spy = Self {
            inner: InMemorySecretStorage::new(),
            exists_log: Arc::clone(&log),
        };
        (spy, log)
    }
}

impl SecretStorage for SpyingSecretStorage {
    fn put(&self, name: &str, stored: StoredSecret) -> Result<(), StorageError> {
        self.inner.put(name, stored)
    }
    fn get(&self, name: &str) -> Result<Option<StoredSecret>, StorageError> {
        self.inner.get(name)
    }
    fn exists(&self, name: &str) -> Result<bool, StorageError> {
        self.exists_log.lock().unwrap().push(name.to_string());
        self.inner.exists(name)
    }
}

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

/// Build a `SecretStore` over the supplied storage, seeded with the given
/// `(name, value)` pairs.
fn make_store_with(storage: Arc<dyn SecretStorage>, secrets: &[(&str, &str)]) -> Arc<SecretStore> {
    let store = SecretStore::new(Zeroizing::new([0xab; 32]), storage);
    for (name, value) in secrets {
        store.store(name, value).expect("seed secret");
    }
    Arc::new(store)
}

/// Extract the inner Val::String reason from a permission-denied Val tree.
/// Asserts the exact shape `Val::Result(Err(Some(Box::new(Val::Variant(
/// "permission-denied", Some(Box::new(Val::String(reason))))))))` and
/// returns `reason` cloned.
fn extract_permission_denied_reason(out: &[Val]) -> String {
    assert_eq!(out.len(), 1, "secret-exists must return exactly one Val");
    let outer = match &out[0] {
        Val::Result(Err(Some(inner))) => inner.as_ref(),
        other => panic!("expected Val::Result(Err(Some(_))), got {other:?}"),
    };
    let (case, payload) = match outer {
        Val::Variant(case, payload) => (case, payload.as_deref()),
        other => panic!("expected Val::Variant, got {other:?}"),
    };
    assert_eq!(case, "permission-denied", "WIT variant case mismatch");
    match payload {
        Some(Val::String(reason)) => reason.clone(),
        other => panic!("expected Variant payload Some(Val::String), got {other:?}"),
    }
}

// T15c: gated handler returns Ok(Bool(true)) for a declared name when the
// store contains that secret.
#[tokio::test]
async fn t15c_declared_name_returns_ok_bool_true() {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let store = make_store_with(storage, &[("allowed_secret", "v")]);
    let policy = DeclaredDependencyPolicy::for_agent("test-agent", vec!["allowed_secret".into()]);
    let handler = GatedSecretExistsHandler::new(store, Arc::new(policy));

    let out = handler
        .call(
            ctx_for("test-agent"),
            vec![Val::String("allowed_secret".into())],
            1,
        )
        .await
        .expect("declared call should succeed");

    assert_eq!(out.len(), 1);
    match &out[0] {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::Bool(b) => assert!(*b, "declared + stored → Bool(true)"),
            other => panic!("expected Val::Bool, got {other:?}"),
        },
        other => panic!("expected Val::Result(Ok(Some(Bool))), got {other:?}"),
    }
}

// T15d: gated handler returns the permission-denied Val variant for a
// non-allowlisted name (declared-policy path).
#[tokio::test]
async fn t15d_undeclared_name_returns_permission_denied_variant() {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let store = make_store_with(storage, &[("other_secret", "v")]);
    let policy = DeclaredDependencyPolicy::for_agent("test-agent", vec!["allowed_secret".into()]);
    let handler = GatedSecretExistsHandler::new(store, Arc::new(policy));

    let out = handler
        .call(
            ctx_for("test-agent"),
            vec![Val::String("other_secret".into())],
            1,
        )
        .await
        .expect("rejection is encoded as a Val variant, not HostCallError");

    let reason = extract_permission_denied_reason(&out);
    assert!(
        reason.starts_with("secret '"),
        "reason should start with 'secret \\'': {reason}"
    );
    assert!(
        reason.contains("not declared by caller"),
        "reason should include 'not declared by caller': {reason}"
    );
    // No raw control codepoints in the reason — the name 'other_secret'
    // is all-printable, so sanitize_identifier is a no-op here.
    assert!(reason.is_ascii(), "reason must be ASCII for this case");
}

// T15e: causal proof — policy check precedes storage probe.
// Undeclared names MUST NOT reach `SecretStorage::exists` (timing-side-
// channel defense depth, MODULE-012 §3.6). Companion happy-path assertion
// proves the policy-permits → storage-probe order.
#[tokio::test]
async fn t15e_policy_check_precedes_storage_probe() {
    // --- denied path: spy must remain untouched ---
    let (spy_denied, log_denied) = SpyingSecretStorage::new();
    let storage_denied: Arc<dyn SecretStorage> = Arc::new(spy_denied);
    let store_denied = make_store_with(storage_denied, &[]);
    // Empty allowlist — every name denied.
    let policy_denied = DeclaredDependencyPolicy::for_agent("test-agent", Vec::<String>::new());
    let handler_denied = GatedSecretExistsHandler::new(store_denied, Arc::new(policy_denied));

    let out = handler_denied
        .call(
            ctx_for("test-agent"),
            vec![Val::String("any_secret".into())],
            1,
        )
        .await
        .expect("rejection encoded as Val variant");
    let _ = extract_permission_denied_reason(&out);

    let exists_calls_denied: Vec<String> = log_denied.lock().unwrap().clone();
    assert!(
        exists_calls_denied.is_empty(),
        "denied path MUST NOT touch SecretStorage::exists; saw {exists_calls_denied:?}"
    );

    // --- permitted path: spy must record exactly one exists("k") call ---
    let (spy_ok, log_ok) = SpyingSecretStorage::new();
    let storage_ok: Arc<dyn SecretStorage> = Arc::new(spy_ok);
    let store_ok = make_store_with(storage_ok, &[("k", "v")]);
    let policy_ok = DeclaredDependencyPolicy::for_agent("test-agent", vec!["k".into()]);
    let handler_ok = GatedSecretExistsHandler::new(store_ok, Arc::new(policy_ok));

    let out_ok = handler_ok
        .call(ctx_for("test-agent"), vec![Val::String("k".into())], 1)
        .await
        .expect("permitted call should succeed");
    match &out_ok[0] {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::Bool(b) => assert!(*b, "permitted + stored → Bool(true)"),
            other => panic!("expected Val::Bool, got {other:?}"),
        },
        other => panic!("expected Val::Result(Ok(Some(Bool))), got {other:?}"),
    }

    let exists_calls_ok: Vec<String> = log_ok.lock().unwrap().clone();
    assert_eq!(
        exists_calls_ok,
        vec!["k".to_string()],
        "permitted path must reach storage exactly once with the declared name"
    );
}

// T15f: sanitization defense — reject reason scrubs control codepoints.
// Attacker-controllable name carrying newline / ESC / BEL / bidi RLO must
// NOT appear verbatim in the reason string (locks the
// `sanitize_identifier` invocation on the reject path).
#[tokio::test]
async fn t15f_reject_reason_strips_control_codepoints() {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let store = make_store_with(storage, &[]);
    // Empty allowlist — every name denied.
    let policy = DeclaredDependencyPolicy::for_agent("test-agent", Vec::<String>::new());
    let handler = GatedSecretExistsHandler::new(store, Arc::new(policy));

    let malicious = "api\n\x1b]0;X\x07\u{202e}";
    let out = handler
        .call(
            ctx_for("test-agent"),
            vec![Val::String(malicious.into())],
            1,
        )
        .await
        .expect("rejection encoded as Val variant");
    let reason = extract_permission_denied_reason(&out);

    assert!(
        !reason.contains('\n'),
        "newline must be sanitized: {reason:?}"
    );
    assert!(
        !reason.contains('\x1b'),
        "ESC must be sanitized: {reason:?}"
    );
    assert!(
        !reason.contains('\x07'),
        "BEL must be sanitized: {reason:?}"
    );
    assert!(
        !reason.contains('\u{202e}'),
        "bidi RLO must be sanitized: {reason:?}"
    );
    assert!(
        reason.starts_with("secret '"),
        "reason still starts with the canonical prefix: {reason}"
    );
}

// T15g: fail-closed on unknown agent_id (HashMap.get returns None →
// permits returns false). Verifies the policy table is keyed by
// `agent_id`, not by global "any agent that calls the handler".
#[tokio::test]
async fn t15g_unknown_agent_fails_closed() {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let store = make_store_with(storage, &[("k", "v")]);
    let policy = DeclaredDependencyPolicy::for_agent("agent-a", vec!["k".into()]);
    let handler = GatedSecretExistsHandler::new(store, Arc::new(policy));

    let out = handler
        .call(ctx_for("agent-b"), vec![Val::String("k".into())], 1)
        .await
        .expect("rejection encoded as Val variant");

    let reason = extract_permission_denied_reason(&out);
    assert!(
        reason.contains("not declared by caller"),
        "unknown agent_id must produce the canonical not-declared reason: {reason}"
    );
}
