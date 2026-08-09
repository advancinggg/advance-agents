//! AC-24 (MODULE-017 §1.4) — tool-retry idempotency gate + harness.
//!
//! `is_retry_allowed` is the predicate; `dispatch_with_retry` is the
//! retry loop. Both are crate-internal — the only production call site
//! is [`crate::lazy_registry::LazyToolRegistry::invoke`]. Helpers are
//! pure async/Rust (no Wasmtime, no engine) so they unit-test in
//! isolation — see MODULE-017 §3.6 (e) for the cargo-component-fixture
//! constraint that drives this design.
//!
//! Slice G scope reminder (MODULE-017 §3.6 (tt)):
//! - This module gates retry by the per-method `idempotent` flag only.
//! - `tool.retry` event emission is deferred (registry layer has no
//!   `Arc<dyn EventBusEmit>`; M019 §15.3.16 taxonomy alignment lands in
//!   a follow-on slice).
//! - Exponential backoff is deferred (the harness does zero-delay
//!   retry; REQ-067's "backoff" sub-requirement is satisfied LLM-side
//!   only via MODULE-009's `RetryConfig`).
//! - Together with MODULE-009's untested AC-05/AC-06, these are the
//!   three reasons REQ-067 stays `Partial` post-slice.

use crate::registry::{MethodInfo, ToolError};

/// Defensive upper bound on `LazyRegistryConfig.tool_invoke_max_retries`
/// applied inside [`dispatch_with_retry`] (audit round 1 W2 fix).
///
/// The field is `pub u32` on a `pub` struct so direct construction can
/// supply any value up to `u32::MAX` (~4.3 billion). Without a clamp,
/// `max_retries = u32::MAX` × `tool_invoke_timeout = 5s` (default) ×
/// a flaky idempotent method returning [`ToolError::InvocationFailed`]
/// would wedge a single `invoke()` for ~680 years. The runtime-side
/// `validate_config` clamp on sibling fields (`max_tool_instances ∈
/// [1, 1024]`) is in `runtime/src/config.rs` which is OUT of this
/// slice's scope — so we apply a defense-in-depth clamp at the
/// `dispatch_with_retry` entry instead. 100 retries × 5 s per attempt
/// = 8.3 min worst case (still long but bounded). Operators wanting
/// finer behaviour bridge `tool_invoke_timeout` smaller; operators
/// wanting more retries hit this internal ceiling.
///
/// This constant is `pub(crate)` because the harness is the only
/// production call site; documenting it on the field's rustdoc in
/// [`crate::lazy_registry::LazyRegistryConfig`] tells operators the
/// effective ceiling without exposing it as public API surface (a
/// future YAML-knob slice can choose whether to surface it).
pub(crate) const MAX_TOOL_INVOKE_RETRIES_CAP: u32 = 100;

/// AC-24 gate predicate.
///
/// Returns `true` iff (a) the method's `describe()`-declared
/// `idempotent` is explicitly `Some(true)` AND (b) the failure
/// belongs to a transient class — currently only
/// [`ToolError::InvocationFailed`]. Every other combination — flag is
/// `Some(false)` / `None`, or the error is a permanent class —
/// returns `false`.
///
/// The transient classification matches MODULE-017 §2.7 step 6's
/// guest-error classifier: `NotFound` / `MethodNotFound` /
/// `InputValidationFailed` / `OutputValidationFailed` /
/// `PermissionDenied` are all permanent (re-issuing the same call
/// with the same args yields the same error). `InvocationFailed` is
/// the catch-all transient bucket (host-side timeouts, transient WASM
/// traps, fuel exhaustion).
///
/// Tool-author contract: marking a method `idempotent: true` commits
/// the tool author to making EVERY `Err` from that method safe to
/// re-invoke. The `InvocationFailed` bucket is permissive — a
/// deterministic business-logic failure that didn't route through a
/// specific prefix (per §2.7 step 6) gets retried wastefully but
/// safely on idempotent methods. Tool authors who want fine-grained
/// retry control encode the failure shape in the guest-error string
/// prefix (`"input-validation-failed: ..."` routes to
/// [`ToolError::InputValidationFailed`] which the gate excludes).
pub(crate) fn is_retry_allowed(method: &MethodInfo, err: &ToolError) -> bool {
    method.idempotent == Some(true) && matches!(err, ToolError::InvocationFailed(_))
}

/// AC-24 retry harness.
///
/// Runs `attempt` up to `1 + min(max_retries, MAX_TOOL_INVOKE_RETRIES_CAP)`
/// times — the cap (currently 100) is a defense-in-depth bound applied
/// inside the harness so operators cannot wedge a single `invoke()`
/// call for unbounded wall-clock time via direct `LazyRegistryConfig`
/// construction (audit round 1 W2 fix; see
/// [`MAX_TOOL_INVOKE_RETRIES_CAP`] for the rationale). On each `Err`,
/// checks `should_retry(&err)`; if `false`, returns the error
/// immediately. If `true`, retries (no back-off — Slice G is minimal;
/// future slices can wrap this in a back-off policy if the surface
/// needs it per MODULE-017 §3.6 (tt) item 2). On the final attempt's
/// `Err`, returns that error.
///
/// `should_retry` is a closure (not a direct call to
/// [`is_retry_allowed`]) because the [`MethodInfo`] lookup happens at
/// the call site in [`crate::lazy_registry::LazyToolRegistry::invoke`]
/// — passing the resolved flag as a closure keeps the harness
/// pure-data and unit-testable.
///
/// `Send` bounds rationale: this helper is awaited inside
/// `#[async_trait] impl ToolRegistry for LazyToolRegistry`
/// (`lazy_registry.rs`'s impl block), and async_trait rewrites every
/// async fn body to return `Pin<Box<dyn Future + Send + 'async_trait>>`
/// because the trait declares `Send + Sync` supertraits
/// (`registry.rs:17`). All three type parameters carry `+ Send` so
/// the harness future composes inside the trait expansion; without
/// these bounds the rust compiler reports "future is not `Send`"
/// inside the async_trait expansion at every call site.
pub(crate) async fn dispatch_with_retry<F, Fut, G>(
    max_retries: u32,
    should_retry: G,
    mut attempt: F,
) -> Result<Vec<u8>, ToolError>
where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = Result<Vec<u8>, ToolError>> + Send,
    G: Fn(&ToolError) -> bool + Send,
{
    let effective_max = max_retries.min(MAX_TOOL_INVOKE_RETRIES_CAP);
    if max_retries > MAX_TOOL_INVOKE_RETRIES_CAP {
        // Adversarial round-1 W3 fix — surface the silent clamp to stderr so
        // operators have at least one signal that their configured value was
        // reduced. eprintln! is consistent with cap-mcp/src/stdio_transport.rs
        // stderr precedent (no `tracing` workspace pin — see §3.6 entry for
        // Slice D's analogous decision). A future slice that adds tracing
        // dependency-wide can promote this to `tracing::warn!`.
        eprintln!(
            "cap-tools dispatch_with_retry: tool_invoke_max_retries={} \
             clamped to MAX_TOOL_INVOKE_RETRIES_CAP={} (see MODULE-017 §2.11)",
            max_retries, MAX_TOOL_INVOKE_RETRIES_CAP,
        );
    }
    let total_attempts = effective_max.saturating_add(1);
    let mut last_err: Option<ToolError> = None;
    let mut attempt_idx: u32 = 0;
    for _ in 0..total_attempts {
        attempt_idx = attempt_idx.saturating_add(1);
        match attempt().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !should_retry(&e) {
                    return Err(e);
                }
                // Adversarial round-1 W5 mitigation — until the deferred
                // `tool.retry` observability event lands (§3.6 (tt) item 1),
                // surface each retry attempt to stderr so operators have a
                // forensic trail. Only emitted when the gate returned true
                // (i.e., a retry actually follows) AND when more attempts
                // remain — the final-attempt error is reported via the
                // returned `Err` and handled by the host-fn boundary's
                // `tool.error` event (existing Slice F emit path).
                if attempt_idx < total_attempts {
                    eprintln!(
                        "cap-tools dispatch_with_retry: attempt {}/{} failed with retryable error; retrying",
                        attempt_idx, total_attempts,
                    );
                }
                last_err = Some(e);
            }
        }
    }
    // Unreachable in practice: `effective_max ≤ MAX_TOOL_INVOKE_RETRIES_CAP`
    // (= 100) and `saturating_add(1)` therefore yields ≥ 1, so the loop
    // runs at least once. If every attempt returned `Ok`, the early
    // `return Ok(v)` fires; otherwise `last_err` is populated on the first
    // failing attempt. The fallback exists only to keep the `unwrap()`
    // off the path — a defensive guard in case a future refactor
    // changes the loop bound.
    Err(last_err.unwrap_or_else(|| {
        ToolError::InvocationFailed(
            "dispatch_with_retry: zero attempts (unreachable bound underflow)".into(),
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn method(idempotent: Option<bool>) -> MethodInfo {
        MethodInfo {
            name: "m".to_string(),
            description: None,
            input_schema: None,
            output_schema: None,
            idempotent,
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Gate-predicate truth table — 8 rows
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn t26_g1_gate_idempotent_true_invocation_failed_true() {
        assert!(is_retry_allowed(
            &method(Some(true)),
            &ToolError::InvocationFailed("x".into())
        ));
    }

    #[test]
    fn t26_g1_gate_idempotent_true_not_found_false() {
        assert!(!is_retry_allowed(
            &method(Some(true)),
            &ToolError::NotFound("x".into())
        ));
    }

    #[test]
    fn t26_g1_gate_idempotent_true_method_not_found_false() {
        assert!(!is_retry_allowed(
            &method(Some(true)),
            &ToolError::MethodNotFound("x".into())
        ));
    }

    #[test]
    fn t26_g1_gate_idempotent_true_permission_denied_false() {
        assert!(!is_retry_allowed(
            &method(Some(true)),
            &ToolError::PermissionDenied("x".into())
        ));
    }

    #[test]
    fn t26_g1_gate_idempotent_true_input_validation_failed_false() {
        assert!(!is_retry_allowed(
            &method(Some(true)),
            &ToolError::InputValidationFailed("x".into())
        ));
    }

    #[test]
    fn t26_g1_gate_idempotent_true_output_validation_failed_false() {
        assert!(!is_retry_allowed(
            &method(Some(true)),
            &ToolError::OutputValidationFailed("x".into())
        ));
    }

    #[test]
    fn t26_g1_gate_idempotent_false_invocation_failed_false() {
        assert!(!is_retry_allowed(
            &method(Some(false)),
            &ToolError::InvocationFailed("x".into())
        ));
    }

    #[test]
    fn t26_g1_gate_idempotent_none_invocation_failed_false() {
        assert!(!is_retry_allowed(
            &method(None),
            &ToolError::InvocationFailed("x".into())
        ));
    }

    // ──────────────────────────────────────────────────────────────
    // dispatch_with_retry harness — 8 rows (H1..H7 base + H8 clamp)
    // ──────────────────────────────────────────────────────────────

    /// Helper: a closure factory that returns `Ok(b"ok")` on every call,
    /// counting via the supplied AtomicU32.
    fn always_ok(
        counter: Arc<AtomicU32>,
    ) -> impl FnMut() -> std::future::Ready<Result<Vec<u8>, ToolError>> + Send {
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(b"ok".to_vec()))
        }
    }

    fn always_err(
        counter: Arc<AtomicU32>,
        err_template: ToolError,
    ) -> impl FnMut() -> std::future::Ready<Result<Vec<u8>, ToolError>> + Send {
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(err_template.clone()))
        }
    }

    /// Helper: returns Err for the first `fail_count` calls, then Ok.
    fn err_then_ok(
        counter: Arc<AtomicU32>,
        fail_count: u32,
    ) -> impl FnMut() -> std::future::Ready<Result<Vec<u8>, ToolError>> + Send {
        move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < fail_count {
                std::future::ready(Err(ToolError::InvocationFailed("transient".into())))
            } else {
                std::future::ready(Ok(b"ok".to_vec()))
            }
        }
    }

    #[tokio::test]
    async fn t26_g2_h1_max_retries_0_immediate_ok() {
        let counter = Arc::new(AtomicU32::new(0));
        let result = dispatch_with_retry(0, |_| true, always_ok(Arc::clone(&counter))).await;
        assert_eq!(result, Ok(b"ok".to_vec()));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn t26_g2_h2_max_retries_3_first_call_ok() {
        let counter = Arc::new(AtomicU32::new(0));
        let result = dispatch_with_retry(3, |_| true, always_ok(Arc::clone(&counter))).await;
        assert_eq!(result, Ok(b"ok".to_vec()));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn t26_g2_h3_max_retries_3_fail_twice_then_ok_gate_true() {
        let counter = Arc::new(AtomicU32::new(0));
        let result = dispatch_with_retry(3, |_| true, err_then_ok(Arc::clone(&counter), 2)).await;
        assert_eq!(result, Ok(b"ok".to_vec()));
        assert_eq!(counter.load(Ordering::SeqCst), 3); // 2 fails + 1 success
    }

    #[tokio::test]
    async fn t26_g2_h4_max_retries_3_always_invocation_failed_gate_true() {
        let counter = Arc::new(AtomicU32::new(0));
        let result = dispatch_with_retry(
            3,
            |_| true,
            always_err(
                Arc::clone(&counter),
                ToolError::InvocationFailed("transient".into()),
            ),
        )
        .await;
        assert!(matches!(result, Err(ToolError::InvocationFailed(_))));
        assert_eq!(counter.load(Ordering::SeqCst), 4); // 1 + 3 retries
    }

    #[tokio::test]
    async fn t26_g2_h5_max_retries_3_first_not_found_gate_only_transient_no_retry() {
        let counter = Arc::new(AtomicU32::new(0));
        let result = dispatch_with_retry(
            3,
            |err| matches!(err, ToolError::InvocationFailed(_)),
            always_err(Arc::clone(&counter), ToolError::NotFound("x".into())),
        )
        .await;
        assert!(matches!(result, Err(ToolError::NotFound(_))));
        assert_eq!(counter.load(Ordering::SeqCst), 1); // gate false → no retry
    }

    #[tokio::test]
    async fn t26_g2_h6_max_retries_0_invocation_failed_single_attempt() {
        let counter = Arc::new(AtomicU32::new(0));
        let result = dispatch_with_retry(
            0,
            |_| true,
            always_err(
                Arc::clone(&counter),
                ToolError::InvocationFailed("x".into()),
            ),
        )
        .await;
        assert!(matches!(result, Err(ToolError::InvocationFailed(_))));
        assert_eq!(counter.load(Ordering::SeqCst), 1); // zero retries → exactly 1 attempt
    }

    #[tokio::test]
    async fn t26_g2_h7_max_retries_2_gate_false_one_attempt() {
        let counter = Arc::new(AtomicU32::new(0));
        let result = dispatch_with_retry(
            2,
            |_| false, // gate always false (e.g. method.idempotent == Some(false))
            always_err(
                Arc::clone(&counter),
                ToolError::InvocationFailed("transient".into()),
            ),
        )
        .await;
        assert!(matches!(result, Err(ToolError::InvocationFailed(_))));
        assert_eq!(counter.load(Ordering::SeqCst), 1); // gate false → no retry despite InvocationFailed
    }

    /// T26-G2-H8 (audit round 1 W2 fix): `max_retries == u32::MAX` clamps
    /// to `MAX_TOOL_INVOKE_RETRIES_CAP` so the harness performs exactly
    /// `1 + CAP` total attempts (= 101 with the current cap of 100).
    /// Protects against operator footgun where a typo / unbounded
    /// configuration would otherwise wedge a single invoke() for
    /// hours-to-years of wall-clock time.
    #[tokio::test]
    async fn t26_g2_h8_max_retries_u32_max_clamps_to_cap() {
        let counter = Arc::new(AtomicU32::new(0));
        let result = dispatch_with_retry(
            u32::MAX,
            |_| true,
            always_err(
                Arc::clone(&counter),
                ToolError::InvocationFailed("transient".into()),
            ),
        )
        .await;
        assert!(matches!(result, Err(ToolError::InvocationFailed(_))));
        // 1 initial attempt + MAX_TOOL_INVOKE_RETRIES_CAP retries.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1 + MAX_TOOL_INVOKE_RETRIES_CAP,
            "max_retries u32::MAX must clamp to MAX_TOOL_INVOKE_RETRIES_CAP \
             (defense-in-depth bound — audit round 1 W2 fix)"
        );
    }
}
