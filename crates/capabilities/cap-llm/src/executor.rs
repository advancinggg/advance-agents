//! Transport-level retry loop wrapping `LlmExecutor` (Slice B-1).
//!
//! Implements MODULE-009 §1.4.2's `while attempt <= max_retries` retry loop
//! with exponential-backoff sleep injection. Slice B-1 ships the wrapper as
//! an internal cap-llm helper — NOT part of CONTRACT-081's `LlmGatewayInternal`
//! trait surface. Future slices wire the wrapper into `generate()` /
//! `gateway.rs` once the WIT host functions are real (AC-01 path).
//!
//! Out-of-slice (still in §3.6 backlog after Slice B-1):
//! - Structured-output retry counter (AC-04)
//! - RunBudget preflight + commit (AC-15)
//! - RepetitionGuard preflight (AC-16)
//! - llm.* event emission (AC-18)
//! - HttpSecurityChain integration (AC-08)
//! - Cost computation + EventBus emit (AC-07)
//!
//! `#[allow(dead_code)]`: every public item in this module is consumed only
//! by tests in this slice. They become live code when Slice C's `gateway.rs`
//! calls `execute_with_retry` from inside the host_fn handler. Marking them
//! `#[cfg(test)]` would force Slice C to undo that gate, so we use
//! `#[allow(dead_code)]` instead.
#![allow(dead_code)]

use std::future::Future;
use std::time::Duration;

use crate::error::LlmError;
use crate::provider::ResolvedProvider;
use crate::retry::{backoff_ms, classify_retryable, RetryConfig};

/// Single-call output from `LlmExecutor::execute_once`.
///
/// Slice B-1 carries the minimum fields needed by `execute_with_retry`'s
/// success path. Future slices promote this to a fuller `LlmResponse`
/// including `parsed_output: Option<Vec<u8>>` (CONTRACT-080 §1.4.1) and
/// `cost_usd: f64` once cost computation lands.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExecutionOutcome {
    pub text: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub finish_reason: String,
}

/// Executor seam over a single `(provider, prompt) → outcome` HTTP call.
///
/// Slice B-1 only ships the trait + a retry wrapper. Future slices implement
/// this trait against real provider HTTP adapters (OpenAI-compatible REST,
/// Anthropic, ...). The trait is intentionally narrow: structured-output
/// validation, budget commitment, and event emission are layered ABOVE
/// `execute_once`, not inside it.
#[async_trait::async_trait]
pub(crate) trait LlmExecutor: Send + Sync {
    async fn execute_once(
        &self,
        provider: &ResolvedProvider,
        prompt: &str,
    ) -> Result<ExecutionOutcome, LlmError>;
}

/// Hard upper bound on `max_retries` honored by [`execute_with_retry`].
///
/// `validate_config` rejects YAML-sourced `retry-default.max-retries > 100`.
/// `RetryConfig` is `pub` and constructable directly, so a programmatic
/// caller could otherwise build `RetryConfig { max_retries: u32::MAX, .. }`
/// and drive the loop into effective non-termination (saturating_add on
/// `u32::MAX` keeps the condition `attempt <= u32::MAX` true forever).
/// The wrapper enforces the same `100` ceiling at runtime as defense in
/// depth, regardless of how `cfg` was constructed.
pub(crate) const MAX_RETRIES_HARD_CAP: u32 = 100;

/// Floor on the per-retry sleep computed by [`execute_with_retry`] (CPU
/// tight-loop guard).
///
/// `validate_config` rejects YAML-sourced `retry-default.base-delay-ms == 0`
/// because zero would defeat exponential backoff. `RetryConfig` is `pub` and
/// direct-constructable, so the wrapper enforces a post-jitter floor: any
/// computed delay below `BASE_DELAY_MS_FLOOR` is silently raised. **Scope of
/// this guard**: prevent both (a) CPU-pegging tight loops when a programmatic
/// caller crafts `RetryConfig` to produce zero-ms backoff, AND (b) attacker-
/// driven retry-storm bursts that overwhelm an upstream rate-limiter.
///
/// Round-AUDIT-ADV-1 W3 hardening: floor raised from `1` to `100` ms. The
/// previous value was effectively a no-op against retry storms (with
/// jitter:true and rand fraction near 0, computed delays collapse to 0; the
/// 1ms floor still allows ~6 backend hits in ~6 ms). 100 ms gives upstream
/// rate-limiters meaningful breathing room without significantly delaying
/// recovery from genuine transient faults.
///
/// Per-provider RPS rate-limiting still belongs in cap-http step 6 — this
/// floor is a defense-in-depth backstop, not a primary rate limit.
pub(crate) const BASE_DELAY_MS_FLOOR: u64 = 100;

/// Hard upper bound (10 min) on per-retry sleep honored by
/// [`execute_with_retry`].
///
/// `validate_config` rejects YAML-sourced `retry-default.max-delay-ms >
/// 600_000`. Symmetric to [`MAX_RETRIES_HARD_CAP`] and [`BASE_DELAY_MS_FLOOR`]:
/// a programmatic caller passing `RetryConfig { max_delay_ms: u64::MAX, .. }`
/// would otherwise trigger a `Duration::from_millis(u64::MAX)` (~584 million
/// years) sleep on a single retry, indefinitely wedging the host task. The
/// wrapper clamps the post-jitter delay to this ceiling so YAML-tier and
/// runtime-tier upper bounds match.
pub(crate) const MAX_DELAY_MS_HARD_CAP: u64 = 600_000;

/// Wraps `LlmExecutor::execute_once` with the §1.4.2 retry loop.
///
/// Loop semantics (matches MODULE-009 §1.4.2 lines 144-148):
/// - `attempt = 0` initial.
/// - `while attempt <= effective_max_retries`: yields up to
///   `effective_max_retries + 1` total tries. `effective_max_retries =
///   min(cfg.max_retries, MAX_RETRIES_HARD_CAP)`. (`max_retries: 0` → 1
///   attempt; `max_retries: 3` → 4 attempts.)
/// - Sleep between iterations only (`if attempt > 0`).
/// - Retryable errors (per [`classify_retryable`]) loop on. Non-retryable
///   errors return immediately. `Ok` returns immediately.
///
/// **Sleep injection**: the `sleep` closure is `Fn(Duration) -> impl Future`
/// with `S: Send + Sync + 'static` and `F: Send + 'static` so the returned
/// future is `Send + 'static`-bounded — required by production callers that
/// box this into `Pin<Box<dyn Future + Send + 'static>>` (see `host_fn.rs:46`).
/// Tests pass `|_: Duration| async {}` (no-op) for deterministic timing.
///
/// **Sentinel `"retry budget exhausted"`** (§1.4.2 line 220): the
/// `unwrap_or` fallback below preserves the spec's pseudocode verbatim. It
/// is structurally unreachable given the loop body — `attempt = 0; while
/// attempt <= max_retries` always executes at least once, so `last_err` is
/// `None` only when every iteration returned `Ok` (in which case the
/// function already early-returned). Preserved for spec fidelity; no test
/// exercises this branch because no input shape can reach it. Future slices
/// changing the loop structure (e.g., adding `max_retries: None` for "no
/// limit") become responsible for adding the test.
pub(crate) async fn execute_with_retry<E, S, F>(
    executor: &E,
    provider: &ResolvedProvider,
    prompt: &str,
    cfg: &RetryConfig,
    sleep: S,
) -> Result<ExecutionOutcome, LlmError>
where
    E: LlmExecutor,
    S: Fn(Duration) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let max_retries = cfg.max_retries.min(MAX_RETRIES_HARD_CAP);
    // Defense-in-depth: apply BOTH BASE_DELAY_MS_FLOOR and MAX_DELAY_MS_HARD_CAP
    // to the FINAL computed delay (post-backoff, post-jitter), not to the input
    // RetryConfig fields. Pre-jitter flooring is insufficient because AWS-jitter
    // computes `delay = capped * fraction` with `fraction ∈ [0, 1)`; even a
    // floored `capped = N` truncates to 0 when `fraction < 1/N` (and for
    // `capped = 1`, EVERY non-trivial fraction collapses to 0 via f64→u64
    // truncation). Post-computation `.max(FLOOR).min(HARD_CAP)` guarantees:
    //   - No matter how a programmatic caller crafts RetryConfig (zero base,
    //     zero max, jitter on), the per-retry sleep is at least FLOOR ms.
    //   - No matter how a programmatic caller inflates max_delay_ms (e.g.
    //     u64::MAX), the per-retry sleep is at most HARD_CAP ms (10 min),
    //     symmetric to validate_config's YAML-tier 600 000ms cap.
    let mut attempt: u32 = 0;
    let mut last_err: Option<LlmError> = None;
    while attempt <= max_retries {
        if attempt > 0 {
            let delay = backoff_ms(attempt, cfg)
                .max(BASE_DELAY_MS_FLOOR)
                .min(MAX_DELAY_MS_HARD_CAP);
            sleep(Duration::from_millis(delay)).await;
        }
        attempt = attempt.saturating_add(1);
        match executor.execute_once(provider, prompt).await {
            Ok(outcome) => return Ok(outcome),
            Err(e) => {
                if !classify_retryable(&e) {
                    return Err(e);
                }
                last_err = Some(e);
                continue;
            }
        }
    }
    Err(last_err.unwrap_or(LlmError::ProviderError("retry budget exhausted".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use advance_runtime::config::LlmProviderConfig;

    use crate::provider::{resolve_provider_and_model, ResolvedProvider};
    use crate::retry::RetryConfig;

    fn outcome(text: &str) -> ExecutionOutcome {
        ExecutionOutcome {
            text: text.into(),
            model: "test-model".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
        }
    }

    fn dummy_provider() -> ResolvedProvider {
        let mut aliases = std::collections::HashMap::new();
        aliases.insert("a".to_string(), "test-model".to_string());
        let cfg = LlmProviderConfig {
            id: "test".into(),
            endpoint: "https://api.test.example".into(),
            api_key_secret: "test-key".into(),
            model_aliases: aliases,
            cost_per_mtoken_in: 1.0,
            cost_per_mtoken_out: 5.0,
            rate_limit: None,
            retry_default: None,
            backend: None,
            auth_scheme: None,
            backend_class: advance_runtime::config::InferenceBackendClass::CloudHttp,
            embedding_model: None,
            sidecar: None,
            profile_id: None,
        };
        resolve_provider_and_model(&[cfg], Some("a")).unwrap()
    }

    /// Mock executor with a scripted queue of responses + a call counter
    /// + an attempt-index sequence trace.
    ///
    /// `Mutex` is `std::sync::Mutex` (not `tokio::sync::Mutex`); each lock is
    /// held only across `pop_front` / `push` (no `.await` under the lock), so
    /// the std mutex is correct here. Future tests adding logic inside the
    /// locked block must preserve the no-await-under-lock invariant.
    struct MockExecutor {
        responses: Mutex<VecDeque<Result<ExecutionOutcome, LlmError>>>,
        /// Records the running call counter at each `execute_once` entry.
        /// First call records 1, second records 2, etc. Used by T32 to
        /// verify the wrapper's attempt-index sequence is `[1, 2, 3, ...]`.
        sequence: Mutex<Vec<u32>>,
        calls: AtomicU32,
    }

    impl MockExecutor {
        fn new(seq: Vec<Result<ExecutionOutcome, LlmError>>) -> Self {
            Self {
                responses: Mutex::new(seq.into()),
                sequence: Mutex::new(Vec::new()),
                calls: AtomicU32::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }

        fn sequence(&self) -> Vec<u32> {
            self.sequence.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl LlmExecutor for MockExecutor {
        async fn execute_once(
            &self,
            _provider: &ResolvedProvider,
            _prompt: &str,
        ) -> Result<ExecutionOutcome, LlmError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.sequence.lock().unwrap().push(n);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(LlmError::ProviderError("mock exhausted".into())))
        }
    }

    fn no_jitter() -> RetryConfig {
        RetryConfig {
            jitter: false,
            ..RetryConfig::default()
        }
    }

    fn no_sleep(
    ) -> impl Fn(Duration) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static
    {
        |_: Duration| -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> { Box::pin(async {}) }
    }

    #[tokio::test]
    async fn t_executor_retry_provider_error_then_ok() {
        let mock = MockExecutor::new(vec![
            Err(LlmError::ProviderError("upstream 500".into())),
            Err(LlmError::ProviderError("upstream 500 again".into())),
            Ok(outcome("ok")),
        ]);
        let cfg = no_jitter();
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, no_sleep()).await;
        assert_eq!(r, Ok(outcome("ok")));
        assert_eq!(mock.calls(), 3, "expected 3 calls (2 retries + success)");
    }

    #[tokio::test]
    async fn t_executor_retry_rate_limited_then_ok() {
        // T06: rate-limited retryable → ok on 2nd attempt.
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("429".into())),
            Ok(outcome("ok")),
        ]);
        let cfg = no_jitter();
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, no_sleep()).await;
        assert_eq!(r, Ok(outcome("ok")));
        assert_eq!(mock.calls(), 2);
    }

    #[tokio::test]
    async fn t_executor_retry_exhausts_budget() {
        let cfg = RetryConfig {
            max_retries: 3,
            jitter: false,
            ..RetryConfig::default()
        };
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("a".into())),
            Err(LlmError::RateLimited("b".into())),
            Err(LlmError::RateLimited("c".into())),
            Err(LlmError::RateLimited("d".into())),
        ]);
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, no_sleep()).await;
        assert!(matches!(r, Err(LlmError::RateLimited(_))));
        // max_retries=3 → 4 total attempts.
        assert_eq!(mock.calls(), 4);
    }

    macro_rules! test_no_retry {
        ($name:ident, $err_ctor:expr) => {
            #[tokio::test]
            async fn $name() {
                let mock = MockExecutor::new(vec![Err($err_ctor)]);
                let cfg = no_jitter();
                let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, no_sleep()).await;
                assert!(matches!(r, Err(_)));
                assert_eq!(mock.calls(), 1, "non-retryable error must not retry");
            }
        };
    }

    test_no_retry!(
        t_executor_no_retry_on_context_too_long,
        LlmError::ContextTooLong("x".into())
    );
    test_no_retry!(
        t_executor_no_retry_on_budget_exceeded,
        LlmError::BudgetExceeded("x".into())
    );
    test_no_retry!(
        t_executor_no_retry_on_model_not_available,
        LlmError::ModelNotAvailable("x".into())
    );
    test_no_retry!(
        t_executor_no_retry_on_structured_output_failed,
        LlmError::StructuredOutputFailed("x".into())
    );
    test_no_retry!(
        t_executor_no_retry_on_repetition_terminated,
        LlmError::RepetitionTerminated("x".into())
    );

    #[tokio::test]
    async fn t_executor_zero_retries_config() {
        let cfg = RetryConfig {
            max_retries: 0,
            jitter: false,
            ..RetryConfig::default()
        };
        let mock = MockExecutor::new(vec![Err(LlmError::RateLimited("once".into()))]);
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, no_sleep()).await;
        assert!(matches!(r, Err(LlmError::RateLimited(_))));
        assert_eq!(mock.calls(), 1, "max_retries=0 → exactly 1 attempt");
    }

    #[tokio::test]
    async fn t_executor_emits_correct_attempt_index() {
        // 2 retries (max_retries=2) → 3 total iterations.
        // §3.3 T32: assert the mock's recorded attempt-index sequence is
        // exactly `[1, 2, 3]`, not just the aggregate call count.
        let cfg = RetryConfig {
            max_retries: 2,
            jitter: false,
            ..RetryConfig::default()
        };
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("a".into())),
            Err(LlmError::RateLimited("b".into())),
            Ok(outcome("ok")),
        ]);
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, no_sleep()).await;
        assert_eq!(r, Ok(outcome("ok")));
        assert_eq!(
            mock.sequence(),
            vec![1, 2, 3],
            "attempt sequence must be [1, 2, 3]"
        );
    }

    #[tokio::test]
    async fn t_executor_floors_base_delay_ms_at_runtime() {
        // RetryConfig is pub-constructable with base_delay_ms = 0. The wrapper
        // floors at BASE_DELAY_MS_FLOOR to prevent tight-loop retry storms even
        // when validate_config is bypassed by a programmatic caller.
        // We verify the floor is applied by checking the actual sleep duration
        // requested via the sleep closure.
        let recorded: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_clone = recorded.clone();
        let cfg = RetryConfig {
            max_retries: 2,
            base_delay_ms: 0, // would yield 0ms backoff if not floored
            max_delay_ms: 30_000,
            jitter: false,
        };
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("a".into())),
            Err(LlmError::RateLimited("b".into())),
            Ok(outcome("ok")),
        ]);
        let recording_sleep =
            move |d: Duration| -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
                recorded_clone.lock().unwrap().push(d);
                Box::pin(async {})
            };
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, recording_sleep).await;
        assert_eq!(r, Ok(outcome("ok")));
        // 2 retries = 2 sleeps. With base=0 unfloored, both would be 0ms.
        // With floor=1, attempt 1 sleeps base*2^0 = 1ms, attempt 2 sleeps base*2^1 = 2ms.
        let sleeps = recorded.lock().unwrap().clone();
        assert_eq!(
            sleeps.len(),
            2,
            "expected 2 sleeps for 2 retries, got {sleeps:?}"
        );
        for s in &sleeps {
            assert!(
                *s >= Duration::from_millis(BASE_DELAY_MS_FLOOR),
                "sleep {s:?} below BASE_DELAY_MS_FLOOR = {BASE_DELAY_MS_FLOOR}ms"
            );
        }
    }

    #[tokio::test]
    async fn t_executor_floors_max_delay_ms_at_runtime() {
        // Round 2 adversarial finding: when both base_delay_ms = 0 AND
        // max_delay_ms = 0, the wrapper must still floor both to prevent
        // backoff_ms's `capped = exp.min(max_delay_ms)` from defeating the
        // floor (min(1, 0) = 0). Verify each sleep ≥ BASE_DELAY_MS_FLOOR.
        let recorded: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_clone = recorded.clone();
        let cfg = RetryConfig {
            max_retries: 2,
            base_delay_ms: 0,
            max_delay_ms: 0, // adversarial round-2 attack: pair zero with zero
            jitter: false,
        };
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("a".into())),
            Err(LlmError::RateLimited("b".into())),
            Ok(outcome("ok")),
        ]);
        let recording_sleep =
            move |d: Duration| -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
                recorded_clone.lock().unwrap().push(d);
                Box::pin(async {})
            };
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, recording_sleep).await;
        assert_eq!(r, Ok(outcome("ok")));
        let sleeps = recorded.lock().unwrap().clone();
        assert_eq!(sleeps.len(), 2, "expected 2 sleeps for 2 retries");
        for s in &sleeps {
            assert!(
                *s >= Duration::from_millis(BASE_DELAY_MS_FLOOR),
                "sleep {s:?} below BASE_DELAY_MS_FLOOR = {BASE_DELAY_MS_FLOOR}ms — \
                 max_delay_ms=0 must not defeat the floor"
            );
        }
    }

    #[tokio::test]
    async fn t_executor_floors_delay_post_jitter() {
        // Round 3 adversarial finding: pre-jitter flooring is insufficient
        // because `delay = capped * fraction` with `fraction ∈ [0, 1)` can
        // truncate to 0 even when capped is non-zero. Specifically with
        // capped=1 and fraction<1.0, the f64→u64 cast yields 0 ALWAYS.
        // Verify the post-jitter floor guarantees ≥ BASE_DELAY_MS_FLOOR ms
        // sleep even with jitter=true and (base=0, max=0).
        let recorded: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_clone = recorded.clone();
        let cfg = RetryConfig {
            max_retries: 5, // multiple iterations to exercise jitter randomness
            base_delay_ms: 0,
            max_delay_ms: 0,
            jitter: true, // <-- the bypass case from Round 3
        };
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("a".into())),
            Err(LlmError::RateLimited("b".into())),
            Err(LlmError::RateLimited("c".into())),
            Err(LlmError::RateLimited("d".into())),
            Err(LlmError::RateLimited("e".into())),
            Ok(outcome("ok")),
        ]);
        let recording_sleep =
            move |d: Duration| -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
                recorded_clone.lock().unwrap().push(d);
                Box::pin(async {})
            };
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, recording_sleep).await;
        assert_eq!(r, Ok(outcome("ok")));
        let sleeps = recorded.lock().unwrap().clone();
        assert_eq!(sleeps.len(), 5, "expected 5 sleeps for 5 retries");
        for s in &sleeps {
            assert!(
                *s >= Duration::from_millis(BASE_DELAY_MS_FLOOR),
                "sleep {s:?} below BASE_DELAY_MS_FLOOR — jitter+zero-cap bypass {s:?}"
            );
        }
    }

    #[tokio::test]
    async fn t_executor_floors_delay_post_jitter_truncation_path() {
        // Round 4 finding: T52 with (base=0, max=0) short-circuits via the
        // capped=0 branch — never exercises the AWS-jitter f64→u64 truncation
        // claim from the doc. This test forces capped=1 with jitter=true,
        // where `1.0 * fraction_clamped` always truncates to 0, exercising
        // the actual stated bypass path.
        let recorded: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_clone = recorded.clone();
        let cfg = RetryConfig {
            max_retries: 5,
            base_delay_ms: 1,
            max_delay_ms: 1,
            jitter: true, // exercises (1.0 * fraction) → 0u64
        };
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("a".into())),
            Err(LlmError::RateLimited("b".into())),
            Err(LlmError::RateLimited("c".into())),
            Err(LlmError::RateLimited("d".into())),
            Err(LlmError::RateLimited("e".into())),
            Ok(outcome("ok")),
        ]);
        let recording_sleep =
            move |d: Duration| -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
                recorded_clone.lock().unwrap().push(d);
                Box::pin(async {})
            };
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, recording_sleep).await;
        assert_eq!(r, Ok(outcome("ok")));
        let sleeps = recorded.lock().unwrap().clone();
        assert_eq!(sleeps.len(), 5);
        for s in &sleeps {
            assert!(
                *s >= Duration::from_millis(BASE_DELAY_MS_FLOOR),
                "post-jitter f64 truncation bypass: sleep {s:?} < floor"
            );
        }
    }

    #[tokio::test]
    async fn t_executor_clamps_max_delay_at_hard_cap() {
        // RetryConfig is pub-constructable with arbitrary max_delay_ms. Without
        // a runtime-tier cap symmetric to validate_config's 600_000ms ceiling,
        // a programmatic caller passing max_delay_ms = u64::MAX would trigger
        // Duration::from_millis(u64::MAX) (~584 million years) per retry. The
        // wrapper clamps post-computation at MAX_DELAY_MS_HARD_CAP.
        let recorded: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_clone = recorded.clone();
        let cfg = RetryConfig {
            max_retries: 1,
            base_delay_ms: u64::MAX,
            max_delay_ms: u64::MAX,
            jitter: false, // deterministic: backoff returns u64::MAX, then clamped
        };
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("a".into())),
            Ok(outcome("ok")),
        ]);
        let recording_sleep =
            move |d: Duration| -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
                recorded_clone.lock().unwrap().push(d);
                Box::pin(async {})
            };
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, recording_sleep).await;
        assert_eq!(r, Ok(outcome("ok")));
        let sleeps = recorded.lock().unwrap().clone();
        assert_eq!(sleeps.len(), 1, "expected 1 sleep for 1 retry");
        assert!(
            sleeps[0] <= Duration::from_millis(MAX_DELAY_MS_HARD_CAP),
            "sleep {:?} exceeds MAX_DELAY_MS_HARD_CAP = {MAX_DELAY_MS_HARD_CAP}ms",
            sleeps[0]
        );
    }

    #[tokio::test]
    async fn t_executor_clamps_max_retries_at_hard_cap() {
        // RetryConfig is pub-constructable with arbitrary max_retries. The
        // wrapper clamps internally at MAX_RETRIES_HARD_CAP to prevent
        // unbounded retry loops from a programmatic caller bypassing
        // validate_config's YAML-tier guard. With max_retries = u32::MAX
        // and all retryable errors, we expect at most HARD_CAP+1 calls.
        let cfg = RetryConfig {
            max_retries: u32::MAX,
            jitter: false,
            ..RetryConfig::default()
        };
        // Seed enough RateLimited errors that we'd exceed hard cap if it
        // weren't enforced; mock fallback emits ProviderError after queue
        // empties (also retryable), so the loop continues.
        let mut seq: Vec<Result<ExecutionOutcome, LlmError>> = Vec::new();
        for i in 0..(MAX_RETRIES_HARD_CAP + 50) {
            seq.push(Err(LlmError::RateLimited(format!("attempt {i}"))));
        }
        let mock = MockExecutor::new(seq);
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, no_sleep()).await;
        assert!(matches!(r, Err(LlmError::RateLimited(_))));
        assert_eq!(
            mock.calls(),
            MAX_RETRIES_HARD_CAP + 1,
            "must clamp at HARD_CAP+1 total attempts (HARD_CAP={MAX_RETRIES_HARD_CAP})"
        );
    }

    #[tokio::test]
    async fn t_executor_sleep_seam_works_with_noop_closure() {
        // No-op sleep closure compiles + runs; verifies the injection seam.
        let cfg = RetryConfig {
            max_retries: 5,
            base_delay_ms: 60_000, // would block 60s+ if real-time
            jitter: false,
            ..RetryConfig::default()
        };
        let mock = MockExecutor::new(vec![
            Err(LlmError::RateLimited("a".into())),
            Err(LlmError::RateLimited("b".into())),
            Ok(outcome("ok")),
        ]);
        let start = std::time::Instant::now();
        let r = execute_with_retry(&mock, &dummy_provider(), "x", &cfg, no_sleep()).await;
        let elapsed = start.elapsed();
        assert_eq!(r, Ok(outcome("ok")));
        // No-op sleep should let this complete in milliseconds, not minutes.
        assert!(
            elapsed < Duration::from_secs(1),
            "no-op sleep elapsed {elapsed:?} (expected < 1s)"
        );
    }
}
