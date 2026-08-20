//! Retry primitives — `RetryConfig` + `classify_retryable` + `backoff_ms`
//! + `backoff_ms_with_fraction`. Slice A ships the math primitive (`backoff_ms`)
//! and the AC-06 classifier (`classify_retryable`); Slice B's `generate()`
//! loop will compose them. AC-05 (loop integration) is in Slice A's
//! `waived_scope` per the slice plan; this module ships the foundation.

use advance_runtime::config::LlmProviderConfig;

use crate::error::LlmError;

/// Per-agent retry configuration matching MODULE-009 §1.4.3c. The retry
/// resolution chain (`run-config.retry-overrides.llm > .agent/config.yaml
/// retry.llm > llm-providers[].retry-default`) is Slice B work — Slice A
/// uses [`RetryConfig::default`] hardcoded values from §1.4.3c.
#[derive(Clone, Debug, PartialEq)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub jitter: bool,
}

impl Default for RetryConfig {
    /// §1.4.3c defaults: max-retries=3, base-delay-ms=1000, max-delay-ms=30000,
    /// jitter=true.
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 1000,
            max_delay_ms: 30_000,
            jitter: true,
        }
    }
}

/// AC-06 truth table from MODULE-009 §1.4.4. `RateLimited` is always retryable;
/// `ProviderError` is retryable ONLY when the message body indicates a
/// transient transport fault per the §2.8 ProviderError sub-rule. Everything
/// else (policy/security gates, permanent upstream client errors like HTTP
/// 4xx, internal serialization failures, malformed responses) is
/// non-retryable. The other five variants are non-retryable.
///
/// `StructuredOutputFailed` is non-retryable at the transport level because
/// it has its own dedicated retry counter inside `try_parse_and_validate`
/// (§1.4.3 — Slice B).
///
/// Round-AUDIT-2 C1 hardening: classifier switched from blacklist (block
/// known policy/security prefixes, retry everything else) to whitelist
/// (allow only transport-flavoured ProviderError messages, block everything
/// else). The blacklist approach incorrectly retried generic `http 400 …`
/// and `http 404 …` upstream client errors that originated in the provider
/// adapters' status-mappers; the whitelist closes that gap.
pub fn classify_retryable(err: &LlmError) -> bool {
    match err {
        LlmError::RateLimited(_) => true,
        LlmError::ProviderError(msg) => is_transport_provider_error(msg),
        _ => false,
    }
}

/// Whitelist of `ProviderError` message bodies that originate from transient
/// transport-level faults (DNS / TLS / connection / timeout / 5xx upstream
/// errors). These are the canonical retryable substrings emitted by
/// `gateway::map_http_err_to_llm` and the provider adapters'
/// `map_status_to_llm_err` / `map_anthropic_status` 5xx branches.
///
/// If either emission site introduces a new transport-flavoured message,
/// add its prefix here. Anything not in this whitelist is treated as
/// non-retryable (covers policy/security gates, HTTP 4xx, malformed
/// responses, internal serialization failures, retry-budget exhaustion,
/// scheme rejection, etc.).
pub(crate) fn is_transport_provider_error(msg: &str) -> bool {
    msg == "dns failed"
        || msg == "tls failed"
        || msg == "connection refused"
        || msg == "transport timeout"
        || msg == "transport error"
        || msg.starts_with("upstream 5")
        || msg.starts_with("upstream 6")
}

/// Round-AUDIT-ADV-1 W4 — companion test surface for the build_http_cap
/// hardening: confirms `endpoint url must not contain user-info, query, or
/// fragment` is on the non-retryable list.
#[cfg(test)]
mod test_audit_adv1 {
    use super::*;
    #[test]
    fn t_classify_endpoint_userinfo_query_fragment_not_retryable() {
        assert!(!classify_retryable(&LlmError::ProviderError(
            "endpoint url must not contain user-info, query, or fragment".into()
        )));
        assert!(
            !classify_retryable(&LlmError::ProviderError("ssrf blocked".into())),
            "SsrfBlocked must stay non-retryable"
        );
        assert!(!classify_retryable(&LlmError::ProviderError(
            "local transport: sidecar dead".into()
        )));
    }
}

/// Production wrapper matching the §1.4.2 caller shape `backoff_ms(attempt,
/// &retry_cfg)`. Samples `rand::random::<f64>()` ONCE when `cfg.jitter ==
/// true` and forwards to [`backoff_ms_with_fraction`]. When `cfg.jitter ==
/// false`, the function is fully deterministic — no `rand` is consulted.
///
/// The 2-arg shape is structural: it must match the pseudocode at MODULE-009
/// §1.4.2 line 146 `let delay = backoff_ms(attempt, &retry_cfg);`. Tests
/// that need deterministic behaviour call [`backoff_ms_with_fraction`]
/// directly instead.
pub fn backoff_ms(attempt: u32, cfg: &RetryConfig) -> u64 {
    let fraction = if cfg.jitter {
        rand::random::<f64>()
    } else {
        0.0
    };
    backoff_ms_with_fraction(attempt, cfg, fraction)
}

/// Deterministic test seam exposing the `jitter_fraction` knob explicitly.
///
/// Behaviour:
/// - `attempt == 0` → returns `0` (boundary; production callers in §1.4.2
///   line 144's loop pass `attempt >= 1`, but this function is total).
/// - `attempt >= 1`:
///   - Compute `exp = base_delay_ms * 2^(attempt-1)` with saturating shift
///     and saturating multiplication (no panic for `attempt = u32::MAX`).
///   - Clamp to `cfg.max_delay_ms`.
///   - If `cfg.jitter == false`: return clamped value verbatim
///     (`jitter_fraction` is ignored).
///   - If `cfg.jitter == true`: AWS full-jitter — multiply clamped by
///     `jitter_fraction.clamp(0.0, 1.0_f64.next_down())`. Pathological
///     inputs (NaN, ±∞, out-of-range) are squashed to the valid range.
pub fn backoff_ms_with_fraction(attempt: u32, cfg: &RetryConfig, jitter_fraction: f64) -> u64 {
    if attempt == 0 {
        return 0;
    }
    let shift = attempt - 1;
    // `1 << shift` computes 2^shift. `2u64.checked_shl(shift)` would
    // compute `2 << shift` = 2^(shift+1) — off by one.
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let exp = cfg.base_delay_ms.saturating_mul(multiplier);
    let capped = exp.min(cfg.max_delay_ms);
    if !cfg.jitter {
        return capped;
    }
    // AWS full-jitter: `delay = (capped * jitter_fraction)` clamped to
    // [0, capped). `f64::clamp` returns the first arg when given NaN, so
    // NaN → 0.0 here.
    let fraction_clamped = jitter_fraction.clamp(0.0, 1.0_f64.next_down());
    (capped as f64 * fraction_clamped) as u64
}

/// Higher-tier override carrier for the §1.4.3c retry-config resolution chain.
///
/// `PartialRetry` represents an "agent-tier" or "run-tier" override. Each field
/// is `Option`-typed so that a tier can override one knob without touching the
/// others — enabling the field-by-field merge documented in
/// [`resolve_retry_config`].
///
/// Public since the small-witness slice (2026-06-11): the agent tier is live —
/// callers install it via `LlmGateway::with_retry_overrides` (a non-trait
/// inherent builder; CONTRACT-081 frozen) and it feeds the agent slot at all
/// three `resolve_retry_config` sites (chat / embed / stream). `jitter:
/// Some(false)` makes backoff fully deterministic (`min(base·2^(n−1),
/// max_delay)`), the SYS-J-40 monotonic-exponential witness shape. The run
/// tier stays unwired until run-config lands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialRetry {
    pub max_retries: Option<u32>,
    pub base_delay_ms: Option<u64>,
    pub max_delay_ms: Option<u64>,
    pub jitter: Option<bool>,
}

/// Resolve a [`RetryConfig`] from the §1.4.3c three-tier chain
/// (`run > agent > provider`), with a static-default safety net.
///
/// Resolution is **field-by-field**: each `RetryConfig` field independently
/// picks the value from the highest tier that supplies it. Tier precedence:
/// 1. `run_overrides.<field>` (if `Some`)
/// 2. `agent_overrides.<field>` (if `Some`)
/// 3. `provider.retry_default.<field>` (if `provider.retry_default` is `Some`)
/// 4. `RetryConfig::default().<field>` (safety net)
///
/// **Static-default safety net**: when all three configured tiers omit a
/// field, this resolver returns the corresponding [`RetryConfig::default`]
/// value. Per MODULE-009 §1.4.3c, the static-default tier is an
/// implementation safety net — NOT a documented fourth tier of the
/// resolution chain — so the resolver remains total in greenfield /
/// under-configured environments.
///
/// **Provider-tier asymmetry — `jitter`**: `RetryDefaults` (provider tier)
/// intentionally OMITS `jitter` per §1.4.3c. `jitter` resolution therefore
/// only consults run / agent overrides, falling back to
/// `RetryConfig::default().jitter` (`true`).
pub(crate) fn resolve_retry_config(
    provider: &LlmProviderConfig,
    agent_overrides: Option<&PartialRetry>,
    run_overrides: Option<&PartialRetry>,
) -> RetryConfig {
    let defaults = RetryConfig::default();
    let provider_rd = provider.retry_default.as_ref();
    let max_retries = run_overrides
        .and_then(|r| r.max_retries)
        .or_else(|| agent_overrides.and_then(|a| a.max_retries))
        .or_else(|| provider_rd.map(|rd| rd.max_retries))
        .unwrap_or(defaults.max_retries);
    let base_delay_ms = run_overrides
        .and_then(|r| r.base_delay_ms)
        .or_else(|| agent_overrides.and_then(|a| a.base_delay_ms))
        .or_else(|| provider_rd.map(|rd| rd.base_delay_ms))
        .unwrap_or(defaults.base_delay_ms);
    let max_delay_ms = run_overrides
        .and_then(|r| r.max_delay_ms)
        .or_else(|| agent_overrides.and_then(|a| a.max_delay_ms))
        .or_else(|| provider_rd.map(|rd| rd.max_delay_ms))
        .unwrap_or(defaults.max_delay_ms);
    // Provider tier omits jitter per §1.4.3c — agent / run only, then default.
    let jitter = run_overrides
        .and_then(|r| r.jitter)
        .or_else(|| agent_overrides.and_then(|a| a.jitter))
        .unwrap_or(defaults.jitter);
    RetryConfig {
        max_retries,
        base_delay_ms,
        max_delay_ms,
        jitter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_jitter() -> RetryConfig {
        RetryConfig {
            jitter: false,
            ..RetryConfig::default()
        }
    }

    // AC-06 classifier truth-table tests.
    #[test]
    fn t_classify_rate_limited_retryable() {
        assert!(classify_retryable(&LlmError::RateLimited("x".into())));
    }

    /// §1.4.4 + §2.8 transport-flavoured ProviderError MUST retry: DNS / TLS
    /// / connection / timeout / 5xx upstream. Everything outside this
    /// whitelist is non-retryable per the round-AUDIT-2 C1 hardening.
    #[test]
    fn t_classify_provider_error_transport_flavoured_retryable() {
        for msg in [
            "dns failed",
            "tls failed",
            "connection refused",
            "transport timeout",
            "transport error",
            "upstream 500",
            "upstream 502",
            "upstream 503",
            "upstream 504",
            "upstream 599",
        ] {
            assert!(
                classify_retryable(&LlmError::ProviderError(msg.into())),
                "ProviderError({msg:?}) must be retryable per §1.4.4 transport whitelist"
            );
        }
    }

    /// §1.4.4 + §2.8 — non-transport ProviderError messages MUST NOT retry.
    /// Covers policy/security gates, HTTP 4xx upstream client errors,
    /// malformed-response failures, internal serialization failures,
    /// retry-budget exhaustion, and scheme rejection.
    #[test]
    fn t_classify_non_transport_provider_errors_not_retryable() {
        for msg in [
            // Policy / security gates (gateway::map_http_err_to_llm).
            "allowlist blocked: https://evil.example/",
            "ssrf blocked",
            "redirect rejected",
            "response failed leak scan",
            "auth setup failed: missing secret",
            "auth setup failed: placeholder not in url",
            "invalid url",
            "invalid endpoint url",
            "scheme not allowed",
            // Auth failures (provider adapters HTTP 401/403).
            "auth failed",
            // Upstream client errors (HTTP 4xx) — NOT retryable.
            "http 400: malformed request body",
            "http 404: endpoint not found",
            "http 410: gone",
            "http 422: unprocessable entity",
            // Malformed responses (parsers).
            "invalid response shape",
            // Internal serialization failures (we own the bug).
            "serialize chat body: trailing comma",
            "serialize embed body: nan in float",
            // Retry-budget exhaustion (gateway terminal path).
            "retry budget exhausted",
        ] {
            assert!(
                !classify_retryable(&LlmError::ProviderError(msg.into())),
                "ProviderError({msg:?}) must NOT be retryable per §1.4.4 non-transport rule"
            );
        }
    }

    #[test]
    fn t_classify_model_not_available_not_retryable() {
        assert!(!classify_retryable(&LlmError::ModelNotAvailable(
            "x".into()
        )));
    }

    #[test]
    fn t_classify_context_too_long_not_retryable() {
        assert!(!classify_retryable(&LlmError::ContextTooLong("x".into())));
    }

    #[test]
    fn t_classify_budget_exceeded_not_retryable() {
        assert!(!classify_retryable(&LlmError::BudgetExceeded("x".into())));
    }

    #[test]
    fn t_classify_structured_output_failed_not_retryable() {
        assert!(!classify_retryable(&LlmError::StructuredOutputFailed(
            "x".into()
        )));
    }

    #[test]
    fn t_classify_repetition_terminated_not_retryable() {
        assert!(!classify_retryable(&LlmError::RepetitionTerminated(
            "x".into()
        )));
    }

    // Deterministic backoff_ms_with_fraction tests (jitter:false).
    #[test]
    fn t_backoff_attempt_0_returns_zero() {
        assert_eq!(backoff_ms_with_fraction(0, &no_jitter(), 0.0), 0);
    }

    #[test]
    fn t_backoff_attempt_1() {
        assert_eq!(backoff_ms_with_fraction(1, &no_jitter(), 0.0), 1000);
    }

    #[test]
    fn t_backoff_attempt_2() {
        assert_eq!(backoff_ms_with_fraction(2, &no_jitter(), 0.0), 2000);
    }

    #[test]
    fn t_backoff_attempt_3() {
        assert_eq!(backoff_ms_with_fraction(3, &no_jitter(), 0.0), 4000);
    }

    #[test]
    fn t_backoff_attempt_4() {
        assert_eq!(backoff_ms_with_fraction(4, &no_jitter(), 0.0), 8000);
    }

    #[test]
    fn t_backoff_attempt_clamps_at_max() {
        assert_eq!(backoff_ms_with_fraction(20, &no_jitter(), 0.0), 30_000);
    }

    #[test]
    fn t_backoff_no_jitter_ignores_fraction() {
        assert_eq!(backoff_ms_with_fraction(3, &no_jitter(), 0.999), 4000);
    }

    #[test]
    fn t_backoff_saturating_arith() {
        assert_eq!(
            backoff_ms_with_fraction(u32::MAX, &no_jitter(), 0.0),
            30_000
        );
    }

    // Jitter-enabled tests (jitter:true).
    #[test]
    fn t_backoff_with_jitter_zero_fraction() {
        assert_eq!(backoff_ms_with_fraction(3, &RetryConfig::default(), 0.0), 0);
    }

    #[test]
    fn t_backoff_with_jitter_max_fraction() {
        // 0.999 is below 1.0_f64.next_down() (~ 0.9999999999999999), so
        // clamp leaves it untouched. (4000 * 0.999) = 3996.
        let result = backoff_ms_with_fraction(3, &RetryConfig::default(), 0.999);
        assert!(
            (3996..=4000).contains(&result),
            "expected ~3996, got {result}"
        );
    }

    #[test]
    fn t_backoff_jitter_fraction_clamps_negative() {
        assert_eq!(
            backoff_ms_with_fraction(3, &RetryConfig::default(), -0.5),
            0
        );
    }

    #[test]
    fn t_backoff_jitter_fraction_clamps_above_one() {
        // 1.5 clamps to 1.0_f64.next_down() ≈ 0.9999999999999999.
        // (4000 * 0.9999999999999999) ≈ 3999.999... → 3999 after f64→u64 truncation.
        let result = backoff_ms_with_fraction(3, &RetryConfig::default(), 1.5);
        assert!(
            (3999..=4000).contains(&result),
            "expected ~3999-4000, got {result}"
        );
    }

    #[test]
    fn t_backoff_jitter_fraction_nan() {
        // f64::clamp returns first arg (0.0) when given NaN.
        assert_eq!(
            backoff_ms_with_fraction(3, &RetryConfig::default(), f64::NAN),
            0
        );
    }

    // Production wrapper smoke tests (R3-C1).
    #[test]
    fn t_backoff_production_no_jitter_deterministic() {
        let cfg = no_jitter();
        assert_eq!(backoff_ms(3, &cfg), 4000);
        assert_eq!(backoff_ms(3, &cfg), 4000);
    }

    #[test]
    fn t_backoff_production_with_jitter_in_range() {
        let cfg = RetryConfig::default();
        let mut seen_distinct = false;
        let mut prev: Option<u64> = None;
        for _ in 0..100 {
            let result = backoff_ms(3, &cfg);
            assert!(
                result <= 4000,
                "production wrapper produced {result} above clamp 4000"
            );
            if let Some(p) = prev {
                if p != result {
                    seen_distinct = true;
                }
            }
            prev = Some(result);
        }
        // Probabilistic: across 100 calls with jitter, at least 2 distinct
        // values should appear with overwhelming probability. If this fires,
        // either rand::random is broken or the jitter path is dead.
        assert!(
            seen_distinct,
            "production jitter wrapper produced identical results 100x"
        );
    }

    use advance_runtime::config::RetryDefaults;
    use std::collections::HashMap;

    fn provider_with_retry(rd: Option<RetryDefaults>) -> LlmProviderConfig {
        LlmProviderConfig {
            id: "p".into(),
            endpoint: "https://x.example".into(),
            api_key_secret: "k".into(),
            model_aliases: HashMap::new(),
            cost_per_mtoken_in: 1.0,
            cost_per_mtoken_out: 5.0,
            rate_limit: None,
            retry_default: rd,
            backend: None,
            auth_scheme: None,
            backend_class: advance_runtime::config::InferenceBackendClass::CloudHttp,
            embedding_model: None,
            sidecar: None,
            profile_id: None,
        }
    }

    fn rd(mr: u32, base: u64, max: u64) -> RetryDefaults {
        RetryDefaults {
            max_retries: mr,
            base_delay_ms: base,
            max_delay_ms: max,
        }
    }

    #[test]
    fn t_resolve_retry_config_run_override_wins() {
        let p = provider_with_retry(Some(rd(2, 100, 1_000)));
        let agent = PartialRetry {
            max_retries: Some(7),
            base_delay_ms: Some(700),
            max_delay_ms: Some(7_000),
            jitter: Some(false),
        };
        let run = PartialRetry {
            max_retries: Some(5),
            base_delay_ms: Some(500),
            max_delay_ms: Some(5_000),
            jitter: Some(true),
        };
        let r = resolve_retry_config(&p, Some(&agent), Some(&run));
        assert_eq!(r.max_retries, 5);
        assert_eq!(r.base_delay_ms, 500);
        assert_eq!(r.max_delay_ms, 5_000);
        assert!(r.jitter);
    }

    #[test]
    fn t_resolve_retry_config_agent_override_wins() {
        let p = provider_with_retry(Some(rd(2, 100, 1_000)));
        let agent = PartialRetry {
            max_retries: Some(7),
            base_delay_ms: Some(700),
            max_delay_ms: Some(7_000),
            jitter: Some(false),
        };
        let r = resolve_retry_config(&p, Some(&agent), None);
        assert_eq!(r.max_retries, 7);
        assert_eq!(r.base_delay_ms, 700);
        assert_eq!(r.max_delay_ms, 7_000);
        assert!(!r.jitter);
    }

    #[test]
    fn t_resolve_retry_config_provider_default_wins() {
        let p = provider_with_retry(Some(rd(2, 100, 1_000)));
        let r = resolve_retry_config(&p, None, None);
        assert_eq!(r.max_retries, 2);
        assert_eq!(r.base_delay_ms, 100);
        assert_eq!(r.max_delay_ms, 1_000);
        // Provider tier omits jitter — falls through to RetryConfig::default().jitter == true.
        assert!(r.jitter);
    }

    #[test]
    fn t_resolve_retry_config_no_tiers_uses_static_default_safety_net() {
        let p = provider_with_retry(None);
        let r = resolve_retry_config(&p, None, None);
        assert_eq!(r, RetryConfig::default());
    }

    #[test]
    fn t_resolve_retry_config_partial_override_merges() {
        // Provider has full set; agent overrides only max_retries.
        let p = provider_with_retry(Some(rd(2, 100, 1_000)));
        let agent = PartialRetry {
            max_retries: Some(9),
            ..Default::default()
        };
        let r = resolve_retry_config(&p, Some(&agent), None);
        assert_eq!(r.max_retries, 9, "agent's override wins for max_retries");
        assert_eq!(r.base_delay_ms, 100, "provider tier supplies base_delay_ms");
        assert_eq!(r.max_delay_ms, 1_000, "provider tier supplies max_delay_ms");
        assert!(r.jitter, "no tier set jitter — defaults to true");
    }
}
