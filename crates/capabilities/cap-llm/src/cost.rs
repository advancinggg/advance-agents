//! Per-call cost computation. MODULE-009 §1.4.2 generate flow + AC-07 ledger.
//!
//! `compute_cost(provider, input_tokens, output_tokens, cache)` returns USD
//! cost using the provider's published per-million-token rates, with the
//! cached share of the input priced at the provider's cache-read / cache-write
//! rates instead of the full input rate. The arithmetic is total —
//! saturating-cast on `u64 → f64` keeps the function panic-free even for
//! adversarial token counts.
//!
//! # Input-token contract (cache billing)
//!
//! `input_tokens` is ALWAYS the TOTAL prompt size, cached share included.
//! The three upstream APIs report this differently and the adapters normalize
//! at the parse boundary:
//!
//! * OpenAI Chat Completions: `usage.prompt_tokens` is already the total;
//!   `usage.prompt_tokens_details.cached_tokens` is a SUBSET of it.
//! * OpenAI Responses: `usage.input_tokens` is the total;
//!   `usage.input_tokens_details.cached_tokens` is a subset.
//! * Anthropic Messages: `usage.input_tokens` is only the UNCACHED REMAINDER.
//!   `usage.cache_creation_input_tokens` and `usage.cache_read_input_tokens`
//!   sit beside it, so the total is the sum of all three. The adapter performs
//!   that sum; a consumer that read `input_tokens` alone silently dropped every
//!   cached token (and its cost) from the run budget.
//!
//! `CacheUsage` carries the cached share split by kind, because the two are
//! priced an order of magnitude apart (Anthropic: reads ≈ 0.1× input, 5-minute
//! writes 1.25×, 1-hour writes 2×). Folding them into one counter can never be
//! priced correctly.

use crate::catalog::CacheCost;
use crate::provider::ResolvedProvider;

/// Cached share of a call's input tokens, split by kind. Both counters are
/// SUBSETS of the total `input_tokens` passed to [`compute_cost`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheUsage {
    /// Tokens served from a prompt cache (Anthropic `cache_read_input_tokens`,
    /// OpenAI `*_details.cached_tokens`).
    pub read_tokens: u64,
    /// Tokens written into a prompt cache this call (Anthropic
    /// `cache_creation_input_tokens`; OpenAI never reports writes).
    pub write_tokens: u64,
}

impl CacheUsage {
    pub const NONE: CacheUsage = CacheUsage {
        read_tokens: 0,
        write_tokens: 0,
    };

    pub fn is_none(&self) -> bool {
        self.read_tokens == 0 && self.write_tokens == 0
    }

    /// Clamp both counters so `read + write <= input_total`. A provider (or a
    /// proxy in front of it) that reports more cached tokens than input tokens
    /// is malformed; the clamp keeps the uncached remainder non-negative and
    /// never lets the cache discount exceed the input it applies to.
    pub fn clamped_to(self, input_total: u64) -> CacheUsage {
        let read = self.read_tokens.min(input_total);
        let write = self.write_tokens.min(input_total.saturating_sub(read));
        CacheUsage {
            read_tokens: read,
            write_tokens: write,
        }
    }

    /// Element-wise `min` against a per-attempt ceiling (mirrors the gateway's
    /// `MAX_TOKENS_PER_ATTEMPT` clamp on the input/output counters).
    pub fn clamp_each(self, ceiling: u64) -> CacheUsage {
        CacheUsage {
            read_tokens: self.read_tokens.min(ceiling),
            write_tokens: self.write_tokens.min(ceiling),
        }
    }
}

/// Compute the USD cost of a single completed LLM call given the provider's
/// per-million-token rates and the token usage reported by the upstream API.
///
/// Formula (MODULE-009 §1.4.2, extended with the cache tiers):
/// ```text
///   uncached = input_tokens - cache.read_tokens - cache.write_tokens
///   cost_usd = (uncached           / 1e6) * cost_per_mtoken_in
///            + (cache.read_tokens  / 1e6) * cache_cost.read_per_mtoken
///            + (cache.write_tokens / 1e6) * cache_cost.write_per_mtoken
///            + (output_tokens      / 1e6) * cost_per_mtoken_out
/// ```
///
/// `cache` is clamped to `input_tokens` first (see [`CacheUsage::clamped_to`]),
/// so the discount can never exceed the input it applies to. With
/// `CacheUsage::NONE` the formula reduces to the historical two-rate form.
///
/// Saturating-cast semantics: `u64 as f64` for tokens above `2^53` loses
/// precision but never panics. Realistic LLM calls fit well below the f64
/// mantissa precision boundary; the saturating cast is purely a defense
/// against adversarial / corrupted upstream `usage` payloads.
pub fn compute_cost(
    provider: &ResolvedProvider,
    input_tokens: u64,
    output_tokens: u64,
    cache: CacheUsage,
) -> f64 {
    compute_cost_with_rates(
        provider.cost_per_mtoken_in,
        provider.cost_per_mtoken_out,
        &provider.cache_cost,
        input_tokens,
        output_tokens,
        cache,
    )
}

/// Rate-level form of [`compute_cost`] for callers that hold the rates but
/// not a `ResolvedProvider` (the live-stream `Settlement`). ONE formula, so
/// the buffered and streaming paths cannot drift.
pub fn compute_cost_with_rates(
    cost_per_mtoken_in: f64,
    cost_per_mtoken_out: f64,
    cache_cost: &CacheCost,
    input_tokens: u64,
    output_tokens: u64,
    cache: CacheUsage,
) -> f64 {
    let cache = cache.clamped_to(input_tokens);
    let uncached = input_tokens
        .saturating_sub(cache.read_tokens)
        .saturating_sub(cache.write_tokens);
    let in_cost = (uncached as f64 / 1_000_000.0) * cost_per_mtoken_in;
    let read_cost = (cache.read_tokens as f64 / 1_000_000.0) * cache_cost.read_per_mtoken;
    let write_cost = (cache.write_tokens as f64 / 1_000_000.0) * cache_cost.write_per_mtoken;
    let out_cost = (output_tokens as f64 / 1_000_000.0) * cost_per_mtoken_out;
    in_cost + read_cost + write_cost + out_cost
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> ResolvedProvider {
        ResolvedProvider {
            id: "openai".into(),
            endpoint: "https://api.openai.com".into(),
            api_key_secret: "openai-api-key".into(),
            model: "gpt-4o-mini".into(),
            cost_per_mtoken_in: 0.150,
            cost_per_mtoken_out: 0.600,
            cache_cost: CacheCost {
                read_per_mtoken: 0.075,
                write_per_mtoken: 0.1875,
            },
            backend: advance_runtime::config::ProviderBackend::OpenAiChat,
            auth_scheme: None,
            backend_class: advance_runtime::config::InferenceBackendClass::CloudHttp,
            embedding_model: None,
        }
    }

    /// MODULE-009-T67 — exact arithmetic, no off-by-million-tokens.
    #[test]
    fn t_compute_cost_exact_arithmetic() {
        let p = provider();
        let cost = compute_cost(&p, 1_000, 500, CacheUsage::NONE);
        // (1000/1e6 * 0.150) + (500/1e6 * 0.600) = 0.000150 + 0.000300 = 0.000450
        let expected = 0.000_450;
        assert!(
            (cost - expected).abs() < 1e-12,
            "cost={cost} expected={expected}"
        );
    }

    /// MODULE-009-T68 — boundary: zero tokens → 0.0; saturating cast on u64::MAX
    /// does not panic (no NaN/Inf in finite arithmetic with finite rates).
    #[test]
    fn t_compute_cost_zero_tokens() {
        let p = provider();
        assert_eq!(compute_cost(&p, 0, 0, CacheUsage::NONE), 0.0);
    }

    #[test]
    fn t_compute_cost_max_tokens_no_panic() {
        let p = provider();
        let cost = compute_cost(&p, u64::MAX, u64::MAX, CacheUsage::NONE);
        // u64::MAX as f64 ~= 1.844674e19; * 0.150 / 1e6 = 2.767e12 (huge but finite)
        assert!(cost.is_finite(), "cost={cost} should be finite");
        assert!(cost > 0.0);
    }

    /// Cache-read share is billed at the read rate, the remainder at the
    /// full input rate. 1000 input of which 600 cached-read:
    ///   400/1e6*0.150 + 600/1e6*0.075 + 500/1e6*0.600
    #[test]
    fn t_compute_cost_cache_read_discounted() {
        let p = provider();
        let cost = compute_cost(
            &p,
            1_000,
            500,
            CacheUsage {
                read_tokens: 600,
                write_tokens: 0,
            },
        );
        let expected = 0.000_060 + 0.000_045 + 0.000_300;
        assert!(
            (cost - expected).abs() < 1e-12,
            "cost={cost} expected={expected}"
        );
        // Strictly cheaper than the same call with no cache hit.
        assert!(cost < compute_cost(&p, 1_000, 500, CacheUsage::NONE));
    }

    /// Cache WRITES are priced at the write rate (above the input rate), so a
    /// call that writes the cache costs MORE than an uncached call, never less.
    #[test]
    fn t_compute_cost_cache_write_premium() {
        let p = provider();
        let cost = compute_cost(
            &p,
            1_000,
            0,
            CacheUsage {
                read_tokens: 0,
                write_tokens: 1_000,
            },
        );
        let expected = 1_000.0 / 1e6 * 0.1875;
        assert!(
            (cost - expected).abs() < 1e-12,
            "cost={cost} expected={expected}"
        );
        assert!(cost > compute_cost(&p, 1_000, 0, CacheUsage::NONE));
    }

    /// Read and write are priced INDEPENDENTLY — a mixed call is the exact
    /// sum of the three tiers, not any single blended rate.
    #[test]
    fn t_compute_cost_cache_read_and_write_independent() {
        let p = provider();
        let cost = compute_cost(
            &p,
            1_000,
            0,
            CacheUsage {
                read_tokens: 300,
                write_tokens: 200,
            },
        );
        let expected = 500.0 / 1e6 * 0.150 + 300.0 / 1e6 * 0.075 + 200.0 / 1e6 * 0.1875;
        assert!(
            (cost - expected).abs() < 1e-12,
            "cost={cost} expected={expected}"
        );
    }

    /// Adversarial: cached counters exceeding the input total are clamped so
    /// the discount can never exceed the input it applies to (no negative
    /// uncached remainder, no runaway write premium).
    #[test]
    fn t_compute_cost_cache_clamped_to_input() {
        let p = provider();
        let over = CacheUsage {
            read_tokens: u64::MAX,
            write_tokens: u64::MAX,
        };
        assert_eq!(
            over.clamped_to(1_000),
            CacheUsage {
                read_tokens: 1_000,
                write_tokens: 0
            }
        );
        let cost = compute_cost(&p, 1_000, 0, over);
        let expected = 1_000.0 / 1e6 * 0.075;
        assert!(
            (cost - expected).abs() < 1e-12,
            "cost={cost} expected={expected}"
        );
        assert!(cost.is_finite());
    }

    /// `CacheUsage::NONE` reduces exactly to the historical two-rate formula.
    #[test]
    fn t_compute_cost_no_cache_is_two_rate_formula() {
        let p = provider();
        let a = compute_cost(&p, 1_234, 567, CacheUsage::NONE);
        let b = (1_234.0 / 1e6) * 0.150 + (567.0 / 1e6) * 0.600;
        assert!((a - b).abs() < 1e-12);
    }
}
