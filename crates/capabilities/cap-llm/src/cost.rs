//! Per-call cost computation. MODULE-009 §1.4.2 generate flow + AC-07 ledger.
//!
//! `compute_cost(provider, input_tokens, output_tokens)` returns USD cost
//! using the provider's published per-million-token rates. The arithmetic
//! is total — saturating-cast on `u64 → f64` keeps the function panic-free
//! even for adversarial token counts.

use crate::provider::ResolvedProvider;

/// Compute the USD cost of a single completed LLM call given the provider's
/// per-million-token rates and the token usage reported by the upstream API.
///
/// Formula (MODULE-009 §1.4.2):
/// ```text
///   cost_usd = (input_tokens  / 1_000_000) * cost_per_mtoken_in
///            + (output_tokens / 1_000_000) * cost_per_mtoken_out
/// ```
///
/// Saturating-cast semantics: `u64 as f64` for tokens above `2^53` loses
/// precision but never panics. Realistic LLM calls fit well below the f64
/// mantissa precision boundary; the saturating cast is purely a defense
/// against adversarial / corrupted upstream `usage` payloads.
pub fn compute_cost(provider: &ResolvedProvider, input_tokens: u64, output_tokens: u64) -> f64 {
    let in_cost = (input_tokens as f64 / 1_000_000.0) * provider.cost_per_mtoken_in;
    let out_cost = (output_tokens as f64 / 1_000_000.0) * provider.cost_per_mtoken_out;
    in_cost + out_cost
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
        let cost = compute_cost(&p, 1_000, 500);
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
        assert_eq!(compute_cost(&p, 0, 0), 0.0);
    }

    #[test]
    fn t_compute_cost_max_tokens_no_panic() {
        let p = provider();
        let cost = compute_cost(&p, u64::MAX, u64::MAX);
        // u64::MAX as f64 ~= 1.844674e19; * 0.150 / 1e6 = 2.767e12 (huge but finite)
        assert!(cost.is_finite(), "cost={cost} should be finite");
        assert!(cost > 0.0);
    }
}
