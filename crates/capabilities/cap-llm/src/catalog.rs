//! CONTRACT-237 Model Profile Catalog (MODULE-009-AC-25).

use std::collections::BTreeMap;

use crate::error::LlmError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CatalogTier {
    Stable,
    Evaluation,
    Experimental,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProfileKey {
    pub model_version: String,
    pub quantization: String,
    pub backend: String,
    pub chat_template: String,
    pub tool_parser: String,
}

/// Quirk-as-data usage normalization: JSON pointers (or bare top-level keys)
/// into the provider's raw `usage` object. Every list is SUMMED.
///
/// The cached share is split into READ and WRITE sources because the two are
/// priced an order of magnitude apart (Anthropic: reads ≈ 0.1× the input
/// rate, cache writes 1.25× / 2×). A single summed "cached" counter could
/// express OpenAI's one `cached_tokens` field but never Anthropic's two.
///
/// `input_token_sources` is summed too, which is what makes the two
/// accounting models fit ONE fold: OpenAI's `prompt_tokens` is already the
/// total (list only it), while Anthropic's `input_tokens` is the uncached
/// REMAINDER (list it together with both cache fields so the fold's
/// `input_tokens` is the true total). See [`UsageNorm::anthropic_messages`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UsageNorm {
    /// Summed into the TOTAL input. Empty → `prompt_tokens` (OpenAI Chat).
    pub input_token_sources: Vec<String>,
    /// Summed into the output count. Empty → `completion_tokens`.
    pub output_token_sources: Vec<String>,
    /// Summed into `cache_read_tokens` (a subset of the total input).
    pub cache_read_sources: Vec<String>,
    /// Summed into `cache_write_tokens` (a subset of the total input).
    pub cache_write_sources: Vec<String>,
}

impl UsageNorm {
    /// OpenAI Chat Completions: `prompt_tokens` is the total;
    /// `prompt_tokens_details.cached_tokens` is a subset. No writes reported.
    pub fn openai_chat() -> Self {
        Self {
            input_token_sources: vec!["/prompt_tokens".into()],
            output_token_sources: vec!["/completion_tokens".into()],
            cache_read_sources: vec!["/prompt_tokens_details/cached_tokens".into()],
            cache_write_sources: Vec::new(),
        }
    }

    /// OpenAI Responses: `input_tokens` is the total;
    /// `input_tokens_details.cached_tokens` is a subset. No writes reported.
    pub fn openai_responses() -> Self {
        Self {
            input_token_sources: vec!["/input_tokens".into()],
            output_token_sources: vec!["/output_tokens".into()],
            cache_read_sources: vec!["/input_tokens_details/cached_tokens".into()],
            cache_write_sources: Vec::new(),
        }
    }

    /// Anthropic Messages: `input_tokens` is only the UNCACHED remainder;
    /// `cache_creation_input_tokens` + `cache_read_input_tokens` sit beside it.
    /// Total input = the sum of all three, hence three input sources.
    pub fn anthropic_messages() -> Self {
        Self {
            input_token_sources: vec![
                "/input_tokens".into(),
                "/cache_creation_input_tokens".into(),
                "/cache_read_input_tokens".into(),
            ],
            output_token_sources: vec!["/output_tokens".into()],
            cache_read_sources: vec!["/cache_read_input_tokens".into()],
            cache_write_sources: vec!["/cache_creation_input_tokens".into()],
        }
    }
}

/// Per-million-token USD rates for the cached share of the input.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CacheCost {
    pub read_per_mtoken: f64,
    pub write_per_mtoken: f64,
}

impl CacheCost {
    /// Published Anthropic multipliers relative to the base input rate:
    /// cache reads 0.1×, 5-minute-TTL cache writes 1.25×.
    pub const ANTHROPIC_READ_MULTIPLIER: f64 = 0.1;
    pub const ANTHROPIC_WRITE_5M_MULTIPLIER: f64 = 1.25;

    /// Fail-CONSERVATIVE default when a provider config omits the cache rates:
    /// reads are billed at the FULL input rate (never an unearned discount) and
    /// writes at the published 1.25× write premium (the only backend that
    /// reports writes charges at least that). An operator who wants the real
    /// read discount sets `cost-per-mtoken-cache-read` explicitly.
    pub fn conservative_from_input_rate(cost_per_mtoken_in: f64) -> Self {
        Self {
            read_per_mtoken: cost_per_mtoken_in,
            write_per_mtoken: cost_per_mtoken_in * Self::ANTHROPIC_WRITE_5M_MULTIPLIER,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProfileQuirks {
    pub reasoning_level_map: BTreeMap<String, String>,
    pub usage_normalization: UsageNorm,
    pub cache_cost: CacheCost,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BenchmarkProvenance {
    pub harness_id: String,
    pub result_ref: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModelProfile {
    pub key: ProfileKey,
    pub tier: CatalogTier,
    pub licence: String,
    pub benchmark_provenance: Option<BenchmarkProvenance>,
    pub quirks: ProfileQuirks,
    pub capabilities: crate::capability::CapabilityDescriptor,
}

#[derive(Clone, Debug, Default)]
pub struct ModelProfileCatalog {
    by_id: BTreeMap<String, ModelProfile>,
}

impl ModelProfileCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, id: &str) -> Option<&ModelProfile> {
        self.by_id.get(id)
    }

    pub fn insert(&mut self, id: String, profile: ModelProfile) -> Result<(), LlmError> {
        if profile.licence.trim().is_empty() {
            return Err(LlmError::ModelNotAvailable(
                "catalog profile missing licence".into(),
            ));
        }
        if self.by_id.values().any(|p| {
            p.key == profile.key && !self.by_id.get(&id).is_some_and(|e| e.key == profile.key)
        }) {
            // uniqueness of registration unit
            if self.by_id.values().any(|p| p.key == profile.key) {
                return Err(LlmError::ModelNotAvailable(
                    "catalog registration unit already exists".into(),
                ));
            }
        }
        if self.by_id.values().any(|p| p.key == profile.key) && !self.by_id.contains_key(&id) {
            return Err(LlmError::ModelNotAvailable(
                "catalog registration unit already exists".into(),
            ));
        }
        self.by_id.insert(id, profile);
        Ok(())
    }

    /// Auto-route never picks `experimental`.
    pub fn default_id(&self) -> Result<&str, LlmError> {
        let mut candidates: Vec<&str> = self
            .by_id
            .iter()
            .filter(|(_, p)| p.tier != CatalogTier::Experimental)
            .map(|(id, _)| id.as_str())
            .collect();
        candidates.sort();
        candidates.into_iter().next().ok_or_else(|| {
            LlmError::ModelNotAvailable("catalog has no stable/evaluation profile".into())
        })
    }

    pub fn promote_to_stable(&mut self, id: &str) -> Result<(), LlmError> {
        let p = self
            .by_id
            .get_mut(id)
            .ok_or_else(|| LlmError::ModelNotAvailable(format!("unknown profile {id}")))?;
        if p.benchmark_provenance.is_none() {
            return Err(LlmError::ModelNotAvailable(
                "promotion to stable requires Advance-benchmark provenance".into(),
            ));
        }
        p.tier = CatalogTier::Stable;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NormalizedUsageFold {
    /// TOTAL input, cached share included (see [`UsageNorm`]).
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Subset of `input_tokens` served from cache.
    pub cache_read_tokens: u64,
    /// Subset of `input_tokens` written to cache.
    pub cache_write_tokens: u64,
}

impl NormalizedUsageFold {
    pub fn cache(&self) -> crate::cost::CacheUsage {
        crate::cost::CacheUsage {
            read_tokens: self.cache_read_tokens,
            write_tokens: self.cache_write_tokens,
        }
    }
}

fn sum_sources(raw: &serde_json::Value, sources: &[String], fallback: &str) -> u64 {
    if sources.is_empty() {
        return raw.get(fallback).and_then(|v| v.as_u64()).unwrap_or(0);
    }
    let mut total = 0u64;
    for path in sources {
        // JSON pointer first (`/a/b`), then a bare top-level key for
        // backward compatibility with pre-pointer quirk data.
        let n = raw
            .pointer(path)
            .and_then(|v| v.as_u64())
            .or_else(|| raw.get(path).and_then(|v| v.as_u64()));
        if let Some(n) = n {
            total = total.saturating_add(n);
        }
    }
    total
}

/// Quirk-as-data usage fold (MODULE-009 §3958). Every source list is summed;
/// the cached counters are then clamped so `read + write <= input_tokens`.
pub fn normalize_usage(raw: &serde_json::Value, quirks: &ProfileQuirks) -> NormalizedUsageFold {
    let norm = &quirks.usage_normalization;
    let input_tokens = sum_sources(raw, &norm.input_token_sources, "prompt_tokens");
    let output_tokens = sum_sources(raw, &norm.output_token_sources, "completion_tokens");
    let cache = crate::cost::CacheUsage {
        read_tokens: sum_sources(raw, &norm.cache_read_sources, ""),
        write_tokens: sum_sources(raw, &norm.cache_write_sources, ""),
    }
    .clamped_to(input_tokens);
    NormalizedUsageFold {
        input_tokens,
        output_tokens,
        cache_read_tokens: cache.read_tokens,
        cache_write_tokens: cache.write_tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityDescriptor, ToolCallingLevel};

    fn key(template: &str, parser: &str) -> ProfileKey {
        ProfileKey {
            model_version: "v1".into(),
            quantization: "q4".into(),
            backend: "local".into(),
            chat_template: template.into(),
            tool_parser: parser.into(),
        }
    }

    fn profile(key: ProfileKey, tier: CatalogTier) -> ModelProfile {
        ModelProfile {
            key,
            tier,
            licence: "Apache-2.0".into(),
            benchmark_provenance: None,
            quirks: ProfileQuirks::default(),
            capabilities: CapabilityDescriptor {
                tool_calling: ToolCallingLevel::Disabled,
                ..CapabilityDescriptor::unbound_local(false)
            },
        }
    }

    #[test]
    fn t130_registration_unit_uniqueness() {
        let mut c = ModelProfileCatalog::new();
        c.insert(
            "a".into(),
            profile(key("t1", "p1"), CatalogTier::Evaluation),
        )
        .unwrap();
        let err = c
            .insert(
                "b".into(),
                profile(key("t1", "p1"), CatalogTier::Evaluation),
            )
            .unwrap_err();
        assert!(matches!(err, LlmError::ModelNotAvailable(_)));
        c.insert(
            "c".into(),
            profile(key("t1", "p2"), CatalogTier::Evaluation),
        )
        .unwrap();
    }

    #[test]
    fn t130_experimental_never_auto() {
        let mut c = ModelProfileCatalog::new();
        c.insert(
            "exp".into(),
            profile(key("t", "p"), CatalogTier::Experimental),
        )
        .unwrap();
        assert!(c.default_id().is_err());
        c.insert(
            "ok".into(),
            profile(
                ProfileKey {
                    model_version: "v2".into(),
                    quantization: "q4".into(),
                    backend: "local".into(),
                    chat_template: "t".into(),
                    tool_parser: "p".into(),
                },
                CatalogTier::Evaluation,
            ),
        )
        .unwrap();
        assert_eq!(c.default_id().unwrap(), "ok");
    }

    #[test]
    fn t130_empty_catalog_generate_unaffected() {
        let c = ModelProfileCatalog::new();
        assert!(c.get("missing").is_none());
    }

    #[test]
    fn t130_promote_requires_benchmark() {
        let mut c = ModelProfileCatalog::new();
        c.insert("a".into(), profile(key("t", "p"), CatalogTier::Evaluation))
            .unwrap();
        assert!(c.promote_to_stable("a").is_err());
        c.by_id.get_mut("a").unwrap().benchmark_provenance = Some(BenchmarkProvenance {
            harness_id: "h".into(),
            result_ref: "r".into(),
        });
        c.promote_to_stable("a").unwrap();
        assert_eq!(c.get("a").unwrap().tier, CatalogTier::Stable);
    }

    #[test]
    fn t130_licence_required() {
        let mut c = ModelProfileCatalog::new();
        let mut p = profile(key("t", "p"), CatalogTier::Evaluation);
        p.licence.clear();
        assert!(c.insert("a".into(), p).is_err());
    }

    #[test]
    fn t130b_multi_source_cached_tokens() {
        let quirks = ProfileQuirks {
            usage_normalization: UsageNorm {
                cache_read_sources: vec![
                    "cached_tokens".into(),
                    "/prompt_tokens_details/cached_tokens".into(),
                ],
                ..UsageNorm::default()
            },
            cache_cost: CacheCost {
                read_per_mtoken: 0.1,
                write_per_mtoken: 0.2,
            },
            ..ProfileQuirks::default()
        };
        let raw = serde_json::json!({
            "prompt_tokens": 10,
            "completion_tokens": 3,
            "cached_tokens": 4,
            "prompt_tokens_details": { "cached_tokens": 2 }
        });
        let n = normalize_usage(&raw, &quirks);
        assert_eq!(n.input_tokens, 10);
        assert_eq!(n.output_tokens, 3);
        assert_eq!(n.cache_read_tokens, 6);
        assert_eq!(n.cache_write_tokens, 0);
    }

    /// OpenAI Chat preset: `prompt_tokens` is the TOTAL and `cached_tokens`
    /// is a subset — the fold must NOT add the cached share on top.
    #[test]
    fn t130c_openai_chat_preset_cached_is_subset() {
        let quirks = ProfileQuirks {
            usage_normalization: UsageNorm::openai_chat(),
            ..ProfileQuirks::default()
        };
        let raw = serde_json::json!({
            "prompt_tokens": 1000,
            "completion_tokens": 20,
            "prompt_tokens_details": { "cached_tokens": 800 }
        });
        let n = normalize_usage(&raw, &quirks);
        assert_eq!(
            (n.input_tokens, n.cache_read_tokens, n.cache_write_tokens),
            (1000, 800, 0)
        );
    }

    /// Anthropic preset: `input_tokens` is the uncached REMAINDER; the total is
    /// remainder + creation + read, with read/write kept apart.
    #[test]
    fn t130d_anthropic_preset_input_is_remainder() {
        let quirks = ProfileQuirks {
            usage_normalization: UsageNorm::anthropic_messages(),
            ..ProfileQuirks::default()
        };
        let raw = serde_json::json!({
            "input_tokens": 100,
            "cache_creation_input_tokens": 300,
            "cache_read_input_tokens": 600,
            "output_tokens": 7
        });
        let n = normalize_usage(&raw, &quirks);
        assert_eq!(n.input_tokens, 1000, "total = remainder + write + read");
        assert_eq!(n.cache_read_tokens, 600);
        assert_eq!(n.cache_write_tokens, 300);
        assert_eq!(n.output_tokens, 7);
    }

    /// Malformed cached counters larger than the input total are clamped.
    #[test]
    fn t130e_cached_share_clamped_to_input_total() {
        let quirks = ProfileQuirks {
            usage_normalization: UsageNorm::openai_chat(),
            ..ProfileQuirks::default()
        };
        let raw = serde_json::json!({
            "prompt_tokens": 10,
            "completion_tokens": 1,
            "prompt_tokens_details": { "cached_tokens": 999 }
        });
        let n = normalize_usage(&raw, &quirks);
        assert_eq!((n.input_tokens, n.cache_read_tokens), (10, 10));
    }
}
