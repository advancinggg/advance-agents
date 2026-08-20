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

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UsageNorm {
    pub cached_token_sources: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CacheCost {
    pub read_per_mtoken: f64,
    pub write_per_mtoken: f64,
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
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
}

/// Quirk-as-data usage fold (MODULE-009 §3958).
pub fn normalize_usage(raw: &serde_json::Value, quirks: &ProfileQuirks) -> NormalizedUsageFold {
    let mut cached = 0u64;
    for path in &quirks.usage_normalization.cached_token_sources {
        if let Some(n) = raw.pointer(path).and_then(|v| v.as_u64()) {
            cached = cached.saturating_add(n);
        } else if let Some(n) = raw.get(path).and_then(|v| v.as_u64()) {
            cached = cached.saturating_add(n);
        }
    }
    NormalizedUsageFold {
        input_tokens: raw
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        output_tokens: raw
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        cached_tokens: cached,
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
                cached_token_sources: vec![
                    "cached_tokens".into(),
                    "/prompt_tokens_details/cached_tokens".into(),
                ],
            },
            cache_cost: CacheCost {
                read_per_mtoken: 0.1,
                write_per_mtoken: 0.2,
            },
            ..Default::default()
        };
        let raw = serde_json::json!({
            "prompt_tokens": 10,
            "completion_tokens": 3,
            "cached_tokens": 4,
            "prompt_tokens_details": { "cached_tokens": 2 }
        });
        let n = normalize_usage(&raw, &quirks);
        assert_eq!(n.cached_tokens, 6);
        assert_eq!(quirks.cache_cost.read_per_mtoken, 0.1);
    }
}
