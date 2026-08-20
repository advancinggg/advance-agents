//! CONTRACT-237 capability descriptors + skip-aware walker (MODULE-009-AC-24).

use crate::catalog::ModelProfileCatalog;
use crate::error::LlmError;
use crate::gateway::ChatParams;
use crate::provider::{make_resolved, ResolvedProvider};
use advance_runtime::config::{InferenceBackendClass, LlmProviderConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolCallingLevel {
    Native,
    Constrained,
    RepairOnly,
    Disabled,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CapabilityDescriptor {
    pub tool_calling: ToolCallingLevel,
    pub structured_output: bool,
    pub embeddings: bool,
    pub image: bool,
    pub max_context: Option<u32>,
    pub max_output: Option<u32>,
}

impl CapabilityDescriptor {
    pub fn unbound_cloud_http() -> Self {
        Self {
            tool_calling: ToolCallingLevel::Disabled,
            structured_output: true,
            embeddings: true,
            image: true,
            max_context: None,
            max_output: None,
        }
    }

    pub fn unbound_local(has_embedding_model: bool) -> Self {
        Self {
            tool_calling: ToolCallingLevel::Disabled,
            structured_output: true,
            embeddings: has_embedding_model,
            image: false,
            max_context: None,
            max_output: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CapabilityNeed {
    pub tools: bool,
    pub output_schema: bool,
    pub image: bool,
    pub prompt_tokens_est: Option<u32>,
    pub max_tokens: Option<u32>,
}

impl CapabilityNeed {
    pub fn from_chat(params: &ChatParams, image: bool) -> Self {
        Self {
            tools: params.tools.as_ref().is_some_and(|t| !t.is_empty()),
            output_schema: false, // filled by caller from LlmRequestContext
            image,
            prompt_tokens_est: None,
            max_tokens: params.max_tokens,
        }
    }
}

pub fn descriptor_for(
    cfg: &LlmProviderConfig,
    catalog: &ModelProfileCatalog,
) -> Result<CapabilityDescriptor, LlmError> {
    if let Some(id) = cfg.profile_id.as_deref() {
        let p = catalog
            .get(id)
            .ok_or_else(|| LlmError::ModelNotAvailable(format!("unknown profile {id}")))?;
        if p.capabilities.image && cfg.backend_class == InferenceBackendClass::Local {
            return Err(LlmError::ModelNotAvailable(
                "catalog profile claims image on a text-only local sidecar".into(),
            ));
        }
        if p.capabilities.tool_calling != ToolCallingLevel::Disabled
            && cfg.backend_class == InferenceBackendClass::CloudHttp
        {
            return Err(LlmError::ModelNotAvailable(
                "catalog profile claims native tools on cloud-http OpenAI-chat before websearch-s1"
                    .into(),
            ));
        }
        return Ok(p.capabilities.clone());
    }
    Ok(match cfg.backend_class {
        InferenceBackendClass::Local => {
            CapabilityDescriptor::unbound_local(cfg.embedding_model.is_some())
        }
        InferenceBackendClass::CloudHttp => CapabilityDescriptor::unbound_cloud_http(),
    })
}

pub fn missing_capability(
    desc: &CapabilityDescriptor,
    need: &CapabilityNeed,
) -> Option<&'static str> {
    if need.tools && desc.tool_calling == ToolCallingLevel::Disabled {
        return Some("tools");
    }
    if need.output_schema && !desc.structured_output {
        return Some("structured-output");
    }
    if need.image && !desc.image {
        return Some("image");
    }
    if let (Some(est), Some(max)) = (need.prompt_tokens_est, desc.max_context) {
        if est > max {
            return Some("max-context");
        }
    }
    if let (Some(out), Some(max)) = (need.max_tokens, desc.max_output) {
        if out > max {
            return Some("max-output");
        }
    }
    None
}

/// Skip-aware walker. Does not re-call `resolve_provider_and_model` (2c leak).
pub fn walk_eligible(
    providers: &[LlmProviderConfig],
    hint: Option<&str>,
    catalog: &ModelProfileCatalog,
    need: &CapabilityNeed,
) -> Result<ResolvedProvider, LlmError> {
    let mut last_unsup: Option<&'static str> = None;
    let mut last_bind: Option<LlmError> = None;
    for p in providers {
        let desc = match descriptor_for(p, catalog) {
            Ok(d) => d,
            Err(e) => {
                last_bind = Some(e);
                continue;
            }
        };
        if let Some(m) = missing_capability(&desc, need) {
            last_unsup = Some(m);
            continue;
        }
        let model = match hint {
            None => {
                if p.model_aliases.is_empty() {
                    continue;
                }
                let mut keys: Vec<&String> = p.model_aliases.keys().collect();
                keys.sort();
                p.model_aliases[keys[0]].clone()
            }
            Some(name) => {
                if let Some(v) = p.model_aliases.get(name) {
                    v.clone()
                } else if p.model_aliases.values().any(|v| v == name) {
                    name.to_string()
                } else {
                    // Do not apply 2c literal-name fallback onto a foreign provider.
                    continue;
                }
            }
        };
        return Ok(make_resolved(p, model));
    }
    if let (None, Some(bind)) = (last_unsup, last_bind) {
        return Err(bind);
    }
    Err(LlmError::ProviderError(format!(
        "unsupported capability: {}",
        last_unsup.unwrap_or("none eligible")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::ToolDefinition;
    use std::collections::HashMap;

    fn cfg(id: &str, class: InferenceBackendClass, aliases: &[(&str, &str)]) -> LlmProviderConfig {
        let mut model_aliases = HashMap::new();
        for (k, v) in aliases {
            model_aliases.insert((*k).into(), (*v).into());
        }
        LlmProviderConfig {
            id: id.into(),
            endpoint: "https://api.example".into(),
            api_key_secret: "s".into(),
            model_aliases,
            cost_per_mtoken_in: 0.1,
            cost_per_mtoken_out: 0.1,
            rate_limit: None,
            retry_default: None,
            backend: None,
            auth_scheme: None,
            backend_class: class,
            embedding_model: None,
            sidecar: None,
            profile_id: None,
        }
    }

    #[test]
    fn t129_unbound_tools_unsupported() {
        let local = cfg("local", InferenceBackendClass::Local, &[("llama", "llama")]);
        let cat = ModelProfileCatalog::new();
        let need = CapabilityNeed {
            tools: true,
            output_schema: false,
            image: false,
            prompt_tokens_est: None,
            max_tokens: None,
        };
        let err = walk_eligible(&[local], Some("llama"), &cat, &need).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unsupported capability"), "{msg}");
    }

    #[test]
    fn t129_walker_does_not_2c_leak() {
        let local = cfg(
            "local",
            InferenceBackendClass::Local,
            &[("llama", "llama-7b")],
        );
        let cloud = cfg(
            "cloud",
            InferenceBackendClass::CloudHttp,
            &[("gpt", "gpt-4o")],
        );
        let cat = ModelProfileCatalog::new();
        let need = CapabilityNeed {
            tools: true,
            output_schema: false,
            image: false,
            prompt_tokens_est: None,
            max_tokens: None,
        };
        // tools disabled on both unbound → no eligible, not "llama" sent to cloud
        let err = walk_eligible(&[local, cloud], Some("llama"), &cat, &need).unwrap_err();
        assert!(format!("{err}").contains("unsupported capability"));
    }

    #[test]
    fn t129_bound_structured_output_false() {
        let mut cat = ModelProfileCatalog::new();
        cat.insert(
            "p".into(),
            crate::catalog::ModelProfile {
                key: crate::catalog::ProfileKey {
                    model_version: "v1".into(),
                    quantization: "q4".into(),
                    backend: "local".into(),
                    chat_template: "t".into(),
                    tool_parser: "p".into(),
                },
                tier: crate::catalog::CatalogTier::Evaluation,
                licence: "Apache-2.0".into(),
                benchmark_provenance: None,
                quirks: crate::catalog::ProfileQuirks::default(),
                capabilities: CapabilityDescriptor {
                    structured_output: false,
                    ..CapabilityDescriptor::unbound_local(false)
                },
            },
        )
        .unwrap();
        let mut local = cfg("local", InferenceBackendClass::Local, &[("llama", "llama")]);
        local.profile_id = Some("p".into());
        let need = CapabilityNeed {
            tools: false,
            output_schema: true,
            image: false,
            prompt_tokens_est: None,
            max_tokens: None,
        };
        let err = walk_eligible(&[local], Some("llama"), &cat, &need).unwrap_err();
        assert!(format!("{err}").contains("unsupported capability"), "{err}");
    }

    #[test]
    fn t129_bound_max_context() {
        let mut cat = ModelProfileCatalog::new();
        cat.insert(
            "p".into(),
            crate::catalog::ModelProfile {
                key: crate::catalog::ProfileKey {
                    model_version: "v1".into(),
                    quantization: "q4".into(),
                    backend: "local".into(),
                    chat_template: "t".into(),
                    tool_parser: "p2".into(),
                },
                tier: crate::catalog::CatalogTier::Evaluation,
                licence: "Apache-2.0".into(),
                benchmark_provenance: None,
                quirks: crate::catalog::ProfileQuirks::default(),
                capabilities: CapabilityDescriptor {
                    max_context: Some(8),
                    ..CapabilityDescriptor::unbound_local(false)
                },
            },
        )
        .unwrap();
        let mut local = cfg("local", InferenceBackendClass::Local, &[("llama", "llama")]);
        local.profile_id = Some("p".into());
        let need = CapabilityNeed {
            tools: false,
            output_schema: false,
            image: false,
            prompt_tokens_est: Some(64),
            max_tokens: None,
        };
        let err = walk_eligible(&[local], Some("llama"), &cat, &need).unwrap_err();
        assert!(format!("{err}").contains("unsupported capability"), "{err}");
    }

    #[test]
    fn t129_unknown_profile_id_is_model_not_available() {
        let mut local = cfg("local", InferenceBackendClass::Local, &[("llama", "llama")]);
        local.profile_id = Some("missing".into());
        let cat = ModelProfileCatalog::new();
        let need = CapabilityNeed {
            tools: false,
            output_schema: false,
            image: false,
            prompt_tokens_est: None,
            max_tokens: None,
        };
        let err = walk_eligible(&[local], Some("llama"), &cat, &need).unwrap_err();
        assert!(matches!(err, LlmError::ModelNotAvailable(_)), "{err}");
    }

    #[test]
    fn t129_tools_struct_nonempty() {
        let params = ChatParams {
            tools: Some(vec![ToolDefinition {
                name: "x".into(),
                description: "d".into(),
                parameters: serde_json::json!({}),
            }]),
            ..Default::default()
        };
        assert!(CapabilityNeed::from_chat(&params, false).tools);
    }
}
