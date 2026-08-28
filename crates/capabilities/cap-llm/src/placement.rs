//! MODULE-009-AC-28 placement: filter → TTFT rank → immutable record.

use crate::capability::{descriptor_for, missing_capability, CapabilityNeed};
use crate::catalog::{CatalogTier, ModelProfileCatalog};
use crate::error::LlmError;
use advance_runtime::config::{InferenceBackendClass, LlmProviderConfig};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserHardConstraint {
    AlwaysLocal,
    NeverCloud,
    DevicePin(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointTelemetry {
    pub queue_ms: u64,
    pub load_ms: u64,
    pub prefill_ms: u64,
    pub rtt_ms: u64,
    pub decode_onset_ms: u64,
}

impl EndpointTelemetry {
    pub fn predicted_ttft_ms(self) -> u64 {
        self.queue_ms
            .saturating_add(self.load_ms)
            .saturating_add(self.prefill_ms)
            .saturating_add(self.rtt_ms)
            .saturating_add(self.decode_onset_ms)
    }
}

pub trait PlacementTelemetry: Send + Sync {
    fn snapshot(&self, endpoint_id: &str) -> Option<EndpointTelemetry>;
    fn device_id(&self, endpoint_id: &str) -> Option<String>;
    fn authorized(&self, endpoint_id: &str) -> bool {
        let _ = endpoint_id;
        true
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NotWiredPlacementTelemetry;

impl PlacementTelemetry for NotWiredPlacementTelemetry {
    fn snapshot(&self, _endpoint_id: &str) -> Option<EndpointTelemetry> {
        None
    }
    fn device_id(&self, _endpoint_id: &str) -> Option<String> {
        None
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Strength {
    pub tier: u8,
    pub max_context: u32,
    pub tool_level: u8,
}

impl Strength {
    pub fn from_parts(
        tier: CatalogTier,
        max_context: Option<u32>,
        tool: crate::capability::ToolCallingLevel,
    ) -> Self {
        use crate::capability::ToolCallingLevel::*;
        Self {
            tier: match tier {
                CatalogTier::Stable => 2,
                CatalogTier::Evaluation => 1,
                CatalogTier::Experimental => 0,
            },
            max_context: max_context.unwrap_or(0),
            tool_level: match tool {
                Native => 3,
                Constrained => 2,
                RepairOnly => 1,
                Disabled => 0,
            },
        }
    }

    pub fn unbound() -> Self {
        Self {
            tier: 1,
            max_context: 0,
            tool_level: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementCandidate {
    pub endpoint_id: String,
    pub model_revision: String,
    pub backend_class: InferenceBackendClass,
    pub device_id: Option<String>,
    pub authorized: bool,
    pub predicted_ttft_ms: u64,
    pub strength: Strength,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementRecord {
    pub endpoint_id: String,
    pub model_revision: String,
    pub placement_reason: String,
    pub strength: Strength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CascadeTrigger {
    StructuredOutputValidationFailure,
    ToolCallParseFailure,
    ContextOverflow,
    ExplicitHardClass,
}

pub fn cascade_trigger(err: &LlmError) -> Option<CascadeTrigger> {
    match err {
        LlmError::StructuredOutputFailed(_) => {
            Some(CascadeTrigger::StructuredOutputValidationFailure)
        }
        LlmError::ContextTooLong(_) => Some(CascadeTrigger::ContextOverflow),
        LlmError::ProviderError(msg) if msg.starts_with("tool-call-parse:") => {
            Some(CascadeTrigger::ToolCallParseFailure)
        }
        _ => None,
    }
}

pub fn is_pre_token_failover(err: &LlmError) -> bool {
    let LlmError::ProviderError(msg) = err else {
        return false;
    };
    // C238: local transport is loopback-only. A dead/absent sidecar must
    // not hop onto cloud-http (SYS-AC-314).
    if msg.starts_with(advance_shared_types::inference::LOCAL_TRANSPORT_PREFIX) {
        return false;
    }
    let rest = msg
        .strip_prefix(advance_shared_types::inference::MESH_REMOTE_PREFIX)
        .map(str::trim_start)
        .unwrap_or(msg);
    if rest.starts_with(advance_shared_types::inference::LOCAL_TRANSPORT_PREFIX) {
        return false;
    }
    rest == "not wired" || rest == "unavailable" || crate::retry::is_transport_provider_error(rest)
}

pub fn candidates_for(
    providers: &[LlmProviderConfig],
    model_hint: Option<&str>,
    catalog: &ModelProfileCatalog,
    need: &CapabilityNeed,
    telemetry: &dyn PlacementTelemetry,
) -> Result<Vec<PlacementCandidate>, LlmError> {
    if providers.is_empty() {
        return Err(LlmError::ModelNotAvailable(
            "no llm-providers configured".into(),
        ));
    }
    let mut out = Vec::new();
    let mut saw_capability_skip = false;
    let mut saw_bind = false;
    let mut last_desc_err: Option<LlmError> = None;
    for p in providers {
        let model = match bind_model(p, model_hint) {
            Some(m) => m,
            None => continue,
        };
        saw_bind = true;
        let desc = match descriptor_for(p, catalog) {
            Ok(d) => d,
            Err(e) => {
                last_desc_err = Some(e);
                continue;
            }
        };
        if missing_capability(&desc, need).is_some() {
            saw_capability_skip = true;
            continue;
        }
        let ttft = telemetry
            .snapshot(&p.id)
            .map(EndpointTelemetry::predicted_ttft_ms)
            .unwrap_or(u64::MAX);
        let device_id = p.device_id.clone().or_else(|| telemetry.device_id(&p.id));
        let strength = if let Some(pid) = p.profile_id.as_deref() {
            catalog
                .get(pid)
                .map(|pr| {
                    Strength::from_parts(
                        pr.tier,
                        pr.capabilities.max_context,
                        pr.capabilities.tool_calling,
                    )
                })
                .unwrap_or_else(Strength::unbound)
        } else {
            Strength::unbound()
        };
        out.push(PlacementCandidate {
            endpoint_id: p.id.clone(),
            model_revision: model,
            backend_class: p.backend_class,
            device_id,
            authorized: telemetry.authorized(&p.id),
            predicted_ttft_ms: ttft,
            strength,
        });
    }
    if out.is_empty() && model_hint.is_some() && !saw_bind {
        // 2c: first provider + literal name if that row passes capability.
        // Only when ZERO 2a/2b binds occurred — capability-filtered binds
        // must not fall through onto providers[0].
        let p = &providers[0];
        if let Ok(desc) = descriptor_for(p, catalog) {
            if missing_capability(&desc, need).is_some() {
                saw_capability_skip = true;
            } else if let Some(hint) = model_hint {
                let model = hint.to_string();
                let ttft = telemetry
                    .snapshot(&p.id)
                    .map(EndpointTelemetry::predicted_ttft_ms)
                    .unwrap_or(u64::MAX);
                out.push(PlacementCandidate {
                    endpoint_id: p.id.clone(),
                    model_revision: model,
                    backend_class: p.backend_class,
                    device_id: p.device_id.clone().or_else(|| telemetry.device_id(&p.id)),
                    authorized: telemetry.authorized(&p.id),
                    predicted_ttft_ms: ttft,
                    strength: if let Some(pid) = p.profile_id.as_deref() {
                        catalog
                            .get(pid)
                            .map(|pr| {
                                Strength::from_parts(
                                    pr.tier,
                                    pr.capabilities.max_context,
                                    pr.capabilities.tool_calling,
                                )
                            })
                            .unwrap_or_else(Strength::unbound)
                    } else {
                        Strength::unbound()
                    },
                });
            }
        }
    }
    if out.is_empty() {
        if saw_capability_skip {
            return Err(LlmError::ProviderError(format!(
                "{} none eligible",
                advance_shared_types::inference::UNSUPPORTED_CAPABILITY_PREFIX
            )));
        }
        if let Some(e) = last_desc_err {
            return Err(e);
        }
        return Err(LlmError::ModelNotAvailable("no eligible endpoints".into()));
    }
    Ok(out)
}

fn bind_model(p: &LlmProviderConfig, hint: Option<&str>) -> Option<String> {
    match hint {
        None => {
            if p.model_aliases.is_empty() {
                return None;
            }
            let mut keys: Vec<&String> = p.model_aliases.keys().collect();
            keys.sort();
            Some(p.model_aliases[keys[0]].clone())
        }
        Some(name) => {
            if let Some(v) = p.model_aliases.get(name) {
                Some(v.clone())
            } else if p.model_aliases.values().any(|v| v == name) {
                Some(name.to_string())
            } else {
                None
            }
        }
    }
}

pub fn place(
    cands: &[PlacementCandidate],
    constraints: &[UserHardConstraint],
    excluded: &[String],
    strength_floor: Option<Strength>,
) -> Result<Option<PlacementRecord>, LlmError> {
    let mut filtered: Vec<&PlacementCandidate> = cands
        .iter()
        .filter(|c| !excluded.iter().any(|e| e == &c.endpoint_id))
        .filter(|c| c.authorized)
        .collect();
    for cstr in constraints {
        match cstr {
            UserHardConstraint::AlwaysLocal => {
                filtered.retain(|c| c.backend_class == InferenceBackendClass::Local);
            }
            UserHardConstraint::NeverCloud => {
                filtered.retain(|c| c.backend_class != InferenceBackendClass::CloudHttp);
            }
            UserHardConstraint::DevicePin(id) => {
                filtered.retain(|c| c.device_id.as_deref() == Some(id.as_str()));
            }
        }
    }
    if let Some(floor) = strength_floor {
        filtered.retain(|c| c.strength > floor);
        if filtered.is_empty() {
            return Ok(None);
        }
    } else if filtered.is_empty() {
        return Err(LlmError::ModelNotAvailable(
            "no endpoints after constraints".into(),
        ));
    }
    // Stable: equal TTFT keeps declaration order (not lexicographic id).
    filtered.sort_by_key(|c| c.predicted_ttft_ms);
    let w = filtered[0];
    Ok(Some(PlacementRecord {
        endpoint_id: w.endpoint_id.clone(),
        model_revision: w.model_revision.clone(),
        placement_reason: format!(
            "ttft:{};filtered:{}",
            w.predicted_ttft_ms,
            cands.len().saturating_sub(filtered.len())
        ),
        strength: w.strength,
    }))
}

pub fn default_telemetry() -> Arc<dyn PlacementTelemetry> {
    Arc::new(NotWiredPlacementTelemetry)
}

#[cfg(test)]
mod t133_helpers {
    use super::*;
    use crate::capability::CapabilityDescriptor;
    use crate::capability::CapabilityNeed;
    use crate::capability::ToolCallingLevel;
    use advance_runtime::config::ProviderBackend;
    use std::collections::HashMap;

    fn cand(
        id: &str,
        class: InferenceBackendClass,
        ttft: u64,
        strength: Strength,
        device: Option<&str>,
    ) -> PlacementCandidate {
        PlacementCandidate {
            endpoint_id: id.into(),
            model_revision: id.into(),
            backend_class: class,
            device_id: device.map(str::to_string),
            authorized: true,
            predicted_ttft_ms: ttft,
            strength,
        }
    }

    #[test]
    fn t133_cascade_error_triggers() {
        assert_eq!(
            cascade_trigger(&LlmError::StructuredOutputFailed("x".into())),
            Some(CascadeTrigger::StructuredOutputValidationFailure)
        );
        assert_eq!(
            cascade_trigger(&LlmError::ContextTooLong("x".into())),
            Some(CascadeTrigger::ContextOverflow)
        );
        assert_eq!(
            cascade_trigger(&LlmError::ProviderError("tool-call-parse: x".into())),
            Some(CascadeTrigger::ToolCallParseFailure)
        );
        assert_eq!(
            cascade_trigger(&LlmError::ProviderError(
                "provider-error: tool-call-parse: x".into()
            )),
            None
        );
        for e in [
            LlmError::RateLimited("x".into()),
            LlmError::BudgetExceeded("x".into()),
            LlmError::ProviderError("connection refused".into()),
            LlmError::RepetitionTerminated("x".into()),
        ] {
            assert_eq!(cascade_trigger(&e), None);
        }
    }

    #[test]
    fn t133_rank_is_ttft_not_device_class() {
        let mac = cand(
            "mac",
            InferenceBackendClass::Local,
            5000,
            Strength::unbound(),
            Some("mac"),
        );
        let phone = cand(
            "phone",
            InferenceBackendClass::Local,
            10,
            Strength::unbound(),
            Some("phone"),
        );
        let rec = place(&[mac, phone], &[], &[], None).unwrap().unwrap();
        assert_eq!(rec.endpoint_id, "phone");
    }

    #[test]
    fn t133_hard_constraint_never_overridden() {
        let cloud = cand(
            "cloud",
            InferenceBackendClass::CloudHttp,
            1,
            Strength::unbound(),
            None,
        );
        let local = cand(
            "local",
            InferenceBackendClass::Local,
            5000,
            Strength::unbound(),
            None,
        );
        let rec = place(
            &[cloud.clone(), local.clone()],
            &[UserHardConstraint::AlwaysLocal],
            &[],
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(rec.endpoint_id, "local");
        let rec = place(
            &[cloud, local],
            &[UserHardConstraint::NeverCloud],
            &[],
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(rec.endpoint_id, "local");
    }

    #[test]
    fn t133_record_immutable() {
        let a = cand(
            "a",
            InferenceBackendClass::Local,
            1,
            Strength::unbound(),
            None,
        );
        let rec = place(&[a], &[], &[], None).unwrap().unwrap();
        let clone = rec.clone();
        assert_eq!(clone.endpoint_id, rec.endpoint_id);
        assert_eq!(clone.model_revision, rec.model_revision);
        assert!(!rec.placement_reason.is_empty());
    }

    #[test]
    fn t133_hard_class_skips_weaker() {
        let fast_low = cand(
            "fast",
            InferenceBackendClass::Local,
            1,
            Strength {
                tier: 0,
                max_context: 0,
                tool_level: 0,
            },
            None,
        );
        let mid_weaker = cand(
            "mid",
            InferenceBackendClass::Local,
            2,
            Strength {
                tier: 0,
                max_context: 0,
                tool_level: 0,
            },
            None,
        );
        let slow_high = cand(
            "slow",
            InferenceBackendClass::CloudHttp,
            100,
            Strength {
                tier: 2,
                max_context: 0,
                tool_level: 0,
            },
            None,
        );
        let first = place(
            &[fast_low.clone(), mid_weaker.clone(), slow_high.clone()],
            &[],
            &[],
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(first.endpoint_id, "fast");
        let second = place(
            &[fast_low, mid_weaker, slow_high],
            &[],
            &["fast".into()],
            Some(first.strength),
        )
        .unwrap()
        .unwrap();
        assert_eq!(second.endpoint_id, "slow");
    }

    #[test]
    fn t133_2c_only_when_zero_binds() {
        let mut cat = ModelProfileCatalog::new();
        cat.insert(
            "tight".into(),
            crate::catalog::ModelProfile {
                key: crate::catalog::ProfileKey {
                    model_version: "v1".into(),
                    quantization: "q4".into(),
                    backend: "local".into(),
                    chat_template: "t".into(),
                    tool_parser: "tight".into(),
                },
                tier: crate::catalog::CatalogTier::Evaluation,
                licence: "MIT".into(),
                benchmark_provenance: None,
                quirks: crate::catalog::ProfileQuirks::default(),
                capabilities: CapabilityDescriptor {
                    max_context: Some(8),
                    ..CapabilityDescriptor::unbound_local(false)
                },
            },
        )
        .unwrap();
        let mut cloud = _cfg();
        cloud.id = "cloud".into();
        cloud.model_aliases.clear();
        cloud.model_aliases.insert("gpt".into(), "gpt".into());
        let mut local = _cfg();
        local.id = "local".into();
        local.endpoint = String::new();
        local.backend_class = InferenceBackendClass::Local;
        local.profile_id = Some("tight".into());
        local.model_aliases.clear();
        local.model_aliases.insert("llama".into(), "llama".into());
        let need = CapabilityNeed {
            tools: false,
            output_schema: false,
            image: false,
            prompt_tokens_est: Some(64),
            max_tokens: None,
        };
        let err = candidates_for(
            &[cloud, local],
            Some("llama"),
            &cat,
            &need,
            &NotWiredPlacementTelemetry,
        )
        .unwrap_err();
        let s = format!("{err}");
        assert!(
            s.contains("unsupported capability"),
            "2c must not rewrite llama onto cloud after a capability-filtered bind, got {s}"
        );
    }

    #[test]
    fn t133_failover_payload_not_display() {
        assert!(is_pre_token_failover(&LlmError::ProviderError(
            "connection refused".into()
        )));
        assert!(is_pre_token_failover(&LlmError::ProviderError(
            "mesh-remote: connection refused".into()
        )));
        assert!(is_pre_token_failover(&LlmError::ProviderError(
            "mesh-remote: not wired".into()
        )));
        assert!(!is_pre_token_failover(&LlmError::ProviderError(
            "mesh-remote: lease-denied".into()
        )));
        assert!(!is_pre_token_failover(&LlmError::ProviderError(
            "local transport: not wired".into()
        )));
        assert!(!is_pre_token_failover(&LlmError::ProviderError(
            "local transport: sidecar dead".into()
        )));
        assert!(!is_pre_token_failover(&LlmError::RateLimited("x".into())));
    }

    #[allow(dead_code)]
    fn _desc() -> CapabilityDescriptor {
        CapabilityDescriptor {
            tool_calling: ToolCallingLevel::Disabled,
            structured_output: true,
            embeddings: true,
            image: false,
            max_context: None,
            max_output: None,
        }
    }

    #[allow(dead_code)]
    fn _cfg() -> LlmProviderConfig {
        let mut aliases = HashMap::new();
        aliases.insert("m".into(), "m".into());
        LlmProviderConfig {
            id: "p".into(),
            endpoint: "https://x.example".into(),
            api_key_secret: "s".into(),
            model_aliases: aliases,
            cost_per_mtoken_in: 1.0,
            cost_per_mtoken_out: 1.0,
            rate_limit: None,
            retry_default: None,
            backend: Some(ProviderBackend::OpenAiChat),
            auth_scheme: None,
            backend_class: InferenceBackendClass::CloudHttp,
            embedding_model: None,
            sidecar: None,
            profile_id: None,
            device_id: None,
        }
    }
}
