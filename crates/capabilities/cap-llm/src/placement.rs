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
    // ADR 2026-09-28 `agent-cli`: an absent / unwired / signed-out / paused subscription CLI
    // has spent no tokens — the walker moves on. A blocked egress scan never hops.
    if let Some(cli) = rest.strip_prefix(crate::backend_cli::AGENT_CLI_PREFIX) {
        let cli = cli.trim_start();
        return cli == "not wired"
            || cli.starts_with("cli not found")
            || cli.starts_with("not signed in")
            || cli.starts_with("subscription usage limit")
            || cli.starts_with("daemon identity unknown")
            || cli.starts_with("egress scan not wired");
    }
    // A Sign in with ChatGPT entry that is signed out, out of plan usage or refused by the
    // upstream has spent no tokens either: same policy as the agent-cli sign-in and quota
    // reasons, for every reason of that closed vocabulary.
    if crate::plan_usage::is_plan_usage_error(rest) {
        return true;
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

/// Whether a request naming `model` is placed on the entry `entry_id` of `providers`
/// ([`candidates_for`]): the entry serves the model ([`bind_model`]), or no entry does and
/// it is the first of them — where such a request goes, sent the name as it stands (rule
/// 2c). Whether the entry has the capabilities a request needs is not asked.
pub(crate) fn places_model_on(
    providers: &[LlmProviderConfig],
    model: &str,
    entry_id: &str,
) -> bool {
    let serves = |p: &LlmProviderConfig| bind_model(p, Some(model)).is_some();
    match providers.iter().find(|p| p.id == entry_id) {
        None => false,
        Some(entry) if serves(entry) => true,
        Some(_) => {
            !providers.iter().any(serves) && providers.first().is_some_and(|p| p.id == entry_id)
        }
    }
}

/// The model `p` is sent for a request naming `hint`: the alias it names, a model `p`
/// lists under it, or (no hint) the first alias by name; `None` when `p` serves none of
/// it.
pub(crate) fn bind_model(p: &LlmProviderConfig, hint: Option<&str>) -> Option<String> {
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

/// Whether `constraints` let a request run on an entry of `backend_class` on `device_id`.
/// The one statement of what each hard constraint means, shared by [`place`] and the
/// per-entry checks below.
fn constraints_allow(
    backend_class: InferenceBackendClass,
    device_id: Option<&str>,
    constraints: &[UserHardConstraint],
) -> bool {
    constraints.iter().all(|c| match c {
        UserHardConstraint::AlwaysLocal => backend_class == InferenceBackendClass::Local,
        // `agent-cli` egresses to the vendor inside the CLI: it is cloud too.
        UserHardConstraint::NeverCloud => {
            backend_class != InferenceBackendClass::CloudHttp && !backend_class.is_remote_egress()
        }
        UserHardConstraint::DevicePin(id) => device_id == Some(id.as_str()),
    })
}

/// Whether a request under `constraints` can ever be placed on `p`, read from the entry's
/// configuration alone. A superset of what [`place`] lets through at any moment: an entry
/// that configures no device may be reported on the pinned one by telemetry, so it counts,
/// and an entry telemetry reports unauthorized still counts. What it rules out, no request
/// of that agent can reach.
pub fn admits(p: &LlmProviderConfig, constraints: &[UserHardConstraint]) -> bool {
    constraints.iter().all(|c| match c {
        UserHardConstraint::DevicePin(_) if p.device_id.is_none() => true,
        one => constraints_allow(
            p.backend_class,
            p.device_id.as_deref(),
            std::slice::from_ref(one),
        ),
    })
}

/// Whether a request under `constraints` can be placed on `p` right now: the filter
/// [`place`] applies, for one entry.
pub fn admits_now(
    p: &LlmProviderConfig,
    constraints: &[UserHardConstraint],
    telemetry: &dyn PlacementTelemetry,
) -> bool {
    let device_id = p.device_id.clone().or_else(|| telemetry.device_id(&p.id));
    telemetry.authorized(&p.id)
        && constraints_allow(p.backend_class, device_id.as_deref(), constraints)
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
        .filter(|c| constraints_allow(c.backend_class, c.device_id.as_deref(), constraints))
        .collect();
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

    /// Every reason of the ChatGPT plan vocabulary is a pre-token failover trigger and is
    /// never retried on the same endpoint; neighbours of the prefix are not affected.
    #[test]
    fn chatgpt_plan_errors_fail_over_before_tokens_and_never_retry() {
        for msg in [
            "chatgpt-plan: not signed in",
            "chatgpt-plan: plan usage not authorized",
            "chatgpt-plan: credential refresh unavailable",
            "chatgpt-plan: credential source not wired",
            "chatgpt-plan: sign-in rejected",
            "chatgpt-plan: request not permitted",
            "chatgpt-plan: usage limit reached",
            "chatgpt-plan: account not eligible",
            "chatgpt-plan: unsupported capability",
            "chatgpt-plan: route not supported",
            "chatgpt-plan: streamed transport required",
        ] {
            let err = LlmError::ProviderError(msg.into());
            assert!(is_pre_token_failover(&err), "{msg}");
            assert!(!crate::retry::classify_retryable(&err), "{msg}");
            assert!(cascade_trigger(&err).is_none(), "{msg}");
        }
        // The ordinary credential failures of an API-key entry keep their terminal policy,
        // and a plan reason on another variant is not a trigger.
        for msg in ["auth failed", "stream auth rejected", "http 403"] {
            assert!(
                !is_pre_token_failover(&LlmError::ProviderError(msg.into())),
                "{msg}"
            );
        }
        assert!(!is_pre_token_failover(&LlmError::RateLimited(
            "chatgpt-plan: usage limit reached".into()
        )));
        // A reason reached after bytes were released is no longer this vocabulary.
        assert!(!is_pre_token_failover(&LlmError::ProviderError(
            "stream-partial: chatgpt-plan: usage limit reached".into()
        )));
    }

    /// [`places_model_on`] answers where [`candidates_for`] places a request naming the
    /// model: over every order of four entries — one listing no model, three listing some,
    /// two of those sharing an alias — and every prefix of each order, for a name by alias,
    /// by listed model and listed by none.
    #[test]
    fn a_model_is_placed_on_an_entry_exactly_where_candidates_for_places_it() {
        let entry = |id: &str, aliases: &[(&str, &str)]| {
            let mut p = _cfg();
            p.id = id.into();
            p.model_aliases = aliases
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            p
        };
        let entries = [
            entry("plain", &[]),
            entry("openai", &[("gpt4o", "gpt-4o-2024-08-06")]),
            entry("chat-only", &[("fast", "fast-chat")]),
            entry("eu", &[("fast", "fast-eu"), ("gpt4o", "gpt-4o-eu")]),
        ];
        let need = CapabilityNeed {
            tools: false,
            output_schema: false,
            image: false,
            prompt_tokens_est: None,
            max_tokens: None,
        };
        let catalog = ModelProfileCatalog::new();
        let mut checked = 0;
        for order in orders_of(entries.len()) {
            for len in 1..=order.len() {
                let providers: Vec<LlmProviderConfig> =
                    order[..len].iter().map(|&i| entries[i].clone()).collect();
                for model in ["gpt4o", "gpt-4o-2024-08-06", "fast", "fast-eu", "unlisted"] {
                    let placed: Vec<String> = candidates_for(
                        &providers,
                        Some(model),
                        &catalog,
                        &need,
                        &NotWiredPlacementTelemetry,
                    )
                    .map(|cands| cands.into_iter().map(|c| c.endpoint_id).collect())
                    .unwrap_or_default();
                    for id in ["plain", "openai", "chat-only", "eu", "absent"] {
                        assert_eq!(
                            places_model_on(&providers, model, id),
                            placed.iter().any(|p| p == id),
                            "{model} on {id} of {:?}",
                            providers.iter().map(|p| p.id.as_str()).collect::<Vec<_>>()
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 24 * 4 * 5 * 5);
    }

    /// Every order of `0..n`.
    fn orders_of(n: usize) -> Vec<Vec<usize>> {
        if n == 0 {
            return vec![Vec::new()];
        }
        let mut out = Vec::new();
        for shorter in orders_of(n - 1) {
            for at in 0..=shorter.len() {
                let mut order = shorter.clone();
                order.insert(at, n - 1);
                out.push(order);
            }
        }
        out
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
            cost_per_mtoken_cache_read: None,
            cost_per_mtoken_cache_write: None,
            cost_per_mtoken_cache_write_1h: None,
            rate_limit: None,
            retry_default: None,
            backend: Some(ProviderBackend::OpenAiChat),
            auth_scheme: None,
            backend_class: InferenceBackendClass::CloudHttp,
            embedding_model: None,
            sidecar: None,
            profile_id: None,
            device_id: None,
            agent_cli: None,
            auth_source: advance_runtime::config::ProviderAuthSource::ApiKey,
            generate_timeout_secs: None,
            reasoning_effort: None,
            system_messages: None,
        }
    }
}
