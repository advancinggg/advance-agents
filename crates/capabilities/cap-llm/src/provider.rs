//! Provider+Model resolver — `ResolvedProvider` + `resolve_provider_and_model`.
//!
//! The function maps an `Option<&str>` model hint (sourced at the WIT layer
//! from `llm-params.model: option<string>` per MODULE-009 §1.4.1) onto a
//! concrete `(provider, model)` pair drawn from
//! `RuntimeConfig::llm_providers`. The resolution algorithm is documented
//! at MODULE-009 §2.7 Provider+Model Resolution Flow.
//!
//! Key invariants:
//! - **Pure function** — no `&self`, no IO, no hidden state. Two calls with
//!   identical inputs produce identical outputs (AC-03).
//! - **Stateless** — neither the input slice nor the output `ResolvedProvider`
//!   carries any provider-session-id field (AC-03).
//! - **Defense-in-depth redaction** — `ResolvedProvider`'s manual `Debug`
//!   impl redacts `api_key_secret`, even though `LlmProviderConfig` already
//!   redacts at its source.

use std::fmt;

use advance_runtime::config::{
    AuthScheme, InferenceBackendClass, LlmProviderConfig, ProviderBackend,
};

use crate::error::LlmError;

/// A resolved (provider, model) tuple ready for HTTP execution.
///
/// `api_key_secret` is the secret-name *reference* (per
/// `LlmProviderConfig`'s rustdoc) — not the actual key. The manual `Debug`
/// impl redacts it as a defense-in-depth measure even though
/// `LlmProviderConfig` already redacts at its source.
#[derive(Clone, PartialEq)]
pub struct ResolvedProvider {
    pub id: String,
    pub endpoint: String,
    pub api_key_secret: String,
    pub model: String,
    pub cost_per_mtoken_in: f64,
    pub cost_per_mtoken_out: f64,
    /// Wire-protocol family (ADR 2026-07-22 D4). Always concrete here:
    /// `make_resolved` applies `backend_of` inference when the config field
    /// is absent, so downstream dispatch never re-derives from the id string.
    pub backend: ProviderBackend,
    /// Credential-position override (ADR 2026-07-22 fork f). `None` → the
    /// backend default (see `providers::credential_position_for`).
    pub auth_scheme: Option<AuthScheme>,
    pub backend_class: InferenceBackendClass,
    pub embedding_model: Option<String>,
}

impl fmt::Debug for ResolvedProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedProvider")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .field("api_key_secret", &"<REDACTED>")
            .field("model", &self.model)
            .field("cost_per_mtoken_in", &self.cost_per_mtoken_in)
            .field("cost_per_mtoken_out", &self.cost_per_mtoken_out)
            .field("backend", &self.backend)
            .field("auth_scheme", &self.auth_scheme)
            .field("backend_class", &self.backend_class)
            .field("embedding_model", &self.embedding_model)
            .finish()
    }
}

/// Resolve a `(provider, model)` pair from the runtime-config `llm-providers`
/// list and an optional `model_hint`. See MODULE-009 §2.7 for the canonical
/// algorithm description.
///
/// Algorithm:
/// 1. Empty list → `LlmError::ModelNotAvailable("no llm-providers configured")`.
/// 2. `Some(name)`:
///    a. Forward alias-key scan (declaration order). First provider with
///       `model_aliases.contains_key(name)` wins; returned model =
///       `model_aliases[name]`.
///    b. Reverse alias-value scan if (a) found nothing. First provider with
///       `name` as a VALUE in `model_aliases` wins; returned model = `name`.
///    c. Default fallback: first provider, literal `name` as model id.
/// 3. `None`:
///    a. First provider (default).
///    b. Empty `model_aliases` → `LlmError::ModelNotAvailable(...)`.
///    c. Else: lexicographically-smallest alias key wins.
///
/// Provider id matching above is case-sensitive (YAML key convention).
pub fn resolve_provider_and_model(
    providers: &[LlmProviderConfig],
    model_hint: Option<&str>,
) -> Result<ResolvedProvider, LlmError> {
    if providers.is_empty() {
        return Err(LlmError::ModelNotAvailable(
            "no llm-providers configured".into(),
        ));
    }
    match model_hint {
        Some(name) => {
            // 2a. Forward alias-key scan.
            for provider in providers {
                if let Some(target) = provider.model_aliases.get(name) {
                    return Ok(make_resolved(provider, target.clone()));
                }
            }
            // 2b. Reverse alias-value scan.
            for provider in providers {
                if provider.model_aliases.values().any(|v| v == name) {
                    return Ok(make_resolved(provider, name.to_string()));
                }
            }
            // 2c. Default fallback.
            Ok(make_resolved(&providers[0], name.to_string()))
        }
        None => {
            let p = &providers[0];
            if p.model_aliases.is_empty() {
                return Err(LlmError::ModelNotAvailable(format!(
                    "provider {} has no model_aliases and no model_hint provided",
                    p.id
                )));
            }
            // Lexicographic-first alias key for determinism across HashMap
            // iteration randomization (§2.7).
            let mut keys: Vec<&String> = p.model_aliases.keys().collect();
            keys.sort();
            let target = p.model_aliases[keys[0]].clone();
            Ok(make_resolved(p, target))
        }
    }
}

/// Backend inference (ADR 2026-07-22 D4): explicit `backend:` wins; absent →
/// byte-compatible with the historical id-keyed `select_adapter` routing
/// (`id == "anthropic"` → `AnthropicMessages`, any other id → `OpenAiChat`,
/// covering openai / local-llm / mistral / together-ai etc.).
///
/// Inference lives HERE in the resolver — deliberately NOT in serde — so an
/// on-disk config without the field deserializes to `None` and existing
/// configs are bit-for-bit unaffected (MODULE-009-AC-21 byte-compat leg).
pub fn backend_of(cfg: &LlmProviderConfig) -> ProviderBackend {
    cfg.backend.unwrap_or({
        if cfg.id == "anthropic" {
            ProviderBackend::AnthropicMessages
        } else {
            ProviderBackend::OpenAiChat
        }
    })
}

pub(crate) fn make_resolved(p: &LlmProviderConfig, model: String) -> ResolvedProvider {
    ResolvedProvider {
        id: p.id.clone(),
        endpoint: p.endpoint.clone(),
        api_key_secret: p.api_key_secret.clone(),
        model,
        cost_per_mtoken_in: p.cost_per_mtoken_in,
        cost_per_mtoken_out: p.cost_per_mtoken_out,
        backend: backend_of(p),
        auth_scheme: p.auth_scheme,
        backend_class: p.backend_class,
        embedding_model: p.embedding_model.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn provider(id: &str, aliases: &[(&str, &str)]) -> LlmProviderConfig {
        let mut model_aliases: HashMap<String, String> = HashMap::new();
        for (k, v) in aliases {
            model_aliases.insert((*k).to_string(), (*v).to_string());
        }
        LlmProviderConfig {
            id: id.to_string(),
            endpoint: format!("https://api.{id}.example"),
            api_key_secret: format!("{id}-api-key"),
            model_aliases,
            cost_per_mtoken_in: 1.0,
            cost_per_mtoken_out: 5.0,
            rate_limit: None,
            retry_default: None,
            backend: None,
            auth_scheme: None,
            backend_class: InferenceBackendClass::CloudHttp,
            embedding_model: None,
            sidecar: None,
            profile_id: None,
        }
    }

    #[test]
    fn t_resolve_alias_key_match_returns_value() {
        let providers = vec![
            provider(
                "anthropic",
                &[("sonnet", "claude-sonnet-4-5"), ("opus", "claude-opus-4-6")],
            ),
            provider("openai", &[("gpt-4o", "gpt-4o-2024-11-20")]),
        ];
        let r = resolve_provider_and_model(&providers, Some("sonnet")).unwrap();
        assert_eq!(r.id, "anthropic");
        assert_eq!(r.model, "claude-sonnet-4-5");
    }

    #[test]
    fn t_resolve_alias_key_match_routes_to_owning_provider() {
        let providers = vec![
            provider("anthropic", &[("sonnet", "claude-sonnet-4-5")]),
            provider("openai", &[("gpt-4o", "gpt-4o-2024-11-20")]),
        ];
        let r = resolve_provider_and_model(&providers, Some("gpt-4o")).unwrap();
        assert_eq!(r.id, "openai");
        assert_eq!(r.model, "gpt-4o-2024-11-20");
    }

    #[test]
    fn t_resolve_alias_value_match_returns_provider() {
        let providers = vec![
            provider(
                "anthropic",
                &[("sonnet", "claude-sonnet-4-5"), ("opus", "claude-opus-4-6")],
            ),
            provider("openai", &[("gpt-4o", "gpt-4o-2024-11-20")]),
        ];
        let r = resolve_provider_and_model(&providers, Some("claude-sonnet-4-5")).unwrap();
        assert_eq!(r.id, "anthropic");
        assert_eq!(r.model, "claude-sonnet-4-5");
    }

    #[test]
    fn t_resolve_alias_value_routes_to_owning_provider() {
        let providers = vec![
            provider("anthropic", &[("sonnet", "claude-sonnet-4-5")]),
            provider("openai", &[("gpt-4o", "gpt-4o-2024-11-20")]),
        ];
        let r = resolve_provider_and_model(&providers, Some("gpt-4o-2024-11-20")).unwrap();
        assert_eq!(r.id, "openai");
        assert_eq!(r.model, "gpt-4o-2024-11-20");
    }

    #[test]
    fn t_resolve_no_match_falls_through_to_default_provider() {
        let providers = vec![
            provider("anthropic", &[("sonnet", "claude-sonnet-4-5")]),
            provider("openai", &[("gpt-4o", "gpt-4o-2024-11-20")]),
        ];
        let r = resolve_provider_and_model(&providers, Some("unknown-model")).unwrap();
        assert_eq!(r.id, "anthropic");
        assert_eq!(r.model, "unknown-model");
    }

    #[test]
    fn t_resolve_no_hint_default_provider_lexicographic_alias() {
        let providers = vec![provider(
            "anthropic",
            &[
                ("sonnet", "claude-sonnet-4-5"),
                ("opus", "claude-opus-4-6"),
                ("haiku", "claude-haiku-4-5"),
            ],
        )];
        let r = resolve_provider_and_model(&providers, None).unwrap();
        assert_eq!(r.id, "anthropic");
        // "haiku" < "opus" < "sonnet" lexicographically — haiku wins.
        assert_eq!(r.model, "claude-haiku-4-5");
    }

    #[test]
    fn t_resolve_no_hint_no_aliases_returns_error() {
        let providers = vec![provider("bare", &[])];
        match resolve_provider_and_model(&providers, None) {
            Err(LlmError::ModelNotAvailable(msg)) => {
                assert!(
                    msg.contains("bare"),
                    "expected provider id in error msg: {msg}"
                );
            }
            other => panic!("expected ModelNotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn t_resolve_empty_providers_returns_error() {
        match resolve_provider_and_model(&[], None) {
            Err(LlmError::ModelNotAvailable(msg)) => {
                assert!(msg.contains("no llm-providers configured"), "msg: {msg}");
            }
            other => panic!("expected ModelNotAvailable, got {other:?}"),
        }
        match resolve_provider_and_model(&[], Some("anything")) {
            Err(LlmError::ModelNotAvailable(_)) => {}
            other => panic!("expected ModelNotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn t_resolve_is_pure_function() {
        let providers = vec![provider(
            "anthropic",
            &[("sonnet", "claude-sonnet-4-5"), ("opus", "claude-opus-4-6")],
        )];
        let baseline = resolve_provider_and_model(&providers, Some("sonnet")).unwrap();
        for _ in 0..100 {
            let r = resolve_provider_and_model(&providers, Some("sonnet")).unwrap();
            assert_eq!(
                r, baseline,
                "resolver mutated under repeated identical input"
            );
        }
    }

    #[test]
    fn t_resolved_provider_debug_redacts_api_key_secret() {
        let providers = vec![provider("anthropic", &[("sonnet", "claude-sonnet-4-5")])];
        let r = resolve_provider_and_model(&providers, Some("sonnet")).unwrap();
        let dbg = format!("{r:?}");
        assert!(
            dbg.contains("<REDACTED>"),
            "expected '<REDACTED>' in debug output: {dbg}"
        );
        assert!(
            !dbg.contains("anthropic-api-key"),
            "raw secret-name leaked through Debug: {dbg}"
        );
    }

    /// MODULE-009-T116 — `backend_of` inference is byte-compatible with the
    /// historical id-keyed routing (absent `backend:` → "anthropic" maps to
    /// AnthropicMessages, every other id to OpenAiChat).
    #[test]
    fn t116_backend_of_inference_byte_compatible() {
        assert_eq!(
            backend_of(&provider("anthropic", &[])),
            ProviderBackend::AnthropicMessages
        );
        for id in ["openai", "local-llm", "mistral", "together-ai", "anything"] {
            assert_eq!(
                backend_of(&provider(id, &[])),
                ProviderBackend::OpenAiChat,
                "non-anthropic id {id} must infer OpenAiChat"
            );
        }
    }

    /// MODULE-009-T116 — an explicit `backend:` override WINS over id
    /// inference, and `make_resolved` carries backend + auth_scheme onto
    /// `ResolvedProvider`.
    #[test]
    fn t116_explicit_backend_override_wins() {
        let mut cfg = provider("anthropic", &[("a", "m")]);
        cfg.backend = Some(ProviderBackend::OpenAiResponses);
        cfg.auth_scheme = Some(AuthScheme::ApiKey);
        assert_eq!(backend_of(&cfg), ProviderBackend::OpenAiResponses);
        let resolved = make_resolved(&cfg, "m".into());
        assert_eq!(resolved.backend, ProviderBackend::OpenAiResponses);
        assert_eq!(resolved.auth_scheme, Some(AuthScheme::ApiKey));
    }

    /// MODULE-009-T116 — serde: the ADR-pinned kebab spellings parse, and
    /// ABSENT fields deserialize to None so existing configs are
    /// bit-for-bit unaffected (deny_unknown_fields intact).
    #[test]
    fn t116_serde_backend_auth_scheme_shapes() {
        let with_fields: LlmProviderConfig = serde_json::from_value(serde_json::json!({
            "id": "azure", "endpoint": "https://a.example",
            "api-key-secret": "s", "model-aliases": {},
            "cost-per-mtoken-in": 0.0, "cost-per-mtoken-out": 0.0,
            "backend": "openai-responses", "auth-scheme": "api-key"
        }))
        .expect("explicit backend/auth-scheme must parse");
        assert_eq!(with_fields.backend, Some(ProviderBackend::OpenAiResponses));
        assert_eq!(with_fields.auth_scheme, Some(AuthScheme::ApiKey));

        let without_fields: LlmProviderConfig = serde_json::from_value(serde_json::json!({
            "id": "openai", "endpoint": "https://a.example",
            "api-key-secret": "s", "model-aliases": {},
            "cost-per-mtoken-in": 0.0, "cost-per-mtoken-out": 0.0
        }))
        .expect("legacy config without the new fields must parse unchanged");
        assert_eq!(without_fields.backend, None);
        assert_eq!(without_fields.auth_scheme, None);
    }

    #[test]
    fn t_local_backend_yaml_maps_to_class() {
        let cfg: LlmProviderConfig = serde_json::from_value(serde_json::json!({
            "id": "local", "endpoint": "",
            "api-key-secret": "local-dummy", "model-aliases": {"llama": "llama-3.1-8b"},
            "cost-per-mtoken-in": 0.001, "cost-per-mtoken-out": 0.001,
            "backend": "local"
        }))
        .expect("backend: local must parse as class");
        assert_eq!(cfg.backend, Some(ProviderBackend::OpenAiChat));
        assert_eq!(cfg.backend_class, InferenceBackendClass::Local);
        let resolved = make_resolved(&cfg, "llama-3.1-8b".into());
        assert_eq!(resolved.backend, ProviderBackend::OpenAiChat);
        assert_eq!(resolved.backend_class, InferenceBackendClass::Local);
    }

    #[test]
    fn t116_unknown_field_rejected() {
        let err = serde_json::from_value::<LlmProviderConfig>(serde_json::json!({
            "id": "openai", "endpoint": "https://a.example",
            "api-key-secret": "s", "model-aliases": {},
            "cost-per-mtoken-in": 0.0, "cost-per-mtoken-out": 0.0,
            "unknown-knob": true
        }));
        assert!(err.is_err(), "deny_unknown_fields must reject unknown-knob");
    }

    #[test]
    fn t128_provider_backend_three_members() {
        // Compile-time: a match without a fourth arm is exhaustive.
        fn count(b: ProviderBackend) -> u8 {
            match b {
                ProviderBackend::OpenAiChat => 1,
                ProviderBackend::OpenAiResponses => 2,
                ProviderBackend::AnthropicMessages => 3,
            }
        }
        assert_eq!(count(ProviderBackend::OpenAiChat), 1);
    }
}
