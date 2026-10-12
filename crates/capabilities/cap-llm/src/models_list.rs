//! Vendor model-catalog request, capability, and parsers (provider-summary
//! `available_models`). Request + capability stay in cap-llm so they can call
//! crate-internal `build_http_cap` / `auth_header_for` / `make_resolved`. The
//! HTTP execute loop lives in advance-home.

use advance_runtime::config::{LlmProviderConfig, ProviderBackend};
use advance_shared_types::security_validator::{
    HttpCapability, HttpMethod, HttpRequest,
};
use serde_json::Value;

use crate::error::LlmError;
use crate::gateway::build_http_cap;
use crate::provider::{backend_of, make_resolved};
use crate::providers::auth_header_for;

/// Same literal as `providers/anthropic.rs` (`ANTHROPIC_VERSION` is private).
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_MODELS: usize = 256;
const KEY_DROP_MIN: usize = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListedModel {
    pub id: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogFill {
    pub models: Vec<ListedModel>,
    pub complete: bool,
}

impl CatalogFill {
    pub fn complete(models: Vec<ListedModel>) -> Self {
        Self {
            models,
            complete: true,
        }
    }

    pub fn incomplete(models: Vec<ListedModel>) -> Self {
        Self {
            models,
            complete: false,
        }
    }

    pub fn empty_complete() -> Self {
        Self {
            models: Vec::new(),
            complete: true,
        }
    }

    pub fn empty_incomplete() -> Self {
        Self {
            models: Vec::new(),
            complete: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogPage {
    Parsed {
        models: Vec<ListedModel>,
        has_more: bool,
        last_id: Option<String>,
    },
    EmptySuccess,
    Unparseable,
}

pub fn is_vendor_model_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
}

pub fn is_display_text(s: &str) -> bool {
    !s.trim().is_empty() && s.chars().count() <= 128 && !s.chars().any(char::is_control)
}

pub fn drop_key_rows(models: Vec<ListedModel>, key: &str) -> Vec<ListedModel> {
    if key.len() < KEY_DROP_MIN {
        return models;
    }
    models
        .into_iter()
        .filter(|m| {
            !m.id.contains(key) && m.display_name.as_deref().map_or(true, |n| !n.contains(key))
        })
        .collect()
}

fn dedup_preserve(models: Vec<ListedModel>) -> Vec<ListedModel> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in models {
        if seen.insert(m.id.clone()) {
            out.push(m);
            if out.len() == MAX_MODELS {
                break;
            }
        }
    }
    out
}

pub fn build_models_list_request(
    entry: &LlmProviderConfig,
    after_id: Option<&str>,
) -> Result<HttpRequest, LlmError> {
    let resolved = make_resolved(entry, String::new());
    let mut url = format!("{}/v1/models", resolved.endpoint.trim_end_matches('/'));
    if backend_of(entry) == ProviderBackend::AnthropicMessages {
        url.push_str("?limit=100");
        if let Some(id) = after_id {
            url.push_str("&after_id=");
            url.push_str(&urlencoding(id));
        }
    }
    let (name, value) = auth_header_for(&resolved);
    let mut headers = vec![
        (name, value),
        ("Accept".into(), "application/json".into()),
    ];
    if backend_of(entry) == ProviderBackend::AnthropicMessages {
        headers.push(("anthropic-version".into(), ANTHROPIC_VERSION.into()));
    }
    Ok(HttpRequest {
        method: HttpMethod::Get,
        url,
        headers,
        body: Vec::new(),
    })
}

pub fn build_models_list_capability(
    entry: &LlmProviderConfig,
) -> Result<HttpCapability, LlmError> {
    let resolved = make_resolved(entry, String::new());
    build_http_cap(&resolved, entry)
}

fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn parse_models_catalog_page(body: &[u8]) -> CatalogPage {
    if body.len() > MAX_JSON_BYTES {
        return CatalogPage::Unparseable;
    }
    let Ok(document) = serde_json::from_slice::<Value>(body) else {
        return CatalogPage::Unparseable;
    };
    let Some(list) = document
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| document.get("models").and_then(Value::as_array))
    else {
        return CatalogPage::Unparseable;
    };
    if list.is_empty() {
        return CatalogPage::EmptySuccess;
    }
    let mut models = Vec::new();
    for entry in list.iter().take(MAX_MODELS) {
        let Some(id) = entry
            .get("id")
            .or_else(|| entry.get("slug"))
            .and_then(Value::as_str)
            .filter(|s| is_vendor_model_id(s))
        else {
            continue;
        };
        let display_name = entry
            .get("display_name")
            .or_else(|| entry.get("name"))
            .and_then(Value::as_str)
            .filter(|s| is_display_text(s))
            .map(String::from);
        models.push(ListedModel {
            id: id.to_string(),
            display_name,
        });
    }
    let has_more = document
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let last_id = document
        .get("last_id")
        .and_then(Value::as_str)
        .map(String::from)
        .or_else(|| models.last().map(|m| m.id.clone()));
    CatalogPage::Parsed {
        models: dedup_preserve(models),
        has_more,
        last_id,
    }
}

const SIGN_IN_PHRASES: &[&str] = &[
    "please sign in",
    "sign in to view",
    "not logged in",
    "not signed in",
];

pub fn stdout_has_sign_in_language(stdout: &str) -> bool {
    let lower = stdout.to_lowercase();
    SIGN_IN_PHRASES.iter().any(|p| lower.contains(p))
}

pub fn parse_cli_models_stdout(stdout: &str) -> Vec<ListedModel> {
    let trimmed = stdout.trim();
    if trimmed.starts_with('{') {
        return match parse_models_catalog_page(trimmed.as_bytes()) {
            CatalogPage::Parsed { models, .. } => models,
            CatalogPage::EmptySuccess => Vec::new(),
            CatalogPage::Unparseable => parse_text_models(stdout),
        };
    }
    parse_text_models(stdout)
}

fn parse_text_models(stdout: &str) -> Vec<ListedModel> {
    if let Some(from_section) = parse_grok_section(stdout) {
        if !from_section.is_empty() {
            return from_section;
        }
    }
    parse_line_models(stdout)
}

fn parse_grok_section(stdout: &str) -> Option<Vec<ListedModel>> {
    let mut lines = stdout.lines();
    let found = lines.any(|line| line.trim() == "Available models:");
    if !found {
        return None;
    }
    let mut models = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(id) = bullet_id(trimmed) {
            models.push(ListedModel {
                id,
                display_name: None,
            });
        }
    }
    Some(dedup_preserve(models))
}

fn parse_line_models(stdout: &str) -> Vec<ListedModel> {
    let mut models = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Fetching")
            || trimmed.starts_with("Error:")
            || stdout_has_sign_in_language(trimmed)
        {
            continue;
        }
        if is_vendor_model_id(trimmed) {
            models.push(ListedModel {
                id: trimmed.to_string(),
                display_name: None,
            });
            continue;
        }
        if let Some(id) = bullet_id(trimmed) {
            models.push(ListedModel {
                id,
                display_name: None,
            });
        }
    }
    dedup_preserve(models)
}

fn bullet_id(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("* ")
        .or_else(|| line.strip_prefix("- "))
        .or_else(|| line.strip_prefix("*\t"))
        .or_else(|| line.strip_prefix("-\t"))?;
    let token = rest.split_whitespace().next()?.trim();
    let id = token.trim_end_matches("(default)");
    is_vendor_model_id(id).then(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_runtime::config::{
        InferenceBackendClass, ProviderAuthSource, ProviderBackend,
    };
    use std::collections::HashMap;

    fn entry(id: &str, endpoint: &str, backend: Option<ProviderBackend>) -> LlmProviderConfig {
        LlmProviderConfig {
            id: id.into(),
            endpoint: endpoint.into(),
            api_key_secret: "prov-key".into(),
            model_aliases: HashMap::from([("fast".into(), "m".into())]),
            cost_per_mtoken_in: 1.0,
            cost_per_mtoken_out: 2.0,
            cost_per_mtoken_cache_read: None,
            cost_per_mtoken_cache_write: None,
            cost_per_mtoken_cache_write_1h: None,
            rate_limit: None,
            retry_default: None,
            backend,
            auth_scheme: None,
            backend_class: InferenceBackendClass::CloudHttp,
            embedding_model: None,
            sidecar: None,
            profile_id: None,
            device_id: None,
            agent_cli: None,
            auth_source: ProviderAuthSource::ApiKey,
        }
    }

    #[test]
    fn am_t04_grok_indented_bullets() {
        let stdout = "You are logged in with grok.com.\n\nDefault model: grok-4.6\n\nAvailable models:\n  * grok-4.6 (default)\n  - grok-4.5\n";
        let ids: Vec<_> = parse_cli_models_stdout(stdout)
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, vec!["grok-4.6", "grok-4.5"]);
    }

    #[test]
    fn am_t05_gemini_lines_and_bullets() {
        let stdout = "Fetching available models...\nmodel-a\nmodel-b\n* also-ok\nthis line has spaces\n";
        let ids: Vec<_> = parse_cli_models_stdout(stdout)
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, vec!["model-a", "model-b", "also-ok"]);
    }

    #[test]
    fn am_t06_gemini_signed_out() {
        let stdout =
            "Fetching available models...\nError: Please sign in to view available models.\n";
        assert!(stdout_has_sign_in_language(stdout));
        assert!(parse_cli_models_stdout(stdout).is_empty());
    }

    #[test]
    fn am_t10_anthropic_inferred_from_id() {
        let req = build_models_list_request(&entry("anthropic", "https://api.anthropic.com", None), None)
            .unwrap();
        assert_eq!(req.url, "https://api.anthropic.com/v1/models?limit=100");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "anthropic-version" && v == ANTHROPIC_VERSION));
        let page2 = build_models_list_request(
            &entry("anthropic", "https://api.anthropic.com", None),
            Some("id/1"),
        )
        .unwrap();
        assert_eq!(
            page2.url,
            "https://api.anthropic.com/v1/models?limit=100&after_id=id%2F1"
        );
        assert!(!page2.url.contains("?limit=100?"));
    }

    #[test]
    fn am_t10_openai_inferred_from_other_id() {
        let req = build_models_list_request(&entry("openai", "https://api.openai.com", None), None)
            .unwrap();
        assert_eq!(req.url, "https://api.openai.com/v1/models");
        assert!(!req.headers.iter().any(|(k, _)| k == "anthropic-version"));
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer {prov-key}"));
    }

    #[test]
    fn am_t11_parser_and_key_drop() {
        let page = parse_models_catalog_page(
            br#"{"data":[{"id":"gpt-4o","display_name":"GPT"},{"id":"secret-key-xyz","display_name":"x"}]}"#,
        );
        let CatalogPage::Parsed { models, has_more, .. } = page else {
            panic!("{page:?}");
        };
        assert!(!has_more);
        let dropped = drop_key_rows(models, "secret-key-xyz");
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].id, "gpt-4o");
        assert!(matches!(
            parse_models_catalog_page(&vec![b'x'; MAX_JSON_BYTES + 1]),
            CatalogPage::Unparseable
        ));
        let short = drop_key_rows(
            vec![ListedModel {
                id: "gpt-4o".into(),
                display_name: None,
            }],
            "4",
        );
        assert_eq!(short[0].id, "gpt-4o");
    }

    #[test]
    fn capability_origin_prefix() {
        let cap =
            build_models_list_capability(&entry("openai", "https://api.openai.com", None)).unwrap();
        assert_eq!(cap.allowlist.patterns, vec!["https://api.openai.com/".to_string()]);
    }
}
