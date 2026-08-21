use std::sync::Arc;
use std::time::Duration;

use advance_runtime::config::ToolsConfig;
use advance_shared_types::capability::ToolEntry;
use advance_shared_types::security_validator::HttpSecurityChain;
use advance_shared_types::traits::{GrantCheck, PromptInjectionHelpers};
use advance_shared_types::web_search::{
    EvidenceChunk, ExtractProviderRequest, SearchProviderError, SearchProviderRequest,
    SearchProviderSpi, WebExtractArgs, WebRunMode, WebSearchArgs, WebSearchHit, WebSearchResult,
    WEB_EXTRACT_TOOL_ID, WEB_SEARCH_TOOL_ID,
};

use crate::inventory::tool_entries_from_infos;
use crate::lazy_registry::{compile_method_schemas, json_check, CompiledSchema, GateFail};
use crate::registry::{MethodInfo, ToolError, ToolInfo};

use super::cache::{CacheKey, QueryCache};
use super::grant::web_tool_visible;
use super::http_fetch::HttpFetchAdapter;
use super::is_web_tool_id;
use super::sanitize::sanitize_web_text;
use super::stores::{EvidenceIdStore, ResultRefRecord, ResultRefStore};

const PRIVACY_QUERY_CAP: usize = 512;

pub fn agent_tool_infos() -> Vec<ToolInfo> {
    let search_in = r#"{"type":"object","properties":{"query":{"type":"string"},"filters":{"type":"object"},"mode":{"type":"string"}},"required":["query"],"additionalProperties":false}"#;
    let search_out =
        r#"{"type":"object","properties":{"hits":{"type":"array"}},"required":["hits"]}"#;
    let extract_in = r#"{"type":"object","properties":{"result_ref":{"type":"string"}},"required":["result_ref"],"additionalProperties":false}"#;
    let extract_out = r#"{"type":"object","properties":{"evidence_id":{"type":"string"},"url":{"type":"string"},"text":{"type":"string"},"title":{"type":"string"}},"required":["evidence_id","url","text"]}"#;
    vec![
        ToolInfo {
            id: WEB_SEARCH_TOOL_ID.into(),
            description: "Constrained web search. Returns title/url/snippet/rank and result_ref handles. No raw HTML.".into(),
            methods: vec![MethodInfo {
                name: "search".into(),
                description: Some("Run a constrained query".into()),
                input_schema: Some(search_in.into()),
                output_schema: Some(search_out.into()),
                idempotent: Some(true),
            }],
        },
        ToolInfo {
            id: WEB_EXTRACT_TOOL_ID.into(),
            description: "Extract readable text for a result_ref issued by web.search. Arbitrary URLs are refused.".into(),
            methods: vec![MethodInfo {
                name: "extract".into(),
                description: Some("Extract a previously searched result".into()),
                input_schema: Some(extract_in.into()),
                output_schema: Some(extract_out.into()),
                idempotent: Some(true),
            }],
        },
    ]
}

/// CLI Layer-3 inventory pre-filter (MODULE-017 (eee)(7) / INV-01).
///
/// Non-web names are filtered by the `tools.ids` allowlist. `web.search` /
/// `web.extract` are never passed through that reader (it is capability
/// `"tools"` only). They are appended iff [`web_tool_visible`].
pub fn project_callable_tool_entries(
    listed: Vec<ToolInfo>,
    tools_allowlist: Option<&[String]>,
    web_grant: Option<&dyn GrantCheck>,
    agent_id: &str,
) -> Vec<ToolEntry> {
    let mut entries = tool_entries_from_infos(listed)
        .into_iter()
        .filter(|e| {
            if is_web_tool_id(&e.name) {
                false
            } else {
                tools_allowlist
                    .map(|s| s.iter().any(|a| a == &e.name))
                    .unwrap_or(true)
            }
        })
        .collect::<Vec<_>>();
    if web_tool_visible(web_grant, agent_id) {
        entries.extend(tool_entries_from_infos(agent_tool_infos()));
    }
    entries
}

#[derive(Clone, Debug)]
pub struct WebFamilyConfig {
    pub mode: WebRunMode,
    pub provider_id: String,
    pub provider_allowlist: Vec<String>,
    pub pinned_hosts: Vec<String>,
    pub tenant: String,
    pub principal: String,
    pub kb_index_cutoff: String,
}

impl Default for WebFamilyConfig {
    fn default() -> Self {
        Self {
            mode: WebRunMode::Standard,
            provider_id: "fixture".into(),
            provider_allowlist: Vec::new(),
            pinned_hosts: Vec::new(),
            tenant: "default".into(),
            principal: "default".into(),
            kb_index_cutoff: "local-kb".into(),
        }
    }
}

pub struct WebFamilyParts {
    pub chain: Option<Arc<dyn HttpSecurityChain>>,
    pub helpers: Option<Arc<dyn PromptInjectionHelpers>>,
    pub web: WebFamilyConfig,
    pub tools: ToolsConfig,
    pub evidence_ids: Arc<EvidenceIdStore>,
    pub provider: Arc<dyn SearchProviderSpi>,
}

pub struct WebFamilyDispatcher {
    provider: Arc<dyn SearchProviderSpi>,
    refs: ResultRefStore,
    pub evidence: Arc<EvidenceIdStore>,
    cache: QueryCache,
    cfg: WebFamilyConfig,
    chain: Option<Arc<dyn HttpSecurityChain>>,
    helpers: Option<Arc<dyn PromptInjectionHelpers>>,
    invoke_timeout: Duration,
    max_result_bytes: usize,
    search_input: CompiledSchema,
    extract_input: CompiledSchema,
}

impl WebFamilyDispatcher {
    pub fn from_parts(parts: WebFamilyParts) -> Self {
        let infos = agent_tool_infos();
        let (mut search_in, _) = compile_method_schemas(&infos[0].methods);
        let (mut extract_in, _) = compile_method_schemas(&infos[1].methods);
        Self {
            provider: parts.provider,
            refs: ResultRefStore::new(),
            evidence: parts.evidence_ids,
            cache: QueryCache::new(),
            cfg: parts.web,
            chain: parts.chain,
            helpers: parts.helpers,
            invoke_timeout: Duration::from_secs(parts.tools.tool_invoke_timeout_sec.max(1)),
            max_result_bytes: parts.tools.max_result_bytes.max(1),
            search_input: search_in
                .remove("search")
                .unwrap_or(CompiledSchema::Invalid),
            extract_input: extract_in
                .remove("extract")
                .unwrap_or(CompiledSchema::Invalid),
        }
    }

    pub fn config(&self) -> &WebFamilyConfig {
        &self.cfg
    }

    pub async fn invoke(
        &self,
        agent_id: &str,
        tool_id: &str,
        method: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        let fut = self.dispatch(agent_id, tool_id, method, params);
        match tokio::time::timeout(self.invoke_timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(ToolError::InvocationFailed("web tool timeout".into())),
        }
    }

    async fn dispatch(
        &self,
        agent_id: &str,
        tool_id: &str,
        method: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        let bytes = if tool_id == WEB_SEARCH_TOOL_ID {
            if method != "search" {
                return Err(ToolError::MethodNotFound(method.into()));
            }
            check_input(&self.search_input, params)?;
            self.search(params).await?
        } else if tool_id == WEB_EXTRACT_TOOL_ID {
            if method != "extract" {
                return Err(ToolError::MethodNotFound(method.into()));
            }
            refuse_arbitrary_url(params)?;
            check_input(&self.extract_input, params)?;
            self.extract(agent_id, params).await?
        } else {
            return Err(ToolError::NotFound(tool_id.into()));
        };
        if bytes.len() > self.max_result_bytes {
            return Err(ToolError::OutputValidationFailed(format!(
                "tool result exceeds max_result_bytes ({} > {})",
                bytes.len(),
                self.max_result_bytes
            )));
        }
        Ok(bytes)
    }

    async fn search(&self, params: &[u8]) -> Result<Vec<u8>, ToolError> {
        let args: WebSearchArgs = parse_search_args(params)?;
        let mut query = args.query.split_whitespace().collect::<Vec<_>>().join(" ");
        let filters = if self.cfg.mode == WebRunMode::Privacy {
            None
        } else {
            args.filters.clone()
        };
        if self.cfg.mode == WebRunMode::Privacy && query.len() > PRIVACY_QUERY_CAP {
            truncate_utf8(&mut query, PRIVACY_QUERY_CAP);
        }
        if self.cfg.mode == WebRunMode::Enterprise
            && !self
                .cfg
                .provider_allowlist
                .iter()
                .any(|p| p == &self.cfg.provider_id)
        {
            return Err(map_spi(SearchProviderError::ProviderNotAllowlisted));
        }
        let filters_s = filters.as_ref().map(|v| v.to_string()).unwrap_or_default();
        let key = CacheKey {
            tenant: self.cfg.tenant.clone(),
            principal: self.cfg.principal.clone(),
            mode: self.cfg.mode,
            provider: self.provider.id().to_string(),
            query: query.clone(),
            filters: filters_s,
        };
        if self.cfg.mode != WebRunMode::Privacy {
            if let Some(hits) = self.cache.get(&key) {
                return encode(&WebSearchResult { hits });
            }
        }
        let req = SearchProviderRequest {
            query,
            filters,
            include_answer: self.cfg.mode != WebRunMode::Privacy,
            tenant: self.cfg.tenant.clone(),
            principal: self.cfg.principal.clone(),
            mode: self.cfg.mode,
        };
        let hits_raw = self.provider.search(req).await.map_err(map_spi)?;
        let helpers = self.helpers.as_deref();
        let mut hits = Vec::new();
        for h in hits_raw {
            let url = sanitize_url(&h.url)?;
            let title = sanitize_web_text(&h.title, helpers);
            let snippet = sanitize_web_text(&h.snippet, helpers);
            let result_ref = self.refs.mint(ResultRefRecord {
                url: url.clone(),
                rank: h.rank,
                tenant: self.cfg.tenant.clone(),
                needs_fetch: h.needs_fetch,
                cached_body: h.cached_body,
            });
            hits.push(WebSearchHit {
                title,
                url,
                snippet,
                rank: h.rank,
                result_ref,
            });
        }
        if self.cfg.mode != WebRunMode::Privacy {
            self.cache.put(key, hits.clone());
        }
        encode(&WebSearchResult { hits })
    }

    async fn extract(&self, agent_id: &str, params: &[u8]) -> Result<Vec<u8>, ToolError> {
        refuse_arbitrary_url(params)?;
        let args: WebExtractArgs = serde_json::from_slice(params)
            .map_err(|_| ToolError::InputValidationFailed("invalid extract args".into()))?;
        let rec = self
            .refs
            .get(&args.result_ref, &self.cfg.tenant)
            .ok_or(map_spi(SearchProviderError::InvalidResultRef))?;
        if self.cfg.mode == WebRunMode::Enterprise {
            let host = url_host(&rec.url)?;
            if !self
                .cfg
                .pinned_hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&host))
            {
                return Err(map_spi(SearchProviderError::EgressDenied));
            }
        }
        let body = if rec.needs_fetch {
            let chain = self
                .chain
                .as_ref()
                .ok_or(map_spi(SearchProviderError::EgressDenied))?;
            let allow = if self.cfg.mode == WebRunMode::Enterprise {
                self.cfg.pinned_hosts.clone()
            } else {
                vec![url_host(&rec.url)?]
            };
            HttpFetchAdapter::new(Arc::clone(chain))
                .fetch(agent_id, &rec.url, &allow)
                .await
                .map_err(map_spi)?
        } else {
            self.provider
                .extract(ExtractProviderRequest {
                    url: rec.url.clone(),
                    cached_body: rec.cached_body.clone(),
                })
                .await
                .map_err(map_spi)?
                .body
        };
        let helpers = self.helpers.as_deref();
        let text = sanitize_web_text(&body, helpers);
        let evidence_id = self.evidence.mint();
        encode(&EvidenceChunk {
            evidence_id,
            url: rec.url,
            text,
            title: None,
        })
    }
}

fn parse_search_args(params: &[u8]) -> Result<WebSearchArgs, ToolError> {
    serde_json::from_slice(params)
        .map_err(|_| ToolError::InputValidationFailed("invalid search args".into()))
}

fn refuse_arbitrary_url(params: &[u8]) -> Result<(), ToolError> {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(params) {
        if v.get("url").is_some() {
            return Err(map_spi(SearchProviderError::ArbitraryUrlRefused));
        }
        if v.is_string() {
            let s = v.as_str().unwrap_or("");
            if s.starts_with("http://") || s.starts_with("https://") {
                return Err(map_spi(SearchProviderError::ArbitraryUrlRefused));
            }
        }
        if v.get("result_ref").is_none() {
            return Err(map_spi(SearchProviderError::ArbitraryUrlRefused));
        }
    } else if let Ok(s) = std::str::from_utf8(params) {
        let t = s.trim();
        if t.starts_with("http://") || t.starts_with("https://") {
            return Err(map_spi(SearchProviderError::ArbitraryUrlRefused));
        }
    }
    Ok(())
}

fn sanitize_url(raw: &str) -> Result<String, ToolError> {
    let lower = raw.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return Err(ToolError::InputValidationFailed(
            "url scheme refused".into(),
        ));
    }
    Ok(raw.to_string())
}

fn url_host(raw: &str) -> Result<String, ToolError> {
    let rest = raw
        .split_once("://")
        .map(|(_, r)| r)
        .ok_or_else(|| ToolError::InputValidationFailed("url host missing".into()))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next().unwrap_or("").trim()
    } else {
        authority.split(':').next().unwrap_or("").trim()
    };
    if host.is_empty() {
        return Err(ToolError::InputValidationFailed("url host missing".into()));
    }
    Ok(host.to_string())
}

fn truncate_utf8(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

fn check_input(schema: &CompiledSchema, params: &[u8]) -> Result<(), ToolError> {
    match schema {
        CompiledSchema::Valid(compiled) => json_check(compiled, params).map_err(|g| match g {
            GateFail::NotJson | GateFail::SchemaFail => {
                ToolError::InputValidationFailed("input validation failed".into())
            }
        }),
        CompiledSchema::Invalid => Err(ToolError::InputValidationFailed(
            "input schema invalid".into(),
        )),
    }
}

fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, ToolError> {
    serde_json::to_vec(v).map_err(|e| ToolError::InvocationFailed(e.to_string()))
}

fn map_spi(e: SearchProviderError) -> ToolError {
    match e {
        SearchProviderError::ArbitraryUrlRefused => {
            ToolError::InputValidationFailed("arbitrary url refused".into())
        }
        SearchProviderError::InvalidResultRef => {
            ToolError::InputValidationFailed("invalid result_ref".into())
        }
        SearchProviderError::StdioProviderRefused => {
            ToolError::PermissionDenied("stdio provider refused".into())
        }
        SearchProviderError::ProviderNotAllowlisted | SearchProviderError::EgressDenied => {
            ToolError::PermissionDenied(e.to_string())
        }
        SearchProviderError::Provider(m) => ToolError::InvocationFailed(m),
    }
}
