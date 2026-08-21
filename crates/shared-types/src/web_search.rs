//! CONTRACT-240 Search Provider SPI + CONTRACT-239 agent-visible web-tool DTOs.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub const WEB_SEARCH_TOOL_ID: &str = "web.search";
pub const WEB_EXTRACT_TOOL_ID: &str = "web.extract";
pub const WEB_GRANT_CAPABILITY: &str = "web";

pub fn is_web_tool_id(id: &str) -> bool {
    id == WEB_SEARCH_TOOL_ID || id == WEB_EXTRACT_TOOL_ID
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebRunMode {
    Offline,
    Privacy,
    #[default]
    Standard,
    Enterprise,
}

impl WebRunMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Privacy => "privacy",
            Self::Standard => "standard",
            Self::Enterprise => "enterprise",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct WebRunStatus {
    pub mode: WebRunMode,
    pub index_cutoff: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSearchArgs {
    pub query: String,
    #[serde(default)]
    pub filters: Option<serde_json::Value>,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSearchHit {
    pub title: String,
    pub url: String,
    pub snippet: String,
    pub rank: u32,
    pub result_ref: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSearchResult {
    pub hits: Vec<WebSearchHit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebExtractArgs {
    pub result_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceChunk {
    pub evidence_id: String,
    pub url: String,
    pub text: String,
    #[serde(default)]
    pub title: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchProviderRequest {
    pub query: String,
    pub filters: Option<serde_json::Value>,
    pub include_answer: bool,
    pub tenant: String,
    pub principal: String,
    pub mode: WebRunMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchProviderHit {
    pub title: String,
    pub url: String,
    pub snippet: String,
    pub rank: u32,
    pub needs_fetch: bool,
    pub cached_body: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractProviderRequest {
    pub url: String,
    pub cached_body: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractProviderResponse {
    pub title: Option<String>,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchProviderError {
    StdioProviderRefused,
    ProviderNotAllowlisted,
    EgressDenied,
    InvalidResultRef,
    ArbitraryUrlRefused,
    Provider(String),
}

impl fmt::Display for SearchProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StdioProviderRefused => write!(f, "mcp stdio refused as web provider"),
            Self::ProviderNotAllowlisted => write!(f, "provider not allowlisted"),
            Self::EgressDenied => write!(f, "egress denied"),
            Self::InvalidResultRef => write!(f, "invalid result_ref"),
            Self::ArbitraryUrlRefused => write!(f, "arbitrary url refused"),
            Self::Provider(msg) => write!(f, "provider: {msg}"),
        }
    }
}

impl std::error::Error for SearchProviderError {}

#[async_trait]
pub trait SearchProviderSpi: Send + Sync {
    fn id(&self) -> &str;
    fn vendor_extensions_schema(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    async fn search(
        &self,
        req: SearchProviderRequest,
    ) -> Result<Vec<SearchProviderHit>, SearchProviderError>;
    async fn extract(
        &self,
        req: ExtractProviderRequest,
    ) -> Result<ExtractProviderResponse, SearchProviderError>;
}
