//! CONTRACT-239 host-fn `web.search` / `web.extract` family.

mod cache;
mod citations;
mod dispatcher;
mod grant;
mod http_fetch;
mod providers;
mod registry;
mod sanitize;
mod stores;

pub use cache::{CacheKey, QueryCache};
pub use citations::{strip_unissued_citations, validate_citations};
pub use dispatcher::{
    agent_tool_infos, project_callable_tool_entries, WebFamilyConfig, WebFamilyDispatcher,
    WebFamilyParts,
};
pub use grant::{check_web_grant, web_tool_visible, OfflineDenyingGrantCheck};
pub use http_fetch::HttpFetchAdapter;
pub use providers::{FixtureProvider, RecordingProvider};
pub use registry::{CompositeToolRegistry, HostToolRegistry};
pub use sanitize::sanitize_web_text;
pub use stores::{EvidenceIdStore, ResultRefRecord, ResultRefStore};

pub use advance_shared_types::web_search::{
    is_web_tool_id, WEB_EXTRACT_TOOL_ID, WEB_GRANT_CAPABILITY, WEB_SEARCH_TOOL_ID,
};
