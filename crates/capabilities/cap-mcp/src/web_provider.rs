use advance_shared_types::web_search::SearchProviderError;

use crate::whitelist::McpTransportSpec;

pub fn refuse_stdio_web_provider(spec: &McpTransportSpec) -> Result<(), SearchProviderError> {
    match spec {
        McpTransportSpec::Stdio { .. } => Err(SearchProviderError::StdioProviderRefused),
        McpTransportSpec::Http { .. } => Ok(()),
    }
}
