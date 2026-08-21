//! MODULE-017-T104 stdio-as-web-provider refusal.

use std::collections::BTreeMap;

use advance_shared_types::security_validator::{Allowlist, HttpCapability};
use advance_shared_types::web_search::SearchProviderError;
use cap_mcp::{refuse_stdio_web_provider, McpTransportSpec};

#[test]
fn t104_stdio_web_provider_refused() {
    let spec = McpTransportSpec::Stdio {
        command: "npx".into(),
        args: vec!["-y".into(), "fake-search".into()],
        env: BTreeMap::new(),
    };
    assert_eq!(
        refuse_stdio_web_provider(&spec),
        Err(SearchProviderError::StdioProviderRefused)
    );
}

#[test]
fn t104_http_web_provider_ok() {
    let spec = McpTransportSpec::Http {
        endpoint_url: "https://example.com/mcp".into(),
        capability: HttpCapability {
            allowlist: Allowlist {
                patterns: vec!["example.com".into()],
            },
            credentials: vec![],
            component_id: "web".into(),
        },
    };
    assert!(refuse_stdio_web_provider(&spec).is_ok());
}
