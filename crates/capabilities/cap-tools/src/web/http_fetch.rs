use std::sync::Arc;

use advance_shared_types::security_validator::{
    Allowlist, HttpCapability, HttpMethod, HttpRequest, HttpSecurityChain,
};
use advance_shared_types::web_search::SearchProviderError;

pub struct HttpFetchAdapter {
    chain: Arc<dyn HttpSecurityChain>,
}

impl HttpFetchAdapter {
    pub fn new(chain: Arc<dyn HttpSecurityChain>) -> Self {
        Self { chain }
    }

    pub async fn fetch(
        &self,
        agent_id: &str,
        url: &str,
        allow_hosts: &[String],
    ) -> Result<String, SearchProviderError> {
        let cap = HttpCapability {
            allowlist: Allowlist {
                patterns: allow_hosts.to_vec(),
            },
            credentials: Vec::new(),
            component_id: "web.extract".into(),
        };
        let req = HttpRequest {
            method: HttpMethod::Get,
            url: url.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let resp = self
            .chain
            .execute(agent_id, req, &cap)
            .await
            .map_err(|e| SearchProviderError::Provider(format!("egress denied: {e:?}")))?;
        String::from_utf8(resp.body).map_err(|_| SearchProviderError::Provider("utf8".into()))
    }
}
