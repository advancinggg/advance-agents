use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use advance_shared_types::web_search::WEB_GRANT_CAPABILITY;
use std::sync::Arc;

pub fn web_tool_visible(grant: Option<&dyn GrantCheck>, agent_id: &str) -> bool {
    let Some(g) = grant else {
        return false;
    };
    matches!(
        g.check(
            agent_id,
            WEB_GRANT_CAPABILITY,
            "tool-invoke",
            &CapParams::empty()
        ),
        GrantDecision::Allow
    )
}

pub fn check_web_grant(grant: &dyn GrantCheck, agent_id: &str) -> GrantDecision {
    grant.check(
        agent_id,
        WEB_GRANT_CAPABILITY,
        "tool-invoke",
        &CapParams::empty(),
    )
}

/// Denies capability `"web"` when offline; otherwise delegates.
pub struct OfflineDenyingGrantCheck {
    pub inner: Arc<dyn GrantCheck>,
    pub offline: bool,
}

impl GrantCheck for OfflineDenyingGrantCheck {
    fn check(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        params: &CapParams,
    ) -> GrantDecision {
        if self.offline && capability == WEB_GRANT_CAPABILITY {
            return GrantDecision::Deny("web withheld in offline mode".into());
        }
        self.inner.check(agent_id, capability, function, params)
    }
}
