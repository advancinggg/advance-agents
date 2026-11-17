//! Layer-3-only capabilities in the catalog filter (ADR 2026-10-28 D1).

use std::sync::Arc;

use super::dispatch::AgentCapsLookup;

/// Appends the home's declared Layer-3-only capabilities (`browser`, `screen`:
/// [`crate::agent_config::LAYER3_CAPABILITIES`]) to every agent's capability
/// list. They are home-level declarations without a `CapRequest`, so the agent
/// tree never carries them; the catalog lists their callables for every agent of
/// the home and the caller's grant (CONTRACT-122) decides each call.
pub struct HomeLayer3Caps {
    inner: Arc<dyn AgentCapsLookup>,
    extra: Vec<String>,
}

impl HomeLayer3Caps {
    pub fn new(inner: Arc<dyn AgentCapsLookup>, extra: Vec<String>) -> Self {
        Self { inner, extra }
    }
}

impl AgentCapsLookup for HomeLayer3Caps {
    fn capabilities(&self, agent_id: &str) -> Vec<String> {
        let mut caps = self.inner.capabilities(agent_id);
        for cap in &self.extra {
            if !caps.contains(cap) {
                caps.push(cap.clone());
            }
        }
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callables::StaticCaps;

    #[test]
    fn layer3_caps_are_appended_once() {
        let lookup = HomeLayer3Caps::new(
            Arc::new(StaticCaps(vec!["llm".into(), "browser".into()])),
            vec!["browser".into(), "screen".into()],
        );
        assert_eq!(
            lookup.capabilities("agent"),
            vec!["llm", "browser", "screen"]
        );
    }
}
