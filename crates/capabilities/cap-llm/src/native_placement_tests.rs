//! ADR 2026-10-24 D6 / A5 — `would_be_native_placement` (V17).

use std::collections::HashMap;
use std::sync::Arc;

use advance_runtime::config::{
    AgentCliSpec, AgentCliVendor, InferenceBackendClass, LlmProviderConfig, ProviderBackend,
};

use crate::gateway::LlmGateway;
use crate::policy::{AgentLlmPolicy, AgentLlmPolicySource};
use crate::test_support::{
    fixture_runtime_config, no_op_repetition_guard, MockEventBusEmit, MockHttpSecurityChain,
    MockRunBudget, MockRuntimeConfigProvider,
};

struct PinPolicy {
    agent: String,
    provider: String,
}

impl AgentLlmPolicySource for PinPolicy {
    fn policy_for(&self, agent_id: &str) -> Option<AgentLlmPolicy> {
        if agent_id == self.agent {
            Some(AgentLlmPolicy {
                provider: Some(self.provider.clone()),
                model: None,
                constraint: None,
            })
        } else {
            None
        }
    }
}

fn agent_cli_cfg() -> LlmProviderConfig {
    let mut aliases = HashMap::new();
    aliases.insert("sonnet".into(), "sonnet".into());
    LlmProviderConfig {
        id: "claude-sub".into(),
        endpoint: String::new(),
        api_key_secret: "claude-sub-api-key".into(),
        model_aliases: aliases,
        cost_per_mtoken_in: 0.001,
        cost_per_mtoken_out: 0.001,
        cost_per_mtoken_cache_read: None,
        cost_per_mtoken_cache_write: None,
        cost_per_mtoken_cache_write_1h: None,
        rate_limit: None,
        retry_default: None,
        backend: Some(ProviderBackend::OpenAiChat),
        auth_scheme: None,
        backend_class: InferenceBackendClass::AgentCli,
        embedding_model: None,
        sidecar: None,
        profile_id: None,
        device_id: None,
        agent_cli: Some(AgentCliSpec {
            vendor: AgentCliVendor::Claude,
            command: "/nonexistent/claude".into(),
            args: vec![],
        }),
        auth_source: advance_runtime::config::ProviderAuthSource::ApiKey,
        generate_timeout_secs: None,
        reasoning_effort: None,
        system_messages: None,
    }
}

fn gateway_with(
    cfg: advance_runtime::config::RuntimeConfig,
    policy: Option<Arc<dyn AgentLlmPolicySource>>,
) -> LlmGateway {
    let cfg_provider = Arc::new(MockRuntimeConfigProvider::new(cfg));
    let chain = Arc::new(MockHttpSecurityChain::default());
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let mut gw = LlmGateway::new(
        cfg_provider,
        chain,
        budget,
        bus,
        no_op_repetition_guard(),
        "test-agent".into(),
    );
    if let Some(source) = policy {
        gw = gw.with_agent_policy(source);
    }
    gw
}

#[test]
fn v17_head_cloud_http_is_native() {
    let gw = gateway_with(fixture_runtime_config(), None);
    assert!(
        gw.would_be_native_placement("any-agent"),
        "fixture head provider is openai CloudHttp = Native"
    );
}

#[test]
fn v17_agent_cli_pin_is_not_native() {
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers.push(agent_cli_cfg());
    let gw = gateway_with(
        cfg,
        Some(Arc::new(PinPolicy {
            agent: "cli-agent".into(),
            provider: "claude-sub".into(),
        })),
    );
    assert!(
        !gw.would_be_native_placement("cli-agent"),
        "agent-cli pin is Disabled"
    );
    assert!(
        gw.would_be_native_placement("other"),
        "unpinned agent uses the openai head"
    );
}

#[test]
fn v17_missing_pin_is_false() {
    let gw = gateway_with(
        fixture_runtime_config(),
        Some(Arc::new(PinPolicy {
            agent: "ghost".into(),
            provider: "no-such-provider".into(),
        })),
    );
    assert!(
        !gw.would_be_native_placement("ghost"),
        "a pin that is not in llm-providers is not native"
    );
}

#[test]
fn v17_empty_providers_is_false() {
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers.clear();
    let gw = gateway_with(cfg, None);
    assert!(!gw.would_be_native_placement("any"));
}
