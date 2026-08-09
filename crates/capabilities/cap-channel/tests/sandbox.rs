//! Integration tests for the per-adapter sandbox (AC-02, AC-06).

use std::collections::BTreeSet;
use std::sync::Arc;

use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
};
use async_trait::async_trait;
use cap_channel::{
    register_channel_host, AdapterCapabilitySet, AdapterType, ChannelHostBundle,
    OutboundDispatcher, SubscriptionManager, CHANNEL_HOST_CAPABILITY, CHANNEL_HOST_METHODS,
    CHANNEL_HOST_NAMESPACE,
};

struct NoopChain;
#[async_trait]
impl HttpSecurityChain for NoopChain {
    async fn execute(
        &self,
        _: &str,
        _: HttpRequest,
        _: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        })
    }
}

/// T02 (AC-02): channel-host registers via standard HostRegistry path.
///
/// Asserts that cap-channel uses the SAME `HostRegistry::register` API path as
/// every other capability (cap-grant, cap-skills, cap-tools, …); no
/// special-cased runtime gateway code, no Gateway/Proxy/Bridge type names in
/// the public API. This is the architectural property AC-02 asserts: "adapters
/// are normal WASM components".
#[test]
fn t02_channel_host_registers_via_standard_host_registry() {
    let registry = InMemoryHostRegistry::new();
    let manager = Arc::new(SubscriptionManager::new());
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(NoopChain);
    let outbound = Arc::new(OutboundDispatcher::new(chain, manager.clone()));

    register_channel_host(&registry, ChannelHostBundle { manager, outbound });

    // (i) + (ii) + (iii): exactly 3 specs, all under
    // CHANNEL_HOST_NAMESPACE with names in CHANNEL_HOST_METHODS.
    let specs = registry.lookup(CHANNEL_HOST_CAPABILITY);
    assert_eq!(specs.len(), 3, "expected 3 specs, got {}", specs.len());
    let names: Vec<_> = specs.iter().map(|s| s.name.clone()).collect();
    for required in CHANNEL_HOST_METHODS {
        assert!(
            names.contains(&required.to_string()),
            "missing required method {required}"
        );
    }
    for spec in &specs {
        assert_eq!(
            spec.namespace, CHANNEL_HOST_NAMESPACE,
            "spec {} has wrong namespace {}",
            spec.name, spec.namespace
        );
        assert_eq!(spec.capability, CHANNEL_HOST_CAPABILITY);
    }

    // (iv): no Gateway/Proxy/Bridge type name in the public API. We verify
    // by source-grep in tests/structural.rs (more precise) — this test
    // pins the constants surface. The constants pin in lib.rs ensures any
    // future contributor who imports `cap_channel::CHANNEL_HOST_NAMESPACE`
    // gets the same value as registered.
    assert_eq!(CHANNEL_HOST_NAMESPACE, "advance:runtime/channel-host@0.1.0");
    assert_eq!(CHANNEL_HOST_CAPABILITY, "channel");
}

/// T06 (AC-06): cross-adapter isolation — each preset declares only its own
/// minimum capabilities and outbound allowlist; cross-adapter capabilities
/// (e.g. slack.api inside telegram preset) are absent.
#[test]
fn t06_cross_adapter_isolation() {
    let telegram = AdapterCapabilitySet::preset_for(&AdapterType::Telegram);
    let slack = AdapterCapabilitySet::preset_for(&AdapterType::Slack);
    let signal = AdapterCapabilitySet::preset_for(&AdapterType::Signal);
    let webhook = AdapterCapabilitySet::preset_for(&AdapterType::Webhook);

    // Telegram preset must not include slack.api or websocket.
    let slack_caps: BTreeSet<String> = vec!["slack.api".to_string(), "websocket".to_string()]
        .into_iter()
        .collect();
    assert!(telegram.is_disjoint_from(&slack_caps));

    // Webhook preset has no outbound surface — empty allowlist + no
    // http.outbound capability.
    assert!(!webhook.capabilities.contains("http.outbound"));
    assert!(webhook.outbound_allowlist.patterns.is_empty());

    // Slack preset must NOT include telegram-specific markers.
    let telegram_only: BTreeSet<String> =
        vec!["telegram.bot_api".to_string()].into_iter().collect();
    assert!(slack.is_disjoint_from(&telegram_only));

    // Allowlists are scoped to the respective adapter's API origin.
    assert_eq!(
        telegram.outbound_allowlist.patterns,
        vec!["https://api.telegram.org/".to_string()]
    );
    assert_eq!(
        slack.outbound_allowlist.patterns,
        vec!["https://slack.com/api/".to_string()]
    );
    assert!(signal
        .outbound_allowlist
        .patterns
        .iter()
        .any(|p| p.contains("signal-server")));

    // `preset_default_deny()` (the `Other(*)` fallback) returns empty
    // capabilities AND empty allowlist.
    let default_deny = AdapterCapabilitySet::preset_for(&AdapterType::Other("discord".into()));
    assert!(default_deny.capabilities.is_empty());
    assert!(default_deny.outbound_allowlist.patterns.is_empty());
}
