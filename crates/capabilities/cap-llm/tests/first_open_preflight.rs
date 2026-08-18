//! T138 — MODULE-009-AC-32 in-memory one-element pin + recorded outbound.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider};
use advance_shared_types::security_validator::{HttpResponse, SsrfGuard};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultRateLimiter, DefaultSsrfGuard,
    HttpExecutor, MockHttpExecutor, MockResolver,
};
use cap_llm::{chat_preflight, resolve_provider_and_model, DiscardEventBus, StaticConfig};
use cap_secrets::{InMemorySecretStorage, SecretStore};
use zeroize::Zeroizing;

fn openai_ok_body() -> Vec<u8> {
    br#"{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1},"model":"gpt-4o"}"#
        .to_vec()
}

fn one_element_yaml() -> &'static str {
    r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
database:
  db-path: ".runtime/index.db"
  pool-size: 4
  wal-mode: true
  embedding-dim: 768
  recall-max-depth: 3
"#
}

#[tokio::test]
async fn t138_one_element_list_resolves_named_provider() {
    let cfg: RuntimeConfig = serde_yml::from_str(one_element_yaml()).expect("parse");
    let resolved = resolve_provider_and_model(&cfg.llm_providers, None).unwrap();
    assert_eq!(resolved.id, "openai");

    let storage = Arc::new(InMemorySecretStorage::default());
    let store = SecretStore::new(Zeroizing::new([0x11u8; 32]), storage);
    store.store("openai-api-key", "sk-test-T138").unwrap();
    let exec = Arc::new(MockHttpExecutor::new().with_response(
        "https://api.openai.com",
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: openai_ok_body(),
        },
    ));
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(
        MockResolver::new().with(
            "api.openai.com",
            vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()],
        ),
    )));
    let chain = Arc::new(DefaultHttpSecurityChain::new(
        Arc::new(store),
        Arc::new(DefaultLeakDetector::new()),
        ssrf,
        Arc::new(DefaultRateLimiter::new()),
        Arc::clone(&exec) as Arc<dyn HttpExecutor>,
    ));
    let config: Arc<dyn RuntimeConfigProvider> = Arc::new(StaticConfig(Arc::new(cfg)));
    chat_preflight(
        config,
        chain,
        Arc::new(DiscardEventBus),
        &AtomicBool::new(false),
    )
    .await
    .expect("chat_preflight");
    let recorded = exec.recorded_requests.lock().unwrap();
    assert!(
        recorded.iter().any(|(u, _)| u.contains("api.openai.com")),
        "{recorded:?}"
    );
    assert!(
        !recorded.iter().any(|(u, _)| u.contains("anthropic")),
        "{recorded:?}"
    );
}

fn two_element_starter_openai_first() -> RuntimeConfig {
    let yaml = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
database:
  db-path: ".runtime/index.db"
  pool-size: 4
  wal-mode: true
  embedding-dim: 768
  recall-max-depth: 3
"#;
    let mut cfg: RuntimeConfig = serde_yml::from_str(yaml).expect("parse starter");
    let openai = cfg
        .llm_providers
        .iter()
        .position(|p| p.id == "openai")
        .unwrap();
    let entry = cfg.llm_providers.remove(openai);
    cfg.llm_providers.insert(0, entry);
    cfg
}

/// After first-open rewrite (openai selected, anthropic still present), the
/// next generate must target openai — no silent fallback.
#[tokio::test]
async fn t138_next_generate_uses_preflighted_not_previous() {
    let cfg = two_element_starter_openai_first();
    assert_eq!(cfg.llm_providers.len(), 2);
    assert_eq!(cfg.llm_providers[0].id, "openai");
    assert_eq!(cfg.llm_providers[1].id, "anthropic");
    assert_eq!(
        resolve_provider_and_model(&cfg.llm_providers, None)
            .unwrap()
            .id,
        "openai"
    );

    let storage = Arc::new(InMemorySecretStorage::default());
    let store = SecretStore::new(Zeroizing::new([0x11u8; 32]), storage);
    store.store("openai-api-key", "sk-test-T138-next").unwrap();
    store
        .store("anthropic-api-key", "sk-test-T138-previous")
        .unwrap();
    let exec = Arc::new(
        MockHttpExecutor::new()
            .with_response(
                "https://api.openai.com",
                HttpResponse {
                    status: 200,
                    headers: vec![("content-type".into(), "application/json".into())],
                    body: openai_ok_body(),
                },
            )
            .with_response(
                "https://api.anthropic.com",
                HttpResponse {
                    status: 200,
                    headers: vec![("content-type".into(), "application/json".into())],
                    body: openai_ok_body(),
                },
            ),
    );
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(
        MockResolver::new()
            .with(
                "api.openai.com",
                vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()],
            )
            .with(
                "api.anthropic.com",
                vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()],
            ),
    )));
    let chain = Arc::new(DefaultHttpSecurityChain::new(
        Arc::new(store),
        Arc::new(DefaultLeakDetector::new()),
        ssrf,
        Arc::new(DefaultRateLimiter::new()),
        Arc::clone(&exec) as Arc<dyn HttpExecutor>,
    ));
    let config: Arc<dyn RuntimeConfigProvider> = Arc::new(StaticConfig(Arc::new(cfg)));
    chat_preflight(
        config,
        chain,
        Arc::new(DiscardEventBus),
        &AtomicBool::new(false),
    )
    .await
    .expect("post-pass generate");
    let recorded = exec.recorded_requests.lock().unwrap();
    assert!(
        recorded.iter().any(|(u, _)| u.contains("api.openai.com")),
        "{recorded:?}"
    );
    assert!(
        !recorded.iter().any(|(u, _)| u.contains("anthropic")),
        "silent fallback to previous provider: {recorded:?}"
    );
}
