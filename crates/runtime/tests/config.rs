//! Tests for RuntimeConfig loader + hot-reload (CONTRACT-003, AC-12).

use advance_runtime::config::*;
use std::io::Write;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// Canonical YAML from MODULE-001 §1.4.2 lines 318-378.
const CANONICAL_YAML: &str = r#"
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
      opus: claude-opus-4-6
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
  - id: openai
    endpoint: https://api.openai.com/v1
    api-key-secret: openai-api-key
    model-aliases:
      gpt4o: gpt-4o-2024-08-06
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

circuit-breakers:
  - scope: capability
    target: llm
    state: open
    kill-existing: false
    reason: "LLM provider outage"
  - scope: component-type
    target: cron
    state: open
  - scope: agent
    target: "agent-id-xxx"
    state: open

secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY

users:
  - id: "user:alice"
    channels:
      - telegram: "user123"
      - slack: "U456ABC"

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

/// Minimal valid YAML with just the required sections.
fn minimal_yaml() -> String {
    r#"
wasm:
  max_memory_pages: 512
  epoch_interruption_ms: 50
  fuel_enabled: true
llm-providers: []
cron:
  max_jitter_ratio: 0.05
git:
  gc_interval_hours: 12
  max_tracked_file_mb: 5
circuit-breakers: []
secrets:
  master-key-source: env-var
  env-var-name: MY_KEY
users: []
post-processor:
  llm-model: fast
  llm-failure-cooldown-seconds: 300
"#
    .to_string()
}

fn write_config(path: &std::path::Path, content: &str) {
    std::fs::write(path, content).expect("failed to write config");
}

fn replace_config_atomically(path: &std::path::Path, content: &str) {
    let tmp_path = path.with_extension("yaml.tmp");
    write_config(&tmp_path, content);
    std::fs::rename(&tmp_path, path).expect("failed to replace config");
}

// -----------------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------------

#[test]
fn parse_full_config() {
    let config: RuntimeConfig = serde_yml::from_str(CANONICAL_YAML).unwrap();

    // Wasm
    assert_eq!(config.wasm.max_memory_pages, 1024);
    assert_eq!(config.wasm.epoch_interruption_ms, 100);
    assert!(!config.wasm.fuel_enabled);

    // LLM providers
    assert_eq!(config.llm_providers.len(), 2);
    assert_eq!(config.llm_providers[0].id, "anthropic");
    assert_eq!(config.llm_providers[1].id, "openai");
    assert!(config.llm_providers[0].rate_limit.is_some());
    assert!(config.llm_providers[1].rate_limit.is_none());

    // Cron
    assert!((config.cron.max_jitter_ratio - 0.1).abs() < f64::EPSILON);

    // Git
    assert_eq!(config.git.gc_interval_hours, 24);
    assert_eq!(config.git.max_tracked_file_mb, 10);

    // Circuit breakers
    assert_eq!(config.circuit_breakers.len(), 3);
    assert_eq!(
        config.circuit_breakers[0].scope,
        CircuitBreakerScope::Capability
    );
    assert_eq!(config.circuit_breakers[0].kill_existing, Some(false));
    assert_eq!(
        config.circuit_breakers[0].reason.as_deref(),
        Some("LLM provider outage")
    );
    assert!(config.circuit_breakers[1].kill_existing.is_none());
    assert!(config.circuit_breakers[1].reason.is_none());
    assert_eq!(config.circuit_breakers[2].scope, CircuitBreakerScope::Agent);

    // Secrets
    assert_eq!(config.secrets.master_key_source, MasterKeySource::Keychain);
    assert_eq!(config.secrets.env_var_name, "SECRETS_MASTER_KEY");

    // Users
    assert_eq!(config.users.len(), 1);
    assert_eq!(config.users[0].id, "user:alice");
    assert_eq!(config.users[0].channels.len(), 2);
    assert_eq!(
        config.users[0].channels[0].get("telegram").unwrap(),
        "user123"
    );
    assert_eq!(config.users[0].channels[1].get("slack").unwrap(), "U456ABC");

    // Post-processor
    assert_eq!(config.post_processor.llm_model, "sonnet-light");
    assert_eq!(config.post_processor.llm_failure_cooldown_seconds, 600);

    // Auto-loop defaults (absent from YAML, defaults to empty)
    assert_eq!(config.auto_loop_defaults, AutoLoopDefaults {});
}

#[test]
fn deny_unknown_fields_rejects_extra() {
    let yaml = format!("{}\nextra_field: true\n", CANONICAL_YAML.trim());
    let result = serde_yml::from_str::<RuntimeConfig>(&yaml);
    assert!(result.is_err(), "should reject unknown top-level field");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field"),
        "error should mention unknown field: {err}"
    );
}

#[test]
fn parse_llm_providers_nested() {
    let config: RuntimeConfig = serde_yml::from_str(CANONICAL_YAML).unwrap();

    let anthropic = &config.llm_providers[0];
    assert_eq!(anthropic.model_aliases.len(), 2);
    assert_eq!(
        anthropic.model_aliases.get("sonnet").unwrap(),
        "claude-sonnet-4-5"
    );
    assert_eq!(
        anthropic.model_aliases.get("opus").unwrap(),
        "claude-opus-4-6"
    );
    assert!((anthropic.cost_per_mtoken_in - 3.0).abs() < f64::EPSILON);
    assert!((anthropic.cost_per_mtoken_out - 15.0).abs() < f64::EPSILON);

    let rl = anthropic.rate_limit.as_ref().unwrap();
    assert_eq!(rl.requests_per_minute, 1000);
    assert_eq!(rl.tokens_per_minute, 400000);

    let openai = &config.llm_providers[1];
    assert_eq!(openai.model_aliases.len(), 1);
    assert_eq!(
        openai.model_aliases.get("gpt4o").unwrap(),
        "gpt-4o-2024-08-06"
    );
    assert!(openai.rate_limit.is_none());
}

#[test]
fn provider_trait_object_safe() {
    // Compile-time check: `dyn RuntimeConfigProvider` must be object-safe.
    fn _assert_object_safe(_: &dyn RuntimeConfigProvider) {}
    let _: Option<Box<dyn RuntimeConfigProvider>> = None;
}

// -----------------------------------------------------------------------
// Integration tests (hot-reload)
// -----------------------------------------------------------------------

#[tokio::test]
async fn current_returns_latest() {
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(minimal_yaml().as_bytes()).unwrap();
    tmp.flush().unwrap();

    let watcher = RuntimeConfigWatcher::new(tmp.path()).await.unwrap();
    let config = watcher.current();
    assert_eq!(config.wasm.max_memory_pages, 512);
    assert!(config.wasm.fuel_enabled);
}

#[tokio::test]
async fn hot_reload_notifies_subscribers() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &minimal_yaml());

    let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
    let mut rx = watcher.subscribe();

    // Verify initial state
    assert_eq!(watcher.current().wasm.max_memory_pages, 512);

    // Modify: change max_memory_pages from 512 to 2048
    tokio::time::sleep(Duration::from_millis(100)).await;
    let modified = minimal_yaml().replace("max_memory_pages: 512", "max_memory_pages: 2048");
    write_config(&config_path, &modified);

    // Wait for notification (with timeout)
    let new_config = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for config reload")
        .expect("channel closed");

    assert_eq!(new_config.wasm.max_memory_pages, 2048);
    assert_eq!(watcher.current().wasm.max_memory_pages, 2048);
}

#[tokio::test]
async fn hot_reload_ignores_invalid_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &minimal_yaml());

    let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
    let original = watcher.current();

    // Write invalid YAML
    tokio::time::sleep(Duration::from_millis(100)).await;
    write_config(&config_path, "invalid: yaml: [[[");

    // Give the watcher time to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Current config should be unchanged
    assert_eq!(*watcher.current(), *original);
}

#[tokio::test]
async fn multiple_subscribers() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &minimal_yaml());

    let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
    let mut rx1 = watcher.subscribe();
    let mut rx2 = watcher.subscribe();

    // Modify config
    tokio::time::sleep(Duration::from_millis(100)).await;
    let modified = minimal_yaml().replace("max_memory_pages: 512", "max_memory_pages: 4096");
    write_config(&config_path, &modified);

    // Both subscribers should receive the update
    let c1 = tokio::time::timeout(Duration::from_secs(5), rx1.recv())
        .await
        .expect("timeout rx1")
        .expect("rx1 closed");
    let c2 = tokio::time::timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("timeout rx2")
        .expect("rx2 closed");

    assert_eq!(c1.wasm.max_memory_pages, 4096);
    assert_eq!(c2.wasm.max_memory_pages, 4096);
}

#[tokio::test]
async fn new_fails_on_missing_file() {
    let result = RuntimeConfigWatcher::new("/nonexistent/path/config.yaml").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ConfigError::IoError { .. }),
        "expected IoError, got: {err}"
    );
}

#[tokio::test]
async fn hot_reload_handles_atomic_rename() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &minimal_yaml());

    let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
    let mut rx = watcher.subscribe();

    // Atomic rename: write to a temp file, then rename over the original
    tokio::time::sleep(Duration::from_millis(100)).await;
    let tmp_path = dir.path().join("runtime-config.yaml.tmp");
    let modified = minimal_yaml().replace("max_memory_pages: 512", "max_memory_pages: 8192");
    write_config(&tmp_path, &modified);
    std::fs::rename(&tmp_path, &config_path).expect("rename failed");

    let new_config = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for atomic rename reload")
        .expect("channel closed");

    assert_eq!(new_config.wasm.max_memory_pages, 8192);
}

#[tokio::test]
async fn subscriber_disconnect_pruned() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &minimal_yaml());

    let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();

    // Subscribe then immediately drop the receiver
    let rx = watcher.subscribe();
    drop(rx);

    // Subscribe a second receiver that we keep alive
    let mut rx2 = watcher.subscribe();

    // Modify config — should not panic despite the first receiver being dropped
    tokio::time::sleep(Duration::from_millis(100)).await;
    let modified = minimal_yaml().replace("max_memory_pages: 512", "max_memory_pages: 1024");
    write_config(&config_path, &modified);

    let new_config = tokio::time::timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("timeout")
        .expect("rx2 closed");

    assert_eq!(new_config.wasm.max_memory_pages, 1024);
}

#[tokio::test]
async fn file_size_limit_rejects_oversized_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    // Write > MAX_CONFIG_SIZE (64 KiB).
    let padding = "#".repeat((MAX_CONFIG_SIZE + 1024) as usize);
    let content = format!("{}\n{padding}", minimal_yaml());
    write_config(&config_path, &content);

    let result = RuntimeConfigWatcher::new(&config_path).await;
    assert!(
        matches!(result, Err(ConfigError::FileTooLarge { .. })),
        "expected FileTooLarge error, got: {:?}",
        result.map(|_| "Ok").unwrap_or_else(|e| match e {
            ConfigError::FileTooLarge { .. } => "FileTooLarge",
            ConfigError::ParseFailure { .. } => "ParseFailure",
            ConfigError::IoError { .. } => "IoError",
            ConfigError::WatchError { .. } => "WatchError",
        })
    );
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_non_regular_file() {
    // FIFO has metadata().len() == 0 but blocks on read. Must be rejected by
    // is_file() check, not by size cap. Timeout guards against regression.
    use std::os::unix::fs::FileTypeExt;
    let dir = tempfile::tempdir().unwrap();
    let fifo_path = dir.path().join("runtime-config.yaml");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("mkfifo failed");
    assert!(status.success(), "mkfifo did not succeed");
    let meta = std::fs::symlink_metadata(&fifo_path).unwrap();
    assert!(meta.file_type().is_fifo(), "expected FIFO");

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        RuntimeConfigWatcher::new(&fifo_path),
    )
    .await
    .expect("watcher hung reading FIFO — is_file() check missing")
    .expect_err("expected error for non-regular file");

    assert!(
        matches!(result, ConfigError::IoError { .. }),
        "expected IoError for non-regular file, got: {result}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_symlink_at_config_path() {
    // A symlink at the config path — even to a valid regular file — must be rejected.
    // Defeats the symlink-swap TOCTOU attack where an attacker replaces the config
    // with a symlink to an attacker-controlled file between reloads.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real-config.yaml");
    write_config(&target, &minimal_yaml());

    let link = dir.path().join("runtime-config.yaml");
    std::os::unix::fs::symlink(&target, &link).expect("symlink failed");

    let result = RuntimeConfigWatcher::new(&link).await;
    assert!(
        matches!(result, Err(ConfigError::IoError { .. })),
        "expected IoError for symlinked config path, got: {:?}",
        result.map(|_| "Ok").unwrap_or_else(|e| match e {
            ConfigError::FileTooLarge { .. } => "FileTooLarge",
            ConfigError::ParseFailure { .. } => "ParseFailure",
            ConfigError::IoError { .. } => "IoError",
            ConfigError::WatchError { .. } => "WatchError",
        })
    );
}

#[tokio::test]
async fn last_error_records_reload_failure() {
    // Corrupted reload (invalid YAML) must be observable via last_error() — no more
    // silent drops.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &minimal_yaml());

    let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
    assert!(
        watcher.last_error().is_none(),
        "initial last_error should be None"
    );

    // Write invalid YAML to trigger a parse failure on reload.
    tokio::time::sleep(Duration::from_millis(100)).await;
    replace_config_atomically(&config_path, "invalid: yaml: [[[");

    // Poll last_error until it's populated (bounded wait).
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if watcher.last_error().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let err = watcher.last_error();
    assert!(
        err.is_some(),
        "last_error should be populated after parse failure"
    );
    assert!(
        err.as_deref().unwrap().contains("parse") || err.as_deref().unwrap().contains("yaml"),
        "last_error should mention parse/yaml: {err:?}"
    );
}

#[test]
fn validate_rejects_duplicate_llm_provider_id() {
    let yaml = CANONICAL_YAML.replace("  - id: openai", "  - id: anthropic\n    ");
    // The replacement creates two providers both with id "anthropic" → should reject.
    let result: Result<RuntimeConfig, serde_yml::Error> = serde_yml::from_str(&yaml);
    // serde_yml parses OK; validation happens in load_config. Test via load_config
    // on a file containing duplicate IDs.
    if result.is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &yaml);
        let err = load_config(&config_path).expect_err("expected validation error");
        assert!(
            matches!(err, ConfigError::IoError { .. }),
            "expected IoError for duplicate provider id, got: {err}"
        );
        assert!(
            err.to_string().contains("duplicate") || err.to_string().contains("provider"),
            "error should mention duplicate or provider: {err}"
        );
    }
}

#[test]
fn validate_rejects_nan_jitter_ratio() {
    let yaml = minimal_yaml().replace("max_jitter_ratio: 0.05", "max_jitter_ratio: .nan");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected NaN validation error");
    assert!(matches!(err, ConfigError::IoError { .. }));
    assert!(err.to_string().contains("jitter"), "error: {err}");
}

#[test]
fn validate_rejects_bogus_env_var_name() {
    let yaml = minimal_yaml().replace("env-var-name: MY_KEY", "env-var-name: lowercase-bad");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected env-var-name validation error");
    assert!(err.to_string().contains("env-var-name"), "error: {err}");
}

#[test]
fn validate_rejects_http_endpoint_non_localhost() {
    let yaml = CANONICAL_YAML.replace("https://api.anthropic.com", "http://evil.example");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected https-only rejection");
    assert!(err.to_string().contains("https://"), "error: {err}");
}

#[test]
fn validate_accepts_http_localhost() {
    // Build a minimal config with a single provider at http://localhost.
    let yaml = format!(
        "{}\n{}",
        minimal_yaml().trim_end_matches('\n').replace(
            "llm-providers: []",
            "llm-providers:\n\
             - id: local\n  \
               endpoint: http://localhost:8080\n  \
               api-key-secret: local-key\n  \
               model-aliases:\n    \
                 m: local-model\n  \
               cost-per-mtoken-in: 1.0\n  \
               cost-per-mtoken-out: 2.0\n  \
               rate-limit:\n    \
                 requests-per-minute: 100\n    \
                 tokens-per-minute: 10000",
        ),
        ""
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let cfg = load_config(&config_path).expect("localhost http should be allowed");
    assert_eq!(cfg.llm_providers[0].endpoint, "http://localhost:8080");
}

#[test]
fn validate_rejects_missing_rate_limit() {
    // The canonical YAML has OpenAI provider without rate-limit. Under the new
    // stricter validation this must be rejected.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, CANONICAL_YAML);
    let err = load_config(&config_path).expect_err("expected rate-limit-required rejection");
    assert!(
        err.to_string().contains("rate-limit"),
        "error should mention rate-limit: {err}"
    );
}

#[test]
fn validate_rejects_yaml_alias_bomb() {
    // Billion-laughs-style YAML — well under 64 KiB but has many aliases.
    let mut bomb = String::from(
        "wasm:\n  max_memory_pages: 1024\n  epoch_interruption_ms: 100\n  fuel_enabled: false\n",
    );
    // 70 alias references will exceed MAX_YAML_ANCHORS_AND_ALIASES (64).
    bomb.push_str("alias-stress: &a [");
    for i in 0..70 {
        if i > 0 {
            bomb.push_str(", ");
        }
        bomb.push_str("*a");
    }
    bomb.push_str("]\n");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &bomb);
    let err = load_config(&config_path).expect_err("expected alias-bomb rejection");
    assert!(
        err.to_string().contains("anchors") || err.to_string().contains("aliases"),
        "error should mention anchors/aliases: {err}"
    );
}

#[test]
fn validate_rejects_localhost_prefix_bypass() {
    // "http://localhost.evil.example" must be rejected — R15 found that
    // starts_with("http://localhost") was a bypass to external hosts.
    let yaml = CANONICAL_YAML.replace("https://api.anthropic.com", "http://localhost.evil.example");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected localhost-prefix-bypass rejection");
    assert!(
        err.to_string().contains("https://") || err.to_string().contains("localhost"),
        "error: {err}"
    );
}

#[test]
fn validate_rejects_localhost_userinfo_bypass() {
    // `http://localhost@evil.example` has userinfo=localhost, host=evil.example.
    // My R15 fix split on `@` as a host terminator — that was wrong. Must reject.
    let yaml = CANONICAL_YAML.replace("https://api.anthropic.com", "http://localhost@evil.example");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected userinfo-bypass rejection");
    assert!(
        err.to_string().contains("https://") || err.to_string().contains("localhost"),
        "error: {err}"
    );
}

#[test]
fn validate_rejects_reserved_env_var_name() {
    let yaml = minimal_yaml().replace("env-var-name: MY_KEY", "env-var-name: PATH");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected reserved-name rejection");
    assert!(err.to_string().contains("reserved"), "error: {err}");
}

#[test]
fn debug_redacts_api_key_secret() {
    let config: RuntimeConfig = serde_yml::from_str(CANONICAL_YAML).unwrap();
    let debug_str = format!("{:?}", config.llm_providers[0]);
    assert!(
        debug_str.contains("<REDACTED>"),
        "Debug output should redact api_key_secret: {debug_str}"
    );
    assert!(
        !debug_str.contains("anthropic-api-key"),
        "Debug output must not leak api_key_secret value: {debug_str}"
    );
}

#[tokio::test]
async fn hot_reload_latency_under_1s() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &minimal_yaml());

    let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
    let mut rx = watcher.subscribe();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let modified = minimal_yaml().replace("max_memory_pages: 512", "max_memory_pages: 9999");
    let start = Instant::now();
    write_config(&config_path, &modified);

    let _new_config = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timeout waiting for latency test")
        .expect("channel closed");

    let elapsed = start.elapsed();
    // §1.6 NFR target: < 1 second. Use 3s tolerance for CI/loaded machines.
    assert!(
        elapsed < Duration::from_secs(3),
        "hot reload took {elapsed:?}, expected < 3s"
    );
}

// -----------------------------------------------------------------------
// MODULE-009 Slice B-1 — LlmProviderConfig.retry-default tests (T39-T48)
// -----------------------------------------------------------------------

/// Build a single-provider YAML containing the supplied retry-default block.
/// `retry_block` is rendered verbatim (e.g. an empty string omits the block).
fn yaml_with_retry_default(retry_block: &str) -> String {
    let mut s = String::new();
    s.push_str("wasm:\n");
    s.push_str("  max_memory_pages: 512\n");
    s.push_str("  epoch_interruption_ms: 50\n");
    s.push_str("  fuel_enabled: true\n");
    s.push_str("llm-providers:\n");
    s.push_str("  - id: anthropic\n");
    s.push_str("    endpoint: https://api.anthropic.com\n");
    s.push_str("    api-key-secret: anthropic-api-key\n");
    s.push_str("    model-aliases:\n");
    s.push_str("      sonnet: claude-sonnet-4-5\n");
    s.push_str("    cost-per-mtoken-in: 3.0\n");
    s.push_str("    cost-per-mtoken-out: 15.0\n");
    s.push_str("    rate-limit:\n");
    s.push_str("      requests-per-minute: 1000\n");
    s.push_str("      tokens-per-minute: 400000\n");
    s.push_str(retry_block);
    s.push_str("cron:\n  max_jitter_ratio: 0.05\n");
    s.push_str("git:\n  gc_interval_hours: 12\n  max_tracked_file_mb: 5\n");
    s.push_str("circuit-breakers: []\n");
    s.push_str("secrets:\n  master-key-source: env-var\n  env-var-name: MY_KEY\n");
    s.push_str("users: []\n");
    s.push_str("post-processor:\n  llm-model: fast\n  llm-failure-cooldown-seconds: 300\n");
    s
}

#[test]
fn t_llm_provider_config_parses_retry_default() {
    // T39: YAML with retry-default block populated → field is Some(...)
    let yaml = yaml_with_retry_default(
        "    retry-default:\n      max-retries: 3\n      base-delay-ms: 1000\n      max-delay-ms: 30000\n",
    );
    let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("should parse");
    let rd = config.llm_providers[0]
        .retry_default
        .as_ref()
        .expect("retry_default should be Some");
    assert_eq!(rd.max_retries, 3);
    assert_eq!(rd.base_delay_ms, 1000);
    assert_eq!(rd.max_delay_ms, 30000);
}

#[test]
fn t_llm_provider_config_retry_default_optional() {
    // T40: YAML without retry-default block → field is None
    let yaml = yaml_with_retry_default("");
    let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("should parse");
    assert!(config.llm_providers[0].retry_default.is_none());
}

#[test]
fn t_llm_provider_config_retry_default_unknown_subkey_rejected() {
    // T41: deny_unknown_fields on RetryDefaults rejects unknown subkeys.
    let yaml = yaml_with_retry_default(
        "    retry-default:\n      max-retries: 3\n      base-delay-ms: 1000\n      max-delay-ms: 30000\n      unknown-knob: 1\n",
    );
    let result: Result<RuntimeConfig, _> = serde_yml::from_str(&yaml);
    assert!(
        result.is_err(),
        "expected deny_unknown_fields rejection, got: {result:?}"
    );
}

// -----------------------------------------------------------------------
// Wave-6 Lane C (2026-06-21) — `channels.notify` config block (SYS-AC-257 seam).
// -----------------------------------------------------------------------

/// `minimal_yaml()` + a `channels:` block carrying a `notify:` sub-block.
fn yaml_with_notify(notify_block: &str) -> String {
    format!("{}\nchannels:\n{notify_block}", minimal_yaml())
}

#[test]
fn t_channels_notify_block_parses() {
    let yaml = yaml_with_notify(
        "  notify:\n    adapter: telegram\n    url-template: \"https://api.telegram.org/bot123/sendMessage\"\n    conversation-id: \"98765\"\n    reply-address:\n      - {key: chat_id, value: \"98765\"}\n",
    );
    let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("notify block should parse");
    let notify = config
        .channels
        .notify
        .as_ref()
        .expect("channels.notify should be Some");
    assert_eq!(notify.adapter, "telegram");
    assert_eq!(
        notify.url_template,
        "https://api.telegram.org/bot123/sendMessage"
    );
    assert_eq!(notify.conversation_id, "98765");
    assert_eq!(notify.reply_address.len(), 1);
    assert_eq!(notify.reply_address[0].key, "chat_id");
    assert_eq!(notify.reply_address[0].value, "98765");
}

#[test]
fn t_channels_notify_absent_is_none() {
    // No `channels:` block at all → ChannelsConfig::default() → notify None (back-compat).
    let config: RuntimeConfig = serde_yml::from_str(&minimal_yaml()).expect("parses");
    assert!(
        config.channels.notify.is_none(),
        "absent notify block → None"
    );
    // A `channels:` block with no `notify:` key also yields None (serde default).
    let yaml = yaml_with_notify("  webhook-listen-addr: \"127.0.0.1:8080\"\n  channels: []\n");
    let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("parses");
    assert!(
        config.channels.notify.is_none(),
        "notify-less channels block → None"
    );
}

#[test]
fn t_notify_channel_config_debug_redacts_url_template() {
    // The url_template carries the bot token → must be redacted in Debug, like ChannelEntry.
    let yaml = yaml_with_notify(
        "  notify:\n    adapter: telegram\n    url-template: \"https://api.telegram.org/botSECRET123/sendMessage\"\n    conversation-id: \"42\"\n",
    );
    let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("parses");
    let dbg = format!("{:?}", config.channels.notify.as_ref().unwrap());
    assert!(
        !dbg.contains("SECRET123"),
        "url_template credential must be redacted: {dbg}"
    );
    assert!(
        dbg.contains("redacted"),
        "Debug should mark the redaction: {dbg}"
    );
    // Non-credential fields stay visible.
    assert!(dbg.contains("telegram") && dbg.contains("42"), "{dbg}");
}

#[test]
fn t_channels_notify_unknown_subkey_rejected() {
    // deny_unknown_fields on NotifyChannelConfig rejects unknown subkeys.
    let yaml = yaml_with_notify(
        "  notify:\n    adapter: telegram\n    url-template: \"https://x/y\"\n    conversation-id: \"1\"\n    bogus-knob: 1\n",
    );
    let result: Result<RuntimeConfig, _> = serde_yml::from_str(&yaml);
    assert!(
        result.is_err(),
        "expected deny_unknown_fields rejection, got: {result:?}"
    );
}

#[test]
fn t_llm_provider_config_retry_default_partial_subkey_rejected() {
    // T47: Missing required subfield (no per-field defaults) → parse error.
    let yaml = yaml_with_retry_default("    retry-default:\n      max-retries: 3\n");
    let result: Result<RuntimeConfig, _> = serde_yml::from_str(&yaml);
    assert!(
        result.is_err(),
        "expected missing-field rejection for partial retry-default, got: {result:?}"
    );
}

#[test]
fn t_llm_provider_config_debug_includes_retry_default() {
    // T48: Debug impl exposes retry_default field name.
    let yaml = yaml_with_retry_default(
        "    retry-default:\n      max-retries: 3\n      base-delay-ms: 1000\n      max-delay-ms: 30000\n",
    );
    let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("should parse");
    let debug_str = format!("{:?}", config.llm_providers[0]);
    assert!(
        debug_str.contains("retry_default"),
        "Debug must include retry_default field: {debug_str}"
    );
    assert!(
        debug_str.contains("Some"),
        "Debug must show Some(...) for populated retry_default: {debug_str}"
    );
}

#[test]
fn t_validate_config_retry_default_max_retries_too_high() {
    // T42: max_retries = 101 → validate rejects.
    let yaml = yaml_with_retry_default(
        "    retry-default:\n      max-retries: 101\n      base-delay-ms: 1000\n      max-delay-ms: 30000\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected max-retries upper bound rejection");
    assert!(err.to_string().contains("max-retries"), "error: {err}");
}

#[test]
fn t_validate_config_retry_default_max_retries_zero() {
    // T43: max_retries = 0 with retry-default present → validate rejects (omit block instead).
    let yaml = yaml_with_retry_default(
        "    retry-default:\n      max-retries: 0\n      base-delay-ms: 1000\n      max-delay-ms: 30000\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected max-retries=0 rejection");
    assert!(err.to_string().contains("max-retries"), "error: {err}");
}

#[test]
fn t_validate_config_retry_default_zero_base_delay() {
    // T44: base_delay_ms = 0 → validate rejects (would defeat backoff → tight retry storm).
    let yaml = yaml_with_retry_default(
        "    retry-default:\n      max-retries: 3\n      base-delay-ms: 0\n      max-delay-ms: 30000\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected zero-base-delay rejection");
    assert!(err.to_string().contains("base-delay-ms"), "error: {err}");
}

#[test]
fn t_validate_config_retry_default_inverted_delays() {
    // T45: base_delay_ms > max_delay_ms → validate rejects.
    let yaml = yaml_with_retry_default(
        "    retry-default:\n      max-retries: 3\n      base-delay-ms: 60000\n      max-delay-ms: 30000\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected base>max rejection");
    assert!(err.to_string().contains("base-delay-ms"), "error: {err}");
}

#[test]
fn t_validate_config_retry_default_max_delay_excessive() {
    // T46: max_delay_ms = 700_000 (> 10 min) → validate rejects.
    let yaml = yaml_with_retry_default(
        "    retry-default:\n      max-retries: 3\n      base-delay-ms: 1000\n      max-delay-ms: 700000\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("expected max-delay-ms upper bound rejection");
    assert!(err.to_string().contains("max-delay-ms"), "error: {err}");
}

// ───────────────────────────────────────────────────────────────────────────
// Slice AE (2026-05-09) — DatabaseConfig validation + defaults
// ───────────────────────────────────────────────────────────────────────────

/// Build a minimal valid runtime-config.yaml; if `database_block` is non-empty,
/// append it (otherwise the `database:` section is omitted to exercise the
/// `#[serde(default)]` path).
fn yaml_with_database_block(database_block: &str) -> String {
    let mut s = String::new();
    s.push_str("wasm:\n");
    s.push_str("  max_memory_pages: 512\n");
    s.push_str("  epoch_interruption_ms: 50\n");
    s.push_str("  fuel_enabled: true\n");
    s.push_str("llm-providers:\n");
    s.push_str("  - id: anthropic\n");
    s.push_str("    endpoint: https://api.anthropic.com\n");
    s.push_str("    api-key-secret: anthropic-api-key\n");
    s.push_str("    model-aliases:\n");
    s.push_str("      sonnet: claude-sonnet-4-5\n");
    s.push_str("    cost-per-mtoken-in: 3.0\n");
    s.push_str("    cost-per-mtoken-out: 15.0\n");
    s.push_str("    rate-limit:\n");
    s.push_str("      requests-per-minute: 1000\n");
    s.push_str("      tokens-per-minute: 400000\n");
    s.push_str("cron:\n  max_jitter_ratio: 0.05\n");
    s.push_str("git:\n  gc_interval_hours: 12\n  max_tracked_file_mb: 5\n");
    s.push_str("circuit-breakers: []\n");
    s.push_str("secrets:\n  master-key-source: env-var\n  env-var-name: MY_KEY\n");
    s.push_str("users: []\n");
    s.push_str("post-processor:\n  llm-model: fast\n  llm-failure-cooldown-seconds: 300\n");
    s.push_str(database_block);
    s
}

#[test]
fn t69_database_field_defaults_when_block_omitted() {
    // T69: YAML omitting `database:` block → DatabaseConfig::default() applies.
    let yaml = yaml_with_database_block("");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let cfg = load_config(&config_path).expect("default database block should parse");
    assert_eq!(cfg.database.db_path, ".runtime/index.db");
    assert_eq!(cfg.database.pool_size, 4);
}

#[test]
fn t67a_database_pool_size_zero_rejected() {
    let yaml =
        yaml_with_database_block("database:\n  db-path: \".runtime/index.db\"\n  pool-size: 0\n");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("pool-size 0 must be rejected");
    assert!(err.to_string().contains("pool-size"), "error: {err}");
}

#[test]
fn t67b_database_db_path_empty_rejected() {
    let yaml = yaml_with_database_block("database:\n  db-path: \"\"\n  pool-size: 4\n");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("empty db-path must be rejected");
    assert!(err.to_string().contains("database.db-path"), "error: {err}");
}

#[test]
fn t67c_database_db_path_nul_byte_rejected() {
    // NUL byte cannot appear in a valid filesystem path; `check_nonempty` rejects it.
    let yaml = yaml_with_database_block("database:\n  db-path: \"a\\u0000b\"\n  pool-size: 4\n");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("NUL in db-path must be rejected");
    assert!(err.to_string().contains("database.db-path"), "error: {err}");
}

#[test]
fn t67d_database_pool_size_above_cap_rejected() {
    // Slice-AE policy ceiling: 256.
    let yaml =
        yaml_with_database_block("database:\n  db-path: \".runtime/index.db\"\n  pool-size: 257\n");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("pool-size 257 must be rejected");
    assert!(err.to_string().contains("pool-size"), "error: {err}");
}

#[test]
fn t_adv_w2a_database_db_path_absolute_rejected() {
    // Adversarial R1 W2: tampered config with absolute db-path must be
    // rejected at validate_config time so the bootstrap layer never opens
    // SQLite at an attacker-chosen filesystem location.
    let yaml = yaml_with_database_block("database:\n  db-path: \"/etc/passwd\"\n  pool-size: 4\n");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("absolute db-path must be rejected");
    assert!(err.to_string().contains("db-path"), "error: {err}");
    assert!(
        err.to_string().contains("relative") || err.to_string().contains("absolute"),
        "error: {err}"
    );
}

#[test]
fn t_adv_w2b_database_db_path_traversal_rejected() {
    // Adversarial R1 W2: `..` segments must be rejected.
    let yaml =
        yaml_with_database_block("database:\n  db-path: \"../../etc/index.db\"\n  pool-size: 4\n");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("`..` segment must be rejected");
    assert!(err.to_string().contains(".."), "error: {err}");
}

#[test]
fn t69b_database_explicit_block_round_trip() {
    // Explicit non-default values round-trip through parse + validate.
    let yaml = yaml_with_database_block("database:\n  db-path: \"my.db\"\n  pool-size: 16\n");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let cfg = load_config(&config_path).expect("explicit database block should parse");
    assert_eq!(cfg.database.db_path, "my.db");
    assert_eq!(cfg.database.pool_size, 16);
    // Slice G: omitting `wal-mode` / `embedding-dim` / `recall-max-depth`
    // within a present `database:` block falls back to per-field defaults.
    assert!(cfg.database.wal_mode);
    assert_eq!(cfg.database.embedding_dim, 768);
    assert_eq!(cfg.database.recall_max_depth, 3);
}

// =============================================================================
// Slice G (2026-05-09) — AC-19 hot-reload field validation tests
// =============================================================================

#[test]
fn slice_g_database_explicit_full_block_round_trip() {
    // All 5 database knobs explicit, non-default; all parse + validate.
    let yaml = yaml_with_database_block(
        "database:\n  \
         db-path: \"custom.db\"\n  \
         pool-size: 32\n  \
         wal-mode: false\n  \
         embedding-dim: 1024\n  \
         recall-max-depth: 7\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let cfg = load_config(&config_path).expect("full database block should parse");
    assert_eq!(cfg.database.db_path, "custom.db");
    assert_eq!(cfg.database.pool_size, 32);
    assert!(!cfg.database.wal_mode);
    assert_eq!(cfg.database.embedding_dim, 1024);
    assert_eq!(cfg.database.recall_max_depth, 7);
}

#[test]
fn slice_g_database_embedding_dim_zero_rejected() {
    let yaml = yaml_with_database_block(
        "database:\n  db-path: \".runtime/index.db\"\n  pool-size: 4\n  embedding-dim: 0\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("embedding-dim 0 must be rejected");
    assert!(err.to_string().contains("embedding-dim"), "error: {err}");
}

#[test]
fn slice_g_database_embedding_dim_above_cap_rejected() {
    let yaml = yaml_with_database_block(
        "database:\n  db-path: \".runtime/index.db\"\n  pool-size: 4\n  embedding-dim: 8193\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("embedding-dim 8193 must be rejected");
    assert!(err.to_string().contains("embedding-dim"), "error: {err}");
}

#[test]
fn slice_g_database_recall_max_depth_zero_rejected() {
    let yaml = yaml_with_database_block(
        "database:\n  db-path: \".runtime/index.db\"\n  pool-size: 4\n  recall-max-depth: 0\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("recall-max-depth 0 must be rejected");
    assert!(err.to_string().contains("recall-max-depth"), "error: {err}");
}

#[test]
fn slice_g_database_recall_max_depth_above_cap_rejected() {
    let yaml = yaml_with_database_block(
        "database:\n  db-path: \".runtime/index.db\"\n  pool-size: 4\n  recall-max-depth: 11\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("recall-max-depth 11 must be rejected");
    assert!(err.to_string().contains("recall-max-depth"), "error: {err}");
}

// ─────────────────────────────────────────────────────────────────────
// Slice m017-B (2026-05-14) — ToolsConfig validate_config arms.
// Six reject paths added in audit round 1 of /dev m017-slice-b. These
// tests guard the round-1 fix against future regression — a refactor
// dropping any of the bound checks would surface here.
// ─────────────────────────────────────────────────────────────────────

/// Build a minimal valid runtime-config.yaml; append the given `tools:`
/// block if non-empty (otherwise tools block is omitted to exercise
/// `#[serde(default)]`).
fn yaml_with_tools_block(tools_block: &str) -> String {
    let mut s = yaml_with_database_block("");
    s.push_str(tools_block);
    s
}

#[test]
fn slice_m017b_tools_default_when_block_omitted() {
    let yaml = yaml_with_tools_block("");
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let cfg = load_config(&config_path).expect("omitted tools block must default");
    assert_eq!(cfg.tools.max_tool_instances, 20);
    assert_eq!(cfg.tools.lazy_load_timeout_sec, 30);
    assert_eq!(cfg.tools.max_result_bytes, 16 * 1024 * 1024);
}

#[test]
fn slice_m017b_tools_max_tool_instances_zero_rejected() {
    let yaml = yaml_with_tools_block(
        "tools:\n  max-tool-instances: 0\n  lazy-load-timeout-sec: 30\n  max-result-bytes: 16777216\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("max-tool-instances 0 must be rejected");
    assert!(
        err.to_string().contains("max-tool-instances"),
        "error: {err}"
    );
}

#[test]
fn slice_m017b_tools_max_tool_instances_above_cap_rejected() {
    let yaml = yaml_with_tools_block(
        "tools:\n  max-tool-instances: 1025\n  lazy-load-timeout-sec: 30\n  max-result-bytes: 16777216\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("max-tool-instances 1025 must be rejected");
    assert!(
        err.to_string().contains("max-tool-instances"),
        "error: {err}"
    );
}

#[test]
fn slice_m017b_tools_lazy_load_timeout_zero_rejected() {
    let yaml = yaml_with_tools_block(
        "tools:\n  max-tool-instances: 20\n  lazy-load-timeout-sec: 0\n  max-result-bytes: 16777216\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("lazy-load-timeout-sec 0 must be rejected");
    assert!(
        err.to_string().contains("lazy-load-timeout-sec"),
        "error: {err}"
    );
}

#[test]
fn slice_m017b_tools_lazy_load_timeout_above_cap_rejected() {
    let yaml = yaml_with_tools_block(
        "tools:\n  max-tool-instances: 20\n  lazy-load-timeout-sec: 601\n  max-result-bytes: 16777216\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("lazy-load-timeout-sec 601 must be rejected");
    assert!(
        err.to_string().contains("lazy-load-timeout-sec"),
        "error: {err}"
    );
}

#[test]
fn slice_m017b_tools_max_result_bytes_zero_rejected() {
    let yaml = yaml_with_tools_block(
        "tools:\n  max-tool-instances: 20\n  lazy-load-timeout-sec: 30\n  max-result-bytes: 0\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("max-result-bytes 0 must be rejected");
    assert!(err.to_string().contains("max-result-bytes"), "error: {err}");
}

#[test]
fn slice_m017b_tools_max_result_bytes_above_cap_rejected() {
    // 1 GiB + 1 byte
    let yaml = yaml_with_tools_block(
        "tools:\n  max-tool-instances: 20\n  lazy-load-timeout-sec: 30\n  max-result-bytes: 1073741825\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("max-result-bytes > 1 GiB must be rejected");
    assert!(err.to_string().contains("max-result-bytes"), "error: {err}");
}

#[test]
fn slice_m017b_tools_yaml_kebab_keys_accepted() {
    // Round-2 audit fix — doc claimed snake_case originally; the wire
    // format is kebab-case per #[serde(rename)]. This test locks the
    // contract: a YAML config with kebab-case keys parses successfully.
    let yaml = yaml_with_tools_block(
        "tools:\n  max-tool-instances: 42\n  lazy-load-timeout-sec: 60\n  max-result-bytes: 8388608\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let cfg = load_config(&config_path).expect("kebab-case keys must parse");
    assert_eq!(cfg.tools.max_tool_instances, 42);
    assert_eq!(cfg.tools.lazy_load_timeout_sec, 60);
    assert_eq!(cfg.tools.max_result_bytes, 8 * 1024 * 1024);
}

// -----------------------------------------------------------------------
// Hotreload pre-build (2026-06-10): runtime.config_reloaded emission seam
// (HR-R1..HR-R11 from the plan's test design; traces to REQ-352 and the
// future harness witnesses SYS-AC-153/154/237 — no AC/SYS-AC flips here).
// -----------------------------------------------------------------------

mod config_reload_emission {
    use super::*;
    use advance_shared_types::event::Event as BusEvent;
    use advance_shared_types::traits::EventBusEmit;
    use std::sync::{Arc, Mutex};

    /// Minimal recording sink (the `trigger_emit.rs` RecordingBus precedent).
    /// Stores whole events; accessors clone only the cheap projections so the
    /// shared-types `Event` does not need `Clone`.
    #[derive(Default)]
    struct RecordingBus {
        events: Mutex<Vec<BusEvent>>,
    }

    impl RecordingBus {
        fn len(&self) -> usize {
            self.events.lock().unwrap().len()
        }
        fn event_type_at(&self, i: usize) -> String {
            self.events.lock().unwrap()[i].event_type.clone()
        }
        fn agent_id_at(&self, i: usize) -> String {
            self.events.lock().unwrap()[i].agent_id.clone()
        }
        fn payload_at(&self, i: usize) -> serde_json::Value {
            self.events.lock().unwrap()[i].payload.clone()
        }
    }

    impl EventBusEmit for RecordingBus {
        fn emit(&self, event: BusEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    /// Emitter that always panics — the hostile/buggy implementer HR-R7 models.
    struct PanickingBus;
    impl EventBusEmit for PanickingBus {
        fn emit(&self, _event: BusEvent) {
            panic!("hostile emitter panic");
        }
    }

    /// Poll until the recorder holds at least `n` events or the deadline
    /// passes (3 s — the same CI tolerance as `hot_reload_latency_under_1s`;
    /// the <1 s SLO witness belongs to the future harness slice).
    async fn wait_for_events(bus: &RecordingBus, n: usize, deadline: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if bus.len() >= n {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        bus.len() >= n
    }

    async fn wait_for_last_error(watcher: &RuntimeConfigWatcher, deadline: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if watcher.last_error().is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        watcher.last_error().is_some()
    }

    fn parsed_minimal() -> RuntimeConfig {
        serde_yml::from_str(&minimal_yaml()).expect("minimal yaml parses")
    }

    // HR-R1: single-section diffs detected; identical configs → empty.
    #[test]
    fn sections_changed_detects_single_section_edits() {
        let base = parsed_minimal();

        let mut cron_edit = parsed_minimal();
        cron_edit.cron.max_jitter_ratio = 0.42;
        assert_eq!(config_sections_changed(&base, &cron_edit), vec!["cron"]);

        let mut db_edit = parsed_minimal();
        db_edit.database.pool_size = 9;
        assert_eq!(config_sections_changed(&base, &db_edit), vec!["database"]);

        let mut llm_edit = parsed_minimal();
        llm_edit.llm_providers = serde_yml::from_str(
            r#"
- id: anthropic
  endpoint: https://api.anthropic.com
  api-key-secret: anthropic-api-key
  model-aliases:
    sonnet: claude-sonnet-4-5
  cost-per-mtoken-in: 3.0
  cost-per-mtoken-out: 15.0
  rate-limit:
    requests-per-minute: 10
    tokens-per-minute: 1000
"#,
        )
        .expect("provider list parses");
        assert_eq!(
            config_sections_changed(&base, &llm_edit),
            vec!["llm-providers"]
        );

        assert!(config_sections_changed(&base, &parsed_minimal()).is_empty());
    }

    #[test]
    fn cfg_01_absent_web_defaults_standard() {
        // MODULE-017-CFG-01
        let base = parsed_minimal();
        assert_eq!(base.web, WebConfig::default());
        assert_eq!(
            base.web.mode,
            advance_shared_types::web_search::WebRunMode::Standard
        );
        let mut edit = parsed_minimal();
        edit.web.mode = advance_shared_types::web_search::WebRunMode::Offline;
        assert_eq!(config_sections_changed(&base, &edit), vec!["web"]);
    }

    // HR-R2: multi-section edit → both names, deterministic declaration order.
    #[test]
    fn sections_changed_reports_multi_section_edits_in_order() {
        let base = parsed_minimal();
        let mut edit = parsed_minimal();
        edit.cron.max_jitter_ratio = 0.33;
        edit.git.gc_interval_hours = 99;
        edit.database.pool_size = 11;
        assert_eq!(
            config_sections_changed(&base, &edit),
            vec!["cron", "git", "database"]
        );
    }

    // HR-R3: one applied reload → exactly one event, correct type/agent/payload.
    #[tokio::test]
    async fn emits_config_reloaded_with_sections_changed() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        let bus = Arc::new(RecordingBus::default());
        watcher.set_event_emitter(bus.clone());
        let mut rx = watcher.subscribe();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let modified = minimal_yaml().replace("max_jitter_ratio: 0.05", "max_jitter_ratio: 0.25");
        write_config(&config_path, &modified);

        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout waiting for reload")
            .expect("channel closed");
        assert!(
            wait_for_events(&bus, 1, Duration::from_secs(3)).await,
            "no runtime.config_reloaded observed within the 3s CI tolerance"
        );
        assert_eq!(bus.len(), 1, "exactly one event per applied reload");
        assert_eq!(bus.event_type_at(0), RUNTIME_CONFIG_RELOADED_EVENT_TYPE);
        assert_eq!(bus.agent_id_at(0), "runtime");
        assert_eq!(
            bus.payload_at(0)["sections_changed"],
            serde_json::json!(["cron"])
        );
    }

    // HR-R4: emission latency within the 3 s CI tolerance of the file write
    // (precedent: hot_reload_latency_under_1s asserts <3 s for the apply leg).
    #[tokio::test]
    async fn emission_observed_within_ci_tolerance() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        let bus = Arc::new(RecordingBus::default());
        watcher.set_event_emitter(bus.clone());

        tokio::time::sleep(Duration::from_millis(100)).await;
        let start = Instant::now();
        let modified = minimal_yaml().replace("gc_interval_hours: 12", "gc_interval_hours: 13");
        write_config(&config_path, &modified);

        assert!(
            wait_for_events(&bus, 1, Duration::from_secs(3)).await,
            "event not observed within 3s of the file write"
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "emission latency {:?} exceeded the 3s CI tolerance",
            start.elapsed()
        );
        assert_eq!(
            bus.payload_at(0)["sections_changed"],
            serde_json::json!(["git"])
        );
    }

    // HR-R5: invalid YAML → NO event, last_error set, old config retained;
    // a subsequent valid write resumes emission.
    #[tokio::test]
    async fn invalid_config_emits_nothing_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        let bus = Arc::new(RecordingBus::default());
        watcher.set_event_emitter(bus.clone());
        let original = watcher.current();

        tokio::time::sleep(Duration::from_millis(100)).await;
        replace_config_atomically(&config_path, "invalid: yaml: [[[");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) && watcher.last_error().is_none() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert_eq!(bus.len(), 0, "fail-closed rejection must not emit");
        assert!(
            wait_for_last_error(&watcher, Duration::from_secs(3)).await,
            "rejection must be recorded"
        );
        assert_eq!(*watcher.current(), *original, "old config must stay live");

        let modified = minimal_yaml().replace("max_jitter_ratio: 0.05", "max_jitter_ratio: 0.15");
        replace_config_atomically(&config_path, &modified);
        assert!(
            wait_for_events(&bus, 1, Duration::from_secs(3)).await,
            "valid write after rejection must resume emission"
        );
        assert_eq!(
            bus.payload_at(0)["sections_changed"],
            serde_json::json!(["cron"])
        );
    }

    // HR-R6: rewriting identical content → no event (value-dedup path).
    #[tokio::test]
    async fn identical_rewrite_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        let bus = Arc::new(RecordingBus::default());
        watcher.set_event_emitter(bus.clone());

        tokio::time::sleep(Duration::from_millis(100)).await;
        write_config(&config_path, &minimal_yaml());
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert_eq!(bus.len(), 0, "equal-value rewrite must not emit");
    }

    // HR-R7: panicking emitter → reload still applies, bridge survives
    // (subsequent reload works), last_error records the panic.
    #[tokio::test]
    async fn panicking_emitter_does_not_kill_the_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        watcher.set_event_emitter(Arc::new(PanickingBus));
        let mut rx = watcher.subscribe();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let modified = minimal_yaml().replace("max_memory_pages: 512", "max_memory_pages: 1024");
        write_config(&config_path, &modified);

        let applied = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout: reload did not apply with a panicking emitter")
            .expect("channel closed");
        assert_eq!(applied.wasm.max_memory_pages, 1024);

        let start = Instant::now();
        loop {
            if watcher
                .last_error()
                .map(|e| e.contains("panicked"))
                .unwrap_or(false)
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "emitter panic was not recorded in last_error; got {:?}",
                watcher.last_error()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Bridge survival witness: a SECOND reload still applies.
        let modified2 = modified.replace("max_memory_pages: 1024", "max_memory_pages: 2048");
        write_config(&config_path, &modified2);
        let applied2 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout: bridge died after emitter panic")
            .expect("channel closed");
        assert_eq!(applied2.wasm.max_memory_pages, 2048);
    }

    // HR-R8: no emitter set → reloads behave exactly as before this slice.
    #[tokio::test]
    async fn no_emitter_reloads_unaffected() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        let mut rx = watcher.subscribe();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let modified = minimal_yaml().replace("max_memory_pages: 512", "max_memory_pages: 768");
        write_config(&config_path, &modified);

        let applied = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(applied.wasm.max_memory_pages, 768);
    }

    // HR-R9: two sequential edits → two events with STEP-LOCAL diffs (the
    // second payload names only the second delta, not the cumulative set).
    #[tokio::test]
    async fn sequential_reloads_emit_step_local_diffs() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        let bus = Arc::new(RecordingBus::default());
        watcher.set_event_emitter(bus.clone());
        let mut rx = watcher.subscribe();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let first = minimal_yaml().replace("max_jitter_ratio: 0.05", "max_jitter_ratio: 0.30");
        write_config(&config_path, &first);
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout on first reload")
            .expect("closed");
        assert!(wait_for_events(&bus, 1, Duration::from_secs(3)).await);

        let second = first.replace("gc_interval_hours: 12", "gc_interval_hours: 48");
        write_config(&config_path, &second);
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout on second reload")
            .expect("closed");
        assert!(wait_for_events(&bus, 2, Duration::from_secs(3)).await);

        assert_eq!(bus.len(), 2);
        assert_eq!(
            bus.payload_at(0)["sections_changed"],
            serde_json::json!(["cron"]),
            "first event must carry only the first delta"
        );
        assert_eq!(
            bus.payload_at(1)["sections_changed"],
            serde_json::json!(["git"]),
            "second event must be step-local (not cumulative)"
        );
        assert_eq!(bus.event_type_at(0), RUNTIME_CONFIG_RELOADED_EVENT_TYPE);
        assert_eq!(bus.event_type_at(1), RUNTIME_CONFIG_RELOADED_EVENT_TYPE);
        assert_eq!(bus.agent_id_at(1), "runtime");
    }

    // HR-R10: the emitter_live Drop-gate — events queued before drop must not
    // be published by the post-drop bridge drain. Deterministic on the
    // default current-thread #[tokio::test] flavor: the bridge task cannot
    // run between the queue-up and the drop (no await point), so no emit can
    // be in flight past the gate check. (A multi_thread flavor would make
    // this assertion racy — keep the default flavor.)
    #[tokio::test]
    async fn dropped_watcher_drain_does_not_emit() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        let bus = Arc::new(RecordingBus::default());
        watcher.set_event_emitter(bus.clone());

        // Queue a change WITHOUT yielding to the bridge: std::thread::sleep
        // blocks the current-thread runtime, so the notify thread enqueues
        // the fs event while the bridge task stays parked.
        let modified = minimal_yaml().replace("max_memory_pages: 512", "max_memory_pages: 1536");
        write_config(&config_path, &modified);
        std::thread::sleep(Duration::from_millis(300));

        drop(watcher); // gate closes before the bridge drains

        // Now let the bridge drain the queued event(s) and exit.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            bus.len(),
            0,
            "post-drop bridge drain must not publish phantom events"
        );
    }

    // HR-R11: emitter replacement — only the new emitter records after swap.
    #[tokio::test]
    async fn emitter_replacement_routes_to_new_sink() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &minimal_yaml());

        let watcher = RuntimeConfigWatcher::new(&config_path).await.unwrap();
        let bus1 = Arc::new(RecordingBus::default());
        let bus2 = Arc::new(RecordingBus::default());
        watcher.set_event_emitter(bus1.clone());
        let mut rx = watcher.subscribe();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let first = minimal_yaml().replace("max_jitter_ratio: 0.05", "max_jitter_ratio: 0.20");
        write_config(&config_path, &first);
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout on first reload")
            .expect("closed");
        assert!(wait_for_events(&bus1, 1, Duration::from_secs(3)).await);

        watcher.set_event_emitter(bus2.clone());

        let second = first.replace("gc_interval_hours: 12", "gc_interval_hours: 36");
        write_config(&config_path, &second);
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout on second reload")
            .expect("closed");
        assert!(wait_for_events(&bus2, 1, Duration::from_secs(3)).await);

        assert_eq!(bus1.len(), 1, "replaced emitter must stop receiving");
        assert_eq!(bus2.len(), 1, "new emitter must receive the second event");
        assert_eq!(
            bus2.payload_at(0)["sections_changed"],
            serde_json::json!(["git"])
        );
    }
}

#[test]
fn validate_accepts_mesh_remote_empty_endpoint() {
    let yaml = format!(
        "{}\n{}",
        minimal_yaml().trim_end_matches('\n').replace(
            "llm-providers: []",
            "llm-providers:\n  - id: mesh\n    endpoint: \"\"\n    api-key-secret: k\n    backend-class: mesh-remote\n    device-id: peer-b\n    model-aliases:\n      llama: llama\n    cost-per-mtoken-in: 0.001\n    cost-per-mtoken-out: 0.001\n    rate-limit:\n      requests-per-minute: 1\n      tokens-per-minute: 1"
        ),
        ""
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    load_config(&config_path).expect("mesh-remote empty endpoint must load");
}

#[test]
fn validate_rejects_mesh_remote_missing_device_id() {
    let yaml = format!(
        "{}\n",
        minimal_yaml().trim_end_matches('\n').replace(
            "llm-providers: []",
            "llm-providers:\n  - id: mesh\n    endpoint: \"\"\n    api-key-secret: k\n    backend-class: mesh-remote\n    model-aliases:\n      llama: llama\n    cost-per-mtoken-in: 0.001\n    cost-per-mtoken-out: 0.001\n    rate-limit:\n      requests-per-minute: 1\n      tokens-per-minute: 1"
        )
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("mesh-remote needs device-id");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("device-id") || err.to_string().contains("device-id"),
        "error: {err:?}"
    );
}

#[test]
fn validate_rejects_mesh_remote_whitespace_or_nul_device_id() {
    for device_id in [" ", "\t"] {
        let yaml = format!(
            "{}\n",
            minimal_yaml().trim_end_matches('\n').replace(
                "llm-providers: []",
                &format!(
                    "llm-providers:\n  - id: mesh\n    endpoint: \"\"\n    api-key-secret: k\n    backend-class: mesh-remote\n    device-id: \"{device_id}\"\n    model-aliases:\n      llama: llama\n    cost-per-mtoken-in: 0.001\n    cost-per-mtoken-out: 0.001\n    rate-limit:\n      requests-per-minute: 1\n      tokens-per-minute: 1"
                )
            )
        );
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &yaml);
        let err = load_config(&config_path).expect_err("mesh-remote device-id must be an identity");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("device-id") || err.to_string().contains("device-id"),
            "device_id={device_id:?} error: {err:?}"
        );
    }
}

#[test]
fn validate_rejects_backend_local_with_class_mesh_remote() {
    let yaml = format!(
        "{}\n",
        minimal_yaml().trim_end_matches('\n').replace(
            "llm-providers: []",
            "llm-providers:\n  - id: mesh\n    endpoint: \"\"\n    api-key-secret: k\n    backend: local\n    backend-class: mesh-remote\n    model-aliases:\n      llama: llama\n    cost-per-mtoken-in: 0.001\n    cost-per-mtoken-out: 0.001\n    rate-limit:\n      requests-per-minute: 1\n      tokens-per-minute: 1"
        )
    );
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("runtime-config.yaml");
    write_config(&config_path, &yaml);
    let err = load_config(&config_path).expect_err("clash");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("mesh-remote") || err.to_string().contains("parse"),
        "error: {err:?}"
    );
}

// -----------------------------------------------------------------------
// MODULE-001-T110 — CONTRACT-003 `genui:` (AC-29 claims `enabled` only)
// -----------------------------------------------------------------------

#[test]
fn genui_absent_block_defaults_off() {
    for yaml in [minimal_yaml(), CANONICAL_YAML.to_string()] {
        let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("parses without genui:");
        assert!(!config.genui.enabled);
        assert_eq!(config.genui.max_document_bytes, 262_144);
        assert!(!config.genui.mcp_apps_enabled);
        assert!(config.genui.catalog_extensions.is_empty());
    }
}

#[test]
fn genui_config_default_enabled_false() {
    let d = GenUiConfig::default();
    assert!(!d.enabled);
    assert_eq!(d.max_document_bytes, 262_144);
    assert!(!d.mcp_apps_enabled);
    assert!(d.catalog_extensions.is_empty());
}

#[test]
fn genui_snake_case_key_set_parses() {
    let yaml = format!(
        "{}\ngenui:\n  enabled: false\n  max_document_bytes: 4096\n  mcp_apps_enabled: true\n  catalog_extensions:\n    - name: demo\n",
        minimal_yaml().trim_end()
    );
    let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("snake_case genui: parses");
    assert!(!config.genui.enabled);
    assert_eq!(config.genui.max_document_bytes, 4096);
    assert!(config.genui.mcp_apps_enabled);
    assert_eq!(config.genui.catalog_extensions.len(), 1);
}

#[test]
fn genui_kebab_case_aliases_still_parse() {
    let yaml = format!(
        "{}\ngenui:\n  enabled: false\n  max-document-bytes: 8192\n  mcp-apps-enabled: true\n  catalog-extensions:\n    - kind: extra\n",
        minimal_yaml().trim_end()
    );
    let config: RuntimeConfig = serde_yml::from_str(&yaml).expect("kebab-case genui: aliases bind");
    assert_eq!(config.genui.max_document_bytes, 8192);
    assert!(config.genui.mcp_apps_enabled);
    assert_eq!(config.genui.catalog_extensions.len(), 1);
}

#[test]
fn genui_max_document_bytes_range() {
    let accept = |n: usize| {
        let yaml = format!(
            "{}\ngenui:\n  enabled: false\n  max_document_bytes: {n}\n",
            minimal_yaml().trim_end()
        );
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &yaml);
        load_config(&config_path)
            .unwrap_or_else(|e| panic!("max_document_bytes={n} must accept: {e}"))
    };
    let reject = |n: usize| {
        let yaml = format!(
            "{}\ngenui:\n  enabled: false\n  max_document_bytes: {n}\n",
            minimal_yaml().trim_end()
        );
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("runtime-config.yaml");
        write_config(&config_path, &yaml);
        let err =
            load_config(&config_path).expect_err(&format!("max_document_bytes={n} must reject"));
        assert!(
            err.to_string().contains("262144") || err.to_string().contains("max_document_bytes"),
            "error should name the range: {err}"
        );
    };
    accept(1);
    accept(262_144);
    reject(0);
    reject(262_145);
}
