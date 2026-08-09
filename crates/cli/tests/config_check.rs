//! Integration tests for `advance config check`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

fn advance() -> Command {
    Command::cargo_bin("advance").unwrap()
}

const CANONICAL_YAML: &str = "\
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
";

#[test]
fn config_check_valid() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("runtime-config.yaml");
    fs::write(&cfg, CANONICAL_YAML).unwrap();
    advance()
        .args(["config", "check"])
        .arg(&cfg)
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn config_check_missing_file() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("does-not-exist.yaml");
    advance()
        .args(["config", "check"])
        .arg(&cfg)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("does-not-exist"));
}

#[test]
fn config_check_invalid_yaml() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("bad.yaml");
    fs::write(&cfg, ":::bad:::").unwrap();
    advance()
        .args(["config", "check"])
        .arg(&cfg)
        .assert()
        .failure()
        .code(1);
}

#[test]
fn config_check_fails_on_validation_error() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("bad-jitter.yaml");
    let bad = CANONICAL_YAML.replace("max_jitter_ratio: 0.1", "max_jitter_ratio: -1.0");
    fs::write(&cfg, bad).unwrap();
    advance()
        .args(["config", "check"])
        .arg(&cfg)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("jitter"));
}

#[test]
fn config_check_no_arg_uses_default_path() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir(tmp.path().join(".advance")).unwrap();
    fs::write(
        tmp.path().join(".advance/runtime-config.yaml"),
        CANONICAL_YAML,
    )
    .unwrap();
    advance()
        .current_dir(tmp.path())
        .env_remove("ADVANCE_WORKSPACE")
        .args(["config", "check"])
        .assert()
        .success();
}

#[test]
fn config_check_respects_advance_workspace_env() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir(tmp.path().join(".advance")).unwrap();
    fs::write(
        tmp.path().join(".advance/runtime-config.yaml"),
        CANONICAL_YAML,
    )
    .unwrap();
    let elsewhere = TempDir::new().unwrap();
    advance()
        .current_dir(elsewhere.path())
        .env("ADVANCE_WORKSPACE", tmp.path())
        .args(["config", "check"])
        .assert()
        .success();
}

#[test]
fn config_check_rejects_symlink() {
    let tmp = TempDir::new().unwrap();
    let real = tmp.path().join("real.yaml");
    fs::write(&real, CANONICAL_YAML).unwrap();
    let link = tmp.path().join("link.yaml");
    symlink(&real, &link).unwrap();
    advance()
        .args(["config", "check"])
        .arg(&link)
        .assert()
        .failure()
        .code(1);
}
