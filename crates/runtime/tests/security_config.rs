//! MODULE-012 AC-17 — `security:` RuntimeConfig block (CONTRACT-003 additive).
//! Witnesses: defaults are byte-identical to the cap-http constants; explicit
//! `security.*` keys parse; `config_sections_changed` names `security`; and
//! `validate_config` (via `load_config`) rejects out-of-range knobs fail-closed
//! (validate-before-swap → an invalid reload never reaches the live config).

use advance_runtime::config::*;

/// Minimal VALID base config (no `security:` block) — exercises the
/// `#[serde(default)]` back-compat path.
fn base_yaml() -> &'static str {
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
}

fn write_cfg(yaml: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("runtime-config.yaml");
    std::fs::write(&path, yaml).unwrap();
    (dir, path)
}

/// T17a — an absent `security:` block parses to `SecurityConfig::default()`,
/// which equals the cap-http compile-time constants (byte-identical back-compat).
#[test]
fn t17a_absent_security_block_uses_constant_defaults() {
    let cfg: RuntimeConfig = serde_yml::from_str(base_yaml()).expect("base parses");
    assert_eq!(cfg.security, SecurityConfig::default());
    assert_eq!(cfg.security.leak_detector.max_scan_bytes, 1024 * 1024);
    assert_eq!(cfg.security.ssrf.dns_cache_ttl_seconds, 300);
    assert_eq!(cfg.security.ssrf.dns_timeout_ms, 50);
    assert_eq!(cfg.security.rate_limit.per_component_rps, 10.0);
    assert_eq!(cfg.security.action_validator.max_message_size, 1024 * 1024);
}

/// T17a — explicit `security.*` keys parse into the expected field values (all 5).
#[test]
fn t17a_explicit_security_keys_parse() {
    let yaml = format!(
        "{}{}",
        base_yaml(),
        r#"
security:
  leak_detector:
    max_scan_bytes: 2048
  ssrf:
    dns_cache_ttl_seconds: 120
    dns_timeout_ms: 25
  rate_limit:
    per_component_rps: 50.0
  action_validator:
    max_message_size: 4096
"#
    );
    let cfg: RuntimeConfig = serde_yml::from_str(&yaml).expect("explicit security parses");
    assert_eq!(cfg.security.leak_detector.max_scan_bytes, 2048);
    assert_eq!(cfg.security.ssrf.dns_cache_ttl_seconds, 120);
    assert_eq!(cfg.security.ssrf.dns_timeout_ms, 25);
    assert_eq!(cfg.security.rate_limit.per_component_rps, 50.0);
    assert_eq!(cfg.security.action_validator.max_message_size, 4096);
}

/// T17b — `config_sections_changed` names `"security"` when (and only when) the
/// block differs, so `runtime.config_reloaded` reports it.
#[test]
fn t17b_config_sections_changed_names_security() {
    let old: RuntimeConfig = serde_yml::from_str(base_yaml()).unwrap();
    let mut new = old.clone();
    // identical → not reported
    assert!(!config_sections_changed(&old, &new).contains(&"security"));
    // change a security knob → reported
    new.security.rate_limit.per_component_rps = 99.0;
    assert!(
        config_sections_changed(&old, &new).contains(&"security"),
        "security must be named when the block differs"
    );
}

/// T17f — `validate_config` (via `load_config`) rejects out-of-range security
/// knobs fail-closed. The divide-by-rps hazard (rps ≤ 0) and the DoS-ceiling
/// over-bounds are all rejected; the prior valid config is therefore never
/// swapped in (validate-before-swap).
#[test]
fn t17f_invalid_security_rejected_failclosed() {
    let cases: &[(&str, &str)] = &[
        (
            "security:\n  rate_limit:\n    per_component_rps: 0.0\n",
            "per_component_rps",
        ),
        (
            "security:\n  rate_limit:\n    per_component_rps: -1.0\n",
            "per_component_rps",
        ),
        (
            "security:\n  rate_limit:\n    per_component_rps: .nan\n", // non-finite
            "per_component_rps",
        ),
        (
            "security:\n  rate_limit:\n    per_component_rps: 1000001.0\n", // just over MAX
            "per_component_rps",
        ),
        (
            "security:\n  leak_detector:\n    max_scan_bytes: 67108865\n", // 64 MiB + 1
            "max_scan_bytes",
        ),
        (
            "security:\n  leak_detector:\n    max_scan_bytes: 0\n",
            "max_scan_bytes",
        ),
        (
            "security:\n  leak_detector:\n    max_scan_bytes: 134217728\n", // 128 MiB > 64 MiB
            "max_scan_bytes",
        ),
        (
            "security:\n  ssrf:\n    dns_timeout_ms: 0\n",
            "dns_timeout_ms",
        ),
        (
            "security:\n  ssrf:\n    dns_timeout_ms: 120000\n", // > 60_000
            "dns_timeout_ms",
        ),
        (
            "security:\n  ssrf:\n    dns_cache_ttl_seconds: 999999\n", // > 86_400
            "dns_cache_ttl_seconds",
        ),
        (
            "security:\n  action_validator:\n    max_message_size: 0\n",
            "max_message_size",
        ),
        (
            "security:\n  action_validator:\n    max_message_size: 134217728\n", // 128 MiB
            "max_message_size",
        ),
    ];
    for (block, needle) in cases {
        let yaml = format!("{}{}", base_yaml(), block);
        let (_dir, path) = write_cfg(&yaml);
        let err = load_config(&path)
            .err()
            .unwrap_or_else(|| panic!("expected validation error for `{needle}`:\n{block}"));
        assert!(
            err.to_string().contains(needle),
            "error for `{needle}` should mention it; got: {err}\nblock:\n{block}"
        );
    }
}

/// T17f companion — a VALID `security:` block loads cleanly (the rejection is
/// specific to out-of-range values, not the block's presence).
#[test]
fn t17f_valid_security_loads_ok() {
    let yaml = format!(
        "{}{}",
        base_yaml(),
        "security:\n  rate_limit:\n    per_component_rps: 25.0\n  leak_detector:\n    max_scan_bytes: 2097152\n",
    );
    let (_dir, path) = write_cfg(&yaml);
    let cfg = load_config(&path).expect("valid security block must load");
    assert_eq!(cfg.security.rate_limit.per_component_rps, 25.0);
    assert_eq!(cfg.security.leak_detector.max_scan_bytes, 2_097_152);
}

/// T17f exact-boundary — values AT the inclusive ceilings load OK (the rejects
/// fire strictly OVER the bound; this catches an off-by-one in the validator).
#[test]
fn t17f_exact_boundary_values_accepted() {
    let yaml = format!(
        "{}{}",
        base_yaml(),
        "security:\n  leak_detector:\n    max_scan_bytes: 67108864\n  ssrf:\n    dns_cache_ttl_seconds: 86400\n    dns_timeout_ms: 60000\n  rate_limit:\n    per_component_rps: 1000000.0\n  action_validator:\n    max_message_size: 67108864\n",
    );
    let (_dir, path) = write_cfg(&yaml);
    let cfg = load_config(&path).expect("exact-boundary security values must load");
    assert_eq!(cfg.security.leak_detector.max_scan_bytes, 67_108_864); // 64 MiB
    assert_eq!(cfg.security.ssrf.dns_cache_ttl_seconds, 86_400);
    assert_eq!(cfg.security.ssrf.dns_timeout_ms, 60_000);
    assert_eq!(cfg.security.rate_limit.per_component_rps, 1_000_000.0);
    assert_eq!(cfg.security.action_validator.max_message_size, 67_108_864);
}
