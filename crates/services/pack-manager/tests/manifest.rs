//! Manifest parser integration tests (some unit tests live inline in src/manifest.rs).

use advance_pack_manager::{PackError, PackManifest};

const FULL_PACK: &str = r#"
name: research-pack
version: 1.2.0
author: alice@example.com
description: Research workflow with sub-agents, crawlers, hooks
license: MIT
runtime-version: ">=0.0.1, <2.0.0"

dependencies:
  - name: base-utils
    version: "^1.0.0"

provides:
  behavior-binaries: [researcher, daily-summary, cost-alerter]
  agent-templates: [researcher]
  skills: [web-search]
  components: [daily-summary, cost-alerter]
  channel-adapters: [telegram-adapter]
  mcp-servers: [brave-search]
  presets: [research-autonomous]
  workflows: [auto-research]
  memory-seeds: [researcher-seed]
  meta-schema-extensions: [research-meta]

required-capabilities:
  - fs
  - llm
  - http
  - mcp

trust-level: untrusted
checksums:
  algo: sha256
  files:
    behavior-binaries/researcher.wasm: "0000000000000000000000000000000000000000000000000000000000000000"
    workflows/auto-research.yaml: "1111111111111111111111111111111111111111111111111111111111111111"
"#;

#[test]
fn full_example_parses_with_all_10_provides_lists() {
    let m = PackManifest::from_yaml(FULL_PACK).unwrap();
    assert_eq!(m.name, "research-pack");
    assert_eq!(m.provides.behavior_binaries.len(), 3);
    assert_eq!(m.provides.agent_templates.len(), 1);
    assert_eq!(m.provides.skills.len(), 1);
    assert_eq!(m.provides.components.len(), 2);
    assert_eq!(m.provides.channel_adapters.len(), 1);
    assert_eq!(m.provides.mcp_servers.len(), 1);
    assert_eq!(m.provides.presets.len(), 1);
    assert_eq!(m.provides.workflows.len(), 1);
    assert_eq!(m.provides.memory_seeds.len(), 1);
    assert_eq!(m.provides.meta_schema_extensions.len(), 1);
    assert_eq!(m.required_capabilities, vec!["fs", "llm", "http", "mcp"]);
    assert_eq!(m.dependencies.len(), 1);
}

#[test]
fn dep_with_invalid_version_rejected() {
    let yaml = r#"
name: x
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies:
  - name: y
    version: "not-semver"
checksums:
  algo: sha256
  files:
    pack.yaml: abc
"#;
    match PackManifest::from_yaml(yaml) {
        Err(PackError::InvalidManifest(_)) => {}
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}
