//! `pack.yaml` parser per MODULE-018 §1.3.1 / §19.4 (AC-04, AC-16).
//!
//! Slice A invariants:
//! - All top-level fields validated via `#[serde(deny_unknown_fields)]`.
//! - `version` parses as `semver::Version`.
//! - `dependencies[*].version` parses as `semver::VersionReq`.
//! - `runtime-version` parses as `semver::VersionReq`.
//! - `trust-level` defaults to `Untrusted` when absent (AC-16).
//! - `checksums.algo` is `sha256` and `checksums.files` may be empty (Slice A:
//!   pack.yaml itself is NOT required to checksum itself — the self-referential
//!   fixed-point is not computable without a signed-manifest scheme that is a
//!   Slice C concern. Integrity of pack.yaml is enforced at step ④ admin
//!   approval where required-capabilities + trust-level are displayed for
//!   review; other files in the pack (.wasm, .yaml in subdirs) ARE checksummed
//!   by entries in `checksums.files`).

use serde::Deserialize;
use std::collections::BTreeMap;

use crate::error::PackError;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    pub name: String,
    pub version: String, // semver::Version

    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,

    #[serde(rename = "runtime-version")]
    pub runtime_version: String, // semver::VersionReq

    #[serde(default)]
    pub dependencies: Vec<PackDependency>,

    #[serde(default)]
    pub provides: PackProvides,

    #[serde(rename = "required-capabilities", default)]
    pub required_capabilities: Vec<String>,

    #[serde(rename = "trust-level", default)]
    pub trust_level: TrustLevel,

    pub checksums: PackChecksums,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackDependency {
    pub name: String,
    pub version: String, // semver::VersionReq
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackProvides {
    #[serde(rename = "behavior-binaries", default)]
    pub behavior_binaries: Vec<String>,
    #[serde(rename = "agent-templates", default)]
    pub agent_templates: Vec<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(rename = "channel-adapters", default)]
    pub channel_adapters: Vec<String>,
    #[serde(rename = "mcp-servers", default)]
    pub mcp_servers: Vec<String>,
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default)]
    pub workflows: Vec<String>,
    #[serde(rename = "memory-seeds", default)]
    pub memory_seeds: Vec<String>,
    #[serde(rename = "meta-schema-extensions", default)]
    pub meta_schema_extensions: Vec<String>,
    /// Type 11 (AC-17, REQ-380) — pack-provided resource capabilities. Each name maps to
    /// the directory `resource-capabilities/{name}/` with a required `capability.yaml`.
    #[serde(rename = "resource-capabilities", default)]
    pub resource_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum TrustLevel {
    #[default]
    Untrusted, // AC-16: default when field absent
    Trusted,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackChecksums {
    pub algo: ChecksumAlgo,
    pub files: BTreeMap<String, String>, // relpath → hex digest
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum ChecksumAlgo {
    Sha256,
}

fn validate_provides_names(kind: &str, names: &[String]) -> Result<(), PackError> {
    for n in names {
        if n.is_empty()
            || n.contains('/')
            || n.contains('\\')
            || n.contains('\0')
            || n.contains("..")
            || n.contains('.')        // bare identifier: no file-extension suffix
            || n.starts_with('.')
            || n.contains(' ')
            || n.contains('\t')
            // Adversarial round 12: reject ALL ASCII control bytes (`\n`, `\r`, ESC, …)
            // and non-ASCII — parity with the stricter pack-`name` / `required-capabilities`
            // gates. A provide name becomes a literal FS directory component AND is
            // interpolated into install/rescan error strings; control/escape bytes are a
            // terminal-/log-injection surface (no legitimate bare identifier uses them).
            || n.chars().any(|c| !c.is_ascii() || c.is_ascii_control())
        {
            return Err(PackError::InvalidManifest(format!(
                "provides.{kind} entry rejected (must be a bare ASCII identifier, no extension/path/whitespace/control): {n:?}"
            )));
        }
    }
    Ok(())
}

/// Pre-parse YAML alias-reference detection. libyml (the parser underneath
/// serde_yml) does NOT bound alias expansion, so a small input with deeply
/// nested anchor/alias references can balloon into multi-GiB allocations
/// during `from_str` — a billion-laughs attack. The post-parse collection
/// caps in PackManifest::from_yaml only fire AFTER the OOM has already
/// happened. Reject any `*alias` reference outright before deserialization;
/// Slice A pack manifests have no need for YAML anchors/aliases — a flat
/// document is the only legitimate shape. Round-9 adversarial round-2 W1.
///
/// Slice C adversarial round 11 W1 hardening: the original implementation
/// only flagged `*` followed by ASCII `[A-Za-z0-9_]`. YAML node names
/// permit hyphens (`*kebab-alias`) and non-ASCII identifier chars
/// (`*é`-anchored references); attackers could craft alias graphs whose
/// names sidestep the prefilter and still trigger libyml expansion. The
/// hardened predicate ALSO flags `*` followed by `-` or any non-ASCII
/// codepoint as a potential alias reference. False-positive risk in
/// legitimate prose is bounded: unquoted YAML strings with literal `*`
/// must use ASCII control chars (space, comma, newline) between `*` and
/// the next char to avoid scanner confusion; quoted strings (`"..."`,
/// `'...'`) escape `*` and are tokenized differently by libyml, so the
/// pre-parse scan flagging them is a defense-in-depth false positive
/// rather than a real reject. The flat-document policy means no pack
/// SHOULD need anchors/aliases at all.
pub(crate) fn yaml_has_alias_refs(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // `*` followed by an alias-name byte is an alias ref. Accepted
        // alias-name bytes: ASCII identifier chars (alnum / `_`), kebab
        // continuation (`-`), and any non-ASCII byte (Unicode identifier
        // tail; libyml accepts these as node-name continuation). `**`
        // (multiplication or string content) doesn't match this pattern.
        if bytes[i] == b'*' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next.is_ascii_alphanumeric() || next == b'_' || next == b'-' || !next.is_ascii() {
                return true;
            }
        }
        i += 1;
    }
    false
}

impl PackManifest {
    /// Parse + validate the pack.yaml text.
    pub fn from_yaml(yaml: &str) -> Result<Self, PackError> {
        if yaml_has_alias_refs(yaml) {
            return Err(PackError::InvalidManifest(
                "pack.yaml contains YAML alias references (`*name`) — rejected to prevent billion-laughs amplification".into(),
            ));
        }
        // Adversarial round 16 (crate-wide): bound flow-nesting/indentation depth before
        // serde_yml (deep-flow-nested pack.yaml measured at ~5–6 min per 1 MiB parse — and
        // pack.yaml re-parses on every rescan). See `component_manifest::yaml_nesting_within_bound`.
        if !crate::component_manifest::yaml_nesting_within_bound(yaml) {
            return Err(PackError::InvalidManifest(
                "pack.yaml nesting/indentation is too deep — rejected to prevent parse-time resource exhaustion (serde_yml deep-nesting DoS)".into(),
            ));
        }
        let parsed: PackManifest = serde_yml::from_str(yaml)
            .map_err(|e| PackError::InvalidManifest(format!("yaml parse: {e}")))?;

        // name validation: non-empty, no path separators, no `..`, no `@`
        // (rescan uses `@` to split `{name}@{version}` keys), no leading `.`
        // (rescan rejects keys starting with `.`), no null byte. The
        // round-9 r2 rescan tightening added ASCII-only enforcement — the
        // manifest gate MUST match so installs cannot succeed at step ⑦
        // with a name that step ⑧ rescan would later reject (Codex r2 W2:
        // disk-vs-memory state drift). Reject non-ASCII, ASCII-control,
        // and ASCII-whitespace in addition to the structural rejections.
        if parsed.name.is_empty()
            || parsed.name.contains('/')
            || parsed.name.contains('\\')
            || parsed.name.contains('@')
            || parsed.name.contains('\0')
            || parsed.name.contains("..")
            || parsed.name.starts_with('.')
            || parsed
                .name
                .chars()
                .any(|c| !c.is_ascii() || c.is_ascii_control() || c.is_ascii_whitespace())
        {
            return Err(PackError::InvalidManifest(format!(
                "invalid pack name (non-ASCII/control/whitespace/separator/traversal/leading-dot/@/null): {:?}",
                parsed.name
            )));
        }
        // version was already semver-parsed below; semver::Version::parse
        // rejects non-ASCII/whitespace by grammar, so version doesn't need
        // this additional gate.

        // version: semver::Version
        semver::Version::parse(&parsed.version).map_err(|e| {
            PackError::InvalidManifest(format!(
                "version {:?} is not valid SemVer: {e}",
                parsed.version
            ))
        })?;

        // dependencies[*].version: semver::VersionReq
        for dep in &parsed.dependencies {
            if dep.name.is_empty() {
                return Err(PackError::InvalidManifest(
                    "dependency name cannot be empty".into(),
                ));
            }
            semver::VersionReq::parse(&dep.version).map_err(|e| {
                PackError::InvalidManifest(format!(
                    "dependency {:?} version {:?} not a valid SemVer range: {e}",
                    dep.name, dep.version
                ))
            })?;
        }

        // runtime-version: semver::VersionReq
        semver::VersionReq::parse(&parsed.runtime_version).map_err(|e| {
            PackError::InvalidManifest(format!(
                "runtime-version {:?} not a valid SemVer range: {e}",
                parsed.runtime_version
            ))
        })?;

        // required-capabilities entries non-empty + ASCII-only. The admin
        // approval prompt (Slice B InteractiveApproval) writes these names
        // verbatim to stdout, so a name containing ANSI escape sequences
        // ("\x1b[2J\x1b[H...") or control bytes could redraw the prompt to
        // spoof a default-accept verdict. Reject non-ASCII / control bytes /
        // whitespace at parse time. (Adversarial round 2 Critical 2 fix.)
        for cap in &parsed.required_capabilities {
            if cap.is_empty() {
                return Err(PackError::InvalidManifest(
                    "required-capabilities entry cannot be empty".into(),
                ));
            }
            if cap
                .chars()
                .any(|c| !c.is_ascii() || c.is_ascii_control() || c.is_ascii_whitespace())
            {
                return Err(PackError::InvalidManifest(format!(
                    "required-capabilities entry rejected (non-ASCII / control / whitespace): {cap:?}"
                )));
            }
        }

        // Round-9 adversarial W4: bound collection sizes to prevent
        // YAML-alias amplification (billion-laughs-style) or naive oversized
        // manifests from forcing the parser/installer to allocate unbounded
        // memory or perform unbounded syscalls. Caps are generous for any
        // realistic pack — a real-world manifest hits at most a few dozen
        // entries per kind.
        const MAX_DEPENDENCIES: usize = 256;
        const MAX_PROVIDES_PER_KIND: usize = 256;
        const MAX_REQUIRED_CAPABILITIES: usize = 64;
        const MAX_CHECKSUM_ENTRIES: usize = 4096;
        if parsed.dependencies.len() > MAX_DEPENDENCIES {
            return Err(PackError::InvalidManifest(format!(
                "dependencies length {} exceeds max {MAX_DEPENDENCIES}",
                parsed.dependencies.len()
            )));
        }
        if parsed.required_capabilities.len() > MAX_REQUIRED_CAPABILITIES {
            return Err(PackError::InvalidManifest(format!(
                "required-capabilities length {} exceeds max {MAX_REQUIRED_CAPABILITIES}",
                parsed.required_capabilities.len()
            )));
        }
        for (kind, list) in [
            ("behavior-binaries", &parsed.provides.behavior_binaries),
            ("agent-templates", &parsed.provides.agent_templates),
            ("skills", &parsed.provides.skills),
            ("components", &parsed.provides.components),
            ("channel-adapters", &parsed.provides.channel_adapters),
            ("mcp-servers", &parsed.provides.mcp_servers),
            ("presets", &parsed.provides.presets),
            ("workflows", &parsed.provides.workflows),
            ("memory-seeds", &parsed.provides.memory_seeds),
            (
                "meta-schema-extensions",
                &parsed.provides.meta_schema_extensions,
            ),
            (
                "resource-capabilities",
                &parsed.provides.resource_capabilities,
            ),
        ] {
            if list.len() > MAX_PROVIDES_PER_KIND {
                return Err(PackError::InvalidManifest(format!(
                    "provides.{kind} length {} exceeds max {MAX_PROVIDES_PER_KIND}",
                    list.len()
                )));
            }
        }
        if parsed.checksums.files.len() > MAX_CHECKSUM_ENTRIES {
            return Err(PackError::InvalidManifest(format!(
                "checksums.files entry count {} exceeds max {MAX_CHECKSUM_ENTRIES}",
                parsed.checksums.files.len()
            )));
        }

        // provides[*] entries must be bare component identifiers. Downstream
        // `registry::resolve()` + `path_for_kind()` synthesize paths from these
        // names by appending the canonical PRD §19.3 extension per kind
        // (e.g. `behavior-binaries/<name>.wasm`), so an entry like
        // `tool.wasm` would resolve to `tool.wasm.wasm`; an entry with `/`
        // or `..` would break FQ-ref grammar or escape pack roots. Reject
        // here to fail-fast at manifest parse instead of silently mis-routing.
        validate_provides_names("behavior-binaries", &parsed.provides.behavior_binaries)?;
        validate_provides_names("agent-templates", &parsed.provides.agent_templates)?;
        validate_provides_names("skills", &parsed.provides.skills)?;
        validate_provides_names("components", &parsed.provides.components)?;
        validate_provides_names("channel-adapters", &parsed.provides.channel_adapters)?;
        validate_provides_names("mcp-servers", &parsed.provides.mcp_servers)?;
        validate_provides_names("presets", &parsed.provides.presets)?;
        validate_provides_names("workflows", &parsed.provides.workflows)?;
        validate_provides_names("memory-seeds", &parsed.provides.memory_seeds)?;
        validate_provides_names(
            "meta-schema-extensions",
            &parsed.provides.meta_schema_extensions,
        )?;
        // AC-17: same bare-identifier gate as the other 10 categories — rejects `/`, `\`,
        // `..`, leading-`.`, whitespace, control bytes. Without this, resource-capabilities
        // would be the ONE category feeding unvalidated names into `path_for_kind`.
        validate_provides_names(
            "resource-capabilities",
            &parsed.provides.resource_capabilities,
        )?;

        // checksums: algo enforced by enum. `files` MAY be empty (pack with no
        // checksummable content — uncommon but valid). pack.yaml is NOT required
        // to checksum itself (self-referential fixed-point is not computable
        // without a signed-manifest scheme — Slice C concern). Integrity of
        // pack.yaml relies on admin approval review at step ④.
        //
        // Per-entry value-shape validation: SHA-256 produces a 64-char hex digest
        // (256 bits / 4 bits per nibble). Reject malformed digests at parse time
        // so a typo / truncation / wrong-algo digest fails fast as
        // `InvalidManifest`, not later as `ChecksumMismatch`. (AC-04 contract: a
        // valid pack.yaml is parseable; a digest of the wrong length is not.)
        match parsed.checksums.algo {
            ChecksumAlgo::Sha256 => {
                for (relpath, digest) in &parsed.checksums.files {
                    if digest.len() != 64 {
                        return Err(PackError::InvalidManifest(format!(
                            "checksums.files[{relpath:?}]: sha256 digest must be 64 hex chars, got {}",
                            digest.len()
                        )));
                    }
                    if !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(PackError::InvalidManifest(format!(
                            "checksums.files[{relpath:?}]: sha256 digest contains non-hex characters"
                        )));
                    }
                }
            }
        }

        Ok(parsed)
    }

    /// Validate `runtime_version` against the runtime currently in use.
    /// `current` is typically `env!("CARGO_PKG_VERSION")` at the caller site
    /// (Installer construction). Returns `RuntimeVersionMismatch` if the range
    /// does not match.
    pub fn check_runtime_compat(&self, current: &str) -> Result<(), PackError> {
        let req = semver::VersionReq::parse(&self.runtime_version).map_err(|e| {
            PackError::InvalidManifest(format!(
                "runtime-version {:?} not a valid SemVer range: {e}",
                self.runtime_version
            ))
        })?;
        let cur = semver::Version::parse(current).map_err(|e| {
            PackError::InvalidManifest(format!(
                "current runtime version {:?} not a valid SemVer: {e}",
                current
            ))
        })?;
        if !req.matches(&cur) {
            return Err(PackError::RuntimeVersionMismatch {
                required: self.runtime_version.clone(),
                current: current.into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PACK: &str = r#"
name: research-pack
version: 1.2.0
author: alice@example.com
description: Research workflow
license: MIT
runtime-version: ">=0.0.1, <2.0.0"

dependencies: []

provides:
  behavior-binaries: [researcher]
  agent-templates: [researcher]
  skills: [web-search]
  components: []
  channel-adapters: []
  mcp-servers: []
  presets: []
  workflows: []
  memory-seeds: []
  meta-schema-extensions: []

required-capabilities:
  - fs
  - llm

trust-level: untrusted
checksums:
  algo: sha256
  files:
    behavior-binaries/researcher.wasm: "0000000000000000000000000000000000000000000000000000000000000000"
"#;

    #[test]
    fn t01_parse_valid_manifest() {
        let m = PackManifest::from_yaml(VALID_PACK).unwrap();
        assert_eq!(m.name, "research-pack");
        assert_eq!(m.version, "1.2.0");
        assert_eq!(m.provides.behavior_binaries, vec!["researcher".to_string()]);
        assert_eq!(m.trust_level, TrustLevel::Untrusted);
    }

    #[test]
    fn t02_reject_unknown_field() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nfoo: bar\nchecksums:\n  algo: sha256\n  files:\n    pack.yaml: abc";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t03_reject_invalid_version() {
        let yaml = "name: x\nversion: not-semver\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files:\n    pack.yaml: abc";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t04_reject_invalid_runtime_range() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \"not-semver-range\"\nchecksums:\n  algo: sha256\n  files:\n    pack.yaml: abc";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t05_runtime_range_excludes_current_returns_mismatch() {
        let m = PackManifest::from_yaml(VALID_PACK).unwrap();
        let mut m = m;
        m.runtime_version = ">=0.1.0, <1.0.0".into();
        match m.check_runtime_compat("2.0.0") {
            Err(PackError::RuntimeVersionMismatch { .. }) => {}
            other => panic!("expected RuntimeVersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn t06_runtime_range_includes_current() {
        let m = PackManifest::from_yaml(VALID_PACK).unwrap();
        m.check_runtime_compat("0.5.0").unwrap();
    }

    #[test]
    fn t07_default_trust_level_untrusted() {
        // pack.yaml without `trust-level:` field — parse via direct serde to
        // hit the Default impl path. Use empty checksum map to avoid digest
        // shape validation (independent dimension).
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files: {}";
        let m = PackManifest::from_yaml(yaml).unwrap();
        assert_eq!(m.trust_level, TrustLevel::Untrusted);
    }

    #[test]
    fn t08_explicit_untrusted_round_trips() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\ntrust-level: untrusted\nchecksums:\n  algo: sha256\n  files: {}";
        let m = PackManifest::from_yaml(yaml).unwrap();
        assert_eq!(m.trust_level, TrustLevel::Untrusted);
    }

    // Round-6 W2: checksum digest-shape validation at parse time.
    #[test]
    fn checksum_rejects_short_sha256_digest() {
        // 63 chars — one short of 64.
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files:\n    behavior-binaries/tool.wasm: \"000000000000000000000000000000000000000000000000000000000000000\"";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("64 hex chars"),
                "expected digest-length rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn checksum_rejects_long_sha256_digest() {
        // 65 chars — one over 64.
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files:\n    behavior-binaries/tool.wasm: \"00000000000000000000000000000000000000000000000000000000000000000\"";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("64 hex chars"),
                "expected digest-length rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn checksum_rejects_non_hex_sha256_digest() {
        // 64 chars but with a non-hex 'g'.
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files:\n    behavior-binaries/tool.wasm: \"g000000000000000000000000000000000000000000000000000000000000000\"";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("non-hex"),
                "expected non-hex rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t33_empty_checksums_files_is_allowed() {
        // pack.yaml integrity is enforced via admin approval at step ④, not
        // via self-checksum (which would require a fixed-point algorithm).
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files: {}";
        let m = PackManifest::from_yaml(yaml).unwrap();
        assert!(m.checksums.files.is_empty());
    }

    // Pack-name validation symmetry with registry.rs::rescan() key check —
    // ensures install cannot succeed at step ⑦ then fail at step ⑧ rescan
    // due to name characters that survive parsing but break the registry key.
    #[test]
    fn pack_name_rejects_at_symbol() {
        let yaml = "name: foo@bar\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn pack_name_rejects_leading_dot() {
        let yaml = "name: .hidden\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn pack_name_rejects_null_byte() {
        // YAML's `\0` escape requires double-quoted strings.
        let yaml = "name: \"foo\\0bar\"\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    // Codex r2 W2: pack name validation must reject non-ASCII / whitespace
    // so installs cannot succeed at step ⑦ but fail at step ⑧ rescan
    // (the rescan key gate also rejects these), leaving on-disk state
    // diverged from in-memory registry state.
    #[test]
    fn pack_name_rejects_whitespace() {
        let yaml = "name: \"evil pack\"\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("non-ASCII/control/whitespace") || msg.contains("whitespace"),
                "expected whitespace rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn pack_name_rejects_non_ascii() {
        let yaml = "name: \"foo\u{200B}bar\"\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("non-ASCII") || msg.contains("invalid pack name"),
                "expected non-ASCII rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    // provides[*] entry validation — fail-fast at manifest parse, so
    // `registry::resolve()` + `path_for_kind()` never see malformed names
    // they'd quietly mis-route or double-extension.
    #[test]
    fn provides_entry_rejects_file_extension() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  behavior-binaries: [tool.wasm]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn provides_entry_rejects_path_separator() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  workflows: [\"sub/tool\"]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn provides_entry_rejects_traversal() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  workflows: [\"..\"]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    // ── MODULE-018-T93 (AC-17): validate_provides_names + length-cap parity for
    //    the resource-capabilities category (both non-compiler-forced wiring sites).
    //    Without the wired gate, resource-capabilities would be the ONE category
    //    feeding unvalidated names into path_for_kind (a traversal surface).
    #[test]
    fn t93_resource_capabilities_name_rejects_extension() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [\"cap.yaml\"]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t93_resource_capabilities_name_rejects_path_separator() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [\"a/b\"]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t93_resource_capabilities_name_rejects_traversal() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [\"..\"]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t93_resource_capabilities_name_rejects_nul_byte() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [\"foo\\0bar\"]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t93_resource_capabilities_name_rejects_whitespace() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [\"has space\"]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t93_resource_capabilities_name_rejects_control_bytes() {
        // Adversarial round 12: newline/CR/ESC and other control bytes are rejected
        // (terminal-/log-injection defense) — parity with the pack-`name` gate.
        for bad in ["cap\\ncap", "cap\\rcap", "cap\\x1bcap"] {
            let yaml = format!(
                "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [\"{bad}\"]\nchecksums:\n  algo: sha256\n  files: {{}}"
            );
            match PackManifest::from_yaml(&yaml) {
                Err(PackError::InvalidManifest(_)) => {}
                other => panic!("expected InvalidManifest for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn t93_resource_capabilities_name_rejects_non_ascii() {
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [\"cap\u{200b}x\"]\nchecksums:\n  algo: sha256\n  files: {}";
        match PackManifest::from_yaml(yaml) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn pack_yaml_deep_flow_nesting_rejected_fast() {
        // Adversarial round 16 (crate-wide): a deep-flow-nested pack.yaml is rejected FAST
        // by the shared nesting guard, before serde_yml's O(n²) scan (a 1 MiB deep-nested
        // pack.yaml was measured at ~5–6 min — and pack.yaml re-parses on every rescan).
        let mut y = String::from("name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nx: ");
        y.push_str(&"[".repeat(5_000));
        let start = std::time::Instant::now();
        let r = PackManifest::from_yaml(&y);
        assert!(start.elapsed().as_secs() < 2, "guard must reject fast");
        match r {
            Err(PackError::InvalidManifest(m)) => {
                assert!(m.contains("nesting") || m.contains("deep"), "got: {m}")
            }
            other => panic!("expected InvalidManifest (deep nesting), got {other:?}"),
        }
    }

    #[test]
    fn t93_resource_capabilities_valid_name_accepted() {
        // Positive control: a bare identifier passes, so the rejections above are
        // load-bearing (not a blanket reject of the new category).
        let yaml = "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [structured-data]\nchecksums:\n  algo: sha256\n  files: {}";
        let m = PackManifest::from_yaml(yaml).unwrap();
        assert_eq!(
            m.provides.resource_capabilities,
            vec!["structured-data".to_string()]
        );
    }

    #[test]
    fn t93_resource_capabilities_length_cap_enforced() {
        // MAX_PROVIDES_PER_KIND is a fn-local const (256) in from_yaml; 257 exceeds it.
        let names: Vec<String> = (0..257).map(|i| format!("cap{i}")).collect();
        let yaml = format!(
            "name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\nprovides:\n  resource-capabilities: [{}]\nchecksums:\n  algo: sha256\n  files: {{}}",
            names.join(", ")
        );
        match PackManifest::from_yaml(&yaml) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("resource-capabilities")),
            other => panic!("expected InvalidManifest (length cap), got {other:?}"),
        }
    }

    // Round-9 adversarial round-2 W1: YAML billion-laughs defense.
    #[test]
    fn yaml_alias_detection_basic() {
        assert!(!yaml_has_alias_refs("name: foo\nversion: 1.0.0"));
        assert!(!yaml_has_alias_refs("description: \"this * that\""));
        assert!(yaml_has_alias_refs("a: &x [1,2]\nb: *x"));
        assert!(yaml_has_alias_refs("foo: *anchor"));
    }

    #[test]
    fn from_yaml_rejects_alias_references() {
        // A canonical billion-laughs structure: each `*x` doubles the
        // expansion. Even a small input balloons the parser's allocation.
        let bomb = r#"
name: foo
version: 1.0.0
runtime-version: ">=0.0.1"
a: &a [1,1,1,1,1,1,1,1,1]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
checksums:
  algo: sha256
  files: {}
"#;
        match PackManifest::from_yaml(bomb) {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("alias references") || msg.contains("billion-laughs"),
                "expected alias-ref rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }
}
