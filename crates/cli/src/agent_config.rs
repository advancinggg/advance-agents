//! Shared `.agent/config.yaml` capability gate (/dev WS-A, 2026-06-04).
//!
//! Single source of truth for "is capability X active for this agent". Used by
//! both [`crate::wiring::wire_capabilities`] (which host fns to register at L0)
//! and [`crate::commands::start`]'s agent-loop wiring (which `CapRequest`s to
//! inject into the guest's linker). Factored out of `wiring.rs` so the two
//! paths cannot drift — a capability the daemon registers at L0 is exactly the
//! one the loop requests for the guest.
//!
//! **`genui` is an intentional two-gate exception (MODULE-001-AC-29 / T110):**
//! yaml `genui: true` still produces `CapRequest { capability: "genui" }` via
//! [`KNOWN_CAPABILITIES`], but L0 **registration** is
//! `RuntimeConfig.genui.enabled` only. yaml on + flag off → `inject` returns
//! `UnknownCapability` (typed absence).

use std::io::Read;
use std::path::{Path, PathBuf};

use advance_shared_types::capability::{CapRequest, CapabilityId};

/// Capabilities the runtime knows how to wire, in a deterministic order. Each
/// name is BOTH the `.agent/config.yaml` `capabilities:` key AND the
/// registration capability string of its host-fn provider — verified against
/// the providers: cap-fs `"fs"`, cap-llm `"llm"`, cap-secrets `"secrets"`,
/// cap-skills `"skills"`, cap-memory `"memory"`, cap-grant agent-grant
/// `"grant"` (`AGENT_GRANT_CAPABILITY`), cap-tools `"tools"`, and — await-leg
/// B-4a (2026-06-22) — reply-tracker `"messaging"` (the `await-replies` /
/// `heartbeat` / `send` host fns under ns `advance:runtime/agent-messaging@0.1.0`,
/// registered by `wire_capabilities`'s `declares_messaging` block). Including
/// `"messaging"` here is what makes a `messaging`-declaring guest LINK the
/// interface (so its `await-replies` parks the Run via the host-fn suspend sink);
/// DORMANT for shipped agents (no shipped guest imports `agent-messaging`, no
/// shipped `.agent/config.yaml` declares `messaging:true`).
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "secrets",
    "fs",
    "skills",
    "memory",
    "grant",
    "llm",
    "tools",
    "messaging",
    // Wave-23 `perchild-daemon-1` seam (a): lifting `"lifecycle"` here makes a
    // config-declaring guest LINK the `agent-lifecycle` interface (so a shipped
    // guest can call `spawn-child`). Paired with the `declares_lifecycle` gate in
    // `wiring.rs` (which registers the spawn host-fns + opens the agent tree) and
    // the `PerChildLoopManager` observer that serves the spawned child.
    "lifecycle",
    // MODULE-001-AC-29 / T110: CapRequest gate only. L0 registration is
    // `RuntimeConfig.genui.enabled` (see module rustdoc two-gate note).
    "genui",
];

/// Defence-in-depth bound on `.agent/config.yaml` size (mirrors the read in
/// `wiring.rs` — a pathologically large config cannot force an unbounded
/// allocation before the size check).
const MAX_AGENT_YAML_BYTES: usize = 1 << 20;

/// Read `<workspace>/.agent/config.yaml` with a bounded allocation. Returns
/// `None` when the file is absent, oversize (> 1 MiB), or unreadable — the
/// graceful-degradation contract (no config ⇒ no active capabilities), matching
/// the Slice-AG/BS-1 wiring posture.
pub fn read_agent_yaml(workspace: &Path) -> Option<Vec<u8>> {
    let path = workspace.join(".agent/config.yaml");
    if !path.is_file() {
        return None;
    }
    let f = std::fs::File::open(&path).ok()?;
    let mut buf = Vec::new();
    match f
        .take((MAX_AGENT_YAML_BYTES as u64) + 1)
        .read_to_end(&mut buf)
    {
        Ok(_) if buf.len() <= MAX_AGENT_YAML_BYTES => Some(buf),
        // oversize / unreadable → graceful skip (None)
        _ => None,
    }
}

/// Returns `true` iff snapshot YAML `bytes` declare `cap` as an **L0-active**
/// capability under the top-level `capabilities:` mapping.
///
/// **Active-for-L0 rule**:
///   - `<cap>: false`            → L0-inactive (operator opt-out).
///   - `<cap>: true`             → L0-active (default).
///   - `<cap>: { ... }` (any map) → L0-active. Returns `true` for ANY mapping
///     value, including `{ auto-grant: false }`; the function does NOT
///     introspect the mapping (cap-grant `compile.rs` independently skips the
///     persistent Grant for `auto-grant: false`).
///   - any other value (null, sequence, string) → L0-inactive.
///
/// Lenient on parse errors → returns `false`. Operates on `&[u8]` (not
/// re-reading the file) so callers can snapshot once and share the bytes.
pub fn yaml_declares_active_capability(bytes: &[u8], cap: &str) -> bool {
    let v: serde_yml::Value = match serde_yml::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let caps = v
        .as_mapping()
        .and_then(|m| m.get(serde_yml::Value::String("capabilities".into())))
        .and_then(|c| c.as_mapping());
    let Some(caps) = caps else { return false };
    let entry = caps.iter().find(|(k, _)| k.as_str() == Some(cap));
    let Some((_, val)) = entry else { return false };
    match val {
        serde_yml::Value::Bool(false) => false,
        serde_yml::Value::Bool(true) => true,
        serde_yml::Value::Mapping(_) => true,
        _ => false,
    }
}

/// The `CapRequest` set an agent loop injects into its guest's linker, derived
/// from the agent's `.agent/config.yaml` snapshot. `None` (no config) ⇒ empty
/// set (graceful degradation). Each active [`KNOWN_CAPABILITIES`] entry becomes
/// one `CapRequest` whose `CapabilityId` equals the capability name (the
/// host-fn registration string), so the requested caps and the registered host
/// fns line up exactly.
pub fn active_capabilities(yaml: Option<&[u8]>) -> Vec<CapRequest> {
    let Some(bytes) = yaml else {
        return Vec::new();
    };
    KNOWN_CAPABILITIES
        .iter()
        .filter(|cap| yaml_declares_active_capability(bytes, cap))
        .map(|cap| CapRequest {
            capability: CapabilityId::from(*cap),
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Wave-17 Lane 3 (MODULE-005-AC-25) — config-driven child-agent hierarchy.
//
// The `agents:` block of `<ws>/.agent/config.yaml` declares child agents the
// daemon materializes into the agent-tree at boot (BEFORE the EventBus / any
// message), so a workspace's hierarchy exists up-front rather than only after a
// runtime `spawn-child`. This module owns the schema + parse + validation; the
// boot-time materialization (BFS over the tree applying the MODULE-005 §1.4.5
// ensure-present matrix per decl, carrying `capabilities:`) lives in
// `wiring::materialize_config_tree`.
// ─────────────────────────────────────────────────────────────────────────────

/// Defensive caps on the declared agent hierarchy. `MAX_AGENT_TREE_NODES` bounds
/// the total declared-child count across the whole tree; `MAX_AGENT_TREE_DEPTH`
/// bounds nesting (the depth-0 root's direct children are depth 1).
pub const MAX_AGENT_TREE_NODES: usize = 256;
pub const MAX_AGENT_TREE_DEPTH: usize = 16;

/// Defensive YAML anchor / alias caps (mirrors cap-lifecycle
/// `auto_bootstrap::precheck_yaml_anchors`): a small operator config with many
/// aliases can blow up serde_yml's parse-time alias expansion (billion-laughs)
/// before any size check fires.
const MAX_YAML_ANCHORS: usize = 64;
const MAX_YAML_ALIASES: usize = 64;

/// One declared child agent. The `agents:` block is a sequence of these; `children`
/// nests recursively. `target-path` is parent-workspace-relative (validated lexically by
/// `resolve_under_parent` at materialization time — `..` / absolute / hidden / over-depth
/// are rejected there). `deny_unknown_fields`
/// rejects typo'd keys so a malformed declared hierarchy fails loudly rather than
/// silently dropping a node.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDecl {
    pub alias: String,
    pub template: String,
    #[serde(rename = "target-path")]
    pub target_path: PathBuf,
    /// Whole-capability ids the child is spawned with (the persisted form of a client create's
    /// `capabilities`; `CapParams::empty()` each). Subset-gated against the parent at
    /// materialization; absent ⇒ no capabilities (byte-identical to the pre-2026-09-15 schema).
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub children: Vec<AgentDecl>,
}

/// Bound on `capabilities:` entries per declaration (mirrors the tree's per-node cap).
pub const MAX_DECLARED_CAPABILITIES: usize = 64;

/// Errors from parsing / validating the `agents:` hierarchy. Distinct from the
/// lenient capability gate: a well-formed config whose `agents:` block is itself
/// malformed / over-budget fails loudly (the operator asked for a hierarchy and it
/// is wrong), while a wholly-unparseable config degrades to "no declared hierarchy"
/// exactly as the capability gate degrades (no boot regression for already-broken
/// configs).
#[derive(Debug)]
pub enum AgentConfigError {
    /// The `agents:` block exists but does not deserialize into the typed schema
    /// (unknown field, wrong type, missing required field).
    Parse(String),
    /// An `alias` failed the cap-lifecycle id charset (`[A-Za-z0-9_-]{1,64}`).
    InvalidAlias(String),
    /// The same `alias` appears more than once across the declared tree (each
    /// alias becomes a unique `AgentId`).
    DuplicateAlias(String),
    /// The declared tree exceeds `MAX_AGENT_TREE_NODES`.
    TooManyNodes(usize),
    /// The declared tree exceeds `MAX_AGENT_TREE_DEPTH`.
    TooDeep(usize),
    /// Anchor / alias amplification exceeded the defensive cap.
    YamlAnchorAmplification(usize),
    /// A `capabilities:` entry failed the id charset, was duplicated, or the list is over the cap.
    InvalidCapability(String),
    /// Lane agent-llm-policy: the `llm:` block exists but is malformed (unknown key, wrong
    /// shape, bad provider id charset, over-long / multi-line model, unknown constraint).
    InvalidLlm(String),
}

impl std::fmt::Display for AgentConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentConfigError::Parse(e) => write!(f, "agents: parse error: {e}"),
            AgentConfigError::InvalidAlias(a) => write!(f, "invalid agent alias: {a:?}"),
            AgentConfigError::DuplicateAlias(a) => write!(f, "duplicate agent alias: {a:?}"),
            AgentConfigError::TooManyNodes(n) => write!(
                f,
                "declared agent tree exceeds {MAX_AGENT_TREE_NODES} nodes (got {n})"
            ),
            AgentConfigError::TooDeep(d) => write!(
                f,
                "declared agent tree exceeds depth {MAX_AGENT_TREE_DEPTH} (got {d})"
            ),
            AgentConfigError::YamlAnchorAmplification(n) => write!(
                f,
                "agents: yaml anchor/alias count exceeds defensive cap ({n})"
            ),
            AgentConfigError::InvalidCapability(c) => {
                write!(f, "invalid declared capability: {c:?}")
            }
            AgentConfigError::InvalidLlm(reason) => write!(f, "llm: {reason}"),
        }
    }
}

impl std::error::Error for AgentConfigError {}

/// Defensive pre-scan for YAML anchor / alias amplification (billion-laughs).
/// Mirrors `cap_lifecycle::auto_bootstrap::precheck_yaml_anchors`: count raw `&` /
/// `*` occurrences followed by a word byte; bail past the cap before serde_yml
/// expands them.
fn precheck_yaml_anchors(bytes: &[u8]) -> Result<(), AgentConfigError> {
    let mut anchors = 0usize;
    let mut aliases = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if (b == b'&' || b == b'*') && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            let is_word = next.is_ascii_alphanumeric() || next == b'_' || next == b'-';
            if is_word {
                if b == b'&' {
                    anchors += 1;
                    if anchors > MAX_YAML_ANCHORS {
                        return Err(AgentConfigError::YamlAnchorAmplification(anchors));
                    }
                } else {
                    aliases += 1;
                    if aliases > MAX_YAML_ALIASES {
                        return Err(AgentConfigError::YamlAnchorAmplification(aliases));
                    }
                }
            }
        }
        i += 1;
    }
    Ok(())
}

/// Parse the `agents:` hierarchy from an already-read `.agent/config.yaml` snapshot
/// (shares the bytes `wire_capabilities` already read — no second disk read, no
/// TOCTOU window).
///
/// - `None` (no config) ⇒ `Ok(empty)` — root-only boot, byte-identical to
///   pre-Wave-17.
/// - A config that does not parse as YAML at all ⇒ `Ok(empty)` — same graceful
///   degradation as [`yaml_declares_active_capability`] (no boot regression for
///   already-broken configs).
/// - No `agents:` key ⇒ `Ok(empty)`.
/// - The `agents:` key EXISTS but is malformed / over-budget ⇒ `Err` (fail-closed:
///   the declared hierarchy is wrong, so abort boot rather than silently materialize
///   a partial / different tree).
/// - **Whole-doc fail-closed guard**: the anchor/alias amplification precheck runs
///   on the ENTIRE config before this function's lenient `from_slice` (it MUST precede
///   it — serde_yml expands aliases during that parse). A config exceeding the cap
///   therefore yields `Err` even with no `agents:` key. This is the safe direction
///   (rejecting a DoS-shaped input) and fires only for pathological configs
///   (≥ `MAX_YAML_ANCHORS`/`MAX_YAML_ALIASES` patterns); a normal `agents:`-less
///   config stays well under the cap and returns `Ok(empty)`. Scope note: this is
///   defense-in-depth for THIS function's parse only — [`yaml_declares_active_capability`]
///   (the capability gate) parses the same bytes EARLIER in boot WITHOUT this guard,
///   so the system-level bound on a billion-laughs payload remains the 1 MiB
///   [`read_agent_yaml`] read cap; adding the precheck to the capability gate is a
///   pre-existing concern outside this additive lane.
pub fn parse_agents_config(yaml: Option<&[u8]>) -> Result<Vec<AgentDecl>, AgentConfigError> {
    let Some(bytes) = yaml else {
        return Ok(Vec::new());
    };
    // Defense-in-depth guard BEFORE this function's lenient parse: bounds serde_yml's
    // parse-time alias expansion for the `from_slice` below. (The capability gate
    // parses the same bytes earlier unguarded; the shared hard bound is the 1 MiB
    // read_agent_yaml cap. See the doc-comment's scope note.)
    precheck_yaml_anchors(bytes)?;
    // Lenient whole-doc parse: matches the capability gate's posture so a
    // wholly-unparseable config keeps booting (cap-less, root-only) instead of newly
    // failing.
    let Ok(value) = serde_yml::from_slice::<serde_yml::Value>(bytes) else {
        return Ok(Vec::new());
    };
    let Some(agents_val) = value
        .as_mapping()
        .and_then(|m| m.get(serde_yml::Value::String("agents".into())))
    else {
        return Ok(Vec::new());
    };
    // Strict from here: the `agents:` key is present, so a malformed sub-tree is a
    // loud error (typed shape + `deny_unknown_fields`).
    let decls: Vec<AgentDecl> = serde_yml::from_value(agents_val.clone())
        .map_err(|e| AgentConfigError::Parse(e.to_string()))?;
    let mut seen = std::collections::HashSet::new();
    let mut count = 0usize;
    validate_decls(&decls, 1, &mut seen, &mut count)?;
    Ok(decls)
}

/// Recursive validation of a declared sub-tree: alias charset (cap-lifecycle
/// `validate_agent_id`), GLOBAL alias uniqueness (each alias becomes a distinct
/// `AgentId` — a cross-parent duplicate would otherwise fail `spawn_child` with
/// `AlreadyExists` mid-materialization), node-count cap, depth cap. `depth` is
/// 1-based (top-level children are depth 1 under the depth-0 root).
fn validate_decls(
    decls: &[AgentDecl],
    depth: usize,
    seen: &mut std::collections::HashSet<String>,
    count: &mut usize,
) -> Result<(), AgentConfigError> {
    if depth > MAX_AGENT_TREE_DEPTH {
        return Err(AgentConfigError::TooDeep(depth));
    }
    for d in decls {
        cap_lifecycle::validate_agent_id(&d.alias)
            .map_err(|_| AgentConfigError::InvalidAlias(d.alias.clone()))?;
        if !seen.insert(d.alias.clone()) {
            return Err(AgentConfigError::DuplicateAlias(d.alias.clone()));
        }
        validate_declared_capabilities(&d.capabilities)?;
        *count += 1;
        if *count > MAX_AGENT_TREE_NODES {
            return Err(AgentConfigError::TooManyNodes(*count));
        }
        validate_decls(&d.children, depth + 1, seen, count)?;
    }
    Ok(())
}

/// Validate a declaration's `capabilities:` list: bounded, each id `^[A-Za-z0-9_-]{1,64}$`
/// (the cap-lifecycle id charset — never a `:`-scoped form), no duplicates.
pub fn validate_declared_capabilities(capabilities: &[String]) -> Result<(), AgentConfigError> {
    if capabilities.len() > MAX_DECLARED_CAPABILITIES {
        return Err(AgentConfigError::InvalidCapability(format!(
            "{} entries > {MAX_DECLARED_CAPABILITIES}",
            capabilities.len()
        )));
    }
    for (i, cap) in capabilities.iter().enumerate() {
        cap_lifecycle::validate_agent_id(cap)
            .map_err(|_| AgentConfigError::InvalidCapability(cap.clone()))?;
        if capabilities[..i].iter().any(|c| c == cap) {
            return Err(AgentConfigError::InvalidCapability(format!(
                "duplicate {cap}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(caps: &[CapRequest]) -> Vec<&str> {
        caps.iter().map(|c| c.capability.as_str()).collect()
    }

    #[test]
    fn scaffold_fs_llm_yields_fs_and_llm() {
        let yaml = b"capabilities:\n  fs: true\n  llm: true\n";
        // KNOWN order is [secrets, fs, skills, memory, grant, llm, tools].
        assert_eq!(names(&active_capabilities(Some(yaml))), vec!["fs", "llm"]);
    }

    #[test]
    fn single_fs_only() {
        let yaml = b"capabilities:\n  fs: true\n";
        assert_eq!(names(&active_capabilities(Some(yaml))), vec!["fs"]);
    }

    #[test]
    fn explicit_false_is_inactive() {
        let yaml = b"capabilities:\n  fs: false\n  llm: true\n";
        assert_eq!(names(&active_capabilities(Some(yaml))), vec!["llm"]);
    }

    #[test]
    fn absent_yaml_is_empty() {
        assert!(active_capabilities(None).is_empty());
    }

    #[test]
    fn mapping_value_is_active() {
        // `secrets: { auto-grant: false }` is still L0-active.
        let yaml = b"capabilities:\n  secrets:\n    auto-grant: false\n  fs: true\n";
        assert_eq!(
            names(&active_capabilities(Some(yaml))),
            vec!["secrets", "fs"]
        );
    }

    #[test]
    fn no_capabilities_key_is_empty() {
        let yaml = b"agent_id: foo\n";
        assert!(active_capabilities(Some(yaml)).is_empty());
        assert!(!yaml_declares_active_capability(yaml, "fs"));
    }

    #[test]
    fn parse_error_is_inactive() {
        let yaml = b"{ this is not: valid: yaml";
        assert!(!yaml_declares_active_capability(yaml, "fs"));
    }

    // ── await-leg B-4a — the messaging capability flip (the keystone) ──

    #[test]
    fn known_capabilities_includes_genui() {
        assert!(KNOWN_CAPABILITIES.contains(&"genui"));
        let yaml = b"capabilities:\n  genui: true\n";
        assert_eq!(names(&active_capabilities(Some(yaml))), vec!["genui"]);
        let undeclared = b"capabilities:\n  fs: true\n  llm: true\n";
        let caps = active_capabilities(Some(undeclared));
        let got = names(&caps);
        assert!(
            !got.contains(&"genui"),
            "undeclared yaml must not yield a genui CapRequest: {got:?}"
        );
    }

    #[test]
    fn known_capabilities_includes_messaging() {
        // The keystone: with `"messaging"` in KNOWN_CAPABILITIES, a `messaging:true`
        // config yields a `messaging` CapRequest the agent loop injects into the
        // guest linker (start.rs `caps = active_capabilities(..)`), so a guest that
        // imports `agent-messaging` LINKS the interface and can park on await-replies.
        assert!(KNOWN_CAPABILITIES.contains(&"messaging"));
        let yaml = b"capabilities:\n  messaging: true\n";
        assert_eq!(names(&active_capabilities(Some(yaml))), vec!["messaging"]);
    }

    #[test]
    fn messaging_inactive_unless_declared() {
        // DORMANT for non-declaring agents: a config NOT declaring messaging yields
        // NO messaging CapRequest, so the guest never links it (zero-flip honesty —
        // shipped/scaffold configs declare only {fs, llm}, never messaging).
        let yaml = b"capabilities:\n  fs: true\n  llm: true\n";
        let caps = active_capabilities(Some(yaml));
        let got = names(&caps);
        assert!(
            !got.contains(&"messaging"),
            "messaging must stay inactive: {got:?}"
        );
        assert_eq!(got, vec!["fs", "llm"]);
    }

    // ── Wave-17 Lane 3 (MODULE-005-AC-25) — `agents:` hierarchy parse/validate ──

    #[test]
    fn no_config_is_empty_hierarchy() {
        // None (no .agent/config.yaml) ⇒ root-only boot (byte-identical to pre-Wave-17).
        assert_eq!(parse_agents_config(None).unwrap(), Vec::new());
    }

    #[test]
    fn no_agents_key_is_empty_hierarchy() {
        // A config declaring only capabilities ⇒ no declared children.
        let yaml = b"capabilities:\n  fs: true\n  llm: true\n";
        assert_eq!(parse_agents_config(Some(yaml)).unwrap(), Vec::new());
    }

    #[test]
    fn wholly_unparseable_config_degrades_to_empty() {
        // Matches the lenient capability gate: a broken config keeps booting
        // (root-only) rather than newly failing — no boot regression.
        let yaml = b"{ not: valid: yaml [";
        assert_eq!(parse_agents_config(Some(yaml)).unwrap(), Vec::new());
    }

    #[test]
    fn nested_hierarchy_parses() {
        let yaml = b"\
agents:
  - alias: child-a
    template: explorer
    target-path: children/a
    children:
      - alias: grandchild
        template: planner
        target-path: g
  - alias: child-b
    template: reviewer
    target-path: children/b
";
        let decls = parse_agents_config(Some(yaml)).unwrap();
        assert_eq!(decls.len(), 2);
        assert_eq!(decls[0].alias, "child-a");
        assert_eq!(decls[0].template, "explorer");
        assert_eq!(decls[0].target_path, PathBuf::from("children/a"));
        assert_eq!(decls[0].children.len(), 1);
        assert_eq!(decls[0].children[0].alias, "grandchild");
        assert_eq!(decls[0].children[0].target_path, PathBuf::from("g"));
        assert_eq!(decls[1].alias, "child-b");
        assert!(decls[1].children.is_empty());
    }

    #[test]
    fn declared_capabilities_parse_and_validate() {
        let yaml = b"\
agents:
  - alias: r
    template: explorer
    target-path: r
    capabilities: [fs, llm]
";
        let decls = parse_agents_config(Some(yaml)).unwrap();
        assert_eq!(
            decls[0].capabilities,
            vec!["fs".to_string(), "llm".to_string()]
        );
        // Absent ⇒ empty (backward compatible).
        let yaml = b"agents:\n  - alias: r\n    template: explorer\n    target-path: r\n";
        assert!(parse_agents_config(Some(yaml)).unwrap()[0]
            .capabilities
            .is_empty());
        for bad in [
            "capabilities: [\"a b\"]",
            "capabilities: [\"cap:x\"]",
            "capabilities: [fs, fs]",
            "capabilities: [\"\"]",
        ] {
            let yaml = format!(
                "agents:\n  - alias: r\n    template: explorer\n    target-path: r\n    {bad}\n"
            );
            assert!(
                matches!(
                    parse_agents_config(Some(yaml.as_bytes())),
                    Err(AgentConfigError::InvalidCapability(_))
                ),
                "{bad}"
            );
        }
        let many: Vec<String> = (0..=MAX_DECLARED_CAPABILITIES)
            .map(|i| format!("c{i}"))
            .collect();
        assert!(matches!(
            validate_declared_capabilities(&many),
            Err(AgentConfigError::InvalidCapability(_))
        ));
    }

    #[test]
    fn unknown_field_in_agents_is_loud_error() {
        // deny_unknown_fields: a present-but-malformed `agents:` block fails loudly
        // (NOT a silent drop), since the operator explicitly declared a hierarchy.
        let yaml = b"\
agents:
  - alias: x
    template: explorer
    target-path: x
    bogus: 1
";
        assert!(matches!(
            parse_agents_config(Some(yaml)),
            Err(AgentConfigError::Parse(_))
        ));
    }

    #[test]
    fn invalid_alias_is_rejected() {
        let yaml = b"\
agents:
  - alias: \"bad id!!\"
    template: explorer
    target-path: x
";
        assert!(matches!(
            parse_agents_config(Some(yaml)),
            Err(AgentConfigError::InvalidAlias(_))
        ));
    }

    #[test]
    fn duplicate_alias_across_tree_is_rejected() {
        // Same alias under two different parents → would collide as one AgentId.
        let yaml = b"\
agents:
  - alias: dup
    template: explorer
    target-path: a
    children:
      - alias: dup
        template: planner
        target-path: b
";
        assert!(matches!(
            parse_agents_config(Some(yaml)),
            Err(AgentConfigError::DuplicateAlias(_))
        ));
    }

    #[test]
    fn over_deep_hierarchy_is_rejected() {
        // Build MAX_AGENT_TREE_DEPTH + 1 levels of single-child nesting.
        let mut yaml = String::from("agents:\n");
        let mut indent = String::from("  ");
        for i in 0..=MAX_AGENT_TREE_DEPTH {
            yaml.push_str(&format!("{indent}- alias: a{i}\n"));
            yaml.push_str(&format!("{indent}  template: explorer\n"));
            yaml.push_str(&format!("{indent}  target-path: d{i}\n"));
            yaml.push_str(&format!("{indent}  children:\n"));
            indent.push_str("    ");
        }
        // Innermost child has no further children (drop the trailing `children:`).
        let yaml = yaml.trim_end().trim_end_matches("children:").to_string();
        assert!(matches!(
            parse_agents_config(Some(yaml.as_bytes())),
            Err(AgentConfigError::TooDeep(_))
        ));
    }

    #[test]
    fn anchor_amplification_is_rejected() {
        let mut yaml = String::from("agents:\n");
        for i in 0..(MAX_YAML_ALIASES + 5) {
            yaml.push_str(&format!("ref{i}: *a{i}\n"));
        }
        assert!(matches!(
            parse_agents_config(Some(yaml.as_bytes())),
            Err(AgentConfigError::YamlAnchorAmplification(_))
        ));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane agent-llm-policy (2026-09-16) — the per-agent `llm:` policy block.
//
// `<workspace>/.agent/config.yaml`:
//
//   llm:
//     provider: local            # llm-providers[].id, optional
//     model: tiny                # alias key or literal model id, optional
//     constraint: always-local   # always-local | never-cloud | device:<id>, optional
//
// Same reading posture as `agents:`: a wholly-unparseable document degrades to
// "no block"; a PRESENT but malformed block is a loud error. The API path
// (client_api_agents.rs) refuses such a block; the call path
// (agent_llm_policy.rs) treats it as absent and emits `agent.llm_policy_invalid`.
// ─────────────────────────────────────────────────────────────────────────────

/// Bound on an `llm.model` hint (mirrors the client-api `MAX_LLM_MODEL_BYTES`).
pub const MAX_LLM_MODEL_BYTES: usize = 128;

/// The typed `llm:` block. `deny_unknown_fields` so a typo'd key fails loudly.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLlmDecl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint: Option<String>,
}

impl AgentLlmDecl {
    /// `true` when no field is set (an empty block is equivalent to no block).
    pub fn is_empty(&self) -> bool {
        self.provider.is_none() && self.model.is_none() && self.constraint.is_none()
    }
}

/// Validate a decoded block: provider id charset (`^[A-Za-z0-9_-]{1,64}$`), a bounded
/// single-token model hint, and the cap-llm constraint grammar.
pub fn validate_llm_decl(decl: &AgentLlmDecl) -> Result<(), AgentConfigError> {
    if let Some(provider) = &decl.provider {
        cap_lifecycle::validate_agent_id(provider).map_err(|_| {
            AgentConfigError::InvalidLlm(format!("invalid provider id {provider:?}"))
        })?;
    }
    if let Some(model) = &decl.model {
        if model.is_empty()
            || model.len() > MAX_LLM_MODEL_BYTES
            || model.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(AgentConfigError::InvalidLlm(
                "model must be a single token of at most 128 bytes".into(),
            ));
        }
    }
    if let Some(constraint) = &decl.constraint {
        cap_llm::parse_constraint(constraint)
            .map_err(|e| AgentConfigError::InvalidLlm(e.to_string()))?;
    }
    Ok(())
}

/// Parse the `llm:` block from an already-read `.agent/config.yaml` snapshot.
///
/// - `None` (no config) / a document that does not parse as YAML / no `llm:` key ⇒ `Ok(None)`.
/// - `llm:` present ⇒ strict: typed shape (`deny_unknown_fields`) + [`validate_llm_decl`];
///   an empty mapping (`llm: {}`) or `llm:` with no fields ⇒ `Ok(None)`.
/// - The same anchor/alias amplification guard as [`parse_agents_config`] runs first.
pub fn parse_agent_llm_config(
    yaml: Option<&[u8]>,
) -> Result<Option<AgentLlmDecl>, AgentConfigError> {
    let Some(bytes) = yaml else {
        return Ok(None);
    };
    precheck_yaml_anchors(bytes)?;
    let Ok(value) = serde_yml::from_slice::<serde_yml::Value>(bytes) else {
        return Ok(None);
    };
    let Some(llm_val) = value
        .as_mapping()
        .and_then(|m| m.get(serde_yml::Value::String("llm".into())))
    else {
        return Ok(None);
    };
    if llm_val.is_null() {
        return Ok(None);
    }
    if !llm_val.is_mapping() {
        return Err(AgentConfigError::InvalidLlm(
            "llm must be a mapping of provider / model / constraint".into(),
        ));
    }
    let decl: AgentLlmDecl = serde_yml::from_value(llm_val.clone())
        .map_err(|e| AgentConfigError::InvalidLlm(e.to_string()))?;
    validate_llm_decl(&decl)?;
    Ok(if decl.is_empty() { None } else { Some(decl) })
}

/// Replace (or, with `None` / an empty decl, remove) the top-level `llm:` key of a config
/// document mapping, leaving every other key untouched. The caller writes the document.
pub fn upsert_llm_block(doc: &mut serde_yml::Mapping, decl: Option<&AgentLlmDecl>) {
    let key = serde_yml::Value::String("llm".into());
    match decl {
        Some(d) if !d.is_empty() => {
            let value = serde_yml::to_value(d).expect("AgentLlmDecl serializes");
            doc.insert(key, value);
        }
        _ => {
            doc.remove(&key);
        }
    }
}

#[cfg(test)]
mod llm_tests {
    use super::*;

    #[test]
    fn llm_block_parses_and_validates() {
        let yaml = b"capabilities:\n  llm: true\nllm:\n  provider: local\n  model: tiny\n  constraint: always-local\n";
        let decl = parse_agent_llm_config(Some(yaml)).unwrap().unwrap();
        assert_eq!(decl.provider.as_deref(), Some("local"));
        assert_eq!(decl.model.as_deref(), Some("tiny"));
        assert_eq!(decl.constraint.as_deref(), Some("always-local"));
        // Partial blocks are fine.
        let decl = parse_agent_llm_config(Some(b"llm:\n  model: sonnet\n"))
            .unwrap()
            .unwrap();
        assert!(decl.provider.is_none() && decl.constraint.is_none());
        assert_eq!(decl.model.as_deref(), Some("sonnet"));
        // device pin
        let decl = parse_agent_llm_config(Some(b"llm:\n  constraint: device:mac-1\n"))
            .unwrap()
            .unwrap();
        assert_eq!(decl.constraint.as_deref(), Some("device:mac-1"));
    }

    #[test]
    fn absent_empty_or_unparseable_is_none() {
        assert!(parse_agent_llm_config(None).unwrap().is_none());
        assert!(parse_agent_llm_config(Some(b"capabilities:\n  fs: true\n"))
            .unwrap()
            .is_none());
        assert!(parse_agent_llm_config(Some(b"llm: {}\n"))
            .unwrap()
            .is_none());
        assert!(parse_agent_llm_config(Some(b"llm:\n")).unwrap().is_none());
        // Whole-document breakage degrades like the capability gate (no boot regression).
        assert!(parse_agent_llm_config(Some(b"{ not: valid: yaml ["))
            .unwrap()
            .is_none());
    }

    #[test]
    fn present_but_malformed_block_is_loud() {
        for (yaml, label) in [
            (&b"llm:\n  providr: local\n"[..], "unknown key"),
            (b"llm: local\n", "scalar block"),
            (b"llm:\n  - provider: local\n", "sequence block"),
            (b"llm:\n  provider: \"agent:x\"\n", "provider charset"),
            (b"llm:\n  provider: \"\"\n", "provider empty"),
            (b"llm:\n  model: \"a b\"\n", "model whitespace"),
            (b"llm:\n  constraint: gpu-only\n", "constraint grammar"),
            (b"llm:\n  constraint: \"device:\"\n", "device empty"),
            (b"llm:\n  provider: [a]\n", "provider type"),
        ] {
            assert!(
                matches!(
                    parse_agent_llm_config(Some(yaml)),
                    Err(AgentConfigError::InvalidLlm(_))
                ),
                "{label}"
            );
        }
        let long = format!("llm:\n  model: {}\n", "x".repeat(MAX_LLM_MODEL_BYTES + 1));
        assert!(matches!(
            parse_agent_llm_config(Some(long.as_bytes())),
            Err(AgentConfigError::InvalidLlm(_))
        ));
        let ok = format!("llm:\n  model: {}\n", "x".repeat(MAX_LLM_MODEL_BYTES));
        assert!(parse_agent_llm_config(Some(ok.as_bytes()))
            .unwrap()
            .is_some());
    }

    #[test]
    fn upsert_preserves_other_keys_and_round_trips() {
        let mut doc: serde_yml::Mapping = serde_yml::from_str(
            "capabilities:\n  fs: true\nagents:\n  - alias: r\n    template: explorer\n    target-path: r\n",
        )
        .unwrap();
        upsert_llm_block(
            &mut doc,
            Some(&AgentLlmDecl {
                provider: Some("local".into()),
                model: None,
                constraint: Some("never-cloud".into()),
            }),
        );
        let text = serde_yml::to_string(&serde_yml::Value::Mapping(doc.clone())).unwrap();
        assert!(text.contains("capabilities:") && text.contains("agents:"));
        let decl = parse_agent_llm_config(Some(text.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(decl.provider.as_deref(), Some("local"));
        assert!(decl.model.is_none(), "None fields are not written");
        assert_eq!(decl.constraint.as_deref(), Some("never-cloud"));
        // Replace, then clear.
        upsert_llm_block(
            &mut doc,
            Some(&AgentLlmDecl {
                model: Some("tiny".into()),
                ..Default::default()
            }),
        );
        let text = serde_yml::to_string(&serde_yml::Value::Mapping(doc.clone())).unwrap();
        let decl = parse_agent_llm_config(Some(text.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(
            decl,
            AgentLlmDecl {
                model: Some("tiny".into()),
                ..Default::default()
            }
        );
        upsert_llm_block(&mut doc, Some(&AgentLlmDecl::default()));
        assert!(!doc.contains_key(serde_yml::Value::String("llm".into())));
        upsert_llm_block(&mut doc, None);
        let text = serde_yml::to_string(&serde_yml::Value::Mapping(doc)).unwrap();
        assert!(parse_agent_llm_config(Some(text.as_bytes()))
            .unwrap()
            .is_none());
        assert!(text.contains("agents:"));
    }

    /// The client-api handler grammar and the cli/cap-llm grammar must agree on the same table
    /// (the handler cannot depend on cap-llm, so the grammar is spelled twice).
    #[test]
    fn constraint_grammar_agrees_with_client_api() {
        for c in [
            "always-local",
            "never-cloud",
            "device:phone",
            "device:mac.local:1",
            "",
            "Always-Local",
            " always-local",
            "device",
            "device:",
            "device:a b",
            "device:a/b",
            "cloud-only",
        ] {
            assert_eq!(
                cap_llm::parse_constraint(c).is_ok(),
                advance_client_api::agents::validate_llm_constraint(c).is_ok(),
                "{c:?}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Root identity — three names, three jobs (MODULE-005; `cap_lifecycle::identity`):
// the immutable `id` (UUID, every store's key), the addressable `handle`
// (mailbox `agent:<handle>`), and the free-text `display-name`.
// ─────────────────────────────────────────────────────────────────────────────

/// The root agent's resolved identity for this boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootIdentity {
    /// Immutable tree / cap-layer / persistence id.
    pub id: String,
    /// Addressable handle (`root` unless the config carries or derives another).
    pub handle: String,
}

impl RootIdentity {
    /// The root's mailbox / serve key.
    pub fn mailbox_id(&self) -> String {
        format!("agent:{}", self.handle)
    }
}

/// Top-level `handle` key of `.agent/config.yaml`.
pub const HANDLE_KEY: &str = "handle";

fn top_level_string(yaml: &[u8], key: &str) -> Option<String> {
    let v: serde_yml::Value = serde_yml::from_slice(yaml).ok()?;
    let s = v
        .as_mapping()?
        .get(serde_yml::Value::String(key.into()))?
        .as_str()?
        .trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Resolve — and persist on first sight — the root identity of `workspace`.
///
/// - `id`: the config's `id` key, else a fresh UUID written back (the persistence key
///   must survive restarts). A workspace without a `.agent/` directory (no config at
///   all) gets an ephemeral id: it declares no capabilities, so nothing is keyed by it.
/// - `handle`: the config's `handle` key when valid; else derived ONCE from
///   `display-name` (and written back, so a later rename never re-derives it); else
///   `root`.
pub fn resolve_root_identity(workspace: &Path) -> Result<RootIdentity, String> {
    use advance_shared_types::agent_tree::derive_agent_id;
    let agent_dir = workspace.join(".agent");
    let persisted = std::fs::symlink_metadata(&agent_dir)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false);
    if !persisted {
        return Ok(RootIdentity {
            id: cap_lifecycle::identity::new_agent_id(),
            handle: cap_lifecycle::identity::ROOT_HANDLE.to_string(),
        });
    }
    let id = cap_lifecycle::identity::ensure_agent_id(workspace)
        .map_err(|e| format!("root agent id: {e}"))?;
    let yaml = read_agent_yaml(workspace).unwrap_or_default();
    let handle = match top_level_string(&yaml, HANDLE_KEY) {
        Some(h) if cap_lifecycle::identifier::validate_agent_id(&h).is_ok() => h,
        Some(h) => return Err(format!("root handle {h:?} is not a valid agent id")),
        None => {
            let derived = top_level_string(&yaml, advance_home::DISPLAY_NAME_KEY)
                .and_then(|name| derive_agent_id(&name))
                .unwrap_or_else(|| cap_lifecycle::identity::ROOT_HANDLE.to_string());
            cap_lifecycle::identity::upsert_config_key(workspace, HANDLE_KEY, &derived)
                .map_err(|e| format!("persist root handle: {e}"))?;
            derived
        }
    };
    Ok(RootIdentity { id, handle })
}

/// Served mailbox key (`agent:<handle>`) or bare id → the tree id, via the tree's handle
/// registry. A colon key whose handle the tree does not know falls back to the handle itself
/// (the pre-identity mechanical form, so fixtures keyed id-as-handle keep working).
pub fn tree_id_for(
    tree: &dyn advance_shared_types::agent_tree::AgentTreeReader,
    reference: &str,
) -> String {
    match reference.strip_prefix("agent:") {
        Some(handle) => tree
            .id_by_handle(handle)
            .unwrap_or_else(|| handle.to_string()),
        None => reference.to_string(),
    }
}

/// Bare tree id → served mailbox key (`agent:<handle>`), via the tree's handle registry; an
/// id the tree does not know keeps the mechanical form.
pub fn mailbox_key_for(
    tree: &dyn advance_shared_types::agent_tree::AgentTreeReader,
    bare: &str,
) -> String {
    format!(
        "agent:{}",
        tree.handle_of(bare).unwrap_or_else(|| bare.to_string())
    )
}

#[cfg(test)]
mod root_identity_tests {
    use super::*;

    #[test]
    fn derives_handle_from_display_name_once() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        std::fs::create_dir_all(ws.join(".agent")).unwrap();
        std::fs::write(
            ws.join(".agent/config.yaml"),
            "capabilities:\n  fs: true\ndisplay-name: Soul Mate\n",
        )
        .unwrap();
        let first = resolve_root_identity(ws).unwrap();
        assert_eq!(first.handle, "soul-mate");
        assert_eq!(first.mailbox_id(), "agent:soul-mate");
        // A later rename does not move the handle or the id.
        std::fs::write(
            ws.join(".agent/config.yaml"),
            format!(
                "capabilities:\n  fs: true\ndisplay-name: Someone Else\nid: {}\nhandle: soul-mate\n",
                first.id
            ),
        )
        .unwrap();
        let again = resolve_root_identity(ws).unwrap();
        assert_eq!(again, first);
    }

    #[test]
    fn falls_back_to_root_and_ephemeral_without_config() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        std::fs::create_dir_all(ws.join(".agent")).unwrap();
        std::fs::write(ws.join(".agent/config.yaml"), "display-name: 灵魂伴侣\n").unwrap();
        let r = resolve_root_identity(ws).unwrap();
        assert_eq!(r.handle, "root");
        let text = std::fs::read_to_string(ws.join(".agent/config.yaml")).unwrap();
        assert!(text.contains("handle: root"), "{text}");
        let bare = tempfile::tempdir().unwrap();
        let e = resolve_root_identity(bare.path()).unwrap();
        assert_eq!(e.handle, "root");
        assert!(!bare.path().join(".agent").exists());
    }
}
