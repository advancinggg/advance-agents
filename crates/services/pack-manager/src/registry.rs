//! `PackRegistry` trait + `InMemoryPackRegistry` per MODULE-018 §2.3 / §2.6 verbatim.
//!
//! Slice A:
//! - `resolve(fq_ref)` supports prefixed `{pack}@{ver}/{kind-dir}/{name}` AND
//!   bare-name `{pack}@{ver}/{name}` (kind inferred by scanning all 11 `provides:`
//!   lists — the 10 §19.3 kinds + the AC-17 `resource-capabilities` category;
//!   ambiguity → `AmbiguousComponent`).
//! - Prefixed form verifies `{name}` is actually in the matching `provides:` list.
//! - `parse_fq_ref` rejects unversioned / empty-tail / null-byte / `..` traversal.
//! - `rescan(&self)` is async no-arg per §1.3.2 line 124; atomic read-build-swap.
//! - `resolve_pack_component` returns `NotImplemented` (AC-14 waived for Slice A).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use advance_shared_types::capability::CapRequest;

use crate::{
    error::PackError,
    install::verify_provides_on_disk,
    manifest::{PackManifest, PackProvides, TrustLevel},
    meta::read_meta_index,
};

pub trait PackRegistry: Send + Sync {
    fn list_installed(&self) -> Vec<PackMetadata>;
    /// Resolves a fully-qualified versioned ref of form `{pack}@{version}/{component}`.
    /// Unversioned refs return `PackError::UnversionedRef`.
    fn resolve(&self, fq_ref: &str) -> Result<PackResolution, PackError>;
    fn has(&self, name: &str, version: &str) -> bool;
    /// PRD §4.7.4 / REQ-073 — Slice A returns `NotImplemented` (AC-14 waived).
    fn resolve_pack_component(&self, fq_ref: &str) -> Result<PackComponentResolution, PackError>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct PackResolution {
    pub pack_name: String,
    pub version: String,
    pub component_kind: ComponentKind,
    pub local_path: PathBuf,
    pub manifest_snippet: PackProvideEntry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentKind {
    Binary,
    AgentTemplate,
    Skill,
    RunnableComponent,
    ChannelAdapter,
    McpServer,
    Preset,
    Workflow,
    MemorySeed,
    MetaSchemaExtension,
    /// Type 11 (AC-17, REQ-380) — pack-provided resource capability. Directory-backed:
    /// `resource-capabilities/{name}/capability.yaml`. Registered-not-copied (the preset
    /// precedent): install/rescan validate the manifest and the pack registry resolves the
    /// capability; nothing materializes into agent workspaces.
    ResourceCapability,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PackComponentResolution {
    pub binary: Vec<u8>,
    pub capabilities: Vec<CapRequest>,
    pub output_dir: PathBuf,
    pub manifest: ComponentManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackMetadata {
    pub name: String,
    pub version: String,
    pub install_path: PathBuf,
    pub trust_level: TrustLevel,
    pub required_capabilities: Vec<String>,
}

/// Slice A skeleton shape (full schema lands in Slice C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackProvideEntry {
    pub kind: ComponentKind,
    pub name: String,
}

/// Slice A skeleton shape for component.yaml (full PRD §4.3 schema in Slice C).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComponentManifest {
    pub component_type: String,
    pub raw_yaml: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// FQ-ref parser

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedFqRef {
    pub pack: String,
    pub version: String,
    pub component_path: String,
}

pub(crate) fn parse_fq_ref(fq: &str) -> Result<ParsedFqRef, PackError> {
    if fq.contains('\0') {
        return Err(PackError::UnversionedRef(fq.into()));
    }
    // ASCII-only gate (Adversarial round 2 Warning 6). FQ refs flow into
    // executor calls, audit-trail logs, and error messages. Non-ASCII +
    // ASCII-control bytes admit prompt-spoofing / log-confusion attacks
    // (e.g. `template: "pack@1.0.0/agent-templates/\x1b[31mFAKE\x1b[0m"`).
    if fq.chars().any(|c| !c.is_ascii() || c.is_ascii_control()) {
        return Err(PackError::UnversionedRef(fq.into()));
    }
    let (head, tail) = fq
        .split_once('/')
        .ok_or_else(|| PackError::UnversionedRef(fq.into()))?;
    let (pack, version) = head
        .split_once('@')
        .ok_or_else(|| PackError::UnversionedRef(fq.into()))?;
    if pack.is_empty() || version.is_empty() || tail.is_empty() {
        return Err(PackError::UnversionedRef(fq.into()));
    }
    for seg in tail.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(PackError::UnversionedRef(fq.into()));
        }
    }
    if pack.contains('@')
        || version.contains('@')
        || pack.contains('\\')
        || pack.contains('/')
        || pack.starts_with('.')
    {
        return Err(PackError::UnversionedRef(fq.into()));
    }
    // Defense-in-depth on `version` shape: `rescan()` joins the literal
    // `"{name}@{version}"` key into `packs_dir`, so a malformed version
    // (`..`, `/`, `\`, leading `.`) could escape the pack root even though
    // the standard ingestion path (`PackManifest::from_yaml`) gates this via
    // `semver::Version::parse`. Bypass paths exist for tests and future
    // less-trusted seed sources; harden here regardless.
    if version.contains('/')
        || version.contains('\\')
        || version == "."
        || version == ".."
        || version.starts_with('.')
    {
        return Err(PackError::UnversionedRef(fq.into()));
    }
    Ok(ParsedFqRef {
        pack: pack.into(),
        version: version.into(),
        component_path: tail.into(),
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// In-memory implementation

struct PackEntry {
    metadata: PackMetadata,
    manifest: PackManifest,
}

pub struct InMemoryPackRegistry {
    packs_dir: PathBuf,
    /// `.unwrap()` on `.read()` / `.write()` of this lock is the canonical Rust
    /// pattern for `std::sync::RwLock` poison handling: a poisoned lock means
    /// another thread panicked while holding it, in which case the registry
    /// state is potentially corrupt — recovering would risk surfacing partial
    /// updates. The lock-poison case panics the calling thread (same as the
    /// implicit panic-on-deadlock pattern), which is acceptable for Slice A's
    /// single-process admin-CLI invariant. If multi-thread contention becomes
    /// relevant in Slice B+, switch to `parking_lot::RwLock` (no poison
    /// semantics) or explicit `Result<RwLockReadGuard, PoisonError>` handling.
    packs: RwLock<BTreeMap<(String, String), PackEntry>>,
}

impl InMemoryPackRegistry {
    pub fn new(packs_dir: PathBuf) -> Self {
        Self {
            packs_dir,
            packs: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn packs_dir(&self) -> &Path {
        &self.packs_dir
    }

    /// Step ⑧ — async no-arg per MODULE-018 §1.3.2 line 124. Atomic read-build-swap:
    ///
    /// 1. Read `<packs_dir>/.meta.yaml`.
    /// 2. For each entry, parse `<packs_dir>/<name>@<version>/pack.yaml`.
    /// 3. Build new map locally. On ANY parse failure, return Err WITHOUT
    ///    touching `self.packs` (atomic abort — previous state preserved).
    /// 4. `std::mem::replace` swaps under a single write-lock acquisition.
    ///
    /// Concurrent readers see EITHER old OR new map, never a partial state.
    pub async fn rescan(&self) -> Result<(), PackError> {
        let idx = read_meta_index(&self.packs_dir)?;
        // Fresh-install boundary: if packs_dir doesn't exist yet (first
        // install hasn't run), treat as empty registry rather than surfacing
        // Io(NotFound). `read_meta_index` already handles the missing
        // .meta.yaml case; canonicalize requires the dir to exist.
        if !self.packs_dir.exists() {
            let mut guard = self.packs.write().unwrap();
            let _ = std::mem::take(&mut *guard);
            return Ok(());
        }
        let packs_dir_canon =
            std::fs::canonicalize(&self.packs_dir).map_err(|e| PackError::Io {
                path: self.packs_dir.clone(),
                source: e,
            })?;
        let mut new_map: BTreeMap<(String, String), PackEntry> = BTreeMap::new();
        for (key, entry) in &idx.packs {
            // Defense-in-depth: `.meta.yaml` keys are joined into `packs_dir`,
            // so a hand-edited or stale-tempfile-resurrected entry must not
            // contain path-separator characters, traversal segments, null
            // bytes, or leading dots that could escape the pack root.
            if key.contains('\0')
                || key.contains('/')
                || key.contains('\\')
                || key.starts_with('.')
                || key.contains("..")
                // Reject any non-ASCII codepoint OR ASCII control/whitespace.
                // Unicode invisible / control / format / whitespace codepoints
                // (zero-width space U+200B, non-breaking space U+00A0,
                // BiDi formatting marks, etc.) could visually impersonate ASCII
                // but resolve to a different filesystem path. (Round-9 W5.)
                // SemVer + pack-name grammar is ASCII-only, so a tight
                // ASCII-only gate is appropriate.
                || key.chars().any(|c| !c.is_ascii() || c.is_ascii_control() || c.is_ascii_whitespace())
            {
                return Err(PackError::InvalidManifest(format!(
                    ".meta.yaml key rejected (null/traversal/separator/non-ASCII/control/whitespace): {key:?}"
                )));
            }
            let (name, version) = key.split_once('@').ok_or_else(|| {
                PackError::InvalidManifest(format!(".meta.yaml key not `name@version`: {key}"))
            })?;
            if name.is_empty() || version.is_empty() {
                return Err(PackError::InvalidManifest(format!(
                    ".meta.yaml key empty name or version: {key}"
                )));
            }
            // Reject embedded `@` in name OR version. `split_once('@')` splits
            // on the FIRST `@`, so `foo@bar@1.0.0` would yield name="foo",
            // version="bar@1.0.0" — opening a spoofing vector against
            // `path_for_kind`-style consumers that re-split. (Round-9 W5.)
            if name.contains('@') || version.contains('@') {
                return Err(PackError::InvalidManifest(format!(
                    ".meta.yaml key has extra `@` (spoofing): {key:?}"
                )));
            }
            let install_path = self.packs_dir.join(key);
            // Ancestor check: confirm the joined path stays inside packs_dir
            // (canonicalize resolves any symlinks introduced post-hoc).
            let install_canon =
                std::fs::canonicalize(&install_path).map_err(|e| PackError::Io {
                    path: install_path.clone(),
                    source: e,
                })?;
            if !install_canon.starts_with(&packs_dir_canon) {
                return Err(PackError::InvalidManifest(format!(
                    ".meta.yaml entry escapes packs_dir: {key}"
                )));
            }
            let pack_yaml_path = install_path.join("pack.yaml");
            // Slice C adversarial round 13 W2 fix: rescan's pack.yaml
            // read previously used `std::fs::read_to_string`, which
            // followed a post-install symlink swap of `pack.yaml`. Reuse
            // the Slice C O_NOFOLLOW + fstat-on-FD + bounded read helper
            // for parity with `parse_component_manifest`. Cap at 1 MiB
            // matching `install.rs::MAX_PACK_YAML_BYTES`.
            let yaml = crate::component_manifest::open_text_nofollow_bounded(
                &pack_yaml_path,
                1024 * 1024,
                "pack.yaml",
            )?;
            let manifest = PackManifest::from_yaml(&yaml)?;
            // Cross-validate: pack.yaml's declared name@version MUST match
            // the .meta.yaml key, preventing a misnamed install directory
            // from masquerading as a different pack.
            if manifest.name != name || manifest.version != version {
                return Err(PackError::InvalidManifest(format!(
                    ".meta.yaml key {key} does not match pack.yaml {}@{}",
                    manifest.name, manifest.version
                )));
            }
            // Round-9 adversarial C1: cross-validate trust-level and
            // required-capabilities against pack.yaml. .meta.yaml is a
            // convenience index — pack.yaml is the source of truth. A
            // hand-edited .meta.yaml that claims `trust_level: Trusted`
            // for a pack whose pack.yaml declares Untrusted would have
            // surfaced as a privilege escalation in pre-fix code that
            // bound metadata fields straight from the entry.
            if manifest.trust_level != entry.trust_level {
                return Err(PackError::InvalidManifest(format!(
                    ".meta.yaml trust_level for {key} ({:?}) does not match pack.yaml ({:?}) — possible tamper",
                    entry.trust_level, manifest.trust_level
                )));
            }
            // Set-equality (order-insensitive). `required_capabilities` is
            // an unordered set of capability names; reordering the YAML
            // list should NOT trigger a tamper false-positive. Codex r2
            // Info finding.
            let mut entry_caps = entry.required_capabilities.clone();
            entry_caps.sort();
            let mut manifest_caps = manifest.required_capabilities.clone();
            manifest_caps.sort();
            if manifest_caps != entry_caps {
                return Err(PackError::InvalidManifest(format!(
                    ".meta.yaml required_capabilities for {key} does not match pack.yaml — possible tamper"
                )));
            }
            // Use manifest values authoritatively (pack.yaml is SSOT for
            // both fields; .meta.yaml entry only retains them as the
            // audit-time copy for admin review).
            // Re-run step ⑥a artifact existence/type check here too —
            // catches post-install tampering of declared `provides[*]`
            // (deletion, wrong-type swap, intermediate symlink). Codex r3
            // W1 defense. Cheap per-artifact stat; full re-checksumming is
            // intentionally NOT done here (Slice B concern — would
            // multiply rescan cost by total declared bytes).
            verify_provides_on_disk(&install_path, &manifest.provides)?;
            // AC-17: rescan re-checks resource-capability EXISTENCE (dir + inner
            // `capability.yaml`) cheaply via `verify_provides_on_disk` above. The full
            // ADR-shape PARSE (`verify_resource_capabilities`) is INSTALL-ONLY — matching
            // the `verify_skill_tool_exports` precedent and honoring this function's own
            // "don't multiply rescan cost by total declared bytes" invariant (a per-pack
            // 1-MiB × ≤256-capability parse on every rescan would be an availability
            // regression + would repeatedly re-run the bounded parse). A post-install
            // manifest-shape tamper is instead caught on-demand by
            // `register_resource_capability` (which re-parses + validates). (Adversarial
            // round 12: rescan re-parse fan-out + deep-nesting parse-DoS amplifier.)
            let metadata = PackMetadata {
                name: name.into(),
                version: version.into(),
                install_path,
                trust_level: manifest.trust_level,
                required_capabilities: manifest.required_capabilities.clone(),
            };
            new_map.insert(
                (name.into(), version.into()),
                PackEntry { metadata, manifest },
            );
        }
        // Atomic swap under write-lock.
        let mut guard = self.packs.write().unwrap();
        let _ = std::mem::replace(&mut *guard, new_map);
        Ok(())
    }
}

impl PackRegistry for InMemoryPackRegistry {
    fn list_installed(&self) -> Vec<PackMetadata> {
        self.packs
            .read()
            .unwrap()
            .values()
            .map(|e| e.metadata.clone())
            .collect()
    }

    fn resolve(&self, fq_ref: &str) -> Result<PackResolution, PackError> {
        let parsed = parse_fq_ref(fq_ref)?;
        let packs = self.packs.read().unwrap();
        let entry = packs
            .get(&(parsed.pack.clone(), parsed.version.clone()))
            .ok_or_else(|| PackError::PackNotFound(parsed.pack.clone(), parsed.version.clone()))?;

        let (kind, name) = match parsed.component_path.split_once('/') {
            Some((prefix, rest)) => {
                if rest.is_empty() || rest.contains('/') {
                    return Err(PackError::ComponentNotFound {
                        pack: parsed.pack.clone(),
                        version: parsed.version.clone(),
                        component: parsed.component_path.clone(),
                    });
                }
                let kind = kind_from_dir(prefix).ok_or_else(|| PackError::ComponentNotFound {
                    pack: parsed.pack.clone(),
                    version: parsed.version.clone(),
                    component: parsed.component_path.clone(),
                })?;
                let list = list_for_kind(&entry.manifest.provides, kind);
                if !list.iter().any(|n| n == rest) {
                    return Err(PackError::ComponentNotFound {
                        pack: parsed.pack.clone(),
                        version: parsed.version.clone(),
                        component: parsed.component_path.clone(),
                    });
                }
                (kind, rest.to_string())
            }
            None => find_kind_by_name_strict(
                &entry.manifest.provides,
                &parsed.component_path,
                &parsed.pack,
                &parsed.version,
            )?,
        };

        let local_path = path_for_kind(&entry.metadata.install_path, kind, &name);

        Ok(PackResolution {
            pack_name: parsed.pack,
            version: parsed.version,
            component_kind: kind,
            local_path,
            manifest_snippet: PackProvideEntry { kind, name },
        })
    }

    fn has(&self, name: &str, version: &str) -> bool {
        self.packs
            .read()
            .unwrap()
            .contains_key(&(name.into(), version.into()))
    }

    fn resolve_pack_component(&self, fq_ref: &str) -> Result<PackComponentResolution, PackError> {
        // (1) Resolve the FQ ref via the existing `resolve()` — validates
        //     grammar, kind discovery, provides-list membership.
        let resolution = self.resolve(fq_ref)?;

        // (2) AC-14 constraint surface: kind MUST be RunnableComponent.
        //     Caller wants an auto-loop evaluator, not a different artifact
        //     type.
        if resolution.component_kind != ComponentKind::RunnableComponent {
            return Err(PackError::ConstraintViolation {
                reason: format!(
                    "FQ ref must resolve to a runnable component (got {:?})",
                    resolution.component_kind
                ),
            });
        }

        // (3) Look up the pack's install_path via the BTreeMap lookup so we
        //     anchor `parse_component_manifest` at the canonical disk
        //     location.
        let packs = self.packs.read().unwrap();
        let entry = packs
            .get(&(resolution.pack_name.clone(), resolution.version.clone()))
            .ok_or_else(|| {
                PackError::PackNotFound(resolution.pack_name.clone(), resolution.version.clone())
            })?;
        let install_path = entry.metadata.install_path.clone();
        drop(packs);

        // (4) Parse + enforce PRD §4.7.4 constraint surface; read binary.
        let (binary, capabilities, output_dir, manifest) =
            crate::component_manifest::parse_component_manifest(
                &install_path,
                &resolution.manifest_snippet.name,
            )?;

        Ok(PackComponentResolution {
            binary,
            capabilities,
            output_dir,
            manifest,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers

fn kind_from_dir(prefix: &str) -> Option<ComponentKind> {
    Some(match prefix {
        "behavior-binaries" => ComponentKind::Binary,
        "agent-templates" => ComponentKind::AgentTemplate,
        "skills" => ComponentKind::Skill,
        "components" => ComponentKind::RunnableComponent,
        "channel-adapters" => ComponentKind::ChannelAdapter,
        "mcp-servers" => ComponentKind::McpServer,
        "presets" => ComponentKind::Preset,
        "workflows" => ComponentKind::Workflow,
        "memory-seeds" => ComponentKind::MemorySeed,
        "meta-schema-extensions" => ComponentKind::MetaSchemaExtension,
        "resource-capabilities" => ComponentKind::ResourceCapability,
        _ => return None,
    })
}

fn list_for_kind(p: &PackProvides, kind: ComponentKind) -> &Vec<String> {
    match kind {
        ComponentKind::Binary => &p.behavior_binaries,
        ComponentKind::AgentTemplate => &p.agent_templates,
        ComponentKind::Skill => &p.skills,
        ComponentKind::RunnableComponent => &p.components,
        ComponentKind::ChannelAdapter => &p.channel_adapters,
        ComponentKind::McpServer => &p.mcp_servers,
        ComponentKind::Preset => &p.presets,
        ComponentKind::Workflow => &p.workflows,
        ComponentKind::MemorySeed => &p.memory_seeds,
        ComponentKind::MetaSchemaExtension => &p.meta_schema_extensions,
        ComponentKind::ResourceCapability => &p.resource_capabilities,
    }
}

fn find_kind_by_name_strict(
    p: &PackProvides,
    name: &str,
    pack: &str,
    version: &str,
) -> Result<(ComponentKind, String), PackError> {
    let kinds = [
        ComponentKind::Binary,
        ComponentKind::AgentTemplate,
        ComponentKind::Skill,
        ComponentKind::RunnableComponent,
        ComponentKind::ChannelAdapter,
        ComponentKind::McpServer,
        ComponentKind::Preset,
        ComponentKind::Workflow,
        ComponentKind::MemorySeed,
        ComponentKind::MetaSchemaExtension,
        ComponentKind::ResourceCapability,
    ];
    let mut hits: Vec<ComponentKind> = Vec::new();
    for k in kinds {
        if list_for_kind(p, k).iter().any(|n| n == name) {
            hits.push(k);
        }
    }
    match hits.as_slice() {
        [] => Err(PackError::ComponentNotFound {
            pack: pack.into(),
            version: version.into(),
            component: name.into(),
        }),
        [k] => Ok((*k, name.to_string())),
        _ => Err(PackError::AmbiguousComponent {
            pack: pack.into(),
            version: version.into(),
            component: name.into(),
            kinds: hits,
        }),
    }
}

/// Canonical install-relative path per PRD §19.3 / MODULE-018 §2.5 layout.
/// File-backed kinds append the canonical extension; directory-backed kinds
/// return the named directory.
pub fn path_for_kind(install_path: &Path, kind: ComponentKind, name: &str) -> PathBuf {
    match kind {
        ComponentKind::Binary => install_path
            .join("behavior-binaries")
            .join(format!("{name}.wasm")),
        ComponentKind::McpServer => install_path
            .join("mcp-servers")
            .join(format!("{name}.yaml")),
        ComponentKind::Preset => install_path.join("presets").join(format!("{name}.yaml")),
        ComponentKind::Workflow => install_path.join("workflows").join(format!("{name}.yaml")),
        ComponentKind::MemorySeed => install_path
            .join("memory-seeds")
            .join(format!("{name}.jsonl")),
        ComponentKind::MetaSchemaExtension => install_path
            .join("meta-schema-extensions")
            .join(format!("{name}.yaml")),
        ComponentKind::AgentTemplate => install_path.join("agent-templates").join(name),
        ComponentKind::Skill => install_path.join("skills").join(name),
        ComponentKind::RunnableComponent => install_path.join("components").join(name),
        ComponentKind::ChannelAdapter => install_path.join("channel-adapters").join(name),
        // Directory-backed (type 11): `resource-capabilities/{name}/` holds the required
        // `capability.yaml` + capability-owned payload. verify_provides_on_disk checks the
        // inner manifest exists; verify_resource_capabilities parses/validates its shape.
        ComponentKind::ResourceCapability => install_path.join("resource-capabilities").join(name),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Slice C — AC-11 NamespaceResolver three-tier lookup chain.

/// Three-tier namespace lookup per MODULE-018 AC-11: agent-local →
/// `/.advance/` (admin) → runtime built-in. Each tier is a `PackRegistry`
/// impl; the resolver delegates `resolve(fq_ref)` and
/// `resolve_pack_component(fq_ref)` to the tiers in priority order.
///
/// Fall-through rule (per MODULE-018 §2.7 Slice C operational additions):
/// - `Ok(...)` short-circuits — tier owns the resolution.
/// - `PackError::PackNotFound` falls through to the next tier — tier does
///   NOT contain the requested `{pack}@{version}` at all.
/// - `PackError::ComponentNotFound` / `PackError::AmbiguousComponent`
///   propagate VERBATIM — tier owns the pack but the requested component
///   is missing/ambiguous within it. Falling through here would let an
///   agent-local pack's missing component silently resolve to the admin
///   tier's same-named pack's copy, violating the AC-11 priority contract.
/// - `PackError::UnversionedRef` / `PackError::ConstraintViolation` and
///   all other error variants bubble up immediately — these are
///   grammar / constraint failures, not tier-membership questions.
///
/// When every tier returns `PackNotFound`, surface a `PackNotFound`
/// naming the original FQ ref's parsed `{pack}@{version}` so the caller
/// sees what they asked for.
///
/// Slice C tier wiring: only `admin` is concretely populated; `agent_local`
/// + `builtin` are Optional and accept any `Arc<dyn PackRegistry>`. M005
///   agent-tree-lifecycle + M001 runtime-host built-in template registry
///   land in Slice C+.
pub struct NamespaceResolver {
    pub agent_local: Option<Arc<dyn PackRegistry>>,
    pub admin: Arc<dyn PackRegistry>,
    pub builtin: Option<Arc<dyn PackRegistry>>,
}

impl NamespaceResolver {
    pub fn new(admin: Arc<dyn PackRegistry>) -> Self {
        Self {
            agent_local: None,
            admin,
            builtin: None,
        }
    }

    pub fn with_agent_local(mut self, agent_local: Arc<dyn PackRegistry>) -> Self {
        self.agent_local = Some(agent_local);
        self
    }

    pub fn with_builtin(mut self, builtin: Arc<dyn PackRegistry>) -> Self {
        self.builtin = Some(builtin);
        self
    }

    /// Resolve an FQ ref through the three-tier chain. See struct rustdoc
    /// for the fall-through discipline.
    pub fn resolve(&self, fq_ref: &str) -> Result<PackResolution, PackError> {
        if let Some(reg) = &self.agent_local {
            match reg.resolve(fq_ref) {
                Ok(r) => return Ok(r),
                Err(PackError::PackNotFound(_, _)) => {}
                Err(other) => return Err(other),
            }
        }
        match self.admin.resolve(fq_ref) {
            Ok(r) => return Ok(r),
            Err(PackError::PackNotFound(_, _)) => {}
            Err(other) => return Err(other),
        }
        if let Some(reg) = &self.builtin {
            match reg.resolve(fq_ref) {
                Ok(r) => return Ok(r),
                Err(PackError::PackNotFound(_, _)) => {}
                Err(other) => return Err(other),
            }
        }
        // Every tier returned PackNotFound (or no tier configured). Surface
        // a final PackNotFound naming the original FQ ref's pack@version.
        let parsed = parse_fq_ref(fq_ref)?;
        Err(PackError::PackNotFound(parsed.pack, parsed.version))
    }

    /// Resolve an FQ ref to a Pack component with REQ-073 constraint
    /// surface validation. Same fall-through discipline as `resolve`.
    pub fn resolve_pack_component(
        &self,
        fq_ref: &str,
    ) -> Result<PackComponentResolution, PackError> {
        if let Some(reg) = &self.agent_local {
            match reg.resolve_pack_component(fq_ref) {
                Ok(r) => return Ok(r),
                Err(PackError::PackNotFound(_, _)) => {}
                Err(other) => return Err(other),
            }
        }
        match self.admin.resolve_pack_component(fq_ref) {
            Ok(r) => return Ok(r),
            Err(PackError::PackNotFound(_, _)) => {}
            Err(other) => return Err(other),
        }
        if let Some(reg) = &self.builtin {
            match reg.resolve_pack_component(fq_ref) {
                Ok(r) => return Ok(r),
                Err(PackError::PackNotFound(_, _)) => {}
                Err(other) => return Err(other),
            }
        }
        let parsed = parse_fq_ref(fq_ref)?;
        Err(PackError::PackNotFound(parsed.pack, parsed.version))
    }
}

impl InMemoryPackRegistry {
    /// Test-only helper — bypasses rescan/disk and inserts directly into the
    /// in-memory map. Not part of the production API surface. Doc-hidden so
    /// it does not appear in rustdoc output.
    #[doc(hidden)]
    pub fn upsert_for_test(&self, metadata: PackMetadata, manifest: PackManifest) {
        self.packs.write().unwrap().insert(
            (metadata.name.clone(), metadata.version.clone()),
            PackEntry { metadata, manifest },
        );
    }

    /// Slice B helper for recursive-dep dedup (AC-08 diamond case): returns ANY
    /// installed version of `name` whose parsed `Version` satisfies `req`.
    /// Iterates the BTreeMap in lexicographic `(name, version-string)` order —
    /// note this is string-lex order ("10.0.0" < "2.0.0"), NOT semver order, so
    /// the returned version is "any satisfying" rather than "smallest" or
    /// "highest". Diamond dedup only requires existence, so iteration order is
    /// irrelevant for correctness; future Slice C cargo-style resolution may
    /// need a semver-ordered variant.
    pub fn find_installed_satisfying(
        &self,
        name: &str,
        req: &semver::VersionReq,
    ) -> Option<semver::Version> {
        self.packs
            .read()
            .unwrap()
            .iter()
            .filter(|((n, _), _)| n == name)
            .filter_map(|((_, v), _)| semver::Version::parse(v).ok())
            .find(|v| req.matches(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t09_parse_prefixed() {
        let p = parse_fq_ref("pack-a@1.0.0/components/foo").unwrap();
        assert_eq!(p.pack, "pack-a");
        assert_eq!(p.version, "1.0.0");
        assert_eq!(p.component_path, "components/foo");
    }

    #[test]
    fn t10_reject_unversioned() {
        match parse_fq_ref("pack-a/foo") {
            Err(PackError::UnversionedRef(_)) => {}
            other => panic!("expected UnversionedRef, got {other:?}"),
        }
    }

    #[test]
    fn t11_reject_empty_version() {
        match parse_fq_ref("pack-a@/foo") {
            Err(PackError::UnversionedRef(_)) => {}
            other => panic!("expected UnversionedRef, got {other:?}"),
        }
    }

    #[test]
    fn t12_reject_empty_pack() {
        match parse_fq_ref("@1.0.0/foo") {
            Err(PackError::UnversionedRef(_)) => {}
            other => panic!("expected UnversionedRef, got {other:?}"),
        }
    }

    #[test]
    fn t24_reject_empty_tail() {
        match parse_fq_ref("pack-a@1.0.0/") {
            Err(PackError::UnversionedRef(_)) => {}
            other => panic!("expected UnversionedRef, got {other:?}"),
        }
    }

    #[test]
    fn t35_reject_traversal_tail() {
        match parse_fq_ref("pack-a@1.0.0/foo/../bar") {
            Err(PackError::UnversionedRef(_)) => {}
            other => panic!("expected UnversionedRef, got {other:?}"),
        }
    }

    #[test]
    fn t36_reject_null_byte_tail() {
        match parse_fq_ref("pack-a@1.0.0/foo\0bar") {
            Err(PackError::UnversionedRef(_)) => {}
            other => panic!("expected UnversionedRef, got {other:?}"),
        }
    }

    // ── MODULE-018-T94 (AC-17): bare-name resolution + cross-kind ambiguity for
    //    the resource-capabilities category. Pins the `find_kind_by_name_strict`
    //    11-array (non-compiler-forced — a missing element would silently drop the
    //    resource-capability hit and mis-resolve / mask ambiguity). Prefixed-ref
    //    resolution is covered by tests/materialize.rs + T89.
    #[test]
    fn t94_bare_resource_capability_resolves() {
        let p = PackProvides {
            resource_capabilities: vec!["structured-data".to_string()],
            ..Default::default()
        };
        let (kind, name) = find_kind_by_name_strict(&p, "structured-data", "pk", "1.0.0").unwrap();
        assert_eq!(kind, ComponentKind::ResourceCapability);
        assert_eq!(name, "structured-data");
    }

    #[test]
    fn t94_bare_resource_capability_ambiguous_across_kinds() {
        let p = PackProvides {
            resource_capabilities: vec!["dup".to_string()],
            skills: vec!["dup".to_string()],
            ..Default::default()
        };
        match find_kind_by_name_strict(&p, "dup", "pk", "1.0.0") {
            Err(PackError::AmbiguousComponent { kinds, .. }) => {
                assert!(kinds.contains(&ComponentKind::ResourceCapability));
                assert!(kinds.contains(&ComponentKind::Skill));
            }
            other => panic!("expected AmbiguousComponent, got {other:?}"),
        }
    }

    #[test]
    fn t94_bare_resource_capability_not_found() {
        let p = PackProvides::default();
        match find_kind_by_name_strict(&p, "nope", "pk", "1.0.0") {
            Err(PackError::ComponentNotFound { .. }) => {}
            other => panic!("expected ComponentNotFound, got {other:?}"),
        }
    }
}
