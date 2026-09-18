//! Installed packs → the running runtime.
//!
//! Every installed pack's `meta-schema-extensions/` are merged into the live meta-schema, its
//! `presets/` become known to the grant preset registry, and its skills' `tool.wasm` sidecars
//! are registered as `skill::<name>` tools. [`PackRuntime::apply`] recomputes all three from
//! the pack registry's current state, so the same call runs at boot, after every Client API
//! install / uninstall, and whenever the packs dir's `.meta.yaml` index changes (an
//! `advance pack install` run from a shell while the daemon runs, see
//! [`PackRuntime::spawn_packs_watcher`]). An install takes effect without a restart; an
//! uninstall takes the pack's contributions away again.
//!
//! - **In memory only.** The merged schema is never written back. The base is the
//!   workspace's `.agent/meta-schema.yaml` when present (re-read on every apply), else the
//!   built-in default ([`DEFAULT_META_SCHEMA_YAML`]). Pack extensions are merged on top in
//!   pack-name order with pack-manager's structured merge, and every candidate is dry-run
//!   parsed by cap-fs before it can replace the live schema.
//! - **Conflicts warn and skip.** A pack whose extension conflicts with the base or with a
//!   pack merged before it is skipped as a whole. A preset or skill tool whose name is
//!   already taken (a built-in preset, a workspace skill, another pack) is skipped. Nothing
//!   here blocks boot or fails an install; each distinct warning is logged once.
//! - **One version per pack.** When several versions of a pack are installed (mid-upgrade),
//!   only the highest applies.
//! - **Existing records follow.** A change of the effective schema re-projects the
//!   workspace's Markdown files into the entity index, so records gain (or lose) the pack's
//!   aspects without being rewritten.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use advance_pack_manager::meta_schema_merge::merge_documents;
use advance_pack_manager::registry::path_for_kind;
use advance_pack_manager::{ComponentKind, InMemoryPackRegistry, PackMetadata, PackRegistry};
use advance_shared_types::entity::EntityIndex;
use cap_fs::meta_schema::{MetaSchemaLoader, DEFAULT_META_SCHEMA_YAML};
use cap_fs::SchemaEntityProjector;
use cap_grant::preset::{Preset, PresetRegistry};
use cap_tools::LazyToolRegistry;
use sha2::{Digest, Sha256};

/// How often the packs dir's `.meta.yaml` index is polled for installs made by another
/// process (`advance pack install` while the daemon runs).
pub const PACKS_POLL_INTERVAL: Duration = Duration::from_secs(2);

const SKILL_TOOL_PREFIX: &str = "skill::";
/// Bound on the workspace schema file and on one pack extension document.
const MAX_SCHEMA_DOC_BYTES: u64 = 1024 * 1024;
/// The bound pack-manager applies to `.meta.yaml`.
const MAX_META_INDEX_BYTES: u64 = 10 * 1024 * 1024;

// ── pure composition ─────────────────────────────────────────────────────────────────────────

/// One pack's meta-schema extensions, in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSchemaExtensions {
    /// `name@version`.
    pub pack: String,
    /// `(extension name, document text)`.
    pub documents: Vec<(String, String)>,
}

/// The effective schema document and what went into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedSchema {
    pub yaml: String,
    /// Packs whose extensions are part of `yaml`, in merge order.
    pub merged: Vec<String>,
    pub warnings: Vec<String>,
}

/// Merge each pack's extensions onto `base`, pack by pack. A pack is all-or-nothing: if any
/// of its documents conflicts, or the merged result does not parse as a cap-fs schema, the
/// pack is skipped with a warning and the document stays as it was before that pack.
pub fn compose_schema(base: &str, packs: &[PackSchemaExtensions]) -> ComposedSchema {
    let mut yaml = base.to_string();
    let mut merged = Vec::new();
    let mut warnings = Vec::new();
    for pack in packs {
        let mut candidate = yaml.clone();
        let mut failure = None;
        for (name, document) in &pack.documents {
            match merge_documents(Some(&candidate), document) {
                Ok((next, _)) => candidate = next,
                Err(e) => {
                    failure = Some(format!("extension {name}: {e}"));
                    break;
                }
            }
        }
        if failure.is_none() {
            if let Err(e) = MetaSchemaLoader::from_yaml(PathBuf::new(), &candidate) {
                failure = Some(format!("the merged schema is rejected: {e}"));
            }
        }
        match failure {
            None => {
                yaml = candidate;
                merged.push(pack.pack.clone());
            }
            Some(why) => warnings.push(format!(
                "pack {}: meta-schema extensions skipped: {why}",
                pack.pack
            )),
        }
    }
    ComposedSchema {
        yaml,
        merged,
        warnings,
    }
}

fn label(pack: &PackMetadata) -> String {
    format!("{}@{}", pack.name, pack.version)
}

fn version_newer(a: &str, b: &str) -> bool {
    match (semver::Version::parse(a), semver::Version::parse(b)) {
        (Ok(a), Ok(b)) => a > b,
        _ => a > b,
    }
}

/// The highest installed version of each pack, in pack-name order; every other installed
/// version is reported in `warnings`.
fn effective_packs(installed: Vec<PackMetadata>, warnings: &mut Vec<String>) -> Vec<PackMetadata> {
    let mut newest: BTreeMap<String, PackMetadata> = BTreeMap::new();
    let mut shadowed = Vec::new();
    for pack in installed {
        let replace = match newest.get(&pack.name) {
            None => true,
            Some(current) => version_newer(&pack.version, &current.version),
        };
        if replace {
            if let Some(old) = newest.insert(pack.name.clone(), pack) {
                shadowed.push(old);
            }
        } else {
            shadowed.push(pack);
        }
    }
    for old in shadowed {
        warnings.push(format!(
            "pack {} is not applied: {} is installed too, and only the highest version applies",
            label(&old),
            label(&newest[&old.name])
        ));
    }
    newest.into_values().collect()
}

// ── file reads ───────────────────────────────────────────────────────────────────────────────

fn regular_file(path: &Path) -> Result<(), String> {
    let md = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if md.len() > MAX_SCHEMA_DOC_BYTES {
        return Err(format!(
            "{} is larger than {MAX_SCHEMA_DOC_BYTES} bytes",
            path.display()
        ));
    }
    Ok(())
}

fn read_pack_text(path: &Path) -> Result<String, String> {
    regular_file(path)?;
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The base schema document: the workspace file when present and valid, else the built-in
/// default (with a warning when a present file had to be ignored).
fn read_base_schema(path: &Path) -> (String, Option<String>) {
    let fallback = |why: String| {
        (
            DEFAULT_META_SCHEMA_YAML.to_string(),
            Some(format!(
                "workspace meta-schema {} is ignored ({why}); the built-in default is used",
                path.display()
            )),
        )
    };
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (DEFAULT_META_SCHEMA_YAML.to_string(), None)
        }
        Err(e) => return fallback(e.to_string()),
        Ok(_) => {}
    }
    let text = match read_pack_text(path) {
        Ok(text) => text,
        Err(why) => return fallback(why),
    };
    match MetaSchemaLoader::from_yaml(PathBuf::new(), &text) {
        Ok(_) => (text, None),
        Err(e) => fallback(e.to_string()),
    }
}

fn meta_index_fingerprint(packs_dir: &Path) -> Option<[u8; 32]> {
    let path = packs_dir.join(".meta.yaml");
    let md = std::fs::symlink_metadata(&path).ok()?;
    if !md.is_file() || md.len() > MAX_META_INDEX_BYTES {
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    Some(digest(&bytes))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

// ── the runtime applier ──────────────────────────────────────────────────────────────────────

struct SchemaTarget {
    loader: Arc<MetaSchemaLoader>,
    base_path: PathBuf,
}

struct EntityReindex {
    workspace_root: PathBuf,
    agent_id: String,
    index: Arc<dyn EntityIndex>,
}

#[derive(Default)]
struct Applied {
    schema_yaml: Option<String>,
    /// Pack preset name → owning pack.
    presets: BTreeMap<String, String>,
    /// Pack skill tool id → the registered bytes' digest.
    tools: BTreeMap<String, [u8; 32]>,
    /// Warnings already logged (each distinct one is logged once).
    warned: BTreeSet<String>,
}

/// What an [`PackRuntime::apply`] left in place.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackApplyReport {
    /// The applied pack set (`name@version`, highest version per pack), in pack-name order.
    pub packs: Vec<String>,
    /// Packs whose meta-schema extensions are part of the live schema.
    pub schema_packs: Vec<String>,
    pub schema_changed: bool,
    /// Aspects of the live schema after the apply.
    pub aspects: Vec<String>,
    /// Pack presets registered after the apply.
    pub presets: Vec<String>,
    /// Pack skill tools registered after the apply.
    pub tools: Vec<String>,
    pub warnings: Vec<String>,
    /// Files re-projected into the entity index after a schema change.
    pub reindexed_files: Option<usize>,
}

/// Applies the installed packs to the running runtime (module docs). The parts it feeds are
/// attached as the composition root builds them; an unattached part is simply skipped.
pub struct PackRuntime {
    registry: Arc<InMemoryPackRegistry>,
    packs_dir: PathBuf,
    schema: OnceLock<SchemaTarget>,
    presets: OnceLock<Arc<PresetRegistry>>,
    tools: OnceLock<Arc<LazyToolRegistry>>,
    reindex: OnceLock<EntityReindex>,
    state: tokio::sync::Mutex<Applied>,
}

impl PackRuntime {
    pub fn new(registry: Arc<InMemoryPackRegistry>, packs_dir: PathBuf) -> Self {
        Self {
            registry,
            packs_dir,
            schema: OnceLock::new(),
            presets: OnceLock::new(),
            tools: OnceLock::new(),
            reindex: OnceLock::new(),
            state: tokio::sync::Mutex::new(Applied::default()),
        }
    }

    /// The live meta-schema loader (the one cap-fs, the `.meta.yaml` maintainer and the
    /// `data` store read) and the workspace schema file used as the merge base.
    pub fn attach_schema(&self, loader: Arc<MetaSchemaLoader>, base_path: PathBuf) {
        let _ = self.schema.set(SchemaTarget { loader, base_path });
    }

    /// The ONE shared grant preset registry.
    pub fn attach_presets(&self, presets: Arc<PresetRegistry>) {
        let _ = self.presets.set(presets);
    }

    /// The tool registry the `tool-invoke` host fn and the `data` store's reducer use.
    pub fn attach_tools(&self, tools: Arc<LazyToolRegistry>) {
        let _ = self.tools.set(tools);
    }

    /// Where a schema change re-projects the workspace's Markdown files.
    pub fn attach_entity_reindex(
        &self,
        workspace_root: PathBuf,
        agent_id: String,
        index: Arc<dyn EntityIndex>,
    ) {
        let _ = self.reindex.set(EntityReindex {
            workspace_root,
            agent_id,
            index,
        });
    }

    pub fn packs_dir(&self) -> &Path {
        &self.packs_dir
    }

    pub fn registry(&self) -> &Arc<InMemoryPackRegistry> {
        &self.registry
    }

    pub fn schema_loader(&self) -> Option<Arc<MetaSchemaLoader>> {
        self.schema.get().map(|t| Arc::clone(&t.loader))
    }

    /// Recompute the live schema, pack presets and pack skill tools from the registry's
    /// current state (module docs). Serialized: concurrent callers apply one after another.
    pub async fn apply(&self) -> PackApplyReport {
        let mut state = self.state.lock().await;
        let mut report = PackApplyReport::default();
        let packs = effective_packs(self.registry.list_installed(), &mut report.warnings);
        report.packs = packs.iter().map(label).collect();

        if let Some(target) = self.schema.get() {
            let (base, warning) = read_base_schema(&target.base_path);
            report.warnings.extend(warning);
            let mut extensions = Vec::new();
            for pack in &packs {
                match self.schema_extensions(pack) {
                    Ok(e) if e.documents.is_empty() => {}
                    Ok(e) => extensions.push(e),
                    Err(why) => report.warnings.push(format!(
                        "pack {}: meta-schema extensions skipped: {why}",
                        label(pack)
                    )),
                }
            }
            let composed = compose_schema(&base, &extensions);
            report.warnings.extend(composed.warnings);
            report.schema_packs = composed.merged;
            if state.schema_yaml.as_deref() != Some(composed.yaml.as_str()) {
                match target.loader.reload_from_yaml(&composed.yaml) {
                    Ok(()) => {
                        state.schema_yaml = Some(composed.yaml);
                        report.schema_changed = true;
                    }
                    Err(e) => report.warnings.push(format!(
                        "the merged meta-schema was rejected on reload; the previous schema stays live: {e}"
                    )),
                }
            }
            report.aspects = target.loader.current().aspects.keys().cloned().collect();
        }
        if let Some(presets) = self.presets.get() {
            self.apply_presets(presets, &packs, &mut state, &mut report.warnings);
        }
        if let Some(tools) = self.tools.get() {
            self.apply_tools(tools, &packs, &mut state, &mut report.warnings)
                .await;
        }
        report.presets = state.presets.keys().cloned().collect();
        report.tools = state.tools.keys().cloned().collect();

        if report.schema_changed {
            if let (Some(reindex), Some(target)) = (self.reindex.get(), self.schema.get()) {
                let projector = SchemaEntityProjector::new(Arc::clone(&target.loader));
                report.reindexed_files = Some(
                    crate::data_wiring::seed_entity_index(
                        &reindex.workspace_root,
                        &reindex.agent_id,
                        &projector,
                        reindex.index.as_ref(),
                    )
                    .await,
                );
            }
        }

        let current: BTreeSet<String> = report.warnings.iter().cloned().collect();
        for warning in current.difference(&state.warned) {
            eprintln!("advance: WARN {warning}");
        }
        state.warned = current;
        report
    }

    /// Re-read the packs dir into the registry, then [`apply`](Self::apply).
    pub async fn sync_from_disk(&self) -> Result<PackApplyReport, advance_pack_manager::PackError> {
        self.registry.rescan().await?;
        Ok(self.apply().await)
    }

    /// Poll the packs dir's `.meta.yaml` index every `interval`; when it changes (an install
    /// or uninstall by another process), rescan the registry and apply. The task holds only a
    /// weak reference and ends once the runtime is dropped.
    pub fn spawn_packs_watcher(
        self: &Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let weak: Weak<Self> = Arc::downgrade(self);
        let packs_dir = self.packs_dir.clone();
        // The baseline is taken NOW, not when the task first runs: an install that lands
        // between this call and the first poll must still count as a change.
        let mut seen = meta_index_fingerprint(&packs_dir);
        tokio::spawn(async move {
            let mut failed_at: Option<Option<[u8; 32]>> = None;
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(this) = weak.upgrade() else { break };
                let now = meta_index_fingerprint(&packs_dir);
                if now == seen {
                    continue;
                }
                match this.registry.rescan().await {
                    Ok(()) => {
                        seen = now;
                        failed_at = None;
                        this.apply().await;
                    }
                    Err(e) => {
                        if failed_at != Some(now) {
                            eprintln!(
                                "advance: WARN the packs dir changed but its rescan failed (retrying): {e}"
                            );
                            failed_at = Some(now);
                        }
                    }
                }
            }
        })
    }

    fn provides_of(&self, pack: &PackMetadata, kind: ComponentKind) -> Vec<String> {
        self.registry
            .provides(&pack.name, &pack.version)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.kind == kind)
            .map(|p| p.name)
            .collect()
    }

    fn schema_extensions(&self, pack: &PackMetadata) -> Result<PackSchemaExtensions, String> {
        let mut documents = Vec::new();
        for name in self.provides_of(pack, ComponentKind::MetaSchemaExtension) {
            let path = path_for_kind(
                &pack.install_path,
                ComponentKind::MetaSchemaExtension,
                &name,
            );
            documents.push((name, read_pack_text(&path)?));
        }
        Ok(PackSchemaExtensions {
            pack: label(pack),
            documents,
        })
    }

    fn apply_presets(
        &self,
        presets: &PresetRegistry,
        packs: &[PackMetadata],
        state: &mut Applied,
        warnings: &mut Vec<String>,
    ) {
        let mut wanted: BTreeMap<String, (String, Preset)> = BTreeMap::new();
        for pack in packs {
            for file in self.provides_of(pack, ComponentKind::Preset) {
                let path = path_for_kind(&pack.install_path, ComponentKind::Preset, &file);
                let parsed = regular_file(&path).and_then(|()| {
                    PresetRegistry::parse_custom_yaml(&path).map_err(|e| e.to_string())
                });
                let preset = match parsed {
                    Ok(preset) => preset,
                    Err(why) => {
                        warnings.push(format!(
                            "pack {}: preset {file} skipped: {why}",
                            label(pack)
                        ));
                        continue;
                    }
                };
                if let Some((owner, _)) = wanted.get(&preset.name) {
                    warnings.push(format!(
                        "pack {}: preset {} skipped: already provided by {owner}",
                        label(pack),
                        preset.name
                    ));
                    continue;
                }
                if presets.contains(&preset.name) && !state.presets.contains_key(&preset.name) {
                    warnings.push(format!(
                        "pack {}: preset {} skipped: the name is already registered",
                        label(pack),
                        preset.name
                    ));
                    continue;
                }
                wanted.insert(preset.name.clone(), (label(pack), preset));
            }
        }
        let stale: Vec<String> = state
            .presets
            .keys()
            .filter(|name| !wanted.contains_key(*name))
            .cloned()
            .collect();
        for name in stale {
            presets.remove(&name);
            state.presets.remove(&name);
        }
        for (name, (pack, preset)) in wanted {
            match presets.insert(preset) {
                Ok(()) => {
                    state.presets.insert(name, pack);
                }
                Err(e) => warnings.push(format!("pack {pack}: preset {name} skipped: {e}")),
            }
        }
    }

    async fn apply_tools(
        &self,
        tools: &LazyToolRegistry,
        packs: &[PackMetadata],
        state: &mut Applied,
        warnings: &mut Vec<String>,
    ) {
        let mut wanted: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
        for pack in packs {
            for skill in self.provides_of(pack, ComponentKind::Skill) {
                let wasm = path_for_kind(&pack.install_path, ComponentKind::Skill, &skill)
                    .join("tool.wasm");
                if std::fs::symlink_metadata(&wasm).is_err() {
                    continue; // a knowledge-only skill carries no tool
                }
                if cap_skills::security_scan::validate_skill_name(&skill).is_err() {
                    warnings.push(format!(
                        "pack {}: skill tool {skill} skipped: not a valid skill name",
                        label(pack)
                    ));
                    continue;
                }
                let Some(bytes) = crate::wiring::read_regular_capped_bytes(
                    &wasm,
                    crate::wiring::MAX_SKILL_TOOL_WASM_BYTES,
                ) else {
                    warnings.push(format!(
                        "pack {}: skill tool {skill} skipped: tool.wasm is not a regular file of at most {} bytes",
                        label(pack),
                        crate::wiring::MAX_SKILL_TOOL_WASM_BYTES
                    ));
                    continue;
                };
                let id = format!("{SKILL_TOOL_PREFIX}{skill}");
                if let Some((owner, _)) = wanted.get(&id) {
                    warnings.push(format!(
                        "pack {}: skill tool {id} skipped: already provided by {owner}",
                        label(pack)
                    ));
                    continue;
                }
                if !state.tools.contains_key(&id) && tools.is_registered(&id).await {
                    warnings.push(format!(
                        "pack {}: skill tool {id} skipped: the id is already taken (a workspace skill of the same name wins)",
                        label(pack)
                    ));
                    continue;
                }
                wanted.insert(id, (label(pack), bytes));
            }
        }
        let stale: Vec<String> = state
            .tools
            .keys()
            .filter(|id| !wanted.contains_key(*id))
            .cloned()
            .collect();
        for id in stale {
            tools.unregister_binary(&id).await;
            state.tools.remove(&id);
        }
        for (id, (_pack, bytes)) in wanted {
            let digest = digest(&bytes);
            if state.tools.get(&id) != Some(&digest) {
                tools.register_binary(id.clone(), bytes).await;
            }
            state.tools.insert(id, digest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENDA: &str = include_str!("../../../packs/agenda/meta-schema-extensions/agenda.yaml");

    fn pack(name: &str, docs: &[(&str, &str)]) -> PackSchemaExtensions {
        PackSchemaExtensions {
            pack: name.to_string(),
            documents: docs
                .iter()
                .map(|(n, d)| (n.to_string(), d.to_string()))
                .collect(),
        }
    }

    fn parse(yaml: &str) -> cap_fs::meta_schema::MetaSchema {
        (*MetaSchemaLoader::from_yaml(PathBuf::new(), yaml)
            .expect("parses")
            .current())
        .clone()
    }

    #[test]
    fn agenda_merges_onto_the_default_without_losing_required_fields() {
        let composed = compose_schema(
            DEFAULT_META_SCHEMA_YAML,
            &[pack("agenda@0.1.0", &[("agenda", AGENDA)])],
        );
        assert!(composed.warnings.is_empty(), "{:?}", composed.warnings);
        assert_eq!(composed.merged, vec!["agenda@0.1.0"]);
        let schema = parse(&composed.yaml);
        assert!(schema.aspects.contains_key("agenda"));
        for field in ["id", "name", "slug", "description", "type"] {
            assert!(schema.required.contains_key(field), "{field} kept");
        }
        assert_eq!(schema.aspects["agenda"].operations.len(), 2);
    }

    #[test]
    fn a_conflicting_pack_is_skipped_whole_and_the_others_stay() {
        let rival = "aspect: agenda\nkey: [status]\nfields:\n  status:\n    type: [open, closed]\n";
        let extra = "optional:\n  mood:\n    type: string\n";
        let composed = compose_schema(
            DEFAULT_META_SCHEMA_YAML,
            &[
                pack("agenda@0.1.0", &[("agenda", AGENDA)]),
                pack("rival@1.0.0", &[("extra", extra), ("agenda", rival)]),
            ],
        );
        assert_eq!(composed.merged, vec!["agenda@0.1.0"]);
        assert_eq!(composed.warnings.len(), 1);
        assert!(
            composed.warnings[0].starts_with("pack rival@1.0.0:"),
            "{:?}",
            composed.warnings
        );
        let schema = parse(&composed.yaml);
        assert!(
            !schema.optional.contains_key("mood"),
            "the rival pack is all-or-nothing: its first, valid document is not kept either"
        );
        assert!(schema.aspects["agenda"].fields.contains_key("due"));
    }

    #[test]
    fn identical_redeclaration_is_idempotent() {
        let composed = compose_schema(
            DEFAULT_META_SCHEMA_YAML,
            &[
                pack("agenda@0.1.0", &[("agenda", AGENDA)]),
                pack("agenda-mirror@0.1.0", &[("agenda", AGENDA)]),
            ],
        );
        assert!(composed.warnings.is_empty(), "{:?}", composed.warnings);
        assert_eq!(composed.merged.len(), 2);
    }

    #[test]
    fn a_pack_conflicting_with_the_base_is_skipped() {
        // The default schema's optional `tags` is a list; redeclaring it differently conflicts.
        let clash = "optional:\n  tags:\n    type: string\n";
        let composed = compose_schema(
            DEFAULT_META_SCHEMA_YAML,
            &[pack("clash@1.0.0", &[("clash", clash)])],
        );
        assert!(composed.merged.is_empty());
        assert_eq!(composed.yaml, DEFAULT_META_SCHEMA_YAML);
        assert_eq!(composed.warnings.len(), 1);
    }

    #[test]
    fn only_the_highest_installed_version_applies() {
        let meta = |name: &str, version: &str| PackMetadata {
            name: name.into(),
            version: version.into(),
            install_path: PathBuf::from(format!("/p/{name}@{version}")),
            trust_level: advance_pack_manager::TrustLevel::Untrusted,
            required_capabilities: vec![],
            signed_by: None,
        };
        let mut warnings = Vec::new();
        let packs = effective_packs(
            vec![
                meta("agenda", "0.10.0"),
                meta("agenda", "0.9.1"),
                meta("zeta", "1.0.0"),
            ],
            &mut warnings,
        );
        assert_eq!(
            packs.iter().map(label).collect::<Vec<_>>(),
            vec!["agenda@0.10.0", "zeta@1.0.0"],
            "semver order, not string order"
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("agenda@0.9.1"), "{warnings:?}");
    }
}
