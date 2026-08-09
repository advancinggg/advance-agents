//! Slice C — `SkillStorage` trait + in-memory + disk-backed implementations.
//!
//! Storage layout per MODULE-017 §2.5 (cap-fs §6.5-compliant — drafts and
//! versions live as `.agent/_*` immediate children so cap-fs's hidden-name
//! walk fires):
//!
//! ```text
//! <agent_root>/
//!   .agent/
//!     _skill_drafts/{name}/SKILL.md + .meta.yaml      (hidden)
//!     _skill_versions/{name}/v{N}.md                  (hidden)
//!     skills/{name}/SKILL.md + .meta.yaml             (visible)
//! ```
//!
//! `DiskSkillStorage` uses `cap-fs::AtomicWriter` for atomic writes. The
//! cap-fs `atomic_write` does NOT create parent directories (per
//! `cap-fs/src/atomic.rs`) — Slice C explicitly calls
//! `tokio::fs::create_dir_all(parent)` before each write.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::SkillError;

/// On-disk shape of a draft. SKILL.md content + .meta.yaml sidecar.
///
/// Slice C: name-keyed (one draft per name; `propose_draft("foo", ...)` twice
/// overwrites). `parent` + `reason` distinguish patch drafts from fresh
/// drafts (both invariants must hold together: `parent.is_some() ==
/// reason.is_some()`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DraftBlob {
    pub name: String,
    pub content: String,
    pub tags: Vec<String>,
    /// `Some(skill_id)` on `propose_patch` drafts; `None` on fresh drafts.
    #[serde(default)]
    pub parent: Option<String>,
    /// `Some(reason)` on patch drafts; `None` on fresh drafts.
    /// Invariant: `parent.is_some() == reason.is_some()`.
    #[serde(default)]
    pub reason: Option<String>,
    /// ISO 8601 timestamp; populated by SkillStore on write.
    /// Used by the 24h sweep to identify expired drafts.
    pub created_at: DateTime<Utc>,
}

/// On-disk shape of an active skill. SKILL.md content + .meta.yaml sidecar
/// holding provenance + trust + version + tags.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillBlob {
    pub skill_id: String,
    pub version: u32,
    pub content: String,
    pub tags: Vec<String>,
    pub provenance: advance_shared_types::skills::Provenance,
    pub trust_level: advance_shared_types::skills::TrustLevel,
}

/// `.meta.yaml` shape for drafts.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DraftMeta {
    name: String,
    tags: Vec<String>,
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    created_at: DateTime<Utc>,
}

/// `.meta.yaml` shape for active skills.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveMeta {
    skill_id: String,
    version: u32,
    tags: Vec<String>,
    provenance: advance_shared_types::skills::Provenance,
    trust_level: advance_shared_types::skills::TrustLevel,
}

/// Storage abstraction for the Slice C SkillStore.
///
/// Slice C ships two implementations: `InMemorySkillStorage` (test-only +
/// Slice A behaviour preservation) and `DiskSkillStorage` (production —
/// atomic writes via cap-fs).
#[async_trait]
pub trait SkillStorage: Send + Sync {
    // ─── Drafts ───────────────────────────────────────────────────
    async fn read_draft(&self, name: &str) -> Result<Option<DraftBlob>, SkillError>;
    async fn write_draft(&self, blob: &DraftBlob) -> Result<(), SkillError>;
    async fn delete_draft(&self, name: &str) -> Result<(), SkillError>;
    async fn list_drafts(&self) -> Result<Vec<DraftBlob>, SkillError>;

    // ─── Active skills ────────────────────────────────────────────
    async fn read_active(&self, skill_id: &str) -> Result<Option<SkillBlob>, SkillError>;
    async fn write_active(&self, blob: &SkillBlob) -> Result<(), SkillError>;
    async fn delete_active(&self, skill_id: &str) -> Result<(), SkillError>;
    async fn list_active(&self) -> Result<Vec<SkillBlob>, SkillError>;

    // ─── Versions ─────────────────────────────────────────────────
    async fn read_version(
        &self,
        skill_id: &str,
        version: u32,
    ) -> Result<Option<String>, SkillError>;
    async fn write_version(
        &self,
        skill_id: &str,
        version: u32,
        content: &str,
    ) -> Result<(), SkillError>;
    async fn list_versions(&self, skill_id: &str) -> Result<Vec<u32>, SkillError>;

    // ─── Slice E — Sidecars ───────────────────────────────────────
    //
    // The default impl is `Ok(())` / `Ok(None)` no-op for foreign-impl
    // compatibility. In-tree `InMemorySkillStorage` overrides to store
    // sidecars in a HashMap; `DiskSkillStorage` overrides to atomic-write
    // to `<agent_root>/.agent/skills/{skill_id}/<filename>` with
    // defense-in-depth filename re-validation. See MODULE-017 §3.6 (z)
    // for the foreign-impl trade-off.
    async fn write_skill_sidecar(
        &self,
        skill_id: &str,
        kind: SkillSidecar,
        bytes: &[u8],
    ) -> Result<(), SkillError> {
        let _ = (skill_id, kind, bytes);
        Ok(())
    }

    async fn read_skill_sidecar(
        &self,
        skill_id: &str,
        kind: SkillSidecar,
    ) -> Result<Option<Vec<u8>>, SkillError> {
        let _ = (skill_id, kind);
        Ok(None)
    }

    /// Slice E (round-6 fix) — clear ALL sidecars for a skill_id.
    /// Used by `materialize_skill` to remove stale sidecars BEFORE
    /// writing the new bundle's sidecars, so re-materializing a shrunk
    /// bundle correctly removes files dropped upstream (closes the
    /// round-6 audit's additive-not-synchronizing gap).
    ///
    /// Default impl is no-op (foreign impls without sidecar persistence
    /// need not do anything). In-tree InMemorySkillStorage drops all
    /// HashMap entries for the skill_id; DiskSkillStorage removes
    /// tool.wasm, tool.capabilities.json, templates/, and source-scripts/
    /// under `.agent/skills/{skill_id}/`.
    async fn clear_skill_sidecars(&self, skill_id: &str) -> Result<(), SkillError> {
        let _ = skill_id;
        Ok(())
    }
}

/// Sidecar file kind for SkillStorage routing (Slice E). Maps to the
/// on-disk filename of an admin-pool bundle file (§2.5):
/// - `ToolWasm` → `<skill>/tool.wasm`
/// - `ToolCapabilitiesJson` → `<skill>/tool.capabilities.json`
/// - `Template(filename)` → `<skill>/templates/{filename}`
/// - `SourceScript(filename)` → `<skill>/source-scripts/{filename}`
///
/// The variant payloads for Template/SourceScript carry the per-file
/// filename validated by `validate_skill_filename` at construction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SkillSidecar {
    ToolWasm,
    ToolCapabilitiesJson,
    Template(String),
    SourceScript(String),
}

// ─────────────────────────────────────────────────────────────────────
// InMemorySkillStorage
// ─────────────────────────────────────────────────────────────────────

/// In-memory backing for `SkillStore`. Behaviour-equivalent to Slice A's
/// HashMap state but exposed through the async `SkillStorage` trait.
#[derive(Default)]
pub struct InMemorySkillStorage {
    inner: RwLock<MemoryState>,
}

#[derive(Default)]
struct MemoryState {
    drafts: HashMap<String, DraftBlob>,
    active: HashMap<String, SkillBlob>,
    versions: HashMap<String, BTreeMap<u32, String>>,
    /// Slice E — sidecar files keyed by (skill_id, kind). The in-memory
    /// HashMap mirrors the on-disk layout used by DiskSkillStorage; tests
    /// using `InMemorySkillStorage` get full sidecar round-trip without
    /// needing a tempdir.
    sidecars: HashMap<(String, SkillSidecar), Vec<u8>>,
}

impl InMemorySkillStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

#[async_trait]
impl SkillStorage for InMemorySkillStorage {
    async fn read_draft(&self, name: &str) -> Result<Option<DraftBlob>, SkillError> {
        Ok(self.inner.read().await.drafts.get(name).cloned())
    }

    async fn write_draft(&self, blob: &DraftBlob) -> Result<(), SkillError> {
        self.inner
            .write()
            .await
            .drafts
            .insert(blob.name.clone(), blob.clone());
        Ok(())
    }

    async fn delete_draft(&self, name: &str) -> Result<(), SkillError> {
        self.inner.write().await.drafts.remove(name);
        Ok(())
    }

    async fn list_drafts(&self) -> Result<Vec<DraftBlob>, SkillError> {
        Ok(self.inner.read().await.drafts.values().cloned().collect())
    }

    async fn read_active(&self, skill_id: &str) -> Result<Option<SkillBlob>, SkillError> {
        Ok(self.inner.read().await.active.get(skill_id).cloned())
    }

    async fn write_active(&self, blob: &SkillBlob) -> Result<(), SkillError> {
        self.inner
            .write()
            .await
            .active
            .insert(blob.skill_id.clone(), blob.clone());
        Ok(())
    }

    async fn delete_active(&self, skill_id: &str) -> Result<(), SkillError> {
        self.inner.write().await.active.remove(skill_id);
        Ok(())
    }

    async fn list_active(&self) -> Result<Vec<SkillBlob>, SkillError> {
        Ok(self.inner.read().await.active.values().cloned().collect())
    }

    async fn read_version(
        &self,
        skill_id: &str,
        version: u32,
    ) -> Result<Option<String>, SkillError> {
        Ok(self
            .inner
            .read()
            .await
            .versions
            .get(skill_id)
            .and_then(|v| v.get(&version).cloned()))
    }

    async fn write_version(
        &self,
        skill_id: &str,
        version: u32,
        content: &str,
    ) -> Result<(), SkillError> {
        let mut state = self.inner.write().await;
        state
            .versions
            .entry(skill_id.to_string())
            .or_default()
            .insert(version, content.to_string());
        Ok(())
    }

    async fn list_versions(&self, skill_id: &str) -> Result<Vec<u32>, SkillError> {
        Ok(self
            .inner
            .read()
            .await
            .versions
            .get(skill_id)
            .map(|v| v.keys().copied().collect())
            .unwrap_or_default())
    }

    /// Slice E — store sidecar bytes in-memory keyed by (skill_id, kind).
    /// Defense-in-depth: re-validate skill_id + filename even though the
    /// SkillBundle::new constructor should have validated upstream.
    async fn write_skill_sidecar(
        &self,
        skill_id: &str,
        kind: SkillSidecar,
        bytes: &[u8],
    ) -> Result<(), SkillError> {
        crate::security_scan::validate_skill_name(skill_id)?;
        match &kind {
            SkillSidecar::Template(name) | SkillSidecar::SourceScript(name) => {
                crate::security_scan::validate_skill_filename(name)?;
            }
            SkillSidecar::ToolWasm | SkillSidecar::ToolCapabilitiesJson => {}
        }
        self.inner
            .write()
            .await
            .sidecars
            .insert((skill_id.to_string(), kind), bytes.to_vec());
        Ok(())
    }

    async fn read_skill_sidecar(
        &self,
        skill_id: &str,
        kind: SkillSidecar,
    ) -> Result<Option<Vec<u8>>, SkillError> {
        crate::security_scan::validate_skill_name(skill_id)?;
        Ok(self
            .inner
            .read()
            .await
            .sidecars
            .get(&(skill_id.to_string(), kind))
            .cloned())
    }

    /// Slice E (round-6 fix) — drop every sidecar entry whose skill_id
    /// matches. Closes the additive-not-synchronizing gap by removing
    /// stale sidecars before re-materialize writes the new bundle's
    /// sidecars.
    async fn clear_skill_sidecars(&self, skill_id: &str) -> Result<(), SkillError> {
        crate::security_scan::validate_skill_name(skill_id)?;
        self.inner
            .write()
            .await
            .sidecars
            .retain(|(sid, _), _| sid != skill_id);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// DiskSkillStorage
// ─────────────────────────────────────────────────────────────────────

/// Disk-backed `SkillStorage`. All writes go through `cap-fs::AtomicWriter`
/// (after `tokio::fs::create_dir_all(parent)`) for crash-consistency.
/// Reads use plain `tokio::fs::read_to_string` / `read_dir`.
///
/// ## Trust boundary (adversarial round 1 disclosure)
///
/// `DiskSkillStorage` trusts that `agent_root` and its `.agent/` subtree
/// are **host-controlled** and free of malicious symlinks. `ensure_parent`
/// calls `tokio::fs::create_dir_all(parent)` which **follows symlinks** —
/// this is the same TOCTOU surface that `cap-fs::atomic_write` explicitly
/// refuses to introduce. Slice C's pragmatic mitigation is:
///
/// 1. **Canonicalize at construction**: `with_default_writer` resolves
///    `agent_root` via `std::fs::canonicalize` (if the directory exists),
///    so any pre-existing symlinks on the host path are flattened once.
/// 2. **Path-component validation**: agent-supplied skill names pass
///    through `security_scan::validate_skill_name` at every public
///    mutation entry point, so the leaf path component cannot itself
///    be a path-traversal payload.
/// 3. **Out-of-scope assumption**: a co-located adversary with write
///    access to the canonicalized `<agent_root>/.agent/` after
///    construction (e.g., another process running as the same user) can
///    still plant symlinks between calls — this is the same trust level
///    as direct disk write access and is treated as host-side compromise
///    rather than agent-side exploitation. Operators isolating multiple
///    agents on the same host must use OS-level isolation (separate
///    users, containers, or filesystem namespaces) to prevent this.
///
/// A future slice can route writes through `cap-fs::VirtualPathResolver`
/// for symlink-safe `openat`-style semantics; tracked in §3.6 known
/// gap (h).
pub struct DiskSkillStorage {
    /// Path to the agent's workspace root (the directory CONTAINING `.agent/`).
    /// Canonicalized at construction when possible.
    agent_root: PathBuf,
    /// Atomic writer for crash-safe disk writes.
    atomic: Arc<dyn cap_fs::AtomicWriter>,
}

impl DiskSkillStorage {
    pub fn new(agent_root: PathBuf, atomic: Arc<dyn cap_fs::AtomicWriter>) -> Self {
        // Canonicalize once at construction — flattens any pre-existing
        // symlinks on the host path. If canonicalization fails (path
        // doesn't exist yet, or std::fs returns IO error), fall back to
        // the raw path so first-use construction still works.
        let canonical = std::fs::canonicalize(&agent_root).unwrap_or(agent_root);
        Self {
            agent_root: canonical,
            atomic,
        }
    }

    /// Construct with the default `cap_fs::DefaultAtomicWriter`.
    pub fn with_default_writer(agent_root: PathBuf) -> Self {
        Self::new(agent_root, Arc::new(cap_fs::DefaultAtomicWriter))
    }

    fn drafts_root(&self) -> PathBuf {
        self.agent_root.join(".agent/_skill_drafts")
    }
    fn versions_root(&self) -> PathBuf {
        self.agent_root.join(".agent/_skill_versions")
    }
    fn skills_root(&self) -> PathBuf {
        self.agent_root.join(".agent/skills")
    }

    fn draft_md_path(&self, name: &str) -> PathBuf {
        self.drafts_root().join(name).join("SKILL.md")
    }
    fn draft_meta_path(&self, name: &str) -> PathBuf {
        self.drafts_root().join(name).join(".meta.yaml")
    }
    fn active_md_path(&self, skill_id: &str) -> PathBuf {
        self.skills_root().join(skill_id).join("SKILL.md")
    }
    fn active_meta_path(&self, skill_id: &str) -> PathBuf {
        self.skills_root().join(skill_id).join(".meta.yaml")
    }
    fn version_path(&self, skill_id: &str, version: u32) -> PathBuf {
        self.versions_root()
            .join(skill_id)
            .join(format!("v{}.md", version))
    }

    async fn ensure_parent(&self, path: &Path) -> Result<(), SkillError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                SkillError::InvalidTransition(format!("create_dir_all failed: {e}"))
            })?;
        }
        Ok(())
    }

    async fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<(), SkillError> {
        self.ensure_parent(path).await?;
        self.atomic
            .write(path, bytes)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("atomic write failed: {e}")))
    }

    async fn read_text(&self, path: &Path) -> Result<Option<String>, SkillError> {
        match tokio::fs::read_to_string(path).await {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SkillError::InvalidTransition(format!("read failed: {e}"))),
        }
    }
}

#[async_trait]
impl SkillStorage for DiskSkillStorage {
    async fn read_draft(&self, name: &str) -> Result<Option<DraftBlob>, SkillError> {
        let md_path = self.draft_md_path(name);
        let meta_path = self.draft_meta_path(name);
        let content = match self.read_text(&md_path).await? {
            Some(c) => c,
            None => return Ok(None),
        };
        let meta_text = match self.read_text(&meta_path).await? {
            Some(m) => m,
            None => return Ok(None),
        };
        let meta: DraftMeta = serde_yml::from_str(&meta_text)
            .map_err(|e| SkillError::InvalidTransition(format!("draft meta yaml: {e}")))?;
        // Adversarial round 2 fix (C2): cross-check the meta.name field
        // against the path key. A tampered .meta.yaml with a path-
        // traversal `name` would otherwise inject a malicious identifier
        // into the in-memory DraftBlob that later host_fn handlers would
        // pass through to write paths. The path key is the source of
        // truth — refuse to load if the meta disagrees.
        if meta.name != name {
            return Err(SkillError::InvalidTransition(format!(
                "draft meta.name mismatch with path key (corruption or tampering)"
            )));
        }
        Ok(Some(DraftBlob {
            name: meta.name,
            content,
            tags: meta.tags,
            parent: meta.parent,
            reason: meta.reason,
            created_at: meta.created_at,
        }))
    }

    async fn write_draft(&self, blob: &DraftBlob) -> Result<(), SkillError> {
        self.write_file(&self.draft_md_path(&blob.name), blob.content.as_bytes())
            .await?;
        let meta = DraftMeta {
            name: blob.name.clone(),
            tags: blob.tags.clone(),
            parent: blob.parent.clone(),
            reason: blob.reason.clone(),
            created_at: blob.created_at,
        };
        let meta_yaml = serde_yml::to_string(&meta)
            .map_err(|e| SkillError::InvalidTransition(format!("draft meta yaml: {e}")))?;
        self.write_file(&self.draft_meta_path(&blob.name), meta_yaml.as_bytes())
            .await
    }

    async fn delete_draft(&self, name: &str) -> Result<(), SkillError> {
        let dir = self.drafts_root().join(name);
        // Adversarial round 2 fix (C3): use symlink_metadata + reject
        // symlinks BEFORE remove_dir_all. tokio::fs::remove_dir_all follows
        // symlinks during traversal, so a co-located adversary swapping
        // _skill_drafts/<name>/ for a symlink to `/etc/...` between the
        // exists() check and the remove call (TOCTOU) would delete the
        // target. symlink_metadata checks the link itself (not its
        // target); if it's a symlink we refuse the operation.
        match tokio::fs::symlink_metadata(&dir).await {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(SkillError::InvalidTransition(format!(
                        "refusing to remove_dir_all on symlink (security)"
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(SkillError::InvalidTransition(format!(
                    "symlink_metadata: {e}"
                )))
            }
        }
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("remove draft dir: {e}")))?;
        Ok(())
    }

    async fn list_drafts(&self) -> Result<Vec<DraftBlob>, SkillError> {
        let root = self.drafts_root();
        let mut out = Vec::new();
        let mut entries = match tokio::fs::read_dir(&root).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SkillError::InvalidTransition(format!("read_dir: {e}"))),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
        {
            if let Some(name) = entry.file_name().to_str().map(str::to_string) {
                // Audit round 3 fix: per-entry log-and-skip. A single
                // corrupt `.meta.yaml` previously short-circuited the
                // whole enumeration, blackouting all other drafts +
                // wedging the opportunistic sweep. Now we log via
                // `tracing` (or stderr if tracing isn't wired) and
                // continue, so transient/persistent corruption affects
                // only the one bad record.
                match self.read_draft(&name).await {
                    Ok(Some(blob)) => out.push(blob),
                    Ok(None) => { /* missing meta or md — silently skip */ }
                    Err(e) => {
                        eprintln!("cap-skills: list_drafts skipping corrupt draft {name}: {e}");
                    }
                }
            }
        }
        Ok(out)
    }

    async fn read_active(&self, skill_id: &str) -> Result<Option<SkillBlob>, SkillError> {
        let md_path = self.active_md_path(skill_id);
        let meta_path = self.active_meta_path(skill_id);
        let content = match self.read_text(&md_path).await? {
            Some(c) => c,
            None => return Ok(None),
        };
        let meta_text = match self.read_text(&meta_path).await? {
            Some(m) => m,
            None => return Ok(None),
        };
        let meta: ActiveMeta = serde_yml::from_str(&meta_text)
            .map_err(|e| SkillError::InvalidTransition(format!("active meta yaml: {e}")))?;
        // Adversarial round 2 fix (C2): cross-check meta.skill_id against
        // the path key. Same rationale as read_draft above.
        if meta.skill_id != skill_id {
            return Err(SkillError::InvalidTransition(format!(
                "active meta.skill_id mismatch with path key (corruption or tampering)"
            )));
        }
        Ok(Some(SkillBlob {
            skill_id: meta.skill_id,
            version: meta.version,
            content,
            tags: meta.tags,
            provenance: meta.provenance,
            trust_level: meta.trust_level,
        }))
    }

    async fn write_active(&self, blob: &SkillBlob) -> Result<(), SkillError> {
        self.write_file(
            &self.active_md_path(&blob.skill_id),
            blob.content.as_bytes(),
        )
        .await?;
        let meta = ActiveMeta {
            skill_id: blob.skill_id.clone(),
            version: blob.version,
            tags: blob.tags.clone(),
            provenance: blob.provenance.clone(),
            trust_level: blob.trust_level.clone(),
        };
        let meta_yaml = serde_yml::to_string(&meta)
            .map_err(|e| SkillError::InvalidTransition(format!("active meta yaml: {e}")))?;
        self.write_file(&self.active_meta_path(&blob.skill_id), meta_yaml.as_bytes())
            .await
    }

    async fn delete_active(&self, skill_id: &str) -> Result<(), SkillError> {
        let dir = self.skills_root().join(skill_id);
        // Adversarial round 2 fix (C3): same symlink defense as delete_draft.
        match tokio::fs::symlink_metadata(&dir).await {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(SkillError::InvalidTransition(format!(
                        "refusing to remove_dir_all on symlink (security)"
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(SkillError::InvalidTransition(format!(
                    "symlink_metadata: {e}"
                )))
            }
        }
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("remove active dir: {e}")))?;
        Ok(())
    }

    async fn list_active(&self) -> Result<Vec<SkillBlob>, SkillError> {
        let root = self.skills_root();
        let mut out = Vec::new();
        let mut entries = match tokio::fs::read_dir(&root).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SkillError::InvalidTransition(format!("read_dir: {e}"))),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
        {
            if let Some(skill_id) = entry.file_name().to_str().map(str::to_string) {
                // Audit round 3 fix: per-entry log-and-skip (same
                // rationale as list_drafts above).
                match self.read_active(&skill_id).await {
                    Ok(Some(blob)) => out.push(blob),
                    Ok(None) => { /* missing meta or md — silently skip */ }
                    Err(e) => {
                        eprintln!("cap-skills: list_active skipping corrupt skill {skill_id}: {e}");
                    }
                }
            }
        }
        Ok(out)
    }

    async fn read_version(
        &self,
        skill_id: &str,
        version: u32,
    ) -> Result<Option<String>, SkillError> {
        self.read_text(&self.version_path(skill_id, version)).await
    }

    async fn write_version(
        &self,
        skill_id: &str,
        version: u32,
        content: &str,
    ) -> Result<(), SkillError> {
        self.write_file(&self.version_path(skill_id, version), content.as_bytes())
            .await
    }

    async fn list_versions(&self, skill_id: &str) -> Result<Vec<u32>, SkillError> {
        let root = self.versions_root().join(skill_id);
        let mut out = Vec::new();
        let mut entries = match tokio::fs::read_dir(&root).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SkillError::InvalidTransition(format!("read_dir: {e}"))),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
        {
            if let Some(name) = entry.file_name().to_str().map(str::to_string) {
                if let Some(v) = name
                    .strip_prefix('v')
                    .and_then(|s| s.strip_suffix(".md"))
                    .and_then(|s| s.parse::<u32>().ok())
                {
                    out.push(v);
                }
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Slice E — atomic-write a sidecar file under `.agent/skills/{skill_id}/`.
    /// Defense-in-depth: re-validate skill_id + filename payload BEFORE any
    /// path join, closing the storage-boundary path-traversal surface for
    /// callers that bypass SkillBundle::new's constructor validation
    /// (SE-33 locks this property).
    async fn write_skill_sidecar(
        &self,
        skill_id: &str,
        kind: SkillSidecar,
        bytes: &[u8],
    ) -> Result<(), SkillError> {
        crate::security_scan::validate_skill_name(skill_id)?;
        let rel = match &kind {
            SkillSidecar::ToolWasm => "tool.wasm".to_string(),
            SkillSidecar::ToolCapabilitiesJson => "tool.capabilities.json".to_string(),
            SkillSidecar::Template(name) => {
                crate::security_scan::validate_skill_filename(name)?;
                format!("templates/{name}")
            }
            SkillSidecar::SourceScript(name) => {
                crate::security_scan::validate_skill_filename(name)?;
                format!("source-scripts/{name}")
            }
        };
        let path = self.skills_root().join(skill_id).join(rel);
        self.write_file(&path, bytes).await
    }

    async fn read_skill_sidecar(
        &self,
        skill_id: &str,
        kind: SkillSidecar,
    ) -> Result<Option<Vec<u8>>, SkillError> {
        crate::security_scan::validate_skill_name(skill_id)?;
        let rel = match &kind {
            SkillSidecar::ToolWasm => "tool.wasm".to_string(),
            SkillSidecar::ToolCapabilitiesJson => "tool.capabilities.json".to_string(),
            SkillSidecar::Template(name) => {
                crate::security_scan::validate_skill_filename(name)?;
                format!("templates/{name}")
            }
            SkillSidecar::SourceScript(name) => {
                crate::security_scan::validate_skill_filename(name)?;
                format!("source-scripts/{name}")
            }
        };
        let path = self.skills_root().join(skill_id).join(rel);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SkillError::InvalidTransition(format!(
                "read sidecar failed: {e}"
            ))),
        }
    }

    /// Slice E (round-6 fix) — remove all sidecar files for the skill.
    /// Closes the additive-not-synchronizing gap so re-materializing a
    /// shrunk bundle correctly drops stale tool.wasm /
    /// tool.capabilities.json / templates / source-scripts files.
    ///
    /// Removes (in order):
    /// 1. `<skill>/tool.wasm`
    /// 2. `<skill>/tool.capabilities.json`
    /// 3. `<skill>/templates/` directory (recursive)
    /// 4. `<skill>/source-scripts/` directory (recursive)
    ///
    /// SKILL.md + .meta.yaml are deliberately NOT removed — the
    /// caller (`materialize_skill`) overwrites those via
    /// `write_active` as the LAST step, preserving the prior
    /// SkillBlob if anything fails earlier.
    async fn clear_skill_sidecars(&self, skill_id: &str) -> Result<(), SkillError> {
        crate::security_scan::validate_skill_name(skill_id)?;
        let skill_dir = self.skills_root().join(skill_id);

        // Files: symlink_metadata reject + remove_file. Refuses to follow
        // a symlinked tool.wasm / tool.capabilities.json (defense-in-depth
        // against round-1 adversarial finding C3-class on the delete path).
        for rel in ["tool.wasm", "tool.capabilities.json"] {
            let p = skill_dir.join(rel);
            match tokio::fs::symlink_metadata(&p).await {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(SkillError::InvalidTransition(format!(
                            "refusing to clear symlinked sidecar {rel}"
                        )));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(SkillError::InvalidTransition(format!(
                        "symlink_metadata {rel}: {e}"
                    )))
                }
            }
            match tokio::fs::remove_file(&p).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(SkillError::InvalidTransition(format!(
                        "remove_file {rel}: {e}"
                    )))
                }
            }
        }

        // Dirs: symlink_metadata reject BEFORE remove_dir_all — closes
        // the round-1 adversarial finding (Codex W3) where
        // remove_dir_all on a symlinked templates/ or source-scripts/
        // would follow to the symlink target.
        for rel in ["templates", "source-scripts"] {
            let p = skill_dir.join(rel);
            match tokio::fs::symlink_metadata(&p).await {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(SkillError::InvalidTransition(format!(
                            "refusing to clear symlinked sidecar dir {rel}"
                        )));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(SkillError::InvalidTransition(format!(
                        "symlink_metadata {rel}: {e}"
                    )))
                }
            }
            match tokio::fs::remove_dir_all(&p).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(SkillError::InvalidTransition(format!(
                        "remove_dir_all {rel}: {e}"
                    )))
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    fn sample_draft() -> DraftBlob {
        DraftBlob {
            name: "foo".into(),
            content: "---\nname: foo\ndescription: x\n---\n".into(),
            tags: vec!["tag1".into()],
            parent: None,
            reason: None,
            created_at: Utc::now(),
        }
    }

    fn sample_skill() -> SkillBlob {
        SkillBlob {
            skill_id: "foo".into(),
            version: 1,
            content: "---\nname: foo\ndescription: x\n---\n".into(),
            tags: vec!["tag1".into()],
            provenance: advance_shared_types::skills::Provenance::AgentCreated,
            trust_level: advance_shared_types::skills::TrustLevel::Untrusted,
        }
    }

    /// SC-04-mem — in-memory roundtrip: write_draft → read_draft.
    #[tokio::test]
    async fn sc_04_mem_draft_roundtrip() {
        let storage = InMemorySkillStorage::new();
        let draft = sample_draft();
        storage.write_draft(&draft).await.unwrap();
        let read = storage.read_draft("foo").await.unwrap().unwrap();
        assert_eq!(read, draft);
    }

    /// SC-04-disk — disk roundtrip: write_draft → read_draft from new
    /// DiskSkillStorage instance pointing at the same TempDir.
    #[tokio::test]
    async fn sc_04_disk_draft_roundtrip() {
        let dir = TempDir::new().unwrap();
        let storage = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        let draft = sample_draft();
        storage.write_draft(&draft).await.unwrap();

        // Drop + reconstruct to verify disk persistence (simulates restart).
        drop(storage);
        let storage2 = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        let read = storage2.read_draft("foo").await.unwrap().unwrap();
        assert_eq!(read.content, draft.content);
        assert_eq!(read.name, "foo");
        assert_eq!(read.tags, vec!["tag1"]);
    }

    /// SC-disk-04 — disk active skill roundtrip with provenance + trust_level.
    #[tokio::test]
    async fn sc_disk_active_roundtrip() {
        let dir = TempDir::new().unwrap();
        let storage = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        let skill = sample_skill();
        storage.write_active(&skill).await.unwrap();
        let read = storage.read_active("foo").await.unwrap().unwrap();
        assert_eq!(read, skill);
    }

    /// SC-disk-versions — write_version → list_versions returns sorted.
    #[tokio::test]
    async fn sc_disk_versions_sorted() {
        let dir = TempDir::new().unwrap();
        let storage = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        storage.write_version("foo", 3, "v3 body").await.unwrap();
        storage.write_version("foo", 1, "v1 body").await.unwrap();
        storage.write_version("foo", 2, "v2 body").await.unwrap();
        let versions = storage.list_versions("foo").await.unwrap();
        assert_eq!(versions, vec![1, 2, 3]);
        assert_eq!(
            storage.read_version("foo", 2).await.unwrap(),
            Some("v2 body".to_string())
        );
    }

    /// SC-disk-list-empty — listing on empty disk returns empty vec (no error).
    #[tokio::test]
    async fn sc_disk_list_empty_no_error() {
        let dir = TempDir::new().unwrap();
        let storage = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        assert!(storage.list_drafts().await.unwrap().is_empty());
        assert!(storage.list_active().await.unwrap().is_empty());
        assert!(storage.list_versions("nope").await.unwrap().is_empty());
    }

    /// Audit round 3 fix: list_drafts logs-and-skips per-entry on corrupt
    /// `.meta.yaml`, instead of short-circuiting the whole enumeration.
    #[tokio::test]
    async fn audit_round_3_list_drafts_skips_corrupt_meta() {
        let dir = TempDir::new().unwrap();
        let storage = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());

        // Write a valid draft.
        let good = DraftBlob {
            name: "good".into(),
            content: "---\nname: good\ndescription: x\n---\n".into(),
            tags: vec![],
            parent: None,
            reason: None,
            created_at: Utc::now(),
        };
        storage.write_draft(&good).await.unwrap();

        // Manually plant a draft directory with corrupt .meta.yaml.
        let bad_dir = dir.path().join(".agent/_skill_drafts/bad");
        tokio::fs::create_dir_all(&bad_dir).await.unwrap();
        tokio::fs::write(bad_dir.join("SKILL.md"), b"body")
            .await
            .unwrap();
        tokio::fs::write(bad_dir.join(".meta.yaml"), b"not: [valid: yaml")
            .await
            .unwrap();

        // list_drafts should return the good one and skip the bad one
        // (NOT short-circuit with an error).
        let drafts = storage.list_drafts().await.unwrap();
        assert_eq!(drafts.len(), 1, "good draft visible despite corrupt bad");
        assert_eq!(drafts[0].name, "good");
    }

    /// SC-08 — mkdir -p before AtomicWriter::write (parent dirs created
    /// automatically by ensure_parent).
    #[tokio::test]
    async fn sc_08_creates_nested_parents() {
        let dir = TempDir::new().unwrap();
        let storage = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        let draft = sample_draft();
        storage.write_draft(&draft).await.unwrap();
        // Path is <root>/.agent/_skill_drafts/foo/SKILL.md — 4 levels deep,
        // none of which existed before this call.
        let md = dir.path().join(".agent/_skill_drafts/foo/SKILL.md");
        assert!(md.exists());
        let meta = dir.path().join(".agent/_skill_drafts/foo/.meta.yaml");
        assert!(meta.exists());
    }
}
