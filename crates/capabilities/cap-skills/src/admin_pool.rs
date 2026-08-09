//! Slice E — `AdminPoolStorage`: operator-owned bundle library.
//!
//! Per PRD §12.4.3 the admin pool lives at `/.advance/skills/` (root
//! configurable). `AdminPoolStorage` is admin-side only — NO host_fn
//! registration in cap-skills means agents have no WASM-callable route
//! to the admin pool. This partially supports AC-28's "agents never
//! access /.advance/skills/ directly" claim on the cap-skills side; the
//! whole-system audit across cap-fs path resolution + runtime route
//! discovery + grant gates remains out of slice boundary (AC-28 untested).
//!
//! Path traversal defenses:
//! - `validate_skill_name` at every public entry rejects `..` / `/`.
//! - Per-FILE `tokio::fs::symlink_metadata` reject-symlink before every read.
//! - Per-DIRECTORY `symlink_metadata` before every `read_dir`.
//! - `safe_remove_dir_all` walks leaf-up rejecting any symlinked entry —
//!   closes the `tokio::fs::remove_dir_all` symlink-traversal hazard.
//! - Constructor canonicalizes the root via `std::fs::canonicalize`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::SkillError;
use crate::security_scan::validate_skill_name;
use crate::skill_bundle::{BundleMeta, SkillBundle};

/// Admin-pool storage rooted at a configurable path.
pub struct AdminPoolStorage {
    root: PathBuf,
    atomic: Arc<dyn cap_fs::AtomicWriter>,
}

impl AdminPoolStorage {
    pub fn new(root: PathBuf, atomic: Arc<dyn cap_fs::AtomicWriter>) -> Self {
        // Canonicalize once at construction (symmetric with DiskSkillStorage::new).
        let canonical = std::fs::canonicalize(&root).unwrap_or(root);
        Self {
            root: canonical,
            atomic,
        }
    }

    /// Convenience constructor using `cap_fs::DefaultAtomicWriter`.
    pub fn with_default_writer(root: PathBuf) -> Self {
        Self::new(root, Arc::new(cap_fs::DefaultAtomicWriter))
    }

    /// Expose the canonicalized root for tests that need to assert
    /// post-construction path equality (SE-07).
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn bundle_root(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn skill_md_path(&self, name: &str) -> PathBuf {
        self.bundle_root(name).join("SKILL.md")
    }

    fn meta_path(&self, name: &str) -> PathBuf {
        self.bundle_root(name).join(".meta.yaml")
    }

    fn tool_wasm_path(&self, name: &str) -> PathBuf {
        self.bundle_root(name).join("tool.wasm")
    }

    fn tool_capabilities_path(&self, name: &str) -> PathBuf {
        self.bundle_root(name).join("tool.capabilities.json")
    }

    fn templates_dir(&self, name: &str) -> PathBuf {
        self.bundle_root(name).join("templates")
    }

    fn source_scripts_dir(&self, name: &str) -> PathBuf {
        self.bundle_root(name).join("source-scripts")
    }

    async fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<(), SkillError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("create_dir_all: {e}")))?;
        }
        self.atomic
            .write(path, bytes)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("atomic write: {e}")))
    }

    /// Reject if the path is itself a symlink (read path defense). Returns
    /// `Ok(None)` on NotFound so optional bundle files can be probed
    /// uniformly.
    async fn check_path_no_symlink(
        &self,
        path: &Path,
    ) -> Result<Option<std::fs::Metadata>, SkillError> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(SkillError::InvalidTransition(format!(
                        "refusing to follow symlink at {path:?}"
                    )));
                }
                Ok(Some(meta))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SkillError::InvalidTransition(format!(
                "symlink_metadata: {e}"
            ))),
        }
    }

    /// Read a text file after symlink reject + size cap pre-check.
    /// Caps the file at `cap` bytes BEFORE `read_to_string` — closes the
    /// adversarial round-2 W2 DoS surface where a tampered admin pool
    /// could plant oversized files past SkillBundle::new's write-time
    /// caps.
    async fn read_text_file_capped(
        &self,
        path: &Path,
        cap: u64,
    ) -> Result<Option<String>, SkillError> {
        match self.check_path_no_symlink(path).await? {
            Some(meta) if meta.is_file() => {
                if meta.len() > cap {
                    return Err(SkillError::ContentTooLarge(meta.len() as usize));
                }
                match tokio::fs::read_to_string(path).await {
                    Ok(s) => Ok(Some(s)),
                    Err(e) => Err(SkillError::InvalidTransition(format!(
                        "read_to_string: {e}"
                    ))),
                }
            }
            _ => Ok(None),
        }
    }

    #[allow(dead_code)] // legacy uncapped wrapper: all callers migrated to *_capped; delete in a cleanup slice
    async fn read_text_file(&self, path: &Path) -> Result<Option<String>, SkillError> {
        self.read_text_file_capped(path, u64::MAX).await
    }

    async fn read_bytes_file_capped(
        &self,
        path: &Path,
        cap: u64,
    ) -> Result<Option<Vec<u8>>, SkillError> {
        match self.check_path_no_symlink(path).await? {
            Some(meta) if meta.is_file() => {
                if meta.len() > cap {
                    return Err(SkillError::ContentTooLarge(meta.len() as usize));
                }
                match tokio::fs::read(path).await {
                    Ok(b) => Ok(Some(b)),
                    Err(e) => Err(SkillError::InvalidTransition(format!("read: {e}"))),
                }
            }
            _ => Ok(None),
        }
    }

    #[allow(dead_code)] // legacy uncapped wrapper: all callers migrated to *_capped; delete in a cleanup slice
    async fn read_bytes_file(&self, path: &Path) -> Result<Option<Vec<u8>>, SkillError> {
        self.read_bytes_file_capped(path, u64::MAX).await
    }

    /// Walk a sidecar directory with size + count caps. Each entry's
    /// filename + content is symlink-checked + size-prechecked BEFORE
    /// `read_to_string`. Closes adversarial round-2 W2 DoS surface where
    /// a tampered admin pool could plant entries that bypass write-time
    /// caps on the read side.
    async fn read_text_dir_capped(
        &self,
        dir: &Path,
        max_entries: usize,
        max_bytes_per_entry: u64,
    ) -> Result<Vec<(String, String)>, SkillError> {
        match self.check_path_no_symlink(dir).await? {
            Some(meta) if meta.is_dir() => {}
            _ => return Ok(Vec::new()),
        }
        let mut entries = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read_dir: {e}")))?;
        let mut out = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
        {
            let path = entry.path();
            let meta = self.check_path_no_symlink(&path).await?;
            let file_meta = match meta {
                Some(m) if m.is_file() => m,
                _ => continue,
            };
            if out.len() >= max_entries {
                return Err(SkillError::InvalidTransition(format!(
                    "admin pool directory entry count exceeds {max_entries}: {dir:?}"
                )));
            }
            if file_meta.len() > max_bytes_per_entry {
                return Err(SkillError::ContentTooLarge(file_meta.len() as usize));
            }
            let filename = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Defense-in-depth: validate filename against the same rule
            // SkillBundle::new applies at write time. Closes round-3
            // Codex W1 read-side filename validation gap.
            crate::security_scan::validate_skill_filename(&filename)?;
            let body = tokio::fs::read_to_string(&path).await.map_err(|e| {
                SkillError::InvalidTransition(format!("read_to_string {filename}: {e}"))
            })?;
            out.push((filename, body));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    #[allow(dead_code)] // legacy uncapped wrapper: all callers migrated to *_capped; delete in a cleanup slice
    async fn read_text_dir(&self, dir: &Path) -> Result<Vec<(String, String)>, SkillError> {
        self.read_text_dir_capped(dir, usize::MAX, u64::MAX).await
    }

    /// Write the bundle to disk via staging-dir + rename. Layout (see
    /// MODULE-017 §2.5):
    /// ```text
    /// <root>/{name}/
    ///   SKILL.md                  (always)
    ///   .meta.yaml                (always)
    ///   tool.wasm                 (if Some)
    ///   tool.capabilities.json    (if Some)
    ///   templates/{filename}      (one per entry)
    ///   source-scripts/{filename} (one per entry)
    /// ```
    ///
    /// **Crash-safe staging**: the new bundle is staged to a uniquely-
    /// timestamped sibling directory `<root>/.tmp.{name}.{nanos}/`. If any
    /// per-file write fails mid-staging, the staging dir is cleaned up
    /// and the original bundle is UNTOUCHED. Closes the round-3 audit's
    /// mid-write integrity regression at the staging phase.
    ///
    /// **Rename phase — atomic on fresh-write, remove-then-rename on
    /// overwrite**: `tokio::fs::rename(staging, live)` is atomic on POSIX
    /// when the destination is ABSENT (fresh-write case). When the
    /// destination is an existing NON-EMPTY directory, POSIX `rename(2)`
    /// returns `ENOTEMPTY` (per `rename(2)` man pages on Linux + macOS),
    /// so the overwrite path always falls back to `safe_remove_dir_all(live)`
    /// + `rename(staging, live)`. The fallback has a narrow window where
    /// the bundle is briefly absent — but cannot be half-written since
    /// staging is complete by the time the rename phase begins. If the
    /// remove succeeds but the subsequent rename fails (extremely rare
    /// — e.g. external concurrent mutation), staging is preserved on
    /// disk and the error message points operators to its location.
    /// Stale sidecars from the OLD bundle are removed via the
    /// `safe_remove_dir_all` step of the fallback, so the new bundle is
    /// the only on-disk representation post-write.
    pub async fn write_bundle(&self, bundle: &SkillBundle) -> Result<(), SkillError> {
        validate_skill_name(&bundle.name)?;

        // Pick a uniquely-timestamped staging dir alongside the target.
        let stamp = chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let staging = self.root.join(format!(".tmp.{}.{stamp}", &bundle.name));

        // Write to staging dir. If anything fails, clean up staging and
        // leave the live bundle (if any) untouched.
        let result = self.write_bundle_to_dir(bundle, &staging).await;
        if let Err(e) = result {
            let _ = safe_remove_dir_all(&staging).await;
            return Err(e);
        }

        // Rename: staging → live bundle root.
        //
        // FRESH-WRITE (no existing bundle): POSIX rename(2) succeeds
        // atomically — a single syscall publishes the new bundle.
        //
        // OVERWRITE (live already exists as a non-empty directory): POSIX
        // rename(2) returns ENOTEMPTY (per Linux + macOS man pages). The
        // primary `tokio::fs::rename` call below therefore ALWAYS fails
        // for the overwrite case on Linux/macOS, and the fallback path
        // (safe_remove_dir_all(live) + rename(staging, live)) is the one
        // that actually runs. The fallback has a narrow window where the
        // bundle is briefly absent — but cannot be half-written, since
        // staging is fully populated by the time the rename phase begins.
        // §3.6 (bb) documents this trade-off + future-slice options
        // (renameat2 RENAME_EXCHANGE on Linux, renamex_np RENAME_SWAP on
        // macOS) for closing the absence window.
        let live = self.bundle_root(&bundle.name);
        match tokio::fs::rename(&staging, &live).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Overwrite path: tokio::fs::rename failed (typically
                // ENOTEMPTY on Linux/macOS, or platform variant). Remove
                // live, then retry rename. Bundle is briefly absent
                // between the two syscalls but cannot be half-written.
                if let Err(e) = safe_remove_dir_all(&live).await {
                    // Couldn't clean live — leave staging on disk for
                    // operator recovery.
                    return Err(SkillError::InvalidTransition(format!(
                        "rename fallback (live remove) failed: {e}; staging preserved at {staging:?}"
                    )));
                }
                tokio::fs::rename(&staging, &live).await.map_err(|e| {
                    SkillError::InvalidTransition(format!(
                        "rename fallback failed: {e}; staging preserved at {staging:?}"
                    ))
                })
            }
        }
    }

    /// Write all bundle files into `dest_dir`. Used by `write_bundle` for
    /// the staging phase; if this fails the caller cleans up `dest_dir`.
    async fn write_bundle_to_dir(
        &self,
        bundle: &SkillBundle,
        dest_dir: &Path,
    ) -> Result<(), SkillError> {
        tokio::fs::create_dir_all(dest_dir)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("create staging dir: {e}")))?;

        self.write_file(&dest_dir.join("SKILL.md"), bundle.skill_md.as_bytes())
            .await?;

        let meta_yaml = serde_yml::to_string(&bundle.meta())
            .map_err(|e| SkillError::InvalidTransition(format!("meta yaml: {e}")))?;
        self.write_file(&dest_dir.join(".meta.yaml"), meta_yaml.as_bytes())
            .await?;

        if let Some(wasm) = bundle.tool_wasm.as_ref() {
            self.write_file(&dest_dir.join("tool.wasm"), wasm).await?;
        }
        if let Some(caps) = bundle.tool_capabilities.as_ref() {
            self.write_file(&dest_dir.join("tool.capabilities.json"), caps.as_bytes())
                .await?;
        }

        let templates_dir = dest_dir.join("templates");
        for (filename, body) in &bundle.templates {
            self.write_file(&templates_dir.join(filename), body.as_bytes())
                .await?;
        }

        let scripts_dir = dest_dir.join("source-scripts");
        for (filename, body) in &bundle.source_scripts {
            self.write_file(&scripts_dir.join(filename), body.as_bytes())
                .await?;
        }

        Ok(())
    }

    /// Read a bundle from disk. Returns `Ok(None)` if `.meta.yaml` is
    /// absent. Every per-file + per-directory read is symlink-checked,
    /// INCLUDING the bundle root directory itself — closes the round-2
    /// list_bundles ↔ read_bundle asymmetry where read_bundle previously
    /// followed an intermediate symlinked bundle root via leaf-stat.
    pub async fn read_bundle(&self, name: &str) -> Result<Option<SkillBundle>, SkillError> {
        validate_skill_name(name)?;

        // Bundle root must be a non-symlink directory. If the root is
        // absent OR is a symlink OR isn't a directory, silently return
        // None — consistent with list_bundles skipping the entry. This
        // closes the round-2 list↔read asymmetry where read_bundle
        // previously followed an intermediate symlinked bundle root.
        match tokio::fs::symlink_metadata(&self.bundle_root(name)).await {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(None),
            Ok(meta) if !meta.is_dir() => return Ok(None),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(SkillError::InvalidTransition(format!(
                    "symlink_metadata bundle_root: {e}"
                )))
            }
        }

        // Defense-in-depth size caps on every read — closes the
        // adversarial round-2 W2 surface where a tampered admin pool
        // could plant entries that bypass SkillBundle::new's write-time
        // caps. The caps match crate::skill_bundle constants.
        use crate::skill_bundle::{
            MAX_SKILL_MD_BYTES, MAX_SOURCE_SCRIPTS, MAX_TEMPLATES, MAX_TOOL_CAPABILITIES_BYTES,
            MAX_TOOL_WASM_BYTES,
        };
        // .meta.yaml is itself small (YAML serialization of BundleMeta);
        // bound at 256 KiB to give some room for future field additions
        // without permitting megabytes.
        const META_YAML_CAP: u64 = 256 * 1024;

        let meta_text = match self
            .read_text_file_capped(&self.meta_path(name), META_YAML_CAP)
            .await?
        {
            Some(t) => t,
            None => return Ok(None),
        };
        let meta: BundleMeta = serde_yml::from_str(&meta_text)
            .map_err(|e| SkillError::InvalidTransition(format!("meta yaml parse: {e}")))?;

        if meta.name != name {
            return Err(SkillError::InvalidTransition(format!(
                "meta.name mismatch with path key (corruption or tampering)"
            )));
        }

        let skill_md = match self
            .read_text_file_capped(&self.skill_md_path(name), MAX_SKILL_MD_BYTES as u64)
            .await?
        {
            Some(s) => s,
            None => {
                return Err(SkillError::InvalidTransition(format!(
                    "bundle {name} has .meta.yaml but missing SKILL.md"
                )))
            }
        };

        let tool_wasm = if meta.has_tool_wasm {
            self.read_bytes_file_capped(&self.tool_wasm_path(name), MAX_TOOL_WASM_BYTES as u64)
                .await?
        } else {
            None
        };
        let tool_capabilities = if meta.has_tool_capabilities {
            self.read_text_file_capped(
                &self.tool_capabilities_path(name),
                MAX_TOOL_CAPABILITIES_BYTES as u64,
            )
            .await?
        } else {
            None
        };

        let templates = self
            .read_text_dir_capped(
                &self.templates_dir(name),
                MAX_TEMPLATES,
                MAX_SKILL_MD_BYTES as u64,
            )
            .await?;
        let source_scripts = self
            .read_text_dir_capped(
                &self.source_scripts_dir(name),
                MAX_SOURCE_SCRIPTS,
                MAX_SKILL_MD_BYTES as u64,
            )
            .await?;

        // Defense-in-depth: cross-check the manifest declared in
        // .meta.yaml against what's actually on disk. Closes round-3
        // Codex W1 manifest-consistency gap where a tampered admin pool
        // could plant undeclared template/script files.
        let mut declared_templates: Vec<String> = meta.template_files.clone();
        declared_templates.sort();
        let mut actual_templates: Vec<String> = templates.iter().map(|(f, _)| f.clone()).collect();
        actual_templates.sort();
        if declared_templates != actual_templates {
            return Err(SkillError::InvalidTransition(format!(
                "bundle {name}: templates manifest mismatch (declared {declared_templates:?} vs on-disk {actual_templates:?})"
            )));
        }
        let mut declared_scripts: Vec<String> = meta.source_script_files.clone();
        declared_scripts.sort();
        let mut actual_scripts: Vec<String> =
            source_scripts.iter().map(|(f, _)| f.clone()).collect();
        actual_scripts.sort();
        if declared_scripts != actual_scripts {
            return Err(SkillError::InvalidTransition(format!(
                "bundle {name}: source_scripts manifest mismatch (declared {declared_scripts:?} vs on-disk {actual_scripts:?})"
            )));
        }
        // tool.wasm + tool.capabilities.json existence vs manifest flag
        if meta.has_tool_wasm != tool_wasm.is_some() {
            return Err(SkillError::InvalidTransition(format!(
                "bundle {name}: has_tool_wasm flag disagrees with on-disk tool.wasm presence"
            )));
        }
        if meta.has_tool_capabilities != tool_capabilities.is_some() {
            return Err(SkillError::InvalidTransition(format!(
                "bundle {name}: has_tool_capabilities flag disagrees with on-disk tool.capabilities.json presence"
            )));
        }

        Ok(Some(SkillBundle {
            name: meta.name,
            skill_md,
            tool_wasm,
            tool_capabilities,
            templates,
            source_scripts,
            provenance: meta.provenance,
            trust_level: meta.trust_level,
            created_at: meta.created_at,
        }))
    }

    /// Enumerate bundle names. Each direct child of `<root>` that is a
    /// plain (non-symlink) directory containing a plain (non-symlink)
    /// `.meta.yaml` is treated as a bundle name. Sorted.
    ///
    /// Both the bundle root and its `.meta.yaml` are symlink-checked via
    /// `symlink_metadata` (not `try_exists`, which follows symlinks).
    /// This prevents a `list_bundles` ↔ `read_bundle` inconsistency where
    /// a symlink-planted name would appear in the list but fail at read.
    pub async fn list_bundles(&self) -> Result<Vec<String>, SkillError> {
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SkillError::InvalidTransition(format!("read_dir: {e}"))),
        };
        let mut names = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
        {
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if validate_skill_name(&name).is_err() {
                // Skip directories whose name doesn't match the canonical
                // skill name regex (e.g. transient tempdirs operators may
                // have placed here).
                continue;
            }
            // Bundle root must be a non-symlink directory.
            let bundle_dir = self.bundle_root(&name);
            let bundle_meta = match tokio::fs::symlink_metadata(&bundle_dir).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            if bundle_meta.file_type().is_symlink() || !bundle_meta.is_dir() {
                continue;
            }
            // .meta.yaml must be a non-symlink plain file.
            let meta_path = self.meta_path(&name);
            let meta_meta = match tokio::fs::symlink_metadata(&meta_path).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta_meta.file_type().is_symlink() || !meta_meta.is_file() {
                continue;
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }

    /// Delete a bundle directory using the safe leaf-up walker that
    /// rejects symlinks. The symlink TARGET is never followed; partial
    /// state on a symlinked-leaf rejection is acceptable here because
    /// the bundle is already being torn down.
    pub async fn delete_bundle(&self, name: &str) -> Result<(), SkillError> {
        validate_skill_name(name)?;
        safe_remove_dir_all(&self.bundle_root(name)).await
    }
}

/// Leaf-up directory walker that refuses symlinked entries. Mitigates the
/// `tokio::fs::remove_dir_all` follow-symlink hazard inherited from the
/// Slice C `DiskSkillStorage::delete_draft` precedent.
///
/// On encountering a symlinked entry, returns `Err`. Files visited BEFORE
/// the symlink encounter have already been deleted (partial-delete state);
/// the symlinked target itself is NOT followed. SE-05a locks the
/// symlink-target-untouched property.
fn safe_remove_dir_all(
    dir: &Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SkillError>> + Send + '_>> {
    Box::pin(async move {
        let meta = match tokio::fs::symlink_metadata(dir).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(SkillError::InvalidTransition(format!(
                    "symlink_metadata: {e}"
                )))
            }
        };
        if meta.file_type().is_symlink() {
            return Err(SkillError::InvalidTransition(format!(
                "refusing to walk symlink at {dir:?}"
            )));
        }
        if meta.is_dir() {
            let mut entries = tokio::fs::read_dir(dir)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("read_dir: {e}")))?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
            {
                safe_remove_dir_all(&entry.path()).await?;
            }
            tokio::fs::remove_dir(dir)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("remove_dir: {e}")))?;
        } else {
            tokio::fs::remove_file(dir)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("remove_file: {e}")))?;
        }
        Ok(())
    })
}
