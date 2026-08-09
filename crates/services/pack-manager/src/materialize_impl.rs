//! `DefaultMaterializer` (Slice B, AC-02 partial + AC-10 entry-point).
//!
//! Concrete `MaterializeAction` (CONTRACT-171) impl. Slice B ships 5 methods:
//! - `materialize_template`: copies pack `agent-templates/{name}/` → target/
//! - `materialize_skill`: copies pack `skills/{name}/` → target/
//! - `materialize_component`: returns runtime-internal `local_path` (no copy)
//! - `register_mcp_server`: returns deterministic McpServerId (pre-resolved secret-refs pass-through)
//! - `apply_workflow`: delegates to `WorkflowApplier`
//!
//! Remaining 5 methods return `PackError::NotImplemented(...)` per §3.5 Slice C
//! Feature Implementation Record row.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::PackError;
use crate::fetch::copy_dir_no_symlinks;
use crate::materialize::{
    GrantId, MaterializeAction, McpServerId, ResourceCapabilityId, WorkflowContext, WorkflowReport,
};
use crate::registry::{ComponentKind, PackRegistry};
use crate::workflow::{SecretStore, WorkflowApplier, WorkflowExecutor};

/// Maximum permitted workflow.yaml size at materialize time. Slice A
/// enforces this cap on `pack.yaml`; Slice B mirrors the same bound on
/// `provides[*]` files materialized post-install. Without this cap a pack
/// could ship a multi-GiB workflows/foo.yaml that is checksum-unbounded
/// (manifest controls coverage) and OOM the runtime at first apply_workflow
/// invocation. Adversarial round 1 W1 fix.
const MAX_WORKFLOW_YAML_BYTES_AT_MATERIALIZE: u64 = 1024 * 1024;

/// Slice C: cap on per-binary materialize copy size (matches
/// `verify::MAX_PER_ENTRY_BYTES`). Applied to `materialize_binary` and
/// `copy_memory_seed` source files.
const MAX_BINARY_MATERIALIZE_BYTES: u64 = 256 * 1024 * 1024;

/// Slice C: cap on small YAML files (preset YAML, meta-schema-extension
/// source/target) — matches the workflow.yaml cap.
const MAX_SMALL_YAML_BYTES: u64 = 1024 * 1024;

/// Slice C adversarial round 12 W2 fix: open `path` with `O_NOFOLLOW`
/// on Unix, fstat on the open FD, and read into a `Vec<u8>` bounded by
/// `max_bytes`. Used by `merge_meta_schema_extension` for both the pack
/// source and the on-disk target. Mirrors `copy_file_nofollow_bounded`
/// minus the copy-to-destination side.
fn read_bytes_nofollow_bounded(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, PackError> {
    use std::io::Read;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    PackError::InvalidManifest(format!(
                        "{label} is a symlink (rejected by O_NOFOLLOW): {}",
                        path.display()
                    ))
                } else {
                    PackError::Io {
                        path: path.to_path_buf(),
                        source: e,
                    }
                }
            })?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| PackError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    let md = file.metadata().map_err(|e| PackError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if !md.is_file() {
        return Err(PackError::InvalidManifest(format!(
            "{label} must be a regular file: {}",
            path.display()
        )));
    }
    if md.len() > max_bytes {
        return Err(PackError::InvalidManifest(format!(
            "{label} exceeds max size {max_bytes} bytes ({} bytes)",
            md.len()
        )));
    }
    let mut buf = Vec::with_capacity(md.len() as usize);
    (&mut file)
        .take(max_bytes)
        .read_to_end(&mut buf)
        .map_err(|e| PackError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(buf)
}

/// Open `src` with `O_NOFOLLOW` on Unix, fstat on the open FD to enforce
/// the size cap against the SAME inode the subsequent read will consume,
/// then stream-copy into `dst` (which must NOT pre-exist). Closes the
/// Slice C adversarial round 11 W3 TOCTOU window where a swap between
/// `symlink_metadata`/`std::fs::canonicalize` and `std::fs::copy` could
/// redirect the read to a different (potentially symlinked or oversized)
/// inode. On non-Unix platforms the open uses default behavior — the
/// residual TOCTOU window remains, bounded by the admin-trust model
/// (same posture as Slice B's `open_workflow_yaml_bounded`).
///
/// Returns the destination `PathBuf` on success; errors mirror
/// `materialize_binary` / `copy_memory_seed` semantics (InvalidManifest
/// for symlink/size/type rejections; Io for OS failures).
fn copy_file_nofollow_bounded(src: &Path, dst: &Path, max_bytes: u64) -> Result<(), PackError> {
    use std::io::{Read, Write};

    #[cfg(unix)]
    let mut src_file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(src)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    PackError::InvalidManifest(format!(
                        "materialize source is a symlink (rejected by O_NOFOLLOW): {}",
                        src.display()
                    ))
                } else {
                    PackError::Io {
                        path: src.to_path_buf(),
                        source: e,
                    }
                }
            })?
    };
    #[cfg(not(unix))]
    let mut src_file = std::fs::OpenOptions::new()
        .read(true)
        .open(src)
        .map_err(|e| PackError::Io {
            path: src.to_path_buf(),
            source: e,
        })?;
    let md = src_file.metadata().map_err(|e| PackError::Io {
        path: src.to_path_buf(),
        source: e,
    })?;
    if !md.is_file() {
        return Err(PackError::InvalidManifest(format!(
            "materialize source must be a regular file: {}",
            src.display()
        )));
    }
    if md.len() > max_bytes {
        return Err(PackError::InvalidManifest(format!(
            "materialize source exceeds max {max_bytes} bytes ({} bytes): {}",
            md.len(),
            src.display()
        )));
    }

    // Destination must NOT pre-exist (fresh-write invariant). Probe via
    // symlink_metadata so a planted symlink at dst is rejected outright.
    match std::fs::symlink_metadata(dst) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(PackError::InvalidManifest(format!(
                "materialize destination must not pre-exist: {}",
                dst.display()
            )));
        }
        Err(e) => {
            return Err(PackError::Io {
                path: dst.to_path_buf(),
                source: e,
            });
        }
    }
    // Open dst with `create_new(true)` (O_EXCL) so a concurrent attacker
    // creating dst between the probe above and the open below races into
    // an `AlreadyExists` error rather than silent overwrite.
    let mut dst_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| PackError::Io {
            path: dst.to_path_buf(),
            source: e,
        })?;
    // Stream-copy bounded by `take(max_bytes)` as defense-in-depth (fstat
    // already enforced size, but if the FD's underlying inode somehow
    // grows between fstat and read, the take limits the write).
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    let mut bounded = (&mut src_file).take(max_bytes);
    loop {
        let n = bounded.read(&mut buf).map_err(|e| PackError::Io {
            path: src.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        total += n as u64;
        dst_file.write_all(&buf[..n]).map_err(|e| PackError::Io {
            path: dst.to_path_buf(),
            source: e,
        })?;
    }
    if total > max_bytes {
        return Err(PackError::InvalidManifest(format!(
            "materialize source exceeded max {max_bytes} bytes mid-stream"
        )));
    }
    dst_file.sync_all().map_err(|e| PackError::Io {
        path: dst.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Open `path` with O_NOFOLLOW on Unix to refuse following any symlink-swap
/// that races between resolution and open (closing Adversarial round 2 W3
/// TOCTOU window). Then `metadata()` on the open FD (`fstat`-equivalent) so
/// the size check sees the SAME inode the read will consume. Finally read at
/// most `MAX_WORKFLOW_YAML_BYTES_AT_MATERIALIZE` bytes via `Read::take`.
///
/// Cross-platform note: Windows does not expose `O_NOFOLLOW` directly via
/// `std::fs::OpenOptions`; on Windows the open call uses default behavior and
/// the residual TOCTOU window from Slice A remains. Same admin-trust-model
/// bound as the rest of MODULE-018 §2.9.
fn open_workflow_yaml_bounded(path: &Path) -> Result<String, PackError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                // O_NOFOLLOW returns ELOOP when the FINAL path component is a
                // symlink. Surface this as InvalidWorkflow (matches the
                // intent of "reject symlink swap") rather than a raw I/O
                // error. ELOOP corresponds to ErrorKind::FilesystemLoop on
                // recent Rust, but for portability we match the raw_os_error.
                if e.raw_os_error() == Some(libc::ELOOP) {
                    PackError::InvalidWorkflow(format!(
                        "workflow yaml is a symlink (rejected by O_NOFOLLOW): {}",
                        path.display()
                    ))
                } else {
                    PackError::Io {
                        path: path.to_path_buf(),
                        source: e,
                    }
                }
            })?
    };
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| PackError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    let md = file.metadata().map_err(|e| PackError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if !md.is_file() {
        return Err(PackError::InvalidWorkflow(format!(
            "workflow yaml must be a regular file: {}",
            path.display()
        )));
    }
    if md.len() > MAX_WORKFLOW_YAML_BYTES_AT_MATERIALIZE {
        return Err(PackError::InvalidWorkflow(format!(
            "workflow yaml exceeds max {MAX_WORKFLOW_YAML_BYTES_AT_MATERIALIZE} bytes ({} bytes)",
            md.len()
        )));
    }
    let mut buf = String::with_capacity(md.len() as usize);
    file.take(MAX_WORKFLOW_YAML_BYTES_AT_MATERIALIZE)
        .read_to_string(&mut buf)
        .map_err(|e| PackError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(buf)
}

pub struct DefaultMaterializer {
    pub registry: Arc<dyn PackRegistry>,
    pub executor: Arc<dyn WorkflowExecutor>,
    pub secret_store: Arc<dyn SecretStore>,
}

impl DefaultMaterializer {
    pub fn new(
        registry: Arc<dyn PackRegistry>,
        executor: Arc<dyn WorkflowExecutor>,
        secret_store: Arc<dyn SecretStore>,
    ) -> Self {
        Self {
            registry,
            executor,
            secret_store,
        }
    }

    fn resolve_kind(&self, pack_ref: &str, expected: ComponentKind) -> Result<PathBuf, PackError> {
        let resolution = self.registry.resolve(pack_ref)?;
        if resolution.component_kind != expected {
            return Err(PackError::MaterializeMissingProvide {
                kind: format!("{expected:?}"),
                name: resolution.manifest_snippet.name.clone(),
            });
        }
        Ok(resolution.local_path)
    }
}

impl MaterializeAction for DefaultMaterializer {
    /// Slice C — `target` is the destination DIRECTORY. Copies the pack
    /// binary as `target.join("{name}.wasm")`. Caller pre-creates parent
    /// dirs; the final destination file MUST NOT pre-exist (fresh write
    /// invariant matching `copy_dir_no_symlinks`). Uses
    /// `copy_file_nofollow_bounded` to close the post-install
    /// symlink-swap TOCTOU window on the source path.
    fn materialize_binary(&self, pack_ref: &str, target: &Path) -> Result<PathBuf, PackError> {
        let local_path = self.resolve_kind(pack_ref, ComponentKind::Binary)?;
        // Use `name` directly from the resolution rather than re-deriving
        // via file_stem — `path_for_kind` already produces
        // `{install}/behavior-binaries/{name}.wasm`, so the resolved name
        // is the canonical identifier. Avoids the file_stem corner case
        // where a multi-dot name (e.g. `foo.bar`) would strip only the
        // last extension.
        let resolution = self.registry.resolve(pack_ref)?;
        let dest = target.join(format!("{}.wasm", resolution.manifest_snippet.name));
        copy_file_nofollow_bounded(&local_path, &dest, MAX_BINARY_MATERIALIZE_BYTES)?;
        Ok(dest)
    }

    fn materialize_template(&self, pack_ref: &str, target: &Path) -> Result<(), PackError> {
        let local_path = self.resolve_kind(pack_ref, ComponentKind::AgentTemplate)?;
        copy_dir_no_symlinks(&local_path, target)
    }

    fn materialize_skill(&self, pack_ref: &str, target: &Path) -> Result<(), PackError> {
        let local_path = self.resolve_kind(pack_ref, ComponentKind::Skill)?;
        copy_dir_no_symlinks(&local_path, target)
    }

    fn materialize_component(&self, pack_ref: &str, _target: &Path) -> Result<PathBuf, PackError> {
        let local_path = self.resolve_kind(pack_ref, ComponentKind::RunnableComponent)?;
        Ok(local_path)
    }

    /// Slice C — `target` is the destination DIRECTORY. Copies the channel
    /// adapter tree to `target/` using `copy_dir_no_symlinks` (same security
    /// posture as `materialize_template` / `materialize_skill`).
    fn materialize_channel_adapter(
        &self,
        pack_ref: &str,
        target: &Path,
    ) -> Result<PathBuf, PackError> {
        let local_path = self.resolve_kind(pack_ref, ComponentKind::ChannelAdapter)?;
        copy_dir_no_symlinks(&local_path, target)?;
        Ok(target.to_path_buf())
    }

    fn register_mcp_server(
        &self,
        pack_ref: &str,
        secret_refs: &HashMap<String, String>,
    ) -> Result<McpServerId, PackError> {
        let resolution = self.registry.resolve(pack_ref)?;
        if resolution.component_kind != ComponentKind::McpServer {
            return Err(PackError::MaterializeMissingProvide {
                kind: format!("{:?}", ComponentKind::McpServer),
                name: resolution.manifest_snippet.name.clone(),
            });
        }
        // Defense-in-depth: probe the YAML file exists as a regular file.
        let md = std::fs::symlink_metadata(&resolution.local_path).map_err(|e| PackError::Io {
            path: resolution.local_path.clone(),
            source: e,
        })?;
        if md.file_type().is_symlink() {
            return Err(PackError::InvalidManifest(format!(
                "mcp-server config is a symlink (rejected): {}",
                resolution.local_path.display()
            )));
        }
        if !md.is_file() {
            return Err(PackError::InvalidManifest(format!(
                "mcp-server config must be a regular file: {}",
                resolution.local_path.display()
            )));
        }
        // Resolve each `(placeholder, secret_id)` through SecretStore.
        // Adversarial round 2 W4 fix: previous Slice B behavior silently
        // discarded `secret_refs` and returned a deterministic ID, opening a
        // confused-deputy surface (Caller-A's prod-secret and Caller-B's
        // hijack-secret yielded the same ID). Now: missing secret →
        // MissingSecret error returned BEFORE any McpServerId is constructed,
        // matching the WorkflowApplier-layer pre-check (T28). The resolved
        // values are bound on the BTreeMap and dropped here (Slice B placeholder
        // semantics — actual MCP registration lands in M017 Slice C+).
        for secret_id in secret_refs.values() {
            if self.secret_store.get(secret_id).is_none() {
                return Err(PackError::MissingSecret {
                    key: secret_id.clone(),
                });
            }
        }
        // Slice B placeholder: returns deterministic McpServerId. Real M017
        // wiring computes its own id scheme (Slice C+).
        Ok(McpServerId(format!(
            "{}@{}/{}",
            resolution.pack_name, resolution.version, resolution.manifest_snippet.name
        )))
    }

    /// Slice C placeholder — validate the preset YAML exists at the
    /// resolved canonical path + validate `target_agent_id` is ASCII / no
    /// control bytes / non-empty, and return `Ok(vec![])`.
    ///
    /// Real grant issuance is MODULE-013's `PresetApplyApi` concern;
    /// Slice C ships the resolve + validate path so AC-02 收尾 (all 10
    /// materializer methods functional) is satisfied without crossing
    /// the M013 boundary. Documented in §3.5 / §3.6 Known Gaps.
    fn apply_preset(
        &self,
        pack_ref: &str,
        target_agent_id: &str,
    ) -> Result<Vec<GrantId>, PackError> {
        if target_agent_id.is_empty() {
            return Err(PackError::ConstraintViolation {
                reason: "apply_preset: target_agent_id must be non-empty".into(),
            });
        }
        if target_agent_id
            .chars()
            .any(|c| !c.is_ascii() || c.is_ascii_control())
        {
            return Err(PackError::ConstraintViolation {
                reason: "apply_preset: target_agent_id must be ASCII without control bytes".into(),
            });
        }
        let local_path = self.resolve_kind(pack_ref, ComponentKind::Preset)?;
        let md = std::fs::symlink_metadata(&local_path).map_err(|e| PackError::Io {
            path: local_path.clone(),
            source: e,
        })?;
        if md.file_type().is_symlink() {
            return Err(PackError::InvalidManifest(format!(
                "preset yaml is a symlink (rejected): {}",
                local_path.display()
            )));
        }
        if !md.is_file() {
            return Err(PackError::InvalidManifest(format!(
                "preset yaml must be a regular file: {}",
                local_path.display()
            )));
        }
        if md.len() > MAX_SMALL_YAML_BYTES {
            return Err(PackError::InvalidManifest(format!(
                "preset yaml exceeds max {MAX_SMALL_YAML_BYTES} bytes ({} bytes)",
                md.len()
            )));
        }
        // Slice C placeholder: zero grants issued; real grant integration
        // is MODULE-013 (§3.6 Known Gap).
        Ok(Vec::new())
    }

    fn apply_workflow(
        &self,
        pack_ref: &str,
        context: WorkflowContext,
    ) -> Result<WorkflowReport, PackError> {
        let local_path = self.resolve_kind(pack_ref, ComponentKind::Workflow)?;
        let yaml = open_workflow_yaml_bounded(&local_path)?;
        WorkflowApplier::apply(&yaml, &context, &*self.executor, &*self.secret_store)
    }

    /// Slice C — `target` is the destination FILE PATH (full path including
    /// filename; distinct from `materialize_binary`'s directory semantic —
    /// see method-level rustdoc above). Uses `copy_file_nofollow_bounded`
    /// to close the source-side symlink-swap TOCTOU window.
    fn copy_memory_seed(&self, pack_ref: &str, target: &Path) -> Result<(), PackError> {
        let local_path = self.resolve_kind(pack_ref, ComponentKind::MemorySeed)?;
        copy_file_nofollow_bounded(&local_path, target, MAX_BINARY_MATERIALIZE_BYTES)
    }

    /// Slice C — byte-level multi-document YAML concatenation. Real
    /// semantic union (parse → merge → re-emit) belongs to MODULE-002's
    /// `MetaSchemaManager` (§3.6 Known Gap). When `target_schema` exists
    /// without a trailing `\n`, prepend `\n` to the `---\n` separator so
    /// downstream multi-doc parsers see a clean document boundary.
    /// Atomic-write via tempfile + rename. Slice C adversarial round 12
    /// W2: source AND target reads go through `read_bytes_nofollow_bounded`
    /// (Unix O_NOFOLLOW + fstat-on-FD + bounded Read::take) so a swap
    /// between probe and read cannot bypass the 1 MiB cap or symlink
    /// rejection.
    fn merge_meta_schema_extension(
        &self,
        pack_ref: &str,
        target_schema: &Path,
    ) -> Result<(), PackError> {
        let local_path = self.resolve_kind(pack_ref, ComponentKind::MetaSchemaExtension)?;
        let source_bytes = read_bytes_nofollow_bounded(
            &local_path,
            MAX_SMALL_YAML_BYTES,
            "meta-schema-extension source",
        )?;

        // Target may not exist (copy verbatim) OR may exist (append with
        // separator). Both branches use O_NOFOLLOW + bounded read.
        let merged: Vec<u8> = match std::fs::symlink_metadata(target_schema) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut v = source_bytes.clone();
                if v.last().is_none_or(|b| *b != b'\n') {
                    v.push(b'\n');
                }
                v
            }
            Ok(leaf_md) => {
                if leaf_md.file_type().is_symlink() {
                    return Err(PackError::InvalidManifest(format!(
                        "meta-schema-extension target is a symlink (rejected): {}",
                        target_schema.display()
                    )));
                }
                let target_bytes = read_bytes_nofollow_bounded(
                    target_schema,
                    MAX_SMALL_YAML_BYTES,
                    "meta-schema-extension target",
                )?;
                let mut v = target_bytes;
                let needs_leading_nl = v.last().is_none_or(|b| *b != b'\n');
                if needs_leading_nl {
                    v.push(b'\n');
                }
                v.extend_from_slice(b"---\n");
                v.extend_from_slice(&source_bytes);
                if v.last().is_none_or(|b| *b != b'\n') {
                    v.push(b'\n');
                }
                v
            }
            Err(e) => {
                return Err(PackError::Io {
                    path: target_schema.to_path_buf(),
                    source: e,
                });
            }
        };

        // Atomic-write: tempfile in same dir → fsync → rename.
        let parent = target_schema.parent().unwrap_or_else(|| Path::new("."));
        let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let tmp = parent.join(format!(
            ".meta-schema-merge.tmp.{}.{}",
            std::process::id(),
            nanos
        ));
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| PackError::Io {
                    path: tmp.clone(),
                    source: e,
                })?;
            f.write_all(&merged).map_err(|e| PackError::Io {
                path: tmp.clone(),
                source: e,
            })?;
            f.sync_all().map_err(|e| PackError::Io {
                path: tmp.clone(),
                source: e,
            })?;
        }
        std::fs::rename(&tmp, target_schema).map_err(|e| {
            // Best-effort cleanup of the tempfile if rename fails.
            let _ = std::fs::remove_file(&tmp);
            PackError::Io {
                path: target_schema.to_path_buf(),
                source: e,
            }
        })?;
        Ok(())
    }

    /// AC-17 (m018-rescap) — register-not-copy REGISTRATION surface for the
    /// `resource-capabilities` category (the `apply_preset` precedent). Resolves the
    /// pack ref to `ComponentKind::ResourceCapability` (wrong-kind → `MaterializeMissingProvide`),
    /// parses + validates the on-disk `capability.yaml` (bounded / symlink-safe /
    /// alias-guarded, via `parse_resource_capability_manifest`), and returns the
    /// content-derived `ResourceCapabilityId` (the manifest `id`). Nothing is copied into
    /// a workspace — there is no `target`. The live runtime-ToolRegistry bridge +
    /// exposure (MODULE-017 §3.6 (ddd)) that makes the capability's tools callable by
    /// agents is deferred.
    fn register_resource_capability(
        &self,
        pack_ref: &str,
    ) -> Result<ResourceCapabilityId, PackError> {
        // resolve_kind returns the capability DIRECTORY
        // (`{install}/resource-capabilities/{name}`) and enforces the kind guard.
        let cap_dir = self.resolve_kind(pack_ref, ComponentKind::ResourceCapability)?;
        let manifest = crate::component_manifest::parse_resource_capability_manifest(&cap_dir)?;
        Ok(ResourceCapabilityId(manifest.id))
    }
}
