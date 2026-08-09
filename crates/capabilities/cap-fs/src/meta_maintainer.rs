//! `.meta.yaml` maintenance — load + auto-populate + atomic update (slice B).
//!
//! Implements MODULE-002 §1.4.4 (handle_fs_write/handle_fs_delete triple-consistency
//! flow, `.meta.yaml` half) + §1.4.5 (workspace meta-schema) + §1.4.6 fs.write/delete
//! integration via the meta-first commit pattern.
//!
//! Concurrency: a per-instance `tokio::sync::Mutex<()>` (`meta_lock`) serializes
//! ALL `.meta.yaml` mutations. Slice B's pin: single global lock — accept the
//! contention; slice C may refine to per-directory locking via DashMap.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::atomic::AtomicWriter;
use crate::entry::ScopeMeta;
use crate::error::{sanitize_io_error, FsError};
use crate::meta_schema::{entity_type, parse_frontmatter_type, FieldType, MetaSchemaLoader};

/// Per-entry metadata in a `.meta.yaml`. Maps the WIT `record entry` shape PLUS
/// schema-extension fields stored in `extra`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryMetaValues {
    pub name: String,
    pub slug: String,
    pub description: String,
    /// First-class OKF entity `type` discriminator (ADR 2026-06-29 Decision 1).
    /// Auto-populated deterministically (never model-inferred): `.md` w/ OKF
    /// frontmatter `type` → that value; `.md` w/o → `document`; non-`.md` file →
    /// `asset`; directory child → `collection` (set at the directory sites).
    /// `#[serde(default)]` keeps deserialization of pre-`type` `.meta.yaml`
    /// entries backward-compatible (empty → the reconciler backfills).
    #[serde(rename = "type", default)]
    pub r#type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Schema-extension fields (e.g. `priority: 0`, `published: false`).
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_yml::Value>,
}

/// In-memory representation of a `.meta.yaml` file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MetaFile {
    pub scope: ScopeMeta,
    /// Entry name → entry meta. Entries are persisted as top-level YAML keys
    /// alongside `_scope`.
    pub entries: BTreeMap<String, EntryMetaValues>,
}

/// `.meta.yaml` filename (always `.meta.yaml` at the directory level).
const META_YAML_NAME: &str = ".meta.yaml";

/// Per-field bounds on guest-supplied metadata. The cap is intentionally small
/// relative to MAX_WRITE_BYTES (64 MiB): a guest can otherwise persist a
/// near-MAX_WRITE_BYTES `.meta.yaml` inside their own territory and force
/// every subsequent `scan` / `load` to read+parse it, amplifying memory and
/// CPU per call.
const MAX_DESCRIPTION_BYTES: usize = 4096;
const MAX_TAGS_COUNT: usize = 32;
const MAX_TAG_BYTES: usize = 128;

/// Aggregate cap on the on-disk `.meta.yaml` size. Per-field caps alone don't
/// stop a guest from creating thousands of files in one dir — each entry
/// individually capped at ~5 KiB — to balloon the aggregate `.meta.yaml`
/// past hundreds of MiB. Subsequent `load`/`scan` would then read+parse the
/// whole file. 4 MiB caps the directory at ~400 max-sized entries, well
/// above realistic per-dir entry counts but far below DoS amplification.
const MAX_META_YAML_BYTES: usize = 4 * 1024 * 1024;

/// Adversarial-round-1 W6: per-field cap on schema-optional default
/// values that flow into `entry.extra`. The schema loader itself is
/// operator-trusted (M013 grant-manager owns it), so this is defense in
/// depth — a misconfigured schema with a multi-MB default would
/// otherwise inflate every entry's `.meta.yaml` serialization past
/// `MAX_META_YAML_BYTES`, bricking writes/loads in that directory. 4 KiB
/// matches the per-description cap so optional extension defaults can't
/// exceed the same per-field budget required fields face.
const MAX_EXTRA_FIELD_BYTES: usize = 4096;

/// Approximate the serialized size of a `serde_yml::Value` and reject
/// values exceeding `MAX_EXTRA_FIELD_BYTES`. We use `serde_yml::to_string`
/// for an upper bound that closely matches what the on-disk YAML body
/// will contain. On serialization error (very rare for valid Values),
/// reject conservatively.
fn extra_field_within_cap(v: &serde_yml::Value) -> bool {
    serde_yml::to_string(v)
        .map(|s| s.len() <= MAX_EXTRA_FIELD_BYTES)
        .unwrap_or(false)
}

/// Bound description + tags for `update_scope` / `update_entry_meta`. Returns
/// `InvalidPath` (the schema-validation error variant) on violation so
/// guest-visible errors are consistent with the rest of the schema-validation
/// path (e.g. empty description).
fn validate_metadata_strings(description: &str, tags: &[String]) -> Result<(), FsError> {
    if description.trim().is_empty() {
        return Err(FsError::InvalidPath(
            "schema validation: description must not be empty".to_string(),
        ));
    }
    if description.len() > MAX_DESCRIPTION_BYTES {
        return Err(FsError::InvalidPath(format!(
            "schema validation: description exceeds MAX_DESCRIPTION_BYTES ({MAX_DESCRIPTION_BYTES} bytes)"
        )));
    }
    if tags.len() > MAX_TAGS_COUNT {
        return Err(FsError::InvalidPath(format!(
            "schema validation: tags count exceeds MAX_TAGS_COUNT ({MAX_TAGS_COUNT})"
        )));
    }
    for t in tags {
        if t.len() > MAX_TAG_BYTES {
            return Err(FsError::InvalidPath(format!(
                "schema validation: tag exceeds MAX_TAG_BYTES ({MAX_TAG_BYTES} bytes)"
            )));
        }
    }
    Ok(())
}

/// `.meta.yaml` maintainer — loads, auto-populates, writes via injectable AtomicWriter.
pub struct MetaMaintainer {
    schema: Arc<MetaSchemaLoader>,
    writer: Arc<dyn AtomicWriter>,
    /// Per-instance global mutex serializing ALL .meta.yaml writes. Slice B's
    /// pin (acknowledged limitation in plan Risk #14): accept the contention.
    meta_lock: Mutex<()>,
}

impl MetaMaintainer {
    pub fn new(schema: Arc<MetaSchemaLoader>, writer: Arc<dyn AtomicWriter>) -> Self {
        Self {
            schema,
            writer,
            meta_lock: Mutex::new(()),
        }
    }

    /// Compute the `.meta.yaml` path for a given directory.
    pub fn meta_path(dir: &Path) -> PathBuf {
        dir.join(META_YAML_NAME)
    }

    /// Acquire the global meta-write lock.
    pub async fn acquire(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.meta_lock.lock().await
    }

    /// Load `.meta.yaml` from `dir`. Returns `Ok(None)` if missing,
    /// `Err` for parse / IO errors. Reads are bounded by `MAX_META_YAML_BYTES`
    /// to prevent aggregate-DoS: even with per-field caps, a guest could
    /// otherwise create thousands of files in one dir → an unbounded
    /// `.meta.yaml` that subsequent scan/load reads + parses on every call.
    pub async fn load(&self, dir: &Path) -> Result<Option<MetaFile>, FsError> {
        let path = Self::meta_path(dir);
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(FsError::IoError(sanitize_io_error(&e))),
        };
        if metadata.len() > MAX_META_YAML_BYTES as u64 {
            return Err(FsError::IoError(format!(
                ".meta.yaml exceeds MAX_META_YAML_BYTES ({MAX_META_YAML_BYTES} bytes)"
            )));
        }
        match tokio::fs::read_to_string(&path).await {
            Ok(yaml) => parse_meta_yaml(&yaml).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(FsError::IoError(sanitize_io_error(&e))),
        }
    }

    /// Unified add-entry-on-write: takes Option<MetaFile> (None = no .meta.yaml
    /// existed) and produces the new state with the entry auto-populated.
    /// Returns the updated MetaFile + list of fields that were set.
    pub fn add_entry_for_write(
        &self,
        meta_pre: Option<MetaFile>,
        file_name: &str,
        body_for_extract: &[u8],
    ) -> Result<(MetaFile, Vec<String>), FsError> {
        let schema = self.schema.current();
        let mut meta = meta_pre.unwrap_or_default();
        let mut changed_fields = Vec::new();

        if !meta.entries.contains_key(file_name) {
            // New entry — auto-populate required fields.
            let name = schema
                .auto_generate("name", file_name, body_for_extract)
                .unwrap_or_else(|| file_name.to_string());
            let slug = schema
                .auto_generate("slug", file_name, body_for_extract)
                .unwrap_or_default();
            let description_raw = schema
                .auto_generate("description", file_name, body_for_extract)
                .unwrap_or_default();
            let description = if description_raw.is_empty() {
                format!("[pending] {file_name}")
            } else {
                description_raw
            };
            // Entity `type` FILE default (ADR 2026-06-29 Decision 1). Always a
            // FILE here (fs.write / reconcile-file paths); the directory →
            // `collection` case is set explicitly at the directory sites.
            // `auto_generate` uses the schema's EntityTypeDefault rule when the
            // schema declares `type`; the fallback covers a custom schema that
            // does not (the entry is still a first-class-typed value).
            let r#type = schema
                .auto_generate("type", file_name, body_for_extract)
                .unwrap_or_else(|| {
                    entity_type(
                        file_name,
                        false,
                        parse_frontmatter_type(body_for_extract).as_deref(),
                    )
                });

            // Apply optional schema defaults to materialize tags/status/extension fields.
            let mut tags: Vec<String> = Vec::new();
            let mut status: Option<String> = None;
            let mut extra: BTreeMap<String, serde_yml::Value> = BTreeMap::new();
            for (field_name, spec) in &schema.optional {
                if let Some(default) = &spec.default {
                    // Adversarial-round-2 W6 closure: apply the same per-
                    // field byte cap to ALL schema-optional defaults
                    // (`tags`, `status`, AND extension fields). The
                    // round-1 fix only covered the `extra` flow; oversized
                    // tags/status defaults in a misconfigured schema could
                    // still inflate every entry's `.meta.yaml`. Reject
                    // oversized defaults uniformly — the per-field cap
                    // matches MAX_DESCRIPTION_BYTES so optional-field
                    // budgets cannot exceed required-field budgets.
                    if !extra_field_within_cap(default) {
                        continue;
                    }
                    match field_name.as_str() {
                        "tags" => {
                            if let serde_yml::Value::Sequence(items) = default {
                                tags = items
                                    .iter()
                                    .filter_map(|i| match i {
                                        serde_yml::Value::String(s) => Some(s.clone()),
                                        _ => None,
                                    })
                                    .collect();
                            }
                        }
                        "status" => {
                            if let serde_yml::Value::String(s) = default {
                                status = Some(s.clone());
                            }
                        }
                        other => {
                            extra.insert(other.to_string(), default.clone());
                        }
                    }
                }
            }

            let entry = EntryMetaValues {
                name,
                slug,
                description,
                r#type,
                tags,
                status,
                extra,
            };
            meta.entries.insert(file_name.to_string(), entry);
            changed_fields.push("name".to_string());
            changed_fields.push("slug".to_string());
            changed_fields.push("description".to_string());
            changed_fields.push("type".to_string());
        }
        // Existing entry: do NOT re-auto-populate (preserve user-set values).
        Ok((meta, changed_fields))
    }

    /// Remove an entry from MetaFile. If the entry didn't exist, returns the
    /// unchanged MetaFile + empty changed_fields.
    pub fn remove_entry(&self, mut meta: MetaFile, file_name: &str) -> (MetaFile, Vec<String>) {
        if meta.entries.remove(file_name).is_some() {
            (meta, vec!["_removed".to_string()])
        } else {
            (meta, Vec::new())
        }
    }

    /// Atomic `.meta.yaml` write via the injectable writer. Returns the
    /// serialized yaml bytes — callers may store them as a "what we just
    /// committed" snapshot for cancellation-safe rollback (see
    /// `MetaRollbackGuard` in host_fn.rs: rollback only fires if the on-disk
    /// .meta.yaml still matches these bytes; otherwise an intervening op
    /// has superseded our commit and we leave it alone).
    ///
    /// The aggregate `MAX_META_YAML_BYTES` cap is enforced BEFORE persistence
    /// here, not just on read — otherwise a guest could push the .meta.yaml
    /// from just under the cap to just over via one final mutation, after
    /// which every subsequent load (4 MiB+) fails and the directory becomes
    /// permanently unscannable (self-DoS, AC-10 invariant violated).
    pub async fn write(&self, dir: &Path, meta: &MetaFile) -> Result<Vec<u8>, FsError> {
        let yaml = serialize_meta_yaml(meta)?;
        if yaml.len() > MAX_META_YAML_BYTES {
            return Err(FsError::IoError(format!(
                ".meta.yaml serialization exceeds MAX_META_YAML_BYTES ({MAX_META_YAML_BYTES} bytes)"
            )));
        }
        let path = Self::meta_path(dir);
        let bytes = yaml.into_bytes();
        self.writer.write(&path, &bytes).await?;
        Ok(bytes)
    }

    /// Update `_scope` (used by update-scope host fn). Validates description
    /// non-empty + bounded, tags bounded (count + per-element length).
    pub fn update_scope(
        &self,
        mut meta: MetaFile,
        description: String,
        tags: Vec<String>,
    ) -> Result<(MetaFile, Vec<String>), FsError> {
        validate_metadata_strings(&description, &tags)?;
        meta.scope.description = description;
        meta.scope.tags = tags;
        Ok((meta, vec!["description".to_string(), "tags".to_string()]))
    }

    /// Update entry meta. Validates entry exists + description non-empty +
    /// bounded, tags bounded.
    pub fn update_entry_meta(
        &self,
        mut meta: MetaFile,
        entry_name: &str,
        description: String,
        tags: Vec<String>,
    ) -> Result<(MetaFile, Vec<String>), FsError> {
        let schema = self.schema.current();
        validate_metadata_strings(&description, &tags)?;
        // Validate tags type matches schema (if tags is declared in schema)
        if let Some(spec) = schema.optional.get("tags") {
            if !matches!(spec.field_type, FieldType::ListString) {
                return Err(FsError::InvalidPath(
                    "schema validation: tags field type mismatch".to_string(),
                ));
            }
        }
        let entry = meta.entries.get_mut(entry_name).ok_or_else(|| {
            FsError::InvalidPath(format!(
                "schema validation: entry {entry_name} does not exist"
            ))
        })?;
        entry.description = description;
        entry.tags = tags;
        Ok((meta, vec!["description".to_string(), "tags".to_string()]))
    }

    /// Best-effort delete of `.meta.yaml` (used as part of fs.write rollback when
    /// meta_pre was None — i.e. the meta-first commit created a new file that
    /// we need to undo).
    pub async fn delete_meta_file(&self, dir: &Path) -> Result<(), FsError> {
        let path = Self::meta_path(dir);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(FsError::IoError(sanitize_io_error(&e))),
        }
    }

    /// Ensure `.meta.yaml` exists at `dir`. If missing, create with auto-populated
    /// `_scope` (slug from dir name; description = `[pending] {dir_name}`;
    /// status = None; tags = []).
    /// `parent_for_entry`: when `Some`, also ensures the parent's `.meta.yaml`
    /// has an entry for `dir`'s name (auto-populated via `add_entry_for_write`
    /// with empty body, marked `extra.is_dir = true`). If the parent has no
    /// `.meta.yaml`, one is created with auto-populated `_scope` first. Both
    /// legs are idempotent: the function may be re-invoked safely after a prior
    /// partial failure (e.g. child write succeeded but parent write crashed) —
    /// the second call detects the existing child + missing parent entry and
    /// completes only the unfinished work.
    /// Returns `Ok(true)` if a NEW `.meta.yaml` was created at `dir`,
    /// `Ok(false)` if `.meta.yaml` already existed (parent leg may still have
    /// run on this call to repair partial-failure drift).
    ///
    /// Slice C primitive (AC-03): MODULE-005 spawn-child / spawn-sub will call this
    /// when creating territory directories. Reconciliation also calls this for any
    /// directory missing its `.meta.yaml`.
    pub async fn ensure_dir_meta(
        &self,
        dir: &Path,
        parent_for_entry: Option<&Path>,
    ) -> Result<bool, FsError> {
        let _guard = self.acquire().await;
        let dir_name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("workspace")
            .to_string();

        // Step 1: child leg — ensure dir/.meta.yaml exists with auto-scope.
        let child_existed = self.load(dir).await?.is_some();
        if !child_existed {
            let meta = self.build_default_meta(&dir_name);
            self.write(dir, &meta).await?;
        }

        // Step 2: parent leg — ensure parent's .meta.yaml lists this dir as
        // an entry. Runs independently of step 1 so a retry after a
        // partial-failure (child written, parent crashed) still completes the
        // parent leg. If the parent has no .meta.yaml at all, bootstrap one
        // with auto-scope before adding the entry — preserves the AC-17
        // "single metadata index tree root" invariant.
        if let Some(parent) = parent_for_entry {
            let mut parent_meta = match self.load(parent).await? {
                Some(m) => m,
                None => {
                    let parent_name = parent
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("workspace")
                        .to_string();
                    self.build_default_meta(&parent_name)
                }
            };
            if !parent_meta.entries.contains_key(&dir_name) {
                let (next, _changed) =
                    self.add_entry_for_write(Some(parent_meta.clone()), &dir_name, b"")?;
                parent_meta = next;
                if let Some(entry) = parent_meta.entries.get_mut(&dir_name) {
                    entry
                        .extra
                        .insert("is_dir".to_string(), serde_yml::Value::Bool(true));
                    // The subdir child is a directory → `collection` (ADR
                    // 2026-06-29 Decision 1). Override `add_entry_for_write`'s
                    // FILE default (`is_dir=false` → `asset`), which would
                    // otherwise be stickily wrong (the reconcile repair loop
                    // preserves non-empty types).
                    entry.r#type = "collection".to_string();
                }
                self.write(parent, &parent_meta).await?;
            }
        }

        Ok(!child_existed)
    }

    /// Build a fresh `MetaFile` with auto-populated `_scope` for `dir_name`,
    /// no entries. Internal helper for `ensure_dir_meta`'s child + parent
    /// bootstrap legs (kept private — callers go through `ensure_dir_meta`
    /// which owns the meta_lock acquisition + idempotency contract).
    fn build_default_meta(&self, dir_name: &str) -> MetaFile {
        let schema = self.schema.current();
        let mut scope = ScopeMeta::default();
        scope.slug = schema.auto_generate("slug", dir_name, b"");
        let raw_desc = schema
            .auto_generate("description", dir_name, b"")
            .unwrap_or_default();
        scope.description = if raw_desc.is_empty() {
            format!("[pending] {dir_name}")
        } else {
            raw_desc
        };
        scope.tags = Vec::new();
        scope.status = None;
        MetaFile {
            scope,
            entries: BTreeMap::new(),
        }
    }

    /// Repair empty required fields on an existing entry. For each schema-required
    /// field where `entry`'s current value is empty, run
    /// `schema.auto_generate(field, file_name, b"")` and mutate the entry in place.
    /// Returns the list of repaired field names (empty if no repairs were needed).
    ///
    /// Slice C primitive (AC-13): the `WorkspaceReconciler` invokes this on every
    /// existing meta entry during reconciliation. This fn repairs only
    /// `name`/`slug`/`description` and does NOT read file bytes — body is `b""`,
    /// so the schema's `content-extract` rule produces the `[pending] {file_name}`
    /// description fallback. The entity `type` (ADR 2026-06-29 Decision 1) is NOT
    /// repaired here — it is resolved by the reconcile loop's dedicated
    /// `backfill_entry_type` step (which has `dir` + `is_dir` and does a bounded,
    /// hardened `.md` frontmatter head-read for type-absent Markdown entries;
    /// MODULE-002 §1.4.6). Future hardening (deferred to a perf-budget slice) may
    /// re-read text files when description is `[pending]`.
    pub fn repair_entry_required_fields(
        &self,
        entry: &mut EntryMetaValues,
        file_name: &str,
    ) -> Vec<String> {
        let schema = self.schema.current();
        let mut repaired = Vec::new();
        if entry.name.is_empty() {
            if let Some(v) = schema.auto_generate("name", file_name, b"") {
                if !v.is_empty() {
                    entry.name = v;
                    repaired.push("name".to_string());
                }
            }
        }
        if entry.slug.is_empty() {
            if let Some(v) = schema.auto_generate("slug", file_name, b"") {
                if !v.is_empty() {
                    entry.slug = v;
                    repaired.push("slug".to_string());
                }
            }
        }
        if entry.description.is_empty() {
            let raw = schema
                .auto_generate("description", file_name, b"")
                .unwrap_or_default();
            entry.description = if raw.is_empty() {
                format!("[pending] {file_name}")
            } else {
                raw
            };
            repaired.push("description".to_string());
        }
        repaired
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML serialization. The serialized shape:
//   _scope:
//     slug: ...
//     description: ...
//     tags: [...]
//     status: ...
//   <entry-name>:
//     name: ...
//     slug: ...
//     description: ...
//     tags: [...]
//     status: ...
//     <extension-fields>: ...
// ─────────────────────────────────────────────────────────────────────────────

fn serialize_meta_yaml(meta: &MetaFile) -> Result<String, FsError> {
    let mut top = serde_yml::Mapping::new();
    // _scope
    let mut scope_map = serde_yml::Mapping::new();
    if let Some(slug) = &meta.scope.slug {
        scope_map.insert(
            serde_yml::Value::String("slug".to_string()),
            serde_yml::Value::String(slug.clone()),
        );
    }
    scope_map.insert(
        serde_yml::Value::String("description".to_string()),
        serde_yml::Value::String(meta.scope.description.clone()),
    );
    if !meta.scope.tags.is_empty() {
        scope_map.insert(
            serde_yml::Value::String("tags".to_string()),
            serde_yml::Value::Sequence(
                meta.scope
                    .tags
                    .iter()
                    .map(|t| serde_yml::Value::String(t.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(status) = &meta.scope.status {
        scope_map.insert(
            serde_yml::Value::String("status".to_string()),
            serde_yml::Value::String(status.clone()),
        );
    }
    // Scope entity `type` (ADR 2026-06-29 Decision 1) — `collection` for a
    // directory scope by default; persisted when present.
    if let Some(t) = &meta.scope.r#type {
        scope_map.insert(
            serde_yml::Value::String("type".to_string()),
            serde_yml::Value::String(t.clone()),
        );
    }
    top.insert(
        serde_yml::Value::String("_scope".to_string()),
        serde_yml::Value::Mapping(scope_map),
    );
    // entries
    for (name, entry) in &meta.entries {
        let mut em = serde_yml::Mapping::new();
        em.insert(
            serde_yml::Value::String("name".to_string()),
            serde_yml::Value::String(entry.name.clone()),
        );
        em.insert(
            serde_yml::Value::String("slug".to_string()),
            serde_yml::Value::String(entry.slug.clone()),
        );
        em.insert(
            serde_yml::Value::String("description".to_string()),
            serde_yml::Value::String(entry.description.clone()),
        );
        // Entity `type` (ADR 2026-06-29 Decision 1) — first-class, emitted when
        // set (empty only transiently before the reconciler backfills it).
        if !entry.r#type.is_empty() {
            em.insert(
                serde_yml::Value::String("type".to_string()),
                serde_yml::Value::String(entry.r#type.clone()),
            );
        }
        if !entry.tags.is_empty() {
            em.insert(
                serde_yml::Value::String("tags".to_string()),
                serde_yml::Value::Sequence(
                    entry
                        .tags
                        .iter()
                        .map(|t| serde_yml::Value::String(t.clone()))
                        .collect(),
                ),
            );
        }
        if let Some(status) = &entry.status {
            em.insert(
                serde_yml::Value::String("status".to_string()),
                serde_yml::Value::String(status.clone()),
            );
        }
        for (k, v) in &entry.extra {
            em.insert(serde_yml::Value::String(k.clone()), v.clone());
        }
        top.insert(
            serde_yml::Value::String(name.clone()),
            serde_yml::Value::Mapping(em),
        );
    }
    serde_yml::to_string(&serde_yml::Value::Mapping(top))
        .map_err(|e| FsError::IoError(format!("serialize meta.yaml: {e}")))
}

fn parse_meta_yaml(yaml: &str) -> Result<MetaFile, FsError> {
    let v: serde_yml::Value = serde_yml::from_str(yaml).map_err(|_| {
        FsError::IoError("malformed .meta.yaml: invalid yaml structure".to_string())
    })?;
    let map = match v {
        serde_yml::Value::Mapping(m) => m,
        _ => {
            return Err(FsError::IoError(
                "malformed .meta.yaml: top-level must be a mapping".to_string(),
            ))
        }
    };

    let mut scope = ScopeMeta::default();
    let mut entries: BTreeMap<String, EntryMetaValues> = BTreeMap::new();

    for (k, v) in map {
        let key_str = match k {
            serde_yml::Value::String(s) => s,
            _ => continue,
        };
        if key_str == "_scope" {
            scope = parse_scope_block(v)?;
        } else {
            // Per-entry block
            let entry = parse_entry_block(&key_str, v)?;
            entries.insert(key_str, entry);
        }
    }

    Ok(MetaFile { scope, entries })
}

fn parse_scope_block(v: serde_yml::Value) -> Result<ScopeMeta, FsError> {
    let map = match v {
        serde_yml::Value::Mapping(m) => m,
        _ => {
            return Err(FsError::IoError(
                "malformed .meta.yaml: _scope must be a mapping".to_string(),
            ))
        }
    };
    let mut scope = ScopeMeta::default();
    for (k, val) in map {
        let key_str = match k {
            serde_yml::Value::String(s) => s,
            _ => continue,
        };
        match key_str.as_str() {
            "slug" => {
                if let serde_yml::Value::String(s) = val {
                    scope.slug = Some(s);
                }
            }
            "description" => {
                if let serde_yml::Value::String(s) = val {
                    scope.description = s;
                }
            }
            "tags" => {
                if let serde_yml::Value::Sequence(items) = val {
                    scope.tags = items
                        .into_iter()
                        .filter_map(|i| match i {
                            serde_yml::Value::String(s) => Some(s),
                            _ => None,
                        })
                        .collect();
                }
            }
            "status" => {
                if let serde_yml::Value::String(s) = val {
                    scope.status = Some(s);
                }
            }
            // Explicit `_scope.type` overrides the `Default` (`collection`);
            // an absent `type` leaves the `ScopeMeta::default()` value in place
            // (ADR 2026-06-29 Decision 1 — read-time backfill for old files).
            "type" => {
                if let serde_yml::Value::String(s) = val {
                    scope.r#type = Some(s);
                }
            }
            _ => {}
        }
    }
    Ok(scope)
}

fn parse_entry_block(_name: &str, v: serde_yml::Value) -> Result<EntryMetaValues, FsError> {
    let map = match v {
        serde_yml::Value::Mapping(m) => m,
        _ => {
            return Err(FsError::IoError(
                "malformed .meta.yaml: entry must be a mapping".to_string(),
            ))
        }
    };
    let mut name = String::new();
    let mut slug = String::new();
    let mut description = String::new();
    let mut r#type = String::new();
    let mut tags: Vec<String> = Vec::new();
    let mut status: Option<String> = None;
    let mut extra: BTreeMap<String, serde_yml::Value> = BTreeMap::new();

    for (k, val) in map {
        let key_str = match k {
            serde_yml::Value::String(s) => s,
            _ => continue,
        };
        match key_str.as_str() {
            "name" => {
                if let serde_yml::Value::String(s) = val {
                    name = s;
                }
            }
            "slug" => {
                if let serde_yml::Value::String(s) = val {
                    slug = s;
                }
            }
            "description" => {
                if let serde_yml::Value::String(s) = val {
                    description = s;
                }
            }
            "tags" => {
                if let serde_yml::Value::Sequence(items) = val {
                    tags = items
                        .into_iter()
                        .filter_map(|i| match i {
                            serde_yml::Value::String(s) => Some(s),
                            _ => None,
                        })
                        .collect();
                }
            }
            "status" => {
                if let serde_yml::Value::String(s) = val {
                    status = Some(s);
                }
            }
            // First-class entity `type` (ADR 2026-06-29 Decision 1) — routed to
            // the struct field, NOT the `extra` catch-all below.
            "type" => {
                if let serde_yml::Value::String(s) = val {
                    r#type = s;
                }
            }
            other => {
                extra.insert(other.to_string(), val);
            }
        }
    }
    Ok(EntryMetaValues {
        name,
        slug,
        description,
        r#type,
        tags,
        status,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomic::DefaultAtomicWriter;

    fn maintainer() -> Arc<MetaMaintainer> {
        let schema_path = std::env::temp_dir().join("schema-mm-test.yaml");
        let loader = Arc::new(MetaSchemaLoader::new_with_default(schema_path));
        Arc::new(MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter)))
    }

    #[tokio::test]
    async fn load_returns_none_for_missing_meta_yaml() {
        let dir = tempfile::TempDir::new().unwrap();
        let mm = maintainer();
        let r = mm.load(dir.path()).await.unwrap();
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn write_then_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let mm = maintainer();
        let mut meta = MetaFile::default();
        meta.scope.description = "test scope".into();
        meta.scope.tags = vec!["a".into(), "b".into()];
        meta.entries.insert(
            "x.md".into(),
            EntryMetaValues {
                name: "x".into(),
                slug: "x".into(),
                description: "the x file".into(),
                r#type: "document".into(),
                tags: vec![],
                status: None,
                extra: BTreeMap::new(),
            },
        );
        mm.write(dir.path(), &meta).await.unwrap();
        let loaded = mm.load(dir.path()).await.unwrap().unwrap();
        assert_eq!(loaded.scope.description, "test scope");
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries.get("x.md").unwrap().slug, "x");
        // `type` round-trips through serialize/parse (first-class field).
        assert_eq!(loaded.entries.get("x.md").unwrap().r#type, "document");
        // `_scope.type` defaults to `collection` and round-trips.
        assert_eq!(loaded.scope.r#type.as_deref(), Some("collection"));
    }

    #[tokio::test]
    async fn add_entry_for_write_auto_populates_required_fields() {
        let mm = maintainer();
        let (meta, fields) = mm
            .add_entry_for_write(None, "my-doc.md", b"# Hello\n\nbody")
            .unwrap();
        assert!(fields.contains(&"name".to_string()));
        assert!(fields.contains(&"slug".to_string()));
        assert!(fields.contains(&"description".to_string()));
        assert!(fields.contains(&"type".to_string()));
        let entry = meta.entries.get("my-doc.md").unwrap();
        assert_eq!(entry.name, "my-doc");
        assert_eq!(entry.slug, "my-doc");
        assert_eq!(entry.description, "Hello");
        // .md without OKF frontmatter type → document (ADR Decision 1).
        assert_eq!(entry.r#type, "document");
    }

    #[tokio::test]
    async fn add_entry_for_write_existing_entry_no_change() {
        let mm = maintainer();
        let (meta1, _) = mm
            .add_entry_for_write(None, "x.md", b"first content\n")
            .unwrap();
        let (meta2, fields2) = mm
            .add_entry_for_write(Some(meta1), "x.md", b"second content\n")
            .unwrap();
        assert!(fields2.is_empty());
        // description preserved from first call
        assert_eq!(
            meta2.entries.get("x.md").unwrap().description,
            "first content"
        );
    }

    #[tokio::test]
    async fn add_entry_for_write_binary_uses_pending_description() {
        let mm = maintainer();
        let (meta, _) = mm
            .add_entry_for_write(None, "img.png", &[0xFF, 0xD8, 0xFF, 0xE0])
            .unwrap();
        let entry = meta.entries.get("img.png").unwrap();
        assert_eq!(entry.description, "[pending] img.png");
        // non-Markdown file → asset (ADR Decision 1).
        assert_eq!(entry.r#type, "asset");
    }

    #[tokio::test]
    async fn add_entry_for_write_md_frontmatter_type_is_read() {
        let mm = maintainer();
        let body = b"---\ntype: project\nname: Roadmap\n---\n# Roadmap\n";
        let (meta, _) = mm.add_entry_for_write(None, "roadmap.md", body).unwrap();
        // .md WITH OKF frontmatter type → that value (ADR Decision 1).
        assert_eq!(meta.entries.get("roadmap.md").unwrap().r#type, "project");
    }

    #[tokio::test]
    async fn remove_entry_changes_fields_to_removed() {
        let mm = maintainer();
        let (meta, _) = mm.add_entry_for_write(None, "x.md", b"x").unwrap();
        let (meta2, fields) = mm.remove_entry(meta, "x.md");
        assert_eq!(fields, vec!["_removed".to_string()]);
        assert!(meta2.entries.is_empty());
    }

    #[tokio::test]
    async fn remove_entry_for_missing_returns_empty_fields() {
        let mm = maintainer();
        let meta = MetaFile::default();
        let (_, fields) = mm.remove_entry(meta, "nonexistent");
        assert!(fields.is_empty());
    }

    #[tokio::test]
    async fn update_scope_updates_description_and_tags() {
        let mm = maintainer();
        let meta = MetaFile::default();
        let (meta2, fields) = mm
            .update_scope(meta, "new desc".into(), vec!["t1".into()])
            .unwrap();
        assert!(fields.contains(&"description".to_string()));
        assert!(fields.contains(&"tags".to_string()));
        assert_eq!(meta2.scope.description, "new desc");
        assert_eq!(meta2.scope.tags, vec!["t1".to_string()]);
    }

    #[tokio::test]
    async fn update_scope_rejects_empty_description() {
        let mm = maintainer();
        let meta = MetaFile::default();
        let err = mm.update_scope(meta, "  ".into(), vec![]).unwrap_err();
        match err {
            FsError::InvalidPath(s) => assert!(s.contains("description")),
            other => panic!("expected InvalidPath, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_entry_meta_rejects_missing_entry() {
        let mm = maintainer();
        let meta = MetaFile::default();
        let err = mm
            .update_entry_meta(meta, "nope.md", "desc".into(), vec![])
            .unwrap_err();
        match err {
            FsError::InvalidPath(s) => assert!(s.contains("does not exist")),
            other => panic!("expected InvalidPath, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_entry_meta_succeeds_for_existing() {
        let mm = maintainer();
        let (meta, _) = mm.add_entry_for_write(None, "x.md", b"x").unwrap();
        let (meta2, fields) = mm
            .update_entry_meta(meta, "x.md", "new".into(), vec!["a".into()])
            .unwrap();
        assert!(fields.contains(&"description".to_string()));
        assert_eq!(meta2.entries.get("x.md").unwrap().description, "new");
        assert_eq!(
            meta2.entries.get("x.md").unwrap().tags,
            vec!["a".to_string()]
        );
    }
}
