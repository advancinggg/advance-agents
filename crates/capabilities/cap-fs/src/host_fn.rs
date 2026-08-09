//! 4 `HostFunctionHandler` impls for the slice A `agent-fs` subset.
//!
//! Slice A bodies `read`, `write`, `list`, `delete` on the agent's own territory.
//! The remaining 14 fns of CONTRACT-010 (slug, child, history, scan, update-meta)
//! are deferred to slices B+. This module also defines the DoS bound constants
//! enforced at handler entry BEFORE allocating the `Vec<u8>` / `Vec<Entry>`
//! conversion, plus `list_over_limit_msg` as the canonical error-message formatter
//! shared between `FsListHandler` and SA-T29e (so handler + test cannot drift).
//!
//! ## WIT result encoding
//!
//! - `read`/`list` return WIT `result<list<u8>, fs-error>` / `result<list<entry>, fs-error>` —
//!   non-unit OK arm → `Val::Result(Ok(Some(Box::new(Val::List(...)))))`.
//! - `write`/`delete` return WIT `result<_, fs-error>` — UNIT OK arm →
//!   `Val::Result(Ok(None))`. Wasmtime 43 rejects `Some(payload)` for a unit OK
//!   arm with "payload provided to `ok` but not expected"
//!   (`wasmtime/src/runtime/component/values.rs:783-810`).
//!
//! Errors always lower as `Val::Result(Err(Some(Box::new(fs_error_to_val(&err)))))`.
//!
//! ## Event emission ordering
//!
//! Events are emitted ONLY AFTER the disk I/O succeeds — path/resolve rejections,
//! over-limit rejections, and disk-level errors all skip emission. This ensures
//! downstream M004 indexer subscribers don't see events for operations that didn't
//! actually mutate the filesystem.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use advance_shared_types::agent_tree::AgentTreeSnapshot;
use advance_shared_types::traits::EventBusEmit;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use wasmtime::component::Val;

use crate::atomic::{AtomicWriter, DefaultAtomicWriter, MAX_WRITE_BYTES};
use crate::entry::{
    entry_to_val, scan_result_to_val, version_entry_to_val, ChildMeta, Entry, ScanResult, ScopeMeta,
};
use crate::error::{fs_error_to_val, sanitize_io_error, FsError};
use crate::events::{emit_fs_event, emit_runtime_degraded, FsEvent, FsSource, MetaSource};
use crate::git_sync::{GitSync, GitSyncError, GitSyncOp};
use crate::history_provider::FileHistoryProvider;
use crate::meta_maintainer::{MetaFile, MetaMaintainer};
use crate::meta_schema::MetaSchemaLoader;
use crate::resolver::{is_workspace_hidden_name, VirtualPathResolver};
use crate::sqlite_sync::{
    agent_id_for_m004, is_text_for_sql_index, normalize_ws_path, FsSyncError, SqliteSync,
    MAX_SQL_PREVIEW_CHARS,
};

/// Maximum vpath byte length accepted at handler entry. 4096 matches POSIX PATH_MAX.
pub const MAX_PATH_BYTES: usize = 4096;

/// Maximum file size returned by `read`. Bounds the `Val::List<Val::U8>` expansion
/// (each `Val` is enum-tagged at ~16-24 bytes, so a 64 MiB read can expand to
/// ~1-1.5 GiB host memory in the response Vec). 64 MiB pin matches MAX_WRITE_BYTES.
pub const MAX_READ_BYTES: usize = 64 * 1024 * 1024;

/// Default per-list-call entry limit. A directory with 1M files would otherwise
/// build a 1M-element `Vec<Val::Record>` (~200 MiB). 64K handles realistic
/// workspaces while bounding worst-case allocation.
pub const DEFAULT_MAX_LIST_ENTRIES: usize = 65536;

/// Maximum number of `VersionEntry`s the history host fns return. A buggy or
/// malicious provider could otherwise return billions of versions; each
/// VersionEntry's `message: Option<String>` is unbounded, so the resulting
/// `Vec<Val::Record>` could exhaust host memory. 65536 is the same cap as
/// directory listings — well above any realistic per-file git history.
///
/// **Cap semantics (MODULE-002 §1.7.1 clause 4)**: this is a response-shape
/// bound enforced AFTER `FileHistoryProvider::file_history` returns. It rejects
/// oversized payloads from reaching the WASM guest, but does NOT prevent
/// peak in-flight host memory amplification if the trusted provider materializes
/// an oversized response. The provider surface is part of the trusted storage
/// adapter (slice A owns the trait); pre-provider enforcement requires
/// extending `FileHistoryProvider::file_history` to accept a `max_count`
/// parameter, which falls to the slice that owns that contract.
pub const MAX_HISTORY_VERSIONS: usize = 65536;

/// Default semaphore-bounded concurrency cap on inflight fs operations per
/// `register_agent_fs` registration. Bounds:
///   - file-descriptor exhaustion via concurrent fs.read holding open File
///     handles through `take().read_to_end()` of up to MAX_READ_BYTES
///   - tempfile-handle accumulation via concurrent fs.write holding
///     `NamedTempFile`s pre-persist
///   - directory-entry iterator handles via concurrent fs.list
///   - peak host memory from `Val::List<Val::U8>` expansion: each `Val` is
///     enum-tagged at ~16-24 bytes, so a 64 MiB read produces a ~1-1.5 GiB
///     `Vec<Val>`. With concurrency = 16 + MAX_READ_BYTES = 64 MiB, peak
///     memory for concurrent reads is bounded at ~16 × 1.5 GiB = ~24 GiB
///     before the OOM-killer fires — fits a typical 64 GiB host. A larger
///     concurrency would multiply this cost; slice A pin: 16. Configurable
///     via RuntimeConfig in a later slice.
pub const DEFAULT_FS_CONCURRENCY: usize = 16;

/// Canonical error-message formatter for the over-limit list rejection. Used by
/// `FsListHandler::call` AND by SA-T29e so the test asserts against the exact
/// string the handler produces — no string-template drift possible.
pub fn list_over_limit_msg(n: usize) -> String {
    format!("directory has more than {n} entries; aborting list")
}

/// Off-load the resolver's sync `std::fs::symlink_metadata` walk onto tokio's
/// blocking pool so the async worker thread isn't pinned by 32 sync syscalls
/// on slow filesystems (NFS, FUSE, busy disk). Called by every handler
/// AFTER `resolver.resolve_*` returns the candidate physical path. The
/// resolver itself still runs the same walk synchronously as defense-in-depth
/// for sync-test contexts; this just guarantees the production async path
/// doesn't block tokio workers.
async fn resolve_via_blocking(
    resolver: Arc<dyn VirtualPathResolver>,
    agent_id: String,
    vpath: String,
    write_op: bool,
) -> Result<std::path::PathBuf, FsError> {
    tokio::task::spawn_blocking(move || {
        if write_op {
            resolver.resolve_write(&agent_id, &vpath)
        } else {
            resolver.resolve_read(&agent_id, &vpath)
        }
    })
    .await
    .map_err(|join_err| FsError::IoError(format!("resolver join error: {join_err}")))?
}

fn ok_err_variant(err: &FsError) -> Vec<Val> {
    vec![Val::Result(Err(Some(Box::new(fs_error_to_val(err)))))]
}

/// Validate path-param length. Returns FsError so callers route through the
/// WIT result-arm (`result<_, fs-error>`) rather than a host-level trap.
/// The documented WIT surface promises every host fn returns a typed
/// fs-error on guest-controlled error paths; trap-level errors are
/// reserved for shape-mismatch invariants that should never reach a
/// well-formed guest.
fn validate_path_param(path: &str) -> Result<(), FsError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(FsError::InvalidPath(format!(
            "path exceeds MAX_PATH_BYTES ({MAX_PATH_BYTES} bytes)"
        )));
    }
    Ok(())
}

/// Helper: convert a guest-bound check `Result<(), FsError>` into the
/// handler's return shape — Ok(ok_err_variant(&e)) for the err case so the
/// guest receives a typed fs-error variant instead of a wasmtime trap.
/// Macro form lets us early-return from the enclosing handler future without
/// every site rewriting the pattern manually.
macro_rules! check_param {
    ($expr:expr) => {
        if let Err(e) = $expr {
            return Ok(ok_err_variant(&e));
        }
    };
}

/// Maximum length (bytes) for non-path WIT string parameters: peer_id,
/// child_id, slug, version, entry_name. These never traverse the filesystem
/// the way a vpath does, but they are still hashed/cloned/serialized in
/// hot paths and an unbounded guest-controlled string is a DoS vector
/// (memory amplification under per-handler concurrency).
const MAX_WIT_STRING_PARAM_BYTES: usize = 1024;

/// Handler-side mirrors of meta_maintainer's metadata caps. We bound at the
/// WIT parse boundary BEFORE `s.clone()` runs, so a guest cannot amplify
/// host allocation past these caps even though the maintainer also enforces
/// them after the fact (defense in depth).
const MAX_DESCRIPTION_BYTES_HANDLER: usize = 4096;
const MAX_TAGS_COUNT_HANDLER: usize = 32;
const MAX_TAG_BYTES_HANDLER: usize = 128;

/// Cancellation-safe meta rollback. After the meta-first commit succeeds
/// but before the data-side I/O completes, the handler arms a guard. If the
/// future is dropped (e.g. wasmtime epoch interrupt, resource limiter,
/// process shutdown) before the data side either succeeds or runs its
/// inline rollback, this guard's `Drop` impl spawns a detached tokio task
/// that re-acquires the meta_lock and rolls the `.meta.yaml` back to its
/// pre-state. Without this, a dropped future leaves `.meta.yaml` advertising
/// an entry whose data file never committed (or, for delete, leaves the data
/// file alive after .meta.yaml dropped its entry).
struct MetaRollbackGuard {
    armed: bool,
    inner: Option<MetaRollbackInner>,
}

struct MetaRollbackInner {
    maintainer: Arc<crate::meta_maintainer::MetaMaintainer>,
    emitter: Arc<dyn EventBusEmit>,
    parent_dir: std::path::PathBuf,
    meta_pre: Option<crate::meta_maintainer::MetaFile>,
    /// Bytes that were on disk immediately after the meta-first commit. Used
    /// by the detached rollback task as a "no-intervening-change" guard:
    /// rollback only fires if the current on-disk content still matches.
    meta_post_yaml: Vec<u8>,
    agent_id: String,
    trace_id: String,
    vpath: String,
    reason: &'static str,
}

impl MetaRollbackGuard {
    /// Mark the rollback as no longer needed (success path, or rollback was
    /// run inline).
    fn disarm(&mut self) {
        self.armed = false;
        self.inner = None;
    }
}

impl Drop for MetaRollbackGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(inner) = self.inner.take() else {
            return;
        };
        // tokio::runtime::Handle::try_current returns Ok inside any tokio
        // runtime context; wasmtime's host-call dispatch is async-driven so
        // this is always inside one. If we ever run outside (e.g. future
        // dropped from a sync test), the rollback is best-effort skipped.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            let _g = inner.maintainer.acquire().await;
            // Cancellation-safe rollback: re-read the on-disk .meta.yaml and
            // compare to the bytes we committed at meta-first commit time.
            // If they differ, an intervening op has superseded our commit —
            // skipping the rollback (instead of stomping on it). The byte
            // comparison + meta_lock together linearize the rollback against
            // any concurrent maintainer writes.
            let meta_path = inner.parent_dir.join(".meta.yaml");
            let current = tokio::fs::read(&meta_path).await.unwrap_or_default();
            if current != inner.meta_post_yaml {
                emit_runtime_degraded(
                    &*inner.emitter,
                    &inner.agent_id,
                    &inner.trace_id,
                    inner.reason,
                    serde_json::json!({
                        "vpath": inner.vpath,
                        "trigger": "future-dropped",
                        "rollback_skipped": "intervening_change",
                    }),
                );
                return;
            }
            let rb_result: Result<(), FsError> = match inner.meta_pre.as_ref() {
                None => inner.maintainer.delete_meta_file(&inner.parent_dir).await,
                Some(m_pre) => inner
                    .maintainer
                    .write(&inner.parent_dir, m_pre)
                    .await
                    .map(|_| ()),
            };
            if let Err(rb_err) = rb_result {
                emit_runtime_degraded(
                    &*inner.emitter,
                    &inner.agent_id,
                    &inner.trace_id,
                    inner.reason,
                    serde_json::json!({
                        "vpath": inner.vpath,
                        "trigger": "future-dropped",
                        "rollback_error": format!("{:?}", rb_err),
                    }),
                );
            }
        });
    }
}

/// Validate non-path WIT string-param length. Returns FsError so callers
/// route through the WIT result-arm rather than a host-level trap; see
/// validate_path_param for the same rationale.
fn validate_string_param(value: &str, name: &'static str) -> Result<(), FsError> {
    if value.len() > MAX_WIT_STRING_PARAM_BYTES {
        return Err(FsError::InvalidPath(format!(
            "{name} exceeds MAX_WIT_STRING_PARAM_BYTES ({MAX_WIT_STRING_PARAM_BYTES} bytes)"
        )));
    }
    Ok(())
}

/// Slice C: derive M004's path-derived agent_id from cap-fs `HostCallContext`.
/// Looks up the agent's workspace_path via `AgentTreeSnapshot.snapshot()`,
/// then maps via `agent_id_for_m004(workspace_root, agent_workspace)`.
/// Returns `None` when the agent isn't in the snapshot or its workspace_path
/// isn't under workspace_root — caller emits `runtime.degraded.sqlite_sync_failed`.
fn derive_m004_agent_id(
    agent_tree: &Arc<dyn AgentTreeSnapshot>,
    workspace_root: &std::path::Path,
    ctx_agent_id: &str,
) -> Option<String> {
    let snap = agent_tree.snapshot();
    let node = snap.nodes.iter().find(|n| n.id.0 == ctx_agent_id)?;
    agent_id_for_m004(workspace_root, &node.workspace_path)
}

/// Slice C: SQL leg for FsWriteHandler. Runs AFTER FS + meta commit, BEFORE
/// FsEvent::Write emission. Errors emit `runtime.degraded.sqlite_sync_failed`
/// but propagate as no-op so the caller continues to event emission.
#[allow(clippy::too_many_arguments)]
async fn sqlite_sync_after_write(
    db_sync: &Option<Arc<dyn SqliteSync>>,
    workspace_root: &Option<PathBuf>,
    agent_tree: &Option<Arc<dyn AgentTreeSnapshot>>,
    emitter: &dyn EventBusEmit,
    ctx: &HostCallContext,
    path: &str,
    physical: &std::path::Path,
    parent_dir: &std::path::Path,
    file_name: &str,
    data: &[u8],
    meta_new: &MetaFile,
) {
    let (Some(sync), Some(ws), Some(tree)) = (
        db_sync.as_ref(),
        workspace_root.as_ref(),
        agent_tree.as_ref(),
    ) else {
        return;
    };

    let m004_agent = match derive_m004_agent_id(tree, ws, &ctx.agent_id) {
        Some(s) => s,
        None => {
            emit_runtime_degraded(
                emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                "sqlite_sync_failed",
                serde_json::json!({
                    "vpath": path,
                    "op": "agent_id_normalize",
                    "error": "agent not in tree or workspace_path outside workspace_root",
                }),
            );
            return;
        }
    };

    // Adversarial-round-1 W3 fix: defense-in-depth assert that physical +
    // parent_dir are under workspace_root. The resolver IS supposed to
    // guarantee containment (resolver.rs Rules 1/7 + traversal rejection),
    // so this branch should never fire in well-formed paths. If it does,
    // skip the SQL leg and emit runtime.degraded — preventing
    // accidental host-path leaks (e.g. "/Users/<name>/...") into
    // content_index.file_path / meta_index.directory under a future resolver
    // regression.
    if !physical.starts_with(ws) || !parent_dir.starts_with(ws) {
        emit_runtime_degraded(
            emitter,
            &ctx.agent_id,
            &ctx.trace_id,
            "sqlite_sync_failed",
            serde_json::json!({
                "vpath": path,
                "op": "workspace_root_check",
                "error": "physical or parent_dir not under workspace_root (resolver invariant violated)",
            }),
        );
        return;
    }

    let ws_path = normalize_ws_path(ws, physical);
    let ws_dir = normalize_ws_path(ws, parent_dir);

    // Use file mtime, not Utc::now, so hot-path and rebuild-path agree on
    // last_modified (matches M004 rebuild scanner per rebuild.rs:883-889).
    //
    // Adversarial-round-1 W4 (acknowledged, low-likelihood TOCTOU): the
    // metadata read happens AFTER the data write commit, so a concurrent
    // peer write or external touch between the two syscalls can land a
    // mtime that disagrees with the bytes THIS write persisted. The race
    // window is bounded by file-system metadata syscall latency (sub-ms);
    // the next-boot M004 rebuild_full re-reads file mtime and overwrites
    // any drift. Slice C's pin: accept the race; reconciliation
    // (CONTRACT-033) is the recovery path consistent with the
    // best-effort-triple model documented in §1.4.4.
    let last_modified = tokio::fs::metadata(physical)
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });

    if is_text_for_sql_index(data) {
        let preview: String = std::str::from_utf8(data)
            .expect("is_text_for_sql_index just verified UTF-8")
            .chars()
            .take(MAX_SQL_PREVIEW_CHARS)
            .collect();
        if let Err(FsSyncError(msg)) = sync
            .upsert_content(&m004_agent, &ws_path, &preview, last_modified.as_deref())
            .await
        {
            emit_runtime_degraded(
                emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                "sqlite_sync_failed",
                serde_json::json!({
                    "vpath": path,
                    "op": "upsert_content",
                    "error": msg,
                }),
            );
        }
    }

    let entry = meta_new.entries.get(file_name);
    let desc = entry.map(|e| e.description.clone());
    let tags_json = entry.and_then(|e| serde_json::to_string(&e.tags).ok());
    if let Err(FsSyncError(msg)) = sync
        .upsert_meta(
            &m004_agent,
            &ws_dir,
            file_name,
            desc.as_deref(),
            tags_json.as_deref(),
        )
        .await
    {
        emit_runtime_degraded(
            emitter,
            &ctx.agent_id,
            &ctx.trace_id,
            "sqlite_sync_failed",
            serde_json::json!({
                "vpath": path,
                "op": "upsert_meta",
                "error": msg,
            }),
        );
    }
}

/// Slice C: SQL leg for FsDeleteHandler. Runs AFTER FS + meta delete, BEFORE
/// FsEvent::Delete emission. Idempotent per CONTRACT-030 (missing row → Ok).
#[allow(clippy::too_many_arguments)]
async fn sqlite_sync_after_delete(
    db_sync: &Option<Arc<dyn SqliteSync>>,
    workspace_root: &Option<PathBuf>,
    agent_tree: &Option<Arc<dyn AgentTreeSnapshot>>,
    emitter: &dyn EventBusEmit,
    ctx: &HostCallContext,
    path: &str,
    physical: &std::path::Path,
    parent_dir: &std::path::Path,
    file_name: &str,
) {
    let (Some(sync), Some(ws), Some(tree)) = (
        db_sync.as_ref(),
        workspace_root.as_ref(),
        agent_tree.as_ref(),
    ) else {
        return;
    };

    let m004_agent = match derive_m004_agent_id(tree, ws, &ctx.agent_id) {
        Some(s) => s,
        None => {
            emit_runtime_degraded(
                emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                "sqlite_sync_failed",
                serde_json::json!({
                    "vpath": path,
                    "op": "agent_id_normalize",
                    "error": "agent not in tree or workspace_path outside workspace_root",
                }),
            );
            return;
        }
    };

    // Adversarial-round-1 W3 fix: defense-in-depth ws_root check
    // mirroring sqlite_sync_after_write. Prevents accidental host-path
    // leakage if a resolver regression returns physical outside ws.
    if !physical.starts_with(ws) || !parent_dir.starts_with(ws) {
        emit_runtime_degraded(
            emitter,
            &ctx.agent_id,
            &ctx.trace_id,
            "sqlite_sync_failed",
            serde_json::json!({
                "vpath": path,
                "op": "workspace_root_check",
                "error": "physical or parent_dir not under workspace_root (resolver invariant violated)",
            }),
        );
        return;
    }

    let ws_path = normalize_ws_path(ws, physical);
    let ws_dir = normalize_ws_path(ws, parent_dir);

    if let Err(FsSyncError(msg)) = sync.delete_content(&m004_agent, &ws_path).await {
        emit_runtime_degraded(
            emitter,
            &ctx.agent_id,
            &ctx.trace_id,
            "sqlite_sync_failed",
            serde_json::json!({
                "vpath": path,
                "op": "delete_content",
                "error": msg,
            }),
        );
    }

    if let Err(FsSyncError(msg)) = sync.delete_meta(&m004_agent, &ws_dir, file_name).await {
        emit_runtime_degraded(
            emitter,
            &ctx.agent_id,
            &ctx.trace_id,
            "sqlite_sync_failed",
            serde_json::json!({
                "vpath": path,
                "op": "delete_meta",
                "error": msg,
            }),
        );
    }
}

/// Slice D: git leg for FsWriteHandler. Runs AFTER the SQL leg (slice C) and
/// BEFORE FsEvent::Write emission. Submits a `[turn] [agent:<id>]` commit
/// covering both the data file and the parent's `.meta.yaml`. Errors emit
/// `runtime.degraded.git_sync_failed` but propagate as a no-op so the caller
/// continues to event emission. fs.write returns `Ok(())` regardless of the
/// git leg outcome (FS source-of-truth is committed before the git leg runs).
async fn git_sync_after_write(
    git_sync: &Option<Arc<dyn GitSync>>,
    emitter: &dyn EventBusEmit,
    ctx: &HostCallContext,
    vpath: &str,
    physical: &std::path::Path,
    parent_dir: &std::path::Path,
) {
    let Some(sync) = git_sync.as_ref() else {
        return;
    };
    let meta_yaml = parent_dir.join(".meta.yaml");
    if let Err(GitSyncError(msg)) = sync
        .submit_fs_commit(
            &ctx.agent_id,
            GitSyncOp::Write,
            vpath,
            physical.to_path_buf(),
            meta_yaml,
        )
        .await
    {
        emit_runtime_degraded(
            emitter,
            &ctx.agent_id,
            &ctx.trace_id,
            "git_sync_failed",
            serde_json::json!({
                "vpath": vpath,
                "op": "write",
                "error": msg,
            }),
        );
    }
}

/// Slice D: git leg for FsDeleteHandler. Mirror of `git_sync_after_write` with
/// `op = Delete`. The physical path no longer exists on disk after the data
/// leg removed it — advance-git's `do_commit` (slice D enhancement) detects
/// the missing path via `symlink_metadata` and routes to `index.remove_path`
/// to stage the deletion in the resulting commit's tree.
async fn git_sync_after_delete(
    git_sync: &Option<Arc<dyn GitSync>>,
    emitter: &dyn EventBusEmit,
    ctx: &HostCallContext,
    vpath: &str,
    physical: &std::path::Path,
    parent_dir: &std::path::Path,
) {
    let Some(sync) = git_sync.as_ref() else {
        return;
    };
    let meta_yaml = parent_dir.join(".meta.yaml");
    if let Err(GitSyncError(msg)) = sync
        .submit_fs_commit(
            &ctx.agent_id,
            GitSyncOp::Delete,
            vpath,
            physical.to_path_buf(),
            meta_yaml,
        )
        .await
    {
        emit_runtime_degraded(
            emitter,
            &ctx.agent_id,
            &ctx.trace_id,
            "git_sync_failed",
            serde_json::json!({
                "vpath": vpath,
                "op": "delete",
                "error": msg,
            }),
        );
    }
}

/// Convert an `std::io::Error` into a typed `FsError` variant. Crucially,
/// `ErrorKind::NotFound` on an otherwise visible path becomes `FsError::NotFound`
/// rather than `FsError::IoError("io error: NotFound")` — without this mapping
/// a guest can fingerprint hidden-class paths (which always return `NotFound`)
/// vs missing visible paths (which would return `IoError`). AC-06 anti-
/// fingerprinting requires the variants to be indistinguishable.
fn map_io_error(e: &std::io::Error) -> FsError {
    if e.kind() == std::io::ErrorKind::NotFound {
        FsError::NotFound("path not found".to_string())
    } else {
        FsError::IoError(sanitize_io_error(e))
    }
}

// ---- FsReadHandler -------------------------------------------------------------

pub struct FsReadHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    /// Optional L1 preview budget (bytes). When `Some(n)`, the handler clamps
    /// the returned data to the first `n` bytes after reading. When `None`,
    /// returns full file content (L2 semantics). Slice B addition for AC-05.
    pub preview_max_bytes: Option<usize>,
}

impl HostFunctionHandler for FsReadHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let preview_budget = self.preview_max_bytes;
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.read, got {results_len}"
                )));
            }
            let path = match params.as_slice() {
                [Val::String(s)] => s.clone(),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected single Val::String parameter".into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));

            // Acquire FD-cap semaphore permit for the duration of the disk op.
            // Permit is released on Drop (when this future completes), so even
            // panics inside the disk op release the slot. Acquired AFTER param
            // validation so cheap-rejection paths don't waste permits.
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.read concurrency semaphore closed".into())
            })?;

            let physical =
                match resolve_via_blocking(resolver, ctx.agent_id.clone(), path.clone(), false)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => return Ok(ok_err_variant(&e)),
                };

            // Read-size pre-check via metadata (fail fast on obviously-large
            // files when in non-preview mode). In preview mode, a large file
            // is fine — we'll only sample the first `preview_max_bytes` bytes
            // via the take() limiter below — so do NOT reject on size here.
            let metadata = match tokio::fs::metadata(&physical).await {
                Ok(m) => m,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            if preview_budget.is_none() && u64::from(metadata.len()) > MAX_READ_BYTES as u64 {
                return Ok(ok_err_variant(&FsError::IoError(format!(
                    "file size {} exceeds MAX_READ_BYTES ({MAX_READ_BYTES})",
                    metadata.len()
                ))));
            }

            // Bounded read using AsyncReadExt::take — closes the metadata-then-
            // read TOCTOU. The cap is the EFFECTIVE cap: when an L1 preview
            // budget is set, only read up to budget bytes (not MAX_READ_BYTES).
            // Otherwise the preview "budget" would be a post-read truncation
            // that didn't actually limit disk I/O or heap growth — defeating
            // the AC-05 L1 progressive-loading promise.
            let effective_cap = match preview_budget {
                Some(b) => b,
                None => MAX_READ_BYTES,
            };
            let file = match tokio::fs::File::open(&physical).await {
                Ok(f) => f,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            let mut limited = file.take((effective_cap as u64) + 1);
            let mut data = Vec::with_capacity(metadata.len().min(effective_cap as u64) as usize);
            if let Err(e) = limited.read_to_end(&mut data).await {
                return Ok(ok_err_variant(&map_io_error(&e)));
            }
            // L1 preview: truncate to the budget if file is larger than budget
            // (limited reader returns up to budget+1 — the +1 sentinel signals
            // the file is larger than budget, in which case truncate is the
            // expected outcome, NOT an error). For full reads (preview = None),
            // any data.len() > MAX_READ_BYTES means the file grew past the
            // bound during read — that IS an error.
            match preview_budget {
                Some(budget) => {
                    if data.len() > budget {
                        data.truncate(budget);
                    }
                }
                None => {
                    if data.len() > MAX_READ_BYTES {
                        return Ok(ok_err_variant(&FsError::IoError(format!(
                            "file grew past MAX_READ_BYTES ({MAX_READ_BYTES}) during read"
                        ))));
                    }
                }
            }

            let size = data.len();
            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::Read {
                    agent_id: ctx.agent_id.clone(),
                    path: path.clone(),
                    source: FsSource::Private,
                    size,
                },
            );

            let val_bytes: Vec<Val> = data.into_iter().map(Val::U8).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(val_bytes)))))])
        })
    }
}

// ---- FsWriteHandler ------------------------------------------------------------

pub struct FsWriteHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub maintainer: Arc<MetaMaintainer>,
    pub writer: Arc<dyn AtomicWriter>,
    /// Slice C: optional CONTRACT-030 sync surface. `None` = pre-slice-C
    /// behavior (no SQLite triple sync). All three slice C fields must be
    /// `Some` together or `None` together — enforced in `register_agent_fs`.
    pub db_sync: Option<Arc<dyn SqliteSync>>,
    /// Slice C: workspace root for path normalization.
    pub workspace_root: Option<PathBuf>,
    /// Slice C: agent tree snapshot for per-call M004 agent_id derivation.
    pub agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
    /// Slice D: optional CONTRACT-020 git commit queue surface for AC-16
    /// per-fs-write attribution commits. `None` = pre-slice-D behavior
    /// (no git audit-trail). Independent of the slice C trio.
    pub git_sync: Option<Arc<dyn GitSync>>,
}

impl HostFunctionHandler for FsWriteHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let maintainer = Arc::clone(&self.maintainer);
        let writer = Arc::clone(&self.writer);
        let db_sync = self.db_sync.clone();
        let workspace_root = self.workspace_root.clone();
        let agent_tree = self.agent_tree.clone();
        let git_sync = self.git_sync.clone();
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.write, got {results_len}"
                )));
            }
            // Step 1: bound the params on borrowed references — no clone, no
            // materialization. This rejects oversized inputs cheaply.
            match params.as_slice() {
                [Val::String(s), Val::List(d)] => {
                    if d.len() > MAX_WRITE_BYTES {
                        return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                            "data length {} exceeds MAX_WRITE_BYTES ({MAX_WRITE_BYTES})",
                            d.len()
                        ))));
                    }
                    if s.len() > MAX_PATH_BYTES {
                        return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                            "path exceeds MAX_PATH_BYTES ({MAX_PATH_BYTES} bytes)"
                        ))));
                    }
                }
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::List) parameters".into(),
                    ));
                }
            }

            // Step 2: acquire the FD-cap semaphore BEFORE the heavy clone +
            // u8 materialization. With a 16-permit cap, peak host allocation
            // for cloning the bounded ≤MAX_WRITE_BYTES Val::List is now
            // bounded to 16 × clone_size; without this ordering, an
            // unbounded number of concurrent guests could each be cloning
            // a near-MAX_WRITE_BYTES list before any reached the semaphore.
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.write concurrency semaphore closed".into())
            })?;

            // Step 3: under the semaphore, take an owning copy of the path
            // and convert the Val::List into a Vec<u8>. The semaphore caps
            // peak amplification.
            let (path, data) = match params.as_slice() {
                [Val::String(s), Val::List(d)] => {
                    let path = s.clone();
                    let mut data = Vec::with_capacity(d.len());
                    for v in d {
                        match v {
                            Val::U8(b) => data.push(*b),
                            _ => {
                                return Err(HostCallError::HandlerError(
                                    "non-u8 element in write data list".into(),
                                ));
                            }
                        }
                    }
                    (path, data)
                }
                _ => unreachable!(),
            };

            let physical = match resolve_via_blocking(
                resolver,
                ctx.agent_id.clone(),
                path.clone(),
                true,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };

            // Slice B: meta-first atomic commit pattern (AC-10).
            //
            // 1) Capture pre-state of `.meta.yaml` as Option<MetaFile> (None if missing).
            // 2) Compute new state via add_entry_for_write.
            // 3) Write meta first.
            // 4) Write data second.
            // 5) On data-write failure, roll back meta to its pre-state.
            let parent_dir = match physical.parent() {
                Some(p) => p.to_path_buf(),
                None => {
                    return Ok(ok_err_variant(&FsError::IoError(
                        "no parent dir for write".into(),
                    )));
                }
            };
            let file_name = match physical.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => {
                    return Ok(ok_err_variant(&FsError::IoError(
                        "invalid file name".into(),
                    )));
                }
            };

            // is_new_file: best-effort async pre-check. TOCTOU race acknowledged.
            let is_new_file = tokio::fs::metadata(&physical).await.is_err();

            let _meta_guard = maintainer.acquire().await;

            let meta_pre = match maintainer.load(&parent_dir).await {
                Ok(v) => v,
                Err(e) => return Ok(ok_err_variant(&e)),
            };

            let (meta_new, changed_fields) =
                match maintainer.add_entry_for_write(meta_pre.clone(), &file_name, &data) {
                    Ok(v) => v,
                    Err(e) => return Ok(ok_err_variant(&e)),
                };

            // Step 5: meta first.
            let meta_post_yaml = match maintainer.write(&parent_dir, &meta_new).await {
                Ok(bytes) => bytes,
                // Meta write failed — no rollback needed (nothing committed yet).
                Err(e) => return Ok(ok_err_variant(&e)),
            };

            // Arm cancellation-safe rollback. From here until data write
            // completes (success → disarm; error → inline rollback then
            // disarm AFTER the rollback await), the guard is responsible for
            // ensuring .meta.yaml is rolled back. Drop spawns a detached task
            // that compares on-disk bytes to meta_post_yaml; if they diverge
            // (intervening op already superseded our commit), the rollback
            // is skipped instead of stomping on legitimate later state.
            let mut rollback_guard = MetaRollbackGuard {
                armed: true,
                inner: Some(MetaRollbackInner {
                    maintainer: Arc::clone(&maintainer),
                    emitter: Arc::clone(&emitter),
                    parent_dir: parent_dir.clone(),
                    meta_pre: meta_pre.clone(),
                    meta_post_yaml,
                    agent_id: ctx.agent_id.clone(),
                    trace_id: ctx.trace_id.clone(),
                    vpath: path.clone(),
                    reason: "fs_write_meta_rollback_failed",
                }),
            };

            // Step 6: data second.
            if let Err(data_err) = writer.write(&physical, &data).await {
                // Inline rollback (sync with the error response). Keep the
                // guard armed during the rollback await so cancellation
                // mid-await still triggers the detached Drop path. The
                // detached path's byte-compare makes double-rollback
                // idempotent (after our successful write of meta_pre, the
                // detached task sees current_yaml != meta_post_yaml and
                // skips). Disarm only AFTER the rollback completes.
                let rollback: Result<(), FsError> = match &meta_pre {
                    None => maintainer.delete_meta_file(&parent_dir).await,
                    Some(m_pre) => maintainer.write(&parent_dir, m_pre).await.map(|_| ()),
                };
                rollback_guard.disarm();
                if let Err(rb_err) = rollback {
                    emit_runtime_degraded(
                        &*emitter,
                        &ctx.agent_id,
                        &ctx.trace_id,
                        "fs_write_meta_rollback_failed",
                        serde_json::json!({
                            "vpath": path,
                            "data_error": format!("{:?}", data_err),
                            "rollback_error": format!("{:?}", rb_err),
                        }),
                    );
                }
                return Ok(ok_err_variant(&data_err));
            }

            // Data write succeeded — disarm the cancellation guard so its
            // Drop won't roll back a successful commit.
            rollback_guard.disarm();

            let size = data.len();

            // Adversarial-round-1 fix (C2): release the global meta_lock
            // BEFORE the SQL leg. The SQL leg only uses
            // `physical`/`parent_dir`/`file_name`/`data`/`meta_new` — none
            // of which require the lock for correctness — and each upsert
            // dispatches to `tokio::task::spawn_blocking` for an
            // `Immediate` rusqlite transaction. Holding the lock through
            // those awaits would serialise EVERY runtime fs.write /
            // fs.delete / fs.update-* through one rusqlite-write window,
            // collapsing fs.write effective concurrency from 16 (the
            // semaphore permit count) to 1. M004's CONTRACT-030 already
            // serialises concurrent SQL upserts at the SQLite level
            // (last-writer-wins on the row id), so the cap-fs lock is
            // unnecessary for the SQL leg.
            //
            // Adversarial-round-2 acknowledged trade-off: releasing the
            // lock before the SQL leg admits a narrow same-path same-agent
            // SQL ordering race — if a guest issues two concurrent fs.write
            // calls to the same vpath, both serialize through the meta_lock
            // for the FS+meta legs (correct order preserved on disk) but
            // their SQL upserts may then run in a different order through
            // `spawn_blocking` → SQLite's TransactionBehavior::Immediate
            // window. Final SQL row content reflects whichever upsert
            // acquired the SQLite write lock LAST, which may not be the
            // newest-on-disk version. Recovery: the next-boot
            // `IndexRebuild::rebuild_full()` (CONTRACT-033) re-reads the
            // FS source-of-truth and overwrites any drifted rows. The race
            // window is bounded by `spawn_blocking` queue + Immediate-tx
            // duration (sub-ms in healthy state), and realistic WASM
            // guests issue fs.write sequentially per agent task — so the
            // race manifests only under pathological per-agent
            // concurrency. A future hardening slice may add per-path
            // serialization or a last_modified compare-and-swap in
            // CONTRACT-030 to close this window without re-introducing
            // the global lock contention.
            drop(_meta_guard);

            // Slice C: SQLite triple sync. Runs BEFORE event emission (matches
            // §2.7 sequence diagram: meta-first → data → SQLite → events).
            // The SQL leg is awaited inline (NEVER spawned) so fs.write returns
            // Ok() only after the SQL leg has either succeeded or emitted a
            // runtime.degraded event. SQL failures emit
            // runtime.degraded.sqlite_sync_failed but the FsEvent::Write +
            // MetaUpdated still fire — FS source-of-truth is committed;
            // reconciliation (CONTRACT-033) is the recovery path.
            sqlite_sync_after_write(
                &db_sync,
                &workspace_root,
                &agent_tree,
                &*emitter,
                &ctx,
                &path,
                &physical,
                &parent_dir,
                &file_name,
                &data,
                &meta_new,
            )
            .await;

            // Slice D: git audit-trail commit. Runs AFTER the SQL leg, BEFORE
            // event emission. Submits a `[turn] [agent:<id>] write <vpath>`
            // commit covering the data file + parent's `.meta.yaml`. Failure
            // emits `runtime.degraded.git_sync_failed` but fs.write still
            // returns Ok() — FS source-of-truth is committed; git is
            // best-effort audit. Same await-not-spawn invariant as the SQL
            // leg.
            git_sync_after_write(&git_sync, &*emitter, &ctx, &path, &physical, &parent_dir).await;

            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::Write {
                    agent_id: ctx.agent_id.clone(),
                    path: path.clone(),
                    size,
                    is_new_file,
                },
            );
            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::MetaUpdated {
                    dir: parent_dir.display().to_string(),
                    entry: file_name.clone(),
                    source: MetaSource::FsWrite,
                    fields: changed_fields,
                },
            );

            // WIT `result<_, fs-error>` — unit OK arm lowers to Val::Result(Ok(None)).
            Ok(vec![Val::Result(Ok(None))])
        })
    }
}

// ---- FsListHandler -------------------------------------------------------------

pub struct FsListHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    /// Per-handler entry-count cap. Default `DEFAULT_MAX_LIST_ENTRIES`; tests
    /// construct with a small value (e.g. 8) to exercise the over-limit path
    /// without creating 65537 inodes.
    pub max_entries: usize,
}

impl HostFunctionHandler for FsListHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let max_entries = self.max_entries;
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.list, got {results_len}"
                )));
            }
            let path = match params.as_slice() {
                [Val::String(s)] => s.clone(),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected single Val::String parameter".into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));

            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.list concurrency semaphore closed".into())
            })?;

            let physical =
                match resolve_via_blocking(resolver, ctx.agent_id.clone(), path.clone(), false)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => return Ok(ok_err_variant(&e)),
                };

            let mut rd = match tokio::fs::read_dir(&physical).await {
                Ok(rd) => rd,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            let target_is_agent_dir = is_agent_dir(&physical);
            let mut entries: Vec<Entry> = Vec::new();
            loop {
                let de = match rd.next_entry().await {
                    Ok(Some(de)) => de,
                    Ok(None) => break,
                    Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
                };
                let name = de.file_name().to_string_lossy().into_owned();
                // Filter workspace-scope hidden entries — keeps `fs.list`
                // honoring the same policy as `resolve_read` Step 6, so a
                // guest can't fingerprint hidden paths via enumeration.
                if is_workspace_hidden_name(&name) {
                    continue;
                }
                // Also skip non-ASCII filenames (slice A surface reduction —
                // matches the resolver's Step 1 policy so `fs.list` doesn't
                // surface entries the agent could not subsequently `fs.read`).
                if !name.is_ascii() {
                    continue;
                }
                // .agent/_* hidden subset filter at enumeration time —
                // when listing an .agent/ dir, skip _-prefixed entries.
                if target_is_agent_dir && name.starts_with('_') {
                    continue;
                }
                if entries.len() >= max_entries {
                    return Ok(ok_err_variant(&FsError::IoError(list_over_limit_msg(
                        max_entries,
                    ))));
                }
                // Use file_type() (lstat under the hood) to AVOID following
                // symlinks. For symlinks, we skip the entry rather than
                // disclose target metadata or abort the whole list on a
                // broken link.
                let file_type = match de.file_type().await {
                    Ok(ft) => ft,
                    Err(_) => continue, // skip entries whose lstat fails
                };
                if file_type.is_symlink() {
                    continue;
                }
                let meta = match de.metadata().await {
                    Ok(m) => m,
                    Err(_) => continue, // skip entries whose metadata fails
                };
                entries.push(Entry::from_metadata(name, &meta));
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));

            let count = entries.len();
            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::List {
                    agent_id: ctx.agent_id.clone(),
                    path: path.clone(),
                    source: FsSource::Private,
                    count,
                },
            );

            let val_entries: Vec<Val> = entries.iter().map(entry_to_val).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(
                val_entries,
            )))))])
        })
    }
}

// ---- FsDeleteHandler -----------------------------------------------------------

pub struct FsDeleteHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub maintainer: Arc<MetaMaintainer>,
    /// Slice C: optional CONTRACT-030 sync surface. Same all-or-nothing
    /// invariant as FsWriteHandler.
    pub db_sync: Option<Arc<dyn SqliteSync>>,
    pub workspace_root: Option<PathBuf>,
    pub agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
    /// Slice D: optional CONTRACT-020 git commit queue surface — mirror of
    /// FsWriteHandler. Independent of the slice C trio.
    pub git_sync: Option<Arc<dyn GitSync>>,
}

impl HostFunctionHandler for FsDeleteHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let maintainer = Arc::clone(&self.maintainer);
        let db_sync = self.db_sync.clone();
        let workspace_root = self.workspace_root.clone();
        let agent_tree = self.agent_tree.clone();
        let git_sync = self.git_sync.clone();
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.delete, got {results_len}"
                )));
            }
            let path = match params.as_slice() {
                [Val::String(s)] => s.clone(),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected single Val::String parameter".into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));

            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.delete concurrency semaphore closed".into())
            })?;

            let physical = match resolve_via_blocking(
                resolver,
                ctx.agent_id.clone(),
                path.clone(),
                true,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };

            // Slice B meta-first delete (AC-10):
            // 1) Capture meta_pre.
            // 2) Remove entry → meta_new.
            // 3) Write meta first (only if meta_pre was Some).
            // 4) remove_file second.
            // 5) On remove failure, roll back meta.
            let parent_dir = match physical.parent() {
                Some(p) => p.to_path_buf(),
                None => {
                    return Ok(ok_err_variant(&FsError::IoError(
                        "no parent dir for delete".into(),
                    )));
                }
            };
            let file_name = match physical.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => {
                    return Ok(ok_err_variant(&FsError::IoError(
                        "invalid file name".into(),
                    )));
                }
            };

            let _meta_guard = maintainer.acquire().await;

            let meta_pre = match maintainer.load(&parent_dir).await {
                Ok(v) => v,
                Err(e) => return Ok(ok_err_variant(&e)),
            };

            let mut emit_meta_updated = false;
            let mut changed_fields_for_emit: Vec<String> = Vec::new();
            let mut meta_post_yaml: Vec<u8> = Vec::new();
            if let Some(ref m_pre) = meta_pre {
                let (meta_new, fields) = maintainer.remove_entry(m_pre.clone(), &file_name);
                if !fields.is_empty() {
                    match maintainer.write(&parent_dir, &meta_new).await {
                        Ok(bytes) => meta_post_yaml = bytes,
                        Err(e) => return Ok(ok_err_variant(&e)),
                    };
                    emit_meta_updated = true;
                    changed_fields_for_emit = fields;
                }
            }

            // Arm cancellation-safe rollback if we performed the meta-first
            // commit. Mirrors FsWriteHandler's pattern: the detached Drop
            // task compares on-disk yaml to meta_post_yaml and skips
            // rollback if an intervening op has superseded our commit.
            let mut rollback_guard = MetaRollbackGuard {
                armed: emit_meta_updated,
                inner: if emit_meta_updated {
                    Some(MetaRollbackInner {
                        maintainer: Arc::clone(&maintainer),
                        emitter: Arc::clone(&emitter),
                        parent_dir: parent_dir.clone(),
                        meta_pre: meta_pre.clone(),
                        meta_post_yaml,
                        agent_id: ctx.agent_id.clone(),
                        trace_id: ctx.trace_id.clone(),
                        vpath: path.clone(),
                        reason: "fs_delete_meta_rollback_failed",
                    })
                } else {
                    None
                },
            };

            // Now remove the data file.
            if let Err(e) = tokio::fs::remove_file(&physical).await {
                // Inline rollback. Keep guard armed during the await; the
                // detached Drop path is idempotent via byte-compare. Disarm
                // only AFTER the rollback completes.
                if emit_meta_updated {
                    if let Some(ref m_pre) = meta_pre {
                        if let Err(rb_err) = maintainer.write(&parent_dir, m_pre).await {
                            emit_runtime_degraded(
                                &*emitter,
                                &ctx.agent_id,
                                &ctx.trace_id,
                                "fs_delete_meta_rollback_failed",
                                serde_json::json!({
                                    "vpath": path,
                                    "remove_error": format!("{:?}", e),
                                    "rollback_error": format!("{:?}", rb_err),
                                }),
                            );
                        }
                    }
                }
                rollback_guard.disarm();
                return Ok(ok_err_variant(&map_io_error(&e)));
            }

            // Data delete succeeded — disarm the cancellation guard.
            rollback_guard.disarm();

            // Adversarial-round-1 fix (C2): release the meta_lock BEFORE
            // the SQL leg. SQL upserts/deletes through CONTRACT-030 already
            // serialise at the SQLite level (TransactionBehavior::Immediate);
            // holding cap-fs's global mutex through two `spawn_blocking`
            // awaits would collapse fs.delete effective concurrency to 1
            // and stall every concurrent fs.write/fs.delete in the runtime
            // when SQLite contends. Mirror of FsWriteHandler's release.
            drop(_meta_guard);

            // Slice C: SQLite triple-sync delete leg. Runs BEFORE event emission.
            // delete_content / delete_meta are idempotent per CONTRACT-030
            // (handle.rs:188-211 "missing row → Ok(())"), so they're safe to
            // call when no row exists.
            sqlite_sync_after_delete(
                &db_sync,
                &workspace_root,
                &agent_tree,
                &*emitter,
                &ctx,
                &path,
                &physical,
                &parent_dir,
                &file_name,
            )
            .await;

            // Slice D: git audit-trail commit. Runs AFTER the SQL leg, BEFORE
            // event emission. Submits a `[turn] [agent:<id>] delete <vpath>`
            // commit. The physical path no longer exists on disk; advance-git's
            // do_commit (slice D enhancement) detects the missing path via
            // symlink_metadata and routes to index.remove_path to stage the
            // deletion. Failure emits runtime.degraded.git_sync_failed but
            // fs.delete still returns Ok().
            git_sync_after_delete(&git_sync, &*emitter, &ctx, &path, &physical, &parent_dir).await;

            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::Delete {
                    agent_id: ctx.agent_id.clone(),
                    path: path.clone(),
                },
            );
            if emit_meta_updated {
                emit_fs_event(
                    &*emitter,
                    &ctx.agent_id,
                    &ctx.trace_id,
                    FsEvent::MetaUpdated {
                        dir: parent_dir.display().to_string(),
                        entry: file_name.clone(),
                        source: MetaSource::FsDelete,
                        fields: changed_fields_for_emit,
                    },
                );
            }

            // WIT `result<_, fs-error>` — unit OK arm lowers to Val::Result(Ok(None)).
            Ok(vec![Val::Result(Ok(None))])
        })
    }
}

// ============================================================================
// Slice B handlers — scan / slug / child / history / update-meta (14 fns).
// ============================================================================

/// Returns true if the directory's leaf name is `.agent` (case-insensitive,
/// matching `is_workspace_hidden_name`'s policy so HFS+/APFS case-folding
/// doesn't allow a guest to bypass the `.agent/_*` filter via `.AGENT/_x`).
fn is_agent_dir(physical: &std::path::Path) -> bool {
    physical
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.eq_ignore_ascii_case(".agent"))
        .unwrap_or(false)
}

// Helper: shared list-enumeration logic used by FsListHandler + the slug/child
// list variants. Filters hidden + non-ASCII + symlinks; respects max_entries.
// Auto-detects whether the directory itself is `.agent` (for the cross-territory
// `.agent/_*` hidden subset rule).
async fn enumerate_directory(
    physical: &std::path::Path,
    max_entries: usize,
) -> Result<Vec<Entry>, FsError> {
    let enumeration_root_is_agent_dir = is_agent_dir(physical);
    let mut rd = match tokio::fs::read_dir(physical).await {
        Ok(rd) => rd,
        Err(e) => return Err(map_io_error(&e)),
    };
    let mut entries: Vec<Entry> = Vec::new();
    loop {
        let de = match rd.next_entry().await {
            Ok(Some(de)) => de,
            Ok(None) => break,
            Err(e) => return Err(map_io_error(&e)),
        };
        let name = de.file_name().to_string_lossy().into_owned();
        if is_workspace_hidden_name(&name) || !name.is_ascii() {
            continue;
        }
        // .agent/_* hidden subset filter — when enumerating an .agent/ dir,
        // skip entries starting with _.
        if enumeration_root_is_agent_dir && name.starts_with('_') {
            continue;
        }
        if entries.len() >= max_entries {
            return Err(FsError::IoError(list_over_limit_msg(max_entries)));
        }
        let file_type = match de.file_type().await {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }
        let meta = match de.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        entries.push(Entry::from_metadata(name, &meta));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

// Helper: build a ScanResult by reading `.meta.yaml` for `_scope` + listing
// children. Internal `.meta.yaml` reads do NOT emit fs.read events (per AC-05
// L0 requirement; only the outer fs.scan event is emitted).
async fn build_scan_result(
    physical: &std::path::Path,
    meta: Option<crate::meta_maintainer::MetaFile>,
    max_entries: usize,
) -> Result<ScanResult, FsError> {
    // The caller is responsible for loading `meta` under `meta_lock` and
    // releasing the lock before calling us — the directory walk does NOT
    // need the lock. The race window where an intervening fs.write/fs.delete
    // commits between the meta load and the dir walk produces consistent
    // user-visible state: a new file shows up as a "[pending]" child, a
    // newly-deleted file simply disappears from the listing.
    let scope = match &meta {
        Some(m) => m.scope.clone(),
        None => ScopeMeta::default(),
    };
    let entries = enumerate_directory(physical, max_entries).await?;
    let mut children: Vec<ChildMeta> = Vec::new();
    for e in entries {
        // Single lookup of the child's meta entry (if any).
        let stored = match &meta {
            Some(m) => m.entries.get(&e.name),
            None => None,
        };
        let (description, tags, stored_type) = match stored {
            Some(em) => (
                em.description.clone(),
                em.tags.clone(),
                Some(em.r#type.clone()),
            ),
            None => (format!("[pending] {}", e.name), Vec::new(), None),
        };
        // Child entity `type` (ADR 2026-06-29 Decision 1 / CONTRACT-010): the
        // stored non-empty value wins; otherwise the deterministic is_dir-aware
        // fallback (dir → collection; `.md` → document; else asset) so the
        // record's required-non-empty `type` invariant holds even for an
        // absent-from-meta child (the `[pending]` case) or a metaed-but-empty
        // entry loaded before the reconciler backfills it. scan does NOT read
        // child bytes (AC-05), so a not-yet-metaed frontmatter `.md` surfaces as
        // `document` until fs.write/reconcile metas it — a transient divergence
        // consistent with the `[pending] {name}` description behaviour.
        let r#type = match stored_type {
            // Trim on exposure so a hand-edited/imported `type: " x "` surfaces
            // consistently with the (already-trimmed) fallback path.
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => crate::meta_schema::entity_type(&e.name, e.is_dir, None),
        };
        let has_agent = if e.is_dir {
            tokio::fs::metadata(physical.join(&e.name).join(".agent"))
                .await
                .map(|m| m.is_dir())
                .unwrap_or(false)
        } else {
            false
        };
        children.push(ChildMeta {
            name: e.name,
            description,
            tags,
            is_dir: e.is_dir,
            has_agent,
            r#type,
        });
    }
    Ok(ScanResult { scope, children })
}

// ---- FsScanHandler -------------------------------------------------------------

pub struct FsScanHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub maintainer: Arc<MetaMaintainer>,
    pub max_entries: usize,
}

impl HostFunctionHandler for FsScanHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let maintainer = Arc::clone(&self.maintainer);
        let max_entries = self.max_entries;
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.scan, got {results_len}"
                )));
            }
            let path = match params.as_slice() {
                [Val::String(s)] => s.clone(),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected single Val::String parameter".into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.scan concurrency semaphore closed".into())
            })?;
            let physical =
                match resolve_via_blocking(resolver, ctx.agent_id.clone(), path.clone(), false)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => return Ok(ok_err_variant(&e)),
                };
            // Narrow lock window (round 9 fix): hold meta_lock ONLY across
            // the .meta.yaml load. The directory walk runs after release, so
            // a guest cannot monopolize the global mutex by looping scans
            // over a max-sized directory. The race between meta load and
            // dir walk produces consistent UX (newly-written file shows as
            // [pending] child; newly-deleted file disappears) — the partial
            // meta-then-data window is never user-visible.
            let meta = {
                let _scan_guard = maintainer.acquire().await;
                match maintainer.load(&physical).await {
                    Ok(v) => v,
                    Err(e) => return Ok(ok_err_variant(&e)),
                }
            };
            let result = match build_scan_result(&physical, meta, max_entries).await {
                Ok(r) => r,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::Scan {
                    agent_id: ctx.agent_id.clone(),
                    path: path.clone(),
                    source: FsSource::Private,
                    children_count: result.children.len(),
                },
            );
            Ok(vec![Val::Result(Ok(Some(Box::new(scan_result_to_val(
                &result,
            )))))])
        })
    }
}

// ---- FsReadSlugHandler / FsListSlugHandler / FsScanSlugHandler ----------------

pub struct FsReadSlugHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
}

impl HostFunctionHandler for FsReadSlugHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.read-slug, got {results_len}"
                )));
            }
            let (peer_id, slug, file) = match params.as_slice() {
                [Val::String(a), Val::String(s), Val::String(f)] => {
                    (a.clone(), s.clone(), f.clone())
                }
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_string_param(&peer_id, "peer_id"));
            check_param!(validate_string_param(&slug, "slug"));
            check_param!(validate_path_param(&file));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.read-slug concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let pid = peer_id.clone();
                let slug = slug.clone();
                let file = file.clone();
                tokio::task::spawn_blocking(move || {
                    resolver.resolve_slug_read(&aid, &pid, &slug, &file)
                })
                .await
                .map_err(|join_err| FsError::IoError(format!("resolver join error: {join_err}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            let metadata = match tokio::fs::metadata(&physical).await {
                Ok(m) => m,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            if u64::from(metadata.len()) > MAX_READ_BYTES as u64 {
                return Ok(ok_err_variant(&FsError::IoError(format!(
                    "file size {} exceeds MAX_READ_BYTES",
                    metadata.len()
                ))));
            }
            let file_handle = match tokio::fs::File::open(&physical).await {
                Ok(f) => f,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            let mut limited = file_handle.take((MAX_READ_BYTES as u64) + 1);
            let mut data = Vec::with_capacity(metadata.len().min(MAX_READ_BYTES as u64) as usize);
            if let Err(e) = limited.read_to_end(&mut data).await {
                return Ok(ok_err_variant(&map_io_error(&e)));
            }
            if data.len() > MAX_READ_BYTES {
                return Ok(ok_err_variant(&FsError::IoError(
                    "file grew past MAX_READ_BYTES".into(),
                )));
            }
            let size = data.len();
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::Read {
                    agent_id: agent_id.clone(),
                    path: format!("{}/{}", slug, file),
                    source: FsSource::Slug,
                    size,
                },
            );
            let val_bytes: Vec<Val> = data.into_iter().map(Val::U8).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(val_bytes)))))])
        })
    }
}

pub struct FsListSlugHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub max_entries: usize,
}

impl HostFunctionHandler for FsListSlugHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let max_entries = self.max_entries;
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.list-slug, got {results_len}"
                )));
            }
            let (peer_id, slug) = match params.as_slice() {
                [Val::String(a), Val::String(s)] => (a.clone(), s.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_string_param(&peer_id, "peer_id"));
            check_param!(validate_string_param(&slug, "slug"));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.list-slug concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let pid = peer_id.clone();
                let slug = slug.clone();
                tokio::task::spawn_blocking(move || {
                    resolver.resolve_slug_read(&aid, &pid, &slug, "")
                })
                .await
                .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            let entries = match enumerate_directory(&physical, max_entries).await {
                Ok(e) => e,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            let count = entries.len();
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::List {
                    agent_id: agent_id.clone(),
                    path: slug.clone(),
                    source: FsSource::Slug,
                    count,
                },
            );
            let val_entries: Vec<Val> = entries.iter().map(entry_to_val).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(
                val_entries,
            )))))])
        })
    }
}

pub struct FsScanSlugHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub maintainer: Arc<MetaMaintainer>,
    pub max_entries: usize,
}

impl HostFunctionHandler for FsScanSlugHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let maintainer = Arc::clone(&self.maintainer);
        let max_entries = self.max_entries;
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.scan-slug, got {results_len}"
                )));
            }
            let (peer_id, slug) = match params.as_slice() {
                [Val::String(a), Val::String(s)] => (a.clone(), s.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_string_param(&peer_id, "peer_id"));
            check_param!(validate_string_param(&slug, "slug"));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.scan-slug concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let pid = peer_id.clone();
                let slug = slug.clone();
                tokio::task::spawn_blocking(move || {
                    resolver.resolve_slug_read(&aid, &pid, &slug, "")
                })
                .await
                .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            // Narrow lock window (round 9 fix): hold meta_lock ONLY across
            // the .meta.yaml load. See FsScanHandler for rationale.
            let meta = {
                let _scan_guard = maintainer.acquire().await;
                match maintainer.load(&physical).await {
                    Ok(v) => v,
                    Err(e) => return Ok(ok_err_variant(&e)),
                }
            };
            let result = match build_scan_result(&physical, meta, max_entries).await {
                Ok(r) => r,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::Scan {
                    agent_id: agent_id.clone(),
                    path: slug.clone(),
                    source: FsSource::Slug,
                    children_count: result.children.len(),
                },
            );
            Ok(vec![Val::Result(Ok(Some(Box::new(scan_result_to_val(
                &result,
            )))))])
        })
    }
}

// ---- FsReadChildHandler / FsListChildHandler / FsScanChildHandler ------------

pub struct FsReadChildHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
}

impl HostFunctionHandler for FsReadChildHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.read-child, got {results_len}"
                )));
            }
            let (child_id, path) = match params.as_slice() {
                [Val::String(c), Val::String(p)] => (c.clone(), p.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_string_param(&child_id, "child_id"));
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.read-child concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let cid = child_id.clone();
                let p = path.clone();
                tokio::task::spawn_blocking(move || resolver.resolve_child_read(&aid, &cid, &p))
                    .await
                    .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            let metadata = match tokio::fs::metadata(&physical).await {
                Ok(m) => m,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            if u64::from(metadata.len()) > MAX_READ_BYTES as u64 {
                return Ok(ok_err_variant(&FsError::IoError(format!(
                    "file size {} exceeds MAX_READ_BYTES",
                    metadata.len()
                ))));
            }
            let file_handle = match tokio::fs::File::open(&physical).await {
                Ok(f) => f,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            let mut limited = file_handle.take((MAX_READ_BYTES as u64) + 1);
            let mut data = Vec::with_capacity(metadata.len().min(MAX_READ_BYTES as u64) as usize);
            if let Err(e) = limited.read_to_end(&mut data).await {
                return Ok(ok_err_variant(&map_io_error(&e)));
            }
            if data.len() > MAX_READ_BYTES {
                return Ok(ok_err_variant(&FsError::IoError(
                    "file grew past MAX_READ_BYTES".into(),
                )));
            }
            let size = data.len();
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::Read {
                    agent_id: agent_id.clone(),
                    path: format!("{}/{}", child_id, path),
                    source: FsSource::Child,
                    size,
                },
            );
            let val_bytes: Vec<Val> = data.into_iter().map(Val::U8).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(val_bytes)))))])
        })
    }
}

pub struct FsListChildHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub max_entries: usize,
}

impl HostFunctionHandler for FsListChildHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let max_entries = self.max_entries;
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.list-child, got {results_len}"
                )));
            }
            let (child_id, path) = match params.as_slice() {
                [Val::String(c), Val::String(p)] => (c.clone(), p.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_string_param(&child_id, "child_id"));
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.list-child concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let cid = child_id.clone();
                let p = path.clone();
                tokio::task::spawn_blocking(move || resolver.resolve_child_read(&aid, &cid, &p))
                    .await
                    .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            let entries = match enumerate_directory(&physical, max_entries).await {
                Ok(e) => e,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            let count = entries.len();
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::List {
                    agent_id: agent_id.clone(),
                    path: format!("{}/{}", child_id, path),
                    source: FsSource::Child,
                    count,
                },
            );
            let val_entries: Vec<Val> = entries.iter().map(entry_to_val).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(
                val_entries,
            )))))])
        })
    }
}

pub struct FsScanChildHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub maintainer: Arc<MetaMaintainer>,
    pub max_entries: usize,
}

impl HostFunctionHandler for FsScanChildHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let maintainer = Arc::clone(&self.maintainer);
        let max_entries = self.max_entries;
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.scan-child, got {results_len}"
                )));
            }
            let (child_id, path) = match params.as_slice() {
                [Val::String(c), Val::String(p)] => (c.clone(), p.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_string_param(&child_id, "child_id"));
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.scan-child concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let cid = child_id.clone();
                let p = path.clone();
                tokio::task::spawn_blocking(move || resolver.resolve_child_read(&aid, &cid, &p))
                    .await
                    .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            // Narrow lock window (round 9 fix): hold meta_lock ONLY across
            // the .meta.yaml load. See FsScanHandler for rationale.
            let meta = {
                let _scan_guard = maintainer.acquire().await;
                match maintainer.load(&physical).await {
                    Ok(v) => v,
                    Err(e) => return Ok(ok_err_variant(&e)),
                }
            };
            let result = match build_scan_result(&physical, meta, max_entries).await {
                Ok(r) => r,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::Scan {
                    agent_id: agent_id.clone(),
                    path: format!("{}/{}", child_id, path),
                    source: FsSource::Child,
                    children_count: result.children.len(),
                },
            );
            Ok(vec![Val::Result(Ok(Some(Box::new(scan_result_to_val(
                &result,
            )))))])
        })
    }
}

// ---- History family (5 handlers) -----------------------------------------------

pub struct FsFileHistoryHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub history: Arc<dyn FileHistoryProvider>,
}

impl HostFunctionHandler for FsFileHistoryHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let history = Arc::clone(&self.history);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.file-history, got {results_len}"
                )));
            }
            let path = match params.as_slice() {
                [Val::String(s)] => s.clone(),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected single Val::String parameter".into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.file-history concurrency closed".into())
            })?;
            let physical =
                match resolve_via_blocking(resolver, ctx.agent_id.clone(), path.clone(), false)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => return Ok(ok_err_variant(&e)),
                };
            // Existence pre-check: history queries against a path that
            // doesn't exist on disk must return the same NotFound payload
            // as the resolver-level hidden-class rejection. Without this,
            // a guest could fingerprint hidden vs visible-missing by
            // observing that file-history("missing.txt") returns Ok([])
            // while file-history(".git/config") returns NotFound.
            if let Err(e) = tokio::fs::metadata(&physical).await {
                return Ok(ok_err_variant(&map_io_error(&e)));
            }
            // Wrap sync provider call in spawn_blocking.
            let physical_for_blocking = physical.clone();
            let history_clone = Arc::clone(&history);
            let versions = match tokio::task::spawn_blocking(move || {
                history_clone.file_history(&physical_for_blocking)
            })
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Ok(ok_err_variant(&e)),
                Err(join_err) => {
                    return Ok(ok_err_variant(&FsError::IoError(format!(
                        "history join error: {join_err}"
                    ))));
                }
            };
            // Cap the version list so a malicious or buggy provider can't
            // explode the response `Vec<Val::Record>`. Response-shape bound only
            // (MODULE-002 §1.7.1 clause 4): the provider has already materialized
            // `versions`, so peak in-flight memory still depends on trusted
            // provider behavior. Pre-provider enforcement requires a slice A
            // trait extension (e.g. `file_history(path, max_count)`) — out of
            // slice B's surface.
            if versions.len() > MAX_HISTORY_VERSIONS {
                return Ok(ok_err_variant(&FsError::IoError(format!(
                    "history version count {} exceeds MAX_HISTORY_VERSIONS ({MAX_HISTORY_VERSIONS})",
                    versions.len()
                ))));
            }
            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::History {
                    agent_id: ctx.agent_id.clone(),
                    path: path.clone(),
                    source: FsSource::History,
                    versions_count: versions.len(),
                },
            );
            let val_versions: Vec<Val> = versions.iter().map(version_entry_to_val).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(
                val_versions,
            )))))])
        })
    }
}

pub struct FsReadAtHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub history: Arc<dyn FileHistoryProvider>,
}

impl HostFunctionHandler for FsReadAtHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let history = Arc::clone(&self.history);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.read-at, got {results_len}"
                )));
            }
            let (path, version) = match params.as_slice() {
                [Val::String(p), Val::String(v)] => {
                    check_param!(validate_string_param(v, "version"));
                    (p.clone(), v.clone())
                }
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));
            let _permit = concurrency
                .acquire()
                .await
                .map_err(|_| HostCallError::HandlerError("fs.read-at concurrency closed".into()))?;
            let physical =
                match resolve_via_blocking(resolver, ctx.agent_id.clone(), path.clone(), false)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => return Ok(ok_err_variant(&e)),
                };
            // Existence pre-check (anti-fingerprinting): see file-history.
            if let Err(e) = tokio::fs::metadata(&physical).await {
                return Ok(ok_err_variant(&map_io_error(&e)));
            }
            // Wrap sync provider call in spawn_blocking to avoid pinning the
            // tokio worker (per FileHistoryProvider contract).
            let physical_for_blocking = physical.clone();
            let version_for_blocking = version.clone();
            let history_clone = Arc::clone(&history);
            let data = match tokio::task::spawn_blocking(move || {
                history_clone.read_at(&physical_for_blocking, &version_for_blocking)
            })
            .await
            {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => return Ok(ok_err_variant(&e)),
                Err(join_err) => {
                    return Ok(ok_err_variant(&FsError::IoError(format!(
                        "history join error: {join_err}"
                    ))));
                }
            };
            // Apply MAX_READ_BYTES bound on history-read data — provider may
            // return arbitrarily large blobs from git history. Response-shape
            // bound only (MODULE-002 §1.7.1 clause 4): the provider has already
            // materialized `data`, so peak in-flight memory still depends on
            // trusted provider behavior. Pre-provider enforcement requires a
            // slice A trait extension (e.g. `read_at(path, version, max_bytes)`)
            // — out of slice B's surface.
            if data.len() > MAX_READ_BYTES {
                return Ok(ok_err_variant(&FsError::IoError(format!(
                    "history blob size {} exceeds MAX_READ_BYTES ({MAX_READ_BYTES})",
                    data.len()
                ))));
            }
            let size = data.len();
            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::Read {
                    agent_id: ctx.agent_id.clone(),
                    path: path.clone(),
                    source: FsSource::History,
                    size,
                },
            );
            let val_bytes: Vec<Val> = data.into_iter().map(Val::U8).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(val_bytes)))))])
        })
    }
}

pub struct FsChildFileHistoryHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub history: Arc<dyn FileHistoryProvider>,
}

impl HostFunctionHandler for FsChildFileHistoryHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let history = Arc::clone(&self.history);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.child-file-history, got {results_len}"
                )));
            }
            let (child_id, path) = match params.as_slice() {
                [Val::String(c), Val::String(p)] => (c.clone(), p.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_string_param(&child_id, "child_id"));
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.child-file-history concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let cid = child_id.clone();
                let p = path.clone();
                tokio::task::spawn_blocking(move || resolver.resolve_child_read(&aid, &cid, &p))
                    .await
                    .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            // Existence pre-check (anti-fingerprinting): see file-history.
            if let Err(e) = tokio::fs::metadata(&physical).await {
                return Ok(ok_err_variant(&map_io_error(&e)));
            }
            // Wrap sync provider call in spawn_blocking.
            let physical_for_blocking = physical.clone();
            let history_clone = Arc::clone(&history);
            let versions = match tokio::task::spawn_blocking(move || {
                history_clone.file_history(&physical_for_blocking)
            })
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Ok(ok_err_variant(&e)),
                Err(join_err) => {
                    return Ok(ok_err_variant(&FsError::IoError(format!(
                        "history join error: {join_err}"
                    ))));
                }
            };
            // Cap the version list so a malicious or buggy provider can't
            // explode the response `Vec<Val::Record>`. Response-shape bound only
            // (MODULE-002 §1.7.1 clause 4): the provider has already materialized
            // `versions`, so peak in-flight memory still depends on trusted
            // provider behavior. Pre-provider enforcement requires a slice A
            // trait extension (e.g. `file_history(path, max_count)`) — out of
            // slice B's surface.
            if versions.len() > MAX_HISTORY_VERSIONS {
                return Ok(ok_err_variant(&FsError::IoError(format!(
                    "history version count {} exceeds MAX_HISTORY_VERSIONS ({MAX_HISTORY_VERSIONS})",
                    versions.len()
                ))));
            }
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::History {
                    agent_id: agent_id.clone(),
                    path: format!("{}/{}", child_id, path),
                    source: FsSource::History,
                    versions_count: versions.len(),
                },
            );
            let val_versions: Vec<Val> = versions.iter().map(version_entry_to_val).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(
                val_versions,
            )))))])
        })
    }
}

pub struct FsReadChildAtHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub history: Arc<dyn FileHistoryProvider>,
}

impl HostFunctionHandler for FsReadChildAtHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let history = Arc::clone(&self.history);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.read-child-at, got {results_len}"
                )));
            }
            let (child_id, path, version) = match params.as_slice() {
                [Val::String(c), Val::String(p), Val::String(v)] => {
                    check_param!(validate_string_param(c, "child_id"));
                    check_param!(validate_string_param(v, "version"));
                    (c.clone(), p.clone(), v.clone())
                }
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.read-child-at concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let cid = child_id.clone();
                let p = path.clone();
                tokio::task::spawn_blocking(move || resolver.resolve_child_read(&aid, &cid, &p))
                    .await
                    .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            // Existence pre-check (anti-fingerprinting): see file-history.
            if let Err(e) = tokio::fs::metadata(&physical).await {
                return Ok(ok_err_variant(&map_io_error(&e)));
            }
            // Wrap sync provider call in spawn_blocking to avoid pinning the
            // tokio worker (per FileHistoryProvider contract).
            let physical_for_blocking = physical.clone();
            let version_for_blocking = version.clone();
            let history_clone = Arc::clone(&history);
            let data = match tokio::task::spawn_blocking(move || {
                history_clone.read_at(&physical_for_blocking, &version_for_blocking)
            })
            .await
            {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => return Ok(ok_err_variant(&e)),
                Err(join_err) => {
                    return Ok(ok_err_variant(&FsError::IoError(format!(
                        "history join error: {join_err}"
                    ))));
                }
            };
            // Apply MAX_READ_BYTES bound on history-read data — provider may
            // return arbitrarily large blobs from git history. Response-shape
            // bound only (MODULE-002 §1.7.1 clause 4): the provider has already
            // materialized `data`, so peak in-flight memory still depends on
            // trusted provider behavior. Pre-provider enforcement requires a
            // slice A trait extension (e.g. `read_at(path, version, max_bytes)`)
            // — out of slice B's surface.
            if data.len() > MAX_READ_BYTES {
                return Ok(ok_err_variant(&FsError::IoError(format!(
                    "history blob size {} exceeds MAX_READ_BYTES ({MAX_READ_BYTES})",
                    data.len()
                ))));
            }
            let size = data.len();
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::Read {
                    agent_id: agent_id.clone(),
                    path: format!("{}/{}", child_id, path),
                    source: FsSource::History,
                    size,
                },
            );
            let val_bytes: Vec<Val> = data.into_iter().map(Val::U8).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(val_bytes)))))])
        })
    }
}

pub struct FsSlugFileHistoryHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub history: Arc<dyn FileHistoryProvider>,
}

impl HostFunctionHandler for FsSlugFileHistoryHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let history = Arc::clone(&self.history);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.slug-file-history, got {results_len}"
                )));
            }
            let (peer_id, slug, file) = match params.as_slice() {
                [Val::String(a), Val::String(s), Val::String(f)] => {
                    (a.clone(), s.clone(), f.clone())
                }
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String, Val::String) parameters".into(),
                    ));
                }
            };
            check_param!(validate_string_param(&peer_id, "peer_id"));
            check_param!(validate_string_param(&slug, "slug"));
            check_param!(validate_path_param(&file));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.slug-file-history concurrency closed".into())
            })?;
            let agent_id = ctx.agent_id.clone();
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = agent_id.clone();
                let pid = peer_id.clone();
                let s = slug.clone();
                let f = file.clone();
                tokio::task::spawn_blocking(move || resolver.resolve_slug_read(&aid, &pid, &s, &f))
                    .await
                    .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            // Existence pre-check (anti-fingerprinting): see file-history.
            if let Err(e) = tokio::fs::metadata(&physical).await {
                return Ok(ok_err_variant(&map_io_error(&e)));
            }
            // Wrap sync provider call in spawn_blocking.
            let physical_for_blocking = physical.clone();
            let history_clone = Arc::clone(&history);
            let versions = match tokio::task::spawn_blocking(move || {
                history_clone.file_history(&physical_for_blocking)
            })
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Ok(ok_err_variant(&e)),
                Err(join_err) => {
                    return Ok(ok_err_variant(&FsError::IoError(format!(
                        "history join error: {join_err}"
                    ))));
                }
            };
            // Cap the version list so a malicious or buggy provider can't
            // explode the response `Vec<Val::Record>`. Response-shape bound only
            // (MODULE-002 §1.7.1 clause 4): the provider has already materialized
            // `versions`, so peak in-flight memory still depends on trusted
            // provider behavior. Pre-provider enforcement requires a slice A
            // trait extension (e.g. `file_history(path, max_count)`) — out of
            // slice B's surface.
            if versions.len() > MAX_HISTORY_VERSIONS {
                return Ok(ok_err_variant(&FsError::IoError(format!(
                    "history version count {} exceeds MAX_HISTORY_VERSIONS ({MAX_HISTORY_VERSIONS})",
                    versions.len()
                ))));
            }
            emit_fs_event(
                &*emitter,
                &agent_id,
                &ctx.trace_id,
                FsEvent::History {
                    agent_id: agent_id.clone(),
                    path: format!("{}/{}", slug, file),
                    source: FsSource::History,
                    versions_count: versions.len(),
                },
            );
            let val_versions: Vec<Val> = versions.iter().map(version_entry_to_val).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(
                val_versions,
            )))))])
        })
    }
}

// ---- Update-meta family (2 handlers) -------------------------------------------

pub struct FsUpdateScopeHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub maintainer: Arc<MetaMaintainer>,
}

impl HostFunctionHandler for FsUpdateScopeHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let maintainer = Arc::clone(&self.maintainer);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.update-scope, got {results_len}"
                )));
            }
            let (path, description, tags) = match params.as_slice() {
                [Val::String(p), Val::String(d), Val::List(ts)] => {
                    // Bound description AND each tag BEFORE cloning so a guest
                    // cannot amplify host-side allocation past these caps.
                    // Return via WIT result-arm (invalid-path) so guests get a
                    // typed fs-error, not a wasmtime trap.
                    if d.len() > MAX_DESCRIPTION_BYTES_HANDLER {
                        return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                            "description exceeds MAX_DESCRIPTION_BYTES ({MAX_DESCRIPTION_BYTES_HANDLER} bytes)"
                        ))));
                    }
                    if ts.len() > MAX_TAGS_COUNT_HANDLER {
                        return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                            "tags exceeds MAX_TAGS_COUNT ({MAX_TAGS_COUNT_HANDLER})"
                        ))));
                    }
                    let mut tag_strs = Vec::with_capacity(ts.len());
                    for v in ts {
                        match v {
                            Val::String(s) => {
                                if s.len() > MAX_TAG_BYTES_HANDLER {
                                    return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                                        "tag exceeds MAX_TAG_BYTES ({MAX_TAG_BYTES_HANDLER} bytes)"
                                    ))));
                                }
                                tag_strs.push(s.clone());
                            }
                            _ => {
                                return Err(HostCallError::HandlerError(
                                    "expected list<string> for tags".into(),
                                ));
                            }
                        }
                    }
                    (p.clone(), d.clone(), tag_strs)
                }
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String, Val::List<Val::String>)".into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.update-scope concurrency closed".into())
            })?;
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = ctx.agent_id.clone();
                let p = path.clone();
                tokio::task::spawn_blocking(move || resolver.resolve_dir_write(&aid, &p))
                    .await
                    .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            // Rule 6 enforcement: reject .agent/ paths via the user-provided
            // vpath rather than scanning physical's full components (which
            // could false-positive if the host workspace itself sits under a
            // dir named `.agent`). The vpath is what the agent typed; if any
            // of its components is `.agent`, we reject. This matches the
            // resolver's relative-component semantics in apply_hidden_name_walk.
            // Case-insensitive on `.agent` to match the resolver-side walk
            // (HFS+/APFS case-folding bypass defense).
            for comp in std::path::Path::new(&path).components() {
                if let std::path::Component::Normal(name) = comp {
                    if name.to_string_lossy().eq_ignore_ascii_case(".agent") {
                        return Ok(ok_err_variant(&FsError::PermissionDenied(
                            ".agent/ scope not editable via update-scope".to_string(),
                        )));
                    }
                }
            }
            let metadata = match tokio::fs::metadata(&physical).await {
                Ok(m) => m,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            if !metadata.is_dir() {
                return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                    "update-scope target is not a directory: {path}"
                ))));
            }
            let _meta_guard = maintainer.acquire().await;
            let meta_pre = match maintainer.load(&physical).await {
                Ok(Some(m)) => m,
                Ok(None) => MetaFile::default(),
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            let (meta_new, changed_fields) =
                match maintainer.update_scope(meta_pre, description, tags) {
                    Ok(v) => v,
                    Err(e) => return Ok(ok_err_variant(&e)),
                };
            if let Err(e) = maintainer.write(&physical, &meta_new).await {
                return Ok(ok_err_variant(&e));
            }
            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::MetaUpdated {
                    dir: physical.display().to_string(),
                    entry: "_scope".to_string(),
                    source: MetaSource::UpdateScope,
                    fields: changed_fields,
                },
            );
            drop(_meta_guard);
            Ok(vec![Val::Result(Ok(None))])
        })
    }
}

pub struct FsUpdateEntryMetaHandler {
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub concurrency: Arc<Semaphore>,
    pub maintainer: Arc<MetaMaintainer>,
}

impl HostFunctionHandler for FsUpdateEntryMetaHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let resolver = Arc::clone(&self.resolver);
        let emitter = Arc::clone(&self.emitter);
        let concurrency = Arc::clone(&self.concurrency);
        let maintainer = Arc::clone(&self.maintainer);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for fs.update-entry-meta, got {results_len}"
                )));
            }
            let (path, entry_name, description, tags) = match params.as_slice() {
                [Val::String(p), Val::String(e), Val::String(d), Val::List(ts)] => {
                    // Bound entry_name + description + each tag BEFORE cloning.
                    // Return via WIT result-arm so guests get a typed fs-error,
                    // not a wasmtime trap.
                    if e.len() > MAX_WIT_STRING_PARAM_BYTES {
                        return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                            "entry_name exceeds MAX_WIT_STRING_PARAM_BYTES ({MAX_WIT_STRING_PARAM_BYTES} bytes)"
                        ))));
                    }
                    if d.len() > MAX_DESCRIPTION_BYTES_HANDLER {
                        return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                            "description exceeds MAX_DESCRIPTION_BYTES ({MAX_DESCRIPTION_BYTES_HANDLER} bytes)"
                        ))));
                    }
                    if ts.len() > MAX_TAGS_COUNT_HANDLER {
                        return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                            "tags exceeds MAX_TAGS_COUNT ({MAX_TAGS_COUNT_HANDLER})"
                        ))));
                    }
                    let mut tag_strs = Vec::with_capacity(ts.len());
                    for v in ts {
                        match v {
                            Val::String(s) => {
                                if s.len() > MAX_TAG_BYTES_HANDLER {
                                    return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                                        "tag exceeds MAX_TAG_BYTES ({MAX_TAG_BYTES_HANDLER} bytes)"
                                    ))));
                                }
                                tag_strs.push(s.clone());
                            }
                            _ => {
                                return Err(HostCallError::HandlerError(
                                    "expected list<string> for tags".into(),
                                ));
                            }
                        }
                    }
                    (p.clone(), e.clone(), d.clone(), tag_strs)
                }
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected (Val::String, Val::String, Val::String, Val::List<Val::String>)"
                            .into(),
                    ));
                }
            };
            check_param!(validate_path_param(&path));
            let _permit = concurrency.acquire().await.map_err(|_| {
                HostCallError::HandlerError("fs.update-entry-meta concurrency closed".into())
            })?;
            let physical = {
                let resolver = Arc::clone(&resolver);
                let aid = ctx.agent_id.clone();
                let p = path.clone();
                tokio::task::spawn_blocking(move || resolver.resolve_dir_write(&aid, &p))
                    .await
                    .map_err(|e| FsError::IoError(format!("resolver join error: {e}")))
            };
            let physical = match physical.and_then(|r| r) {
                Ok(p) => p,
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            // Rule 6: reject .agent/ paths via the user-provided vpath
            // (not the absolute physical) to avoid false-positives on
            // host-side ancestors named .agent.
            // Case-insensitive on `.agent` to match the resolver-side walk
            // (HFS+/APFS case-folding bypass defense).
            for comp in std::path::Path::new(&path).components() {
                if let std::path::Component::Normal(name) = comp {
                    if name.to_string_lossy().eq_ignore_ascii_case(".agent") {
                        return Ok(ok_err_variant(&FsError::PermissionDenied(
                            ".agent/ entries not editable via update-entry-meta".to_string(),
                        )));
                    }
                }
            }
            let metadata = match tokio::fs::metadata(&physical).await {
                Ok(m) => m,
                Err(e) => return Ok(ok_err_variant(&map_io_error(&e))),
            };
            if !metadata.is_dir() {
                return Ok(ok_err_variant(&FsError::InvalidPath(format!(
                    "update-entry-meta target is not a directory: {path}"
                ))));
            }
            let _meta_guard = maintainer.acquire().await;
            let meta_pre = match maintainer.load(&physical).await {
                Ok(Some(m)) => m,
                Ok(None) => MetaFile::default(),
                Err(e) => return Ok(ok_err_variant(&e)),
            };
            let (meta_new, changed_fields) =
                match maintainer.update_entry_meta(meta_pre, &entry_name, description, tags) {
                    Ok(v) => v,
                    Err(e) => return Ok(ok_err_variant(&e)),
                };
            if let Err(e) = maintainer.write(&physical, &meta_new).await {
                return Ok(ok_err_variant(&e));
            }
            emit_fs_event(
                &*emitter,
                &ctx.agent_id,
                &ctx.trace_id,
                FsEvent::MetaUpdated {
                    dir: physical.display().to_string(),
                    entry: entry_name.clone(),
                    source: MetaSource::UpdateEntryMeta,
                    fields: changed_fields,
                },
            );
            drop(_meta_guard);
            Ok(vec![Val::Result(Ok(None))])
        })
    }
}

// ---- registration --------------------------------------------------------------

/// Register the slice A subset of `agent-fs` (read/write/list/delete) into the
/// supplied `HostRegistry` under capability `"fs"` and namespace
/// `"advance:runtime/agent-fs@0.1.0"`. The full 18-fn surface ships across slices A→B+;
/// later slices add more `register_*` calls that target the same namespace.
///
/// # Trust boundary — `HostCallContext.agent_id` (slice A waiver)
///
/// Every handler in this module trusts `ctx.agent_id` from the
/// [`HostCallContext`] passed in by the runtime as the SOLE authority for
/// resolving the calling agent's territory. The resolver (`resolver.rs`)
/// then looks up the agent's `workspace_path` from the
/// [`AgentTreeSnapshot`](advance_shared_types::traits::AgentTreeSnapshot)
/// based on this string id; cap-fs performs NO independent verification.
///
/// **The runtime layer that constructs `HostCallContext` is responsible for
/// ensuring `agent_id` cannot be guest-forged.** This is the same trust model
/// as cap-secrets and cap-llm (see their `host_fn.rs` modules and their
/// AC-15/AC-16-style waivers). Slice A ships before MODULE-001's
/// `CapabilityInjector` slice that will wire `agent_id` from the WASM
/// instance's identity through `Linker::func_wrap_async`'s closure capture;
/// until that lands, this is a documented latent attack surface, not an
/// active vulnerability — no production wiring exists today.
///
/// **DO NOT** add a host function in cap-fs (or any other capability) that
/// reads `agent_id` from a guest-supplied parameter and hands it to a cap-fs
/// handler — that would immediately let any guest enumerate / read / write /
/// delete any agent's territory by spoofing the id. The id MUST flow from the
/// runtime's per-instance binding to `HostCallContext`, never from the
/// guest's own argument list.
/// Register the 18 cap-fs `agent-fs` host functions.
///
/// Slice C parameters (`db_sync`, `workspace_root`, `agent_tree`) wire CONTRACT-030
/// triple-sync into FsWriteHandler / FsDeleteHandler. They MUST be all-Some
/// (slice C wiring) or all-None (slice A/B compatibility). Mixing produces a
/// panic at registration time. `register_agent_fs_default` is the convenience
/// wrapper that passes None for all three.
pub fn register_agent_fs(
    registry: &dyn HostRegistry,
    resolver: Arc<dyn VirtualPathResolver>,
    emitter: Arc<dyn EventBusEmit>,
    schema: Arc<MetaSchemaLoader>,
    history: Arc<dyn FileHistoryProvider>,
    atomic_writer: Arc<dyn AtomicWriter>,
    preview_max_bytes: Option<usize>,
    db_sync: Option<Arc<dyn SqliteSync>>,
    workspace_root: Option<PathBuf>,
    agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
    git_sync: Option<Arc<dyn GitSync>>,
) {
    // Slice C invariant: db_sync, workspace_root, agent_tree must be all-Some
    // or all-None. Caller-side configuration error → panic at registration
    // time (matches slice A/B's policy of asserting invariants on registration
    // arguments rather than threading errors through every call site).
    //
    // Slice D `git_sync` is INDEPENDENT of the slice C trio — a runtime can
    // wire git attribution without SQL (or vice versa). The trio invariant is
    // preserved exactly as-is; `git_sync` is checked separately (no assertion
    // — `None` is the silent-skip case identical to the slice C trio's None
    // mode).
    assert!(
        db_sync.is_some() == workspace_root.is_some() && db_sync.is_some() == agent_tree.is_some(),
        "register_agent_fs: db_sync, workspace_root, and agent_tree must all be Some \
         (slice C triple-sync wiring) or all be None (slice A/B compatibility)"
    );
    let concurrency = Arc::new(Semaphore::new(DEFAULT_FS_CONCURRENCY));
    let cap = "fs".to_string();
    // Versioned (`@0.1.0`) to match the canonical WIT package `advance:runtime@0.1.0`: a
    // wit-bindgen guest built against that package emits *versioned* import paths
    // (`advance:runtime/agent-fs@0.1.0`), and Wasmtime's component linker only satisfies an
    // import from a matching (versioned) `Linker::instance` name. An unversioned registration
    // is unreachable from any real guest (the reply-tracker `agent-messaging@0.1.0`
    // registration is the working precedent). See MODULE-001 §3.6 namespace-version discovery.
    let ns = "advance:runtime/agent-fs@0.1.0".to_string();
    let maintainer = Arc::new(MetaMaintainer::new(
        Arc::clone(&schema),
        Arc::clone(&atomic_writer),
    ));

    // ---- core 4 (slice A) ----
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "read".to_string(),
        handler: Arc::new(FsReadHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            preview_max_bytes,
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "write".to_string(),
        handler: Arc::new(FsWriteHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            maintainer: Arc::clone(&maintainer),
            writer: Arc::clone(&atomic_writer),
            db_sync: db_sync.clone(),
            workspace_root: workspace_root.clone(),
            agent_tree: agent_tree.clone(),
            git_sync: git_sync.clone(),
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "list".to_string(),
        handler: Arc::new(FsListHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "delete".to_string(),
        handler: Arc::new(FsDeleteHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            maintainer: Arc::clone(&maintainer),
            db_sync: db_sync.clone(),
            workspace_root: workspace_root.clone(),
            agent_tree: agent_tree.clone(),
            git_sync: git_sync.clone(),
        }),
        idempotent: false,
    });

    // ---- scan (1) ----
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "scan".to_string(),
        handler: Arc::new(FsScanHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            maintainer: Arc::clone(&maintainer),
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
        }),
        idempotent: true,
    });

    // ---- slug (3) ----
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "read-slug".to_string(),
        handler: Arc::new(FsReadSlugHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "list-slug".to_string(),
        handler: Arc::new(FsListSlugHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "scan-slug".to_string(),
        handler: Arc::new(FsScanSlugHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            maintainer: Arc::clone(&maintainer),
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
        }),
        idempotent: true,
    });

    // ---- child (3) ----
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "read-child".to_string(),
        handler: Arc::new(FsReadChildHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "list-child".to_string(),
        handler: Arc::new(FsListChildHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "scan-child".to_string(),
        handler: Arc::new(FsScanChildHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            maintainer: Arc::clone(&maintainer),
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
        }),
        idempotent: true,
    });

    // ---- history (5) ----
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "file-history".to_string(),
        handler: Arc::new(FsFileHistoryHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            history: Arc::clone(&history),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "read-at".to_string(),
        handler: Arc::new(FsReadAtHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            history: Arc::clone(&history),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "child-file-history".to_string(),
        handler: Arc::new(FsChildFileHistoryHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            history: Arc::clone(&history),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "read-child-at".to_string(),
        handler: Arc::new(FsReadChildAtHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            history: Arc::clone(&history),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "slug-file-history".to_string(),
        handler: Arc::new(FsSlugFileHistoryHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            history: Arc::clone(&history),
        }),
        idempotent: true,
    });

    // ---- update-meta (2) ----
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "update-scope".to_string(),
        handler: Arc::new(FsUpdateScopeHandler {
            resolver: Arc::clone(&resolver),
            emitter: Arc::clone(&emitter),
            concurrency: Arc::clone(&concurrency),
            maintainer: Arc::clone(&maintainer),
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: cap,
        namespace: ns,
        name: "update-entry-meta".to_string(),
        handler: Arc::new(FsUpdateEntryMetaHandler {
            resolver,
            emitter,
            concurrency,
            maintainer,
        }),
        idempotent: false,
    });
}

/// Convenience wrapper that registers all 18 handlers using `DefaultAtomicWriter`
/// and `StubFileHistoryProvider` defaults. Production wiring slices may use this
/// when they don't need to inject custom providers; tests use the full
/// `register_agent_fs` to inject `FailingAtomicWriter` etc.
pub fn register_agent_fs_default(
    registry: &dyn HostRegistry,
    resolver: Arc<dyn VirtualPathResolver>,
    emitter: Arc<dyn EventBusEmit>,
    schema: Arc<MetaSchemaLoader>,
    preview_max_bytes: Option<usize>,
) {
    register_agent_fs(
        registry,
        resolver,
        emitter,
        schema,
        Arc::new(crate::history_provider::StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        preview_max_bytes,
        None, // db_sync
        None, // workspace_root
        None, // agent_tree
        None, // git_sync (slice D)
    );
}
