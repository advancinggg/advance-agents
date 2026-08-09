//! Production impls of the 4 terminate-cascade seams (`terminate.rs`) —
//! dev-task-cascade-subset (MODULE-005 Part A).
//!
//! `terminate.rs` defines the cascade as dependency-inversion seams
//! (`GrantCascadeRevoke` / `MailboxCascade` / `RunCascade` / `WorkspaceCleanup`)
//! with no library-side impl; only test recorders existed. These adapters wire
//! each seam to its real backend and are injected into
//! `DefaultTerminateController::new`.
//!
//! One leg is honestly bounded by the callee's existing public API (disclosed in
//! MODULE-005 §3.8, never softened):
//! - [`MailboxFlushCascade::flush_mailbox`] is a best-effort `poll()`-drain —
//!   `MailboxStore` has no drain/remove API and `Mailbox::poll` returns `None`
//!   on freeze / `try_lock` contention.
//!
//! [`RunManagerCascade::cancel_run`] is a SYNCHRONOUS agent-keyed forced cancel
//! (`RunManager::cancel_all_runs_for_agent`, MODULE-008 §1.4.3) — it scans live
//! runs by `controller_agent`, blocks new run creation for that agent, and
//! force-settles all runs for the terminating agent Active→Cancelled,
//! observable the instant terminate returns (no `tokio::Handle::spawn`, no
//! local index). If a residual run-cancel error is ever surfaced, the adapter
//! logs it and lets grant revoke / mailbox flush / workspace cleanup continue.
//!
//! `GrantRevokeCascade`, `notify_parent_crash`, and `FsWorkspaceCleanup` are
//! fully real.

use std::io::Read as _;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use advance_messaging::MailboxStore;
use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::mailbox::{Message, MessageKind};
use cap_grant::GrantStore;

use crate::error::LifecycleError;
use crate::terminate::{
    GrantCascadeRevoke, MailboxCascade, MemoryArchiver, RunCascade, WorkspaceCleanup,
};

/// `GrantCascadeRevoke` → cap-grant `GrantStore::revoke_by_grantee`. Fully real:
/// revokes every `Active` grant whose `grantee == agent_id` (the seam contract —
/// NOT delegated descendants, which cascade with each descendant's own
/// terminate). `revoke_by_grantee` emits a `grant.revoked` event per grant.
pub struct GrantRevokeCascade {
    store: Arc<GrantStore>,
}

impl GrantRevokeCascade {
    pub fn new(store: Arc<GrantStore>) -> Self {
        Self { store }
    }
}

impl GrantCascadeRevoke for GrantRevokeCascade {
    fn revoke_for_agent(&self, agent_id: &str) -> Result<(), LifecycleError> {
        self.store
            .revoke_by_grantee(agent_id)
            .map(|_| ())
            .map_err(|e| {
                LifecycleError::CascadePartial(format!("revoke grants for {agent_id}: {e}"))
            })
    }
}

/// `MailboxCascade` → advance-messaging. `notify_parent_crash` is fully real
/// (delivers a `System` message into the parent's mailbox — the AC-18 path);
/// `flush_mailbox` is best-effort (see module docs).
pub struct MailboxFlushCascade {
    store: Arc<MailboxStore>,
}

impl MailboxFlushCascade {
    pub fn new(store: Arc<MailboxStore>) -> Self {
        Self { store }
    }
}

impl MailboxCascade for MailboxFlushCascade {
    fn flush_mailbox(&self, agent_id: &str) -> Result<(), LifecycleError> {
        // Best-effort drain over the existing public API: `MailboxStore` has no
        // drain/remove, and `Mailbox::poll` returns `None` on freeze / try_lock
        // contention. On a terminating (quiescent, unfrozen) agent the mailbox
        // drains fully; a frozen/contended one may retain messages (disclosed in
        // MODULE-005 §3.8). The iteration budget bounds against a livelock with
        // concurrent delivery. Probing a non-existent mailbox is a no-op.
        if let Some(mb) = self.store.get(agent_id) {
            let mut budget = mb.depth().saturating_add(8);
            while budget > 0 && mb.poll().is_some() {
                budget -= 1;
            }
        }
        Ok(())
    }

    fn notify_parent_crash(
        &self,
        parent_id: &str,
        child_id: &str,
        reason: &str,
    ) -> Result<(), LifecycleError> {
        let mb = self.store.get_or_create(parent_id).map_err(|e| {
            LifecycleError::CascadePartial(format!("get parent mailbox {parent_id}: {e:?}"))
        })?;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let payload = serde_json::json!({
            "event": "component.terminated",
            "child": child_id,
            "reason": reason,
        })
        .to_string()
        .into_bytes();
        let msg = Message {
            id: format!("sys-crash:{child_id}:{nanos}"),
            kind: MessageKind::System,
            from: "system".to_string(),
            to: parent_id.to_string(),
            payload,
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        mb.deliver(msg).map_err(|e| {
            LifecycleError::CascadePartial(format!("deliver crash notice to {parent_id}: {e:?}"))
        })
    }
}

/// `RunCascade` → advance-run-manager. `ensure_run` is sync (creates the agent's
/// run; the returned `RunId` is discarded — `cancel_run` resolves by agent id, so
/// no local index is kept). `cancel_run` is the SYNCHRONOUS agent-keyed forced
/// cancel-all `RunManager::cancel_all_runs_for_agent` (MODULE-008 §1.4.3): it
/// blocks new run creation for the terminating `controller_agent`, scans live
/// runs by that agent, and force-settles every live run to Cancelled, so the
/// post-terminate `status != Active` is observable the instant
/// `terminate_child` returns — preserving SYS-AC-156 without relying on a
/// 1-agent==1-live-run precondition.
pub struct RunManagerCascade {
    rm: Arc<RunManager>,
}

impl RunManagerCascade {
    pub fn new(rm: Arc<RunManager>) -> Self {
        Self { rm }
    }
}

impl RunCascade for RunManagerCascade {
    fn ensure_run(&self, agent_id: &str) -> Result<(), LifecycleError> {
        // Create the agent's run (task_id == controller_agent == agent_id, so
        // `cancel_run_for_agent`'s `controller_agent` store scan can later find
        // it). The returned `RunId` is intentionally discarded — `cancel_run`
        // resolves by agent id, so no local agent→RunId index is needed.
        self.rm
            .ensure_run(agent_id, agent_id, RunConfig::default())
            .map_err(|e| {
                LifecycleError::CascadePartial(format!("ensure_run for {agent_id}: {e:?}"))
            })?;
        Ok(())
    }

    fn cancel_run(&self, agent_id: &str) -> Result<(), LifecycleError> {
        // SYNC forced cancel-all: resolve all live runs by `controller_agent` and
        // settle each to `Cancelled` immediately (no spawn). 0 live runs → clean
        // no-op; one or many → forced `Cancelled` for each. The helper blocks
        // new run creation before scanning, so a residual error is unexpected;
        // if one still appears, continue terminate teardown so grants and
        // workspaces are not retained behind the run leg.
        if let Err(e) = self
            .rm
            .cancel_all_runs_for_agent(agent_id, "terminate-cascade".to_string())
        {
            eprintln!(
                "cap-lifecycle: cancel_all_runs_for_agent failed for {agent_id}; \
                 continuing terminate teardown: {e:?}"
            );
        }
        Ok(())
    }
}

/// `WorkspaceCleanup` → containment-guarded `std::fs::remove_dir_all`. Fully real.
/// cap-fs exposes no public delete; `std::fs` is already used throughout
/// `workspace.rs`. The path comes from the trusted canonical
/// `AgentTreeSnapshot.workspace_path`.
pub struct FsWorkspaceCleanup {
    workspace_root: PathBuf,
}

impl FsWorkspaceCleanup {
    pub fn new(workspace_root: PathBuf) -> Self {
        Self { workspace_root }
    }
}

impl WorkspaceCleanup for FsWorkspaceCleanup {
    fn remove_sub_workspace(&self, workspace_path: &Path) -> Result<(), LifecycleError> {
        // Containment guard: never recursively delete outside the workspace root.
        // `symlink_check` does NOT enforce containment (a strip_prefix miss walks
        // nothing and returns Ok), so this explicit guard is load-bearing for a
        // public recursive-delete adapter.
        //
        // Reject `..` traversal FIRST: `Path::starts_with` is purely lexical and
        // does not resolve `..`, so a non-canonical path like `<root>/../etc`
        // would otherwise pass `starts_with(root)` and then `remove_dir_all`
        // would follow `..` at the OS level and escape the root. Mirror
        // `workspace::resolve_under_parent`'s ParentDir rejection (the production
        // cascade only ever feeds tree-canonicalized `..`-free paths, but this is
        // a `pub` recursive-delete API and must enforce the invariant it claims).
        if workspace_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(LifecycleError::InvalidTarget(format!(
                "remove_sub_workspace: path {} contains a `..` component — \
                 traversal is rejected (the guard does not canonicalize)",
                workspace_path.display()
            )));
        }
        if !workspace_path.starts_with(&self.workspace_root) {
            return Err(LifecycleError::InvalidTarget(format!(
                "remove_sub_workspace: {} not under workspace_root {}",
                workspace_path.display(),
                self.workspace_root.display()
            )));
        }
        // Pre-existing-symlink-ancestor guard (mirrors workspace.rs discipline).
        crate::workspace::symlink_check(&self.workspace_root, workspace_path).map_err(|e| {
            LifecycleError::IoFailure(format!("symlink_check {}: {e}", workspace_path.display()))
        })?;
        match std::fs::remove_dir_all(workspace_path) {
            Ok(()) => Ok(()),
            // Idempotent: an already-absent workspace is a successful no-op.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LifecycleError::IoFailure(format!(
                "remove_dir_all {}: {e}",
                workspace_path.display()
            ))),
        }
    }
}

/// `MemoryArchiver` (M011-AC-29) → preserve a terminating Sub's `.agent/memory/`
/// into the parent's `.agent/memory/archive/<sub_id>/`. The Sub's own per-agent
/// `knowledge.jsonl` files are merged (appended) into
/// `archive/<sub_id>/knowledge.jsonl`; any pre-existing nested `archive/<X>/`
/// under the Sub (a grandchild already archived to this Sub during a multi-level
/// cascade) is RE-HOMED to the parent's `archive/<X>/`, so a deep terminate does
/// not lose grandchild memory. Source reads never follow symlinks; the write
/// target is `..`-rejected, parent-contained, and symlink-checked (mirrors
/// [`FsWorkspaceCleanup::remove_sub_workspace`]). cap-memory's
/// `KnowledgeJsonlStore::open` reads this `archive/<id>/` layout at level-2.
pub struct FsMemoryArchiver;

/// Relative memory root under an agent workspace.
const AGENT_MEMORY_REL: &str = ".agent/memory";
/// Mirrors `cap_memory::persistence::ARCHIVE_DIR_NAME` (kept as a local literal
/// to avoid a cap-lifecycle → cap-memory dependency edge).
const ARCHIVE_SUBDIR: &str = "archive";
const KNOWLEDGE_FILE: &str = "knowledge.jsonl";

impl FsMemoryArchiver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FsMemoryArchiver {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryArchiver for FsMemoryArchiver {
    fn archive_sub_memory(
        &self,
        sub_id: &str,
        sub_workspace: &Path,
        parent_workspace: &Path,
    ) -> Result<(), LifecycleError> {
        // `..`-reject both endpoints (lexical; the cascade only feeds
        // tree-canonicalized paths, but this is a defensive archive writer).
        for p in [sub_workspace, parent_workspace] {
            if p.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(LifecycleError::InvalidTarget(format!(
                    "archive_sub_memory: path {} contains a `..` component",
                    p.display()
                )));
            }
        }
        let src_mem = sub_workspace.join(AGENT_MEMORY_REL);
        let rd = match std::fs::read_dir(&src_mem) {
            Ok(rd) => rd,
            // No memory dir → nothing to archive (a Sub legitimately may never
            // have created `.agent/memory/`). Idempotent no-op.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(LifecycleError::IoFailure(format!(
                    "archive read_dir {}: {e}",
                    src_mem.display()
                )));
            }
        };
        let dst_archive = parent_workspace.join(AGENT_MEMORY_REL).join(ARCHIVE_SUBDIR);
        for ent in rd {
            let ent = ent.map_err(|e| {
                LifecycleError::IoFailure(format!(
                    "archive dir entry under {}: {e}",
                    src_mem.display()
                ))
            })?;
            let p = ent.path();
            // No-follow: skip a symlinked memory subdir.
            match std::fs::symlink_metadata(&p) {
                Ok(md) if md.is_dir() => {}
                _ => continue,
            }
            let name = match p.file_name().and_then(|s| s.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if name == ARCHIVE_SUBDIR {
                // Re-home the Sub's OWN nested archives:
                // archive/<X>/knowledge.jsonl → parent archive/<X>/knowledge.jsonl
                // (preserve the original id X — its memory is NOT this sub's).
                let inner = match std::fs::read_dir(&p) {
                    Ok(rd) => rd,
                    Err(_) => continue,
                };
                for x in inner {
                    let x = x.map_err(|e| {
                        LifecycleError::IoFailure(format!(
                            "archive dir entry under {}: {e}",
                            p.display()
                        ))
                    })?;
                    let xp = x.path();
                    match std::fs::symlink_metadata(&xp) {
                        Ok(md) if md.is_dir() => {}
                        _ => continue,
                    }
                    let xname = match xp.file_name().and_then(|s| s.to_str()) {
                        Some(n) if is_safe_component(n) => n,
                        _ => continue,
                    };
                    let src_kf = xp.join(KNOWLEDGE_FILE);
                    if is_regular_file(&src_kf) {
                        append_into(
                            &src_kf,
                            &dst_archive.join(xname).join(KNOWLEDGE_FILE),
                            parent_workspace,
                        )?;
                    }
                }
            } else {
                // The Sub's own per-agent knowledge.jsonl → archive/<sub_id>/.
                if !is_safe_component(sub_id) {
                    continue;
                }
                let src_kf = p.join(KNOWLEDGE_FILE);
                if is_regular_file(&src_kf) {
                    append_into(
                        &src_kf,
                        &dst_archive.join(sub_id).join(KNOWLEDGE_FILE),
                        parent_workspace,
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// A single path component safe to use as a literal directory name.
fn is_safe_component(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains('/')
        && !s.contains('\\')
        && !s.contains('\0')
}

fn is_regular_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// Append `src`'s bytes to `dst` (creating `dst`'s parent dirs), with a parent-
/// containment + symlink-ancestor guard mirroring [`FsWorkspaceCleanup`]. Ensures
/// a trailing newline so concatenated JSONL lines never merge.
fn append_into(src: &Path, dst: &Path, parent_root: &Path) -> Result<(), LifecycleError> {
    // Containment: dst must be under parent_root (lexical; both are `..`-free).
    if !dst.starts_with(parent_root) {
        return Err(LifecycleError::InvalidTarget(format!(
            "archive target {} not under parent workspace {}",
            dst.display(),
            parent_root.display()
        )));
    }
    // Stream the source in bounded chunks rather than slurping the whole file into
    // RAM (defense-in-depth: bounds peak memory regardless of file size — matches the
    // capped-read discipline used for comparable host-side reads — WITHOUT truncating
    // a legitimately large knowledge.jsonl, which would itself be data loss).
    let src_file = std::fs::File::open(src).map_err(|e| {
        LifecycleError::IoFailure(format!("archive open src {}: {e}", src.display()))
    })?;
    let mut reader = std::io::BufReader::new(src_file);
    let mut buf = [0u8; 64 * 1024];
    // Peek the first chunk: an empty source is a no-op and (matching the prior
    // behavior) must NOT create the destination dir/file.
    let first_n = reader
        .read(&mut buf)
        .map_err(|e| LifecycleError::IoFailure(format!("archive read {}: {e}", src.display())))?;
    if first_n == 0 {
        return Ok(());
    }
    if let Some(dir) = dst.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            LifecycleError::IoFailure(format!("archive mkdir {}: {e}", dir.display()))
        })?;
        // Pre-existing-symlink-ancestor guard (mirrors remove_sub_workspace).
        crate::workspace::symlink_check(parent_root, dir).map_err(|e| {
            LifecycleError::IoFailure(format!("archive symlink_check {}: {e}", dir.display()))
        })?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dst)
        .map_err(|e| LifecycleError::IoFailure(format!("archive open {}: {e}", dst.display())))?;
    f.write_all(&buf[..first_n])
        .map_err(|e| LifecycleError::IoFailure(format!("archive write {}: {e}", dst.display())))?;
    let mut last_byte = buf[first_n - 1];
    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            LifecycleError::IoFailure(format!("archive read {}: {e}", src.display()))
        })?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n]).map_err(|e| {
            LifecycleError::IoFailure(format!("archive write {}: {e}", dst.display()))
        })?;
        last_byte = buf[n - 1];
    }
    // Ensure a trailing newline so concatenated JSONL lines never merge.
    if last_byte != b'\n' {
        f.write_all(b"\n").map_err(|e| {
            LifecycleError::IoFailure(format!("archive write nl {}: {e}", dst.display()))
        })?;
    }
    Ok(())
}
