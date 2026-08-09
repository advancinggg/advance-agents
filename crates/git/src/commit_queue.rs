//! CONTRACT-020 `GitCommitQueue` + serialized worker impl.
//!
//! Signature byte-matches MODULE-003 §1.4.1 line 110 and §2.3 line 509:
//! `submit(&self, CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>>`.

use crate::config::{GitConfigProvider, StaticGitConfigProvider};
use crate::error::GitError;
use crate::repo::open_repo_internal;
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use git2::{Oid, Repository, Signature};
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Bucket caps for the `git.commit` event's `affected_paths` payload field
/// (MODULE-003-AC-25, lifecycle-harvest 2026-06-12). Mirrors the cap-fs
/// schema-event bucket discipline: a bounded name list + full-count fields,
/// keeping the serialized payload well under MODULE-019's 64 KiB event cap
/// (64 × 256 B = 16 KiB worst-case for the path bucket). Truncation is
/// silent in the list; `affected_paths_count` / `files_changed` always carry
/// the full staged-path count.
const GIT_COMMIT_EVENT_MAX_PATHS: usize = 64;
const GIT_COMMIT_EVENT_MAX_PATH_BYTES: usize = 256;

/// Process-wide set of canonical repo paths that currently have an active
/// `DefaultGitCommitQueue`. Protects against the adversarial scenario where
/// two queues spawn on the same repo and race on the shared index, `.gitignore`,
/// and `refs/heads/main` — AC-03's serialization invariant is documentation-
/// only across queue instances without this guard.
static ACTIVE_QUEUES: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn active_queues() -> &'static Mutex<HashSet<PathBuf>> {
    ACTIVE_QUEUES.get_or_init(|| Mutex::new(HashSet::new()))
}

// Slice C+D — auto-gitignore threshold is now read from
// `GitConfigProvider::snapshot()` per commit iteration rather than hard-coded.
// `StaticGitConfigProvider::defaults()` preserves the historic Slice A value
// (10 MiB) as the out-of-the-box default.

/// Commit-type taxonomy from PRD §7.2 and MODULE-003 §1.4.1.
/// The `Display` formatter emits the exact lowercase token written into the
/// commit-message prefix `[<commit_type>]` — no capitalization drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitType {
    Turn,
    Micro,
    L6,
}

impl std::fmt::Display for CommitType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Turn => "turn",
            Self::Micro => "micro",
            Self::L6 => "l6",
        })
    }
}

/// Payload submitted to the queue. The `reply` Sender is populated by `submit()`
/// itself — callers construct via [`Self::new`] and never touch `reply`.
///
/// `affected_paths` may be absolute or repo-workdir-relative; absolute paths are
/// normalized to workdir-relative at commit time. A path that resolves outside
/// the repository workdir — by absolute-prefix mismatch **or** by containing a
/// `..` (ParentDir) component in the relative form — is rejected with
/// [`GitError::PathOutsideWorkdir`] (PRD §7.2 path rules).
///
/// `correlation_id` is accepted on the request for forward compatibility with
/// the later observability-wiring slice (it will be surfaced in the `git.commit`
/// event payload). **Slice A does not persist `correlation_id`** — it is neither
/// baked into the commit message nor otherwise stored. Callers depending on
/// ordering identifiers should encode them in `message`.
pub struct CommitRequest {
    pub agent_id: String,
    pub message: String,
    pub affected_paths: Vec<PathBuf>,
    pub commit_type: CommitType,
    pub initiator: String,
    pub correlation_id: Option<String>,
    pub(crate) reply: Option<oneshot::Sender<Result<Oid, GitError>>>,
}

impl CommitRequest {
    pub fn new(
        agent_id: impl Into<String>,
        message: impl Into<String>,
        affected_paths: Vec<PathBuf>,
        commit_type: CommitType,
        initiator: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            message: message.into(),
            affected_paths,
            commit_type,
            initiator: initiator.into(),
            correlation_id: None,
            reply: None,
        }
    }
}

/// CONTRACT-020 — single method returning the oneshot Receiver matched with the
/// in-request Sender allocated by the impl.
///
/// Signature matches MODULE-003 §1.4.1 / §2.3 byte-for-byte.
pub trait GitCommitQueue: Send + Sync {
    fn submit(&self, req: CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>>;
}

/// Serialized commit-queue implementation. Spawns one Tokio blocking-pool worker
/// that owns a re-opened `git2::Repository` handle. Drop of the queue closes the
/// channel; the worker exits after draining remaining requests.
pub struct DefaultGitCommitQueue {
    tx: mpsc::UnboundedSender<CommitRequest>,
    _worker: JoinHandle<()>,
    registered_path: PathBuf,
    _config: Arc<dyn GitConfigProvider>,
}

impl DefaultGitCommitQueue {
    /// `repo_path` must point at a repository already bootstrapped via
    /// [`crate::repo::bootstrap_repo_at`]. `spawn` performs a sanity re-open to
    /// fail fast on config errors before the first `submit()`, AND registers
    /// the canonical repo path into a process-wide active-queue set so that a
    /// second `spawn()` on the same repo fails closed with
    /// `Io(AlreadyExists)`. Without this guard, two queues would race on the
    /// shared `index`, `.gitignore`, and `refs/heads/main` — AC-03's
    /// "serialized commit queue" invariant is only a per-queue guarantee.
    pub fn spawn(repo_path: PathBuf) -> Result<Self, GitError> {
        // Delegate to spawn_inner with the Slice A defaults preserved
        // via `StaticGitConfigProvider::defaults()`. Slice A/B tests and
        // existing callers that use `spawn(path)` continue to observe the
        // historic 10-MiB auto-gitignore threshold. No event bus → the
        // worker emits nothing (existing behavior preserved).
        Self::spawn_inner(
            repo_path,
            Arc::new(StaticGitConfigProvider::defaults()),
            None,
        )
    }

    /// Lifecycle-harvest (2026-06-12) additive constructor
    /// (MODULE-003-AC-25): same defaults as [`Self::spawn`] (shared
    /// `spawn_inner` — the `StaticGitConfigProvider::defaults()` threading,
    /// incl. the 10-MiB `max_tracked_file_mb` default, is preserved), plus an
    /// observability sink captured by the worker at spawn. The worker calls
    /// `bus.emit` once per successful commit — after `do_commit` returns and
    /// the coord guard is dropped, BEFORE the submitter's oneshot reply
    /// resolves (so an acked `submit()` implies the emit was CALLED; whether
    /// the event is durably visible then depends on the sink — a synchronous
    /// bus persists inline, while the async `EventBus` `try_send`s and may drop
    /// under backpressure, incrementing its dropped-count). Failed commits emit
    /// nothing.
    pub fn spawn_with_event_bus(
        repo_path: PathBuf,
        event_bus: Arc<dyn EventBusEmit>,
    ) -> Result<Self, GitError> {
        Self::spawn_inner(
            repo_path,
            Arc::new(StaticGitConfigProvider::defaults()),
            Some(event_bus),
        )
    }

    /// Slice C+D additive constructor: accepts an `Arc<dyn GitConfigProvider>`
    /// so the caller can wire dynamic `max_tracked_file_mb` hot-reload.
    /// The trait's `snapshot()` is read per-commit; callers that only need a
    /// static default should use [`Self::spawn`] instead.
    pub fn spawn_with_config(
        repo_path: PathBuf,
        config: Arc<dyn GitConfigProvider>,
    ) -> Result<Self, GitError> {
        Self::spawn_inner(repo_path, config, None)
    }

    fn spawn_inner(
        repo_path: PathBuf,
        config: Arc<dyn GitConfigProvider>,
        event_bus: Option<Arc<dyn EventBusEmit>>,
    ) -> Result<Self, GitError> {
        let _sanity = open_repo_internal(&repo_path)?;
        drop(_sanity);

        // Canonicalize MUST succeed — otherwise two callers passing the same
        // repo under different path-variants (macOS `/var` vs `/private/var`,
        // trailing-slash variations, transient EACCES-during-canonicalize)
        // would register as distinct keys in ACTIVE_QUEUES, defeating the
        // cross-queue mutex and letting a second spawn through. Fail closed.
        let registered_path = std::fs::canonicalize(&repo_path).map_err(|e| {
            GitError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "cannot canonicalize repo path for queue registration: {} ({e})",
                    repo_path.display()
                ),
            ))
        })?;
        {
            let mut set = active_queues()
                .lock()
                .expect("active_queues mutex poisoned");
            if !set.insert(registered_path.clone()) {
                return Err(GitError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "DefaultGitCommitQueue already active for repo path: {}",
                        repo_path.display()
                    ),
                )));
            }
        }

        let (tx, rx) = mpsc::unbounded_channel::<CommitRequest>();
        // Worker opens the repo via the canonical path so `git_repo_lock` key
        // matches the one `rollback` / `checkpoint` use in the same process.
        let path_for_worker = registered_path.clone();
        let config_for_worker = Arc::clone(&config);
        let _worker = tokio::task::spawn_blocking(move || {
            worker_loop(path_for_worker, rx, config_for_worker, event_bus)
        });
        Ok(Self {
            tx,
            _worker,
            registered_path,
            _config: config,
        })
    }
}

impl Drop for DefaultGitCommitQueue {
    fn drop(&mut self) {
        if let Ok(mut set) = active_queues().lock() {
            set.remove(&self.registered_path);
        }
    }
}

impl GitCommitQueue for DefaultGitCommitQueue {
    fn submit(&self, mut req: CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>> {
        let (tx, rx) = oneshot::channel();
        req.reply = Some(tx);
        if self.tx.send(req).is_err() {
            // Worker died — fabricate a pre-resolved receiver carrying WorkerClosed.
            let (etx, erx) = oneshot::channel();
            let _ = etx.send(Err(GitError::WorkerClosed));
            return erx;
        }
        rx
    }
}

fn worker_loop(
    repo_path: PathBuf,
    mut rx: mpsc::UnboundedReceiver<CommitRequest>,
    config: Arc<dyn GitConfigProvider>,
    event_bus: Option<Arc<dyn EventBusEmit>>,
) {
    let repo = match open_repo_internal(&repo_path) {
        Ok(r) => r,
        Err(_) => {
            drain_with_err(rx);
            return;
        }
    };
    let coord = crate::coord::git_repo_lock(&repo_path);
    while let Some(mut req) = rx.blocking_recv() {
        let reply = req.reply.take();
        // Slice C+D: read the auto-gitignore threshold from the provider
        // snapshot per commit iteration so hot-reload of
        // `max_tracked_file_mb` takes effect without a restart. `snapshot()`
        // is cheap (Arc clone under RwLock::read in the runtime impl).
        //
        // Defense-in-depth clamp to ≥1 MiB: the production
        // `StaticGitConfigProvider::new` validates `max_tracked_file_mb ∈
        // (0, 4096]` matching MODULE-001, but a malicious/buggy trait
        // implementation could publish 0 — which would silently make
        // every non-empty file auto-gitignored, breaking tracking for
        // every future commit with no error surface (R1 adversarial C1
        // fix). 1 MiB is the minimum representable in MODULE-001's `u64
        // MB` schema so the clamp is semantically tight.
        let max_tracked_bytes = config
            .snapshot()
            .max_tracked_file_mb
            .saturating_mul(1024 * 1024)
            .max(1024 * 1024);
        // Per-commit failures propagate as typed `GitError`. If `do_commit`
        // panics (e.g. allocation failure in `format!`), the worker unwinds
        // and the JoinHandle resolves to an error — the next caller's
        // `tx.send()` will fail (channel closed after worker exits), which
        // `submit()` catches and fabricates a pre-resolved
        // `Err(GitError::WorkerClosed)` receiver. We deliberately do NOT use
        // `catch_unwind` + `AssertUnwindSafe(&repo)` because libgit2 state
        // may be mid-mutation at panic time — continuing with the same `repo`
        // handle risks poisoned internal state (Warning #5 in R1 adversarial).
        //
        // Slice B: acquire the per-repo-path coord mutex so a concurrent
        // `DefaultWorkspaceRollback::rollback` or `DefaultNamedCheckpoint::*`
        // on the same repo can't race on `.git/index` or `refs/*` mutations.
        // Unwrap on poisoned mutex: we have no safe way to continue after a
        // prior holder panicked mid-mutation — fail closed.
        let guard = coord.lock().expect("git coord mutex poisoned mid-commit");
        let outcome = do_commit(&repo, &repo_path, &req, max_tracked_bytes);
        drop(guard);
        // MODULE-003-AC-25: emit AFTER the coord guard is dropped (rollback.rs
        // emit-after-guard precedent) and BEFORE the oneshot reply, so an
        // acked `submit()` implies the event is visible to the bus.
        let reply_outcome = match outcome {
            Ok((oid, staged_paths)) => {
                if let Some(bus) = &event_bus {
                    emit_commit_event(bus.as_ref(), &req, oid, &staged_paths);
                }
                Ok(oid)
            }
            Err(e) => Err(e),
        };
        if let Some(tx) = reply {
            let _ = tx.send(reply_outcome);
        }
    }
    // Channel closed (queue dropped). No further submissions possible.
}

/// Truncate `s` to at most `max` bytes on a char boundary (payload-cap
/// helper; path components are typically ASCII but vpaths are
/// guest-influenced, so the boundary walk keeps this panic-free).
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Construct + dispatch the `git.commit` event (PRD §15.3.17 +
/// MODULE-003-AC-25). Payload fields: `agent_id`, `commit_type`
/// (`turn|micro|l6`), `initiator`, `message`, `sha`, `affected_paths`
/// (the staged repo-relative normalized paths returned by `do_commit` —
/// never the caller-raw/absolute `req.affected_paths`; bucket-capped),
/// `affected_paths_count` + `files_changed` (full staged count), and
/// `correlation_id` (sanitized, present when set). All FOUR audit-influenced
/// string fields (`agent_id`, `initiator`, `message`, `correlation_id`) go
/// through the same `sanitize_audit_field` boundary the commit message uses,
/// so the event surface cannot carry forged audit lines either; the
/// `affected_paths` entries are repo-relative (never absolute — `do_commit`
/// normalized + ignore-filtered them) and char-boundary-truncated.
fn emit_commit_event(bus: &dyn EventBusEmit, req: &CommitRequest, oid: Oid, staged: &[String]) {
    let paths: Vec<&str> = staged
        .iter()
        .take(GIT_COMMIT_EVENT_MAX_PATHS)
        .map(|p| truncate_on_char_boundary(p, GIT_COMMIT_EVENT_MAX_PATH_BYTES))
        .collect();
    let safe_agent_id = sanitize_audit_field(&req.agent_id);
    let mut payload = serde_json::json!({
        "agent_id": safe_agent_id,
        "commit_type": req.commit_type.to_string(),
        "initiator": sanitize_audit_field(&req.initiator),
        "message": sanitize_audit_field(&req.message),
        "sha": oid.to_string(),
        "affected_paths": paths,
        "affected_paths_count": staged.len(),
        "files_changed": staged.len(),
    });
    if let Some(cid) = &req.correlation_id {
        payload["correlation_id"] = serde_json::Value::String(sanitize_audit_field(cid));
    }
    bus.emit(Event::observability(
        "git.commit",
        safe_agent_id,
        payload,
        None,
    ));
}

fn drain_with_err(mut rx: mpsc::UnboundedReceiver<CommitRequest>) {
    // Called only on the initial `open_repo_internal` failure path before
    // entering the receive loop. After entering the loop, reply closure happens
    // per-iteration via the `catch_unwind` branch.
    //
    // `rx.close()` must come BEFORE the try_recv loop: it prevents any new sends
    // from being accepted into the channel. Without it, a producer concurrent
    // with the drain could enqueue a request after try_recv() returns Empty;
    // that request's reply Sender would then be dropped when `rx` itself drops,
    // leaving the caller observing an anonymous `RecvError` on their oneshot
    // instead of the typed `GitError::WorkerClosed`. After `close()`, subsequent
    // `UnboundedSender::send` calls return `Err(SendError(...))`, which
    // `submit()` catches and fabricates a pre-resolved
    // `Err(GitError::WorkerClosed)` receiver.
    rx.close();
    while let Ok(mut req) = rx.try_recv() {
        if let Some(reply) = req.reply.take() {
            let _ = reply.send(Err(GitError::WorkerClosed));
        }
    }
}

/// Normalize caller-supplied path to workdir-relative.
///
/// Rejects:
/// - Absolute paths whose canonical form is not inside canonical workdir
///   (`strip_prefix` failure).
/// - Any path containing a `..` (ParentDir) component — even if the net
///   resolution would stay inside workdir, PRD §7.2 treats `..` as a hard
///   `permission-denied` in path rules.
/// - Any path whose first-or-any component is `.git` (case-insensitive), as
///   defense-in-depth against adversarial `affected_paths` that try to
///   overwrite `.git/hooks/post-commit` and execute arbitrary code on the next
///   checkout. libgit2 has a historical CVE surface here on case-insensitive
///   filesystems; we reject at the crate boundary.
/// - Relative paths whose canonical joined form (workdir + rel, resolving any
///   symlinked component) escapes the canonical workdir.
///
/// Both sides are `canonicalize`d when the filesystem resolves them, which
/// handles symlink pairs like macOS's `/var` ↔ `/private/var` AND any
/// intra-tree symlink component. If canonicalize fails for either side
/// (e.g., caller-supplied path points at a file that doesn't exist yet — new
/// file being committed), we fall back to raw strip_prefix; that path is
/// safe only for absolute paths and pure-relative-without-symlinks.
/// Canonicalize the closest existing ancestor of `p` (bounded by
/// `workdir_canon`) and re-attach the missing tail components in original
/// order. Returns `None` when no ancestor at or below the workdir can be
/// canonicalized (i.e., the entire under-workdir chain is missing — the
/// input path is fundamentally bogus or the workdir itself was unlinked
/// out-of-band).
///
/// Slice D regression fix: deleted-leaf paths (fs.delete already removed the
/// file before the queue runs) cannot be `canonicalize`d directly, but the
/// raw absolute path may live under a platform symlink (macOS
/// `/var` → `/private/var`). Plain raw-fallback breaks `strip_prefix` against
/// the canonical workdir; this helper preserves the canonical normalization
/// for the existing portion of the chain so `strip_prefix` can succeed.
///
/// **Workdir bound** (slice D adversarial round 1): the walk-up MUST stop
/// at the canonicalized workdir. Without this bound, an entirely-missing
/// chain under workdir would let the loop pop past workdir and canonicalize
/// e.g. `/private/var/folders/...`, then re-attach a tail that escapes the
/// workdir (a future direct caller of this helper without the strip_prefix
/// gate could leak above-workdir paths). The bound is enforced by checking
/// that each canonicalized ancestor either equals or descends from
/// `workdir_canon`; any walk that pops past workdir returns None.
fn canonicalize_existing_ancestor(p: &Path, workdir_canon: &Path) -> Option<PathBuf> {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut current = p.to_path_buf();
    loop {
        if let Ok(c) = std::fs::canonicalize(&current) {
            // Bound check: canonicalized ancestor must be at or below the
            // canonicalized workdir. If the walk popped above workdir (the
            // workdir itself was rmrf'd or `p` was never under workdir),
            // refuse to canonicalize — the strip_prefix gate downstream
            // would also catch this, but defense-in-depth matters because
            // the helper's contract is "stay within workdir" regardless of
            // caller.
            if c != workdir_canon && c.strip_prefix(workdir_canon).is_err() {
                return None;
            }
            let mut full = c;
            for component in tail.iter().rev() {
                full.push(component);
            }
            return Some(full);
        }
        let leaf = current.file_name().map(|n| n.to_os_string());
        if !current.pop() {
            return None;
        }
        if let Some(name) = leaf {
            tail.push(name);
        }
    }
}

fn normalize_workdir_rel(workdir: &Path, p: &Path) -> Result<PathBuf, GitError> {
    // Fail closed if the workdir itself cannot be canonicalized: a fallback
    // to the raw path mixes canonical/non-canonical comparisons (macOS
    // `/var` vs `/private/var` asymmetry) and silently loosens the trust
    // decision. Callers should see a typed error rather than a relaxed check.
    let canon_workdir = std::fs::canonicalize(workdir).map_err(|e| {
        GitError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "cannot canonicalize workdir for path validation: {} ({e})",
                workdir.display()
            ),
        ))
    })?;

    let rel = if p.is_absolute() {
        // Canonicalize(p): NotFound is acceptable (target may not exist —
        // either a new-file commit not yet written, or a slice D fs.delete
        // where the file was removed BEFORE submission). Any other I/O
        // error (permission-denied mid-traversal, ELOOP, etc.) fails closed
        // so a transient FS glitch can't let the absolute path skip symlink
        // resolution.
        //
        // For the NotFound branch we walk up to the closest existing
        // ancestor, canonicalize THAT, and re-attach the missing tail.
        // Required because on macOS the workdir canonicalizes to
        // `/private/var/...` while raw absolute paths often start with
        // `/var/...`; a plain `p.to_path_buf()` fallback would make
        // `strip_prefix(canon_workdir, p)` spuriously fail and emit
        // `PathOutsideWorkdir` for legitimate slice D deletions.
        let canon_p = match std::fs::canonicalize(p) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                canonicalize_existing_ancestor(p, &canon_workdir).unwrap_or_else(|| p.to_path_buf())
            }
            Err(e) => {
                return Err(GitError::Io(std::io::Error::new(
                    e.kind(),
                    format!("cannot canonicalize path {}: {e}", p.display()),
                )));
            }
        };
        canon_p
            .strip_prefix(&canon_workdir)
            .map(PathBuf::from)
            .map_err(|_| GitError::PathOutsideWorkdir {
                path: p.to_path_buf(),
            })?
    } else {
        p.to_path_buf()
    };

    // Reject `..` before any symlink resolution (defense-in-depth: canonicalize
    // may silently normalize `a/b/..` to `a` which would then pass the symlink
    // check, but the PRD §7.2 rule is to reject the input outright).
    // Reject any `.git` component (case-insensitive) at the same pass —
    // adversarial callers cannot route writes into `.git/...` via the queue.
    for c in rel.components() {
        match c {
            Component::ParentDir => {
                return Err(GitError::PathOutsideWorkdir {
                    path: p.to_path_buf(),
                });
            }
            Component::Normal(name) => {
                if name.to_string_lossy().eq_ignore_ascii_case(".git") {
                    return Err(GitError::PathOutsideWorkdir {
                        path: p.to_path_buf(),
                    });
                }
            }
            _ => {}
        }
    }

    // Symlink-escape defense: if the relative path resolves (via any symlinked
    // directory component) to outside the canonical workdir, OR resolves into
    // the `.git` subtree via an innocent-looking filename, reject. Covers the
    // `ln -s .git/config evil.md` case where `rel` is literally `evil.md`
    // (no `.git` component) but `canon_full` lives inside `.git`.
    let full = workdir.join(&rel);
    if let Ok(canon_full) = std::fs::canonicalize(&full) {
        if canon_full.strip_prefix(&canon_workdir).is_err() {
            return Err(GitError::PathOutsideWorkdir {
                path: p.to_path_buf(),
            });
        }
        // Re-scan the resolved (post-symlink) components for `.git`.
        for c in canon_full
            .strip_prefix(&canon_workdir)
            .unwrap()
            .components()
        {
            if let Component::Normal(name) = c {
                if name.to_string_lossy().eq_ignore_ascii_case(".git") {
                    return Err(GitError::PathOutsideWorkdir {
                        path: p.to_path_buf(),
                    });
                }
            }
        }
    }

    Ok(rel)
}

/// Sanitize caller-supplied audit-trail metadata before interpolating into the
/// commit prefix or signature author name. Without this, a crafted value
/// containing structural metacharacters (`[`, `]`, newlines, control chars, or
/// double-quotes that break git's author format) could forge or corrupt the
/// `[<initiator>]` bracket boundary OR the `author:email<>` pair. Replace any
/// such character with `_`; preserves ASCII-printable and common unicode while
/// stripping metacharacters. See lib.rs Security Posture §4.
fn sanitize_audit_field(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '[' | ']' | '<' | '>' | '"' | '\n' | '\r' | '\0' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}

fn do_commit(
    repo: &Repository,
    repo_path: &Path,
    req: &CommitRequest,
    max_tracked_bytes: u64,
) -> Result<(Oid, Vec<String>), GitError> {
    // Commit-time single-branch guard (AC-02, PRD §7.2 "no per-agent branches").
    // `bootstrap_repo_at` enforces the invariant at open time, but a long-lived
    // queue must re-verify on every commit that (a) HEAD still points at
    // `refs/heads/main` and (b) no side branch has appeared in `refs/heads/`
    // since bootstrap. Both checks are O(refs/heads/*) which is O(1) for the
    // intended single-branch workspace.
    match repo.head() {
        Ok(h) => {
            let name = h.name().unwrap_or("<unnamed>");
            if name != "refs/heads/main" {
                return Err(GitError::NotSingleBranch {
                    observed: name.to_string(),
                });
            }
        }
        Err(e) if e.code() == git2::ErrorCode::UnbornBranch => {
            let sym = repo.find_reference("HEAD")?;
            let target = sym.symbolic_target().unwrap_or("<unknown>");
            if target != "refs/heads/main" {
                return Err(GitError::NotSingleBranch {
                    observed: target.to_string(),
                });
            }
        }
        Err(e) => return Err(GitError::from(e)),
    }
    // Branches iteration: the only acceptable local branch name is "main".
    for b in repo.branches(Some(git2::BranchType::Local))? {
        let (branch, _) = b?;
        let name = branch.name()?.unwrap_or("<unnamed>").to_string();
        if name != "main" {
            return Err(GitError::NotSingleBranch {
                observed: format!("refs/heads/{name}"),
            });
        }
    }

    let workdir = repo.workdir().unwrap_or(repo_path);
    let mut index = repo.index()?;
    // Resync the in-memory index with what's on disk. Otherwise a prior
    // iteration that errored AFTER `index.add_path` but BEFORE `index.write`
    // leaves staged paths cached in this handle; the next iteration would
    // silently commit those leaked paths alongside its own declared
    // `affected_paths` (R1 adversarial Warning #3).
    index.read(true)?;
    let mut gitignore_touched = false;
    let mut to_autoignore: Vec<PathBuf> = Vec::new();
    // MODULE-003-AC-25: the staged repo-relative normalized paths actually
    // recorded by this commit (add OR delete arms; excludes ignored/
    // autoignored paths and the auto-`.gitignore` housekeeping entry).
    // Surfaced to the worker for the `git.commit` event payload — the
    // `do_rollback → Vec<PathBuf>` precedent.
    let mut staged: Vec<String> = Vec::new();

    // First pass: check ignore + size, defer any large-file .gitignore
    // appends to a batched second pass so libgit2's per-repo attr cache
    // doesn't get stale mid-loop (R1 adversarial Warning #6).
    for raw_p in &req.affected_paths {
        let rel = normalize_workdir_rel(workdir, raw_p)?;
        let full = workdir.join(&rel);

        // CRITICAL: `git2::Index::add_path` delegates to libgit2
        // `git_index_add_bypath`, which is a forced-add that IGNORES
        // `.gitignore`. We consult `repo.status_should_ignore(&rel)` and
        // skip paths covered by a static pattern (AC-12 first half).
        // Fail-closed on matcher error.
        if repo.status_should_ignore(&rel)? {
            continue;
        }

        // Slice D: split the existence-decision (via `symlink_metadata`,
        // does NOT follow symlinks) from the size-decision (via inner
        // `metadata`, follows symlinks for AC-12 size-autoignore parity
        // with slice A).
        //
        // - `Ok(_)` arm: any path entry exists (file, dir, dangling symlink,
        //   or symlink to file). Take the slice A add_path branch + size
        //   autoignore via inner `metadata` (which follows the symlink to the
        //   target's actual size — preserves AC-12 byte-identically). If the
        //   inner `metadata` fails (e.g. dangling symlink, target removed
        //   between the two stat syscalls), the size gate is silently skipped
        //   and `add_path` runs — same as slice A, where the inner
        //   `if let Ok(meta) = metadata(&full)` was always permitted to fail
        //   soft.
        // - `Err(NotFound)` arm: caller pre-deleted the path before
        //   submitting (e.g. cap-fs's fs.delete commit). Stage the removal
        //   via `index.remove_path`. libgit2 internally swallows
        //   `GIT_ENOTFOUND` for never-tracked paths (returns 0 / Ok), so no
        //   explicit `Err(NotFound)` arm is needed here — the `?` only
        //   propagates genuine errors (corrupted index, I/O failure on
        //   `.git/index`).
        // - Other I/O errors (EACCES, ELOOP, etc.) on the outer
        //   `symlink_metadata` fail closed via a typed `GitError::Io(...)`
        //   with the path embedded for diagnosability. (Slice A would have
        //   reached `add_path` and surfaced libgit2's own typed error;
        //   slice D shifts the failure surface to the outer stat for
        //   uniform error reporting.)
        match std::fs::symlink_metadata(&full) {
            Ok(_) => {
                // AC-12 size-autoignore (preserved byte-identically from
                // slice A; uses follow-symlink `metadata` for size).
                if let Ok(meta) = std::fs::metadata(&full) {
                    if meta.len() > max_tracked_bytes {
                        to_autoignore.push(rel);
                        continue;
                    }
                }
                index.add_path(&rel)?;
                staged.push(rel.to_string_lossy().into_owned());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Slice D: stage the deletion. Silent no-op for never-tracked
                // paths (libgit2 swallows GIT_ENOTFOUND internally).
                index.remove_path(&rel)?;
                staged.push(rel.to_string_lossy().into_owned());
            }
            Err(e) => {
                return Err(GitError::Io(std::io::Error::new(
                    e.kind(),
                    format!("cannot stat {} for index decision: {e}", full.display()),
                )));
            }
        }
    }

    // Second pass: batch-write all autoignore entries in one .gitignore
    // mutation, then flush libgit2's ignore matcher so any downstream
    // operation (rollback slice, post-commit hooks) observes the update.
    if !to_autoignore.is_empty() {
        for rel in &to_autoignore {
            append_gitignore_entry(workdir, rel)?;
        }
        gitignore_touched = true;
    }

    // Stage `.gitignore` only when it is not already in sync with HEAD — either
    // because `bootstrap_repo_at` wrote it and no commit has recorded it yet
    // (i.e. the first-ever commit on this repo), or because this commit's
    // oversized-file branch just auto-appended to it. This keeps the commit
    // scope aligned with caller-declared `affected_paths` when the gitignore
    // policy is already persisted in HEAD, while still guaranteeing AC-12's
    // "durable in history" property when it isn't.
    if workdir.join(".gitignore").exists()
        && (gitignore_touched || gitignore_diverges_from_head(repo)?)
    {
        index.add_path(Path::new(".gitignore"))?;
    }

    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;

    // Parent commit (if any). Unborn branch → no parents. Corrupt HEAD (target
    // points at a non-existent or non-commit object, or resolves to a non-
    // target symbolic ref) → fail closed, NOT a silent reset to root commit,
    // because a silent root would break the single-linear-history guarantee
    // (AC-02) and hide repo corruption behind a successful Oid.
    let parent_commit = match repo.head() {
        Ok(h) => match h.target() {
            Some(oid) => Some(repo.find_commit(oid)?),
            None => {
                // Ok(head) + None target only happens if HEAD resolved to a
                // symbolic ref whose own target is unborn/corrupt — the
                // UnbornBranch arm below would normally catch the unborn case,
                // so reaching here means the ref chain is partially valid but
                // does not yield an Oid. Fail closed.
                return Err(GitError::NotSingleBranch {
                    observed: h.name().unwrap_or("<corrupt-head>").to_string(),
                });
            }
        },
        Err(e) if e.code() == git2::ErrorCode::UnbornBranch => None,
        Err(e) => return Err(GitError::from(e)),
    };
    let parents: Vec<&git2::Commit> = parent_commit.iter().collect();

    // All three caller-supplied audit-trail fields (`agent_id`, `initiator`,
    // `message`) are sanitized via `sanitize_audit_field` so structural
    // metacharacters cannot forge any audit surface. `agent_id` interpolates
    // into the signature author name; `initiator` into the commit-message
    // prefix; `message` is the free-form trailing text (cap-fs slice D
    // packages this as `"<verb> <vpath>"`, where `vpath` is guest-controlled
    // — without sanitization, a vpath containing `\n[turn] [agent:victim]
    // write secret.md` would forge a fake second log line that audit-log
    // tooling that splits on newlines would attribute to another agent).
    // This sanitizer is the single trust-boundary point for ALL audit
    // surfaces; callers in cap-fs deliberately do not duplicate it.
    let safe_agent_id = sanitize_audit_field(&req.agent_id);
    let safe_initiator = sanitize_audit_field(&req.initiator);
    let safe_message = sanitize_audit_field(&req.message);
    let author_name = format!("agent:{}", safe_agent_id);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let when = git2::Time::new(now, 0);
    let sig = Signature::new(&author_name, "runtime@advance-agents", &when)?;

    // Prefix format: `[<type>] [<initiator>] <message>` (MODULE-003 §1.4.1; PRD §7.2).
    // All three interpolated fields are sanitized so structural metacharacters
    // (`[`, `]`, `<`, `>`, `"`, newlines, control chars) cannot forge or break the
    // prefix boundary OR the post-prefix message body. Preserves lib.rs §4
    // "prefix is not user-controlled" AND extends it to "no audit line is
    // user-controllable" against vpath-newline injection (slice D adversarial
    // round 1).
    let full_msg = format!(
        "[{}] [{}] {}",
        req.commit_type, safe_initiator, safe_message
    );

    let oid = repo.commit(Some("HEAD"), &sig, &sig, &full_msg, &tree, &parents)?;
    Ok((oid, staged))
}

/// Check whether the on-disk `.gitignore` differs from the version recorded in
/// HEAD's tree. Returns true when:
/// - HEAD is unborn (no commits yet — this is the first commit and the file
///   has not yet been recorded anywhere).
/// - HEAD's tree has no `.gitignore` entry (the file was added after the last
///   commit).
/// - The workdir `.gitignore` blob content differs from the HEAD tree's
///   `.gitignore` blob content.
///
/// Returns false if HEAD's tree contains an identical `.gitignore`.
///
/// On any error resolving HEAD's tree or blob, fail OPEN (return true) so the
/// commit will include `.gitignore`. This preserves AC-12 durability in
/// degraded states.
fn gitignore_diverges_from_head(repo: &Repository) -> Result<bool, GitError> {
    let workdir = match repo.workdir() {
        Some(w) => w,
        None => return Ok(true),
    };
    let gi_path = workdir.join(".gitignore");
    let on_disk = match std::fs::read(&gi_path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(true),
    };
    let head = match repo.head() {
        Ok(h) => h,
        Err(e) if e.code() == git2::ErrorCode::UnbornBranch => return Ok(true),
        Err(e) => return Err(GitError::from(e)),
    };
    let head_tree = match head.peel_to_commit().and_then(|c| c.tree()) {
        Ok(t) => t,
        Err(_) => return Ok(true),
    };
    let head_entry = match head_tree.get_path(Path::new(".gitignore")) {
        Ok(e) => e,
        Err(_) => return Ok(true),
    };
    let head_blob = match head_entry.to_object(repo).and_then(|o| o.peel_to_blob()) {
        Ok(b) => b,
        Err(_) => return Ok(true),
    };
    Ok(head_blob.content() != on_disk.as_slice())
}

/// Escape a filename for use as a literal `.gitignore` pattern. Git's
/// gitignore grammar treats `*`, `?`, `[`, `!`, `#`, `\` as metacharacters
/// (plus trailing `/` meaning directory-only, and trailing spaces stripped
/// unless escaped as `\ `). A large-binary file named e.g. `report*.bin`
/// would otherwise generate an overmatching pattern that hides unrelated
/// siblings, breaking AC-12's "excluded from tracking" guarantee for the
/// intended file and spuriously hiding others.
///
/// Escape strategy:
/// - Prepend `\` to every metacharacter so Git treats it as a literal.
/// - Escape a leading `#` or `!` (sentinels for comment and negation).
/// - Escape trailing spaces (Git strips unescaped trailing spaces, so a
///   filename ending in space would silently not match).
fn escape_gitignore_literal(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    // Find the index of the last non-space char (to identify trailing-space run).
    let last_non_space = chars.iter().rposition(|c| *c != ' ');
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in chars.iter().enumerate() {
        let is_trailing_space = *c == ' ' && last_non_space.is_none_or(|ns| i > ns);
        let needs_escape = matches!(c, '*' | '?' | '[' | ']' | '\\')
            || (i == 0 && (*c == '#' || *c == '!'))
            || is_trailing_space;
        if needs_escape {
            out.push('\\');
        }
        out.push(*c);
    }
    out
}

fn append_gitignore_entry(workdir: &Path, rel: &Path) -> Result<(), GitError> {
    // Reject non-UTF8 paths via `GitError::Io(InvalidInput)` — a lossy pattern
    // would not match the actual file in Git's gitignore matcher, silently
    // degrading AC-12's "auto-append large binaries" guarantee on exotic paths.
    // `PathOutsideWorkdir` would be semantically misleading here because the
    // path IS inside the workdir — it simply cannot be written as a gitignore
    // pattern.
    let rel_str = rel.to_str().ok_or_else(|| {
        GitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "non-UTF8 path cannot be written to .gitignore: {}",
                rel.display()
            ),
        ))
    })?;
    // Reject control characters outright. `escape_gitignore_literal` protects
    // against glob metacharacters, but a filename containing `\n` or `\r` would
    // split the .gitignore write into multiple lines, letting an attacker
    // inject additional ignore rules. Filesystems generally reject these in
    // path components anyway, but we defend in depth at the write boundary.
    if rel_str.chars().any(|c| c.is_control()) {
        return Err(GitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "path contains control character; cannot write to .gitignore: {}",
                rel.display()
            ),
        )));
    }
    let gi = workdir.join(".gitignore");
    // Reject symlinked `.gitignore`. `std::fs::read_to_string` / `write`
    // follow symlinks by default, which lets a local attacker place
    // `ln -s /etc/passwd workdir/.gitignore` before any commit and have the
    // runtime-uid process overwrite the symlink target (R1 adversarial
    // Critical #1). `symlink_metadata` does NOT follow; it reports the
    // symlink itself.
    reject_if_symlink(&gi)?;
    let existing = if gi.exists() {
        std::fs::read_to_string(&gi)?
    } else {
        String::new()
    };
    // Prepend `/` so the pattern is anchored at workdir root (avoids matching
    // the file name anywhere in the tree); escape metacharacters so the entry
    // is a literal exact-match pattern.
    let entry = format!("/{}", escape_gitignore_literal(rel_str));
    if existing.lines().any(|l| l.trim() == entry) {
        return Ok(());
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&entry);
    out.push('\n');
    std::fs::write(&gi, out)?;
    Ok(())
}

/// Reject a path that exists as a symlink. Used at `.gitignore` read/write
/// boundaries in `commit_queue::append_gitignore_entry` and
/// `repo::ensure_gitignore` to prevent symlink-follow arbitrary-file-overwrite
/// attacks. NotFound is accepted (file doesn't exist yet — legitimate first
/// write). Any other error (EACCES on parent, ELOOP, ENOTDIR mid-path) fails
/// closed so an attacker cannot induce a metadata-read failure and then race
/// a symlink into place.
pub(crate) fn reject_if_symlink(path: &Path) -> Result<(), GitError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(GitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to read/write through symlink: {}", path.display()),
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(GitError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot stat {} for symlink rejection: {e}", path.display()),
        ))),
    }
}

#[cfg(test)]
mod tests {
    //! Unit-test coverage for slice D adversarial round 2 Info — the
    //! workdir-bound rejection path of `canonicalize_existing_ancestor`.
    //! `normalize_workdir_rel`'s downstream `strip_prefix` gate also
    //! catches above-workdir escapes (defense-in-depth), but locking in
    //! the helper's own contract here prevents future direct callers from
    //! relying on the gate alone.
    use super::canonicalize_existing_ancestor;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn returns_some_when_leaf_missing_under_workdir() {
        let td = TempDir::new().unwrap();
        let workdir_canon = std::fs::canonicalize(td.path()).unwrap();
        let leaf = workdir_canon.join("nonexistent.md");
        let got = canonicalize_existing_ancestor(&leaf, &workdir_canon)
            .expect("should canonicalize the workdir + reattach the missing leaf");
        assert_eq!(got, workdir_canon.join("nonexistent.md"));
    }

    #[test]
    fn returns_some_when_intermediate_missing_under_workdir() {
        let td = TempDir::new().unwrap();
        let workdir_canon = std::fs::canonicalize(td.path()).unwrap();
        // workdir/nonexistent_dir/nonexistent_leaf — both missing, but workdir exists.
        let target = workdir_canon.join("missing_dir").join("missing_leaf.md");
        let got = canonicalize_existing_ancestor(&target, &workdir_canon)
            .expect("should canonicalize the workdir + reattach both missing components");
        assert_eq!(
            got,
            workdir_canon.join("missing_dir").join("missing_leaf.md")
        );
    }

    #[test]
    fn returns_none_when_path_above_workdir() {
        let td = TempDir::new().unwrap();
        let workdir_canon = std::fs::canonicalize(td.path()).unwrap();
        // A path whose closest existing ancestor is well above workdir
        // (filesystem root or its immediate descendants).
        let outside = PathBuf::from("/tmp/some_chain_that_does_not_exist/leaf.md");
        let got = canonicalize_existing_ancestor(&outside, &workdir_canon);
        assert!(
            got.is_none(),
            "must reject paths whose existing ancestor lives above the workdir bound; got {got:?}"
        );
    }

    #[test]
    fn returns_some_when_path_equals_workdir() {
        let td = TempDir::new().unwrap();
        let workdir_canon = std::fs::canonicalize(td.path()).unwrap();
        // Edge case: caller passes workdir itself. The c == workdir_canon
        // exact-equality short-circuit must accept this.
        let got = canonicalize_existing_ancestor(&workdir_canon, &workdir_canon)
            .expect("workdir itself is a valid ancestor of itself");
        assert_eq!(got, workdir_canon);
    }
}
