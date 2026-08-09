//! Per-repo-path coordination mutex serializing commit queue, rollback, and
//! checkpoint operations across threads.
//!
//! Slice B extends Slice A's cross-queue `ACTIVE_QUEUES` HashSet (which only
//! rejects duplicate `DefaultGitCommitQueue::spawn` on the same repo) with a
//! per-repo-path `std::sync::Mutex<()>` that serializes the actual refdb +
//! index mutations coming from three distinct op types:
//!
//! - [`crate::commit_queue::DefaultGitCommitQueue`] worker iterations (per commit).
//! - [`crate::rollback::DefaultWorkspaceRollback::rollback`] and siblings.
//! - [`crate::checkpoint::DefaultNamedCheckpoint`] `create`/`list`/`delete`.
//!
//! All three touch `.git/index`, `.git/refs/heads/main`, `.git/refs/tags/*`, and
//! `.git/objects/*` — libgit2 has its own per-op internal refdb lock but it
//! does NOT serialize across distinct operations initiated by different top-
//! level methods. Without this mutex, an in-flight commit and a concurrent
//! `tag` call can race on the same index file, leading to either a lost commit
//! or a corrupt `.git/index`.
//!
//! # `std::sync::Mutex`, not `tokio::sync::Mutex`
//!
//! All three op types execute their critical sections on a blocking-pool
//! thread (via [`tokio::task::spawn_blocking`] for the async methods, or
//! directly on the caller thread for the sync `memory_rollback_paths`).
//! That blocking thread retains a tokio runtime `Handle::current()` in TLS
//! (the whole point of `spawn_blocking` — the closure can still dispatch
//! into tokio). [`tokio::sync::Mutex::blocking_lock`] panics when called
//! from such a thread; [`std::sync::Mutex::lock`] does not. The critical
//! section holds the guard across a sequence of synchronous libgit2 calls
//! — no `.await` — so `std::sync::Mutex` is both correct and free of the
//! panic surface.
//!
//! # Scope and invalidation
//!
//! The registry entry is keyed by the canonical repo path (the caller must
//! pass a `std::fs::canonicalize`d `PathBuf`). Distinct path variants —
//! macOS `/var` vs `/private/var`, trailing-slash differences — must
//! canonicalize to the same key or the mutex is bypassed. Helpers in this
//! module expect the caller to hand in an already-canonical path;
//! `commit_queue::DefaultGitCommitQueue::spawn` and the Slice B helpers do
//! this at queue/impl construction time.
//!
//! Entries are never evicted during process lifetime — an `Arc<Mutex<()>>`
//! can safely outlive its holders. Repo deletion is a caller concern.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Per-repo-path coordination registry. Keyed by canonical repo path.
static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<PathBuf, Arc<Mutex<()>>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Return the process-wide coordination mutex for `canonical_repo`.
///
/// Caller MUST pass an already-canonical path (`std::fs::canonicalize` result);
/// the registry keys by raw `PathBuf::Hash` equality, so a non-canonical input
/// collides with a different canonical form under `/var` vs `/private/var` on
/// macOS, producing two mutexes for the same repo on disk and defeating
/// serialization. Slice A's `DefaultGitCommitQueue::spawn` already canonicalizes
/// at registration time; Slice B helpers follow the same pattern.
///
/// Returns a cloned `Arc` so callers can hold the mutex independently across
/// the life of a single op without keeping the registry `HashMap` locked.
pub(crate) fn git_repo_lock(canonical_repo: &Path) -> Arc<Mutex<()>> {
    let mut map = registry()
        .lock()
        .expect("git coord registry mutex poisoned");
    map.entry(canonical_repo.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_same_mutex_for_same_path() {
        let p = PathBuf::from("/tmp/coord-test-same");
        let a = git_repo_lock(&p);
        let b = git_repo_lock(&p);
        assert!(Arc::ptr_eq(&a, &b), "same path must yield same Arc<Mutex>");
    }

    #[test]
    fn returns_distinct_mutex_for_distinct_paths() {
        let p1 = PathBuf::from("/tmp/coord-test-a");
        let p2 = PathBuf::from("/tmp/coord-test-b");
        let a = git_repo_lock(&p1);
        let b = git_repo_lock(&p2);
        assert!(
            !Arc::ptr_eq(&a, &b),
            "distinct paths must yield distinct Arc<Mutex>"
        );
    }
}
