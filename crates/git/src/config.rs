//! Dep-inversion trait for MODULE-001 RuntimeConfig consumption (Slice C+D).
//!
//! `advance-git` is Phase-2 in `IMPLEMENTATION_ORDER.md`; MODULE-001
//! runtime-host is Phase-1. For `advance-git` to consume RuntimeConfig
//! without adding a reverse dep on `advance-runtime`, this module
//! publishes a local trait `GitConfigProvider` that the runtime crate
//! will implement via an adapter wrapping its `RuntimeConfigWatcher`.
//!
//! Contract: callers pass `Arc<dyn GitConfigProvider>` into
//! [`crate::commit_queue::DefaultGitCommitQueue::spawn_with_config`] +
//! [`crate::gc::GcTask::spawn`]. The trait's [`GitConfigProvider::snapshot`]
//! is read per-commit for dynamic `max_tracked_file_mb` (auto-gitignore
//! threshold per §2.10); [`GitConfigProvider::subscribe`] is used by the
//! gc task to rebuild its ticker on `gc_interval_hours` change.
//!
//! Both the commit queue and the gc task clamp defensively against
//! out-of-bounds values so a buggy provider cannot panic the runtime
//! (zero-interval → `tokio::time::interval` panic). See §3.8 caveat (e).

use crate::error::GitError;
use tokio::sync::mpsc;

/// Snapshot of the git-related runtime config subset. Cheap to copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitConfigSnapshot {
    /// MODULE-001 validates `(0, 8760]` — we accept the same bounds.
    pub gc_interval_hours: u64,
    /// MODULE-001 validates `(0, 4096]` — we accept the same bounds.
    pub max_tracked_file_mb: u64,
}

impl GitConfigSnapshot {
    /// Default values matching MODULE-003 §2.10: 24h interval, 10 MB
    /// auto-gitignore threshold.
    pub const DEFAULTS: Self = Self {
        gc_interval_hours: 24,
        max_tracked_file_mb: 10,
    };
}

/// Dep-inversion trait: implemented by the runtime-crate adapter wrapping
/// `RuntimeConfigWatcher`, and by [`StaticGitConfigProvider`] for tests /
/// bootstrap.
pub trait GitConfigProvider: Send + Sync {
    /// Current snapshot. Cheap — production impl returns values from an
    /// `Arc<RuntimeConfig>` held under `RwLock::read`.
    fn snapshot(&self) -> GitConfigSnapshot;

    /// Subscribe to config updates. Each `Receiver` is single-consumer;
    /// every `subscribe()` call returns a fresh channel. Updates that
    /// arrive faster than the receiver drains are dropped (bounded
    /// channel). Consumers should re-read [`snapshot`] on every wake to
    /// pick up any updates that may have been dropped.
    fn subscribe(&self) -> mpsc::Receiver<GitConfigSnapshot>;
}

/// Immutable provider for production bootstrap paths and for tests that
/// never hot-reload. `subscribe()` returns a receiver whose sender is
/// dropped immediately — consumers see `Poll::Ready(None)` on the first
/// `recv()` and then no-op for the task's lifetime.
#[derive(Debug)]
pub struct StaticGitConfigProvider {
    snapshot: GitConfigSnapshot,
}

impl StaticGitConfigProvider {
    /// Build a provider with validated arguments. Out-of-bounds inputs
    /// produce [`GitError::InvalidConfig`] (matches MODULE-001's bounds).
    ///
    /// `gc_interval_hours` must be in `(0, 8760]` (≤ 1 year).
    /// `max_tracked_file_mb` must be in `(0, 4096]` (≤ 4 GiB).
    pub fn new(gc_interval_hours: u64, max_tracked_file_mb: u64) -> Result<Self, GitError> {
        if gc_interval_hours == 0 || gc_interval_hours > 8_760 {
            return Err(GitError::InvalidConfig {
                field: "gc_interval_hours",
                value: gc_interval_hours,
                reason: "must be in (0, 8760]".to_string(),
            });
        }
        if max_tracked_file_mb == 0 || max_tracked_file_mb > 4_096 {
            return Err(GitError::InvalidConfig {
                field: "max_tracked_file_mb",
                value: max_tracked_file_mb,
                reason: "must be in (0, 4096]".to_string(),
            });
        }
        Ok(Self {
            snapshot: GitConfigSnapshot {
                gc_interval_hours,
                max_tracked_file_mb,
            },
        })
    }

    /// Default values matching MODULE-003 §2.10: 24h / 10 MB. Infallible —
    /// the hard-coded values are in-bounds by construction.
    pub fn defaults() -> Self {
        Self {
            snapshot: GitConfigSnapshot::DEFAULTS,
        }
    }
}

impl GitConfigProvider for StaticGitConfigProvider {
    fn snapshot(&self) -> GitConfigSnapshot {
        self.snapshot
    }

    fn subscribe(&self) -> mpsc::Receiver<GitConfigSnapshot> {
        // Static provider never publishes — return a receiver whose sender
        // is dropped so consumers immediately see a closed channel.
        let (_tx, rx) = mpsc::channel(1);
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_module_003_section_2_10() {
        let p = StaticGitConfigProvider::defaults();
        let s = p.snapshot();
        assert_eq!(s.gc_interval_hours, 24);
        assert_eq!(s.max_tracked_file_mb, 10);
    }

    #[test]
    fn new_accepts_in_bounds() {
        assert!(StaticGitConfigProvider::new(1, 1).is_ok());
        assert!(StaticGitConfigProvider::new(8760, 4096).is_ok());
        assert!(StaticGitConfigProvider::new(24, 10).is_ok());
    }

    #[test]
    fn new_rejects_zero_gc_interval() {
        let err = StaticGitConfigProvider::new(0, 10).unwrap_err();
        assert!(matches!(
            err,
            GitError::InvalidConfig {
                field: "gc_interval_hours",
                value: 0,
                ..
            }
        ));
    }

    #[test]
    fn new_rejects_overflow_gc_interval() {
        let err = StaticGitConfigProvider::new(8761, 10).unwrap_err();
        assert!(matches!(
            err,
            GitError::InvalidConfig {
                field: "gc_interval_hours",
                value: 8761,
                ..
            }
        ));
    }

    #[test]
    fn new_rejects_zero_max_tracked_file_mb() {
        let err = StaticGitConfigProvider::new(24, 0).unwrap_err();
        assert!(matches!(
            err,
            GitError::InvalidConfig {
                field: "max_tracked_file_mb",
                value: 0,
                ..
            }
        ));
    }

    #[test]
    fn new_rejects_overflow_max_tracked_file_mb() {
        let err = StaticGitConfigProvider::new(24, 4097).unwrap_err();
        assert!(matches!(
            err,
            GitError::InvalidConfig {
                field: "max_tracked_file_mb",
                value: 4097,
                ..
            }
        ));
    }

    #[test]
    fn subscribe_returns_closed_receiver() {
        let p = StaticGitConfigProvider::defaults();
        let mut rx = p.subscribe();
        // Channel sender is dropped immediately inside subscribe; recv should
        // return None quickly (not hang).
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            assert!(rx.recv().await.is_none());
        });
    }
}
