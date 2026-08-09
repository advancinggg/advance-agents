//! Git-history provider trait — slice B forward-binding seam.
//!
//! cap-fs's 5 history host fns (file-history, read-at, child-file-history,
//! read-child-at, slug-file-history) call into a `FileHistoryProvider` trait
//! that future MODULE-003 work will implement with real git2-backed history.
//! Slice B ships `StubFileHistoryProvider` as a placeholder that returns:
//!   - `Ok(empty list)` for `file_history` (so `AC-01: 18 fns implemented and
//!     callable` passes — the host fn is callable and returns a valid empty result)
//!   - `Err(NotFound)` for `read_at` (no version exists yet — caller must handle).
//!
//! When MODULE-003 ships the GitFileHistoryProvider, the slice that wires it
//! will swap `Arc<StubFileHistoryProvider>` for `Arc<GitFileHistoryProvider>`
//! at the `register_agent_fs` call site. The trait may also migrate to
//! `shared-types` at that point.

use std::path::Path;

use crate::entry::VersionEntry;
use crate::error::FsError;

/// Trait providing git-version history for paths inside an agent's territory.
///
/// All implementations MUST be Send + Sync. Methods are sync because git2 is
/// sync; callers wrap in `tokio::task::spawn_blocking` if they need async
/// integration with the rest of the runtime.
pub trait FileHistoryProvider: Send + Sync {
    /// Most-recent-first git history for `physical_path`. Empty list = no
    /// history (e.g. file was just created, or history not yet wired).
    fn file_history(&self, physical_path: &Path) -> Result<Vec<VersionEntry>, FsError>;

    /// Read file content at the given git version. The version string is the
    /// hex commit SHA-1 (40 chars) or a Git ref name. Returns NotFound if the
    /// version doesn't exist.
    fn read_at(&self, physical_path: &Path, version: &str) -> Result<Vec<u8>, FsError>;
}

/// Slice B placeholder. Returns Ok(empty) for file_history and Err(NotFound) for read_at.
///
/// Documented asymmetry: `file_history` returning `Ok(empty)` is more user-friendly
/// (callers can iterate; empty means "no history yet") whereas `read_at`
/// fundamentally cannot return data without a real version, so it returns
/// `NotFound`. Both are "callable from WASM" for AC-01 verification — the
/// distinction is whether the WIT result is Ok or Err.
pub struct StubFileHistoryProvider;

impl FileHistoryProvider for StubFileHistoryProvider {
    fn file_history(&self, _physical_path: &Path) -> Result<Vec<VersionEntry>, FsError> {
        Ok(Vec::new())
    }

    fn read_at(&self, _physical_path: &Path, _version: &str) -> Result<Vec<u8>, FsError> {
        Err(FsError::NotFound(
            "history read-at: M003 git-history provider not yet wired".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn stub_file_history_returns_empty() {
        let p = StubFileHistoryProvider;
        let path = PathBuf::from("/tmp/example.txt");
        let r = p.file_history(&path).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn stub_read_at_returns_notfound() {
        let p = StubFileHistoryProvider;
        let path = PathBuf::from("/tmp/example.txt");
        let err = p.read_at(&path, "deadbeef").unwrap_err();
        match err {
            FsError::NotFound(_) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
