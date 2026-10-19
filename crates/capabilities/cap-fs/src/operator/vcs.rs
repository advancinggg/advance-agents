//! Read-only git port used by list/stat (`VcsReadPort` + `GitVcsReadPort`).

use std::path::{Path, PathBuf};

use advance_git::{
    repo_status, FileAtVersion, GitHistoryReader, GitRepoStatus, HistoryError, RepoSummary,
};

/// Listing `vcs` leaf (INTEGRATED §3.2 `ClientFileEntry.vcs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcsPathState {
    Committed,
    Modified,
    Untracked,
    Ignored,
    Unknown,
    Unavailable,
}

impl VcsPathState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Modified => "modified",
            Self::Untracked => "untracked",
            Self::Ignored => "ignored",
            Self::Unknown => "unknown",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Read-only git facts the operator needs outside L1.
pub trait VcsReadPort: Send + Sync {
    fn repo_status(&self) -> GitRepoStatus;
    fn summary(&self) -> RepoSummary;
    fn probe_path(&self, rel: &str) -> VcsPathState;
    fn head_blob_oid(&self, rel: &str) -> Option<String>;
    fn read_file_at(&self, path: &str, sha: &str) -> Result<FileAtVersion, HistoryError>;
}

/// Adapter over [`GitHistoryReader`] plus a libgit2 status/tree probe.
pub struct GitVcsReadPort {
    workspace: PathBuf,
    history: GitHistoryReader,
}

impl GitVcsReadPort {
    pub fn new(workspace: PathBuf) -> Self {
        let history = GitHistoryReader::new(workspace.clone());
        Self { workspace, history }
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

impl VcsReadPort for GitVcsReadPort {
    fn repo_status(&self) -> GitRepoStatus {
        repo_status(&self.workspace)
    }

    fn summary(&self) -> RepoSummary {
        self.history.summary()
    }

    fn probe_path(&self, rel: &str) -> VcsPathState {
        if !matches!(repo_status(&self.workspace), GitRepoStatus::Ready) {
            return VcsPathState::Unavailable;
        }
        let repo = match git2::Repository::open(&self.workspace) {
            Ok(repo) => repo,
            Err(_) => return VcsPathState::Unavailable,
        };
        let path = Path::new(rel);
        match repo.status_file(path) {
            Ok(status) => classify_git2_status(status),
            Err(err) => {
                if err.code() == git2::ErrorCode::NotFound {
                    VcsPathState::Untracked
                } else {
                    VcsPathState::Unknown
                }
            }
        }
    }

    fn head_blob_oid(&self, rel: &str) -> Option<String> {
        let repo = git2::Repository::open(&self.workspace).ok()?;
        let obj = repo.revparse_single("HEAD").ok()?;
        let tree = obj.peel_to_tree().ok()?;
        let entry = tree.get_path(Path::new(rel)).ok()?;
        if entry.kind() != Some(git2::ObjectType::Blob) {
            return None;
        }
        Some(entry.id().to_string())
    }

    fn read_file_at(&self, path: &str, sha: &str) -> Result<FileAtVersion, HistoryError> {
        self.history.read_file_at(path, sha)
    }
}

fn classify_git2_status(status: git2::Status) -> VcsPathState {
    if status.is_ignored() {
        VcsPathState::Ignored
    } else if status.is_wt_new() || status.is_index_new() {
        VcsPathState::Untracked
    } else if status.intersects(
        git2::Status::WT_MODIFIED
            | git2::Status::WT_DELETED
            | git2::Status::WT_RENAMED
            | git2::Status::WT_TYPECHANGE
            | git2::Status::INDEX_MODIFIED
            | git2::Status::INDEX_DELETED
            | git2::Status::INDEX_RENAMED
            | git2::Status::INDEX_TYPECHANGE,
    ) {
        VcsPathState::Modified
    } else if status.is_empty() || status.contains(git2::Status::CURRENT) {
        VcsPathState::Committed
    } else {
        VcsPathState::Unknown
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn missing_repo_is_unavailable() {
        let dir = tempfile::tempdir().expect("tmp");
        let port = GitVcsReadPort::new(dir.path().to_path_buf());
        assert!(matches!(port.repo_status(), GitRepoStatus::Missing));
        assert_eq!(port.probe_path("a.md"), VcsPathState::Unavailable);
        assert_eq!(port.head_blob_oid("a.md"), None);
    }
}
