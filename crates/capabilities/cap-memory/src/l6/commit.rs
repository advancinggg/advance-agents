//! L6 Step 5b — git commit seam. MODULE-011 §1.3.6 step 5b. Internal
//! cap-memory seam; production wires MODULE-003 git, Slice C ships
//! `InMemoryCommitter` (records what WOULD have been committed for trace/order
//! assertions; real on-disk write + git commit `waived_scope`).

use std::sync::Mutex;

use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentKind {
    KnowledgeJsonl,
    KnowledgeMapYaml,
    Synthesis { path: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitFile {
    pub vpath: String,
    pub content_kind: ContentKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum L6CommitError {
    #[error("l6 commit failed: {0}")]
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedCommit {
    pub agent_id: String,
    pub batch_id: String,
    pub files: Vec<CommitFile>,
    /// Pseudo-Oid (slice C: deterministic from batch_id).
    pub oid: String,
}

pub trait L6Committer: Send + Sync {
    fn commit(
        &self,
        agent_id: &str,
        batch_id: &str,
        files: &[CommitFile],
    ) -> Result<String, L6CommitError>;
}

#[derive(Default)]
pub struct InMemoryCommitter {
    commits: Mutex<Vec<RecordedCommit>>,
}

impl InMemoryCommitter {
    pub fn new() -> Self {
        Self {
            commits: Mutex::new(Vec::new()),
        }
    }

    pub fn commits(&self) -> Vec<RecordedCommit> {
        self.commits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl L6Committer for InMemoryCommitter {
    fn commit(
        &self,
        agent_id: &str,
        batch_id: &str,
        files: &[CommitFile],
    ) -> Result<String, L6CommitError> {
        let oid = format!("l6-oid-{batch_id}");
        self.commits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(RecordedCommit {
                agent_id: agent_id.to_string(),
                batch_id: batch_id.to_string(),
                files: files.to_vec(),
                oid: oid.clone(),
            });
        Ok(oid)
    }
}

impl std::fmt::Debug for InMemoryCommitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.commits.lock().map(|c| c.len()).unwrap_or(0);
        f.debug_struct("InMemoryCommitter")
            .field("commits", &n)
            .finish()
    }
}

/// A committer whose [`L6Committer::commit`] ALWAYS fails with
/// [`L6CommitError::Failed`] — the Step-5 `GitCommitFailed` failure injector for
/// the L6 mid-run-failure lease-cleanup test (slice m011-mem-product).
///
/// PUBLIC (not `#[cfg(test)]`) on purpose: integration tests in `tests/` link
/// only the crate's public, non-test surface, so a `#[cfg(test)]` mod item
/// would be invisible to them. `InMemoryCommitter` always returns `Ok`, so a
/// dedicated failing double is the only way to drive `L6Runnable::handle`'s
/// Step-5 commit error path. See §3.8 note 16(d).
///
/// `#[doc(hidden)]` because it is a TEST double, not a production committer —
/// it must stay reachable from `tests/` but should not advertise itself as a
/// wiring option (adversarial-round Info-6: reduce the production-injection
/// footgun of an "always fails" committer on the public API).
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct FailingCommitter;

impl FailingCommitter {
    pub fn new() -> Self {
        Self
    }
}

impl L6Committer for FailingCommitter {
    fn commit(
        &self,
        _agent_id: &str,
        _batch_id: &str,
        _files: &[CommitFile],
    ) -> Result<String, L6CommitError> {
        Err(L6CommitError::Failed("injected commit failure".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_commit_with_pseudo_oid() {
        let c = InMemoryCommitter::new();
        let files = vec![CommitFile {
            vpath: ".agent/memory/knowledge.jsonl".into(),
            content_kind: ContentKind::KnowledgeJsonl,
        }];
        let oid = c.commit("a", "b0c1d2e3", &files).unwrap();
        assert_eq!(oid, "l6-oid-b0c1d2e3");
        let recorded = c.commits();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].files, files);
        assert_eq!(recorded[0].batch_id, "b0c1d2e3");
    }
}
