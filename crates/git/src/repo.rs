//! Repository bootstrap + single-branch enforcement + `.gitignore` installation.
//!
//! MODULE-003 §1.1 / §2.5 / PRD §7.2: workspace is a single-repo, single-branch
//! (`main`) Git model. `bootstrap_repo_at` is idempotent and does not return the
//! raw `git2::Repository` handle — only internal workers re-open via
//! [`open_repo_internal`].

use crate::error::GitError;
use git2::{BranchType, Repository, RepositoryInitOptions};
use std::path::Path;

/// PRD §7.3 + MODULE-003 §2.5 "Ignored paths" table — patterns merged into
/// `.gitignore` with dedup. Comment lines in this constant are header-only and
/// are NOT written into the target file.
pub(crate) const DEFAULT_GITIGNORE: &str = "\
# advance-agents runtime — MODULE-003 §2.5 (REQ-147, AC-12).
*.sqlite
*.sqlite-wal
*.sqlite-shm
/.runtime/
/.advance/packs/*/tmp
";

/// Bootstrap a single-branch Git repository at `path`, returning `()` on success.
/// Enforces:
/// - single `main` branch — HEAD symbolically targets `refs/heads/main` AND no
///   other local branches exist (PRD §7.2, REQ-140, MODULE-003-AC-02).
/// - `.gitignore` contains SQLite + runtime-internal patterns (REQ-147, AC-12
///   first half).
///
/// The raw `git2::Repository` handle is NOT returned — module-boundary invariant
/// per MODULE-003 §1.1 ("No other module imports `git2` directly — cross-module
/// Git operations go through CONTRACT-020 GitCommitQueue, CONTRACT-021
/// WorkspaceRollback, and CONTRACT-022 NamedCheckpoint").
pub fn bootstrap_repo_at(path: &Path) -> Result<(), GitError> {
    let repo = if path.join(".git").exists() {
        Repository::open(path)?
    } else {
        let mut opts = RepositoryInitOptions::new();
        opts.initial_head("main");
        Repository::init_opts(path, &opts)?
    };
    enforce_single_branch(&repo)?;
    drop(repo);
    ensure_gitignore(path)?;
    Ok(())
}

/// Internal re-opener for the commit-queue worker. Not part of the public API
/// — matches the MODULE-003 §1.1 invariant that `Repository` never crosses the
/// crate boundary.
pub(crate) fn open_repo_internal(path: &Path) -> Result<Repository, GitError> {
    Ok(Repository::open(path)?)
}

/// The observable state of a workspace repository (git-family PR-1).
///
/// Produced by [`repo_status`] (read-only probe) and [`ensure_workspace_repo`]
/// (compose-time bootstrap). The composition root exposes it on its handles
/// and the Client API projects it (`/client/git/status`, `/client/health`), so
/// a workspace whose history is unavailable says WHY instead of degrading
/// silently. `observed` / `reason` are Git ref names and libgit2 messages —
/// never user content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRepoStatus {
    /// `.git` exists, opens, HEAD targets `refs/heads/main` (born or unborn)
    /// and no other local branch coexists: the commit queue can commit.
    Ready,
    /// No `.git` at the workspace root (the workspace was never bootstrapped).
    Missing,
    /// The repository exists but HEAD is not `refs/heads/main` OR a second
    /// local branch coexists. Never "fixed" by the runtime: the commit queue
    /// refuses every commit until an operator restores the single-`main` layout.
    NotMain { observed: String },
    /// `.git` exists but libgit2 could not open or read the repository.
    Unreadable { reason: String },
}

impl GitRepoStatus {
    /// `true` only for [`GitRepoStatus::Ready`].
    pub fn is_ready(&self) -> bool {
        matches!(self, GitRepoStatus::Ready)
    }

    /// The stable lowercase token the Client API carries: `ready` / `missing` /
    /// `not_main` / `unreadable`.
    pub fn token(&self) -> &'static str {
        match self {
            GitRepoStatus::Ready => "ready",
            GitRepoStatus::Missing => "missing",
            GitRepoStatus::NotMain { .. } => "not_main",
            GitRepoStatus::Unreadable { .. } => "unreadable",
        }
    }
}

impl std::fmt::Display for GitRepoStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitRepoStatus::Ready => f.write_str("ready"),
            GitRepoStatus::Missing => f.write_str("missing (no .git at the workspace root)"),
            GitRepoStatus::NotMain { observed } => {
                write!(f, "not_main (observed {observed})")
            }
            GitRepoStatus::Unreadable { reason } => write!(f, "unreadable ({reason})"),
        }
    }
}

/// Read-only probe of the repository at `path`. Never writes, never takes the
/// per-repo coord mutex (`coord.rs`) — safe to call from any thread at any time.
pub fn repo_status(path: &Path) -> GitRepoStatus {
    if !path.join(".git").exists() {
        return GitRepoStatus::Missing;
    }
    let repo = match Repository::open(path) {
        Ok(repo) => repo,
        Err(e) => {
            return GitRepoStatus::Unreadable {
                reason: e.message().to_string(),
            }
        }
    };
    match enforce_single_branch(&repo) {
        Ok(()) => GitRepoStatus::Ready,
        Err(GitError::NotSingleBranch { observed }) => GitRepoStatus::NotMain { observed },
        Err(e) => GitRepoStatus::Unreadable {
            reason: e.to_string(),
        },
    }
}

/// Compose-time bootstrap of the workspace repository.
///
/// - `path` is not a directory → [`GitRepoStatus::Unreadable`] (nothing is created:
///   the runtime never conjures a workspace).
/// - No `.git` → [`bootstrap_repo_at`] (single-branch `main`, `.gitignore`
///   installed; idempotent) → `Ready`.
/// - `.git` exists → [`repo_status`] only. An existing repository is NEVER
///   rewritten: a HEAD off `main` is reported as [`GitRepoStatus::NotMain`], not
///   re-pointed; `.gitignore` is left as the operator keeps it.
pub fn ensure_workspace_repo(path: &Path) -> GitRepoStatus {
    if !path.is_dir() {
        return GitRepoStatus::Unreadable {
            reason: format!("workspace {} is not a directory", path.display()),
        };
    }
    if path.join(".git").exists() {
        return repo_status(path);
    }
    match bootstrap_repo_at(path) {
        Ok(()) => GitRepoStatus::Ready,
        Err(GitError::NotSingleBranch { observed }) => GitRepoStatus::NotMain { observed },
        Err(e) => GitRepoStatus::Unreadable {
            reason: e.to_string(),
        },
    }
}

fn enforce_single_branch(repo: &Repository) -> Result<(), GitError> {
    // (a) HEAD must symbolically target refs/heads/main. Detached HEAD or a non-
    //     main target is rejected. Unborn branch (fresh init) is accepted if the
    //     symbolic ref target is refs/heads/main.
    match repo.head() {
        Ok(r) => {
            let name = r.name().unwrap_or("<unnamed>");
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
    // (b) No other local branches may exist. Only acceptable local branch is "main".
    for b in repo.branches(Some(BranchType::Local))? {
        let (branch, _) = b?;
        let name = branch.name()?.unwrap_or("<unnamed>").to_string();
        if name != "main" {
            return Err(GitError::NotSingleBranch {
                observed: format!("refs/heads/{name}"),
            });
        }
    }
    Ok(())
}

fn ensure_gitignore(path: &Path) -> Result<(), GitError> {
    let gi = path.join(".gitignore");
    // Reject symlinked `.gitignore` — `std::fs::read_to_string` / `write`
    // follow symlinks, which would let a pre-placed `ln -s /etc/passwd
    // workdir/.gitignore` redirect our writes to an arbitrary file
    // (AC-12-adversarial concern from R1 adversarial review).
    crate::commit_queue::reject_if_symlink(&gi)?;
    let existing = if gi.exists() {
        std::fs::read_to_string(&gi)?
    } else {
        String::new()
    };
    let mut out = existing.clone();
    if !existing.is_empty() && !existing.ends_with('\n') {
        out.push('\n');
    }
    for line in DEFAULT_GITIGNORE.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let needle = line.trim();
        if !existing.lines().any(|l| l.trim() == needle) {
            out.push_str(line);
            out.push('\n');
        }
    }
    if out != existing {
        std::fs::write(&gi, out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_status_missing_without_dot_git() {
        let td = tempfile::TempDir::new().unwrap();
        assert_eq!(repo_status(td.path()), GitRepoStatus::Missing);
        assert_eq!(GitRepoStatus::Missing.token(), "missing");
    }

    #[test]
    fn ensure_bootstraps_an_empty_directory_once() {
        let td = tempfile::TempDir::new().unwrap();
        assert_eq!(ensure_workspace_repo(td.path()), GitRepoStatus::Ready);
        assert!(td.path().join(".git").is_dir());
        let head = std::fs::read_to_string(td.path().join(".git/HEAD")).unwrap();
        assert_eq!(head.trim(), "ref: refs/heads/main");
        assert!(td.path().join(".gitignore").is_file());
        // Idempotent: a second call opens, never re-inits.
        assert_eq!(ensure_workspace_repo(td.path()), GitRepoStatus::Ready);
        assert_eq!(repo_status(td.path()), GitRepoStatus::Ready);
    }

    #[test]
    fn ensure_refuses_a_missing_directory() {
        let td = tempfile::TempDir::new().unwrap();
        let gone = td.path().join("nope");
        assert!(matches!(
            ensure_workspace_repo(&gone),
            GitRepoStatus::Unreadable { .. }
        ));
        assert!(!gone.exists(), "nothing is created for a missing workspace");
    }

    #[test]
    fn ensure_reports_not_main_without_rewriting() {
        let td = tempfile::TempDir::new().unwrap();
        let mut opts = RepositoryInitOptions::new();
        opts.initial_head("other");
        Repository::init_opts(td.path(), &opts).unwrap();
        let before = std::fs::read_to_string(td.path().join(".git/HEAD")).unwrap();
        let status = ensure_workspace_repo(td.path());
        assert_eq!(
            status,
            GitRepoStatus::NotMain {
                observed: "refs/heads/other".to_string()
            }
        );
        assert_eq!(status.token(), "not_main");
        let after = std::fs::read_to_string(td.path().join(".git/HEAD")).unwrap();
        assert_eq!(before, after, "HEAD is reported, never re-pointed");
        assert!(
            !td.path().join(".gitignore").exists(),
            "an existing repository is not rewritten"
        );
    }

    #[test]
    fn repo_status_unreadable_for_a_corrupt_dot_git() {
        let td = tempfile::TempDir::new().unwrap();
        std::fs::write(td.path().join(".git"), "gitdir: /nonexistent/elsewhere\n").unwrap();
        assert!(matches!(
            repo_status(td.path()),
            GitRepoStatus::Unreadable { .. }
        ));
        assert!(matches!(
            ensure_workspace_repo(td.path()),
            GitRepoStatus::Unreadable { .. }
        ));
    }
}
