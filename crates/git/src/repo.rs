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
