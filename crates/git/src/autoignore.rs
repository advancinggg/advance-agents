//! Runtime auto-ignore registry (MODULE-003 §2.5 / AC-34, oss-git §11.3).
//!
//! Auto-entries are `/<escaped path>` lines without a marker, so a user-written
//! identical `.gitignore` line cannot be told apart by content. The runtime
//! records **its own** entries in `.git/advance/autoignore`: one escaped pattern
//! per line, written atomically, runtime-private.
//!
//! - Append writes the pattern to `.gitignore` and to the registry.
//! - Shrink (pattern in the registry and the file now ≤ the threshold) removes
//!   both lines and the file is re-evaluated. A user-written line that is not
//!   in the registry is never removed.
//! - Move/MoveTree rewrite `from` (and under `from/`) to `to` in both files.
//! - Remove/RemoveTree drop the matching entries.
//!
//! Panic-free: it runs while the coord mutex is held.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use git2::Repository;

use crate::commit_queue::reject_if_symlink;
use crate::error::GitError;
use crate::journal::RUNTIME_DIR;
use crate::safe_fs::write_atomic;

const REGISTRY_FILE: &str = "autoignore";
const GITIGNORE: &str = ".gitignore";

/// `/<escaped>` pattern for a workdir-relative tree path.
pub(crate) fn pattern_for(rel: &str) -> Result<String, GitError> {
    if rel.is_empty() || rel.chars().any(char::is_control) {
        return Err(GitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("cannot write an auto-ignore pattern for {rel:?}"),
        )));
    }
    Ok(format!("/{}", escape_gitignore_literal(rel)))
}

/// `true` when `rel`'s pattern is in the registry.
pub(crate) fn contains(repo: &Repository, rel: &str) -> Result<bool, GitError> {
    let pattern = pattern_for(rel)?;
    Ok(load_registry(repo.path())?
        .iter()
        .any(|line| line == &pattern))
}

/// Append `rel` to `.gitignore` and the registry. `true` when either file changed.
pub(crate) fn append(repo: &Repository, rel: &Path) -> Result<bool, GitError> {
    let rel_str = utf8_rel(rel)?;
    let pattern = pattern_for(rel_str)?;
    let gi = gitignore_changed(workdir(repo)?, &pattern, GitignoreOp::Ensure)?;
    let reg = registry_changed(repo.path(), &pattern, RegistryOp::Ensure)?;
    Ok(gi || reg)
}

/// Drop the registry entry for `rel` (and the matching `.gitignore` line iff it
/// is in the registry). `true` when either file changed.
pub(crate) fn drop_exact(repo: &Repository, rel: &str) -> Result<bool, GitError> {
    let pattern = pattern_for(rel)?;
    apply_drop(repo, |line| line == pattern)
}

/// Drop registry entries for `dir` and every path under it.
pub(crate) fn drop_tree(repo: &Repository, dir: &str) -> Result<bool, GitError> {
    let pattern = pattern_for(dir)?;
    let prefix = format!("{pattern}/");
    apply_drop(repo, |line| line == pattern || line.starts_with(&prefix))
}

/// Rewrite registry (and matching `.gitignore`) entries from `from` to `to`.
/// When `tree`, every path under `from/` moves with it.
pub(crate) fn rewrite_move(
    repo: &Repository,
    from: &str,
    to: &str,
    tree: bool,
) -> Result<bool, GitError> {
    let from_pat = pattern_for(from)?;
    let to_pat = pattern_for(to)?;
    let from_prefix = format!("{from_pat}/");
    let map_line = |line: &str| -> String {
        if line == from_pat {
            return to_pat.clone();
        }
        if tree {
            if let Some(rest) = line.strip_prefix(&from_prefix) {
                return format!("{to_pat}/{rest}");
            }
        }
        line.to_string()
    };
    let (reg_before, mut registry) = load_registry_raw(repo.path())?;
    let in_registry: Vec<String> = registry.clone();
    for line in registry.iter_mut() {
        *line = map_line(line);
    }
    registry.sort();
    registry.dedup();
    let reg = save_registry_if(repo.path(), &reg_before, &registry)?;
    let gi = rewrite_gitignore(workdir(repo)?, &in_registry, map_line)?;
    Ok(gi || reg)
}

/// Remove `rel` from the registry and from `.gitignore` when it is an auto-entry.
pub(crate) fn shrink(repo: &Repository, rel: &str) -> Result<bool, GitError> {
    drop_exact(repo, rel)
}

fn apply_drop(repo: &Repository, drop_line: impl Fn(&str) -> bool) -> Result<bool, GitError> {
    let (reg_before, registry) = load_registry_raw(repo.path())?;
    let dropped: Vec<String> = registry
        .iter()
        .filter(|line| drop_line(line))
        .cloned()
        .collect();
    if dropped.is_empty() {
        return Ok(false);
    }
    let kept: Vec<String> = registry
        .into_iter()
        .filter(|line| !drop_line(line))
        .collect();
    let reg = save_registry_if(repo.path(), &reg_before, &kept)?;
    let gi = strip_gitignore(workdir(repo)?, &dropped)?;
    Ok(gi || reg)
}

fn workdir(repo: &Repository) -> Result<&Path, GitError> {
    repo.workdir().ok_or_else(|| {
        GitError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "auto-ignore needs a repository with a workdir",
        ))
    })
}

fn utf8_rel(rel: &Path) -> Result<&str, GitError> {
    rel.to_str().ok_or_else(|| {
        GitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "non-UTF8 path cannot be written to .gitignore: {}",
                rel.display()
            ),
        ))
    })
}

fn registry_path(git_dir: &Path) -> PathBuf {
    git_dir.join(RUNTIME_DIR).join(REGISTRY_FILE)
}

fn load_registry(git_dir: &Path) -> Result<Vec<String>, GitError> {
    Ok(load_registry_raw(git_dir)?.1)
}

fn load_registry_raw(git_dir: &Path) -> Result<(Vec<u8>, Vec<String>), GitError> {
    let path = registry_path(git_dir);
    reject_if_symlink(&path)?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            let lines = parse_lines(&bytes);
            Ok((bytes, lines))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), Vec::new())),
        Err(e) => Err(e.into()),
    }
}

fn parse_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn save_registry_if(git_dir: &Path, before: &[u8], lines: &[String]) -> Result<bool, GitError> {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    if before == out.as_bytes() {
        return Ok(false);
    }
    let dir = git_dir.join(RUNTIME_DIR);
    reject_if_symlink(&dir)?;
    std::fs::create_dir_all(&dir)?;
    let path = registry_path(git_dir);
    reject_if_symlink(&path)?;
    write_atomic(&path, out.as_bytes())?;
    Ok(true)
}

enum RegistryOp {
    Ensure,
}

fn registry_changed(git_dir: &Path, pattern: &str, op: RegistryOp) -> Result<bool, GitError> {
    let (before, mut lines) = load_registry_raw(git_dir)?;
    match op {
        RegistryOp::Ensure => {
            if lines.iter().any(|line| line == pattern) {
                return Ok(false);
            }
            lines.push(pattern.to_string());
        }
    }
    save_registry_if(git_dir, &before, &lines)
}

enum GitignoreOp {
    Ensure,
}

fn gitignore_changed(workdir: &Path, pattern: &str, op: GitignoreOp) -> Result<bool, GitError> {
    match op {
        GitignoreOp::Ensure => ensure_gitignore_line(workdir, pattern),
    }
}

fn ensure_gitignore_line(workdir: &Path, pattern: &str) -> Result<bool, GitError> {
    let gi = workdir.join(GITIGNORE);
    reject_if_symlink(&gi)?;
    let existing = match std::fs::read_to_string(&gi) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    if existing.lines().any(|line| line.trim() == pattern) {
        return Ok(false);
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(pattern);
    out.push('\n');
    reject_if_symlink(&gi)?;
    write_atomic(&gi, out.as_bytes())?;
    Ok(true)
}

fn strip_gitignore(workdir: &Path, drop_lines: &[String]) -> Result<bool, GitError> {
    let gi = workdir.join(GITIGNORE);
    reject_if_symlink(&gi)?;
    let existing = match std::fs::read_to_string(&gi) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let mut kept = String::new();
    let mut changed = false;
    for line in existing.lines() {
        if drop_lines.iter().any(|d| line.trim() == d) {
            changed = true;
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    if !changed {
        return Ok(false);
    }
    write_atomic(&gi, kept.as_bytes())?;
    Ok(true)
}

fn rewrite_gitignore(
    workdir: &Path,
    in_registry: &[String],
    map_line: impl Fn(&str) -> String,
) -> Result<bool, GitError> {
    let gi = workdir.join(GITIGNORE);
    reject_if_symlink(&gi)?;
    let existing = match std::fs::read_to_string(&gi) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let mut out = String::new();
    let mut changed = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        let next = if in_registry.iter().any(|p| p == trimmed) {
            map_line(trimmed)
        } else {
            trimmed.to_string()
        };
        if next != trimmed {
            changed = true;
        }
        out.push_str(&next);
        out.push('\n');
    }
    if !changed {
        return Ok(false);
    }
    write_atomic(&gi, out.as_bytes())?;
    Ok(true)
}

/// Escape a filename for a literal `.gitignore` pattern (AC-12).
pub(crate) fn escape_gitignore_literal(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let last_non_space = chars.iter().rposition(|c| *c != ' ');
    let mut out = String::new();
    for (i, c) in chars.iter().copied().enumerate() {
        let is_trailing_space = c == ' ' && last_non_space.is_none_or(|ns| i > ns);
        let needs_escape = matches!(c, '*' | '?' | '[' | ']' | '\\')
            || (i == 0 && (c == '#' || c == '!'))
            || is_trailing_space;
        if needs_escape {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::repo::bootstrap_repo_at;
    use git2::Repository;
    use tempfile::TempDir;

    fn vault() -> (TempDir, Repository) {
        let td = TempDir::new().unwrap();
        bootstrap_repo_at(td.path()).unwrap();
        let repo = Repository::open(td.path()).unwrap();
        (td, repo)
    }

    #[test]
    fn append_writes_gitignore_and_registry() {
        let (_td, repo) = vault();
        assert!(append(&repo, Path::new("media/big.mov")).unwrap());
        assert!(!append(&repo, Path::new("media/big.mov")).unwrap());
        let gi = std::fs::read_to_string(repo.workdir().unwrap().join(".gitignore")).unwrap();
        assert!(gi.lines().any(|l| l == "/media/big.mov"));
        assert!(contains(&repo, "media/big.mov").unwrap());
    }

    #[test]
    fn shrink_drops_only_registry_lines() {
        let (_td, repo) = vault();
        let workdir = repo.workdir().unwrap();
        let mut gi = std::fs::read_to_string(workdir.join(".gitignore")).unwrap();
        gi.push_str("/keep.md\n");
        std::fs::write(workdir.join(".gitignore"), &gi).unwrap();
        append(&repo, Path::new("media/big.mov")).unwrap();
        assert!(shrink(&repo, "media/big.mov").unwrap());
        assert!(!contains(&repo, "media/big.mov").unwrap());
        let gi = std::fs::read_to_string(workdir.join(".gitignore")).unwrap();
        assert!(gi.lines().any(|l| l == "/keep.md"));
        assert!(!gi.lines().any(|l| l == "/media/big.mov"));
        assert!(!shrink(&repo, "keep.md").unwrap(), "user line stays");
        let gi = std::fs::read_to_string(workdir.join(".gitignore")).unwrap();
        assert!(gi.lines().any(|l| l == "/keep.md"));
    }

    #[test]
    fn move_rewrites_tree_prefix() {
        let (_td, repo) = vault();
        append(&repo, Path::new("a/big.mov")).unwrap();
        append(&repo, Path::new("a/nested/c.mov")).unwrap();
        assert!(rewrite_move(&repo, "a", "b", true).unwrap());
        assert!(contains(&repo, "b/big.mov").unwrap());
        assert!(contains(&repo, "b/nested/c.mov").unwrap());
        assert!(!contains(&repo, "a/big.mov").unwrap());
        let gi = std::fs::read_to_string(repo.workdir().unwrap().join(".gitignore")).unwrap();
        assert!(gi.lines().any(|l| l == "/b/big.mov"));
        assert!(gi.lines().any(|l| l == "/b/nested/c.mov"));
    }
}
