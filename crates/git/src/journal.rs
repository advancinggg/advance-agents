//! The user lane's crash journal (ADR 2026-10-15; MODULE-003 §1.4.1 item 2, §2.5; AC-27).
//!
//! A user-lane item writes the shared `.git/index` **before** it moves `main` (a legacy
//! agent commit is `index.write_tree()` over the whole index, so an index that lagged
//! behind HEAD would let the next agent commit revert the user's edit). A crash between
//! the index write and the ref move would leave the index ahead of HEAD, and the next
//! legacy commit would record the user's content under the agent's attribution.
//!
//! So right before the index write the item records
//! `.git/advance/user-lane.journal` = `{"parent": <sha|null>, "commit": <sha>,
//! "paths": [...], "prefixes": [...]}` atomically (temp file, fsync, rename), and deletes
//! it once the ref moved (or the index write failed). The entries are tree paths; a
//! vault-scope item journals the prefix `""` (the vault root), which covers the whole
//! index. Before **every** item, legacy items included, the worker runs [`heal`]:
//!
//! - no journal → nothing to do;
//! - `main` == the journal's commit → the item landed; the journal is deleted;
//! - otherwise the journal's paths and prefixes are reset in the index from the
//!   **current** HEAD tree ([`reset_from_tree`]), smudged (zero stat, so the next status
//!   re-hashes), the index is written and the journal deleted;
//! - anything else at the journal's path resets the whole index from HEAD and is removed:
//!   bytes that do not parse, an entry that is not a tree path, a symlink (never followed,
//!   at `.git/advance` either), a FIFO or socket (never opened for a blocking read), a
//!   directory. It cannot say which paths it covered, and refusing every later item would
//!   stop all commits.
//!
//! [`reset_from_tree`] removes every covered index entry before it adds any HEAD entry,
//! and under `core.ignorecase` it compares paths the way the index does (ASCII case
//! folded), so a crashed case-only rename heals in either journal order. The user lane's
//! `HeadMoved` and `Unchanged` index normalization goes through the same helper.
//!
//! Index writes go through [`update_index_with_retry`]: every attempt re-reads
//! `.git/index`, re-applies the item's operations and writes, and `GIT_ELOCKED` is retried
//! five times (20, 40, 80, 160 and 320 ms, ≤ 620 ms under coord) because IDEs and external
//! tools take `.git/index.lock` opportunistically. An attempt that starts after a lock
//! holder installed its index builds on it, so what that writer wrote survives. libgit2 takes
//! the lock only to write, though: a holder that finishes between an attempt's read and its
//! write is overwritten by that attempt (the window lasts as long as the attempt's
//! operations). A heal that still cannot write fails with `Libgit2 { code: "Locked" }` and
//! keeps the journal: no item runs on an unhealed index.
//!
//! The journal lives inside `.git`, so it is never tracked and never visible to clients.
//! It runs while the coord mutex is held, so it is panic-free: a panic there poisons coord
//! and stops every later commit.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use git2::{ErrorCode, Index, IndexEntry, IndexTime, ObjectType, Oid, Repository, Tree, TreeEntry};
use serde_json::{json, Map, Value};

use crate::commit_queue::reject_if_symlink;
use crate::error::GitError;
use crate::safe_fs::{open_entry, write_atomic, DiskEntry, SafeRoot};

/// The runtime-private directory inside `.git`.
pub(crate) const RUNTIME_DIR: &str = "advance";
/// The journal's file name inside [`RUNTIME_DIR`].
pub(crate) const JOURNAL_FILE: &str = "user-lane.journal";
/// The backoff before each retry of an index write that met `GIT_ELOCKED`.
pub(crate) const INDEX_LOCK_BACKOFF_MS: [u64; 5] = [20, 40, 80, 160, 320];

const MAIN_REF: &str = "refs/heads/main";

/// One in-flight user-lane item: what its index write touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Journal {
    /// The `main` tip the item built on (`None` = unborn).
    pub(crate) parent: Option<String>,
    /// The commit object the item created (not yet on `main` when the journal is written).
    pub(crate) commit: String,
    /// Tree paths whose index entries the item wrote or removed.
    pub(crate) paths: Vec<String>,
    /// Folders (no trailing `/`) whose entries the item removed or moved wholesale; `""` is
    /// the vault root (a vault-scope item), which covers the whole index.
    pub(crate) prefixes: Vec<String>,
}

fn is_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A tree path the index accepts: `/`-separated components, none empty, `.` or `..`, and
/// no NUL.
fn is_tree_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains('\0'))
}

fn string_list(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_string))
        .collect()
}

impl Journal {
    /// The journal's JSON bytes.
    pub(crate) fn to_json(&self) -> Vec<u8> {
        json!({
            "parent": self.parent,
            "commit": self.commit,
            "paths": self.paths,
            "prefixes": self.prefixes,
        })
        .to_string()
        .into_bytes()
    }

    /// Strict parse: an object with exactly `parent` (40 hex or null), `commit` (40 hex),
    /// `paths` (tree paths) and `prefixes` (tree paths or `""`). An entry the index cannot
    /// take (empty, absolute, `.`, `..`, NUL) is refused like bytes that do not parse:
    /// [`heal`] could never reset it, and every later item would wait on it.
    pub(crate) fn from_json(bytes: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let object: &Map<String, Value> = value.as_object()?;
        if object.len() != 4 {
            return None;
        }
        let parent = match object.get("parent")? {
            Value::Null => None,
            Value::String(sha) if is_sha(sha) => Some(sha.clone()),
            _ => return None,
        };
        let commit = object
            .get("commit")?
            .as_str()
            .filter(|sha| is_sha(sha))?
            .to_string();
        let paths = string_list(object.get("paths"))?;
        let prefixes = string_list(object.get("prefixes"))?;
        let resettable = paths.iter().all(|path| is_tree_path(path))
            && prefixes
                .iter()
                .all(|prefix| prefix.is_empty() || is_tree_path(prefix));
        resettable.then_some(Self {
            parent,
            commit,
            paths,
            prefixes,
        })
    }
}

/// What [`read_journal`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JournalState {
    Valid(Journal),
    /// Something at the journal's path that is not a journal heal can apply.
    Corrupt,
}

/// `<git_dir>/advance/user-lane.journal`.
pub(crate) fn journal_path(git_dir: &Path) -> PathBuf {
    git_dir.join(RUNTIME_DIR).join(JOURNAL_FILE)
}

/// Write the journal atomically and durably (temp file, fsync, rename).
pub(crate) fn write_journal(git_dir: &Path, journal: &Journal) -> Result<(), GitError> {
    let dir = git_dir.join(RUNTIME_DIR);
    reject_if_symlink(&dir)?;
    std::fs::create_dir_all(&dir)?;
    write_atomic(&journal_path(git_dir), &journal.to_json())?;
    Ok(())
}

/// The journal, if one is present. It is opened from the git directory with the
/// fd-relative walk of [`open_entry`]: no symlink is followed (`.git/advance` included)
/// and the open never blocks. Anything but a regular file there (a symlink, a FIFO, a
/// socket, a directory, or a `.git/advance` that is not a directory) reads as
/// [`JournalState::Corrupt`], as do bytes [`Journal::from_json`] refuses.
pub(crate) fn read_journal(git_dir: &Path) -> Result<Option<JournalState>, GitError> {
    let root = SafeRoot::open(git_dir)?;
    match open_entry(&root, &format!("{RUNTIME_DIR}/{JOURNAL_FILE}"))? {
        DiskEntry::Absent => Ok(None),
        DiskEntry::File(mut opened) => {
            let mut bytes = Vec::new();
            opened.file.read_to_end(&mut bytes)?;
            Ok(Some(
                Journal::from_json(&bytes).map_or(JournalState::Corrupt, JournalState::Valid),
            ))
        }
        DiskEntry::Symlink { .. }
        | DiskEntry::Dir
        | DiskEntry::Other
        | DiskEntry::SymlinkedParent => Ok(Some(JournalState::Corrupt)),
    }
}

/// Delete the journal; an absent journal is fine. Nothing is followed: whatever sits at
/// the journal's path goes (a directory with its contents, a symlink itself), and so does
/// a non-directory at `.git/advance`, so a [`JournalState::Corrupt`] state is cleared once.
pub(crate) fn delete_journal(git_dir: &Path) -> Result<(), GitError> {
    let dir = git_dir.join(RUNTIME_DIR);
    let removed = match std::fs::symlink_metadata(&dir) {
        Ok(meta) if !meta.is_dir() => std::fs::remove_file(&dir),
        Ok(_) => {
            let path = dir.join(JOURNAL_FILE);
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&path),
                Ok(_) => std::fs::remove_file(&path),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    };
    match removed {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Read `.git/index`, apply `apply` to it and write it back, retrying `GIT_ELOCKED` after
/// each [`INDEX_LOCK_BACKOFF_MS`] step. Every attempt starts from a fresh read of
/// `.git/index` and runs `apply` again (which re-reads whatever else it builds on, such as
/// the `main` tip), so an attempt that starts after a lock holder installed its index keeps
/// what that writer wrote; `apply` must be safe to repeat. libgit2 takes the lock only to
/// write, so the window between the read and the lock stays open while `apply` runs: a holder
/// that finishes inside it is overwritten by the attempt's write. On failure the in-memory
/// index is read again, so no half-applied state stays in the repository's shared index, and
/// the last error is returned (`Libgit2 { code: "Locked" }` when the lock stayed).
pub(crate) fn update_index_with_retry<T>(
    repo: &Repository,
    mut apply: impl FnMut(&mut Index) -> Result<T, GitError>,
) -> Result<T, GitError> {
    let mut index = repo.index()?;
    let mut backoff = INDEX_LOCK_BACKOFF_MS.iter();
    loop {
        index.read(true)?;
        let value = match apply(&mut index) {
            Ok(value) => value,
            Err(e) => return Err(discard(&mut index, e)),
        };
        match index.write() {
            Ok(()) => return Ok(value),
            Err(e) if e.code() == ErrorCode::Locked => match backoff.next() {
                Some(ms) => std::thread::sleep(Duration::from_millis(*ms)),
                None => return Err(discard(&mut index, e.into())),
            },
            Err(e) => return Err(discard(&mut index, e.into())),
        }
    }
}

/// Drop half-applied in-memory index changes (best effort) and hand back `error`.
fn discard(index: &mut Index, error: GitError) -> GitError {
    let _ = index.read(true);
    error
}

/// Whether `repo`'s index compares paths with ASCII case folded. libgit2 takes this from
/// `core.ignorecase` when it loads the index; an unset or unreadable value leaves it off.
pub(crate) fn index_folds_case(repo: &Repository) -> bool {
    repo.config()
        .and_then(|config| config.get_bool("core.ignorecase"))
        .unwrap_or(false)
}

/// The `main` tip; `None` while `main` is unborn. Any other failure to read the ref is an
/// error: reading it as unborn would reset entries to the empty tree.
pub(crate) fn main_tip(repo: &Repository) -> Result<Option<Oid>, GitError> {
    match repo.find_reference(MAIN_REF) {
        Ok(reference) => Ok(reference.resolve()?.target()),
        Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// What [`heal`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealOutcome {
    /// No journal.
    NoJournal,
    /// `main` is the journal's commit: the item landed; the journal was deleted.
    Landed,
    /// The journal's paths and prefixes were reset from HEAD.
    Reset { paths: usize, prefixes: usize },
    /// The journal could not be applied; the whole index was reset from HEAD.
    ResetAll,
}

fn smudged(path: Vec<u8>, id: Oid, mode: u32) -> IndexEntry {
    IndexEntry {
        ctime: IndexTime::new(0, 0),
        mtime: IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode,
        uid: 0,
        gid: 0,
        file_size: 0,
        id,
        flags: 0,
        flags_extended: 0,
        path,
    }
}

/// `dir/name`, or `name` at the root.
fn child_path(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = dir.to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// A path as the index compares it: ASCII case folded when the index folds case.
fn case_key(path: &[u8], fold: bool) -> Vec<u8> {
    if fold {
        path.to_ascii_lowercase()
    } else {
        path.to_vec()
    }
}

/// Whether the case key `key` is one of `keys` or lies under one of them.
fn is_covered(keys: &HashSet<Vec<u8>>, key: &[u8]) -> bool {
    keys.contains(key)
        || key
            .iter()
            .enumerate()
            .any(|(at, byte)| *byte == b'/' && key.get(..at).is_some_and(|dir| keys.contains(dir)))
}

/// The index mode of a tree entry (libgit2 normalizes it, so a legacy `100664` reads
/// `100644`).
fn entry_mode(entry: &TreeEntry<'_>) -> u32 {
    u32::try_from(entry.filemode()).unwrap_or(0o100_644)
}

/// The mode git writes for an index entry whose mode is `raw` (libgit2's tree-entry
/// normalization).
pub(crate) fn canonical_mode(raw: u32) -> u32 {
    match raw & 0o170_000 {
        0o040_000 | 0o120_000 | 0o160_000 => raw & 0o170_000,
        _ if raw & 0o111 != 0 => 0o100_755,
        _ => 0o100_644,
    }
}

/// Add `entry` of a tree, found at `path`: a blob, link or gitlink as one smudged entry, a
/// tree as every entry under it.
fn add_tree_entry(
    repo: &Repository,
    index: &mut Index,
    path: Vec<u8>,
    entry: &TreeEntry<'_>,
) -> Result<(), GitError> {
    if entry.kind() == Some(ObjectType::Tree) {
        return add_subtree(repo, index, path, entry.id());
    }
    index.add(&smudged(path, entry.id(), entry_mode(entry)))?;
    Ok(())
}

/// Put every non-tree entry of the tree `tree` under `prefix/` into the index, smudged.
fn add_subtree(
    repo: &Repository,
    index: &mut Index,
    prefix: Vec<u8>,
    tree: Oid,
) -> Result<(), GitError> {
    let mut pending: Vec<(Vec<u8>, Oid)> = vec![(prefix, tree)];
    while let Some((dir, oid)) = pending.pop() {
        let tree = repo.find_tree(oid)?;
        for entry in tree.iter() {
            let path = child_path(&dir, entry.name_bytes());
            if entry.kind() == Some(ObjectType::Tree) {
                pending.push((path, entry.id()));
            } else {
                index.add(&smudged(path, entry.id(), entry_mode(&entry)))?;
            }
        }
    }
    Ok(())
}

/// Add `tree`'s entries at every item of `missed` (items `tree` has no exact entry for),
/// matched the way a case-folding index compares paths and kept in the tree's own
/// spelling. Only the folders on the way to a missed item are listed.
fn add_folded_matches(
    repo: &Repository,
    index: &mut Index,
    tree: &Tree<'_>,
    missed: &[&str],
) -> Result<(), GitError> {
    let keys: HashSet<Vec<u8>> = missed
        .iter()
        .map(|item| item.as_bytes().to_ascii_lowercase())
        .collect();
    let on_the_way: HashSet<Vec<u8>> = keys
        .iter()
        .flat_map(|key| {
            key.iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'/')
                .filter_map(|(at, _)| key.get(..at).map(<[u8]>::to_vec))
        })
        .collect();
    let mut pending: Vec<(Vec<u8>, Oid)> = vec![(Vec::new(), tree.id())];
    while let Some((dir, oid)) = pending.pop() {
        let listing = repo.find_tree(oid)?;
        for entry in listing.iter() {
            let path = child_path(&dir, entry.name_bytes());
            let key = path.to_ascii_lowercase();
            if keys.contains(&key) {
                add_tree_entry(repo, index, path, &entry)?;
            } else if entry.kind() == Some(ObjectType::Tree) && on_the_way.contains(&key) {
                pending.push((path, entry.id()));
            }
        }
    }
    Ok(())
}

/// Reset the whole index to `tree` (`None` = the empty tree). `read_tree` keeps the stat of
/// an entry whose id and mode did not change, but copies modes verbatim, so an entry whose
/// mode git no longer writes (a legacy `100664`) is re-added with its canonical mode: the
/// next `write_tree` would refuse the raw one.
fn reset_all(index: &mut Index, tree: Option<&Tree<'_>>) -> Result<(), GitError> {
    match tree {
        Some(tree) => index.read_tree(tree)?,
        None => index.clear()?,
    }
    let legacy: Vec<IndexEntry> = index
        .iter()
        .filter(|entry| canonical_mode(entry.mode) != entry.mode)
        .collect();
    for mut entry in legacy {
        entry.mode = canonical_mode(entry.mode);
        index.add(&entry)?;
    }
    Ok(())
}

/// Make the index entries at `items` equal `tree`'s (`None` = the empty tree), smudged.
/// An item is a tree path, a file or a folder with everything under it, or `""`, the vault
/// root, which resets the whole index. [`heal`] passes the journal's entries; the user
/// lane's `HeadMoved` and `Unchanged` index normalization passes an item's touched paths
/// (MODULE-003 §1.4.1 item 2).
///
/// Every entry an item covers is removed before any of `tree`'s entries is added, so the
/// order of `items` never matters. With `fold` ([`index_folds_case`]) both steps compare
/// paths the way that index does, with ASCII case folded: the removal clears a slot
/// whatever its spelling, and an item `tree` has no exact entry for takes `tree`'s
/// entries in the tree's own spelling. A crashed case-only rename `notes.md` → `Notes.md`
/// thus heals to HEAD's `notes.md` in either journal order, and a touched path that a
/// foreign commit renamed by case follows the new tip.
pub(crate) fn reset_from_tree(
    repo: &Repository,
    index: &mut Index,
    tree: Option<&Tree<'_>>,
    items: &[&str],
    fold: bool,
) -> Result<(), GitError> {
    if items.iter().any(|item| item.is_empty()) {
        return reset_all(index, tree);
    }
    let keys: HashSet<Vec<u8>> = items
        .iter()
        .map(|item| case_key(item.as_bytes(), fold))
        .collect();
    let mut covered: Vec<Vec<u8>> = index
        .iter()
        .map(|entry| entry.path)
        .filter(|path| is_covered(&keys, &case_key(path, fold)))
        .collect();
    covered.dedup();
    for path in &covered {
        index.remove_path(Path::new(OsStr::from_bytes(path)))?;
    }
    let Some(tree) = tree else {
        return Ok(());
    };
    let mut missed: Vec<&str> = Vec::new();
    for item in items {
        match tree.get_path(Path::new(item)) {
            Ok(entry) => add_tree_entry(repo, index, item.as_bytes().to_vec(), &entry)?,
            Err(e) if e.code() == ErrorCode::NotFound => missed.push(item),
            Err(e) => return Err(e.into()),
        }
    }
    if fold && !missed.is_empty() {
        add_folded_matches(repo, index, tree, &missed)?;
    }
    Ok(())
}

/// Heal the index from a journal left by a crashed user-lane item (see the module docs).
/// Runs under coord before every item; on `Err` the journal is kept and the item must not
/// run.
pub(crate) fn heal(repo: &Repository) -> Result<HealOutcome, GitError> {
    let git_dir = repo.path();
    let Some(state) = read_journal(git_dir)? else {
        return Ok(HealOutcome::NoJournal);
    };
    if let JournalState::Valid(journal) = &state {
        let tip = main_tip(repo)?.map(|oid| oid.to_string());
        if tip.as_deref() == Some(journal.commit.as_str()) {
            delete_journal(git_dir)?;
            return Ok(HealOutcome::Landed);
        }
    }
    let fold = index_folds_case(repo);
    let outcome = update_index_with_retry(repo, |index| {
        // Read on every attempt: whoever held the index lock may have moved `main` too.
        let head = match main_tip(repo)? {
            Some(oid) => Some(repo.find_commit(oid)?.tree()?),
            None => None,
        };
        match &state {
            JournalState::Valid(journal) => {
                let items: Vec<&str> = journal
                    .prefixes
                    .iter()
                    .chain(&journal.paths)
                    .map(String::as_str)
                    .collect();
                reset_from_tree(repo, index, head.as_ref(), &items, fold)?;
                Ok(HealOutcome::Reset {
                    paths: journal.paths.len(),
                    prefixes: journal.prefixes.len(),
                })
            }
            JournalState::Corrupt => {
                reset_all(index, head.as_ref())?;
                Ok(HealOutcome::ResetAll)
            }
        }
    })?;
    delete_journal(git_dir)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;
    use tempfile::TempDir;

    struct Fixture {
        _td: TempDir,
        repo: Repository,
    }

    fn sig() -> git2::Signature<'static> {
        git2::Signature::new("runtime", "runtime@advance-agents", &git2::Time::new(1, 0)).unwrap()
    }

    /// A repository whose `main` holds `a.md`, `b.md` and `dir/{x,y}.md`, with the index
    /// equal to HEAD.
    fn fixture() -> Fixture {
        let td = TempDir::new().unwrap();
        let root = std::fs::canonicalize(td.path()).unwrap();
        let mut opts = git2::RepositoryInitOptions::new();
        opts.initial_head("main");
        let repo = Repository::init_opts(&root, &opts).unwrap();
        for (path, content) in [
            ("a.md", "a1"),
            ("b.md", "b1"),
            ("dir/x.md", "x1"),
            ("dir/y.md", "y1"),
        ] {
            let full = root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        {
            let mut index = repo.index().unwrap();
            for path in ["a.md", "b.md", "dir/x.md", "dir/y.md"] {
                index.add_path(Path::new(path)).unwrap();
            }
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            repo.commit(Some("HEAD"), &sig(), &sig(), "base", &tree, &[])
                .unwrap();
        }
        Fixture { _td: td, repo }
    }

    /// A repository whose `main` holds `files` (objects only, nothing on disk) with the
    /// index equal to HEAD and `core.ignorecase` set as asked. The handle is opened after
    /// the config write, because the index takes its case rule from it when it loads.
    fn repo_with(files: &[(&str, &str)], ignorecase: bool) -> Fixture {
        let td = TempDir::new().unwrap();
        let root = std::fs::canonicalize(td.path()).unwrap();
        let mut opts = git2::RepositoryInitOptions::new();
        opts.initial_head("main");
        Repository::init_opts(&root, &opts)
            .unwrap()
            .config()
            .unwrap()
            .open_level(git2::ConfigLevel::Local)
            .unwrap()
            .set_bool("core.ignorecase", ignorecase)
            .unwrap();
        let repo = Repository::open(&root).unwrap();
        assert_eq!(index_folds_case(&repo), ignorecase);
        {
            let mut index = repo.index().unwrap();
            for (path, content) in files {
                let blob = repo.blob(content.as_bytes()).unwrap();
                index
                    .add(&smudged(path.as_bytes().to_vec(), blob, 0o100_644))
                    .unwrap();
            }
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            repo.commit(Some("HEAD"), &sig(), &sig(), "base", &tree, &[])
                .unwrap();
        }
        Fixture { _td: td, repo }
    }

    fn journal_for(repo: &Repository, paths: &[&str], prefixes: &[&str]) -> Journal {
        Journal {
            parent: Some(repo.head().unwrap().target().unwrap().to_string()),
            commit: "c".repeat(40),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
        }
    }

    fn index_oid(repo: &Repository, path: &str) -> Option<Oid> {
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        index.get_path(Path::new(path), 0).map(|e| e.id)
    }

    fn head_oid(repo: &Repository, path: &str) -> Option<Oid> {
        let tree = repo.head().unwrap().peel_to_tree().unwrap();
        tree.get_path(Path::new(path)).ok().map(|e| e.id())
    }

    /// Every `.git/index` entry as (path, id, mode), sorted by path bytes.
    fn index_entries(repo: &Repository) -> Vec<(Vec<u8>, Oid, u32)> {
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        let mut entries: Vec<_> = index.iter().map(|e| (e.path, e.id, e.mode)).collect();
        entries.sort();
        entries
    }

    /// Every non-tree entry of HEAD as (path, id, mode), sorted by path bytes.
    fn head_entries(repo: &Repository) -> Vec<(Vec<u8>, Oid, u32)> {
        let mut index = Index::new().unwrap();
        let tree = repo.head().unwrap().peel_to_tree().unwrap();
        add_subtree(repo, &mut index, Vec::new(), tree.id()).unwrap();
        let mut entries: Vec<_> = index.iter().map(|e| (e.path, e.id, e.mode)).collect();
        entries.sort();
        entries
    }

    /// Simulate a crashed user item: the index got its entries, `main` did not move.
    fn crash_mid_item(f: &Fixture) -> Journal {
        let repo = &f.repo;
        let parent = repo.head().unwrap().target().unwrap();
        let new_a = repo.blob(b"user bytes").unwrap();
        let new_dir_file = repo.blob(b"moved").unwrap();
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        index
            .add(&smudged(b"a.md".to_vec(), new_a, 0o100_644))
            .unwrap();
        index.remove_dir(Path::new("dir"), 0).unwrap();
        index
            .add(&smudged(b"moved/x.md".to_vec(), new_dir_file, 0o100_644))
            .unwrap();
        index.write().unwrap();
        Journal {
            parent: Some(parent.to_string()),
            commit: "c".repeat(40),
            paths: vec!["a.md".into(), "moved/x.md".into()],
            prefixes: vec!["dir".into()],
        }
    }

    /// Another git writer in flight: it holds `index.lock`; after `delay` it moves `main` to
    /// a commit adding `rows/x.json` and installs its new index (the current one plus
    /// `rows/x.json`), and 150 ms later it drops the lock. git renames the lock over the index
    /// in one step; splitting the two keeps any attempt from reading before the install and
    /// writing after the release (the read-to-lock window `update_index_with_retry`
    /// documents), so the outcome does not depend on scheduling.
    fn foreign_writer(repo: &Repository, delay: Duration) -> std::thread::JoinHandle<()> {
        let git_dir = repo.path().to_path_buf();
        let row = repo.blob(b"{\"row\":1}\n").unwrap();
        let theirs = git_dir.join("theirs.index");
        std::fs::copy(git_dir.join("index"), &theirs).unwrap();
        {
            let mut index = Index::open(&theirs).unwrap();
            index
                .add(&smudged(b"rows/x.json".to_vec(), row, 0o100_644))
                .unwrap();
            index.write().unwrap();
        }
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        let mut builder = git2::build::TreeUpdateBuilder::new();
        builder.upsert("rows/x.json", row, git2::FileMode::Blob);
        let tree = builder.create_updated(repo, &head.tree().unwrap()).unwrap();
        let tree = repo.find_tree(tree).unwrap();
        let commit = repo
            .commit(None, &sig(), &sig(), "row io", &tree, &[&head])
            .unwrap();
        std::fs::write(git_dir.join("index.lock"), b"held").unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            let repo = Repository::open(&git_dir).unwrap();
            repo.reference(MAIN_REF, commit, true, "row io").unwrap();
            std::fs::rename(&theirs, git_dir.join("index")).unwrap();
            std::thread::sleep(Duration::from_millis(150));
            std::fs::remove_file(git_dir.join("index.lock")).unwrap();
        })
    }

    fn mkfifo(path: &Path) {
        // Test-only: neither std nor the pinned rustix creates a FIFO on every Unix.
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo {}", path.display());
    }

    /// `heal` on its own handle, failing the test (not hanging it) after 5 s.
    fn heal_within_5s(f: &Fixture) -> HealOutcome {
        let git_dir = f.repo.path().to_path_buf();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let repo = Repository::open(&git_dir).unwrap();
            let _ = tx.send(heal(&repo).map_err(|e| e.to_string()));
        });
        rx.recv_timeout(Duration::from_secs(5))
            .expect("heal returned within 5 s")
            .unwrap()
    }

    #[test]
    fn journal_round_trips_and_parses_strictly() {
        let journal = Journal {
            parent: None,
            commit: "a".repeat(40),
            paths: vec!["notes/周报.md".into(), "x \"q\".md".into()],
            prefixes: vec!["drafts".into()],
        };
        assert_eq!(
            Journal::from_json(&journal.to_json()),
            Some(journal.clone())
        );
        let with_parent = Journal {
            parent: Some("b".repeat(40)),
            ..journal
        };
        assert_eq!(
            Journal::from_json(&with_parent.to_json()),
            Some(with_parent)
        );
        let sha = "a".repeat(40);
        for bad in [
            "".to_string(),
            "[]".to_string(),
            "{}".to_string(),
            format!(r#"{{"parent":null,"commit":"{sha}","paths":[]}}"#),
            format!(r#"{{"parent":null,"commit":"{sha}","paths":[],"prefixes":[],"x":1}}"#),
            format!(r#"{{"parent":null,"commit":"short","paths":[],"prefixes":[]}}"#),
            format!(r#"{{"parent":1,"commit":"{sha}","paths":[],"prefixes":[]}}"#),
            format!(r#"{{"parent":null,"commit":"{sha}","paths":[1],"prefixes":[]}}"#),
            format!(r#"{{"parent":null,"commit":"{sha}","paths":"a","prefixes":[]}}"#),
        ] {
            assert_eq!(Journal::from_json(bad.as_bytes()), None, "{bad}");
        }
    }

    // Entries heal could not reset would keep every later item waiting: they parse as
    // corrupt. The vault root is a prefix only.
    #[test]
    fn journal_entries_must_be_tree_paths() {
        let journal = |paths: &[&str], prefixes: &[&str]| Journal {
            parent: None,
            commit: "a".repeat(40),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
        };
        let root = journal(&["a.md"], &[""]);
        assert_eq!(Journal::from_json(&root.to_json()), Some(root));
        for bad in [
            "", "/etc/x", "../x", "a/../b", "./a", "a/./b", "a//b", "a/", "a\0b",
        ] {
            let as_path = journal(&[bad], &[]);
            assert_eq!(Journal::from_json(&as_path.to_json()), None, "path {bad:?}");
            if !bad.is_empty() {
                let as_prefix = journal(&[], &[bad]);
                assert_eq!(
                    Journal::from_json(&as_prefix.to_json()),
                    None,
                    "prefix {bad:?}"
                );
            }
        }
    }

    #[test]
    fn journal_write_is_atomic_and_delete_is_idempotent() {
        let f = fixture();
        let git_dir = f.repo.path().to_path_buf();
        assert_eq!(read_journal(&git_dir).unwrap(), None);
        let journal = Journal {
            parent: None,
            commit: "a".repeat(40),
            paths: vec!["a.md".into()],
            prefixes: vec![],
        };
        write_journal(&git_dir, &journal).unwrap();
        assert_eq!(
            read_journal(&git_dir).unwrap(),
            Some(JournalState::Valid(journal))
        );
        let leftovers: Vec<_> = std::fs::read_dir(git_dir.join(RUNTIME_DIR))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from(JOURNAL_FILE)]);
        delete_journal(&git_dir).unwrap();
        delete_journal(&git_dir).unwrap();
        assert_eq!(read_journal(&git_dir).unwrap(), None);
        std::fs::write(journal_path(&git_dir), b"{not json").unwrap();
        assert_eq!(read_journal(&git_dir).unwrap(), Some(JournalState::Corrupt));
    }

    #[test]
    fn heal_without_journal_is_a_no_op() {
        let f = fixture();
        assert_eq!(heal(&f.repo).unwrap(), HealOutcome::NoJournal);
    }

    #[test]
    fn heal_deletes_a_landed_journal() {
        let f = fixture();
        let head = f.repo.head().unwrap().target().unwrap();
        // A staged leftover of someone else stays staged: a landed item needs no reset.
        let leftover = f.repo.blob(b"staged elsewhere").unwrap();
        let mut index = f.repo.index().unwrap();
        index
            .add(&smudged(b"b.md".to_vec(), leftover, 0o100_644))
            .unwrap();
        index.write().unwrap();
        let journal = Journal {
            parent: None,
            commit: head.to_string(),
            paths: vec!["b.md".into()],
            prefixes: vec![],
        };
        write_journal(f.repo.path(), &journal).unwrap();
        assert_eq!(heal(&f.repo).unwrap(), HealOutcome::Landed);
        assert_eq!(read_journal(f.repo.path()).unwrap(), None);
        assert_eq!(index_oid(&f.repo, "b.md"), Some(leftover));
    }

    #[test]
    fn heal_resets_paths_and_prefixes_from_head() {
        let f = fixture();
        let journal = crash_mid_item(&f);
        // An unrelated staged leftover is not the journal's business.
        let leftover = f.repo.blob(b"leftover").unwrap();
        let mut index = f.repo.index().unwrap();
        index.read(true).unwrap();
        index
            .add(&smudged(b"b.md".to_vec(), leftover, 0o100_644))
            .unwrap();
        index.write().unwrap();
        write_journal(f.repo.path(), &journal).unwrap();

        assert_eq!(
            heal(&f.repo).unwrap(),
            HealOutcome::Reset {
                paths: 2,
                prefixes: 1
            }
        );
        assert_eq!(read_journal(f.repo.path()).unwrap(), None);
        assert_eq!(index_oid(&f.repo, "a.md"), head_oid(&f.repo, "a.md"));
        assert_eq!(
            index_oid(&f.repo, "dir/x.md"),
            head_oid(&f.repo, "dir/x.md")
        );
        assert_eq!(
            index_oid(&f.repo, "dir/y.md"),
            head_oid(&f.repo, "dir/y.md")
        );
        assert_eq!(index_oid(&f.repo, "moved/x.md"), None);
        assert_eq!(index_oid(&f.repo, "b.md"), Some(leftover));
        // The reset entries are smudged, so a status re-hashes them and finds them clean.
        let mut index = f.repo.index().unwrap();
        index.read(true).unwrap();
        let a = index.get_path(Path::new("a.md"), 0).unwrap();
        assert_eq!((a.mtime.seconds(), a.file_size), (0, 0));
        let statuses = f.repo.statuses(None).unwrap();
        let a_status = statuses
            .iter()
            .find(|s| s.path() == Some("a.md"))
            .map(|s| s.status());
        assert!(
            a_status.is_none(),
            "a.md is clean after the heal: {a_status:?}"
        );
    }

    // A crash mid case-only rename leaves the new spelling in the index and both spellings
    // in the journal. Under `core.ignorecase` (the macOS default) the index matches either
    // spelling, so a reset that interleaved removes and adds dropped HEAD's entry in one of
    // the two orders; with every removal first, both orders end with index == HEAD.
    #[test]
    fn heal_case_only_renames_in_either_order() {
        for ignorecase in [true, false] {
            for order in [["notes.md", "Notes.md"], ["Notes.md", "notes.md"]] {
                let f = repo_with(&[("notes.md", "n1"), ("other.md", "o1")], ignorecase);
                let head = head_entries(&f.repo);
                let notes = head_oid(&f.repo, "notes.md").unwrap();
                let mut index = f.repo.index().unwrap();
                index.read(true).unwrap();
                index.remove_path(Path::new("notes.md")).unwrap();
                index
                    .add(&smudged(b"Notes.md".to_vec(), notes, 0o100_644))
                    .unwrap();
                index.write().unwrap();
                write_journal(f.repo.path(), &journal_for(&f.repo, &order, &[])).unwrap();
                assert_eq!(
                    heal(&f.repo).unwrap(),
                    HealOutcome::Reset {
                        paths: 2,
                        prefixes: 0
                    }
                );
                assert_eq!(
                    index_entries(&f.repo),
                    head,
                    "ignorecase={ignorecase} order={order:?}"
                );
            }
            for order in [["Dir", "dir"], ["dir", "Dir"]] {
                let f = repo_with(
                    &[("Dir/a.md", "a1"), ("Dir/b.md", "b1"), ("other.md", "o1")],
                    ignorecase,
                );
                let head = head_entries(&f.repo);
                let a = head_oid(&f.repo, "Dir/a.md").unwrap();
                let b = head_oid(&f.repo, "Dir/b.md").unwrap();
                let mut index = f.repo.index().unwrap();
                index.read(true).unwrap();
                index.remove_dir(Path::new("Dir"), 0).unwrap();
                for (path, id) in [(&b"dir/a.md"[..], a), (&b"dir/b.md"[..], b)] {
                    index.add(&smudged(path.to_vec(), id, 0o100_644)).unwrap();
                }
                index.write().unwrap();
                write_journal(f.repo.path(), &journal_for(&f.repo, &[], &order)).unwrap();
                assert!(matches!(heal(&f.repo).unwrap(), HealOutcome::Reset { .. }));
                assert_eq!(
                    index_entries(&f.repo),
                    head,
                    "ignorecase={ignorecase} folder order={order:?}"
                );
            }
        }
    }

    // Under `core.ignorecase` a journal entry addresses an index slot whatever its case: a
    // slot whose HEAD spelling the journal does not name (a foreign commit renamed it by
    // case, or an ancestor folder differs in case) still ends equal to HEAD.
    #[test]
    fn heal_takes_heads_spelling_of_a_folded_slot() {
        let f = repo_with(&[("dir/notes.md", "n1"), ("other.md", "o1")], true);
        let head = head_entries(&f.repo);
        let stale = f.repo.blob(b"user bytes").unwrap();
        let mut index = f.repo.index().unwrap();
        index.read(true).unwrap();
        index.remove_path(Path::new("dir/notes.md")).unwrap();
        index
            .add(&smudged(b"DIR/NOTES.md".to_vec(), stale, 0o100_644))
            .unwrap();
        index.write().unwrap();
        write_journal(f.repo.path(), &journal_for(&f.repo, &["DIR/NOTES.md"], &[])).unwrap();
        assert_eq!(
            heal(&f.repo).unwrap(),
            HealOutcome::Reset {
                paths: 1,
                prefixes: 0
            }
        );
        assert_eq!(index_entries(&f.repo), head);
    }

    // `""` journals a vault-scope item: the whole index is reset, leftovers included.
    #[test]
    fn heal_resets_the_whole_index_for_the_root_prefix() {
        let f = fixture();
        crash_mid_item(&f);
        let leftover = f.repo.blob(b"leftover").unwrap();
        let mut index = f.repo.index().unwrap();
        index.read(true).unwrap();
        index
            .add(&smudged(b"b.md".to_vec(), leftover, 0o100_644))
            .unwrap();
        index.write().unwrap();
        write_journal(f.repo.path(), &journal_for(&f.repo, &[], &[""])).unwrap();
        assert_eq!(
            heal(&f.repo).unwrap(),
            HealOutcome::Reset {
                paths: 0,
                prefixes: 1
            }
        );
        assert_eq!(index_entries(&f.repo), head_entries(&f.repo));
        assert_eq!(read_journal(f.repo.path()).unwrap(), None);
    }

    #[test]
    fn heal_with_corrupt_journal_resets_the_whole_index() {
        let f = fixture();
        crash_mid_item(&f);
        let leftover = f.repo.blob(b"leftover").unwrap();
        let mut index = f.repo.index().unwrap();
        index.read(true).unwrap();
        index
            .add(&smudged(b"b.md".to_vec(), leftover, 0o100_644))
            .unwrap();
        index.write().unwrap();
        let dir = f.repo.path().join(RUNTIME_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(journal_path(f.repo.path()), b"\x00garbage").unwrap();

        assert_eq!(heal(&f.repo).unwrap(), HealOutcome::ResetAll);
        assert_eq!(read_journal(f.repo.path()).unwrap(), None);
        for path in ["a.md", "b.md", "dir/x.md", "dir/y.md"] {
            assert_eq!(index_oid(&f.repo, path), head_oid(&f.repo, path), "{path}");
        }
        assert_eq!(index_oid(&f.repo, "moved/x.md"), None);

        // A symlink planted at the journal's path is never followed: it heals like a
        // corrupt journal and only the link is removed.
        crash_mid_item(&f);
        let outside = TempDir::new().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, journal_path(f.repo.path())).unwrap();
        assert_eq!(heal(&f.repo).unwrap(), HealOutcome::ResetAll);
        assert!(std::fs::symlink_metadata(journal_path(f.repo.path())).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(index_oid(&f.repo, "a.md"), head_oid(&f.repo, "a.md"));
    }

    // Nothing at the journal's path can stall or block the worker: a FIFO is never opened
    // for a blocking read, a directory and a symlinked `.git/advance` read as corrupt. Each
    // heals once (whole index from HEAD), is removed without being followed, and the lane
    // can write its journal again.
    #[test]
    fn heal_clears_a_fifo_directory_or_symlinked_runtime_dir() {
        let f = fixture();
        let git_dir = f.repo.path().to_path_buf();
        std::fs::create_dir_all(git_dir.join(RUNTIME_DIR)).unwrap();

        crash_mid_item(&f);
        mkfifo(&journal_path(&git_dir));
        let started = Instant::now();
        assert_eq!(heal_within_5s(&f), HealOutcome::ResetAll);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(std::fs::symlink_metadata(journal_path(&git_dir)).is_err());
        assert_eq!(index_entries(&f.repo), head_entries(&f.repo));

        crash_mid_item(&f);
        std::fs::create_dir_all(journal_path(&git_dir).join("nested")).unwrap();
        std::fs::write(journal_path(&git_dir).join("nested/x"), b"x").unwrap();
        assert_eq!(heal_within_5s(&f), HealOutcome::ResetAll);
        assert!(std::fs::symlink_metadata(journal_path(&git_dir)).is_err());
        assert_eq!(index_entries(&f.repo), head_entries(&f.repo));
        assert_eq!(heal(&f.repo).unwrap(), HealOutcome::NoJournal);

        // `.git/advance` replaced by a symlink to a folder holding a well-formed journal:
        // the journal behind it is never read, and only the link is removed.
        let crashed = crash_mid_item(&f);
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join(JOURNAL_FILE), crashed.to_json()).unwrap();
        std::fs::remove_dir_all(git_dir.join(RUNTIME_DIR)).unwrap();
        std::os::unix::fs::symlink(outside.path(), git_dir.join(RUNTIME_DIR)).unwrap();
        assert_eq!(read_journal(&git_dir).unwrap(), Some(JournalState::Corrupt));
        assert_eq!(heal_within_5s(&f), HealOutcome::ResetAll);
        assert!(std::fs::symlink_metadata(git_dir.join(RUNTIME_DIR)).is_err());
        assert_eq!(
            std::fs::read(outside.path().join(JOURNAL_FILE)).unwrap(),
            crashed.to_json()
        );
        assert_eq!(index_entries(&f.repo), head_entries(&f.repo));
        write_journal(&git_dir, &crashed).unwrap();
        assert_eq!(
            read_journal(&git_dir).unwrap(),
            Some(JournalState::Valid(crashed))
        );
    }

    // `read_tree` copies tree modes verbatim; the whole-index reset re-adds a legacy
    // `100664` entry as `100644`, so the next legacy `write_tree` still succeeds.
    #[test]
    fn heal_reset_all_writes_canonical_modes() {
        let f = fixture();
        let repo = &f.repo;
        let blob = repo.blob(b"legacy\n").unwrap();
        let mut raw = Vec::new();
        raw.extend_from_slice(b"100664 legacy.md\0");
        raw.extend_from_slice(blob.as_bytes());
        let tree = repo.odb().unwrap().write(ObjectType::Tree, &raw).unwrap();
        let tree = repo.find_tree(tree).unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        repo.commit(
            Some("HEAD"),
            &sig(),
            &sig(),
            "legacy mode",
            &tree,
            &[&parent],
        )
        .unwrap();
        std::fs::create_dir_all(repo.path().join(RUNTIME_DIR)).unwrap();
        std::fs::write(journal_path(repo.path()), b"garbage").unwrap();

        assert_eq!(heal(repo).unwrap(), HealOutcome::ResetAll);
        let entries = index_entries(repo);
        assert_eq!(entries, vec![(b"legacy.md".to_vec(), blob, 0o100_644)]);
        // The next legacy commit adds a file beside it, so the root tree is rebuilt.
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        index
            .add(&smudged(b"agent.md".to_vec(), blob, 0o100_644))
            .unwrap();
        let written = index.write_tree().unwrap();
        assert_eq!(
            repo.find_tree(written)
                .unwrap()
                .get_path(Path::new("legacy.md"))
                .unwrap()
                .filemode(),
            0o100_644
        );
    }

    // A `main` that cannot be read is an error, never "unborn": an unborn reading would
    // reset the index to the empty tree.
    #[test]
    fn heal_keeps_the_journal_when_main_cannot_be_read() {
        let f = fixture();
        let before = index_entries(&f.repo);
        std::fs::create_dir_all(f.repo.path().join(RUNTIME_DIR)).unwrap();
        std::fs::write(journal_path(f.repo.path()), b"garbage").unwrap();
        std::fs::write(f.repo.path().join(MAIN_REF), b"not a sha\n").unwrap();
        assert!(heal(&f.repo).is_err());
        assert_eq!(
            read_journal(f.repo.path()).unwrap(),
            Some(JournalState::Corrupt)
        );
        assert_eq!(index_entries(&f.repo), before);
    }

    #[test]
    fn heal_fails_closed_while_index_lock_is_held() {
        let f = fixture();
        let journal = crash_mid_item(&f);
        write_journal(f.repo.path(), &journal).unwrap();
        let lock = f.repo.path().join("index.lock");
        std::fs::write(&lock, b"held").unwrap();
        let started = Instant::now();
        match heal(&f.repo) {
            Err(GitError::Libgit2 { code, .. }) => assert_eq!(code, "Locked"),
            other => panic!("expected Locked, got {other:?}"),
        }
        assert!(started.elapsed() >= Duration::from_millis(600));
        assert_eq!(
            read_journal(f.repo.path()).unwrap(),
            Some(JournalState::Valid(journal)),
            "the journal is kept until the heal succeeds"
        );
        std::fs::remove_file(&lock).unwrap();
        assert!(matches!(heal(&f.repo).unwrap(), HealOutcome::Reset { .. }));
        assert_eq!(index_oid(&f.repo, "a.md"), head_oid(&f.repo, "a.md"));
    }

    #[test]
    fn index_write_retries_a_briefly_held_lock() {
        let f = fixture();
        let lock = f.repo.path().join("index.lock");
        std::fs::write(&lock, b"held").unwrap();
        let releaser = {
            let lock = lock.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(60));
                std::fs::remove_file(lock).unwrap();
            })
        };
        let blob = f.repo.blob(b"after the lock").unwrap();
        update_index_with_retry(&f.repo, |index| {
            index.add(&smudged(b"a.md".to_vec(), blob, 0o100_644))?;
            Ok(())
        })
        .unwrap();
        releaser.join().unwrap();
        assert_eq!(index_oid(&f.repo, "a.md"), Some(blob));
    }

    // A retry after `GIT_ELOCKED` starts from the index the lock holder installed: its
    // entries survive, ours are applied on top, and heal resets from the `main` it moved.
    #[test]
    fn index_retry_keeps_what_the_lock_holder_wrote() {
        let f = fixture();
        let row = f.repo.blob(b"{\"row\":1}\n").unwrap();
        let ours = f.repo.blob(b"user bytes\n").unwrap();
        let writer = foreign_writer(&f.repo, Duration::from_millis(50));
        update_index_with_retry(&f.repo, |index| {
            index.add(&smudged(b"b.md".to_vec(), ours, 0o100_644))?;
            Ok(())
        })
        .unwrap();
        writer.join().unwrap();
        assert_eq!(index_oid(&f.repo, "rows/x.json"), Some(row));
        assert_eq!(index_oid(&f.repo, "b.md"), Some(ours));

        let f = fixture();
        let journal = crash_mid_item(&f);
        write_journal(f.repo.path(), &journal).unwrap();
        let writer = foreign_writer(&f.repo, Duration::from_millis(50));
        assert!(matches!(heal(&f.repo).unwrap(), HealOutcome::Reset { .. }));
        writer.join().unwrap();
        assert_eq!(head_oid(&f.repo, "rows/x.json"), Some(row));
        assert_eq!(index_oid(&f.repo, "rows/x.json"), Some(row));
        assert_eq!(index_entries(&f.repo), head_entries(&f.repo));
        assert_eq!(read_journal(f.repo.path()).unwrap(), None);
    }
}
