//! Exact-content trees for the user commit lane (ADR 2026-10-15, MODULE-003 §1.4.1 item 1,
//! MODULE-003-AC-27).
//!
//! A user commit's tree is the parent tree plus exactly the request's resolved edits; it
//! is never `index.write_tree()` over the shared index, so staged leftovers (an agent's
//! non-committing rollback, an external `git add`) cannot enter it.
//!
//! [`build_tree`] validates the plan first, then picks a builder:
//!
//! - **`git_tree_create_updated`** ([`build_with_updater`], O(changes × depth)) for every
//!   plan without a type change. libgit2 refuses to upsert over an entry of another object
//!   type, to change a file into a folder against the baseline, to remove an absent path,
//!   and duplicate paths.
//! - **An in-memory index** ([`build_with_index`]) for an explicit type change: a folder
//!   replaced by a file (`Remove{d}` + `Upsert{d, blob}`) or a file replaced by a folder
//!   (`Remove{p}` + `Upsert{p/x}`). It loads the parent tree, applies the removes first,
//!   expands tree upserts into their blob entries (an index rejects tree modes) and
//!   writes the tree. It never touches `.git/index`.
//!
//! The plan rules mirror the lane's request grammar, so a resolution bug cannot produce an
//! unexpected tree: duplicate paths ([`UserOpRefusal::DuplicatePath`]), an edit below an
//! upserted path or a remove below a removed one, or an upsert below a removed **folder**
//! ([`UserOpRefusal::NestedChange`]), a remove of an absent path
//! ([`UserOpRefusal::SourceMissing`]), an implicit type change
//! ([`UserOpRefusal::TypeConflict`]) and malformed paths ([`UserOpRefusal::InvalidPath`])
//! are refused before anything is written.
//!
//! Panic-free (it runs while the coord mutex is held): paths are validated before they
//! reach git2's builders, which `unwrap` a NUL-containing path.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use git2::{FileMode, Index, IndexEntry, IndexTime, ObjectType, Oid, Repository, Tree};

use crate::error::{GitError, UserOpRefusal};
use crate::journal::canonical_mode;
use crate::user_lane::MAX_RESTORE_PATHS;

/// The mode of an upserted entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EntryMode {
    /// `100644`.
    File,
    /// `100755`.
    Executable,
    /// `120000`: a symlink blob (only the adopt and restore paths record one).
    Link,
    /// `040000`: a whole subtree (`MoveTree` / `CopyTree` reuse the subtree oid).
    Tree,
}

impl EntryMode {
    fn file_mode(self) -> FileMode {
        match self {
            EntryMode::File => FileMode::Blob,
            EntryMode::Executable => FileMode::BlobExecutable,
            EntryMode::Link => FileMode::Link,
            EntryMode::Tree => FileMode::Tree,
        }
    }

    fn raw(self) -> u32 {
        match self {
            EntryMode::File => 0o100_644,
            EntryMode::Executable => 0o100_755,
            EntryMode::Link => 0o120_000,
            EntryMode::Tree => 0o040_000,
        }
    }

    fn object_type(self) -> ObjectType {
        match self {
            EntryMode::Tree => ObjectType::Tree,
            EntryMode::File | EntryMode::Executable | EntryMode::Link => ObjectType::Blob,
        }
    }

    /// The mode of a tree entry's raw filemode; `None` for a gitlink or anything else.
    pub(crate) fn from_raw(mode: i32) -> Option<Self> {
        match mode {
            0o100_644 => Some(EntryMode::File),
            0o100_755 => Some(EntryMode::Executable),
            0o120_000 => Some(EntryMode::Link),
            0o040_000 => Some(EntryMode::Tree),
            _ => None,
        }
    }
}

/// One resolved edit against the parent tree. Paths are tree spellings without a
/// trailing `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TreeEdit {
    /// Put `oid` at `path` with `mode` (a blob, a symlink, or a whole subtree).
    Upsert {
        path: String,
        oid: Oid,
        mode: EntryMode,
    },
    /// Remove the entry at `path` (a blob, a symlink or a subtree). It must exist in the
    /// parent tree.
    Remove { path: String },
}

impl TreeEdit {
    pub(crate) fn path(&self) -> &str {
        match self {
            TreeEdit::Upsert { path, .. } | TreeEdit::Remove { path } => path,
        }
    }
}

fn refuse(reason: UserOpRefusal, path: &str) -> GitError {
    GitError::InvalidUserOp {
        reason,
        path: Some(PathBuf::from(path)),
    }
}

/// A tree path: non-empty, no leading or trailing `/`, no empty, `.` or `..` component,
/// no NUL.
fn validate_tree_path(path: &str) -> Result<(), GitError> {
    let valid = !path.is_empty()
        && !path.contains('\0')
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..");
    if valid {
        Ok(())
    } else {
        Err(refuse(UserOpRefusal::InvalidPath, path))
    }
}

/// The proper ancestors of a tree path, shortest first (`a`, `a/b` for `a/b/c`).
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/')
        .filter_map(move |(at, _)| path.get(..at))
}

/// The folder an index path sits in (empty at the root).
fn folder_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(at) => path.get(..at).unwrap_or_default(),
        None => &[],
    }
}

fn base_kind(base: Option<&Tree<'_>>, path: &str) -> Option<ObjectType> {
    base?.get_path(Path::new(path)).ok()?.kind()
}

/// Validate a plan against its parent tree; `Ok(true)` when it holds an explicit type
/// change and needs the index builder.
fn check_plan(base: Option<&Tree<'_>>, edits: &[TreeEdit]) -> Result<bool, GitError> {
    let mut upserts: HashMap<&str, EntryMode> = HashMap::new();
    let mut removes: HashSet<&str> = HashSet::new();
    for edit in edits {
        validate_tree_path(edit.path())?;
        let fresh = match edit {
            TreeEdit::Upsert { path, mode, .. } => upserts.insert(path, *mode).is_none(),
            TreeEdit::Remove { path } => removes.insert(path),
        };
        if !fresh {
            return Err(refuse(UserOpRefusal::DuplicatePath, edit.path()));
        }
    }
    let mut type_change = false;
    for edit in edits {
        let path = edit.path();
        if ancestors(path).any(|a| upserts.contains_key(a)) {
            return Err(refuse(UserOpRefusal::NestedChange, path));
        }
        match edit {
            TreeEdit::Remove { .. } => {
                if base_kind(base, path).is_none() {
                    return Err(refuse(UserOpRefusal::SourceMissing, path));
                }
                if ancestors(path).any(|a| removes.contains(a)) {
                    return Err(refuse(UserOpRefusal::NestedChange, path));
                }
            }
            TreeEdit::Upsert { mode, .. } => {
                let removed_here = removes.contains(path);
                match base_kind(base, path) {
                    Some(kind) if kind != mode.object_type() => {
                        if !removed_here {
                            return Err(refuse(UserOpRefusal::TypeConflict, path));
                        }
                        type_change = true;
                    }
                    // A remove and an upsert of one path are only the explicit type-change
                    // form; with the same type the upsert alone says it.
                    Some(_) if removed_here => {
                        return Err(refuse(UserOpRefusal::DuplicatePath, path));
                    }
                    None if removed_here => {
                        return Err(refuse(UserOpRefusal::SourceMissing, path));
                    }
                    _ => {}
                }
                for ancestor in ancestors(path) {
                    match (removes.contains(ancestor), base_kind(base, ancestor)) {
                        // A file replaced by a folder.
                        (true, Some(kind)) if kind != ObjectType::Tree => type_change = true,
                        // A change below a folder the plan removes.
                        (true, Some(_)) => {
                            return Err(refuse(UserOpRefusal::NestedChange, path));
                        }
                        (true, None) => {
                            return Err(refuse(UserOpRefusal::SourceMissing, ancestor));
                        }
                        // Below a file the plan keeps.
                        (false, Some(kind)) if kind != ObjectType::Tree => {
                            return Err(refuse(UserOpRefusal::TypeConflict, path));
                        }
                        (false, _) => {}
                    }
                }
            }
        }
    }
    Ok(type_change)
}

/// The tree of `base` (`None` = unborn: the empty tree) plus exactly `edits`.
pub(crate) fn build_tree(
    repo: &Repository,
    base: Option<&Tree<'_>>,
    edits: &[TreeEdit],
) -> Result<Oid, GitError> {
    if check_plan(base, edits)? {
        build_with_index(repo, base, edits)
    } else {
        build_with_updater(repo, base, edits)
    }
}

fn empty_tree(repo: &Repository) -> Result<Tree<'_>, GitError> {
    let oid = repo.treebuilder(None)?.write()?;
    Ok(repo.find_tree(oid)?)
}

/// `git_tree_create_updated` over the parent tree. No type changes (libgit2 refuses them).
pub(crate) fn build_with_updater(
    repo: &Repository,
    base: Option<&Tree<'_>>,
    edits: &[TreeEdit],
) -> Result<Oid, GitError> {
    let empty;
    let baseline = match base {
        Some(tree) => tree,
        None => {
            empty = empty_tree(repo)?;
            &empty
        }
    };
    let mut builder = git2::build::TreeUpdateBuilder::new();
    for edit in edits {
        validate_tree_path(edit.path())?;
        match edit {
            TreeEdit::Upsert { path, oid, mode } => {
                builder.upsert(path.as_str(), *oid, mode.file_mode());
            }
            TreeEdit::Remove { path } => {
                builder.remove(path.as_str());
            }
        }
    }
    Ok(builder.create_updated(repo, baseline)?)
}

fn smudged_entry(path: Vec<u8>, id: Oid, mode: u32) -> IndexEntry {
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

/// Add every non-tree entry of `tree` under `prefix/`, at most `budget` of them. Every folder
/// under `prefix` is rebuilt, so a legacy raw mode is written canonically (see
/// [`build_with_index`]).
fn add_subtree(
    repo: &Repository,
    index: &mut Index,
    prefix: &[u8],
    tree: Oid,
    budget: &mut usize,
) -> Result<(), GitError> {
    let mut pending: Vec<(Vec<u8>, Oid)> = vec![(prefix.to_vec(), tree)];
    while let Some((dir, oid)) = pending.pop() {
        let tree = repo.find_tree(oid)?;
        for entry in tree.iter() {
            let mut path = dir.clone();
            path.push(b'/');
            path.extend_from_slice(entry.name_bytes());
            if entry.kind() == Some(ObjectType::Tree) {
                pending.push((path, entry.id()));
                continue;
            }
            *budget = budget.checked_sub(1).ok_or_else(|| {
                refuse(
                    UserOpRefusal::TreeTooLarge,
                    &String::from_utf8_lossy(prefix),
                )
            })?;
            let mode = u32::try_from(entry.filemode()).map_err(|_| {
                refuse(UserOpRefusal::TypeConflict, &String::from_utf8_lossy(&path))
            })?;
            index.add(&smudged_entry(path, entry.id(), canonical_mode(mode)))?;
        }
    }
    Ok(())
}

/// The index builder for explicit type changes: `Index::new` (never `.git/index`), the
/// parent tree, removes first, then upserts; a tree upsert replaces whatever was under its
/// path and is expanded into its entries (at most `MAX_RESTORE_PATHS`).
///
/// `write_tree_to` reuses the parent's tree object for every folder no edit runs through (the
/// cache `read_tree` fills), so everything there is kept byte for byte. A folder an edit runs
/// through is rebuilt, and libgit2 refuses to write a mode git no longer writes (a legacy
/// `100664`, which `read_tree` copies verbatim): only the entries of rebuilt folders are re-added
/// with their canonical mode.
pub(crate) fn build_with_index(
    repo: &Repository,
    base: Option<&Tree<'_>>,
    edits: &[TreeEdit],
) -> Result<Oid, GitError> {
    let mut index = Index::new()?;
    if let Some(base) = base {
        index.read_tree(base)?;
        // The root and every folder above an edited path.
        let rebuilt: HashSet<&[u8]> = edits
            .iter()
            .flat_map(|edit| std::iter::once("").chain(ancestors(edit.path())))
            .map(str::as_bytes)
            .collect();
        let legacy: Vec<IndexEntry> = index
            .iter()
            .filter(|entry| canonical_mode(entry.mode) != entry.mode)
            .filter(|entry| rebuilt.contains(folder_of(&entry.path)))
            .collect();
        for mut entry in legacy {
            entry.mode = canonical_mode(entry.mode);
            index.add(&entry)?;
        }
    }
    for edit in edits {
        validate_tree_path(edit.path())?;
        if let TreeEdit::Remove { path } = edit {
            if base_kind(base, path) == Some(ObjectType::Tree) {
                index.remove_dir(Path::new(path), 0)?;
            } else {
                index.remove_path(Path::new(path))?;
            }
        }
    }
    let mut budget = MAX_RESTORE_PATHS;
    for edit in edits {
        if let TreeEdit::Upsert { path, oid, mode } = edit {
            if *mode == EntryMode::Tree {
                index.remove_dir(Path::new(path), 0)?;
                add_subtree(repo, &mut index, path.as_bytes(), *oid, &mut budget)?;
            } else {
                index.add(&smudged_entry(path.as_bytes().to_vec(), *oid, mode.raw()))?;
            }
        }
    }
    Ok(index.write_tree_to(repo)?)
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
    use tempfile::TempDir;

    struct Fixture {
        _td: TempDir,
        repo: Repository,
        base: Oid,
        a: Oid,
        b: Oid,
        dir: Oid,
    }

    /// A base tree: `a.md`, `keep.md`, `dir/x.md`, `dir/run.sh` (exec), `dir/link`
    /// (symlink), `dir/sub/y.md`.
    fn fixture() -> Fixture {
        let td = TempDir::new().unwrap();
        let repo = Repository::init(td.path()).unwrap();
        let a = repo.blob(b"alpha\n").unwrap();
        let b = repo.blob(b"beta\n").unwrap();
        let target = repo.blob(b"../keep.md").unwrap();
        let edits = vec![
            TreeEdit::Upsert {
                path: "a.md".into(),
                oid: a,
                mode: EntryMode::File,
            },
            TreeEdit::Upsert {
                path: "keep.md".into(),
                oid: b,
                mode: EntryMode::File,
            },
            TreeEdit::Upsert {
                path: "dir/x.md".into(),
                oid: a,
                mode: EntryMode::File,
            },
            TreeEdit::Upsert {
                path: "dir/run.sh".into(),
                oid: b,
                mode: EntryMode::Executable,
            },
            TreeEdit::Upsert {
                path: "dir/link".into(),
                oid: target,
                mode: EntryMode::Link,
            },
            TreeEdit::Upsert {
                path: "dir/sub/y.md".into(),
                oid: b,
                mode: EntryMode::File,
            },
        ];
        let base = build_with_updater(&repo, None, &edits).unwrap();
        let dir = repo
            .find_tree(base)
            .unwrap()
            .get_path(Path::new("dir"))
            .unwrap()
            .id();
        Fixture {
            _td: td,
            repo,
            base,
            a,
            b,
            dir,
        }
    }

    fn upsert(path: &str, oid: Oid, mode: EntryMode) -> TreeEdit {
        TreeEdit::Upsert {
            path: path.into(),
            oid,
            mode,
        }
    }

    fn remove(path: &str) -> TreeEdit {
        TreeEdit::Remove { path: path.into() }
    }

    fn entry(repo: &Repository, tree: Oid, path: &str) -> Option<(Oid, i32)> {
        let tree = repo.find_tree(tree).unwrap();
        let entry = tree.get_path(Path::new(path)).ok()?;
        Some((entry.id(), entry.filemode()))
    }

    // MODULE-003-AC-27: both builders produce the same tree for every plan the updater takes.
    #[test]
    fn tree_builder_and_index_fallback_agree() {
        let f = fixture();
        let base = f.repo.find_tree(f.base).unwrap();
        let plans: Vec<(&str, Vec<TreeEdit>)> = vec![
            ("put", vec![upsert("new/deep/n.md", f.b, EntryMode::File)]),
            ("modify", vec![upsert("a.md", f.b, EntryMode::File)]),
            ("exec bit", vec![upsert("a.md", f.a, EntryMode::Executable)]),
            ("remove", vec![remove("keep.md")]),
            (
                "move",
                vec![remove("a.md"), upsert("b.md", f.a, EntryMode::File)],
            ),
            (
                "case-only rename",
                vec![remove("a.md"), upsert("A.md", f.a, EntryMode::File)],
            ),
            (
                "subtree move",
                vec![remove("dir"), upsert("moved", f.dir, EntryMode::Tree)],
            ),
            ("subtree copy", vec![upsert("copy", f.dir, EntryMode::Tree)]),
            ("remove subtree", vec![remove("dir")]),
            ("remove empties parent", vec![remove("dir/sub/y.md")]),
            ("no change", vec![]),
        ];
        for (name, edits) in plans {
            let updater = build_with_updater(&f.repo, Some(&base), &edits).unwrap();
            let index = build_with_index(&f.repo, Some(&base), &edits).unwrap();
            assert_eq!(updater, index, "{name}");
            assert_eq!(
                build_tree(&f.repo, Some(&base), &edits).unwrap(),
                updater,
                "{name}"
            );
        }
        let unborn = vec![
            upsert("a.md", f.a, EntryMode::File),
            upsert("d/b.md", f.b, EntryMode::Executable),
        ];
        let tree = build_tree(&f.repo, None, &unborn).unwrap();
        assert_eq!(tree, build_with_index(&f.repo, None, &unborn).unwrap());
        assert_eq!(entry(&f.repo, tree, "d/b.md"), Some((f.b, 0o100_755)));

        // The move reuses the blob; the subtree move reuses the subtree oid; an emptied
        // folder disappears.
        let moved = build_tree(
            &f.repo,
            Some(&base),
            &[remove("a.md"), upsert("b.md", f.a, EntryMode::File)],
        )
        .unwrap();
        assert_eq!(entry(&f.repo, moved, "b.md"), Some((f.a, 0o100_644)));
        assert_eq!(entry(&f.repo, moved, "a.md"), None);
        let moved = build_tree(
            &f.repo,
            Some(&base),
            &[remove("dir"), upsert("moved", f.dir, EntryMode::Tree)],
        )
        .unwrap();
        assert_eq!(entry(&f.repo, moved, "moved").unwrap().0, f.dir);
        let emptied = build_tree(&f.repo, Some(&base), &[remove("dir/sub/y.md")]).unwrap();
        assert_eq!(entry(&f.repo, emptied, "dir/sub"), None);
    }

    #[test]
    fn type_change_requires_explicit_remove() {
        let f = fixture();
        let base = f.repo.find_tree(f.base).unwrap();
        // Folder → file.
        let dir_to_file = vec![remove("dir"), upsert("dir", f.b, EntryMode::File)];
        assert!(build_with_updater(&f.repo, Some(&base), &dir_to_file).is_err());
        let tree = build_tree(&f.repo, Some(&base), &dir_to_file).unwrap();
        assert_eq!(entry(&f.repo, tree, "dir"), Some((f.b, 0o100_644)));
        assert_eq!(entry(&f.repo, tree, "keep.md"), Some((f.b, 0o100_644)));
        // File → folder.
        let file_to_dir = vec![remove("a.md"), upsert("a.md/x.md", f.b, EntryMode::File)];
        let tree = build_tree(&f.repo, Some(&base), &file_to_dir).unwrap();
        assert_eq!(entry(&f.repo, tree, "a.md/x.md"), Some((f.b, 0o100_644)));
        // Implicit forms are refused.
        for edits in [
            vec![upsert("dir", f.b, EntryMode::File)],
            vec![upsert("a.md/x.md", f.b, EntryMode::File)],
            vec![upsert("a.md", f.dir, EntryMode::Tree)],
        ] {
            match build_tree(&f.repo, Some(&base), &edits) {
                Err(GitError::InvalidUserOp {
                    reason: UserOpRefusal::TypeConflict,
                    ..
                }) => {}
                other => panic!("expected TypeConflict for {edits:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn fallback_expands_move_tree_into_blobs() {
        let f = fixture();
        let base = f.repo.find_tree(f.base).unwrap();
        // The file → folder change forces the index builder; the subtree move rides in it.
        let edits = vec![
            remove("a.md"),
            upsert("a.md/x.md", f.b, EntryMode::File),
            remove("dir"),
            upsert("moved", f.dir, EntryMode::Tree),
        ];
        let tree = build_tree(&f.repo, Some(&base), &edits).unwrap();
        assert_eq!(entry(&f.repo, tree, "moved").unwrap().0, f.dir);
        assert_eq!(entry(&f.repo, tree, "moved/run.sh"), Some((f.b, 0o100_755)));
        assert_eq!(entry(&f.repo, tree, "moved/link").unwrap().1, 0o120_000);
        assert_eq!(
            entry(&f.repo, tree, "moved/sub/y.md"),
            Some((f.b, 0o100_644))
        );
        assert_eq!(entry(&f.repo, tree, "dir"), None);
        // A tree upsert over an existing folder replaces it in both builders.
        let sub = entry(&f.repo, f.base, "dir/sub").unwrap().0;
        let replace = vec![upsert("dir", sub, EntryMode::Tree)];
        let updater = build_with_updater(&f.repo, Some(&base), &replace).unwrap();
        assert_eq!(
            build_with_index(&f.repo, Some(&base), &replace).unwrap(),
            updater
        );
        assert_eq!(entry(&f.repo, updater, "dir").unwrap().0, sub);
    }

    #[test]
    fn plan_refusals() {
        let f = fixture();
        let base = f.repo.find_tree(f.base).unwrap();
        let index_path = f.repo.path().join("index");
        let cases: Vec<(UserOpRefusal, Vec<TreeEdit>)> = vec![
            (
                UserOpRefusal::DuplicatePath,
                vec![
                    upsert("n.md", f.a, EntryMode::File),
                    upsert("n.md", f.b, EntryMode::File),
                ],
            ),
            (
                UserOpRefusal::DuplicatePath,
                vec![remove("a.md"), remove("a.md")],
            ),
            (
                UserOpRefusal::DuplicatePath,
                vec![remove("a.md"), upsert("a.md", f.b, EntryMode::File)],
            ),
            (
                UserOpRefusal::NestedChange,
                vec![
                    upsert("moved", f.dir, EntryMode::Tree),
                    upsert("moved/extra.md", f.a, EntryMode::File),
                ],
            ),
            (
                UserOpRefusal::NestedChange,
                vec![remove("dir"), remove("dir/x.md")],
            ),
            (
                UserOpRefusal::NestedChange,
                vec![remove("dir"), upsert("dir/new.md", f.a, EntryMode::File)],
            ),
            (UserOpRefusal::SourceMissing, vec![remove("absent.md")]),
            (UserOpRefusal::InvalidPath, vec![remove("")]),
            (UserOpRefusal::InvalidPath, vec![remove("/a.md")]),
            (UserOpRefusal::InvalidPath, vec![remove("dir/")]),
            (UserOpRefusal::InvalidPath, vec![remove("dir//x.md")]),
            (UserOpRefusal::InvalidPath, vec![remove("dir/../a.md")]),
            (
                UserOpRefusal::InvalidPath,
                vec![upsert("a\0b", f.a, EntryMode::File)],
            ),
        ];
        for (reason, edits) in cases {
            match build_tree(&f.repo, Some(&base), &edits) {
                Err(GitError::InvalidUserOp { reason: got, .. }) => {
                    assert_eq!(got, reason, "{edits:?}")
                }
                other => panic!("expected {reason:?} for {edits:?}, got {other:?}"),
            }
        }
        // Both builders refuse a NUL path instead of panicking inside git2.
        let nul = vec![upsert("a\0b", f.a, EntryMode::File)];
        assert!(build_with_updater(&f.repo, Some(&base), &nul).is_err());
        assert!(build_with_index(&f.repo, Some(&base), &nul).is_err());
        // No builder touched the repository's index.
        assert!(!index_path.exists());
        assert_eq!(EntryMode::from_raw(0o100_755), Some(EntryMode::Executable));
        assert_eq!(EntryMode::from_raw(0o160_000), None);
    }

    // A legacy raw `100664` entry in a folder the type-change fallback rebuilds is written with
    // git's canonical mode instead of failing the build; a folder no edit runs through keeps
    // its tree object, raw modes included (MODULE-003-AC-27: the parent tree plus exactly the
    // edits).
    #[test]
    fn index_builder_canonicalizes_legacy_modes() {
        let f = fixture();
        let odb = f.repo.odb().unwrap();
        let legacy = f.repo.blob(b"legacy\n").unwrap();
        let raw_tree = |entries: &[(&[u8], &[u8], Oid)]| {
            let mut raw = Vec::new();
            for (mode, name, oid) in entries {
                raw.extend_from_slice(mode);
                raw.push(b' ');
                raw.extend_from_slice(name);
                raw.push(0);
                raw.extend_from_slice(oid.as_bytes());
            }
            odb.write(ObjectType::Tree, &raw).unwrap()
        };
        // `deep/` and `src/` each hold a raw `100664` entry; the root holds one beside a file
        // that becomes a folder (the type change sends the plan through the index builder,
        // which rebuilds the root) and `src/` moves within the same plan.
        let deep = raw_tree(&[(b"100664", b"legacy.md", legacy)]);
        let src = raw_tree(&[(b"100664", b"x.md", legacy)]);
        let root = raw_tree(&[
            (b"100664", b"a.md", legacy),
            (b"100644", b"b.md", f.b),
            (b"40000", b"deep", deep),
            (b"40000", b"src", src),
        ]);
        let base = f.repo.find_tree(root).unwrap();
        let edits = vec![
            TreeEdit::Remove {
                path: "b.md".into(),
            },
            upsert("b.md/c.md", f.a, EntryMode::File),
            TreeEdit::Remove { path: "src".into() },
            upsert("dst", src, EntryMode::Tree),
        ];
        let built = build_tree(&f.repo, Some(&base), &edits).unwrap();
        let tree = f.repo.find_tree(built).unwrap();
        let kept = tree.get_path(Path::new("a.md")).unwrap();
        assert_eq!((kept.id(), kept.filemode_raw()), (legacy, 0o100_644));
        assert_eq!(entry(&f.repo, built, "b.md/c.md"), Some((f.a, 0o100_644)));
        assert_eq!(
            entry(&f.repo, built, "deep").unwrap().0,
            deep,
            "byte for byte"
        );
        let untouched = tree.get_path(Path::new("deep/legacy.md")).unwrap();
        assert_eq!(untouched.filemode_raw(), 0o100_664);
        assert_eq!(entry(&f.repo, built, "dst/x.md"), Some((legacy, 0o100_644)));
        assert_eq!(entry(&f.repo, built, "src"), None);
    }
}
