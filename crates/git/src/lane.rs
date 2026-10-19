//! Shared machinery of the user commit lane's worker items (ADR 2026-10-15, CONTRACT-247;
//! MODULE-003 §1.4.1 items 1–3, AC-27, AC-36).
//!
//! Both lane items that write history, `commit_user` (`lane_commit`) and the adopt step of
//! `prepare` (`lane_prepare`), land their commit through [`land`]:
//!
//! 1. the commit object is created without moving any ref (`repo.commit(None, …)`);
//! 2. the crash journal `.git/advance/user-lane.journal` names the touched paths;
//! 3. `.git/index` is made equal to the new tree for every touched path, smudged (zero stat, so a
//!    later status re-hashes), except a `Put` whose provider [`IndexStat`] still matches an
//!    `fstat` of the file: that entry keeps the real stat;
//! 4. `main` moves by compare-and-swap. When something outside the queue moved it (a CLI
//!    `git commit`, which holds `index.lock` and `refs/heads/main.lock` while it does), the
//!    touched entries are reset from the **new** tip (read after any lock wait), the journal
//!    is deleted and the caller re-resolves against that tip (at most [`MAX_ATTEMPTS`] times).
//!
//! The index is written before the ref so that a legacy agent commit (`index.write_tree()` over
//! the whole index) can never revert a user edit; the journal closes the crash window between
//! the two (healed before every item, `journal::heal`).
//!
//! The helpers also hold the repository facts each item reads (`core.ignorecase`,
//! `core.precomposeunicode`), the one tracked-size threshold ([`effective_max_tracked`], R2a /
//! R11), the existing spelling of a request path ([`Spellings`]), the case-collision guard
//! (MODULE-003-AC-36) and the agent-territory walk.
//!
//! Everything here runs while the coord mutex is held, so it is panic-free: a panic there
//! poisons coord and stops every later commit.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use advance_shared_types::workspace_path::{is_agent_dir_name, to_nfc};
use git2::{ErrorCode, Index, IndexTime, ObjectType, Oid, Repository, Tree, TreeEntry};
use std::os::unix::fs::MetadataExt;

use crate::config::GitConfigSnapshot;
use crate::error::{GitError, UserOpRefusal};
use crate::journal::{self, Journal};
use crate::paths::collision_fold;
use crate::safe_fs::{open_entry, stream_blob, DiskEntry, SafeRoot};
use crate::tree_edit::{EntryMode, TreeEdit};
use crate::user_lane::{
    Authorship, IndexStat, ADOPT_TIME_BUDGET, MAX_ADOPT_BYTES, MAX_RESTORE_PATHS, MAX_USER_BYTES,
    MAX_USER_CHANGES,
};

/// The one branch the runtime commits to.
pub(crate) const MAIN_REF: &str = "refs/heads/main";
/// Ref compare-and-swap attempts per item before `GitError::HeadMoved` (MODULE-003 §1.4.1
/// item 3).
pub(crate) const MAX_ATTEMPTS: usize = 3;

const MIB: u64 = 1024 * 1024;

/// The tracked-size threshold of the user lane (R2a / R11): `git.max_tracked_file_mb`, at least
/// 1 MiB (the legacy clamp) and at most [`MAX_USER_BYTES`] (64 MiB). A file above it is saved but
/// not versioned, and `prepare` never hashes it. The one accessor every over-threshold decision
/// of the lane goes through.
pub(crate) fn effective_max_tracked(snapshot: &GitConfigSnapshot) -> u64 {
    let cap = u64::try_from(MAX_USER_BYTES).unwrap_or(u64::MAX);
    snapshot
        .max_tracked_file_mb
        .saturating_mul(MIB)
        .max(MIB)
        .min(cap)
}

/// Repository facts read per item (MODULE-003 §1.4.1 "paths").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RepoFacts {
    /// `core.ignorecase` (unset or unreadable: `true`, as rollback reads it): new paths that fold
    /// equal to an existing entry under case and NFC are refused.
    pub(crate) ignorecase: bool,
    /// `core.precomposeunicode` (unset: `false`): tree spellings are NFC iff set.
    pub(crate) precompose: bool,
    /// How the shared index compares paths (`journal::index_folds_case`): ASCII case folded iff
    /// `core.ignorecase` is set.
    pub(crate) index_fold: bool,
}

impl RepoFacts {
    pub(crate) fn read(repo: &Repository) -> Self {
        let config = repo.config().ok();
        let flag = |key: &str| config.as_ref().and_then(|c| c.get_bool(key).ok());
        let ignorecase = flag("core.ignorecase");
        Self {
            ignorecase: ignorecase.unwrap_or(true),
            precompose: flag("core.precomposeunicode").unwrap_or(false),
            index_fold: ignorecase.unwrap_or(false),
        }
    }
}

/// Values a test may override (test-support `LaneTestHooks`); production uses the defaults.
#[derive(Default)]
pub(crate) struct LaneOverrides {
    /// Called with the workdir right before each ref compare-and-swap.
    pub(crate) before_ref_cas: Option<Box<dyn Fn(&Path) + Send>>,
    pub(crate) max_user_changes: Option<usize>,
    pub(crate) max_restore_paths: Option<usize>,
    pub(crate) max_adopt_bytes: Option<u64>,
    pub(crate) adopt_time_budget: Option<Duration>,
    /// Elapsed time since any origin; replaces the monotonic clock of the adopt budget.
    pub(crate) adopt_clock: Option<Box<dyn Fn() -> Duration + Send>>,
}

/// The bounds one item runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LaneLimits {
    pub(crate) max_user_changes: usize,
    pub(crate) max_restore_paths: usize,
    pub(crate) max_adopt_bytes: u64,
    pub(crate) adopt_time_budget: Duration,
}

impl LaneLimits {
    fn from_overrides(overrides: &LaneOverrides) -> Self {
        Self {
            max_user_changes: overrides.max_user_changes.unwrap_or(MAX_USER_CHANGES),
            max_restore_paths: overrides.max_restore_paths.unwrap_or(MAX_RESTORE_PATHS),
            max_adopt_bytes: overrides.max_adopt_bytes.unwrap_or(MAX_ADOPT_BYTES),
            adopt_time_budget: overrides.adopt_time_budget.unwrap_or(ADOPT_TIME_BUDGET),
        }
    }
}

/// Everything one lane item needs: the worker's repository handle, the workdir anchor for
/// fd-relative reads, the facts, the threshold and the bounds.
pub(crate) struct LaneCtx<'a> {
    pub(crate) repo: &'a Repository,
    pub(crate) workdir: PathBuf,
    pub(crate) root: SafeRoot,
    pub(crate) facts: RepoFacts,
    /// [`effective_max_tracked`] for this item.
    pub(crate) max_tracked: u64,
    pub(crate) limits: LaneLimits,
    overrides: &'a Mutex<LaneOverrides>,
    started: Instant,
}

impl<'a> LaneCtx<'a> {
    pub(crate) fn new(
        repo: &'a Repository,
        snapshot: &GitConfigSnapshot,
        overrides: &'a Mutex<LaneOverrides>,
    ) -> Result<Self, GitError> {
        let workdir = repo
            .workdir()
            .ok_or_else(|| {
                GitError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "the user lane needs a repository with a workdir",
                ))
            })?
            .to_path_buf();
        let root = SafeRoot::open(&workdir)?;
        let limits = LaneLimits::from_overrides(&lock(overrides));
        Ok(Self {
            repo,
            root,
            workdir,
            facts: RepoFacts::read(repo),
            max_tracked: effective_max_tracked(snapshot),
            limits,
            overrides,
            started: Instant::now(),
        })
    }

    /// The test seam right before a ref compare-and-swap (no-op in production).
    fn before_ref_cas(&self) {
        if let Some(hook) = &lock(self.overrides).before_ref_cas {
            hook(&self.workdir);
        }
    }

    /// The adopt budget's clock: time since the item started, or the injected clock.
    pub(crate) fn adopt_clock(&self) -> Duration {
        match &lock(self.overrides).adopt_clock {
            Some(clock) => clock(),
            None => self.started.elapsed(),
        }
    }

    /// Open `rel` (a disk spelling) under the workdir without following any symlink.
    pub(crate) fn open(&self, rel: &str) -> Result<DiskEntry, GitError> {
        Ok(open_entry(&self.root, rel)?)
    }
}

fn lock(overrides: &Mutex<LaneOverrides>) -> MutexGuard<'_, LaneOverrides> {
    overrides
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A refusal naming `path`.
pub(crate) fn refuse(reason: UserOpRefusal, path: &str) -> GitError {
    GitError::InvalidUserOp {
        reason,
        path: Some(PathBuf::from(path)),
    }
}

/// The commit `refs/heads/main` points at, and its tree (`None` while unborn).
pub(crate) fn main_state(repo: &Repository) -> Result<(Option<Oid>, Option<Tree<'_>>), GitError> {
    match journal::main_tip(repo)? {
        Some(oid) => Ok((Some(oid), Some(repo.find_commit(oid)?.tree()?))),
        None => Ok((None, None)),
    }
}

/// The entry of `tree` at `path`; `None` when absent (other lookup errors propagate).
pub(crate) fn entry_at(
    tree: Option<&Tree<'_>>,
    path: &str,
) -> Result<Option<TreeEntry<'static>>, GitError> {
    let Some(tree) = tree else {
        return Ok(None);
    };
    if path.is_empty() || path.contains('\0') {
        return Ok(None);
    }
    match tree.get_path(Path::new(path)) {
        Ok(entry) => Ok(Some(entry)),
        Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// What a tree entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadKind {
    /// `100644` / `100755` (or a legacy raw blob mode); `executable` for `100755`.
    File {
        executable: bool,
    },
    /// `120000`.
    Link,
    Tree,
    /// `160000` (never written by the lane).
    Gitlink,
}

/// The kind of a tree entry (a legacy raw blob mode reads as a plain file).
pub(crate) fn head_kind(entry: &TreeEntry<'_>) -> HeadKind {
    match (entry.kind(), EntryMode::from_raw(entry.filemode())) {
        (Some(ObjectType::Tree), _) => HeadKind::Tree,
        (Some(ObjectType::Commit), _) => HeadKind::Gitlink,
        (_, Some(EntryMode::Link)) => HeadKind::Link,
        (_, Some(EntryMode::Executable)) => HeadKind::File { executable: true },
        _ => HeadKind::File { executable: false },
    }
}

/// Whether the subtree `tree` holds an entry named `.agent` (policy fold) at any depth: an
/// agent territory, which folder ops never carry (MODULE-003-AC-36). At most `limit` entries
/// are visited; past it the walk refuses with `TreeTooLarge` (naming `at`).
pub(crate) fn holds_agent_territory(
    repo: &Repository,
    tree: Oid,
    limit: usize,
    at: &str,
) -> Result<bool, GitError> {
    let mut pending = vec![tree];
    let mut budget = limit;
    while let Some(oid) = pending.pop() {
        let listing = repo.find_tree(oid)?;
        for entry in listing.iter() {
            budget = budget
                .checked_sub(1)
                .ok_or_else(|| refuse(UserOpRefusal::TreeTooLarge, at))?;
            if std::str::from_utf8(entry.name_bytes()).is_ok_and(is_agent_dir_name) {
                return Ok(true);
            }
            if entry.kind() == Some(ObjectType::Tree) {
                pending.push(entry.id());
            }
        }
    }
    Ok(false)
}

/// The case-collision guard (MODULE-003-AC-36), used only under `core.ignorecase`: a new tree
/// path must not fold equal (case and NFC, `paths::collision_fold`) to an existing entry with
/// other bytes at any level of the parent tree. The one exception is an entry the request moves
/// away (the source of a case-only rename). Each folder's fold table is built once.
#[derive(Default)]
pub(crate) struct CollisionGuard {
    folds: HashMap<Oid, HashMap<String, Vec<Vec<u8>>>>,
}

impl CollisionGuard {
    fn folds_of(&mut self, tree: &Tree<'_>) -> &HashMap<String, Vec<Vec<u8>>> {
        self.folds.entry(tree.id()).or_insert_with(|| {
            let mut table: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
            for entry in tree.iter() {
                let name = String::from_utf8_lossy(entry.name_bytes());
                table
                    .entry(collision_fold(&name))
                    .or_default()
                    .push(entry.name_bytes().to_vec());
            }
            table
        })
    }

    /// Refuse `path` with `CaseCollision` when some level of `base` holds a fold-equal entry with
    /// other bytes that `exempt` (full tree paths) does not name.
    pub(crate) fn check(
        &mut self,
        repo: &Repository,
        base: Option<&Tree<'_>>,
        path: &str,
        exempt: &HashSet<String>,
    ) -> Result<(), GitError> {
        let Some(base) = base else {
            return Ok(());
        };
        let mut current: Tree<'_> = repo.find_tree(base.id())?;
        let mut prefix = String::new();
        for component in path.split('/') {
            let fold = collision_fold(component);
            let clashes: Vec<Vec<u8>> = self
                .folds_of(&current)
                .get(&fold)
                .map(|names| {
                    names
                        .iter()
                        .filter(|name| name.as_slice() != component.as_bytes())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            for name in clashes {
                let full = format!("{prefix}{}", String::from_utf8_lossy(&name));
                if !exempt.contains(&full) {
                    return Err(refuse(UserOpRefusal::CaseCollision, path));
                }
            }
            let next = match current.get_name(component) {
                Some(entry) if entry.kind() == Some(ObjectType::Tree) => entry.id(),
                _ => return Ok(()),
            };
            current = repo.find_tree(next)?;
            prefix.push_str(component);
            prefix.push('/');
        }
        Ok(())
    }
}

/// The spelling a parent tree holds for a request path (MODULE-003 §1.4.1 "paths", AC-27). With
/// `core.precomposeunicode` set the lane spells tree paths in NFC, but the legacy lane stores the
/// bytes an agent passed (`index.add_path` keeps a decomposed name), so HEAD may hold a
/// canonically equivalent spelling of a path the user names. A component the tree does not hold
/// as spelled takes the one entry of that folder whose NFC form is the component's, so an edit,
/// move, copy or delete reaches the entry history has instead of reading as untracked; from the
/// first component the tree does not hold, the path keeps the request's spelling (a new path
/// follows the setting). Without `precompose` paths are used as given. Each folder's table is
/// built once.
#[derive(Default)]
pub(crate) struct Spellings {
    tables: HashMap<Oid, HashMap<String, Vec<String>>>,
}

impl Spellings {
    /// The spelling of `path` in `base` (see the type docs).
    pub(crate) fn resolve(
        &mut self,
        ctx: &LaneCtx<'_>,
        base: Option<&Tree<'_>>,
        path: &str,
    ) -> Result<String, GitError> {
        let Some(base) = base.filter(|_| ctx.facts.precompose) else {
            return Ok(path.to_string());
        };
        // git2's name lookups panic on a NUL; no tree path holds one.
        if path.is_empty() || path.contains('\0') || entry_at(Some(base), path)?.is_some() {
            return Ok(path.to_string());
        }
        let repo = ctx.repo;
        let mut folder = Some(repo.find_tree(base.id())?);
        let mut spelled = String::with_capacity(path.len());
        for component in path.split('/') {
            if !spelled.is_empty() {
                spelled.push('/');
            }
            let Some(tree) = folder.take() else {
                spelled.push_str(component);
                continue;
            };
            let name = match tree.get_name(component) {
                Some(_) => component.to_string(),
                None => self
                    .equivalent(&tree, component)
                    .unwrap_or_else(|| component.to_string()),
            };
            folder = match tree.get_name(&name) {
                Some(entry) if entry.kind() == Some(ObjectType::Tree) => {
                    Some(repo.find_tree(entry.id())?)
                }
                _ => None,
            };
            spelled.push_str(&name);
        }
        Ok(spelled)
    }

    /// The one entry of `tree` whose NFC form is `component`'s. ASCII names are skipped: they
    /// are their own NFC form, so one of them would have matched as spelled.
    fn equivalent(&mut self, tree: &Tree<'_>, component: &str) -> Option<String> {
        let table = self.tables.entry(tree.id()).or_insert_with(|| {
            let mut table: HashMap<String, Vec<String>> = HashMap::new();
            for entry in tree.iter() {
                if let Some(name) = entry.name().filter(|name| !name.is_ascii()) {
                    table
                        .entry(to_nfc(name))
                        .or_default()
                        .push(name.to_string());
                }
            }
            table
        });
        match table.get(&to_nfc(component)).map(Vec::as_slice) {
            Some([only]) => Some(only.clone()),
            _ => None,
        }
    }
}

/// The paths an item's index write covers: files, and folders with everything under them
/// (first-touch order, no duplicates).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Touched {
    pub(crate) files: Vec<String>,
    pub(crate) dirs: Vec<String>,
    seen_files: HashSet<String>,
    seen_dirs: HashSet<String>,
}

impl Touched {
    pub(crate) fn file(&mut self, path: &str) {
        if self.seen_files.insert(path.to_string()) {
            self.files.push(path.to_string());
        }
    }

    pub(crate) fn dir(&mut self, path: &str) {
        if self.seen_dirs.insert(path.to_string()) {
            self.dirs.push(path.to_string());
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.is_empty()
    }

    fn items(&self) -> Vec<&str> {
        self.dirs
            .iter()
            .chain(&self.files)
            .map(String::as_str)
            .collect()
    }
}

/// A provider `IndexStat` for an upserted path: recorded in the index only when an `fstat` of
/// the file (opened by its disk spelling, never followed) still matches it on dev, ino, size,
/// mtime and ctime, and the index entry holds `oid` (MODULE-003-AC-27).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatFix {
    pub(crate) tree_path: String,
    pub(crate) disk_path: String,
    pub(crate) oid: Oid,
    pub(crate) stat: IndexStat,
}

fn stat_matches(meta: &std::fs::Metadata, stat: &IndexStat) -> bool {
    meta.dev() == stat.dev
        && meta.ino() == stat.ino
        && meta.size() == stat.size
        && meta.mtime() == stat.mtime_s
        && meta.mtime_nsec() == i64::from(stat.mtime_ns)
        && meta.ctime() == stat.ctime_s
        && meta.ctime_nsec() == i64::from(stat.ctime_ns)
}

/// Record the verified stats in `index` (entries that do not qualify stay smudged). The index
/// fields are 32-bit; they are truncated the way libgit2 fills them from `stat`, so a later
/// status compares like with like.
fn apply_stats(ctx: &LaneCtx<'_>, index: &mut Index, stats: &[StatFix]) -> Result<(), GitError> {
    for fix in stats {
        let Some(mut entry) = index.get_path(Path::new(&fix.tree_path), 0) else {
            continue;
        };
        if entry.id != fix.oid {
            continue;
        }
        let Ok(DiskEntry::File(opened)) = ctx.open(&fix.disk_path) else {
            continue;
        };
        let Ok(meta) = opened.stat() else {
            continue;
        };
        if !stat_matches(&meta, &fix.stat) {
            continue;
        }
        entry.ctime = IndexTime::new(meta.ctime() as i32, meta.ctime_nsec() as u32);
        entry.mtime = IndexTime::new(meta.mtime() as i32, meta.mtime_nsec() as u32);
        entry.dev = meta.dev() as u32;
        entry.ino = meta.ino() as u32;
        entry.uid = meta.uid();
        entry.gid = meta.gid();
        entry.file_size = meta.size() as u32;
        index.add(&entry)?;
    }
    Ok(())
}

/// Make `.git/index` equal the `main` tip's tree (unborn: the empty tree) for every touched
/// path, smudged, then record the verified stats (MODULE-003 §1.4.1 item 2: after every lane
/// item, also `Unchanged` and `HeadMoved` ones). Index-lock contention is retried, and every
/// attempt reads `main` again, as `journal::heal` does: a CLI `git commit` holds `index.lock`
/// while it moves `main`, so a tip read before the wait would leave the index behind HEAD for
/// these paths, and the next legacy commit would revert them. Answers the tip the index now
/// follows (MODULE-003-AC-27).
pub(crate) fn normalize_index(
    ctx: &LaneCtx<'_>,
    touched: &Touched,
    stats: &[StatFix],
) -> Result<Option<Oid>, GitError> {
    let repo = ctx.repo;
    if touched.is_empty() {
        return journal::main_tip(repo);
    }
    let items = touched.items();
    journal::update_index_with_retry(repo, |index| {
        let tip = journal::main_tip(repo)?;
        let tree = match tip {
            Some(oid) => Some(repo.find_commit(oid)?.tree()?),
            None => None,
        };
        journal::reset_from_tree(repo, index, tree.as_ref(), &items, ctx.facts.index_fold)?;
        apply_stats(ctx, index, stats)?;
        Ok(tip)
    })
}

/// One commit to land on `main`.
pub(crate) struct Landing<'a> {
    /// The tip the tree was built on (`None` = unborn).
    pub(crate) parent: Option<Oid>,
    pub(crate) tree: Oid,
    /// The full commit message (prefix, subject, trailers).
    pub(crate) message: &'a str,
    /// The subject, for the reflog.
    pub(crate) subject: &'a str,
    pub(crate) authorship: &'a Authorship,
    pub(crate) touched: &'a Touched,
    pub(crate) stats: &'a [StatFix],
}

/// What [`land`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Landed {
    /// `main` is the new commit.
    Committed(Oid),
    /// Something outside the queue moved `main` to this tip; the touched entries now equal it.
    HeadMoved(Option<Oid>),
}

/// Land one commit: object, journal, index, ref compare-and-swap (see the module docs).
///
/// - An index write that fails (after the lock retries) deletes the journal and returns the
///   error: nothing is visible (the commit object dangles, `main` did not move).
/// - A compare-and-swap that fails, whether it lost (`main` moved) or met
///   `refs/heads/main.lock`, resets the touched entries from the tip read while the index is
///   written ([`normalize_index`]: a writer that holds the ref lock is moving `main` and holds
///   `index.lock` too) and deletes the journal. Then a tip that is not the parent answers
///   [`Landed::HeadMoved`], the parent itself returns the error, and the item's own commit
///   (the ref write failed after it landed) is [`Landed::Committed`]. A reset that cannot be
///   written keeps the journal, so the heal before the next item finishes it.
pub(crate) fn land(ctx: &LaneCtx<'_>, landing: &Landing<'_>) -> Result<Landed, GitError> {
    let repo = ctx.repo;
    let tree = repo.find_tree(landing.tree)?;
    let parent = match landing.parent {
        Some(oid) => Some(repo.find_commit(oid)?),
        None => None,
    };
    let parents: Vec<&git2::Commit<'_>> = parent.iter().collect();
    let commit = repo.commit(
        None,
        &landing.authorship.author,
        &landing.authorship.committer,
        landing.message,
        &tree,
        &parents,
    )?;
    publish(ctx, landing, commit)
}

/// Journal, index and ref compare-and-swap for an existing commit object (the restore
/// path applies the disk between `repo.commit` and this). See [`land`].
pub(crate) fn publish(
    ctx: &LaneCtx<'_>,
    landing: &Landing<'_>,
    commit: Oid,
) -> Result<Landed, GitError> {
    let repo = ctx.repo;
    let tree = repo.find_tree(landing.tree)?;
    let record = Journal {
        parent: landing.parent.map(|oid| oid.to_string()),
        commit: commit.to_string(),
        paths: landing.touched.files.clone(),
        prefixes: landing.touched.dirs.clone(),
    };
    journal::write_journal(repo.path(), &record)?;
    let items = landing.touched.items();
    let written = journal::update_index_with_retry(repo, |index| {
        journal::reset_from_tree(repo, index, Some(&tree), &items, ctx.facts.index_fold)?;
        apply_stats(ctx, index, landing.stats)
    });
    if let Err(e) = written {
        // A journal left behind is harmless: the next heal resets these paths from HEAD.
        let _ = journal::delete_journal(repo.path());
        return Err(e);
    }
    ctx.before_ref_cas();
    let reflog = format!("commit: {}", landing.subject);
    let swapped = match landing.parent {
        Some(current) => repo
            .reference_matching(MAIN_REF, commit, true, current, &reflog)
            .map(drop),
        None => repo.reference(MAIN_REF, commit, false, &reflog).map(drop),
    };
    match swapped {
        Ok(()) => {
            // A journal left behind is harmless: `main` is its commit, so heal just deletes it.
            let _ = journal::delete_journal(repo.path());
            Ok(Landed::Committed(commit))
        }
        Err(e) => {
            let tip = normalize_index(ctx, landing.touched, &[])?;
            let _ = journal::delete_journal(repo.path());
            if tip == Some(commit) {
                Ok(Landed::Committed(commit))
            } else if tip != landing.parent {
                Ok(Landed::HeadMoved(tip))
            } else {
                Err(e.into())
            }
        }
    }
}

/// The runtime's `.gitignore` rides along in the first commit that records the vault (HEAD has
/// none yet), as the legacy lane stages it then (MODULE-003-AC-12 durability). It is not a
/// primary change, so it never makes a commit on its own. Best effort: a `.gitignore` that is
/// not a regular file, is over the threshold or changes while read is left for a later commit.
pub(crate) fn gitignore_rider(
    ctx: &LaneCtx<'_>,
    base: Option<&Tree<'_>>,
    edits: &mut Vec<TreeEdit>,
    touched: &mut Touched,
) -> Result<(), GitError> {
    const GITIGNORE: &str = ".gitignore";
    if entry_at(base, GITIGNORE)?.is_some() || edits.iter().any(|edit| edit.path() == GITIGNORE) {
        return Ok(());
    }
    let DiskEntry::File(mut opened) = ctx.open(GITIGNORE)? else {
        return Ok(());
    };
    if opened.len > ctx.max_tracked {
        return Ok(());
    }
    let Ok(oid) = stream_blob(ctx.repo, &mut opened) else {
        return Ok(());
    };
    edits.push(TreeEdit::Upsert {
        path: GITIGNORE.to_string(),
        oid,
        mode: EntryMode::File,
    });
    touched.file(GITIGNORE);
    Ok(())
}

/// The parent folder of a tree path (`""` at the root).
pub(crate) fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The proper ancestors of a tree path, shortest first (`a`, `a/b` for `a/b/c`).
pub(crate) fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/')
        .filter_map(move |(at, _)| path.get(..at))
}

/// `true` when `path` is `dir` or lies under it (`dir == ""`: everything), comparing the way
/// the index does (ASCII case folded when `fold`).
pub(crate) fn within(dir: &str, path: &str, fold: bool) -> bool {
    if dir.is_empty() {
        return true;
    }
    let eq = |a: &str, b: &str| {
        if fold {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    };
    if path.len() == dir.len() {
        return eq(path, dir);
    }
    match (path.get(..dir.len()), path.get(dir.len()..)) {
        (Some(head), Some(rest)) => eq(head, dir) && rest.starts_with('/'),
        _ => false,
    }
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

    // R2a / R11: one threshold — the configured MiB, at least 1 MiB, at most 64 MiB.
    #[test]
    fn effective_max_tracked_clamps() {
        let at = |mb: u64| {
            effective_max_tracked(&GitConfigSnapshot {
                gc_interval_hours: 24,
                max_tracked_file_mb: mb,
            })
        };
        assert_eq!(at(10), 10 * MIB);
        assert_eq!(
            effective_max_tracked(&GitConfigSnapshot::DEFAULTS),
            10 * MIB
        );
        assert_eq!(at(0), MIB);
        assert_eq!(at(64), 64 * MIB);
        assert_eq!(at(100), 64 * MIB);
        assert_eq!(at(u64::MAX), 64 * MIB);
    }

    #[test]
    fn path_helpers() {
        assert_eq!(parent_of("a.md"), "");
        assert_eq!(parent_of("d/e/a.md"), "d/e");
        assert_eq!(ancestors("a/b/c").collect::<Vec<_>>(), vec!["a", "a/b"]);
        assert!(within("", "x", false));
        assert!(within("notes", "notes", false));
        assert!(within("notes", "notes/a.md", false));
        assert!(!within("notes", "notes2/a.md", false));
        assert!(!within("notes", "Notes/a.md", false));
        assert!(within("notes", "Notes/a.md", true));
        assert!(!within("notes/a", "notes", false));
    }
}
