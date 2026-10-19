//! `prepare`: the FIFO barrier and the adopt step (ADR 2026-10-15, CONTRACT-247; MODULE-003
//! §1.4.1 "`prepare`", AC-31, AC-37).
//!
//! A `prepare` item runs after every item enqueued before it (the queue is FIFO), so an earlier
//! legacy commit has hashed the pre-user disk. It then:
//!
//! 1. observes each `File` target (request order) through `safe_fs`: a regular file within the
//!    tracked-size threshold is hashed (its `fstat` identity is returned for the caller's
//!    re-check under its lock), a symlink is read, a FIFO, socket or device is never read;
//! 2. walks each `Tree` target with `statuses()` (untracked and ignored entries included, path
//!    order): an entry under an `.agent` component flags `agent_territory` and is never
//!    adopted (every entry takes this string test, past the bounds too); Junk is skipped
//!    silently; the runtime's `.~advance-*` scratch names are not counted; Private,
//!    unrepresentable, nested-repository and ignored untracked entries are counted as
//!    `unversioned`; everything else is a candidate whose disk state is compared with HEAD
//!    through `safe_fs`. At most `MAX_TREE_ADOPT_ENTRIES` entries are examined, and ignored ones
//!    have a bound of their own (they are only ever counted), so a large ignored tree never
//!    keeps a candidate that sorts after it from being recorded;
//! 3. records the uncommitted state its targets' policies ask for (`AdoptPolicy`; candidates of a
//!    `Tree` target always) as **one** `[micro] [runtime:adopt]` commit (`op: adopt`), never as
//!    the user's: the runtime cannot know who wrote those bytes;
//! 4. answers HEAD and disk state after the adopt.
//!
//! Adoption is budgeted (R1): hashing stops at `MAX_ADOPT_BYTES` (the sum is taken from `fstat`
//! before any hashing) or `ADOPT_TIME_BUDGET`, in visit order; whatever is past the budget is
//! counted into `unversioned_count` / `unversioned_bytes`, sets `adopt_incomplete`, and is
//! neither hashed nor written into `.git`. An untracked file that is ignored or over the
//! threshold is never adopted; a tracked one keeps git's semantics.
//!
//! Panic-free: it runs while the coord mutex is held.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use advance_shared_types::workspace_path::{
    classify_lexical, is_agent_dir_name, normalize_workspace_path, policy_skeleton, AccessClass,
    META_SIDECAR_NAME,
};
use advance_shared_types::FileIdentity;
use git2::{ErrorCode, ObjectType, Oid, Status, StatusOptions, Tree};

use crate::commit_queue::branch_guard;
use crate::emit::EmitPlan;
use crate::error::{GitError, UserOpRefusal};
use crate::label::{self, CommitLabel, MAX_LABEL_PATHS, OP_ADOPT};
use crate::lane::{
    ancestors, entry_at, gitignore_rider, head_kind, holds_agent_territory, land, main_state,
    refuse, within, CollisionGuard, HeadKind, Landed, Landing, LaneCtx, Spellings, Touched,
    MAX_ATTEMPTS,
};
use crate::lane_commit::is_oid;
use crate::paths::RepoPath;
use crate::safe_fs::{stream_blob, DiskEntry};
use crate::tree_edit::{self, EntryMode, TreeEdit};
use crate::user_lane::{
    runtime_authorship, signature_time_now, AdoptPolicy, EntryKind, PathState, PrepareOutcome,
    PrepareRequest, PrepareTarget, TreeState, ADOPT_INITIATOR, MAX_TREE_ADOPT_ENTRIES,
};

/// The runtime's scratch-name prefix (its skeleton): never counted as unversioned content.
const SCRATCH_PREFIX: &str = ".~advance-";
/// `unversioned` and `adopted_paths` list at most this many paths (the counts are complete).
const MAX_LISTED: usize = 64;

/// What a path is on disk, as observed once per item.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Obs {
    Absent,
    File {
        /// `None`: over the threshold, past the adopt budget, or changing while read.
        oid: Option<Oid>,
        size: u64,
        identity: FileIdentity,
        executable: bool,
        oversize: bool,
    },
    /// A symlink (never followed): the blob id of its target bytes. The blob is written only
    /// when the link is adopted.
    Link {
        oid: Oid,
        target: Vec<u8>,
    },
    Dir,
    Other,
    SymlinkedParent,
    /// The entry could not be opened or read (permission refused, an I/O error): never
    /// recorded, counted as unversioned.
    Unreadable,
}

/// What the adopt commit does at one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Adopt {
    /// Record a file or a link.
    Put { oid: Oid, mode: EntryMode },
    /// Record that a file or link is gone.
    Remove,
    /// A folder in HEAD is now this file or link.
    ReplaceTree { oid: Oid, mode: EntryMode },
    /// Record that a folder is gone.
    RemoveTree,
}

fn mode_of(executable: bool) -> EntryMode {
    if executable {
        EntryMode::Executable
    } else {
        EntryMode::File
    }
}

/// One item's observations, budget and counters.
struct Scan<'c, 'a> {
    ctx: &'c LaneCtx<'a>,
    /// The spellings HEAD holds for the targets (`lane::Spellings`).
    spellings: Spellings,
    observed: HashMap<String, Obs>,
    clock_start: Duration,
    bytes_used: u64,
    /// Once something did not fit, everything after it is past the budget too (visit order).
    exhausted: bool,
    adopt_incomplete: bool,
    agent_territory: bool,
    counted: HashSet<String>,
    unversioned: Vec<String>,
    unversioned_count: u32,
    unversioned_bytes: u64,
    /// `Tree` candidates, in visit order.
    candidates: Vec<String>,
}

impl<'c, 'a> Scan<'c, 'a> {
    fn new(ctx: &'c LaneCtx<'a>) -> Self {
        Self {
            clock_start: ctx.adopt_clock(),
            ctx,
            spellings: Spellings::default(),
            observed: HashMap::new(),
            bytes_used: 0,
            exhausted: false,
            adopt_incomplete: false,
            agent_territory: false,
            counted: HashSet::new(),
            unversioned: Vec::new(),
            unversioned_count: 0,
            unversioned_bytes: 0,
            candidates: Vec::new(),
        }
    }

    /// Count `path` as content this item does not version (once per path).
    fn count(&mut self, path: &str, bytes: u64) {
        if !self.counted.insert(path.to_string()) {
            return;
        }
        self.unversioned_count = self.unversioned_count.saturating_add(1);
        self.unversioned_bytes = self.unversioned_bytes.saturating_add(bytes);
        if self.unversioned.len() < MAX_LISTED {
            self.unversioned.push(path.to_string());
        }
    }

    /// Admit `size` bytes of hashing (R1): within the byte and time budgets, in visit order.
    fn admit(&mut self, size: u64) -> bool {
        if self.exhausted {
            return false;
        }
        let elapsed = self.ctx.adopt_clock().saturating_sub(self.clock_start);
        let total = self.bytes_used.checked_add(size);
        match total {
            Some(total)
                if total <= self.ctx.limits.max_adopt_bytes
                    && elapsed < self.ctx.limits.adopt_time_budget =>
            {
                self.bytes_used = total;
                true
            }
            _ => {
                self.exhausted = true;
                self.adopt_incomplete = true;
                false
            }
        }
    }

    /// Observe `disk` (a disk spelling) once: classify without following symlinks, hash a
    /// regular file within the threshold and the budget.
    fn observe(&mut self, disk: &str) -> Result<Obs, GitError> {
        if let Some(obs) = self.observed.get(disk) {
            return Ok(obs.clone());
        }
        let obs = match self.ctx.open(disk) {
            Ok(DiskEntry::Absent) => Obs::Absent,
            Ok(DiskEntry::File(mut opened)) => {
                let size = opened.len;
                let oversize = size > self.ctx.max_tracked;
                let oid = if oversize || !self.admit(size) {
                    None
                } else {
                    match stream_blob(self.ctx.repo, &mut opened) {
                        Ok(oid) => Some(oid),
                        // Written to while it was read, or unreadable: not recorded this time.
                        Err(_) => {
                            self.adopt_incomplete = true;
                            None
                        }
                    }
                };
                Obs::File {
                    oid,
                    size,
                    identity: opened.identity,
                    executable: opened.executable,
                    oversize,
                }
            }
            Ok(DiskEntry::Symlink { target }) => Obs::Link {
                oid: Oid::hash_object(ObjectType::Blob, &target)?,
                target,
            },
            Ok(DiskEntry::Dir) => Obs::Dir,
            Ok(DiskEntry::Other) => Obs::Other,
            Ok(DiskEntry::SymlinkedParent) => Obs::SymlinkedParent,
            Err(_) => {
                self.adopt_incomplete = true;
                Obs::Unreadable
            }
        };
        self.observed.insert(disk.to_string(), obs.clone());
        Ok(obs)
    }

    /// The `fstat` size of a counted entry (0 for anything but a regular file).
    fn size_of(&self, disk: &str) -> u64 {
        match self.ctx.open(disk) {
            Ok(DiskEntry::File(opened)) => opened.len,
            _ => 0,
        }
    }

    /// The spelling `base` holds for `tree_path` (`lane::Spellings`).
    fn spell(&mut self, base: Option<&Tree<'_>>, tree_path: &str) -> Result<String, GitError> {
        self.spellings.resolve(self.ctx, base, tree_path)
    }

    /// Observe a `File` target and count what it holds that will not be versioned: content
    /// that was not hashed, an untracked ignored file, a path below a symlinked folder.
    fn file_target(
        &mut self,
        path: &RepoPath,
        tree_path: &str,
        base: Option<&Tree<'_>>,
    ) -> Result<(), GitError> {
        let obs = self.observe(path.given())?;
        match obs {
            Obs::File {
                oid: None, size, ..
            } => self.count(tree_path, size),
            Obs::File {
                oid: Some(_), size, ..
            } => {
                let spelled = self.spell(base, tree_path)?;
                let untracked = entry_at(base, &spelled)?.is_none();
                if untracked && ignored(self.ctx, tree_path)? {
                    self.count(tree_path, size);
                }
            }
            Obs::SymlinkedParent | Obs::Unreadable => self.count(tree_path, 0),
            Obs::Absent | Obs::Link { .. } | Obs::Dir | Obs::Other => {}
        }
        Ok(())
    }

    /// Walk a `Tree` target (MODULE-003 §1.4.1 "`prepare`" table, `Tree{dir}` row).
    fn tree_target(&mut self, dir: &str, base: Option<&Tree<'_>>) -> Result<(), GitError> {
        let ctx = self.ctx;
        let head = if dir.is_empty() {
            base.map(Tree::id)
        } else {
            let spelled = self.spell(base, dir)?;
            entry_at(base, &spelled)?
                .filter(|entry| head_kind(entry) == HeadKind::Tree)
                .map(|entry| entry.id())
        };
        if let Some(subtree) = head {
            if holds_agent_territory(ctx.repo, subtree, ctx.limits.max_restore_paths, dir)? {
                self.agent_territory = true;
            }
        }
        // Ignored entries are only ever counted, so they have a bound of their own and never
        // use up the one of the entries that can be recorded.
        let mut examined = 0usize;
        let mut ignored_seen = 0usize;
        for (path, status) in tree_statuses(ctx, dir)? {
            // A string test, so every entry takes it, past the bounds too.
            if names_agent_territory(&path) {
                self.agent_territory = true;
                continue;
            }
            let seen = if status.contains(Status::IGNORED) {
                &mut ignored_seen
            } else {
                &mut examined
            };
            if *seen >= MAX_TREE_ADOPT_ENTRIES {
                // Past the bound nothing is examined: counted, never adopted.
                self.adopt_incomplete = true;
                self.count(&String::from_utf8_lossy(&path), 0);
                continue;
            }
            *seen = seen.saturating_add(1);
            self.examine(path, status)?;
        }
        Ok(())
    }

    /// Classify one status entry outside agent territory: skipped, counted, or a candidate.
    fn examine(&mut self, raw: Vec<u8>, status: Status) -> Result<(), GitError> {
        let path = match String::from_utf8(raw) {
            Ok(path) => path,
            Err(e) => {
                // A name that is not UTF-8 cannot be addressed or versioned by the lane.
                let lossy = String::from_utf8_lossy(e.as_bytes()).into_owned();
                self.count(&lossy, 0);
                return Ok(());
            }
        };
        let body = path.strip_suffix('/').unwrap_or(&path);
        if path.ends_with('/') {
            // A nested repository (or another folder status cannot enter): never a gitlink.
            self.count(body, 0);
            return Ok(());
        }
        match classify(&path) {
            Class::Junk | Class::Scratch => {}
            Class::Unversionable => {
                let bytes = self.size_of(&path);
                self.count(&path, bytes);
            }
            Class::Versionable if status.contains(Status::IGNORED) => {
                let bytes = self.size_of(&path);
                self.count(&path, bytes);
            }
            Class::Versionable => self.candidates.push(path),
        }
        Ok(())
    }

    /// Hash the `Tree` candidates in visit order (within the budget) and count what stays
    /// unrecorded.
    fn observe_candidates(&mut self) -> Result<(), GitError> {
        let candidates = std::mem::take(&mut self.candidates);
        for path in &candidates {
            match self.observe(path)? {
                Obs::File {
                    oid: None, size, ..
                } => self.count(path, size),
                Obs::Unreadable => self.count(path, 0),
                _ => {}
            }
        }
        self.candidates = candidates;
        Ok(())
    }
}

/// Whether a status path (a trailing `/` marks a folder) has a component named `.agent` (policy
/// fold): agent territory, never adopted (MODULE-003-AC-36).
fn names_agent_territory(raw: &[u8]) -> bool {
    let path = String::from_utf8_lossy(raw);
    path.strip_suffix('/')
        .unwrap_or(&path)
        .split('/')
        .any(is_agent_dir_name)
}

/// How the lane treats a path a status walk found.
enum Class {
    /// OS and editor litter: skipped silently.
    Junk,
    /// The runtime's own scratch names: skipped, not counted.
    Scratch,
    /// Private, or outside the path grammar: kept on disk, counted as unversioned.
    Unversionable,
    /// Normal, a `.meta.yaml` sidecar, or a VCS control file.
    Versionable,
}

fn classify(path: &str) -> Class {
    if path
        .split('/')
        .any(|name| policy_skeleton(name).starts_with(SCRATCH_PREFIX))
    {
        return Class::Scratch;
    }
    let Ok(nfc) = normalize_workspace_path(path, false) else {
        return Class::Unversionable;
    };
    match classify_lexical(&nfc).access {
        AccessClass::Junk { .. } => Class::Junk,
        AccessClass::Private { at_final: true }
            if nfc.rsplit('/').next() == Some(META_SIDECAR_NAME) =>
        {
            Class::Versionable
        }
        AccessClass::Private { .. } => Class::Unversionable,
        AccessClass::Normal | AccessClass::ReadOnly(_) => Class::Versionable,
    }
}

fn ignored(ctx: &LaneCtx<'_>, path: &str) -> Result<bool, GitError> {
    Ok(ctx.repo.status_should_ignore(Path::new(path))?)
}

/// The status entries under `dir` (the vault root when empty), sorted by path bytes:
/// untracked and ignored files included (recursively), submodules excluded. Smudged index
/// entries that turn out clean get their stat refreshed (`update_index`); when the index is
/// locked by another writer the walk runs without that refresh.
fn tree_statuses(ctx: &LaneCtx<'_>, dir: &str) -> Result<Vec<(Vec<u8>, Status)>, GitError> {
    if dir.contains('\0') {
        return Err(refuse(UserOpRefusal::InvalidPath, dir));
    }
    let options = |refresh: bool| {
        let mut opts = StatusOptions::new();
        opts.include_untracked(true)
            .recurse_untracked_dirs(true)
            .include_ignored(true)
            .recurse_ignored_dirs(true)
            .exclude_submodules(true)
            .disable_pathspec_match(true)
            .update_index(refresh);
        if !dir.is_empty() {
            opts.pathspec(dir);
        }
        opts
    };
    let statuses = match ctx.repo.statuses(Some(&mut options(true))) {
        Ok(statuses) => statuses,
        Err(e) if e.code() == ErrorCode::Locked => ctx.repo.statuses(Some(&mut options(false)))?,
        Err(e) => return Err(e.into()),
    };
    let mut entries: Vec<(Vec<u8>, Status)> = statuses
        .iter()
        .map(|entry| (entry.path_bytes().to_vec(), entry.status()))
        .filter(|(path, _)| {
            std::str::from_utf8(path).map_or(true, |p| within(dir, p, ctx.facts.index_fold))
        })
        .collect();
    entries.sort();
    Ok(entries)
}

/// Decide the adopt for a `File` target (MODULE-003 §1.4.1 "`prepare`" table).
fn decide_file(
    ctx: &LaneCtx<'_>,
    policy: &AdoptPolicy,
    tree_path: &str,
    head: Option<&git2::TreeEntry<'_>>,
    obs: &Obs,
) -> Result<Option<Adopt>, GitError> {
    let untracked_ignored =
        || -> Result<bool, GitError> { Ok(head.is_none() && ignored(ctx, tree_path)?) };
    if head.map(head_kind) == Some(HeadKind::Gitlink) {
        // The lane never records over a submodule.
        return Ok(None);
    }
    match policy {
        AdoptPolicy::Never => Ok(None),
        AdoptPolicy::IfDiskIs(base) => {
            let Ok(base) = Oid::from_str(base) else {
                return Ok(None);
            };
            let head_oid = head.map(git2::TreeEntry::id);
            let adopt = match obs {
                Obs::File {
                    oid: Some(disk),
                    executable,
                    ..
                } if *disk == base && head_oid != Some(base) => Some(Adopt::Put {
                    oid: *disk,
                    mode: mode_of(*executable),
                }),
                Obs::Link { oid, .. } if *oid == base && head_oid != Some(base) => {
                    Some(Adopt::Put {
                        oid: *oid,
                        mode: EntryMode::Link,
                    })
                }
                _ => None,
            };
            if adopt.is_some() && untracked_ignored()? {
                return Ok(None);
            }
            Ok(adopt.map(|a| with_head_shape(a, head)))
        }
        AdoptPolicy::IfDiskAbsent => Ok(match (obs, head.map(head_kind)) {
            (Obs::Absent, Some(HeadKind::Tree)) => Some(Adopt::RemoveTree),
            (Obs::Absent, Some(HeadKind::File { .. } | HeadKind::Link)) => Some(Adopt::Remove),
            _ => None,
        }),
        AdoptPolicy::Always => {
            let adopt = decide_always(head, obs);
            if matches!(adopt, Some(Adopt::Put { .. })) && untracked_ignored()? {
                return Ok(None);
            }
            Ok(adopt)
        }
    }
}

/// A put over a folder in HEAD replaces the folder (an explicit type change).
fn with_head_shape(adopt: Adopt, head: Option<&git2::TreeEntry<'_>>) -> Adopt {
    match (adopt, head.map(head_kind)) {
        (Adopt::Put { oid, mode }, Some(HeadKind::Tree)) => Adopt::ReplaceTree { oid, mode },
        (adopt, _) => adopt,
    }
}

/// `Always`: record whatever differs from HEAD (an untracked file included). Content that was
/// not hashed (over the threshold or the budget) and special files are left alone.
fn decide_always(head: Option<&git2::TreeEntry<'_>>, obs: &Obs) -> Option<Adopt> {
    let kind = head.map(head_kind);
    if kind == Some(HeadKind::Gitlink) {
        return None;
    }
    let same = |oid: Oid, mode: EntryMode| {
        head.is_some_and(|entry| {
            entry.id() == oid
                && match head_kind(entry) {
                    HeadKind::File { executable } => mode == mode_of(executable),
                    HeadKind::Link => mode == EntryMode::Link,
                    HeadKind::Tree | HeadKind::Gitlink => false,
                }
        })
    };
    let put = |oid: Oid, mode: EntryMode| {
        if same(oid, mode) {
            None
        } else {
            Some(with_head_shape(Adopt::Put { oid, mode }, head))
        }
    };
    match obs {
        Obs::Absent => match kind {
            Some(HeadKind::Tree) => Some(Adopt::RemoveTree),
            Some(_) => Some(Adopt::Remove),
            None => None,
        },
        Obs::File {
            oid: Some(oid),
            executable,
            ..
        } => put(*oid, mode_of(*executable)),
        Obs::Link { oid, .. } => put(*oid, EntryMode::Link),
        // A file in HEAD is a folder on disk now: the file is gone (the folder's own files
        // are separate candidates).
        Obs::Dir => match kind {
            Some(HeadKind::File { .. } | HeadKind::Link) => Some(Adopt::Remove),
            _ => None,
        },
        Obs::File { oid: None, .. } | Obs::Other | Obs::SymlinkedParent | Obs::Unreadable => None,
    }
}

/// An adopted symlink's blob (its target bytes) is written when the link is adopted.
fn store_link(ctx: &LaneCtx<'_>, obs: &Obs) -> Result<(), GitError> {
    if let Obs::Link { target, .. } = obs {
        ctx.repo.blob(target)?;
    }
    Ok(())
}

/// The adopt commit's edits for one parent tree, its adopted paths and its touched paths.
struct Decision {
    edits: Vec<TreeEdit>,
    adopted: Vec<String>,
    labels: Vec<String>,
    touched: Touched,
}

/// Re-make every adopt decision against `base` from the cached observations, then drop what the
/// tree cannot take: anything below a folder the adopt removes or replaces, a new path below a
/// file the adopt keeps, a folder removal that would carry an agent territory, and (under
/// `core.ignorecase`) a new path that folds equal to an existing entry. Each path is decided
/// and recorded at the spelling `base` holds for it.
fn decide(
    scan: &mut Scan<'_, '_>,
    files: &[(&RepoPath, &AdoptPolicy, String)],
    base: Option<&Tree<'_>>,
) -> Result<Decision, GitError> {
    let ctx = scan.ctx;
    let mut wanted: BTreeMap<String, Adopt> = BTreeMap::new();
    for (path, policy, tree_path) in files {
        let obs = scan.observe(path.given())?;
        let spelled = scan.spell(base, tree_path)?;
        let head = entry_at(base, &spelled)?;
        if let Some(adopt) = decide_file(ctx, policy, tree_path, head.as_ref(), &obs)? {
            store_link(ctx, &obs)?;
            wanted.insert(spelled, adopt);
        }
    }
    let candidates = scan.candidates.clone();
    for path in &candidates {
        let obs = scan.observe(path)?;
        let spelled = scan.spell(base, path)?;
        let head = entry_at(base, &spelled)?;
        if let Some(adopt) = decide_always(head.as_ref(), &obs) {
            if !wanted.contains_key(&spelled) {
                store_link(ctx, &obs)?;
                wanted.insert(spelled, adopt);
            }
        }
    }
    // Folder removals never carry an agent territory.
    let mut kept: BTreeMap<String, Adopt> = BTreeMap::new();
    for (path, adopt) in wanted {
        if matches!(adopt, Adopt::RemoveTree | Adopt::ReplaceTree { .. }) {
            let subtree = entry_at(base, &path)?.map(|entry| entry.id());
            if let Some(subtree) = subtree {
                if holds_agent_territory(ctx.repo, subtree, ctx.limits.max_restore_paths, &path)? {
                    scan.agent_territory = true;
                    continue;
                }
            }
        }
        kept.insert(path, adopt);
    }
    let removed_folders: HashSet<String> = kept
        .iter()
        .filter(|(_, adopt)| matches!(adopt, Adopt::RemoveTree | Adopt::ReplaceTree { .. }))
        .map(|(path, _)| path.clone())
        .collect();
    let mut guard = CollisionGuard::default();
    let none: HashSet<String> = HashSet::new();
    let mut decision = Decision {
        edits: Vec::new(),
        adopted: Vec::new(),
        labels: Vec::new(),
        touched: Touched::default(),
    };
    for (path, adopt) in &kept {
        if ancestors(path).any(|a| removed_folders.contains(a)) {
            continue;
        }
        let puts = matches!(adopt, Adopt::Put { .. } | Adopt::ReplaceTree { .. });
        if puts {
            let mut blocked = false;
            for ancestor in ancestors(path) {
                blocked |= match kept.get(ancestor) {
                    Some(Adopt::Remove) => false,
                    Some(_) => true,
                    None => entry_at(base, ancestor)?
                        .is_some_and(|entry| head_kind(&entry) != HeadKind::Tree),
                };
            }
            let new = entry_at(base, path)?.is_none();
            if !blocked && new && ctx.facts.ignorecase {
                blocked = guard.check(ctx.repo, base, path, &none).is_err();
            }
            if blocked {
                let bytes = scan.size_of(path);
                scan.count(path, bytes);
                continue;
            }
        }
        match *adopt {
            Adopt::Put { oid, mode } => {
                decision.edits.push(TreeEdit::Upsert {
                    path: path.clone(),
                    oid,
                    mode,
                });
                decision.touched.file(path);
                decision.labels.push(path.clone());
            }
            Adopt::Remove => {
                decision.edits.push(TreeEdit::Remove { path: path.clone() });
                decision.touched.file(path);
                decision.labels.push(path.clone());
            }
            Adopt::ReplaceTree { oid, mode } => {
                decision.edits.push(TreeEdit::Remove { path: path.clone() });
                decision.edits.push(TreeEdit::Upsert {
                    path: path.clone(),
                    oid,
                    mode,
                });
                decision.touched.dir(path);
                decision.labels.push(path.clone());
            }
            Adopt::RemoveTree => {
                decision.edits.push(TreeEdit::Remove { path: path.clone() });
                decision.touched.dir(path);
                decision.labels.push(format!("{path}/"));
            }
        }
        decision.adopted.push(path.clone());
    }
    Ok(decision)
}

/// Run one `prepare` item (see the module docs).
/// One `prepare` item's answer plus the events the worker emits after L2.
pub(crate) struct PrepareItemResult {
    pub outcome: PrepareOutcome,
    pub emit: EmitPlan,
    pub refresh_repo: bool,
}

pub(crate) struct Adopted {
    pub sha: Oid,
    pub paths: Vec<String>,
    pub parent_tree: Option<Oid>,
    pub new_tree: Oid,
    pub subject: String,
    pub agent_id: String,
}

/// One adopt step's commit (if any) and the counters the caller reports.
pub(crate) struct AdoptRun {
    pub adopted: Option<Adopted>,
    pub adopt_incomplete: bool,
    pub unversioned: Vec<String>,
    pub unversioned_count: u32,
    pub unversioned_bytes: u64,
}

impl AdoptRun {
    pub(crate) fn emit(&self, correlation_id: Option<&str>) -> EmitPlan {
        match &self.adopted {
            Some(a) => EmitPlan::adopt(
                &a.agent_id,
                ADOPT_INITIATOR,
                &a.subject,
                &a.sha.to_string(),
                correlation_id,
                a.paths.clone(),
                a.parent_tree,
                a.new_tree,
            ),
            None => EmitPlan::none(),
        }
    }

    pub(crate) fn sha_hex(&self) -> Option<String> {
        self.adopted.as_ref().map(|a| a.sha.to_string())
    }
}

fn finish_run(scan: Scan<'_, '_>, adopted: Option<Adopted>) -> AdoptRun {
    AdoptRun {
        adopted,
        adopt_incomplete: scan.adopt_incomplete,
        unversioned: scan.unversioned,
        unversioned_count: scan.unversioned_count,
        unversioned_bytes: scan.unversioned_bytes,
    }
}

/// Land one `[micro] [runtime:adopt]` commit from the scan's observations, or none
/// when the tree already matches disk.
fn land_adopt(
    scan: &mut Scan<'_, '_>,
    files: &[(&RepoPath, &AdoptPolicy, String)],
) -> Result<Option<Adopted>, GitError> {
    let ctx = scan.ctx;
    let mut adopted: Option<Adopted> = None;
    let mut moved: Option<(Option<Oid>, Option<Oid>)> = None;
    for _ in 0..MAX_ATTEMPTS {
        moved = None;
        let (tip, base) = main_state(ctx.repo)?;
        let mut decision = decide(scan, files, base.as_ref())?;
        if decision.edits.is_empty() {
            break;
        }
        let label = CommitLabel {
            op: OP_ADOPT.to_string(),
            paths: decision
                .labels
                .iter()
                .take(MAX_LABEL_PATHS)
                .cloned()
                .collect(),
            count: u32::try_from(decision.labels.len()).unwrap_or(u32::MAX),
            ..CommitLabel::default()
        };
        let subject = label::render_subject(&label).ok_or_else(op_shape)?;
        let message = label::render_message(&label, ADOPT_INITIATOR, None).ok_or_else(op_shape)?;
        gitignore_rider(
            ctx,
            base.as_ref(),
            &mut decision.edits,
            &mut decision.touched,
        )?;
        let tree = tree_edit::build_tree(ctx.repo, base.as_ref(), &decision.edits)?;
        let authorship = runtime_authorship(ADOPT_INITIATOR, &signature_time_now())?;
        let landing = Landing {
            parent: tip,
            tree,
            message: &message,
            subject: &subject,
            authorship: &authorship,
            touched: &decision.touched,
            stats: &[],
        };
        match land(ctx, &landing)? {
            Landed::Committed(sha) => {
                adopted = Some(Adopted {
                    sha,
                    paths: decision.adopted,
                    parent_tree: base.as_ref().map(Tree::id),
                    new_tree: tree,
                    subject,
                    agent_id: authorship.event_agent_id.clone(),
                });
                break;
            }
            Landed::HeadMoved(now) => moved = Some((tip, now)),
        }
    }
    if let Some((expected, actual)) = moved {
        return Err(GitError::HeadMoved {
            expected: expected.map(|oid| oid.to_string()),
            actual: actual.map(|oid| oid.to_string()),
        });
    }
    Ok(adopted)
}

/// R1 save-version adopt: tracked dirty paths, plus untracked content only under
/// `explicit` (never a whole-vault Tree walk).
pub(crate) fn adopt_for_version(
    ctx: &LaneCtx<'_>,
    explicit: &[RepoPath],
    _correlation_id: Option<&str>,
) -> Result<AdoptRun, GitError> {
    let always = AdoptPolicy::Always;
    let mut owned: Vec<(RepoPath, String)> = Vec::new();
    let mut trees: Vec<String> = Vec::new();
    let mut scan = Scan::new(ctx);
    let (_, base) = main_state(ctx.repo)?;
    for (raw, status) in tracked_dirty_statuses(ctx)? {
        if names_agent_territory(&raw) {
            continue;
        }
        let path = match String::from_utf8(raw) {
            Ok(path) => path,
            Err(e) => {
                scan.count(&String::from_utf8_lossy(e.as_bytes()), 0);
                continue;
            }
        };
        match classify(&path) {
            Class::Junk | Class::Scratch => {}
            Class::Unversionable => {
                let bytes = scan.size_of(&path);
                scan.count(&path, bytes);
            }
            Class::Versionable => {
                if status.contains(Status::IGNORED) {
                    let bytes = scan.size_of(&path);
                    scan.count(&path, bytes);
                } else {
                    scan.candidates.push(path);
                }
            }
        }
    }
    for path in explicit {
        if path.is_root() {
            continue;
        }
        let tree_path = path.tree_spelling(ctx.facts.precompose).to_string();
        let obs = scan.observe(path.given())?;
        let head_tree = entry_at(base.as_ref(), &tree_path)?
            .filter(|entry| head_kind(entry) == HeadKind::Tree)
            .is_some();
        if matches!(obs, Obs::Dir) || head_tree {
            trees.push(tree_path);
        } else {
            owned.push((path.clone(), tree_path));
        }
    }
    for dir in &trees {
        scan.tree_target(dir, base.as_ref())?;
    }
    let files: Vec<(&RepoPath, &AdoptPolicy, String)> = owned
        .iter()
        .map(|(path, tree_path)| (path, &always, tree_path.clone()))
        .collect();
    for (path, _, tree_path) in &files {
        scan.file_target(path, tree_path, base.as_ref())?;
    }
    scan.observe_candidates()?;
    let adopted = land_adopt(&mut scan, &files)?;
    Ok(finish_run(scan, adopted))
}

/// Adopt the named paths (`Always`) — restore_tree's pre-checkout record of dirty
/// plan paths and shape prefixes.
pub(crate) fn adopt_named_paths(
    ctx: &LaneCtx<'_>,
    paths: &[String],
    _correlation_id: Option<&str>,
) -> Result<AdoptRun, GitError> {
    let mut scan = Scan::new(ctx);
    for path in paths {
        if path.is_empty() || names_agent_territory(path.as_bytes()) {
            continue;
        }
        match classify(path) {
            Class::Junk | Class::Scratch => {}
            Class::Unversionable => {
                let bytes = scan.size_of(path);
                scan.count(path, bytes);
            }
            Class::Versionable => scan.candidates.push(path.clone()),
        }
    }
    scan.observe_candidates()?;
    let adopted = land_adopt(&mut scan, &[])?;
    Ok(finish_run(scan, adopted))
}

/// Tracked entries whose disk or index differs from HEAD (untracked omitted).
fn tracked_dirty_statuses(ctx: &LaneCtx<'_>) -> Result<Vec<(Vec<u8>, Status)>, GitError> {
    let options = |refresh: bool| {
        let mut opts = StatusOptions::new();
        opts.include_untracked(false)
            .include_ignored(true)
            .recurse_ignored_dirs(false)
            .exclude_submodules(true)
            .disable_pathspec_match(true)
            .update_index(refresh);
        opts
    };
    let statuses = match ctx.repo.statuses(Some(&mut options(true))) {
        Ok(statuses) => statuses,
        Err(e) if e.code() == ErrorCode::Locked => ctx.repo.statuses(Some(&mut options(false)))?,
        Err(e) => return Err(e.into()),
    };
    let mut entries: Vec<(Vec<u8>, Status)> = statuses
        .iter()
        .filter(|entry| {
            let status = entry.status();
            !status.is_empty() && !status.contains(Status::WT_NEW)
        })
        .map(|entry| (entry.path_bytes().to_vec(), entry.status()))
        .collect();
    entries.sort();
    Ok(entries)
}

pub(crate) fn exec_prepare(
    ctx: &LaneCtx<'_>,
    req: &PrepareRequest,
) -> Result<PrepareItemResult, GitError> {
    let mut files: Vec<(&RepoPath, &AdoptPolicy, String)> = Vec::new();
    let mut trees: Vec<String> = Vec::new();
    for target in &req.targets {
        match target {
            PrepareTarget::File { path, adopt } => {
                if path.is_root() {
                    return Err(refuse(UserOpRefusal::InvalidPath, ""));
                }
                if let AdoptPolicy::IfDiskIs(oid) = adopt {
                    if !is_oid(oid) {
                        return Err(refuse(UserOpRefusal::OpShape, path.nfc()));
                    }
                }
                files.push((
                    path,
                    adopt,
                    path.tree_spelling(ctx.facts.precompose).to_string(),
                ));
            }
            PrepareTarget::Tree { dir } => {
                trees.push(dir.tree_spelling(ctx.facts.precompose).to_string());
            }
        }
    }
    branch_guard(ctx.repo)?;
    let mut scan = Scan::new(ctx);
    let (_, base) = main_state(ctx.repo)?;
    for (path, _, tree_path) in &files {
        scan.file_target(path, tree_path, base.as_ref())?;
    }
    for dir in &trees {
        scan.tree_target(dir, base.as_ref())?;
    }
    scan.observe_candidates()?;
    let adopted = land_adopt(&mut scan, &files)?;

    let (tip, base) = main_state(ctx.repo)?;
    let mut states = Vec::with_capacity(files.len());
    for (path, _, tree_path) in &files {
        let obs = scan.observe(path.given())?;
        let spelled = scan.spell(base.as_ref(), tree_path)?;
        states.push(path_state(ctx, &spelled, base.as_ref(), &obs)?);
    }
    let mut tree_states = Vec::with_capacity(trees.len());
    for dir in &trees {
        let head_tree_oid = if dir.is_empty() {
            base.as_ref().map(Tree::id)
        } else {
            let spelled = scan.spell(base.as_ref(), dir)?;
            entry_at(base.as_ref(), &spelled)?
                .filter(|entry| head_kind(entry) == HeadKind::Tree)
                .map(|entry| entry.id())
        };
        tree_states.push(TreeState {
            dir: dir.clone(),
            head_tree_oid: head_tree_oid.map(|oid| oid.to_string()),
        });
    }
    let run = AdoptRun {
        adopted,
        adopt_incomplete: scan.adopt_incomplete,
        unversioned: scan.unversioned.clone(),
        unversioned_count: scan.unversioned_count,
        unversioned_bytes: scan.unversioned_bytes,
    };
    let emit = run.emit(req.correlation_id.as_deref());
    let (adopted_sha, adopted_paths) = match run.adopted {
        Some(a) => (Some(a.sha.to_string()), a.paths),
        None => (None, Vec::new()),
    };
    Ok(PrepareItemResult {
        outcome: PrepareOutcome {
            head_sha: tip.map(|oid| oid.to_string()),
            adopted_sha,
            adopted_count: u32::try_from(adopted_paths.len()).unwrap_or(u32::MAX),
            adopted_paths: adopted_paths.into_iter().take(MAX_LISTED).collect(),
            states,
            tree_states,
            unversioned: run.unversioned,
            unversioned_count: run.unversioned_count,
            unversioned_bytes: run.unversioned_bytes,
            agent_territory: scan.agent_territory,
            adopt_incomplete: scan.adopt_incomplete,
        },
        emit,
        refresh_repo: false,
    })
}

fn op_shape() -> GitError {
    GitError::InvalidUserOp {
        reason: UserOpRefusal::OpShape,
        path: None,
    }
}

/// One `File` target's state after any adopt.
fn path_state(
    ctx: &LaneCtx<'_>,
    tree_path: &str,
    base: Option<&Tree<'_>>,
    obs: &Obs,
) -> Result<PathState, GitError> {
    let head = entry_at(base, tree_path)?;
    let head_kind = head.as_ref().map(|entry| match head_kind(entry) {
        HeadKind::File { .. } => EntryKind::File,
        HeadKind::Link => EntryKind::Symlink,
        HeadKind::Tree => EntryKind::Dir,
        HeadKind::Gitlink => EntryKind::Other,
    });
    let (disk_oid, disk_kind, identity, size, oversize) = match obs {
        Obs::Absent => (None, None, None, None, false),
        Obs::File {
            oid,
            size,
            identity,
            oversize,
            ..
        } => (
            *oid,
            Some(EntryKind::File),
            Some(*identity),
            Some(*size),
            *oversize,
        ),
        Obs::Link { oid, .. } => (Some(*oid), Some(EntryKind::Symlink), None, None, false),
        Obs::Dir => (None, Some(EntryKind::Dir), None, None, false),
        Obs::Other | Obs::SymlinkedParent | Obs::Unreadable => {
            (None, Some(EntryKind::Other), None, None, false)
        }
    };
    Ok(PathState {
        path: tree_path.to_string(),
        head_oid: head.as_ref().map(|entry| entry.id().to_string()),
        head_kind,
        disk_oid: disk_oid.map(|oid| oid.to_string()),
        disk_kind,
        identity,
        tracked: head.is_some(),
        ignored: ignored(ctx, tree_path)?,
        oversize,
        size,
    })
}
