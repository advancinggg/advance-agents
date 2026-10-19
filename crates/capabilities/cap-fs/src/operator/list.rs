//! List / stat / search over a cached sorted snapshot (oss-fs-core §3.2–§3.3).
//!
//! Hidden/Junk/`.runtime` (Private) names are never listed. Kind comes from
//! `d_type` (`DT_UNKNOWN` → `statat`). Natural order lives in
//! `advance_shared_types::natural_order`. The listing fingerprint is
//! `hex16(sha256(sort params ‖ sorted names))`.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use advance_git::{blob_oid_of_bytes, HistoryError};
use advance_shared_types::file_identity::{unix_time_ns, FileIdentity};
use advance_shared_types::media_type::content_type_for_name;
use advance_shared_types::natural_order::{compare, EntryOrder};
use advance_shared_types::workspace_path::{
    classify_component, gate, is_agent_dir_name, is_dotfile_name, normalize_workspace_path, to_nfc,
    AccessClass, ComponentClass, PathUse, ReadOnlyReason,
};
use rustix::fs::{fstat, statat, AtFlags, Dir, FileType};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use super::fsops::{
    is_locked, mtime_ns, open_dir_nofollow, open_regular_at, stat_dev, stat_ino, statat_nofollow,
    DirChain,
};
use super::identity::{hash_opened_file, IdentityError};
use super::policy::{classify_h1, PhysicalFacts};
use super::vcs::VcsPathState;
use super::{FilesError, OperatorFiles, LIST_SCAN_CAP};

/// Default page size (INTEGRATED §3.5).
pub const LIST_DEFAULT_LIMIT: usize = 200;
/// Transport page cap.
pub const LIST_MAX_PAGE_LIMIT: usize = 500;
/// Search default / max (INTEGRATED §3.5).
pub const SEARCH_DEFAULT_LIMIT: usize = 50;
pub const SEARCH_MAX_LIMIT: usize = 200;
pub const SEARCH_MAX_QUERY: usize = 128;
pub const SEARCH_MAX_VISITS: usize = 50_000;
pub const SEARCH_BUDGET: Duration = Duration::from_millis(250);
const LISTING_CACHE_CAP: usize = 32;

/// Listing sort key (oss-fs-core §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListSort {
    Name,
    Kind,
    Size,
    Modified,
}

impl ListSort {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Kind => "kind",
            Self::Size => "size",
            Self::Modified => "modified",
        }
    }
}

impl Default for ListSort {
    fn default() -> Self {
        Self::Name
    }
}

/// `ClientFileEntry.kind` (X26): `dir` everywhere, never `directory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

impl EntryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }

    pub const fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }
}

/// One listed / stated entry. Meta decoration is OSS-5c; this slice fills
/// physical facts, territory / foreign-repo flags, and optional VCS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub modified_ns: Option<i64>,
    pub oid: Option<String>,
    pub vcs: Option<VcsPathState>,
    pub content_type: Option<&'static str>,
    pub read_only: bool,
    pub read_only_reason: Option<ReadOnlyReason>,
    pub territory_root: bool,
    pub foreign_repo: bool,
    pub mount_point: bool,
    pub dotfile: bool,
    pub package: bool,
}

/// `FilesListQuery` shape the adapter maps (oss-fs-core §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListQuery {
    pub dir: String,
    pub offset: usize,
    pub fingerprint: Option<String>,
    pub limit: usize,
    pub sort: ListSort,
    pub descending: bool,
    pub folders_first: bool,
}

impl Default for ListQuery {
    fn default() -> Self {
        Self {
            dir: String::new(),
            offset: 0,
            fingerprint: None,
            limit: LIST_DEFAULT_LIMIT,
            sort: ListSort::Name,
            descending: false,
            folders_first: false,
        }
    }
}

/// `DirListing` the adapter maps to `ClientFileList`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirListing {
    pub path: String,
    pub entries: Vec<ListEntry>,
    pub total: usize,
    pub next_offset: Option<usize>,
    pub fingerprint: String,
    pub skipped_unsupported: usize,
    pub truncated: bool,
    pub vcs_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatQuery {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatResult {
    pub entry: ListEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    pub path: String,
    pub q: String,
    pub limit: usize,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            path: String::new(),
            q: String::new(),
            limit: SEARCH_DEFAULT_LIMIT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    pub query: String,
    pub path: String,
    pub items: Vec<ListEntry>,
    pub truncated: bool,
    pub visited: usize,
}

/// H2: an unstable file above this size stays readable; oid may be omitted
/// (identity-fingerprint ETag). Never [`FilesError::FileBusy`].
pub const UNSTABLE_READ_OID_THRESHOLD: u64 = 16 * 1024 * 1024;

/// `FilesReadQuery` shape the adapter maps (INTEGRATED §3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadQuery {
    pub path: String,
    pub rev: Option<String>,
    pub want_oid: bool,
}

/// Working-tree or historical identity the raw ticket / GET consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadVersion {
    pub path: String,
    pub size: u64,
    pub content_type: String,
    pub oid: Option<String>,
    pub identity: Option<FileIdentity>,
    pub rev: Option<String>,
    pub already_current: bool,
}

/// Bytes for a historical `rev`; a verified working-tree path for streaming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadSource {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct DirCacheKey {
    dev: u64,
    ino: u64,
    mtime_ns: i64,
}

#[derive(Clone)]
struct SnapEntry {
    name: String,
    kind: EntryKind,
    size: u64,
    mtime_ns: i64,
    st_dev: u64,
    stated: bool,
}

impl SnapEntry {
    fn is_dir(&self) -> bool {
        self.kind.is_dir()
    }
}

struct RawSnapshot {
    entries: Vec<SnapEntry>,
    skipped_unsupported: usize,
    truncated: bool,
}

/// LRU of 32 directory snapshots keyed by `(dev, ino, mtime_ns)`.
pub(crate) struct ListingCache {
    cap: usize,
    map: HashMap<DirCacheKey, Arc<RawSnapshot>>,
    order: VecDeque<DirCacheKey>,
}

impl ListingCache {
    pub(crate) fn new() -> Self {
        Self {
            cap: LISTING_CACHE_CAP,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &DirCacheKey) -> Option<Arc<RawSnapshot>> {
        if self.map.contains_key(key) {
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
                self.order.push_back(*key);
            }
            self.map.get(key).cloned()
        } else {
            None
        }
    }

    fn insert(&mut self, key: DirCacheKey, snap: Arc<RawSnapshot>) {
        if self.map.contains_key(&key) {
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
        } else if self.map.len() >= self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.order.push_back(key);
        self.map.insert(key, snap);
    }
}

impl OperatorFiles {
    /// Synchronous, lock-free vs L1: one readdir snapshot, then page.
    pub fn list(&self, query: &ListQuery) -> Result<DirListing, FilesError> {
        let rel = normalize_workspace_path(&query.dir, true).map_err(FilesError::InvalidPath)?;
        let chain = DirChain::walk_dir(&self.root, &rel)?;
        let need_stat = matches!(query.sort, ListSort::Size | ListSort::Modified);
        let snap = self.cached_snapshot(&chain, need_stat)?;
        let mut entries = snap.entries.clone();
        let order = EntryOrder {
            folders_first: query.folders_first,
            descending: query.descending,
        };
        sort_snapshot(&mut entries, query.sort, order);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        let fingerprint =
            listing_fingerprint(query.sort, query.descending, query.folders_first, &names);
        if query.offset > 0 {
            if let Some(expected) = query.fingerprint.as_deref() {
                if expected != fingerprint {
                    return Err(FilesError::ListingChanged);
                }
            }
        }
        let total = entries.len();
        let limit = page_limit(query.limit);
        let start = query.offset.min(total);
        let end = start.saturating_add(limit).min(total);
        let page = &entries[start..end];
        let parent_is_agent = chain.parent_is_agent();
        let parent_dev = chain.current_dev();
        let parent_facts = chain.facts();
        let vcs_available = self.vcs.is_some();
        let mut out = Vec::with_capacity(page.len());
        for snap_ent in page {
            out.push(self.decorate(
                chain.current_fd(),
                &rel,
                snap_ent,
                parent_is_agent,
                parent_dev,
                parent_facts,
                true,
            )?);
        }
        let next_offset = if end < total { Some(end) } else { None };
        Ok(DirListing {
            path: rel,
            entries: out,
            total,
            next_offset,
            fingerprint,
            skipped_unsupported: snap.skipped_unsupported,
            truncated: snap.truncated,
            vcs_available,
        })
    }

    pub fn stat(&self, query: &StatQuery) -> Result<StatResult, FilesError> {
        let rel = normalize_workspace_path(&query.path, true).map_err(FilesError::InvalidPath)?;
        if rel.is_empty() {
            let st = fstat(self.root.fd()).map_err(|e| FilesError::Io(e.to_string()))?;
            let snap = SnapEntry {
                name: String::new(),
                kind: EntryKind::Dir,
                size: st.st_size as u64,
                mtime_ns: mtime_ns(&st),
                st_dev: stat_dev(&st),
                stated: true,
            };
            let entry = self.decorate(
                self.root.fd(),
                "",
                &snap,
                false,
                self.root.st_dev(),
                PhysicalFacts::workspace_root(),
                true,
            )?;
            return Ok(StatResult { entry });
        }
        let (chain, leaf) = DirChain::walk_parent(&self.root, &rel)?;
        gate_hidden_leaf(&leaf, chain.parent_is_agent())?;
        let st = match statat_nofollow(chain.current_fd(), &leaf) {
            Ok(st) => st,
            Err(FilesError::NotFound) => {
                let resolved = super::fsops::resolve_component_name(chain.current_fd(), &leaf)?;
                statat_nofollow(chain.current_fd(), &resolved)?
            }
            Err(e) => return Err(e),
        };
        let stored = leaf_stored_name(chain.current_fd(), &leaf, &st)?;
        gate_hidden_leaf(&stored, chain.parent_is_agent())?;
        let kind = kind_from_file_type(FileType::from_raw_mode(st.st_mode));
        let snap = SnapEntry {
            name: stored,
            kind,
            size: st.st_size as u64,
            mtime_ns: mtime_ns(&st),
            st_dev: stat_dev(&st),
            stated: true,
        };
        let parent_rel = match rel.rsplit_once('/') {
            Some((p, _)) => p.to_string(),
            None => String::new(),
        };
        let entry = self.decorate(
            chain.current_fd(),
            &parent_rel,
            &snap,
            chain.parent_is_agent(),
            chain.current_dev(),
            chain.facts(),
            true,
        )?;
        Ok(StatResult { entry })
    }

    pub fn search(&self, query: &SearchQuery) -> Result<SearchResult, FilesError> {
        if query.q.len() > SEARCH_MAX_QUERY {
            return Err(FilesError::InvalidPath(
                advance_shared_types::workspace_path::PathDefect::TooLong,
            ));
        }
        let rel = normalize_workspace_path(&query.path, true).map_err(FilesError::InvalidPath)?;
        let chain = DirChain::walk_dir(&self.root, &rel)?;
        let q_fold = fold_name(&query.q);
        if q_fold.is_empty() {
            return Ok(SearchResult {
                query: query.q.clone(),
                path: rel,
                items: Vec::new(),
                truncated: false,
                visited: 0,
            });
        }
        let limit = search_limit(query.limit);
        let start = Instant::now();
        let mut items = Vec::new();
        let mut visited = 0usize;
        let truncated = search_dir(
            chain.current_fd(),
            &rel,
            chain.parent_is_agent(),
            chain.current_dev(),
            chain.facts(),
            &q_fold,
            start,
            &mut visited,
            &mut items,
            limit,
            0,
            self,
        )?;
        Ok(SearchResult {
            query: query.q.clone(),
            path: rel,
            items,
            truncated,
            visited,
        })
    }

    /// NFC walk + `O_NOFOLLOW`. Historical `rev` is a commit sha via [`VcsReadPort`].
    /// H2: a file that is unstable or >16 MiB is still readable; oid may be
    /// omitted. Instability never becomes [`FilesError::FileBusy`].
    pub fn prepare_read(&self, query: &ReadQuery) -> Result<ReadVersion, FilesError> {
        let rel = lexical_read_path(&query.path)?;
        if let Some(rev) = query.rev.as_deref() {
            return self.prepare_historical(&rel, rev, query.want_oid);
        }
        let (chain, stored) = self.open_regular_leaf(&rel)?;
        let file = open_regular_at(chain.current_fd(), &stored)?;
        let meta = file.metadata().map_err(|e| FilesError::Io(e.to_string()))?;
        let identity = FileIdentity::from_metadata(&meta);
        let oid = self.oid_for_opened(&file, &identity, query.want_oid);
        Ok(ReadVersion {
            path: rel,
            size: identity.size,
            content_type: content_type_for_name(&stored).to_string(),
            oid,
            identity: Some(identity),
            rev: None,
            already_current: false,
        })
    }

    /// Re-walks the working tree (or re-reads the commit) and returns a stream
    /// source. The path is never followed as a symlink.
    pub fn open_read(&self, path: &str, version: &ReadVersion) -> Result<ReadSource, FilesError> {
        let rel = lexical_read_path(path)?;
        if let Some(rev) = version.rev.as_deref() {
            let port = self
                .vcs
                .as_ref()
                .ok_or(FilesError::VcsUnavailable { reason: "repo" })?;
            let at = port.read_file_at(&rel, rev).map_err(map_history)?;
            return Ok(ReadSource::Bytes(at.bytes));
        }
        let (chain, stored) = self.open_regular_leaf(&rel)?;
        let _file = open_regular_at(chain.current_fd(), &stored)?;
        Ok(ReadSource::Path(abs_under_home(&self.home, &rel)))
    }

    fn prepare_historical(
        &self,
        rel: &str,
        rev: &str,
        want_oid: bool,
    ) -> Result<ReadVersion, FilesError> {
        let port = self.vcs.as_ref().ok_or(FilesError::UnknownVersion)?;
        let at = port.read_file_at(rel, rev).map_err(map_history)?;
        let oid = if want_oid {
            Some(blob_oid_of_bytes(&at.bytes))
        } else {
            None
        };
        let head = port.head_blob_oid(rel);
        let already_current = match (head.as_deref(), oid.as_deref()) {
            (Some(h), Some(o)) => h == o,
            (Some(h), None) => h == blob_oid_of_bytes(&at.bytes),
            _ => false,
        };
        let leaf = rel.rsplit_once('/').map(|(_, n)| n).unwrap_or(rel);
        Ok(ReadVersion {
            path: rel.to_string(),
            size: at.bytes.len() as u64,
            content_type: content_type_for_name(leaf).to_string(),
            oid,
            identity: None,
            rev: Some(rev.to_string()),
            already_current,
        })
    }

    fn open_regular_leaf<'a>(&'a self, rel: &'a str) -> Result<(DirChain<'a>, String), FilesError> {
        let (chain, leaf) = DirChain::walk_parent(&self.root, rel)?;
        gate_hidden_leaf(&leaf, chain.parent_is_agent())?;
        let st = match statat_nofollow(chain.current_fd(), &leaf) {
            Ok(st) => st,
            Err(FilesError::NotFound) => {
                let resolved = super::fsops::resolve_component_name(chain.current_fd(), &leaf)?;
                gate_hidden_leaf(&resolved, chain.parent_is_agent())?;
                statat_nofollow(chain.current_fd(), &resolved)?
            }
            Err(e) => return Err(e),
        };
        let stored = leaf_stored_name(chain.current_fd(), &leaf, &st)?;
        gate_hidden_leaf(&stored, chain.parent_is_agent())?;
        match FileType::from_raw_mode(st.st_mode) {
            FileType::RegularFile => Ok((chain, stored)),
            FileType::Directory => Err(FilesError::NotAFile { item: None }),
            FileType::Symlink => Err(FilesError::ReadOnly(ReadOnlyReason::Symlink)),
            _ => Err(FilesError::ReadOnly(ReadOnlyReason::Special)),
        }
    }

    fn oid_for_opened(
        &self,
        file: &std::fs::File,
        identity: &FileIdentity,
        want_oid: bool,
    ) -> Option<String> {
        if !want_oid {
            return None;
        }
        let now = unix_time_ns(SystemTime::now());
        let stable = identity.is_stable_at(now);
        if identity.size > UNSTABLE_READ_OID_THRESHOLD && !stable {
            return None;
        }
        if stable {
            let mut cache = match self.oids.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Some(hit) = cache.get(identity) {
                return Some(hit.to_string());
            }
        }
        match hash_opened_file(file) {
            Ok(oid) => {
                if stable {
                    let mut cache = match self.oids.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    cache.insert(*identity, oid.clone());
                }
                Some(oid)
            }
            Err(IdentityError::LengthMismatch { .. }) => None,
            Err(_) => None,
        }
    }

    fn cached_snapshot(
        &self,
        chain: &DirChain<'_>,
        need_stat: bool,
    ) -> Result<Arc<RawSnapshot>, FilesError> {
        let st = fstat(chain.current_fd()).map_err(|e| FilesError::Io(e.to_string()))?;
        let key = DirCacheKey {
            dev: stat_dev(&st),
            ino: stat_ino(&st),
            mtime_ns: mtime_ns(&st),
        };
        {
            let mut cache = match self.listings.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Some(hit) = cache.get(&key) {
                if !need_stat || hit.entries.iter().all(|e| e.stated) {
                    return Ok(hit);
                }
            }
        }
        let snap = Arc::new(read_snapshot(
            chain.current_fd(),
            chain.parent_is_agent(),
            chain.current_dev(),
            self.limits.max_list_entries.max(LIST_SCAN_CAP),
            need_stat,
        )?);
        let mut cache = match self.listings.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        cache.insert(key, Arc::clone(&snap));
        Ok(snap)
    }

    fn decorate(
        &self,
        parent: BorrowedFd<'_>,
        parent_rel: &str,
        snap: &SnapEntry,
        parent_is_agent: bool,
        parent_dev: u64,
        parent_facts: PhysicalFacts,
        with_stat: bool,
    ) -> Result<ListEntry, FilesError> {
        let path = join_rel(parent_rel, &snap.name);
        let class = classify_h1(&snap.name, &snap.name, parent_is_agent);
        let mut mount_point = snap.stated && snap.st_dev != parent_dev && snap.kind.is_dir();
        let mut size = if snap.stated { Some(snap.size) } else { None };
        let mut modified_ns = if snap.stated {
            Some(snap.mtime_ns)
        } else {
            None
        };
        let mut locked = false;
        let mut kind = snap.kind;
        if with_stat && !snap.stated {
            if let Ok(st) = statat_nofollow(parent, &snap.name) {
                size = Some(st.st_size as u64);
                modified_ns = Some(mtime_ns(&st));
                mount_point = stat_dev(&st) != parent_dev && snap.kind.is_dir();
                locked = is_locked(&st);
                kind = kind_from_file_type(FileType::from_raw_mode(st.st_mode));
            }
        } else if with_stat {
            if let Ok(st) = statat_nofollow(parent, &snap.name) {
                locked = is_locked(&st);
                mount_point = stat_dev(&st) != parent_dev && kind.is_dir();
            }
        }
        let mut territory_root = false;
        let mut foreign_repo = false;
        if kind.is_dir() {
            if let Ok(child) = open_dir_nofollow(parent, &snap.name, true) {
                territory_root = statat(&child, ".agent", AtFlags::SYMLINK_NOFOLLOW).is_ok();
                foreign_repo = statat(&child, ".git", AtFlags::SYMLINK_NOFOLLOW).is_ok();
            }
        }
        let (read_only, read_only_reason) = entry_protection(
            class,
            kind,
            mount_point,
            locked,
            territory_root,
            foreign_repo,
            parent_facts,
        );
        let content_type = match kind {
            EntryKind::File => Some(content_type_for_name(&snap.name)),
            _ => None,
        };
        let vcs = self.vcs.as_ref().map(|port| port.probe_path(&path));
        Ok(ListEntry {
            name: snap.name.clone(),
            path,
            kind,
            size,
            modified_ns,
            oid: None,
            vcs,
            content_type,
            read_only,
            read_only_reason,
            territory_root,
            foreign_repo,
            mount_point,
            dotfile: is_dotfile_name(&snap.name),
            package: false,
        })
    }
}

fn gate_hidden_leaf(stored: &str, parent_is_agent: bool) -> Result<(), FilesError> {
    match classify_h1(stored, stored, parent_is_agent) {
        ComponentClass::Private | ComponentClass::Junk => Err(FilesError::NotFound),
        _ => {
            let access = match classify_component(stored, parent_is_agent) {
                ComponentClass::Private => AccessClass::Private { at_final: true },
                ComponentClass::Junk => AccessClass::Junk { at_final: true },
                ComponentClass::ReadOnly(r) => AccessClass::ReadOnly(r),
                ComponentClass::Normal => AccessClass::Normal,
            };
            match gate(access, PathUse::Read) {
                Ok(()) => Ok(()),
                Err(_) => Err(FilesError::NotFound),
            }
        }
    }
}

fn leaf_stored_name(
    _parent: BorrowedFd<'_>,
    lookup: &str,
    _st: &rustix::fs::Stat,
) -> Result<String, FilesError> {
    Ok(lookup.to_string())
}

fn read_snapshot(
    dir_fd: BorrowedFd<'_>,
    parent_is_agent: bool,
    parent_dev: u64,
    cap: usize,
    need_stat: bool,
) -> Result<RawSnapshot, FilesError> {
    let dir = Dir::read_from(dir_fd).map_err(|e| FilesError::Io(e.to_string()))?;
    let mut entries = Vec::new();
    let mut skipped_unsupported = 0usize;
    let mut truncated = false;
    for entry in dir {
        let entry = entry.map_err(|e| FilesError::Io(e.to_string()))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if entries.len() >= cap {
            truncated = true;
            break;
        }
        let Some(name) = entry.file_name().to_str().ok() else {
            skipped_unsupported = skipped_unsupported.saturating_add(1);
            continue;
        };
        if normalize_workspace_path(name, false).is_err() {
            skipped_unsupported = skipped_unsupported.saturating_add(1);
            continue;
        }
        match classify_h1(name, name, parent_is_agent) {
            ComponentClass::Private | ComponentClass::Junk => continue,
            _ => {}
        }
        let mut kind = kind_from_file_type(entry.file_type());
        let mut size = 0u64;
        let mut mtime = 0i64;
        let mut st_dev = parent_dev;
        let mut stated = false;
        if kind == EntryKind::Other || need_stat {
            match statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => {
                    kind = kind_from_file_type(FileType::from_raw_mode(st.st_mode));
                    size = st.st_size as u64;
                    mtime = mtime_ns(&st);
                    st_dev = stat_dev(&st);
                    stated = true;
                }
                Err(e) if e == Errno::NOENT => continue,
                Err(_) => {
                    skipped_unsupported = skipped_unsupported.saturating_add(1);
                    continue;
                }
            }
        }
        entries.push(SnapEntry {
            name: name.to_string(),
            kind,
            size,
            mtime_ns: mtime,
            st_dev,
            stated,
        });
    }
    Ok(RawSnapshot {
        entries,
        skipped_unsupported,
        truncated,
    })
}

fn kind_from_file_type(ft: FileType) -> EntryKind {
    match ft {
        FileType::Directory => EntryKind::Dir,
        FileType::RegularFile => EntryKind::File,
        FileType::Symlink => EntryKind::Symlink,
        FileType::Unknown => EntryKind::Other,
        _ => EntryKind::Other,
    }
}

fn sort_snapshot(entries: &mut [SnapEntry], sort: ListSort, order: EntryOrder) {
    entries.sort_by(|a, b| cmp_entries(a, b, sort, order));
}

fn cmp_entries(a: &SnapEntry, b: &SnapEntry, sort: ListSort, order: EntryOrder) -> Ordering {
    if order.folders_first && a.is_dir() != b.is_dir() {
        return if a.is_dir() {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let primary = match sort {
        ListSort::Name => compare(&a.name, &b.name),
        ListSort::Kind => extension_key(&a.name)
            .cmp(&extension_key(&b.name))
            .then_with(|| compare(&a.name, &b.name)),
        ListSort::Size => a.size.cmp(&b.size).then_with(|| compare(&a.name, &b.name)),
        ListSort::Modified => a
            .mtime_ns
            .cmp(&b.mtime_ns)
            .then_with(|| compare(&a.name, &b.name)),
    };
    if order.descending {
        primary.reverse()
    } else {
        primary
    }
}

fn extension_key(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

fn listing_fingerprint(
    sort: ListSort,
    descending: bool,
    folders_first: bool,
    names: &[&str],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sort.as_str().as_bytes());
    hasher.update([u8::from(descending), u8::from(folders_first)]);
    for name in names {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(16);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in digest.iter().take(8) {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    hex
}

fn page_limit(requested: usize) -> usize {
    let n = if requested == 0 {
        LIST_DEFAULT_LIMIT
    } else {
        requested
    };
    n.min(LIST_MAX_PAGE_LIMIT)
}

fn search_limit(requested: usize) -> usize {
    let n = if requested == 0 {
        SEARCH_DEFAULT_LIMIT
    } else {
        requested
    };
    n.min(SEARCH_MAX_LIMIT)
}

fn lexical_read_path(raw: &str) -> Result<String, FilesError> {
    let rel = normalize_workspace_path(raw, true).map_err(FilesError::InvalidPath)?;
    if rel.is_empty() {
        return Err(FilesError::NotAFile { item: None });
    }
    let leaf = rel.rsplit_once('/').map(|(_, n)| n).unwrap_or(rel.as_str());
    let parent_is_agent = match rel.rsplit_once('/') {
        Some((parent, _)) => parent
            .rsplit_once('/')
            .map(|(_, last)| is_agent_dir_name(last))
            .unwrap_or_else(|| is_agent_dir_name(parent)),
        None => false,
    };
    gate_hidden_leaf(leaf, parent_is_agent)?;
    Ok(rel)
}

fn abs_under_home(home: &Path, rel: &str) -> PathBuf {
    if rel.is_empty() {
        home.to_path_buf()
    } else {
        home.join(rel)
    }
}

fn map_history(err: HistoryError) -> FilesError {
    match err {
        HistoryError::MalformedSha(_) | HistoryError::UnknownCommit(_) => {
            FilesError::UnknownVersion
        }
        HistoryError::InvalidPath { .. } | HistoryError::PathNotFound { .. } => {
            FilesError::NotFound
        }
        HistoryError::BlobTooLarge { .. } => FilesError::BlobTooLarge,
        HistoryError::Repo(_) => FilesError::VcsUnavailable { reason: "repo" },
    }
}

fn join_rel(parent: &str, name: &str) -> String {
    let nfc = to_nfc(name);
    if parent.is_empty() {
        nfc
    } else {
        let mut out =
            String::with_capacity(parent.len().saturating_add(nfc.len()).saturating_add(1));
        out.push_str(parent);
        out.push('/');
        out.push_str(&nfc);
        out
    }
}

fn fold_name(s: &str) -> String {
    to_nfc(s).chars().flat_map(char::to_lowercase).collect()
}

fn entry_protection(
    class: ComponentClass,
    kind: EntryKind,
    mount_point: bool,
    locked: bool,
    territory_root: bool,
    foreign_repo: bool,
    parent_facts: PhysicalFacts,
) -> (bool, Option<ReadOnlyReason>) {
    if matches!(kind, EntryKind::Symlink) {
        return (true, Some(ReadOnlyReason::Symlink));
    }
    if matches!(kind, EntryKind::Other) {
        return (true, Some(ReadOnlyReason::Special));
    }
    if mount_point {
        return (true, Some(ReadOnlyReason::MountPoint));
    }
    if foreign_repo {
        return (true, Some(ReadOnlyReason::ForeignRepo));
    }
    if locked {
        return (true, Some(ReadOnlyReason::Locked));
    }
    if let ComponentClass::ReadOnly(r) = class {
        return (true, Some(r));
    }
    if territory_root {
        return (true, Some(ReadOnlyReason::TerritoryRoot));
    }
    if parent_facts.subtree == super::policy::SubtreeClass::MountPoint {
        return (true, Some(ReadOnlyReason::MountPoint));
    }
    let _ = parent_facts;
    (false, None)
}

fn search_dir(
    fd: BorrowedFd<'_>,
    rel: &str,
    parent_is_agent: bool,
    parent_dev: u64,
    parent_facts: PhysicalFacts,
    q_fold: &str,
    start: Instant,
    visited: &mut usize,
    out: &mut Vec<ListEntry>,
    limit: usize,
    depth: usize,
    core: &OperatorFiles,
) -> Result<bool, FilesError> {
    if out.len() >= limit {
        return Ok(true);
    }
    if depth >= 32 || *visited >= SEARCH_MAX_VISITS || start.elapsed() >= SEARCH_BUDGET {
        return Ok(true);
    }
    let snap = read_snapshot(fd, parent_is_agent, parent_dev, LIST_SCAN_CAP, false)?;
    for ent in &snap.entries {
        *visited = visited.saturating_add(1);
        if *visited >= SEARCH_MAX_VISITS || start.elapsed() >= SEARCH_BUDGET {
            return Ok(true);
        }
        if fold_name(&ent.name).contains(q_fold)
            || fold_name(&join_rel(rel, &ent.name)).contains(q_fold)
        {
            out.push(core.decorate(
                fd,
                rel,
                ent,
                parent_is_agent,
                parent_dev,
                parent_facts,
                true,
            )?);
            if out.len() >= limit {
                return Ok(true);
            }
        }
        if ent.kind.is_dir() {
            if ent.stated && ent.st_dev != parent_dev {
                continue;
            }
            let child_fd = match open_dir_nofollow(fd, &ent.name, true) {
                Ok(fd) => fd,
                Err(_) => continue,
            };
            let child_rel = join_rel(rel, &ent.name);
            let child_agent = is_agent_dir_name(&ent.name);
            let child_st = match fstat(&child_fd) {
                Ok(st) => st,
                Err(_) => continue,
            };
            if stat_dev(&child_st) != parent_dev {
                continue;
            }
            let truncated = search_dir(
                child_fd.as_fd(),
                &child_rel,
                child_agent,
                parent_dev,
                parent_facts,
                q_fold,
                start,
                visited,
                out,
                limit,
                depth.saturating_add(1),
                core,
            )?;
            if truncated {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Re-export for `OperatorFiles::open`.
pub(crate) fn new_listing_cache() -> ListingCache {
    ListingCache::new()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::operator::{OperatorFilesConfig, OperatorLimits};

    fn snap(name: &str, kind: EntryKind, size: u64, mtime_ns: i64) -> SnapEntry {
        SnapEntry {
            name: name.to_string(),
            kind,
            size,
            mtime_ns,
            st_dev: 1,
            stated: true,
        }
    }

    fn names(entries: &[SnapEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    #[test]
    fn sort_natural_numeric_runs() {
        let mut entries = vec![
            snap("file10.txt", EntryKind::File, 0, 0),
            snap("file2.txt", EntryKind::File, 0, 0),
            snap("file1.txt", EntryKind::File, 0, 0),
            snap("file.txt", EntryKind::File, 0, 0),
            snap("file11.txt", EntryKind::File, 0, 0),
            snap("file9.txt", EntryKind::File, 0, 0),
        ];
        sort_snapshot(
            &mut entries,
            ListSort::Name,
            EntryOrder {
                folders_first: false,
                descending: false,
            },
        );
        assert_eq!(
            names(&entries),
            [
                "file.txt",
                "file1.txt",
                "file2.txt",
                "file9.txt",
                "file10.txt",
                "file11.txt",
            ]
        );
    }

    #[test]
    fn sort_folders_first_all_keys_both_directions() {
        for sort in [
            ListSort::Name,
            ListSort::Kind,
            ListSort::Size,
            ListSort::Modified,
        ] {
            for descending in [false, true] {
                let mut entries = vec![
                    snap("z.md", EntryKind::File, 10, 10),
                    snap("b", EntryKind::Dir, 3, 3),
                    snap("a.md", EntryKind::File, 2, 2),
                    snap("m", EntryKind::Dir, 1, 1),
                    snap("link", EntryKind::Symlink, 0, 0),
                    snap("fifo", EntryKind::Other, 0, 0),
                ];
                sort_snapshot(
                    &mut entries,
                    sort,
                    EntryOrder {
                        folders_first: true,
                        descending,
                    },
                );
                let first_file = entries
                    .iter()
                    .position(|e| !e.is_dir())
                    .unwrap_or(entries.len());
                assert!(
                    entries[..first_file].iter().all(|e| e.is_dir()),
                    "{sort:?} descending={descending}: directories must group first"
                );
                assert!(
                    entries[first_file..].iter().all(|e| !e.is_dir()),
                    "{sort:?} descending={descending}: non-dirs stay in the file group"
                );
                assert_eq!(
                    entries[..first_file].len(),
                    2,
                    "two directories in the leading group"
                );
                if sort == ListSort::Name {
                    let dir_names = names(&entries[..first_file]);
                    if descending {
                        assert_eq!(dir_names, ["m", "b"]);
                    } else {
                        assert_eq!(dir_names, ["b", "m"]);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn fingerprint_changes_on_insert() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("a.md"), b"a").unwrap();
        let core = OperatorFiles::open(OperatorFilesConfig {
            home: home.path().to_path_buf(),
            files_state: home.path().join(".runtime").join("files"),
            limits: OperatorLimits::default(),
            vcs: None,
            maintainer: None,
            lane: None,
        })
        .await
        .unwrap();
        let first = core.list(&ListQuery::default()).unwrap();
        assert!(
            first.entries.iter().any(|e| e.name == "a.md"),
            "seed file is listed: {:?}",
            first.entries
        );
        std::fs::write(home.path().join("b.md"), b"b").unwrap();
        let second = core.list(&ListQuery::default()).unwrap();
        assert_ne!(
            first.fingerprint, second.fingerprint,
            "inserting a name must change the listing fingerprint"
        );
        assert!(second.entries.iter().any(|e| e.name == "b.md"));
        let stale = core.list(&ListQuery {
            offset: 1,
            fingerprint: Some(first.fingerprint.clone()),
            limit: 1,
            ..ListQuery::default()
        });
        assert_eq!(stale.unwrap_err(), FilesError::ListingChanged);
    }

    #[tokio::test]
    async fn list_hides_private_junk_and_runtime() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("visible.md"), b"v").unwrap();
        std::fs::create_dir(home.path().join(".runtime")).unwrap();
        std::fs::create_dir(home.path().join(".git")).unwrap();
        std::fs::write(home.path().join(".DS_Store"), b"junk").unwrap();
        std::fs::write(home.path().join(".tmpAbc123"), b"tmp").unwrap();
        std::fs::write(home.path().join(".obsidian"), b"ok").unwrap();
        let core = OperatorFiles::open(OperatorFilesConfig {
            home: home.path().to_path_buf(),
            files_state: home.path().join(".runtime").join("files"),
            limits: OperatorLimits::default(),
            vcs: None,
            maintainer: None,
            lane: None,
        })
        .await
        .unwrap();
        let listing = core.list(&ListQuery::default()).unwrap();
        let got: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(got.contains(&"visible.md"));
        assert!(got.contains(&".obsidian"));
        assert!(!got.contains(&".runtime"));
        assert!(!got.contains(&".git"));
        assert!(!got.contains(&".DS_Store"));
        assert!(!got.contains(&".tmpAbc123"));
    }
}
