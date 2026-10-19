//! Fd-relative IO for the operator core (oss-fs-core §2.4–§2.6, INTEGRATED §3.6).
//!
//! `RootDir` holds the canonical home as `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`.
//! `DirChain` walks each component the same way, re-classifies from the **stored**
//! name (H1), and never follows a symlink. Mutations are single-component `*at`
//! calls on an already-opened parent (`mkdirat`, no-replace publish, trash-rename).

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use advance_shared_types::workspace_path::{
    classify_component, is_agent_dir_name, AccessClass, ComponentClass, PathClassifier,
    ReadOnlyReason, META_SIDECAR_NAME, PROTECTED_ANY_LEVEL_NAMES, PROTECTED_ROOT_NAMES,
};
use rustix::fs::{
    fstat, mkdirat, openat, renameat, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags, Stat,
    StatExt, CWD,
};
use rustix::io::Errno;

use super::policy::{classify_h1, stored_nfc, NodeProtection, PhysicalFacts, SubtreeClass};
use super::{FilesError, LIST_SCAN_CAP};

/// Directory open: never follow, never leave the parent fd.
pub fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Regular-file read: `O_NONBLOCK` so a FIFO cannot park the caller.
pub fn file_read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
}

/// Exclusive create: a planted symlink at the name is never followed.
pub fn file_create_flags() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn io_err(err: impl std::fmt::Display) -> FilesError {
    FilesError::Io(err.to_string())
}

pub(crate) fn mtime_ns(st: &Stat) -> i64 {
    st.mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(st.st_mtime_nsec as i64)
}

pub(crate) fn stat_dev(st: &Stat) -> u64 {
    st.st_dev as u64
}

pub(crate) fn stat_ino(st: &Stat) -> u64 {
    st.st_ino as u64
}

/// Canonical workspace root, opened once at [`super::OperatorFiles::open`].
pub struct RootDir {
    fd: OwnedFd,
    canonical: PathBuf,
    st_dev: u64,
    st_ino: u64,
}

impl RootDir {
    /// Canonicalize `home` (so `/var` becomes `/private/var`) and open it
    /// `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`.
    pub fn open(home: &Path) -> Result<Self, FilesError> {
        let canonical = std::fs::canonicalize(home).map_err(io_err)?;
        let fd = openat(CWD, canonical.as_path(), dir_flags(), Mode::empty()).map_err(io_err)?;
        let st = fstat(&fd).map_err(io_err)?;
        Ok(Self {
            fd,
            canonical,
            st_dev: stat_dev(&st),
            st_ino: stat_ino(&st),
        })
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn canonical(&self) -> &Path {
        &self.canonical
    }

    pub fn st_dev(&self) -> u64 {
        self.st_dev
    }

    pub fn st_ino(&self) -> u64 {
        self.st_ino
    }
}

/// One opened directory component of a walk.
pub struct OpenedComp {
    fd: OwnedFd,
    stored_name: String,
    st_dev: u64,
    st_ino: u64,
    mtime_ns: i64,
    mount_point: bool,
}

impl OpenedComp {
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn stored_name(&self) -> &str {
        &self.stored_name
    }

    pub fn st_dev(&self) -> u64 {
        self.st_dev
    }

    pub fn st_ino(&self) -> u64 {
        self.st_ino
    }

    pub fn mtime_ns(&self) -> i64 {
        self.mtime_ns
    }

    pub fn is_mount_point(&self) -> bool {
        self.mount_point
    }
}

/// What `statat(AT_SYMLINK_NOFOLLOW)` reported for an ENOTDIR/ELOOP open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenClass {
    Symlink,
    Directory,
    Other,
}

/// Stack of opened directories from the workspace root.
pub struct DirChain<'a> {
    root: &'a RootDir,
    stack: Vec<OpenedComp>,
    classifier: PathClassifier,
}

impl<'a> DirChain<'a> {
    pub fn new(root: &'a RootDir) -> Self {
        Self {
            root,
            stack: Vec::new(),
            classifier: PathClassifier::new(),
        }
    }

    /// Walk every component as a directory. Hidden/Junk → [`FilesError::NotFound`].
    /// A symlink component is traversal → `not_found`. A regular file →
    /// [`FilesError::NotADirectory`].
    pub fn walk_dir(root: &'a RootDir, rel_nfc: &str) -> Result<Self, FilesError> {
        let mut chain = Self::new(root);
        if !rel_nfc.is_empty() {
            for name in rel_nfc.split('/') {
                chain.descend(name)?;
            }
        }
        if chain.access().is_hidden() {
            return Err(FilesError::NotFound);
        }
        Ok(chain)
    }

    /// Walk every parent as a directory; return the chain at the parent and the
    /// final component. `rel_nfc` must be non-empty.
    pub fn walk_parent(root: &'a RootDir, rel_nfc: &str) -> Result<(Self, String), FilesError> {
        if rel_nfc.is_empty() {
            return Err(FilesError::NotFound);
        }
        match rel_nfc.rsplit_once('/') {
            Some((parents, leaf)) => {
                let chain = Self::walk_dir(root, parents)?;
                Ok((chain, leaf.to_string()))
            }
            None => Ok((Self::new(root), rel_nfc.to_string())),
        }
    }

    pub fn root(&self) -> &'a RootDir {
        self.root
    }

    pub fn current_fd(&self) -> BorrowedFd<'_> {
        match self.stack.last() {
            Some(comp) => comp.fd(),
            None => self.root.fd(),
        }
    }

    pub fn current_dev(&self) -> u64 {
        match self.stack.last() {
            Some(comp) => comp.st_dev,
            None => self.root.st_dev,
        }
    }

    pub fn current_ino(&self) -> u64 {
        match self.stack.last() {
            Some(comp) => comp.st_ino,
            None => self.root.st_ino,
        }
    }

    pub fn current_mtime_ns(&self) -> Result<i64, FilesError> {
        match self.stack.last() {
            Some(comp) => Ok(comp.mtime_ns),
            None => {
                let st = fstat(self.root.fd()).map_err(io_err)?;
                Ok(mtime_ns(&st))
            }
        }
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    pub fn parent_is_agent(&self) -> bool {
        self.stack
            .last()
            .is_some_and(|comp| is_agent_dir_name(&comp.stored_name))
    }

    pub fn access(&self) -> AccessClass {
        self.classifier.class().access
    }

    pub fn facts(&self) -> PhysicalFacts {
        if self.stack.is_empty() {
            return PhysicalFacts::workspace_root();
        }
        let mut facts = facts_from_access(self.access());
        if self.stack.iter().any(|comp| comp.mount_point) {
            facts.subtree = SubtreeClass::MountPoint;
        }
        if matches!(
            self.access(),
            AccessClass::ReadOnly(ReadOnlyReason::VcsControl)
        ) {
            facts.protection = Some(NodeProtection::VcsControl);
        }
        facts
    }

    pub fn rel_disk(&self) -> String {
        let mut out = String::new();
        for (i, comp) in self.stack.iter().enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.push_str(&comp.stored_name);
        }
        out
    }

    pub fn rel_nfc(&self) -> String {
        stored_nfc(&self.rel_disk())
    }

    pub fn stored_components(&self) -> Vec<&str> {
        self.stack
            .iter()
            .map(|comp| comp.stored_name.as_str())
            .collect()
    }

    /// Open `lookup` (NFC) as a directory relative to the current fd.
    pub fn descend(&mut self, lookup: &str) -> Result<(), FilesError> {
        let parent = self.current_fd();
        let parent_dev = self.current_dev();
        let parent_is_agent = self.parent_is_agent();
        let at_root = self.stack.is_empty();
        let stored_lookup = resolve_component_name(parent, lookup)?;
        let fd = open_dir_nofollow(parent, &stored_lookup, true)?;
        let st = fstat(&fd).map_err(io_err)?;
        let st_dev = stat_dev(&st);
        let st_ino = stat_ino(&st);
        let mount_point = st_dev != parent_dev;
        let stored = stored_name_of(&fd, parent, &stored_lookup, &st, true)?;
        let mut class = classify_h1(lookup, &stored, parent_is_agent);
        if let Some(id_class) = identity_class(parent, st_dev, st_ino, at_root) {
            class = tighten_class(class, id_class);
        }
        if matches!(class, ComponentClass::Private | ComponentClass::Junk) {
            return Err(FilesError::NotFound);
        }
        self.classifier.push(&stored);
        if self.classifier.class().access.is_hidden() {
            return Err(FilesError::NotFound);
        }
        self.stack.push(OpenedComp {
            fd,
            stored_name: stored,
            st_dev,
            st_ino,
            mtime_ns: mtime_ns(&st),
            mount_point,
        });
        Ok(())
    }
}

fn facts_from_access(access: AccessClass) -> PhysicalFacts {
    match access {
        AccessClass::Normal => PhysicalFacts::inner_territory(),
        AccessClass::Private { .. } => PhysicalFacts {
            subtree: SubtreeClass::Hidden,
            protection: None,
        },
        AccessClass::Junk { .. } => PhysicalFacts {
            subtree: SubtreeClass::Junk,
            protection: None,
        },
        AccessClass::ReadOnly(ReadOnlyReason::AgentSystem) => PhysicalFacts::agent_system(),
        AccessClass::ReadOnly(ReadOnlyReason::ForeignRepo) => PhysicalFacts::foreign_repo(),
        AccessClass::ReadOnly(ReadOnlyReason::MountPoint) => PhysicalFacts::mount_point(),
        AccessClass::ReadOnly(ReadOnlyReason::VcsControl) => PhysicalFacts {
            subtree: SubtreeClass::Normal,
            protection: Some(NodeProtection::VcsControl),
        },
        AccessClass::ReadOnly(ReadOnlyReason::Symlink) => PhysicalFacts {
            subtree: SubtreeClass::Symlink,
            protection: None,
        },
        AccessClass::ReadOnly(ReadOnlyReason::Special) => PhysicalFacts {
            subtree: SubtreeClass::Special,
            protection: None,
        },
        AccessClass::ReadOnly(_) => PhysicalFacts::inner_territory(),
    }
}

fn tighten_class(a: ComponentClass, b: ComponentClass) -> ComponentClass {
    match (a, b) {
        (ComponentClass::Private, _) | (_, ComponentClass::Private) => ComponentClass::Private,
        (ComponentClass::Junk, _) | (_, ComponentClass::Junk) => ComponentClass::Junk,
        (ComponentClass::ReadOnly(ReadOnlyReason::AgentSystem), _)
        | (_, ComponentClass::ReadOnly(ReadOnlyReason::AgentSystem)) => {
            ComponentClass::ReadOnly(ReadOnlyReason::AgentSystem)
        }
        (ComponentClass::ReadOnly(r), _) | (_, ComponentClass::ReadOnly(r)) => {
            ComponentClass::ReadOnly(r)
        }
        (ComponentClass::Normal, ComponentClass::Normal) => ComponentClass::Normal,
    }
}

/// Look up one NFC component: try the NFC spelling, then (non-ASCII only) a
/// bounded readdir for `nfc(entry) == c`. Two matches → ambiguous.
pub fn resolve_component_name(
    parent: BorrowedFd<'_>,
    nfc_name: &str,
) -> Result<String, FilesError> {
    match statat(parent, nfc_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(nfc_name.to_string()),
        Err(e) if e == Errno::NOENT => {
            if nfc_name.is_ascii() {
                Err(FilesError::NotFound)
            } else {
                scan_nfc_match(parent, nfc_name)
            }
        }
        Err(e) => Err(io_err(e)),
    }
}

fn scan_nfc_match(parent: BorrowedFd<'_>, nfc_name: &str) -> Result<String, FilesError> {
    let dir = Dir::read_from(parent).map_err(io_err)?;
    let mut found: Option<String> = None;
    let mut scanned = 0usize;
    for entry in dir {
        let entry = entry.map_err(io_err)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        scanned = scanned.saturating_add(1);
        if scanned > LIST_SCAN_CAP {
            break;
        }
        let Some(name) = entry.file_name().to_str().ok() else {
            continue;
        };
        if stored_nfc(name) != nfc_name {
            continue;
        }
        match found {
            Some(_) => {
                return Err(FilesError::ReadOnly(ReadOnlyReason::AmbiguousName));
            }
            None => found = Some(name.to_string()),
        }
    }
    found.ok_or(FilesError::NotFound)
}

/// Open a directory component. ENOTDIR/ELOOP are classified: `S_IFLNK` is a
/// symlink (traversal → not_found), a raced directory is retried once then
/// busy, anything else is not-a-directory.
pub fn open_dir_nofollow(
    parent: BorrowedFd<'_>,
    name: &str,
    retry: bool,
) -> Result<OwnedFd, FilesError> {
    match openat(parent, name, dir_flags(), Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(e) if e == Errno::NOENT => Err(FilesError::NotFound),
        Err(e) if e == Errno::NOTDIR || e == Errno::LOOP => match classify_open_errno(parent, name)
        {
            Ok(OpenClass::Symlink) => Err(FilesError::NotFound),
            Ok(OpenClass::Directory) if retry => open_dir_nofollow(parent, name, false),
            Ok(OpenClass::Directory) => Err(FilesError::FileBusy),
            Ok(OpenClass::Other) => Err(FilesError::NotADirectory),
            Err(err) => Err(err),
        },
        Err(e) => Err(io_err(e)),
    }
}

/// Same as [`open_dir_nofollow`], but a symlink is `read_only reason:symlink`
/// (write / mkdir into a linked name).
pub fn open_dir_nofollow_for_write(
    parent: BorrowedFd<'_>,
    name: &str,
    retry: bool,
) -> Result<OwnedFd, FilesError> {
    match open_dir_nofollow(parent, name, retry) {
        Err(FilesError::NotFound) => match classify_open_errno(parent, name) {
            Ok(OpenClass::Symlink) => Err(FilesError::ReadOnly(ReadOnlyReason::Symlink)),
            Ok(_) => Err(FilesError::NotFound),
            Err(FilesError::NotFound) => Err(FilesError::NotFound),
            Err(err) => Err(err),
        },
        other => other,
    }
}

/// Classify ENOTDIR/ELOOP with `statat(parent, name, AT_SYMLINK_NOFOLLOW)`.
pub fn classify_open_errno(parent: BorrowedFd<'_>, name: &str) -> Result<OpenClass, FilesError> {
    let st = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(e) if e == Errno::NOENT => return Err(FilesError::NotFound),
        Err(e) => return Err(io_err(e)),
    };
    Ok(match FileType::from_raw_mode(st.st_mode) {
        FileType::Symlink => OpenClass::Symlink,
        FileType::Directory => OpenClass::Directory,
        _ => OpenClass::Other,
    })
}

fn stored_name_of(
    opened: &OwnedFd,
    parent: BorrowedFd<'_>,
    lookup: &str,
    st: &Stat,
    is_dir: bool,
) -> Result<String, FilesError> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let nlink = st.st_nlink as u64;
        // Directories always have nlink ≥ 2; getpath is still the stored path.
        // A hard-linked *leaf* (nlink > 1) may name another link — use d_ino.
        if is_dir || nlink <= 1 {
            if let Some(base) = getpath_basename(opened) {
                return Ok(base);
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (opened, is_dir);
    }
    stored_name_by_ino(parent, stat_ino(st), lookup)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn getpath_basename(fd: &OwnedFd) -> Option<String> {
    let path = rustix::fs::getpath(fd).ok()?;
    let s = path.to_str().ok()?;
    let base = s.rsplit('/').next().unwrap_or("");
    if base.is_empty() {
        None
    } else {
        Some(base.to_string())
    }
}

fn stored_name_by_ino(
    parent: BorrowedFd<'_>,
    ino: u64,
    lookup: &str,
) -> Result<String, FilesError> {
    let dir = Dir::read_from(parent).map_err(io_err)?;
    let mut found: Option<String> = None;
    for entry in dir {
        let entry = entry.map_err(io_err)?;
        if entry.ino() != ino {
            continue;
        }
        let Some(name) = entry.file_name().to_str().ok() else {
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        match found {
            Some(_) => return Ok(lookup.to_string()),
            None => found = Some(name.to_string()),
        }
    }
    Ok(found.unwrap_or_else(|| lookup.to_string()))
}

fn identity_class(
    parent: BorrowedFd<'_>,
    dev: u64,
    ino: u64,
    at_root: bool,
) -> Option<ComponentClass> {
    let root_names = PROTECTED_ROOT_NAMES;
    let any_names = PROTECTED_ANY_LEVEL_NAMES;
    let names: Vec<&str> = if at_root {
        root_names
            .iter()
            .copied()
            .chain([META_SIDECAR_NAME])
            .collect()
    } else {
        any_names
            .iter()
            .copied()
            .chain([META_SIDECAR_NAME])
            .collect()
    };
    for name in names {
        match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if stat_dev(&st) == dev && stat_ino(&st) == ino => {
                return Some(classify_component(name, false));
            }
            _ => {}
        }
    }
    None
}

/// `statat(parent, name, AT_SYMLINK_NOFOLLOW)`.
pub fn statat_nofollow(parent: BorrowedFd<'_>, name: &str) -> Result<Stat, FilesError> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(st),
        Err(e) if e == Errno::NOENT => Err(FilesError::NotFound),
        Err(e) => Err(io_err(e)),
    }
}

/// Open a regular leaf: `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, then `fstat`.
/// A symlink is never followed; a FIFO cannot park the call.
pub fn open_regular_at(parent: BorrowedFd<'_>, name: &str) -> Result<File, FilesError> {
    let fd = match openat(parent, name, file_read_flags(), Mode::empty()) {
        Ok(fd) => fd,
        Err(e) if e == Errno::NOENT => return Err(FilesError::NotFound),
        Err(e) if e == Errno::LOOP => return Err(FilesError::ReadOnly(ReadOnlyReason::Symlink)),
        Err(e) => return Err(io_err(e)),
    };
    let file = File::from(fd);
    let st = fstat(&file).map_err(io_err)?;
    match FileType::from_raw_mode(st.st_mode) {
        FileType::RegularFile => Ok(file),
        FileType::Symlink => Err(FilesError::ReadOnly(ReadOnlyReason::Symlink)),
        FileType::Directory => Err(FilesError::NotADirectory),
        _ => Err(FilesError::ReadOnly(ReadOnlyReason::Special)),
    }
}

/// `mkdirat(parent, name, 0755)`. Existing → [`FilesError::TargetExists`].
pub fn mkdir_at(parent: impl AsFd, name: &str) -> Result<(), FilesError> {
    match mkdirat(parent, name, Mode::from_raw_mode(0o755)) {
        Ok(()) => Ok(()),
        Err(e) if e == Errno::EXIST => Err(FilesError::TargetExists {
            current_oid: None,
            name_collision: false,
        }),
        Err(e) if e == Errno::NOENT => Err(FilesError::ParentNotFound),
        Err(e) => Err(io_err(e)),
    }
}

/// Publish `src_dir/src_name` onto `dst_dir/dst_name` without replacing.
/// Linux uses `renameat2(RENAME_NOREPLACE)`; elsewhere a `statat` then `renameat`.
pub fn publish_noreplace(
    src_dir: impl AsFd,
    src_name: &str,
    dst_dir: impl AsFd,
    dst_name: &str,
) -> Result<(), FilesError> {
    let src = src_dir.as_fd();
    let dst = dst_dir.as_fd();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::fs::{renameat_with, RenameFlags};
        return match renameat_with(src, src_name, dst, dst_name, RenameFlags::NOREPLACE) {
            Ok(()) => Ok(()),
            Err(e) if e == Errno::EXIST => Err(FilesError::TargetExists {
                current_oid: None,
                name_collision: false,
            }),
            Err(e) if e == Errno::NOENT => Err(FilesError::NotFound),
            Err(e) => Err(io_err(e)),
        };
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        match statat(dst, dst_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                return Err(FilesError::TargetExists {
                    current_oid: None,
                    name_collision: false,
                });
            }
            Err(e) if e == Errno::NOENT => {}
            Err(e) => return Err(io_err(e)),
        }
        match renameat(src, src_name, dst, dst_name) {
            Ok(()) => Ok(()),
            Err(e) if e == Errno::EXIST => Err(FilesError::TargetExists {
                current_oid: None,
                name_collision: false,
            }),
            Err(e) if e == Errno::NOENT => Err(FilesError::NotFound),
            Err(e) => Err(io_err(e)),
        }
    }
}

/// Move `parent/name` into the trash directory under `trash_name` (`renameat`).
pub fn trash_rename(
    parent: impl AsFd,
    name: &str,
    trash_dir: impl AsFd,
    trash_name: &str,
) -> Result<(), FilesError> {
    match renameat(parent, name, trash_dir, trash_name) {
        Ok(()) => Ok(()),
        Err(e) if e == Errno::NOENT => Err(FilesError::NotFound),
        Err(e) if e == Errno::EXIST => Err(FilesError::TargetExists {
            current_oid: None,
            name_collision: false,
        }),
        Err(e) => Err(io_err(e)),
    }
}

/// Stream a regular file into a new exclusive dest (no-replace). `clonefile` is
/// unsafe in rustix 0.38, so this is always a streamed copy.
pub fn copy_regular_noreplace(
    src_dir: impl AsFd,
    src_name: &str,
    dst_dir: impl AsFd,
    dst_name: &str,
) -> Result<(), FilesError> {
    let src = src_dir.as_fd();
    let dst = dst_dir.as_fd();
    let mut reader = open_regular_at(src, src_name)?;
    let out = match openat(
        dst,
        dst_name,
        file_create_flags(),
        Mode::from_raw_mode(0o644),
    ) {
        Ok(fd) => fd,
        Err(e) if e == Errno::EXIST => {
            return Err(FilesError::TargetExists {
                current_oid: None,
                name_collision: false,
            });
        }
        Err(e) => return Err(io_err(e)),
    };
    let mut writer = File::from(out);
    let copied = std::io::copy(&mut reader, &mut writer);
    if let Err(e) = copied {
        let _ = unlinkat(dst, dst_name, AtFlags::empty());
        return Err(io_err(e));
    }
    if let Err(e) = writer.flush() {
        let _ = unlinkat(dst, dst_name, AtFlags::empty());
        return Err(io_err(e));
    }
    Ok(())
}

/// macOS immutable / append-only flags (`UF_IMMUTABLE|SF_IMMUTABLE|UF_APPEND|SF_APPEND`).
pub fn is_locked(st: &Stat) -> bool {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        const UF_IMMUTABLE: u32 = 0x0000_0002;
        const UF_APPEND: u32 = 0x0000_0004;
        const SF_IMMUTABLE: u32 = 0x0002_0000;
        const SF_APPEND: u32 = 0x0004_0000;
        st.st_flags & (UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND) != 0
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = st;
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn dir_symlink_component_classified_symlink_not_enotdir() {
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir(td.path().join("real")).unwrap();
        symlink("real", td.path().join("link")).unwrap();
        std::fs::write(td.path().join("file.md"), b"x").unwrap();
        let root = RootDir::open(td.path()).unwrap();
        assert_eq!(
            DirChain::walk_dir(&root, "link").map(|_| ()),
            Err(FilesError::NotFound),
            "symlink traversal is not_found"
        );
        assert_eq!(
            DirChain::walk_dir(&root, "file.md").map(|_| ()),
            Err(FilesError::NotADirectory)
        );
        let chain = DirChain::walk_dir(&root, "real").unwrap();
        assert_eq!(chain.rel_disk(), "real");
        assert_eq!(
            classify_open_errno(root.fd(), "link").unwrap(),
            OpenClass::Symlink
        );
        assert_eq!(
            classify_open_errno(root.fd(), "file.md").unwrap(),
            OpenClass::Other
        );
    }

    #[test]
    fn publish_noreplace_refuses_existing() {
        let td = tempfile::tempdir().unwrap();
        std::fs::write(td.path().join("src"), b"a").unwrap();
        std::fs::write(td.path().join("dst"), b"b").unwrap();
        let root = RootDir::open(td.path()).unwrap();
        let err = publish_noreplace(root.fd(), "src", root.fd(), "dst").unwrap_err();
        assert!(matches!(
            err,
            FilesError::TargetExists {
                name_collision: false,
                ..
            }
        ));
        assert_eq!(std::fs::read(td.path().join("dst")).unwrap(), b"b");
        publish_noreplace(root.fd(), "src", root.fd(), "out").unwrap();
        assert_eq!(std::fs::read(td.path().join("out")).unwrap(), b"a");
    }

    #[test]
    fn mkdir_and_trash_rename() {
        let td = tempfile::tempdir().unwrap();
        let trash = td.path().join("trash");
        std::fs::create_dir(&trash).unwrap();
        let root = RootDir::open(td.path()).unwrap();
        let trash_fd = openat(root.fd(), "trash", dir_flags(), Mode::empty()).unwrap();
        mkdir_at(root.fd(), "notes").unwrap();
        assert!(td.path().join("notes").is_dir());
        trash_rename(root.fd(), "notes", &trash_fd, "notes").unwrap();
        assert!(!td.path().join("notes").exists());
        assert!(trash.join("notes").is_dir());
    }
}
