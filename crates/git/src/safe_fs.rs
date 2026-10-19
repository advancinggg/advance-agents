//! Safe disk access for the commit worker (ADR 2026-10-15, MODULE-003 §1.4.1 item 1,
//! MODULE-003-AC-35).
//!
//! Every disk read the user lane performs while the coord mutex is held (`prepare`,
//! `BlobSource::Disk`, the adopt step, the `restore_tree` adopt) goes through
//! [`open_entry`]: an fd-relative walk from the workdir that opens each parent component
//! with `O_DIRECTORY | O_NOFOLLOW`, classifies the leaf with `statat(AT_SYMLINK_NOFOLLOW)`,
//! and opens a regular leaf with `O_NOFOLLOW | O_NONBLOCK` before an `fstat` that must
//! report `S_ISREG`. So:
//!
//! - no symlink is ever followed, at the leaf or above it (a symlinked parent is reported
//!   as [`DiskEntry::SymlinkedParent`]); the walk is per component, so it is correct on
//!   case-insensitive volumes where `canonicalize` can change case;
//! - a FIFO, socket or device is never read, and a swap between `statat` and `openat`
//!   cannot block: `O_NONBLOCK` opens a FIFO without waiting and the `fstat` re-classifies;
//! - a regular file is read exactly once, streamed into the object writer
//!   ([`stream_blob`]), and the blob is committed only when a second `fstat` of the
//!   descriptor still reports the open's identity and ctime, so it is one state of the
//!   file (never a mix of two) and the identity reported with it describes its bytes.
//!
//! It replaces the legacy lane's canonicalize + `strip_prefix` guard for this lane.
//! [`write_atomic`] is the runtime-private write: temp file created exclusively (a planted
//! symlink is never followed), fsync, rename, best-effort directory fsync.
//!
//! Unix only (Linux, macOS, iOS), like the runtime. Panic-free: it runs while the coord
//! mutex is held.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use advance_shared_types::FileIdentity;
use git2::{Oid, Repository};
use rustix::fs::{openat, readlinkat, statat, AtFlags, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;

use crate::error::GitError;

/// The workdir, opened once as the anchor of every fd-relative walk.
#[derive(Debug)]
pub(crate) struct SafeRoot {
    dir: OwnedFd,
}

impl SafeRoot {
    /// Open the (canonical) workdir.
    pub(crate) fn open(workdir: &Path) -> io::Result<Self> {
        let dir = openat(
            CWD,
            workdir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { dir })
    }
}

/// A regular file opened by [`open_entry`] (`O_NOFOLLOW | O_NONBLOCK`): the descriptor and
/// what its `fstat` reported.
#[derive(Debug)]
pub(crate) struct OpenFile {
    pub(crate) file: File,
    pub(crate) len: u64,
    pub(crate) identity: FileIdentity,
    pub(crate) executable: bool,
    /// `st_ctime` in nanoseconds: every write moves it and no call sets it back, so a
    /// rewrite that also restores the mtime still shows.
    ctime_ns: i64,
}

impl OpenFile {
    fn new(file: File, meta: &Metadata) -> Self {
        Self {
            len: meta.len(),
            identity: FileIdentity::from_metadata(meta),
            executable: meta.permissions().mode() & 0o111 != 0,
            ctime_ns: ctime_ns(meta),
            file,
        }
    }

    /// A fresh `fstat` of the descriptor (no read).
    pub(crate) fn stat(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }

    /// `true` while a fresh `fstat` of the descriptor reports the open's identity and ctime.
    fn unchanged(&self) -> io::Result<bool> {
        let meta = self.file.metadata()?;
        Ok(FileIdentity::from_metadata(&meta) == self.identity && ctime_ns(&meta) == self.ctime_ns)
    }
}

fn ctime_ns(meta: &Metadata) -> i64 {
    meta.ctime()
        .saturating_mul(1_000_000_000)
        .saturating_add(meta.ctime_nsec())
}

/// What a workdir-relative path is on disk.
#[derive(Debug)]
pub(crate) enum DiskEntry {
    /// Nothing at the path (or a parent is missing).
    Absent,
    /// A regular file, opened and `fstat`-ed.
    File(OpenFile),
    /// A symbolic link (never followed); its target bytes.
    Symlink {
        target: Vec<u8>,
    },
    Dir,
    /// A FIFO, socket or device: never read.
    Other,
    /// A parent component is a symlink (or not a directory).
    SymlinkedParent,
}

fn invalid_path(rel: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("not a plain workdir-relative path: {rel:?}"),
    )
}

/// The components of a workdir-relative path: non-empty, no empty, `.` or `..`
/// component, no NUL.
fn components(rel: &str) -> io::Result<Vec<&str>> {
    if rel.is_empty() {
        return Err(invalid_path(rel));
    }
    let parts: Vec<&str> = rel.split('/').collect();
    if parts
        .iter()
        .any(|c| c.is_empty() || *c == "." || *c == ".." || c.contains('\0'))
    {
        return Err(invalid_path(rel));
    }
    Ok(parts)
}

/// Classify (and for a regular file, open) `rel` under `root` without following any
/// symlink. Errors are I/O failures other than "absent" (permission refused, …).
pub(crate) fn open_entry(root: &SafeRoot, rel: &str) -> io::Result<DiskEntry> {
    let parts = components(rel)?;
    let Some((leaf, parents)) = parts.split_last() else {
        return Err(invalid_path(rel));
    };
    let mut opened: Option<OwnedFd> = None;
    for name in parents {
        let dir = match &opened {
            Some(fd) => fd.as_fd(),
            None => root.dir.as_fd(),
        };
        match openat(
            dir,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => opened = Some(fd),
            Err(e) if e == Errno::NOENT => return Ok(DiskEntry::Absent),
            Err(e) if e == Errno::LOOP || e == Errno::NOTDIR => {
                return Ok(DiskEntry::SymlinkedParent)
            }
            Err(e) => return Err(e.into()),
        }
    }
    let parent = match &opened {
        Some(fd) => fd.as_fd(),
        None => root.dir.as_fd(),
    };
    classify_leaf(parent, leaf)
}

fn classify_leaf(parent: BorrowedFd<'_>, leaf: &str) -> io::Result<DiskEntry> {
    let stat = match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(e) if e == Errno::NOENT => return Ok(DiskEntry::Absent),
        Err(e) => return Err(e.into()),
    };
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Symlink => read_link(parent, leaf),
        FileType::Directory => Ok(DiskEntry::Dir),
        FileType::RegularFile => open_regular(parent, leaf),
        _ => Ok(DiskEntry::Other),
    }
}

/// Open a leaf that `statat` reported regular. A swap since then is re-classified from
/// what the open finds: `ELOOP` (now a symlink) → read the link; a non-regular `fstat`
/// (a FIFO opened without blocking, a directory) → `Other` / `Dir`, never read.
fn open_regular(parent: BorrowedFd<'_>, leaf: &str) -> io::Result<DiskEntry> {
    let fd = match openat(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) if e == Errno::LOOP => return read_link(parent, leaf),
        Err(e) if e == Errno::NOENT => return Ok(DiskEntry::Absent),
        Err(e) => return Err(e.into()),
    };
    let file = File::from(fd);
    let meta = file.metadata()?;
    let kind = meta.file_type();
    if kind.is_dir() {
        return Ok(DiskEntry::Dir);
    }
    if !kind.is_file() {
        return Ok(DiskEntry::Other);
    }
    Ok(DiskEntry::File(OpenFile::new(file, &meta)))
}

fn read_link(parent: BorrowedFd<'_>, leaf: &str) -> io::Result<DiskEntry> {
    match readlinkat(parent, leaf, Vec::new()) {
        Ok(target) => Ok(DiskEntry::Symlink {
            target: target.into_bytes(),
        }),
        Err(e) if e == Errno::NOENT => Ok(DiskEntry::Absent),
        // No longer a symlink: it changed again; report it as something not to read.
        Err(e) if e == Errno::INVAL => Ok(DiskEntry::Other),
        Err(e) => Err(e.into()),
    }
}

fn changed_while_read() -> GitError {
    GitError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        "file changed while it was read",
    ))
}

/// `true` when a read at the current offset finds no more bytes.
fn at_end(file: &mut File) -> io::Result<bool> {
    let mut probe = [0u8; 1];
    loop {
        match file.read(&mut probe) {
            Ok(n) => return Ok(n == 0),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Stream an opened regular file into `repo.blob_writer(None)` (filter-free) and return
/// the blob id. The file is read once, and the object is committed only when exactly
/// `len` bytes were read and a second `fstat` of the descriptor still reports the open's
/// identity and ctime. A file that grew, shrank or was rewritten in place (to the same
/// length, even with its mtime put back) between the open and the end of the read is
/// refused and no object is committed, so the blob is never a mix of two states and
/// `identity` describes its bytes. Detection is as fine as the file system's timestamps.
pub(crate) fn stream_blob(repo: &Repository, opened: &mut OpenFile) -> Result<Oid, GitError> {
    let mut writer = repo.blob_writer(None)?;
    let copied = io::copy(
        &mut Read::by_ref(&mut opened.file).take(opened.len),
        &mut writer,
    )?;
    if copied != opened.len || !at_end(&mut opened.file)? || !opened.unchanged()? {
        return Err(changed_while_read());
    }
    Ok(writer.commit()?)
}

/// Replace `path` with `bytes` atomically: a sibling temp file is created exclusively
/// (`O_CREAT | O_EXCL`, so a planted symlink is never followed), written, fsynced and
/// renamed over `path` (a symlink at `path` is replaced, not followed); the directory is
/// fsynced on a best-effort basis (some file systems refuse it).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no parent directory for {}", path.display()),
        ));
    };
    let mut temp_name = OsString::from(".");
    temp_name.push(name);
    temp_name.push(".advance-tmp");
    let temp = dir.join(temp_name);
    match std::fs::remove_file(&temp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    if let Ok(dir) = File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
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
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn root_of(td: &TempDir) -> (std::path::PathBuf, SafeRoot) {
        let path = std::fs::canonicalize(td.path()).unwrap();
        let root = SafeRoot::open(&path).unwrap();
        (path, root)
    }

    fn mkfifo(path: &Path) {
        // Test-only: neither std nor the pinned rustix creates a FIFO on every Unix.
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo {}", path.display());
    }

    // MODULE-003-AC-35: every leaf kind, symlinks never followed, special
    // files never read (no hang), symlinked or non-directory parents reported.
    #[test]
    fn open_entry_classifies() {
        let td = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let (path, root) = root_of(&td);
        std::fs::create_dir_all(path.join("notes/sub")).unwrap();
        std::fs::write(path.join("notes/a.md"), b"alpha").unwrap();
        std::fs::write(path.join("run.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path.join("run.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::write(outside.path().join("secret"), b"secret").unwrap();
        symlink(outside.path().join("secret"), path.join("link")).unwrap();
        symlink(outside.path(), path.join("linked-dir")).unwrap();
        mkfifo(&path.join("fifo"));
        let _listener = UnixListener::bind(path.join("sock")).unwrap();

        match open_entry(&root, "notes/a.md").unwrap() {
            DiskEntry::File(OpenFile {
                mut file,
                len,
                identity,
                executable,
                ..
            }) => {
                assert_eq!(len, 5);
                assert!(!executable);
                let meta = std::fs::metadata(path.join("notes/a.md")).unwrap();
                assert_eq!(identity, FileIdentity::from_metadata(&meta));
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"alpha");
            }
            other => panic!("expected File, got {other:?}"),
        }
        assert!(matches!(
            open_entry(&root, "run.sh").unwrap(),
            DiskEntry::File(OpenFile {
                executable: true,
                ..
            })
        ));
        match open_entry(&root, "link").unwrap() {
            DiskEntry::Symlink { target } => {
                assert_eq!(
                    target,
                    outside.path().join("secret").as_os_str().as_encoded_bytes()
                )
            }
            other => panic!("expected Symlink, got {other:?}"),
        }
        assert!(matches!(
            open_entry(&root, "notes").unwrap(),
            DiskEntry::Dir
        ));
        assert!(matches!(
            open_entry(&root, "notes/sub").unwrap(),
            DiskEntry::Dir
        ));
        let started = Instant::now();
        assert!(matches!(
            open_entry(&root, "fifo").unwrap(),
            DiskEntry::Other
        ));
        assert!(matches!(
            open_entry(&root, "sock").unwrap(),
            DiskEntry::Other
        ));
        // The race path: a FIFO reached by the regular-file open neither blocks nor reads.
        assert!(matches!(
            open_regular(root.dir.as_fd(), "fifo").unwrap(),
            DiskEntry::Other
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        // ... and a symlink reached by it is read as a link, never followed.
        assert!(matches!(
            open_regular(root.dir.as_fd(), "link").unwrap(),
            DiskEntry::Symlink { .. }
        ));
        assert!(matches!(
            open_entry(&root, "linked-dir/secret").unwrap(),
            DiskEntry::SymlinkedParent
        ));
        assert!(matches!(
            open_entry(&root, "notes/a.md/x").unwrap(),
            DiskEntry::SymlinkedParent
        ));
        assert!(matches!(
            open_entry(&root, "notes/missing.md").unwrap(),
            DiskEntry::Absent
        ));
        assert!(matches!(
            open_entry(&root, "missing/a.md").unwrap(),
            DiskEntry::Absent
        ));
        for bad in ["", "/abs", "a//b", "a/./b", "../x", "notes/", "a\0b"] {
            assert_eq!(
                open_entry(&root, bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn stream_blob_reads_once_and_matches_hash_object() {
        let td = TempDir::new().unwrap();
        let (path, root) = root_of(&td);
        let repo = Repository::init(&path).unwrap();
        let content = b"line one\r\nline two\n".repeat(1000);
        std::fs::write(path.join("a.txt"), &content).unwrap();
        let expected = git2::Oid::hash_object(git2::ObjectType::Blob, &content).unwrap();

        let DiskEntry::File(mut opened) = open_entry(&root, "a.txt").unwrap() else {
            panic!("a regular file");
        };
        let len = opened.len;
        assert_eq!(stream_blob(&repo, &mut opened).unwrap(), expected);
        assert_eq!(repo.find_blob(expected).unwrap().content(), &content[..]);

        // A declared length that is wrong either way (the file changed) is refused.
        for declared in [len - 1, len + 1] {
            let DiskEntry::File(mut opened) = open_entry(&root, "a.txt").unwrap() else {
                panic!("a regular file");
            };
            opened.len = declared;
            match stream_blob(&repo, &mut opened) {
                Err(GitError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    // A same-length rewrite between the open and the end of the read (here: before the
    // read, deterministically) is refused before the object is committed, also when the
    // writer puts the mtime back: the ctime still moved.
    #[test]
    fn stream_blob_refuses_a_same_length_rewrite() {
        use std::os::unix::fs::FileExt;
        let td = TempDir::new().unwrap();
        let (path, root) = root_of(&td);
        let repo = Repository::init(&path).unwrap();
        let before = b"first state of the file\n".repeat(64);
        let mut after = before.clone();
        after[0] = b'F';
        let last = after.len() - 1;
        after[last] = b'!';
        let oids = [&before, &after]
            .map(|bytes| git2::Oid::hash_object(git2::ObjectType::Blob, bytes).unwrap());
        for restore_mtime in [false, true] {
            std::fs::write(path.join("a.txt"), &before).unwrap();
            let DiskEntry::File(mut opened) = open_entry(&root, "a.txt").unwrap() else {
                panic!("a regular file");
            };
            let mtime = opened.file.metadata().unwrap().modified().unwrap();
            // Past any timestamp granularity of the volume under test.
            std::thread::sleep(Duration::from_millis(20));
            let writer = OpenOptions::new()
                .write(true)
                .open(path.join("a.txt"))
                .unwrap();
            writer.write_all_at(&after[..1], 0).unwrap();
            writer.write_all_at(&after[last..], last as u64).unwrap();
            if restore_mtime {
                writer.set_modified(mtime).unwrap();
                let now = std::fs::metadata(path.join("a.txt")).unwrap();
                assert_eq!(FileIdentity::from_metadata(&now), opened.identity);
            }
            match stream_blob(&repo, &mut opened) {
                Err(GitError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
                other => panic!("restore_mtime={restore_mtime}: expected a refusal, got {other:?}"),
            }
            let odb = repo.odb().unwrap();
            assert!(
                oids.iter().all(|oid| !odb.exists(*oid)),
                "no object written"
            );
        }
    }

    #[test]
    fn write_atomic_replaces_without_following_symlinks() {
        let td = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let (path, _root) = root_of(&td);
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();

        let target = path.join("attributes");
        write_atomic(&target, b"one\n").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"one\n");
        write_atomic(&target, b"two\n").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"two\n");

        // A symlink at the target is replaced, not written through.
        std::fs::remove_file(&target).unwrap();
        symlink(&victim, &target).unwrap();
        write_atomic(&target, b"three\n").unwrap();
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"three\n");
        // A planted temp symlink is removed, not followed.
        symlink(&victim, path.join(".attributes.advance-tmp")).unwrap();
        write_atomic(&target, b"four\n").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"four\n");
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!path.join(".attributes.advance-tmp").exists());
        assert!(write_atomic(Path::new("/"), b"x").is_err());
    }
}
