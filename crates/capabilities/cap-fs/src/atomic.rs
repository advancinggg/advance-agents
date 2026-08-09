//! Atomic file write — temp file + same-fs persist.
//!
//! POSIX rename(2) is atomic when source and target live on the same filesystem.
//! `tempfile::NamedTempFile::new_in(parent)` places the temp file in the target's
//! parent directory, guaranteeing same-fs persist semantics on macOS/Linux.
//!
//! Two-gate DoS protection: `MAX_WRITE_BYTES` is checked here at the disk-I/O
//! boundary, AND again in `host_fn::FsWriteHandler` BEFORE the `Val::List` →
//! `Vec<u8>` conversion so we never materialize oversized payloads even briefly.
//!
//! Slice A drift acknowledgement: `tokio::fs::create_dir_all` may auto-create new
//! parent directories during a write. Those new dirs are NOT given a `.meta.yaml`
//! in slice A — `.meta.yaml` Maintainer ships in slice B, and slice B's startup
//! reconciliation will backfill any missing files. This deliberately violates
//! MODULE-002 §1.4.4's "every directory has exactly one `.meta.yaml`" invariant
//! during the slice A → B window; documented in the slice A waived_scope.

use std::path::Path;

use tokio::io::AsyncWriteExt;

use crate::error::{sanitize_io_error, FsError};

/// Maximum bytes accepted by `atomic_write`. 64 MiB pin matches MAX_READ_BYTES;
/// configurable via RuntimeConfig in a later slice.
pub const MAX_WRITE_BYTES: usize = 64 * 1024 * 1024;

/// Write `data` to `path` atomically: writes to a temp file in the target's parent
/// directory, fsyncs, then `persist`-renames into place. On error, the partial temp
/// file is dropped automatically (NamedTempFile's Drop impl unlinks).
pub async fn atomic_write(path: &Path, data: &[u8]) -> Result<(), FsError> {
    if data.len() > MAX_WRITE_BYTES {
        return Err(FsError::IoError(format!(
            "payload exceeds MAX_WRITE_BYTES ({MAX_WRITE_BYTES} bytes)"
        )));
    }

    let parent = path
        .parent()
        .ok_or_else(|| FsError::IoError("no parent component in target path".to_string()))?;

    // SLICE A: parent dir MUST already exist. We do NOT call `create_dir_all`
    // here because that would silently follow a symlink injected at any missing
    // intermediate component (TOCTOU race against the resolver's pre-walk),
    // potentially escaping the agent's territory. Auto-creation of nested
    // directories is deferred to slice B+ which will use rustix's openat2 with
    // RESOLVE_NO_SYMLINKS for symlink-safe path traversal. For now, the agent's
    // territory layout is set up by MODULE-005 spawn-child / init-child-workspace;
    // intra-territory dirs must be created by an explicit (future) host fn.
    match tokio::fs::symlink_metadata(parent).await {
        Ok(m) if m.file_type().is_dir() => {}
        Ok(_) => return Err(FsError::IoError("parent is not a directory".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FsError::IoError(
                "parent directory does not exist (auto-creation deferred to slice B)".into(),
            ));
        }
        Err(e) => return Err(FsError::IoError(sanitize_io_error(&e))),
    }

    // tempfile is a sync API; building the NamedTempFile is cheap (just opens a
    // temp inode in the same parent dir). The actual write happens via tokio's
    // async writer below, then we hand back to tempfile for atomic persist.
    let temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| FsError::IoError(sanitize_io_error(&e)))?;

    // Write data + fsync via tokio. We move the std::fs::File out of NamedTempFile,
    // wrap in tokio::fs::File for async writes, then reattach via persist.
    let temp_path = temp.path().to_path_buf();
    {
        // Open by path so we don't have to share the temp file handle across the
        // sync/async boundary — NamedTempFile keeps the unlink-on-drop guard alive.
        let mut writer = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .await
            .map_err(|e| FsError::IoError(sanitize_io_error(&e)))?;
        writer
            .write_all(data)
            .await
            .map_err(|e| FsError::IoError(sanitize_io_error(&e)))?;
        writer
            .flush()
            .await
            .map_err(|e| FsError::IoError(sanitize_io_error(&e)))?;
        writer
            .sync_all()
            .await
            .map_err(|e| FsError::IoError(sanitize_io_error(&e)))?;
    }

    // Atomic rename — runs sync, but it's a single syscall on POSIX.
    temp.persist(path)
        .map_err(|e| FsError::IoError(sanitize_io_error(&e.error)))?;

    // Parent-dir fsync — closes the post-rename durability gap on filesystems
    // where directory entries aren't transactionally durable (e.g. xfs without
    // explicit dir-fsync). On Linux ext4 default `data=ordered` and macOS APFS
    // this is implicit, but POSIX doesn't guarantee it. Best-effort: if open
    // or sync fails, the rename has already succeeded so we silently continue.
    if let Ok(dir_handle) = tokio::fs::File::open(parent).await {
        let _ = dir_handle.sync_all().await;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// AtomicWriter trait — slice B injection seam.
//
// Both `MetaMaintainer` (.meta.yaml writes) and `FsWriteHandler` (data writes)
// route through this trait so tests can inject failures at specific call counts
// to exercise the meta-first commit / rollback paths (SB-T66 series). Production
// uses `DefaultAtomicWriter` which forwards to `atomic_write`.
// ─────────────────────────────────────────────────────────────────────────────

/// Injectable atomic-write seam used by MetaMaintainer + FsWriteHandler.
#[async_trait::async_trait]
pub trait AtomicWriter: Send + Sync {
    async fn write(&self, path: &Path, data: &[u8]) -> Result<(), FsError>;
}

/// Production impl — forwards to `atomic_write`.
pub struct DefaultAtomicWriter;

#[async_trait::async_trait]
impl AtomicWriter for DefaultAtomicWriter {
    async fn write(&self, path: &Path, data: &[u8]) -> Result<(), FsError> {
        atomic_write(path, data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn atomic_write_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("a.txt");
        atomic_write(&path, b"hello").await.unwrap();
        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, b"hello");
    }

    #[tokio::test]
    async fn atomic_write_overwrites_existing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("b.txt");
        std::fs::write(&path, b"old-content-larger").unwrap();
        atomic_write(&path, b"new").await.unwrap();
        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, b"new");
    }

    #[tokio::test]
    async fn atomic_write_rejects_oversized() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("c.txt");
        let data = vec![0u8; MAX_WRITE_BYTES + 1];
        let err = atomic_write(&path, &data).await.unwrap_err();
        match err {
            FsError::IoError(msg) => assert!(msg.contains("MAX_WRITE_BYTES"), "got: {msg}"),
            other => panic!("expected IoError, got {other:?}"),
        }
        assert!(
            !path.exists(),
            "atomic_write must not create the file when bound is exceeded"
        );
    }

    #[tokio::test]
    async fn atomic_write_rejects_when_parent_missing() {
        // Slice A intentionally does NOT auto-create parent dirs — TOCTOU
        // hardening per adversarial round 1 (symlink injection between resolver
        // walk and create_dir_all). atomic_write returns IoError instead.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested/deeper/d.txt");
        let err = atomic_write(&path, b"x").await.unwrap_err();
        match err {
            FsError::IoError(msg) => assert!(
                msg.contains("parent directory does not exist"),
                "expected parent-missing error, got: {msg}"
            ),
            other => panic!("expected IoError, got {other:?}"),
        }
        assert!(!path.exists());
    }
}
