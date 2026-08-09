//! Slice-A sync atomic_write: write-tmp + `std::fs::rename`.
//!
//! Mirrors cap-fs `atomic_write` semantics but synchronous (no tokio dep).
//! Slice A use is bounded to small files (config.yaml, AGENTS.md placeholder,
//! empty knowledge.jsonl) — `MAX_BYTES = 64 KiB` is a generous cap relative
//! to actual usage (~ few hundred bytes each).

use std::path::Path;

use crate::error::SpawnError;
use crate::identifier::sub_uuid_v4;

pub const MAX_BYTES: usize = 64 * 1024;

/// Write `content` atomically to `path`. Writes a unique tmp file in the
/// same directory then `std::fs::rename` over the target. Parent dir MUST
/// exist (no `create_dir_all`); caller is responsible for parent creation.
///
/// Errors:
/// - `content.len() > MAX_BYTES` → `WorkspaceIoFailure("payload N > MAX_BYTES")`.
/// - missing parent dir → `WorkspaceIoFailure`.
/// - missing filename component in `path` → `WorkspaceIoFailure`.
/// - any `std::fs::write` / `rename` io::Error → `WorkspaceIoFailure(msg)`.
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<(), SpawnError> {
    if content.len() > MAX_BYTES {
        return Err(SpawnError::WorkspaceIoFailure(format!(
            "payload {} > MAX_BYTES {}",
            content.len(),
            MAX_BYTES
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        SpawnError::WorkspaceIoFailure(format!("no parent dir for {}", path.display()))
    })?;
    if !parent.is_dir() {
        return Err(SpawnError::WorkspaceIoFailure(format!(
            "parent dir missing: {}",
            parent.display()
        )));
    }
    let file_name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
        SpawnError::WorkspaceIoFailure(format!("no filename: {}", path.display()))
    })?;
    let tmp_name = format!(".{}.{}.tmp", file_name, sub_uuid_v4());
    let tmp_path = parent.join(&tmp_name);
    // Defensive cleanup of any leftover with the same tmp name (rare given UUID).
    if tmp_path.exists() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    std::fs::write(&tmp_path, content).map_err(|e| {
        SpawnError::WorkspaceIoFailure(format!("write {}: {e}", tmp_path.display()))
    })?;
    std::fs::rename(&tmp_path, path).map_err(|e| {
        // best-effort cleanup; surface original error
        let _ = std::fs::remove_file(&tmp_path);
        SpawnError::WorkspaceIoFailure(format!(
            "rename {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn happy_path() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("file.txt");
        atomic_write(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn empty_content_ok() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("empty.txt");
        atomic_write(&p, b"").unwrap();
        assert!(p.is_file());
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 0);
    }

    #[test]
    fn rejects_overlong() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("big.bin");
        let big = vec![0u8; MAX_BYTES + 1];
        assert!(matches!(
            atomic_write(&p, &big),
            Err(SpawnError::WorkspaceIoFailure(_))
        ));
    }

    #[test]
    fn rejects_missing_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("nonexistent").join("file.txt");
        assert!(matches!(
            atomic_write(&p, b"x"),
            Err(SpawnError::WorkspaceIoFailure(_))
        ));
    }
}
