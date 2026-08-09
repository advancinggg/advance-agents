//! SHA-256 checksum verification per MODULE-018 §1.3.2 step ③ (AC-06).
//!
//! Slice A defense:
//! - Reject suspicious checksum-keys BEFORE filesystem access (abs / empty / null
//!   / parent-traversal).
//! - Hoist `canonicalize(root)` out of the per-entry loop.
//! - Missing file → `ChecksumMismatch` with `actual="<missing>"`, NOT opaque Io.
//! - Final canonicalize+ancestor check catches symlink escape introduced after
//!   manifest write.
//!
//! Caller pre-condition (TOCTOU note — best effort, NOT absolute): the `root`
//! directory passed in SHOULD have been populated via
//! [`crate::fetch::copy_dir_no_symlinks`] (or an equivalent symlink-rejecting
//! copy). `install.rs` step ② calls `copy_dir_no_symlinks` before this, but
//! that copier itself has a TOCTOU window between `symlink_metadata` and
//! `std::fs::copy` — an attacker with write access to the *source* directory
//! during install can still smuggle a symlink in. Slice A's threat model
//! bounds this by trusting the admin source (admin's local checkout);
//! Slice B closes the window via `rustix::fs::openat2(RESOLVE_NO_SYMLINKS)`
//! on Linux 5.6+. See MODULE-018 §2.9 + §3.6 for the full documented gap.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{error::PackError, manifest::PackChecksums};

/// Maximum permitted size for any single checksummed artifact — 256 MiB.
/// Bounds memory + I/O cost during step ③ hashing; an unbounded
/// `std::fs::read` would otherwise let a malicious source ship a multi-GiB
/// `.wasm` and OOM the installer (round-9 adversarial W4 / W3).
const MAX_CHECKSUM_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum permitted total bytes hashed in a single `verify_checksums` call —
/// 1 GiB. Per-entry capping at 256 MiB still allows up to
/// 4096 (`MAX_CHECKSUM_ENTRIES` in manifest.rs) × 256 MiB = 1 TiB of total
/// hash work, which is a straightforward CPU/I/O DoS surface (Codex round-9
/// r2 W3). The combined cap keeps any single install bounded to a few
/// minutes of hashing on commodity hardware.
const MAX_TOTAL_CHECKSUM_BYTES: u64 = 1024 * 1024 * 1024;

/// I/O chunk size for streaming sha256. 64 KiB matches the host page-cluster
/// granularity on most platforms; oversized (≥1 MiB) chunks cause unnecessary
/// `Vec` stack pressure without throughput benefit on small files.
const HASH_CHUNK_BYTES: usize = 64 * 1024;

pub fn verify_checksums(root: &Path, checksums: &PackChecksums) -> Result<(), PackError> {
    // Canonicalize root ONCE (not per entry).
    let root_canon = std::fs::canonicalize(root).map_err(|e| PackError::Io {
        path: root.to_path_buf(),
        source: e,
    })?;

    // Cumulative-size budget enforcement (Codex r2 W3).
    let mut total_bytes_seen: u64 = 0;

    for (relpath, expected_hex) in &checksums.files {
        // Key validation BEFORE filesystem access.
        if relpath.is_empty()
            || relpath.contains('\0')
            || Path::new(relpath).is_absolute()
            || Path::new(relpath)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(PackError::InvalidManifest(format!(
                "checksum key rejected (abs/empty/null/traversal): {relpath:?}"
            )));
        }

        let abs = root.join(relpath);

        // Round-9 adversarial W6: probe with `symlink_metadata` (which does
        // NOT follow symlinks). NotFound → ChecksumMismatch (`<missing>`);
        // any symlink at the artifact path is rejected outright since a
        // valid checksum target inside an admin-supplied pack should never
        // be a symlink. `path.exists()` previously short-circuited on
        // dangling links, leaking a path-existence oracle and admitting a
        // post-canonicalize Io re-surface on dangling-in-root links.
        let md = match std::fs::symlink_metadata(&abs) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(PackError::ChecksumMismatch(
                    relpath.clone(),
                    expected_hex.clone(),
                    "<missing>".into(),
                ));
            }
            Err(e) => {
                return Err(PackError::Io {
                    path: abs.clone(),
                    source: e,
                });
            }
            Ok(md) => md,
        };
        if md.file_type().is_symlink() {
            return Err(PackError::InvalidManifest(format!(
                "checksum entry rejected (is a symlink): {relpath}"
            )));
        }
        if !md.is_file() {
            return Err(PackError::InvalidManifest(format!(
                "checksum entry not a regular file: {relpath}"
            )));
        }
        if md.len() > MAX_CHECKSUM_FILE_BYTES {
            return Err(PackError::InvalidManifest(format!(
                "checksum entry exceeds max size {MAX_CHECKSUM_FILE_BYTES} bytes ({} bytes): {relpath}",
                md.len()
            )));
        }
        total_bytes_seen = total_bytes_seen.saturating_add(md.len());
        if total_bytes_seen > MAX_TOTAL_CHECKSUM_BYTES {
            return Err(PackError::InvalidManifest(format!(
                "checksums.files total size exceeds {MAX_TOTAL_CHECKSUM_BYTES} bytes ({total_bytes_seen} bytes so far)"
            )));
        }

        // Canonicalize + ancestor check (catches symlinks in INTERMEDIATE
        // path components; the leaf symlink case is already rejected above).
        let canon = std::fs::canonicalize(&abs).map_err(|e| PackError::Io {
            path: abs.clone(),
            source: e,
        })?;
        if !canon.starts_with(&root_canon) {
            return Err(PackError::InvalidManifest(format!(
                "checksum entry escapes pack root: {relpath}"
            )));
        }

        // Round-9 adversarial W3: stream the hash in fixed-size chunks
        // instead of `std::fs::read` (which allocates the full file).
        // Bounded by `MAX_CHECKSUM_FILE_BYTES` above; memory is `O(chunk)`.
        let mut f = std::fs::File::open(&canon).map_err(|e| PackError::Io {
            path: canon.clone(),
            source: e,
        })?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; HASH_CHUNK_BYTES];
        loop {
            let n = f.read(&mut buf).map_err(|e| PackError::Io {
                path: canon.clone(),
                source: e,
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hex::encode(hasher.finalize());
        if !constant_time_eq(actual.as_bytes(), expected_hex.as_bytes()) {
            return Err(PackError::ChecksumMismatch(
                relpath.clone(),
                expected_hex.clone(),
                actual,
            ));
        }
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ChecksumAlgo, PackChecksums};
    use std::collections::BTreeMap;
    use std::io::Write;

    fn make_pack_with_file(name: &str, content: &[u8]) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        let digest = hex::encode(Sha256::digest(content));
        (dir, digest)
    }

    #[test]
    fn t15_tampered_file_returns_mismatch() {
        let (dir, _real) = make_pack_with_file("pack.yaml", b"actual-content");
        let mut files = BTreeMap::new();
        files.insert("pack.yaml".into(), "0".repeat(64));
        let checksums = PackChecksums {
            algo: ChecksumAlgo::Sha256,
            files,
        };
        match verify_checksums(dir.path(), &checksums) {
            Err(PackError::ChecksumMismatch(rel, _, _)) => assert_eq!(rel, "pack.yaml"),
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn t16_reject_parent_traversal_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut files = BTreeMap::new();
        files.insert("../escape".into(), "abc".into());
        let checksums = PackChecksums {
            algo: ChecksumAlgo::Sha256,
            files,
        };
        match verify_checksums(dir.path(), &checksums) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t25_reject_absolute_path_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut files = BTreeMap::new();
        files.insert("/etc/passwd".into(), "abc".into());
        let checksums = PackChecksums {
            algo: ChecksumAlgo::Sha256,
            files,
        };
        match verify_checksums(dir.path(), &checksums) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t26_reject_null_byte_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut files = BTreeMap::new();
        files.insert("foo\0bar".into(), "abc".into());
        let checksums = PackChecksums {
            algo: ChecksumAlgo::Sha256,
            files,
        };
        match verify_checksums(dir.path(), &checksums) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t34_missing_file_returns_mismatch_not_io() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut files = BTreeMap::new();
        files.insert("pack.yaml".into(), "abc".into());
        let checksums = PackChecksums {
            algo: ChecksumAlgo::Sha256,
            files,
        };
        match verify_checksums(dir.path(), &checksums) {
            Err(PackError::ChecksumMismatch(_, _, actual)) => assert_eq!(actual, "<missing>"),
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn happy_path_passes() {
        let (dir, digest) = make_pack_with_file("pack.yaml", b"hello");
        let mut files = BTreeMap::new();
        files.insert("pack.yaml".into(), digest);
        let checksums = PackChecksums {
            algo: ChecksumAlgo::Sha256,
            files,
        };
        verify_checksums(dir.path(), &checksums).unwrap();
    }
}
