//! Repo-free git-blob content hash — the L6 staleness lookup primitive (Wave-9 Lane B).
//!
//! The L6 `StalenessProbe` (MODULE-011) judges a `kind=file-ref` knowledge source by
//! comparing its stored `blob_id` against the CURRENT git blob of the on-disk file.
//! `git2::Oid::hash_file` computes that OID exactly as `git hash-object` would — it streams
//! the file content through libgit2's blob hasher WITHOUT needing (or touching) any
//! repository or object database. Keeping this primitive inside MODULE-003 — the only crate
//! that imports `git2` directly (§1.1) — lets the cli L6 `GitBlobFileResolver` compute the
//! current blob WITHOUT the cli crate naming `git2` (whose cli dependency is dev-only).
//!
//! This is an internal utility, NOT a §6.1 CONTRACT.
//!
//! [`BlobHasher`] (ADR 2026-10-15; MODULE-002 §1.4.9) is the streaming form: callers that
//! must never hash by path (the fs core hashes an already-opened `O_NOFOLLOW|O_NONBLOCK`
//! descriptor after an `S_ISREG` `fstat`; a staged upload is verified as it streams) feed
//! the bytes themselves and get the same `git hash-object` id, with no repository and no
//! object written.

use std::path::Path;

use sha1::{Digest, Sha1};

/// Compute the git blob OID (`git hash-object` semantics) of the file at `path`.
///
/// Returns `Some(<40-char lowercase hex OID>)` on success, or `None` if the file is
/// missing / unreadable / cannot be hashed. The `None`-on-error contract is the
/// conservative "no current blob" outcome the L6 staleness probe wants: a file that no
/// longer resolves (gone, permission-denied, etc.) is judged stale rather than erroring
/// the consolidation.
///
/// Repo-free: `git2::Oid::hash_file` reads + hashes the content without opening a
/// repository, so this works on any path (inside or outside a git workdir).
pub fn blob_oid_of_file(path: &Path) -> Option<String> {
    git2::Oid::hash_file(git2::ObjectType::Blob, path)
        .ok()
        .map(|oid| oid.to_string())
}

/// The git blob id (`git hash-object` semantics, 40 lowercase hex) of `bytes`.
pub fn blob_oid_of_bytes(bytes: &[u8]) -> String {
    let mut hasher = BlobHasher::new(bytes.len() as u64);
    hasher.update(bytes);
    // The declared length is the slice's own, so the length check cannot fail.
    hasher.finish().unwrap_or_default()
}

/// A streaming git blob id: `sha1("blob <len>\0" ‖ content)`, the id `git hash-object`
/// prints, computed without a repository and without writing an object.
///
/// The content length is part of the header, so it is declared up front (the `fstat` size
/// of the file being read, or an upload's `Content-Length`); [`BlobHasher::finish`]
/// refuses a stream that delivered a different number of bytes, because the id would then
/// name content other than what was declared (a file that changed while it was read).
/// `std::io::Write` is implemented, so `std::io::copy` streams a reader into it.
#[derive(Clone)]
pub struct BlobHasher {
    sha: Sha1,
    declared: u64,
    fed: u64,
}

impl BlobHasher {
    /// Start hashing a blob of `len` bytes.
    pub fn new(len: u64) -> Self {
        let mut sha = Sha1::new();
        sha.update(format!("blob {len}\0").as_bytes());
        Self {
            sha,
            declared: len,
            fed: 0,
        }
    }

    /// Feed the next bytes of the content.
    pub fn update(&mut self, bytes: &[u8]) {
        self.sha.update(bytes);
        self.fed = self.fed.saturating_add(bytes.len() as u64);
    }

    /// Bytes fed so far.
    pub fn fed(&self) -> u64 {
        self.fed
    }

    /// The blob id, or [`BlobLengthMismatch`] when the stream did not deliver exactly the
    /// declared length.
    pub fn finish(self) -> Result<String, BlobLengthMismatch> {
        if self.fed != self.declared {
            return Err(BlobLengthMismatch {
                declared: self.declared,
                fed: self.fed,
            });
        }
        let digest = self.sha.finalize();
        let mut hex = String::with_capacity(40);
        for byte in digest.iter() {
            hex.push_str(&format!("{byte:02x}"));
        }
        Ok(hex)
    }
}

impl std::fmt::Debug for BlobHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobHasher")
            .field("declared", &self.declared)
            .field("fed", &self.fed)
            .finish_non_exhaustive()
    }
}

impl std::io::Write for BlobHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A [`BlobHasher`] stream that did not deliver the declared length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobLengthMismatch {
    pub declared: u64,
    pub fed: u64,
}

impl std::fmt::Display for BlobLengthMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "blob declared {} bytes but {} were fed",
            self.declared, self.fed
        )
    }
}

impl std::error::Error for BlobLengthMismatch {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ADR 2026-10-15 (MODULE-002 §1.4.9): chunked == one-shot == libgit2's own hash.
    #[test]
    fn blob_hasher_matches_git_hash_object() {
        let mut big = Vec::with_capacity(1 << 20);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..(1 << 20) {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            big.push((x >> 16) as u8);
        }
        for content in [&b""[..], b"hello world\n", b"a\r\nb\0c", &big[..]] {
            let expected = git2::Oid::hash_object(git2::ObjectType::Blob, content)
                .unwrap()
                .to_string();
            assert_eq!(blob_oid_of_bytes(content), expected);
            let mut hasher = BlobHasher::new(content.len() as u64);
            for chunk in content.chunks(4093) {
                hasher.write_all(chunk).unwrap();
            }
            assert_eq!(hasher.fed(), content.len() as u64);
            assert_eq!(hasher.finish().unwrap(), expected);
            let mut hasher = BlobHasher::new(content.len() as u64);
            std::io::copy(&mut &content[..], &mut hasher).unwrap();
            assert_eq!(hasher.finish().unwrap(), expected);
        }
        assert_eq!(
            blob_oid_of_bytes(b"hello world\n"),
            "3b18e512dba79e4c8300dd08aeb37f8e728b8dad"
        );
    }

    #[test]
    fn blob_hasher_refuses_length_mismatch() {
        let mut short = BlobHasher::new(5);
        short.update(b"four");
        assert_eq!(
            short.finish(),
            Err(BlobLengthMismatch {
                declared: 5,
                fed: 4
            })
        );
        let mut long = BlobHasher::new(3);
        long.update(b"four");
        let err = long.finish().unwrap_err();
        assert_eq!(err.fed, 4);
        assert_eq!(err.to_string(), "blob declared 3 bytes but 4 were fed");
    }

    // W0: an existing file hashes to the deterministic git blob OID — equal to git2's
    // own hash and to the well-known `git hash-object` value, proving genuine
    // `git hash-object` semantics (not some ad-hoc digest).
    #[test]
    fn blob_oid_of_existing_file_is_git_hash_object() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"hello world\n").unwrap();
        drop(f);

        let got = blob_oid_of_file(&p).expect("an existing file hashes");
        assert_eq!(got.len(), 40, "git blob OID is 40 hex chars: {got}");
        assert!(
            got.chars().all(|c| c.is_ascii_hexdigit()),
            "hex only: {got}"
        );
        // Deterministic + equal to git2's own hash of the same content.
        let direct = git2::Oid::hash_file(git2::ObjectType::Blob, &p)
            .unwrap()
            .to_string();
        assert_eq!(got, direct);
        assert_eq!(got, blob_oid_of_file(&p).unwrap(), "stable across calls");
        // The canonical `git hash-object` value for the bytes "hello world\n".
        assert_eq!(got, "3b18e512dba79e4c8300dd08aeb37f8e728b8dad");
    }

    // W0: a missing file yields None (the conservative "no current blob" outcome).
    #[test]
    fn blob_oid_of_missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.txt");
        assert_eq!(blob_oid_of_file(&missing), None);
    }

    // Different content → different OID (so a superseded file is judged stale).
    #[test]
    fn blob_oid_differs_on_content_change() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.txt");
        std::fs::write(&p, b"one").unwrap();
        let a = blob_oid_of_file(&p).unwrap();
        std::fs::write(&p, b"two").unwrap();
        let b = blob_oid_of_file(&p).unwrap();
        assert_ne!(a, b, "a different blob hashes differently");
    }
}
