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

use std::path::Path;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
