//! `FileSecretStorage` — the first *persistent* [`SecretStorage`] backend
//! (/dev WS-A, 2026-06-04).
//!
//! Persists already-encrypted [`StoredSecret`] blobs to a JSON file
//! (`<workspace>/.advance/secrets.json` in production). It is a peer of
//! `InMemorySecretStorage` on the same trait seam (MODULE-012 §1.4.1); the
//! MODULE-004-coordinated `SqliteSecretStorage` remains a valid future backend.
//!
//! **NO extra crypto.** [`SecretStore`](crate::SecretStore) already
//! AES-256-GCM-encrypts each value (under the keychain-derived master key)
//! *before* calling [`SecretStorage::put`], so this backend only ever sees
//! ciphertext. It therefore just (de)serializes the two `Vec<u8>`
//! ciphertext+salt fields — hex-encoded via a private serde DTO, because
//! `StoredSecret` deliberately derives no serde and zeroizes on drop.
//!
//! **Memory hygiene** is best-effort defense-in-depth: the persisted bytes are
//! ciphertext, not plaintext, so this layer cannot leak a usable secret. To
//! honor MODULE-012 §1.7's "all key material forms" bar for the ciphertext
//! form, the serialized JSON buffer and the file bytes read back on `open` are
//! wrapped in [`Zeroizing`]; the transient hex `String`s inside the DTO are not
//! individually scrubbed (ciphertext-only ⇒ accepted residual).
//!
//! **Concurrency**: single-process. The `advance start` runtime lock enforces a
//! single active runtime, and `advance secrets set` is an admin op. There is no
//! cross-process file lock — a concurrent-safe / index-backed store is the
//! `SqliteSecretStorage` slice's concern (MODULE-012 §3.6).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::storage::{SecretStorage, StorageError, StoredSecret};

/// On-disk file schema version. Bumped if the JSON layout changes; `open`
/// rejects unknown versions so a forward-incompatible file fails loudly rather
/// than silently dropping secrets.
const FORMAT_VERSION: u32 = 1;

/// Serde DTO for one persisted row. `StoredSecret` derives no serde (and
/// zeroizes on drop), so the two `Vec<u8>` ciphertext fields are hex-encoded
/// here at the file boundary and decoded back into `StoredSecret` on read.
#[derive(Serialize, Deserialize)]
struct PersistedSecret {
    /// hex of `StoredSecret.encrypted_value` (`[VERSION|nonce|ciphertext+tag]`).
    encrypted_value: String,
    /// hex of `StoredSecret.key_salt` (the per-secret HKDF salt).
    key_salt: String,
}

/// Top-level JSON document: `{ "version": 1, "secrets": { name: {...} } }`.
#[derive(Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    secrets: BTreeMap<String, PersistedSecret>,
}

/// On-disk [`SecretStorage`] backend. Holds an in-memory cache (loaded at
/// `open`) and atomically rewrites the whole JSON file on every mutation.
pub struct FileSecretStorage {
    path: PathBuf,
    cache: RwLock<HashMap<String, StoredSecret>>,
}

impl FileSecretStorage {
    /// Open (or initialize) the secret file at `path`.
    ///
    /// - File absent → starts with an empty cache (first `put` creates it).
    /// - File present → parsed + hex-decoded into the cache.
    /// - File present but unreadable / not valid JSON / unknown version /
    ///   non-hex field → [`StorageError::Backend`] (fail loud, never silently
    ///   drop secrets).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let path = path.into();
        let cache = if fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_file() && m.len() <= 1_048_576)
            .unwrap_or(false)
        {
            let bytes = Zeroizing::new({
                let mut opts = fs::OpenOptions::new();
                opts.read(true);
                #[cfg(unix)]
                {
                    opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                }
                let mut f = opts
                    .open(&path)
                    .map_err(|e| StorageError::Backend(format!("read secrets file: {e}")))?;
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut f, &mut buf)
                    .map_err(|e| StorageError::Backend(format!("read secrets file: {e}")))?;
                if buf.len() > 1_048_576 {
                    return Err(StorageError::Backend("secrets file too large".into()));
                }
                buf
            });
            let doc: FileFormat = serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::Backend(format!("parse secrets file: {e}")))?;
            if doc.version != FORMAT_VERSION {
                return Err(StorageError::Backend(format!(
                    "unsupported secrets file version {} (expected {FORMAT_VERSION})",
                    doc.version
                )));
            }
            let mut map = HashMap::with_capacity(doc.secrets.len());
            for (name, row) in doc.secrets {
                let encrypted_value =
                    Zeroizing::new(hex::decode(&row.encrypted_value).map_err(|e| {
                        StorageError::Backend(format!("decode encrypted_value: {e}"))
                    })?);
                let key_salt = Zeroizing::new(
                    hex::decode(&row.key_salt)
                        .map_err(|e| StorageError::Backend(format!("decode key_salt: {e}")))?,
                );
                map.insert(
                    name,
                    StoredSecret {
                        encrypted_value: encrypted_value.to_vec(),
                        key_salt: key_salt.to_vec(),
                    },
                );
            }
            map
        } else {
            HashMap::new()
        };
        Ok(Self {
            path,
            cache: RwLock::new(cache),
        })
    }

    /// Names of all stored secrets, sorted. Backs `advance secrets list`.
    /// Returns names only — never any (even encrypted) value bytes.
    pub fn names(&self) -> Vec<String> {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<String> = guard.keys().cloned().collect();
        names.sort();
        names
    }

    /// Remove a secret by name, rewriting the file. Returns `Ok(true)` if it
    /// existed, `Ok(false)` if there was nothing to remove (no file write in
    /// that case). Backs `advance secrets remove`.
    pub fn remove(&self, name: &str) -> Result<bool, StorageError> {
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        let Some(old) = guard.remove(name) else {
            return Ok(false);
        };
        match persist(&self.path, &guard) {
            Ok(()) => Ok(true),
            Err(e) => {
                // Roll back the in-memory state so cache and disk stay consistent.
                guard.insert(name.to_string(), old);
                Err(e)
            }
        }
    }
}

impl SecretStorage for FileSecretStorage {
    fn put(&self, name: &str, stored: StoredSecret) -> Result<(), StorageError> {
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        let old = guard.insert(name.to_string(), stored);
        match persist(&self.path, &guard) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Roll back to the prior state (restore the overwritten value,
                // or remove the freshly-inserted name) so cache == disk.
                match old {
                    Some(prev) => {
                        guard.insert(name.to_string(), prev);
                    }
                    None => {
                        guard.remove(name);
                    }
                }
                Err(e)
            }
        }
    }

    fn get(&self, name: &str) -> Result<Option<StoredSecret>, StorageError> {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.get(name).cloned())
    }

    fn exists(&self, name: &str) -> Result<bool, StorageError> {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.contains_key(name))
    }
}

/// Serialize the whole map to the JSON file atomically (temp file + rename),
/// mode `0600`. The whole file is rewritten on every mutation — the secret set
/// is tiny (a handful of provider keys), so this is simpler and safer than
/// in-place edits.
fn persist(path: &Path, map: &HashMap<String, StoredSecret>) -> Result<(), StorageError> {
    let mut secrets = BTreeMap::new();
    for (name, stored) in map {
        secrets.insert(
            name.clone(),
            PersistedSecret {
                encrypted_value: hex::encode(&stored.encrypted_value),
                key_salt: hex::encode(&stored.key_salt),
            },
        );
    }
    let doc = FileFormat {
        version: FORMAT_VERSION,
        secrets,
    };
    // Ciphertext-hex buffer — Zeroizing per the best-effort §1.7 posture.
    let json = Zeroizing::new(
        serde_json::to_vec_pretty(&doc)
            .map_err(|e| StorageError::Backend(format!("serialize secrets: {e}")))?,
    );
    atomic_write(path, &json)
}

/// Write `bytes` to `path` atomically: write a sibling temp file (mode `0600`),
/// fsync it, then `rename` over the target (atomic within a filesystem). The
/// target inherits the temp's `0600` mode. The enclosing `.advance/` directory
/// is `0700` (owner-only, created by `advance init`), which is the trust
/// boundary for the file itself.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::Backend("secrets path has no parent directory".to_string()))?;
    fs::create_dir_all(parent)
        .map_err(|e| StorageError::Backend(format!("create secrets dir: {e}")))?;

    // Temp path: "<file>.tmp" in the same directory (so rename is intra-fs).
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);

    {
        if let Ok(m) = fs::symlink_metadata(&tmp) {
            if !m.file_type().is_file() {
                fs::remove_file(&tmp).map_err(|e| {
                    StorageError::Backend(format!("remove planted secrets tmp: {e}"))
                })?;
            }
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| StorageError::Backend(format!("open temp secrets file: {e}")))?;
        // `mode(_)` only applies on creation; if a stale temp existed it keeps
        // its old mode, so re-assert 0600 explicitly.
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| StorageError::Backend(format!("chmod temp secrets file: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| StorageError::Backend(format!("write temp secrets file: {e}")))?;
        f.sync_all()
            .map_err(|e| StorageError::Backend(format!("fsync temp secrets file: {e}")))?;
    }

    fs::rename(&tmp, path).map_err(|e| {
        // Best-effort cleanup of the temp on rename failure.
        let _ = fs::remove_file(&tmp);
        StorageError::Backend(format!("rename temp secrets file into place: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn secret(a: u8, b: u8) -> StoredSecret {
        StoredSecret {
            encrypted_value: vec![a; 44],
            key_salt: vec![b; 16],
        }
    }

    #[test]
    fn put_get_exists_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let s = FileSecretStorage::open(&path).unwrap();
        s.put("k", secret(0xab, 0xcd)).unwrap();
        let got = s.get("k").unwrap().unwrap();
        assert_eq!(got.encrypted_value, vec![0xab; 44]);
        assert_eq!(got.key_salt, vec![0xcd; 16]);
        assert!(s.exists("k").unwrap());
        assert!(!s.exists("absent").unwrap());
        assert!(s.get("absent").unwrap().is_none());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        {
            let s = FileSecretStorage::open(&path).unwrap();
            s.put("openai-api-key", secret(0x11, 0x22)).unwrap();
            s.put("anthropic-api-key", secret(0x33, 0x44)).unwrap();
        }
        // Fresh instance over the same file sees both.
        let s2 = FileSecretStorage::open(&path).unwrap();
        assert_eq!(
            s2.get("openai-api-key").unwrap().unwrap().encrypted_value,
            vec![0x11; 44]
        );
        assert_eq!(
            s2.get("anthropic-api-key").unwrap().unwrap().key_salt,
            vec![0x44; 16]
        );
        assert_eq!(
            s2.names(),
            vec![
                "anthropic-api-key".to_string(),
                "openai-api-key".to_string()
            ]
        );
    }

    #[test]
    fn overwrite_then_reopen_keeps_latest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let s = FileSecretStorage::open(&path).unwrap();
        s.put("k", secret(0x01, 0x02)).unwrap();
        s.put("k", secret(0x09, 0x0a)).unwrap(); // overwrite
        drop(s);
        let s2 = FileSecretStorage::open(&path).unwrap();
        assert_eq!(
            s2.get("k").unwrap().unwrap().encrypted_value,
            vec![0x09; 44]
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_is_mode_0600_and_no_temp_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let s = FileSecretStorage::open(&path).unwrap();
        s.put("k", secret(0xaa, 0xbb)).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secrets.json must be mode 0600, got {mode:o}");
        let mut tmp_os = path.as_os_str().to_owned();
        tmp_os.push(".tmp");
        assert!(
            !PathBuf::from(tmp_os).exists(),
            "no .tmp file should be left behind"
        );
    }

    #[test]
    fn remove_deletes_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let s = FileSecretStorage::open(&path).unwrap();
        s.put("a", secret(1, 2)).unwrap();
        s.put("b", secret(3, 4)).unwrap();
        assert!(s.remove("a").unwrap());
        assert!(!s.remove("a").unwrap()); // already gone → false, no rewrite
        assert!(!s.exists("a").unwrap());
        // persisted: reopen sees only "b"
        let s2 = FileSecretStorage::open(&path).unwrap();
        assert_eq!(s2.names(), vec!["b".to_string()]);
    }

    #[test]
    fn corrupt_file_fails_loud_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        fs::write(&path, b"{ this is not valid json").unwrap();
        assert!(FileSecretStorage::open(&path).is_err());
    }

    #[test]
    fn unknown_version_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        fs::write(&path, br#"{"version":999,"secrets":{}}"#).unwrap();
        assert!(FileSecretStorage::open(&path).is_err());
    }

    /// End-to-end through the real `SecretStore` crypto layer: store a value via
    /// one `SecretStore` over `FileSecretStorage`, reopen the file in a fresh
    /// `SecretStore` with the same master key, and `resolve` it back — proving
    /// the ciphertext persists to disk and decrypts cleanly (the daemon-resolve
    /// round-trip `advance secrets set` relies on).
    #[test]
    fn secretstore_over_file_roundtrips_across_reopen() {
        use crate::store::SecretStore;
        use zeroize::Zeroizing;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let master = Zeroizing::new([0x5a; 32]);

        {
            let storage: Arc<dyn SecretStorage> = Arc::new(FileSecretStorage::open(&path).unwrap());
            let store = SecretStore::new(master.clone(), storage);
            store
                .store("anthropic-api-key", "sk-ant-secret-value")
                .unwrap();
        }
        // Fresh store + fresh FileSecretStorage over the same file + same key.
        let storage2: Arc<dyn SecretStorage> = Arc::new(FileSecretStorage::open(&path).unwrap());
        let store2 = SecretStore::new(master, storage2);
        let resolved = store2.resolve("anthropic-api-key").unwrap();
        use secrecy::ExposeSecret;
        assert_eq!(resolved.expose_secret(), "sk-ant-secret-value");
    }
}
