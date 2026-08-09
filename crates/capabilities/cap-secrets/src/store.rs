//! SecretStore: three-layer encryption (master key + per-secret HKDF +
//! AES-256-GCM). Master key is `Zeroizing<[u8; 32]>` (ZeroizeOnDrop);
//! resolved values are wrapped in `secrecy::Secret<String>` for
//! consumer-facing API (Debug-hiding + zeroize on drop).

use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::Secret;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::SecretError;
use crate::storage::{SecretStorage, StoredSecret};

/// Format version byte prefixed onto `StoredSecret.encrypted_value`.
/// Layout: `[VERSION (1) | nonce (12) | ciphertext (n)]`.
///
/// A future algorithm / wire-format upgrade bumps this constant and adds
/// a second read arm; reading an unknown version returns `SecretError::Crypto`
/// rather than attempting best-effort decoding (downgrade-attack defense:
/// an attacker cannot force v2 data to be interpreted as v1 by flipping
/// the version byte, because the AES-GCM AAD binds `name` — but NOT the
/// version byte. A future version bump therefore should also include the
/// version byte in the AAD to commit to it. Slice A only has v1 so the
/// AAD coverage gap has no exploitable content today.).
const FORMAT_VERSION_V1: u8 = 0x01;

pub struct SecretStore {
    master: Zeroizing<[u8; 32]>,
    storage: Arc<dyn SecretStorage>,
}

impl SecretStore {
    pub fn new(master: Zeroizing<[u8; 32]>, storage: Arc<dyn SecretStorage>) -> Self {
        Self { master, storage }
    }

    pub fn store(&self, name: &str, value: &str) -> Result<(), SecretError> {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        // Derived per-secret key is Zeroizing to match §1.7 memory-hygiene
        // commitment across all key material forms (master + hex + decoded
        // bytes + derived key).
        let per_secret_key = derive_key(&self.master, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(per_secret_key.as_ref())
            .map_err(|_| SecretError::Crypto("aes-gcm key init failed"))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Bind the secret name as Additional Associated Data (AAD) so a
        // tampered backend cannot swap (key_salt, encrypted_value) between
        // names — decryption with a mismatched name will fail AEAD
        // authentication. Defends against row-swap attacks on the in-memory
        // storage backend (and future SQLite backend).
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: value.as_bytes(),
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| SecretError::Crypto("aes-gcm encrypt failed"))?;

        // Layout: [VERSION (1) | nonce (12) | ciphertext (n)]
        let mut encrypted = Vec::with_capacity(1 + 12 + ct.len());
        encrypted.push(FORMAT_VERSION_V1);
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&ct);

        self.storage.put(
            name,
            StoredSecret {
                encrypted_value: encrypted,
                key_salt: salt.to_vec(),
            },
        )?;
        Ok(())
    }

    pub fn resolve(&self, name: &str) -> Result<Secret<String>, SecretError> {
        let stored = self
            .storage
            .get(name)?
            .ok_or_else(|| SecretError::NotFound(name.to_string()))?;

        // Layout: [VERSION (1) | nonce (12) | ciphertext (≥16 — AES-GCM tag)]
        if stored.encrypted_value.len() < 1 + 12 + 16 {
            return Err(SecretError::Crypto("ciphertext too short"));
        }
        let version = stored.encrypted_value[0];
        if version != FORMAT_VERSION_V1 {
            return Err(SecretError::Crypto("unknown stored-secret format version"));
        }

        let per_secret_key = derive_key(&self.master, &stored.key_salt)?;
        let cipher = Aes256Gcm::new_from_slice(per_secret_key.as_ref())
            .map_err(|_| SecretError::Crypto("aes-gcm key init failed"))?;

        let (nonce_bytes, ct) = stored.encrypted_value[1..].split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypted plaintext wrapped in Zeroizing so the pre-String
        // buffer is scrubbed on drop (both happy path and error path).
        // Using str::from_utf8 on the slice — on UTF-8 failure, the error
        // only borrows (no owned-bytes leak via FromUtf8Error).
        // Pass the secret name as AAD to require the name to match the
        // one used at encrypt time — blocks row-swap attacks (see store()).
        let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ct,
                        aad: name.as_bytes(),
                    },
                )
                .map_err(|_| SecretError::Crypto("aes-gcm decrypt failed"))?,
        );

        let s = std::str::from_utf8(plaintext.as_slice()).map_err(|_| SecretError::InvalidUtf8)?;
        Ok(Secret::new(s.to_string()))
    }

    pub fn exists(&self, name: &str) -> Result<bool, SecretError> {
        Ok(self.storage.exists(name)?)
    }
}

fn derive_key(
    master: &Zeroizing<[u8; 32]>,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master.as_ref());
    let mut okm: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    hk.expand(b"advance-agents-secret-v1", okm.as_mut())
        .map_err(|_| SecretError::Crypto("hkdf expand failed"))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecretStorage;
    use secrecy::ExposeSecret;

    fn test_store() -> SecretStore {
        let master = Zeroizing::new([0xab; 32]);
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        SecretStore::new(master, storage)
    }

    // T02: round-trip identity.
    #[test]
    fn t02_store_resolve_roundtrip() {
        let store = test_store();
        store.store("api_key", "xoxb-secret").unwrap();
        let resolved = store.resolve("api_key").unwrap();
        assert_eq!(resolved.expose_secret(), "xoxb-secret");
    }

    // T03: fresh salt per store() → different ciphertext; both decrypt identically.
    #[test]
    fn t03_fresh_salt_produces_different_ciphertext() {
        let store = test_store();

        // Use a separate inner storage so we can inspect the two stored rows.
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let master = Zeroizing::new([0xab; 32]);
        let s = SecretStore::new(master, Arc::clone(&storage));

        // First store — capture the StoredSecret.
        s.store("a", "v").unwrap();
        let first = storage.get("a").unwrap().unwrap();
        assert_eq!(s.resolve("a").unwrap().expose_secret(), "v");

        // Second store (overwrites) — fresh salt + nonce → different ciphertext.
        s.store("a", "v").unwrap();
        let second = storage.get("a").unwrap().unwrap();

        assert_ne!(
            first.key_salt, second.key_salt,
            "key_salt must differ between two store() calls"
        );
        assert_ne!(
            first.encrypted_value, second.encrypted_value,
            "encrypted_value must differ between two store() calls"
        );
        assert_eq!(s.resolve("a").unwrap().expose_secret(), "v");

        // Also verify the unused `store` helper (suppresses dead-code in future).
        let _ = store;
    }

    #[test]
    fn test_resolve_not_found_returns_not_found_error() {
        let store = test_store();
        let e = store.resolve("nonexistent").unwrap_err();
        match e {
            SecretError::NotFound(name) => assert_eq!(name, "nonexistent"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_exists_reflects_storage() {
        let store = test_store();
        assert!(!store.exists("k").unwrap());
        store.store("k", "v").unwrap();
        assert!(store.exists("k").unwrap());
    }

    // Crypto error-path coverage.
    #[test]
    fn test_resolve_short_ciphertext_returns_crypto_error() {
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let s = SecretStore::new(Zeroizing::new([0xab; 32]), Arc::clone(&storage));
        // Inject a too-short ciphertext directly.
        storage
            .put(
                "k",
                StoredSecret {
                    encrypted_value: vec![0u8; 10], // < 12 bytes
                    key_salt: vec![0u8; 16],
                },
            )
            .unwrap();
        match s.resolve("k").unwrap_err() {
            SecretError::Crypto(reason) => assert!(reason.contains("too short")),
            other => panic!("expected Crypto, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_tampered_ciphertext_returns_crypto_error() {
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let master = Zeroizing::new([0xab; 32]);
        let s = SecretStore::new(master, Arc::clone(&storage));
        s.store("k", "v").unwrap();
        // Corrupt the last byte of the ciphertext (authentication tag).
        let mut row = storage.get("k").unwrap().unwrap();
        let last = row.encrypted_value.len() - 1;
        row.encrypted_value[last] ^= 0xff;
        storage.put("k", row).unwrap();
        match s.resolve("k").unwrap_err() {
            SecretError::Crypto(_) => {}
            other => panic!("expected Crypto, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_row_swap_returns_crypto_error() {
        // Tampered backend swaps (key_salt, encrypted_value) from secret B
        // onto secret A's name. With AAD binding the secret name, resolve("A")
        // must fail AEAD auth rather than successfully decrypt B's plaintext.
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let master = Zeroizing::new([0xab; 32]);
        let s = SecretStore::new(master, Arc::clone(&storage));
        s.store("a", "secret_for_a").unwrap();
        s.store("b", "secret_for_b").unwrap();

        // Both values decrypt correctly under their own names.
        assert_eq!(s.resolve("a").unwrap().expose_secret(), "secret_for_a");
        assert_eq!(s.resolve("b").unwrap().expose_secret(), "secret_for_b");

        // Swap B's ciphertext+salt onto A's row — simulating a backend tamper.
        let row_b = storage.get("b").unwrap().unwrap();
        storage.put("a", row_b).unwrap();

        // resolve("a") must now fail: AAD is "a" at decrypt time but AAD was "b"
        // at encrypt time, so AES-GCM authentication fails.
        match s.resolve("a").unwrap_err() {
            SecretError::Crypto(_) => {}
            other => panic!("expected Crypto (row-swap AAD mismatch), got {other:?}"),
        }

        // resolve("b") still works (original row unchanged in test fixture).
        // Note: the put("a", row_b) above copied the row, it didn't move it.
        assert_eq!(s.resolve("b").unwrap().expose_secret(), "secret_for_b");
    }

    #[test]
    fn test_resolve_unknown_version_returns_crypto_error() {
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let master = Zeroizing::new([0xab; 32]);
        let s = SecretStore::new(master, Arc::clone(&storage));
        s.store("k", "v").unwrap();
        // Flip the version byte to 0xFF — unsupported version.
        let mut row = storage.get("k").unwrap().unwrap();
        row.encrypted_value[0] = 0xff;
        storage.put("k", row).unwrap();
        match s.resolve("k").unwrap_err() {
            SecretError::Crypto(reason) => {
                assert!(
                    reason.contains("unknown") && reason.contains("version"),
                    "expected unknown-version error, got {reason:?}"
                );
            }
            other => panic!("expected Crypto (unknown version), got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_wrong_salt_returns_crypto_error() {
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let master = Zeroizing::new([0xab; 32]);
        let s = SecretStore::new(master, Arc::clone(&storage));
        s.store("k", "v").unwrap();
        // Replace the salt so HKDF derives a different key — AEAD auth fails.
        let mut row = storage.get("k").unwrap().unwrap();
        row.key_salt = vec![0xff; 16];
        storage.put("k", row).unwrap();
        match s.resolve("k").unwrap_err() {
            SecretError::Crypto(_) => {}
            other => panic!("expected Crypto, got {other:?}"),
        }
    }
}
