//! SecretStorage trait-object seam + in-memory backend for Slice A.
//!
//! A future slice coordinated with MODULE-004 adds `SqliteSecretStorage`
//! against the same trait without changing the `SecretStore` consumer
//! site. The `'static` bound on the trait ensures every backend owns its
//! data (no `&Connection` borrow patterns).

use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Clone, Debug)]
pub struct StoredSecret {
    /// nonce (12 bytes) || ciphertext
    pub encrypted_value: Vec<u8>,
    /// 16-byte random salt (per-secret HKDF input).
    pub key_salt: Vec<u8>,
}

/// Zeroize both fields on drop — defense-in-depth for the in-memory
/// overwrite path (`InMemorySecretStorage::put` drops the prior row
/// when a name is replaced; without this impl the salt + ciphertext
/// would linger in the allocator).
impl Drop for StoredSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.encrypted_value.zeroize();
        self.key_salt.zeroize();
    }
}

pub enum StorageError {
    Backend(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Backend(_) => write!(f, "storage backend error"),
        }
    }
}

/// Manual Debug impl — delegates to Display so `{:?}` formatting cannot
/// leak any `Backend(String)` payload byte content. A backend implementer
/// who needs to see the raw message should log it directly at the backend's
/// own layer, not through StorageError's Debug.
impl std::fmt::Debug for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for StorageError {}

pub trait SecretStorage: Send + Sync + 'static {
    fn put(&self, name: &str, stored: StoredSecret) -> Result<(), StorageError>;
    fn get(&self, name: &str) -> Result<Option<StoredSecret>, StorageError>;
    fn exists(&self, name: &str) -> Result<bool, StorageError>;
    /// Remove a stored secret by name. `Ok(true)` when it existed, `Ok(false)` when there
    /// was nothing to remove. Backs `advance secrets remove` and the provider `:clear-key`
    /// route (lane providers-family, 2026-09-16 — lifted from a `FileSecretStorage`
    /// inherent method so every backend, including the keychain-sync one, serves it
    /// through the trait object the daemon holds).
    fn remove(&self, name: &str) -> Result<bool, StorageError>;
    /// Names of every stored secret, sorted. Names only — never any (even encrypted)
    /// value bytes.
    fn names(&self) -> Vec<String>;
}

#[derive(Default)]
pub struct InMemorySecretStorage {
    inner: RwLock<HashMap<String, StoredSecret>>,
}

impl InMemorySecretStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStorage for InMemorySecretStorage {
    fn put(&self, name: &str, stored: StoredSecret) -> Result<(), StorageError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(name.to_string(), stored);
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<StoredSecret>, StorageError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.get(name).cloned())
    }

    fn exists(&self, name: &str) -> Result<bool, StorageError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.contains_key(name))
    }

    fn remove(&self, name: &str) -> Result<bool, StorageError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        Ok(guard.remove(name).is_some())
    }

    fn names(&self) -> Vec<String> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<String> = guard.keys().cloned().collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_put_get_exists_roundtrip() {
        let s = InMemorySecretStorage::new();
        let secret = StoredSecret {
            encrypted_value: vec![0xab; 44],
            key_salt: vec![0xcd; 16],
        };
        s.put("k", secret.clone()).unwrap();
        let got = s.get("k").unwrap().unwrap();
        assert_eq!(got.encrypted_value, secret.encrypted_value);
        assert_eq!(got.key_salt, secret.key_salt);
        assert!(s.exists("k").unwrap());
    }

    #[test]
    fn test_in_memory_exists_empty_returns_false() {
        let s = InMemorySecretStorage::new();
        assert!(!s.exists("nonexistent").unwrap());
        assert!(s.get("nonexistent").unwrap().is_none());
    }
}
