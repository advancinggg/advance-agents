//! cap-secrets — MODULE-012 secrets foundation.
//!
//! Library crate providing:
//! - [`SecretStore`]: three-layer encryption (master key + per-secret
//!   HKDF-SHA256 + AES-256-GCM) over a pluggable [`SecretStorage`] trait.
//! - [`InMemorySecretStorage`]: default in-memory backend.
//! - [`FileSecretStorage`]: persistent on-disk backend (ciphertext blobs →
//!   `.advance/secrets.json`, atomic 0600). A future slice coordinated with
//!   MODULE-004 adds `SqliteSecretStorage` on the same trait seam.
//! - [`load_master_key`]: master-key loader with Keychain → env-var
//!   fallback via the [`EntryProvider`] trait seam.
//! - [`SecretExistsHandler`] + [`register_agent_secrets`]: Slice-A
//!   permissive host-function primitive implementing MODULE-001's
//!   `HostFunctionHandler` trait. Every caller can probe every secret.
//! - [`GatedSecretExistsHandler`] + [`register_agent_secrets_with_policy`]:
//!   m012-slice-e AC-15 caller-dependency abstraction. Caller-side
//!   declared-dependency policies live in [`mod@caller_dep`]
//!   ([`CallerDependencyPolicy`] trait + [`AllowAllCallerDependencyPolicy`]
//!   permissive default + [`DeclaredDependencyPolicy`] allowlist). Production
//!   wiring of per-call `CapParams` through MODULE-001
//!   `CapabilityInjector::inject` is deferred — see MODULE-012 §3.6.
//!
//! See MODULE-012 §3.7 Change History for slice context.

pub mod caller_dep;
pub mod error;
pub mod file_storage;
pub mod host_fn;
pub mod master_key;
pub mod storage;
pub mod store;

pub use caller_dep::{
    AllowAllCallerDependencyPolicy, CallerDependencyPolicy, DeclaredDependencyPolicy,
};
pub use error::SecretError;
pub use file_storage::FileSecretStorage;
pub use host_fn::{
    register_agent_secrets, register_agent_secrets_with_policy, GatedSecretExistsHandler,
    SecretExistsHandler,
};
pub use master_key::{
    load_master_key, DefaultEntryProvider, EntryError, EntryProvider, MasterKeyConfig,
    DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE,
};
pub use storage::{InMemorySecretStorage, SecretStorage, StorageError, StoredSecret};
pub use store::SecretStore;
