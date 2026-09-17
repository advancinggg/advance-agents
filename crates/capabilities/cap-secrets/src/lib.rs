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
//!
//! keychain-sync: [`keychain_sync`] is
//! the iCloud-Keychain-synchronized backend behind the [`SecItemOps`] seam, [`factory`] maps
//! the `secrets:` config block to a master key + backend for every composition site, and
//! [`migrate`] moves a home between the File backend and keychain-sync.

// The crate is safe Rust except the single Security.framework FFI module
// (`keychain_sync::apple`, Apple targets only), which opts back in per module.
#![deny(unsafe_code)]

pub mod caller_dep;
pub mod error;
pub mod factory;
pub mod file_storage;
pub mod host_fn;
pub mod keychain_sync;
pub mod master_key;
pub mod migrate;
pub mod storage;
pub mod store;

pub use caller_dep::{
    AllowAllCallerDependencyPolicy, CallerDependencyPolicy, DeclaredDependencyPolicy,
};
pub use error::SecretError;
pub use factory::{
    backend_of, default_sec_item_ops, file_master_key_config, keychain_settings,
    load_master_key as load_master_key_for, namespace_of, open_secret_storage_unkeyed,
    open_secret_store, open_storage, platform_supports_keychain_sync, MasterKeyPolicy,
    OpenedSecretStore, SecretsBackend, PLATFORM_UNSUPPORTED_MSG,
};
pub use file_storage::FileSecretStorage;
pub use host_fn::{
    register_agent_secrets, register_agent_secrets_with_policy, GatedSecretExistsHandler,
    SecretExistsHandler,
};
#[cfg(target_vendor = "apple")]
pub use keychain_sync::RealSecItemOps;
pub use keychain_sync::{
    AppleKeychainSecretStorage, KeychainItem, KeychainMasterKeyStore, MockSecItemOps, SecItemError,
    SecItemErrorKind, SecItemOps,
};
pub use master_key::{
    ensure_master_key, load_master_key, read_workspace_master_key, resolve_master_key,
    workspace_master_key_path, DefaultEntryProvider, EntryError, EntryProvider, MasterKeyConfig,
    DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE,
};
pub use migrate::{
    auto_migrate_if_needed, file_artifacts_present, migrate_file_to_keychain,
    migrate_keychain_to_file, MigrationReport, MigrationTarget,
};
pub use storage::{InMemorySecretStorage, SecretStorage, StorageError, StoredSecret};
pub use store::SecretStore;
