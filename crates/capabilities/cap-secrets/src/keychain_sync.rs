//! keychain-sync — the iCloud-Keychain-synchronized secret backend
//!.
//!
//! The encryption envelope of [`crate::SecretStore`] (master key → per-secret HKDF-SHA256 →
//! AES-256-GCM) is unchanged; only WHERE the master key and the ciphertext rows live moves:
//! from `<home>/.advance/master.key` + `<home>/.advance/secrets.json` to generic-password
//! items in the data-protection keychain, marked `kSecAttrSynchronizable` so iCloud Keychain
//! carries them end-to-end between the user's devices. Every home on every device then keeps
//! only secret NAMES (`llm-providers[].api-key-secret`).
//!
//! Item layout (§3.1):
//!
//! | item            | service                              | account         | value |
//! |-----------------|--------------------------------------|-----------------|-------|
//! | master key      | `agents.advance.<namespace>.master`  | `master-key`    | 64 hex chars |
//! | provider secret | `agents.advance.<namespace>.secrets` | `<secret-name>` | `ver(1)=1 \| kid(4) \| salt_len(1) \| salt \| encrypted_value` |
//!
//! `encrypted_value` is exactly the `[VERSION(1) | nonce(12) | ct]` blob `SecretStore` writes
//! into [`StoredSecret::encrypted_value`]; `salt` is [`StoredSecret::key_salt`]. `kid` is the
//! first 4 bytes of SHA-256(master key): a row whose `kid` is not the id of the master key in
//! use answers [`StorageError::KeyMismatch`] (an actionable "different master key" reason,
//! never a generic decrypt failure).
//!
//! Attributes: `kSecUseDataProtectionKeychain = true`, `kSecAttrSynchronizable = true` (or
//! `false` = ThisDeviceOnly when the operator opts this device out of sync),
//! `kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlock`, and `kSecAttrAccessGroup` when
//! the config names the App's shared access group.
//!
//! Every keychain call goes through the [`SecItemOps`] seam: [`RealSecItemOps`] (Apple
//! targets only, the one `unsafe` FFI module of this crate) talks to Security.framework;
//! [`MockSecItemOps`] is the in-memory double every unit test uses, so the storage, master-key
//! and migration logic is witnessed without a real keychain (which needs a signed, entitled
//! process — see the plan's S0 spike record).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::SecretError;
use crate::master_key::decode_to_key;
use crate::storage::{SecretStorage, StorageError, StoredSecret};

/// Service-name prefix of every item this backend owns.
pub const SERVICE_PREFIX: &str = "agents.advance.";
/// Service-name suffix of the master-key item.
pub const MASTER_SERVICE_SUFFIX: &str = ".master";
/// Service-name suffix of the provider-secret items.
pub const SECRETS_SERVICE_SUFFIX: &str = ".secrets";
/// Account of the master-key item.
pub const MASTER_ACCOUNT: &str = "master-key";
/// Version byte of the provider-secret value layout.
pub const VALUE_FORMAT_VERSION: u8 = 1;
/// The namespace a config without `secrets.keychain.namespace` uses.
pub const DEFAULT_NAMESPACE: &str = "default";

/// `errSecSuccess`.
pub const ERR_SEC_SUCCESS: i32 = 0;
/// `errSecDuplicateItem` — `SecItemAdd` over an existing item.
pub const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
/// `errSecItemNotFound`.
pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecInteractionNotAllowed` — the keychain would need UI (locked / no session).
pub const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// `errSecMissingEntitlement` — the calling process lacks the keychain-access-groups /
/// application-identifier entitlement the data-protection keychain requires.
pub const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// Service name of the master-key item of `namespace`.
pub fn master_service(namespace: &str) -> String {
    format!("{SERVICE_PREFIX}{namespace}{MASTER_SERVICE_SUFFIX}")
}

/// Service name of the provider-secret items of `namespace`.
pub fn secrets_service(namespace: &str) -> String {
    format!("{SERVICE_PREFIX}{namespace}{SECRETS_SERVICE_SUFFIX}")
}

/// The identity of one generic-password item (everything but its value).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeychainItem {
    pub service: String,
    pub account: String,
    /// `true` → `kSecAttrSynchronizable = true` (iCloud Keychain carries it);
    /// `false` → a ThisDeviceOnly item.
    pub synchronizable: bool,
    /// `kSecAttrAccessGroup`, when the config names the App's shared group.
    pub access_group: Option<String>,
}

/// Classification of a Security.framework `OSStatus`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecItemErrorKind {
    NotFound,
    DuplicateItem,
    MissingEntitlement,
    InteractionNotAllowed,
    Other,
}

/// A failed keychain call. Carries the raw status for diagnostics; never any item bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecItemError {
    pub status: i32,
    pub kind: SecItemErrorKind,
}

impl SecItemError {
    pub fn from_status(status: i32) -> Self {
        let kind = match status {
            ERR_SEC_ITEM_NOT_FOUND => SecItemErrorKind::NotFound,
            ERR_SEC_DUPLICATE_ITEM => SecItemErrorKind::DuplicateItem,
            ERR_SEC_MISSING_ENTITLEMENT => SecItemErrorKind::MissingEntitlement,
            ERR_SEC_INTERACTION_NOT_ALLOWED => SecItemErrorKind::InteractionNotAllowed,
            _ => SecItemErrorKind::Other,
        };
        Self { status, kind }
    }

    pub fn not_found() -> Self {
        Self::from_status(ERR_SEC_ITEM_NOT_FOUND)
    }

    pub fn duplicate() -> Self {
        Self::from_status(ERR_SEC_DUPLICATE_ITEM)
    }

    pub fn missing_entitlement() -> Self {
        Self::from_status(ERR_SEC_MISSING_ENTITLEMENT)
    }
}

impl fmt::Display for SecItemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "keychain call failed: OSStatus {} ({:?})",
            self.status, self.kind
        )
    }
}

impl std::error::Error for SecItemError {}

/// The Security.framework item calls this backend needs. Implemented by [`RealSecItemOps`]
/// (Apple targets) and [`MockSecItemOps`] (tests).
pub trait SecItemOps: Send + Sync {
    /// `SecItemAdd`: create the item with `data` as its value. [`SecItemErrorKind::DuplicateItem`]
    /// when the item already exists.
    fn add(&self, item: &KeychainItem, data: &[u8]) -> Result<(), SecItemError>;
    /// `SecItemCopyMatching` with `kSecReturnData`: the item's value, `None` when absent.
    fn copy(&self, item: &KeychainItem) -> Result<Option<Zeroizing<Vec<u8>>>, SecItemError>;
    /// `SecItemUpdate`: replace the item's value. [`SecItemErrorKind::NotFound`] when absent.
    fn update(&self, item: &KeychainItem, data: &[u8]) -> Result<(), SecItemError>;
    /// `SecItemDelete`: `Ok(true)` when an item was removed, `Ok(false)` when there was none.
    fn delete(&self, item: &KeychainItem) -> Result<bool, SecItemError>;
    /// Accounts of every item under `service` with the given synchronizable flag (and access
    /// group), sorted. Empty when there are none.
    fn list_accounts(
        &self,
        service: &str,
        synchronizable: bool,
        access_group: Option<&str>,
    ) -> Result<Vec<String>, SecItemError>;

    /// Create-or-replace.
    fn upsert(&self, item: &KeychainItem, data: &[u8]) -> Result<(), SecItemError> {
        match self.add(item, data) {
            Err(e) if e.kind == SecItemErrorKind::DuplicateItem => self.update(item, data),
            other => other,
        }
    }
}

// ── In-memory double ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct MockState {
    items: BTreeMap<KeychainItem, Vec<u8>>,
    failure: Option<SecItemError>,
    log: Vec<String>,
}

/// In-memory [`SecItemOps`]: records every call, keeps items keyed by their full identity
/// (service / account / synchronizable / access group), and can be switched into a failing
/// mode (every call answers the injected error — "keychain unavailable").
#[derive(Default)]
pub struct MockSecItemOps {
    state: Mutex<MockState>,
}

impl MockSecItemOps {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Make every subsequent call fail with `err`.
    pub fn fail_with(&self, err: SecItemError) {
        self.lock().failure = Some(err);
    }

    pub fn clear_failure(&self) {
        self.lock().failure = None;
    }

    pub fn contains(&self, item: &KeychainItem) -> bool {
        self.lock().items.contains_key(item)
    }

    pub fn data(&self, item: &KeychainItem) -> Option<Vec<u8>> {
        self.lock().items.get(item).cloned()
    }

    /// Every stored item identity (values omitted), sorted.
    pub fn items(&self) -> Vec<KeychainItem> {
        self.lock().items.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.lock().items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The call log (`"add service/account sync=…"`, …), in order.
    pub fn log(&self) -> Vec<String> {
        self.lock().log.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn gate(state: &mut MockState, entry: String) -> Result<(), SecItemError> {
        state.log.push(entry);
        match &state.failure {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

fn describe(item: &KeychainItem) -> String {
    format!(
        "{}/{} sync={} group={}",
        item.service,
        item.account,
        item.synchronizable,
        item.access_group.as_deref().unwrap_or("-")
    )
}

impl SecItemOps for MockSecItemOps {
    fn add(&self, item: &KeychainItem, data: &[u8]) -> Result<(), SecItemError> {
        let mut st = self.lock();
        Self::gate(&mut st, format!("add {}", describe(item)))?;
        if st.items.contains_key(item) {
            return Err(SecItemError::duplicate());
        }
        st.items.insert(item.clone(), data.to_vec());
        Ok(())
    }

    fn copy(&self, item: &KeychainItem) -> Result<Option<Zeroizing<Vec<u8>>>, SecItemError> {
        let mut st = self.lock();
        Self::gate(&mut st, format!("copy {}", describe(item)))?;
        Ok(st.items.get(item).map(|v| Zeroizing::new(v.clone())))
    }

    fn update(&self, item: &KeychainItem, data: &[u8]) -> Result<(), SecItemError> {
        let mut st = self.lock();
        Self::gate(&mut st, format!("update {}", describe(item)))?;
        match st.items.get_mut(item) {
            Some(slot) => {
                *slot = data.to_vec();
                Ok(())
            }
            None => Err(SecItemError::not_found()),
        }
    }

    fn delete(&self, item: &KeychainItem) -> Result<bool, SecItemError> {
        let mut st = self.lock();
        Self::gate(&mut st, format!("delete {}", describe(item)))?;
        Ok(st.items.remove(item).is_some())
    }

    fn list_accounts(
        &self,
        service: &str,
        synchronizable: bool,
        access_group: Option<&str>,
    ) -> Result<Vec<String>, SecItemError> {
        let mut st = self.lock();
        Self::gate(&mut st, format!("list {service} sync={synchronizable}"))?;
        let mut out: Vec<String> = st
            .items
            .keys()
            .filter(|k| {
                k.service == service
                    && k.synchronizable == synchronizable
                    && k.access_group.as_deref() == access_group
            })
            .map(|k| k.account.clone())
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }
}

// ── Value codec ──────────────────────────────────────────────────────────────────────────────

/// Key id of a master key: the first 4 bytes of SHA-256(master).
pub fn kid_for(master: &[u8; 32]) -> [u8; 4] {
    let digest = Sha256::digest(master);
    let mut kid = [0u8; 4];
    kid.copy_from_slice(&digest[..4]);
    kid
}

/// Encode a provider-secret value: `ver(1) | kid(4) | salt_len(1) | salt | encrypted_value`.
pub fn encode_value(kid: [u8; 4], stored: &StoredSecret) -> Result<Vec<u8>, StorageError> {
    let salt_len = u8::try_from(stored.key_salt.len())
        .map_err(|_| StorageError::Backend("key salt exceeds 255 bytes".into()))?;
    let mut out = Vec::with_capacity(6 + stored.key_salt.len() + stored.encrypted_value.len());
    out.push(VALUE_FORMAT_VERSION);
    out.extend_from_slice(&kid);
    out.push(salt_len);
    out.extend_from_slice(&stored.key_salt);
    out.extend_from_slice(&stored.encrypted_value);
    Ok(out)
}

/// Decode a provider-secret value into `(kid, stored)`. Malformed → `Backend`.
pub fn decode_value(bytes: &[u8]) -> Result<([u8; 4], StoredSecret), StorageError> {
    if bytes.len() < 6 {
        return Err(StorageError::Backend("keychain value too short".into()));
    }
    if bytes[0] != VALUE_FORMAT_VERSION {
        return Err(StorageError::Backend(format!(
            "unsupported keychain value version {}",
            bytes[0]
        )));
    }
    let mut kid = [0u8; 4];
    kid.copy_from_slice(&bytes[1..5]);
    let salt_len = bytes[5] as usize;
    let salt_end = 6 + salt_len;
    if bytes.len() < salt_end {
        return Err(StorageError::Backend(
            "keychain value salt truncated".into(),
        ));
    }
    Ok((
        kid,
        StoredSecret {
            key_salt: bytes[6..salt_end].to_vec(),
            encrypted_value: bytes[salt_end..].to_vec(),
        },
    ))
}

fn ops_err(e: SecItemError) -> StorageError {
    StorageError::Backend(format!("{e}"))
}

// ── Provider-secret storage ──────────────────────────────────────────────────────────────────

/// [`SecretStorage`] over the provider-secret items of one namespace.
///
/// `synchronizable = false` (the operator opted this device out of sync) reads through: a
/// name with no ThisDeviceOnly item falls back to the synchronizable item and materializes a
/// local copy. Synchronizable items are NEVER deleted by this mode (`remove` only drops the
/// local item), so other devices are unaffected.
pub struct AppleKeychainSecretStorage {
    ops: Arc<dyn SecItemOps>,
    namespace: String,
    access_group: Option<String>,
    synchronizable: bool,
    /// `None` = an unkeyed handle (names / remove only): `get` refuses, `put` refuses.
    kid: Option<[u8; 4]>,
}

impl AppleKeychainSecretStorage {
    /// A keyed handle: `kid` is derived from `master`, so every `get` checks the row was
    /// written under this master key.
    pub fn new(
        ops: Arc<dyn SecItemOps>,
        namespace: &str,
        access_group: Option<&str>,
        synchronizable: bool,
        master: &[u8; 32],
    ) -> Self {
        Self {
            ops,
            namespace: namespace.to_string(),
            access_group: access_group.map(str::to_string),
            synchronizable,
            kid: Some(kid_for(master)),
        }
    }

    /// A handle without a master key (`advance secrets list|remove`): names and removal
    /// only.
    pub fn unkeyed(
        ops: Arc<dyn SecItemOps>,
        namespace: &str,
        access_group: Option<&str>,
        synchronizable: bool,
    ) -> Self {
        Self {
            ops,
            namespace: namespace.to_string(),
            access_group: access_group.map(str::to_string),
            synchronizable,
            kid: None,
        }
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn synchronizable(&self) -> bool {
        self.synchronizable
    }

    pub fn kid(&self) -> Option<[u8; 4]> {
        self.kid
    }

    fn item(&self, account: &str, synchronizable: bool) -> KeychainItem {
        KeychainItem {
            service: secrets_service(&self.namespace),
            account: account.to_string(),
            synchronizable,
            access_group: self.access_group.clone(),
        }
    }

    /// The value for `account`: the item of this handle's mode, else (ThisDeviceOnly mode
    /// only) the synchronizable item — copied into a ThisDeviceOnly item when `materialize`.
    fn lookup(
        &self,
        account: &str,
        materialize: bool,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        let local = self
            .ops
            .copy(&self.item(account, self.synchronizable))
            .map_err(ops_err)?;
        if local.is_some() || self.synchronizable {
            return Ok(local);
        }
        let synced = self.ops.copy(&self.item(account, true)).map_err(ops_err)?;
        if let (Some(bytes), true) = (&synced, materialize) {
            match self.ops.add(&self.item(account, false), bytes) {
                Ok(()) => {}
                Err(e) if e.kind == SecItemErrorKind::DuplicateItem => {}
                Err(e) => return Err(ops_err(e)),
            }
        }
        Ok(synced)
    }
}

impl SecretStorage for AppleKeychainSecretStorage {
    fn put(&self, name: &str, stored: StoredSecret) -> Result<(), StorageError> {
        let kid = self.kid.ok_or_else(|| {
            StorageError::Backend("unkeyed keychain handle cannot store secrets".into())
        })?;
        let value = Zeroizing::new(encode_value(kid, &stored)?);
        self.ops
            .upsert(&self.item(name, self.synchronizable), &value)
            .map_err(ops_err)
    }

    fn get(&self, name: &str) -> Result<Option<StoredSecret>, StorageError> {
        let kid = self.kid.ok_or_else(|| {
            StorageError::Backend("unkeyed keychain handle cannot read secrets".into())
        })?;
        let Some(bytes) = self.lookup(name, true)? else {
            return Ok(None);
        };
        let (row_kid, stored) = decode_value(&bytes)?;
        if row_kid != kid {
            return Err(StorageError::KeyMismatch);
        }
        Ok(Some(stored))
    }

    fn exists(&self, name: &str) -> Result<bool, StorageError> {
        Ok(self.lookup(name, false)?.is_some())
    }

    fn remove(&self, name: &str) -> Result<bool, StorageError> {
        self.ops
            .delete(&self.item(name, self.synchronizable))
            .map_err(ops_err)
    }

    fn names(&self) -> Vec<String> {
        let service = secrets_service(&self.namespace);
        let group = self.access_group.as_deref();
        let mut names = self
            .ops
            .list_accounts(&service, self.synchronizable, group)
            .unwrap_or_default();
        if !self.synchronizable {
            names.extend(
                self.ops
                    .list_accounts(&service, true, group)
                    .unwrap_or_default(),
            );
        }
        names.sort();
        names.dedup();
        names
    }
}

// ── Master key item ──────────────────────────────────────────────────────────────────────────

/// The master-key item of one namespace.
pub struct KeychainMasterKeyStore {
    ops: Arc<dyn SecItemOps>,
    namespace: String,
    access_group: Option<String>,
    synchronizable: bool,
}

fn key_load(e: SecItemError) -> SecretError {
    SecretError::KeyLoad(format!("keychain unavailable: {e}"))
}

impl KeychainMasterKeyStore {
    pub fn new(
        ops: Arc<dyn SecItemOps>,
        namespace: &str,
        access_group: Option<&str>,
        synchronizable: bool,
    ) -> Self {
        Self {
            ops,
            namespace: namespace.to_string(),
            access_group: access_group.map(str::to_string),
            synchronizable,
        }
    }

    pub fn item(&self, synchronizable: bool) -> KeychainItem {
        KeychainItem {
            service: master_service(&self.namespace),
            account: MASTER_ACCOUNT.to_string(),
            synchronizable,
            access_group: self.access_group.clone(),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, SecretError> {
        let text = Zeroizing::new(
            std::str::from_utf8(bytes)
                .map_err(|_| SecretError::KeyLoad("keychain master key is not UTF-8".into()))?
                .trim()
                .to_string(),
        );
        decode_to_key(&text)
    }

    /// The stored master key, `None` when the namespace has none. ThisDeviceOnly mode reads
    /// through to the synchronizable item and materializes a local copy.
    pub fn read(&self) -> Result<Option<Zeroizing<[u8; 32]>>, SecretError> {
        let local = self
            .ops
            .copy(&self.item(self.synchronizable))
            .map_err(key_load)?;
        if let Some(bytes) = local {
            return Self::decode(&bytes).map(Some);
        }
        if self.synchronizable {
            return Ok(None);
        }
        let Some(bytes) = self.ops.copy(&self.item(true)).map_err(key_load)? else {
            return Ok(None);
        };
        match self.ops.add(&self.item(false), &bytes) {
            Ok(()) => {}
            Err(e) if e.kind == SecItemErrorKind::DuplicateItem => {}
            Err(e) => return Err(key_load(e)),
        }
        Self::decode(&bytes).map(Some)
    }

    /// Write `key` (hex) as the master item of this handle's mode (create-or-replace).
    pub fn store(&self, key: &[u8; 32]) -> Result<(), SecretError> {
        let hex = Zeroizing::new(hex::encode(key));
        self.ops
            .upsert(&self.item(self.synchronizable), hex.as_bytes())
            .map_err(key_load)
    }

    /// Mint a fresh random master key and add it. A concurrent minter that won the race is
    /// honoured: `DuplicateItem` re-reads the existing item instead of overwriting it.
    pub fn mint(&self) -> Result<Zeroizing<[u8; 32]>, SecretError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *bytes);
        let hex = Zeroizing::new(hex::encode(&*bytes));
        match self
            .ops
            .add(&self.item(self.synchronizable), hex.as_bytes())
        {
            Ok(()) => Ok(bytes),
            Err(e) if e.kind == SecItemErrorKind::DuplicateItem => self.read()?.ok_or_else(|| {
                SecretError::KeyLoad("keychain master key vanished after a duplicate add".into())
            }),
            Err(e) => Err(key_load(e)),
        }
    }

    /// Whether ANY provider-secret item (synchronizable or ThisDeviceOnly) exists under this
    /// namespace — the guard that forbids minting a new master key over live ciphertext.
    pub fn namespace_has_ciphertext(&self) -> Result<bool, SecretError> {
        let service = secrets_service(&self.namespace);
        let group = self.access_group.as_deref();
        for sync in [true, false] {
            if !self
                .ops
                .list_accounts(&service, sync, group)
                .map_err(key_load)?
                .is_empty()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// ── Security.framework backend (Apple targets) ───────────────────────────────────────────────

#[cfg(target_vendor = "apple")]
pub use apple::RealSecItemOps;

/// The one FFI module of this crate: `SecItem*` over CoreFoundation dictionaries. Every
/// `unsafe` block is a single framework call whose arguments are CoreFoundation objects this
/// module keeps alive for the duration of the call.
#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
mod apple {
    use core_foundation::array::{CFArray, CFArrayRef};
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::{CFData, CFDataRef};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlock;
    use security_framework_sys::item::{
        kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes,
        kSecReturnData, kSecValueData,
    };
    use security_framework_sys::keychain_item::{
        SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
    };
    use zeroize::Zeroizing;

    use super::{KeychainItem, SecItemError, SecItemOps, ERR_SEC_ITEM_NOT_FOUND, ERR_SEC_SUCCESS};

    // Two keys the pinned `security-framework-sys` does not export on the default feature
    // set: the accessibility attribute key and the data-protection-keychain switch
    // (macOS 10.15+). Both are plain `CFStringRef` constants of Security.framework.
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecAttrAccessible: CFStringRef;
        static kSecUseDataProtectionKeychain: CFStringRef;
    }

    /// Production [`SecItemOps`] over Security.framework.
    #[derive(Default)]
    pub struct RealSecItemOps;

    /// Borrow a framework-owned constant `CFStringRef` as a `CFString` (get rule: the
    /// framework owns the constant; wrapping retains it, dropping releases that retain).
    fn constant(key: CFStringRef) -> CFString {
        // SAFETY: `key` is one of the immutable `kSec*` constants exported by
        // Security.framework; it is a valid CFString for the lifetime of the process.
        unsafe { CFString::wrap_under_get_rule(key) }
    }

    fn text(s: &str) -> CFType {
        CFString::new(s).as_CFType()
    }

    fn boolean(b: bool) -> CFType {
        if b {
            CFBoolean::true_value().as_CFType()
        } else {
            CFBoolean::false_value().as_CFType()
        }
    }

    fn dict(pairs: &[(CFString, CFType)]) -> CFDictionary<CFString, CFType> {
        CFDictionary::from_CFType_pairs(pairs)
    }

    /// The attributes that identify `item` (class / service / account / synchronizable /
    /// access group), on the data-protection keychain.
    fn identity(item: &KeychainItem) -> Vec<(CFString, CFType)> {
        // SAFETY: reading an extern constant declared above — an immutable CFStringRef
        // exported by Security.framework, valid for the process lifetime.
        let data_protection_key = unsafe { kSecUseDataProtectionKeychain };
        // SAFETY: the `kSec*` statics of `security-framework-sys` are the same kind of
        // framework-owned constants; reading them is the crate's documented use.
        let mut pairs = unsafe {
            vec![
                (
                    constant(kSecClass),
                    constant(kSecClassGenericPassword).as_CFType(),
                ),
                (constant(kSecAttrService), text(&item.service)),
                (constant(kSecAttrAccount), text(&item.account)),
                (constant(data_protection_key), boolean(true)),
                (
                    constant(kSecAttrSynchronizable),
                    boolean(item.synchronizable),
                ),
            ]
        };
        if let Some(group) = &item.access_group {
            // SAFETY: see above.
            pairs.push((unsafe { constant(kSecAttrAccessGroup) }, text(group)));
        }
        pairs
    }

    fn status_result(status: i32) -> Result<(), SecItemError> {
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(SecItemError::from_status(status))
        }
    }

    impl SecItemOps for RealSecItemOps {
        fn add(&self, item: &KeychainItem, data: &[u8]) -> Result<(), SecItemError> {
            let mut pairs = identity(item);
            // SAFETY: framework-owned constants (see `identity`).
            unsafe {
                pairs.push((
                    constant(kSecAttrAccessible),
                    constant(kSecAttrAccessibleAfterFirstUnlock).as_CFType(),
                ));
                pairs.push((
                    constant(kSecValueData),
                    CFData::from_buffer(data).as_CFType(),
                ));
            }
            let attrs = dict(&pairs);
            // SAFETY: `attrs` is a live CFDictionary for the duration of the call; no result
            // object is requested (null out-pointer is documented as allowed).
            let status = unsafe { SecItemAdd(attrs.as_concrete_TypeRef(), std::ptr::null_mut()) };
            status_result(status)
        }

        fn copy(&self, item: &KeychainItem) -> Result<Option<Zeroizing<Vec<u8>>>, SecItemError> {
            let mut pairs = identity(item);
            // SAFETY: framework-owned constant.
            pairs.push((unsafe { constant(kSecReturnData) }, boolean(true)));
            let query = dict(&pairs);
            let mut result: CFTypeRef = std::ptr::null();
            // SAFETY: `query` is live for the call; on success `result` receives a +1
            // retained CFDataRef that we take ownership of under the create rule below.
            let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
            if status == ERR_SEC_ITEM_NOT_FOUND {
                return Ok(None);
            }
            status_result(status)?;
            if result.is_null() {
                return Err(SecItemError::from_status(-1));
            }
            // SAFETY: with `kSecReturnData` the result of a successful single-item match is a
            // CFDataRef owned by the caller (create rule).
            let data = unsafe { CFData::wrap_under_create_rule(result as CFDataRef) };
            Ok(Some(Zeroizing::new(data.bytes().to_vec())))
        }

        fn update(&self, item: &KeychainItem, data: &[u8]) -> Result<(), SecItemError> {
            let query = dict(&identity(item));
            // SAFETY: framework-owned constant.
            let attrs = dict(&[(
                unsafe { constant(kSecValueData) },
                CFData::from_buffer(data).as_CFType(),
            )]);
            // SAFETY: both dictionaries are live for the duration of the call.
            let status =
                unsafe { SecItemUpdate(query.as_concrete_TypeRef(), attrs.as_concrete_TypeRef()) };
            status_result(status)
        }

        fn delete(&self, item: &KeychainItem) -> Result<bool, SecItemError> {
            let query = dict(&identity(item));
            // SAFETY: `query` is live for the duration of the call.
            let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
            if status == ERR_SEC_ITEM_NOT_FOUND {
                return Ok(false);
            }
            status_result(status).map(|()| true)
        }

        fn list_accounts(
            &self,
            service: &str,
            synchronizable: bool,
            access_group: Option<&str>,
        ) -> Result<Vec<String>, SecItemError> {
            // SAFETY: reading framework-owned constants.
            let data_protection_key = unsafe { kSecUseDataProtectionKeychain };
            // SAFETY: framework-owned constants (see `identity`).
            let mut pairs = unsafe {
                vec![
                    (
                        constant(kSecClass),
                        constant(kSecClassGenericPassword).as_CFType(),
                    ),
                    (constant(kSecAttrService), text(service)),
                    (constant(data_protection_key), boolean(true)),
                    (constant(kSecAttrSynchronizable), boolean(synchronizable)),
                    (constant(kSecReturnAttributes), boolean(true)),
                    (
                        constant(kSecMatchLimit),
                        constant(kSecMatchLimitAll).as_CFType(),
                    ),
                ]
            };
            if let Some(group) = access_group {
                // SAFETY: framework-owned constant.
                pairs.push((unsafe { constant(kSecAttrAccessGroup) }, text(group)));
            }
            let query = dict(&pairs);
            let mut result: CFTypeRef = std::ptr::null();
            // SAFETY: `query` is live for the call; on success `result` is a +1 retained
            // CFArrayRef of attribute dictionaries (create rule, taken below).
            let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
            if status == ERR_SEC_ITEM_NOT_FOUND {
                return Ok(Vec::new());
            }
            status_result(status)?;
            if result.is_null() {
                return Ok(Vec::new());
            }
            // SAFETY: with `kSecReturnAttributes` + `kSecMatchLimitAll` the result is a
            // CFArray of CFDictionary<CFString, CFType> owned by the caller.
            let rows: CFArray<CFDictionary<CFString, CFType>> =
                unsafe { CFArray::wrap_under_create_rule(result as CFArrayRef) };
            // SAFETY: framework-owned constant.
            let account_key = unsafe { constant(kSecAttrAccount) };
            let mut out = Vec::new();
            for row in rows.iter() {
                if let Some(value) = row.find(account_key.clone()) {
                    if let Some(account) = value.downcast::<CFString>() {
                        out.push(account.to_string());
                    }
                }
            }
            out.sort();
            out.dedup();
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(account: &str, sync: bool) -> KeychainItem {
        KeychainItem {
            service: secrets_service("t"),
            account: account.into(),
            synchronizable: sync,
            access_group: None,
        }
    }

    #[test]
    fn service_names_follow_the_layout() {
        assert_eq!(master_service("default"), "agents.advance.default.master");
        assert_eq!(secrets_service("work"), "agents.advance.work.secrets");
    }

    #[test]
    fn value_codec_roundtrips_and_rejects_malformed() {
        let stored = StoredSecret {
            encrypted_value: vec![1, 2, 3, 4, 5],
            key_salt: vec![9; 16],
        };
        let kid = kid_for(&[7u8; 32]);
        let bytes = encode_value(kid, &stored).unwrap();
        assert_eq!(bytes[0], VALUE_FORMAT_VERSION);
        assert_eq!(&bytes[1..5], &kid);
        assert_eq!(bytes[5], 16);
        let (k, back) = decode_value(&bytes).unwrap();
        assert_eq!(k, kid);
        assert_eq!(back.key_salt, stored.key_salt);
        assert_eq!(back.encrypted_value, stored.encrypted_value);
        assert!(decode_value(&bytes[..4]).is_err());
        let mut bad_ver = bytes.clone();
        bad_ver[0] = 9;
        assert!(decode_value(&bad_ver).is_err());
        let mut truncated = bytes.clone();
        truncated.truncate(10);
        assert!(decode_value(&truncated).is_err());
    }

    #[test]
    fn kid_is_stable_and_key_specific() {
        assert_eq!(kid_for(&[1u8; 32]), kid_for(&[1u8; 32]));
        assert_ne!(kid_for(&[1u8; 32]), kid_for(&[2u8; 32]));
    }

    #[test]
    fn sec_item_error_classifies_known_statuses() {
        assert_eq!(
            SecItemError::from_status(ERR_SEC_MISSING_ENTITLEMENT).kind,
            SecItemErrorKind::MissingEntitlement
        );
        assert_eq!(SecItemError::not_found().kind, SecItemErrorKind::NotFound);
        assert_eq!(
            SecItemError::duplicate().kind,
            SecItemErrorKind::DuplicateItem
        );
        assert_eq!(
            SecItemError::from_status(-25308).kind,
            SecItemErrorKind::InteractionNotAllowed
        );
        assert_eq!(SecItemError::from_status(-50).kind, SecItemErrorKind::Other);
        let s = format!("{}", SecItemError::missing_entitlement());
        assert!(s.contains("-34018"));
    }

    #[test]
    fn mock_ops_add_copy_update_delete_list() {
        let ops = MockSecItemOps::new();
        ops.add(&item("a", true), b"1").unwrap();
        assert_eq!(
            ops.add(&item("a", true), b"2").unwrap_err().kind,
            SecItemErrorKind::DuplicateItem
        );
        assert_eq!(&**ops.copy(&item("a", true)).unwrap().unwrap(), b"1");
        ops.update(&item("a", true), b"2").unwrap();
        assert_eq!(&**ops.copy(&item("a", true)).unwrap().unwrap(), b"2");
        assert_eq!(
            ops.update(&item("zz", true), b"2").unwrap_err().kind,
            SecItemErrorKind::NotFound
        );
        ops.add(&item("b", false), b"3").unwrap();
        assert_eq!(
            ops.list_accounts(&secrets_service("t"), true, None)
                .unwrap(),
            vec!["a".to_string()]
        );
        assert_eq!(
            ops.list_accounts(&secrets_service("t"), false, None)
                .unwrap(),
            vec!["b".to_string()]
        );
        assert!(ops.delete(&item("a", true)).unwrap());
        assert!(!ops.delete(&item("a", true)).unwrap());
        assert!(ops.copy(&item("a", true)).unwrap().is_none());
        ops.fail_with(SecItemError::missing_entitlement());
        assert_eq!(
            ops.copy(&item("b", false)).unwrap_err().kind,
            SecItemErrorKind::MissingEntitlement
        );
        ops.clear_failure();
        assert!(ops.copy(&item("b", false)).unwrap().is_some());
        assert!(ops.log().iter().any(|l| l.starts_with("add ")));
    }

    #[test]
    fn upsert_creates_then_replaces() {
        let ops = MockSecItemOps::new();
        ops.upsert(&item("k", true), b"v1").unwrap();
        ops.upsert(&item("k", true), b"v2").unwrap();
        assert_eq!(ops.data(&item("k", true)).unwrap(), b"v2");
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn storage_put_get_checks_kid() {
        let ops = MockSecItemOps::new();
        let master_a = [0xa1u8; 32];
        let master_b = [0xb2u8; 32];
        let a = AppleKeychainSecretStorage::new(ops.clone(), "t", None, true, &master_a);
        let stored = StoredSecret {
            encrypted_value: vec![1, 2, 3],
            key_salt: vec![4; 16],
        };
        a.put("openai-api-key", stored).unwrap();
        assert!(a.exists("openai-api-key").unwrap());
        assert_eq!(a.names(), vec!["openai-api-key".to_string()]);
        let back = a.get("openai-api-key").unwrap().unwrap();
        assert_eq!(back.encrypted_value, vec![1, 2, 3]);
        // Another master key sees the row but must not decrypt it silently.
        let b = AppleKeychainSecretStorage::new(ops.clone(), "t", None, true, &master_b);
        assert!(matches!(
            b.get("openai-api-key"),
            Err(StorageError::KeyMismatch)
        ));
        assert!(a.remove("openai-api-key").unwrap());
        assert!(!a.remove("openai-api-key").unwrap());
        assert!(a.get("openai-api-key").unwrap().is_none());
    }

    #[test]
    fn this_device_only_reads_through_and_keeps_the_synced_item() {
        let ops = MockSecItemOps::new();
        let master = [0x11u8; 32];
        let synced = AppleKeychainSecretStorage::new(ops.clone(), "t", None, true, &master);
        synced
            .put(
                "k",
                StoredSecret {
                    encrypted_value: vec![1],
                    key_salt: vec![2; 16],
                },
            )
            .unwrap();
        let local = AppleKeychainSecretStorage::new(ops.clone(), "t", None, false, &master);
        // Listing sees the synced name even before any local copy exists.
        assert_eq!(local.names(), vec!["k".to_string()]);
        assert!(local.exists("k").unwrap());
        assert!(
            !ops.contains(&item("k", false)),
            "exists() must not materialize"
        );
        let row = local.get("k").unwrap().unwrap();
        assert_eq!(row.encrypted_value, vec![1]);
        assert!(
            ops.contains(&item("k", false)),
            "get() materialized a local copy"
        );
        assert!(
            ops.contains(&item("k", true)),
            "the synced item is untouched"
        );
        // Local removal drops only the local copy.
        assert!(local.remove("k").unwrap());
        assert!(!ops.contains(&item("k", false)));
        assert!(ops.contains(&item("k", true)));
    }

    #[test]
    fn unkeyed_handle_lists_and_removes_but_never_reads() {
        let ops = MockSecItemOps::new();
        let keyed = AppleKeychainSecretStorage::new(ops.clone(), "t", None, true, &[3u8; 32]);
        keyed
            .put(
                "n",
                StoredSecret {
                    encrypted_value: vec![1],
                    key_salt: vec![2; 16],
                },
            )
            .unwrap();
        let unkeyed = AppleKeychainSecretStorage::unkeyed(ops.clone(), "t", None, true);
        assert_eq!(unkeyed.names(), vec!["n".to_string()]);
        assert!(unkeyed.get("n").is_err());
        assert!(unkeyed
            .put(
                "n",
                StoredSecret {
                    encrypted_value: vec![],
                    key_salt: vec![]
                }
            )
            .is_err());
        assert!(unkeyed.remove("n").unwrap());
    }

    #[test]
    fn master_key_store_mint_read_and_ciphertext_guard() {
        let ops = MockSecItemOps::new();
        let mk = KeychainMasterKeyStore::new(ops.clone(), "t", None, true);
        assert!(mk.read().unwrap().is_none());
        assert!(!mk.namespace_has_ciphertext().unwrap());
        let minted = mk.mint().unwrap();
        let read = mk.read().unwrap().unwrap();
        assert_eq!(*minted, *read);
        let raw = ops.data(&mk.item(true)).unwrap();
        assert_eq!(raw.len(), 64, "stored as 64 hex chars");
        // A second mint honours the existing item (lost race).
        let again = mk.mint().unwrap();
        assert_eq!(*again, *minted);
        let storage = AppleKeychainSecretStorage::new(ops.clone(), "t", None, true, &minted);
        storage
            .put(
                "x",
                StoredSecret {
                    encrypted_value: vec![1],
                    key_salt: vec![2; 16],
                },
            )
            .unwrap();
        assert!(mk.namespace_has_ciphertext().unwrap());
        // ThisDeviceOnly mode reads through to the synced master item and copies it.
        let local = KeychainMasterKeyStore::new(ops.clone(), "t", None, false);
        let via_local = local.read().unwrap().unwrap();
        assert_eq!(*via_local, *minted);
        assert!(ops.contains(&local.item(false)));
        assert!(ops.contains(&local.item(true)));
    }

    #[test]
    fn master_key_store_fails_closed_when_keychain_unavailable() {
        let ops = MockSecItemOps::new();
        ops.fail_with(SecItemError::missing_entitlement());
        let mk = KeychainMasterKeyStore::new(ops.clone(), "t", None, true);
        let err = mk.read().unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("keychain unavailable"), "{text}");
        assert!(text.contains("-34018"), "{text}");
        assert!(mk.mint().is_err());
        assert!(ops.is_empty(), "nothing minted while unavailable");
    }
}
