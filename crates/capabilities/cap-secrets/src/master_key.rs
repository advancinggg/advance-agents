//! Master-key loader + EntryProvider trait seam.
//!
//! AC-04: master key is `Zeroizing<[u8; 32]>` (ZeroizeOnDrop).
//! AC-03: Keychain-primary + env-var fallback sequencing via
//! `EntryProvider` trait seam. `DefaultEntryProvider` wraps
//! `keyring::Entry`; tests inject `TestEntryProvider` to avoid touching
//! the real OS credential store (keyring 2.3.3 exposes no per-test mock
//! without a process-global `set_default_credential_builder` race).

use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::SecretError;

/// Default Keychain service name used by MasterKeyConfig::Keychain in
/// AC-17-wired deployments. A future slice will map the runtime-config
/// `SecretsConfig` into `MasterKeyConfig::Keychain { service:
/// DEFAULT_KEYCHAIN_SERVICE.into(), ... }` unless the operator overrides.
pub const DEFAULT_KEYCHAIN_SERVICE: &str = "advance-agents";

/// Default Keychain account name (same rationale).
pub const DEFAULT_KEYCHAIN_ACCOUNT: &str = "master-key";

#[derive(Clone, Debug)]
pub enum MasterKeyConfig {
    /// Try OS Keychain first. On NotFound, fall back to the named env
    /// var if provided; otherwise KeyLoad error.
    Keychain {
        service: String,
        account: String,
        fallback_env_var: Option<String>,
    },
    /// Only use the env var.
    EnvVar(String),
}

/// Test seam over the OS credential store. `DefaultEntryProvider` wraps
/// `keyring::Entry`; test code injects a mock impl to avoid touching the
/// real store.
pub trait EntryProvider: Send + Sync {
    fn get_password(&self, service: &str, account: &str) -> Result<String, EntryError>;
    fn set_password(
        &self,
        _service: &str,
        _account: &str,
        _password: &str,
    ) -> Result<(), EntryError> {
        Err(EntryError::Open("set_password not supported".into()))
    }
}

#[derive(Debug, Clone)]
pub enum EntryError {
    Open(String),
    NotFound(String),
}

impl std::fmt::Display for EntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryError::Open(msg) => write!(f, "keychain entry open failed: {msg}"),
            EntryError::NotFound(msg) => write!(f, "keychain entry not found: {msg}"),
        }
    }
}

impl std::error::Error for EntryError {}

pub struct DefaultEntryProvider;

impl EntryProvider for DefaultEntryProvider {
    fn get_password(&self, service: &str, account: &str) -> Result<String, EntryError> {
        let entry =
            keyring::Entry::new(service, account).map_err(|e| EntryError::Open(e.to_string()))?;
        entry.get_password().map_err(|e| match &e {
            keyring::Error::NoEntry => EntryError::NotFound(format!("{service}/{account}")),
            _ => EntryError::Open(e.to_string()),
        })
    }

    fn set_password(&self, service: &str, account: &str, password: &str) -> Result<(), EntryError> {
        let entry =
            keyring::Entry::new(service, account).map_err(|e| EntryError::Open(e.to_string()))?;
        entry
            .set_password(password)
            .map_err(|e| EntryError::Open(e.to_string()))
    }
}

pub fn load_master_key(
    cfg: &MasterKeyConfig,
    entries: &dyn EntryProvider,
) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    // All intermediates wrapped in Zeroizing so key material is scrubbed
    // on drop. zeroize 1.8 provides `impl Zeroize for String` and
    // `impl<T: Zeroize> Zeroize for Vec<T>` — so `Zeroizing<String>` and
    // `Zeroizing<Vec<u8>>` are both valid ZeroizeOnDrop wrappers.
    let hex_str: Zeroizing<String> = match cfg {
        MasterKeyConfig::Keychain {
            service,
            account,
            fallback_env_var,
        } => match entries.get_password(service, account) {
            Ok(s) => Zeroizing::new(s),
            Err(EntryError::NotFound(_)) => match fallback_env_var {
                Some(var) => match std::env::var(var) {
                    Ok(s) => Zeroizing::new(s),
                    // VarError::NotUnicode(OsString) carries the env-var
                    // bytes verbatim — do NOT echo them into the error
                    // message (SECRETS_MASTER_KEY content = master key).
                    Err(std::env::VarError::NotPresent) => {
                        return Err(SecretError::KeyLoad(format!(
                            "keychain NotFound; env var {var} also not set"
                        )));
                    }
                    Err(std::env::VarError::NotUnicode(_)) => {
                        return Err(SecretError::KeyLoad(format!(
                            "keychain NotFound; env var {var} contains non-UTF-8 bytes"
                        )));
                    }
                },
                None => {
                    return Err(SecretError::KeyLoad(
                        "keychain NotFound; no fallback env var configured".into(),
                    ));
                }
            },
            Err(e) => {
                // EntryError's Display carries only service/account names +
                // opaque keyring error string — no key material.
                return Err(SecretError::KeyLoad(format!("{e}")));
            }
        },
        MasterKeyConfig::EnvVar(name) => match std::env::var(name) {
            Ok(s) => Zeroizing::new(s),
            Err(std::env::VarError::NotPresent) => {
                return Err(SecretError::KeyLoad(format!("env var {name} not set")));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                // See NotUnicode rationale above — do NOT echo env-var
                // bytes into the error message.
                return Err(SecretError::KeyLoad(format!(
                    "env var {name} contains non-UTF-8 bytes"
                )));
            }
        },
    };
    decode_to_key(&hex_str)
}

/// `{workspace}/.advance/master.key` — first-open mint + CLI fallback.
pub fn workspace_master_key_path(workspace: &std::path::Path) -> std::path::PathBuf {
    workspace.join(".advance").join("master.key")
}

pub fn read_workspace_master_key(
    workspace: &std::path::Path,
) -> Result<Option<Zeroizing<[u8; 32]>>, SecretError> {
    let path = workspace_master_key_path(workspace);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if !meta.file_type().is_file() || meta.len() > 128 {
        return Err(SecretError::KeyLoad(
            "master.key is not a regular file of expected size".into(),
        ));
    }
    let raw = {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut f = opts
            .open(&path)
            .map_err(|e| SecretError::KeyLoad(format!("read master.key: {e}")))?;
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut f, &mut buf)
            .map_err(|e| SecretError::KeyLoad(format!("read master.key: {e}")))?;
        if buf.len() > 128 {
            return Err(SecretError::KeyLoad("master.key too large".into()));
        }
        buf
    };
    let hex_str = Zeroizing::new(raw.trim().to_string());
    decode_to_key(&hex_str).map(Some)
}

/// Load existing key or mint one.
///
/// Order: **explicitly configured source (keychain/env) → valid workspace file → mint.**
/// An operator-provided key ALWAYS wins over a workspace-minted one — the pre-C243
/// contract (`SECRETS_MASTER_KEY` drives the whole set→resolve chain, witnessed by
/// `cli/tests/secrets_roundtrip.rs`) must keep holding after first-open bootstrap
/// exists. A present-but-invalid `master.key` fail-closes (does not overwrite).
/// A recovered configured key is persisted to the file if the file is missing; if
/// the file exists with DIFFERENT bytes it is left untouched (explicit key wins for
/// this process; changing keys is an operator action, never a silent overwrite).
/// A freshly minted key is never written into the process-global keychain.
pub fn ensure_master_key(
    workspace: &std::path::Path,
    cfg: &MasterKeyConfig,
    entries: &dyn EntryProvider,
) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    let path = workspace_master_key_path(workspace);
    let file_present = std::fs::symlink_metadata(&path).is_ok();
    match try_existing_configured_key(cfg, entries) {
        Ok(Some(key)) => {
            if !file_present {
                persist_master_key_file_exclusive(workspace, &key)?;
            }
            return Ok(key);
        }
        Ok(None) => {}
        Err(e) => {
            // Broken keychain + existing ciphertext: fail closed.
            // Empty first-open home: fall through to file / mint.
            if workspace.join(".advance").join("secrets.json").is_file() {
                return Err(e);
            }
        }
    }
    if file_present {
        return read_workspace_master_key(workspace)?
            .ok_or_else(|| SecretError::KeyLoad("master.key present but empty/unreadable".into()));
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    persist_master_key_file_exclusive(workspace, &bytes)?;
    Ok(Zeroizing::new(bytes))
}

/// Resolve WITHOUT minting: **explicitly configured source → workspace file → None.**
/// The read-side twin of [`ensure_master_key`] — both must agree on precedence or a
/// `secrets set` under an explicit env key and a daemon resolve would use different
/// keys (the exact bug this order fixes).
pub fn resolve_master_key(
    workspace: &std::path::Path,
    cfg: &MasterKeyConfig,
    entries: &dyn EntryProvider,
) -> Result<Option<Zeroizing<[u8; 32]>>, SecretError> {
    match try_existing_configured_key(cfg, entries) {
        Ok(Some(key)) => return Ok(Some(key)),
        Ok(None) => {}
        Err(e) => {
            if workspace.join(".advance").join("secrets.json").is_file() {
                return Err(e);
            }
        }
    }
    read_workspace_master_key(workspace)
}

fn try_existing_configured_key(
    cfg: &MasterKeyConfig,
    entries: &dyn EntryProvider,
) -> Result<Option<Zeroizing<[u8; 32]>>, SecretError> {
    match cfg {
        MasterKeyConfig::Keychain {
            service,
            account,
            fallback_env_var,
        } => match entries.get_password(service, account) {
            Ok(s) => decode_to_key(&Zeroizing::new(s)).map(Some),
            Err(EntryError::NotFound(_)) => match fallback_env_var {
                Some(var) => match std::env::var(var) {
                    Ok(s) => decode_to_key(&Zeroizing::new(s)).map(Some),
                    Err(std::env::VarError::NotPresent) => Ok(None),
                    Err(_) => Err(SecretError::KeyLoad(format!(
                        "env var {var} contains non-UTF-8 bytes"
                    ))),
                },
                None => Ok(None),
            },
            Err(e) => Err(SecretError::KeyLoad(format!("{e}"))),
        },
        MasterKeyConfig::EnvVar(name) => match std::env::var(name) {
            Ok(s) => decode_to_key(&Zeroizing::new(s)).map(Some),
            Err(_) => Ok(None),
        },
    }
}

fn persist_master_key_file_exclusive(
    workspace: &std::path::Path,
    key: &[u8; 32],
) -> Result<(), SecretError> {
    let dir = workspace.join(".advance");
    std::fs::create_dir_all(&dir)
        .map_err(|e| SecretError::KeyLoad(format!("create .advance: {e}")))?;
    let path = workspace_master_key_path(workspace);
    let hex = zeroize::Zeroizing::new(hex::encode(key));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| SecretError::KeyLoad(format!("create master.key: {e}")))?;
        f.write_all(hex.as_bytes())
            .map_err(|e| SecretError::KeyLoad(format!("write master.key: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            return Err(SecretError::KeyLoad("master.key already exists".into()));
        }
        std::fs::write(&path, hex.as_bytes())
            .map_err(|e| SecretError::KeyLoad(format!("write master.key: {e}")))?;
    }
    Ok(())
}

fn decode_to_key(hex_str: &Zeroizing<String>) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    // hex 0.4: `hex::decode(&str) -> Result<Vec<u8>, FromHexError>`.
    // Expected input: 64 hex chars (32 bytes) — matches the established
    // project convention (MODULE-001 runtime-config.yaml + PRD §secrets:
    // "hex-encoded master key for non-Keychain environments"). Discard
    // the FromHexError to keep Display free of any input-derived bytes.
    let raw: Zeroizing<Vec<u8>> = Zeroizing::new(hex::decode(hex_str.as_str()).map_err(|_| {
        SecretError::KeyLoad("hex decode failed (invalid input — expected 64 hex chars)".into())
    })?);
    if raw.len() != 32 {
        return Err(SecretError::KeyLoad(format!(
            "expected 32 bytes of master key, got {}",
            raw.len()
        )));
    }
    let mut key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(raw.as_slice());
    Ok(key)
    // raw drops here; Zeroizing<Vec<u8>> zeros the 32-byte buffer.
    // hex_str drops in the caller; Zeroizing<String> zeros the hex text.
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    // T04a: compile-time ZeroizeOnDrop trait-bound assertion.
    #[test]
    fn t04a_zeroizing_array_impls_zeroize_on_drop() {
        fn assert_zod<T: ZeroizeOnDrop>() {}
        assert_zod::<Zeroizing<[u8; 32]>>();
    }

    // T04b: runtime zeroize-function test on [u8; 32].
    #[test]
    fn t04b_zeroize_function_zeros_bytes() {
        use zeroize::Zeroize;
        let mut bytes: [u8; 32] = [0xab; 32];
        bytes.zeroize();
        assert_eq!(bytes, [0u8; 32]);
    }
}
