//! Read / rewrite the `secrets:` section of `<home>/.advance/runtime-config.yaml`
//! (this lane): the one writer the `secrets` Client API family
//! (`POST /client/secrets:set-mode`) and `advance secrets migrate` share.
//!
//! Same write chain as the selected-provider rewrite: edit the parsed `serde_yml::Value`,
//! write `runtime-config.yaml.tmp` (0600, nofollow), `load_config(&tmp)` so an invalid
//! result is never installed, then rename over the live file. Only the `secrets:` mapping's
//! `master-key-source` and `keychain` keys are touched (`env-var-name`, `dependencies` and
//! every other section survive byte-for-byte at the YAML-value level).

use std::path::Path;

use advance_runtime::config::{load_config, MasterKeySource};
use serde_yml::{Mapping, Value};

use crate::scaffold::SecretsMode;

/// The effective `secrets:` view (defaults applied).
#[derive(Clone, Debug, PartialEq)]
pub struct SecretsModeView {
    pub mode: SecretsMode,
    pub master_key_source: MasterKeySource,
    pub synchronizable: bool,
    pub namespace: String,
    pub access_group: Option<String>,
}

/// A `set-mode` request against the YAML.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretsModeChange {
    pub mode: SecretsMode,
    /// keychain-sync only; `None` keeps the current value (default `true`).
    pub synchronizable: Option<bool>,
    /// keychain-sync only; `None` keeps the current value (default `default`).
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsModeWriteError {
    /// `runtime-config.yaml` is missing, unreadable, or not a mapping.
    Unreadable,
    /// The rewritten document failed `load_config` validation (the live file is untouched).
    Invalid(String),
    Io,
}

impl std::fmt::Display for SecretsModeWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable => write!(f, "runtime-config.yaml unreadable"),
            Self::Invalid(m) => write!(f, "rewritten runtime-config.yaml invalid: {m}"),
            Self::Io => write!(f, "runtime-config.yaml write failed"),
        }
    }
}

impl std::error::Error for SecretsModeWriteError {}

fn config_path(home: &Path) -> std::path::PathBuf {
    home.join(".advance").join("runtime-config.yaml")
}

/// The current `secrets:` view of `home` (through the validating loader).
pub fn read_secrets_mode(home: &Path) -> Result<SecretsModeView, SecretsModeWriteError> {
    let cfg = load_config(&config_path(home)).map_err(|_| SecretsModeWriteError::Unreadable)?;
    let kc = cfg.secrets.keychain.clone().unwrap_or_default();
    let mode = match cfg.secrets.master_key_source {
        MasterKeySource::KeychainSync => SecretsMode::KeychainSync,
        MasterKeySource::Keychain | MasterKeySource::EnvVar => SecretsMode::File,
    };
    Ok(SecretsModeView {
        mode,
        master_key_source: cfg.secrets.master_key_source,
        synchronizable: kc.synchronizable,
        namespace: kc.namespace,
        access_group: kc.access_group,
    })
}

fn key(s: &str) -> Value {
    Value::String(s.to_string())
}

/// Rewrite the `secrets:` section for `change`. File mode sets `master-key-source: keychain`
/// (the scaffold default — `keyring` store with the env var as fallback) and drops the
/// `keychain:` block; keychain-sync sets `master-key-source: keychain-sync` and merges the
/// requested `synchronizable` / `namespace` into the (possibly new) `keychain:` block.
pub fn rewrite_secrets_mode(
    home: &Path,
    change: &SecretsModeChange,
) -> Result<SecretsModeView, SecretsModeWriteError> {
    let cfg_path = config_path(home);
    let raw = crate::scaffold::read_small_regular(&cfg_path, 64 * 1024)
        .ok_or(SecretsModeWriteError::Unreadable)?;
    let mut doc: Value =
        serde_yml::from_str(&raw).map_err(|_| SecretsModeWriteError::Unreadable)?;
    let root = doc
        .as_mapping_mut()
        .ok_or(SecretsModeWriteError::Unreadable)?;
    let secrets = match root.get_mut(key("secrets")) {
        Some(Value::Mapping(m)) => m,
        _ => {
            root.insert(key("secrets"), Value::Mapping(Mapping::new()));
            match root.get_mut(key("secrets")) {
                Some(Value::Mapping(m)) => m,
                _ => unreachable!("secrets mapping was just inserted"),
            }
        }
    };
    if !secrets.contains_key(key("env-var-name")) {
        secrets.insert(key("env-var-name"), key("SECRETS_MASTER_KEY"));
    }
    match change.mode {
        SecretsMode::File => {
            secrets.insert(key("master-key-source"), key("keychain"));
            secrets.remove(key("keychain"));
        }
        SecretsMode::KeychainSync => {
            secrets.insert(key("master-key-source"), key("keychain-sync"));
            let block = match secrets.get_mut(key("keychain")) {
                Some(Value::Mapping(m)) => m,
                _ => {
                    secrets.insert(key("keychain"), Value::Mapping(Mapping::new()));
                    match secrets.get_mut(key("keychain")) {
                        Some(Value::Mapping(m)) => m,
                        _ => unreachable!("keychain mapping was just inserted"),
                    }
                }
            };
            if let Some(sync) = change.synchronizable {
                block.insert(key("synchronizable"), Value::Bool(sync));
            }
            if let Some(ns) = &change.namespace {
                block.insert(key("namespace"), key(ns));
            }
        }
    }
    let rendered = serde_yml::to_string(&doc).map_err(|_| SecretsModeWriteError::Io)?;
    let tmp = home.join(".advance").join("runtime-config.yaml.tmp");
    crate::scaffold::write_0600_nofollow(&tmp, rendered.as_bytes())
        .map_err(|_| SecretsModeWriteError::Io)?;
    if let Err(e) = load_config(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SecretsModeWriteError::Invalid(e.to_string()));
    }
    std::fs::rename(&tmp, &cfg_path).map_err(|_| SecretsModeWriteError::Io)?;
    read_secrets_mode(home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffold::{write_recognizable_home_with_mode, SecretsMode};

    #[test]
    fn rewrite_flips_both_ways_and_keeps_other_sections() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("h");
        write_recognizable_home_with_mode(&home, SecretsMode::File).unwrap();
        let before = read_secrets_mode(&home).unwrap();
        assert_eq!(before.mode, SecretsMode::File);
        assert_eq!(before.master_key_source, MasterKeySource::Keychain);

        let view = rewrite_secrets_mode(
            &home,
            &SecretsModeChange {
                mode: SecretsMode::KeychainSync,
                synchronizable: Some(false),
                namespace: Some("work".into()),
            },
        )
        .unwrap();
        assert_eq!(view.mode, SecretsMode::KeychainSync);
        assert_eq!(view.master_key_source, MasterKeySource::KeychainSync);
        assert!(!view.synchronizable);
        assert_eq!(view.namespace, "work");
        let raw = std::fs::read_to_string(home.join(".advance/runtime-config.yaml")).unwrap();
        assert!(raw.contains("master-key-source: keychain-sync"));
        assert!(raw.contains("llm-providers"), "other sections kept");
        assert!(raw.contains("env-var-name: SECRETS_MASTER_KEY"));
        assert!(!home.join(".advance/runtime-config.yaml.tmp").exists());

        let back = rewrite_secrets_mode(
            &home,
            &SecretsModeChange {
                mode: SecretsMode::File,
                synchronizable: None,
                namespace: None,
            },
        )
        .unwrap();
        assert_eq!(back.mode, SecretsMode::File);
        assert_eq!(back.master_key_source, MasterKeySource::Keychain);
        let raw = std::fs::read_to_string(home.join(".advance/runtime-config.yaml")).unwrap();
        assert!(!raw.contains("keychain:"), "block dropped in File mode");
    }

    #[test]
    fn invalid_namespace_is_rejected_and_the_live_file_survives() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("h");
        write_recognizable_home_with_mode(&home, SecretsMode::File).unwrap();
        let raw_before =
            std::fs::read_to_string(home.join(".advance/runtime-config.yaml")).unwrap();
        let err = rewrite_secrets_mode(
            &home,
            &SecretsModeChange {
                mode: SecretsMode::KeychainSync,
                synchronizable: None,
                namespace: Some("bad namespace!".into()),
            },
        )
        .unwrap_err();
        assert!(matches!(err, SecretsModeWriteError::Invalid(_)));
        let raw_after = std::fs::read_to_string(home.join(".advance/runtime-config.yaml")).unwrap();
        assert_eq!(raw_before, raw_after);
        assert!(!home.join(".advance/runtime-config.yaml.tmp").exists());
    }

    #[test]
    fn keychain_sync_starter_has_no_master_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("h");
        write_recognizable_home_with_mode(&home, SecretsMode::KeychainSync).unwrap();
        assert!(!home.join(".advance/master.key").exists());
        let view = read_secrets_mode(&home).unwrap();
        assert_eq!(view.mode, SecretsMode::KeychainSync);
        assert!(view.synchronizable);
        assert_eq!(view.namespace, "default");
        // File mode still mints the workspace key.
        let home2 = dir.path().join("h2");
        write_recognizable_home_with_mode(&home2, SecretsMode::File).unwrap();
        assert!(home2.join(".advance/master.key").is_file());
    }
}
