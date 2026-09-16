//! MODULE-005 persist for an agent's display name (first-open write path).
//!
//! The display name lives in the agent's own config document,
//! `<home>/.agent/config.yaml`, under the top-level `display-name` key. The
//! runtime never reads that key at boot (it consumes `capabilities:` and
//! `agents:` only), so a rename is not a capability change and needs no
//! restart. Homes written before this key existed persisted the name in a
//! sidecar file `<home>/.agent/display-name`; [`TopLevelDisplayName::get`]
//! still falls back to it, so an old home keeps its name without migration.
//! A write always goes to the config document, and clears a stale sidecar
//! so the two can never disagree afterwards.

use std::fs;
use std::path::{Path, PathBuf};

use serde_yml::{Mapping, Value};

use crate::contract::DisplayNameError;

/// Top-level YAML key carrying the user-visible name.
pub const DISPLAY_NAME_KEY: &str = "display-name";

/// Bound on the config document read here (mirrors the lifecycle atomic-write cap).
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Bound on the legacy sidecar file.
const MAX_SIDECAR_BYTES: u64 = 256;

pub struct TopLevelDisplayName;

impl TopLevelDisplayName {
    pub const TREE_ID: &'static str = "default-agent";
    pub const MAILBOX_ID: &'static str = "agent:default";

    /// The config document the name is persisted in.
    pub fn config_path(home: &Path) -> PathBuf {
        home.join(".agent").join("config.yaml")
    }

    /// The pre-`display-name`-key sidecar file (read-only fallback).
    pub fn path(home: &Path) -> PathBuf {
        home.join(".agent").join("display-name")
    }

    /// Persist `name` as the `display-name` key of `<home>/.agent/config.yaml`,
    /// keeping every other key of the document intact. An absent document is
    /// created with just that key; a document that is not a YAML mapping (or
    /// exceeds the bound) is left untouched and the write fails.
    pub fn set(home: &Path, name: &str) -> Result<(), DisplayNameError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(DisplayNameError::Empty);
        }
        let dest = Self::config_path(home);
        let mut doc = match fs::symlink_metadata(&dest) {
            Ok(_) => {
                let raw = crate::scaffold::read_small_regular(&dest, MAX_CONFIG_BYTES)
                    .ok_or(DisplayNameError::Empty)?;
                parse_mapping(&raw).ok_or(DisplayNameError::Empty)?
            }
            Err(_) => Mapping::new(),
        };
        doc.insert(
            Value::String(DISPLAY_NAME_KEY.to_string()),
            Value::String(trimmed.to_string()),
        );
        let text =
            serde_yml::to_string(&Value::Mapping(doc)).map_err(|_| DisplayNameError::Empty)?;
        let tmp = home.join(".agent").join(".config.yaml.tmp");
        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
        crate::scaffold::write_0600_nofollow(&tmp, text.as_bytes())
            .map_err(|_| DisplayNameError::Empty)?;
        fs::rename(&tmp, &dest).map_err(|_| DisplayNameError::Empty)?;
        // The document is now authoritative: drop a stale sidecar so a later
        // read can never resurrect the old name.
        let legacy = Self::path(home);
        if matches!(fs::symlink_metadata(&legacy), Ok(m) if m.file_type().is_file()) {
            let _ = fs::remove_file(&legacy);
        }
        Ok(())
    }

    /// The persisted display name: the `display-name` key of the config
    /// document, else the legacy sidecar file, else `None`.
    pub fn get(home: &Path) -> Option<String> {
        if let Some(name) = Self::from_config(home) {
            return Some(name);
        }
        let raw = crate::scaffold::read_small_regular(&Self::path(home), MAX_SIDECAR_BYTES)?;
        non_empty(&raw)
    }

    fn from_config(home: &Path) -> Option<String> {
        let raw = crate::scaffold::read_small_regular(&Self::config_path(home), MAX_CONFIG_BYTES)?;
        let doc = parse_mapping(&raw)?;
        let value = doc.get(Value::String(DISPLAY_NAME_KEY.to_string()))?;
        non_empty(value.as_str()?)
    }
}

fn parse_mapping(raw: &str) -> Option<Mapping> {
    match serde_yml::from_str::<Value>(raw).ok()? {
        Value::Mapping(m) => Some(m),
        Value::Null => Some(Mapping::new()),
        _ => None,
    }
}

fn non_empty(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
