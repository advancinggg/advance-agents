//! MODULE-005 persist for an agent's display name (first-open write path).
//!
//! An agent has three names (see `cap-lifecycle::identity`): the immutable `id`
//! (UUID, every store's key), the addressable `handle` (mailbox `agent:<handle>`,
//! derived once from the display name and frozen), and the free-text
//! `display-name` this module persists. All three live in the agent's own
//! `<home>/.agent/config.yaml`. The runtime never reads `display-name` at boot,
//! so a rename is not a capability change and needs no restart.

use std::fs;
use std::path::{Path, PathBuf};

use serde_yml::{Mapping, Value};

use crate::contract::DisplayNameError;

/// Top-level YAML key carrying the user-visible name.
pub const DISPLAY_NAME_KEY: &str = "display-name";

/// Bound on the config document read here (mirrors the lifecycle atomic-write cap).
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

pub struct TopLevelDisplayName;

impl TopLevelDisplayName {
    /// The config document the name is persisted in.
    pub fn config_path(home: &Path) -> PathBuf {
        home.join(".agent").join("config.yaml")
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
        Ok(())
    }

    /// The persisted display name (the `display-name` key), if any.
    pub fn get(home: &Path) -> Option<String> {
        let raw = crate::scaffold::read_small_regular(&Self::config_path(home), MAX_CONFIG_BYTES)?;
        let doc = parse_mapping(&raw)?;
        let value = doc.get(Value::String(DISPLAY_NAME_KEY.to_string()))?;
        let trimmed = value.as_str()?.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

fn parse_mapping(raw: &str) -> Option<Mapping> {
    match serde_yml::from_str::<Value>(raw).ok()? {
        Value::Mapping(m) => Some(m),
        Value::Null => Some(Mapping::new()),
        _ => None,
    }
}
