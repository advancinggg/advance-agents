//! MODULE-005 persist for the top-level display name (first-open write path).

use std::fs;
use std::path::Path;

use crate::contract::DisplayNameError;

pub struct TopLevelDisplayName;

impl TopLevelDisplayName {
    pub const TREE_ID: &'static str = "default-agent";
    pub const MAILBOX_ID: &'static str = "agent:default";

    pub fn path(home: &Path) -> std::path::PathBuf {
        home.join(".agent").join("display-name")
    }

    pub fn set(home: &Path, name: &str) -> Result<(), DisplayNameError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(DisplayNameError::Empty);
        }
        let dest = Self::path(home);
        let tmp = home.join(".agent").join(".display-name.tmp");
        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
        crate::scaffold::write_0600_nofollow(&tmp, trimmed.as_bytes())
            .map_err(|_| DisplayNameError::Empty)?;
        fs::rename(&tmp, &dest).map_err(|_| DisplayNameError::Empty)?;
        Ok(())
    }

    pub fn get(home: &Path) -> Option<String> {
        let raw = crate::scaffold::read_small_regular(&Self::path(home), 256)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}
