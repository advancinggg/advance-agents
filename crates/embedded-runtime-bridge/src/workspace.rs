//! Workspace create / symlink fail-closed binding.

use std::fs;
use std::path::{Path, PathBuf};

use advance_runtime::config::check_no_ancestor_symlinks_parents;

use crate::error::BridgeError;

/// Prepare workspace root: create if missing, reject file/symlink, create dirs.
pub fn prepare_workspace(root: &Path) -> Result<PathBuf, BridgeError> {
    if root.exists() {
        let meta = fs::symlink_metadata(root).map_err(|e| {
            BridgeError::InvalidWorkspace(format!("metadata: {e}"))
        })?;
        if meta.file_type().is_symlink() {
            return Err(BridgeError::InvalidWorkspace(
                "workspace root must not be a symlink".into(),
            ));
        }
        if meta.is_file() {
            return Err(BridgeError::InvalidWorkspace(
                "workspace root is a file".into(),
            ));
        }
    } else {
        create_dir_private(root)?;
    }

    // Canonicalize first so macOS /var → /private/var does not trip ancestor checks.
    let root = root
        .canonicalize()
        .map_err(|e| BridgeError::InvalidWorkspace(format!("canonicalize: {e}")))?;

    // Ancestor symlink check on a sentinel path under the resolved root.
    let sentinel = root.join(".advance").join("runtime-config.yaml");
    if let Err(e) = check_no_ancestor_symlinks_parents(&sentinel) {
        return Err(BridgeError::InvalidWorkspace(format!(
            "ancestor symlink: {e}"
        )));
    }

    let advance = root.join(".advance");
    let runtime = root.join(".runtime");
    if !advance.exists() {
        create_dir_private(&advance)?;
    }
    if !runtime.exists() {
        create_dir_private(&runtime)?;
    }

    Ok(root)
}

fn create_dir_private(path: &Path) -> Result<(), BridgeError> {
    fs::create_dir_all(path)
        .map_err(|e| BridgeError::InvalidWorkspace(format!("create_dir {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}
