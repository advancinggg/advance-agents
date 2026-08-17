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
    reject_symlink_path(&advance)?;
    reject_symlink_path(&runtime)?;
    if !advance.exists() {
        create_dir_private(&advance)?;
    }
    if !runtime.exists() {
        create_dir_private(&runtime)?;
    }
    // Reject a symlinked runtime.lock leaf if present.
    reject_symlink_path(&runtime.join("runtime.lock"))?;
    reject_symlink_path(&root.join(".agent"))?;
    reject_symlink_path(&root.join(".agent").join("config.yaml"))?;
    // runtime.lock must be missing or a regular file (not FIFO/socket).
    reject_non_regular_file(&runtime.join("runtime.lock"))?;

    Ok(root)
}

fn reject_symlink_path(path: &Path) -> Result<(), BridgeError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(BridgeError::InvalidWorkspace(format!(
            "symlink not allowed: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BridgeError::InvalidWorkspace(format!(
            "metadata {}: {e}",
            path.display()
        ))),
    }
}

fn reject_non_regular_file(path: &Path) -> Result<(), BridgeError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() || meta.file_type().is_symlink() => {
            // symlink already rejected; allow regular file
            if meta.file_type().is_symlink() {
                return Err(BridgeError::InvalidWorkspace(format!(
                    "symlink not allowed: {}",
                    path.display()
                )));
            }
            Ok(())
        }
        Ok(meta) if !meta.file_type().is_dir() => Err(BridgeError::InvalidWorkspace(format!(
            "non-regular lock path not allowed: {}",
            path.display()
        ))),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn create_dir_private(path: &Path) -> Result<(), BridgeError> {
    // Recurse only through *missing* parents so existing system aliases
    // (macOS `/var` → `/private/var`) are not rejected.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            create_dir_private(parent)?;
        }
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(BridgeError::InvalidWorkspace(format!(
            "symlink not allowed: {}",
            path.display()
        ))),
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(BridgeError::InvalidWorkspace(format!(
            "not a directory: {}",
            path.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|e| {
                BridgeError::InvalidWorkspace(format!("create_dir {}: {e}", path.display()))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
                    BridgeError::InvalidWorkspace(format!("chmod 0700 {}: {e}", path.display()))
                })?;
            }
            reject_symlink_path(path)
        }
        Err(e) => Err(BridgeError::InvalidWorkspace(format!(
            "metadata {}: {e}",
            path.display()
        ))),
    }
}
