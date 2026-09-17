//! Create parent + single-segment name.

use std::path::Path;

use crate::contract::{CreateError, RecognizeClass, WorkspaceHomeHandle};
use crate::recognize::{open, recognize};
use crate::scaffold::{write_create_driver, write_recognizable_home_with_mode, SecretsMode};

/// File secrets mode (the pre-existing `create`).
pub fn create(parent: &Path, name: &str) -> Result<WorkspaceHomeHandle, CreateError> {
    create_with_secrets_mode(parent, name, SecretsMode::File)
}

/// `create` with an explicit secrets mode. The
/// product's `along_home_create` grows the matching parameter (and its ABI version) on its
/// side.
pub fn create_with_secrets_mode(
    parent: &Path,
    name: &str,
    mode: SecretsMode,
) -> Result<WorkspaceHomeHandle, CreateError> {
    let name = name.trim();
    if !valid_name(name) {
        return Err(CreateError::InvalidName);
    }
    if !crate::recognize::is_real_dir(parent) {
        return Err(CreateError::ParentUnusable(recognize(parent)));
    }
    match recognize(parent) {
        RecognizeClass::Unreadable | RecognizeClass::Unwritable => {
            return Err(CreateError::ParentUnusable(recognize(parent)));
        }
        _ => {}
    }
    let target = parent.join(name);
    if std::fs::symlink_metadata(&target).is_ok() {
        match recognize(&target) {
            RecognizeClass::Recognized { .. } => {
                return open(&target).map_err(|_| CreateError::Io);
            }
            _ => return Err(CreateError::ExistsNotWorkspaceHome),
        }
    }
    write_recognizable_home_with_mode(&target, mode).map_err(|_| CreateError::Io)?;
    if write_create_driver(&target).is_err() {
        rollback_created_home(&target);
        return Err(CreateError::Io);
    }
    match open(&target) {
        Ok(handle) => Ok(handle),
        Err(_) => {
            rollback_created_home(&target);
            Err(CreateError::Io)
        }
    }
}

/// Unlink a home this `create` just minted. Never follow a symlink (would
/// delete a victim tree or only drop the link and leave `master.key`).
fn rollback_created_home(target: &Path) {
    match std::fs::symlink_metadata(target) {
        Ok(m) if m.file_type().is_symlink() => {}
        Ok(m) if m.file_type().is_dir() => {
            let _ = std::fs::remove_dir_all(target);
        }
        _ => {}
    }
}

fn valid_name(name: &str) -> bool {
    if name.is_empty() || name == ".." || name == "." {
        return false;
    }
    !name.contains('/') && !name.contains('\\')
}
