//! Create parent + single-segment name.

use std::path::Path;

use crate::contract::{AlongHomeHandle, CreateError, RecognizeClass};
use crate::recognize::{open, recognize};
use crate::scaffold::write_recognizable_home;

pub fn create(parent: &Path, name: &str) -> Result<AlongHomeHandle, CreateError> {
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
            _ => return Err(CreateError::ExistsNotAlongHome),
        }
    }
    write_recognizable_home(&target).map_err(|_| CreateError::Io)?;
    open(&target).map_err(|_| CreateError::Io)
}

fn valid_name(name: &str) -> bool {
    if name.is_empty() || name == ".." || name == "." {
        return false;
    }
    !name.contains('/') && !name.contains('\\')
}
