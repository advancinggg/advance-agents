//! Recognize / open.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use advance_runtime::config::load_config;

use crate::contract::{AlongHomeHandle, RecognizeClass};

pub fn recognize(path: &Path) -> RecognizeClass {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => return RecognizeClass::Unreadable,
        Err(e) if e.kind() == ErrorKind::NotFound => return RecognizeClass::NotAnAlongHome,
        Err(_) => return RecognizeClass::Unreadable,
    };
    if meta.file_type().is_symlink() {
        return RecognizeClass::NotAnAlongHome;
    }
    if !meta.is_dir() {
        return RecognizeClass::NotAnAlongHome;
    }
    #[cfg(unix)]
    {
        if !dir_accessible(path, libc::R_OK) {
            return RecognizeClass::Unreadable;
        }
        if !dir_accessible(path, libc::W_OK) {
            return RecognizeClass::Unwritable;
        }
    }

    let advance = path.join(".advance");
    let runtime = path.join(".runtime");
    let agent = path.join(".agent");
    let cfg = advance.join("runtime-config.yaml");

    let any_marker = path_exists_nofollow(&advance)
        || path_exists_nofollow(&runtime)
        || path_exists_nofollow(&agent)
        || path_exists_nofollow(&cfg);
    if !any_marker {
        return RecognizeClass::NotAnAlongHome;
    }
    if !(is_real_dir(&advance)
        && is_real_dir(&runtime)
        && is_real_dir(&agent)
        && is_real_file(&cfg))
    {
        return RecognizeClass::Damaged;
    }
    match load_config(&cfg) {
        Ok(_) => RecognizeClass::Recognized {
            path: path.to_path_buf(),
        },
        Err(_) => RecognizeClass::Damaged,
    }
}

pub fn open(path: &Path) -> Result<AlongHomeHandle, RecognizeClass> {
    match recognize(path) {
        RecognizeClass::Recognized { path } => Ok(AlongHomeHandle { path }),
        other => Err(other),
    }
}

#[allow(dead_code)]
pub(crate) fn require_recognized(home: &AlongHomeHandle) -> Result<PathBuf, RecognizeClass> {
    match recognize(&home.path) {
        RecognizeClass::Recognized { path } => Ok(path),
        other => Err(other),
    }
}

pub(crate) fn is_real_dir(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_dir(),
        Err(_) => false,
    }
}

pub(crate) fn is_real_file(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_file(),
        Err(_) => false,
    }
}

fn path_exists_nofollow(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn dir_accessible(path: &Path, mode: libc::c_int) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let Ok(c) = std::ffi::CString::new(bytes) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path; access is a query.
    unsafe { libc::access(c.as_ptr(), mode) == 0 }
}

#[cfg(not(unix))]
fn dir_accessible(path: &Path, _mode: i32) -> bool {
    let _ = path;
    true
}
