//! `FsError` — slice-A representation of the WIT `variant fs-error`.
//!
//! The WIT enum has four cases (per MODULE-002 §1.4.1):
//!   not-found(string), permission-denied(string), invalid-path(string), io-error(string)
//!
//! Slice A maps each case onto a Rust enum variant carrying the same `String` payload
//! and provides `fs_error_to_val` to encode an `FsError` value into the
//! `Val::Variant(case_name, Some(Box::new(Val::String(payload))))` shape that
//! Wasmtime 43's canonical-ABI lowering expects for the WIT result-error position
//! (matches cap-llm `host_fn.rs` precedent for `Val::Variant`).

use wasmtime::component::Val;

/// WIT `variant fs-error` — the four-case error type returned by every host function.
///
/// Per MODULE-002 §2.9, hidden paths (Rule 7 `.advance/`, Rule 5 non-adjacent, the
/// workspace-scope hidden names `.git`/`.meta.yaml`/`*.sqlite[-wal]`) all surface as
/// `NotFound` — never `PermissionDenied` — so a malicious guest cannot fingerprint
/// hidden paths from a different error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// Path doesn't exist OR is hidden by Rule 7 / hidden-name policy.
    NotFound(String),
    /// Path resolves but the operation is denied (e.g. write to `.agent/` in slice B+).
    PermissionDenied(String),
    /// vpath fails the syntactic validation: contains `..` (ParentDir),
    /// is absolute (RootDir / Prefix), or is otherwise malformed.
    InvalidPath(String),
    /// Underlying filesystem I/O failure (disk full, EIO, etc.) OR a
    /// guest-induced bound exceeded (over-large file, over-many entries).
    IoError(String),
}

impl FsError {
    /// WIT case-name string for the encoded variant.
    pub fn case_name(&self) -> &'static str {
        match self {
            FsError::NotFound(_) => "not-found",
            FsError::PermissionDenied(_) => "permission-denied",
            FsError::InvalidPath(_) => "invalid-path",
            FsError::IoError(_) => "io-error",
        }
    }

    /// The string payload carried inside the variant case.
    pub fn payload(&self) -> &str {
        match self {
            FsError::NotFound(s)
            | FsError::PermissionDenied(s)
            | FsError::InvalidPath(s)
            | FsError::IoError(s) => s,
        }
    }
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.case_name(), self.payload())
    }
}

impl std::error::Error for FsError {}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        FsError::IoError(sanitize_io_error(&e))
    }
}

/// Sanitize an `std::io::Error` for guest-visible payload: emit ONLY the error
/// kind, never the underlying message (which on tokio/std typically contains the
/// resolved physical path — leaking host filesystem layout to the guest).
///
/// All cap-fs io error reporting MUST go through this function (or carry the
/// vpath only, never the physical path). The error kind is stable; the message
/// is platform-dependent and frequently embeds the host path.
pub fn sanitize_io_error(e: &std::io::Error) -> String {
    format!("io error: {:?}", e.kind())
}

/// Encode an [`FsError`] into the Wasmtime `Val::Variant` shape for the WIT
/// `result<T, fs-error>` error arm: `Val::Variant(case_name, Some(Box::new(Val::String(payload))))`.
pub fn fs_error_to_val(err: &FsError) -> Val {
    Val::Variant(
        err.case_name().to_string(),
        Some(Box::new(Val::String(err.payload().to_string()))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_name_round_trip() {
        assert_eq!(FsError::NotFound("p".into()).case_name(), "not-found");
        assert_eq!(
            FsError::PermissionDenied("p".into()).case_name(),
            "permission-denied"
        );
        assert_eq!(FsError::InvalidPath("p".into()).case_name(), "invalid-path");
        assert_eq!(FsError::IoError("p".into()).case_name(), "io-error");
    }

    #[test]
    fn fs_error_to_val_shape() {
        let v = fs_error_to_val(&FsError::NotFound("missing".into()));
        match v {
            Val::Variant(case, payload) => {
                assert_eq!(case, "not-found");
                match payload.as_deref() {
                    Some(Val::String(s)) => assert_eq!(s, "missing"),
                    other => panic!("expected Some(Val::String), got {other:?}"),
                }
            }
            other => panic!("expected Val::Variant, got {other:?}"),
        }
    }

    #[test]
    fn from_io_error_maps_to_io_error_variant_with_sanitized_payload() {
        // sanitize_io_error MUST NOT include the underlying io error message
        // (which on tokio/std typically embeds the resolved physical path —
        // leaking host filesystem layout to the guest).
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "boom-host-/path/leak");
        let fs: FsError = io.into();
        assert_eq!(fs.case_name(), "io-error");
        assert!(
            !fs.payload().contains("boom-host"),
            "sanitized payload must not contain underlying message; got: {}",
            fs.payload()
        );
        assert!(
            fs.payload().contains("PermissionDenied"),
            "sanitized payload must include the io::ErrorKind; got: {}",
            fs.payload()
        );
    }
}
