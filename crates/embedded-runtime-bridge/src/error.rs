//! Bridge error types (no secrets on the wire).

use std::path::PathBuf;

use thiserror::Error;

/// Public bridge errors. Display strings are redacted for FFI last_error.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("invalid argument")]
    InvalidArg,
    #[error("invalid utf-8")]
    InvalidUtf8,
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid workspace: {0}")]
    InvalidWorkspace(String),
    #[error("already running for workspace")]
    AlreadyRunning,
    #[error("invalid handle")]
    InvalidHandle,
    #[error("config error: {0}")]
    Config(String),
    #[error("bootstrap error: {0}")]
    Bootstrap(String),
    #[error("supervise error: {0}")]
    Supervise(String),
    #[error("supervise start timeout")]
    SuperviseStartTimeout,
    #[error("nested tokio runtime — use async API")]
    NestedRuntime,
    #[error("output buffer too small")]
    BufferTooSmall { required: usize },
    #[error("internal error")]
    Internal(String),
    #[error("path error: {0}")]
    Path(PathBuf),
}

impl BridgeError {
    /// Stable C status codes (see advance_bridge.h).
    pub fn c_code(&self) -> i32 {
        match self {
            Self::InvalidArg => 1,
            Self::InvalidUtf8 => 2,
            Self::InvalidConfig(_) => 3,
            Self::InvalidWorkspace(_) => 4,
            Self::AlreadyRunning => 5,
            Self::InvalidHandle => 6,
            Self::Config(_) => 7,
            Self::Bootstrap(_) => 8,
            Self::Supervise(_) => 9,
            Self::SuperviseStartTimeout => 10,
            Self::NestedRuntime => 11,
            Self::BufferTooSmall { .. } => 12,
            Self::Internal(_) | Self::Path(_) => 13,
        }
    }

    /// Redacted message for FFI (no key material).
    pub fn redacted_message(&self) -> String {
        let raw = self.to_string();
        redact(&raw)
    }
}

fn redact(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    if lower.contains("key=")
        || lower.contains("token=")
        || lower.contains("bearer")
        || lower.contains("secrets.json")
        || lower.contains("master")
    {
        "redacted error".to_string()
    } else {
        raw_truncate(s, 512)
    }
}

fn raw_truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}
