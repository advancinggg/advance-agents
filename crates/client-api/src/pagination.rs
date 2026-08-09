//! CONTRACT-190 — opaque cursor pagination for list endpoints.
//!
//! The cursor is an opaque base64url token wrapping a small JSON position `{offset, last_id}`.
//! Clients treat it as opaque; the server bounds its length before decoding (adversarial input
//! never reaches an unbounded allocation).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Upper bound on an accepted cursor token (bounds decode work; a real position is ~tens of
/// bytes).
pub const MAX_CURSOR_LEN: usize = 512;

/// Default and maximum page size for list endpoints.
pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 500;

/// The decoded cursor position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Cursor {
    pub offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_id: Option<String>,
}

impl Cursor {
    pub fn new(offset: u64, last_id: Option<String>) -> Self {
        Self { offset, last_id }
    }

    /// Encode to an opaque base64url token.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("Cursor serializes");
        URL_SAFE_NO_PAD.encode(json)
    }

    /// Decode an opaque token. Returns `None` for a malformed or over-long token (never panics,
    /// never allocates unboundedly).
    pub fn decode(token: &str) -> Option<Cursor> {
        if token.len() > MAX_CURSOR_LEN {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?;
        serde_json::from_slice::<Cursor>(&bytes).ok()
    }
}

/// A page of results plus an optional continuation cursor (absent when the list is exhausted).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, next_cursor: Option<String>) -> Self {
        Self { items, next_cursor }
    }
}

/// Clamp a caller-provided limit into `[1, MAX_LIMIT]`, defaulting when `None`.
pub fn clamp_limit(limit: Option<usize>) -> usize {
    match limit {
        None => DEFAULT_LIMIT,
        Some(0) => 1,
        Some(n) => n.min(MAX_LIMIT),
    }
}
