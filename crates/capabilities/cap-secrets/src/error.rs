//! SecretError and StorageError variants. Display impls are deliberately
//! terse and never echo ciphertext / key / nonce / salt bytes — enforced
//! by `error::test_display_hygiene_all_variants`.

use crate::storage::StorageError;

pub enum SecretError {
    /// Secret name not in storage.
    NotFound(String),
    /// Master key loader failed (env / keychain / hex decode / length).
    /// Message is human-readable but contains no raw bytes.
    KeyLoad(String),
    /// AES-GCM or HKDF operation failed. `&'static str` so no ciphertext
    /// can be formatted through Display / Debug.
    Crypto(&'static str),
    /// Underlying storage backend error.
    Storage(StorageError),
    /// Decrypted plaintext was not valid UTF-8.
    InvalidUtf8,
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Sanitize `name` to prevent log-injection via control chars,
            // ANSI escape sequences, bidi Unicode, etc. The secret name is
            // attacker-controllable from a WASM guest (once agent-secrets is
            // wired post-AC-16), and its Display output bubbles into
            // wasmtime error messages → tracing::error! → log aggregators /
            // terminals. Limit to printable ASCII + safe punctuation;
            // replace the rest with '?'.
            SecretError::NotFound(name) => {
                let sanitized = sanitize_identifier(name);
                write!(f, "secret not found: {sanitized}")
            }
            SecretError::KeyLoad(msg) => write!(f, "master key load failed: {msg}"),
            SecretError::Crypto(reason) => write!(f, "crypto operation failed: {reason}"),
            // Elide the backend string on Display and Debug alike.
            SecretError::Storage(_) => write!(f, "secret storage backend error"),
            SecretError::InvalidUtf8 => write!(f, "decrypted secret not valid UTF-8"),
        }
    }
}

/// Replace any char that is NOT ASCII-printable (space through tilde) with
/// '?'. Truncates to 128 chars to bound log volume. Used by the NotFound
/// Display branch + the m012-slice-e `GatedSecretExistsHandler` reject path
/// (host_fn.rs) to defang log-injection attempts on attacker-controllable
/// secret names. `pub(crate)` visibility — crate-internal helper, no
/// external pub-surface change.
pub(crate) fn sanitize_identifier(s: &str) -> String {
    s.chars()
        .take(128)
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .collect()
}

/// Manual Debug impl — delegates to Display so `{:?}` formatting (used by
/// `panic!`, `anyhow::Error` backtraces, `tracing::error!(err = ?e)`,
/// etc.) cannot leak any payload byte content. The deriving `#[derive(Debug)]`
/// would print `Storage(Backend("..."))` verbatim, which would defeat the
/// hygiene posture for any backend-produced error string that might contain
/// sensitive payload bytes.
impl std::fmt::Debug for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for SecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SecretError::Storage(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StorageError> for SecretError {
    fn from(e: StorageError) -> Self {
        SecretError::Storage(e)
    }
}

impl From<std::string::FromUtf8Error> for SecretError {
    fn from(_: std::string::FromUtf8Error) -> Self {
        SecretError::InvalidUtf8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageError;

    #[test]
    fn test_display_hygiene_all_variants() {
        // Crypto: static reason, no bytes.
        let c = SecretError::Crypto("aes-gcm decrypt failed");
        let s = format!("{c}");
        assert!(!contains_long_hex(&s), "Crypto Display leaked hex: {s}");
        // Debug (delegates to Display) must also not leak.
        let d = format!("{c:?}");
        assert!(!contains_long_hex(&d), "Crypto Debug leaked hex: {d}");

        // Storage: Display and Debug must NOT echo the Backend string.
        let backing_hex = "deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef";
        let storage_err = SecretError::Storage(StorageError::Backend(backing_hex.to_string()));
        let s = format!("{storage_err}");
        assert!(
            !s.contains(backing_hex),
            "Storage Display echoed raw backend string: {s}"
        );
        assert!(!contains_long_hex(&s), "Storage Display leaked hex: {s}");
        let d = format!("{storage_err:?}");
        assert!(
            !d.contains(backing_hex),
            "Storage Debug echoed raw backend string: {d}"
        );
        assert!(!contains_long_hex(&d), "Storage Debug leaked hex: {d}");

        // KeyLoad: fixed prefix + category message.
        let k = SecretError::KeyLoad(
            "hex decode failed (invalid input — expected 64 hex chars)".to_string(),
        );
        let s = format!("{k}");
        assert!(!contains_long_hex(&s));
        assert!(s.starts_with("master key load failed:"));
        let d = format!("{k:?}");
        assert!(!contains_long_hex(&d));

        // NotFound: safe ASCII name passes through; control chars / ANSI
        // escapes / bidi Unicode are sanitized to '?'.
        let nf = SecretError::NotFound("api_key".to_string());
        let s = format!("{nf}");
        assert!(s.contains("api_key"));
        assert!(s.starts_with("secret not found:"));

        // Log-injection attempt — control chars, ANSI escapes, bidi:
        let malicious = "api\n\x1b]0;PWN\x07\u{202e}";
        let nf2 = SecretError::NotFound(malicious.to_string());
        let s2 = format!("{nf2}");
        assert!(!s2.contains('\n'), "newline not sanitized: {s2:?}");
        assert!(!s2.contains('\x1b'), "ESC not sanitized: {s2:?}");
        assert!(!s2.contains('\x07'), "BEL not sanitized: {s2:?}");
        assert!(!s2.contains('\u{202e}'), "bidi RLO not sanitized: {s2:?}");
        assert!(s2.starts_with("secret not found:"));

        // Length bound: very long name truncated to 128 chars of sanitized output.
        let long = "x".repeat(1024);
        let nf3 = SecretError::NotFound(long);
        let s3 = format!("{nf3}");
        // "secret not found: " prefix (18 chars) + 128 sanitized chars = 146 chars.
        assert!(
            s3.len() <= 18 + 128,
            "NotFound Display not truncated: {}",
            s3.len()
        );

        // InvalidUtf8: trivial.
        let u = SecretError::InvalidUtf8;
        let s = format!("{u}");
        assert_eq!(s, "decrypted secret not valid UTF-8");
        let d = format!("{u:?}");
        assert_eq!(d, "decrypted secret not valid UTF-8");

        // StorageError direct Debug must also elide the backend string.
        let raw_storage = StorageError::Backend(backing_hex.to_string());
        let s = format!("{raw_storage}");
        assert!(!s.contains(backing_hex));
        let d = format!("{raw_storage:?}");
        assert!(!d.contains(backing_hex), "StorageError Debug echoed: {d}");
    }

    fn contains_long_hex(s: &str) -> bool {
        let mut run = 0usize;
        for c in s.chars() {
            if c.is_ascii_hexdigit() {
                run += 1;
                if run >= 16 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }
}
