//! CONTRACT-193 — session auth policy: local-first bootstrap, CSRF, CORS/same-origin, and the
//! loopback-only default bind admission gate (§1.4.4, §1.7).

use std::sync::Mutex;

use rand::RngCore;

use crate::config::ClientApiConfig;
use crate::envelope::ClientErrorCode;

/// Bytes of entropy for the bearer token / CSRF token (256-bit).
const TOKEN_BYTES: usize = 32;
/// Bytes of entropy for the one-time bootstrap code (128-bit floor).
const BOOTSTRAP_CODE_BYTES: usize = 16;

struct BootstrapState {
    code: Option<String>,
    minted_at: u64,
    attempts: u32,
}

/// CONTRACT-193 auth policy + one-time bootstrap-code state for a single operator.
pub struct ClientSessionAuth {
    os_user: String,
    code_ttl_ms: u64,
    max_attempts: u32,
    bootstrap: Mutex<BootstrapState>,
}

impl ClientSessionAuth {
    pub fn new(os_user: impl Into<String>, code_ttl_ms: u64, max_attempts: u32) -> Self {
        Self {
            os_user: os_user.into(),
            code_ttl_ms,
            max_attempts: max_attempts.max(1),
            bootstrap: Mutex::new(BootstrapState {
                code: None,
                minted_at: 0,
                attempts: 0,
            }),
        }
    }

    /// The OS user this daemon runs as (the single operator principal id).
    pub fn os_user(&self) -> &str {
        &self.os_user
    }

    // ── Admission / CORS ────────────────────────────────────────────────────────────────

    /// Loopback-only default bind admission. A non-loopback peer is refused unless remote bind
    /// is explicitly enabled. This is the enforcement behind "loopback-only default binding".
    pub fn check_admission(
        config: &ClientApiConfig,
        is_loopback_peer: bool,
    ) -> Result<(), ClientErrorCode> {
        if is_loopback_peer || config.remote_bind_enabled {
            Ok(())
        } else {
            Err(ClientErrorCode::RemoteBindForbidden)
        }
    }

    /// Exact-match CORS allowlist. A request carrying an `Origin` not in the allowlist is
    /// refused (fail-closed: the default allowlist is empty).
    pub fn check_origin(
        config: &ClientApiConfig,
        origin: Option<&str>,
    ) -> Result<(), ClientErrorCode> {
        match origin {
            None => Ok(()),
            Some(o) if config.origin_allowed(o) => Ok(()),
            Some(_) => Err(ClientErrorCode::OriginNotAllowed),
        }
    }

    /// CSRF gate for a browser mutation. A request carrying an `Origin` (browser) must present a
    /// CSRF token that matches the session's (constant-time). Native clients (no `Origin`) are
    /// exempt (they authenticate via the signed bearer session).
    pub fn check_csrf(
        origin: Option<&str>,
        presented: Option<&str>,
        session_csrf: Option<&str>,
    ) -> Result<(), ClientErrorCode> {
        if origin.is_none() {
            return Ok(());
        }
        let expected = match session_csrf {
            Some(c) => c,
            None => return Err(ClientErrorCode::CsrfRequired),
        };
        match presented {
            None => Err(ClientErrorCode::CsrfRequired),
            Some(p) if ct_eq(p.as_bytes(), expected.as_bytes()) => Ok(()),
            Some(_) => Err(ClientErrorCode::CsrfInvalid),
        }
    }

    // ── Bootstrap one-time code ─────────────────────────────────────────────────────────

    /// Mint (or replace) the one-time non-loopback bootstrap code. Returns the code for the
    /// daemon CLI to print. ≥128-bit entropy; resets the attempt counter.
    pub fn mint_bootstrap_code(&self, now: u64) -> String {
        let code = random_hex(BOOTSTRAP_CODE_BYTES);
        let mut st = self.bootstrap.lock().expect("bootstrap lock");
        st.code = Some(code.clone());
        st.minted_at = now;
        st.attempts = 0;
        code
    }

    /// Verify a presented bootstrap code. Single-use (consumed on success); constant-time
    /// compare; after `max_attempts` wrong guesses within the TTL the code is invalidated
    /// (blocks online brute-force). Any failure returns `InvalidBootstrapCode`.
    pub fn verify_bootstrap_code(&self, presented: &str, now: u64) -> Result<(), ClientErrorCode> {
        let mut st = self.bootstrap.lock().expect("bootstrap lock");
        let code = match &st.code {
            None => return Err(ClientErrorCode::InvalidBootstrapCode),
            Some(c) => c.clone(),
        };
        // Expired → invalidate.
        if now.saturating_sub(st.minted_at) >= self.code_ttl_ms {
            st.code = None;
            return Err(ClientErrorCode::InvalidBootstrapCode);
        }
        if ct_eq(presented.as_bytes(), code.as_bytes()) {
            st.code = None; // single-use
            st.attempts = 0;
            return Ok(());
        }
        // Wrong guess → count; lock out at the threshold.
        st.attempts += 1;
        if st.attempts >= self.max_attempts {
            st.code = None;
        }
        Err(ClientErrorCode::InvalidBootstrapCode)
    }

    // ── Secret generation ───────────────────────────────────────────────────────────────

    /// A fresh opaque bearer/session token (256-bit).
    pub fn generate_token(&self) -> String {
        random_hex(TOKEN_BYTES)
    }

    /// A fresh CSRF token (256-bit).
    pub fn generate_csrf_token(&self) -> String {
        random_hex(TOKEN_BYTES)
    }

    /// A fresh public session id.
    pub fn generate_session_id(&self) -> String {
        format!("sess_{}", uuid::Uuid::new_v4().simple())
    }
}

/// Constant-time byte comparison (defeats timing side-channels on secret compares). The
/// length-difference early-out is acceptable: all compared secrets are fixed-length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `n` bytes of CSPRNG entropy, hex-encoded.
fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}
