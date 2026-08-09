//! CONTRACT-193 — client sessions and the single-operator principal model (§1.4.4).
//!
//! Every session maps to the single workspace operator; `scopes` narrow *what* a session may
//! do, not *who* it is. The bearer token is the map key (a high-entropy opaque secret) and is
//! never stored inside the session value; a lookup by token is not a linear secret compare, so
//! constant-time comparison is unnecessary here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::ClientErrorCode;

/// The single-operator principal (local-first). `id` == the OS user the daemon runs as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Principal {
    pub id: String,
    pub os_user: String,
}

impl Principal {
    pub fn operator(os_user: impl Into<String>) -> Self {
        let os_user = os_user.into();
        Self {
            id: os_user.clone(),
            os_user,
        }
    }
}

/// Client platform (shared multi-platform contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Web,
    Mac,
    Ios,
    Android,
    Windows,
}

/// A capability scope narrowing what a session may do (never who it is).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    ReadRuns,
    ControlRuns,
    ReadMessages,
    SendMessages,
    ApproveGrants,
    ReadInventory,
    /// m020-s3 CONTRACT-191 — read client event stream and historical query.
    ReadEvents,
    /// Tee T2 (CONTRACT-235) — subscribe to the LLM token-delta stream (§2.4).
    ReadLlmDeltas,
}

impl Scope {
    /// The full operator scope set (single-operator local-first: the operator may do anything).
    pub fn operator_default() -> Vec<Scope> {
        vec![
            Scope::ReadRuns,
            Scope::ControlRuns,
            Scope::ReadMessages,
            Scope::SendMessages,
            Scope::ApproveGrants,
            Scope::ReadInventory,
            Scope::ReadEvents,
            Scope::ReadLlmDeltas,
        ]
    }
}

/// A live client session (server-side state). `Debug` redacts the CSRF token.
#[derive(Clone)]
pub struct ClientSession {
    pub session_id: String,
    pub principal: Principal,
    pub platform: Platform,
    pub scopes: Vec<Scope>,
    /// Present for browser sessions (required for browser mutations); `None` for native.
    pub csrf_token: Option<String>,
    pub expires_at: u64,
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSession")
            .field("session_id", &self.session_id)
            .field("principal", &self.principal)
            .field("platform", &self.platform)
            .field("scopes", &self.scopes)
            .field(
                "csrf_token",
                &self.csrf_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The wire DTO returned by login/refresh. Carries the bearer `token` (the client stores it)
/// plus the public session metadata. Part of the CONTRACT-192 schema. `Debug` redacts the
/// bearer token and CSRF token.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionInfo {
    pub session_id: String,
    pub token: String,
    pub principal: Principal,
    pub platform: Platform,
    pub scopes: Vec<Scope>,
    pub csrf_token: Option<String>,
    pub expires_at: u64,
}

impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionInfo")
            .field("session_id", &self.session_id)
            .field("token", &"<redacted>")
            .field("principal", &self.principal)
            .field("platform", &self.platform)
            .field("scopes", &self.scopes)
            .field(
                "csrf_token",
                &self.csrf_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Token-keyed session store with TTL expiry, an expiry sweep, and a hard cap (bounded memory).
/// `Debug` shows only the live count (never the bearer-token keys).
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<Mutex<HashMap<String, ClientSession>>>,
    cap: usize,
}

impl std::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStore")
            .field("live_sessions", &self.len())
            .finish()
    }
}

impl SessionStore {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            cap: cap.max(1),
        }
    }

    /// Insert a freshly-minted session under its bearer token. Sweeps expired sessions and
    /// enforces the cap (evicting the soonest-to-expire) so the store stays bounded even under
    /// abandoned-token / re-login churn.
    pub fn insert(&self, token: String, session: ClientSession, now: u64) {
        let mut map = self.inner.lock().expect("session store lock");
        map.retain(|_, s| s.expires_at > now); // sweep expired sessions
        if !map.contains_key(&token) && map.len() >= self.cap {
            if let Some(victim) = map
                .iter()
                .min_by_key(|(_, s)| s.expires_at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&victim);
            }
        }
        map.insert(token, session);
    }

    /// Look up a valid (non-expired) session by bearer token. Expired sessions are removed and
    /// reported as `SessionExpired`; absent/unknown tokens are `Unauthenticated`.
    pub fn get_valid(&self, token: &str, now: u64) -> Result<ClientSession, ClientErrorCode> {
        let mut map = self.inner.lock().expect("session store lock");
        match map.get(token) {
            None => Err(ClientErrorCode::Unauthenticated),
            Some(s) if s.expires_at <= now => {
                map.remove(token);
                Err(ClientErrorCode::SessionExpired)
            }
            Some(s) => Ok(s.clone()),
        }
    }

    /// Rotate the bearer token and extend expiry. Returns the new token + session.
    pub fn refresh(
        &self,
        token: &str,
        now: u64,
        new_expires_at: u64,
        new_token: String,
    ) -> Result<(String, ClientSession), ClientErrorCode> {
        let mut map = self.inner.lock().expect("session store lock");
        let mut session = match map.get(token) {
            None => return Err(ClientErrorCode::Unauthenticated),
            Some(s) if s.expires_at <= now => {
                map.remove(token);
                return Err(ClientErrorCode::SessionExpired);
            }
            Some(s) => s.clone(),
        };
        map.remove(token);
        session.expires_at = new_expires_at;
        map.insert(new_token.clone(), session.clone());
        Ok((new_token, session))
    }

    /// Revoke a session by token (logout). Idempotent.
    pub fn revoke(&self, token: &str) {
        self.inner.lock().expect("session store lock").remove(token);
    }

    /// Revoke EVERY token belonging to `session_id`. Idempotent. Used by logout so the session
    /// dies even if a concurrent `refresh` rotated its token in the validate→revoke window (the
    /// rotated token shares the session id and is removed too).
    pub fn revoke_session(&self, session_id: &str) {
        self.inner
            .lock()
            .expect("session store lock")
            .retain(|_, s| s.session_id != session_id);
    }

    /// Live session count (test/introspection helper).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("session store lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
