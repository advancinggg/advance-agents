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
use sha2::{Digest, Sha256};

use crate::envelope::ClientErrorCode;

/// Domain separator for the session digest that file tickets bind.
const SESSION_DIGEST_DOMAIN: &[u8] = b"advance.files.session.v1\0";

/// SHA-256(`"advance.files.session.v1\0"` ‖ session_id). Refresh keeps the id, so the digest
/// survives a token rotation; logout / expiry / `revoke_all` drop it.
pub fn session_digest(session_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_DIGEST_DOMAIN);
    hasher.update(session_id.as_bytes());
    hasher.finalize().into()
}

/// First 8 bytes of [`session_digest`] as 16 hex chars (`FilesActor.session_ref`).
pub fn session_ref_hex(session_id: &str) -> String {
    hex::encode(&session_digest(session_id)[..8])
}

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
    /// Entity-data lane E3 — the entities-family mutations (create / patch / apply / promote /
    /// demote). Reads (`/client/schema`, `:query`, one row) stay under `ReadInventory`.
    WriteEntities,
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
            Scope::WriteEntities,
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
struct SessionMaps {
    by_token: HashMap<String, ClientSession>,
    by_digest: HashMap<[u8; 32], String>,
}

#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<Mutex<SessionMaps>>,
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
            inner: Arc::new(Mutex::new(SessionMaps {
                by_token: HashMap::new(),
                by_digest: HashMap::new(),
            })),
            cap: cap.max(1),
        }
    }

    fn forget_token(maps: &mut SessionMaps, token: &str) {
        if let Some(session) = maps.by_token.remove(token) {
            maps.by_digest.remove(&session_digest(&session.session_id));
        }
    }

    fn index_session(maps: &mut SessionMaps, token: String, session: ClientSession) {
        let digest = session_digest(&session.session_id);
        if let Some(old_token) = maps.by_digest.insert(digest, token.clone()) {
            if old_token != token {
                maps.by_token.remove(&old_token);
            }
        }
        maps.by_token.insert(token, session);
    }

    /// Insert a freshly-minted session under its bearer token. Sweeps expired sessions and
    /// enforces the cap (evicting the soonest-to-expire) so the store stays bounded even under
    /// abandoned-token / re-login churn.
    pub fn insert(&self, token: String, session: ClientSession, now: u64) {
        let mut maps = self.inner.lock().expect("session store lock");
        let expired: Vec<String> = maps
            .by_token
            .iter()
            .filter(|(_, s)| s.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for token in expired {
            Self::forget_token(&mut maps, &token);
        }
        if !maps.by_token.contains_key(&token) && maps.by_token.len() >= self.cap {
            if let Some(victim) = maps
                .by_token
                .iter()
                .min_by_key(|(_, s)| s.expires_at)
                .map(|(k, _)| k.clone())
            {
                Self::forget_token(&mut maps, &victim);
            }
        }
        Self::index_session(&mut maps, token, session);
    }

    /// Look up a valid (non-expired) session by bearer token. Expired sessions are removed and
    /// reported as `SessionExpired`; absent/unknown tokens are `Unauthenticated`.
    pub fn get_valid(&self, token: &str, now: u64) -> Result<ClientSession, ClientErrorCode> {
        let mut maps = self.inner.lock().expect("session store lock");
        match maps.by_token.get(token) {
            None => Err(ClientErrorCode::Unauthenticated),
            Some(s) if s.expires_at <= now => {
                Self::forget_token(&mut maps, token);
                Err(ClientErrorCode::SessionExpired)
            }
            Some(s) => Ok(s.clone()),
        }
    }

    /// Look up a live session by the digest a file ticket binds.
    pub fn get_valid_by_session_digest(
        &self,
        digest: &[u8; 32],
        now: u64,
    ) -> Result<ClientSession, ClientErrorCode> {
        let mut maps = self.inner.lock().expect("session store lock");
        let token = maps
            .by_digest
            .get(digest)
            .cloned()
            .ok_or(ClientErrorCode::Unauthenticated)?;
        match maps.by_token.get(&token) {
            None => {
                maps.by_digest.remove(digest);
                Err(ClientErrorCode::Unauthenticated)
            }
            Some(s) if s.expires_at <= now => {
                Self::forget_token(&mut maps, &token);
                Err(ClientErrorCode::SessionExpired)
            }
            Some(s) => Ok(s.clone()),
        }
    }

    /// True when [`get_valid_by_session_digest`] would succeed.
    pub fn is_live_digest(&self, digest: &[u8; 32], now: u64) -> bool {
        self.get_valid_by_session_digest(digest, now).is_ok()
    }

    /// Rotate the bearer token and extend expiry. Returns the new token + session.
    pub fn refresh(
        &self,
        token: &str,
        now: u64,
        new_expires_at: u64,
        new_token: String,
    ) -> Result<(String, ClientSession), ClientErrorCode> {
        let mut maps = self.inner.lock().expect("session store lock");
        let mut session = match maps.by_token.get(token) {
            None => return Err(ClientErrorCode::Unauthenticated),
            Some(s) if s.expires_at <= now => {
                Self::forget_token(&mut maps, token);
                return Err(ClientErrorCode::SessionExpired);
            }
            Some(s) => s.clone(),
        };
        maps.by_token.remove(token);
        session.expires_at = new_expires_at;
        Self::index_session(&mut maps, new_token.clone(), session.clone());
        Ok((new_token, session))
    }

    /// Revoke a session by token (logout). Idempotent.
    pub fn revoke(&self, token: &str) {
        let mut maps = self.inner.lock().expect("session store lock");
        Self::forget_token(&mut maps, token);
    }

    /// Revoke EVERY token belonging to `session_id`. Idempotent. Used by logout so the session
    /// dies even if a concurrent `refresh` rotated its token in the validate→revoke window (the
    /// rotated token shares the session id and is removed too).
    pub fn revoke_session(&self, session_id: &str) {
        let mut maps = self.inner.lock().expect("session store lock");
        let victims: Vec<String> = maps
            .by_token
            .iter()
            .filter(|(_, s)| s.session_id == session_id)
            .map(|(k, _)| k.clone())
            .collect();
        for token in victims {
            Self::forget_token(&mut maps, &token);
        }
    }

    /// Revoke every session (every token of every session id). Returns how many tokens were removed.
    pub fn revoke_all(&self) -> usize {
        let mut maps = self.inner.lock().expect("session store lock");
        let n = maps.by_token.len();
        maps.by_token.clear();
        maps.by_digest.clear();
        n
    }

    /// Live session count (test/introspection helper).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("session store lock")
            .by_token
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sess(id: &str, exp: u64) -> ClientSession {
        ClientSession {
            session_id: id.into(),
            principal: Principal::operator("op"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: exp,
        }
    }

    fn digest_of(store: &SessionStore, id: &str) -> [u8; 32] {
        let d = session_digest(id);
        assert!(store.is_live_digest(&d, 0) || store.get_valid_by_session_digest(&d, 0).is_err());
        d
    }

    fn linear_live(store: &SessionStore, digest: &[u8; 32], now: u64) -> bool {
        let maps = store.inner.lock().expect("lock");
        maps.by_token
            .values()
            .any(|s| s.expires_at > now && session_digest(&s.session_id) == *digest)
    }

    #[test]
    fn session_digest_index_consistent() {
        let store = SessionStore::new(2);
        store.insert("tok-a".into(), sess("sess-a", 100), 0);
        store.insert("tok-b".into(), sess("sess-b", 200), 0);
        let da = digest_of(&store, "sess-a");
        let db = digest_of(&store, "sess-b");
        assert!(store.is_live_digest(&da, 0));
        assert!(store.is_live_digest(&db, 0));
        assert_eq!(linear_live(&store, &da, 0), store.is_live_digest(&da, 0));

        let (new_tok, _) = store.refresh("tok-a", 0, 150, "tok-a2".into()).unwrap();
        assert_eq!(new_tok, "tok-a2");
        assert!(store.is_live_digest(&da, 0), "refresh keeps the digest");
        assert!(store.get_valid("tok-a", 0).is_err());
        assert_eq!(linear_live(&store, &da, 0), store.is_live_digest(&da, 0));

        store.revoke("tok-b");
        assert!(!store.is_live_digest(&db, 0));
        assert_eq!(linear_live(&store, &db, 0), store.is_live_digest(&db, 0));

        store.insert("tok-c".into(), sess("sess-c", 300), 0);
        store.revoke_session("sess-a");
        assert!(!store.is_live_digest(&da, 0));

        store.insert("tok-d".into(), sess("sess-d", 10), 0);
        assert!(store
            .get_valid_by_session_digest(&session_digest("sess-d"), 10)
            .is_err());
        assert!(!store.is_live_digest(&session_digest("sess-d"), 10));

        store.insert("tok-e".into(), sess("sess-e", 400), 0);
        store.insert("tok-f".into(), sess("sess-f", 500), 0);
        // cap 2: inserting a third evicts the soonest-to-expire
        assert_eq!(store.len(), 2);

        store.revoke_all();
        assert_eq!(store.len(), 0);
        assert!(!store.is_live_digest(&session_digest("sess-e"), 0));
        assert!(!store.is_live_digest(&session_digest("sess-f"), 0));
    }
}
