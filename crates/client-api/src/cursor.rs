//! CONTRACT-191 opaque authenticated event IDs and stream cursors.
//!
//! `last_event_id` / delivered `event_id` are AES-256-GCM sealed tokens (never raw Event ids).
//! Typed seal payloads: tag `0x01` empty-join watermark, tag `0x02` raw id body.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{TimeZone, Utc};
use zeroize::Zeroizing;

use crate::envelope::{ClientError, ClientErrorCode, API_VERSION};

/// Empty-join watermark plaintext body (tag `0x01`).
pub const EMPTY_JOIN_WATERMARK_BODY: &str = "advance/client-event-empty-join/v1";
/// Typed seal tag: empty-join watermark.
pub const SEAL_TAG_EMPTY_JOIN: u8 = 0x01;
/// Typed seal tag: raw event id (ReadCursor body).
pub const SEAL_TAG_RAW_ID: u8 = 0x02;
/// Typed seal tag: tee T2 delta cursor body `{stream_key, seq}` (both-or-neither).
pub const SEAL_TAG_DELTA_CURSOR: u8 = 0x03;

const TOKEN_VERSION: &str = "c1";
const AAD_DOMAIN_CURSOR: &str = "advance/client-event-cursor";
const AAD_DOMAIN_EVENT_ID: &str = "advance/client-event-id";
/// Independent delta-cursor AAD domain (precedent `STREAM_FP_DOMAIN`): event cursors and delta
/// cursors are mutually non-replayable — a token sealed under one domain cannot open under the
/// other, whatever its tag.
const AAD_DOMAIN_DELTA_CURSOR: &str = "advance/client-llm-delta-cursor";
/// Max sealed `stream_key` length inside a delta-cursor body.
const MAX_DELTA_STREAM_KEY_LEN: usize = 256;
const MAX_CURSOR_KEYS: usize = 4;
const MAX_SEALS_PER_KEY: u64 = 4_294_967_295;
const MAX_TOKEN_LEN: usize = 512;
const MAX_RAW_ID_LEN: usize = 256;
const FUTURE_SKEW_MS: u64 = 5 * 60 * 1000;

/// Seal purpose selects the AAD domain so event-id tokens cannot open as stream cursors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealPurpose {
    /// Stream/history page cursor (`last_event_id`).
    Cursor,
    /// Delivered `ClientEvent.event_id`.
    EventId,
    /// Tee T2 LLM delta reconnect cursor (`{stream_key, seq}`, both-or-neither).
    DeltaCursor,
}

/// Opened seal body after AEAD auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenedSeal {
    /// Authenticated empty-join watermark → `resume(None)`.
    EmptyJoin,
    /// Raw CONTRACT-185 event id (0..=256 UTF-8 bytes).
    RawId(String),
    /// Tee T2 delta cursor: the sealed body carries BOTH fields (both-or-neither — the body
    /// encoding is structurally complete or the open rejects; no half state exists).
    DeltaCursor { stream_key: String, seq: u64 },
}

/// Injectable wall clock (milliseconds since Unix epoch).
pub trait CursorClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// System wall clock for production/composition.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCursorClock;

impl CursorClock for SystemCursorClock {
    fn now_ms(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Injectable 12-byte nonce source.
pub trait CursorEntropy: Send + Sync {
    fn fill_nonce(&self, out: &mut [u8; 12]) -> Result<(), ClientError>;
}

/// OS CSPRNG entropy (production).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsCursorEntropy;

impl CursorEntropy for OsCursorEntropy {
    fn fill_nonce(&self, out: &mut [u8; 12]) -> Result<(), ClientError> {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(out);
        Ok(())
    }
}

/// One keyring entry.
#[derive(Clone)]
pub struct CursorKeyEntry {
    pub key_id: String,
    pub key_bytes: Zeroizing<[u8; 32]>,
    pub active: bool,
    pub activated_ms: u64,
    pub retired_ms: Option<u64>,
    pub last_sealed_ms: u64,
    pub seals_used: u64,
}

/// Immutable generation-tagged keyring snapshot.
#[derive(Clone)]
pub struct CursorKeyring {
    pub generation: u64,
    pub keys: Vec<CursorKeyEntry>,
}

/// Durable key custody protocol (Wave-25 production; in-memory for tests).
pub trait CursorKeyCustody: Send + Sync {
    fn keyring(&self) -> CursorKeyring;
    fn reserve_seal(
        &self,
        key_id: &str,
        issued_at_ms: u64,
        retention_days: u32,
    ) -> Result<(), ClientError>;
    fn replace_keyring(
        &self,
        expected_generation: u64,
        replacement: CursorKeyring,
        now_ms: u64,
        retention_days: u32,
    ) -> Result<(), ClientError>;
}

/// Codec port: seal / open authenticated tokens.
pub trait ClientCursorCodec: Send + Sync {
    fn seal(
        &self,
        purpose: SealPurpose,
        stream_id: &str,
        tag: u8,
        body: &[u8],
    ) -> Result<String, ClientError>;
    fn open(
        &self,
        purpose: SealPurpose,
        stream_id: &str,
        token: &str,
    ) -> Result<OpenedSeal, ClientError>;
}

/// AES-256-GCM cursor codec. `retention_days` is snapshotted at construction (never re-queried).
pub struct AeadClientCursorCodec {
    custody: Arc<dyn CursorKeyCustody>,
    clock: Arc<dyn CursorClock>,
    entropy: Arc<dyn CursorEntropy>,
    retention_days: u32,
}

impl AeadClientCursorCodec {
    pub fn new(
        custody: Arc<dyn CursorKeyCustody>,
        clock: Arc<dyn CursorClock>,
        entropy: Arc<dyn CursorEntropy>,
        retention_days: u32,
    ) -> Self {
        Self {
            custody,
            clock,
            entropy,
            retention_days,
        }
    }

    fn err_not_found() -> ClientError {
        ClientError::new(ClientErrorCode::NotFound, "event cursor not found")
    }

    fn err_unavailable() -> ClientError {
        ClientError::new(
            ClientErrorCode::ModuleUnavailable,
            "event cursor unavailable",
        )
    }

    fn aad_domain(purpose: SealPurpose) -> &'static str {
        match purpose {
            SealPurpose::Cursor => AAD_DOMAIN_CURSOR,
            SealPurpose::EventId => AAD_DOMAIN_EVENT_ID,
            SealPurpose::DeltaCursor => AAD_DOMAIN_DELTA_CURSOR,
        }
    }

    fn build_aad(
        purpose: SealPurpose,
        key_id: &str,
        issued_at_ms: u64,
        stream_id: &str,
    ) -> Vec<u8> {
        let mut aad = Vec::new();
        push_lp(&mut aad, Self::aad_domain(purpose).as_bytes());
        push_lp(&mut aad, TOKEN_VERSION.as_bytes());
        push_lp(&mut aad, API_VERSION.as_bytes());
        push_lp(&mut aad, key_id.as_bytes());
        aad.extend_from_slice(&issued_at_ms.to_be_bytes());
        push_lp(&mut aad, stream_id.as_bytes());
        aad
    }

    fn validate_key_id(id: &str) -> bool {
        let b = id.as_bytes();
        if b.is_empty() || b.len() > 32 {
            return false;
        }
        let first = b[0];
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return false;
        }
        b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
    }

    fn parse_token(token: &str) -> Result<(&str, &str, &str), ClientError> {
        if token.is_empty() || token.len() > MAX_TOKEN_LEN || !token.is_ascii() {
            return Err(Self::err_not_found());
        }
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Self::err_not_found());
        }
        let (ver, key_id, payload_b64) = (parts[0], parts[1], parts[2]);
        if ver != TOKEN_VERSION || key_id.is_empty() || payload_b64.is_empty() {
            return Err(Self::err_not_found());
        }
        if !Self::validate_key_id(key_id) {
            return Err(Self::err_not_found());
        }
        Ok((ver, key_id, payload_b64))
    }

    fn token_in_retention(&self, issued_at_ms: u64, now_ms: u64) -> bool {
        if issued_at_ms > now_ms.saturating_add(FUTURE_SKEW_MS) {
            return false;
        }
        if self.retention_days == 0 {
            return true;
        }
        let Some(issue_date) = ms_to_utc_date(issued_at_ms) else {
            return false;
        };
        let Some(today) = ms_to_utc_date(now_ms) else {
            return false;
        };
        let cutoff = today - chrono::Duration::days(self.retention_days as i64);
        issue_date >= cutoff
    }
}

impl ClientCursorCodec for AeadClientCursorCodec {
    fn seal(
        &self,
        purpose: SealPurpose,
        stream_id: &str,
        tag: u8,
        body: &[u8],
    ) -> Result<String, ClientError> {
        if tag != SEAL_TAG_EMPTY_JOIN && tag != SEAL_TAG_RAW_ID && tag != SEAL_TAG_DELTA_CURSOR {
            return Err(Self::err_unavailable());
        }
        // Purpose↔tag consistency: the delta tag seals ONLY under the delta purpose and vice
        // versa (belt-and-braces on top of the AAD domain split).
        if (tag == SEAL_TAG_DELTA_CURSOR) != (purpose == SealPurpose::DeltaCursor) {
            return Err(Self::err_unavailable());
        }
        if tag == SEAL_TAG_RAW_ID && body.len() > MAX_RAW_ID_LEN {
            return Err(Self::err_unavailable());
        }
        if tag == SEAL_TAG_EMPTY_JOIN && body != EMPTY_JOIN_WATERMARK_BODY.as_bytes() {
            return Err(Self::err_unavailable());
        }
        if tag == SEAL_TAG_DELTA_CURSOR {
            // Body must be the structurally complete both-or-neither encoding.
            if decode_delta_cursor_body(body).is_none() {
                return Err(Self::err_unavailable());
            }
        } else {
            // Plaintext must be valid UTF-8 for open (raw id / watermark body).
            if std::str::from_utf8(body).is_err() {
                return Err(Self::err_unavailable());
            }
        }

        let now_ms = self.clock.now_ms();
        let ring = self.custody.keyring();
        let active = ring
            .keys
            .iter()
            .find(|k| k.active)
            .ok_or_else(Self::err_unavailable)?;
        let key_id = active.key_id.clone();
        self.custody
            .reserve_seal(&key_id, now_ms, self.retention_days)?;

        // Re-read after reserve (counts may have changed; key material immutable).
        let ring = self.custody.keyring();
        let active = ring
            .keys
            .iter()
            .find(|k| k.active && k.key_id == key_id)
            .ok_or_else(Self::err_unavailable)?;

        let mut plaintext = Vec::with_capacity(1 + body.len());
        plaintext.push(tag);
        plaintext.extend_from_slice(body);

        let mut nonce_bytes = [0u8; 12];
        self.entropy.fill_nonce(&mut nonce_bytes)?;

        let aad = Self::build_aad(purpose, &key_id, now_ms, stream_id);
        let cipher = Aes256Gcm::new_from_slice(active.key_bytes.as_ref())
            .map_err(|_| Self::err_unavailable())?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Self::err_unavailable())?;

        let mut payload = Vec::with_capacity(8 + 12 + ct.len());
        payload.extend_from_slice(&now_ms.to_be_bytes());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ct);
        let b64 = URL_SAFE_NO_PAD.encode(&payload);
        Ok(format!("{TOKEN_VERSION}.{key_id}.{b64}"))
    }

    fn open(
        &self,
        purpose: SealPurpose,
        stream_id: &str,
        token: &str,
    ) -> Result<OpenedSeal, ClientError> {
        let (_ver, key_id, payload_b64) = Self::parse_token(token)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| Self::err_not_found())?;
        // Canonical base64url: re-encode and compare.
        let re = URL_SAFE_NO_PAD.encode(&decoded);
        if re != payload_b64 {
            return Err(Self::err_not_found());
        }
        // issue_time (8) + nonce (12) + ciphertext+tag (≥16)
        if decoded.len() < 8 + 12 + 16 {
            return Err(Self::err_not_found());
        }
        let mut issue_buf = [0u8; 8];
        issue_buf.copy_from_slice(&decoded[0..8]);
        let issued_at_ms = u64::from_be_bytes(issue_buf);
        let nonce_bytes = &decoded[8..20];
        let ct = &decoded[20..];

        let now_ms = self.clock.now_ms();
        if !self.token_in_retention(issued_at_ms, now_ms) {
            return Err(Self::err_not_found());
        }

        let ring = self.custody.keyring();
        let entry = ring
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(Self::err_not_found)?;
        // Key validity window: issue time must be on/after activation; if retired, before retirement.
        if issued_at_ms < entry.activated_ms {
            return Err(Self::err_not_found());
        }
        if let Some(retired) = entry.retired_ms {
            if issued_at_ms >= retired {
                return Err(Self::err_not_found());
            }
        }

        let aad = Self::build_aad(purpose, key_id, issued_at_ms, stream_id);
        let cipher = Aes256Gcm::new_from_slice(entry.key_bytes.as_ref())
            .map_err(|_| Self::err_not_found())?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload { msg: ct, aad: &aad },
            )
            .map_err(|_| Self::err_not_found())?;
        if plaintext.is_empty() {
            return Err(Self::err_not_found());
        }
        let tag = plaintext[0];
        let body = &plaintext[1..];
        match tag {
            SEAL_TAG_EMPTY_JOIN => {
                if purpose == SealPurpose::DeltaCursor {
                    return Err(Self::err_not_found());
                }
                if body != EMPTY_JOIN_WATERMARK_BODY.as_bytes() {
                    return Err(Self::err_not_found());
                }
                Ok(OpenedSeal::EmptyJoin)
            }
            SEAL_TAG_RAW_ID => {
                if purpose == SealPurpose::DeltaCursor {
                    return Err(Self::err_not_found());
                }
                if body.len() > MAX_RAW_ID_LEN {
                    return Err(Self::err_not_found());
                }
                let s = std::str::from_utf8(body).map_err(|_| Self::err_not_found())?;
                Ok(OpenedSeal::RawId(s.to_string()))
            }
            SEAL_TAG_DELTA_CURSOR => {
                // Tag↔purpose guard (the AAD domain split already rejects cross-domain opens;
                // this keeps the guard structural even if a domain ever collided).
                if purpose != SealPurpose::DeltaCursor {
                    return Err(Self::err_not_found());
                }
                let (stream_key, seq) =
                    decode_delta_cursor_body(body).ok_or_else(Self::err_not_found)?;
                Ok(OpenedSeal::DeltaCursor { stream_key, seq })
            }
            _ => Err(Self::err_not_found()),
        }
    }
}

/// Encode the delta-cursor plaintext body: `[u16 BE key_len][stream_key][u64 BE seq]`.
/// Both fields ride one sealed body, so the pair is both-or-neither by construction.
pub(crate) fn encode_delta_cursor_body(stream_key: &str, seq: u64) -> Option<Vec<u8>> {
    let key = stream_key.as_bytes();
    if key.is_empty() || key.len() > MAX_DELTA_STREAM_KEY_LEN {
        return None;
    }
    let mut body = Vec::with_capacity(2 + key.len() + 8);
    body.extend_from_slice(&(key.len() as u16).to_be_bytes());
    body.extend_from_slice(key);
    body.extend_from_slice(&seq.to_be_bytes());
    Some(body)
}

/// Strict decode of the delta-cursor body. Exact-length: any truncation, padding, or
/// half-encoding (one field without the other) fails — the both-or-neither guarantee.
pub(crate) fn decode_delta_cursor_body(body: &[u8]) -> Option<(String, u64)> {
    if body.len() < 2 + 1 + 8 {
        return None;
    }
    let key_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if key_len == 0 || key_len > MAX_DELTA_STREAM_KEY_LEN {
        return None;
    }
    if body.len() != 2 + key_len + 8 {
        return None;
    }
    let key = std::str::from_utf8(&body[2..2 + key_len]).ok()?;
    let mut seq_buf = [0u8; 8];
    seq_buf.copy_from_slice(&body[2 + key_len..]);
    Some((key.to_string(), u64::from_be_bytes(seq_buf)))
}

fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn ms_to_utc_date(ms: u64) -> Option<chrono::NaiveDate> {
    let secs = (ms / 1000) as i64;
    let nsecs = ((ms % 1000) * 1_000_000) as u32;
    Utc.timestamp_opt(secs, nsecs)
        .single()
        .map(|dt| dt.date_naive())
}

// ── In-memory custody (tests + local composition) ─────────────────────────────────────────

/// Test/local in-memory custody implementing the full protocol.
pub struct MemoryCursorKeyCustody {
    inner: Mutex<MemoryCustodyState>,
}

struct MemoryCustodyState {
    generation: u64,
    keys: Vec<CursorKeyEntry>,
    used_ids: HashSet<String>,
}

impl MemoryCursorKeyCustody {
    /// Construct with a single active key.
    pub fn with_active_key(key_id: impl Into<String>, key_bytes: [u8; 32], now_ms: u64) -> Self {
        let key_id = key_id.into();
        assert!(AeadClientCursorCodec::validate_key_id(&key_id));
        let mut used = HashSet::new();
        used.insert(key_id.clone());
        Self {
            inner: Mutex::new(MemoryCustodyState {
                generation: 1,
                keys: vec![CursorKeyEntry {
                    key_id,
                    key_bytes: Zeroizing::new(key_bytes),
                    active: true,
                    activated_ms: now_ms,
                    retired_ms: None,
                    last_sealed_ms: 0,
                    seals_used: 0,
                }],
                used_ids: used,
            }),
        }
    }

    /// Convenience: random 32-byte key material, key id `k1`.
    pub fn new_for_tests() -> Self {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        Self::with_active_key("k1", bytes, 1_700_000_000_000)
    }

    /// Process-lifetime local custody for loopback-only composition. Tokens
    /// fail closed after restart; durable/remote composition must provide a
    /// persisted `CursorKeyCustody` instead.
    pub fn new_local() -> Self {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self::with_active_key("local-k1", bytes, 1_700_000_000_000)
    }
}

impl CursorKeyCustody for MemoryCursorKeyCustody {
    fn keyring(&self) -> CursorKeyring {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        CursorKeyring {
            generation: g.generation,
            keys: g.keys.clone(),
        }
    }

    fn reserve_seal(
        &self,
        key_id: &str,
        issued_at_ms: u64,
        _retention_days: u32,
    ) -> Result<(), ClientError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let active_count = g.keys.iter().filter(|k| k.active).count();
        if active_count != 1 {
            return Err(AeadClientCursorCodec::err_unavailable());
        }
        let key = g
            .keys
            .iter_mut()
            .find(|k| k.key_id == key_id && k.active)
            .ok_or_else(AeadClientCursorCodec::err_unavailable)?;
        if key.seals_used >= MAX_SEALS_PER_KEY {
            return Err(AeadClientCursorCodec::err_unavailable());
        }
        key.seals_used = key.seals_used.saturating_add(1);
        key.last_sealed_ms = key.last_sealed_ms.max(issued_at_ms);
        Ok(())
    }

    fn replace_keyring(
        &self,
        expected_generation: u64,
        replacement: CursorKeyring,
        now_ms: u64,
        retention_days: u32,
    ) -> Result<(), ClientError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.generation != expected_generation {
            return Err(AeadClientCursorCodec::err_unavailable());
        }
        if replacement.generation <= g.generation {
            return Err(AeadClientCursorCodec::err_unavailable());
        }
        if replacement.keys.is_empty() || replacement.keys.len() > MAX_CURSOR_KEYS {
            return Err(AeadClientCursorCodec::err_unavailable());
        }
        let active_n = replacement.keys.iter().filter(|k| k.active).count();
        if active_n != 1 {
            return Err(AeadClientCursorCodec::err_unavailable());
        }
        // Validate IDs + material.
        let mut seen = HashSet::new();
        for k in &replacement.keys {
            if !AeadClientCursorCodec::validate_key_id(&k.key_id) {
                return Err(AeadClientCursorCodec::err_unavailable());
            }
            if !seen.insert(k.key_id.clone()) {
                return Err(AeadClientCursorCodec::err_unavailable());
            }
        }
        // Material immutability for known IDs; tombstones grow-only.
        let old_by_id: HashMap<String, CursorKeyEntry> = g
            .keys
            .iter()
            .map(|k| (k.key_id.clone(), k.clone()))
            .collect();
        for k in &replacement.keys {
            if let Some(old) = old_by_id.get(&k.key_id) {
                if old.key_bytes.as_ref() != k.key_bytes.as_ref() {
                    return Err(AeadClientCursorCodec::err_unavailable());
                }
                if k.seals_used < old.seals_used
                    || k.activated_ms < old.activated_ms
                    || k.last_sealed_ms < old.last_sealed_ms
                {
                    return Err(AeadClientCursorCodec::err_unavailable());
                }
                // Retirement timestamp is grow-only: once set, cannot decrease or clear.
                match (old.retired_ms, k.retired_ms) {
                    (Some(old_r), Some(new_r)) if new_r < old_r => {
                        return Err(AeadClientCursorCodec::err_unavailable());
                    }
                    (Some(_), None) => {
                        return Err(AeadClientCursorCodec::err_unavailable());
                    }
                    _ => {}
                }
                // Retained never becomes active.
                if !old.active && k.active {
                    return Err(AeadClientCursorCodec::err_unavailable());
                }
            } else if g.used_ids.contains(&k.key_id) {
                // Reuse of tombstoned ID forbidden.
                return Err(AeadClientCursorCodec::err_unavailable());
            }
        }
        // Removal only when retention-safe.
        for old in &g.keys {
            if !replacement.keys.iter().any(|k| k.key_id == old.key_id) {
                if retention_days == 0 {
                    return Err(AeadClientCursorCodec::err_unavailable());
                }
                let Some(last_date) = ms_to_utc_date(old.last_sealed_ms) else {
                    return Err(AeadClientCursorCodec::err_unavailable());
                };
                let Some(today) = ms_to_utc_date(now_ms) else {
                    return Err(AeadClientCursorCodec::err_unavailable());
                };
                let cutoff = today - chrono::Duration::days(retention_days as i64);
                // last-sealed UTC date strictly older than cutoff + skew elapsed.
                if last_date >= cutoff {
                    return Err(AeadClientCursorCodec::err_unavailable());
                }
                if now_ms < old.last_sealed_ms.saturating_add(FUTURE_SKEW_MS) {
                    return Err(AeadClientCursorCodec::err_unavailable());
                }
            }
        }
        for k in &replacement.keys {
            g.used_ids.insert(k.key_id.clone());
        }
        g.generation = replacement.generation;
        g.keys = replacement.keys;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// §3.3 T2 unit witnesses U-4 / U-5 (delta-cursor domain + body completeness)
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod delta_cursor_tests {
    use super::*;
    use crate::deltas::{open_delta_cursor, seal_delta_cursor, DELTA_CURSOR_STREAM_DOMAIN};

    struct FixedClock(u64);
    impl CursorClock for FixedClock {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    fn codec() -> AeadClientCursorCodec {
        AeadClientCursorCodec::new(
            Arc::new(MemoryCursorKeyCustody::new_for_tests()),
            Arc::new(FixedClock(1_700_000_100_000)),
            Arc::new(OsCursorEntropy),
            30,
        )
    }

    // ── U-4 cursor codec domain split ────────────────────────────────────
    // Isolating mutation: a shared AAD domain would let an event cursor replay as a delta
    // cursor (and vice versa) — cross-domain opens MUST reject.
    #[test]
    fn u4_domain_split_event_and_delta_cursors_not_interchangeable() {
        let codec = codec();
        // A sealed delta cursor round-trips under its own purpose…
        let token = seal_delta_cursor(&codec, "stream-abc", 42).expect("seal");
        let (key, seq) = open_delta_cursor(&codec, &token).expect("open");
        assert_eq!((key.as_str(), seq), ("stream-abc", 42));
        // …but NEVER opens as an event cursor or event id (independent AAD domain).
        assert!(codec
            .open(SealPurpose::Cursor, DELTA_CURSOR_STREAM_DOMAIN, &token)
            .is_err());
        assert!(codec
            .open(SealPurpose::EventId, DELTA_CURSOR_STREAM_DOMAIN, &token)
            .is_err());
        // An EVENT-domain cursor never opens as a delta cursor.
        let ev = codec
            .seal(SealPurpose::Cursor, "stream-1", SEAL_TAG_RAW_ID, b"ev-9")
            .expect("event seal");
        assert!(open_delta_cursor(&codec, &ev).is_err());
        // Purpose↔tag guards at seal time: the delta tag seals ONLY under the delta purpose.
        let body = encode_delta_cursor_body("stream-abc", 42).unwrap();
        assert!(codec
            .seal(
                SealPurpose::Cursor,
                "stream-1",
                SEAL_TAG_DELTA_CURSOR,
                &body
            )
            .is_err());
        assert!(codec
            .seal(
                SealPurpose::DeltaCursor,
                DELTA_CURSOR_STREAM_DOMAIN,
                SEAL_TAG_RAW_ID,
                b"raw"
            )
            .is_err());
    }

    // ── U-5 body completeness (both-or-neither) ──────────────────────────
    // Isolating mutation: a body carrying only one of {stream_key, seq} (or a truncated /
    // padded encoding) opening successfully would break the both-or-neither pin.
    #[test]
    fn u5_body_both_or_neither() {
        let codec = codec();
        // Structurally strict decode: exact length, no truncation, no padding.
        let body = encode_delta_cursor_body("k", 7).unwrap();
        assert_eq!(decode_delta_cursor_body(&body), Some(("k".to_string(), 7)));
        assert!(
            decode_delta_cursor_body(&body[..body.len() - 1]).is_none(),
            "seq truncated"
        );
        assert!(
            decode_delta_cursor_body(&body[..2]).is_none(),
            "key-only half rejected"
        );
        let mut padded = body.clone();
        padded.push(0);
        assert!(
            decode_delta_cursor_body(&padded).is_none(),
            "trailing bytes rejected"
        );
        // A key-without-seq body (length-prefixed key alone) never seals.
        let mut half = Vec::new();
        half.extend_from_slice(&1u16.to_be_bytes());
        half.push(b'k');
        assert!(codec
            .seal(
                SealPurpose::DeltaCursor,
                DELTA_CURSOR_STREAM_DOMAIN,
                SEAL_TAG_DELTA_CURSOR,
                &half
            )
            .is_err());
        // Tampering any token byte fails the AEAD open (both fields authenticated together).
        let token = seal_delta_cursor(&codec, "stream-abc", 42).unwrap();
        let payload_start = token.rfind('.').unwrap() + 1;
        let mut chars: Vec<char> = token.chars().collect();
        let i = payload_start + 5;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(open_delta_cursor(&codec, &tampered).is_err());
        // Empty / oversized stream keys never encode.
        assert!(encode_delta_cursor_body("", 1).is_none());
        assert!(encode_delta_cursor_body(&"x".repeat(257), 1).is_none());
    }
}
