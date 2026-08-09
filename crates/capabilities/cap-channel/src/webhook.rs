//! Webhook receiver — pure-logic handler for inbound `/hooks/{path}` requests.
//!
//! Slice B intentionally does NOT bind a TCP listener; the runtime's HTTP
//! server (a future transport-binding slice) routes POST /hooks/* to
//! [`WebhookReceiver::handle_request`]. Integration tests drive the handler
//! directly via the same API surface.
//!
//! HMAC-SHA256 verification per MODULE-016 §2.11 (HMAC algo: HMAC-SHA256). The
//! length-cap (default 1 MB) runs BEFORE HMAC compute to prevent CPU/allocation
//! DoS on oversized bodies — see §2.7 webhook flow.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::ChannelError;
use crate::subscription::{SecretBytes, SubscriptionManager};
use crate::types::{CapParam, RawEvent, SubscriptionId};

/// Default max inbound webhook body size (1 MB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

/// Max webhook path length. The handler rejects requests with longer paths
/// BEFORE hashing them against the `path_map` to prevent O(N)-hash CPU DoS
/// (Adversarial Eval R17 #3). 1024 bytes is generous — webhook URL paths in
/// real adapters fit comfortably (e.g., `/hooks/github-pr-12345`).
pub const MAX_WEBHOOK_PATH_BYTES: usize = 1024;

/// Max number of distinct `/hooks/{path}` entries the receiver will register.
/// Bounds `path_map` size to prevent unbounded growth from buggy or hostile
/// boot-time configuration (Adversarial Eval R19 #3).
pub const MAX_PATH_MAP_ENTRIES: usize = 4096;

/// Max number of HTTP headers cap-channel will scan per inbound request.
/// `find_header` is O(N) per lookup; the handler performs up to 4 lookups
/// (signature header + 3 sender_id precedence rungs). Without this cap, an
/// attacker who reaches the request handler can drive O(M·N) comparisons
/// where M=4 and N=attacker-controlled header count. Adversarial Eval R19 #5.
pub const MAX_HEADERS_PER_REQUEST: usize = 64;

/// Bound on the `User-Agent` header rung of the sender_id precedence chain to
/// keep `channel.sender_id` strings tractable in downstream logs / queries.
const USER_AGENT_SENDER_ID_MAX: usize = 64;

/// Webhook handler response — status code + optional body. The transport-binding
/// slice maps these onto wire HTTP responses.
#[derive(Debug, PartialEq, Eq)]
pub struct WebhookResponse {
    pub status: u16,
    pub body: &'static str,
}

impl WebhookResponse {
    pub const OK: Self = Self {
        status: 200,
        body: "ok",
    };
    pub const UNAUTHORIZED: Self = Self {
        status: 401,
        body: "unauthorized",
    };
    pub const NOT_FOUND: Self = Self {
        status: 404,
        body: "not found",
    };
    /// Phase-2 Step-3 — a channel verifier rejected the payload as unparseable
    /// / missing required fields (`Reject::BadRequest`).
    pub const BAD_REQUEST: Self = Self {
        status: 400,
        body: "bad request",
    };
    pub const PAYLOAD_TOO_LARGE: Self = Self {
        status: 413,
        body: "payload too large",
    };
    pub const SERVICE_UNAVAILABLE: Self = Self {
        status: 503,
        body: "service unavailable",
    };
}

/// Pure-logic webhook handler. Owns:
/// - reference to the shared `SubscriptionManager` (for enqueue),
/// - per-path → subscription routing table,
/// - max body size cap.
pub struct WebhookReceiver {
    manager: Arc<SubscriptionManager>,
    path_map: RwLock<HashMap<String, SubscriptionId>>,
    max_body_bytes: usize,
}

impl WebhookReceiver {
    pub fn new(manager: Arc<SubscriptionManager>) -> Self {
        Self {
            manager,
            path_map: RwLock::new(HashMap::new()),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    pub fn with_max_body_bytes(mut self, max: usize) -> Self {
        self.max_body_bytes = max;
        self
    }

    /// Bind `/hooks/{path}` to a subscription. Idempotent for an already-
    /// registered path (overwrite). Rejects with `InvalidConfig` if:
    /// - `path.len() > MAX_WEBHOOK_PATH_BYTES` (avoids storing oversized keys)
    /// - the map already has `MAX_PATH_MAP_ENTRIES` distinct paths
    ///   (DoS defense — Adversarial Eval R19 #3).
    pub fn register_path(
        &self,
        path: impl Into<String>,
        sub_id: SubscriptionId,
    ) -> Result<(), ChannelError> {
        let path: String = path.into();
        if path.len() > MAX_WEBHOOK_PATH_BYTES {
            return Err(ChannelError::InvalidConfig(format!(
                "webhook path exceeds {MAX_WEBHOOK_PATH_BYTES} bytes"
            )));
        }
        let mut map = self.path_map.write().unwrap_or_else(|e| e.into_inner());
        // Overwriting an existing path is allowed (no entry growth).
        if !map.contains_key(&path) && map.len() >= MAX_PATH_MAP_ENTRIES {
            return Err(ChannelError::InvalidConfig(format!(
                "path_map at cap ({MAX_PATH_MAP_ENTRIES})"
            )));
        }
        map.insert(path, sub_id);
        Ok(())
    }

    /// Handle an inbound POST /hooks/{path}. Performs the §2.7 webhook flow
    /// in this exact order:
    /// 1. path lookup → 404 on miss
    /// 2. body length-cap (BEFORE HMAC compute — DoS defense) → 413 on overflow
    /// 3. pull signature header → 401 on miss/malformed
    /// 4. pull subscription's webhook secret → 401 on miss
    /// 5. HMAC-SHA256 + constant-time compare → 401 on mismatch
    /// 6. build RawEvent + 5 `channel.*` provenance keys
    /// 7. enqueue (buffer-cap aware) → 503 on overflow, 200 otherwise
    ///
    /// Returns [`WebhookResponse`] for the runtime's HTTP server to emit on
    /// the wire.
    pub fn handle_request(
        &self,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> WebhookResponse {
        // Step 0a: path length cap (DoS defense — Adversarial Eval R17 #3).
        // Rejecting BEFORE the HashMap lookup avoids the O(N) hash cost on
        // attacker-supplied multi-megabyte path strings.
        if path.len() > MAX_WEBHOOK_PATH_BYTES {
            return WebhookResponse::NOT_FOUND;
        }

        // Step 0b: header count cap (DoS defense — Adversarial Eval R19 #5).
        // The handler performs up to 4 linear header scans; bounding the
        // header count keeps the worst-case CPU cost predictable.
        if headers.len() > MAX_HEADERS_PER_REQUEST {
            return WebhookResponse::PAYLOAD_TOO_LARGE;
        }

        // Step 1: path lookup.
        let sub_id = match self.lookup_path(path) {
            Some(id) => id,
            None => return WebhookResponse::NOT_FOUND,
        };

        // Step 2: length cap BEFORE HMAC compute (DoS defense — HMACing an
        // unbounded body before length-checking lets an attacker force CPU
        // + allocation on multi-MB payloads).
        if body.len() > self.max_body_bytes {
            return WebhookResponse::PAYLOAD_TOO_LARGE;
        }

        // Step 3: pull signature header.
        let signature_hex = match find_header(headers, "X-Signature-256") {
            Some(v) => v,
            None => return WebhookResponse::UNAUTHORIZED,
        };
        let expected_hex = match parse_sha256_signature(&signature_hex) {
            Some(s) => s,
            None => return WebhookResponse::UNAUTHORIZED,
        };

        // Step 4: pull subscription + its webhook secret.
        let sub = match self.manager.lookup(&sub_id) {
            Some(s) => s,
            None => return WebhookResponse::NOT_FOUND,
        };

        // Step 5: HMAC-SHA256(secret, body), constant-time compare. Done
        // under the secret's read-lock guard via `with_webhook_secret`.
        let verified = sub.with_webhook_secret(|maybe_secret| match maybe_secret {
            Some(secret) => verify_hmac_sha256(secret, body, &expected_hex),
            None => false,
        });
        if !verified {
            return WebhookResponse::UNAUTHORIZED;
        }

        // Step 6: build RawEvent + 5 channel.* provenance keys.
        let raw_event = build_raw_event(path, headers, body, &sub_id);

        // Step 7: enqueue (buffer-cap aware).
        match self.manager.enqueue_event(&sub_id, raw_event) {
            Ok(()) => WebhookResponse::OK,
            Err(ChannelError::BufferOverflow(_)) => WebhookResponse::SERVICE_UNAVAILABLE,
            Err(_) => WebhookResponse::NOT_FOUND,
        }
    }

    fn lookup_path(&self, path: &str) -> Option<SubscriptionId> {
        let map = self.path_map.read().unwrap_or_else(|e| e.into_inner());
        map.get(path).cloned()
    }
}

/// Find a header value case-insensitively.
fn find_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Parse a header value of the form `sha256=<hex>`. Returns the hex portion as
/// a `Vec<u8>` (decoded). Returns `None` if the prefix is missing or the hex is
/// malformed.
fn parse_sha256_signature(header_value: &str) -> Option<Vec<u8>> {
    let hex_part = header_value.strip_prefix("sha256=")?;
    decode_hex(hex_part)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Compute HMAC-SHA256(secret, body) and constant-time-compare against the
/// expected tag.
fn verify_hmac_sha256(secret: &SecretBytes, body: &[u8], expected_tag: &[u8]) -> bool {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(secret.expose_secret_bytes()).expect("HMAC key length OK");
    mac.update(body);
    let computed = mac.finalize().into_bytes();
    // Constant-time compare. `ct_eq` returns a `Choice` (0 or 1); convert to
    // bool. Length mismatch short-circuits to false BEFORE the ct_eq call —
    // length is non-secret (HMAC-SHA256 tags are always 32 bytes).
    if computed.len() != expected_tag.len() {
        return false;
    }
    computed.as_slice().ct_eq(expected_tag).into()
}

/// Build the `RawEvent` payload + 5 required `channel.*` provenance keys per
/// MODULE-016 §2.5. The `channel.sender_id` value is derived per the
/// precedence chain in MODULE-016 §2.7 (X-Hub-Signature-Key-Id →
/// X-GitHub-Hook-Installation-Target-ID → User-Agent → `webhook:{path}`
/// fallback).
fn build_raw_event(
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    sub_id: &SubscriptionId,
) -> RawEvent {
    let sender_id = derive_sender_id(path, headers);
    let timestamp = current_unix_timestamp();
    let metadata = vec![
        CapParam::new("channel.adapter", "webhook"),
        CapParam::new("channel.subscription_id", sub_id.as_str()),
        CapParam::new("channel.sender_id", sender_id),
        CapParam::new("channel.conversation_id", path),
        CapParam::new("channel.timestamp", timestamp.to_string()),
    ];
    RawEvent {
        data: body.to_vec(),
        metadata,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Phase-2 Step-3 — channel-specific inbound verifier (ADR L1)
// ════════════════════════════════════════════════════════════════════════════

/// Why a channel-specific inbound verifier rejected a request. Maps to an HTTP
/// status at the transport boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Authentication failed (secret-token / signature mismatch) → 401.
    Unauthorized,
    /// The payload could not be parsed / lacks required fields → 400.
    BadRequest,
}

impl Reject {
    pub fn http_status(&self) -> u16 {
        match self {
            Reject::Unauthorized => 401,
            Reject::BadRequest => 400,
        }
    }
}

/// The normalized result of channel-specific inbound parsing (ADR L1). The
/// generic HMAC `WebhookReceiver` is reusable HMAC infrastructure but is NOT
/// itself sufficient normalization — a generic verifier cannot know a Telegram
/// `chat_id` without parsing the channel's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundOutcome {
    /// Channel-native sender id (e.g. Telegram `message.from.id`).
    pub sender_id: String,
    /// The REAL channel/thread id (e.g. Telegram `message.chat.id`) — NOT the
    /// webhook path. Becomes `channel.conversation_id`.
    pub conversation_id: String,
    /// Reply-target tokens (the `channel.reply_address.*` family), one per
    /// entry — e.g. `[("chat_id", "<id>")]`. A `Vec<(String,String)>` bag so
    /// multi-token channels are additive.
    pub reply_address: Vec<(String, String)>,
    /// A content-dependent synchronous handshake body (Slack `url_verification`,
    /// Discord PING→PONG). `None` for Telegram. Deferred handshake channels need
    /// `WebhookResponse` to gain an arbitrary-body variant.
    pub ack: Option<Vec<u8>>,
    /// Opaque passthrough metadata keys (non-`channel.*`).
    pub extra: Vec<(String, String)>,
    /// The message's own time (epoch seconds) when the verifier can parse it
    /// (e.g. Telegram `message.date`); `None` → fall back to HTTP receipt time.
    pub timestamp: Option<u64>,
}

/// Channel-specific inbound verify + extract (ADR L1). The first impl is
/// [`TelegramVerifier`]. This is channel-specific payload parsing, NOT generic
/// verification.
pub trait InboundVerifier: Send + Sync {
    fn process(&self, headers: &[(String, String)], body: &[u8]) -> Result<InboundOutcome, Reject>;
}

/// Telegram inbound verifier — secret-token header check + Telegram update JSON
/// extraction (`message.chat.id` → conversation_id, `message.from.id` →
/// sender_id, `message.date` → timestamp). The `X-Telegram-Bot-Api-Secret-Token`
/// scheme (NOT HMAC) is Telegram's webhook authentication.
pub struct TelegramVerifier {
    secret_token: String,
}

impl TelegramVerifier {
    pub fn new(secret_token: impl Into<String>) -> Self {
        Self {
            secret_token: secret_token.into(),
        }
    }
}

impl InboundVerifier for TelegramVerifier {
    fn process(&self, headers: &[(String, String)], body: &[u8]) -> Result<InboundOutcome, Reject> {
        // 1. Secret-token header check (constant-time over equal length).
        let provided = find_header(headers, "X-Telegram-Bot-Api-Secret-Token").unwrap_or_default();
        if !secret_token_matches(provided.as_bytes(), self.secret_token.as_bytes()) {
            return Err(Reject::Unauthorized);
        }
        // 2. Parse the Telegram update JSON and extract the routing fields.
        let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| Reject::BadRequest)?;
        let msg = v.get("message").ok_or(Reject::BadRequest)?;
        let chat_id = msg
            .get("chat")
            .and_then(|c| c.get("id"))
            .and_then(json_id_to_string)
            .ok_or(Reject::BadRequest)?;
        let from_id = msg
            .get("from")
            .and_then(|f| f.get("id"))
            .and_then(json_id_to_string)
            .ok_or(Reject::BadRequest)?;
        let date = msg.get("date").and_then(|d| d.as_u64());
        Ok(InboundOutcome {
            sender_id: from_id,
            conversation_id: chat_id.clone(),
            reply_address: vec![("chat_id".to_string(), chat_id)],
            ack: None,
            extra: vec![],
            timestamp: date,
        })
    }
}

/// Constant-time secret-token comparison (length check first; the length of a
/// configured secret is not itself secret).
///
/// **Fail-closed (audit r1 Critical):** an EMPTY `provided` (missing/blank
/// `X-Telegram-Bot-Api-Secret-Token` header) OR an EMPTY `expected` (a
/// misconfigured `secret: ""`) is rejected outright — otherwise an empty
/// configured secret + a missing header would compare `"" == ""` → authenticate,
/// silently disabling webhook authentication.
fn secret_token_matches(provided: &[u8], expected: &[u8]) -> bool {
    if provided.is_empty() || expected.is_empty() {
        return false;
    }
    if provided.len() != expected.len() {
        return false;
    }
    provided.ct_eq(expected).into()
}

/// Telegram ids are JSON integers (chat ids can be negative for groups). Accept
/// a number or a string id.
fn json_id_to_string(v: &serde_json::Value) -> Option<String> {
    if let Some(n) = v.as_i64() {
        return Some(n.to_string());
    }
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    None
}

/// Build the normalized [`RawEvent`] from a channel-specific [`InboundOutcome`]
/// (ADR L2 — the Step-3 channel path). Stamps the REAL `channel.conversation_id`
/// (NOT the webhook path) + the `channel.reply_address.*` key family + the
/// message-time `channel.timestamp` (epoch seconds). The generic-HMAC
/// `build_raw_event(path, …)` is UNCHANGED (GitHub-style notifications keep
/// path-as-conversation_id).
pub fn build_raw_event_from_outcome(
    adapter: &str,
    body: &[u8],
    outcome: &InboundOutcome,
    sub_id: &SubscriptionId,
) -> RawEvent {
    let timestamp = outcome.timestamp.unwrap_or_else(current_unix_timestamp);
    let mut metadata = vec![
        CapParam::new("channel.adapter", adapter),
        CapParam::new("channel.subscription_id", sub_id.as_str()),
        CapParam::new("channel.sender_id", outcome.sender_id.clone()),
        // The FIX: real channel/thread id from the verifier, not the webhook path.
        CapParam::new("channel.conversation_id", outcome.conversation_id.clone()),
        CapParam::new("channel.timestamp", timestamp.to_string()),
    ];
    // channel.reply_address.* family — one flat entry per token (lossless).
    for (k, val) in &outcome.reply_address {
        metadata.push(CapParam::new(
            format!("channel.reply_address.{k}"),
            val.clone(),
        ));
    }
    // Opaque passthrough keys.
    for (k, val) in &outcome.extra {
        metadata.push(CapParam::new(k.clone(), val.clone()));
    }
    RawEvent {
        data: body.to_vec(),
        metadata,
    }
}

/// Derive `channel.sender_id` per the §2.7 precedence chain.
fn derive_sender_id(path: &str, headers: &[(String, String)]) -> String {
    if let Some(v) = find_header(headers, "X-Hub-Signature-Key-Id") {
        if !v.is_empty() {
            return v;
        }
    }
    if let Some(v) = find_header(headers, "X-GitHub-Hook-Installation-Target-ID") {
        if !v.is_empty() {
            return v;
        }
    }
    if let Some(v) = find_header(headers, "User-Agent") {
        if !v.is_empty() {
            return truncate_at_char_boundary(&v, USER_AGENT_SENDER_ID_MAX);
        }
    }
    format!("webhook:{path}")
}

/// Truncate `s` to at most `max_bytes` bytes without splitting a UTF-8
/// multi-byte sequence. Walks the char boundaries and returns the longest
/// prefix whose byte length is ≤ `max_bytes`.
///
/// Rationale: `String::truncate(n)` panics if `n` is not a char boundary.
/// On an attacker-supplied `User-Agent` header where byte 64 falls inside
/// a multi-byte sequence (e.g., 63 ASCII bytes + 4-byte char), naive
/// truncation aborts the request worker. This helper truncates safely.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Walk char_indices to find the largest index <= max_bytes that is a
    // char boundary. char_indices yields the start byte of each char; the
    // last boundary <= max_bytes is the safe truncation point.
    let cutoff = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max_bytes)
        .last()
        .unwrap_or(0);
    s[..cutoff].to_string()
}

/// Current Unix epoch as seconds. Falls back to 0 on the (impossible-in-prod)
/// case where the system clock is before the epoch.
fn current_unix_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::subscription::SubscriptionManager;
    use crate::types::{AdapterType, ChannelConfig};

    fn webhook_config() -> ChannelConfig {
        ChannelConfig {
            adapter_type: AdapterType::Webhook,
            params: vec![],
            outbound: None,
        }
    }

    /// 16-byte minimum secret per `MIN_WEBHOOK_SECRET_BYTES`; padded with
    /// repeat bytes for tests.
    const TEST_SECRET: &[u8] = b"hunter2-padding!"; // 16 bytes exactly.

    fn setup() -> (Arc<SubscriptionManager>, WebhookReceiver, SubscriptionId) {
        let mgr = Arc::new(SubscriptionManager::new());
        let id = mgr.subscribe("test-agent", webhook_config()).unwrap();
        mgr.set_webhook_secret(&id, SecretBytes::new(TEST_SECRET.to_vec()).unwrap())
            .unwrap();
        let recv = WebhookReceiver::new(mgr.clone());
        recv.register_path("github", id.clone()).unwrap();
        (mgr, recv, id)
    }

    fn hmac_sig(secret: &[u8], body: &[u8]) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        format!("sha256={}", hex_encode(&bytes))
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(nibble(b >> 4));
            out.push(nibble(b & 0xf));
        }
        out
    }

    fn nibble(n: u8) -> char {
        if n < 10 {
            (b'0' + n) as char
        } else {
            (b'a' + n - 10) as char
        }
    }

    #[test]
    fn happy_path_returns_200_and_enqueues() {
        let (mgr, recv, id) = setup();
        let body = b"{\"event\":\"push\"}";
        let sig = hmac_sig(TEST_SECRET, body);
        let headers = vec![("X-Signature-256".into(), sig)];
        let response = recv.handle_request("github", &headers, body);
        assert_eq!(response, WebhookResponse::OK);
        let event = mgr.poll_raw("test-agent", &id).unwrap().unwrap();
        assert_eq!(event.data, body);
    }

    #[test]
    fn unknown_path_returns_404() {
        let (_mgr, recv, _id) = setup();
        let response = recv.handle_request("does-not-exist", &[], b"");
        assert_eq!(response, WebhookResponse::NOT_FOUND);
    }

    #[test]
    fn oversize_path_returns_404_before_hashmap_lookup() {
        let (_mgr, recv, _id) = setup();
        // Path exceeds MAX_WEBHOOK_PATH_BYTES; the handler must reject BEFORE
        // hashing the path against path_map (CPU DoS defense).
        let huge_path = "x".repeat(MAX_WEBHOOK_PATH_BYTES + 1);
        let response = recv.handle_request(&huge_path, &[], b"");
        assert_eq!(response, WebhookResponse::NOT_FOUND);
    }

    #[test]
    fn missing_signature_returns_401() {
        let (_mgr, recv, _id) = setup();
        let response = recv.handle_request("github", &[], b"body");
        assert_eq!(response, WebhookResponse::UNAUTHORIZED);
    }

    #[test]
    fn malformed_signature_returns_401() {
        let (_mgr, recv, _id) = setup();
        let headers = vec![("X-Signature-256".into(), "wrongformat".into())];
        let response = recv.handle_request("github", &headers, b"body");
        assert_eq!(response, WebhookResponse::UNAUTHORIZED);
    }

    #[test]
    fn bad_hmac_returns_401() {
        let (_mgr, recv, _id) = setup();
        let sig = hmac_sig(b"wrong-key", b"body");
        let headers = vec![("X-Signature-256".into(), sig)];
        let response = recv.handle_request("github", &headers, b"body");
        assert_eq!(response, WebhookResponse::UNAUTHORIZED);
    }

    #[test]
    fn missing_secret_returns_401() {
        let mgr = Arc::new(SubscriptionManager::new());
        let id = mgr.subscribe("test-agent", webhook_config()).unwrap();
        // Do NOT attach a secret.
        let recv = WebhookReceiver::new(mgr);
        recv.register_path("github", id).unwrap();
        let sig = hmac_sig(TEST_SECRET, b"body");
        let headers = vec![("X-Signature-256".into(), sig)];
        let response = recv.handle_request("github", &headers, b"body");
        assert_eq!(response, WebhookResponse::UNAUTHORIZED);
    }

    #[test]
    fn body_over_max_returns_413_before_hmac_check() {
        let (_mgr, recv, _id) = setup();
        let recv = recv.with_max_body_bytes(10);
        let body = vec![0u8; 100];
        // No HMAC header at all — proves length check runs first (if HMAC
        // ran first, would return 401).
        let response = recv.handle_request("github", &[], &body);
        assert_eq!(response, WebhookResponse::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn case_insensitive_header_lookup() {
        let (_mgr, recv, _id) = setup();
        let body = b"x";
        let sig = hmac_sig(TEST_SECRET, body);
        let headers = vec![("x-signature-256".into(), sig)];
        let response = recv.handle_request("github", &headers, body);
        assert_eq!(response, WebhookResponse::OK);
    }

    #[test]
    fn buffer_overflow_returns_503() {
        let (mgr, recv, id) = setup();
        // Fill the buffer to cap via the bounded public push path.
        for _ in 0..crate::subscription::DEFAULT_BUFFER_CAP {
            mgr.enqueue_event(
                &id,
                RawEvent {
                    data: vec![],
                    metadata: vec![],
                },
            )
            .unwrap();
        }
        let body = b"new event";
        let sig = hmac_sig(TEST_SECRET, body);
        let headers = vec![("X-Signature-256".into(), sig)];
        let response = recv.handle_request("github", &headers, body);
        assert_eq!(response, WebhookResponse::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn sender_id_derivation_precedence() {
        // (i) X-Hub-Signature-Key-Id takes precedence.
        let id = derive_sender_id(
            "p",
            &[
                ("X-Hub-Signature-Key-Id".into(), "key-abc".into()),
                (
                    "X-GitHub-Hook-Installation-Target-ID".into(),
                    "tgt-1".into(),
                ),
                ("User-Agent".into(), "ua".into()),
            ],
        );
        assert_eq!(id, "key-abc");

        // (ii) GitHub installation target id wins over User-Agent.
        let id = derive_sender_id(
            "p",
            &[
                (
                    "X-GitHub-Hook-Installation-Target-ID".into(),
                    "tgt-1".into(),
                ),
                ("User-Agent".into(), "ua".into()),
            ],
        );
        assert_eq!(id, "tgt-1");

        // (iii) User-Agent rung.
        let id = derive_sender_id("p", &[("User-Agent".into(), "GitHub-Hookshot".into())]);
        assert_eq!(id, "GitHub-Hookshot");

        // (iii) User-Agent truncates at 64 bytes.
        let long_ua = "x".repeat(100);
        let id = derive_sender_id("p", &[("User-Agent".into(), long_ua)]);
        assert_eq!(id.len(), 64);

        // (iii) User-Agent with multi-byte chars at the byte-64 boundary
        // must NOT panic. 63 ASCII bytes + a 4-byte char would place the
        // boundary inside the multi-byte sequence under naive truncate.
        let utf8_ua = format!("{}{}", "x".repeat(63), "💧"); // 💧 = 4-byte UTF-8
        let id = derive_sender_id("p", &[("User-Agent".into(), utf8_ua)]);
        assert!(id.len() <= 64);
        // Result should be the 63 'x' bytes (the 💧 doesn't fit).
        assert_eq!(id.len(), 63);
        assert!(id.chars().all(|c| c == 'x'));

        // (iv) fallback distinct per path.
        let id_a = derive_sender_id("path-a", &[]);
        let id_b = derive_sender_id("path-b", &[]);
        assert_ne!(id_a, id_b);
        assert!(id_a.starts_with("webhook:"));
        // Never the bare literal "webhook" (which would collapse all events
        // to one synthetic sender, breaking MODULE-006 IdentityResolver's
        // distinct-user promise).
        assert_ne!(id_a, "webhook");
    }

    #[test]
    fn raw_event_carries_five_required_provenance_keys() {
        let (mgr, recv, id) = setup();
        let body = b"payload";
        let sig = hmac_sig(TEST_SECRET, body);
        let headers = vec![
            ("X-Signature-256".into(), sig),
            ("X-Hub-Signature-Key-Id".into(), "key-7".into()),
        ];
        recv.handle_request("github", &headers, body);
        let event = mgr.poll_raw("test-agent", &id).unwrap().unwrap();
        let keys: Vec<_> = event.metadata.iter().map(|p| p.key.as_str()).collect();
        for required in [
            "channel.adapter",
            "channel.subscription_id",
            "channel.sender_id",
            "channel.conversation_id",
            "channel.timestamp",
        ] {
            assert!(
                keys.contains(&required),
                "missing required key {required}, got {keys:?}"
            );
        }
        // sender_id must reflect the key-id, not bare "webhook".
        let sender = event
            .metadata
            .iter()
            .find(|p| p.key == "channel.sender_id")
            .unwrap();
        assert_eq!(sender.value, "key-7");
    }

    // ── Phase-2 Step-3 — TelegramVerifier (T7) ──

    const TG_SECRET: &str = "tg-secret-token-xyz";

    fn tg_update(chat_id: i64, from_id: i64, date: u64, text: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "update_id": 1,
            "message": {
                "message_id": 10,
                "date": date,
                "chat": { "id": chat_id, "type": "private" },
                "from": { "id": from_id, "is_bot": false, "first_name": "U" },
                "text": text,
            }
        }))
        .unwrap()
    }

    #[test]
    fn telegram_verifier_extracts_chat_from_and_date() {
        let v = TelegramVerifier::new(TG_SECRET);
        let headers = vec![(
            "X-Telegram-Bot-Api-Secret-Token".into(),
            TG_SECRET.to_string(),
        )];
        let outcome = v
            .process(&headers, &tg_update(-100200, 4242, 1700000123, "hello"))
            .unwrap();
        assert_eq!(outcome.conversation_id, "-100200"); // group chat ids are negative
        assert_eq!(outcome.sender_id, "4242");
        assert_eq!(outcome.timestamp, Some(1700000123));
        assert_eq!(
            outcome.reply_address,
            vec![("chat_id".to_string(), "-100200".to_string())]
        );
    }

    #[test]
    fn telegram_verifier_rejects_wrong_secret_token() {
        let v = TelegramVerifier::new(TG_SECRET);
        let headers = vec![(
            "X-Telegram-Bot-Api-Secret-Token".into(),
            "wrong".to_string(),
        )];
        assert_eq!(
            v.process(&headers, &tg_update(1, 2, 3, "x")).unwrap_err(),
            Reject::Unauthorized
        );
        // Missing header → also unauthorized.
        assert_eq!(
            v.process(&[], &tg_update(1, 2, 3, "x")).unwrap_err(),
            Reject::Unauthorized
        );
    }

    #[test]
    fn telegram_verifier_fails_closed_on_empty_secret() {
        // Audit r1 Critical: an empty configured secret must NOT authenticate a
        // missing/empty header (would be "" == "" → authenticated).
        let v = TelegramVerifier::new("");
        // Missing header.
        assert_eq!(
            v.process(&[], &tg_update(1, 2, 3, "x")).unwrap_err(),
            Reject::Unauthorized
        );
        // Empty header value.
        let headers = vec![("X-Telegram-Bot-Api-Secret-Token".into(), String::new())];
        assert_eq!(
            v.process(&headers, &tg_update(1, 2, 3, "x")).unwrap_err(),
            Reject::Unauthorized
        );
    }

    #[test]
    fn telegram_verifier_rejects_unparseable_body() {
        let v = TelegramVerifier::new(TG_SECRET);
        let headers = vec![(
            "X-Telegram-Bot-Api-Secret-Token".into(),
            TG_SECRET.to_string(),
        )];
        assert_eq!(
            v.process(&headers, b"not json").unwrap_err(),
            Reject::BadRequest
        );
        // Well-formed JSON but no message → bad request.
        assert_eq!(
            v.process(&headers, b"{\"update_id\":1}").unwrap_err(),
            Reject::BadRequest
        );
    }

    #[test]
    fn build_raw_event_from_outcome_stamps_real_conversation_id_not_path() {
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe_host_pump(
                "agent:default",
                ChannelConfig {
                    adapter_type: AdapterType::Telegram,
                    params: vec![],
                    outbound: None,
                },
            )
            .unwrap();
        let outcome = InboundOutcome {
            sender_id: "4242".into(),
            conversation_id: "98765".into(),
            reply_address: vec![("chat_id".into(), "98765".into())],
            ack: None,
            extra: vec![],
            timestamp: Some(1700000000),
        };
        let ev = build_raw_event_from_outcome("telegram", b"hi", &outcome, &id);
        let kv: std::collections::HashMap<_, _> = ev
            .metadata
            .iter()
            .map(|p| (p.key.clone(), p.value.clone()))
            .collect();
        // The FIX: conversation_id is the real chat id, NOT a webhook path.
        assert_eq!(kv["channel.conversation_id"], "98765");
        assert_eq!(kv["channel.reply_address.chat_id"], "98765");
        assert_eq!(kv["channel.adapter"], "telegram");
        assert_eq!(kv["channel.timestamp"], "1700000000"); // epoch seconds
        assert_eq!(ev.data, b"hi");
    }
}
