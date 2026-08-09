//! Type definitions shared across cap-channel modules.
//!
//! Mirrors the CONTRACT-150 WIT shapes (see MODULE-016 §1.4.1) with Rust-native
//! types. WIT `cap-param` → [`CapParam`]; `subscription-id` → [`SubscriptionId`];
//! `raw-event` → [`RawEvent`]; `channel-config` → [`ChannelConfig`].

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Newtype around a stable, ASCII-only subscription identifier. Slice B
/// allocates UUID-v4 strings.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubscriptionId(pub String);

impl SubscriptionId {
    /// Allocate a fresh subscription id (UUID v4).
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Construct from a caller-supplied string (for tests + WIT lifting).
    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    /// Reference accessor — the raw id bytes-as-str.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SubscriptionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Key-value pair mirroring the WIT `record cap-param` shape (PRD §9.9).
/// Sibling-consistent with `cap-grant::data::CapParam`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapParam {
    pub key: String,
    pub value: String,
}

impl CapParam {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Channel adapter type. The 4 enumerated variants have host-authoritative
/// presets in [`crate::sandbox`]. `Other(raw)` carries an unknown adapter type
/// string for type-system completeness; `SubscriptionManager::subscribe`
/// rejects `Other(*)` with `InvalidConfig` per MODULE-016 §1.4.2:97.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterType {
    Telegram,
    Slack,
    Signal,
    Webhook,
    Other(String),
}

impl AdapterType {
    /// The kebab-case wire string used by WIT lifting + `channel.adapter`
    /// provenance metadata key.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Telegram => "telegram",
            Self::Slack => "slack",
            Self::Signal => "signal",
            Self::Webhook => "webhook",
            Self::Other(s) => s,
        }
    }
}

impl FromStr for AdapterType {
    type Err = std::convert::Infallible;

    /// Always succeeds; unknown strings produce `Other(raw)` so the WIT handler
    /// can return a stable `InvalidConfig` message that includes the raw value.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "telegram" => Self::Telegram,
            "slack" => Self::Slack,
            "signal" => Self::Signal,
            "webhook" => Self::Webhook,
            other => Self::Other(other.to_string()),
        })
    }
}

/// HTTP method enum used by [`OutboundConfig`]. Slice B's dispatcher allows
/// only `Post | Put | Patch | Get`; `Delete` / `Head` / `Options` are intentionally
/// excluded (see MODULE-016 §2.7 outbound flow).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
}

impl HttpMethod {
    /// Map to the shared-types `HttpMethod` used by `HttpSecurityChain`.
    pub fn to_shared(&self) -> advance_shared_types::security_validator::HttpMethod {
        use advance_shared_types::security_validator::HttpMethod as Shared;
        match self {
            Self::Get => Shared::Get,
            Self::Post => Shared::Post,
            Self::Put => Shared::Put,
            Self::Patch => Shared::Patch,
        }
    }
}

/// Outbound HTTPS configuration per subscription. Owned by the subscription;
/// `OutboundDispatcher` materializes this into an `HttpRequest` at send-raw time.
///
/// **No `allowlist` field** — the allowlist is host-authoritative (sourced from
/// [`crate::sandbox::AdapterCapabilitySet`] preset indexed by adapter type),
/// NOT subscribe-supplied. See MODULE-016 §2.7 send-raw flow + Plan Eval R4
/// Warning #4 for rationale.
///
/// Manual `Debug` impl redacts header values matching the global redaction
/// set (Authorization / Proxy-Authorization / X-API-Key / X-Auth-Token /
/// X-Access-Token / Cookie / Set-Cookie / case-insensitive suffix `-key` /
/// `-token` / `-secret` / `-password`) — adapter authors routinely place
/// bearer tokens in `headers`. Per Adversarial Eval R19 #1, the default
/// `#[derive(Debug)]` would leak these into any operator log dump.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub method: HttpMethod,
    pub url_template: String,
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for OutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundConfig")
            .field("method", &self.method)
            // Audit r6 Critical: under the Step-3 credential-in-URL model the
            // `url_template` carries the bot token (e.g. `/bot<token>/sendMessage`),
            // so a verbatim `{:?}` (via this struct, or `Subscription`/`ChannelConfig`
            // which embed it) would leak the token into operator logs. Keep the
            // scheme+host (non-secret, SSRF-relevant) and redact the path+query.
            .field("url_template", &RedactedUrl(&self.url_template))
            .field("headers", &RedactedHeaders(&self.headers))
            .finish()
    }
}

/// URL-redaction helper for `Debug`: prints `scheme://host/[redacted-path]`,
/// scrubbing the path+query (which may carry a credential — e.g. a Telegram
/// `/bot<token>/` segment). A URL with no path is non-secret and printed as-is.
struct RedactedUrl<'a>(&'a str);

impl<'a> std::fmt::Debug for RedactedUrl<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self.0;
        // No scheme separator → we can't safely isolate a non-secret host; a bare
        // `host/bot<token>/…` would leak, so redact entirely (audit r7).
        let Some(scheme_end) = url.find("://") else {
            return write!(f, "[redacted-url]");
        };
        let after = scheme_end + 3;
        let rest = &url[after..];
        // The authority may carry userinfo (`user:pass@host`) — itself a
        // credential — so if `@` precedes the path, redact the whole authority.
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        if rest[..authority_end].contains('@') {
            return write!(f, "{}[redacted-authority]", &url[..after]);
        }
        // A credential can ride in the path, query, OR fragment — scrub from the
        // earliest of `/ ? #` after the host.
        match rest.find(['/', '?', '#']) {
            Some(rel) => write!(f, "{}/[redacted-path]", &url[..after + rel]),
            // scheme://host with nothing after → non-secret, print verbatim.
            None => write!(f, "{url}"),
        }
    }
}

/// Header-redaction helper: prints each header value as `[REDACTED]` when the
/// name matches the sensitive set, else verbatim.
struct RedactedHeaders<'a>(&'a [(String, String)]);

impl<'a> std::fmt::Debug for RedactedHeaders<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for (k, v) in self.0 {
            if is_sensitive_header(k) {
                list.entry(&(k.as_str(), "[REDACTED]"));
            } else {
                list.entry(&(k.as_str(), v.as_str()));
            }
        }
        list.finish()
    }
}

fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let exact = [
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "cookie",
        "set-cookie",
    ];
    if exact.iter().any(|e| *e == lower) {
        return true;
    }
    for suffix in ["-key", "-token", "-secret", "-password"] {
        if lower.ends_with(suffix) {
            return true;
        }
    }
    false
}

/// Channel subscription configuration. The `outbound` field is optional —
/// inbound-only subscriptions (e.g. webhook receivers) have `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub adapter_type: AdapterType,
    pub params: Vec<CapParam>,
    pub outbound: Option<OutboundConfig>,
}

/// Inbound raw event surfaced through `poll-raw`. Mirrors the WIT `raw-event`
/// shape (`data: list<u8>`, `metadata: option<list<cap-param>>` — Slice B
/// represents `None` as `vec![]` for ergonomic Rust; the WIT-lifting code
/// converts both directions).
///
/// Manual `Debug` impl prints `data` as `[BODY_LEN={N}]` rather than the raw
/// bytes — webhook bodies (which `RawEvent.data` carries) routinely include
/// OAuth callbacks, PR diffs, and customer PII per GitHub/Slack/Telegram
/// payload conventions; the default `#[derive(Debug)]` would leak these
/// verbatim into any state-dump log. Per Adversarial Eval R19 #1.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvent {
    pub data: Vec<u8>,
    pub metadata: Vec<CapParam>,
}

impl std::fmt::Debug for RawEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawEvent")
            .field("data", &format_args!("[BODY_LEN={}]", self.data.len()))
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_id_new_is_unique() {
        let a = SubscriptionId::new();
        let b = SubscriptionId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn outbound_config_debug_redacts_url_credential_in_all_forms() {
        let dbg = |u: &str| {
            format!(
                "{:?}",
                OutboundConfig {
                    method: HttpMethod::Post,
                    url_template: u.to_string(),
                    headers: vec![],
                }
            )
        };
        // Telegram path-credential (the shipped form).
        let s = dbg("https://api.telegram.org/bot123:SECRET/sendMessage");
        assert!(
            !s.contains("SECRET") && s.contains("api.telegram.org"),
            "{s}"
        );
        // Query credential.
        let s = dbg("https://api.example.com?token=SECRET");
        assert!(!s.contains("SECRET"), "{s}");
        // Userinfo credential.
        let s = dbg("https://user:SECRET@api.example.com/path");
        assert!(!s.contains("SECRET"), "{s}");
        // Fragment credential.
        let s = dbg("https://api.example.com#SECRET");
        assert!(!s.contains("SECRET"), "{s}");
        // Scheme-less (can't isolate host) → fully redacted.
        let s = dbg("api.telegram.org/bot123:SECRET/sendMessage");
        assert!(!s.contains("SECRET"), "{s}");
        // Host-only (nothing secret) → printed verbatim.
        let s = dbg("https://api.telegram.org");
        assert!(s.contains("api.telegram.org"), "{s}");
    }

    #[test]
    fn adapter_type_round_trips() {
        for variant in [
            AdapterType::Telegram,
            AdapterType::Slack,
            AdapterType::Signal,
            AdapterType::Webhook,
        ] {
            let s = variant.as_str().to_string();
            let parsed: AdapterType = s.parse().unwrap();
            assert_eq!(variant, parsed);
        }
    }

    #[test]
    fn adapter_type_unknown_becomes_other() {
        let parsed: AdapterType = "discord".parse().unwrap();
        assert!(matches!(parsed, AdapterType::Other(ref s) if s == "discord"));
    }

    #[test]
    fn cap_param_constructs_from_into() {
        let p = CapParam::new("k", "v");
        assert_eq!(p.key, "k");
        assert_eq!(p.value, "v");
    }

    #[test]
    fn http_method_maps_to_shared() {
        use advance_shared_types::security_validator::HttpMethod as Shared;
        assert_eq!(HttpMethod::Get.to_shared(), Shared::Get);
        assert_eq!(HttpMethod::Post.to_shared(), Shared::Post);
        assert_eq!(HttpMethod::Put.to_shared(), Shared::Put);
        assert_eq!(HttpMethod::Patch.to_shared(), Shared::Patch);
    }
}
