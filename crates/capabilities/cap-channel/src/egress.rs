//! L6 outbound egress (Phase-2 Step-3, ADR `2026-06-05-extensible-channel-adapter`).
//!
//! `OutboundDispatcher`'s static-URL `send-raw` path is generalized behind the
//! [`OutboundTransport`] trait. [`HttpEgress`] is the sole impl in Step-3 — the
//! `HttpSecurityChain` logic (ownership check, host-authoritative preset
//! allowlist, method / 64 KB / CRLF guards) lives HERE now, so this module is
//! the **single `security_chain.execute` call site** in cap-channel `src/`
//! (AC-09 sole-consumer invariant, re-established for the in-host pump; pinned
//! by `tests/structural.rs::dispatcher_is_sole_security_chain_consumer`).
//!
//! The per-adapter **renderer** derives the HTTP request from `(target, data)`:
//! scheme+host stay **preset-allowlisted** (the host NEVER comes from the
//! message — SSRF surface unchanged), the body is `data` (a per-adapter renderer
//! may merge a routing field — Telegram's `chat_id` — into the JSON body when
//! the channel addresses by body rather than path). The allowlist is re-checked
//! after expansion by the security chain itself (it receives the final URL).

use std::sync::Arc;

use async_trait::async_trait;

use advance_shared_types::event::Event;
use advance_shared_types::outbound::{
    DeliveryReport, OutboundEncoding, OutboundRoute, OutboundTarget, RoutedOutboundMessage,
};
use advance_shared_types::progress_card::OutboundRouteRef;
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain, ScanContext,
    ScanResult,
};
use advance_shared_types::traits::{EventBusEmit, LeakDetector};

use crate::error::ChannelError;
use crate::progress_card::{
    ProgressCardRenderer, ProgressTransportError, TelegramProgressOperation,
    TelegramProgressTransport,
};
use crate::sandbox::AdapterCapabilitySet;
use crate::subscription::Subscription;
use crate::types::{AdapterType, HttpMethod, OutboundConfig};

fn contains_cr_or_lf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

/// Max outbound payload bytes for the in-host egress path — mirrors the WIT
/// `send-raw` 64 KB cap (MODULE-016 §2.7 outbound body-size). The in-host channel
/// reply path is a NEW caller (the WIT lift's cap does not cover it), so the cap
/// is re-applied here (audit r1 Warning). A guest reply (validated as an
/// `AgentAction`, ≤ 1 MiB) that exceeds this is rejected before the chain.
pub const MAX_EGRESS_DATA_BYTES: usize = 65_536;

/// Outbound transport seam — selected by the adapter preset's `egress_kind`.
/// `HttpEgress` is the sole impl in Step-3; `LocalProcessEgress` / `PushNotify`
/// are designed-for-deferred (ADR L6).
#[async_trait]
pub trait OutboundTransport: Send + Sync {
    /// Deliver `data` to `target` on behalf of `agent_id` over `sub`'s preset.
    /// Returns a structured [`DeliveryReport`]. `agent_id` MUST own `sub`.
    async fn send(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: OutboundTarget,
        data: &[u8],
    ) -> Result<DeliveryReport, ChannelError>;

    /// Provider-owned typed entry used by the routed C215/C216 branch. Legacy
    /// payloads retain the exact `send` behavior; providers that do not stage
    /// C215 reject ProgressV1 before transport.
    async fn send_typed(
        &self,
        agent_id: &str,
        sub: &Subscription,
        message: &RoutedOutboundMessage,
        route_ref: Option<&OutboundRouteRef>,
    ) -> Result<DeliveryReport, ChannelError> {
        if message.encoding != OutboundEncoding::LegacyRaw || route_ref.is_some() {
            return Err(ChannelError::InvalidConfig(
                "typed progress transport unavailable".into(),
            ));
        }
        self.send(
            agent_id,
            sub,
            target_from_routed_message(message)?,
            &message.body,
        )
        .await
    }
}

struct TypedOutboundTransport {
    egress: Arc<HttpEgress>,
    renderer: Arc<ProgressCardRenderer>,
}

/// Stage the single M016 typed transport entry over the same concrete
/// `HttpEgress` used by legacy replies. Progress fallback therefore re-enters
/// the identical security-chain call site instead of bypassing the provider.
pub fn stage_typed_outbound_transport(
    egress: Arc<HttpEgress>,
    renderer: Arc<ProgressCardRenderer>,
) -> Arc<dyn OutboundTransport> {
    Arc::new(TypedOutboundTransport { egress, renderer })
}

#[async_trait]
impl OutboundTransport for TypedOutboundTransport {
    async fn send(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: OutboundTarget,
        data: &[u8],
    ) -> Result<DeliveryReport, ChannelError> {
        self.egress.send(agent_id, sub, target, data).await
    }

    async fn send_typed(
        &self,
        agent_id: &str,
        sub: &Subscription,
        message: &RoutedOutboundMessage,
        route_ref: Option<&OutboundRouteRef>,
    ) -> Result<DeliveryReport, ChannelError> {
        if matches!(
            &message.route,
            OutboundRoute::Channel { subscription_id, .. }
                if subscription_id != sub.id.as_str()
        ) {
            return Err(ChannelError::InvalidConfig(
                "typed outbound subscription mismatch".into(),
            ));
        }
        match message.encoding {
            OutboundEncoding::LegacyRaw => {
                if route_ref.is_some() {
                    return Err(ChannelError::InvalidConfig(
                        "legacy outbound cannot consume progress route ref".into(),
                    ));
                }
                self.egress
                    .send(
                        agent_id,
                        sub,
                        target_from_routed_message(message)?,
                        &message.body,
                    )
                    .await
            }
            OutboundEncoding::ProgressV1 => {
                let route_ref = route_ref.ok_or_else(|| {
                    ChannelError::InvalidConfig("progress route ref missing".into())
                })?;
                self.renderer
                    .render(agent_id, sub, message, route_ref)
                    .await
            }
        }
    }
}

fn target_from_routed_message(
    message: &RoutedOutboundMessage,
) -> Result<OutboundTarget, ChannelError> {
    match &message.route {
        OutboundRoute::Channel {
            conversation_id,
            reply_address,
            ..
        } => Ok(OutboundTarget::ChatReply {
            conversation_id: conversation_id.clone(),
            reply_address: reply_address.clone(),
        }),
        OutboundRoute::DirectReply => Err(ChannelError::InvalidConfig(
            "typed channel route required".into(),
        )),
    }
}

/// The HTTPS egress — the SOLE [`HttpSecurityChain`] (CONTRACT-111) consumer.
/// Holds only the trait-object chain (the subscription is passed per-call).
pub struct HttpEgress {
    security_chain: Arc<dyn HttpSecurityChain>,
    /// Phase-3 kickoff (2026-06-06): optional observability sink. `None`
    /// (default) → no emit (the guest `send-raw` `HttpEgress` built inside
    /// `OutboundDispatcher::new` stays unemitting). The daemon reply egress
    /// (built in `channels_boot`) opts in via [`Self::with_event_bus`] →
    /// emits `channel.raw_sent` after a successful chain pass (MODULE-016-AC-12).
    event_bus: Option<Arc<dyn EventBusEmit>>,
    /// Wave-20 security lane (MODULE-012-AC-19 ChannelBidi leg): optional
    /// [`LeakDetector`] applied to the PRE-render channel **message content**
    /// (`data`) under [`ScanContext::ChannelBidi`] before the security chain.
    /// `None` (default) → no scan (byte-identical to the prior egress; the
    /// guest/test egress built via `new()` stays unscanned). The daemon egress
    /// (built in `channels_boot`) opts in via [`Self::with_leak_detector`] with
    /// the production `DefaultLeakDetector` — covering all channel egress callers
    /// that funnel through this single `send`. Distinct from the chain's
    /// post-render `HttpOutbound` body scan. Scan ≠ `security_chain.execute`, so
    /// the AC-09 sole-chain-call-site invariant is preserved.
    leak_detector: Option<Arc<dyn LeakDetector>>,
}

impl HttpEgress {
    pub fn new(security_chain: Arc<dyn HttpSecurityChain>) -> Self {
        Self {
            security_chain,
            event_bus: None,
            leak_detector: None,
        }
    }

    /// Phase-3 kickoff opt-in builder — wire an observability sink so a
    /// successful outbound reply emits `channel.raw_sent`. Additive; existing
    /// `new()` callers (incl. the guest-path egress) emit nothing.
    pub fn with_event_bus(mut self, bus: Arc<dyn EventBusEmit>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Wave-20 opt-in builder — wire a [`LeakDetector`] so the PRE-render
    /// channel message content is scanned under [`ScanContext::ChannelBidi`]
    /// before egress (MODULE-012-AC-19 ChannelBidi leg). Additive; existing
    /// `new()` callers stay unscanned.
    pub fn with_leak_detector(mut self, detector: Arc<dyn LeakDetector>) -> Self {
        self.leak_detector = Some(detector);
        self
    }

    /// The one physical security-chain call used by legacy and progress
    /// Telegram egress. Keeping execution here prevents the definitive-loss
    /// fallback from bypassing or reusing a prior security decision.
    async fn execute_security_chain(
        &self,
        agent_id: &str,
        req: HttpRequest,
        cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        self.security_chain.execute(agent_id, req, cap).await
    }
}

#[async_trait]
impl OutboundTransport for HttpEgress {
    async fn send(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: OutboundTarget,
        data: &[u8],
    ) -> Result<DeliveryReport, ChannelError> {
        // 1. Per-agent ownership check — the subscription is bound to its creating
        //    agent at subscribe time; no other agent may drive egress through it.
        if sub.owner_agent_id != agent_id {
            return Err(ChannelError::PermissionDenied(format!(
                "subscription {} not owned by caller",
                sub.id.as_str()
            )));
        }

        // 2. Pull the preset OutboundConfig (the base host/url + method + headers).
        let outbound = sub.config.outbound.as_ref().ok_or_else(|| {
            ChannelError::InvalidConfig(format!(
                "subscription {} has no outbound config",
                sub.id.as_str()
            ))
        })?;

        // 3. Method allowlist {POST, PUT, PATCH, GET} (HttpMethod has no
        //    destructive verbs — this match is exhaustive, type-system-enforced).
        match outbound.method {
            HttpMethod::Get | HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => {}
        }

        // 3a. Header CRLF defense (header-splitting).
        for (k, v) in &outbound.headers {
            if contains_cr_or_lf(k) || contains_cr_or_lf(v) {
                return Err(ChannelError::InvalidConfig(
                    "outbound header contains CR/LF (header-splitting attempt)".into(),
                ));
            }
        }

        // 3b. Outbound 64 KB cap (audit r1 Warning): the in-host pump is a new
        // chain caller not covered by the WIT send-raw lift's cap; re-apply it
        // here so a large guest reply cannot send an oversized outbound body.
        // FAST-PATH pre-render check on the raw `data` (rejects gross over-size
        // before the renderer allocates).
        if data.len() > MAX_EGRESS_DATA_BYTES {
            return Err(ChannelError::InvalidConfig(format!(
                "outbound data {} bytes exceeds {} byte cap",
                data.len(),
                MAX_EGRESS_DATA_BYTES
            )));
        }

        // 3c. Wave-20 (MODULE-012-AC-19 ChannelBidi leg): scan the PRE-render
        //     channel MESSAGE CONTENT (`data`) under `ScanContext::ChannelBidi`
        //     before rendering. This is a SEPARATE surface from the chain's
        //     post-render `HttpOutbound` body scan (the chain scans the rendered
        //     HTTP envelope; here we scan the raw message text). Block withholds
        //     egress; Redact masks the message in place (the rendered request
        //     then carries the redacted content). `None` detector → no scan
        //     (byte-identical). Scan != `security_chain.execute`, so the AC-09
        //     sole-chain-call-site invariant (`tests/structural.rs`) is preserved.
        //     The block error carries NO message bytes (operator-log safety).
        let scanned: std::borrow::Cow<'_, [u8]> = match &self.leak_detector {
            Some(detector) => {
                match detector.scan(&String::from_utf8_lossy(data), ScanContext::ChannelBidi) {
                    ScanResult::Blocked { .. } => {
                        return Err(ChannelError::OutboundBlocked(
                            "channel message withheld by ChannelBidi leak scan".to_string(),
                        ));
                    }
                    ScanResult::Redacted { redacted, .. } => {
                        std::borrow::Cow::Owned(redacted.into_bytes())
                    }
                    ScanResult::Clean | ScanResult::Warned { .. } => {
                        std::borrow::Cow::Borrowed(data)
                    }
                }
            }
            None => std::borrow::Cow::Borrowed(data),
        };

        // 4. Per-adapter renderer: derive (url, body) from (target, data). The
        //    HOST stays the preset url_template (never from the message — SSRF
        //    immutability); only the body/path derive from the message.
        let (url, body) = render_request(
            &sub.config.adapter_type,
            outbound,
            &target,
            scanned.as_ref(),
        )?;

        // 4a. HARD post-render body cap (audit r2 Warning): the renderer can
        // EXPAND `data` (e.g. JSON-escaping control chars into `\uXXXX`), so the
        // pre-render fast-path is not sufficient — bound the FINAL bytes that
        // reach the chain/executor.
        if body.len() > MAX_EGRESS_DATA_BYTES {
            return Err(ChannelError::InvalidConfig(format!(
                "rendered outbound body {} bytes exceeds {} byte cap",
                body.len(),
                MAX_EGRESS_DATA_BYTES
            )));
        }

        // 5. Build the host-authoritative HttpCapability from the preset allowlist.
        //    The security chain re-checks the final URL against this allowlist
        //    (the "allowlist re-checked after expansion" invariant).
        let preset = AdapterCapabilitySet::preset_for(&sub.config.adapter_type);
        let component_id = format!("cap-channel:{}", sub.config.adapter_type.as_str());
        let cap = HttpCapability {
            allowlist: preset.outbound_allowlist.clone(),
            component_id,
            credentials: vec![],
        };
        let req = HttpRequest {
            method: outbound.method.to_shared(),
            url,
            headers: outbound.headers.clone(),
            body,
        };

        // 6. THE single security-chain call site in cap-channel src/ (AC-09).
        //    Kept on one physical line for the structural grep.
        let chain_result = self.execute_security_chain(agent_id, req, &cap).await;
        // Map the chain error to a KIND label WITHOUT the URL (audit r3 Warning):
        // the Step-3 credential-in-`url_template` model puts the bot token in the
        // URL, but `HttpError::{AllowlistBlocked,InvalidUrl,RedirectRejected}`
        // embed the URL — so `format!("{e:?}")` would leak the token into operator
        // logs (it eventually `eprintln`s up the dispatch-error path). Emit only
        // the variant kind; the full (token-bearing) error stays in the security
        // chain's own audit surface, never in cap-channel's error string.
        chain_result.map_err(|e| ChannelError::OutboundBlocked(outbound_error_kind(&e)))?;

        // 6a. channel.raw_sent (Phase-3 kickoff) — the outbound reply passed the
        // chain. Payload carries ONLY the adapter + the outbound byte count: NEVER
        // the `target` (it can carry a chat_id / reply-address token) and NEVER the
        // body. Wave-20 (audit-r1 diff Info-1): report the POST-ChannelBidi-scan
        // message length (`scanned`), so a Redact path reports the masked size
        // actually sent rather than the pre-scan `data.len()` (Clean → identical).
        if let Some(bus) = &self.event_bus {
            bus.emit(Event::observability(
                "channel.raw_sent",
                agent_id,
                serde_json::json!({
                    "adapter": sub.config.adapter_type.as_str(),
                    "body_bytes": scanned.len(),
                }),
                None,
            ));
        }

        // 7. Step-3 HttpEgress returns a single Delivered (Pruned/Retry are push-era).
        Ok(DeliveryReport::delivered())
    }
}

#[async_trait]
impl TelegramProgressTransport for HttpEgress {
    fn prepare_text(&self, text: &str) -> Result<String, ChannelError> {
        match &self.leak_detector {
            Some(detector) => match detector.scan(text, ScanContext::ChannelBidi) {
                ScanResult::Blocked { .. } => Err(ChannelError::OutboundBlocked(
                    "channel message withheld by ChannelBidi leak scan".to_string(),
                )),
                ScanResult::Redacted { redacted, .. } => Ok(redacted),
                ScanResult::Clean | ScanResult::Warned { .. } => Ok(text.to_string()),
            },
            None => Ok(text.to_string()),
        }
    }

    async fn execute_progress(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: &OutboundTarget,
        operation: TelegramProgressOperation,
        text: &str,
    ) -> Result<HttpResponse, ProgressTransportError> {
        let before_http = |error| ProgressTransportError::DefinitelyNotDelivered(error);
        if sub.owner_agent_id != agent_id {
            return Err(before_http(ChannelError::PermissionDenied(
                "progress subscription not owned by caller".to_string(),
            )));
        }
        if sub.config.adapter_type != AdapterType::Telegram {
            return Err(before_http(ChannelError::InvalidConfig(
                "progress-adapter-unsupported".to_string(),
            )));
        }
        let outbound = sub.config.outbound.as_ref().ok_or_else(|| {
            before_http(ChannelError::InvalidConfig(
                "progress outbound config missing".to_string(),
            ))
        })?;
        if outbound.method != HttpMethod::Post {
            return Err(before_http(ChannelError::InvalidConfig(
                "progress outbound method invalid".to_string(),
            )));
        }
        for (key, value) in &outbound.headers {
            if contains_cr_or_lf(key) || contains_cr_or_lf(value) {
                return Err(before_http(ChannelError::InvalidConfig(
                    "outbound header contains CR/LF".to_string(),
                )));
            }
        }
        let conversation_id = target.conversation_id().unwrap_or("");
        validate_routing_token(conversation_id).map_err(before_http)?;
        if conversation_id.is_empty() {
            return Err(before_http(ChannelError::InvalidConfig(
                "progress-route-invalid".to_string(),
            )));
        }
        let send_suffix = "/sendMessage";
        let Some(prefix) = outbound.url_template.strip_suffix(send_suffix) else {
            return Err(before_http(ChannelError::InvalidConfig(
                "progress-url-template-invalid".to_string(),
            )));
        };
        let (url, body) = match operation {
            TelegramProgressOperation::SendMessage => (
                outbound.url_template.clone(),
                serde_json::json!({"chat_id": conversation_id, "text": text}),
            ),
            TelegramProgressOperation::EditMessageText { message_id } => {
                if message_id <= 0 {
                    return Err(before_http(ChannelError::InvalidConfig(
                        "progress-message-id-invalid".to_string(),
                    )));
                }
                (
                    format!("{prefix}/editMessageText"),
                    serde_json::json!({
                        "chat_id": conversation_id,
                        "message_id": message_id,
                        "text": text,
                    }),
                )
            }
        };
        let body = serde_json::to_vec(&body).map_err(|_| {
            before_http(ChannelError::InvalidConfig(
                "telegram body encode failed".to_string(),
            ))
        })?;
        if body.len() > MAX_EGRESS_DATA_BYTES {
            return Err(before_http(ChannelError::InvalidConfig(
                "rendered outbound body exceeds cap".to_string(),
            )));
        }

        let preset = AdapterCapabilitySet::preset_for(&sub.config.adapter_type);
        let cap = HttpCapability {
            allowlist: preset.outbound_allowlist.clone(),
            component_id: format!("cap-channel:{}", sub.config.adapter_type.as_str()),
            credentials: vec![],
        };
        let request = HttpRequest {
            method: outbound.method.to_shared(),
            url,
            headers: outbound.headers.clone(),
            body,
        };
        let response = self
            .execute_security_chain(agent_id, request, &cap)
            .await
            .map_err(|error| {
                ProgressTransportError::Ambiguous(ChannelError::OutboundBlocked(
                    outbound_error_kind(&error),
                ))
            })?;

        if let Some(bus) = &self.event_bus {
            bus.emit(Event::observability(
                "channel.raw_sent",
                agent_id,
                serde_json::json!({
                    "adapter": sub.config.adapter_type.as_str(),
                    "body_bytes": text.len(),
                }),
                None,
            ));
        }
        Ok(response)
    }
}

/// Map an `HttpError` to a NON-URL-bearing kind label for the cap-channel error
/// string (audit r3). The URL-carrying variants (`AllowlistBlocked` / `InvalidUrl`
/// / `RedirectRejected`) would otherwise leak the bot token (which rides in the
/// preset `url_template` under the Step-3 credential-in-URL model). Only the
/// variant kind is surfaced — never the inner URL/string.
fn outbound_error_kind(e: &HttpError) -> String {
    let kind = match e {
        HttpError::AllowlistBlocked(_) => "allowlist_blocked",
        HttpError::InvalidUrl(_) => "invalid_url",
        HttpError::RedirectRejected { .. } => "redirect_rejected",
        // All other variants (transport / leak / rate-limit / etc.) do NOT carry
        // the request URL; still surface only a generic kind to avoid leaking any
        // inner string into operator logs.
        _ => "blocked",
    };
    format!("security chain rejected outbound ({kind})")
}

/// Reject a routing token that could splice an HTTP request line (CR/LF) — the
/// conversation id / reply-address values come from the inbound payload, so they
/// are untrusted. For Telegram they land in a JSON body (serde-escaped), but this
/// is defense-in-depth so a future path-addressed renderer cannot be CRLF-spliced.
fn validate_routing_token(token: &str) -> Result<(), ChannelError> {
    if token.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(ChannelError::InvalidConfig(
            "routing token contains CR/LF/NUL".into(),
        ));
    }
    Ok(())
}

/// Derive the `(url, body)` for an outbound request. The host/scheme always come
/// from the preset `url_template`; only the body/path derive from `(target,
/// data)`. The WIT `send-raw` path (and non-Telegram adapters) use the generic
/// passthrough (url_template + raw `data` body) — byte-identical to the pre-Step-3
/// `OutboundDispatcher::dispatch` behavior.
fn render_request(
    adapter: &AdapterType,
    outbound: &OutboundConfig,
    target: &OutboundTarget,
    data: &[u8],
) -> Result<(String, Vec<u8>), ChannelError> {
    match adapter {
        AdapterType::Telegram => render_telegram(outbound, target, data),
        // Generic passthrough: WIT send-raw + non-Telegram adapters keep the
        // existing url_template + raw-data-body behavior.
        _ => Ok((outbound.url_template.clone(), data.to_vec())),
    }
}

/// Telegram addresses by **body**: `POST {preset-host}/bot{token}/sendMessage`
/// with `chat_id` merged into the JSON body. The URL is always the preset
/// `url_template` (host immutability); `chat_id` comes from the per-message
/// `OutboundTarget.conversation_id`. An empty conversation id (the WIT send-raw
/// path, which has no per-message target) falls back to the raw-data passthrough.
fn render_telegram(
    outbound: &OutboundConfig,
    target: &OutboundTarget,
    data: &[u8],
) -> Result<(String, Vec<u8>), ChannelError> {
    let conversation_id = target.conversation_id().unwrap_or("");
    if conversation_id.is_empty() {
        // WIT send-raw path (no per-message routing) → passthrough.
        return Ok((outbound.url_template.clone(), data.to_vec()));
    }
    validate_routing_token(conversation_id)?;
    // `text` is the guest reply payload (interim: opaque first-action bytes).
    let text = String::from_utf8_lossy(data);
    let body = serde_json::json!({
        "chat_id": conversation_id,
        "text": text,
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|_| ChannelError::InvalidConfig("telegram body encode failed".into()))?;
    // URL is ALWAYS the preset url_template — host never derives from the message.
    Ok((outbound.url_template.clone(), body_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::AdapterCapabilitySet;
    use crate::types::ChannelConfig;

    fn telegram_outbound() -> OutboundConfig {
        OutboundConfig {
            method: HttpMethod::Post,
            url_template: "https://api.telegram.org/bot123/sendMessage".to_string(),
            headers: vec![("Content-Type".into(), "application/json".into())],
        }
    }

    #[test]
    fn telegram_renderer_merges_chat_id_into_body_host_immutable() {
        let target = OutboundTarget::ChatReply {
            conversation_id: "98765".into(),
            reply_address: vec![("chat_id".into(), "98765".into())],
        };
        let (url, body) = render_request(
            &AdapterType::Telegram,
            &telegram_outbound(),
            &target,
            b"hi there",
        )
        .unwrap();
        // Host is ALWAYS the preset url_template (never from the message).
        assert_eq!(url, "https://api.telegram.org/bot123/sendMessage");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["chat_id"], "98765");
        assert_eq!(v["text"], "hi there");
    }

    #[test]
    fn telegram_renderer_empty_conversation_is_passthrough() {
        // WIT send-raw path: no per-message conversation → raw data body.
        let target = OutboundTarget::ChatReply {
            conversation_id: String::new(),
            reply_address: vec![],
        };
        let (url, body) = render_request(
            &AdapterType::Telegram,
            &telegram_outbound(),
            &target,
            b"raw",
        )
        .unwrap();
        assert_eq!(url, "https://api.telegram.org/bot123/sendMessage");
        assert_eq!(body, b"raw");
    }

    #[test]
    fn telegram_renderer_rejects_crlf_in_conversation_id() {
        let target = OutboundTarget::ChatReply {
            conversation_id: "1\r\nHost: evil".into(),
            reply_address: vec![],
        };
        let err = render_request(&AdapterType::Telegram, &telegram_outbound(), &target, b"x")
            .unwrap_err();
        assert!(matches!(err, ChannelError::InvalidConfig(_)));
    }

    #[test]
    fn path_injection_in_conversation_id_does_not_change_host() {
        // A traversal-looking conversation id is JSON-escaped into the body and
        // the URL (host) is unchanged — host-immutability holds.
        let target = OutboundTarget::ChatReply {
            conversation_id: "../../admin".into(),
            reply_address: vec![],
        };
        let (url, body) =
            render_request(&AdapterType::Telegram, &telegram_outbound(), &target, b"x").unwrap();
        assert_eq!(url, "https://api.telegram.org/bot123/sendMessage");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["chat_id"], "../../admin");
    }

    #[test]
    fn webhook_adapter_passthrough_keeps_raw_body() {
        let cfg = OutboundConfig {
            method: HttpMethod::Post,
            url_template: "https://example.test/hook".into(),
            headers: vec![],
        };
        let target = OutboundTarget::ChatReply {
            conversation_id: "c".into(),
            reply_address: vec![],
        };
        // Non-Telegram adapter → generic passthrough (no chat_id merge).
        let (url, body) =
            render_request(&AdapterType::Webhook, &cfg, &target, b"raw-body").unwrap();
        assert_eq!(url, "https://example.test/hook");
        assert_eq!(body, b"raw-body");
    }

    #[tokio::test]
    async fn egress_rejects_oversized_data_before_chain() {
        use crate::subscription::{Consumer, Subscription};
        use crate::types::SubscriptionId;
        use advance_shared_types::security_validator::{HttpError, HttpResponse};

        // A chain that panics if reached — proves the 64 KB cap fires first.
        struct PanicChain;
        #[async_trait]
        impl HttpSecurityChain for PanicChain {
            async fn execute(
                &self,
                _agent_id: &str,
                _req: HttpRequest,
                _cap: &advance_shared_types::security_validator::HttpCapability,
            ) -> Result<HttpResponse, HttpError> {
                panic!("security chain must not be reached for oversized data");
            }
        }

        let egress = HttpEgress::new(Arc::new(PanicChain));
        let sub = Subscription::new_with_consumer(
            SubscriptionId::new(),
            "agent:default",
            ChannelConfig {
                adapter_type: AdapterType::Telegram,
                params: vec![],
                outbound: Some(telegram_outbound()),
            },
            Consumer::HostPump,
        );
        let big = vec![0u8; MAX_EGRESS_DATA_BYTES + 1];
        let target = OutboundTarget::ChatReply {
            conversation_id: "1".into(),
            reply_address: vec![],
        };
        let err = egress
            .send("agent:default", &sub, target, &big)
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::InvalidConfig(_)));
    }

    // Compile-time guard: a Telegram preset is send-capable (sanity for the
    // egress path — the allowlist the chain sees is the preset's).
    #[test]
    fn telegram_preset_allowlist_is_host_authoritative() {
        let preset = AdapterCapabilitySet::preset_for(&AdapterType::Telegram);
        assert_eq!(
            preset.outbound_allowlist.patterns,
            vec!["https://api.telegram.org/".to_string()]
        );
        let _ = ChannelConfig {
            adapter_type: AdapterType::Telegram,
            params: vec![],
            outbound: Some(telegram_outbound()),
        };
    }

    // ─── Phase-3 kickoff (2026-06-06) — MODULE-016-AC-12: channel.raw_sent ───
    use crate::subscription::Subscription;
    use crate::types::SubscriptionId;
    use advance_shared_types::security_validator::{
        HttpResponse as SHttpResponse, HttpSecurityChain,
    };
    use std::sync::Mutex;

    /// A security chain that always returns a fixed OK response (the executor /
    /// network is out of scope for the emit test).
    struct OkChain;
    #[async_trait]
    impl HttpSecurityChain for OkChain {
        async fn execute(
            &self,
            _agent_id: &str,
            _req: HttpRequest,
            _cap: &HttpCapability,
        ) -> Result<SHttpResponse, HttpError> {
            Ok(SHttpResponse {
                status: 200,
                headers: vec![],
                body: b"{\"ok\":true}".to_vec(),
            })
        }
    }

    #[derive(Default)]
    struct RecBus(Mutex<Vec<advance_shared_types::event::Event>>);
    impl EventBusEmit for RecBus {
        fn emit(&self, e: advance_shared_types::event::Event) {
            self.0.lock().unwrap().push(e);
        }
    }

    fn tg_sub() -> Subscription {
        Subscription::new(
            SubscriptionId("sub-1".into()),
            "agent-a",
            ChannelConfig {
                adapter_type: AdapterType::Telegram,
                params: vec![],
                outbound: Some(telegram_outbound()),
            },
        )
    }

    #[tokio::test]
    async fn http_egress_emits_channel_raw_sent_redacted() {
        let bus = Arc::new(RecBus::default());
        let egress = HttpEgress::new(Arc::new(OkChain)).with_event_bus(bus.clone());
        let target = OutboundTarget::ChatReply {
            conversation_id: "98765".into(),
            reply_address: vec![("chat_id".into(), "98765".into())],
        };
        egress
            .send("agent-a", &tg_sub(), target, b"hello reply")
            .await
            .expect("send ok");

        let events = bus.0.lock().unwrap();
        let sent: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == "channel.raw_sent")
            .collect();
        assert_eq!(sent.len(), 1, "exactly one channel.raw_sent");
        let p = &sent[0].payload;
        assert_eq!(p["adapter"], "telegram");
        // body_bytes = the POST-ChannelBidi-scan message length (`scanned.len()`).
        // No detector here → `scanned == data`, so it equals the guest data length
        // (b"hello reply" == 11) — NOT the rendered Telegram JSON wire body.
        assert_eq!(p["body_bytes"].as_u64(), Some("hello reply".len() as u64));
        // Redaction: no conversation_id / reply token / body in the payload.
        let dump = serde_json::to_string(&*events).unwrap();
        assert!(!dump.contains("98765"), "conversation id leaked: {dump}");
        assert!(!dump.contains("hello reply"), "body leaked: {dump}");
        assert!(p.get("target").is_none() && p.get("conversation_id").is_none());
    }

    /// Wave-20 (audit-r2): on the ChannelBidi Redact path, `channel.raw_sent`
    /// `body_bytes` reports the POST-scan (masked) length — NOT the pre-scan
    /// `data.len()`. Witnesses the `scanned.len()` semantic the §1.5 AC-12 text
    /// now documents.
    #[tokio::test]
    async fn http_egress_raw_sent_body_bytes_is_post_scan_on_redact() {
        struct RedactDet;
        impl LeakDetector for RedactDet {
            fn scan(&self, text: &str, _c: ScanContext) -> ScanResult {
                ScanResult::Redacted {
                    redacted: text.replace("MASKME", "X"),
                    findings: vec![],
                }
            }
            fn scan_headers(&self, _h: &[(String, String)]) -> ScanResult {
                ScanResult::Clean
            }
        }
        let bus = Arc::new(RecBus::default());
        let egress = HttpEgress::new(Arc::new(OkChain))
            .with_event_bus(bus.clone())
            .with_leak_detector(Arc::new(RedactDet));
        let target = OutboundTarget::ChatReply {
            conversation_id: "1".into(),
            reply_address: vec![],
        };
        // "MASKME" (6) → "X" (1): redacted body is 5 bytes shorter than the input.
        let data = b"MASKME tail";
        egress
            .send("agent-a", &tg_sub(), target, data)
            .await
            .expect("send ok");
        let events = bus.0.lock().unwrap();
        let sent: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == "channel.raw_sent")
            .collect();
        assert_eq!(sent.len(), 1, "exactly one channel.raw_sent");
        let body_bytes = sent[0].payload["body_bytes"].as_u64().unwrap() as usize;
        assert_eq!(body_bytes, data.len() - 5, "post-scan (masked) length");
        assert_ne!(body_bytes, data.len(), "NOT the pre-scan data.len()");
    }

    #[tokio::test]
    async fn http_egress_no_event_bus_no_emit() {
        // No with_event_bus → the un-wired recording bus captures nothing.
        let bus = Arc::new(RecBus::default());
        let egress = HttpEgress::new(Arc::new(OkChain));
        let target = OutboundTarget::ChatReply {
            conversation_id: "1".into(),
            reply_address: vec![],
        };
        egress
            .send("agent-a", &tg_sub(), target, b"x")
            .await
            .expect("send ok");
        assert!(bus.0.lock().unwrap().is_empty());
    }
}
