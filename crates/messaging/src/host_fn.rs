//! notify-agent host-fn slice (2026-06-13) — the WIT `notify-agent` host
//! function handler + [`HostRegistry`] registration for MODULE-006.
//!
//! This is the first `register_*` host-fn entry point in `crates/messaging/src`
//! (the `reply-tracker` sub-crate already ships its own `await-replies` /
//! `heartbeat` handlers). It is a thin Val encode/decode bridge over the
//! already-shipped `MailboxDispatcherImpl::notify_agent`
//! (`dispatcher.rs:568-582` → shared `deliver_notify`): the dispatcher does all
//! the work (Layer-1 circuit-breaker gate → context byte-cap → target existence
//! → MessageKind classification → mailbox enqueue → the §3.8 (c) `MsgError →
//! NotifyError` 4-variant collapse); this handler only lifts the 3 WIT params,
//! derives the sender from the authenticated [`HostCallContext`], and lowers the
//! `Result<(), NotifyError>` onto the WIT `result<_, notify-error>`.
//!
//! ## WIT signature (`crates/runtime/wit/advance.wit:639-640`)
//!
//! ```wit
//! notify-agent: func(agent-id: string, payload: list<u8>, context: option<message-context>)
//!     -> result<_, notify-error>;
//! ```
//!
//! **The WIT `agent-id` param is the TARGET, not the sender.** The WIT signature
//! has no `from`; the sender is derived from [`HostCallContext::agent_id`] (the
//! authenticated caller stamped by the Wasmtime `CapabilityInjector`). For the
//! SYS-J-55 system→agent bypass the runnable composition root stamps notify
//! handler calls as `ctx.agent_id == "system"` while preserving the component id
//! for capability gates; a `component:`-shaped sender would be rejected by
//! [`crate::is_safe_id`] inside the dispatcher (→ `InvalidTarget("invalid_id")`).
//!
//! ## NotifyError — canonical 4-variant, name-keyed lowering
//!
//! `encode_notify_error` maps the §2.3 canonical 4-variant
//! [`NotifyError`] onto the WIT `notify-error` arms
//! (`invalid-target(string)` / `mailbox-full` / `capability-denied(string)` /
//! `identity-unknown(string)`, `advance.wit:632-637`). NO 5-variant shape (no
//! `circuit-breaker-open`, no `invalid-context`) — the 2026-06-12 `/spec`
//! MODULE-006 doc-drift rerun settled the 4-variant set as canonical;
//! breaker-open already arrives as `CapabilityDenied("breaker_open")` from the
//! dispatcher, so it is passed through. Wasmtime's dynamic [`Val::Variant`]
//! lowering resolves the arm by case-NAME, so the load-bearing CONTRACT-050
//! binding is that each emitted case-name byte-matches its WIT arm — guarded by
//! the in-crate unit test below (the WIT-source side is independently pinned by
//! `tests/wit_notify_presence.rs`).
//!
//! ## PII discipline
//!
//! The `NotifyError` inner strings the dispatcher produces are invariant
//! identifiers (`target_unknown` / `breaker_open`) — never guest target/payload
//! bytes. The only string this handler synthesizes is the decode-failure echo,
//! which is bounded + control-stripped via `sanitize_decode_error` before being
//! projected into a guest-visible `InvalidTarget("decode-failed:...")`.
//!
//! ## Scope — `notify-agent` + `notify-channel` handlers
//!
//! [`register_notify_host_fns`] registers `notify-agent`. Wave-18 Lane-3 adds
//! [`NotifyChannelHandler`] + [`register_notify_channel_host_fn`] for the WIT
//! `notify-channel` method (over the narrow [`ChannelNotifier`] port — see
//! `dispatcher.rs` for why `notify_channel` stays off CONTRACT-051). The default
//! registration helpers remain byte-identical and unscanned; the
//! `*_with_leak_detector` helpers are the production composition-root entry
//! points for the NotifyOutbound leak-scan leg.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use advance_shared_types::mailbox::{MessageContext, NotifyError};
use advance_shared_types::security_validator::{ScanContext, ScanResult};
use advance_shared_types::traits::LeakDetector;
use wasmtime::component::Val;

use crate::dispatcher::{ChannelNotifier, MailboxDispatcher};
use crate::id_validation::MAX_ID_BYTES;
use crate::mailbox::MAX_PAYLOAD_BYTES;

/// Capability string the `notify-agent` spec is registered under. `"messaging"`
/// is shared with the `reply-tracker` `agent-messaging` host fns for grant-model
/// continuity; the distinct namespace ([`NOTIFY_NAMESPACE`]) keeps the
/// `(namespace, name)` linker key collision-free. Pinned in a test (the cli
/// linker lookup must agree).
pub const NOTIFY_CAPABILITY: &str = "messaging";

/// Namespace for the `notify-agent` spec — the WIT `interface notify`
/// (`advance:runtime/notify@0.1.0`), distinct from the `agent-messaging`
/// namespace used by `reply-tracker`. Pinned in a test.
pub const NOTIFY_NAMESPACE: &str = "advance:runtime/notify@0.1.0";

/// Sanitize attacker-supplied decoder error text before projecting it into a
/// guest-visible WIT error: strip ASCII control chars (defang log-injection) and
/// truncate to a bounded length (defang echo-channel amplification). Mirrors the
/// `reply-tracker` `sanitize_decode_error` discipline (`host_fn.rs:86-93`).
fn sanitize_decode_error(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control()).take(256).collect()
}

/// `notify-agent` WIT host-fn handler. Holds an `Arc<dyn MailboxDispatcher>`
/// (the handler only needs the `notify_agent` trait method); the concrete
/// [`crate::MailboxDispatcherImpl`] is built + configured
/// (`with_circuit_breaker_bus` / `with_event_bus`) before the unsizing coercion.
pub struct NotifyAgentHandler {
    dispatcher: Arc<dyn MailboxDispatcher>,
    /// Wave-20 (MODULE-012-AC-19 NotifyOutbound leg): optional [`LeakDetector`]
    /// applied to the decoded notify `payload` under
    /// [`ScanContext::NotifyOutbound`] before delegation. `None` (default) → no
    /// scan (byte-identical); production wiring injects the live detector.
    leak_detector: Option<Arc<dyn LeakDetector>>,
}

impl NotifyAgentHandler {
    pub fn new(dispatcher: Arc<dyn MailboxDispatcher>) -> Self {
        Self {
            dispatcher,
            leak_detector: None,
        }
    }

    /// Wave-20 opt-in builder — wire a [`LeakDetector`] so the notify `payload`
    /// is scanned under [`ScanContext::NotifyOutbound`] before delivery
    /// (MODULE-012-AC-19 NotifyOutbound leg). Additive; `new()` stays unscanned.
    pub fn with_leak_detector(mut self, detector: Arc<dyn LeakDetector>) -> Self {
        self.leak_detector = Some(detector);
        self
    }
}

/// Wave-20 (MODULE-012-AC-19 NotifyOutbound leg): scan the notify `payload` (the
/// notify host function's outbound message content — scan-point 4 "payload before
/// delivery") under [`ScanContext::NotifyOutbound`] before the dispatcher
/// delegation. Returns the (possibly redacted) payload, or a [`NotifyError`] when
/// content is BLOCKED (the error carries NO payload bytes — guest/log safety).
/// `None` detector → `payload` unchanged (byte-identical for the legacy
/// registration helpers).
fn scan_notify_outbound(
    detector: &Option<Arc<dyn LeakDetector>>,
    payload: Vec<u8>,
) -> Result<Vec<u8>, NotifyError> {
    let Some(detector) = detector else {
        return Ok(payload);
    };
    match detector.scan(
        &String::from_utf8_lossy(&payload),
        ScanContext::NotifyOutbound,
    ) {
        ScanResult::Blocked { .. } => Err(NotifyError::InvalidTarget(
            "notify payload withheld by NotifyOutbound leak scan".to_string(),
        )),
        ScanResult::Redacted { redacted, .. } => Ok(redacted.into_bytes()),
        ScanResult::Clean | ScanResult::Warned { .. } => Ok(payload),
    }
}

impl HostFunctionHandler for NotifyAgentHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        // Clone the Arc into the async block; `&self` cannot outlive `call()`
        // (mirrors reply-tracker host_fn.rs:139).
        let dispatcher = Arc::clone(&self.dispatcher);
        let leak_detector = self.leak_detector.clone();
        Box::pin(async move {
            // Step 1: decode the 3 WIT params (or return the decode-failed Err arm,
            // sanitized).
            let (target, payload, context) = match decode_notify_agent_params(&params) {
                Ok(d) => d,
                Err(e) => {
                    return Ok(vec![encode_notify_error(&NotifyError::InvalidTarget(
                        format!("decode-failed:{}", sanitize_decode_error(&e)),
                    ))])
                }
            };
            // Step 1b (Wave-20, MODULE-012-AC-19 NotifyOutbound leg): scan the
            // decoded payload BEFORE delivery; Block returns a NotifyError (no
            // payload bytes), Redact masks in place. `None` detector → unchanged.
            let payload = match scan_notify_outbound(&leak_detector, payload) {
                Ok(p) => p,
                Err(e) => return Ok(vec![encode_notify_error(&e)]),
            };
            // Step 2: the sender derives from the authenticated HostCallContext,
            // NOT a WIT param. The dispatcher re-runs `is_safe_id(from)`.
            let from = ctx.agent_id;
            // Step 3: delegate to the already-built dispatcher path.
            let result = dispatcher
                .notify_agent(&from, &target, payload, context)
                .await;
            // Step 4: lower onto the WIT `result<_, notify-error>`.
            Ok(vec![match result {
                Ok(()) => Val::Result(Ok(None)),
                Err(e) => encode_notify_error(&e),
            }])
        })
    }
}

/// `notify-channel` WIT host-fn handler (Wave-18 Lane-3, MODULE-006-AC-02
/// infra). Holds an `Arc<dyn ChannelNotifier>` — the narrow additive port over
/// the inherent [`crate::MailboxDispatcherImpl::notify_channel`] (kept off
/// CONTRACT-051; see `dispatcher.rs`). Mirrors [`NotifyAgentHandler`]: a thin
/// Val encode/decode bridge that lifts the 4 WIT params, derives the sender from
/// the authenticated [`HostCallContext`], delegates to the dispatcher, and lowers
/// `Result<(), NotifyError>` onto the WIT `result<_, notify-error>`.
///
/// ## WIT signature (`crates/runtime/wit/advance.wit`)
///
/// ```wit
/// notify-channel: func(channel-id: string, user-id: string, payload: list<u8>,
///     context: option<message-context>) -> result<_, notify-error>;
/// ```
///
/// Unlike `notify-agent`, `notify-channel` has TWO leading string params
/// (`channel-id` then `user-id`); like `notify-agent` it has no `from` — the
/// sender is derived from [`HostCallContext::agent_id`].
pub struct NotifyChannelHandler {
    notifier: Arc<dyn ChannelNotifier>,
    /// Wave-20 (MODULE-012-AC-19 NotifyOutbound leg): optional [`LeakDetector`]
    /// scanning the decoded notify `payload` under [`ScanContext::NotifyOutbound`]
    /// before delegation. `None` (default) → no scan (byte-identical); production
    /// wiring injects the live detector.
    leak_detector: Option<Arc<dyn LeakDetector>>,
}

impl NotifyChannelHandler {
    pub fn new(notifier: Arc<dyn ChannelNotifier>) -> Self {
        Self {
            notifier,
            leak_detector: None,
        }
    }

    /// Wave-20 opt-in builder — wire a [`LeakDetector`] so the notify `payload`
    /// is scanned under [`ScanContext::NotifyOutbound`] before delivery. Additive.
    pub fn with_leak_detector(mut self, detector: Arc<dyn LeakDetector>) -> Self {
        self.leak_detector = Some(detector);
        self
    }
}

impl HostFunctionHandler for NotifyChannelHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let notifier = Arc::clone(&self.notifier);
        let leak_detector = self.leak_detector.clone();
        Box::pin(async move {
            // Step 1: decode the 4 WIT params (or return the sanitized decode-failed
            // Err arm).
            let (channel_id, user_id, payload, context) =
                match decode_notify_channel_params(&params) {
                    Ok(d) => d,
                    Err(e) => {
                        return Ok(vec![encode_notify_error(&NotifyError::InvalidTarget(
                            format!("decode-failed:{}", sanitize_decode_error(&e)),
                        ))])
                    }
                };
            // Step 1b (Wave-20, MODULE-012-AC-19 NotifyOutbound leg): scan the
            // decoded payload BEFORE delivery (no payload bytes leak on Block).
            let payload = match scan_notify_outbound(&leak_detector, payload) {
                Ok(p) => p,
                Err(e) => return Ok(vec![encode_notify_error(&e)]),
            };
            // Step 2: the sender derives from the authenticated HostCallContext.
            // The dispatcher re-runs `is_safe_id(from)`.
            let from = ctx.agent_id;
            // Step 3: delegate to the inherent notify_channel via the ChannelNotifier port.
            let result = notifier
                .notify_channel(&from, &channel_id, &user_id, payload, context)
                .await;
            // Step 4: lower onto the WIT `result<_, notify-error>`.
            Ok(vec![match result {
                Ok(()) => Val::Result(Ok(None)),
                Err(e) => encode_notify_error(&e),
            }])
        })
    }
}

// ════════════════════════════════════════════════════════════════════════
// Decoders
// ════════════════════════════════════════════════════════════════════════

/// Decode `notify-channel` WIT params: `(channel-id: string, user-id: string,
/// payload: list<u8>, context: option<message-context>)`. Reuses the same
/// bounded decoders as [`decode_notify_agent_params`].
///
/// **Two-tier payload cap (by design).** `decode_byte_list` bounds the
/// `Vec<u8>` materialization at `MAX_PAYLOAD_BYTES` (1 MiB) — the SAME
/// allocation ceiling as the shipped `notify-agent` decoder, so notify-channel
/// is no looser than the existing path. The *tighter*
/// `MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES` envelope cap is then enforced inside the
/// inherent `MailboxDispatcherImpl::notify_channel` (pre-encode fast-path + hard
/// post-encode check) — an ADDITIONAL protection notify-agent does not even have.
/// The worst-case transient allocation between the two caps is therefore bounded
/// at the universal 1 MiB ceiling (not unbounded); the guest-supplied `Val::List`
/// is already materialized by Wasmtime before this handler runs, so the decode
/// walk adds no allocation Wasmtime had not already bounded.
///
/// Begins with an explicit arity guard so a short/empty `params` slice can never
/// reach an out-of-bounds index (a guest-reachable host panic).
pub(crate) fn decode_notify_channel_params(
    params: &[Val],
) -> Result<(String, String, Vec<u8>, Option<MessageContext>), String> {
    if params.len() != 4 {
        return Err(format!(
            "notify-channel expects 4 params (channel-id, user-id, payload, context), got {}",
            params.len()
        ));
    }
    let channel_id = decode_bounded_string(&params[0], "channel-id", MAX_ID_BYTES)?;
    let user_id = decode_bounded_string(&params[1], "user-id", MAX_ID_BYTES)?;
    let payload = decode_byte_list(&params[2], "payload")?;
    let context = decode_option_message_context(&params[3], "context")?;
    Ok((channel_id, user_id, payload, context))
}

/// Decode `notify-agent` WIT params: `(agent-id: string, payload: list<u8>,
/// context: option<message-context>)`. The `agent-id` param is the TARGET.
///
/// Begins with an explicit arity guard so a short/empty `params` slice can never
/// reach an out-of-bounds index (a guest-reachable host panic) — it routes to the
/// decode-failed path instead (mirrors reply-tracker host_fn.rs:301-306).
pub(crate) fn decode_notify_agent_params(
    params: &[Val],
) -> Result<(String, Vec<u8>, Option<MessageContext>), String> {
    if params.len() != 3 {
        return Err(format!(
            "notify-agent expects 3 params (agent-id, payload, context), got {}",
            params.len()
        ));
    }
    let target = decode_bounded_string(&params[0], "agent-id", MAX_ID_BYTES)?;
    let payload = decode_byte_list(&params[1], "payload")?;
    let context = decode_option_message_context(&params[2], "context")?;
    Ok((target, payload, context))
}

/// Bounded string decode — enforces a per-field max-byte cap at the decode layer,
/// BEFORE allocating the owned `String`. The dispatcher re-validates `target`
/// shape/length via `is_safe_id`; this is the upstream lifter-allocation bound.
fn decode_bounded_string(val: &Val, field: &str, max_bytes: usize) -> Result<String, String> {
    match val {
        Val::String(s) => {
            if s.len() > max_bytes {
                return Err(format!(
                    "{field}: string length {} exceeds bound {}",
                    s.len(),
                    max_bytes
                ));
            }
            Ok(s.clone())
        }
        other => Err(format!("{field}: expected string, got {other:?}")),
    }
}

/// Decode `list<u8>` → `Vec<u8>`. Bounds the list length at `MAX_PAYLOAD_BYTES`
/// BEFORE the per-element walk (each `Val::U8` wrapper is ~24 bytes, so an
/// unbounded list would amplify upstream lifter memory). Mirrors reply-tracker
/// `decode_byte_list_field` (host_fn.rs:568-595).
fn decode_byte_list(val: &Val, field: &str) -> Result<Vec<u8>, String> {
    match val {
        Val::List(items) => {
            if items.len() > MAX_PAYLOAD_BYTES {
                return Err(format!(
                    "{field}: list length {} exceeds MAX_PAYLOAD_BYTES {}",
                    items.len(),
                    MAX_PAYLOAD_BYTES
                ));
            }
            items
                .iter()
                .map(|v| match v {
                    Val::U8(b) => Ok(*b),
                    other => Err(format!("{field}: expected list<u8>, got element {other:?}")),
                })
                .collect()
        }
        other => Err(format!("{field}: expected list<u8>, got {other:?}")),
    }
}

/// Decode `option<message-context>`. The WIT `message-context` is the 3-field
/// subset `{task-id, run-id, execution-id}` (`advance.wit:630` `use
/// agent-messaging.{message-context}`); the other 3 Rust [`MessageContext`]
/// fields (`trace_id` / `in_reply_to` / `correlation_id`) are runtime-internal
/// and default to `None` on decode. Mirrors reply-tracker
/// `decode_option_message_context_field` (host_fn.rs:431-457).
fn decode_option_message_context(val: &Val, field: &str) -> Result<Option<MessageContext>, String> {
    match val {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => {
            let ctx_fields = match inner.as_ref() {
                Val::Record(fields) => fields,
                other => {
                    return Err(format!(
                        "{field}: expected message-context record, got {other:?}"
                    ))
                }
            };
            let task_id = decode_option_string_field(ctx_fields, "task-id")?;
            let run_id = decode_option_string_field(ctx_fields, "run-id")?;
            let execution_id = decode_option_string_field(ctx_fields, "execution-id")?;
            Ok(Some(MessageContext {
                task_id,
                run_id,
                execution_id,
                trace_id: None,
                in_reply_to: None,
                correlation_id: None,
            }))
        }
        other => Err(format!("{field}: expected option, got {other:?}")),
    }
}

fn lookup_field<'a>(fields: &'a [(String, Val)], name: &str) -> Result<&'a Val, String> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .ok_or_else(|| format!("missing field {name:?}"))
}

fn decode_option_string_field(
    fields: &[(String, Val)],
    field: &str,
) -> Result<Option<String>, String> {
    match lookup_field(fields, field)? {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => match inner.as_ref() {
            Val::String(s) => Ok(Some(s.clone())),
            other => Err(format!("{field}: expected option<string>, got {other:?}")),
        },
        other => Err(format!("{field}: expected option<string>, got {other:?}")),
    }
}

// ════════════════════════════════════════════════════════════════════════
// Encoder
// ════════════════════════════════════════════════════════════════════════

/// Encode the §2.3 canonical 4-variant [`NotifyError`] as the WIT
/// `result<_, notify-error>::Err`. Case-names byte-match the WIT arms
/// (`advance.wit:632-637`) and the variant order matches the Rust enum so the
/// WIT ordinals align — though the dynamic `Val::Variant` path is name-keyed, so
/// the case-NAME spelling is what is load-bearing. `mailbox-full` carries no
/// payload; the other three carry their invariant-identifier string. Mirrors the
/// reply-tracker `encode_msg_error` shape (host_fn.rs:730-754).
pub(crate) fn encode_notify_error(err: &NotifyError) -> Val {
    let (case, payload): (&str, Option<Box<Val>>) = match err {
        NotifyError::InvalidTarget(s) => ("invalid-target", Some(Box::new(Val::String(s.clone())))),
        NotifyError::MailboxFull => ("mailbox-full", None),
        NotifyError::CapabilityDenied(s) => {
            ("capability-denied", Some(Box::new(Val::String(s.clone()))))
        }
        NotifyError::IdentityUnknown(s) => {
            ("identity-unknown", Some(Box::new(Val::String(s.clone()))))
        }
    };
    Val::Result(Err(Some(Box::new(Val::Variant(case.to_string(), payload)))))
}

// ════════════════════════════════════════════════════════════════════════
// Registration
// ════════════════════════════════════════════════════════════════════════

/// Register the single `notify-agent` [`HostFunctionSpec`] into `registry` under
/// capability [`NOTIFY_CAPABILITY`] (`"messaging"`) and namespace
/// [`NOTIFY_NAMESPACE`] (`"advance:runtime/notify@0.1.0"`).
///
/// `idempotent: false` — `notify-agent` is state-modifying (it enqueues a mailbox
/// message), matching `reply-tracker`'s `await-replies` posture (NOT `heartbeat`,
/// which is idempotent).
///
/// **Registers ONLY `notify-agent`.** The WIT `notify` interface also declares
/// `notify-channel`, whose handler is [`register_notify_channel_host_fn`] (built
/// Wave-18 Lane-3 — registered separately, not by this fn). Registration is at the
/// [`HostRegistry`] data layer only — no WIT-world `import notify` is added
/// (preserves the MODULE-001-T42 invariant).
///
/// **Cross-registration**: capability `"messaging"` is shared with
/// `register_reply_tracker_host_fns`. `lookup("messaging")` in a full composition
/// root returns 3 specs (await-replies + heartbeat + notify-agent), non-colliding
/// because the `(namespace, name)` linker keys differ; the future
/// `CapabilityInjector::inject` is the duplicate gate.
pub fn register_notify_host_fns(
    registry: &dyn HostRegistry,
    dispatcher: Arc<dyn MailboxDispatcher>,
) {
    register_notify_host_fns_with_leak_detector(registry, dispatcher, None);
}

pub fn register_notify_host_fns_with_leak_detector(
    registry: &dyn HostRegistry,
    dispatcher: Arc<dyn MailboxDispatcher>,
    leak_detector: Option<Arc<dyn LeakDetector>>,
) {
    let mut handler = NotifyAgentHandler::new(dispatcher);
    if let Some(detector) = leak_detector {
        handler = handler.with_leak_detector(detector);
    }
    registry.register(HostFunctionSpec {
        capability: NOTIFY_CAPABILITY.to_string(),
        namespace: NOTIFY_NAMESPACE.to_string(),
        name: "notify-agent".to_string(),
        handler: Arc::new(handler),
        idempotent: false,
    });
}

/// Register the single `notify-channel` [`HostFunctionSpec`] (Wave-18 Lane-3)
/// into `registry` under capability [`NOTIFY_CAPABILITY`] (`"messaging"`) and
/// namespace [`NOTIFY_NAMESPACE`] (`"advance:runtime/notify@0.1.0"`), name
/// `notify-channel`. `idempotent: false` (state-modifying — it enqueues a
/// channel-delivery mailbox message), matching `notify-agent`.
///
/// Takes an `Arc<dyn ChannelNotifier>` (the narrow port over the inherent
/// `MailboxDispatcherImpl::notify_channel`), distinct from
/// [`register_notify_host_fns`]'s `Arc<dyn MailboxDispatcher>`.
///
/// Production CLI wiring now registers this beside `notify-agent` when
/// `messaging` is declared, sharing the same dispatcher, id bridge, mailbox store,
/// and live NotifyOutbound leak detector. The `(namespace, name)` linker key
/// (`notify` interface, `notify-channel`) differs from `notify-agent`, so both
/// may be registered side-by-side without collision.
pub fn register_notify_channel_host_fn(
    registry: &dyn HostRegistry,
    notifier: Arc<dyn ChannelNotifier>,
) {
    register_notify_channel_host_fn_with_leak_detector(registry, notifier, None);
}

pub fn register_notify_channel_host_fn_with_leak_detector(
    registry: &dyn HostRegistry,
    notifier: Arc<dyn ChannelNotifier>,
    leak_detector: Option<Arc<dyn LeakDetector>>,
) {
    let mut handler = NotifyChannelHandler::new(notifier);
    if let Some(detector) = leak_detector {
        handler = handler.with_leak_detector(detector);
    }
    registry.register(HostFunctionSpec {
        capability: NOTIFY_CAPABILITY.to_string(),
        namespace: NOTIFY_NAMESPACE.to_string(),
        name: "notify-channel".to_string(),
        handler: Arc::new(handler),
        idempotent: false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert `encode_notify_error(err)` lowers to
    /// `Val::Result(Err(Some(Variant(<case>, <payload>))))`.
    fn assert_encoded(err: NotifyError, case: &str, payload: Option<&str>) {
        match encode_notify_error(&err) {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(got_case, got_payload) => {
                    assert_eq!(got_case, case, "variant case-name mismatch");
                    match (got_payload.as_deref(), payload) {
                        (None, None) => {}
                        (Some(Val::String(s)), Some(exp)) => assert_eq!(s.as_str(), exp),
                        (got, exp) => {
                            panic!("{case}: payload mismatch got={got:?} expected={exp:?}")
                        }
                    }
                }
                other => panic!("{case}: expected Variant, got {other:?}"),
            },
            other => panic!("{case}: expected Result(Err(Some(Variant))), got {other:?}"),
        }
    }

    /// TN-09 — `encode_notify_error` 4-variant case-name + payload-shape pin
    /// (CONTRACT-050 encoder-side drift guard). `identity-unknown` is never
    /// produced by the dispatcher, so this is its only encoder→WIT binding
    /// witness; the WIT-source side is pinned by `tests/wit_notify_presence.rs`.
    #[test]
    fn tn09_encode_notify_error_variant_spellings() {
        assert_encoded(
            NotifyError::InvalidTarget("target_unknown".into()),
            "invalid-target",
            Some("target_unknown"),
        );
        assert_encoded(NotifyError::MailboxFull, "mailbox-full", None);
        assert_encoded(
            NotifyError::CapabilityDenied("breaker_open".into()),
            "capability-denied",
            Some("breaker_open"),
        );
        assert_encoded(
            NotifyError::IdentityUnknown("ident".into()),
            "identity-unknown",
            Some("ident"),
        );
    }

    // ── TN-10: NotifyChannelHandler decode + delegate + lower ──────────────

    /// Recording [`ChannelNotifier`] stub — captures the args the handler
    /// forwards and returns a configurable result. Lets TN-10 assert the
    /// handler (a) decodes the 4 WIT params correctly, (b) derives `from` from
    /// `ctx.agent_id`, and (c) lowers the notifier's `Result` faithfully —
    /// WITHOUT a real dispatcher/store.
    struct RecordingChannelNotifier {
        seen: std::sync::Mutex<Option<(String, String, String, Vec<u8>)>>,
        result: Result<(), NotifyError>,
    }

    #[async_trait::async_trait]
    impl ChannelNotifier for RecordingChannelNotifier {
        async fn notify_channel(
            &self,
            from: &str,
            channel_id: &str,
            user_id: &str,
            payload: Vec<u8>,
            _context: Option<MessageContext>,
        ) -> Result<(), NotifyError> {
            *self.seen.lock().unwrap() = Some((
                from.to_string(),
                channel_id.to_string(),
                user_id.to_string(),
                payload,
            ));
            self.result.clone()
        }
    }

    fn ctx_for(agent_id: &str) -> HostCallContext {
        HostCallContext {
            agent_id: agent_id.into(),
            trace_id: "t".into(),
            turn_id: None,
            capability: NOTIFY_CAPABILITY.into(),
            function: "advance:runtime/notify::notify-channel".into(),
            run_id: None,
            iteration: None,
        }
    }

    fn notify_channel_params(channel_id: &str, user_id: &str, body: &[u8]) -> Vec<Val> {
        vec![
            Val::String(channel_id.into()),
            Val::String(user_id.into()),
            Val::List(body.iter().map(|b| Val::U8(*b)).collect()),
            Val::Option(None),
        ]
    }

    /// TN-10a — happy path: the handler decodes the 4 params, forwards
    /// `(from=ctx.agent_id, channel_id, user_id, payload)` to the notifier, and
    /// lowers `Ok(())` onto `Val::Result(Ok(None))`.
    #[tokio::test]
    async fn tn10a_notify_channel_handler_decodes_and_delegates() {
        let notifier = Arc::new(RecordingChannelNotifier {
            seen: std::sync::Mutex::new(None),
            result: Ok(()),
        });
        let handler = NotifyChannelHandler::new(notifier.clone());

        let out = handler
            .call(
                ctx_for("user:alice"),
                notify_channel_params("telegram-main", "user:bob", b"hi"),
                0,
            )
            .await
            .expect("handler call should succeed");

        assert_eq!(out, vec![Val::Result(Ok(None))]);
        let seen = notifier.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            Some((
                "user:alice".to_string(), // from = ctx.agent_id, NOT a WIT param
                "telegram-main".to_string(),
                "user:bob".to_string(),
                b"hi".to_vec(),
            )),
            "handler must forward ctx-derived sender + decoded params"
        );
    }

    /// TN-10b — reject lowering: a notifier `Err(InvalidTarget("channel_unknown"))`
    /// (the unknown-channel case) lowers to the WIT
    /// `invalid-target("channel_unknown")` arm (anti-fake-green: the handler does
    /// not swallow rejects into a fake `Ok`).
    #[tokio::test]
    async fn tn10b_notify_channel_handler_lowers_reject() {
        let notifier = Arc::new(RecordingChannelNotifier {
            seen: std::sync::Mutex::new(None),
            result: Err(NotifyError::InvalidTarget("channel_unknown".into())),
        });
        let handler = NotifyChannelHandler::new(notifier);

        let out = handler
            .call(
                ctx_for("user:alice"),
                notify_channel_params("nope", "user:bob", b"x"),
                0,
            )
            .await
            .expect("handler call should succeed (the error is in-band)");

        match &out[0] {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(case, Some(p)) => {
                    assert_eq!(case, "invalid-target");
                    assert_eq!(p.as_ref(), &Val::String("channel_unknown".into()));
                }
                other => panic!("expected invalid-target variant, got {other:?}"),
            },
            other => panic!("expected Result(Err), got {other:?}"),
        }
    }

    /// TN-10c — arity guard: a short `params` slice routes to the sanitized
    /// `decode-failed` Err arm rather than panicking on an out-of-bounds index.
    #[tokio::test]
    async fn tn10c_notify_channel_handler_arity_guard() {
        let notifier = Arc::new(RecordingChannelNotifier {
            seen: std::sync::Mutex::new(None),
            result: Ok(()),
        });
        let handler = NotifyChannelHandler::new(notifier.clone());

        let out = handler
            .call(
                ctx_for("user:alice"),
                vec![Val::String("only-one".into())],
                0,
            )
            .await
            .expect("handler call should succeed (decode error is in-band)");

        match &out[0] {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(case, Some(p)) => {
                    assert_eq!(case, "invalid-target");
                    match p.as_ref() {
                        Val::String(s) => assert!(
                            s.starts_with("decode-failed:"),
                            "expected decode-failed prefix, got {s}"
                        ),
                        other => panic!("expected string payload, got {other:?}"),
                    }
                }
                other => panic!("expected invalid-target variant, got {other:?}"),
            },
            other => panic!("expected Result(Err), got {other:?}"),
        }
        assert!(
            notifier.seen.lock().unwrap().is_none(),
            "notifier must NOT be called on a decode failure"
        );
    }

    /// TN-10d — `register_notify_channel_host_fn` registers the spec under
    /// `(messaging, advance:runtime/notify@0.1.0, notify-channel)`,
    /// `idempotent: false`, non-colliding with `notify-agent`.
    #[test]
    fn tn10d_register_notify_channel_spec() {
        use advance_runtime::host_registry::InMemoryHostRegistry;

        let notifier = Arc::new(RecordingChannelNotifier {
            seen: std::sync::Mutex::new(None),
            result: Ok(()),
        });
        let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
        register_notify_channel_host_fn(&*registry, notifier);

        let specs = registry.lookup(NOTIFY_CAPABILITY);
        let spec = specs
            .iter()
            .find(|s| s.name == "notify-channel")
            .expect("notify-channel spec should be registered");
        assert_eq!(spec.namespace, NOTIFY_NAMESPACE);
        assert!(!spec.idempotent, "notify-channel is state-modifying");
    }
}
