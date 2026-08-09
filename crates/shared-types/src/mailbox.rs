//! MODULE-006 messaging canonical dependency-inversion surface.
//!
//! Canonical source: `docs/modules/MODULE-006-messaging.md` §2.3
//! (Message + MessageKind + MessageContext + MessageOrigin + MsgError +
//! AgentAction + ActionResult + AgentActionDispatcher + DispatchError +
//! MailboxReader).
//!
//! Verbatim hoist — if the owner module's declaration changes, run
//! `/spec MODULE-006` and re-hoist via a follow-on /dev slice.
//!
//! # Security posture
//!
//! - **Oversized payload DoS pre-validator**: [`Message::payload`],
//!   [`AgentAction::payload`], and [`ActionResult::actions`] deserialize to
//!   owned `Vec` allocations BEFORE [`AgentActionDispatcher::dispatch`]
//!   invokes [`crate::security_validator::ActionValidator::validate`].
//!   The deserialize boundary (channel adapter, IPC, JSONL replay) MUST cap
//!   payload bytes (recommended ≤ 1 MiB) and action-vector length
//!   (recommended ≤ 128) BEFORE materializing these types — `deny_unknown_fields`
//!   does not enforce length.
//! - **`MessageOrigin.channel_metadata` unbounded HashMap**: serde accepts
//!   arbitrary entry counts. Callers at the deserialize boundary MUST cap
//!   entries ≤ 32 with values ≤ 256 bytes (recommended per MODULE-006
//!   prose). Downstream trust boundary: a compromised channel adapter
//!   returning a pathological metadata HashMap can exhaust memory in the
//!   mailbox consumer.
//! - **Error payload PII policy**: [`MsgError`] and [`DispatchError`]
//!   `String` payloads flow into operator logs, EventBus JSONL, and
//!   downstream `Display` surfaces. Implementers MUST NOT embed user
//!   content, API-key fragments, agent-private state, or filesystem paths
//!   in these variants. Reason strings SHOULD be short invariant
//!   identifiers.

use crate::security_validator::SecurityError;
use crate::turn_attribution::{
    DequeuedTurnHandle, TurnExecutionError, TurnExecutionLifecyclePort, TurnMailboxError,
    TurnStartOutcome,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// MODULE-006 §2.3:320-332 — message classification enum. Drives
/// priority ordering (Control preempts Auto; User routes to handle-message;
/// System is mailbox-internal).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageKind {
    /// From a human user via CLI, channel adapter, or direct API.
    User,
    /// Inter-agent delivery (parent→child, child→parent, sibling→sibling).
    Agent,
    /// Control-plane messages that preempt ordinary queue order:
    /// pause-run / resume-run / cancel-run / run.interrupted.
    Control,
    /// Auto-mode-injected messages (evaluator outputs, iteration-start prompts).
    Auto,
    /// System notifications (component.spawned, component.terminated, run.completed).
    System,
}

/// MODULE-006 §2.3:334-347 — per-message threading context. All fields
/// inherit from the parent message on reply per PRD §9.2 / REQ-175.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageContext {
    /// Task the message belongs to (inherited on reply from the original message).
    pub task_id: Option<String>,
    /// Run the message belongs to (inherited on reply).
    pub run_id: Option<String>,
    /// Fan-out execution this message fulfills (inherited on reply).
    pub execution_id: Option<String>,
    /// Trace chain id (inherited on reply; see MODULE-019 §1.3.1).
    pub trace_id: Option<String>,
    /// Message id being replied to (threading; None for original sends).
    pub in_reply_to: Option<String>,
    /// Correlation id used by MODULE-007 to resolve AwaitSession + slot on reply.
    pub correlation_id: Option<String>,
}

/// MODULE-006 §2.3:364-385 — origin metadata for channel-adapter-sourced
/// messages. None for agent-to-agent sends. `channel_metadata` is free-form
/// adapter data (thread ids, message refs) passed through on reply.
///
/// **Implementer Invariants**: bounded field lengths (recommended
/// `message_id`/`original_channel`/`original_sender`/`adapter_id` ≤ 256
/// bytes each; `channel_metadata` ≤ 32 entries with values ≤ 256 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageOrigin {
    /// The mailbox-internal message id this origin is keyed by (same value
    /// that appears as `Message.id` in the MessageTrace map).
    pub message_id: String,
    /// Channel adapter that originated the inbound message.
    pub original_channel: String,
    /// Sender identity as reported by the channel before IdentityResolver
    /// normalization (e.g. `telegram:1234567`).
    pub original_sender: String,
    /// Adapter instance id (stable across restarts for a given channel
    /// configuration). Used for reply routing back to the originating adapter.
    pub adapter_id: String,
    /// Free-form adapter metadata (channel-specific thread ids, message refs,
    /// etc.). Not interpreted by messaging; passed through on reply.
    pub channel_metadata: HashMap<String, String>,
    pub received_at: DateTime<Utc>,
    /// Parent's reply-inheritance context (task-id / run-id / execution-id
    /// per PRD §9.2 / REQ-175).
    pub context: Option<MessageContext>,
}

/// MODULE-006 §2.3:349-362 — canonical Message struct. 8 fields matching
/// the runtime Rust form (richer than the WIT v1 minimal `record message
/// { payload: list<u8> }` — the WIT is the projection, this Rust type is
/// the in-runtime canonical).
///
/// **Wire-format note** (Slice AC v2 §3.11): `timestamp: SystemTime` uses
/// default serde encoding (`{secs_since_epoch, nanos_since_epoch}` struct),
/// asymmetric vs `MessageOrigin.received_at: DateTime<Utc>` which encodes
/// as ISO-8601 string. This asymmetry is canonical-by-design per MODULE-006.
///
/// **Implementer Invariants**: bounded `payload` length (recommended ≤ 1 MiB
/// per MODULE-006 prose); bounded `id`/`from`/`to` (recommended ≤ 256 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: String,
    pub kind: MessageKind,
    /// Agent id (`agent:{name}`), user id (`user:{name}`), or system (`system`).
    pub from: String,
    /// Target agent id (`agent:{name}`) — resolved through IdentityResolver.
    pub to: String,
    /// Opaque payload bytes; the target agent's handle-message interprets it.
    pub payload: Vec<u8>,
    pub context: Option<MessageContext>,
    pub timestamp: SystemTime,
    /// Origin metadata (channel adapter id, etc.); None for agent sends.
    pub origin: Option<MessageOrigin>,
}

/// MODULE-006 §2.3:387-393 — mailbox delivery error surface. 5 variants
/// matching MODULE-006's canonical declaration; consumers discriminate on
/// the variant rather than parsing a stringified payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsgError {
    InvalidTarget(String),
    MailboxFull,
    CircuitBreakerOpen(String),
    CapabilityDenied(String),
    InvalidPayload(String),
}

/// Typed control-message payload (MODULE-006 §2.3), serialized via
/// `serde_json` as the [`Message::payload`] of a [`MessageKind::Control`]
/// delivery. Single variant for now — the MODULE-008 crash-recovery →
/// controller-mailbox bridge (SYS-AC-121 / SYS-J-37). Extensible to
/// pause/resume/cancel per the [`MessageKind::Control`] doc.
///
/// Internally tagged (`tag = "control"`) so the discriminant survives the
/// opaque `payload: Vec<u8>` round-trip; `deny_unknown_fields` rejects
/// malformed control payloads. The variant is struct-style (named fields), for
/// which serde supports `deny_unknown_fields` on internally-tagged enums.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "control")]
pub enum ControlMessage {
    /// MODULE-008 crash recovery flipped a Suspended run back to Active and is
    /// notifying its controller agent. `reason` is a short invariant id (e.g.
    /// `"crash-recovery"`), never user content (see the module PII note).
    RunInterrupted { run_id: String, reason: String },
}

/// Dependency-inversion sink (CONTRACT-182; MODULE-006 §2.3) consumed by
/// MODULE-008 crash-recovery. After `recover_on_startup` emits the
/// `run.interrupted` event, it pushes a synthesized [`Message::run_interrupted`]
/// into the controller agent's mailbox through this port. Defined here
/// (co-located with [`MsgError`]) so MODULE-008 can hold an
/// `Arc<dyn RunInterruptSink>` without a compile-time edge to MODULE-006 — the
/// same dependency-inversion posture as [`crate::await_session::AwaitSessionRef`]
/// and [`crate::traits::EventBusEmit`].
///
/// Sync (mirrors the sync `Mailbox::deliver`); the concrete
/// `MailboxRunInterruptSink` (MODULE-006) builds the [`Message`] and delivers
/// it into the controller's `MailboxStore`.
pub trait RunInterruptSink: Send + Sync {
    /// Synthesize + deliver a `Message::RunInterrupted` into the controller
    /// agent's mailbox. Best-effort; returns `Err` on a delivery failure (the
    /// caller logs and continues — recovery never blocks on the sink).
    fn deliver_run_interrupted(
        &self,
        controller_agent: &str,
        run_id: &str,
        task_id: &str,
        reason: &str,
    ) -> Result<(), MsgError>;
}

/// CONTRACT-184 (Wave-19 Lane 3) — `RunCompletionSink` dependency-inverted port.
///
/// Defined here (co-located with [`MsgError`] / [`RunInterruptSink`]) so
/// MODULE-008 `RunManager` can hold an `Arc<dyn RunCompletionSink>` and fire it
/// from `complete_run` **without** a compile-time edge to MODULE-007 — the same
/// dependency-inversion posture as [`RunInterruptSink`],
/// [`crate::await_session::AwaitSessionRef`], and [`crate::traits::EventBusEmit`].
///
/// The provider (MODULE-007 reply-tracker `ComponentResolutionSink`) reacts to a
/// run completing by resolving the matching `await-replies` `ComponentFinished`
/// slot **status-only**: it marks the slot `reply-status::completed` with an
/// EMPTY payload (MODULE-007 §2.3 / PRD §9.2 — the component output is NOT
/// delivered through the AwaitSession; the caller reads `output-dir/result.bin`
/// directly via MODULE-002 agent-fs). The join key is the completed run's
/// `task_id` == the awaited `component_id` (the 1-component==1-run keying).
///
/// Sync (mirrors [`RunInterruptSink`]). MODULE-008 `complete_run` fires it AFTER
/// emitting `run.completed`. Best-effort: an `Err` is logged by the caller and
/// never blocks completion (resolution is fire-and-forget — the concrete
/// provider may spawn the async slot resolution onto the current runtime).
pub trait RunCompletionSink: Send + Sync {
    /// React to a run completing (the awaited component finished). `outcome` is
    /// the `complete_run` outcome label (event/log context only — the slot is
    /// marked `completed` unconditionally per §2.3, never `failed`). Best-effort;
    /// `Err` is logged and ignored by the caller.
    fn on_run_completed(
        &self,
        controller_agent: &str,
        run_id: &str,
        task_id: &str,
        outcome: &str,
    ) -> Result<(), MsgError>;
}

impl Message {
    /// Synthesize a host-originated `Message::RunInterrupted` — `kind = Control`,
    /// `from = "system"`, `to = controller_agent`, `payload =` the
    /// `serde_json`-encoded [`ControlMessage::RunInterrupted`], `context =`
    /// `{task_id, run_id}`, fresh `id`/`timestamp`, `origin = None`. The
    /// MODULE-008 crash-recovery → MODULE-006 controller-mailbox bridge
    /// (SYS-AC-121). Mirrors the dispatcher's host-message construction pattern.
    pub fn run_interrupted(
        controller_agent: &str,
        run_id: &str,
        task_id: &str,
        reason: &str,
    ) -> Message {
        let payload = serde_json::to_vec(&ControlMessage::RunInterrupted {
            run_id: run_id.to_string(),
            reason: reason.to_string(),
        })
        .expect("ControlMessage::RunInterrupted serialization is infallible");
        Message {
            id: uuid::Uuid::new_v4().to_string(),
            kind: MessageKind::Control,
            from: "system".to_string(),
            to: controller_agent.to_string(),
            payload,
            // MessageContext has no Default derive — full 6-field literal.
            context: Some(MessageContext {
                task_id: Some(task_id.to_string()),
                run_id: Some(run_id.to_string()),
                execution_id: None,
                trace_id: None,
                in_reply_to: None,
                correlation_id: None,
            }),
            timestamp: SystemTime::now(),
            origin: None,
        }
    }
}

#[cfg(test)]
mod run_interrupted_tests {
    use super::*;

    // RI-U1 — ctor field shape + ControlMessage serde round-trip (the
    // anti-fake-green decode the witness/harvest depend on).
    #[test]
    fn run_interrupted_ctor_and_control_message_roundtrip() {
        let msg = Message::run_interrupted("agent:controller", "run-7", "task-1", "crash-recovery");

        // Envelope shape.
        assert_eq!(
            msg.kind,
            MessageKind::Control,
            "RunInterrupted is a Control message"
        );
        assert_eq!(msg.from, "system");
        assert_eq!(msg.to, "agent:controller");
        assert!(
            msg.origin.is_none(),
            "host-originated control message carries no origin"
        );
        assert!(!msg.id.is_empty());
        let ctx = msg.context.as_ref().expect("context populated");
        assert_eq!(ctx.run_id.as_deref(), Some("run-7"));
        assert_eq!(ctx.task_id.as_deref(), Some("task-1"));

        // Payload decodes back to the exact ControlMessage.
        let decoded: ControlMessage =
            serde_json::from_slice(&msg.payload).expect("payload decodes as ControlMessage");
        assert_eq!(
            decoded,
            ControlMessage::RunInterrupted {
                run_id: "run-7".to_string(),
                reason: "crash-recovery".to_string(),
            }
        );

        // Internally-tagged wire shape (the `tag = "control"` discriminant).
        let json = serde_json::to_string(&ControlMessage::RunInterrupted {
            run_id: "r".to_string(),
            reason: "x".to_string(),
        })
        .unwrap();
        assert!(
            json.contains("\"control\":\"RunInterrupted\""),
            "got: {json}"
        );
    }

    // RI-U2 — deny_unknown_fields rejects a malformed control payload.
    #[test]
    fn control_message_rejects_unknown_fields() {
        let bad = r#"{"control":"RunInterrupted","run_id":"r","reason":"x","extra":1}"#;
        assert!(
            serde_json::from_str::<ControlMessage>(bad).is_err(),
            "deny_unknown_fields must reject an extra field"
        );
    }

    // RC-U1 (CONTRACT-184) — RunCompletionSink is object-safe and callable
    // through `Arc<dyn ...>` (the same object-safety guard RunInterruptSink
    // relies on at its use-site; status-only port, so no Message/serde
    // roundtrip — a trait-impl-and-call smoke test).
    #[test]
    fn run_completion_sink_object_safe_and_callable() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingSink(Arc<AtomicUsize>);
        impl RunCompletionSink for CountingSink {
            fn on_run_completed(
                &self,
                controller_agent: &str,
                run_id: &str,
                task_id: &str,
                _outcome: &str,
            ) -> Result<(), MsgError> {
                // Status-only port: the args are the run identity; no payload.
                assert_eq!(controller_agent, "agent:ctrl");
                assert_eq!(run_id, "run-1");
                assert_eq!(task_id, "comp-1");
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let sink: Arc<dyn RunCompletionSink> = Arc::new(CountingSink(Arc::clone(&calls)));
        let r = sink.on_run_completed("agent:ctrl", "run-1", "comp-1", "done");
        assert!(r.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

/// MODULE-006 §2.3:483-488 — notify host-fn delivery error surface.
/// Canonical **4-variant** Rust shape (hoisted verbatim from MODULE-006 §2.3).
///
/// NOTE — §1.3.1 drift: the MODULE-006 §1.3.1 WIT pseudocode shows a divergent
/// 5-variant shape (`not-found` / `capability-denied` / `mailbox-full` /
/// `invalid-context` / `circuit-breaker-open`). §2.3 is the canonical authority
/// (same precedence as the slice-A §1.3.1 `mailbox-full(string)` drift). The
/// §1.3.1 ↔ §2.3 reconciliation is deferred to a `/spec MODULE-006` rerun
/// (MODULE-006 §3.6). The separate cap-channel-local
/// `notify_policy::NotifyError` (5-variant) is MODULE-016-owned and is a
/// documented cross-module divergence, not this type.
///
/// PII discipline (mirrors [`MsgError`]): the inner `String` payloads are
/// short invariant identifiers — never user content, agent-private state,
/// API-key fragments, or filesystem paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotifyError {
    /// Target/channel/context rejected — unknown target agent, channel-registry
    /// miss, bad id shape, empty/oversized/progress-leaking context. The §2.3
    /// model's catch-all for "request is malformed or unroutable".
    InvalidTarget(String),
    /// Target mailbox at capacity (backpressure).
    MailboxFull,
    /// Caller lacks the notify capability, or the target's circuit breaker is
    /// open (`"breaker_open"`).
    CapabilityDenied(String),
    /// IdentityResolver has no mapping for an INBOUND sender. NOT produced by
    /// `notify_agent` / `notify_channel` (they do not perform inbound identity
    /// resolution — that is the future inbound host_fn path). Hoisted for
    /// canonical completeness; slice-B code paths never construct it.
    IdentityUnknown(String),
}

/// MODULE-006 notify-channel outbound envelope. Serialized as the [`Message`]
/// payload delivered to the channel-adapter agent's mailbox; the adapter
/// decodes it to learn the target user + body. Declared here (canonical home,
/// alongside the other hoisted MODULE-006 types) so future adapter consumers
/// share one schema. A future `/spec MODULE-006` may project this to a WIT
/// record (MODULE-006 §3.6).
///
/// `Message.origin` stays `None` for a notify-channel send (it is a fresh
/// agent→adapter outbound, NOT inbound provenance) — the routing data lives
/// in this envelope, not in a forged `MessageOrigin`.
///
/// `user_id` is the **unified identity** (`user:alice` form), symmetric with
/// the IdentityResolver inbound normalization (channel-native → unified). It
/// is NOT a channel-native handle (`telegram:1234567`); the receiving
/// channel adapter reverse-resolves the unified id to its channel-native
/// recipient. `notify_channel` enforces the `user:` prefix. MODULE-006
/// §3.8 (b) records the unified-form rationale.
///
/// **Encoding note**: `notify_channel` serializes this via `serde_json`,
/// which encodes `body: Vec<u8>` as a JSON decimal-number array (worst case
/// `[255,255,…]` = `4N + 1` chars for `N` bytes). `notify_channel` enforces
/// the envelope ≤ `MAX_PAYLOAD_BYTES` invariant via TWO checks: (1) a
/// FAST-PATH raw-`payload.len()` pre-cap at
/// `MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES` (= `(MAX_PAYLOAD_BYTES − reserved
/// skeleton+id overhead) / 4`, with `channel_id`/`user_id` bounded at
/// `MAX_ID_BYTES`) that rejects gross over-size before the encode (no ~4×
/// transient-alloc amplification); and (2) the HARD guarantee — an exact
/// post-encode `envelope.len() > MAX_PAYLOAD_BYTES` check that returns the
/// clear `payload_too_large` *before* delivery (so the envelope handed to
/// the mailbox can never exceed the cap, and the caller never sees the
/// confusing post-deliver error). A future slice may swap to a compact
/// byte encoding / WIT record so the ceiling matches `notify_agent`
/// (MODULE-006 §3.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelDelivery {
    pub channel_id: String,
    pub user_id: String,
    pub body: Vec<u8>,
}

/// MODULE-006 §2.3:420-422 — agent-emitted action record. v1 minimal shape
/// matches WIT `record action { payload: list<u8> }`. The concrete action
/// kind (send-message, reply, fs.write, tool-invoke, grant-request, …) is
/// encoded inside `payload` — serialization is MODULE-006 internal.
///
/// Named `AgentAction` (NOT `Action`) to disambiguate from MODULE-012's
/// `pub enum Action { Block, Redact, Warn }` LeakDetector response enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAction {
    pub payload: Vec<u8>,
}

/// MODULE-006 §2.3:429-437 — guest-produced handle-message return record.
/// Delivered to MODULE-014 AgentLoopDriver which forwards `actions` to
/// [`AgentActionDispatcher::dispatch`] and the full record to
/// `PostProcessorHook::run` (MODULE-011).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResult {
    /// New agent state bytes — opaque to the host, guest controls format.
    /// Persisted as the agent's rehydrated `state: list<u8>` for the next
    /// `handle-message` call.
    pub new_state: Vec<u8>,
    /// Outbound actions to dispatch (post-validation) after this turn returns.
    /// MUST be processed in order.
    pub actions: Vec<AgentAction>,
}

/// MODULE-006 §2.3:459-481 — dispatch error surface. Variants disambiguate
/// validator rejection (before any delivery), mailbox-delivery failure
/// (carries [`MsgError`]), TOCTOU target-not-found, and payload-decode
/// failure. Fail-fast per turn: a single failure halts the remaining batch;
/// earlier actions are NOT rolled back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchError {
    /// ActionValidator rejected the batch before any delivery was attempted.
    ValidationFailed(SecurityError),
    /// Individual mailbox-delivery failure after a validated action was
    /// decoded. Batch halts; earlier actions NOT rolled back.
    DeliveryFailed(MsgError),
    /// Decoded action targeted a non-existent agent / tool / capability
    /// (TOCTOU window where the target disappeared post-validation).
    TargetNotFound(String),
    /// Payload failed to decode as a known AgentAction kind.
    InvalidPayload(String),
}

/// Inverted trait (CONTRACT-051 extension; lives in shared-types). MODULE-006
/// provides the concrete impl; MODULE-014 AgentLoopDriver consumes.
///
/// Per ARCH §4.2 + REQ-101: the implementation MUST invoke
/// `ActionValidator::validate(agent_id, actions)` (CONTRACT-113, MODULE-012)
/// as the first step of `dispatch`. Rejection short-circuits delivery and
/// emits `security.action_rejected` per MODULE-006-AC-11.
///
/// # Implementer Invariants
///
/// 1. **Validator-first**: call `ActionValidator::validate` before any
///    per-action decode or dispatch side effect.
/// 2. **Fail-fast per turn**: on first per-action failure, return the
///    appropriate [`DispatchError`] and halt the remaining batch.
/// 3. **Identifier validation**: `agent_id: &str` must be whitelist-validated.
/// 4. **Bounded batch**: `actions.len()` should be capped (recommended ≤ 128
///    per turn) to prevent unbounded dispatch work.
///
/// # Phase-2 Step-3 seam extension (ADR 2026-06-05 extensible channel adapter)
///
/// `dispatch` carries the **source inbound `Message`** and returns a
/// [`crate::outbound::DeliveryReport`] (was `actions`-only, returning `()`), so
/// the in-host channel reply path can build a per-message `OutboundTarget` from
/// `source.origin.channel_metadata`. Gate-only implementors (no outbound wired)
/// return [`crate::outbound::DeliveryReport::empty()`]. The `source` is the
/// message whose turn produced `actions`; implementors MUST NOT mutate it.
#[async_trait]
pub trait AgentActionDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        agent_id: &str,
        source: &Message,
        actions: &[AgentAction],
    ) -> Result<crate::outbound::DeliveryReport, DispatchError>;
}

/// MODULE-006 §2.3:304-310 — mailbox read-only surface. 5 methods,
/// mixed-async (only `recv` is async; `poll`/`depth`/`freeze`/`unfreeze`
/// are sync). Consumed by MODULE-014 agent-loop driver.
///
/// # Implementer Invariants
///
/// 1. **Non-blocking sync methods**: `poll` / `depth` / `freeze` / `unfreeze`
///    MUST NOT block; use try-lock semantics. The async `recv` may park
///    the caller until a message arrives.
/// 2. **Identifier validation**: `agent_id: &str` must be whitelist-validated
///    before HashMap lookup.
/// 3. **Freeze semantics**: `freeze` MUST persist across restarts via
///    MODULE-006's circuit-breaker state; `unfreeze` is the only way to
///    resume delivery.
/// 4. **depth bounded**: the returned count MUST NOT exceed MODULE-006's
///    mailbox-capacity policy (recommended ≤ 10_000 per agent).
#[async_trait]
pub trait MailboxReader: Send + Sync {
    async fn recv(&self, agent_id: &str) -> Message;

    /// Receive the exact execution envelope for one mailbox turn. Legacy
    /// readers inherit the default wrapper; a C216-aware reader overrides
    /// this method so the message and its move-only dequeue authority cannot
    /// be separated between mailbox removal and scheduler admission.
    async fn recv_turn(&self, agent_id: &str) -> Result<MailboxTurnEnvelope, TurnMailboxError> {
        Ok(MailboxTurnEnvelope::legacy(self.recv(agent_id).await))
    }

    fn poll(&self, agent_id: &str) -> Option<Message>;

    /// Non-blocking counterpart to [`Self::recv_turn`]. The default preserves
    /// every legacy implementation's existing `poll` semantics.
    fn poll_turn(&self, agent_id: &str) -> Result<Option<MailboxTurnEnvelope>, TurnMailboxError> {
        Ok(self.poll(agent_id).map(MailboxTurnEnvelope::legacy))
    }

    fn depth(&self, agent_id: &str) -> usize;
    fn freeze(&self, agent_id: &str);
    fn unfreeze(&self, agent_id: &str);
}

/// Non-authorizing identity frozen beside a protected mailbox entry. The
/// move-only [`DequeuedTurnHandle`] remains the authority; these strings only
/// let the scheduler stamp the trusted runtime context and request the exact
/// Store-quiescence proof after all turn effects finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxTurnIdentity {
    pub turn_id: String,
    pub expected_agent: String,
}

/// Linear mailbox-to-scheduler handoff. Protected envelopes always carry both
/// `identity` and `dequeued_turn`; legacy envelopes carry neither.
pub struct MailboxTurnEnvelope {
    pub message: Message,
    pub identity: Option<MailboxTurnIdentity>,
    dequeued_turn: Option<DequeuedTurnGuard>,
}

impl MailboxTurnEnvelope {
    pub fn legacy(message: Message) -> Self {
        Self {
            message,
            identity: None,
            dequeued_turn: None,
        }
    }

    pub fn protected(
        message: Message,
        identity: MailboxTurnIdentity,
        dequeued_turn: DequeuedTurnGuard,
    ) -> Self {
        Self {
            message,
            identity: Some(identity),
            dequeued_turn: Some(dequeued_turn),
        }
    }

    pub fn into_parts(
        mut self,
    ) -> (
        Message,
        Option<MailboxTurnIdentity>,
        Option<DequeuedTurnGuard>,
    ) {
        (
            self.message,
            self.identity.take(),
            self.dequeued_turn.take(),
        )
    }
}

/// Fail-closed sink used only if a before-start abandon cannot be committed.
/// Implementations must retain the move-only handle in bounded host-owned
/// recovery storage; returning without retaining it violates the contract.
pub trait DequeuedTurnRecoveryLatch: Send + Sync {
    fn latch_before_start(&self, handle: DequeuedTurnHandle);
}

/// RAII owner for a mailbox handoff that has not yet crossed `start_turn`.
/// Dropping an envelope before scheduler admission performs exact abandon; a
/// provider failure transfers the handle to the injected bounded latch.
pub struct DequeuedTurnGuard {
    handle: Option<DequeuedTurnHandle>,
    execution: std::sync::Arc<dyn TurnExecutionLifecyclePort>,
    recovery: std::sync::Arc<dyn DequeuedTurnRecoveryLatch>,
}

impl DequeuedTurnGuard {
    #[doc(hidden)]
    pub fn from_mailbox(
        handle: DequeuedTurnHandle,
        execution: std::sync::Arc<dyn TurnExecutionLifecyclePort>,
        recovery: std::sync::Arc<dyn DequeuedTurnRecoveryLatch>,
    ) -> Self {
        Self {
            handle: Some(handle),
            execution,
            recovery,
        }
    }

    pub fn start(mut self) -> Result<TurnStartOutcome, TurnExecutionError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or(TurnExecutionError::ProofReplayed)?;
        let outcome = self.execution.start_turn(handle)?;
        self.handle.take();
        Ok(outcome)
    }
}

impl Drop for DequeuedTurnGuard {
    fn drop(&mut self) {
        let Some(handle) = self.handle.as_ref() else {
            return;
        };
        if self.execution.abandon_before_start(handle).is_ok() {
            self.handle.take();
        } else if let Some(handle) = self.handle.take() {
            self.recovery.latch_before_start(handle);
        }
    }
}

/// Max accepted inherited `trace_id` length (matches MODULE-006/019 id-class
/// bound `MAX_ID_BYTES = 256`). Beyond this, treat the inherited value as absent.
const MAX_TRACE_ID_BYTES: usize = 256;

/// A trace id is plausible to inherit if it is non-empty, within the id-class
/// length bound, and free of control characters (defense-in-depth against an
/// unvalidated upstream `trace_id` polluting/forging the event-bus chain id).
fn is_plausible_trace_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TRACE_ID_BYTES && !s.chars().any(|c| c.is_control())
}

/// Establish the per-chain `trace_id` for a handle-message turn at the universal
/// inbound admission point (Stage-F obs SLICE 1; MODULE-019 §1.3.1 link-tracing).
///
/// Called by MODULE-014's `run_turn_once` immediately after `recv` (the single
/// point every inbound message converges, since the production daemon's POST /msg
/// + channel pump deliver to the raw mailbox with `context: None` and bypass the
/// dispatcher). INHERITS an existing `trace_id` (a reply / threaded message stays
/// in its originating chain) or MINTS a FRESH `Uuid::new_v4()` per fire (two
/// independent inbound turns get DIFFERENT chain ids — never a process-stable
/// boot constant). The minted id is written back onto `msg.context` so the cloned
/// `AssemblyContext.message` AND the `&msg` passed to `handle_message` both carry
/// it. Returns the chain `trace_id`.
///
/// Lives in shared-types (which already deps `uuid`) so the scheduler needs no new
/// `uuid` dependency.
pub fn ensure_chain_trace(msg: &mut Message) -> String {
    // Inherit only a PLAUSIBLE existing trace (defense-in-depth, adversarial W4):
    // bound the length + reject control chars so an unvalidated/attacker-influenced
    // `context.trace_id` (a latent sink if any future inbound path ever populates it
    // from untrusted data) cannot pollute the event-bus chain id. A legitimate
    // inherited trace is a system-minted UUID (36 chars) — well within the bound —
    // so this never re-mints a valid chain. An implausible value is treated as
    // absent and a fresh chain id is minted instead.
    if let Some(existing) = msg.context.as_ref().and_then(|c| c.trace_id.clone()) {
        if is_plausible_trace_id(&existing) {
            return existing; // inherit (reply / threaded chain)
        }
    }
    let minted = uuid::Uuid::new_v4().to_string();
    match msg.context.as_mut() {
        Some(ctx) => ctx.trace_id = Some(minted.clone()),
        None => {
            // MessageContext has no Default derive; build the full 6-field literal.
            msg.context = Some(MessageContext {
                task_id: None,
                run_id: None,
                execution_id: None,
                trace_id: Some(minted.clone()),
                in_reply_to: None,
                correlation_id: None,
            });
        }
    }
    minted
}

#[cfg(test)]
mod ensure_chain_trace_tests {
    use super::*;

    fn msg_with(context: Option<MessageContext>) -> Message {
        Message {
            id: "m".to_string(),
            kind: MessageKind::User,
            from: "user:t".to_string(),
            to: "agent:t".to_string(),
            payload: Vec::new(),
            context,
            timestamp: SystemTime::now(),
            origin: None,
        }
    }

    // T1 — per-fire distinctness + persistence + inherit (the #1 anti-fake-green trap).
    #[test]
    fn ensure_chain_trace_mints_persists_distinct_and_inherits() {
        // context: None -> mints, persists, returns non-empty.
        let mut a = msg_with(None);
        let ta = ensure_chain_trace(&mut a);
        assert!(!ta.is_empty(), "minted trace_id must be non-empty");
        assert_eq!(
            a.context.as_ref().unwrap().trace_id.as_deref(),
            Some(ta.as_str()),
            "minted trace_id must be persisted onto msg.context"
        );

        // A SECOND independent message -> DIFFERENT trace_id (per-fire, not stable).
        let mut b = msg_with(None);
        let tb = ensure_chain_trace(&mut b);
        assert_ne!(
            ta, tb,
            "two independent inbound turns must get different trace_ids"
        );

        // Already-present trace_id -> INHERIT (kept verbatim), context preserved.
        let mut c = msg_with(Some(MessageContext {
            task_id: Some("task-1".into()),
            run_id: None,
            execution_id: None,
            trace_id: Some("inherited-X".into()),
            in_reply_to: None,
            correlation_id: None,
        }));
        let tc = ensure_chain_trace(&mut c);
        assert_eq!(
            tc, "inherited-X",
            "existing trace_id must be inherited, not re-minted"
        );
        assert_eq!(
            c.context.as_ref().unwrap().task_id.as_deref(),
            Some("task-1"),
            "existing context fields must be preserved"
        );

        // context: Some but trace_id None -> mint + set, preserving siblings.
        let mut d = msg_with(Some(MessageContext {
            task_id: Some("task-2".into()),
            run_id: None,
            execution_id: None,
            trace_id: None,
            in_reply_to: None,
            correlation_id: None,
        }));
        let td = ensure_chain_trace(&mut d);
        assert!(!td.is_empty());
        assert_eq!(
            d.context.as_ref().unwrap().trace_id.as_deref(),
            Some(td.as_str())
        );
        assert_eq!(
            d.context.as_ref().unwrap().task_id.as_deref(),
            Some("task-2")
        );
    }

    // W4 (adversarial defense-in-depth): an IMPLAUSIBLE inherited trace_id
    // (control char / over-long / empty) is NOT inherited verbatim — a fresh
    // plausible chain id is minted instead, so it can't pollute/forge the chain.
    #[test]
    fn ensure_chain_trace_rejects_implausible_inherited_trace() {
        for bad in [
            "trace\nwith-newline".to_string(), // control char (log-forge sink)
            "x".repeat(257),                   // over the id-class bound
            String::new(),                     // empty
        ] {
            let mut m = msg_with(Some(MessageContext {
                task_id: None,
                run_id: None,
                execution_id: None,
                trace_id: Some(bad.clone()),
                in_reply_to: None,
                correlation_id: None,
            }));
            let t = ensure_chain_trace(&mut m);
            assert_ne!(
                t, bad,
                "implausible inherited trace_id must NOT be used verbatim"
            );
            assert!(
                super::is_plausible_trace_id(&t),
                "the minted replacement is plausible"
            );
            // a fresh v4 is UUID-shaped
            assert!(
                uuid::Uuid::parse_str(&t).is_ok(),
                "minted replacement is a fresh UUID"
            );
        }

        // A plausible inherited trace (a real v4) IS still inherited verbatim.
        let good = uuid::Uuid::new_v4().to_string();
        let mut m = msg_with(Some(MessageContext {
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: Some(good.clone()),
            in_reply_to: None,
            correlation_id: None,
        }));
        assert_eq!(
            ensure_chain_trace(&mut m),
            good,
            "a plausible v4 trace is inherited as-is"
        );
    }
}
