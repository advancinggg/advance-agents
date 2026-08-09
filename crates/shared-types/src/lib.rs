//! `advance-shared-types` — dependency-inversion foundation crate for advance-agents.
//!
//! **Slice A'** shipped the 2 fully-canonical sync traits and their 3 data types:
//!
//! - [`traits::RunBudget`] (CONTRACT-073, MODULE-008:490-493)
//! - [`traits::CallableInventoryReader`] (CONTRACT-165, MODULE-017:339-348)
//! - [`capability::BudgetDecision`] (MODULE-001:762)
//! - [`capability::ToolEntry`] (MODULE-017:350-354)
//! - [`capability::McpToolEntry`] (MODULE-017:356-361)
//!
//! **Slice B'** added the observability emit hook and its payload struct:
//!
//! - [`traits::EventBusEmit`] (CONTRACT-180, MODULE-019:384-386)
//! - [`event::Event`] (MODULE-019:88-101, 12 fields with nanosecond `DateTime<Utc>`)
//!
//! **Slice m019-B** (2026-05-04) added the cost tracker query surface:
//!
//! - [`traits::CostTrackerQuery`] (CONTRACT-181, MODULE-019:408-417)
//! - [`cost::RunCost`] (MODULE-019:281-286, 4 monotonic aggregate fields)
//!
//! **Slice I** added the capability-wiring data types (MODULE-001 §3.2):
//!
//! - [`capability::CapabilityId`] (newtype + `Borrow<str>` for HostRegistry HashMap key)
//! - [`capability::CapRequest`] (manifest-time capability declaration; MODULE-018:318)
//! - [`capability::CapParams`] (per-call authorization params; MODULE-013:432)
//!
//! **Slice J** added the invocation-gate authorization surface (CONTRACT-121):
//!
//! - [`traits::GrantCheck`] (MODULE-013:431-433; consumed by MODULE-001 L1 gate)
//! - [`capability::GrantDecision`] (2-state Allow/Deny; MODULE-001 §1.4.1:245-249)
//!
//! **Slice K** added the repetition-guard surface (CONTRACT-072):
//!
//! - [`traits::RepetitionGuardCheck`] (MODULE-008:495-498)
//! - [`repetition::ToolCallSignature`] / [`repetition::OutputHash`]
//!   / [`repetition::RepetitionDecision`]
//!
//! **Slice AC v2** (2026-04-18) closed the 10 remaining trait entries +
//! `L6RunnableSpec` registration struct + `FsWatchEvents` observer marker:
//!
//! - [`agent_tree`]: [`agent_tree::AgentTreeReader`] + [`agent_tree::AgentTreeSnapshot`]
//!   + [`agent_tree::AgentKind`] + [`agent_tree::AgentTreeSnapshotData`]
//!   + [`agent_tree::AgentNode`] + [`agent_tree::AgentStatus`]
//!   + [`agent_tree::AgentState`] + [`agent_tree::Capability`]
//!   + [`agent_tree::AgentId`] newtype (first canonical declaration — MODULE-005 §2.3
//!   head amendment landed in this slice).
//! - [`mailbox`]: [`mailbox::Message`] + [`mailbox::MessageKind`] + [`mailbox::MessageContext`]
//!   + [`mailbox::MessageOrigin`] + [`mailbox::MsgError`] + [`mailbox::AgentAction`]
//!   + [`mailbox::ActionResult`] + [`mailbox::AgentActionDispatcher`]
//!   + [`mailbox::DispatchError`] + [`mailbox::MailboxReader`].
//! - [`memory`]: [`memory::PostProcessorHook`] (CONTRACT-103)
//!   + [`memory::PostProcessorError`] + [`memory::L6RunnableSpec`] (CONTRACT-102
//!   registration struct, manual `impl Debug` redacts handler)
//!   + [`memory::L6Handler`] + [`memory::L6Context`] + [`memory::L6Cursor`]
//!   + [`memory::L6Outcome`] + [`memory::L6Error`]
//!   + [`memory::KnowledgeHealthSnapshot`] (first canonical declaration —
//!   MODULE-011 §2.3 head amendment landed in this slice).
//! - [`skills`]: [`skills::SkillStateReader`] (CONTRACT-164) + [`skills::SkillInfo`]
//!   + [`skills::Provenance`] (TrustLevel re-exported from security_validator).
//! - [`security_validator`]: [`security_validator::ActionValidator`] (CONTRACT-113)
//!   + [`security_validator::PromptInjectionHelpers`] (CONTRACT-114)
//!   + [`security_validator::InjectionFlag`] + [`security_validator::Severity`]
//!   + [`security_validator::SecurityError`]
//!   + [`security_validator::TrustLevel`] (canonical declaration here;
//!   re-exported from `skills`).
//! - [`context`]: [`context::ContextAssembler`] (CONTRACT-090)
//!   + [`context::AssemblyContext`] + [`context::AssemblyResult`]
//!   + [`context::LlmMessage`] + [`context::TierTokenCounts`]
//!   + [`context::AssemblyError`].
//! - [`run`]: [`run::RoundAdvancer`] (CONTRACT-141) + [`run::RoundResult`]
//!   + [`run::MetricSample`] + [`run::RoundDecision`] + [`run::RunError`]
//!   + [`run::TaskRunStatus`].
//! - [`await_session`]: [`await_session::AwaitSessionRef`]
//!   + [`await_session::OrchestrationError`] + [`await_session::AwaitTreeSummary`]
//!   + [`await_session::SessionSummary`] + [`await_session::SessionId`] newtype
//!   (first canonical declaration — MODULE-007 §2.3 head amendment landed in
//!   this slice).
//!
//! `FsWatchEvents` is an observer-pattern marker per MODULE-001 §2.3 Note 2
//! — it is delivered via [`traits::EventBusEmit`] fan-out and has no
//! standalone trait / struct in shared-types.
//!
//! **Final inventory**: 21/21 Rust traits + 1 registration struct
//! (`L6RunnableSpec`) + 1 observer marker (`FsWatchEvents`). The 17-row
//! MODULE-001 §2.3 inventory is complete; Slice m012-B added `LeakDetector`
//! (1 trait) and Slice m012-C added `HttpSecurityChain` / `SsrfGuard` /
//! `RedirectCheck` (3 traits), bringing the count from 15 to 21 (15 + 1 + 3).
//! **Wave-12 Lane B** (2026-06-23) adds `RunInterruptSink` (CONTRACT-182;
//! MODULE-006-provided / MODULE-008-consumed — the crash-recovery →
//! controller-mailbox bridge port), bringing the trait count to 22. Per the
//! m012 precedent, this running tally is the maintained register for
//! post-Slice-AC-v2 DI traits; the frozen MODULE-001 §2.3 17-row snapshot is
//! intentionally NOT re-tallied.
//!
//! **Slice m016-A** (2026-05-14) registers CONTRACT-150 (MODULE-016 `channel-host`
//! WIT) as a WIT-only contract. Per `docs/ARCHITECTURE.md` §6.1, CONTRACT-150 is
//! consumed via WIT by channel adapter WASM components only and has no Rust
//! compile-time importer, so no dependency-inversion trait is introduced here —
//! this entry is a changelog reference, not a Rust type addition. The
//! `cap-channel` host-side crate ships as a workspace skeleton in this slice;
//! the WIT impl, SubscriptionManager, webhook receiver, and outbound dispatch
//! land in subsequent MODULE-016 slices.
//!
//! **Slice m007-A** (2026-05-18) hoists the MODULE-007 await-orchestration
//! canonical data types into [`await_session`]:
//!
//! - [`await_session::AwaitMode`] / [`await_session::TimeoutPolicy`] —
//!   2-variant enums shared by `AwaitOptions` and `AwaitResult`.
//! - [`await_session::AwaitOptions`] — 4-field record (`mode`,
//!   `idle_timeout_secs`, `on_idle_timeout`, `keep_losers`); the
//!   `on_idle_timeout` field name is the slice-A canonical (renamed from
//!   the §2.3 pre-slice-A `timeout_policy` to match WIT `on-idle-timeout`).
//! - [`await_session::AwaitRequest`] — tuple-variant enum wrapping
//!   [`await_session::AgentAwaitRequest`] / [`await_session::ComponentAwaitRequest`].
//!   `AgentAwaitRequest.target` is the canonical `agent:<name>` form per
//!   MODULE-006 `id_validation::is_safe_id`.
//! - [`await_session::AwaitResult`] / [`await_session::ReplyResult`] /
//!   [`await_session::ReplyStatus`] / [`await_session::AwaitSessionStatus`] —
//!   canonical Rust mirrors. `AwaitSessionStatus::FailedDispatch` is a
//!   slice-A addition for the PRD §9.2 all-failed-dispatch fast-path return.
//!
//! See [`await_session`] file-level doc for the 6-bullet WIT-vs-Rust
//! asymmetry block. AwaitSessionManager (CONTRACT-060) lives in
//! `crates/messaging/reply-tracker` (concrete impl); it is consumed
//! via direct compile-time edge by the runtime, not via dependency-
//! inversion through this crate — only the data types are hoisted here
//! per ARCHITECTURE.md §4.2 / §6.1 split.
//!
//! See `docs/ARCHITECTURE.md` §4.2 for the full dependency-inversion rationale.

#![forbid(unsafe_code)]

pub use chrono;

pub mod agent_tree;
pub mod await_session;
pub mod capability;
pub mod component;
pub mod context;
pub mod contract218_previsible;
pub mod cost;
pub mod event;
pub mod mailbox;
pub mod memory;
pub mod observation_identity;
pub mod outbound;
pub mod producer_boundary;
pub mod progress_card;
pub mod progress_lifecycle_recovery;
pub mod repetition;
pub mod run;
pub mod security_validator;
pub mod sensitive_observation;
pub mod skills;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod traits;
pub mod turn_attribution;

pub use component::ComponentType;

// Crate-root re-exports for identifier types (per Slice AC v2 plan §3.13b:
// identifier types get crate-root `pub use` for ergonomic cross-module use;
// domain-specific struct types stay at sub-module path).
pub use agent_tree::AgentId;
pub use await_session::SessionId;
pub use memory::KnowledgeHealthSnapshot;
// MODULE-006 slice-B hoist: canonical 4-variant notify error + the
// notify-channel outbound envelope (cross-crate-discoverable schema).
// Wave-12 Lane B: ControlMessage (Control payload) + RunInterruptSink
// (CONTRACT-182 DI port; MODULE-008 recovery → MODULE-006 mailbox bridge).
// Wave-19 Lane 3: RunCompletionSink (CONTRACT-184 DI port; MODULE-008
// complete_run → MODULE-007 ComponentFinished await-slot resolution).
pub use mailbox::{
    ChannelDelivery, ControlMessage, NotifyError, RunCompletionSink, RunInterruptSink,
};
// Phase-2 Step-3 (ADR 2026-06-05 extensible channel adapter): the settled
// outbound egress contract shapes shared by the MODULE-006 dispatch seam +
// MODULE-016 OutboundTransport.
pub use outbound::{
    DeliveryReport, OutboundEncoding, OutboundRoute, OutboundTarget, RoutedOutboundMessage,
    TargetOutcome,
};
// MODULE-007 slice-A hoist: canonical CONTRACT-060 data types
// (cross-crate-discoverable schemas — same convention as ChannelDelivery /
// NotifyError above; consumed by reply-tracker, future cap-messaging
// host-fn handler, and MODULE-006/008 run-status surface).
pub use await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitResult, AwaitSessionStatus,
    ComponentAwaitRequest, ReplyResult, ReplyStatus, TimeoutPolicy,
};
