//! Dependency-inversion traits shipped across Slices A' / B' / J / K / AC v2 / m012-B / m012-C.
//!
//! Currently shipped: [`RunBudget`], [`CallableInventoryReader`] (Slice A'),
//! [`EventBusEmit`] (Slice B'), [`GrantCheck`] (Slice J),
//! [`RepetitionGuardCheck`] (Slice K), the Slice AC v2 additions
//! ([`AgentTreeReader`] / [`AgentTreeSnapshot`] / [`MailboxReader`] /
//! [`PostProcessorHook`] / [`L6Handler`] / [`SkillStateReader`] /
//! [`ActionValidator`] / [`AgentActionDispatcher`] / [`ContextAssembler`] /
//! [`RoundAdvancer`] / [`AwaitSessionRef`] / [`PromptInjectionHelpers`]),
//! the Slice m012-B addition [`LeakDetector`], the Slice m012-C additions
//! [`HttpSecurityChain`] / [`SsrfGuard`] / [`RedirectCheck`], [`CostTrackerQuery`],
//! the Wave-15 Lane E addition [`ToolsGrantReader`] (CONTRACT-183), and the
//! Wave-23 addition [`RememberContentPolicy`] (CONTRACT-214).
//! Object-safety + `Send + Sync` are regression-locked by
//! `tests/object_safety.rs` — all 24 traits (5 prior + 12 Slice AC v2 +
//! 1 Slice m012-B + 3 Slice m012-C + CostTrackerQuery + ToolsGrantReader +
//! RememberContentPolicy) `Box<dyn>`-constructible.

use crate::capability::{BudgetDecision, CapParams, GrantDecision, McpToolEntry, ToolEntry};
use crate::cost::RunCost;
use crate::event::Event;
use crate::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};

// Slice AC v2 re-exports — canonical trait definitions live in their
// domain-specific submodules (see module-level rustdoc above); re-exporting
// here preserves the `use advance_shared_types::traits::FooTrait` import
// pattern established by Slice A'/B'/J/K.
pub use crate::agent_tree::{AgentTreeReader, AgentTreeSnapshot};
pub use crate::await_session::AwaitSessionRef;
pub use crate::context::ContextAssembler;
pub use crate::inference::{
    InferenceBackendPort, InferenceStream, LocalBodyStream, LocalInferenceTransportPolicy,
};
pub use crate::mailbox::{AgentActionDispatcher, MailboxReader};
pub use crate::memory::{L6Handler, PostProcessorHook};
pub use crate::producer_boundary::{RememberContentPolicy, RememberDecision};
pub use crate::run::RoundAdvancer;
pub use crate::security_validator::{
    ActionValidator, HttpBodyStream, HttpSecurityChain, HttpStreamingChain, LeakDetector,
    PromptInjectionHelpers, RedirectCheck, SsrfGuard,
};
pub use crate::skills::SkillStateReader;

/// CONTRACT-073 — per-run token + cost budget enforcement.
///
/// **Canonical source**: `docs/modules/MODULE-008-run-manager.md` lines 490-493
/// (the implementer module's §2.3 Interface Definitions code block).
///
/// - **Implementer**: MODULE-008 run-manager.
/// - **Consumer**: MODULE-009 cap-llm (per-call budget check before each LLM
///   `generate`/`stream` invocation).
///
/// # Implementer Invariants (security-critical)
///
/// Any type implementing this trait MUST uphold the following or a malicious/buggy
/// caller can bypass budget enforcement:
///
/// 1. **Finite-value rejection**: `additional_tokens` and `additional_cost` must be
///    validated before use. `f64::NAN`, `f64::INFINITY`, `f64::NEG_INFINITY`, and
///    negative finite values MUST be treated as invalid input; the implementer should
///    return `BudgetDecision::Deny(..)` (or panic in test-only builds) rather than
///    silently allowing the operation. NaN comparisons in Rust are always `false`,
///    which would otherwise cause naive `committed < limit` checks to fail open.
/// 2. **Integer overflow**: arithmetic on `additional_tokens` / `tokens` MUST use
///    `checked_add` / `saturating_add`, never wrapping.
/// 3. **Atomicity across `check` then `commit`**: `check` and `commit` are split-phase
///    by design but the implementer MUST serialize per-`run_id` state so two concurrent
///    `check` calls cannot both observe the same "headroom" and then both `commit`
///    successfully.
/// 4. **Deny-reason opacity**: `BudgetDecision::Deny(reason)` MUST NOT contain
///    user PII or secrets — keep it a short invariant identifier.
/// 5. **Identifier validation**: `run_id` is untyped `&str`. Implementers MUST
///    validate against a whitelist.
pub trait RunBudget: Send + Sync {
    fn check(&self, run_id: &str, additional_tokens: u64, additional_cost: f64) -> BudgetDecision;
    fn commit(&self, run_id: &str, tokens: u64, cost: f64);
}

/// CONTRACT-165 — per-agent runtime-internal projection of WASM tool and MCP tool
/// inventories. See Slice A' rustdoc (prior plan history preserved) for full
/// implementer-invariants enumeration.
pub trait CallableInventoryReader: Send + Sync {
    fn list_wasm_tools(&self, agent_id: &str) -> Vec<ToolEntry>;
    fn list_mcp_tools(&self, agent_id: &str) -> Vec<McpToolEntry>;
}

/// CONTRACT-180 — runtime observability emit hook. See Slice B' rustdoc for full
/// implementer invariants (non-blocking, Trigger Bus whitelist validation, etc.).
pub trait EventBusEmit: Send + Sync {
    fn emit(&self, event: Event);
}

/// CONTRACT-180 durable append (D4, m021-s7-core Δ8).
///
/// A SEPARATE SIBLING of [`EventBusEmit`], deliberately not a supertrait and not a new
/// method on it. `EventBusEmit::emit` is infallible and fire-and-forget; durable append
/// is fallible and ordered. Folding the two together would either force every existing
/// emitter to implement durability it does not provide, or let a caller believe an
/// `emit` was durable because the same object happened to offer both.
///
/// `EventBusEmit` is UNTOUCHED by this addition.
///
/// **Status, stated plainly**: this port is BUILT AND HELD. No MODULE-019 §1.5 acceptance
/// criterion declares durable append, and this lane mints none — a new AC row would move
/// the ledger denominator and break the zero-net rule the lane operates under. It is
/// recorded as additive scope in MODULE-019 §3.6 and carries unit-level witnesses only.
pub trait DurableEventAppend: Send + Sync {
    /// Append durably, returning the assigned monotonic sequence number.
    ///
    /// Implementations MUST NOT report success unless the event will survive a crash at
    /// the moment of return. Returning `Ok` for a buffered write is the failure this
    /// trait exists to make nameable.
    fn append_durable(&self, event: Event) -> Result<u64, DurableAppendError>;
}

/// Why an append could not be made durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableAppendError {
    /// The backing store rejected or could not complete the write.
    Storage(String),
    /// The sink is shutting down; the caller must not treat the event as recorded.
    ShuttingDown,
}

impl std::fmt::Display for DurableAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(m) => write!(f, "durable append failed: {m}"),
            Self::ShuttingDown => f.write_str("durable append refused: sink is shutting down"),
        }
    }
}

impl std::error::Error for DurableAppendError {}

/// CONTRACT-121 — L1 invocation-time authorization gate. See Slice J rustdoc
/// for full implementer invariants (non-blocking, lifecycle semantics, deny-reason
/// opacity, identifier validation).
///
/// **Slice C widening (2026-05-08)**: `function: &str` (the host-fn name, e.g.
/// `"ns-fs::read"`) is the 3rd arg, between `capability` and `params`. The new arg
/// surfaces the call-site identity into the `authz.checked` event's `function`
/// payload field per PRD §15.3.18. It is observability-only: it does NOT participate
/// in authorization. The Slice-A fail-closed `CapParams::Null` precondition in the
/// MODULE-013 impl stays intact; SubsetValidator wiring into the L1 path is deferred
/// to a future slice that also lowers WASM call-frame params into `CapParams`.
pub trait GrantCheck: Send + Sync {
    fn check(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        params: &CapParams,
    ) -> GrantDecision;
}

/// CONTRACT-072 — per-agent tool-call-triplet and output-hash repetition guard.
/// See Slice K rustdoc for full implementer invariants.
pub trait RepetitionGuardCheck: Send + Sync {
    fn record_tool_call(&self, agent_id: &str, sig: ToolCallSignature) -> RepetitionDecision;
    fn record_output(&self, agent_id: &str, output_hash: OutputHash) -> RepetitionDecision;
}

/// CONTRACT-181 — per-run / per-iteration cost aggregation accessor.
///
/// **Canonical source**: `docs/modules/MODULE-019-observability.md` §1.3.4 (lines
/// 281-321) and §2.3 `CostTrackerQuery` block (lines 408-417).
///
/// - **Implementer**: MODULE-019 `CostTracker` (Slice B; subscribes to `llm.response`
///   events via the EventBus emit path and folds payload `input_tokens` /
///   `output_tokens` / `cost_usd` / `iteration` into per-Run + per-(Run, iteration)
///   aggregates).
/// - **Consumer**: MODULE-008 run-manager (per-run budget check) + MODULE-015
///   auto-mode (per-iteration budget check) per ARCHITECTURE.md §6.1 line 608.
///
/// # Implementer Invariants
///
/// 1. **Lookup-only — never mutate**: this trait is read-only. Mutation happens
///    inside the implementer's `observe(&self, event: &Event)` method which is NOT
///    part of this trait surface (it lives on the concrete `CostTracker` struct).
///    Calls through `Arc<dyn CostTrackerQuery>` cannot cause aggregator state
///    transitions.
/// 2. **Missing-key returns None**: queries for unknown `run_id` / `(run_id,
///    iteration)` return `None`. Implementations MUST NOT auto-create an empty
///    `RunCost::default()` entry on lookup — that would be a memory-amplification
///    DoS vector under attacker-controlled query streams.
/// 3. **No `&mut self`**: trait methods take `&self`. Implementations use interior
///    mutability (`RwLock<HashMap<...>>`) to allow concurrent reads + writes.
/// 4. **Thread-safety**: `Send + Sync`. Multiple `Arc<dyn CostTrackerQuery>` clones
///    can call `query_run` / `query_iteration` concurrently. Implementations MUST
///    serialize on a per-run lock (or use `RwLock` for read-heavy access patterns).
pub trait CostTrackerQuery: Send + Sync {
    fn query_run(&self, run_id: &str) -> Option<RunCost>;
    fn query_iteration(&self, run_id: &str, iteration: u32) -> Option<RunCost>;
}

/// CONTRACT-183 — per-agent WASM tools-grant allowlist projection (Wave-15 Lane E).
///
/// Provided by MODULE-013 (`cap_grant::ToolsGrantReaderImpl` over `GrantStore`),
/// consumed by MODULE-017's `cap_tools::CallableInventory` to realize CONTRACT-165's
/// documented `list_wasm_tools` "post L1 `tools` grant filter" — dependency-inverted
/// like [`GrantCheck`] so cap-tools never imports cap-grant (the trait lives here in
/// MODULE-001 shared types; only the composition root wires the concrete impl).
///
/// `tool_allowlist(agent_id)` returns the agent's effective WASM-tool allowlist:
/// - `None` = unrestricted (the agent holds an active `"tools"` grant with no `ids`
///   narrowing ⇒ all WASM tools, parity with the capability-level [`GrantCheck`] allow).
/// - `Some(list)` = narrow to those tool ids (the union of `tools.ids` across the agent's
///   active, unexpired `"tools"` grants).
/// - `Some(empty)` = deny all (no active `"tools"` grant for the agent).
///
/// Distinct from [`GrantCheck`] (a per-call Allow/Deny gate): this is a read-only LIST
/// projection for Layer-3 inventory assembly only — it performs no authorization.
///
/// The `Debug` supertrait lets MODULE-017's `CallableInventory` (which is
/// `#[derive(Debug)]`) hold an `Option<Arc<dyn ToolsGrantReader>>` field.
pub trait ToolsGrantReader: Send + Sync + std::fmt::Debug {
    fn tool_allowlist(&self, agent_id: &str) -> Option<Vec<String>>;
}

// ─────────────────────────────────────────────────────────────────────────
// CONTRACT-234 — post-scan LLM token-delta sink (ADR 2026-07-22 D6, tee T1)
// ─────────────────────────────────────────────────────────────────────────

/// One published tee frame, carrying the stream identity every frame needs.
///
/// The ADR's registered frame sketch put identity only on `Begin`; a consumer keyed
/// by `(agent_id, stream_key)` cannot route a bare `Delta`/`Terminal`, and two
/// concurrent streams for one agent collide on `seq`. Wrapping the closed frame
/// family in this envelope keeps the three variant shapes while making routing
/// possible (recorded as a CONTRACT-234 signature delta in MODULE-009 §2.3 ("AS BUILT") and in the ARCHITECTURE §6.1 row).
#[derive(Clone, Debug, PartialEq)]
pub struct LlmDeltaEvent {
    pub agent_id: std::sync::Arc<str>,
    /// Opaque per-stream id minted at stream begin. NOT the guest's `u64` handle —
    /// that is handle-table structure and must never reach a subscriber.
    pub stream_key: std::sync::Arc<str>,
    pub frame: LlmDeltaFrame,
}

/// The closed tee frame family.
#[derive(Clone, Debug, PartialEq)]
pub enum LlmDeltaFrame {
    /// Attribution ids only — never prompt or message bytes.
    ///
    /// **`task_id` is GUEST-INFLUENCED and must be treated as untrusted** (recorded by
    /// the §5.2 adversarial review): the WIT `stream` request carries a `task-id` field
    /// that a guest sets freely, and an explicit value wins over the host's tracked id.
    /// The producer bounds its LENGTH before publishing (cap-llm's
    /// `TeeState::MAX_BEGIN_ID_BYTES`, char-safe truncation) but cannot vouch for its
    /// CONTENT or provenance. A consumer MUST NOT render it as trusted text, use it as a
    /// key into privileged state, or treat a match as proof that two streams belong to
    /// the same task. `run_id` is host-derived and carries no such caveat.
    Begin {
        run_id: Option<String>,
        task_id: Option<String>,
    },
    /// Exactly one guest-visible delta, at the moment the guest received it.
    Delta { seq: u64, text: String },
    /// Published at most once per stream that published a `Begin`. `seq` is the number
    /// of guest-visible deltas allocated AT SETTLEMENT TIME.
    ///
    /// **It is a settlement-time watermark ONLY — not a ceiling, not a floor, not a
    /// completeness claim.** On a successful stream the producer does not discard
    /// already-released ranges, so further deltas can legitimately arrive afterwards.
    /// Their `seq` may be BELOW, EQUAL TO, or ABOVE this value: the producer reads its
    /// counter WITHOUT incrementing it while a poller allocates and publishes outside
    /// the state lock, so whichever side wins the emission race decides. Any consumer
    /// rule of the form "reject when `seq` compares thus against `Terminal.seq`" will
    /// drop deltas the guest actually received, in one direction or the other.
    Terminal {
        seq: u64,
        reason: LlmTerminalReason,
        /// The bill for which `RunBudget::commit` ran AND RETURNED — `None` when no
        /// charge was attempted (no budget or no run_id wired; or a failed-begin
        /// settlement, which bills zero and never charges — such a stream published no
        /// `Begin`, so its `Terminal` frame is itself suppressed and this case is not
        /// observable on the wire), and ALSO `None` when the implementer PANICKED
        /// mid-call: the producer cannot know whether a panicking implementer charged
        /// durably, so it reads conservatively `None` while the bus record still
        /// carries the computed figures (the recorded divergence, MODULE-009 §3.6.6).
        /// Never a projection, and never a computed-but-uncharged figure the producer
        /// could have known about. `commit` returns `()`, so even `Some` records
        /// nothing about the implementer's acceptance of the charge.
        usage: Option<LlmDeltaUsage>,
    },
}

/// Why a stream ended. Closed enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmTerminalReason {
    Completed,
    /// Host-side termination of otherwise-valid output (e.g. repetition guard).
    Aborted,
    BudgetExhausted,
    ProviderError,
    /// Host-authoritative turn-end reap (ADR 2026-07-22 D5).
    Reaped,
    /// TTL expiry or handle drop — ordinary abandonment, not a provider fault.
    Abandoned,
}

/// Settled usage for a finished stream.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LlmDeltaUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

/// CONTRACT-234 — the post-scan token-delta tee port.
///
/// Provider is MODULE-020 (`LlmDeltaHub`, tee slice T2); the MODULE-009 cap-llm
/// stream path is the consumer/caller. Direction follows the CONTRACT-180
/// [`EventBusEmit`] precedent, and both sides already depend on shared-types, so the
/// port adds no dependency edge.
///
/// # Implementer Invariants
///
/// 1. **Non-blocking and bounded.** `publish` runs on the guest's host-call path and
///    on settlement paths. It MUST NOT await, block on I/O, sleep, or perform
///    unbounded work. The composition root owns which sink is installed, so a hostile
///    implementation is out of the threat model exactly as it is for [`EventBusEmit`]
///    — but a slow one stalls a guest turn.
/// 2. **No re-entry.** `publish` MUST NOT call back into cap-llm (in particular not
///    into `stream`/`poll-stream` for the same agent); the caller may hold a
///    tee-ordering lock.
/// 3. **Panics in `publish` are contained by the caller** (`catch_unwind`) and disable
///    the tee for that stream, so a panicking `publish` degrades to silence rather than
///    breaking the guest's stream — but implementations should not rely on it.
///    **`is_wired` is NOT inside that containment — on ANY path.** It is evaluated
///    wherever the producer emits frames or settles: the guest's poll path (per-stream
///    lock held — a panic unwinds through the guest's stream); the owner task's own
///    settlement on normal completion (a panic there spends the exactly-once terminal
///    CAS and strands the stream with no `Terminal` ever published); `Drop for
///    LiveStream` (a panic unwinds out of a destructor — an abort if that thread is
///    already unwinding); TTL expiry, both the background sweep task (a panic silently
///    kills the sweep for the process lifetime) and the inline eviction on the
///    stream-insert path; and turn-end reap, which runs inside `on_turn_complete` on an
///    agent's serve loop with NO `catch_unwind`, where a panic permanently kills that
///    agent's loop. That list is ILLUSTRATIVE, not exhaustive: the invariant is
///    structural — `is_wired` executes outside every panic containment the producer
///    has, on whichever path settlement happens to take — so it MUST be a trivial,
///    panic-free accessor, unconditionally.
/// 3b. **`is_wired` MUST be constant for the sink's lifetime.** The producer consults it
///    at several points in a stream's life and assumes the answer does not change. A
///    sink whose `is_wired` tracked, say, live subscriber count could return `false` at
///    settlement and strand a stream that had already published `Begin` with no
///    `Terminal`, or `false` at begin and then silently drop every delta. Model
///    "nobody is listening" inside `publish`, never by flipping `is_wired`.
/// 4. **Ordering — read this carefully; it is weaker than it first looks.** Frames for
///    one `stream_key` are emitted whole and exactly once, never interleaved. On the
///    normal path the producer publishes deltas serially, in `seq` order, because the
///    per-stream poll gate makes same-handle polls serial. But a `Delta` MAY still be
///    observed AFTER that stream's `Terminal`, in two reachable cases: a successful
///    terminal does not discard already-released ranges, so a later poll can still
///    drain and publish them; and a settlement racing an in-flight poll can win the
///    emission order. Suppressing those deltas would make the tee under-report what
///    the guest actually received, which is the opposite of the port's purpose.
///    **Consumers MUST accept every post-terminal `Delta` unconditionally, whatever its
///    `seq`, and MUST de-duplicate on the `(stream_key, seq)` pair alone.** `Terminal`
///    is an absorbing latch ONLY against a second `Terminal` — never against deltas,
///    in either `seq` direction. One guarantee the producer DOES give: `Begin` always
///    precedes `Terminal` for a stream, because a terminal settling before `Begin`
///    ships is parked and flushed immediately after it under the same ordering guard.
///    No ordering is promised ACROSS streams.
/// 5. **At-most-once, not at-least-once.** A disabled tee (invariant 3) or a bounded
///    consumer may mean a stream's `Terminal` never arrives; consumers treat an absent
///    stream as terminated rather than waiting forever.
/// 6. (docs-minted 2026-08-06) A producer MUST NOT reuse a `stream_key` across streams — the T2 hub's absent semantics rely on it.
pub trait LlmDeltaSink: Send + Sync {
    fn publish(&self, event: LlmDeltaEvent);

    /// `false` for a no-op sink, letting the producer skip building a frame at all.
    ///
    /// This is what makes the headless default genuinely zero-cost: with an
    /// unwired sink the producer allocates no text copy and constructs no envelope,
    /// rather than building a frame and throwing it away behind dynamic dispatch.
    fn is_wired(&self) -> bool {
        true
    }
}

/// The headless default (ADR 2026-07-22 D6; `NotWiredRepetitionGuard` precedent).
///
/// Really installed — the gateway holds an `Arc<dyn LlmDeltaSink>`, never an
/// `Option` — so the "headless daemons inject a `NotWiredDeltaSink`" contract holds
/// literally, while [`LlmDeltaSink::is_wired`] keeps it free.
#[derive(Debug, Default, Clone, Copy)]
pub struct NotWiredDeltaSink;

impl LlmDeltaSink for NotWiredDeltaSink {
    fn publish(&self, _event: LlmDeltaEvent) {}
    fn is_wired(&self) -> bool {
        false
    }
}
