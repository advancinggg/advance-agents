//! WIT poll-stream handle table + delta chunking (buffered legacy + S4 live).
//!
//! Buffered path (pre-S4): buffer-then-replay model for the old fake-stream.
//! S4 live path (ADR 2026-07-22): LiveStream + owner task + settlement + decoded
//! scan via cap-http facade. This module owns both during the tranche transition.
//! Real per-token SSE is the S4 focus; full live loop + emission in progress.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use crate::gateway::{ChatParams, ChatResponse, LlmRequestContext, ReadyStream};

// S4: use consolidated from host_fn::STREAM_HANDLE_TTL (single definition)
/// Max concurrent buffered stream handles (DoS bound). 256 × 256 KiB ≈ 64 MiB
/// worst-case buffered text.
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 256;
/// Max buffered content deltas per stream; the tail is coalesced beyond this so
/// the buffered delta count is bounded regardless of text shape.
pub(crate) const MAX_STREAM_DELTAS: usize = 2048;

/// A buffered stream: ordered content-delta BYTE RANGES into `ready.response.text`
/// + the finalized response payload + the owning agent id.
///
/// Round-AUDIT-9 W2: deltas are stored as `(start, end)` byte ranges into the
/// single buffered `ready.response.text`, NOT as owned `String` copies — so each
/// live handle pins ONE ≈256-KiB text copy (+ tiny ranges), keeping the
/// registry's worst-case footprint at the documented ≈256 × 256 KiB.
/// Round-AUDIT-9 W1: `agent_id` is the owning agent (from `ctx.agent_id`); `poll`
/// refuses handles whose owner does not match the caller (cross-agent isolation).
pub(crate) struct BufferedStream {
    pub deltas: VecDeque<(usize, usize)>,
    pub ready: ReadyStream,
    pub created_at: Instant,
    pub agent_id: String,
}

/// Outcome of a single `poll-stream(handle)` call.
pub(crate) enum PollOutcome {
    /// A content delta (`done = false`, `response = None`).
    Delta(String),
    /// The terminal `done = true` chunk carrying the finalized response.
    Done(ReadyStream),
    /// The stream terminated with an enum-coded error — delivered to the guest as
    /// WIT `result::err` (S4: a live stream's Failed phase surfaces its REAL error;
    /// it is never collapsed to Unknown).
    Failed(crate::LlmError),
    /// Unknown handle / cross-agent probe / expired (existence-hiding).
    Unknown,
}

// === S4 Live streaming types (ADR 2026-07-22; replaces buffered fake-stream for WIT stream/poll-stream) ===

use std::sync::Arc;
use tokio::sync::{Mutex as TokioMutex, Notify};
use tokio::task::JoinHandle;

use advance_shared_types::traits::RunBudget;

/// Live state (visible to guest after post-scan release).
#[derive(Default)]
pub(crate) struct LiveState {
    /// Guest-visible UTF-8 buffer (≤ MAX_ENCODED_TEXT_BYTES), char-safe appends.
    pub visible: String,
    /// Ordered pending (start, end) ranges into visible for unpolled deltas.
    pub pending: VecDeque<(usize, usize)>,
    /// Phase: Running until settlement winner publishes Done/Failed.
    pub phase: LivePhase,
    /// Set once a release had to be TRUNCATED at `MAX_ENCODED_TEXT_BYTES`. From
    /// then on all further text is SUPPRESSED (the criterion's "further text deltas
    /// are suppressed while the upstream is STILL drained"): without this latch a
    /// later fragment could fill the last free byte and appear spliced directly onto
    /// the truncated one, so the done text would interleave non-contiguous upstream
    /// bytes (found by the re-audit's odd-room T114 fixture).
    pub capped: bool,
    /// Terminal consumption latch (the plan's `Available | Claimed`). Exactly ONE
    /// poll may consume the terminal; the registry-map removal is housekeeping, not
    /// the gate — otherwise a poller woken by the reaper (which removes the entry)
    /// would lose its claim and see the existence-hiding `Unknown` instead of the
    /// real enum-coded error (re-audit F2).
    pub terminal_claimed: bool,
    /// Set by the settlement WINNER the instant the bill is committed — before the
    /// terminal event is emitted and before `phase` is published.
    ///
    /// `append_released` keys its write refusal on THIS, not on `phase`. Adversarial
    /// round 20 showed why: `finalize` publishes the phase LAST, so between the commit
    /// and the publication the stream is settled by every other measure while `phase`
    /// is still `Running`, and a phase-keyed guard admits the write. The consequence
    /// was contained — `finalize` clears `pending` after that window and `poll_live`
    /// pops it under the same mutex, so a racing poller observed nothing across 200
    /// attempts — but the guard was inexact, and an inexact guard on an accounting
    /// invariant is a defect waiting for a refactor.
    pub settled: bool,
    /// CONTRACT-234 tee — the next `seq` to hand a guest-visible delta. Allocated in
    /// the SAME critical section as the `pending` pop, so seq order is exactly the
    /// order the guest received bytes in.
    pub next_seq: u64,
}

/// CONTRACT-234 per-stream tee state (ADR 2026-07-22 D6, tee slice T1).
///
/// Frames are published from two sites — the poll path (one `Delta` per guest-visible
/// delta) and `Settlement::finalize`'s winner branch (`Terminal`). `order` guarantees
/// that no two publishes for one stream OVERLAP; it is a dedicated emission-ordering
/// mutex, NOT the registry lock or the `LiveState` lock, and it is never held while
/// acquiring either of those.
///
/// It does NOT guarantee that a `Delta` never follows this stream's `Terminal` — a
/// successful terminal leaves already-released ranges drainable. A trailing delta's
/// `seq` may be BELOW, EQUAL TO or ABOVE `Terminal.seq` (this counter is read without
/// incrementing while a poller allocates and publishes outside the state lock), so a
/// consumer must accept post-terminal deltas unconditionally and de-duplicate on
/// `(stream_key, seq)`. See `LlmDeltaSink` invariant 4.
pub(crate) struct TeeState {
    sink: Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
    agent_id: Arc<str>,
    stream_key: Arc<str>,
    /// `Terminal` is suppressed until a `Begin` was published, so a stream that failed
    /// before its handle was delivered never produces a phantom terminal downstream.
    begin_published: std::sync::atomic::AtomicBool,
    /// Exactly-once latch for `Terminal`.
    terminal_published: std::sync::atomic::AtomicBool,
    /// A terminal that arrived BEFORE `Begin` was published, parked until it can be
    /// emitted in order. AUDIT round 7 found the real lost-terminal window is not
    /// inside `publish_begin` at all: it spans `insert_live` to `publish_begin`,
    /// across the dispatch await. A settlement winner in that span (reap, TTL sweep,
    /// `Drop`) used to hit the `!begin_published` early return WITHOUT consuming the
    /// exactly-once latch, and because `finalize` is settle-once nothing ever retried
    /// — leaving the consumer with a `Begin` and no `Terminal`, forever.
    pending_terminal: std::sync::Mutex<Option<advance_shared_types::traits::LlmDeltaFrame>>,
    /// The frozen criterion's "per-stream tee-disabled latch on first failure":
    /// once a publish panics, this stream's tee is off — terminal included.
    disabled: std::sync::atomic::AtomicBool,
    order: std::sync::Mutex<()>,
}

impl TeeState {
    pub(crate) fn new(
        sink: Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
        agent_id: &str,
        stream_key: &str,
    ) -> Arc<Self> {
        Arc::new(Self {
            sink,
            agent_id: Arc::from(agent_id),
            stream_key: Arc::from(stream_key),
            begin_published: std::sync::atomic::AtomicBool::new(false),
            terminal_published: std::sync::atomic::AtomicBool::new(false),
            pending_terminal: std::sync::Mutex::new(None),
            disabled: std::sync::atomic::AtomicBool::new(false),
            order: std::sync::Mutex::new(()),
        })
    }

    /// True only when a real consumer is installed AND this stream's latch is unset.
    /// Callers check this BEFORE building a frame, so an unwired composition performs
    /// no text copy and no envelope construction — the criterion's "zero cost".
    pub(crate) fn is_live(&self) -> bool {
        self.sink.is_wired() && !self.disabled.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Emit one frame under the ordering mutex, containing panics.
    ///
    /// The guard is taken OUTSIDE `catch_unwind` so an unwinding sink cannot poison it
    /// and wedge every later poll of this stream.
    fn emit(&self, frame: advance_shared_types::traits::LlmDeltaFrame) {
        // AUDIT round 6 (hardened-adversarial Critical 1): the guard is taken FIRST.
        // The previous form built the envelope and only then locked, leaving a wide
        // preemption window between a delta publisher's liveness check and its lock —
        // during which a settlement could take the guard and emit `Terminal`, so the
        // delta landed after it. Ordering the *decision* to emit, not merely each
        // individual emission, is what the invariant actually requires.
        let guard = self
            .order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.emit_under(&guard, frame);
    }

    /// Emit with the ordering guard ALREADY held. Single copy of the publish
    /// sequence: AUDIT round 7 flagged `publish_terminal`'s open-coded duplicate as a
    /// silent-drift hazard, and the ordering witness only ever routed deltas through
    /// `emit`, so a mutation to the terminal copy alone went uncaught.
    fn emit_under(
        &self,
        _guard: &std::sync::MutexGuard<'_, ()>,
        frame: advance_shared_types::traits::LlmDeltaFrame,
    ) {
        if !self.is_live() {
            return;
        }
        let event = advance_shared_types::traits::LlmDeltaEvent {
            agent_id: Arc::clone(&self.agent_id),
            stream_key: Arc::clone(&self.stream_key),
            frame,
        };
        let sink = &self.sink;
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.publish(event)));
        if outcome.is_err() {
            self.disabled
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// Maximum bytes of a `Begin` attribution id that may cross the CONTRACT-234 port.
    ///
    /// ADVERSARIAL §5.2: `task_id` is GUEST-SUPPLIED — `decode_llm_request` applies no
    /// cap and no charset check, and `freeze_request_attribution` lets an explicit guest
    /// value win over the host's tracked id. The port's "ids only, never prompt or
    /// message bytes" promise is about PROVENANCE, which the producer cannot verify, so
    /// it is enforced here as a BOUND instead: an over-long id is truncated at a
    /// char-safe cut rather than cloned wholesale onto the egress path (256 live streams
    /// × an unbounded string was the amplification). Truncation keeps a PREFIX, so two
    /// DISTINCT over-long guest ids sharing a 256-byte prefix collapse to the SAME
    /// published id — one more reason the `traits.rs` caveat forbids treating a
    /// `task_id` match as proof of task identity (round 23; an earlier sentence here
    /// wrongly reassured that a joining consumer could never see conflated ids).
    pub(crate) const MAX_BEGIN_ID_BYTES: usize = 256;

    fn bound_begin_id(id: Option<String>) -> Option<String> {
        id.map(|s| {
            if s.len() <= Self::MAX_BEGIN_ID_BYTES {
                return s;
            }
            let mut cut = Self::MAX_BEGIN_ID_BYTES;
            while cut > 0 && !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s[..cut].to_string()
        })
    }

    pub(crate) fn publish_begin(&self, run_id: Option<String>, task_id: Option<String>) {
        if !self.is_live() {
            return;
        }
        let run_id = Self::bound_begin_id(run_id);
        let task_id = Self::bound_begin_id(task_id);
        // AUDIT round 6: latch BEFORE emitting. Storing it afterwards left a window in
        // which a reap / `Drop` / TTL sweep could read `begin_published == false`,
        // return without consuming the terminal CAS, and — because `finalize` is
        // settle-once — leave the stream with a `Begin` and no `Terminal` FOREVER.
        // AUDIT round 8: take the guard BEFORE latching `begin_published`. Setting the
        // flag first left a two-instruction window in which a settlement winner could
        // take `order`, read the flag as true, emit `Terminal` AHEAD of the `Begin`,
        // and spend the exactly-once CAS — bypassing the park entirely and stranding
        // the stream exactly as the round-7 fix was meant to prevent. Latching under
        // the guard makes "flag set" and "Begin emitted" atomic with respect to
        // `publish_terminal`.
        let guard = self
            .order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.begin_published
            .store(true, std::sync::atomic::Ordering::Release);
        self.emit_under(
            &guard,
            advance_shared_types::traits::LlmDeltaFrame::Begin { run_id, task_id },
        );
        // Flush a terminal that settled before this `Begin` could be published, in
        // order and under the same guard. Without this the stream would begin and
        // never end (AUDIT round 7).
        let parked = self
            .pending_terminal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(frame) = parked {
            self.emit_under(&guard, frame);
        }
    }

    pub(crate) fn publish_delta(&self, seq: u64, text: &str) {
        // Begin-before-Delta was previously held only by the owner's call order in
        // `stream_begin_live` — an unstated remote invariant. Enforce it here so the
        // type itself cannot emit a delta for a stream a consumer has not seen begin
        // (AUDIT round 9).
        if !self.is_live()
            || !self
                .begin_published
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        self.emit(advance_shared_types::traits::LlmDeltaFrame::Delta {
            seq,
            text: text.to_string(),
        });
    }

    /// Publish the terminal frame at most once, and only for a stream that began.
    pub(crate) fn publish_terminal(
        &self,
        seq: u64,
        reason: advance_shared_types::traits::LlmTerminalReason,
        usage: Option<advance_shared_types::traits::LlmDeltaUsage>,
    ) {
        // NOTE (AUDIT round 11): no `is_live()` early return before the CAS. `is_live`
        // ANDs the sink's `is_wired` with the `disabled` latch, and `disabled` DOES flip
        // mid-stream — so returning here let a panicking sink strand a begun stream:
        // the settlement winner would return without spending the latch, and
        // `finalize` being settle-once, nothing retried. The latch is consumed first;
        // whether anything is actually emitted is decided afterwards.
        let guard = self
            .order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Consume the exactly-once latch UNCONDITIONALLY. The previous form returned
        // early when `Begin` had not shipped yet, without consuming it — and since
        // `finalize` is settle-once, no later path ever retried.
        if self
            .terminal_published
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        let frame = advance_shared_types::traits::LlmDeltaFrame::Terminal { seq, reason, usage };
        if self
            .begin_published
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.emit_under(&guard, frame);
        } else {
            // Park it; `publish_begin` emits it immediately after the `Begin`.
            *self
                .pending_terminal
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(frame);
        }
    }

    #[cfg(test)]
    pub(crate) fn is_disabled(&self) -> bool {
        self.disabled.load(std::sync::atomic::Ordering::Acquire)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum LivePhase {
    Running,
    Done {
        model: String,
        input_tokens: u64,
        output_tokens: u64,
        finish_reason: String,
        parsed_output: Option<Vec<u8>>,
        schema_validation: Option<&'static str>,
    },
    Failed(crate::LlmError),
}

impl Default for LivePhase {
    fn default() -> Self {
        LivePhase::Running
    }
}

/// Settlement outcome classes (plan §4). They determine the bill:
/// - `FailedBegin`: head-only exchange (chain error / non-200 / handoff failure /
///   registry-full pre-dispatch) — bills ZERO. No billable generation demonstrably
///   occurred; the reservation drains at run end (ADR D2.6).
/// - `Terminal`: the owner reached a terminal (success OR mid-stream failure) —
///   bills folded usage where seen, conservative byte ceilings otherwise
///   (over-count before under-count, ADR D2.5).
/// - `Abandoned`: a Drop/reaper winner (guest abandoned the handle, or the owner
///   died before settling) — bills like `Terminal` with whatever usage/bytes were
///   observed. Abandoned streams are never free.
pub(crate) enum SettleOutcome {
    FailedBegin,
    Terminal,
    Abandoned,
    /// Host-authoritative turn-end reap (ADR 2026-07-22 D5, tee slice T3). Bills
    /// exactly like [`Self::Abandoned`] — an abandoned stream is never free — and is a
    /// distinct variant ONLY so the CONTRACT-234 terminal reason can say `Reaped`
    /// without matching on an error string.
    Reaped,
}

/// Settlement — the ONE terminal authority (plan §4).
///
/// `finalize` is the winner package (structure as of rounds 24–27 — round 31
/// reverted a round-30 "24–28" label; round 32 precised the reason: round 28's
/// only non-comment change in this file was an `eprintln!` string inside
/// `finalize` — a diagnostic, not structure; an earlier
/// form of this doc still described the pre-round-24 commit-inside-the-lock
/// shape — the exact structure whose daemon-wide stall on the current-thread
/// production runtime was round 24's lead Critical): seal FIRST (its own earlier
/// lock acquisition), then read-flag → compute bill → RECORD figures + claim →
/// set-flag in ONE `std::sync::Mutex` critical section, then — still as the
/// winner, OUTSIDE every guard — the CONTAINED `RunBudget::commit` call (claim
/// corrected to un-committed before anything publishes if the implementer
/// panics), exactly ONE CONTAINED terminal event attempt
/// (`llm.response`/`llm.error` with the Δ7 `submitted_*` values = the bill
/// actually submitted), the terminal phase publication (poison-recovering) +
/// notify, and finally the CONTRACT-234 tee `Terminal`. Seal precision (rounds
/// 30–31): a LOSER that read `committed == false` may also write the idempotent
/// seal before losing the latch — losers produce no state a winner does not
/// already produce — and the ONLY production finalize that runs UNBOUND (hence
/// seals nothing) is `stream_begin_live`'s handoff-failure arm, which fires
/// before `bind`; the other three `FailedBegin` causes (registry-full, chain
/// error/deadline, non-200 head) bind first and DO seal (round 31 corrected a
/// round-30 parenthetical that named "pre-bind `Drop`" — no reachable path —
/// and implied all of `FailedBegin` was unbound). The exactly-once
/// invariants are pinned by `t121_settlement_exactly_once_nonblocking_commit`
/// (the rewritten, renamed T121 arm — the original arm pinned the removed
/// commit-inside-the-lock mechanism). EVERY terminal path converges here: owner
/// terminal, owner failure arms, deadline arm, guest Drop, reaper Drop,
/// claim-side Drop — plus turn-end reap and the TTL sweep, which reach it
/// through `settle_and_evict`/`settle_expired_batch`. Losers do nothing
/// observable (at most the idempotent seal above), so no path can
/// double-commit, double-emit, or publish a terminal before its accounting
/// exists.
pub(crate) struct Settlement {
    inner: std::sync::Mutex<SettlementInner>,
    budget: Option<Arc<dyn RunBudget>>,
    emitter: Option<Arc<dyn advance_shared_types::traits::EventBusEmit + Send + Sync>>,
    agent_id: String,
    /// Bound at LiveStream construction so Drop/reaper winners can publish the
    /// terminal phase + wake pollers (no cycle: these are the shared inner Arcs,
    /// not the registry entry).
    bound: std::sync::Mutex<Option<(Arc<std::sync::Mutex<LiveState>>, Arc<Notify>)>>,
    /// CONTRACT-234 tee, bound alongside `bound` so every settlement winner — owner,
    /// deadline, `Drop`, TTL sweep, turn-end reap — can publish the one `Terminal`.
    tee: std::sync::Mutex<Option<Arc<TeeState>>>,
    /// Set by the consume loop when the mid-stream budget ceiling trips. Read by
    /// `finalize` to report `BudgetExhausted` — the breach is coded as a generic
    /// `ProviderError`, and matching its message text would silently break the moment
    /// that string is reworded.
    ceiling_breached: std::sync::atomic::AtomicBool,
}

struct SettlementInner {
    committed: bool,
    run_id: Option<String>,
    /// Token ceilings from the reservation (input = serialized body bytes at
    /// 1 byte/token; output = resolved max_tokens). Bills clamp per-component
    /// to these before summing (plan §4).
    input_estimate: u64,
    output_estimate: u64,
    /// ALL decoded output bytes — counted at DECODE time, before release,
    /// suppression, or hold, so capped/held/abandoned output is never free.
    decoded_output_bytes: u64,
    /// Provider usage folded LWW by the owner (None until a usage frame arrives).
    folded_input: Option<u64>,
    folded_output: Option<u64>,
    /// `decoded_output_bytes` as of the last time the provider reported OUTPUT usage.
    /// Bytes decoded after that point are not covered by the reported figure, and
    /// billing adds them back — see `finalize`. Adversarial round 16 found that
    /// without this, a single early usage frame permanently suppressed the
    /// decoded-byte fallback and a guest could receive real generated text for free.
    decoded_at_last_output_usage: u64,
    model: String,
    cost_per_mtoken_in: f64,
    cost_per_mtoken_out: f64,
    /// The bill actually submitted (set by the winner; read by tests/snapshot).
    submitted: Option<(u64, u64, f64)>,
    /// Whether `RunBudget::commit` was really called for this stream. `submitted` is
    /// set even when it was not (no budget wired, or no run_id), so this is what
    /// distinguishes a charged bill from a computed one.
    ledger_committed: bool,
    /// Begin instant, so terminal records carry REAL wall-time. §3.5.1's envelope
    /// contract requires `duration_ms` to be a measured latency; hardcoding 0 (as
    /// the first S4 rounds did) silently zeroed every live-stream latency in the
    /// canonical event row.
    began_at: Instant,
}

impl Settlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: Option<String>,
        input_est: u64,
        output_est: u64,
        model: String,
        cost_per_mtoken_in: f64,
        cost_per_mtoken_out: f64,
        budget: Option<Arc<dyn RunBudget>>,
        emitter: Option<Arc<dyn advance_shared_types::traits::EventBusEmit + Send + Sync>>,
        agent_id: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(SettlementInner {
                committed: false,
                run_id,
                input_estimate: input_est,
                output_estimate: output_est,
                decoded_output_bytes: 0,
                decoded_at_last_output_usage: 0,
                folded_input: None,
                folded_output: None,
                model,
                cost_per_mtoken_in,
                cost_per_mtoken_out,
                submitted: None,
                ledger_committed: false,
                began_at: Instant::now(),
            }),
            budget,
            emitter,
            agent_id,
            bound: std::sync::Mutex::new(None),
            tee: std::sync::Mutex::new(None),
            ceiling_breached: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Bind the CONTRACT-234 tee for this stream (tee slice T1). Separate from
    /// [`Self::bind`] so the nine-argument constructor is untouched.
    pub(crate) fn bind_tee(&self, tee: Arc<TeeState>) {
        *self.tee.lock().unwrap_or_else(|p| p.into_inner()) = Some(tee);
    }

    /// The bound tee, if any (cheap `Arc` clone; the guard is never held across a publish).
    pub(crate) fn tee(&self) -> Option<Arc<TeeState>> {
        // Recover rather than propagate: this runs on EVERY guest-visible delta, and
        // one poisoning must degrade the tee to silence, not turn every subsequent
        // `poll_live` into a panic (AUDIT round 7).
        self.tee.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Bind the shared state/notify so ANY winner (incl. Drop/reaper) can publish
    /// the terminal phase and wake pollers. Called once at LiveStream construction.
    pub fn bind(&self, state: Arc<std::sync::Mutex<LiveState>>, notify: Arc<Notify>) {
        // Poison-tolerant like the settle path (round 23 extended the §5.2 round-2
        // sweep to every Settlement lock: a `commit` panic under `inner` must not
        // convert the guest's next append/poll into a second panic).
        *self.bound.lock().unwrap_or_else(|p| p.into_inner()) = Some((state, notify));
    }

    /// Count decoded output bytes at DECODE time (pre-release/suppression).
    pub fn add_decoded_bytes(&self, bytes: u64) {
        // Poison-tolerant (round 23; see `bind`). Accounting fields are saturating
        // monotone counters, so recovery cannot regress a bill.
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.decoded_output_bytes = g.decoded_output_bytes.saturating_add(bytes);
    }

    /// Record LWW-folded provider usage (owner, pre-finalize).
    pub fn set_folded(&self, input: Option<u64>, output: Option<u64>) {
        // Poison-tolerant (round 23; see `bind`); the monotonic floors below make
        // recovery safe — a torn write can only be raised, never lowered.
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(reported_in) = input {
            // Same monotonic floor as the output leg below. Adversarial round 18 found
            // the floor had been applied to output ONLY, leaving the identical erasure
            // open on this axis — and found round 17's own commit message claiming
            // `set_folded` "only ever raises the figure", which was true of one branch.
            // Unreachable through the three shipped adapters (each reports input at most
            // once per stream: Anthropic at `message_start`, OpenAI in its single
            // terminal frame), but a code-level gap is a code-level gap.
            g.folded_input = Some(reported_in.max(g.folded_input.unwrap_or(0)));
        }
        if let Some(reported) = output {
            // MONOTONIC FLOOR. A provider report may only ever raise the figure.
            // Adversarial round 17: without this, `usage(1,100)` -> 500 bytes ->
            // `usage(1,50)` billed 50 output tokens for 500 delivered bytes — a later,
            // LOWER report retroactively erased billing for content that had already
            // flowed. `SseUsageFold::apply` is unconditional last-write-wins and has no
            // monotonicity guard of its own, so the floor lives here, at the accounting
            // boundary that actually owns the invariant.
            let floored = reported.max(g.folded_output.unwrap_or(0));
            g.folded_output = Some(floored);
            // Watermark: everything decoded so far is covered by this report.
            g.decoded_at_last_output_usage = g.decoded_output_bytes;
        }
    }

    /// The bill this settlement WOULD submit right now, by the one formula in
    /// `finalize`. Exists so callers building a terminal phase cannot drift from it —
    /// adversarial round 17 found `stream_begin_live` had its own second copy of the
    /// formula, so the ledger was corrected by round 16's fix while the guest-visible
    /// terminal still reported the stale figure (cost_usd and output_tokens in the same
    /// record disagreed).
    pub fn projected_bill(&self) -> (u64, u64) {
        // Poison-tolerant (round 23; see `bind`).
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::compute_bill(&g)
    }

    pub fn decoded_output_bytes(&self) -> u64 {
        // Poison-tolerant (round 23; see `bind`).
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .decoded_output_bytes
    }

    pub fn run_id(&self) -> Option<String> {
        // Poison-tolerant (round 23; see `bind`).
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .run_id
            .clone()
    }

    /// Wall-time since begin, for the terminal chunk's `latency_ms`.
    pub fn elapsed_ms(&self) -> u64 {
        // Poison-tolerant (round 23; see `bind`).
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.began_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    /// Whether `RunBudget::commit` was invoked for this stream AND RETURNED
    /// normally (round 26 named the predicate exactly — an earlier form said "the
    /// call was made", which a panicking call also satisfies).
    ///
    /// `RunBudget::commit` returns `()`, so even `true` records nothing about the
    /// implementer's acceptance. `false` covers BOTH no-charge-attempted (no budget
    /// or `run_id` wired) and call-panicked — in the panic case the producer cannot
    /// know whether the implementer charged durably before unwinding, so `false`
    /// is the CONSERVATIVE reading and `Terminal.usage` reads `None` while the bus
    /// record still carries the computed figures (the recorded three-channel
    /// divergence, MODULE-009 §3.6.6 item 4).
    ///
    /// Write protocol (rounds 24–26): the winner records this flag under the lock
    /// as its CLAIM before the call executes outside the lock; on a panicking
    /// implementer the claim is corrected to `false` before the phase publishes.
    /// Every guest-visible reader is gated on that phase, so the transient claim
    /// state is unobservable.
    pub(crate) fn ledger_committed(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .ledger_committed
    }

    /// The bill the winner submitted, if settled: (input_tokens, output_tokens, cost_usd).
    /// `FailedBegin` winners record (0, 0, 0.0).
    pub fn submitted_bill(&self) -> Option<(u64, u64, f64)> {
        // Poison-tolerant: reached from `finalize`'s terminal-frame block (ADVERSARIAL
        // §5.2 round 2 — no lock on the settle path may panic).
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .submitted
    }

    /// THE billing formula — one copy, shared by `finalize` and `projected_bill`.
    ///
    /// Provider usage where seen, PLUS any output decoded after that report (which the
    /// report by definition does not cover), each component clamped to its own
    /// reservation ceiling before the checked sum. Round 16 added the addend after an
    /// attack billed 2 tokens for 4000 delivered bytes; round 17 made this the single
    /// source of truth after finding a second, stale copy of the formula in the
    /// gateway's terminal-phase construction.
    fn compute_bill(g: &SettlementInner) -> (u64, u64) {
        let bin = g
            .folded_input
            .unwrap_or(g.input_estimate)
            .min(g.input_estimate);
        let bout = match g.folded_output {
            Some(reported) => {
                let uncovered = g
                    .decoded_output_bytes
                    .saturating_sub(g.decoded_at_last_output_usage);
                reported.saturating_add(uncovered).min(g.output_estimate)
            }
            None => g.decoded_output_bytes.min(g.output_estimate),
        };
        (bin, bout)
    }

    /// The winner package (see type docs). Returns true only for the winner.
    /// `terminal` is the phase the winner publishes (Done for success, Failed
    /// otherwise); it is published AFTER commit + event, never before.
    pub fn finalize(&self, outcome: SettleOutcome, terminal: LivePhase) -> bool {
        // SEAL FIRST, then bill. The write latch must close BEFORE the bill is computed,
        // not after it is committed.
        //
        // Round 20 moved the latch key from the published phase to a `settled` flag set
        // alongside the commit, which narrowed the window but did not close it: the flag
        // write has to take the LiveState lock, so a writer already inside
        // `append_released` holding that lock makes the finalizer wait — and by the time
        // the flag lands, those bytes are already in the visible buffer, on the far side
        // of a bill that was computed without them. Round 21 reproduced that.
        //
        // Sealing before `compute_bill` runs removes the window entirely rather than
        // narrowing it again: once this returns, no further byte can enter the buffer, so
        // whatever the bill counts is exactly what the guest can ever have seen. A racing
        // writer either completed before the seal (and is therefore counted) or is
        // refused after it. Losers of the settle-once race skip this — they take the
        // `committed` early return below without touching the seal.
        // ADVERSARIAL §5.2 round 2: these three acquisitions were the ONLY
        // poison-intolerant locks on the settle path, and this same function already
        // treats the very same `state` mutex tolerantly further down (since round 27
        // the publish site RECOVERS it outright — the cited `if let Ok` form is gone),
        // as do `reap_agent`, `tee()`, `bind_tee` and `ledger_committed()`. The
        // inconsistency was load-bearing: one poisoned `LiveState` made `finalize` panic
        // here and poison `bound` on the way out, after which the settlement could never
        // be finalized OR evicted — which is what turned a contained panic into a wedged
        // registry, and on the `insert_live`/`poll_live` legs into a panic-while-
        // unwinding `abort()`. Recovering keeps settle-once semantics intact: the flags
        // read here are plain `bool`s, and a poisoned guard's data is the same data.
        {
            let already = self
                .inner
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .committed;
            if !already {
                if let Some((state, _)) = self
                    .bound
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .as_ref()
                {
                    state.lock().unwrap_or_else(|p| p.into_inner()).settled = true;
                }
            }
        }

        // --- critical section: read-flag → compute bill → record → set-flag ---
        //
        // ROUND 24 (both reviewers, Critical): the `RunBudget::commit` CALL moved OUT
        // of this critical section. Holding `inner` across the implementer's fsyncs
        // meant every reader of this settlement — the owner task's per-delta
        // `add_decoded_bytes` and a guest poll's `claim_done` accessors, all on the
        // runtime thread — blocked for the fsync duration, which on the production
        // CURRENT-THREAD runtime re-created the daemon-wide stall the deferred reap
        // exists to remove. The WINNER is still decided here (the `committed` latch),
        // so exactly-once is untouched; the call executes below on the winner path
        // BEFORE any terminal event or phase publication, so "no terminal before its
        // accounting" is also untouched; and a panicking `commit` can no longer
        // poison `inner`. `ledger_committed` is written here as the winner's CLAIM
        // on the commit call; the call executes just below, and on a panicking
        // implementer the claim is corrected to `false` before anything publishes
        // (round 25) — so by the time any guest-visible read is possible (all are
        // gated on the phase published at the end of this function), the flag means
        // exactly "the call ran AND RETURNED" (round 27 aligned this comment with
        // the accessor's precise predicate — a panicking call was also 'made').
        let (commit_charge, run_id, model, billed_in, billed_out, billed_cost, elapsed_ms) = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if g.committed {
                return false;
            }
            let (bin, bout) = match outcome {
                SettleOutcome::FailedBegin => (0u64, 0u64),
                SettleOutcome::Terminal | SettleOutcome::Abandoned | SettleOutcome::Reaped => {
                    Self::compute_bill(&g)
                }
            };
            let cost = (bin as f64 / 1_000_000.0) * g.cost_per_mtoken_in
                + (bout as f64 / 1_000_000.0) * g.cost_per_mtoken_out;
            let mut commit_charge: Option<(String, u64, f64)> = None;
            if !matches!(outcome, SettleOutcome::FailedBegin) {
                if let (Some(_), Some(rid)) = (&self.budget, &g.run_id) {
                    commit_charge = Some((rid.clone(), bin.saturating_add(bout), cost));
                }
            }
            g.submitted = Some((bin, bout, cost));
            // AUDIT round 9 (predicate precised rounds 27/31): `submitted` is set
            // unconditionally, but `commit` is only CALLED when the outcome is not
            // `FailedBegin` AND BOTH a budget and a run_id are wired. Recording
            // which happened is what keeps
            // `Terminal.usage` honest — its contract is "a bill for which
            // `RunBudget::commit` ran AND RETURNED, never a projection" (still
            // nothing about acceptance: commit returns `()`), and without this flag
            // an unbudgeted stream shipped a non-zero phantom bill. On a panicking
            // call the claim below is corrected to `false` before publication.
            g.ledger_committed = commit_charge.is_some();
            g.committed = true;
            (
                commit_charge,
                g.run_id.clone(),
                g.model.clone(),
                bin,
                bout,
                cost,
                g.began_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            )
        };

        // --- winner-only, outside the lock: the ledger call FIRST (fsyncs happen
        // here, with no Settlement lock held), then exactly ONE terminal event
        // attempt, then the phase publication — the pre-round-24 order, minus the
        // lock held across the fsyncs. CONTAINED (round 25, both reviewers): with
        // the `committed` latch now claimed BEFORE the call, an uncontained panic
        // here would strand the stream PERMANENTLY un-terminated — no bus record,
        // no phase publication, no CONTRACT-234 `Terminal`, a parked poller left
        // to its deadline — because every later settlement path loses the latch.
        // (Pre-round-24, the same panic left `committed` false and a later path
        // retried — at the risk of a second charge. That retry is deliberately
        // traded away: the winner now owns the terminal UNCONDITIONALLY.) On a
        // panicking implementer the claim is corrected to `ledger_committed =
        // false` before anything publishes, so `Terminal.usage` stays honest
        // (`None`) — the transient true-before-call state is never guest-visible,
        // since every guest-visible read is gated on the phase published below.
        if let (Some(b), Some((rid, tokens, cost))) = (&self.budget, &commit_charge) {
            let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                b.commit(rid, *tokens, *cost)
            }));
            if call.is_err() {
                self.inner
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .ledger_committed = false;
                eprintln!(
                    "cap-llm: RunBudget::commit panicked; terminal still publishes; \
                     tee usage=None, bus record carries the computed figures, \
                     ledger state unknown (charge may or may not have landed)"
                );
            }
        }

        // --- winner-only, outside the lock: exactly ONE terminal event attempt ---
        // CONTAINED (round 27, adversarial): this was the only EXTERNAL-implementor
        // call on the winner tail without a `catch_unwind` — a panicking emitter
        // unwound out of `finalize` AFTER `committed = true` and the ledger charge,
        // skipping the phase publication forever: the stream stayed `Running` while
        // settled, un-evictable by the phase-gated reap arm and invisible to a
        // parked poller until its own deadline. The emit is best-effort telemetry;
        // the phase publication is the guest-visible contract — never trade the
        // second for the first.
        let emit_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(bus) = &self.emitter {
                let ctx = crate::gateway::LlmRequestContext {
                    agent_id: self.agent_id.clone(),
                    task_id: None,
                    run_id,
                    iteration: None,
                    trace_id: None,
                    messages: vec![],
                    params: crate::gateway::ChatParams {
                        model: Some(model.clone()),
                        ..Default::default()
                    },
                    output_schema: None,
                };
                match &terminal {
                    LivePhase::Done {
                        finish_reason,
                        parsed_output,
                        schema_validation,
                        ..
                    } => {
                        let resp = crate::gateway::ChatResponse {
                            text: String::new(),
                            model: model.clone(),
                            input_tokens: billed_in,
                            output_tokens: billed_out,
                            finish_reason: finish_reason.clone(),
                            parsed_output: parsed_output.clone(),
                        };
                        crate::events::emit_llm_response(
                            bus.as_ref(),
                            &ctx,
                            &resp,
                            billed_cost,
                            elapsed_ms,
                            None,
                            *schema_validation,
                        );
                    }
                    LivePhase::Failed(e) => {
                        crate::events::emit_llm_error(
                            bus.as_ref(),
                            &ctx,
                            &model,
                            e.variant_name(),
                            0,
                            Some(billed_in),
                            Some(billed_out),
                            Some(billed_cost),
                        );
                    }
                    LivePhase::Running => {
                        // A winner never publishes Running; treat as an abandoned error
                        // record (defensive — no caller passes Running).
                        crate::events::emit_llm_error(
                            bus.as_ref(),
                            &ctx,
                            &model,
                            "provider-error",
                            0,
                            Some(billed_in),
                            Some(billed_out),
                            Some(billed_cost),
                        );
                    }
                }
            }
        }));
        if emit_outcome.is_err() {
            eprintln!(
                "cap-llm: terminal event emitter panicked — NO llm.response/llm.error \
                 bus record exists for this stream; ledger charge and CONTRACT-234 \
                 terminal (usage intact) still proceed"
            );
        }

        // --- winner-only: publish the terminal phase LAST, then wake pollers ---
        // `tee_seq` is the count of guest-visible deltas allocated for this stream,
        // read under the SAME guard that clears `pending` — so the CONTRACT-234
        // `Terminal.seq` is exact rather than a racy pre-lock snapshot. It stays
        // `None` ONLY when there is NO BINDING (round 28: the round-27
        // poison-recovering publish removed the poisoned arm — a recovered
        // `LiveState` now publishes its real `next_seq`, which after a mid-snapshot
        // panic can over-report by one; the watermark-only contract on
        // `Terminal.seq` makes that safe). The publish site below floors `None` to
        // 0 (AUDIT round 11 reconciled this note with the one at the publish site;
        // both were re-synced at round 28 after the recovery change falsified
        // them).
        let mut tee_seq: Option<u64> = None;
        if let Some((state, notify)) = self.bound.lock().unwrap_or_else(|p| p.into_inner()).clone()
        {
            {
                // Poison-RECOVERING (round 27; a silent `if let Ok` skip here left a
                // settled stream `Running` forever — un-evictable by the phase-gated
                // reap arm, invisible to parked pollers; recovery writes only the
                // phase enum + clears `pending`, which cannot tear byte-ranges).
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                let publish = match &terminal {
                    LivePhase::Running => {
                        LivePhase::Failed(crate::LlmError::ProviderError("stream abandoned".into()))
                    }
                    other => other.clone(),
                };
                // Failure clears undelivered ranges (plan §3: failure never
                // flushes withheld deltas; delivered ones are not retracted).
                if matches!(publish, LivePhase::Failed(_)) {
                    st.pending.clear();
                }
                st.phase = publish;
                tee_seq = Some(st.next_seq);
            }
            notify.notify_waiters();
        }

        // --- CONTRACT-234 terminal frame (tee slice T1) ---
        //
        // Published here, outside every cap-llm guard above, because this is the ONE
        // winner across all six settlement call sites (owner terminal, the three
        // pre-handle failure arms, `Drop`, TTL sweep) plus turn-end reap — so
        // "exactly one Terminal" holds by the same construction that already gives
        // exactly one commit and one terminal record. `TeeState` suppresses it for a
        // stream that never published `Begin`.
        //
        // NOTE (recorded, MODULE-009 §2.3 "AS BUILT" ordering paragraph): on a SUCCESS
        // terminal `pending` is NOT cleared, so a poller may still drain ranges after
        // this point and publish deltas afterwards. Their `seq` may be BELOW, EQUAL TO
        // or ABOVE `tee_seq` — this counter is read without incrementing while a
        // poller allocates and publishes outside the state lock, so the emission race
        // decides. The ordering mutex guarantees no OVERLAP, not that the terminal is
        // last. Consumers must accept post-terminal deltas unconditionally.
        if let Some(tee) = self.tee() {
            let reason = match (&outcome, &terminal) {
                // Reason precedence, settled at AUDIT round 9 after rounds 7 and 8
                // moved it twice in opposite directions:
                //   `Reaped` FIRST — MODULE-009-AC-22's frozen text says turn-end reap
                //   delivers `Terminal(Reaped)`, and `reap_agent` always settles as
                //   `Failed`, so a ceiling-first ordering made `Reaped` unreachable for
                //   every CEILING-BREACHED reap. (AUDIT round 10 corrected this
                //   comment: the round-8 arm was itself guarded by `ceiling_breached`,
                //   so non-breached reaps still reached `Reaped` — the defect was
                //   narrower than an earlier version of this note claimed.)
                //   Then the ceiling flag, which outranks the remaining labels because
                //   a budget breach is why those streams failed.
                (SettleOutcome::Reaped, _) => {
                    advance_shared_types::traits::LlmTerminalReason::Reaped
                }
                (SettleOutcome::Abandoned, _) | (SettleOutcome::Terminal, LivePhase::Failed(_))
                    if self
                        .ceiling_breached
                        .load(std::sync::atomic::Ordering::Acquire) =>
                {
                    advance_shared_types::traits::LlmTerminalReason::BudgetExhausted
                }
                (SettleOutcome::Abandoned, _) => {
                    advance_shared_types::traits::LlmTerminalReason::Abandoned
                }
                // A stream that never delivered its handle published no `Begin`, so
                // this arm is suppressed inside `publish_terminal`; it is spelled out
                // rather than left to a catch-all so the match stays total.
                (SettleOutcome::FailedBegin, _) => {
                    advance_shared_types::traits::LlmTerminalReason::ProviderError
                }
                (SettleOutcome::Terminal, LivePhase::Done { .. }) => {
                    advance_shared_types::traits::LlmTerminalReason::Completed
                }
                // NOTE: `ceiling_breached` is handled by the leading guard arm above,
                // so it is deliberately NOT re-tested here (AUDIT round 8 found the
                // duplicate check unreachable). The explicit flag — never an
                // error-string match — is what keeps `BudgetExhausted` stable when the
                // generic `ProviderError` message is reworded.
                (SettleOutcome::Terminal, LivePhase::Failed(e)) => {
                    if matches!(e, crate::LlmError::RepetitionTerminated(_)) {
                        advance_shared_types::traits::LlmTerminalReason::Aborted
                    } else {
                        advance_shared_types::traits::LlmTerminalReason::ProviderError
                    }
                }
                (SettleOutcome::Terminal, LivePhase::Running) => {
                    advance_shared_types::traits::LlmTerminalReason::ProviderError
                }
            };
            // Only report usage a `commit` call ran AND RETURNED for (AUDIT round 9,
            // predicate precised round 27; nothing about acceptance — commit
            // returns `()`; a panicked call reads `false` here, conservatively).
            let usage = self
                .ledger_committed()
                .then(|| self.submitted_bill())
                .flatten()
                .map(|(input_tokens, output_tokens, cost_usd)| {
                    advance_shared_types::traits::LlmDeltaUsage {
                        input_tokens,
                        output_tokens,
                        cost_usd,
                    }
                });
            // `None` means there is NO BINDING (round 28: the poisoned arm is gone —
            // the round-27 recovery publishes the real `next_seq` instead), so the
            // real watermark is unknown only in the unbound case. There is no better value
            // available here — 0 is a floor, not a claim — and `Terminal.seq` is
            // documented as a watermark rather than a completeness signal precisely so
            // a consumer cannot read this as "the stream produced no deltas".
            // (AUDIT round 9: an earlier comment here described a fallback to the
            // settled delta count, which this code never did.)
            tee.publish_terminal(tee_seq.unwrap_or(0), reason, usage);
        }
        true
    }

    /// Mark that this stream tripped the mid-stream budget ceiling, so the terminal
    /// reason can be `BudgetExhausted` without matching on an error string.
    pub(crate) fn mark_ceiling_breached(&self) {
        self.ceiling_breached
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

/// The live stream handle (registry entry).
pub(crate) struct LiveStream {
    pub agent_id: String,
    pub created_at: Instant,
    pub deadline: Instant,
    pub state: Arc<std::sync::Mutex<LiveState>>,
    pub notify: Arc<Notify>,
    pub poll_gate: Arc<TokioMutex<()>>, // held across await to serialize polls (Δ4)
    pub settlement: Arc<Settlement>,
    pub task: JoinHandle<()>,
}

impl Drop for LiveStream {
    fn drop(&mut self) {
        // Ratified D2.4: Drop synchronously settles (commit is a sync trusted call)
        // and aborts the task. `finalize` is the full winner package — a Drop/reaper
        // winner also emits the one terminal record AND publishes the Failed phase +
        // notify (waiting pollers wake instead of hanging to deadline). A loser
        // (stream already settled by the owner/claim path) does nothing but abort.
        self.settlement.finalize(
            SettleOutcome::Abandoned,
            LivePhase::Failed(crate::LlmError::ProviderError("stream abandoned".into())),
        );
        self.task.abort();
    }
}

// === S4 decoded release pipeline (plan §6 + Δ5) ===
//
// Single decision authority: the injected CONTRACT-112 `LeakDetector` (in
// production the SAME instance the wire chain uses). cap-llm's own logic is hold
// GEOMETRY that can only over-hold, computed in CANONICAL space via cap-http's
// audited facade — a raw-byte window is the defect class the S3 audit round 2
// fixed (invisible/compat inflation must not push a match start out of
// retention).
//
// Soundness argument (as IMPLEMENTED — do not substitute a fixed-window story):
// the release cut is `decoded_hold_split`, the wire layer's own anchored-DFA
// viability walk over the canonical feed, so the released prefix stops at the
// FIRST position from which any Block/Redact pattern is still Matched-or-Viable.
// Consequently no byte of a live candidate or of a completed match is ever
// released, for bounded AND greedy families alike. A completed match resolves at
// terminal: Block fails closed, Redact emits the detector's derivative for the
// held region. Residual: a match whose start scrolled out of the 64-KiB raw
// shadow window (unbounded-interior pem-class text assembled across JSON escapes)
// — the wire layer covers contiguous instances; recorded in MODULE-009 §3.6.

/// Fail-closed outcome of a decoded-release step.
pub(crate) enum DecodedVerdict {
    /// Safe text released (possibly empty while the hold retains).
    Ok,
    /// Fail closed: the stream must terminate with the given static reason.
    Fail(&'static str),
}

/// Per-stream decoded pipeline state (owner-task local).
pub(crate) struct DecodedPipeline {
    /// Raw released text tail (never redacted — the detector's context window,
    /// so pattern anchors persist across fragments). ≤ 64 KiB.
    shadow_tail: Vec<u8>,
    /// Decoded-but-unreleased suffix. ≤ 256 KiB (crossing fails CLOSED, ADR D3).
    hold: Vec<u8>,
    /// Bytes decoded since the last scan (cadence gate).
    unscanned: usize,
    /// Total decoded bytes (cadence phase switch).
    total_decoded: usize,
}

const DECODED_TAIL_WINDOW: usize = 64 * 1024;
const DECODED_HOLD_CAP: usize = 256 * 1024;
const DECODED_SCAN_STEP: usize = 4 * 1024;

impl DecodedPipeline {
    pub fn new() -> Self {
        Self {
            shadow_tail: Vec::new(),
            hold: Vec::new(),
            unscanned: 0,
            total_decoded: 0,
        }
    }

    /// Feed one decoded fragment; returns text safe to release now (may be empty
    /// between scan points / while the hold retains). Scan cadence: every fragment
    /// while total decoded ≤ 4 KiB, then every ≥ 4 KiB of new bytes, and always at
    /// terminal (plan §6).
    pub fn push(
        &mut self,
        detector: &dyn advance_shared_types::security_validator::LeakDetector,
        fragment: &[u8],
    ) -> (String, DecodedVerdict) {
        self.hold.extend_from_slice(fragment);
        self.unscanned += fragment.len();
        self.total_decoded += fragment.len();
        if self.hold.len() > DECODED_HOLD_CAP {
            self.hold.clear();
            return (
                String::new(),
                DecodedVerdict::Fail("decoded hold cap exceeded"),
            );
        }
        if self.total_decoded > DECODED_SCAN_STEP && self.unscanned < DECODED_SCAN_STEP {
            return (String::new(), DecodedVerdict::Ok);
        }
        self.unscanned = 0;
        self.scan_and_release(detector, false)
    }

    /// Terminal resolution: final scan; open greedy candidates fail CLOSED even on
    /// a whole-string Clean (the ratified S3 NFKC-composition counterexample —
    /// cap-http streaming.rs:519-531 — forbids trusting the whole-string verdict
    /// for an entered per-char match); otherwise the tail releases.
    pub fn finish(
        &mut self,
        detector: &dyn advance_shared_types::security_validator::LeakDetector,
    ) -> (String, DecodedVerdict) {
        self.scan_and_release(detector, true)
    }

    fn scan_and_release(
        &mut self,
        detector: &dyn advance_shared_types::security_validator::LeakDetector,
        terminal: bool,
    ) -> (String, DecodedVerdict) {
        use advance_shared_types::security_validator::{Action, ScanContext, ScanResult};
        use cap_http::canonical_facade as cf;

        if self.hold.is_empty() {
            return (String::new(), DecodedVerdict::Ok);
        }

        // Scan input = raw shadow tail ++ hold (raw feed; the detector
        // canonicalizes internally, and Finding offsets land in canonical space).
        let mut scan_input: Vec<u8> = Vec::with_capacity(self.shadow_tail.len() + self.hold.len());
        scan_input.extend_from_slice(&self.shadow_tail);
        scan_input.extend_from_slice(&self.hold);
        let scan_str = match std::str::from_utf8(&scan_input) {
            Ok(s) => s.to_string(),
            // Hold bytes come from adapter-decoded Strings, so this arm is
            // defensive only: fail closed rather than scan a lossy view.
            Err(_) => {
                // Clear like every sibling fail-closed arm. Adversarial round 16 found
                // this arm and the budget-exhaustion arm below were the only two of nine
                // that left `hold` populated. Not reachable as a leak today (the sole
                // caller breaks out of its consume loop on any Fail and never drives the
                // pipeline again), but the asymmetry is exactly what a future refactor of
                // that call site would turn into one.
                self.hold.clear();
                return (
                    String::new(),
                    DecodedVerdict::Fail("decoded scan input not utf-8"),
                );
            }
        };

        // Hold geometry from the AUDITED wire-layer primitive (facade re-export,
        // plan stance 4 / Δ5): the largest raw offset releasable without emitting
        // any byte of a still-viable Block/Redact pattern, computed over the same
        // canonical feed and pattern table the wire layer hardened. Err = fail
        // CLOSED. Benign text has no viable candidate, so the split is the whole
        // buffer and short responses release immediately (no terminal-only delta).
        let canon_len_joined = cf::canonical_scan_text(&scan_str).len();
        let split_raw = match cf::decoded_hold_split(&scan_input, 400 * 1024) {
            Ok(n) => n,
            Err(()) => {
                // Same fail-closed discipline as every sibling arm (round 16).
                self.hold.clear();
                return (
                    String::new(),
                    DecodedVerdict::Fail("decoded hold budget exhausted"),
                );
            }
        };
        let shadow_len = self.shadow_tail.len();

        let verdict = detector.scan(&scan_str, ScanContext::HttpOutbound);

        // The release region is ALWAYS bounded by the hold split: it contains no
        // byte of any Matched-or-Viable candidate, for every verdict. So a
        // non-terminal release needs no derivative — the match bytes are still
        // held. Only terminal resolution consults the verdict's derivative.
        let cut_now = if terminal {
            self.hold.len()
        } else {
            floor_char_boundary(
                &self.hold,
                split_raw.saturating_sub(shadow_len).min(self.hold.len()),
            )
        };

        match verdict {
            ScanResult::Blocked { findings } => {
                // Open-at-end (the match can still grow): keep holding — the next
                // scan re-evaluates with the anchor intact. Otherwise terminate;
                // the completed match's bytes are inside the hold, which this arm
                // never releases.
                // Only Block/Redact findings bear on the hold: `Warn` rows (e.g.
                // `high_entropy_hex`) are pass-through by action, so letting one keep
                // `open` true would defer a CLOSED Block past its detecting scan
                // (re-audit F2).
                let open = findings
                    .iter()
                    .filter(|f| matches!(f.action, Action::Block | Action::Redact))
                    .any(|f| f.offset.saturating_add(f.length) >= canon_len_joined);
                if open && !terminal {
                    (String::new(), DecodedVerdict::Ok)
                } else {
                    self.hold.clear();
                    (String::new(), DecodedVerdict::Fail("blocked by detector"))
                }
            }
            ScanResult::Redacted { findings, .. } => {
                if !terminal {
                    // Release only up to the split (match bytes stay held).
                    return self.release_prefix(cut_now);
                }
                // Terminal: the match must resolve now. A finding that STARTS
                // inside the already-released shadow cannot be retracted — fail
                // CLOSED rather than emit its continuation (this is the defect the
                // merge-gate audit reproduced: a derivative-fed shadow destroyed
                // the anchor and leaked the tail).
                // `Finding.offset` values are measured over the canonicalization of the
                // JOINED shadow++hold. `shadow_canon_len` is the shadow's OWN
                // canonicalization, clamped to the joined length. What that bound is good
                // for — and what it is NOT — was established over audit rounds 4-6:
                //
                //   SOUND DIRECTION (start-based, which is what the guard tests). A
                //   composition at the concatenation boundary must absorb at least one
                //   shadow character, so the composed codepoint's START offset k in joined
                //   space satisfies k <= shadow_canon_len - 1. The guard below tests a
                //   finding's START. A finding whose bytes include released-derived content
                //   must begin at k (a match cannot begin mid-codepoint), and k <
                //   shadow_canon_len fires the guard. A finding beginning at or after
                //   shadow_canon_len begins strictly past that composed codepoint and so
                //   carries no released bytes. Note this is about where the composed region
                //   STARTS: its END can lie past shadow_canon_len, which is why an
                //   end-based phrasing of this argument (round 5's) was wrong.
                //
                //   DISCLOSED LIMIT (round 6; the CONDITION below was corrected in rounds
                //   7-8 — earlier revisions of this very comment stated it wrongly twice,
                //   so read it as written, not as remembered). NFKC is not only
                //   composition: it also canonically REORDERS by combining class.
                //   Reordering can move a shadow-origin mark to an index >=
                //   shadow_canon_len, so "every shadow-derived byte lives below
                //   shadow_canon_len" is FALSE as a general statement.
                //
                //   The bound stays safe because the Canonical Ordering Algorithm
                //   (UAX #15) permutes only NON-STARTERS — characters with a NON-ZERO
                //   canonical combining class — and no shipped LEAK_PATTERNS Block/Redact
                //   pattern can admit one, so a match's own characters can never be
                //   displaced across the bound.
                //
                //   The safety condition is NOT "the classes are ASCII-only". That
                //   phrasing was rejected in round 7 and is FALSE: `bearer_token` and
                //   `auth_header_basic` use `\s`, and the `regex` crate runs in Unicode
                //   mode by default, so U+1680 and U+2028 match — the same fact
                //   cap-http's `build_hold_matchers()` comment and MODULE-012 §2.9's
                //   round-2 history already record, where an ASCII-only `\s` DFA let a
                //   crafted `Bearer<U+1680>eyJ...` slip the wire-layer hold. Those
                //   codepoints are starters, so the conclusion held; the reason did not.
                //
                //   Do not re-derive this by hand: cap-http's in-crate
                //   `patterns::combining_class_invariant` test iterates the REAL
                //   LEAK_PATTERNS table, parses each Block/Redact row to its regex HIR,
                //   and checks every character class and literal the row can match
                //   against the non-zero-combining-class repertoire. It decides the
                //   question on the pattern's match LANGUAGE, not on a sample string —
                //   audit round 9 refuted an earlier sample-sweep form of this witness by
                //   widening a row with an alternation branch the sample could not reach.
                //   Widening the table in any shape breaks that test rather than silently
                //   invalidating this bound. See also MODULE-009 §3.6(8).
                //
                // Audit round 5 rejected the stricter alternative (requiring
                // `joined.starts_with(shadow_canon)` and failing closed otherwise): an
                // adversarial probe showed it denies ORDINARY content — a combining mark
                // near the boundary plus a later benign `Authorization: Basic ...` example
                // composes across the split and discarded the whole unreleased tail. That
                // is an availability regression with no security gain, since the guard is
                // one-sided: it can only over-hold, never release a match.
                let shadow_canon_len = match std::str::from_utf8(&self.shadow_tail) {
                    Ok(sh) => cf::canonical_scan_text(sh).len().min(canon_len_joined),
                    // Unreachable today (the shadow is built from `String` bytes drained on
                    // char boundaries), but a security bound must degrade CLOSED, never
                    // open: claiming the WHOLE joined region is already-released makes any
                    // finding trip the "spans released text" guard below. The rejected
                    // `unwrap_or("")` did the opposite — an empty shadow disables the guard.
                    Err(_) => canon_len_joined,
                };

                // Only Block/Redact findings can require retraction; a `Warn` row in
                // the already-released prefix (a 64-hex digest, say) has nothing to
                // retract and must not hard-fail an otherwise-fine stream
                // (re-audit F1: ordinary "digest <64 hex> ... Bearer eyJ..." content).
                if findings
                    .iter()
                    .filter(|f| matches!(f.action, Action::Block | Action::Redact))
                    .any(|f| f.offset < shadow_canon_len)
                {
                    self.hold.clear();
                    return (
                        String::new(),
                        DecodedVerdict::Fail("decoded match spans released text"),
                    );
                }
                // All findings lie inside the hold, so the hold is self-contained:
                // redact it ALONE (no cross-index-space prefix arithmetic) and
                // release that derivative, while the SHADOW keeps the ORIGINAL
                // bytes so later fragments still see the anchor.
                let hold_str = match std::str::from_utf8(&self.hold) {
                    Ok(t) => t.to_string(),
                    Err(_) => {
                        self.hold.clear();
                        return (
                            String::new(),
                            DecodedVerdict::Fail("decoded scan input not utf-8"),
                        );
                    }
                };
                match detector.scan(&hold_str, ScanContext::HttpOutbound) {
                    ScanResult::Blocked { .. } => {
                        self.hold.clear();
                        (String::new(), DecodedVerdict::Fail("blocked by detector"))
                    }
                    ScanResult::Redacted { redacted, .. } => {
                        let original: Vec<u8> = self.hold.drain(..).collect();
                        // The billing invariant this slice rests on is "counted before
                        // revealed": `add_decoded_bytes` runs on the RAW decoded bytes at
                        // decode time, ahead of the release. A redacted derivative that
                        // were LONGER than the bytes it replaces would break that — the
                        // extra bytes would reach the guest having never been counted, on
                        // the ordinary single-threaded path, with no concurrency needed.
                        //
                        // Adversarial round 22 measured that this holds today by exactly
                        // ONE byte: `redact_at_offsets` substitutes a fixed 10-byte
                        // `[REDACTED]`, and the shortest match either shipped Redact
                        // pattern can produce is 11 bytes (`bearer_token`; the Basic row
                        // needs 21). Nothing enforced that relationship — a new Redact row
                        // with a shorter minimum match, or a longer placeholder, would
                        // silently reopen it. So enforce it here rather than leaving it to
                        // a numeric coincidence between two files.
                        if redacted.len() > original.len() {
                            self.advance_shadow(&original);
                            return (
                                String::new(),
                                DecodedVerdict::Fail("decoded redaction expanded"),
                            );
                        }
                        self.advance_shadow(&original);
                        (redacted, DecodedVerdict::Ok)
                    }
                    // Defensive: the joined scan saw a match the isolated hold does
                    // not (a cross-boundary composition). Fail closed.
                    ScanResult::Clean | ScanResult::Warned { .. } => {
                        self.hold.clear();
                        (
                            String::new(),
                            DecodedVerdict::Fail("decoded redaction misalignment"),
                        )
                    }
                }
            }
            ScanResult::Clean | ScanResult::Warned { .. } => {
                if terminal && split_raw < scan_input.len() {
                    // EOF rule (S3): a hold still carrying a viable candidate is
                    // swept for a COMPLETED match with the non-short-circuiting
                    // walk and fails CLOSED on a hit — never trusting the
                    // whole-string Clean (the ratified NFKC-composition
                    // counterexample).
                    match cf::decoded_region_has_completed_match(&scan_input, 400 * 1024) {
                        Ok(true) => {
                            self.hold.clear();
                            return (
                                String::new(),
                                DecodedVerdict::Fail("unresolved credential candidate at eof"),
                            );
                        }
                        Ok(false) => {}
                        Err(()) => {
                            self.hold.clear();
                            return (
                                String::new(),
                                DecodedVerdict::Fail("decoded hold sweep exhausted"),
                            );
                        }
                    }
                }
                self.release_prefix(cut_now)
            }
        }
    }

    /// Release the first `cut` bytes of the hold verbatim (they are proven free of
    /// candidate bytes by the hold split) and shadow the ORIGINAL bytes so later
    /// fragments still present their real anchors to the detector.
    fn release_prefix(&mut self, cut: usize) -> (String, DecodedVerdict) {
        if cut == 0 {
            return (String::new(), DecodedVerdict::Ok);
        }
        let released: Vec<u8> = self.hold.drain(..cut).collect();
        self.advance_shadow(&released);
        (
            String::from_utf8_lossy(&released).to_string(),
            DecodedVerdict::Ok,
        )
    }

    fn advance_shadow(&mut self, released: &[u8]) {
        self.shadow_tail.extend_from_slice(released);
        if self.shadow_tail.len() > DECODED_TAIL_WINDOW {
            let excess = self.shadow_tail.len() - DECODED_TAIL_WINDOW;
            let cut = floor_char_boundary_min(&self.shadow_tail, excess);
            self.shadow_tail.drain(..cut);
        }
    }
}

/// Largest char-boundary ≤ idx for a valid-UTF-8 buffer (idx == len is a boundary;
/// otherwise walk back off continuation bytes).
fn floor_char_boundary(buf: &[u8], idx: usize) -> usize {
    let mut i = idx.min(buf.len());
    while i > 0 && i < buf.len() && (buf[i] & 0xC0) == 0x80 {
        i -= 1;
    }
    i
}

/// Smallest char-boundary ≥ idx (for shadow trimming — over-trim is safe).
fn floor_char_boundary_min(buf: &[u8], idx: usize) -> usize {
    let mut i = idx.min(buf.len());
    while i < buf.len() && (buf[i] & 0xC0) == 0x80 {
        i += 1;
    }
    i
}

/// Handle table shared by `AgentLlmStreamHandler` + `AgentLlmPollStreamHandler`
/// (one instance per `register_agent_llm` call). Handles are bound to the owning
/// agent — a `poll` from a different `agent_id` returns `Unknown`.
pub(crate) struct StreamRegistry {
    // Buffered for legacy / trait stream tests
    table: Mutex<HashMap<u64, BufferedStream>>,
    // Live for S4 WIT stream/poll
    live_table: Mutex<HashMap<u64, Arc<LiveStream>>>,
    next: AtomicU64,
}

impl StreamRegistry {
    pub(crate) fn new() -> Self {
        Self {
            table: Mutex::new(HashMap::new()),
            live_table: Mutex::new(HashMap::new()),
            // Start at 1 so a `0` handle (a plausible guest default) is never
            // a valid live handle.
            next: AtomicU64::new(1),
        }
    }

    /// Evict expired entries, then insert a finalized stream + its chunked delta
    /// ranges (the owning agent is read from `ready.ctx.agent_id`). Returns the
    /// new handle, or `None` when the registry is full (after eviction) — the
    /// caller maps that to a `provider-error`.
    pub(crate) fn insert(
        &self,
        deltas: VecDeque<(usize, usize)>,
        ready: ReadyStream,
    ) -> Option<u64> {
        let agent_id = ready.ctx.agent_id.clone();
        self.insert_at(deltas, ready, agent_id, Instant::now())
    }

    fn insert_at(
        &self,
        deltas: VecDeque<(usize, usize)>,
        ready: ReadyStream,
        agent_id: String,
        created_at: Instant,
    ) -> Option<u64> {
        let now = Instant::now();
        let mut table = self.table.lock().unwrap();
        table.retain(|_, b| now.duration_since(b.created_at) < crate::host_fn::STREAM_HANDLE_TTL);
        if table.len() >= MAX_CONCURRENT_STREAMS {
            return None;
        }
        let handle = self.next.fetch_add(1, Ordering::Relaxed);
        table.insert(
            handle,
            BufferedStream {
                deltas,
                ready,
                created_at,
                agent_id,
            },
        );
        Some(handle)
    }

    /// Defer a REMOVED-from-table expired batch's settlement off the caller's
    /// thread (round 25, adversarial C1): `insert_live` and `poll_live`'s inline
    /// TTL evictions ran `settle_expired_batch` — N serial `RunBudget::commit`
    /// fsyncs — on the guest's own host-call path, i.e. the production runtime
    /// thread; and with the 30-second sweep now deferred, a guest poll could steal
    /// the sweeper's still-resident victims and settle them inline. Entries handed
    /// here are already OUT of `live_table`, so settlement is NEVER LOST whatever
    /// happens to the task (round 26 precised an overstated timing claim): if the
    /// spawned task runs, `settle_expired_batch` settles (`Reaped`-after-TTL
    /// label); if the pool is SHUTTING DOWN, tokio drops the closure
    /// (`task.shutdown()` before returning), the batch `Vec` drops, and each entry
    /// settles via its own `Drop` — WHEN the last `Arc` goes, which may be a
    /// concurrent poller's or sweeper's clone rather than this batch. A panicking
    /// `spawn_blocking` CALL (worker-thread exhaustion) is contained here; on that
    /// tokio path the task was ALREADY QUEUED before the panic, so the batch is
    /// NOT dropped — round 27 precised the trigger and the drain: the panic is OS
    /// thread-creation REFUSAL (a permanent error, or a temporary one with ZERO
    /// live workers; cap-exhaustion queues and returns Ok, no panic), and the
    /// queued batch drains when an existing worker frees, when a LATER
    /// `spawn_blocking` successfully spawns one, or at pool shutdown (closure
    /// dropped → entries settle via their own `Drop`) — in the zero-worker
    /// sub-case nothing picks it up until one of those happens.
    /// Outside any runtime the batch settles inline (sync witness paths).
    fn defer_expired_settlement(expired: Vec<Arc<LiveStream>>) {
        if expired.is_empty() {
            return;
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            let spawned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tokio::task::spawn_blocking(move || {
                    Self::settle_expired_batch(&expired);
                })
            }));
            if spawned.is_err() {
                // OS thread-creation refusal: tokio queued the task BEFORE
                // panicking, so the batch is NOT dropped by the unwind (round 26
                // corrected the opposite claim; round 27 precised the trigger and
                // drain — see the rustdoc above).
                eprintln!(
                    "cap-llm: expired-stream settlement dispatch panicked (OS \
                     refused a worker thread); the batch remains queued and \
                     drains when a worker exists, or at pool shutdown via Drop"
                );
            }
        } else {
            Self::settle_expired_batch(&expired);
        }
    }

    /// Insert live stream (S4). Evict expired, assign handle.
    /// Insert a live entry. On capacity rejection the entry is RETURNED to the
    /// caller (never dropped here): `LiveStream::drop` settles, so dropping a
    /// rejected entry inside the registry would let the `Abandoned` arm win the
    /// settlement and bill a request that never left the host. The caller
    /// finalizes `FailedBegin` first, then drops the returned value (a loser).
    pub(crate) fn insert_live(&self, live: LiveStream) -> Result<u64, LiveStream> {
        let now = Instant::now();
        // Collect-then-drop: expired entries' Drop (settle + abort) runs OUTSIDE
        // the map lock at every eviction site (plan §3).
        let (handle, expired): (Result<u64, LiveStream>, Vec<Arc<LiveStream>>) = {
            // Poison-tolerant (round 24 completed the live_table family: settlement
            // now runs on another thread, so a poison there must not panic the
            // guest's stream/poll host calls).
            let mut ltable = self.live_table.lock().unwrap_or_else(|p| p.into_inner());
            let mut expired = Vec::new();
            ltable.retain(|_, b| {
                if now.duration_since(b.created_at) < crate::host_fn::STREAM_HANDLE_TTL {
                    true
                } else {
                    expired.push(b.clone());
                    false
                }
            });
            if ltable.len() >= MAX_CONCURRENT_STREAMS {
                (Err(live), expired)
            } else {
                let h = self.next.fetch_add(1, Ordering::Relaxed);
                ltable.insert(h, Arc::new(live));
                (Ok(h), expired)
            }
        };
        Self::defer_expired_settlement(expired);
        handle
    }

    /// Poll the next chunk for `handle` on behalf of `agent_id`. Live (S4) path is async.
    /// See poll_live. Legacy buffered path remains sync for existing tests.
    pub(crate) fn poll(&self, handle: u64, agent_id: &str) -> PollOutcome {
        // Legacy buffered only (live callers use poll_live)
        let now = Instant::now();
        let mut table = self.table.lock().unwrap();
        table.retain(|_, b| now.duration_since(b.created_at) < crate::host_fn::STREAM_HANDLE_TTL);
        match table.get_mut(&handle) {
            None => PollOutcome::Unknown,
            Some(buf) if buf.agent_id != agent_id => PollOutcome::Unknown,
            Some(buf) => match buf.deltas.pop_front() {
                Some((start, end)) => {
                    PollOutcome::Delta(buf.ready.response.text[start..end].to_string())
                }
                None => {
                    let buf = table.remove(&handle).expect("entry present");
                    PollOutcome::Done(buf.ready)
                }
            },
        }
    }

    /// S4 async poll (plan §3): serialize same-handle polls on the poll_gate
    /// (Δ4; claim order == completion order), register-then-recheck with
    /// `Notified::enable` (lost-wake barrier), pop one delta / claim the terminal,
    /// wait bounded by the stream deadline. The owner NEVER receives Unknown for a
    /// live stream: Running-at-expiry is a static timeout error, Failed surfaces
    /// its real enum-coded error, Done carries the REAL phase payload + submitted
    /// bill. Claim removal drops the entry Arc outside all locks.
    pub(crate) async fn poll_live(&self, handle: u64, agent_id: &str) -> PollOutcome {
        // TTL eviction: collect under lock, drop outside (plan §3).
        let now = Instant::now();
        let expired: Vec<Arc<LiveStream>> = {
            // Poison-tolerant (round 24; see `insert_live`).
            let mut ltable = self.live_table.lock().unwrap_or_else(|p| p.into_inner());
            let mut e = Vec::new();
            ltable.retain(|_, b| {
                if now.duration_since(b.created_at) < crate::host_fn::STREAM_HANDLE_TTL {
                    true
                } else {
                    e.push(b.clone());
                    false
                }
            });
            e
        };
        // Round 25 (adversarial C1): deferred — this is the guest's poll host call,
        // i.e. the runtime thread; see `defer_expired_settlement`.
        Self::defer_expired_settlement(expired);

        let live = {
            // Poison-tolerant (round 24; see `insert_live`).
            let ltable = self.live_table.lock().unwrap_or_else(|p| p.into_inner());
            ltable.get(&handle).cloned()
        };
        let live = match live {
            Some(l) if l.agent_id == agent_id => l,
            // Unknown handle / cross-agent probe: existence-hiding (D7).
            _ => return PollOutcome::Unknown,
        };

        let _gate = live.poll_gate.clone().lock_owned().await;

        enum Step {
            /// The delta text plus its CONTRACT-234 `seq`, allocated in the SAME
            /// critical section as the pop so seq order == guest-visible order.
            Delta(String, u64),
            Done,
            Failed(crate::LlmError),
            Wait,
        }
        let snapshot = |st: &mut LiveState| -> Step {
            if let Some((s, e)) = st.pending.pop_front() {
                let seq = st.next_seq;
                st.next_seq = st.next_seq.saturating_add(1);
                return Step::Delta(st.visible[s..e].to_string(), seq);
            }
            match &st.phase {
                LivePhase::Done { .. } => Step::Done,
                LivePhase::Failed(e) => Step::Failed(e.clone()),
                LivePhase::Running => Step::Wait,
            }
        };

        // Every non-delta exit returns directly; the three delta exits BREAK with the
        // popped text + its seq so the CONTRACT-234 publish happens exactly once,
        // below — WITH the poll gate still held. (AUDIT round 11 corrected this
        // comment, which still described the `drop(_gate)` that round 6 reverted; see
        // the publish site for why the gate is deliberately retained.)
        //
        // DELIBERATE FAIL-STOP (round 24): the `LiveState` locks on this poll path
        // stay `.unwrap()` while the `live_table` and `Settlement` families are
        // poison-tolerant. `LiveState` carries the visible buffer + byte-range
        // pairs whose consistency the snapshot's slicing depends on; recovering a
        // guard poisoned MID-APPEND could hand a poller torn ranges — delivering
        // corrupt deltas is strictly worse than PANICKING this poll's host call
        // (the panic unwinds out of cap-llm; containment, if any, is the host-call
        // boundary's — round 25 precision). Recovery scope, rounds 28–29: outside
        // this poll path, users of the SAME mutex recover to write the phase enum
        // and the `settled` flag, clear `pending`, READ `next_seq`, and READ the
        // phase on the eviction path (`settle_and_evict`) — none of which can
        // produce a torn slice (clearing a range deque removes ranges wholesale;
        // the seq is watermark-only; the phase is a plain enum read).
        let (delta_text, delta_seq) = loop {
            let step = snapshot(&mut live.state.lock().unwrap());
            match step {
                Step::Delta(d, seq) => break (d, seq),
                Step::Done => return self.claim_done(handle, &live, agent_id),
                Step::Failed(e) => return self.claim_failed(handle, &live, e),
                Step::Wait => {}
            }

            // Register-then-recheck: enable() registers the waiter BEFORE the
            // recheck, so a producer notify between recheck and await is not lost.
            let notified = live.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let step = snapshot(&mut live.state.lock().unwrap());
            match step {
                Step::Delta(d, seq) => break (d, seq),
                Step::Done => return self.claim_done(handle, &live, agent_id),
                Step::Failed(e) => return self.claim_failed(handle, &live, e),
                Step::Wait => {}
            }

            let res = tokio::time::timeout_at(
                tokio::time::Instant::from_std(live.deadline),
                &mut notified,
            )
            .await;
            if res.is_err() {
                // Expiry: re-check once (Done → claim; Failed → claim+error;
                // Running → static timeout — the owner never gets Unknown; the
                // settle-in-progress window is the plan-documented accepted race).
                let step = snapshot(&mut live.state.lock().unwrap());
                match step {
                    Step::Delta(d, seq) => break (d, seq),
                    Step::Done => return self.claim_done(handle, &live, agent_id),
                    Step::Failed(e) => return self.claim_failed(handle, &live, e),
                    Step::Wait => {
                        return PollOutcome::Failed(crate::LlmError::ProviderError(
                            "stream poll timeout".into(),
                        ))
                    }
                }
            }
            // Woke: loop to re-snapshot.
        };

        // CONTRACT-234 (tee slice T1): publish the delta the guest is about to
        // receive, WITH the poll gate still held.
        //
        // AUDIT round 6 reverted an earlier `drop(_gate)` here. Releasing the gate
        // early repealed the documented Δ4 invariant "claim order == completion
        // order": poller A could pop seq n, drop the gate, then block inside
        // `sink.publish` while poller B popped seq n+1 and returned FIRST — reordering
        // the guest's own byte stream, not merely the tee frames. The gate is the
        // thing that makes same-handle polls serial, and the tee's publish is the
        // longest operation on the path, so dropping it there is precisely where the
        // window is widest. Holding it costs a slow sink stalling that one stream's
        // next poll, which the port's non-blocking implementer invariant already
        // requires callers not to do.
        if let Some(tee) = live.settlement.tee() {
            tee.publish_delta(delta_seq, &delta_text);
        }
        PollOutcome::Delta(delta_text)
    }

    /// Remove a never-delivered entry after a failed begin (owner-side). The Arc
    /// drop (already settled by the owner's finalize — a loser Drop) runs outside
    /// all locks.
    pub(crate) fn remove_live(&self, handle: u64) {
        let _ = self.claim_remove(handle);
    }

    /// Remove the entry; the Arc drop (a settle-once LOSER after any terminal —
    /// its Drop is a no-op settle + abort) runs outside all locks.
    fn claim_remove(&self, handle: u64) -> bool {
        let removed = {
            // Poison-tolerant (round 24; see `insert_live`).
            let mut ltable = self.live_table.lock().unwrap_or_else(|p| p.into_inner());
            ltable.remove(&handle)
        };
        let won = removed.is_some();
        drop(removed);
        won
    }

    /// Deliver a `Failed` terminal exactly once, gated by the same latch as
    /// `claim_done`; the map removal is housekeeping.
    fn claim_failed(&self, handle: u64, live: &Arc<LiveStream>, e: crate::LlmError) -> PollOutcome {
        {
            let mut st = live.state.lock().unwrap();
            if st.terminal_claimed {
                return PollOutcome::Unknown;
            }
            st.terminal_claimed = true;
        }
        let _ = self.claim_remove(handle);
        PollOutcome::Failed(e)
    }

    /// First claimer wins by the terminal latch; the terminal carries the REAL Done
    /// payload (folded usage, validated parsed_output, schema tag) and the
    /// settlement's submitted cost — nothing is fabricated here.
    fn claim_done(&self, handle: u64, live: &Arc<LiveStream>, agent_id: &str) -> PollOutcome {
        let payload = {
            let st = live.state.lock().unwrap();
            match &st.phase {
                LivePhase::Done {
                    model,
                    input_tokens,
                    output_tokens,
                    finish_reason,
                    parsed_output,
                    schema_validation,
                } => Some((
                    model.clone(),
                    *input_tokens,
                    *output_tokens,
                    finish_reason.clone(),
                    parsed_output.clone(),
                    *schema_validation,
                    st.visible.clone(),
                )),
                _ => None,
            }
        };
        let (model, in_t, out_t, finish, parsed, schema_tag, text) = match payload {
            Some(p) => p,
            None => return PollOutcome::Unknown,
        };
        let cost = live
            .settlement
            .submitted_bill()
            .map(|(_, _, c)| c)
            .unwrap_or(0.0);
        let latency_ms = live.settlement.elapsed_ms();
        let run_id = live.settlement.run_id();
        // First claimer wins by the terminal-consumption LATCH (not by the map
        // removal, which the reaper may already have done): exactly one poll gets
        // the terminal, and a reaped-but-still-referenced stream still delivers its
        // real terminal to the waiting owner.
        {
            let mut st = live.state.lock().unwrap();
            if st.terminal_claimed {
                return PollOutcome::Unknown;
            }
            st.terminal_claimed = true;
        }
        let _ = self.claim_remove(handle); // housekeeping
        PollOutcome::Done(ReadyStream {
            ctx: LlmRequestContext {
                agent_id: agent_id.to_string(),
                task_id: None,
                run_id,
                iteration: None,
                trace_id: None,
                messages: vec![],
                params: ChatParams {
                    model: Some(model.clone()),
                    ..Default::default()
                },
                output_schema: None,
            },
            response: ChatResponse {
                text,
                model,
                input_tokens: in_t,
                output_tokens: out_t,
                finish_reason: finish,
                parsed_output: parsed,
            },
            cost_usd: cost,
            latency_ms,
            schema_validation: schema_tag,
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.table.lock().unwrap().len()
    }

    /// S4 reaper sweep (plan §3): collect expired entries under the map lock,
    /// release the lock, then settle them OUTSIDE it.
    ///
    /// It finalizes EXPLICITLY rather than relying on the last-`Arc` drop: a
    /// poller waiting inside `poll_live` holds its own clone, so removal alone
    /// would leave the stream unsettled until that poller's own deadline (found by
    /// the 2026-07-29 merge-gate regression). `finalize` is idempotent, so the
    /// eventual `Drop` is a no-op loser, and it publishes the terminal phase +
    /// notify, which wakes any waiter immediately. The owner task is aborted here
    /// for the same reason.
    /// Settle + abort a batch of expired entries. Shared by the reaper sweep AND by the
    /// inline TTL evictions in `insert_live` / `poll_live`, so every eviction site settles
    /// the same way instead of relying on the last-`Arc` drop: a poller blocked inside
    /// `poll_live` holds its own clone, so a drop-based eviction would remove the entry
    /// without ever finalizing it — and since `finalize` is first-caller-wins with losers
    /// silently discarded, a genuinely successful terminal could later be replaced by an
    /// `Abandoned` outcome with no `llm.response` emitted and no Done delivered
    /// (audit round 4, W3).
    ///
    /// ADVERSARIAL §5.2 round 2: each entry is settled under its OWN containment. Two
    /// of this function's three callers (`insert_live`, `poll_live`) evict
    /// remove-then-settle, so the batch holds the entry's last strong `Arc`; a panic
    /// escaping here would unwind through that `Vec`, run `Drop for LiveStream` →
    /// `finalize` again, and a second panic while already unwinding is an uncatchable
    /// process `abort()` — which no `catch_unwind` at the observer or sweeper boundary
    /// can intercept. Per-entry containment also stops one bad entry from starving the
    /// rest of its batch, and lets every caller reach its eviction block.
    fn settle_expired_batch(entries: &[Arc<LiveStream>]) {
        for entry in entries {
            let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Self::settle_one_expired(entry)
            }));
            if settled.is_err() {
                eprintln!(
                    "cap-llm: settling an expired stream panicked; entry is still evicted \
                     and the batch continues"
                );
            }
        }
    }

    fn settle_one_expired(entry: &Arc<LiveStream>) {
        entry.settlement.finalize(
            SettleOutcome::Abandoned,
            LivePhase::Failed(crate::LlmError::ProviderError(
                "stream reaped after ttl".into(),
            )),
        );
        entry.task.abort();
    }

    pub(crate) fn sweep_expired(&self) {
        self.sweep_expired_at(Instant::now())
    }

    /// Snapshot the live entries owned by `agent_id` (the BARE cap-id), leaving
    /// them IN the map — the SYNCHRONOUS half of a turn-end reap (§5.2 round 3).
    /// One `live_table` acquisition, no settlement I/O. Taking the snapshot AT the
    /// turn boundary is what fixes the victim set before the next turn can begin:
    /// a stream planted by a LATER turn is never in an EARLIER turn's batch, so
    /// deferring the settlement I/O off the runtime thread cannot settle a
    /// legitimately in-flight stream. The common no-victim boundary returns an
    /// empty vec — the same single-lock cost the pre-split `reap_agent` paid.
    pub(crate) fn select_agent_victims(&self, agent_id: &str) -> Vec<(u64, Arc<LiveStream>)> {
        // Recover rather than panic: this runs inside `on_turn_complete` on the
        // serve loop — one poisoned mutex would otherwise permanently kill that
        // agent's loop (AUDIT round 9).
        let ltable = self.live_table.lock().unwrap_or_else(|p| p.into_inner());
        ltable
            .iter()
            .filter(|(_, b)| b.agent_id == agent_id)
            .map(|(h, b)| (*h, b.clone()))
            .collect()
    }

    /// Host-authoritative turn-end reap (ADR 2026-07-22 D5, tee slice T3): settle
    /// every live stream still owned by `agent_id` (the BARE cap-id).
    ///
    /// Ordering satisfies two constraints that govern DIFFERENT pairs, so there is no
    /// conflict to adjudicate:
    /// 1. `task.abort()` runs BEFORE the `Terminal(Reaped)` frame is emitted — the
    ///    ADR D6 / MODULE-009 §3.3 T120 clause ("reap aborts delivery BEFORE emitting
    ///    it"). Note `abort()` is cooperative, so this is call order, not a guarantee
    ///    that the owner has already stopped; correctness rests on the settle latch.
    /// 2. Settlement publishes the terminal phase + `notify` BEFORE the entry is
    ///    evicted, so a waiting poller wakes and claims its REAL enum-coded error
    ///    instead of losing the removal race and collapsing to the existence-hiding
    ///    `Unknown` (re-audit F2, the same discipline `sweep_expired_at` encodes).
    ///
    /// Returns the number of settlements this reap WON. A zero can mean nothing
    /// matched OR every victim lost to a concurrent settler (round 25; an earlier
    /// sentence claimed zero implied no match, which the deferred-overlap state
    /// made false).
    ///
    /// RECORDED DIVERGENCE (MODULE-009 §3.6.6): a reap settles as
    /// `Failed(ProviderError)`, so the BUS record for a reaped stream is `llm.error`
    /// with `provider-error` — the bus vocabulary predates turn-end reap and has no
    /// `reaped` label — while CONTRACT-234 subscribers see `Terminal(Reaped)`. The
    /// two channels intentionally disagree on the label until /spec extends the bus
    /// vocabulary; consumers correlating both must key on the stream, not the label.
    pub(crate) fn reap_agent(&self, agent_id: &str) -> usize {
        self.settle_and_evict(self.select_agent_victims(agent_id))
    }

    /// The settlement half of a reap: abort + settle + evict a previously-selected
    /// victim batch. Runs OUTSIDE the map lock; safe to run from the blocking pool
    /// (the observer defers it there so the fsyncs inside `RunBudget::commit` never
    /// run on the runtime thread — §5.2 round 3). Idempotent against re-selection:
    /// a victim also picked up by a later snapshot loses `finalize`'s settle-once
    /// latch and the second eviction is a no-op `remove`. Returns the number of
    /// settlements this call WON — not `victims.len()`, which over-reported
    /// already-settled overlap victims (round 24).
    pub(crate) fn settle_and_evict(&self, victims: Vec<(u64, Arc<LiveStream>)>) -> usize {
        if victims.is_empty() {
            return 0;
        }
        // Abort first, then settle — both OUTSIDE the map lock, and each victim under
        // its OWN containment (ADVERSARIAL §5.2 round 2): eviction below is a separate
        // block, so a panic escaping this loop would skip it for the WHOLE batch — the
        // already-settled victims included — leaving them resident forever and
        // re-selected at every later turn end. Containing per victim keeps one bad
        // stream from starving the rest and guarantees the eviction block is reached.
        // Count WINS, not victims (round 24): overlapping batches — reachable once
        // settlement is deferred — re-select still-resident entries, and `finalize`
        // makes the second attempt a settle-once LOSER. Returning `victims.len()`
        // over-reported those as reaped.
        let mut settled_count = 0usize;
        let mut evict: Vec<u64> = Vec::with_capacity(victims.len());
        for (h, entry) in &victims {
            let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                entry.task.abort();
                entry.settlement.finalize(
                    SettleOutcome::Reaped,
                    LivePhase::Failed(crate::LlmError::ProviderError(
                        "stream reaped at turn end".into(),
                    )),
                )
            }));
            match settled {
                Ok(true) => {
                    settled_count += 1;
                    evict.push(*h);
                }
                // Round 25 (diff W4): a LOSER whose winner has NOT yet published
                // (phase still `Running` — the winner may be parked inside its
                // commit call) must NOT be evicted: that would violate the
                // publish-before-evict discipline (re-audit F2) for the whole
                // fsync duration, handing a fresh poll the existence-hiding
                // `Unknown` instead of its real error. It stays resident until
                // its winner publishes — evicted at the NEXT boundary — or the
                // TTL sweep (round 27 precised "the winner's own path": the
                // owner-terminal winner itself evicts nothing).
                //
                // Round 26 (adversarial finding 1): a LONG-SETTLED loser — phase
                // already terminal, i.e. its winner PUBLISHED before this call —
                // IS evicted here. The owner's normal terminal never touches
                // `live_table`, so completed-but-never-drained streams (exactly
                // the population turn-end reap exists for) otherwise accumulate
                // against the GLOBAL 256 cap until the TTL sweep, denying
                // `insert_live` to every agent; the blanket non-eviction of round
                // 25 was that regression. Phase observed terminal ⇒ the winner is
                // past its commit and its bus record (round 27 precision: the
                // phase precedes only the CONTRACT-234 tee frame, which publishes
                // through `Settlement.tee`, never through the map — so "published
                // LAST" was overstated), and a parked poller claims via
                // `terminal_claimed` on its own `Arc`, so eviction here cannot
                // steal a terminal: F2 holds. Both skip-publish producers were
                // closed in round 27 (the emit is contained; the phase-publish
                // lock recovers poison), so a committed-but-`Running` entry is no
                // longer reachable through them. TTL EXEMPTION, pre-existing:
                // `sweep_expired_at` evicts every selected entry unconditionally —
                // at 300-second age, reclamation outranks the F2 nicety even for a
                // mid-fsync winner.
                Ok(false) => {
                    let published = !matches!(
                        entry.state.lock().unwrap_or_else(|p| p.into_inner()).phase,
                        LivePhase::Running
                    );
                    if published {
                        evict.push(*h);
                    }
                }
                Err(_) => {
                    // A panicked settle is evicted as before: leaving a broken
                    // entry resident re-selects it forever (the round-2 wedge).
                    evict.push(*h);
                    eprintln!(
                        "cap-llm: turn-end reap panicked settling one stream; \
                         it is still evicted and the reap continues"
                    );
                }
            }
        }
        // Then evict what this call SETTLED (or broke) and a waking poller has not
        // already claimed.
        {
            let mut ltable = self.live_table.lock().unwrap_or_else(|p| p.into_inner());
            for h in &evict {
                ltable.remove(h);
            }
        }
        settled_count
    }

    /// The sweep body with an injectable clock: production passes `Instant::now()`,
    /// tests pass a synthetic instant so the REAL expiry predicate is exercised
    /// (rather than a seam that skips entry selection — re-audit F1).
    pub(crate) fn sweep_expired_at(&self, now: Instant) {
        // Select expired entries under the lock, but leave them IN the map.
        let expired: Vec<(u64, Arc<LiveStream>)> = {
            // Poison-tolerant (round 23): the per-tick containment in `reaper_loop`
            // would otherwise turn one poisoning into a permanently unproductive
            // sweeper — the §5.2 round-2 item-9 class, one lock earlier.
            let ltable = self.live_table.lock().unwrap_or_else(|p| p.into_inner());
            ltable
                .iter()
                .filter(|(_, b)| {
                    now.duration_since(b.created_at) >= crate::host_fn::STREAM_HANDLE_TTL
                })
                .map(|(h, b)| (*h, b.clone()))
                .collect()
        };
        // Settle OUTSIDE the lock, publishing the terminal phase + notify FIRST: a
        // poller waiting on this stream must be able to wake, claim the entry and
        // receive the REAL enum-coded error. Removing before publishing would make
        // its claim lose the removal race and collapse the error to `Unknown`
        // (re-audit F2).
        let entries: Vec<Arc<LiveStream>> = expired.iter().map(|(_, e)| e.clone()).collect();
        Self::settle_expired_batch(&entries);
        // Then evict whatever a waking poller has not already claimed.
        {
            // Poison-tolerant (round 24: the round-23 fix recovered the SELECT lock
            // of this very function and left this eviction lock raw — under the
            // poisoning that comment names, the tick would still have panicked here
            // and left every selected entry resident forever).
            let mut ltable = self.live_table.lock().unwrap_or_else(|p| p.into_inner());
            for (h, _) in &expired {
                ltable.remove(h);
            }
        }
        drop(expired);
    }
}

/// Split `text` into ordered content-delta BYTE RANGES `(start, end)` that
/// reconstruct it exactly when sliced + concatenated.
///
/// Operates on the already-256-KiB-capped `response.text` (capped in
/// `stream_begin`), so `concat(text[r] for r in ranges) == done-chunk response
/// text` by construction. Word-ish ranges via `split_inclusive(char::is_whitespace)`
/// boundaries; the tail is coalesced into one range when the piece count exceeds
/// [`MAX_STREAM_DELTAS`] so the buffered range count is bounded. An empty string
/// yields zero ranges (the caller still emits the terminal `done` chunk);
/// whitespace-only text yields the whitespace ranges that reconstruct it. All
/// boundaries are char-aligned, so slicing the text by these ranges is UTF-8-safe.
pub(crate) fn chunk_text_into_deltas(text: &str) -> VecDeque<(usize, usize)> {
    if text.is_empty() {
        return VecDeque::new();
    }
    // Byte ranges of each split_inclusive piece into `text` (pieces partition
    // `text` in order with no gaps, so cumulative offsets are exact + char-aligned).
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut offset = 0usize;
    for piece in text.split_inclusive(char::is_whitespace) {
        let end = offset + piece.len();
        ranges.push((offset, end));
        offset = end;
    }
    if ranges.len() <= MAX_STREAM_DELTAS {
        return ranges.into_iter().collect();
    }
    // Coalesce the tail into one range spanning to text.len() — bounds the count
    // while preserving exact reconstruction.
    let mut out: VecDeque<(usize, usize)> =
        ranges[..MAX_STREAM_DELTAS - 1].iter().copied().collect();
    let tail_start = ranges[MAX_STREAM_DELTAS - 1].0;
    out.push_back((tail_start, text.len()));
    out
}

#[cfg(test)]
mod tee_state_tests {
    //! MODULE-009-T119 (partial) — CONTRACT-234 `TeeState` state machine.
    //!
    //! BUILD-AND-HOLD: MODULE-009-AC-22 is NOT flipped by these (see MODULE-009
    //! §3.6.6); they are the coverage record for the T1 producer half.
    use super::*;
    use advance_shared_types::traits::{
        LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink, LlmTerminalReason, NotWiredDeltaSink,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Recorder {
        frames: std::sync::Mutex<Vec<LlmDeltaFrame>>,
        panic_on: Option<usize>,
        calls: AtomicUsize,
        /// Set while a publish is in flight; a second concurrent entry trips it.
        in_publish: std::sync::atomic::AtomicBool,
        /// Latched if two publishes were ever in flight at once.
        overlapped: std::sync::atomic::AtomicBool,
    }

    impl Recorder {
        fn panicking(nth: usize) -> Self {
            Self {
                panic_on: Some(nth),
                ..Default::default()
            }
        }
        fn frames(&self) -> Vec<LlmDeltaFrame> {
            self.frames.lock().unwrap().clone()
        }
    }

    impl LlmDeltaSink for Recorder {
        fn publish(&self, event: LlmDeltaEvent) {
            // Overlap detector: `TeeState::order` must guarantee that no two
            // publishes are ever in flight for one stream. A `Mutex<Vec>` recorder
            // alone CANNOT observe a violation — it serializes the pushes itself —
            // so mutual exclusion is witnessed here, on entry, where deleting the
            // ordering guard is detectable.
            // Record rather than assert: an `assert!` here unwinds into `emit`'s own
            // `catch_unwind`, which latches the tee off — so the test would fail on a
            // downstream count with the WRONG reported cause, and the flag would stay
            // set and mask a later real overlap (AUDIT round 7).
            if self.in_publish.swap(true, Ordering::SeqCst) {
                self.overlapped.store(true, Ordering::SeqCst);
            }
            // Widen the window so a missing guard is caught reliably rather than
            // depending on scheduler luck.
            std::thread::yield_now();
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if Some(n) == self.panic_on {
                // Clear before unwinding: the flag is not an RAII guard, and leaving
                // it set would mask a later overlap rather than report one.
                self.in_publish.store(false, Ordering::SeqCst);
                panic!("recorder panics on frame {n}");
            }
            self.frames.lock().unwrap().push(event.frame);
            self.in_publish.store(false, Ordering::SeqCst);
        }
    }

    fn tee_with(sink: Arc<dyn LlmDeltaSink>) -> Arc<TeeState> {
        TeeState::new(sink, "agent-a", "st_test")
    }

    /// The headless default is a REAL installed sink (the criterion says "inject"),
    /// and it is free: `is_live` is false, so no caller builds a frame at all.
    #[test]
    fn t119_notwired_is_installed_and_never_live() {
        let tee = tee_with(Arc::new(NotWiredDeltaSink));
        assert!(!tee.is_live(), "an unwired sink must never be live");
        tee.publish_begin(None, None);
        tee.publish_delta(0, "hello");
        tee.publish_terminal(1, LlmTerminalReason::Completed, None);
        // Nothing to observe — the point is that the caller's `is_live()` guard
        // short-circuits before any text copy or envelope construction.
        assert!(!tee.is_live());
    }

    /// `Terminal` is suppressed for a stream that never published `Begin` — the
    /// three pre-handle failure arms must not create a phantom terminal downstream.
    #[test]
    fn t119_no_terminal_without_begin() {
        let rec = Arc::new(Recorder::default());
        let tee = tee_with(rec.clone());
        tee.publish_terminal(0, LlmTerminalReason::ProviderError, None);
        assert!(
            rec.frames().is_empty(),
            "a stream that never began must publish nothing, got {:?}",
            rec.frames()
        );
    }

    /// Exactly-once terminal, whichever settlement path wins the race.
    #[test]
    fn t119_terminal_publishes_exactly_once() {
        let rec = Arc::new(Recorder::default());
        let tee = tee_with(rec.clone());
        tee.publish_begin(Some("run-1".into()), None);
        tee.publish_delta(0, "a");
        tee.publish_terminal(1, LlmTerminalReason::Completed, None);
        tee.publish_terminal(1, LlmTerminalReason::Reaped, None);
        tee.publish_terminal(1, LlmTerminalReason::Abandoned, None);
        let terminals: Vec<_> = rec
            .frames()
            .into_iter()
            .filter(|f| matches!(f, LlmDeltaFrame::Terminal { .. }))
            .collect();
        assert_eq!(terminals.len(), 1, "got {terminals:?}");
        assert!(matches!(
            terminals[0],
            LlmDeltaFrame::Terminal {
                reason: LlmTerminalReason::Completed,
                ..
            }
        ));
    }

    /// `Begin` carries ids only — never prompt or message bytes.
    #[test]
    fn t119_begin_carries_ids_only() {
        let rec = Arc::new(Recorder::default());
        let tee = tee_with(rec.clone());
        tee.publish_begin(Some("run-7".into()), Some("task-9".into()));
        match &rec.frames()[0] {
            LlmDeltaFrame::Begin { run_id, task_id } => {
                assert_eq!(run_id.as_deref(), Some("run-7"));
                assert_eq!(task_id.as_deref(), Some("task-9"));
            }
            other => panic!("expected Begin, got {other:?}"),
        }
    }

    /// A terminal that settles BEFORE `Begin` could be published is parked and then
    /// emitted in order — not dropped. This is the window AUDIT round 7 found open:
    /// it spans `insert_live` to `publish_begin` (across the dispatch await), and a
    /// reap / TTL sweep / `Drop` winning there used to return without consuming the
    /// exactly-once latch, leaving the stream begun and never terminated. Reverting
    /// either half of the fix (the unconditional CAS, or the flush in `publish_begin`)
    /// fails this.
    #[test]
    fn t119_terminal_before_begin_is_parked_then_flushed_in_order() {
        let rec = Arc::new(Recorder::default());
        let tee = tee_with(rec.clone());
        // Settlement wins before the owner ever publishes `Begin`.
        tee.publish_terminal(0, LlmTerminalReason::Reaped, None);
        assert!(
            rec.frames().is_empty(),
            "nothing may reach the sink before Begin"
        );
        tee.publish_begin(Some("run-1".into()), None);
        let frames = rec.frames();
        assert_eq!(
            frames.len(),
            2,
            "Begin then the parked Terminal, got {frames:?}"
        );
        assert!(matches!(frames[0], LlmDeltaFrame::Begin { .. }));
        assert!(matches!(
            frames[1],
            LlmDeltaFrame::Terminal {
                reason: LlmTerminalReason::Reaped,
                ..
            }
        ));
        // The latch is spent: a second settlement cannot double-publish.
        tee.publish_terminal(0, LlmTerminalReason::Completed, None);
        assert_eq!(rec.frames().len(), 2, "terminal stays exactly-once");
    }

    /// The frozen criterion's "per-stream tee-disabled latch on first failure":
    /// a panicking sink is contained AND the whole tee goes off for that stream,
    /// terminal included. Deleting the `disabled` store makes this fail.
    #[test]
    fn t119_panicking_sink_disables_the_whole_tee() {
        let rec = Arc::new(Recorder::panicking(1)); // survive Begin, panic on the first Delta
        let tee = tee_with(rec.clone());
        tee.publish_begin(None, None);
        assert!(tee.is_live());
        tee.publish_delta(0, "boom");
        assert!(
            tee.is_disabled(),
            "first publish failure must latch the tee off"
        );
        assert!(!tee.is_live());
        tee.publish_delta(1, "after");
        tee.publish_terminal(2, LlmTerminalReason::Completed, None);
        let frames = rec.frames();
        assert_eq!(
            frames.len(),
            1,
            "only Begin should have been recorded, got {frames:?}"
        );
        assert!(matches!(frames[0], LlmDeltaFrame::Begin { .. }));
    }

    /// Concurrent publishers never interleave and never lose a frame: 32 delta
    /// threads racing a terminal thread yield exactly 32 deltas + 1 terminal.
    #[test]
    fn t119_frames_emitted_whole_and_once_under_racing_publishers() {
        let rec = Arc::new(Recorder::default());
        let tee = tee_with(rec.clone());
        tee.publish_begin(None, None);
        // AUDIT round 6 (hardened-adversarial Critical 2): the terminal publisher
        // must NOT be join-ordered against the delta publishers. The previous form
        // joined all 32 threads and only then published the terminal, so
        // "terminal is last" held by construction of the TEST and stayed green with
        // the ordering guard deleted. Racing them is what makes this falsifiable.
        let mut handles = Vec::new();
        for seq in 0..32u64 {
            let t = tee.clone();
            handles.push(std::thread::spawn(move || t.publish_delta(seq, "x")));
        }
        let t_term = tee.clone();
        handles.push(std::thread::spawn(move || {
            t_term.publish_terminal(32, LlmTerminalReason::Completed, None)
        }));
        for h in handles {
            h.join().unwrap();
        }
        let frames = rec.frames();
        // What the guard ACTUALLY guarantees: every frame is emitted whole and
        // exactly once, with no interleaving or loss under concurrent publishers.
        // It does NOT guarantee the terminal is last — a terminal that wins the race
        // is emitted before deltas whose ranges the guest had already popped, and
        // suppressing those would make the tee under-report what the guest received.
        // That limit is stated on the port (invariant 4), not papered over here.
        let deltas = frames
            .iter()
            .filter(|f| matches!(f, LlmDeltaFrame::Delta { .. }))
            .count();
        assert_eq!(
            deltas, 32,
            "every published delta must be recorded exactly once"
        );
        let terminals = frames
            .iter()
            .filter(|f| matches!(f, LlmDeltaFrame::Terminal { .. }))
            .count();
        assert_eq!(
            terminals, 1,
            "exactly one terminal under a racing publisher"
        );
        let begins = frames
            .iter()
            .filter(|f| matches!(f, LlmDeltaFrame::Begin { .. }))
            .count();
        assert_eq!(begins, 1, "exactly one begin");
        assert!(
            !rec.overlapped.load(Ordering::SeqCst),
            "two publishes overlapped for one stream — the ordering guard is gone"
        );
        // 1 Begin + 32 Deltas + 1 Terminal.
        assert_eq!(frames.len(), 34, "no frame lost or duplicated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{ChatResponse, LlmRequestContext, ReadyStream};
    use std::time::Duration;

    /// Reconstruct the full text from delta byte-ranges by slicing `text`.
    fn reconstruct(text: &str, ranges: &VecDeque<(usize, usize)>) -> String {
        ranges.iter().map(|(s, e)| &text[*s..*e]).collect()
    }

    /// MODULE-009-T96 — chunker reconstructs exactly for multi-word / single-word
    /// / empty / whitespace-only; empty → zero deltas; count ≤ MAX_STREAM_DELTAS.
    #[test]
    fn t96_chunk_reconstructs_and_bounds() {
        // Multi-word: multiple deltas, exact reconstruction.
        let mw_text = "hello world foo bar";
        let mw = chunk_text_into_deltas(mw_text);
        assert!(
            mw.len() >= 2,
            "multi-word should produce multiple deltas, got {}",
            mw.len()
        );
        assert_eq!(reconstruct(mw_text, &mw), mw_text);

        // Single word (no whitespace): exactly one delta.
        let sw_text = "singleword";
        let sw = chunk_text_into_deltas(sw_text);
        assert_eq!(sw.len(), 1);
        assert_eq!(reconstruct(sw_text, &sw), sw_text);

        // Empty: zero deltas (the caller still yields the done chunk).
        assert_eq!(chunk_text_into_deltas("").len(), 0);

        // Whitespace-only: deltas reconstruct the whitespace exactly.
        let ws_text = "   ";
        assert_eq!(
            reconstruct(ws_text, &chunk_text_into_deltas(ws_text)),
            ws_text
        );

        // Interior + trailing whitespace + CJK: exact reconstruction (char-aligned ranges).
        let mixed = "a  b\tc\n中文 d";
        assert_eq!(reconstruct(mixed, &chunk_text_into_deltas(mixed)), mixed);
    }

    /// MODULE-009-T96 (bound) — many tokens coalesce so count ≤ MAX_STREAM_DELTAS
    /// while still reconstructing exactly.
    #[test]
    fn t96_chunk_count_bounded() {
        // (MAX_STREAM_DELTAS + 500) single-char words separated by spaces.
        let n = MAX_STREAM_DELTAS + 500;
        let text: String = (0..n).map(|_| "x ").collect();
        let deltas = chunk_text_into_deltas(&text);
        assert!(
            deltas.len() <= MAX_STREAM_DELTAS,
            "delta count {} exceeds MAX_STREAM_DELTAS {}",
            deltas.len(),
            MAX_STREAM_DELTAS
        );
        assert_eq!(
            reconstruct(&text, &deltas),
            text,
            "coalesced tail must still reconstruct"
        );
    }

    fn dummy_ready_for(text: &str, agent_id: &str) -> ReadyStream {
        ReadyStream {
            ctx: LlmRequestContext {
                agent_id: agent_id.into(),
                task_id: None,
                run_id: None,
                iteration: None,
                trace_id: None,
                messages: vec![],
                params: Default::default(),
                output_schema: None,
            },
            response: ChatResponse {
                text: text.into(),
                model: "test-model".into(),
                input_tokens: 1,
                output_tokens: 1,
                finish_reason: "stop".into(),
                parsed_output: None,
            },
            cost_usd: 0.0,
            latency_ms: 0,
            schema_validation: None,
        }
    }

    fn dummy_ready(text: &str) -> ReadyStream {
        dummy_ready_for(text, "test-agent")
    }

    /// Registry insert → poll deltas (sliced + reconstructing) → done removes the handle.
    #[test]
    fn t_registry_insert_poll_done_removes_handle() {
        let reg = StreamRegistry::new();
        let text = "a b c";
        let deltas = chunk_text_into_deltas(text);
        let n = deltas.len();
        let h = reg.insert(deltas, dummy_ready(text)).expect("insert ok");
        assert_eq!(reg.len(), 1);
        let mut reconstructed = String::new();
        for _ in 0..n {
            match reg.poll(h, "test-agent") {
                PollOutcome::Delta(d) => reconstructed.push_str(&d),
                other => panic!(
                    "expected Delta, got a different outcome: {}",
                    matches!(other, PollOutcome::Done(_))
                ),
            }
        }
        assert_eq!(
            reconstructed, text,
            "sliced deltas must reconstruct the text"
        );
        assert!(matches!(reg.poll(h, "test-agent"), PollOutcome::Done(_)));
        // Handle consumed.
        assert_eq!(reg.len(), 0);
        assert!(matches!(reg.poll(h, "test-agent"), PollOutcome::Unknown));
    }

    /// Unknown handle → Unknown.
    #[test]
    fn t_registry_unknown_handle() {
        let reg = StreamRegistry::new();
        assert!(matches!(reg.poll(999, "test-agent"), PollOutcome::Unknown));
    }

    /// Round-AUDIT-9 W1 — cross-agent isolation: a handle owned by agent-A is
    /// NOT pollable by agent-B (→ Unknown, existence not revealed), while
    /// agent-A polls it normally.
    #[test]
    fn t_registry_agent_binding_isolates_handles() {
        let reg = StreamRegistry::new();
        let text = "a b c";
        let h = reg
            .insert(
                chunk_text_into_deltas(text),
                dummy_ready_for(text, "agent-A"),
            )
            .expect("insert ok");
        // agent-B cannot see / drain agent-A's handle.
        assert!(matches!(reg.poll(h, "agent-B"), PollOutcome::Unknown));
        // The handle is still intact for the owner (agent-B's poll didn't consume it).
        assert_eq!(reg.len(), 1);
        assert!(matches!(reg.poll(h, "agent-A"), PollOutcome::Delta(_)));
    }

    /// MODULE-009-T95 — full registry → insert returns None (provider-error at
    /// the handler).
    #[test]
    fn t95_registry_full_rejects() {
        let reg = StreamRegistry::new();
        for _ in 0..MAX_CONCURRENT_STREAMS {
            assert!(reg.insert(VecDeque::new(), dummy_ready("x")).is_some());
        }
        assert_eq!(reg.len(), MAX_CONCURRENT_STREAMS);
        assert!(
            reg.insert(VecDeque::new(), dummy_ready("y")).is_none(),
            "insert past MAX_CONCURRENT_STREAMS must be rejected"
        );
    }

    /// MODULE-009-T95 — a TTL-expired entry is evicted: poll returns Unknown,
    /// and a registry full of expired entries accepts a fresh insert.
    #[test]
    fn t95_ttl_eviction() {
        let reg = StreamRegistry::new();
        let expired = Instant::now()
            .checked_sub(crate::host_fn::STREAM_HANDLE_TTL + Duration::from_secs(1))
            .expect("machine uptime > TTL");
        let h = reg
            .insert_at(
                chunk_text_into_deltas("a b"),
                dummy_ready("a b"),
                "test-agent".into(),
                expired,
            )
            .expect("insert ok");
        // poll() evicts the expired entry before lookup → Unknown.
        assert!(matches!(reg.poll(h, "test-agent"), PollOutcome::Unknown));
        assert_eq!(reg.len(), 0);

        // Fill with expired entries, then a fresh insert succeeds (eviction-first).
        for _ in 0..MAX_CONCURRENT_STREAMS {
            reg.insert_at(
                VecDeque::new(),
                dummy_ready("x"),
                "test-agent".into(),
                expired,
            );
        }
        assert!(
            reg.insert(VecDeque::new(), dummy_ready("fresh")).is_some(),
            "insert must succeed after evicting expired entries"
        );
    }

    // === S4 live witnesses (attempt #3 — real mechanisms, no pre-populated Done phases) ===

    use advance_shared_types::capability::BudgetDecision;
    use advance_shared_types::traits::{EventBusEmit, RunBudget};
    use std::sync::atomic::{AtomicU64, Ordering as AOrd};

    /// Recording budget: counts commits, optionally blocking inside commit while
    /// holding a barrier (for the T121 off-runtime mutual-exclusion arm).
    struct RecBudget {
        commits: AtomicU64,
        last: Mutex<Option<(u64, f64)>>,
        block_in_commit: Option<(
            std::sync::Arc<std::sync::Barrier>,
            std::sync::Arc<std::sync::Barrier>,
        )>,
    }
    impl RecBudget {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                commits: AtomicU64::new(0),
                last: Mutex::new(None),
                block_in_commit: None,
            })
        }
        fn blocking(
            enter: std::sync::Arc<std::sync::Barrier>,
            exit: std::sync::Arc<std::sync::Barrier>,
        ) -> Arc<Self> {
            Arc::new(Self {
                commits: AtomicU64::new(0),
                last: Mutex::new(None),
                block_in_commit: Some((enter, exit)),
            })
        }
    }
    impl RunBudget for RecBudget {
        fn check(&self, _r: &str, _t: u64, _c: f64) -> BudgetDecision {
            BudgetDecision::Allow
        }
        fn commit(&self, _r: &str, tokens: u64, cost: f64) {
            if let Some((enter, exit)) = &self.block_in_commit {
                enter.wait(); // winner is now provably INSIDE commit
                exit.wait(); // held until the test releases it
            }
            self.commits.fetch_add(1, AOrd::SeqCst);
            *self.last.lock().unwrap() = Some((tokens, cost));
        }
    }

    /// Recording emitter: counts terminal events by type.
    #[derive(Default)]
    struct RecBus {
        responses: AtomicU64,
        errors: AtomicU64,
    }
    impl EventBusEmit for RecBus {
        fn emit(&self, event: advance_shared_types::event::Event) {
            match event.event_type.as_str() {
                "llm.response" => {
                    self.responses.fetch_add(1, AOrd::SeqCst);
                }
                "llm.error" => {
                    self.errors.fetch_add(1, AOrd::SeqCst);
                }
                _ => {}
            }
        }
    }

    fn mk_settlement(
        budget: Arc<dyn RunBudget>,
        bus: Arc<RecBus>,
        in_est: u64,
        out_est: u64,
    ) -> Arc<Settlement> {
        Settlement::new(
            Some("run-1".into()),
            in_est,
            out_est,
            "test-model".into(),
            1_000_000.0, // 1.0 usd per token — makes cost assertions exact
            1_000_000.0,
            Some(budget),
            Some(bus as Arc<dyn EventBusEmit + Send + Sync>),
            "agent-A".into(),
        )
    }

    /// Bounded wait for a DEFERRED settlement (round 25: the inline TTL evictions
    /// defer `settle_expired_batch` to the blocking pool, so witnesses of those
    /// paths wait for the effect instead of asserting synchronously).
    async fn wait_until(deadline: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    fn mk_live(settlement: Arc<Settlement>) -> LiveStream {
        let state = Arc::new(Mutex::new(LiveState::default()));
        let notify = Arc::new(Notify::new());
        settlement.bind(state.clone(), notify.clone());
        LiveStream {
            agent_id: "agent-A".into(),
            created_at: Instant::now(),
            deadline: Instant::now() + Duration::from_secs(300),
            state,
            notify,
            poll_gate: Arc::new(TokioMutex::new(())),
            settlement,
            task: tokio::spawn(async {}),
        }
    }

    /// T115 (registry leg): the OWNER of a Running stream WAITS (never Unknown);
    /// a producer append wakes it into Delta; a Failed publication wakes it into
    /// the REAL enum-coded error; a non-owner probe is Unknown immediately.
    #[test]
    fn t115_owner_waits_nonowner_unknown() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let reg = Arc::new(StreamRegistry::new());
            let bus = Arc::new(RecBus::default());
            let settlement = mk_settlement(RecBudget::new(), bus, 10, 10);
            let live = mk_live(settlement.clone());
            let state = live.state.clone();
            let notify = live.notify.clone();
            let h = match reg.insert_live(live) {
                Ok(h) => h,
                Err(_) => panic!("insert ok"),
            };

            // Non-owner: immediate Unknown, consumes nothing.
            assert!(matches!(
                reg.poll_live(h, "agent-B").await,
                PollOutcome::Unknown
            ));

            // Owner poll waits; producer appends 30ms later → Delta (not Unknown).
            let producer = tokio::spawn({
                let state = state.clone();
                let notify = notify.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    {
                        let mut st = state.lock().unwrap();
                        st.visible.push_str("hi");
                        st.pending.push_back((0, 2));
                    }
                    notify.notify_waiters();
                }
            });
            match reg.poll_live(h, "agent-A").await {
                PollOutcome::Delta(d) => assert_eq!(d, "hi"),
                _ => panic!("owner poll on Running stream must wait for the delta, never Unknown"),
            }
            producer.await.unwrap();

            // Failed publication (via the settlement winner package) surfaces the
            // REAL error to the owner, not Unknown.
            let waiter = tokio::spawn({
                let reg = reg.clone();
                async move { reg.poll_live(h, "agent-A").await }
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            settlement.finalize(
                SettleOutcome::Terminal,
                LivePhase::Failed(crate::LlmError::RateLimited("stream rate limited".into())),
            );
            match waiter.await.unwrap() {
                PollOutcome::Failed(crate::LlmError::RateLimited(_)) => {}
                _ => panic!("Failed phase must surface its real enum-coded error"),
            }
        });
    }

    /// T121 arm 1 — REWRITTEN at round 24, when the `RunBudget::commit` CALL moved
    /// OUT of the settlement critical section (holding `inner` across the
    /// implementer's fsyncs let a settling stream stall the production
    /// current-thread runtime via any reader of the same lock). The old arm pinned
    /// the MECHANISM ("a second finalizer must not RETURN while the winner is
    /// inside commit"); this arm pins the INVARIANTS that mechanism served, under
    /// the new structure, with the winner parked INSIDE `commit`:
    /// 1. exactly-once — the loser returns `false` and never triggers a second
    ///    commit;
    /// 2. loser-does-not-block — the loser RETURNS while the winner is still
    ///    inside the fsyncs (the round-24 point: readers no longer wait on I/O);
    /// 3. figures-before-ledger-call — `submitted_bill()` is already readable and
    ///    exact while the winner is mid-commit (recorded under the lock before the
    ///    call);
    /// 4. accounting-before-terminal — NO terminal event exists while the winner
    ///    is inside commit; the record appears only after commit returns.
    #[test]
    fn t121_settlement_exactly_once_nonblocking_commit() {
        let enter = std::sync::Arc::new(std::sync::Barrier::new(2));
        let exit = std::sync::Arc::new(std::sync::Barrier::new(2));
        let budget = RecBudget::blocking(enter.clone(), exit.clone());
        let bus = Arc::new(RecBus::default());
        let settlement = mk_settlement(budget.clone(), bus.clone(), 5, 5);

        let s2 = settlement.clone();
        let winner = std::thread::spawn(move || {
            s2.finalize(
                SettleOutcome::Terminal,
                LivePhase::Failed(crate::LlmError::ProviderError("x".into())),
            )
        });
        // The winner is now provably inside `commit` (outside the lock, round 24).
        enter.wait();

        // Second finalizer, off-runtime. Under the round-24 structure it must LOSE
        // AND RETURN while the winner is still parked in the fsyncs. ROUND 25: the
        // result arrives over a CHANNEL WITH TIMEOUT — a plain `join()` here turned
        // the interesting mutant (commit moved back inside the critical section)
        // into a three-way DEADLOCK of the test binary instead of a failure.
        let s3 = settlement.clone();
        let (loser_tx, loser_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = s3.finalize(
                SettleOutcome::Abandoned,
                LivePhase::Failed(crate::LlmError::ProviderError("y".into())),
            );
            let _ = loser_tx.send(r);
        });
        let lost = loser_rx.recv_timeout(Duration::from_secs(2)).expect(
            "LOSER BLOCKED: a second finalizer did not return while the winner \
                 was parked inside RunBudget::commit — the commit call has moved \
                 back inside the settlement critical section (round-24 regression)",
        );
        assert!(
            !lost,
            "second finalizer must LOSE (the committed latch is claimed under the \
             lock before the winner's commit call)"
        );
        assert_eq!(
            budget.commits.load(AOrd::SeqCst),
            0,
            "no commit may COMPLETE while the winner is parked — the loser's return \
             must not have triggered a second one"
        );
        assert_eq!(
            settlement.submitted_bill(),
            Some((5, 0, 5.0)),
            "figures are recorded under the lock BEFORE the ledger call, so a \
             reader racing the winner's fsyncs sees the exact bill (input = its \
             estimate, output = zero decoded bytes)"
        );
        assert_eq!(
            bus.errors.load(AOrd::SeqCst),
            0,
            "accounting-before-terminal: no terminal record may exist while the \
             winner is still inside RunBudget::commit"
        );

        exit.wait(); // release the winner
        let won = winner.join().unwrap();
        assert!(won, "first finalizer wins");
        assert_eq!(budget.commits.load(AOrd::SeqCst), 1, "exactly one commit");
        assert_eq!(
            bus.errors.load(AOrd::SeqCst),
            1,
            "exactly one terminal record"
        );
    }

    /// Round 26 (adversarial finding 1 + info 6): the eviction policy's BOTH arms
    /// are pinned on residency, not just counts. A published resident (its winner
    /// finished before the reap — the completed-but-never-drained population) is
    /// EVICTED by a zero-win batch, reclaiming its global-cap slot; a loser whose
    /// winner is still parked inside its commit (phase unpublished) STAYS
    /// resident (re-audit F2).
    #[test]
    fn reap_evicts_published_residents_but_not_midflight_losers() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Arm A — published resident: settle directly (the owner-terminal
            // shape, which never evicts), then reap.
            let reg = Arc::new(StreamRegistry::new());
            let budget = RecBudget::new();
            let bus = Arc::new(RecBus::default());
            let settlement = mk_settlement(budget.clone(), bus.clone(), 2, 2);
            let live = mk_live(settlement.clone());
            assert!(reg.insert_live(live).is_ok());
            assert!(settlement.finalize(
                SettleOutcome::Terminal,
                LivePhase::Failed(crate::LlmError::ProviderError("done".into())),
            ));
            let batch = reg.select_agent_victims("agent-A");
            assert_eq!(batch.len(), 1, "settled entry is still resident pre-reap");
            assert_eq!(
                reg.settle_and_evict(batch),
                0,
                "no win against a settled entry"
            );
            assert!(
                reg.live_table.lock().unwrap().is_empty(),
                "a PUBLISHED resident must be evicted by the zero-win batch \
                 (round-25's blanket non-eviction accumulated these against the \
                 global cap)"
            );

            // Arm B — mid-flight loser: the winner is parked inside its commit,
            // phase not yet published; the reap batch must leave it resident.
            let reg2 = Arc::new(StreamRegistry::new());
            let enter = std::sync::Arc::new(std::sync::Barrier::new(2));
            let exit = std::sync::Arc::new(std::sync::Barrier::new(2));
            let budget2 = RecBudget::blocking(enter.clone(), exit.clone());
            let bus2 = Arc::new(RecBus::default());
            let settlement2 = mk_settlement(budget2.clone(), bus2.clone(), 2, 2);
            let live2 = mk_live(settlement2.clone());
            let h2 = match reg2.insert_live(live2) {
                Ok(h) => h,
                Err(_) => panic!("insert ok"),
            };
            let s2 = settlement2.clone();
            let winner = std::thread::spawn(move || {
                s2.finalize(
                    SettleOutcome::Terminal,
                    LivePhase::Failed(crate::LlmError::ProviderError("x".into())),
                )
            });
            enter.wait(); // winner provably parked inside commit, phase unpublished
            let batch2 = reg2.select_agent_victims("agent-A");
            assert_eq!(batch2.len(), 1);
            assert_eq!(
                reg2.settle_and_evict(batch2),
                0,
                "loser against the parked winner"
            );
            assert!(
                reg2.live_table.lock().unwrap().contains_key(&h2),
                "a MID-FLIGHT loser must stay resident (publish-before-evict, F2)"
            );
            exit.wait();
            assert!(winner.join().unwrap());
            // Round 27 (adversarial finding 5): the round trip — once the winner
            // has published, the NEXT boundary's zero-win batch evicts the
            // retained loser, closing the accumulation argument end-to-end.
            let batch3 = reg2.select_agent_victims("agent-A");
            assert_eq!(
                batch3.len(),
                1,
                "retained loser still resident post-publish"
            );
            assert_eq!(reg2.settle_and_evict(batch3), 0, "still a loser");
            assert!(
                reg2.live_table.lock().unwrap().is_empty(),
                "post-publish, the next boundary reclaims the slot"
            );
        });
    }

    /// Round 25 (adversarial I8): the WINS-not-victims return is discriminated —
    /// two snapshots of the same victim, settled in sequence, report 1 then 0.
    /// A `victims.len()` return (the round-23 form) reports 1 then 1.
    #[test]
    fn overlap_batch_reports_wins_not_victims() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let reg = Arc::new(StreamRegistry::new());
            let budget = RecBudget::new();
            let bus = Arc::new(RecBus::default());
            let settlement = mk_settlement(budget.clone(), bus.clone(), 3, 3);
            let live = mk_live(settlement);
            assert!(reg.insert_live(live).is_ok(), "insert");
            let first = reg.select_agent_victims("agent-A");
            let second = reg.select_agent_victims("agent-A");
            assert_eq!(first.len(), 1);
            assert_eq!(
                second.len(),
                1,
                "overlap snapshot selects the resident victim"
            );
            assert_eq!(reg.settle_and_evict(first), 1, "fresh victim: one win");
            assert_eq!(
                reg.settle_and_evict(second),
                0,
                "overlap victim lost the settle-once latch and must not be re-counted"
            );
        });
    }

    /// T121 arm 2 (Drop-wins-unsettled = the reap arm): dropping an UNSETTLED
    /// LiveStream must produce exactly one commit AND one llm.error AND publish
    /// the Failed phase, wake a WAITING poller (no hang), and abort a still-running
    /// owner task.
    #[test]
    fn t121_drop_wins_unsettled_emits_and_publishes() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let reg = Arc::new(StreamRegistry::new());
            let budget = RecBudget::new();
            let bus = Arc::new(RecBus::default());
            let settlement = mk_settlement(budget.clone(), bus.clone(), 7, 9);
            settlement.add_decoded_bytes(3);

            // A REAL long-running owner task so the sweep's abort() has an effect.
            let owner_alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let oa = owner_alive.clone();
            let task = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                oa.store(false, AOrd::SeqCst); // only on normal completion
            });
            let state = Arc::new(Mutex::new(LiveState::default()));
            let notify = Arc::new(Notify::new());
            settlement.bind(state.clone(), notify.clone());
            let live = LiveStream {
                agent_id: "agent-A".into(),
                created_at: Instant::now(),
                deadline: Instant::now() + Duration::from_secs(300),
                state: state.clone(),
                notify,
                poll_gate: Arc::new(TokioMutex::new(())),
                settlement: settlement.clone(),
                task,
            };
            let h = match reg.insert_live(live) {
                Ok(h) => h,
                Err(_) => panic!("insert ok"),
            };

            // A poller is WAITING on the Running stream (the entry is fresh, exactly
            // as in production when a guest polls before the TTL passes).
            let waiter = tokio::spawn({
                let reg = reg.clone();
                async move { reg.poll_live(h, "agent-A").await }
            });
            tokio::time::sleep(Duration::from_millis(40)).await;

            // Drive the PRODUCTION sweep body with a clock past the TTL — the real
            // expiry predicate decides, no seam skips entry selection.
            reg.sweep_expired_at(Instant::now() + crate::host_fn::STREAM_HANDLE_TTL);

            assert_eq!(
                budget.commits.load(AOrd::SeqCst),
                1,
                "reap winner commits once"
            );
            assert_eq!(
                bus.errors.load(AOrd::SeqCst),
                1,
                "reap winner emits one llm.error"
            );
            assert!(
                matches!(state.lock().unwrap().phase, LivePhase::Failed(_)),
                "reap winner publishes the Failed phase"
            );
            // The waiting poller must WAKE and receive the REAL enum-coded error —
            // not the existence-hiding Unknown (re-audit F2: the sweep used to remove
            // the entry before publishing the phase, so the woken poller lost the
            // claim race and got Unknown).
            let woke = tokio::time::timeout(Duration::from_secs(2), waiter)
                .await
                .expect("a reaped stream must wake its waiting poller")
                .unwrap();
            match woke {
                PollOutcome::Failed(crate::LlmError::ProviderError(_)) => {}
                other => panic!(
                    "a reaped stream must surface its REAL error to the waiting owner, got {}",
                    match other {
                        PollOutcome::Delta(_) => "Delta",
                        PollOutcome::Done(_) => "Done",
                        PollOutcome::Failed(_) => "Failed(other variant)",
                        PollOutcome::Unknown => "Unknown",
                    }
                ),
            }
            let (t, c) = budget.last.lock().unwrap().unwrap();
            assert_eq!(t, 7 + 3);
            assert!(
                (c - 10.0).abs() < 1e-9,
                "cost = 10 tokens at 1.0/token, got {c}"
            );
            assert!(
                owner_alive.load(AOrd::SeqCst),
                "owner task was aborted, not completed"
            );
        });
    }

    /// AUDIT round 4, W3: the finalize-before-evict discipline must hold at EVERY
    /// eviction site, not just the reaper sweep. `insert_live` and `poll_live` each run
    /// their own inline TTL eviction; before this fix they relied on the last-`Arc` drop,
    /// so ordinary guest traffic could evict an expired entry whose `Arc` was still held
    /// by a blocked poller WITHOUT settling it — and because `finalize` is
    /// first-caller-wins with losers silently discarded, a genuinely successful terminal
    /// could later be replaced by an `Abandoned` outcome with no `llm.response` emitted.
    #[test]
    fn t121_inline_evictions_settle_expired_entries() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // --- insert_live's inline eviction ---
            let reg = Arc::new(StreamRegistry::new());
            let budget = RecBudget::new();
            let bus = Arc::new(RecBus::default());
            let victim_settlement = mk_settlement(budget.clone(), bus.clone(), 3, 3);
            let victim = mk_live(victim_settlement.clone());
            let victim_state = victim.state.clone();
            let vh = match reg.insert_live(victim) {
                Ok(h) => h,
                Err(_) => panic!("insert ok"),
            };
            // Force expiry, then trigger the INLINE eviction by inserting another stream.
            //
            // TWO Arcs must be pinned for this witness to be falsifiable, because BOTH run
            // `LiveStream::drop` against the SAME shared `Settlement`:
            //   * `original_keeper` — the pre-replacement Arc. Overwriting the map slot
            //     drops it, and that drop ALONE satisfies every assertion below even with
            //     the code under test deleted (verified by mutation).
            //   * `poller_clone` — the post-replacement Arc, aliased exactly as a blocked
            //     poller holds it, so the eviction's `remove` cannot run its Drop either.
            // With both pinned, `settle_expired_batch` is the ONLY thing that can settle.
            let original_keeper = {
                let t = reg.live_table.lock().unwrap();
                t.get(&vh).cloned().expect("entry present")
            };
            {
                let mut t = reg.live_table.lock().unwrap();
                if let Some(e) = t.get_mut(&vh) {
                    // Entries are behind Arc; rebuild the map entry with a back-dated
                    // created_at to drive the real predicate.
                    let expired = Arc::new(LiveStream {
                        agent_id: e.agent_id.clone(),
                        created_at: Instant::now()
                            .checked_sub(crate::host_fn::STREAM_HANDLE_TTL + Duration::from_secs(1))
                            .expect("machine uptime > TTL"),
                        deadline: e.deadline,
                        state: e.state.clone(),
                        notify: e.notify.clone(),
                        poll_gate: e.poll_gate.clone(),
                        settlement: e.settlement.clone(),
                        task: tokio::spawn(async {}),
                    });
                    *e = expired;
                }
            }
            // Hold a live Arc clone exactly as a blocked poller would — taken AFTER the
            // back-dating replacement so it aliases the Arc the map will actually evict.
            // This is what makes the witness falsifiable: with the clone outstanding the
            // evicted entry's own `Drop` CANNOT run, so the only thing that can settle it
            // is the explicit `settle_expired_batch` call under test.
            let poller_clone = {
                let t = reg.live_table.lock().unwrap();
                t.get(&vh).cloned().expect("entry present")
            };
            let other = mk_live(mk_settlement(
                RecBudget::new(),
                Arc::new(RecBus::default()),
                1,
                1,
            ));
            let _ = reg.insert_live(other);

            // Round 25: the settlement is DEFERRED to the blocking pool — wait
            // bounded for the effect. Round 26: the wait gates on the LAST
            // published effect (the phase), not the first (the commit counter) —
            // gating on the first and asserting the later ones synchronously was
            // a preemption flake. The falsifiability argument is unchanged: with
            // both Arcs pinned, only the (now deferred) explicit
            // `settle_expired_batch` can settle; no amount of waiting turns a
            // deleted call green.
            assert!(
                wait_until(Duration::from_secs(2), || matches!(
                    victim_state.lock().unwrap().phase,
                    LivePhase::Failed(_)
                ))
                .await,
                "insert_live's inline eviction must SETTLE the expired entry \
                 (terminal phase published), not just drop it"
            );
            assert_eq!(
                budget.commits.load(AOrd::SeqCst),
                1,
                "with its one ledger commit (ordered before the phase publish)"
            );
            assert_eq!(
                bus.errors.load(AOrd::SeqCst),
                1,
                "and its one terminal record"
            );
            drop(poller_clone);
            drop(original_keeper);

            // --- poll_live's inline eviction ---
            let reg2 = Arc::new(StreamRegistry::new());
            let budget2 = RecBudget::new();
            let bus2 = Arc::new(RecBus::default());
            let victim2_settlement = mk_settlement(budget2.clone(), bus2.clone(), 4, 4);
            let victim2 = mk_live(victim2_settlement.clone());
            let vh2 = match reg2.insert_live(victim2) {
                Ok(h) => h,
                Err(_) => panic!("insert ok"),
            };
            let original_keeper2 = {
                let t = reg2.live_table.lock().unwrap();
                t.get(&vh2).cloned().expect("entry present")
            };
            {
                let mut t = reg2.live_table.lock().unwrap();
                if let Some(e) = t.get_mut(&vh2) {
                    let expired = Arc::new(LiveStream {
                        agent_id: e.agent_id.clone(),
                        created_at: Instant::now()
                            .checked_sub(crate::host_fn::STREAM_HANDLE_TTL + Duration::from_secs(1))
                            .expect("machine uptime > TTL"),
                        deadline: e.deadline,
                        state: e.state.clone(),
                        notify: e.notify.clone(),
                        poll_gate: e.poll_gate.clone(),
                        settlement: e.settlement.clone(),
                        task: tokio::spawn(async {}),
                    });
                    *e = expired;
                }
            }
            // Same discipline as above: alias the post-replacement Arc so Drop is blocked.
            let keeper = {
                let t = reg2.live_table.lock().unwrap();
                t.get(&vh2).cloned().expect("entry present")
            };
            // An UNRELATED poll drives the inline eviction.
            assert!(matches!(
                reg2.poll_live(9999, "agent-A").await,
                PollOutcome::Unknown
            ));
            assert!(
                wait_until(Duration::from_secs(2), || matches!(
                    keeper.state.lock().unwrap().phase,
                    LivePhase::Failed(_)
                ))
                .await,
                "poll_live's inline eviction must SETTLE the expired entry too"
            );
            assert_eq!(budget2.commits.load(AOrd::SeqCst), 1);
            assert_eq!(bus2.errors.load(AOrd::SeqCst), 1);
            drop(keeper);
            drop(original_keeper2);
        });
    }

    /// Re-audit F1: the TTL expiry PREDICATE itself must be witnessed — emptying or
    /// inverting `sweep_expired_at` has to fail. A sweep BEFORE the TTL must leave
    /// the entry untouched; a sweep AFTER it must settle and evict.
    #[test]
    fn t121_sweep_expiry_predicate_selects_only_expired() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let reg = Arc::new(StreamRegistry::new());
            let budget = RecBudget::new();
            let bus = Arc::new(RecBus::default());
            let settlement = mk_settlement(budget.clone(), bus.clone(), 2, 2);
            let live = mk_live(settlement.clone());
            let h = match reg.insert_live(live) {
                Ok(h) => h,
                Err(_) => panic!("insert ok"),
            };

            // Before the TTL: nothing may be selected.
            reg.sweep_expired_at(Instant::now());
            assert_eq!(
                budget.commits.load(AOrd::SeqCst),
                0,
                "a pre-TTL sweep must NOT settle a fresh entry (predicate inverted?)"
            );
            assert_eq!(bus.errors.load(AOrd::SeqCst), 0);

            // After the TTL: settled, emitted, evicted.
            reg.sweep_expired_at(Instant::now() + crate::host_fn::STREAM_HANDLE_TTL);
            assert_eq!(
                budget.commits.load(AOrd::SeqCst),
                1,
                "a post-TTL sweep must settle the expired entry (empty body?)"
            );
            assert_eq!(bus.errors.load(AOrd::SeqCst), 1);
            assert!(
                matches!(reg.poll_live(h, "agent-A").await, PollOutcome::Unknown),
                "the expired entry must be evicted"
            );
        });
    }

    /// Re-audit: the double-terminal repair needs its own witness — two concurrent
    /// pollers on the SAME handle must yield exactly ONE terminal chunk between
    /// them (the loser gets the existence-hiding `Unknown`). Reverting the
    /// terminal-consumption latch makes this fail.
    #[test]
    fn t121_two_pollers_yield_exactly_one_terminal() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            for _ in 0..8 {
                let reg = Arc::new(StreamRegistry::new());
                let settlement = mk_settlement(RecBudget::new(), Arc::new(RecBus::default()), 1, 1);
                let live = mk_live(settlement.clone());
                let state = live.state.clone();
                let h = match reg.insert_live(live) {
                    Ok(h) => h,
                    Err(_) => panic!("insert ok"),
                };
                // Publish a Done terminal through the settlement winner package.
                settlement.finalize(
                    SettleOutcome::Terminal,
                    LivePhase::Done {
                        model: "test-model".into(),
                        input_tokens: 1,
                        output_tokens: 1,
                        finish_reason: "stop".into(),
                        parsed_output: None,
                        schema_validation: None,
                    },
                );
                assert!(matches!(
                    state.lock().unwrap().phase,
                    LivePhase::Done { .. }
                ));

                let a = tokio::spawn({
                    let reg = reg.clone();
                    async move { reg.poll_live(h, "agent-A").await }
                });
                let b = tokio::spawn({
                    let reg = reg.clone();
                    async move { reg.poll_live(h, "agent-A").await }
                });
                let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
                let terminals = [&ra, &rb]
                    .iter()
                    .filter(|o| matches!(o, PollOutcome::Done(_) | PollOutcome::Failed(_)))
                    .count();
                assert_eq!(
                    terminals, 1,
                    "exactly one poller may receive the terminal; the other must get Unknown"
                );
            }
        });
    }

    /// T121 arm 3: owner-terminal vs Drop race — whoever wins, exactly one
    /// commit and one terminal record result.
    #[test]
    fn t121_terminal_vs_drop_race_single_settlement() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            for _ in 0..16 {
                let budget = RecBudget::new();
                let bus = Arc::new(RecBus::default());
                let settlement = mk_settlement(budget.clone(), bus.clone(), 1, 1);
                let live = mk_live(settlement.clone());
                let s2 = settlement.clone();
                let t1 = std::thread::spawn(move || {
                    s2.finalize(
                        SettleOutcome::Terminal,
                        LivePhase::Failed(crate::LlmError::ProviderError("a".into())),
                    );
                });
                let t2 = std::thread::spawn(move || drop(live));
                t1.join().unwrap();
                t2.join().unwrap();
                assert_eq!(budget.commits.load(AOrd::SeqCst), 1);
                assert_eq!(
                    bus.errors.load(AOrd::SeqCst) + bus.responses.load(AOrd::SeqCst),
                    1
                );
            }
        });
    }

    /// Settlement bill rules (plan §4): FailedBegin bills ZERO; folded usage is
    /// clamped per-component; missing output usage falls back to ALL decoded bytes.
    #[test]
    fn settlement_bill_rules() {
        // FailedBegin → no commit at all.
        let b = RecBudget::new();
        let bus = Arc::new(RecBus::default());
        let s = mk_settlement(b.clone(), bus, 100, 200);
        assert!(s.finalize(
            SettleOutcome::FailedBegin,
            LivePhase::Failed(crate::LlmError::ProviderError("head".into()))
        ));
        assert_eq!(b.commits.load(AOrd::SeqCst), 0, "failed begins bill zero");
        assert_eq!(s.submitted_bill().unwrap(), (0, 0, 0.0));

        // Folded usage clamped to the per-component ceilings.
        let b2 = RecBudget::new();
        let bus2 = Arc::new(RecBus::default());
        let s2 = mk_settlement(b2.clone(), bus2, 100, 200);
        s2.set_folded(Some(150), Some(50)); // input over ceiling → clamp to 100
        assert!(s2.finalize(
            SettleOutcome::Terminal,
            LivePhase::Failed(crate::LlmError::ProviderError("x".into()))
        ));
        let (t, _) = b2.last.lock().unwrap().unwrap();
        assert_eq!(t, 100 + 50, "input clamped to its ceiling, output exact");

        // Missing output usage → ALL decoded bytes (incl. would-be-suppressed).
        let b3 = RecBudget::new();
        let bus3 = Arc::new(RecBus::default());
        let s3 = mk_settlement(b3.clone(), bus3, 10, 1000);
        s3.add_decoded_bytes(400);
        assert!(s3.finalize(
            SettleOutcome::Abandoned,
            LivePhase::Failed(crate::LlmError::ProviderError("x".into()))
        ));
        let (t3, _) = b3.last.lock().unwrap().unwrap();
        assert_eq!(t3, 10 + 400, "output falls back to decoded-byte ceiling");
    }

    // === Decoded release pipeline security suite (REAL DefaultLeakDetector) ===

    fn real_detector() -> cap_http::DefaultLeakDetector {
        cap_http::DefaultLeakDetector::new()
    }

    fn anthropic_key() -> String {
        format!("sk-ant-api{}", "A".repeat(95))
    }

    /// Split bounded Block anchor across fragments: the key's PREFIX must never be
    /// released, and completion must fail closed.
    #[test]
    fn decoded_split_anchor_blocks_without_prefix_leak() {
        let det = real_detector();
        let key = anthropic_key();
        let (head, tail) = key.split_at(40);
        let mut p = DecodedPipeline::new();
        let (rel1, v1) = p.push(&det, format!("prose before {head}").as_bytes());
        assert!(matches!(v1, DecodedVerdict::Ok));
        assert!(
            !rel1.contains("sk-ant-api"),
            "no key prefix may be released, got: {rel1}"
        );
        let (rel2, v2) = p.push(&det, tail.as_bytes());
        assert!(
            rel2.is_empty() || !rel2.contains("sk-ant"),
            "completion must not release key bytes"
        );
        match v2 {
            DecodedVerdict::Fail(_) => {}
            DecodedVerdict::Ok => {
                // Completion may land at terminal if cadence deferred the scan.
                let (rel3, v3) = p.finish(&det);
                assert!(
                    !rel3.contains("sk-ant"),
                    "terminal must not release key bytes"
                );
                assert!(
                    matches!(v3, DecodedVerdict::Fail(_)),
                    "completed Block match must fail closed"
                );
            }
        }
    }

    /// Invisible-codepoint inflation (the S3 round-2 defect class): U+200B between
    /// key chars must NOT push the match start out of retention — the completed
    /// key still fails closed and no key octets are released.
    #[test]
    fn decoded_invisible_inflation_still_held() {
        let det = real_detector();
        let key = anthropic_key();
        let inflated: String = key.chars().flat_map(|c| ['\u{200B}', c]).collect();
        let (head, tail) = {
            let mid = inflated.char_indices().nth(120).unwrap().0;
            (inflated[..mid].to_string(), inflated[mid..].to_string())
        };
        let mut p = DecodedPipeline::new();
        let (rel1, _v1) = p.push(&det, head.as_bytes());
        assert!(
            !rel1.replace('\u{200B}', "").contains("sk-ant-api"),
            "inflated key prefix must stay held (canonical-space retention)"
        );
        let (rel2, _v2) = p.push(&det, tail.as_bytes());
        let (rel3, v3) = p.finish(&det);
        let all = format!("{rel1}{rel2}{rel3}").replace('\u{200B}', "");
        assert!(
            !all.contains(&key),
            "the assembled key must never be released"
        );
        assert!(
            matches!(v3, DecodedVerdict::Fail(_)) || !all.contains("sk-ant-api"),
            "completed inflated key fails closed or is fully withheld"
        );
    }

    /// Re-audit: the parity property must be exercised on NON-ASCII text too —
    /// on a pure-ASCII fixture the canonical and raw index spaces coincide, so the
    /// alignment logic is not actually stressed.
    /// ADVERSARIAL round 23: the OTHER way a release could outgrow what was counted.
    ///
    /// Round 22 closed the redaction case. Sweeping every return path of
    /// `scan_and_release` for the same shape turned up one more: `release_prefix` converts
    /// the released bytes with `String::from_utf8_lossy`, which substitutes U+FFFD — THREE
    /// bytes — for each invalid byte. That is the identical failure mode as an expanding
    /// redaction: bytes reaching the guest that `add_decoded_bytes` never counted, on the
    /// ordinary single-threaded path.
    ///
    /// It is unreachable, but only because of an upstream guarantee that lives in a
    /// different function and is easy to lose: `scan_and_release` validates the whole
    /// `shadow ++ hold` buffer with `std::str::from_utf8` before any release decision is
    /// made, and fails closed with `decoded scan input not utf-8` if it does not hold. So
    /// by the time `release_prefix` runs, the hold is known-good and the lossy conversion
    /// is a no-op.
    ///
    /// This row pins that chain rather than the coincidence: it feeds invalid UTF-8 and
    /// asserts the pipeline fails closed and releases nothing, so removing or weakening
    /// the upstream validation fails here instead of silently enabling a lossy expansion.
    #[test]
    fn invalid_utf8_fails_closed_rather_than_expanding_through_lossy_conversion() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();

        // A lone continuation byte: invalid UTF-8, and exactly the input that would make
        // from_utf8_lossy substitute a 3-byte replacement character for 1 raw byte.
        let (released, verdict) = p.push(&det, &[b'h', b'i', 0x80]);
        assert!(
            released.is_empty(),
            "nothing may be released from an invalid-UTF-8 buffer, got {released:?}"
        );
        assert!(
            matches!(verdict, DecodedVerdict::Fail(_)),
            "invalid UTF-8 must fail closed before any release decision"
        );

        // And at terminal: the failing push already cleared the hold (every fail-closed
        // arm does), so `finish` has nothing left to flush. What matters for this
        // invariant is that NOTHING was released along the way — not that `finish`
        // reports a second failure for a buffer that is already empty.
        let mut p2 = DecodedPipeline::new();
        let (mid, v_mid) = p2.push(&det, &[b'o', b'k', 0xff]);
        let (fin, _v_fin) = p2.finish(&det);
        assert!(
            matches!(v_mid, DecodedVerdict::Fail(_)),
            "the invalid buffer must fail closed at push time"
        );
        assert!(
            mid.is_empty() && fin.is_empty(),
            "no byte may be released from an invalid-UTF-8 buffer, at push or at \
             terminal: push gave {mid:?}, finish gave {fin:?}"
        );
    }

    /// ADVERSARIAL round 22: a redacted derivative must never be LONGER than the bytes it
    /// replaces.
    ///
    /// The billing invariant the whole slice rests on is "counted before revealed":
    /// `add_decoded_bytes` runs on the RAW decoded bytes at decode time, ahead of the
    /// release. A derivative longer than its original breaks it — the extra bytes reach
    /// the guest never having been counted, deterministically, on the ordinary
    /// single-threaded path, with no concurrency involved. That is strictly worse than
    /// the raced window recorded in `waived_scope`.
    ///
    /// Round 22 measured that the property held by ONE byte: `redact_at_offsets`
    /// substitutes a fixed 10-byte `[REDACTED]`, and the shortest match either shipped
    /// Redact row can produce is 11 bytes. Nothing enforced it — the margin was a numeric
    /// coincidence between `patterns.rs` and `leak_detector.rs`. It is now checked in
    /// `scan_and_release`, and this row pins the relationship rather than the coincidence:
    /// it drives the tightest real match through the real detector and asserts the
    /// derivative did not grow, so a future Redact row with a shorter minimum match — or a
    /// longer placeholder — fails here instead of shipping an uncounted-byte path.
    #[test]
    fn a_redaction_never_expands_beyond_what_was_counted() {
        use advance_shared_types::security_validator::{
            LeakDetector as _, ScanContext, ScanResult,
        };
        let det = real_detector();

        // The tightest match the shipped table can produce, plus the roomier one.
        for original in ["Bearer eyJx", "Authorization: Basic QQ=="] {
            match det.scan(original, ScanContext::HttpOutbound) {
                ScanResult::Redacted { redacted, .. } => {
                    assert!(
                        redacted.len() <= original.len(),
                        "a redaction must not expand: {original:?} ({} bytes) became \
                         {redacted:?} ({} bytes) — the extra bytes would reach the guest \
                         uncounted, since billing happens on the raw bytes at decode time",
                        original.len(),
                        redacted.len()
                    );
                }
                other => panic!("expected {original:?} to redact, got {other:?}"),
            }
        }

        // And end to end through the pipeline: whatever it releases for a redacting
        // fragment is no longer than the bytes that were counted for it.
        let mut p = DecodedPipeline::new();
        let raw = "Bearer eyJx";
        let (mid, _) = p.push(&det, raw.as_bytes());
        let (fin, _) = p.finish(&det);
        assert!(
            mid.len() + fin.len() <= raw.len(),
            "released {} bytes for {} counted",
            mid.len() + fin.len(),
            raw.len()
        );
    }

    /// ADVERSARIAL round 21: what the seal does and does not guarantee, stated exactly.
    ///
    /// Round 21's reviewer reproduced, at 2.08% under unforced concurrent scheduling, a
    /// write landing in the visible buffer after the bill was committed — delivered to a
    /// real poller as `Delta("leaked")` against a bill of `out=0`. Its fixture spawned a
    /// thread calling `append_released` directly while another finalized.
    ///
    /// I could not close that window by moving the seal earlier, and the reason is
    /// structural rather than a matter of ordering: the seal itself must take the
    /// LiveState lock, so it queues for that lock on exactly the same footing as the
    /// writer it is trying to exclude. Sealing "before the bill" only changes which
    /// instruction runs first inside the finalizer; it does not win the lock race. A real
    /// fix would have to make the bill and the buffer share one mutex, which is a
    /// restructuring of `Settlement`, not a patch.
    ///
    /// What makes that acceptable to ship is that the racing shape does not exist in
    /// production, and this row pins the two facts that make it unreachable:
    ///   1. There is exactly ONE writer. Both `append_released` call sites live in the
    ///      owner task's consume loop (`gateway.rs`), which is serial — there is no second
    ///      thread to race it.
    ///   2. That writer counts bytes BEFORE it releases them: `add_decoded_bytes` runs at
    ///      decode time, ahead of `append_released`. Note the two quantities are NOT the
    ///      same measurement — the count is of the RAW wire delta, while the release is
    ///      the post-scan output, which the pipeline may shorten (holding bytes back) or
    ///      substitute (a redaction). The invariant that matters is therefore directional:
    ///      released bytes never EXCEED the raw bytes already counted for them. Holding
    ///      back is safe (counted, not yet revealed); the one case that could break it is
    ///      a redaction longer than its original, which `scan_and_release` now rejects
    ///      outright — see `a_redaction_never_expands_beyond_what_was_counted`.
    /// The reviewer's fixture bypasses (2) by calling `append_released` without counting
    /// first, which is why it observes the window. Recorded rather than papered over:
    /// MODULE-009 §2.7 carries the same statement.
    #[test]
    fn the_production_write_path_bills_before_it_reveals() {
        let budget = RecBudget::new();
        let settlement = mk_settlement(budget.clone(), Arc::new(RecBus::default()), 1000, 1000);
        let state = Arc::new(std::sync::Mutex::new(LiveState::default()));
        let notify = Arc::new(Notify::new());
        settlement.bind(state.clone(), notify.clone());

        // Drive the production ORDER: count, then reveal — the sequence the owner's
        // consume loop uses at both of its release sites.
        for _ in 0..500 {
            settlement.add_decoded_bytes(1);
            // Assert BETWEEN the two steps: this is the only position that can tell the
            // orders apart. After the count but before the reveal, the counter must
            // ALREADY exceed what is visible — that headroom is exactly what makes a
            // concurrent settlement safe. Asserting after both steps proves nothing,
            // since the count has caught up by then either way.
            let visible_before = state.lock().unwrap().visible.len() as u64;
            assert!(
                settlement.decoded_output_bytes() > visible_before,
                "raw bytes counted must lead what has been revealed: counted {}, \
                 visible {visible_before}",
                settlement.decoded_output_bytes()
            );
            crate::gateway::append_released(&state, &notify, "x");
        }

        // Settle underneath it: whatever was visible is already counted, so the bill
        // covers it.
        settlement.finalize(
            SettleOutcome::Terminal,
            LivePhase::Done {
                model: "m".into(),
                input_tokens: 0,
                output_tokens: 0,
                finish_reason: "stop".into(),
                parsed_output: None,
                schema_validation: None,
            },
        );
        let visible = state.lock().unwrap().visible.len() as u64;
        let (_, billed_out, _) = settlement.submitted_bill().expect("settled");
        assert!(
            billed_out >= visible,
            "the bill must cover every visible byte: billed {billed_out}, visible {visible}"
        );
    }

    /// ADVERSARIAL round 21: the settled-flag write introduced a nested lock
    /// acquisition, and its safety rests on one invariant — the writer path never
    /// takes the settlement lock while holding the state lock.
    ///
    /// `Settlement::finalize` takes `inner`, then `bound`, then `state` — the seal
    /// write runs in its OWN earlier acquisition BEFORE the bill is computed (round
    /// 21 seal-first; since round 24 no critical section commits at all — round 30
    /// re-synced this note, which had kept the round-20 "same critical section that
    /// commits" wording). `append_released` takes
    /// only `state`. That is a strict one-way order, so no deadlock exists — but only
    /// while `append_released` stays free of settlement calls. This row drives both
    /// concurrently on real OS threads: if a future edit makes the write path reach
    /// back into the settlement under its own lock, the order inverts and this hangs
    /// rather than shipping a lock-order inversion into a live streaming path.
    #[test]
    fn the_settled_write_cannot_invert_the_lock_order() {
        let budget = RecBudget::new();
        let settlement = mk_settlement(budget.clone(), Arc::new(RecBus::default()), 1000, 1000);
        let state = Arc::new(std::sync::Mutex::new(LiveState::default()));
        let notify = Arc::new(Notify::new());
        settlement.bind(state.clone(), notify.clone());

        let s2 = settlement.clone();
        let st2 = state.clone();
        let n2 = notify.clone();
        let writer = std::thread::spawn(move || {
            for i in 0..2000 {
                crate::gateway::append_released(&st2, &n2, "x");
                if i == 500 {
                    std::thread::yield_now();
                }
            }
        });
        let finalizer = std::thread::spawn(move || {
            std::thread::yield_now();
            s2.finalize(
                SettleOutcome::Abandoned,
                LivePhase::Failed(crate::LlmError::ProviderError("reaped".into())),
            )
        });

        // Both must complete: a lock-order inversion would hang one of them and this
        // join would never return.
        writer.join().expect("writer must not deadlock");
        let won = finalizer.join().expect("finalizer must not deadlock");
        assert!(won, "the sole finalizer must win");
        assert_eq!(budget.commits.load(AOrd::SeqCst), 1);
        // Whatever the interleaving, no write may land after the flag is set.
        let st = state.lock().unwrap();
        assert!(st.settled, "settlement must have latched");
    }

    /// ADVERSARIAL round 20's finding, as then stated: the write latch must close
    /// with the BILL, not with the phase. As-built it closes even earlier — at the
    /// seal, before the bill is computed (round 21).
    ///
    /// Round 19's latch keyed on `LiveState::phase`. Round 20 showed `finalize` publishes
    /// that phase LAST — after committing the bill, after setting `committed`, after
    /// releasing the settlement lock, and after emitting the terminal event — so in that
    /// window the stream is settled by every other measure while `phase` is still
    /// `Running`, and the guard admitted the write. The reviewer forced it with a
    /// barrier-blocked bus emitter and observed `visible == "hello world"` with
    /// `commits == 1`. The consequence was contained (finalize clears `pending` after the
    /// window, and `poll_live` pops it under the same mutex — a real spawned poller saw
    /// nothing across 200 attempts), but an inexact guard on an accounting invariant is a
    /// defect waiting for a refactor.
    ///
    /// The latch keys on `settled`, which the winner sets in its OWN seal
    /// acquisition BEFORE the bill is even computed (round 21; the round-20 form —
    /// commit-time latching — is the superseded shape this rustdoc described until
    /// round 30). WHAT THIS ROW PINS (name re-corrected round 31 — the round-30
    /// name `..._before_the_bill_is_computed` claimed an ordering no assertion
    /// discriminates; a commit-time-latch revert mutant passed it): once
    /// `finalize` RETURNS, the flag is observable and later writes are refused.
    /// The seal-before-compute placement itself is inspection-verified in
    /// `finalize` (its seal block precedes the critical section) and is not
    /// pinned by any executed assertion here.
    #[test]
    fn the_write_latch_is_closed_once_finalize_returns() {
        let budget = RecBudget::new();
        let bus = Arc::new(RecBus::default());
        let settlement = mk_settlement(budget.clone(), bus.clone(), 1000, 1000);
        let state = Arc::new(std::sync::Mutex::new(LiveState::default()));
        let notify = Arc::new(Notify::new());
        settlement.bind(state.clone(), notify.clone());

        crate::gateway::append_released(&state, &notify, "hello ");
        assert!(!state.lock().unwrap().settled, "not settled while Running");

        settlement.finalize(
            SettleOutcome::Abandoned,
            LivePhase::Failed(crate::LlmError::ProviderError("reaped".into())),
        );

        // The seal is written BEFORE the bill is computed (inspection-verified in
        // `finalize` — NOT pinned by these assertions, per the rustdoc above; the
        // commit call runs outside every guard), so by the time any observer can
        // see the commit it can also see the refusal.
        let st = state.lock().unwrap();
        assert!(
            st.settled,
            "settled must be latched by the time finalize returns"
        );
        assert_eq!(budget.commits.load(AOrd::SeqCst), 1);
        drop(st);

        crate::gateway::append_released(&state, &notify, "world");
        let st = state.lock().unwrap();
        assert_eq!(st.visible, "hello ", "post-commit writes are refused");
        assert!(st.pending.is_empty());
    }

    /// ADVERSARIAL round 19, reproduced attack: a write that lands AFTER settlement must
    /// not resurrect the stream.
    ///
    /// The TTL reaper and `Drop for LiveStream` both call `finalize` from a task
    /// scheduled independently of the owner, and the owner's per-delta path has no
    /// `.await` between its cap check and `append_released` — so a reap can land while
    /// the owner is mid-frame, and the owner will still finish writing that frame.
    /// Before the fix, that write re-populated `pending` and the guest received a normal
    /// `Delta` carrying content that was never billed and never reported: the reviewer
    /// observed `visible` grow to "hello world" with commits and error events both still
    /// at 1. That contradicted this module's own "abandoned streams are never free"
    /// invariant. `append_released` now refuses to write once the phase is terminal.
    #[test]
    fn a_write_after_settlement_cannot_resurrect_the_stream() {
        let budget = RecBudget::new();
        let bus = Arc::new(RecBus::default());
        let settlement = mk_settlement(budget.clone(), bus.clone(), 1000, 1000);
        let state = Arc::new(std::sync::Mutex::new(LiveState::default()));
        let notify = Arc::new(Notify::new());
        settlement.bind(state.clone(), notify.clone());

        // Chunk 1 arrives normally, while the stream is Running.
        crate::gateway::append_released(&state, &notify, "hello ");
        settlement.add_decoded_bytes(6);
        assert_eq!(state.lock().unwrap().visible, "hello ");

        // The reaper lands: exactly the call `settle_expired_batch` and `Drop` make.
        settlement.finalize(
            SettleOutcome::Abandoned,
            LivePhase::Failed(crate::LlmError::ProviderError(
                "stream reaped after ttl".into(),
            )),
        );
        let commits_after_reap = budget.commits.load(AOrd::SeqCst);
        let errors_after_reap = bus.errors.load(AOrd::SeqCst);
        assert_eq!(commits_after_reap, 1, "the reap settles exactly once");
        assert_eq!(errors_after_reap, 1, "and emits its one terminal record");

        // The owner finishes the frame it was already processing when the reap landed.
        crate::gateway::append_released(&state, &notify, "world");
        settlement.add_decoded_bytes(5);

        let st = state.lock().unwrap();
        assert_eq!(
            st.visible, "hello ",
            "a post-settlement write must not extend the guest-visible buffer"
        );
        assert!(
            st.pending.is_empty(),
            "and must not resurrect `pending` for a guest to poll"
        );
        assert_eq!(
            budget.commits.load(AOrd::SeqCst),
            1,
            "still exactly one commit"
        );
        assert_eq!(
            bus.errors.load(AOrd::SeqCst),
            1,
            "still exactly one terminal record"
        );
    }

    /// ADVERSARIAL round 18: the monotonic floor covers BOTH usage legs, not just output.
    ///
    /// Round 17 added the floor to `folded_output` after a later, lower report erased
    /// earlier billing. Round 18's reviewer, reading the code while designing a different
    /// probe, found the input branch was still an unconditional overwrite — the identical
    /// erasure, one axis over — and that round 17's own commit message asserted
    /// `set_folded` "only ever raises the figure", which was true of exactly one branch.
    /// No shipped adapter can produce a second, lower input report (Anthropic sends
    /// `input_tokens` once at `message_start`; OpenAI sends both counters in a single
    /// terminal frame), so this was never reachable — but an unreachable asymmetry is
    /// still the kind of thing a fourth adapter would turn into a live defect.
    #[test]
    fn the_monotonic_floor_covers_both_usage_legs() {
        let budget = RecBudget::new();
        let s = mk_settlement(budget.clone(), Arc::new(RecBus::default()), 5000, 5000);

        s.set_folded(Some(1000), Some(5));
        s.set_folded(Some(1), None); // a later, LOWER input report
        let (bin, bout) = s.projected_bill();
        assert_eq!(
            bin, 1000,
            "a lower later INPUT report must not erase the earlier figure"
        );
        assert_eq!(
            bout, 5,
            "the output leg must be untouched by an input-only report"
        );

        // And the output leg still holds its own floor, unchanged by this fix.
        let s2 = mk_settlement(RecBudget::new(), Arc::new(RecBus::default()), 5000, 5000);
        s2.set_folded(Some(1), Some(100));
        s2.set_folded(Some(1), Some(0));
        let (_, bout2) = s2.projected_bill();
        assert_eq!(
            bout2, 100,
            "a lower later OUTPUT report must not erase either"
        );
    }

    /// ADVERSARIAL round 18: `projected_bill()` and `finalize`'s own `compute_bill` must
    /// agree, and must keep agreeing if writes land between them.
    ///
    /// Round 17 collapsed two DIVERGENT copies of the billing formula into one function,
    /// but the gateway still calls it at a different instant than `finalize` does — the
    /// drift risk moved from the logic to the timing. In production the window is
    /// structurally empty: both writers (`add_decoded_bytes`, `set_folded`) run inside the
    /// owner's `'consume` loop, and `projected_bill()` is called only after that loop has
    /// broken, on the same serial task. This pins that property rather than trusting it:
    /// it asserts agreement in the quiet case, and then asserts that a write landing in
    /// the window is REFLECTED by finalize rather than silently ignored — so a future
    /// change that reintroduces a concurrent writer fails here instead of shipping a
    /// terminal whose figures contradict the ledger.
    #[test]
    fn projected_bill_agrees_with_what_finalize_commits() {
        // --- quiet window: the production shape ---
        let budget = RecBudget::new();
        let bus = Arc::new(RecBus::default());
        let s = mk_settlement(budget.clone(), bus.clone(), 100, 100);
        s.set_folded(Some(7), Some(11));
        s.add_decoded_bytes(40);

        let (pin, pout) = s.projected_bill();
        s.finalize(
            SettleOutcome::Terminal,
            LivePhase::Done {
                model: "m".into(),
                input_tokens: pin,
                output_tokens: pout,
                finish_reason: "stop".into(),
                parsed_output: None,
                schema_validation: None,
            },
        );
        let (committed_total, _) = budget.last.lock().unwrap().unwrap();
        assert_eq!(
            pin.saturating_add(pout),
            committed_total,
            "the figure handed to the guest must equal the figure committed"
        );

        // --- a write LANDS in the window: finalize must account for it ---
        let budget2 = RecBudget::new();
        let s2 = mk_settlement(budget2.clone(), Arc::new(RecBus::default()), 100, 100);
        s2.set_folded(Some(7), Some(11));
        s2.add_decoded_bytes(40);
        let (_, projected_before) = s2.projected_bill();
        // Simulate a concurrent writer slipping in after the projection.
        s2.add_decoded_bytes(25);
        s2.finalize(
            SettleOutcome::Terminal,
            LivePhase::Done {
                model: "m".into(),
                input_tokens: 0,
                output_tokens: 0,
                finish_reason: "stop".into(),
                parsed_output: None,
                schema_validation: None,
            },
        );
        let (total_after, _) = budget2.last.lock().unwrap().unwrap();
        let committed_out = total_after.saturating_sub(7);
        assert_eq!(
            committed_out,
            projected_before + 25,
            "bytes decoded after the projection must still be billed: projected {projected_before}, \
             committed {committed_out}"
        );
    }

    /// AUDIT round 10: the DoS/resource bounds this module and §3.6/§1.6 publish as NUMBERS
    /// were witnessed only SYMBOLICALLY — `t95_registry_full_rejects` and `t95_ttl_eviction`
    /// fill the registry with `0..MAX_CONCURRENT_STREAMS`, so raising the constant scales the
    /// test's own loop in lockstep and nothing fails. A bound whose value no test pins is a
    /// bound that can be relaxed silently. These are the values the docs quote; changing one
    /// must be a deliberate act that updates the doc in the same commit.
    #[test]
    fn published_resource_bounds_are_pinned_to_their_documented_values() {
        assert_eq!(
            MAX_CONCURRENT_STREAMS, 256,
            "MODULE-009 §2.11 Operational Parameters publishes 256 concurrent stream handles"
        );
        assert_eq!(
            MAX_STREAM_DELTAS, 2048,
            "MODULE-009 §2.11 publishes a 2048-delta coalescing bound"
        );
        assert_eq!(
            crate::host_fn::MAX_ENCODED_TEXT_BYTES,
            256 * 1024,
            "MODULE-009 §2.11 publishes the 256-KiB guest-visible cap; §3.6(11) scopes what it suppresses"
        );
        assert_eq!(
            crate::host_fn::STREAM_HANDLE_TTL,
            Duration::from_secs(300),
            "MODULE-009 §2.11 publishes a 300 s handle TTL"
        );
        assert_eq!(
            crate::host_fn::DEFAULT_STREAM_OUTPUT_TOKENS,
            4096,
            "MODULE-009 §2.7 inv 6 and §3.6(2) publish a 4096-token default output ceiling"
        );
        assert_eq!(
            DECODED_TAIL_WINDOW,
            64 * 1024,
            "MODULE-009 §3.6(3) publishes a 64-KiB raw shadow window"
        );
        assert_eq!(
            DECODED_HOLD_CAP,
            256 * 1024,
            "MODULE-009 §2.7 inv 6 publishes a 256-KiB decoded hold cap"
        );
    }

    /// AUDIT round 5: the terminal-Redacted region bound must not deny BENIGN streams.
    /// An adversarial probe showed that requiring the joined canonicalization to be
    /// prefixed by the shadow's own canonicalization fails on ordinary content: a
    /// combining mark near the hold boundary composes with the preceding base letter
    /// under joined NFKC, so the prefix test breaks and the whole unreleased tail is
    /// discarded even though nothing dangerous is present. The bound is one-sided (it
    /// can only over-hold, never release a match), so the correct posture is a
    /// conservative length, not a hard failure.
    #[test]
    fn decoded_boundary_composition_does_not_deny_benign_stream() {
        let det = real_detector();
        // Fragment 1 must exceed the scan cadence so a scan actually fires and prose is
        // RELEASED (a non-empty shadow is what the bound is computed from); it ends on a
        // bare base letter. Fragment 2 opens with a combining acute that composes with
        // that letter under joined NFKC, and carries an auth header that MATCHES the Redact pattern, so the terminal
        // verdict is `Redacted` and the guarded arm actually executes.
        let bulk = "The retry budget resets hourly and callers should back off. ".repeat(90);
        let frag1 = format!("{bulk}See the note");
        let frags = [
            frag1.as_str(),
            "\u{0301} below: Authorization: Basic YWxpY2U6c2VjcmV0 is the shape.",
        ];
        let mut p = DecodedPipeline::new();
        let mut all = String::new();
        for f in frags {
            let (r, v) = p.push(&det, f.as_bytes());
            all.push_str(&r);
            assert!(
                !matches!(v, DecodedVerdict::Fail(_)),
                "benign fragment denied mid-stream"
            );
        }
        let (t, v) = p.finish(&det);
        all.push_str(&t);
        assert!(
            !matches!(v, DecodedVerdict::Fail(_)),
            "benign stream denied at terminal"
        );
        assert!(
            all.contains("The retry budget resets hourly"),
            "released prefix lost: {all:?}"
        );
        assert!(
            all.contains("is the shape"),
            "benign tail was discarded instead of released: {all:?}"
        );
        assert!(
            !all.contains("YWxpY2U6c2VjcmV0"),
            "the matched credential must still be redacted: {all:?}"
        );
    }

    #[test]
    fn decoded_parity_holds_on_non_ascii_text() {
        use advance_shared_types::security_validator::{
            LeakDetector as _, ScanContext, ScanResult,
        };
        let det = real_detector();
        // Combining marks, a ligature, fullwidth forms and an ellipsis around a
        // credential, split at awkward points.
        let frags = [
            "café\u{0301} déjà vu — ",
            "ﬁle … Ｆｕｌｌ width ",
            "Authorization: Basic ",
            "YWRtaW46",
            "cGFzc3dvcmQ=",
            " and a naïve tail…",
        ];
        let whole: String = frags.concat();
        let expected = match det.scan(&whole, ScanContext::HttpOutbound) {
            ScanResult::Redacted { redacted, .. } => Some(redacted),
            ScanResult::Clean | ScanResult::Warned { .. } => None,
            other => panic!("unexpected whole-text verdict {other:?}"),
        };
        let mut p = DecodedPipeline::new();
        let mut all = String::new();
        let mut failed = false;
        for f in frags {
            let (r, v) = p.push(&det, f.as_bytes());
            all.push_str(&r);
            if matches!(v, DecodedVerdict::Fail(_)) {
                failed = true;
                break;
            }
        }
        if !failed {
            let (t, v) = p.finish(&det);
            all.push_str(&t);
            failed = matches!(v, DecodedVerdict::Fail(_));
        }
        assert!(
            !all.contains("YWRtaW46cGFzc3dvcmQ="),
            "credential leaked: {all:?}"
        );
        if !failed {
            // The SECURITY property: re-scanning the assembled release stream must
            // find no Block/Redact match left in it.
            match det.scan(&all, ScanContext::HttpOutbound) {
                ScanResult::Clean | ScanResult::Warned { .. } => {}
                other => panic!("the release stream still carries a match: {other:?} / {all:?}"),
            }
            // And the non-matching text is PRESERVED VERBATIM — the streaming path
            // canonicalizes only the redacted region, whereas the buffered path
            // replaces the WHOLE body with the canonicalized derivative (a
            // divergence in the guest's favour; recorded in MODULE-009 §3.6(10)).
            assert!(
                all.starts_with("café\u{0301} déjà vu — ﬁle … Ｆｕｌｌ width "),
                "non-matching text must be preserved verbatim, got {all:?}"
            );
            if let Some(exp) = &expected {
                assert_ne!(
                    &all, exp,
                    "if this ever becomes equal, the streaming path started canonicalizing \
                     non-matching text — update §3.6(10) and this assertion together"
                );
            }
        }
        // A fail-closed outcome is acceptable here (documented residual 8); a LEAK
        // is not, and the assertion above covers it.
    }

    /// MERGE-GATE REGRESSION (2026-07-29). The audit reproduced a live leak in
    /// which the redacted DERIVATIVE was fed back into the detector's shadow,
    /// destroying the `Bearer`/`Authorization: Basic` anchor so later fragments
    /// scanned Clean and the credential CONTINUATION was released verbatim. The
    /// invariant that closes it is PARITY WITH THE WHOLE-TEXT SCAN: whatever the
    /// buffered path would emit for the same text, the streaming path emits — no
    /// more. This arm pins that parity for a delta-split JWT AND asserts the
    /// matched span itself never appears.
    ///
    /// NOTE on scope: `bearer_token` is `(?i)Bearer\s+eyJ[A-Za-z0-9_-]+`, whose
    /// character class stops at the first `.`, so a JWT's payload and signature
    /// are OUTSIDE the pattern and the detector (on any path, buffered or
    /// streaming) does not redact them. That is a CONTRACT-112 pattern-coverage
    /// property owned by MODULE-012, recorded as a residual in MODULE-009 §3.6 —
    /// not something the decoded layer introduces or may paper over. Asserting
    /// more than parity here would be asserting a property the system does not
    /// have.
    #[test]
    fn decoded_greedy_continuation_matches_whole_text_scan_jwt() {
        use advance_shared_types::security_validator::{
            LeakDetector as _, ScanContext, ScanResult,
        };
        let det = real_detector();
        let frags = [
            "Here is the token: Bearer ",
            "eyJ",
            "hbGciOiJIUzI1NiJ9",
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ];
        let whole: String = frags.concat();
        let expected = match det.scan(&whole, ScanContext::HttpOutbound) {
            ScanResult::Redacted { redacted, .. } => redacted,
            other => panic!("fixture must produce a Redacted whole-text verdict, got {other:?}"),
        };

        let mut p = DecodedPipeline::new();
        let mut all = String::new();
        for frag in frags {
            let (r, v) = p.push(&det, frag.as_bytes());
            all.push_str(&r);
            assert!(
                matches!(v, DecodedVerdict::Ok),
                "benign-shaped stream must not fail"
            );
        }
        let (tail, v) = p.finish(&det);
        assert!(matches!(v, DecodedVerdict::Ok));
        all.push_str(&tail);

        assert_eq!(
            all, expected,
            "streaming release must equal the whole-text scan derivative (no extra bytes)"
        );
        // The MATCHED span — the part the detector does cover — must be gone.
        assert!(
            !all.contains("eyJhbGciOiJIUzI1NiJ9"),
            "the matched credential span leaked: {all:?}"
        );
        assert!(
            all.contains("[REDACTED]"),
            "the derivative must be emitted: {all:?}"
        );
    }

    /// Same class for `Authorization: Basic` where the match completes after a
    /// SINGLE base64 character (the audit's E2): the remaining base64 must never
    /// be released, so the password cannot be recovered.
    #[test]
    fn decoded_greedy_continuation_never_released_basic() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();
        let mut all = String::new();
        let mut first_release: Option<String> = None;
        for frag in [
            "Authorization: Basic ",
            "Y",
            "WRtaW46c3VwZXJzZWNyZXRwYXNzd29yZA==",
            " done",
        ] {
            let (r, v) = p.push(&det, frag.as_bytes());
            if first_release.is_none() {
                first_release = Some(r.clone());
            }
            all.push_str(&r);
            if let DecodedVerdict::Fail(_) = v {
                break;
            }
        }
        // AUDIT round 8: without this assertion the test witnessed NOTHING about the
        // Clean arm. Fragment 1 scans Clean (no completed match yet) but is a fully
        // viable `auth_header_basic` prefix, so the split must hold ALL of it. Releasing
        // the hold verbatim on the Clean arm used to pass here, because fragment 2 trips
        // an unrelated Redacted fail-close before the base64 body is ever pushed — the
        // fixture's own shape, not the bound under test, was doing the work.
        assert_eq!(
            first_release.as_deref(),
            Some(""),
            "a still-viable Block/Redact prefix must be HELD on the Clean arm, not released"
        );
        let (tail, _v) = p.finish(&det);
        all.push_str(&tail);
        assert!(
            !all.contains("WRtaW46c3VwZXJzZWNyZXRwYXNzd29yZA"),
            "base64 credential continuation leaked: {all:?}"
        );
        // And the decoded password must not be recoverable from the release stream.
        assert!(!all.contains("supersecret"), "cleartext-ish leak: {all:?}");
    }

    /// MERGE-GATE REGRESSION: a co-resident still-viable BLOCK candidate must not
    /// ride out on a Redact verdict (the audit released `sk-proj-` alongside a
    /// redacted bearer token because the Redacted arm ignored the hold split).
    #[test]
    fn decoded_redact_does_not_release_coresident_block_candidate() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();
        let (r1, _v1) = p.push(&det, b"Bearer eyJabc sk-proj-");
        assert!(
            !r1.contains("sk-proj-"),
            "viable Block candidate released on a Redact verdict: {r1:?}"
        );
        // Completing the openai key must then fail closed, still without leaking.
        let (r2, v2) = p.push(&det, "A".repeat(40).as_bytes());
        let (r3, v3) = p.finish(&det);
        let all = format!("{r1}{r2}{r3}");
        assert!(!all.contains("sk-proj-A"), "key material leaked: {all:?}");
        assert!(
            matches!(v2, DecodedVerdict::Fail(_)) || matches!(v3, DecodedVerdict::Fail(_)),
            "a completed Block family must fail closed; got {all:?}"
        );
    }

    /// The shadow keeps the ORIGINAL bytes (never the derivative), so a detector
    /// scan after a redaction still sees the real anchor. Witnessed indirectly by
    /// the two continuation arms above and directly here: after a redaction, a
    /// benign continuation is still released (the pipeline is not wedged) while
    /// the credential stays out.
    #[test]
    fn decoded_shadow_keeps_original_after_redaction() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();
        let mut all = String::new();
        for frag in [
            "Bearer eyJabcdefghij",
            " and then ordinary prose follows here.",
        ] {
            let (r, _v) = p.push(&det, frag.as_bytes());
            all.push_str(&r);
        }
        let (t, _v) = p.finish(&det);
        all.push_str(&t);
        assert!(!all.contains("eyJabcdefghij"), "token leaked: {all:?}");
        assert!(
            all.contains("ordinary prose follows here."),
            "benign continuation must still reach the guest: {all:?}"
        );
    }

    /// A bearer token that COMPLETES its pattern is a Redact family: the token
    /// text is never released in cleartext — the detector derivative goes out
    /// instead (and an open-but-incomplete candidate is held, see the EOF test).
    #[test]
    fn decoded_completed_bearer_is_redacted_never_cleartext() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();
        let (r1, v1) = p.push(&det, b"Bearer eyJabc");
        let (r2, v2) = p.finish(&det);
        let all = format!("{r1}{r2}");
        assert!(
            !all.contains("eyJabc"),
            "token cleartext must never be released: {all}"
        );
        assert!(
            all.contains("[REDACTED]")
                || matches!(v1, DecodedVerdict::Fail(_))
                || matches!(v2, DecodedVerdict::Fail(_)),
            "a completed Redact match must emit the derivative or fail closed; got {all}"
        );
    }

    /// An INCOMPLETE candidate (viable prefix, no completed match) is held and
    /// released only when the audited sweep confirms no completed match at EOF —
    /// never flushed on the whole-string verdict alone.
    #[test]
    fn decoded_incomplete_candidate_held_then_released_at_eof() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();
        // "sk-ant-api" + 10 chars: a viable prefix of anthropic_key (needs 90+).
        let (r1, v1) = p.push(&det, b"prefix text sk-ant-apiAAAAAAAAAA");
        assert!(matches!(v1, DecodedVerdict::Ok));
        assert!(
            !r1.contains("sk-ant-api"),
            "viable candidate must be held: {r1}"
        );
        let (r2, v2) = p.finish(&det);
        assert!(
            matches!(v2, DecodedVerdict::Ok),
            "no completed match ⇒ tail releases at EOF"
        );
        assert_eq!(
            format!("{r1}{r2}"),
            "prefix text sk-ant-apiAAAAAAAAAA",
            "held candidate is released exactly once resolved"
        );
    }

    /// MODULE-012-AC-24: `Bearer eyJa` + U+0301 is a detector Redact after
    /// mark-drop. Security property is no credential bytes in the guest-visible
    /// concat of push+finish (loosening only `finish` would miss a leaking push).
    #[test]
    fn decoded_nfkc_composition_eof_fails_closed() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();
        let (r1, v1) = p.push(&det, "Bearer eyJa\u{0301}".as_bytes());
        let (r2, v2) = p.finish(&det);
        let all = format!("{r1}{r2}");
        assert!(
            !all.contains("eyJ"),
            "credential cleartext must never be released: {all:?}"
        );
        assert!(
            all.contains("[REDACTED]")
                || matches!(v1, DecodedVerdict::Fail(_))
                || matches!(v2, DecodedVerdict::Fail(_)),
            "spliced bearer must redact or fail closed; got {all:?}"
        );
    }

    /// Benign text round-trip: releases with retention, terminal flushes the tail,
    /// concat(released) == input.
    #[test]
    fn decoded_benign_roundtrip_exact() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();
        let input = "The quick brown fox jumps over the lazy dog. ".repeat(40);
        let mut out = String::new();
        for chunk in input.as_bytes().chunks(97) {
            let (r, v) = p.push(&det, chunk);
            assert!(matches!(v, DecodedVerdict::Ok));
            out.push_str(&r);
        }
        let (tail, vt) = p.finish(&det);
        assert!(matches!(vt, DecodedVerdict::Ok));
        out.push_str(&tail);
        assert_eq!(out, input, "benign text must round-trip exactly");
    }

    /// Hold-cap overflow fails closed (ADR D3).
    #[test]
    fn decoded_hold_cap_overflow_fails_closed() {
        let det = real_detector();
        let mut p = DecodedPipeline::new();
        // An open bearer candidate pins the hold; grow past 256 KiB.
        let (_r, _v) = p.push(&det, b"Bearer eyJ");
        let big = "a".repeat(300 * 1024);
        let (_r2, v2) = p.push(&det, big.as_bytes());
        assert!(
            matches!(v2, DecodedVerdict::Fail(_)),
            "hold-cap crossing must fail closed"
        );
    }
}
