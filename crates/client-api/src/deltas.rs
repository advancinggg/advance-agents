//! Tee T2 — CONTRACT-235 `LlmDeltaHub` over the CONTRACT-234 `LlmDeltaSink` port (§2.4).
//!
//! The hub owns the bounded per-(agent, stream_key) delta buffer, the egress release
//! frontier (hold-to-the-end scan discipline), the release-gated read path, and the
//! subscriber semaphore. The WS pump + scope-gated subscribe handler land in tee slice 2;
//! everything here is transport-agnostic sync core (the `publish` hot path never awaits).
//!
//! Normative mechanism: MODULE-020 §2.4 pins (i)–(xv), §2.11 LLM-delta rows, §2.12
//! `LlmDeltaHub` owned-state row, §3.8 T2 decisions; port invariants 1/2/3/3b/4/5/6 in
//! `shared-types/src/traits.rs`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use advance_shared_types::traits::{LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink, LlmTerminalReason};

use crate::clock::Clock;
use crate::cursor::{
    encode_delta_cursor_body, ClientCursorCodec, OpenedSeal, SealPurpose, SEAL_TAG_DELTA_CURSOR,
};
use crate::envelope::{ClientError, ClientErrorCode};

// ─────────────────────────────────────────────────────────────────────────
// §2.11 operational constants (enforcement site)
// ─────────────────────────────────────────────────────────────────────────

/// Per-stream window: released + pending text bytes (≤256 KiB). Pending alone reaching this
/// bound triggers the pin-(iii) `Delta` drop (control frames exempt).
pub(crate) const DELTA_WINDOW_BYTES: usize = 256 * 1024;
/// Shared discontinuity budget (seen-range gaps ⊇ storage gaps). Counts GAPS, not seqs.
pub(crate) const DELTA_MAX_DISCONTINUITIES: usize = 1024;
/// Live-stream admission caps (checked ONLY at `Begin`).
pub(crate) const DELTA_GLOBAL_STREAM_CAP: usize = 64;
pub(crate) const DELTA_PER_AGENT_STREAM_CAP: usize = 8;
/// Lingering (terminated, replay-serving) entry cap; overflow displaces the OLDEST.
pub(crate) const DELTA_LINGERING_CAP: usize = 64;
/// Coalesced dropped-seq ranges per stream; overflow merges (over-report, never under).
pub(crate) const DELTA_DROPPED_RANGES_CAP: usize = 64;
/// Egress scan step bound: the release candidate is the maximal prefix of pending WHOLE
/// frames within this bound, or ONE larger frame alone.
pub(crate) const DELTA_SCAN_STEP_BYTES: usize = 64 * 1024;
/// cap-http `MAX_HOLD_BYTES` mirror: a computed hold at/over this degrades the span to
/// `Blocked` (closed-with-progress; never a stall).
pub(crate) const DELTA_MAX_HOLD_BYTES: usize = 256 * 1024;
/// Facade budget passed to the injected `decoded_hold_split` closure (§2.4 pin ii).
pub(crate) const DELTA_MAX_CANONICAL_BYTES: usize = 4 * 1024 * 1024;
/// Page assembly bound (multi-item); a single INDIVISIBLE item may exceed it and ships
/// alone on an oversized page (§2.4 page-bound exception).
pub(crate) const DELTA_PAGE_MAX_BYTES: usize = 64 * 1024;
/// Subscriber cap (RAII permits; transport maps overflow to `stream_backpressure` → 429).
pub(crate) const DELTA_SUBSCRIBER_CAP: usize = 4;
/// Bounded released-item index (the minted-item list is the replay index); overflow evicts
/// the released HEAD only (never unreleased bytes), recorded in the evicted ranges.
const DELTA_RELEASED_ITEMS_CAP: usize = 8192;

/// Slice-2 pump timing constants, pinned at the enforcement site (§2.11 rows; U-17 leg (i)
/// asserts CADENCE ≤ 5s ∧ 2×CADENCE + ALLOWANCE ≤ REAUTH_MAX_AGE ≤ 15s). NOT
/// operator-configurable; test override only behind the `test-support` feature.
pub(crate) const DELTA_PUMP_CADENCE: Duration = Duration::from_secs(5);
pub(crate) const DELTA_PUMP_REAUTH_MAX_AGE: Duration = Duration::from_secs(15);
pub(crate) const DELTA_PUMP_ALLOWANCE: Duration = Duration::from_secs(1);
/// Terminal linger (~30 s): lazy-evicted on read past the deadline; post-terminal
/// publishes do NOT re-arm it (§2.4 round 12).
pub(crate) const DELTA_TERMINAL_LINGER: Duration = Duration::from_secs(30);

/// The `stream_id` slot fed to the cursor codec AAD for delta cursors (the stream identity
/// itself rides INSIDE the sealed body, both-or-neither, so `open` needs no prior key).
pub const DELTA_CURSOR_STREAM_DOMAIN: &str = "llm-deltas";

/// §2.4 pin (xv): THE canonical client-facing absent-semantics string, provenance-token-free.
/// Pinned byte-exactly onto all five `conformance/fixtures/*/surface.json` (the G-1 ship gate
/// compares THIS string) and stated in `sdk-artifacts/README.md`.
pub const LLM_DELTA_ABSENT_NOTE: &str = "An absent stream that this surface previously served \
will never be served again; a stream key you have never received content for reads absent with \
no delivery promise.";

// ─────────────────────────────────────────────────────────────────────────
// Observer seam (§2.4 pin xiv) — the only telemetry; static kinds, never raw text.
// ─────────────────────────────────────────────────────────────────────────

/// Fail-closed drop observations witnessable only through the injected observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubEvent {
    /// A residual nonzero live hold was dropped fail-closed at an entry's final eviction.
    ResidualHoldDropped,
    /// A frame for an unknown/refused key (or an over-cap / duplicate `Begin`) was discarded.
    RefusedStreamDiscard,
    /// A `Terminal` carried a non-finite `cost_usd`; serialized as `Some` + `0.0`.
    NonFiniteCost,
    /// Pending content accepted after linger expiry was evicted unread.
    EvictedUnreadPending,
}

/// Injected hold-geometry closure (composition root wraps
/// `cap_http::canonical_facade::decoded_hold_split`): returns the SPLIT point;
/// hold = input len − split. `Err` fails closed (`Blocked`-advance).
pub type DeltaHoldSplit = Arc<dyn Fn(&[u8], usize) -> Result<usize, ()> + Send + Sync>;
/// Injected observer (production: tracing-backed at the cli root; absent ⇒ no-op).
pub type DeltaObserver = Arc<dyn Fn(HubEvent) + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────
// Wire DTOs (serde, snake_case, deny_unknown_fields). NO not_teed_count field
// (ADR 2026-08-03 B1: producer-side tee suppression is unobservable here).
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LlmDeltaPage {
    pub stream_key: String,
    pub agent_id: String,
    pub run_id: Option<String>,
    pub from_seq: u64,
    pub to_seq: u64,
    pub deltas: Vec<LlmDeltaItem>,
    pub dropped_count: u32,
    pub rejected_count: u32,
    pub redacted_count: u32,
    pub warned_count: u32,
    pub page_limit_reached: bool,
    pub absent: bool,
    pub cursor: Option<LlmDeltaCursor>,
    pub terminal: Option<LlmDeltaTerminal>,
}

/// One wire item: a verbatim per-seq delta (`from_seq == to_seq`) or a synthetic
/// seq-RANGE replacement entry (ADR Correction §C-A3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LlmDeltaItem {
    pub from_seq: u64,
    pub to_seq: u64,
    pub text: String,
}

/// Ships on every page assembled after the `Terminal` frame ARRIVES (a settlement
/// watermark decoupled from the release frontier — §2.4 pin xi).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LlmDeltaTerminal {
    pub seq: u64,
    pub reason: String,
    pub usage: Option<LlmDeltaUsage>,
}

/// Wire usage. A non-finite `cost_usd` serializes as `Some` with `0.0` (+ observer
/// [`HubEvent::NonFiniteCost`]) — never flips `usage` to `None`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LlmDeltaUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

/// Plain (unsealed) cursor DTO; the sealed form rides [`seal_delta_cursor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LlmDeltaCursor {
    pub stream_key: String,
    pub from_cursor: u64,
}

/// The WIRE form of a delta page (what the WS pump sends): identical to [`LlmDeltaPage`]
/// except `cursor` carries the AEAD-SEALED reconnect token (`SealPurpose::DeltaCursor`,
/// minted at the last included item's boundary — pin ix: cursors mint ONLY at wire-item
/// boundaries) instead of the plain DTO. `None` when no item shipped or when no cursor
/// codec is wired (fail closed: page without a resume token, never a plain cursor).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LlmDeltaWirePage {
    pub stream_key: String,
    pub agent_id: String,
    pub run_id: Option<String>,
    pub from_seq: u64,
    pub to_seq: u64,
    pub deltas: Vec<LlmDeltaItem>,
    pub dropped_count: u32,
    pub rejected_count: u32,
    pub redacted_count: u32,
    pub warned_count: u32,
    pub page_limit_reached: bool,
    pub absent: bool,
    pub cursor: Option<String>,
    pub terminal: Option<LlmDeltaTerminal>,
}

impl LlmDeltaWirePage {
    /// Convert a hub page to the wire form, sealing the item-boundary cursor. A seal failure
    /// (or an absent codec) drops the cursor, never the page.
    pub fn seal_from(page: LlmDeltaPage, codec: Option<&dyn ClientCursorCodec>) -> Self {
        let cursor = page.cursor.as_ref().and_then(|c| {
            codec.and_then(|codec| seal_delta_cursor(codec, &c.stream_key, c.from_cursor).ok())
        });
        Self {
            stream_key: page.stream_key,
            agent_id: page.agent_id,
            run_id: page.run_id,
            from_seq: page.from_seq,
            to_seq: page.to_seq,
            deltas: page.deltas,
            dropped_count: page.dropped_count,
            rejected_count: page.rejected_count,
            redacted_count: page.redacted_count,
            warned_count: page.warned_count,
            page_limit_reached: page.page_limit_reached,
            absent: page.absent,
            cursor,
            terminal: page.terminal,
        }
    }
}

/// Inbound WS Text-frame request selecting/resuming a delta stream. Stream selection rides
/// ONLY this frame — never the upgrade query string. `from_cursor` is the sealed token from a
/// prior page; its sealed body carries BOTH `{stream_key, seq}` (both-or-neither) and the
/// decoded `stream_key` must equal the presented plaintext one.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LlmDeltaStreamRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Timing (test-overridable behind `test-support`)
// ─────────────────────────────────────────────────────────────────────────

/// Effective hub/pump timing. Defaults are the §2.11 constants above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaTiming {
    pub cadence: Duration,
    pub reauth_max_age: Duration,
    pub allowance: Duration,
    pub linger: Duration,
}

impl Default for DeltaTiming {
    fn default() -> Self {
        Self {
            cadence: DELTA_PUMP_CADENCE,
            reauth_max_age: DELTA_PUMP_REAUTH_MAX_AGE,
            allowance: DELTA_PUMP_ALLOWANCE,
            linger: DELTA_TERMINAL_LINGER,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Re-auth deadline anchor (U-14): pure state machine the slice-2 pump drives.
// ─────────────────────────────────────────────────────────────────────────

/// Start-anchored revocation-cut deadline (§2.4, corrected 2026-08-05): the anchor is the
/// BEAT-START timestamp of the last SUCCESSFUL full-`handle()` re-auth (completion-anchoring
/// would add the check's own latency and lose the ≤15 s bound). The subscribe-time seed
/// `handle()` pass is the INITIAL anchor, so the deadline is well-defined before any beat
/// completes. A failed or saturated beat never refreshes the anchor (saturation fails CLOSED).
///
/// Unit-agnostic: the anchor and window are an abstract monotonic `u64` tick count. THIS is the
/// production revocation-cut state machine — the tee-T2 pump ([`crate::transport`]) drives it in
/// nanosecond ticks (mapping to/from `tokio::time::Instant` at the `sleep_until` boundary only),
/// and U-14 witnesses the exact same [`seed`](Self::seed) /
/// [`record_success_start`](Self::record_success_start) / [`must_cut`](Self::must_cut) /
/// [`deadline`](Self::deadline) methods in millisecond ticks. There is no parallel inline copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReauthDeadline {
    anchor_start: u64,
    max_age: u64,
}

impl ReauthDeadline {
    /// Seed with the subscribe-time `handle()` pass start tick and the deadline window.
    pub fn seed(seed_beat_start: u64, max_age: u64) -> Self {
        Self {
            anchor_start: seed_beat_start,
            max_age,
        }
    }

    /// Record a SUCCESSFUL re-auth by its beat-START tick. Monotonic (an out-of-order older
    /// success never regresses the anchor).
    pub fn record_success_start(&mut self, beat_start: u64) {
        self.anchor_start = self.anchor_start.max(beat_start);
    }

    /// True when the pump must cut: the last successful re-auth's START is older than the
    /// deadline window. Fires on or off the beat grid.
    pub fn must_cut(&self, now: u64) -> bool {
        now.saturating_sub(self.anchor_start) > self.max_age
    }

    /// The cut tick (anchor + window). The pump maps this to a `tokio::time::Instant` for its
    /// unconditional `sleep_until`; U-14 asserts it directly.
    pub fn deadline(&self) -> u64 {
        self.anchor_start.saturating_add(self.max_age)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Coalesced seq-range structures
// ─────────────────────────────────────────────────────────────────────────

/// Sorted, disjoint, non-adjacent inclusive seq ranges.
#[derive(Debug, Default, Clone)]
struct SeqRanges {
    ranges: Vec<(u64, u64)>,
}

impl SeqRanges {
    fn contains(&self, seq: u64) -> bool {
        let idx = self.ranges.partition_point(|&(lo, _)| lo <= seq);
        idx > 0 && self.ranges[idx - 1].1 >= seq
    }

    /// Would inserting `seq` create a NEW disjoint range (not inside, not adjacent)?
    fn is_new_range(&self, seq: u64) -> bool {
        if self.contains(seq) {
            return false;
        }
        let idx = self.ranges.partition_point(|&(lo, _)| lo <= seq);
        let touches_prev = idx > 0 && self.ranges[idx - 1].1.saturating_add(1) == seq;
        let touches_next = idx < self.ranges.len() && seq.saturating_add(1) == self.ranges[idx].0;
        !(touches_prev || touches_next)
    }

    fn insert(&mut self, seq: u64) {
        self.insert_span(seq, seq);
    }

    fn insert_span(&mut self, lo: u64, hi: u64) {
        debug_assert!(lo <= hi);
        let (mut new_lo, mut new_hi) = (lo, hi);
        let start = self
            .ranges
            .partition_point(|&(_, rhi)| rhi.saturating_add(1) < lo);
        let mut end = start;
        while end < self.ranges.len() && self.ranges[end].0 <= hi.saturating_add(1) {
            new_lo = new_lo.min(self.ranges[end].0);
            new_hi = new_hi.max(self.ranges[end].1);
            end += 1;
        }
        self.ranges
            .splice(start..end, std::iter::once((new_lo, new_hi)));
    }

    fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Total seqs recorded at/above `from` (for page counter derivation).
    fn count_at_or_above(&self, from: u64) -> u64 {
        let mut total: u64 = 0;
        for &(lo, hi) in &self.ranges {
            if hi < from {
                continue;
            }
            let eff_lo = lo.max(from);
            total = total.saturating_add(hi - eff_lo + 1);
        }
        total
    }
}

/// Capped coalesced ranges; on overflow the two closest ranges MERGE — derived counts may
/// then OVER-report (the pinned direction) but never under-report.
#[derive(Debug, Default, Clone)]
struct BoundedRanges {
    inner: SeqRanges,
}

impl BoundedRanges {
    fn record_span(&mut self, lo: u64, hi: u64) {
        self.inner.insert_span(lo, hi);
        while self.inner.ranges.len() > DELTA_DROPPED_RANGES_CAP {
            let mut best = 0usize;
            let mut best_gap = u64::MAX;
            for i in 0..self.inner.ranges.len() - 1 {
                let gap = self.inner.ranges[i + 1].0 - self.inner.ranges[i].1;
                if gap < best_gap {
                    best_gap = gap;
                    best = i;
                }
            }
            let merged = (self.inner.ranges[best].0, self.inner.ranges[best + 1].1);
            self.inner
                .ranges
                .splice(best..best + 2, std::iter::once(merged));
        }
    }

    fn count_at_or_above(&self, from: u64) -> u64 {
        self.inner.count_at_or_above(from)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Entry state
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct PendingFrame {
    seq: u64,
    text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemKind {
    Verbatim,
    Warned,
    Redacted,
    Blocked,
}

#[derive(Debug)]
struct ReleasedItem {
    from_seq: u64,
    to_seq: u64,
    /// Actual seen seqs in the span (contiguous runs ⇒ exact).
    seq_count: u64,
    kind: ItemKind,
    text: String,
}

#[derive(Debug)]
struct EntryState {
    run_id: Option<String>,
    /// Seq-ordered pending frames (the natural per-frame `(seq, len)` queue, pin ix).
    pending: Vec<PendingFrame>,
    pending_bytes: usize,
    /// Live-hold boundary: pending frames with `seq <= hold_end_seq` are the retained hold
    /// from the previous scan step (they re-enter the next scan input).
    hold_end_seq: Option<u64>,
    /// Release-frontier floor in seq space: seqs below it are below-floor.
    floor: u64,
    /// Coalesced ranges of actually-PUBLISHED seqs (exact de-dup; shared 1024-gap budget).
    seen: SeqRanges,
    dropped: BoundedRanges,
    /// Seq spans of released items evicted from the window head (replay floor risen).
    evicted: BoundedRanges,
    /// The immutable shared release history (every subscriber sees identical bytes).
    released: VecDeque<ReleasedItem>,
    released_bytes: usize,
    terminal: Option<LlmDeltaTerminal>,
    linger_deadline_ms: Option<u64>,
}

impl EntryState {
    fn new(run_id: Option<String>) -> Self {
        Self {
            run_id,
            pending: Vec::new(),
            pending_bytes: 0,
            hold_end_seq: None,
            floor: 0,
            seen: SeqRanges::default(),
            dropped: BoundedRanges::default(),
            evicted: BoundedRanges::default(),
            released: VecDeque::new(),
            released_bytes: 0,
            terminal: None,
            linger_deadline_ms: None,
        }
    }

    fn record_drop(&mut self, seq: u64) {
        self.dropped.record_span(seq, seq);
    }

    /// Enforce window/count bounds by consuming the RELEASED head only (pin iii: the window
    /// never evicts unreleased bytes). Evicted spans join the evicted ranges.
    fn evict_released_head_to_fit(&mut self) {
        while (self.released_bytes + self.pending_bytes > DELTA_WINDOW_BYTES
            || self.released.len() > DELTA_RELEASED_ITEMS_CAP)
            && !self.released.is_empty()
        {
            if let Some(item) = self.released.pop_front() {
                self.released_bytes -= item.text.len();
                self.evicted.record_span(item.from_seq, item.to_seq);
            }
        }
    }

    fn hold_frame_count(&self) -> usize {
        match self.hold_end_seq {
            Some(h) => self.pending.partition_point(|f| f.seq <= h),
            None => 0,
        }
    }
}

struct StreamEntry {
    agent_id: Arc<str>,
    /// First-`Terminal` latch (absorbs ONLY a second `Terminal`, never deltas). Atomic so the
    /// registry-lock path never needs the entry lock (one hub lock at a time).
    terminal_latched: AtomicBool,
    /// Per-entry single-advancer claim token (pin iv): lock-free CAS + RAII clear.
    claim: AtomicBool,
    state: Mutex<EntryState>,
}

/// RAII advancer-claim guard: drop clears the ATOMIC only — it never retakes the entry lock,
/// so an unwind through a panicking detector cannot wedge the claim (pin iv).
struct ClaimGuard<'a> {
    claim: &'a AtomicBool,
}

impl Drop for ClaimGuard<'_> {
    fn drop(&mut self) {
        self.claim.store(false, Ordering::Release);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Registry
// ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Registry {
    map: HashMap<Arc<str>, Arc<StreamEntry>>,
    admitted_global: usize,
    admitted_per_agent: HashMap<Arc<str>, usize>,
    /// Terminated-but-replayable entries, oldest first (cap 64; overflow displaces oldest).
    lingering: VecDeque<Arc<str>>,
}

/// RAII subscriber permit (cap 4). Released on ANY drop path, including panic unwinds.
pub struct DeltaSubscriberPermit {
    _permit: OwnedSemaphorePermit,
}

impl std::fmt::Debug for DeltaSubscriberPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeltaSubscriberPermit").finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The hub
// ─────────────────────────────────────────────────────────────────────────

/// CONTRACT-235 `LlmDeltaHub`: in-memory only, no background tasks, no timers. Entry
/// lifecycle Live → Terminal-arrived → lingering → absent (lazy linger eviction on read, or
/// lingering-cap displacement). Absent detector OR hold closure ⇒ releases nothing and
/// refuses subscriptions (fail closed).
pub struct LlmDeltaHub {
    detector: Option<Arc<dyn LeakDetector>>,
    hold_split: Option<DeltaHoldSplit>,
    clock: Arc<dyn Clock>,
    observer: Option<DeltaObserver>,
    timing: DeltaTiming,
    registry: Mutex<Registry>,
    generation_tx: watch::Sender<u64>,
    generation_rx: watch::Receiver<u64>,
    subscribers: Arc<Semaphore>,
    #[cfg(feature = "test-support")]
    registry_acquisitions: std::sync::atomic::AtomicU64,
}

enum Disposition {
    /// Clean/Warned: release input frames wholly below `ceiling` (rounded OUTWARD to frame
    /// boundaries); the rest is retained as the live hold.
    Release { ceiling: usize, warned: bool },
    /// Redacted: the WHOLE input collapses; one synthetic item per contiguous seen run.
    Collapse { replacement: String },
    /// Blocked (incl. `scan_overflow`, facade `Err`, hold-cap overflow): drop the span
    /// fail-closed, count it, advance the frontier — never a stall.
    Blocked,
}

enum StepResult {
    /// Released or advanced (a release-commit) — bump the generation watch.
    Committed,
    /// The whole candidate joined the hold; nothing released. Keep stepping.
    HeldAll,
    /// No step possible (no pending beyond the hold).
    Idle,
}

impl LlmDeltaHub {
    /// Construct the hub. `detector`/`hold_split` are CONSTRUCTION dependencies (§2.4): a hub
    /// composed without either releases nothing and [`Self::subscribe`] refuses. Absent
    /// `observer` ⇒ no-op.
    pub fn new(
        detector: Option<Arc<dyn LeakDetector>>,
        hold_split: Option<DeltaHoldSplit>,
        clock: Arc<dyn Clock>,
        observer: Option<DeltaObserver>,
    ) -> Self {
        Self::build(
            detector,
            hold_split,
            clock,
            observer,
            DeltaTiming::default(),
        )
    }

    /// Timing-override ctor (witnesses drive linger/cadence without wall-clock sleeps).
    #[cfg(feature = "test-support")]
    pub fn with_timing(
        detector: Option<Arc<dyn LeakDetector>>,
        hold_split: Option<DeltaHoldSplit>,
        clock: Arc<dyn Clock>,
        observer: Option<DeltaObserver>,
        timing: DeltaTiming,
    ) -> Self {
        Self::build(detector, hold_split, clock, observer, timing)
    }

    /// U-17 leg (ii): the effective timing (default ctor ⇒ the §2.11 constants).
    #[cfg(feature = "test-support")]
    pub fn effective_timing(&self) -> DeltaTiming {
        self.timing
    }

    /// Crate-internal timing read (the WS pump derives its cadence/deadline/linger from the
    /// hub's effective timing — production = the §2.11 constants; tests override behind
    /// `test-support` only).
    pub(crate) fn timing(&self) -> DeltaTiming {
        self.timing
    }

    /// Registry-acquisition counter (U-7 witness).
    #[cfg(feature = "test-support")]
    pub fn registry_acquisition_count(&self) -> u64 {
        self.registry_acquisitions.load(Ordering::Relaxed)
    }

    fn build(
        detector: Option<Arc<dyn LeakDetector>>,
        hold_split: Option<DeltaHoldSplit>,
        clock: Arc<dyn Clock>,
        observer: Option<DeltaObserver>,
        timing: DeltaTiming,
    ) -> Self {
        let (generation_tx, generation_rx) = watch::channel(0u64);
        Self {
            detector,
            hold_split,
            clock,
            observer,
            timing,
            registry: Mutex::new(Registry::default()),
            generation_tx,
            generation_rx,
            subscribers: Arc::new(Semaphore::new(DELTA_SUBSCRIBER_CAP)),
            #[cfg(feature = "test-support")]
            registry_acquisitions: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The ONE registry-map acquisition helper (pin C-10: `publish` performs exactly one).
    fn registry(&self) -> MutexGuard<'_, Registry> {
        #[cfg(feature = "test-support")]
        self.registry_acquisitions.fetch_add(1, Ordering::Relaxed);
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn observe(&self, event: HubEvent) {
        if let Some(obs) = &self.observer {
            obs(event);
        }
    }

    fn bump_generation(&self) {
        self.generation_tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Watch receiver: bumped by every accepted publish AND every release-commit (pin v).
    pub fn generation_watch(&self) -> watch::Receiver<u64> {
        self.generation_rx.clone()
    }

    /// Acquire a subscriber slot (cap 4, RAII). Fails closed with `module_unavailable` when
    /// the hub lacks its egress detector or hold-geometry closure; overflow maps to the
    /// EXISTING `stream_backpressure` (→ 429 at the transport, no new error code).
    pub fn subscribe(&self) -> Result<DeltaSubscriberPermit, ClientError> {
        if self.detector.is_none() || self.hold_split.is_none() {
            return Err(ClientError::new(
                ClientErrorCode::ModuleUnavailable,
                "llm delta subscription unavailable",
            ));
        }
        match Arc::clone(&self.subscribers).try_acquire_owned() {
            Ok(permit) => Ok(DeltaSubscriberPermit { _permit: permit }),
            Err(_) => Err(ClientError::new(
                ClientErrorCode::StreamBackpressure,
                "llm delta subscriber cap reached",
            )),
        }
    }

    // ── publish legs (hot path: no await, no I/O, bounded work, one registry acquisition,
    //    never two hub locks at once; `catch_unwind` is the PRODUCER's job) ──────────────

    fn publish_begin(&self, agent_id: Arc<str>, stream_key: Arc<str>, run_id: Option<String>) {
        let admitted = {
            let mut reg = self.registry();
            if reg.map.contains_key(&stream_key) {
                // Duplicate Begin (producer-contract violation, CONTRACT-234 invariant 6):
                // dropped at membership — no upsert, no state disturbance.
                false
            } else if reg.admitted_global >= DELTA_GLOBAL_STREAM_CAP
                || reg.admitted_per_agent.get(&agent_id).copied().unwrap_or(0)
                    >= DELTA_PER_AGENT_STREAM_CAP
            {
                // Over-cap Begin refused: NO entry, NO memory — the refused key reads absent
                // and its later frames drop at the membership check (§2.4 pin xii).
                false
            } else {
                let entry = Arc::new(StreamEntry {
                    agent_id: Arc::clone(&agent_id),
                    terminal_latched: AtomicBool::new(false),
                    claim: AtomicBool::new(false),
                    state: Mutex::new(EntryState::new(run_id)),
                });
                reg.admitted_global += 1;
                *reg.admitted_per_agent
                    .entry(Arc::clone(&agent_id))
                    .or_insert(0) += 1;
                reg.map.insert(stream_key, entry);
                true
            }
        };
        if admitted {
            self.bump_generation();
        } else {
            self.observe(HubEvent::RefusedStreamDiscard);
        }
    }

    fn publish_delta(&self, stream_key: &str, seq: u64, text: String) {
        let entry = {
            let reg = self.registry();
            reg.map.get(stream_key).cloned()
        };
        let Some(entry) = entry else {
            // Unknown/refused/evicted key: dropped, no entry ever created (no-upsert).
            self.observe(HubEvent::RefusedStreamDiscard);
            return;
        };
        let accepted = {
            let mut st = entry.state.lock().unwrap_or_else(|e| e.into_inner());
            // Admission is NOT pre-judged against any in-flight scan snapshot span: the snapshot
            // is a READ concern, never an admission gate. A concurrent scan holds only the atomic
            // advancer claim and the entry lock is free while it scans, so an in-bounds
            // out-of-order gap-fill that arrives mid-scan is buffered here by the normal
            // window/dedup/discontinuity/below-floor rules below. The frontier advance then
            // decides release vs retain: a truly-below-floor seq is caught by the `seq < floor`
            // split; a seq that stays PENDING above the post-commit floor (including every
            // `HeldAll` case) is retained and picked up by a later scan step. A mid-span insert
            // that mutates the snapshot prefix is caught by `commit_step`'s defensive bail, which
            // re-snapshots on the next step — never a manufactured drop for an in-bounds stream.
            if st.seen.contains(seq) {
                // Exact de-dup on (stream_key, seq) — incl. the below-floor in-seen drain
                // (invariant 4's re-drain case): ignored, NOT counted.
                return;
            }
            if seq < st.floor {
                // First-time content the window can no longer serve: dropped AND counted.
                st.record_drop(seq);
                return;
            }
            if st.seen.is_new_range(seq) && st.seen.range_count() > DELTA_MAX_DISCONTINUITIES {
                // Would create the 1025th discontinuity (shared seen/storage budget).
                st.record_drop(seq);
                return;
            }
            if st.pending_bytes + text.len() > DELTA_WINDOW_BYTES {
                // Pending-full (pin iii): `Delta` drops with its seq recorded; the window
                // never evicts UNRELEASED bytes to make room. Begin/Terminal are exempt.
                st.record_drop(seq);
                return;
            }
            let pos = st.pending.partition_point(|f| f.seq < seq);
            st.pending_bytes += text.len();
            st.pending.insert(pos, PendingFrame { seq, text });
            st.seen.insert(seq);
            st.evict_released_head_to_fit();
            true
        };
        if accepted {
            self.bump_generation();
        }
    }

    fn publish_terminal(
        &self,
        stream_key: &str,
        seq: u64,
        reason: LlmTerminalReason,
        usage: Option<advance_shared_types::traits::LlmDeltaUsage>,
    ) {
        enum TerminalPath {
            Unknown,
            Absorbed,
            First(Arc<StreamEntry>, Option<Arc<StreamEntry>>),
        }
        let path = {
            let mut reg = self.registry();
            match reg.map.get(stream_key).cloned() {
                None => TerminalPath::Unknown,
                Some(entry) => {
                    if entry.terminal_latched.swap(true, Ordering::AcqRel) {
                        // Terminal absorbs ONLY a second Terminal: no transition, no
                        // displacement, nothing else.
                        TerminalPath::Absorbed
                    } else {
                        // First Terminal on an ADMITTED entry: frees the admission slot and
                        // transitions the entry to lingering. Only THIS transition may
                        // displace the oldest lingering entry (§2.4 round 6).
                        reg.admitted_global = reg.admitted_global.saturating_sub(1);
                        let remove_agent = match reg.admitted_per_agent.get_mut(&entry.agent_id) {
                            Some(c) => {
                                *c = c.saturating_sub(1);
                                *c == 0
                            }
                            None => false,
                        };
                        if remove_agent {
                            reg.admitted_per_agent.remove(&entry.agent_id);
                        }
                        let displaced = if reg.lingering.len() >= DELTA_LINGERING_CAP {
                            reg.lingering
                                .pop_front()
                                .and_then(|oldest| reg.map.remove(&oldest))
                        } else {
                            None
                        };
                        // Re-key from the map so the lingering list owns the map's Arc key.
                        let key_arc: Arc<str> = reg
                            .map
                            .get_key_value(stream_key)
                            .map(|(k, _)| Arc::clone(k))
                            .unwrap_or_else(|| Arc::from(stream_key));
                        reg.lingering.push_back(key_arc);
                        TerminalPath::First(entry, displaced)
                    }
                }
            }
        };
        match path {
            TerminalPath::Unknown => {
                // A refused/unknown key's Terminal was already dropped at the membership
                // check — it displaces nothing.
                self.observe(HubEvent::RefusedStreamDiscard);
            }
            TerminalPath::Absorbed => {}
            TerminalPath::First(entry, displaced) => {
                if let Some(d) = displaced {
                    self.finalize_evicted_entry(&d);
                }
                let now = self.clock.now_millis();
                let mut non_finite = false;
                {
                    let mut st = entry.state.lock().unwrap_or_else(|e| e.into_inner());
                    let usage_dto = usage.map(|u| {
                        let cost = if u.cost_usd.is_finite() {
                            u.cost_usd
                        } else {
                            non_finite = true;
                            0.0
                        };
                        LlmDeltaUsage {
                            input_tokens: u.input_tokens,
                            output_tokens: u.output_tokens,
                            cost_usd: cost,
                        }
                    });
                    st.terminal = Some(LlmDeltaTerminal {
                        seq,
                        reason: terminal_reason_str(reason).to_string(),
                        usage: usage_dto,
                    });
                    st.linger_deadline_ms =
                        Some(now.saturating_add(self.timing.linger.as_millis() as u64));
                }
                if non_finite {
                    self.observe(HubEvent::NonFiniteCost);
                }
                self.bump_generation();
            }
        }
    }

    /// Final-eviction bookkeeping (lingering-cap displacement or lazy linger eviction):
    /// residual unreleased content drops fail-closed, witnessed via the observer seam.
    fn finalize_evicted_entry(&self, entry: &Arc<StreamEntry>) {
        let (residual_hold, unread_pending) = {
            let mut st = entry.state.lock().unwrap_or_else(|e| e.into_inner());
            let hold_frames = st.hold_frame_count();
            let hold_bytes: usize = st.pending[..hold_frames].iter().map(|f| f.text.len()).sum();
            let beyond_hold = st.pending.len() > hold_frames;
            st.pending.clear();
            st.pending_bytes = 0;
            st.hold_end_seq = None;
            (hold_bytes > 0, beyond_hold)
        };
        if residual_hold {
            self.observe(HubEvent::ResidualHoldDropped);
        }
        if unread_pending {
            self.observe(HubEvent::EvictedUnreadPending);
        }
    }

    // ── egress scan / release frontier (on-demand at read time; never inside publish) ────

    fn run_scan_steps(&self, entry: &Arc<StreamEntry>) {
        let (Some(detector), Some(hold_split)) = (&self.detector, &self.hold_split) else {
            // Fail closed: a hub without its detector or hold geometry releases nothing.
            return;
        };
        // Per-entry single-advancer claim (pin iv): lock-free CAS; RAII clear on any exit,
        // including a detector panic unwinding through this frame.
        if entry
            .claim
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let _guard = ClaimGuard {
            claim: &entry.claim,
        };
        // Hard safety bound; the loop terminates naturally (every step consumes candidate
        // frames into released/advanced/hold, and the hold is capped).
        for _ in 0..4096 {
            // Snapshot under the entry lock; scan OUTSIDE it. Read-only now (the scan span is no
            // longer recorded as an admission gate), so an immutable guard suffices.
            let snapshot = {
                let st = entry.state.lock().unwrap_or_else(|e| e.into_inner());
                let hold_count = st.hold_frame_count();
                let mut cand_count = 0usize;
                let mut cand_bytes = 0usize;
                for f in st.pending[hold_count..].iter() {
                    if cand_count == 0 && f.text.len() > DELTA_SCAN_STEP_BYTES {
                        // One larger frame alone (entry-aligned step).
                        cand_count = 1;
                        break;
                    }
                    if cand_bytes + f.text.len() > DELTA_SCAN_STEP_BYTES {
                        break;
                    }
                    cand_bytes += f.text.len();
                    cand_count += 1;
                }
                if cand_count == 0 {
                    None
                } else {
                    let total = hold_count + cand_count;
                    let mut input = String::new();
                    let mut frames: Vec<(u64, usize)> = Vec::with_capacity(total);
                    for f in st.pending[..total].iter() {
                        input.push_str(&f.text);
                        frames.push((f.seq, f.text.len()));
                    }
                    let span = (frames[0].0, frames[total - 1].0);
                    Some((input, frames, span))
                }
            };
            let Some((input, frames, span)) = snapshot else {
                break;
            };
            // Scan + hold geometry, outside every entry lock, serialized by the claim.
            let verdict = detector.scan(&input, ScanContext::LogOutput);
            let disposition = match verdict {
                ScanResult::Clean | ScanResult::Warned { .. } => {
                    let warned = matches!(verdict, ScanResult::Warned { .. });
                    match hold_split(input.as_bytes(), DELTA_MAX_CANONICAL_BYTES) {
                        Err(()) => Disposition::Blocked,
                        Ok(split) => {
                            let hold = input.len().saturating_sub(split.min(input.len()));
                            if hold >= DELTA_MAX_HOLD_BYTES {
                                // Hold-cap overflow (pin xiii): closed with progress.
                                Disposition::Blocked
                            } else {
                                Disposition::Release {
                                    ceiling: input.len() - hold,
                                    warned,
                                }
                            }
                        }
                    }
                }
                ScanResult::Redacted { redacted, .. } => {
                    if redacted.len() > input.len() {
                        // Replacement-expansion guard (round 5): degrade to Block.
                        Disposition::Blocked
                    } else {
                        Disposition::Collapse {
                            replacement: redacted,
                        }
                    }
                }
                ScanResult::Blocked { .. } => Disposition::Blocked,
            };
            let result = {
                let mut st = entry.state.lock().unwrap_or_else(|e| e.into_inner());
                commit_step(&mut st, &frames, disposition, span)
            };
            match result {
                StepResult::Committed => {
                    // A release-commit bumps the same generation watch a publish bumps (pin v).
                    self.bump_generation();
                }
                StepResult::HeldAll => {}
                StepResult::Idle => break,
            }
        }
    }

    // ── release-gated reads ──────────────────────────────────────────────────────────────

    /// Read a page of RELEASED items at/after `from_seq` (≤64 KiB multi-item, with the
    /// single-indivisible-item exception). Unknown/refused/evicted keys read
    /// `absent: true`; a live-but-quiet admitted stream reads `absent: false` empty. A read
    /// of a linger-expired entry lazily evicts it, then answers absent.
    pub fn read_page(&self, stream_key: &str, from_seq: u64) -> LlmDeltaPage {
        let entry = {
            let reg = self.registry();
            reg.map.get(stream_key).cloned()
        };
        let Some(entry) = entry else {
            return absent_page(stream_key, from_seq);
        };
        // Lazy linger eviction (Clock-injected; post-terminal publishes never re-armed it).
        let now = self.clock.now_millis();
        let expired = {
            let st = entry.state.lock().unwrap_or_else(|e| e.into_inner());
            matches!(st.linger_deadline_ms, Some(d) if now >= d)
        };
        if expired {
            let removed = {
                let mut reg = self.registry();
                match reg.map.get(stream_key) {
                    Some(e) if Arc::ptr_eq(e, &entry) => {
                        let e = reg.map.remove(stream_key);
                        reg.lingering.retain(|k| &**k != stream_key);
                        e
                    }
                    _ => None,
                }
            };
            if let Some(e) = removed {
                self.finalize_evicted_entry(&e);
            }
            return absent_page(stream_key, from_seq);
        }
        // On-demand scan steps (never inside publish, never under the entry lock).
        self.run_scan_steps(&entry);
        // Assemble from the immutable released history (structurally release-gated; the
        // ≤64-KiB copy happens under the per-stream lock).
        let st = entry.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut deltas: Vec<LlmDeltaItem> = Vec::new();
        let mut bytes = 0usize;
        let mut included = 0usize;
        let mut matching_total = 0usize;
        let mut rejected: u64 = 0;
        let mut redacted: u64 = 0;
        let mut warned: u64 = 0;
        for item in st.released.iter().filter(|i| i.to_seq >= from_seq) {
            matching_total += 1;
            if included < matching_total - 1 {
                // Already stopped including; keep counting the remainder for the flag.
                continue;
            }
            let len = item.text.len();
            if included > 0 && bytes + len > DELTA_PAGE_MAX_BYTES {
                continue; // page full; remaining matches only feed `page_limit_reached`
            }
            if included == 0 || bytes + len <= DELTA_PAGE_MAX_BYTES {
                bytes += len;
                match item.kind {
                    ItemKind::Verbatim => {}
                    ItemKind::Warned => warned = warned.saturating_add(item.seq_count),
                    ItemKind::Redacted => redacted = redacted.saturating_add(item.seq_count),
                    ItemKind::Blocked => rejected = rejected.saturating_add(item.seq_count),
                }
                deltas.push(LlmDeltaItem {
                    from_seq: item.from_seq,
                    to_seq: item.to_seq,
                    text: item.text.clone(),
                });
                included += 1;
            }
        }
        let page_limit_reached = included < matching_total;
        let dropped = st
            .dropped
            .count_at_or_above(from_seq)
            .saturating_add(st.evicted.count_at_or_above(from_seq));
        let to_seq = deltas.last().map(|i| i.to_seq).unwrap_or(from_seq);
        let cursor = deltas.last().map(|i| LlmDeltaCursor {
            stream_key: stream_key.to_string(),
            from_cursor: i.to_seq,
        });
        LlmDeltaPage {
            stream_key: stream_key.to_string(),
            agent_id: entry.agent_id.to_string(),
            run_id: st.run_id.clone(),
            from_seq,
            to_seq,
            deltas,
            dropped_count: saturating_u32(dropped),
            rejected_count: saturating_u32(rejected),
            redacted_count: saturating_u32(redacted),
            warned_count: saturating_u32(warned),
            page_limit_reached,
            absent: false,
            cursor,
            terminal: st.terminal.clone(),
        }
    }
}

impl LlmDeltaSink for LlmDeltaHub {
    fn publish(&self, event: LlmDeltaEvent) {
        match event.frame {
            // `task_id` is guest-influenced and untrusted (CONTRACT-234): the hub neither
            // stores nor surfaces it.
            LlmDeltaFrame::Begin { run_id, task_id: _ } => {
                self.publish_begin(event.agent_id, event.stream_key, run_id)
            }
            LlmDeltaFrame::Delta { seq, text } => self.publish_delta(&event.stream_key, seq, text),
            LlmDeltaFrame::Terminal { seq, reason, usage } => {
                self.publish_terminal(&event.stream_key, seq, reason, usage)
            }
        }
    }

    /// Constant for the hub's lifetime (invariant 3b) and trivially panic-free
    /// (invariant 3): "nobody is listening" is modeled inside `publish`, never here.
    fn is_wired(&self) -> bool {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Step commit (under the entry lock, claim held)
// ─────────────────────────────────────────────────────────────────────────

fn commit_step(
    st: &mut EntryState,
    frames: &[(u64, usize)],
    disposition: Disposition,
    span: (u64, u64),
) -> StepResult {
    // The snapshot must still be the pending prefix. A mid-span publish now BUFFERS into pending
    // (there is no scan-span admission guard), so an in-bounds out-of-order gap-fill can mutate
    // this prefix; the check below then bails without consuming and the next scan step
    // re-snapshots the (now longer) prefix — so the gap-fill is released in order, never dropped.
    if st.pending.len() < frames.len()
        || !st
            .pending
            .iter()
            .zip(frames.iter())
            .all(|(p, (seq, _))| p.seq == *seq)
    {
        return StepResult::Idle;
    }
    match disposition {
        Disposition::Release { ceiling, warned } => {
            // Frames wholly below the ceiling release; the retained region rounds OUTWARD
            // to frame boundaries (a frame not wholly inside is retained whole).
            let mut cum = 0usize;
            let mut release_count = 0usize;
            for (_, len) in frames {
                if cum + len <= ceiling {
                    cum += len;
                    release_count += 1;
                } else {
                    break;
                }
            }
            if release_count == 0 {
                // Whole input became the live hold. THE VIABLE TAIL IS NEVER RELEASED —
                // terminal and post-terminal steps are ordinary steps.
                st.hold_end_seq = Some(span.1);
                return StepResult::HeldAll;
            }
            let kind = if warned {
                ItemKind::Warned
            } else {
                ItemKind::Verbatim
            };
            let drained: Vec<PendingFrame> = st.pending.drain(..release_count).collect();
            for frame in drained {
                st.pending_bytes -= frame.text.len();
                st.released_bytes += frame.text.len();
                st.released.push_back(ReleasedItem {
                    from_seq: frame.seq,
                    to_seq: frame.seq,
                    seq_count: 1,
                    kind,
                    text: frame.text,
                });
            }
            let retained = frames.len() - release_count;
            if retained > 0 {
                st.hold_end_seq = Some(span.1);
                st.floor = frames[release_count].0;
            } else {
                st.hold_end_seq = None;
                st.floor = span.1.saturating_add(1);
            }
            st.evict_released_head_to_fit();
            StepResult::Committed
        }
        Disposition::Collapse { replacement } => {
            commit_consume_all(st, frames, span, ItemKind::Redacted, replacement);
            StepResult::Committed
        }
        Disposition::Blocked => {
            commit_consume_all(st, frames, span, ItemKind::Blocked, String::new());
            StepResult::Committed
        }
    }
}

/// Consume the WHOLE input span, minting ONE synthetic seq-range item per CONTIGUOUS seen
/// run (never papering over an unseen gap). For `Redacted` the FIRST run carries the
/// detector's whole replacement (offset splicing is forbidden — a replacement applies to a
/// whole scan input or not at all); subsequent runs carry empty text. `Blocked` runs are
/// empty. The frontier advances past the input either way.
fn commit_consume_all(
    st: &mut EntryState,
    frames: &[(u64, usize)],
    span: (u64, u64),
    kind: ItemKind,
    replacement: String,
) {
    let total = frames.len();
    let mut runs: Vec<(u64, u64, u64)> = Vec::new(); // (from, to, seq_count)
    for (seq, _) in frames {
        match runs.last_mut() {
            Some((_, to, count)) if to.saturating_add(1) == *seq => {
                *to = *seq;
                *count += 1;
            }
            _ => runs.push((*seq, *seq, 1)),
        }
    }
    let drained: Vec<PendingFrame> = st.pending.drain(..total).collect();
    for frame in &drained {
        st.pending_bytes -= frame.text.len();
    }
    drop(drained);
    let mut replacement = Some(replacement);
    for (from, to, count) in runs {
        let text = replacement.take().unwrap_or_default();
        st.released_bytes += text.len();
        st.released.push_back(ReleasedItem {
            from_seq: from,
            to_seq: to,
            seq_count: count,
            kind,
            text,
        });
    }
    st.hold_end_seq = None;
    st.floor = span.1.saturating_add(1);
    st.evict_released_head_to_fit();
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

fn absent_page(stream_key: &str, from_seq: u64) -> LlmDeltaPage {
    LlmDeltaPage {
        stream_key: stream_key.to_string(),
        agent_id: String::new(),
        run_id: None,
        from_seq,
        to_seq: from_seq,
        deltas: Vec::new(),
        dropped_count: 0,
        rejected_count: 0,
        redacted_count: 0,
        warned_count: 0,
        page_limit_reached: false,
        absent: true,
        cursor: None,
        terminal: None,
    }
}

fn saturating_u32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

fn terminal_reason_str(reason: LlmTerminalReason) -> &'static str {
    match reason {
        LlmTerminalReason::Completed => "completed",
        LlmTerminalReason::Aborted => "aborted",
        LlmTerminalReason::BudgetExhausted => "budget_exhausted",
        LlmTerminalReason::ProviderError => "provider_error",
        LlmTerminalReason::Reaped => "reaped",
        LlmTerminalReason::Abandoned => "abandoned",
    }
}

/// Seal a delta reconnect cursor: the body carries BOTH `{stream_key, seq}` under the
/// independent `DeltaCursor` AAD domain (event↔delta tokens are mutually non-replayable).
/// No freshness policy beyond the codec's own retention horizon.
pub fn seal_delta_cursor(
    codec: &dyn ClientCursorCodec,
    stream_key: &str,
    seq: u64,
) -> Result<String, ClientError> {
    let body = encode_delta_cursor_body(stream_key, seq).ok_or_else(|| {
        ClientError::new(
            ClientErrorCode::ModuleUnavailable,
            "delta cursor unavailable",
        )
    })?;
    codec.seal(
        SealPurpose::DeltaCursor,
        DELTA_CURSOR_STREAM_DOMAIN,
        SEAL_TAG_DELTA_CURSOR,
        &body,
    )
}

/// Open a sealed delta cursor to its `(stream_key, seq)` pair (both-or-neither).
pub fn open_delta_cursor(
    codec: &dyn ClientCursorCodec,
    token: &str,
) -> Result<(String, u64), ClientError> {
    match codec.open(SealPurpose::DeltaCursor, DELTA_CURSOR_STREAM_DOMAIN, token)? {
        OpenedSeal::DeltaCursor { stream_key, seq } => Ok((stream_key, seq)),
        _ => Err(ClientError::new(
            ClientErrorCode::NotFound,
            "delta cursor not found",
        )),
    }
}

/// Resolve an inbound [`LlmDeltaStreamRequest`] to `(stream_key, from_seq)`.
///
/// Request shape (T24-d): `stream_key` alone = fresh subscribe from seq 0; `stream_key` +
/// `from_cursor` = resume AFTER the sealed cursor's seq; a cursor WITHOUT its plaintext
/// `stream_key` (or an empty frame) rejects — the pair is both-or-neither on the wire exactly
/// as it is inside the sealed body. The sealed body's `stream_key` is compared to the presented
/// plaintext one; a mismatch (incl. an event-domain or tampered token, which fails at `open`)
/// rejects with the codec's uniform `not_found`.
pub fn resolve_stream_request(
    codec: Option<&dyn ClientCursorCodec>,
    request: &LlmDeltaStreamRequest,
) -> Result<(String, u64), ClientError> {
    match (&request.stream_key, &request.from_cursor) {
        (None, None) => Err(ClientError::new(
            ClientErrorCode::InvalidState,
            "stream_key required",
        )),
        (None, Some(_)) => Err(ClientError::new(
            ClientErrorCode::InvalidState,
            "cursor without stream_key",
        )),
        (Some(key), None) => Ok((key.clone(), 0)),
        (Some(key), Some(token)) => {
            let codec = codec.ok_or_else(|| {
                ClientError::new(
                    ClientErrorCode::ModuleUnavailable,
                    "delta cursor unavailable",
                )
            })?;
            let (sealed_key, seq) = open_delta_cursor(codec, token)?;
            if sealed_key != *key {
                return Err(ClientError::new(
                    ClientErrorCode::NotFound,
                    "delta cursor not found",
                ));
            }
            // Resume AFTER the item boundary the cursor was minted at.
            Ok((key.clone(), seq.saturating_add(1)))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Pump exit reasons (transport observability) + the scope-gated subscribe handler
// ─────────────────────────────────────────────────────────────────────────

/// Why the WS delta pump ended. A small closed enum, observable for tests through the
/// `test-support` pump-exit observer on `ClientApi` (T26-e discriminates `PeerDead` vs
/// `PongTimeout` by THIS reason, not wall time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaPumpExit {
    /// A re-auth beat's full-`handle()` verdict failed (revocation/expiry/scope loss/kill
    /// switch, or a panic escaping `handle()`): cut IMMEDIATELY (§2.4 A1).
    AuthFailureImmediate,
    /// The unconditional start-anchored deadline fired: the last SUCCESSFUL re-auth's beat
    /// START is older than `reauth_max_age` (saturation fails CLOSED into this cut).
    ReauthDeadline,
    /// The subscribe-time session `expires_at` cap.
    ExpiresAt,
    /// The pong for the previous beat's ping did not arrive by this beat (~2 beats).
    PongTimeout,
    /// Peer-initiated orderly end: a Close frame or a cleanly finished stream.
    PeerClosed,
    /// Socket-error leg (B3(ii)): recv error, or a ping-SEND error (same dead-peer class).
    PeerDead,
}

impl DeltaPumpExit {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeltaPumpExit::AuthFailureImmediate => "auth_failure_immediate",
            DeltaPumpExit::ReauthDeadline => "reauth_deadline",
            DeltaPumpExit::ExpiresAt => "expires_at",
            DeltaPumpExit::PongTimeout => "pong_timeout",
            DeltaPumpExit::PeerClosed => "peer_closed",
            DeltaPumpExit::PeerDead => "peer_dead",
        }
    }
}

/// Test-support pump-exit observer (transport-level seam; NOT the §2.4 pin-(xiv) hub observer).
pub type DeltaPumpExitObserver = Arc<dyn Fn(DeltaPumpExit) + Send + Sync>;

/// Interior-mutable hub slot (provider-slot precedent): the route closures capture a clone so
/// the composition root / a witness can inject the hub AFTER registration.
pub(crate) type LlmDeltaHubSlot = Arc<RwLock<Option<Arc<LlmDeltaHub>>>>;

/// Register the tee T2 subscribe route: `GET /client/llm/deltas/stream`, scope-gated on
/// `Scope::ReadLlmDeltas` (pipeline-enforced BEFORE the handler runs). The handler is the FULL
/// `handle()` face of the surface — the WS seed pass and every re-auth beat go through it. It
/// never touches the subscriber semaphore (the async transport acquires the RAII permit AFTER a
/// successful seed), so a plain HTTP GET consumes no slot.
pub(crate) fn register(api: &mut crate::api::ClientApi, slot: LlmDeltaHubSlot, enabled: bool) {
    api.register(
        crate::request::Method::Get,
        crate::routes::PATH_LLM_DELTAS_STREAM,
        crate::api::HandlerSpec::read(true, move |_ctx| {
            // Kill switch `client_api.llm_deltas_enabled` (§2.13): evaluated AFTER the scope
            // gate (an under-scoped caller sees 403 whatever the flag) and answers with the
            // EXISTING module_unavailable code — routes stay registered, never a routing oracle.
            if !enabled {
                return Err(ClientError::new(
                    ClientErrorCode::ModuleUnavailable,
                    "llm delta subscription disabled",
                ));
            }
            if slot.read().unwrap_or_else(|e| e.into_inner()).is_none() {
                return Err(ClientError::new(
                    ClientErrorCode::ModuleUnavailable,
                    "llm delta hub not wired",
                ));
            }
            Ok(serde_json::json!({ "subscribed": true }))
        })
        .with_scopes(vec![crate::session::Scope::ReadLlmDeltas]),
    );
}

// ─────────────────────────────────────────────────────────────────────────
// §3.3 T2 unit-witness enumeration (in-crate)
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use advance_shared_types::security_validator::{Action, Finding};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::AtomicUsize;

    // ── stubs ────────────────────────────────────────────────────────────

    /// Stub detector honoring a script of verdicts (default Clean); can panic on demand.
    struct ScriptedDetector {
        script: Mutex<VecDeque<ScanResult>>,
        panics_remaining: AtomicUsize,
        /// When set, returns Blocked iff the input contains this needle (else Clean).
        block_needle: Option<String>,
    }

    impl ScriptedDetector {
        fn clean() -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(VecDeque::new()),
                panics_remaining: AtomicUsize::new(0),
                block_needle: None,
            })
        }
        fn scripted(verdicts: Vec<ScanResult>) -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(verdicts.into()),
                panics_remaining: AtomicUsize::new(0),
                block_needle: None,
            })
        }
        fn panicking_once() -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(VecDeque::new()),
                panics_remaining: AtomicUsize::new(1),
                block_needle: None,
            })
        }
        fn blocking_on(needle: &str) -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(VecDeque::new()),
                panics_remaining: AtomicUsize::new(0),
                block_needle: Some(needle.to_string()),
            })
        }
    }

    impl LeakDetector for ScriptedDetector {
        fn scan(&self, text: &str, _context: ScanContext) -> ScanResult {
            if self
                .panics_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                .is_ok()
            {
                panic!("injected detector panic (U-15)");
            }
            if let Some(needle) = &self.block_needle {
                return if text.contains(needle.as_str()) {
                    ScanResult::Blocked {
                        findings: vec![finding("test_secret")],
                    }
                } else {
                    ScanResult::Clean
                };
            }
            let mut script = self.script.lock().unwrap();
            script.pop_front().unwrap_or(ScanResult::Clean)
        }
        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    fn finding(name: &str) -> Finding {
        Finding {
            pattern_name: name.to_string(),
            offset: 0,
            length: 1,
            action: Action::Block,
        }
    }

    fn release_all_split() -> DeltaHoldSplit {
        Arc::new(|b: &[u8], _max: usize| Ok(b.len()))
    }
    fn hold_all_split() -> DeltaHoldSplit {
        Arc::new(|_b: &[u8], _max: usize| Ok(0))
    }
    fn err_split() -> DeltaHoldSplit {
        Arc::new(|_b: &[u8], _max: usize| Err(()))
    }
    /// Hold everything from the LAST occurrence of `needle` (viable-prefix over-hold stub).
    fn hold_from_needle(needle: &'static [u8]) -> DeltaHoldSplit {
        Arc::new(move |b: &[u8], _max: usize| {
            let pos = b
                .windows(needle.len())
                .rposition(|w| w == needle)
                .unwrap_or(b.len());
            Ok(pos)
        })
    }

    struct Capture {
        events: Arc<Mutex<Vec<HubEvent>>>,
    }

    fn capture_observer() -> (DeltaObserver, Capture) {
        let events: Arc<Mutex<Vec<HubEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        (
            Arc::new(move |e: HubEvent| sink.lock().unwrap().push(e)),
            Capture { events },
        )
    }

    impl Capture {
        fn contains(&self, e: HubEvent) -> bool {
            self.events.lock().unwrap().contains(&e)
        }
        fn count(&self, e: HubEvent) -> usize {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|x| **x == e)
                .count()
        }
    }

    fn hub_with(
        detector: Option<Arc<dyn LeakDetector>>,
        split: Option<DeltaHoldSplit>,
    ) -> (Arc<LlmDeltaHub>, Arc<TestClock>, Capture) {
        let clock = Arc::new(TestClock::new(1_000_000));
        let (obs, cap) = capture_observer();
        let hub = Arc::new(LlmDeltaHub::new(
            detector,
            split,
            Arc::clone(&clock) as Arc<dyn Clock>,
            Some(obs),
        ));
        (hub, clock, cap)
    }

    fn clean_hub() -> (Arc<LlmDeltaHub>, Arc<TestClock>, Capture) {
        hub_with(Some(ScriptedDetector::clean()), Some(release_all_split()))
    }

    fn begin(hub: &LlmDeltaHub, agent: &str, key: &str) {
        hub.publish(LlmDeltaEvent {
            agent_id: Arc::from(agent),
            stream_key: Arc::from(key),
            frame: LlmDeltaFrame::Begin {
                run_id: Some(format!("run-{key}")),
                task_id: None,
            },
        });
    }

    fn delta(hub: &LlmDeltaHub, key: &str, seq: u64, text: &str) {
        hub.publish(LlmDeltaEvent {
            agent_id: Arc::from("agent"),
            stream_key: Arc::from(key),
            frame: LlmDeltaFrame::Delta {
                seq,
                text: text.to_string(),
            },
        });
    }

    fn terminal(hub: &LlmDeltaHub, key: &str, seq: u64) {
        terminal_with_cost(hub, key, seq, 0.01);
    }

    fn terminal_with_cost(hub: &LlmDeltaHub, key: &str, seq: u64, cost: f64) {
        hub.publish(LlmDeltaEvent {
            agent_id: Arc::from("agent"),
            stream_key: Arc::from(key),
            frame: LlmDeltaFrame::Terminal {
                seq,
                reason: LlmTerminalReason::Completed,
                usage: Some(advance_shared_types::traits::LlmDeltaUsage {
                    input_tokens: 10,
                    output_tokens: 20,
                    cost_usd: cost,
                }),
            },
        });
    }

    fn item_seqs(page: &LlmDeltaPage) -> Vec<u64> {
        page.deltas.iter().map(|i| i.from_seq).collect()
    }

    fn joined_text(page: &LlmDeltaPage) -> String {
        page.deltas.iter().map(|i| i.text.as_str()).collect()
    }

    // ── U-1.1 hub model: seq-ordered store ───────────────────────────────
    // Isolating mutation: an arrival-ordered store would release [2, 0, 1].
    #[test]
    fn u1_1_seq_ordered_store() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        delta(&hub, "s", 2, "C");
        delta(&hub, "s", 0, "A");
        delta(&hub, "s", 1, "B");
        let page = hub.read_page("s", 0);
        assert_eq!(item_seqs(&page), vec![0, 1, 2]);
        assert_eq!(joined_text(&page), "ABC");
    }

    // ── U-1.2 window bounds: eviction consumes the RELEASED head only ────
    // Isolating mutations: a window that evicts unreleased bytes would drop pending seq 3;
    // an unenforced window would still serve seq 0 with dropped_count 0.
    #[test]
    fn u1_2_window_bounds_evict_released_head_only() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        let big = "x".repeat(30 * 1024);
        for seq in 0..8 {
            delta(&hub, "s", seq, &big);
        }
        // Release all 240 KiB.
        let p = hub.read_page("s", 0);
        assert_eq!(p.dropped_count, 0);
        // 60 KiB more: released(240K) + pending would exceed 256K → the released HEAD
        // (seqs 0 then 1) is evicted; the new frames are NOT dropped (pending alone is
        // far below the window — the window never evicts UNRELEASED bytes).
        delta(&hub, "s", 8, &big);
        delta(&hub, "s", 9, &big);
        let p = hub.read_page("s", 0);
        assert_eq!(
            item_seqs(&p),
            vec![2, 3],
            "head evicted (floor risen), tail released; page bound cuts at two 30K items"
        );
        assert!(p.page_limit_reached);
        assert_eq!(
            p.dropped_count, 2,
            "evicted seqs 0-1 reported below the floor"
        );
        // The freshly published tail frames survived and are replayable.
        let p = hub.read_page("s", 8);
        assert_eq!(item_seqs(&p), vec![8, 9]);
    }

    // ── U-1.3 tail-coalesce: a contiguous stream never consumes the budget ─
    // Isolating mutation: without tail-coalesce the 1024-discontinuity budget trips.
    #[test]
    fn u1_3_tail_coalesce_contiguous_stream() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        for seq in 0..3000u64 {
            delta(&hub, "s", seq, "x");
        }
        let p = hub.read_page("s", 0);
        assert_eq!(p.dropped_count, 0, "no budget trip for contiguous seqs");
        assert_eq!(p.deltas.len(), 3000);
    }

    // ── U-1.4 range-discontinuity budget (counts GAPS, not seqs) ─────────
    // Isolating mutations: a seq-count cap would drop long contiguous streams (U-1.3);
    // no budget would accept the 1025th discontinuity.
    #[test]
    fn u1_4_discontinuity_budget() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        // 1025 disjoint ranges = 1024 discontinuities (the budget, exactly).
        for i in 0..=1024u64 {
            delta(&hub, "s", i * 2, "x");
        }
        let p = hub.read_page("s", 0);
        assert_eq!(p.dropped_count, 0, "1024 discontinuities are within budget");
        // The 1025th discontinuity drops-and-counts.
        delta(&hub, "s", 2050, "x");
        let p = hub.read_page("s", 2050);
        assert_eq!(p.dropped_count, 1);
        assert!(p.deltas.is_empty());
        // An adjacent seq (extends an existing range, no new discontinuity) still lands.
        delta(&hub, "s", 2049, "y");
        let p = hub.read_page("s", 2049);
        assert_eq!(item_seqs(&p), vec![2049]);
    }

    // ── U-1.5 admission caps (64 global / 8 per agent), Begin-only ───────
    // Isolating mutation: admission checked anywhere but Begin, or an over-cap upsert.
    #[test]
    fn u1_5_admission_caps() {
        let (hub, _, cap) = clean_hub();
        for i in 0..8 {
            begin(&hub, "agent-a", &format!("a{i}"));
        }
        begin(&hub, "agent-a", "a8"); // 9th for one agent → refused
        assert!(
            hub.read_page("a8", 0).absent,
            "per-agent refused key reads absent"
        );
        assert!(!hub.read_page("a7", 0).absent);
        assert!(cap.contains(HubEvent::RefusedStreamDiscard));
        // Fill to the global cap with 7 more agents × 8.
        for a in 0..7 {
            for i in 0..8 {
                begin(&hub, &format!("agent-g{a}"), &format!("g{a}-{i}"));
            }
        }
        begin(&hub, "agent-z", "z0"); // 65th globally → refused
        assert!(
            hub.read_page("z0", 0).absent,
            "global refused key reads absent"
        );
    }

    // ── U-1.6 refused-Begin no-entry (no-upsert on later frames) ─────────
    // Isolating mutation: a Delta/Terminal upserting an entry for a refused key.
    #[test]
    fn u1_6_refused_begin_no_entry() {
        let (hub, _, cap) = clean_hub();
        for i in 0..8 {
            begin(&hub, "agent-a", &format!("k{i}"));
        }
        begin(&hub, "agent-a", "refused");
        let before = cap.count(HubEvent::RefusedStreamDiscard);
        delta(&hub, "refused", 0, "text");
        terminal(&hub, "refused", 1);
        assert!(hub.read_page("refused", 0).absent, "no entry ever created");
        assert_eq!(
            cap.count(HubEvent::RefusedStreamDiscard),
            before + 2,
            "both frames discarded at the membership check"
        );
    }

    // ── U-1.7 de-dup exact via seen-ranges; an unseen gap seq is accepted ─
    // Isolating mutation: range-membership de-dup would discard first-time gap seq 2.
    #[test]
    fn u1_7_dedup_exact_unseen_gap_accepted() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "A");
        delta(&hub, "s", 1, "B");
        delta(&hub, "s", 3, "D");
        delta(&hub, "s", 1, "DUP"); // exact duplicate → ignored (drain), not counted
        delta(&hub, "s", 2, "C"); // unseen seq inside the span → first-time content
        let p = hub.read_page("s", 0);
        assert_eq!(item_seqs(&p), vec![0, 1, 2, 3]);
        assert_eq!(
            joined_text(&p),
            "ABCD",
            "duplicate text never replaces the original"
        );
        assert_eq!(p.dropped_count, 0);
    }

    // ── U-1.8 below-floor split: in-seen drains, not-in-seen counts ──────
    // Isolating mutations: counting the drain (over-report of 2) or ignoring the unseen
    // below-floor frame (under-report of 0).
    #[test]
    fn u1_8_below_floor_split() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        for (seq, t) in [(0, "A"), (1, "B"), (3, "D"), (4, "E")] {
            delta(&hub, "s", seq, t);
        }
        let p = hub.read_page("s", 0);
        assert_eq!(item_seqs(&p), vec![0, 1, 3, 4]); // frontier floor now 5
        delta(&hub, "s", 1, "B"); // below-floor IN seen → drain, ignored
        let p = hub.read_page("s", 0);
        assert_eq!(p.dropped_count, 0, "in-seen drain is never counted");
        delta(&hub, "s", 2, "C"); // below-floor NOT in seen → dropped AND counted
        let p = hub.read_page("s", 0);
        assert_eq!(p.dropped_count, 1);
        assert_eq!(
            item_seqs(&p),
            vec![0, 1, 3, 4],
            "no late insert below the floor"
        );
    }

    /// Detector that, exactly once, publishes an in-bounds out-of-order gap-fill DURING its
    /// `scan` — reproducing the publish-races-an-in-flight-scan window deterministically on one
    /// thread. `run_scan_steps` releases the entry lock before it scans (holding only the atomic
    /// advancer claim), so this reentrant publish drives the exact admission path a concurrent
    /// producer would hit while a scan step is in flight.
    struct GapfillDuringScanDetector {
        hub: Mutex<Option<std::sync::Weak<LlmDeltaHub>>>,
        fired: AtomicBool,
        key: String,
        seq: u64,
        text: String,
    }

    impl GapfillDuringScanDetector {
        fn new(key: &str, seq: u64, text: &str) -> Arc<Self> {
            Arc::new(Self {
                hub: Mutex::new(None),
                fired: AtomicBool::new(false),
                key: key.to_string(),
                seq,
                text: text.to_string(),
            })
        }
        fn set_hub(&self, hub: std::sync::Weak<LlmDeltaHub>) {
            *self.hub.lock().unwrap() = Some(hub);
        }
    }

    impl LeakDetector for GapfillDuringScanDetector {
        fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
            if self
                .fired
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                if let Some(hub) = self.hub.lock().unwrap().as_ref().and_then(|w| w.upgrade()) {
                    // Entry lock is free here (scan runs outside it); the advancer claim is held.
                    hub.publish_delta(&self.key, self.seq, self.text.clone());
                }
            }
            ScanResult::Clean
        }
        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    // ── U-1.11 an in-flight scan never drops a still-pending in-bounds gap-fill ──
    // A gap-fill seq that arrives WHILE a scan step is in flight (entry lock free, advancer
    // claim held) and that stays above the post-commit floor must be BUFFERED, not dropped: the
    // removed scan-span guard dropped-and-counted it against the snapshot span even though the
    // imminent commit was a viable-prefix HeldAll that left the floor unchanged — manufacturing a
    // phantom `dropped_count>0` and a permanent frontier hole for an otherwise in-bounds stream.
    // Isolating mutation: reinstating that scan-span admission guard (seq 1 dropped, seqs 0/2
    // wedged in the hold → a later read returns [] with dropped_count 1 instead of [0,1,2]/0).
    #[test]
    fn u1_11_inflight_scan_does_not_drop_pending_gapfill() {
        // Viable-prefix over-hold stub: a short prefix (<= 4 bytes) is HELD whole (HeldAll — the
        // floor stays put); once enough context accrues (> 4 bytes) the whole span releases.
        let split: DeltaHoldSplit =
            Arc::new(|b: &[u8], _max: usize| if b.len() <= 4 { Ok(0) } else { Ok(b.len()) });
        // Fire the gap-fill (seq 1) DURING the first scan step, whose input is frames [0, 2].
        let detector = GapfillDuringScanDetector::new("s", 1, "bb");
        let clock = Arc::new(TestClock::new(1_000_000));
        let hub = Arc::new(LlmDeltaHub::new(
            Some(Arc::clone(&detector) as Arc<dyn LeakDetector>),
            Some(split),
            Arc::clone(&clock) as Arc<dyn Clock>,
            None,
        ));
        detector.set_hub(Arc::downgrade(&hub));

        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "aa");
        delta(&hub, "s", 2, "cc"); // pending [0, 2]; the gap at seq 1 is still open

        // First read drives the scan: scanning input "aacc" (<= 4 ⇒ would HeldAll, floor stays 0)
        // publishes gap-fill seq 1 mid-flight. Post-fix it is buffered into pending (prefix now
        // [0, 1, 2]); commit_step's defensive bail re-snapshots and NOTHING is dropped. With the
        // old guard seq 1 is dropped-and-counted here and the span wedges as a HeldAll hold.
        let p1 = hub.read_page("s", 0);
        assert_eq!(
            p1.dropped_count, 0,
            "an in-bounds gap-fill published mid-scan is never dropped-and-counted"
        );

        // Second read re-scans the full prefix "aabbcc" (> 4 ⇒ releases the whole span): the
        // retained gap-fill is released IN ORDER with no hole. The old guard leaves the stream
        // wedged (seq 1 gone, seqs 0/2 held forever) — this read returns [] with dropped_count 1.
        let p2 = hub.read_page("s", 0);
        assert_eq!(
            item_seqs(&p2),
            vec![0, 1, 2],
            "the mid-scan gap-fill is retained and released in order"
        );
        assert_eq!(joined_text(&p2), "aabbcc");
        assert_eq!(
            p2.dropped_count, 0,
            "structurally-zero dropped_count within the hub bounds (AC-17)"
        );
    }

    // ── U-1.9 post-terminal deltas accepted AND releasable ───────────────
    // Isolating mutation: any arrival-order or seq-order latch over deltas at Terminal.
    #[test]
    fn u1_9_post_terminal_accept_and_release() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "A");
        terminal(&hub, "s", 5); // watermark ABOVE and BELOW later deltas
        delta(&hub, "s", 1, "B"); // below the terminal watermark
        delta(&hub, "s", 7, "H"); // above the terminal watermark
        let p = hub.read_page("s", 0);
        assert_eq!(
            item_seqs(&p),
            vec![0, 1, 7],
            "post-terminal deltas released"
        );
        assert!(
            p.terminal.is_some(),
            "terminal ships on every page after arrival"
        );
        assert_eq!(p.terminal.as_ref().unwrap().reason, "completed");
    }

    // ── U-1.10 lingering-cap displacement ONLY on an admitted entry's first Terminal ─
    // Isolating mutation: unconditional displacement (refused-key or absorbed second
    // Terminal wiping the lingering set).
    #[test]
    fn u1_10_lingering_displacement_only_on_admitted_first_terminal() {
        let (hub, _, _) = clean_hub();
        // 64 terminated entries fill the lingering list.
        for i in 0..64 {
            let key = format!("s{i}");
            begin(&hub, "a", &key);
            delta(&hub, &key, 0, "x");
            terminal(&hub, &key, 1);
        }
        assert!(!hub.read_page("s0", 0).absent);
        // A refused key's Terminal displaces nothing (dropped at membership).
        terminal(&hub, "never-admitted", 1);
        assert!(
            !hub.read_page("s0", 0).absent,
            "refused-key terminal displaced nothing"
        );
        // An absorbed SECOND Terminal displaces nothing.
        terminal(&hub, "s1", 2);
        assert!(
            !hub.read_page("s0", 0).absent,
            "absorbed terminal displaced nothing"
        );
        // A 65th admitted entry's FIRST Terminal displaces the OLDEST lingering entry.
        begin(&hub, "a", "s64");
        terminal(&hub, "s64", 0);
        assert!(
            hub.read_page("s0", 0).absent,
            "oldest lingering entry displaced"
        );
        assert!(
            !hub.read_page("s1", 0).absent,
            "younger lingering entries retained"
        );
    }

    // ── U-3 page assembly: ≤64 KiB, single-indivisible-item exception ────
    // Isolating mutations: offset splicing of a big item; a bound ignoring the exception
    // (stalling on the oversized item); page_limit_reached never set.
    #[test]
    fn u3_page_assembly_bound_and_indivisible_exception() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        let chunk = "x".repeat(30 * 1024);
        for seq in 0..3 {
            delta(&hub, "s", seq, &chunk);
        }
        let p = hub.read_page("s", 0);
        assert_eq!(
            item_seqs(&p),
            vec![0, 1],
            "two 30 KiB items fit; the third would not"
        );
        assert!(p.page_limit_reached);
        assert_eq!(p.cursor.as_ref().unwrap().from_cursor, 1);
        let p2 = hub.read_page("s", 2);
        assert_eq!(item_seqs(&p2), vec![2]);
        assert!(!p2.page_limit_reached);
        // Indivisible: one frame larger than the page bound ships ALONE, oversized.
        begin(&hub, "a", "big");
        let giant = "y".repeat(100 * 1024);
        delta(&hub, "big", 0, &giant);
        delta(&hub, "big", 1, "tail");
        let p = hub.read_page("big", 0);
        assert_eq!(item_seqs(&p), vec![0], "oversized item ships alone");
        assert_eq!(p.deltas[0].text.len(), 100 * 1024, "never spliced");
        assert!(p.page_limit_reached, "the small tail item remains");
        let p2 = hub.read_page("big", 1);
        assert_eq!(joined_text(&p2), "tail");
    }

    // ── U-7/U-8 publish: exactly ONE registry-map acquisition, no await ──
    // Isolating mutation: a second lookup (e.g. re-acquiring for bookkeeping) counts 2.
    // `publish` is a sync fn (structurally no await) driven here with no runtime at all.
    #[test]
    fn u7_u8_publish_single_registry_acquisition() {
        let (hub, _, _) = clean_hub();
        let base = hub.registry_acquisition_count();
        begin(&hub, "a", "s");
        assert_eq!(
            hub.registry_acquisition_count(),
            base + 1,
            "Begin: one acquisition"
        );
        delta(&hub, "s", 0, "x");
        assert_eq!(
            hub.registry_acquisition_count(),
            base + 2,
            "Delta: one acquisition"
        );
        terminal(&hub, "s", 1);
        assert_eq!(
            hub.registry_acquisition_count(),
            base + 3,
            "Terminal: one acquisition"
        );
        delta(&hub, "unknown", 0, "x");
        assert_eq!(
            hub.registry_acquisition_count(),
            base + 4,
            "unknown-key drop: one"
        );
    }

    // ── U-9 `is_wired` constant for the sink's lifetime ──────────────────
    // Isolating mutation: is_wired tracking subscriber count / detector presence.
    #[test]
    fn u9_is_wired_constant() {
        let (hub, _, _) = clean_hub();
        assert!(hub.is_wired());
        let sub = hub.subscribe().unwrap();
        assert!(hub.is_wired());
        drop(sub);
        assert!(hub.is_wired());
        // Even a fail-closed hub (no detector/hold) stays wired: "nobody listening" is
        // modeled inside publish, never by flipping is_wired (invariant 3b).
        let (bare, _, _) = hub_with(None, None);
        assert!(bare.is_wired());
        begin(&bare, "a", "s");
        terminal(&bare, "s", 0);
        assert!(bare.is_wired());
    }

    // ── U-10 shared-history determinism across anchors + timings ─────────
    // Isolating mutation: per-reader scan state (a second reader re-scanning pending and
    // minting different collapse spans than the first reader observed).
    #[test]
    fn u10_shared_history_determinism() {
        let det = ScriptedDetector::scripted(vec![
            ScanResult::Redacted {
                redacted: "[R]".to_string(),
                findings: vec![finding("p")],
            },
            // every later scan: Clean (script default)
        ]);
        let (hub, _, _) = hub_with(Some(det), Some(release_all_split()));
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "secret-a");
        delta(&hub, "s", 1, "secret-b");
        // Reader 1 triggers the collapse over seqs [0,1].
        let r1_early = hub.read_page("s", 0);
        assert_eq!(r1_early.redacted_count, 2);
        delta(&hub, "s", 2, "clean");
        let r1_late = hub.read_page("s", 2);
        assert_eq!(joined_text(&r1_late), "clean");
        // Reader 2 joins later at anchor 0: identical released history, byte for byte.
        let r2 = hub.read_page("s", 0);
        assert_eq!(r2.deltas.len(), 2);
        assert_eq!(
            r2.deltas[0].text, "[R]",
            "same collapse item, not a re-scan"
        );
        assert_eq!(r2.deltas[0].from_seq, 0);
        assert_eq!(r2.deltas[0].to_seq, 1);
        assert_eq!(r2.deltas[1].text, "clean");
        assert_eq!(r2.redacted_count, 2);
    }

    // ── U-11 collapse per contiguous seen run + resume counters + expansion guard ─
    // Isolating mutations: one item papering over the unseen gap [2]; counters not derived
    // from included items on resume; a replacement longer than its bytes shipping.
    #[test]
    fn u11_collapse_runs_resume_counters_expansion_guard() {
        let det = ScriptedDetector::scripted(vec![ScanResult::Redacted {
            redacted: "[R]".to_string(),
            findings: vec![finding("p")],
        }]);
        let (hub, _, _) = hub_with(Some(det), Some(release_all_split()));
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "aaaa");
        delta(&hub, "s", 1, "bbbb");
        delta(&hub, "s", 3, "dddd"); // unseen gap at 2
        let p = hub.read_page("s", 0);
        assert_eq!(
            p.deltas.len(),
            2,
            "one synthetic item per CONTIGUOUS seen run"
        );
        assert_eq!((p.deltas[0].from_seq, p.deltas[0].to_seq), (0, 1));
        assert_eq!(p.deltas[0].text, "[R]");
        assert_eq!((p.deltas[1].from_seq, p.deltas[1].to_seq), (3, 3));
        assert_eq!(p.redacted_count, 3, "seq-denominated across runs");
        // Resume across the range boundary: counters derive from THIS page's items.
        let p2 = hub.read_page("s", 3);
        assert_eq!(p2.deltas.len(), 1);
        assert_eq!(p2.redacted_count, 1);
        // Expansion guard: a replacement longer than the bytes it replaces → Blocked.
        let det2 = ScriptedDetector::scripted(vec![ScanResult::Redacted {
            redacted: "MUCH-LONGER-REPLACEMENT".to_string(),
            findings: vec![finding("p")],
        }]);
        let (hub2, _, _) = hub_with(Some(det2), Some(release_all_split()));
        begin(&hub2, "a", "s");
        delta(&hub2, "s", 0, "ab");
        let p = hub2.read_page("s", 0);
        assert_eq!(p.rejected_count, 1, "degraded to Blocked");
        assert_eq!(p.redacted_count, 0);
        assert_eq!(p.deltas.len(), 1);
        assert!(p.deltas[0].text.is_empty(), "blocked item is EMPTY");
    }

    // ── U-12 hold straddle: pre-terminal head + post-terminal tail caught WHOLE ─
    // Isolating mutations: a terminal release-all (shipping the held head at Terminal);
    // a scan not joining the live hold (the tail alone looks clean).
    #[test]
    fn u12_hold_straddle_across_terminal() {
        let det = ScriptedDetector::blocking_on("AKIA1234SECRET");
        let (hub, _, _) = hub_with(Some(det), Some(hold_from_needle(b"AKIA")));
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "hello AKIA");
        let p = hub.read_page("s", 0);
        assert!(
            p.deltas.is_empty(),
            "viable-prefix tail withheld (frame rounds outward, nothing releases)"
        );
        terminal(&hub, "s", 1);
        let p = hub.read_page("s", 0);
        assert!(
            p.deltas.is_empty(),
            "NO terminal release-all: the viable tail is never released"
        );
        assert!(
            p.terminal.is_some(),
            "terminal marker decoupled from the frontier"
        );
        // The tail arrives post-terminal; the joined hold scan sees the WHOLE secret.
        delta(&hub, "s", 1, "1234SECRET rest");
        let p = hub.read_page("s", 0);
        assert_eq!(
            joined_text(&p),
            "",
            "secret never on the wire, not even a fragment"
        );
        assert_eq!(p.rejected_count, 2, "whole joined span dropped fail-closed");
        assert_eq!(
            p.deltas.len(),
            1,
            "one empty synthetic item for the contiguous run"
        );
    }

    // ── U-13 `scan_overflow` fail-closed (synthetic Blocked from a hot-lowered cap) ─
    // Isolating mutation: treating scan_overflow as Clean (open) or stalling the frontier.
    #[test]
    fn u13_scan_overflow_fail_closed() {
        let det = ScriptedDetector::scripted(vec![ScanResult::Blocked {
            findings: vec![Finding {
                pattern_name: "scan_overflow".to_string(),
                offset: 0,
                length: 0,
                action: Action::Block,
            }],
        }]);
        let (hub, _, _) = hub_with(Some(det), Some(release_all_split()));
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "aa");
        delta(&hub, "s", 1, "bb");
        let p = hub.read_page("s", 0);
        assert_eq!(p.rejected_count, 2, "span dropped and counted");
        assert_eq!(joined_text(&p), "", "nothing released");
        // Frontier advanced (no re-fetch loop): the stream continues clean afterwards.
        delta(&hub, "s", 2, "ok");
        let p = hub.read_page("s", 2);
        assert_eq!(joined_text(&p), "ok");
    }

    // ── U-14 deadline-anchor state machine (pure, synthetic clock) ───────
    // This drives the SAME `ReauthDeadline` methods the tee-T2 pump runs in production
    // (`delta_pump` in crate::transport constructs one via `ReauthDeadline::seed` and advances it
    // with `record_success_start`, reading `deadline()` for its unconditional `sleep_until`); the
    // pump ticks in nanoseconds, this witness in milliseconds — the state machine is identical.
    // Isolating mutations: completion-anchoring (adds check latency to the bound);
    // a failed/saturated beat refreshing the anchor; a non-monotonic anchor regression.
    #[test]
    fn u14_reauth_deadline_anchor() {
        let clock = TestClock::new(1_000);
        // Seed = the subscribe-time handle() pass start (deadline defined before any beat).
        let mut d = ReauthDeadline::seed(clock.now_millis(), 15_000);
        assert!(!d.must_cut(16_000), "at the deadline exactly: not yet cut");
        assert!(
            d.must_cut(16_001),
            "past the deadline: cut, on or off the beat grid"
        );
        // A successful beat STARTS at 5_000 and completes at 8_000. Start-anchoring pins
        // the next deadline at 20_000; completion-anchoring would stretch it to 23_000.
        clock.advance(4_000); // now 5_000: beat start
        let beat_start = clock.now_millis();
        clock.advance(3_000); // now 8_000: beat completes
        d.record_success_start(beat_start);
        assert_eq!(d.deadline(), 20_000);
        assert!(!d.must_cut(20_000));
        assert!(
            d.must_cut(20_001),
            "completion-anchoring would NOT cut until 23_001"
        );
        // A saturated/failed beat records nothing: the anchor holds.
        assert!(d.must_cut(25_000));
        // Out-of-order older success never regresses the anchor.
        d.record_success_start(2_000);
        assert_eq!(d.deadline(), 20_000);
    }

    // ── U-15 release-gated reads; single advancer; unwind clears the claim; watch bump ─
    // Isolating mutations: serving pending bytes directly (release gate bypass); a claim
    // left set after a detector panic (all later scans skipped); a release-commit that
    // does not bump the generation watch.
    #[test]
    fn u15_release_gate_unwind_claim_watch() {
        // (a) release gate: a hold-everything geometry keeps ALL content pending.
        let (hub, _, _) = hub_with(Some(ScriptedDetector::clean()), Some(hold_all_split()));
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "withheld");
        let p = hub.read_page("s", 0);
        assert!(p.deltas.is_empty(), "reads return ONLY released items");
        assert!(
            !p.absent,
            "live-quiet admitted stream is absent:false empty"
        );

        // (b) panicking detector: the unwind clears the atomic claim lock-free.
        let det = ScriptedDetector::panicking_once();
        let (hub2, _, _) = hub_with(Some(det), Some(release_all_split()));
        begin(&hub2, "a", "s");
        delta(&hub2, "s", 0, "text");
        let panicked = catch_unwind(AssertUnwindSafe(|| hub2.read_page("s", 0))).is_err();
        assert!(panicked, "injected detector panic propagates");
        // The claim was cleared on unwind: the next read claims, scans, releases.
        let p = hub2.read_page("s", 0);
        assert_eq!(joined_text(&p), "text", "claim not wedged by the panic");

        // (c) a release-commit bumps the same generation watch a publish bumps.
        let (hub3, _, _) = clean_hub();
        let rx = hub3.generation_watch();
        begin(&hub3, "a", "s");
        delta(&hub3, "s", 0, "x");
        let after_publish = *rx.borrow();
        let _ = hub3.read_page("s", 0); // triggers the release commit
        assert!(
            *rx.borrow() > after_publish,
            "release-commit bumped the watch"
        );

        // (d) single advancer: concurrent readers never double-release (exact-once items).
        let (hub4, _, _) = clean_hub();
        begin(&hub4, "a", "s");
        for seq in 0..50 {
            delta(&hub4, "s", seq, "y");
        }
        let h1 = Arc::clone(&hub4);
        let h2 = Arc::clone(&hub4);
        let t1 = std::thread::spawn(move || h1.read_page("s", 0));
        let t2 = std::thread::spawn(move || h2.read_page("s", 0));
        t1.join().unwrap();
        t2.join().unwrap();
        let p = hub4.read_page("s", 0);
        let seqs = item_seqs(&p);
        let mut dedup = seqs.clone();
        dedup.dedup();
        assert_eq!(seqs, dedup, "no seq released twice by racing advancers");
        assert_eq!(seqs, (0..50).collect::<Vec<_>>());
    }

    // ── U-17 pump timing: leg (i) constant inequality; leg (ii) effective_timing ─
    // Isolating mutation: a cadence/deadline pair with no re-auth latency margin (the
    // pre-A1 15 s cadence) violates 2×CADENCE + ALLOWANCE ≤ REAUTH_MAX_AGE.
    #[test]
    fn u17_timing_constants_and_effective_timing() {
        // Leg (i): CADENCE ≤ 5s ∧ 2×CADENCE + ALLOWANCE ≤ REAUTH_MAX_AGE ∧ ≤ 15s.
        assert!(DELTA_PUMP_CADENCE <= Duration::from_secs(5));
        assert!(DELTA_PUMP_CADENCE * 2 + DELTA_PUMP_ALLOWANCE <= DELTA_PUMP_REAUTH_MAX_AGE);
        assert!(DELTA_PUMP_REAUTH_MAX_AGE <= Duration::from_secs(15));
        // Leg (ii): default-ctor effective_timing equals the constants.
        let (hub, _, _) = clean_hub();
        let t = hub.effective_timing();
        assert_eq!(t.cadence, DELTA_PUMP_CADENCE);
        assert_eq!(t.reauth_max_age, DELTA_PUMP_REAUTH_MAX_AGE);
        assert_eq!(t.allowance, DELTA_PUMP_ALLOWANCE);
        assert_eq!(t.linger, DELTA_TERMINAL_LINGER);
        // Override ctor takes effect (linger witnessed via lazy eviction elsewhere).
        let clock = Arc::new(TestClock::new(0));
        let hub2 = LlmDeltaHub::with_timing(
            Some(ScriptedDetector::clean()),
            Some(release_all_split()),
            clock as Arc<dyn Clock>,
            None,
            DeltaTiming {
                linger: Duration::from_millis(10),
                ..DeltaTiming::default()
            },
        );
        assert_eq!(hub2.effective_timing().linger, Duration::from_millis(10));
    }

    // ── U-18 bidi/zero-width byte-exact round-trip ───────────────────────
    // Isolating mutation: a hub-side strip/normalization altering released bytes.
    #[test]
    fn u18_bidi_zero_width_byte_exact() {
        let (hub, _, _) = clean_hub();
        begin(&hub, "a", "s");
        let tricky = "\u{200B}\u{200E}\u{202E}abc\u{2066}def\u{FEFF}";
        delta(&hub, "s", 0, tricky);
        let p = hub.read_page("s", 0);
        assert_eq!(p.deltas.len(), 1);
        assert_eq!(
            p.deltas[0].text.as_bytes(),
            tricky.as_bytes(),
            "released verbatim, byte-exact (scan is CONTRACT-112's job, not a hub strip)"
        );
    }

    // ── U-19 `decoded_hold_split` Err ⇒ Blocked-advance (never a stall) ──
    // Isolating mutation: a release-nothing stall on facade Err (frontier frozen).
    #[test]
    fn u19_hold_split_err_blocked_advance() {
        let (hub, _, _) = hub_with(Some(ScriptedDetector::clean()), Some(err_split()));
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "aa");
        delta(&hub, "s", 1, "bb");
        let p = hub.read_page("s", 0);
        assert_eq!(p.rejected_count, 2, "span dropped + counted");
        assert!(joined_text(&p).is_empty(), "nothing released on Err");
        // The frontier ADVANCED: a later frame is processed as a fresh span, proving the
        // Err did not wedge the stream.
        delta(&hub, "s", 2, "cc");
        let p2 = hub.read_page("s", 0);
        assert_eq!(
            p2.rejected_count, 3,
            "later spans keep progressing (no stall)"
        );
    }

    // ── U-20 pending-full: Delta drops recorded; Begin/Terminal exempt; merge never
    //    under-counts; small streams inside bounds drop NOTHING ──────────
    // Isolating mutations: dropping control frames at pending-full (stranding the entry
    // outside linger); a range set that forgets drops on overflow (under-report).
    #[test]
    fn u20_pending_full_discipline() {
        // Hold-everything geometry keeps pending resident (nothing releases before the
        // read; NO read happens until every publish below has hit the full window).
        let (hub, _, _) = hub_with(Some(ScriptedDetector::clean()), Some(hold_all_split()));
        begin(&hub, "a", "s");
        let chunk = "x".repeat(64 * 1024);
        for seq in 0..4 {
            delta(&hub, "s", seq, &chunk); // exactly 256 KiB pending
        }
        delta(&hub, "s", 4, "overflow"); // pending-full → dropped, seq recorded
                                         // 70 further disjoint dropped seqs overflow the 64-range cap; merged ranges may
                                         // over-report but NEVER under-report.
        for i in 0..70u64 {
            delta(&hub, "s", 1_000 + i * 2, "y");
        }
        // Terminal is EXEMPT from the pending-full drop (else the entry strands).
        terminal(&hub, "s", 4);
        let p = hub.read_page("s", 0);
        assert!(p.terminal.is_some(), "Terminal accepted while pending-full");
        assert!(
            p.dropped_count >= 71,
            "merge-on-overflow never under-counts"
        );
        // A small-delta stream inside bounds drops NOTHING.
        let (hub2, _, _) = clean_hub();
        begin(&hub2, "a", "t");
        for seq in 0..1000 {
            delta(&hub2, "t", seq, "tok");
        }
        let p = hub2.read_page("t", 0);
        assert_eq!(p.dropped_count, 0);
        assert_eq!(p.deltas.len(), 1000);
    }

    // ── U-21 `operator_default` membership ───────────────────────────────
    // Isolating mutation: the scope minted but not granted to the single operator.
    #[test]
    fn u21_operator_default_membership() {
        use crate::session::Scope;
        assert!(Scope::operator_default().contains(&Scope::ReadLlmDeltas));
    }

    // ── U-22 hold ≥ MAX_HOLD_BYTES in the degenerate all-pending state ───
    // Isolating mutation: an uncapped hold stalling the stream forever (open, not closed).
    #[test]
    fn u22_hold_cap_overflow_blocked_advance() {
        let (hub, _, _) = hub_with(Some(ScriptedDetector::clean()), Some(hold_all_split()));
        begin(&hub, "a", "s");
        let chunk = "x".repeat(64 * 1024);
        for seq in 0..4 {
            delta(&hub, "s", seq, &chunk); // 256 KiB pending — the whole window
        }
        let p = hub.read_page("s", 0);
        // Steps: hold grows 64K → 128K → 192K; the 4th step's computed hold reaches
        // 256 KiB = MAX_HOLD_BYTES → the span degrades to Blocked (closed WITH progress).
        assert_eq!(
            p.rejected_count, 4,
            "whole over-held span dropped fail-closed"
        );
        assert!(joined_text(&p).is_empty());
        assert!(!p.absent);
        // The stream CONTINUES: new content is accepted and processed.
        delta(&hub, "s", 4, "next");
        let p2 = hub.read_page("s", 0);
        assert!(!p2.absent);
        assert_eq!(p2.rejected_count, 4, "no further rejects; entry alive");
    }

    // ── U-23 non-finite `cost_usd` ⇒ Some + 0.0 + observer event ─────────
    // Isolating mutation: flipping usage to None (erasing token counts).
    #[test]
    fn u23_non_finite_cost() {
        let (hub, _, cap) = clean_hub();
        begin(&hub, "a", "s");
        terminal_with_cost(&hub, "s", 3, f64::NAN);
        let p = hub.read_page("s", 0);
        let term = p.terminal.expect("terminal present");
        let usage = term.usage.expect("usage NEVER flipped to None");
        assert_eq!(usage.cost_usd, 0.0);
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 20);
        assert!(cap.contains(HubEvent::NonFiniteCost));
    }

    // ── supplementary: subscribe fail-closed + cap; linger lazy eviction ─

    #[test]
    fn subscribe_fail_closed_and_cap() {
        // Absent detector OR hold closure ⇒ subscribe refuses (fail closed).
        let (bare, _, _) = hub_with(None, Some(release_all_split()));
        assert_eq!(
            bare.subscribe().unwrap_err().code,
            ClientErrorCode::ModuleUnavailable
        );
        let (bare2, _, _) = hub_with(Some(ScriptedDetector::clean()), None);
        assert_eq!(
            bare2.subscribe().unwrap_err().code,
            ClientErrorCode::ModuleUnavailable
        );
        // Cap 4 with RAII release; overflow maps to the EXISTING stream_backpressure.
        let (hub, _, _) = clean_hub();
        let permits: Vec<_> = (0..4).map(|_| hub.subscribe().unwrap()).collect();
        assert_eq!(
            hub.subscribe().unwrap_err().code,
            ClientErrorCode::StreamBackpressure
        );
        drop(permits);
        assert!(hub.subscribe().is_ok(), "RAII release frees the slot");
    }

    #[test]
    fn linger_lazy_eviction_no_rearm() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let (obs, cap) = capture_observer();
        let hub = LlmDeltaHub::with_timing(
            Some(ScriptedDetector::clean()),
            Some(release_all_split()),
            Arc::clone(&clock) as Arc<dyn Clock>,
            Some(obs),
            DeltaTiming {
                linger: Duration::from_secs(30),
                ..DeltaTiming::default()
            },
        );
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "x");
        terminal(&hub, "s", 1);
        clock.advance(29_999);
        assert!(!hub.read_page("s", 0).absent, "within linger: replayable");
        // A post-terminal publish does NOT re-arm the linger (round 12).
        delta(&hub, "s", 1, "late");
        clock.advance(1);
        let p = hub.read_page("s", 0);
        assert!(
            p.absent,
            "linger expired ⇒ lazy eviction ⇒ absent (no re-arm)"
        );
        assert!(
            p.terminal.is_none(),
            "late reconnect never sees the Terminal"
        );
        // Content accepted after expiry evicted unread → observer event.
        assert!(cap.contains(HubEvent::EvictedUnreadPending));
        // Previously-served ⇒ never served again: still absent on the next read.
        assert!(hub.read_page("s", 0).absent);
    }

    #[test]
    fn no_detector_hub_releases_nothing() {
        let (hub, _, _) = hub_with(None, None);
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "sensitive");
        let p = hub.read_page("s", 0);
        assert!(
            p.deltas.is_empty(),
            "a hub without egress deps releases NOTHING"
        );
        assert!(!p.absent);
    }

    #[test]
    fn warned_verbatim_and_counted() {
        let det = ScriptedDetector::scripted(vec![ScanResult::Warned {
            findings: vec![finding("w")],
        }]);
        let (hub, _, _) = hub_with(Some(det), Some(release_all_split()));
        begin(&hub, "a", "s");
        delta(&hub, "s", 0, "warned-text");
        let p = hub.read_page("s", 0);
        assert_eq!(joined_text(&p), "warned-text", "Warned delivers verbatim");
        assert_eq!(p.warned_count, 1);
    }
}
