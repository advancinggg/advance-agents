//! `MessageTrace` — inbound-channel-message → reply-routing table
//! (CONTRACT-051 sub-surface, MODULE-006 §1.3.5 / §2.3).
//!
//! Records, per inbound `message_id`, the originating [`MessageOrigin`] plus
//! the **recipient** the inbound was delivered to. `MailboxDispatcher::reply`
//! looks the entry up by `to_message_id`, authorizes via
//! `from == recipient` (only the agent that received message X may reply to
//! X), and routes the reply back to `origin.adapter_id`.
//!
//! # Trust boundary (MODULE-006 §1.6 / §3.8)
//!
//! The trace is host-internal runtime state — "MessageTrace table is
//! runtime-internal; agents cannot read it" (§1.6). No WIT surface exposes
//! `record()` this slice; the authenticated inbound host_fn (future slice)
//! is the sole production caller and stamps `recipient` from authenticated
//! context. `reply()`'s authorization is sound within the host trust
//! boundary (the same boundary every host primitive operates under).
//!
//! # DoS posture
//!
//! - **Per-entry size cap** at `record()`: `message_id` length + the stored
//!   `MessageOrigin` (header strings, `channel_metadata` count + entry
//!   bytes, nested context) are bounded with the same slice-A caps that
//!   `Mailbox::deliver` enforces. A trace entry can never exceed the
//!   deliver-time bound, closing the "unbounded per-entry × 10_000 entries"
//!   memory-amplification vector.
//! - **Entry-count cap** (`MAX_TRACE_ENTRIES`); at-cap insert evicts the
//!   **lowest `seq`** (insertion order — clock-skew-immune) in O(log N) via
//!   a `BTreeMap<seq, message_id>` order index (NOT an O(N) full-map scan).
//! - `recorded_at` is **host-stamped** at `record()` (`SystemTime::now()`),
//!   never client-supplied — closes the clock-skew eviction-targeting
//!   vector. The only residual skew is a host clock jump (operational,
//!   accepted).
//! - TTL `gc(now, ttl)` drops stale entries (default 7 days, §2.10). NOTE:
//!   no background reaper is wired this slice (host_fn ingress deferred); a
//!   process recording > `MAX_TRACE_ENTRIES` inbound before any external
//!   `gc` call falls back to lowest-`seq` (insertion-order) eviction of
//!   still-live entries — an accepted availability limitation recorded in
//!   MODULE-006 §3.6 (gc-scheduler deferred to the host_fn-ingress slice).
//!
//! `std::sync::RwLock` (sync) is used deliberately: `gc` is infrequent, the
//! at-cap eviction is now O(log N) (not a full scan), and a
//! `tokio::sync::RwLock` would force an async API on `lookup`. A single
//! lock over `{entries, order}` avoids any lock-ordering hazard.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use advance_shared_types::mailbox::{MessageOrigin, MsgError};

use crate::id_validation::{is_safe_id, MAX_ID_BYTES};
use crate::mailbox::{validate_message_context, MAX_METADATA_ENTRIES, MAX_METADATA_ENTRY_BYTES};

/// Per-process trace-table size cap (mirrors the `MAX_MAILBOXES` precedent).
pub const MAX_TRACE_ENTRIES: usize = 10_000;

/// Default trace-entry TTL (MODULE-006 §2.10 `message_trace.ttl_days = 7`).
pub const DEFAULT_TRACE_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

struct TraceEntry {
    origin: MessageOrigin,
    /// Host-stamped at `record()` — never client-supplied.
    recorded_at: SystemTime,
    /// Monotonic insertion sequence — drives clock-skew-immune eviction.
    seq: u64,
    /// Agent id the inbound was delivered to. `reply()` authorizes
    /// `from == recipient`.
    recipient: String,
}

struct TraceState {
    entries: HashMap<String, TraceEntry>,
    /// `seq → message_id` insertion-order index. `first_key_value()` gives
    /// the lowest-`seq` (oldest) entry in O(log N) for at-cap eviction.
    order: BTreeMap<u64, String>,
}

/// Reapply the slice-A `Mailbox::deliver` size caps to a `MessageOrigin`
/// BEFORE it is stored in the trace. Mirrors `mailbox.rs::Mailbox::deliver`'s
/// origin block (header lengths, `channel_metadata` count + per-entry bytes,
/// nested context) so a trace entry can never exceed the deliver-time bound
/// — defense-in-depth against per-entry memory amplification.
fn validate_origin_caps(origin: &MessageOrigin) -> Result<(), MsgError> {
    if origin.message_id.len() > MAX_ID_BYTES
        || origin.original_channel.len() > MAX_ID_BYTES
        || origin.original_sender.len() > MAX_ID_BYTES
        || origin.adapter_id.len() > MAX_ID_BYTES
    {
        return Err(MsgError::InvalidPayload("trace_origin_too_large".into()));
    }
    if origin.channel_metadata.len() > MAX_METADATA_ENTRIES {
        return Err(MsgError::InvalidPayload("trace_origin_too_large".into()));
    }
    for (k, v) in &origin.channel_metadata {
        if k.len() > MAX_METADATA_ENTRY_BYTES || v.len() > MAX_METADATA_ENTRY_BYTES {
            return Err(MsgError::InvalidPayload("trace_origin_too_large".into()));
        }
    }
    if let Some(ctx) = &origin.context {
        validate_message_context(ctx)?;
    }
    Ok(())
}

/// Reply-routing trace table. See module rustdoc.
pub struct MessageTrace {
    state: RwLock<TraceState>,
    seq: AtomicU64,
}

impl Default for MessageTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageTrace {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(TraceState {
                entries: HashMap::new(),
                order: BTreeMap::new(),
            }),
            seq: AtomicU64::new(0),
        }
    }

    /// Record an inbound message's origin + recipient.
    ///
    /// Rejects an empty / oversized `message_id`, a non-`is_safe_id`
    /// `recipient`, or an oversized `MessageOrigin` (header/metadata/context
    /// over the slice-A deliver caps) with `MsgError::InvalidPayload(<id>)`
    /// (invariant identifier — PII discipline). At [`MAX_TRACE_ENTRIES`] the
    /// lowest-`seq` entry is evicted before the insert (insertion-order,
    /// clock-skew-immune) in O(log N).
    pub fn record(
        &self,
        message_id: &str,
        origin: MessageOrigin,
        recipient: &str,
    ) -> Result<(), MsgError> {
        if message_id.is_empty() || message_id.len() > MAX_ID_BYTES || !is_safe_id(recipient) {
            return Err(MsgError::InvalidPayload("trace_arg_invalid".into()));
        }
        validate_origin_caps(&origin)?;
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut st = self.state.write().expect("trace rwlock poisoned");
        // If replacing an existing id, drop its old order-index entry first.
        if let Some(old) = st.entries.get(message_id) {
            let old_seq = old.seq;
            st.order.remove(&old_seq);
        } else if st.entries.len() >= MAX_TRACE_ENTRIES {
            // Evict the lowest-seq (oldest-inserted) entry — O(log N) via the
            // BTreeMap order index, NOT an O(N) full-map scan.
            let victim = st.order.iter().next().map(|(s, id)| (*s, id.clone()));
            if let Some((victim_seq, victim_id)) = victim {
                st.order.remove(&victim_seq);
                st.entries.remove(&victim_id);
            }
        }
        st.order.insert(seq, message_id.to_string());
        st.entries.insert(
            message_id.to_string(),
            TraceEntry {
                origin,
                recorded_at: SystemTime::now(),
                seq,
                recipient: recipient.to_string(),
            },
        );
        Ok(())
    }

    /// Look up the recorded [`MessageOrigin`] for `message_id`.
    pub fn lookup(&self, message_id: &str) -> Option<MessageOrigin> {
        self.state
            .read()
            .expect("trace rwlock poisoned")
            .entries
            .get(message_id)
            .map(|e| e.origin.clone())
    }

    /// Look up `(origin, recipient)` — used by `reply()` for the
    /// `from == recipient` authorization check.
    pub fn lookup_full(&self, message_id: &str) -> Option<(MessageOrigin, String)> {
        self.state
            .read()
            .expect("trace rwlock poisoned")
            .entries
            .get(message_id)
            .map(|e| (e.origin.clone(), e.recipient.clone()))
    }

    /// Evict entries whose `recorded_at + ttl < now`. Returns the count
    /// evicted. `recorded_at` is host-stamped so the only skew risk is a
    /// host clock jump (accepted).
    pub fn gc(&self, now: SystemTime, ttl: Duration) -> usize {
        let mut st = self.state.write().expect("trace rwlock poisoned");
        let expired: Vec<(String, u64)> = st
            .entries
            .iter()
            .filter(|(_, e)| match e.recorded_at.checked_add(ttl) {
                Some(expiry) => expiry < now,
                // recorded_at + ttl overflowed SystemTime — treat as
                // far-future (never expires); unreachable with 7-day TTLs.
                None => false,
            })
            .map(|(id, e)| (id.clone(), e.seq))
            .collect();
        for (id, seq) in &expired {
            st.entries.remove(id);
            st.order.remove(seq);
        }
        expired.len()
    }

    pub fn len(&self) -> usize {
        self.state
            .read()
            .expect("trace rwlock poisoned")
            .entries
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
