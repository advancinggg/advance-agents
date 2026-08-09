//! In-memory per-`agent_id` warning queue used by
//! [`crate::assembler::ContextAssemblerImpl::inject_tier3_warning`]
//! (CONTRACT-090) and drained by the next `assemble()` call for the same
//! agent_id into the Tier-3 segment of the assembled `Vec<LlmMessage>`.
//!
//! CONTRACT-090 invariant compliance:
//! - **Invariant 3 (bounded mutation)**: `VecDeque` + FIFO drop-oldest cap at
//!   [`MAX_QUEUE_LEN`] = 1024. The newest warning is the most actionable in
//!   the MODULE-008 RepetitionGuard WarnThenTerminate signal path; preserving
//!   it at the cost of older (stale) warnings keeps the load-bearing signal.
//! - **Invariant 4 (identifier validation)**: [`is_valid_agent_id`] mirrors
//!   `crates/run-manager/src/identifier.rs::validate_task_id` exactly
//!   (ASCII alphanumeric + `_-:.`, max 128 bytes). Path-traversal-shaped IDs
//!   (`../etc/passwd`), space-bearing IDs, semicolon-injection IDs are
//!   rejected at both push and drain.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;

/// CONTRACT-090 invariant 3 per-agent bound — "recommended ≤ 1024 entries"
/// per the trait rustdoc at `crates/shared-types/src/context.rs:121-123`.
pub const MAX_QUEUE_LEN: usize = 1024;

/// Mirrors `crates/run-manager/src/identifier.rs:28-29` 128-byte cap. NOT to
/// be confused with `AssemblyContext.model`'s 256-byte recommendation — that's
/// an LLM-model-identifier domain, not an agent-id domain.
pub const MAX_AGENT_ID_LEN: usize = 128;

/// CONTRACT-090 invariant 3 outer bound — caps the number of distinct
/// `agent_id` keys the queue can hold. Defense in depth against a buggy or
/// malicious caller cycling through distinct synthetic IDs to amplify the
/// underlying map's key cardinality. A typical deployment has ≤ a few
/// hundred active agents; 4096 leaves wide headroom while still bounding
/// the keyspace.
///
/// Backed by [`LruCache`]: when a new `agent_id` is pushed at cap, the
/// least-recently-touched agent_id is silently evicted (its pending
/// warnings are dropped). This closes the saturation-DoS finding from
/// AUDIT round 8: under earlier `HashMap`-based eviction-free behavior,
/// a flood of 4096 distinct synthetic valid-charset IDs could lock the
/// keyspace and silently deny subsequent legitimate WarnThenTerminate
/// signals until an `assemble()` drained the stale entries. LRU eviction
/// preserves availability for the most recently active set of agents,
/// which is the operationally-correct behavior given M008's call pattern
/// (active agents touch the queue frequently; stale synthetic IDs from a
/// hypothetical flood lose priority naturally).
pub const MAX_AGENT_KEYSPACE: usize = 4096;

/// Per-message defense-in-depth cap. Repetition warnings are short prose
/// (typically < 200 bytes); 4 KiB leaves room for verbose diagnostic strings
/// while bounding memory amplification under a buggy caller passing
/// megabyte-sized payloads. Oversized messages are TRUNCATED, not rejected —
/// the load-bearing repetition signal is preserved even when the message
/// body is degraded.
pub const MAX_WARNING_MSG_LEN: usize = 4096;

pub struct WarningQueue {
    inner: Mutex<LruCache<String, VecDeque<String>>>,
}

impl WarningQueue {
    pub fn new() -> Self {
        // SAFETY: MAX_AGENT_KEYSPACE is compile-time 4096 (non-zero).
        let cap =
            NonZeroUsize::new(MAX_AGENT_KEYSPACE).expect("MAX_AGENT_KEYSPACE must be non-zero");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Append `msg` to `agent_id`'s queue. Silently no-op when `agent_id`
    /// fails [`is_valid_agent_id`] (CONTRACT-090 invariant 4 fail-closed).
    /// When the outer-keyspace LRU is at [`MAX_AGENT_KEYSPACE`] AND
    /// `agent_id` is not already a key, the least-recently-touched agent_id
    /// is evicted to make room (CONTRACT-090 invariant 3 defense-in-depth
    /// outer bound, with availability-preserving LRU semantics — the most
    /// active agents always retain their queue). Evicts the OLDEST entry
    /// per agent when that agent's queue is at [`MAX_QUEUE_LEN`] (invariant 3
    /// per-agent bound; FIFO drop-oldest preserves the most-actionable
    /// repetition signal). Messages exceeding [`MAX_WARNING_MSG_LEN`] are
    /// truncated at a UTF-8 char boundary; the load-bearing repetition
    /// signal is preserved.
    pub fn push(&self, agent_id: &str, msg: &str) {
        if !is_valid_agent_id(agent_id) {
            return;
        }
        let mut cache = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let truncated = truncate_at_char_boundary(msg, MAX_WARNING_MSG_LEN);
        // LruCache::get_mut touches the LRU order. If the key exists, push to
        // its deque; otherwise, insert a new entry (which evicts the LRU
        // entry at cap — different from the prior fail-closed behavior).
        if let Some(q) = cache.get_mut(agent_id) {
            if q.len() >= MAX_QUEUE_LEN {
                q.pop_front();
            }
            q.push_back(truncated);
        } else {
            let mut q = VecDeque::new();
            q.push_back(truncated);
            cache.put(agent_id.to_string(), q);
        }
    }

    /// Remove and return every queued message for `agent_id` in FIFO order.
    /// Returns empty `Vec` for invalid `agent_id` (CONTRACT-090 invariant 4).
    pub fn drain(&self, agent_id: &str) -> Vec<String> {
        if !is_valid_agent_id(agent_id) {
            return Vec::new();
        }
        let mut cache = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        cache
            .pop(agent_id)
            .map(|d| d.into_iter().collect())
            .unwrap_or_default()
    }
}

impl Default for WarningQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Whitelist mirrors `crates/run-manager/src/identifier.rs::validate_task_id`
/// (M008's `validate_agent_id` delegates to it). Charset = ASCII alphanumeric
/// + `_-:.` (the `:` and `.` are load-bearing for REQ-069 `auto:{agent-id}`
/// and tenant-prefix patterns like `user:alice.smith`).
///
/// `pub(crate)` so [`crate::assembler::ContextAssemblerImpl::assemble`] can
/// reuse the same predicate for `AssemblyContext.agent_id` validation (per
/// CONTRACT-090 invariant 4: agent_id must be whitelist-validated by the
/// implementer — applies to BOTH `assemble` and `inject_tier3_warning`).
pub(crate) fn is_valid_agent_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_AGENT_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
}

/// Truncate `s` to at most `max_bytes` bytes WITHOUT splitting a UTF-8 char.
/// Returns an owned `String` (cheap when no truncation needed). When the input
/// is over-cap, walks backward from `max_bytes` to the nearest char boundary
/// to preserve valid UTF-8. Used by [`WarningQueue::push`] to enforce
/// [`MAX_WARNING_MSG_LEN`] (defense-in-depth against per-message size
/// amplification under a buggy caller).
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Find the largest char-boundary index ≤ max_bytes. `is_char_boundary`
    // is true at index 0 and at index s.len(); for any valid &str the loop
    // terminates at the first boundary at or below max_bytes.
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}
