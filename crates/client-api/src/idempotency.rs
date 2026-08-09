//! CONTRACT-190 — idempotency records for mutating operations (§1.4.1, §2.11).
//!
//! Scope is `(session principal, method, resource family, idempotency-key)` with a 24h TTL for
//! recorded outcomes. A replay inside the window returns the recorded outcome (the original
//! `request_id` echoed in a warning) and **never re-executes**.
//!
//! **Reserve-before-execute + guard-only release (unconditional exactly-once)**: `begin`
//! atomically inserts a *pending* marker under a single lock before the handler runs, so a
//! concurrent same-scope retry gets `InProgress`. A live `Pending` is released **only** by its
//! [`Reservation`] guard — on `commit` (→ recorded outcome) or on `Drop` (handler error/panic →
//! the key is retryable). A pending marker is **never reclaimed by age**, so a concurrent retry
//! of an in-flight operation *always* sees `InProgress` — there is no timeout window in which a
//! second execution could slip through. For this in-memory store the guard always drops on scope
//! exit (normal return, error, or caught panic), so a reservation is never leaked; a process
//! crash discards the whole store, so there is nothing to reclaim. Recorded (`Done`) outcomes are
//! bounded by `cap` (oldest evicted) and by the 24h TTL; live reservations are bounded by the
//! number of concurrent in-flight requests (each guard releases when its request completes).
//!
//! Each reservation carries a unique identity token, so `commit`/`Drop` only act when the slot is
//! still *this* reservation — defensive belt-and-suspenders that also documents intent.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::envelope::{ClientError, ClientWarning};
use crate::request::Method;

/// The idempotency key scope. Two mutations dedupe only when all four components match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyScope {
    pub principal: String,
    pub method: Method,
    pub family: String,
    pub key: String,
}

/// A recorded successful outcome (only successes are recorded; failures release the reservation).
/// `Debug` redacts `data` — a recorded outcome is a response body (§2.14 never-log field).
#[derive(Clone)]
pub struct IdempotencyRecord {
    pub outcome: IdempotencyOutcome,
    pub original_request_id: String,
    pub warnings: Vec<ClientWarning>,
}

#[derive(Clone)]
pub enum IdempotencyOutcome {
    Success(serde_json::Value),
    Error(ClientError),
}

impl std::fmt::Debug for IdempotencyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdempotencyRecord")
            .field("original_request_id", &self.original_request_id)
            .field("outcome", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
enum Entry {
    Pending {
        token: u64,
        request_fingerprint: [u8; 32],
    },
    Done {
        record: IdempotencyRecord,
        stored_at: u64,
        request_fingerprint: [u8; 32],
    },
}

#[derive(Debug)]
struct Inner {
    map: Mutex<HashMap<IdempotencyScope, Entry>>,
    ttl_ms: u64,
    cap: usize,
    next_token: AtomicU64,
}

/// The result of [`IdempotencyStore::begin`].
pub enum Begin {
    /// Caller reserved the slot and must run the handler, then `commit` or drop the guard.
    Reserved(Reservation),
    /// A recorded outcome exists inside the TTL; return it without re-executing.
    Replay(IdempotencyRecord),
    /// Another caller holds a live reservation for this scope; return a retryable error.
    InProgress,
    /// The same idempotency scope was already used for a different canonical request.
    Conflict,
}

/// TTL-bound, bounded idempotency store (CONTRACT-190).
#[derive(Clone)]
pub struct IdempotencyStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for IdempotencyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdempotencyStore")
            .field("records", &self.len())
            .finish()
    }
}

impl IdempotencyStore {
    pub fn new(ttl_ms: u64, cap: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                map: Mutex::new(HashMap::new()),
                ttl_ms,
                cap: cap.max(1),
                next_token: AtomicU64::new(1),
            }),
        }
    }

    /// Reserve-or-replay for `scope` at time `now`. Atomic under a single lock acquisition.
    pub fn begin(&self, scope: &IdempotencyScope, now: u64) -> Begin {
        self.begin_fingerprinted(scope, [0; 32], now)
    }

    /// Reserve-or-replay with an exact canonical request fingerprint.  A reused key with a
    /// different route, target, API version, or typed body is a conflict in every phase and can
    /// never replay the first request's result.
    pub fn begin_fingerprinted(
        &self,
        scope: &IdempotencyScope,
        request_fingerprint: [u8; 32],
        now: u64,
    ) -> Begin {
        let mut map = self.inner.map.lock().expect("idempotency map lock");
        Self::evict_expired_done(&mut map, now, self.inner.ttl_ms);

        match map.get(scope) {
            Some(Entry::Pending {
                request_fingerprint: existing,
                ..
            }) if existing != &request_fingerprint => return Begin::Conflict,
            // A live reservation → never a second execution, regardless of how long it has run.
            Some(Entry::Pending { .. }) => return Begin::InProgress,
            Some(Entry::Done {
                request_fingerprint: existing,
                ..
            }) if existing != &request_fingerprint => return Begin::Conflict,
            Some(Entry::Done {
                record, stored_at, ..
            }) if now.saturating_sub(*stored_at) < self.inner.ttl_ms => {
                return Begin::Replay(record.clone());
            }
            _ => {}
        }

        // Make room among recorded outcomes if at capacity — NEVER evict a live `Pending` (that
        // would let a concurrent retry double-execute). Live reservations are bounded by the
        // number of concurrent in-flight requests.
        if !map.contains_key(scope) && map.len() >= self.inner.cap {
            evict_oldest_done(&mut map, None);
        }
        let token = self.inner.next_token.fetch_add(1, Ordering::SeqCst);
        map.insert(
            scope.clone(),
            Entry::Pending {
                token,
                request_fingerprint,
            },
        );
        Begin::Reserved(Reservation {
            inner: self.inner.clone(),
            scope: scope.clone(),
            token,
            committed: false,
        })
    }

    /// Evict `Done` records past the TTL. Live `Pending` are retained (released only by guards).
    fn evict_expired_done(map: &mut HashMap<IdempotencyScope, Entry>, now: u64, ttl: u64) {
        map.retain(|_, e| match e {
            Entry::Done { stored_at, .. } => now.saturating_sub(*stored_at) < ttl,
            Entry::Pending { .. } => true,
        });
    }

    /// Number of retained records (test/introspection helper).
    pub fn len(&self) -> usize {
        self.inner.map.lock().expect("idempotency map lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// RAII reservation guard. Dropping it without [`Reservation::commit`] releases the pending
/// marker (the abort/rollback path), so a failed or panicking handler leaves the key retryable.
/// Both `commit` and `Drop` are identity-checked (token) so they only ever act on this
/// reservation's own slot.
pub struct Reservation {
    inner: Arc<Inner>,
    scope: IdempotencyScope,
    token: u64,
    committed: bool,
}

impl Reservation {
    /// Retain the live marker for deterministic provider recovery. This consumes the guard without
    /// deleting or committing its entry, so every retry observes `InProgress` until recovery owns
    /// the transition to a terminal record.
    pub fn retain(mut self) {
        self.committed = true;
    }

    /// Finalize with a successful outcome (replayable for the TTL window). No-op if this
    /// reservation no longer owns the slot.
    pub fn commit(self, data: serde_json::Value, original_request_id: String, now: u64) {
        self.commit_with_warnings(data, original_request_id, Vec::new(), now);
    }

    /// Finalize with a successful outcome and its exact client-safe warnings.
    pub fn commit_with_warnings(
        self,
        data: serde_json::Value,
        original_request_id: String,
        warnings: Vec<ClientWarning>,
        now: u64,
    ) {
        self.commit_outcome(
            IdempotencyOutcome::Success(data),
            original_request_id,
            warnings,
            now,
        );
    }

    /// Finalize a provider-entered failure. Once the provider boundary has been crossed, the
    /// exact projected error is terminal for this key/fingerprint and must replay without
    /// entering the provider again.
    pub fn commit_error(
        self,
        error: ClientError,
        original_request_id: String,
        warnings: Vec<ClientWarning>,
        now: u64,
    ) {
        self.commit_outcome(
            IdempotencyOutcome::Error(error),
            original_request_id,
            warnings,
            now,
        );
    }

    fn commit_outcome(
        mut self,
        outcome: IdempotencyOutcome,
        original_request_id: String,
        warnings: Vec<ClientWarning>,
        now: u64,
    ) {
        if let Ok(mut map) = self.inner.map.lock() {
            let owns = matches!(map.get(&self.scope), Some(Entry::Pending { token, .. }) if *token == self.token);
            if owns {
                let request_fingerprint = match map.get(&self.scope) {
                    Some(Entry::Pending {
                        request_fingerprint,
                        ..
                    }) => *request_fingerprint,
                    _ => return,
                };
                map.insert(
                    self.scope.clone(),
                    Entry::Done {
                        record: IdempotencyRecord {
                            outcome,
                            original_request_id,
                            warnings,
                        },
                        stored_at: now,
                        request_fingerprint,
                    },
                );
                // Restore the cap: live `Pending` may have pushed the map over `cap` while this
                // op ran; now that it is `Done`, trim old `Done` records back down — but NEVER
                // this scope's just-committed record (so an immediate retry still replays it),
                // and never a live `Pending`.
                while map.len() > self.inner.cap && evict_oldest_done(&mut map, Some(&self.scope)) {
                }
            }
        }
        self.committed = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Ok(mut map) = self.inner.map.lock() {
            // Only remove if the slot is still *our* pending marker (token identity).
            let owns = matches!(map.get(&self.scope), Some(Entry::Pending { token, .. }) if *token == self.token);
            if owns {
                map.remove(&self.scope);
            }
        }
    }
}

/// Evict the oldest `Done` record (never a live `Pending`, never `except`). Returns `true` if one
/// was removed.
fn evict_oldest_done(
    map: &mut HashMap<IdempotencyScope, Entry>,
    except: Option<&IdempotencyScope>,
) -> bool {
    if let Some(oldest) = map
        .iter()
        .filter_map(|(k, e)| match e {
            Entry::Done { stored_at, .. } if Some(k) != except => Some((k.clone(), *stored_at)),
            _ => None,
        })
        .min_by_key(|(_, ts)| *ts)
        .map(|(k, _)| k)
    {
        map.remove(&oldest);
        true
    } else {
        false
    }
}
