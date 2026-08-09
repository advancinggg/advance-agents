//! L6 Step 5c emission seam + post-processor Step 9 `memory.l6_consolidation_due`.
//! MODULE-011 §1.3.6 step 5c / §2.7 "Slice D implementation seam".
//!
//! Slice C shipped `InMemoryEmitter` (captures payloads for trace/order/shape
//! assertions). Slice D adds the real `EventBusL6Emitter` — the §3.6 line-923
//! "L6Emitter→M019 EventBus" production-wiring closure under the already-
//! `passed` AC-15 (NOT a new AC; AC-15/AC-35 stay passed). `InMemoryEmitter`
//! is retained as the slice-B/C test double.

use std::sync::{Arc, Mutex};

use advance_shared_types::memory::KnowledgeHealthSnapshot;
use advance_shared_types::traits::EventBusEmit;

/// AC-35 `delta` block. Each field is a deterministic this-run count (see
/// MODULE-011 §3.8 note 4 — `entries_pruned ≡ 0` in slice C: the 6-step flow
/// has no entry-prune op).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L6Delta {
    pub clusters_merged: u32,
    pub entries_pruned: u32,
    pub syntheses_generated: u32,
    pub contested_clusters: u32,
    pub orphaned_entries: u32,
}

/// `memory.l6_completed` payload (≠ the CONTRACT-102 `L6Outcome` handler
/// return — distinct structs by design; they SHARE the one snapshot computed
/// at 5c — see §3.8 note 3).
///
/// Slice D adds the additive `lease_id` field (PRD §15.3.22-mandated on the
/// wire). `batch_id` stays an internal correlation field and is deliberately
/// NOT serialized onto the `EventBusL6Emitter` wire payload (§3.8 note 8).
///
/// **Defense-in-depth Debug redaction (round-16 adversarial fix):** the
/// `lease_id` field carries the RAW lease bearer token in-process
/// (`runnable.rs:472` sets it via `ctx.lease_token.clone()`); the wire payload
/// digests it via [`crate::events::l6_completed_event`], but the internal
/// struct keeps the raw value for the `InMemoryEmitter` test capture +
/// scheduler-channel correlation. This struct therefore ships a **manual**
/// `impl Debug` that redacts `lease_id` to `<redacted>`, mirroring
/// `shared-types::memory::L6Context`'s precedent (Slice AC v2 adv-fix R3).
/// `Debug` is NOT derived — any future `format!("{p:?}")` / `tracing::debug!
/// (payload=?p)` / panic message is safe (no raw bearer token in logs).
#[derive(Clone, PartialEq, Eq)]
pub struct L6CompletedPayload {
    pub agent_id: String,
    pub batch_id: String,
    pub lease_id: String,
    pub delta: L6Delta,
    pub snapshot: KnowledgeHealthSnapshot,
}

impl std::fmt::Debug for L6CompletedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L6CompletedPayload")
            .field("agent_id", &self.agent_id)
            .field("batch_id", &self.batch_id)
            .field("lease_id", &"<redacted>")
            .field("delta", &self.delta)
            .field("snapshot", &self.snapshot)
            .finish()
    }
}

pub trait L6Emitter: Send + Sync {
    /// Post-processor Step 9 hot-path trigger fan-out. `lease_id` is the live
    /// lease token (PRD §15.4 `memory.l6_consolidation_due {agent_id,
    /// lease_id}`).
    fn emit_consolidation_due(&self, agent_id: &str, lease_id: &str);
    /// L6 Step 5c completion event.
    fn emit_l6_completed(&self, payload: L6CompletedPayload);
    /// L6 Step 5c skill-candidate generation event (slice wave6-laneB,
    /// `skill.candidate_generated`). DEFAULT no-op so existing `L6Emitter` impls /
    /// test doubles are unaffected; `InMemoryEmitter` overrides it to capture for
    /// assertions, `EventBusL6Emitter` to fire the canonical event on the bus.
    fn emit_skill_candidate_generated(
        &self,
        _agent_id: &str,
        _candidate_id: &str,
        _skill_name: &str,
    ) {
    }
}

/// Slice-B/C test double: captures emitted payloads for assertions. The
/// `consolidation_due()` getter intentionally records only `agent_id` (the
/// slice-C `integration_l6.rs` contract asserts `vec!["agent:r"]`); the
/// `lease_id` arg is accepted but not recorded here.
#[derive(Default)]
pub struct InMemoryEmitter {
    consolidation_due: Mutex<Vec<String>>,
    l6_completed: Mutex<Vec<L6CompletedPayload>>,
    /// (agent_id, candidate_id, skill_name) per captured `skill.candidate_generated`.
    skill_candidates: Mutex<Vec<(String, String, String)>>,
}

impl InMemoryEmitter {
    pub fn new() -> Self {
        Self {
            consolidation_due: Mutex::new(Vec::new()),
            l6_completed: Mutex::new(Vec::new()),
            skill_candidates: Mutex::new(Vec::new()),
        }
    }

    pub fn consolidation_due(&self) -> Vec<String> {
        self.consolidation_due
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn emitted_l6_completed(&self) -> Vec<L6CompletedPayload> {
        self.l6_completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Captured `skill.candidate_generated` events as (agent_id, candidate_id,
    /// skill_name) tuples (slice wave6-laneB).
    pub fn emitted_skill_candidates(&self) -> Vec<(String, String, String)> {
        self.skill_candidates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl L6Emitter for InMemoryEmitter {
    fn emit_consolidation_due(&self, agent_id: &str, _lease_id: &str) {
        self.consolidation_due
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(agent_id.to_string());
    }

    fn emit_l6_completed(&self, payload: L6CompletedPayload) {
        self.l6_completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(payload);
    }

    fn emit_skill_candidate_generated(&self, agent_id: &str, candidate_id: &str, skill_name: &str) {
        self.skill_candidates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((
                agent_id.to_string(),
                candidate_id.to_string(),
                skill_name.to_string(),
            ));
    }
}

impl std::fmt::Debug for InMemoryEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let due = self.consolidation_due.lock().map(|v| v.len()).unwrap_or(0);
        let done = self.l6_completed.lock().map(|v| v.len()).unwrap_or(0);
        let cands = self.skill_candidates.lock().map(|v| v.len()).unwrap_or(0);
        f.debug_struct("InMemoryEmitter")
            .field("consolidation_due", &due)
            .field("l6_completed", &done)
            .field("skill_candidates", &cands)
            .finish()
    }
}

/// Slice D — the real MODULE-019 EventBus-backed `L6Emitter` (CONTRACT-180
/// consumed, not modified). Translates the two L6 seam calls into canonical
/// PRD events via `crate::events` and fires them on the bus. This is the
/// §3.6 line-923 "L6Emitter→M019 EventBus" production-wiring closure.
pub struct EventBusL6Emitter {
    bus: Arc<dyn EventBusEmit + Send + Sync>,
}

impl EventBusL6Emitter {
    pub fn new(bus: Arc<dyn EventBusEmit + Send + Sync>) -> Self {
        Self { bus }
    }
}

impl L6Emitter for EventBusL6Emitter {
    fn emit_consolidation_due(&self, agent_id: &str, lease_id: &str) {
        self.bus.emit(crate::events::l6_consolidation_due_event(
            agent_id, lease_id,
        ));
    }

    fn emit_l6_completed(&self, payload: L6CompletedPayload) {
        self.bus.emit(crate::events::l6_completed_event(&payload));
    }

    fn emit_skill_candidate_generated(&self, agent_id: &str, candidate_id: &str, skill_name: &str) {
        self.bus
            .emit(crate::events::skill_candidate_generated_event(
                agent_id,
                candidate_id,
                skill_name,
            ));
    }
}

impl std::fmt::Debug for EventBusL6Emitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBusL6Emitter")
            .field("bus", &"<EventBusEmit>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::event::Event;

    fn snap() -> KnowledgeHealthSnapshot {
        KnowledgeHealthSnapshot {
            total_active: 1,
            active: 1,
            contested: 0,
            orphaned: 0,
            forgotten: 0,
            superseded: 0,
            partial_stale: 0,
            zero_access_30d: 0,
            clusters_total: 0,
            clusters_contested: 0,
        }
    }

    fn payload() -> L6CompletedPayload {
        L6CompletedPayload {
            agent_id: "agent:a".into(),
            batch_id: "b0c1d2e3".into(),
            lease_id: "lease-x".into(),
            delta: L6Delta {
                clusters_merged: 1,
                entries_pruned: 0,
                syntheses_generated: 1,
                contested_clusters: 0,
                orphaned_entries: 0,
            },
            snapshot: snap(),
        }
    }

    #[test]
    fn in_memory_captures_both_events() {
        let e = InMemoryEmitter::new();
        e.emit_consolidation_due("agent:a", "lease-x");
        e.emit_l6_completed(payload());
        assert_eq!(e.consolidation_due(), vec!["agent:a"]);
        let done = e.emitted_l6_completed();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].delta.entries_pruned, 0);
        assert_eq!(done[0].batch_id, "b0c1d2e3");
        assert_eq!(done[0].lease_id, "lease-x");
    }

    #[derive(Default)]
    struct RecBus {
        events: Mutex<Vec<Event>>,
    }
    impl EventBusEmit for RecBus {
        fn emit(&self, ev: Event) {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ev);
        }
    }

    #[test]
    fn eventbus_l6_emitter_wire_shape() {
        let bus = Arc::new(RecBus::default());
        let em = EventBusL6Emitter::new(bus.clone());
        em.emit_consolidation_due("agent:a", "lease-x");
        em.emit_l6_completed(payload());
        let evs = bus
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(evs.len(), 2);

        assert_eq!(evs[0].event_type, "memory.l6_consolidation_due");
        assert_eq!(evs[0].agent_id, "agent:a");
        // Exactly {agent_id, lease_id} — PRD §15.4.
        let p0 = evs[0].payload.as_object().unwrap();
        assert_eq!(p0.len(), 2);
        assert_eq!(p0["agent_id"], "agent:a");
        // lease_id is the NON-SECRET digest of the token, never the raw bearer
        // secret (§3.8 note 8) — deterministic + correlates both events.
        assert_ne!(
            p0["lease_id"], "lease-x",
            "raw lease bearer token MUST NOT be on the wire"
        );
        assert_eq!(p0["lease_id"], crate::events::lease_id_digest("lease-x"));

        assert_eq!(evs[1].event_type, "memory.l6_completed");
        // Exactly {agent_id, lease_id, delta, snapshot} — PRD §15.3.22.
        // `batch_id` is internal and MUST NOT appear on the wire (§3.8 note 8).
        let p1 = evs[1].payload.as_object().unwrap();
        let mut keys: Vec<&String> = p1.keys().collect();
        keys.sort();
        assert_eq!(keys, vec!["agent_id", "delta", "lease_id", "snapshot"]);
        assert!(p1.get("batch_id").is_none());
        assert_ne!(
            p1["lease_id"], "lease-x",
            "raw lease bearer token MUST NOT be on the wire"
        );
        assert_eq!(p1["lease_id"], crate::events::lease_id_digest("lease-x"));
        assert_eq!(
            p1["lease_id"], p0["lease_id"],
            "same lease ⇒ same digest (consolidation_due↔completed correlation preserved)"
        );
        assert_eq!(p1["delta"].as_object().unwrap().len(), 5);
        assert_eq!(p1["snapshot"].as_object().unwrap().len(), 10);
    }
}
