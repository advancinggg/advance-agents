//! cap-memory-internal `memory.*` observability event builders (MODULE-011
//! slice D; AC-37 / §2.7 "Slice D implementation seam").
//!
//! Canonical event names + payloads are PRD §15.3.12 (the 5 agent-memory WIT
//! host fns) and PRD §15.3.22 / §15.4 (the 2 L6 events). All builders consume
//! the MODULE-019 `EventBusEmit` contract (CONTRACT-180) — *consumed*, not
//! provided; this module is NOT promoted to `shared-types` / NOT in
//! ARCHITECTURE.md §6.1 (same posture as the slice B/C cap-memory-internal
//! seams).
//!
//! ## Envelope rules (mirrors the cap-fs / cap-llm `events.rs` precedent)
//! - `id` / `span_id` = `Uuid::new_v4()` (per-event)
//! - `timestamp`      = `Utc::now()` (via the `advance_shared_types::chrono`
//!                      re-export — NO direct chrono dep, no Cargo change)
//! - `agent_id`       = `ctx.agent_id`
//! - `task_id`        = `None`  (`HostCallContext` carries no task_id)
//! - `run_id`         = `ctx.run_id`
//! - `execution_id`   = `None`
//! - `trace_id`       = `ctx.trace_id`, falling back to `"none"` when empty
//! - `parent_span_id` = `None`
//! - `duration_ms`    = `None`
//!
//! ## Payload hygiene (Event Implementer Invariants 1 & 2)
//! - `content_preview` ≤ 64 chars, `query` ≤ 256 chars (char-boundary-safe,
//!   `…`-suffixed when truncated). A payload-amplification bound — NOT a
//!   secrets fix; `query`/`tags` are PRD-mandated + bounded at the WIT entry,
//!   and MODULE-019's pattern-based LeakDetector on the JSONL/WS output path
//!   is the defense-in-depth secret gate.
//! - Handlers emit on the **success arm only** (see §2.7 / §3.8 note 6).

use std::sync::Arc;

use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::chrono::Utc;
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use serde_json::json;
use uuid::Uuid;

use crate::l6::emit::L6CompletedPayload;

/// `memory.remember` event_type (PRD §15.3.12).
pub const MEMORY_REMEMBER: &str = "memory.remember";
/// `memory.recall` event_type (PRD §15.3.12).
pub const MEMORY_RECALL: &str = "memory.recall";
/// `memory.forget` event_type (PRD §15.3.12).
pub const MEMORY_FORGET: &str = "memory.forget";
/// `memory.recall_at` event_type (PRD §15.3.12).
pub const MEMORY_RECALL_AT: &str = "memory.recall_at";
/// `memory.rollback` event_type (PRD §15.3.12).
pub const MEMORY_ROLLBACK: &str = "memory.rollback";
/// `memory.l6_consolidation_due` event_type (PRD §15.4, Trigger-Bus
/// whitelisted).
pub const MEMORY_L6_CONSOLIDATION_DUE: &str = "memory.l6_consolidation_due";
/// `memory.l6_completed` event_type (PRD §15.3.22).
pub const MEMORY_L6_COMPLETED: &str = "memory.l6_completed";
/// `skill.candidate_generated` event_type (slice wave6-laneB; event-bus taxonomy
/// `skill.candidate_generated`). The L6 Step-5c skill-candidate generation event.
pub const SKILL_CANDIDATE_GENERATED: &str = "skill.candidate_generated";

/// `content_preview` cap (bytes-as-chars; see §3.8 note 6).
pub const MAX_CONTENT_PREVIEW_CHARS: usize = 64;
/// `query` preview cap (see §3.8 note 6).
pub const MAX_QUERY_PREVIEW_CHARS: usize = 256;
/// Max `tags` emitted on the `memory.remember` wire (see §3.8 note 6). Bounds
/// the event under Event-Invariant-2 / the MODULE-019 64 KiB `MAX_PAYLOAD_LEN`
/// even at the WIT entry max (256 tags × 256 B): emitting raw `tags` would let
/// a *valid* `remember` produce an event `validate_event_size` silently drops.
pub const MAX_TAGS_EMITTED: usize = 32;
/// Per-tag preview cap on the `memory.remember` wire (chars).
pub const MAX_TAG_PREVIEW_CHARS: usize = 64;

/// Char-boundary-safe truncation: keep at most `max` chars, append `…` if the
/// input was longer. Never splits a UTF-8 scalar.
pub fn preview(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            return out;
        }
        out.push(ch);
    }
    out
}

/// Bounded `tags` for the `memory.remember` wire payload: each tag
/// char-truncated to `MAX_TAG_PREVIEW_CHARS`, at most `MAX_TAGS_EMITTED`
/// elements, with a trailing `"…"` marker element when the input list was
/// longer (truncation stays observable, mirroring the scalar-`preview` `…`
/// convention). Guarantees the event fits the MODULE-019 64 KiB cap even at
/// the WIT entry max (`MAX_TAGS_COUNT`×`MAX_TAG_BYTES` = 256×256 = 64 KiB of
/// raw tags alone, which `validate_event_size` would silently drop).
fn bounded_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = tags
        .iter()
        .take(MAX_TAGS_EMITTED)
        .map(|t| preview(t, MAX_TAG_PREVIEW_CHARS))
        .collect();
    if tags.len() > MAX_TAGS_EMITTED {
        out.push("…".to_string());
    }
    out
}

fn trace_id_of(ctx: &HostCallContext) -> String {
    if ctx.trace_id.is_empty() {
        "none".to_string()
    } else {
        ctx.trace_id.clone()
    }
}

/// 12-field `Event` envelope from a WIT `HostCallContext`. Caller fills
/// `event_type` + `payload`.
fn envelope(ctx: &HostCallContext, event_type: &str, payload: serde_json::Value) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: ctx.agent_id.clone(),
        task_id: None,
        run_id: ctx.run_id.clone(),
        execution_id: None,
        trace_id: trace_id_of(ctx),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload,
        duration_ms: None,
    }
}

/// 12-field `Event` envelope WITHOUT a `HostCallContext` (the L6 background
/// path has no WIT ctx). `trace_id = "none"`, `run_id = None`.
fn bare_envelope(agent_id: &str, event_type: &str, payload: serde_json::Value) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "none".to_string(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload,
        duration_ms: None,
    }
}

/// `memory.remember` — PRD §15.3.12 `{agent_id, content_preview, tags}`.
pub fn memory_remember_event(ctx: &HostCallContext, content: &str, tags: &[String]) -> Event {
    let payload = json!({
        "agent_id": ctx.agent_id,
        "content_preview": preview(content, MAX_CONTENT_PREVIEW_CHARS),
        "tags": bounded_tags(tags),
    });
    envelope(ctx, MEMORY_REMEMBER, payload)
}

/// `memory.recall` — PRD §15.3.12 `{agent_id, query, result_count, top_score}`.
/// `top_score` is `null` (slice-B `MemoryEntry` carries no relevance score).
pub fn memory_recall_event(ctx: &HostCallContext, query: &str, result_count: usize) -> Event {
    let payload = json!({
        "agent_id": ctx.agent_id,
        "query": preview(query, MAX_QUERY_PREVIEW_CHARS),
        "result_count": result_count,
        "top_score": serde_json::Value::Null,
    });
    envelope(ctx, MEMORY_RECALL, payload)
}

/// `memory.forget` — PRD §15.3.12 `{agent_id, memory_id}`.
pub fn memory_forget_event(ctx: &HostCallContext, memory_id: &str) -> Event {
    let payload = json!({
        "agent_id": ctx.agent_id,
        "memory_id": memory_id,
    });
    envelope(ctx, MEMORY_FORGET, payload)
}

/// `memory.recall_at` — PRD §15.3.12 `{agent_id, query, timestamp, result_count}`.
pub fn memory_recall_at_event(
    ctx: &HostCallContext,
    query: &str,
    timestamp: &str,
    result_count: usize,
) -> Event {
    let payload = json!({
        "agent_id": ctx.agent_id,
        "query": preview(query, MAX_QUERY_PREVIEW_CHARS),
        "timestamp": timestamp,
        "result_count": result_count,
    });
    envelope(ctx, MEMORY_RECALL_AT, payload)
}

/// `memory.rollback` — PRD §15.3.12 `{agent_id, target_timestamp,
/// entries_deactivated}`. `entries_deactivated` is the exact atomic
/// dropped-entry count returned by `MemoryStore::rollback` (§3.8 note 7).
pub fn memory_rollback_event(
    ctx: &HostCallContext,
    target_timestamp: &str,
    entries_deactivated: usize,
) -> Event {
    let payload = json!({
        "agent_id": ctx.agent_id,
        "target_timestamp": target_timestamp,
        "entries_deactivated": entries_deactivated,
    });
    envelope(ctx, MEMORY_ROLLBACK, payload)
}

/// Non-secret, deterministic digest of the L6 lease bearer token for the
/// observability wire. The lease `token` is a token-checked **bearer
/// credential** (`LeaseStore::confirm_acquire` / `release`); shared-types
/// `L6Context` already mandates it be scrubbed from any serialized form
/// ("persistent storage MUST scrub the `lease_token` field at the JSON
/// layer"). The PRD `lease_id` field is a *correlation identifier* — it links
/// the `memory.l6_consolidation_due` → `memory.l6_completed` pair of one L6
/// batch; it does NOT need to be (and MUST NOT be) the raw bearer secret.
/// A stable digest preserves that correlation while keeping the secret off the
/// JSONL / SQLite / WS-broadcast wire.
///
/// The digest is **FNV-1a (64-bit)** — a fixed, published algorithm with
/// hard-coded offset-basis/prime constants, so its output is byte-identical
/// across **every** build, Rust release, and platform. This is deliberate and
/// stronger than the std `std::collections::hash_map::DefaultHasher`, whose
/// algorithm is explicitly "not specified, and … should not be relied upon
/// over releases" (std docs): the `lease_id` is a *persisted* correlation key
/// (JSONL / SQLite), so a `consolidation_due`↔`completed` pair must still
/// correlate when read back by a tool built from a different toolchain or
/// after a runtime upgrade — a non-stable hasher would silently break that.
/// Non-cryptographic (FNV-1a is not preimage-resistant) is acceptable: the
/// goal is secret-elision + stable correlation, not authentication. The
/// internal `ComponentFinished.lease_id` Step-6 release path is a *separate*
/// scheduler-delivered channel and is unaffected (it still carries the raw
/// token, token-checked by `LeaseStore::release`). See §3.8 note 8.
pub fn lease_id_digest(token: &str) -> String {
    // FNV-1a 64-bit (fixed published constants — wire-stable forever).
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET_BASIS;
    for byte in token.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("l6lease-{hash:016x}")
}

/// `memory.l6_consolidation_due` — PRD §15.4 `{agent_id, lease_id}`
/// (Trigger-Bus whitelisted). `lease_id` is the non-secret [`lease_id_digest`]
/// of the live lease token, NOT the raw bearer secret.
pub fn l6_consolidation_due_event(agent_id: &str, lease_id: &str) -> Event {
    let payload = json!({
        "agent_id": agent_id,
        "lease_id": lease_id_digest(lease_id),
    });
    bare_envelope(agent_id, MEMORY_L6_CONSOLIDATION_DUE, payload)
}

/// `memory.l6_completed` — PRD §15.3.22 `{agent_id, lease_id, delta, snapshot}`
/// **exactly**. `L6CompletedPayload.batch_id` is internal and is deliberately
/// NOT serialized onto the wire (§3.8 note 8).
pub fn l6_completed_event(p: &L6CompletedPayload) -> Event {
    let payload = json!({
        "agent_id": p.agent_id,
        "lease_id": lease_id_digest(&p.lease_id),
        "delta": {
            "clusters_merged": p.delta.clusters_merged,
            "entries_pruned": p.delta.entries_pruned,
            "syntheses_generated": p.delta.syntheses_generated,
            "contested_clusters": p.delta.contested_clusters,
            "orphaned_entries": p.delta.orphaned_entries,
        },
        "snapshot": {
            "total_active": p.snapshot.total_active,
            "active": p.snapshot.active,
            "contested": p.snapshot.contested,
            "orphaned": p.snapshot.orphaned,
            "forgotten": p.snapshot.forgotten,
            "superseded": p.snapshot.superseded,
            "partial_stale": p.snapshot.partial_stale,
            "zero_access_30d": p.snapshot.zero_access_30d,
            "clusters_total": p.snapshot.clusters_total,
            "clusters_contested": p.snapshot.clusters_contested,
        },
    });
    bare_envelope(&p.agent_id, MEMORY_L6_COMPLETED, payload)
}

/// `skill.candidate_generated` (slice wave6-laneB) — fired at L6 Step 5c when the
/// consolidation promotes a `skill_health` entry into a pending skill candidate.
/// Payload `{agent_id, candidate_id, skill_name}`: `candidate_id` is a non-secret
/// lowercase-hex sha256 (deterministic, bounded); `skill_name` is preview-bounded.
pub fn skill_candidate_generated_event(
    agent_id: &str,
    candidate_id: &str,
    skill_name: &str,
) -> Event {
    let payload = json!({
        "agent_id": agent_id,
        "candidate_id": candidate_id,
        "skill_name": preview(skill_name, MAX_CONTENT_PREVIEW_CHARS),
    });
    bare_envelope(agent_id, SKILL_CANDIDATE_GENERATED, payload)
}

/// Production null-object `EventBusEmit` — discards every event. Used as the
/// `Components::with_l6_defaults` default `event_bus` (keeps Slice B/C
/// pipeline contracts intact: those tests assert nothing on handler emits)
/// and is available to any caller that does not wire a real bus.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEventBus;

impl EventBusEmit for NoopEventBus {
    fn emit(&self, _event: Event) {}
}

/// Convenience: a `NoopEventBus` behind an `Arc<dyn EventBusEmit + Send + Sync>`.
pub fn noop_bus() -> Arc<dyn EventBusEmit + Send + Sync> {
    Arc::new(NoopEventBus)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(agent: &str) -> HostCallContext {
        HostCallContext {
            agent_id: agent.to_string(),
            trace_id: "trace-1".to_string(),
            turn_id: None,
            capability: "memory".to_string(),
            function: "advance:runtime/agent-memory::test".to_string(),
            run_id: None,
            iteration: None,
        }
    }

    #[test]
    fn preview_is_char_boundary_safe_and_suffixes() {
        assert_eq!(preview("abc", 8), "abc");
        assert_eq!(preview("abcdefgh", 4), "abcd…");
        // Multi-byte: never split a scalar.
        let s = "héllo wörld ☃ こんにちは";
        let p = preview(s, 5);
        assert!(p.ends_with('…'));
        assert_eq!(p.chars().count(), 6); // 5 + the … marker
    }

    #[test]
    fn remember_event_shape() {
        let e = memory_remember_event(&ctx("agent:a"), "x".repeat(200).as_str(), &["t1".into()]);
        assert_eq!(e.event_type, "memory.remember");
        assert_eq!(e.agent_id, "agent:a");
        assert_eq!(e.trace_id, "trace-1");
        assert!(e.task_id.is_none());
        let cp = e.payload["content_preview"].as_str().unwrap();
        assert!(cp.ends_with('…') && cp.chars().count() == MAX_CONTENT_PREVIEW_CHARS + 1);
        assert_eq!(e.payload["tags"], json!(["t1"]));
    }

    #[test]
    fn remember_tags_bounded_under_event_cap() {
        // Within bounds: passthrough, no marker.
        assert_eq!(
            bounded_tags(&["a".to_string(), "b".to_string()]),
            vec!["a".to_string(), "b".to_string()]
        );

        // Count overflow: capped to MAX_TAGS_EMITTED + a trailing `…` marker.
        let many: Vec<String> = (0..1000).map(|i| format!("tag{}", i)).collect();
        let b = bounded_tags(&many);
        assert_eq!(b.len(), MAX_TAGS_EMITTED + 1);
        assert_eq!(b.last().unwrap().as_str(), "…");

        // Per-tag overflow: char-truncated + `…`.
        let bt = bounded_tags(&["z".repeat(500)]);
        assert_eq!(bt.len(), 1);
        assert!(bt[0].ends_with('…'));
        assert_eq!(bt[0].chars().count(), MAX_TAG_PREVIEW_CHARS + 1);

        // The emitted `memory.remember` event stays well under the MODULE-019
        // 64 KiB MAX_PAYLOAD_LEN even at the WIT entry max (256 tags × 256 B),
        // which raw `tags` would exceed and get silently dropped by the bus.
        let wit_max: Vec<String> = (0..256).map(|_| "x".repeat(256)).collect();
        let ev = memory_remember_event(&ctx("agent:a"), "c", &wit_max);
        let serialized = serde_json::to_vec(&ev.payload).expect("payload serializes");
        assert!(
            serialized.len() < 64 * 1024,
            "bounded memory.remember payload must fit the 64 KiB bus cap, got {}",
            serialized.len()
        );
    }

    #[test]
    fn recall_event_top_score_null() {
        let e = memory_recall_event(&ctx("agent:a"), "q", 3);
        assert_eq!(e.event_type, "memory.recall");
        assert_eq!(e.payload["result_count"], json!(3));
        assert!(e.payload["top_score"].is_null());
    }

    #[test]
    fn empty_trace_id_falls_back_to_none() {
        let mut c = ctx("agent:a");
        c.trace_id = String::new();
        let e = memory_forget_event(&c, "m1");
        assert_eq!(e.trace_id, "none");
        assert_eq!(e.payload["memory_id"], json!("m1"));
    }

    #[test]
    fn noop_bus_discards() {
        let b = NoopEventBus;
        b.emit(memory_forget_event(&ctx("a"), "m"));
        // No panic, no state — the null object contract.
    }
}
