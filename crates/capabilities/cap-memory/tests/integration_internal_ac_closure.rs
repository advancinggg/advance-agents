//! MODULE-011 Slice E — Memory internal AC closure (m011-slice-e).
//!
//! In-scope ACs verified by this file:
//! - **MODULE-011-AC-20** (REQ-228): L3 epoch trigger compute (cap-memory side).
//!   Cross-validated here against the unit-test boundary table in
//!   `turn_index.rs::tests`. The "injects task-local enhancements" clause of
//!   AC-20 (§1.4 line 375) is **context-engine (MODULE-010) territory** —
//!   cap-memory provides the trigger primitive only. Same partition pattern
//!   as AC-25 below.
//!
//! - **MODULE-011-AC-25** (REQ-212): 6-category storage classification per
//!   **PRD §11.1.1**. PRD enumerates 6 categories: identity / skills /
//!   knowledge / preferences / task-summary / raw-turns. cap-memory owns
//!   **3 of 6** (knowledge / preferences / task-summary). The other **3** live
//!   in different modules / runtime paths:
//!   - **identity** → `AGENTS.md` write path: owned by **MODULE-005**
//!     (agent-tree-lifecycle, PRD §9.5 + PRD §11.1.1) + runtime/cli scaffolding;
//!     cap-memory has no role in `AGENTS.md` content management.
//!   - **skills** → `SKILL.md` + `.agent/skills/` write path: owned by
//!     **MODULE-017** (skills-tools-mcp, **PRD §12.2-§12.4**) — `agent-skills`
//!     WIT host fns + the import + dual-layer (admin pool + agent-local)
//!     storage; cap-memory has no role in skill content management.
//!   - **raw-turns** → `llm-turns.jsonl` append: owned by the **runtime**
//!     (PRD §11.2 + PRD §11.1.1 line 3831 "runtime 自动追加"); an append-only
//!     audit log written automatically by the runtime, NOT a cap-memory
//!     pipeline output. cap-memory only **references** it via the
//!     `TurnEntry.log_offset` cursor (§1.3.4).
//!
//!   AC-25's §1.4 verification verb is **`code audit`**. The audit deliverable
//!   is THIS file's module-level rustdoc + per-test prose citing PRD §11.1.1 +
//!   MODULE-005 §9.5 + PRD §12.2-§12.4 verbatim. The in-test body exercises the
//!   3 in-crate write-paths as defense-in-depth and observes lifecycle
//!   distinctness via PUBLIC `MemoryStore` API only (no private-field access).
//!
//!   **Boundary partition note**: this is a PRD §11.1.1 *architecture* boundary
//!   (which module owns which file), NOT analogous to slice-D §3.8 note 10's
//!   "seam-wired vs runtime-assembled" *lifecycle* boundary — see §3.8 note 11.
//!
//! Tests for AC-23 (Freshness query-time compute) live in `knowledge.rs::tests`;
//! tests for AC-28 (L4 update-frequency gating) live in `summary.rs::tests`.
//! Both are pure-unit-test concerns; only AC-20 + AC-25 land in this
//! integration file.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use cap_memory::knowledge::{MemoryEntry, MemoryStatus, MemoryType};
use cap_memory::store::MemoryStore;
use cap_memory::summary::{Summary, SummaryMeta};
use cap_memory::turn_index::TurnIndex;

// ───────────────────────────── AC-20 (REQ-228) ─────────────────────────────
//
// Cross-validation of the L3 epoch trigger compute primitive. The unit-test
// boundary table in `turn_index.rs::tests` already covers exact 20-turn /
// 7200-second inclusivity + either-of semantics. This integration-level test
// validates the public API surface (`TurnIndex::should_trigger_epoch` is
// reachable from outside the crate) and re-documents the "L3 injection lives
// in MODULE-010 context-engine, NOT cap-memory" partition.

#[test]
fn ac20_epoch_trigger_public_api_reachable_and_partitioned() {
    // The trigger primitive is the cap-memory deliverable for AC-20.
    // §1.4 line 375 also calls for "injects task-local enhancements" — that
    // clause is partitioned out to MODULE-010 context-engine (L3 epoch
    // payload assembly + LLM-context injection). cap-memory's contribution
    // ends at this boolean trigger.
    assert!(!TurnIndex::should_trigger_epoch(0, Duration::ZERO));
    assert!(TurnIndex::should_trigger_epoch(20, Duration::ZERO));
    assert!(TurnIndex::should_trigger_epoch(
        0,
        Duration::from_secs(7200)
    ));
    assert!(TurnIndex::should_trigger_epoch(
        20,
        Duration::from_secs(7200)
    ));
    assert!(!TurnIndex::should_trigger_epoch(
        19,
        Duration::from_secs(7199)
    ));
}

// ───────────────────────────── AC-25 (REQ-212) ─────────────────────────────
//
// 6-category storage classification per PRD §11.1.1. cap-memory owns 3 of 6
// categories; the other 3 are documented as out-of-crate at the module-level
// rustdoc above. The test below exercises the 3 in-crate write paths via
// PUBLIC `MemoryStore` API only and observes lifecycle distinctness via
// `rollback_l6` (the journal-driven rollback affects ONLY entries inserted by
// `append_consolidated_preference`, never entries inserted by `insert`).

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

fn knowledge_fact(id: &str, agent: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: agent.into(),
        entry_type: MemoryType::Fact,
        content: "竞品A涨价15%因AI功能".into(),
        tags: vec!["knowledge".into()],
        created_at: "2026-03-23T10:00:00Z".into(),
        task_origin: Some("task-001".into()),
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

fn user_preference(id: &str, agent: &str, batch_tag: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: agent.into(),
        entry_type: MemoryType::UserPreference,
        content: "prefer concise summaries".into(),
        // `l6_batch:{id}` reserved tag carries AC-32's l6_batch_id (slice C
        // §3.8 note 1); the `append_consolidated_preference` retry-idempotency
        // guard checks for this tag prefix.
        tags: vec![batch_tag.into(), "topic-conciseness".into()],
        created_at: "2026-03-23T10:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

#[test]
fn ac25_three_in_crate_write_paths_lifecycle_distinctness() {
    // **6-category partition audit (PRD §11.1.1)**:
    //
    // | # | Category    | File              | Owning module          |
    // |---|-------------|-------------------|------------------------|
    // | 1 | identity    | AGENTS.md         | MODULE-005 / runtime   | ← out of crate
    // | 2 | skills      | SKILL.md          | MODULE-017 (PRD §12.2-§12.4) | ← out of crate
    // | 3 | knowledge   | knowledge.jsonl   | MODULE-011 / cap-memory | ← in crate
    // | 4 | preferences | knowledge.jsonl   | MODULE-011 / cap-memory | ← in crate (type=user-preference)
    // | 5 | task-summary| summary.yaml      | MODULE-011 / cap-memory | ← in crate
    // | 6 | raw-turns   | llm-turns.jsonl   | runtime audit log (PRD §11.2) | ← out of crate
    //
    // Rows 1, 2, 6 are NOT exercised here — they live in other modules. This
    // test exercises rows 3, 4, 5 via PUBLIC API only and asserts each
    // category takes a distinct write path / observes a distinct lifecycle.

    let store = Arc::new(MemoryStore::new());
    let agent = "agent:research";

    // ─── Category 3: knowledge (type=Fact, MemoryStore::insert) ───
    let _knowledge_id = store
        .insert(agent, knowledge_fact("k1", agent))
        .expect("knowledge fact inserts");

    // Pre-state: 1 active entry (the knowledge fact).
    assert_eq!(store.list(agent).len(), 1);

    // ─── Category 4: preferences (type=UserPreference, MemoryStore::append_consolidated_preference) ───
    let l6_commit_ts = t0();
    let _pref_id = store
        .append_consolidated_preference(
            agent,
            user_preference("p1", agent, "l6_batch:test-e"),
            l6_commit_ts,
        )
        .expect("preference appends + journals ConsolidatedPrefInsert");

    // After the preference append: 2 active entries.
    assert_eq!(store.list(agent).len(), 2);

    // ─── Category 5: task-summary (Summary, NOT via MemoryStore) ───
    //
    // The task-summary write path goes through the `Summary` struct +
    // serde_yml::to_string, NOT through `MemoryStore` at all. We construct
    // a Summary value here as the in-crate witness. A future MODULE-002 wire
    // would persist it to `.agent/memory/tasks/{task_id}/summary.yaml`; the
    // schema lives at MODULE-011 §1.3.3.
    let summary = Summary {
        meta: SummaryMeta {
            task_id: "task-001".into(),
            agent_id: agent.into(),
            title: "test".into(),
            status: "active".into(),
            profile: "research".into(),
            turns_total: 0,
            last_updated: "2026-03-23T10:00:00Z".into(),
            last_turn_at: "2026-03-23T10:00:00Z".into(),
            last_brief_update: 0,
            last_decisions_update: 0,
            last_state_update: 0,
        },
        brief: "test brief".into(),
        key_decisions: vec![],
        findings: vec![],
        open_questions: vec![],
        current_state: String::new(),
        errors_and_corrections: vec![],
        workflow: String::new(),
    };
    let yaml = serde_yml::to_string(&summary).expect("summary serializes to yaml");
    assert!(yaml.contains("task_id"));
    // The summary value did not affect the MemoryStore at all — distinct
    // write path verified.
    assert_eq!(store.list(agent).len(), 2);

    // ─── Lifecycle distinctness via PUBLIC API ───
    //
    // `MemoryStore::rollback_l6` reverse-replays journal entries where
    // `l6_commit_ts > before` (store.rs:560-606): for the
    // `ConsolidatedPrefInsert` journal action it removes the entry; for the
    // `ClusterId` action it restores the old cluster_id. The knowledge fact
    // was inserted via `insert` (no journal entry), so it is invisible to
    // `rollback_l6` and survives. The preference was inserted via
    // `append_consolidated_preference` (which journals a
    // `ConsolidatedPrefInsert`), so it is rolled back.
    //
    // CUTOFF: `before` must be strictly LESS than `l6_commit_ts` to select the
    // preference's journal entry for replay. We use
    // `l6_commit_ts - Duration::from_millis(1)`.
    let before = l6_commit_ts - Duration::from_millis(1);
    store.rollback_l6(agent, before).expect("rollback_l6 ok");

    // Post-rollback: only the knowledge fact remains. The preference was
    // removed by the journal-driven `rollback_l6`; the knowledge fact has
    // no journal entry and was untouched.
    let remaining = store.list(agent);
    assert_eq!(
        remaining.len(),
        1,
        "after rollback_l6, only the knowledge fact (no journal entry) should remain; got {} entries: {remaining:?}",
        remaining.len()
    );
    assert_eq!(remaining[0].id, "k1");
    assert_eq!(remaining[0].entry_type, MemoryType::Fact);
    assert!(
        !remaining
            .iter()
            .any(|e| matches!(e.entry_type, MemoryType::UserPreference)),
        "no UserPreference entry should survive rollback_l6"
    );
}

#[test]
fn ac25_summary_write_path_does_not_touch_memorystore() {
    // Defense-in-depth witness for the task-summary partition (category 5):
    // building a `Summary` value and serializing it does NOT mutate the
    // MemoryStore. The two write paths are physically separate.
    let store = Arc::new(MemoryStore::new());
    let agent = "agent:test";

    // Empty store baseline.
    assert_eq!(store.list(agent).len(), 0);

    // Build + serialize a Summary. (A future MODULE-002 wiring would persist
    // this to the workspace filesystem, but that's deferred per §3.6
    // "`summary.yaml`+`turn-index.yaml` on-disk write" row.)
    let summary = Summary {
        meta: SummaryMeta {
            task_id: "task-distinct".into(),
            agent_id: agent.into(),
            title: "title".into(),
            status: "active".into(),
            profile: "research".into(),
            turns_total: 5,
            last_updated: "2026-03-23T10:00:00Z".into(),
            last_turn_at: "2026-03-23T10:00:00Z".into(),
            last_brief_update: 3,
            last_decisions_update: 0,
            last_state_update: 0,
        },
        brief: "test".into(),
        key_decisions: vec![],
        findings: vec![],
        open_questions: vec![],
        current_state: String::new(),
        errors_and_corrections: vec![],
        workflow: String::new(),
    };
    let _yaml = serde_yml::to_string(&summary).expect("summary serializes");

    // Post-condition: store untouched.
    assert_eq!(store.list(agent).len(), 0);
}
