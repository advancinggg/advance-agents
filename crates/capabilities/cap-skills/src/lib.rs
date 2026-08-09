//! MODULE-017 cap-skills crate.
//!
//! Slice A (2026-05-11) shipped the foundation skeleton: in-memory
//! `SkillStore` with 6-of-8 canonical `agent-skills` WIT methods (per
//! MODULE-017 §1.3.1) + 4 read accessors, all synchronous.
//!
//! Slice C (2026-05-15) consolidates the state machine — see the §3.7
//! Change History entry for the full delta. New surfaces:
//! - `security_scan` module — all 6 §1.3.2 checks.
//! - `SkillError` extended from 4 to 10 variants + `to_wit_variant`
//!   projection helper (§2.8 Rust ↔ WIT mapping table).

pub use error::{SkillError, WitSkillError};
pub use lifecycle::{
    CandidateAction, CandidateResult, Draft, LiveSnapshot, Skill, SkillCandidate, SkillStore,
};

/// Slice C — `Provenance` + `TrustLevel` re-exported from `advance_shared_types`
/// for ergonomic consumer use without the cross-crate import.
pub use advance_shared_types::skills::{Provenance, TrustLevel};

mod error;
mod lifecycle;

/// Slice C — `activate-skill` security scan per §1.3.2.
pub mod security_scan;

/// Slice C — `SkillStorage` trait + InMemory + Disk impls.
pub mod persistence;

/// Slice C — `SkillStoreProvider` trait + single-agent impl for host_fn wiring.
pub mod provider;

/// Slice C — `register_agent_skills` + 8 HostFunctionHandler structs.
pub mod host_fn;

pub use host_fn::{
    register_agent_skills, register_agent_skills_with_lifecycle,
    register_agent_skills_with_turn_runtime,
};

/// Slice E — `SkillBundle` multi-file skill representation + `BundleMeta`
/// YAML sidecar + `McpImportSpec` JSON descriptor.
pub mod skill_bundle;

/// Slice E — `AdminPoolStorage` operator-owned bundle library (PRD
/// §12.4.3 convention `/.advance/skills/`).
pub mod admin_pool;

/// Slice E — `materialize_skill(name, from_admin, to_agent)` library fn.
pub mod materialize;

/// Slice E — `SkillImporter` Path A library API (knowledge-only).
pub mod import;

pub use admin_pool::AdminPoolStorage;
pub use import::SkillImporter;
pub use materialize::materialize_skill;
pub use persistence::SkillSidecar;
pub use security_scan::validate_skill_filename;
pub use skill_bundle::{McpImportSpec, SkillBundle};

/// Slice H (REQ-275 foundation) — persistence-phase coordinator (library API).
/// Wave-10 Lane C (076/077) wires `activate-skill` / `rollback-skill` host-fns
/// through it (`register_agent_skills_with_lifecycle`) for the agent turn lane.
pub mod persistence_phase;

pub use persistence_phase::{
    Activated, Deleted, Initiator, RolledBack, SkillPersistenceCoordinator,
    SkillPreActivationObserver,
};

/// Wave-20 (build-only) — `SkillTurnPersistenceDriver`: the MODULE-014 turn-end
/// seam wrapping the per-op coordinator with AC-22 legs (b) flush-retry +
/// (c) commit-failure compensation (activate/rollback). AC-22 held untested
/// (§3.6 (ccc)).
pub mod turn_persistence;

pub use turn_persistence::{
    PendingSkillOp, RuntimePrivateFlush, SkillTurnPersistenceDriver, StoreDraftFlush, TurnSkillOp,
};

pub mod turn_runtime;

pub use turn_runtime::{
    CapMemorySkillHealthFlush, NoopSkillHealthFlush, SkillHealthFlush, SkillTurnRuntime,
};

/// Slice V1-c — `SKILL.md` first-paragraph summary extractor for L0
/// progressive-skill injection (AC-27 / REQ-264).
pub mod summary;

pub use summary::{extract_skill_summary, MAX_SKILL_SUMMARY_TOKENS};
