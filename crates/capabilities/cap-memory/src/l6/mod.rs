//! MODULE-011 Slice C — L6 cross-task consolidation.
//!
//! The 6-step background runnable (§1.3.6) + post-processor Step 9 hot-path
//! trigger/lease. All seams are cap-memory-internal (NOT promoted to
//! `shared-types`, NOT in ARCHITECTURE §6.1) — same posture as the Slice B
//! `BatchExtractor`/`SimilarityIndex`/`Clock` seams. `L6ClusterBuilder` is a
//! self-contained pure-compute struct (NOT a trait, NOT dependent on
//! `reconcile::SimilarityIndex`). In-memory backing (on-disk persistence +
//! production M002/M003/M009/M019 wiring are `waived_scope` — see
//! MODULE-011 §3.6).

pub mod batch_id;
pub mod classifier;
pub mod cluster;
pub mod commit;
pub mod cursor;
pub mod emit;
pub mod health_snapshot;
pub mod knowledge_map;
pub mod lease;
pub mod runnable;
pub mod skill_health;
pub mod stale;
pub mod synthesis;
pub mod trigger;

pub use batch_id::{BatchIdSource, FixedBatchIdSource, UuidBatchIdSource};
pub use classifier::{
    ClusterClassification, L6ClassificationInput, L6ClassificationOutput, L6Classifier,
    SkillHealthEntry, StubL6Classifier, TaskRef, TaskSummary, MAX_CLUSTERS, MAX_STALE_ENTRIES,
    MAX_TASK_EXTRACTS,
};
pub use cluster::{ClusterAssignment, L6ClusterBuilder, DEFAULT_CLUSTER_THRESHOLD};
pub use commit::{
    CommitFile, ContentKind, FailingCommitter, InMemoryCommitter, L6CommitError, L6Committer,
    RecordedCommit,
};
pub use cursor::L6CursorStore;
pub use emit::{EventBusL6Emitter, InMemoryEmitter, L6CompletedPayload, L6Delta, L6Emitter};
pub use health_snapshot::{
    compute_health_snapshot, list_contested, list_orphaned, list_partial_stale,
};
pub use knowledge_map::{
    KnowledgeMap, KnowledgeMapError, KnowledgeMapTaskSynthesis, KnowledgeMapTopic, TOKEN_BUDGET,
};
pub use lease::{
    InMemoryLeaseStore, LeaseDecision, LeaseState, LeaseStore, DEFAULT_LEASE_TTL_SECS,
};
pub use runnable::{ComponentFinished, L6Runnable, L6_CANONICAL_STEPS, L6_LEASE_TTL};
pub use skill_health::{
    SkillHealthFile, SkillHealthWriteError, SkillHealthWriter, SkillHealthYamlEntry,
    SKILL_HEALTH_FILENAME,
};
pub use stale::{
    run_stale_detection, FileBlobResolver, InMemoryStalenessProbe, ResolverStalenessProbe,
    StaleDetectionReport, StaleStateSnapshot, StalenessJudgment, StalenessProbe,
};
pub use synthesis::{
    should_synthesize, StubSynthesisGenerator, Synthesis, SynthesisGate, SynthesisGateResult,
    SynthesisGenerator, SynthesisInput, MAX_SYNTHESES,
};
pub use trigger::{
    L6TriggerEvaluator, L6TriggerInput, L6TriggerState, L6TriggerThresholds, TriggerCond,
    TriggerOutcome,
};
