//! AC-06 — 6-level context-processing coordination (§1.3.3 / §11.3.3 /
//! REQ-224).
//!
//! §1.4 AC-06: "6-level context processing coordination (L0 in this module,
//! L1-L6 in MODULE-011)".
//!
//! [`coordinate_processing`] is the COORDINATOR: it drives all six levels in
//! spec order for one assembly pass —
//! - **L0** in-module via [`crate::l0_compress::l0_compress`];
//! - **L1** vector retrieval via [`VectorIndexReader`];
//! - **L2** turn digests via [`L2DigestReader`];
//! - **L3** epoch summary via [`L3EpochReader`];
//! - **L4** task summary via [`L4TaskSummaryReader`];
//! - **L5** cross-task syntheses via [`L5SynthesisReader`];
//! - **L6** consolidated memory via [`L6ConsolidationReader`].
//!
//! The five L2–L6 readers + the L1 vector reader are crate-local (B1)
//! narrowings of CONTRACT-101 `MemoryStoreReader` surfaces (L1–L6 are owned by
//! MODULE-011 per the AC criterion). Invocation is **sequential / fail-fast**:
//! the first reader error short-circuits with the matching per-level
//! [`ProcessingError`] variant. No fan-out parallelism this slice (deterministic
//! order is the safer choice; a future optimization slice may parallelize if
//! benchmarks demand it).
//!
//! Non-wired scope (MODULE-010 §3.6 Slice-D (a)): the coordinator is exported +
//! integration-tested but NOT wired into `assemble()`'s live multi-source tier
//! population — the §1.3.5 multi-source history population is the deferred
//! history-load surface. AC-06's criterion is "coordination", satisfied by the
//! standalone orchestrator + the all-levels-invoked-in-order test (T07). This
//! is the Slice-C `UnifiedSearchCoordinator` / `rerank_by_retention` non-wired
//! precedent. Landing milestone: wired into `assemble()` when CONTRACT-101's
//! full `MemoryStoreReader` surface is hoisted to shared-types AND the §1.3.5
//! representation dimension lands (a coordinated M010+M011 slice).

use crate::l0_compress::{l0_compress, L0Entry};
use crate::ports::{
    L2DigestReader, L3EpochReader, L4TaskSummaryReader, L5SynthesisReader, L6ConsolidationReader,
    MultiLevelContextDigest, VectorIndexReader,
};

/// Per-level coordination error. The local control-flow error enum owned by
/// this module (NOT a `ports.rs` data carrier — MODULE-010 §4.1 carrier rule).
/// One variant per reader-backed level so a failing level is unambiguous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessingError {
    /// L1 vector-index lookup failed.
    L1(String),
    /// L2 digest read failed.
    L2(String),
    /// L3 epoch read failed.
    L3(String),
    /// L4 task-summary read failed.
    L4(String),
    /// L5 synthesis read failed.
    L5(String),
    /// L6 consolidation read failed.
    L6(String),
}

impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (level, msg) = match self {
            ProcessingError::L1(m) => ("L1", m),
            ProcessingError::L2(m) => ("L2", m),
            ProcessingError::L3(m) => ("L3", m),
            ProcessingError::L4(m) => ("L4", m),
            ProcessingError::L5(m) => ("L5", m),
            ProcessingError::L6(m) => ("L6", m),
        };
        write!(f, "context processing failed at {level}: {msg}")
    }
}

impl std::error::Error for ProcessingError {}

/// The six reader ports for L1–L6, borrowed for one coordination pass.
pub struct MultiLevelReaders<'a> {
    pub vector: &'a dyn VectorIndexReader,
    pub l2: &'a dyn L2DigestReader,
    pub l3: &'a dyn L3EpochReader,
    pub l4: &'a dyn L4TaskSummaryReader,
    pub l5: &'a dyn L5SynthesisReader,
    pub l6: &'a dyn L6ConsolidationReader,
}

/// Drive all 6 levels in spec order (L0 → L1 → L2 → L3 → L4 → L5 → L6) and
/// assemble the [`MultiLevelContextDigest`]. Sequential / fail-fast: the first
/// reader error returns the matching per-level [`ProcessingError`].
///
/// - `l0_input` feeds the in-module L0 compression (no reader).
/// - `query_embedding` drives the L1 vector lookup (pre-computed by the caller
///   via the embedding port — same split as the Slice-B `unified_search`
///   coordinator, which does NOT call `embed()` on the read path).
/// - `agent_id` / `task_id` scope the L2–L6 reads.
pub async fn coordinate_processing(
    agent_id: &str,
    task_id: &str,
    l0_input: &[L0Entry],
    query_embedding: &[f32],
    readers: &MultiLevelReaders<'_>,
) -> Result<MultiLevelContextDigest, ProcessingError> {
    // L0 — in-module pure compression (no I/O).
    let l0 = l0_compress(l0_input);

    // L1 — vector retrieval.
    let l1 = readers
        .vector
        .lookup(agent_id, query_embedding)
        .await
        .map_err(|e| ProcessingError::L1(e.0))?;

    // L2 — turn digests.
    let l2 = readers
        .l2
        .read_digests(agent_id, task_id)
        .await
        .map_err(|e| ProcessingError::L2(e.0))?;

    // L3 — epoch summary.
    let l3 = readers
        .l3
        .read_epoch(agent_id, task_id)
        .await
        .map_err(|e| ProcessingError::L3(e.0))?;

    // L4 — task summary.
    let l4 = readers
        .l4
        .read_task_summary(agent_id, task_id)
        .await
        .map_err(|e| ProcessingError::L4(e.0))?;

    // L5 — cross-task syntheses.
    let l5 = readers
        .l5
        .read_syntheses(agent_id, task_id)
        .await
        .map_err(|e| ProcessingError::L5(e.0))?;

    // L6 — consolidated / global memory.
    let l6 = readers
        .l6
        .read_global_memory(agent_id)
        .await
        .map_err(|e| ProcessingError::L6(e.0))?;

    Ok(MultiLevelContextDigest {
        l0,
        l1,
        l2,
        l3,
        l4,
        l5,
        l6,
    })
}
