//! AC-06 (MODULE-010-T07) — 6-level context-processing coordination.
//!
//! 4 sub-cases: (a) all 6 levels invoked exactly once; (b) deterministic
//! spec-order L0→L1→L2→L3→L4→L5→L6; (c) `MultiLevelContextDigest` captures each
//! level's data; (d) one-reader-error → matching `ProcessingError::<level>`.

use std::sync::{Arc, Mutex};

use advance_context_engine::l0_compress::{L0Entry, L0Kind};
use advance_context_engine::{
    coordinate_processing, EpochSummary, GlobalMemoryRecord, L2DigestReader, L3EpochReader,
    L4TaskSummaryReader, L5SynthesisReader, L6ConsolidationReader, MultiLevelReaders, PortError,
    ProcessingError, SynthesisView, TaskSummaryView, TurnDigestForEmbed, VectorHit,
    VectorIndexReader,
};
use async_trait::async_trait;

type Log = Arc<Mutex<Vec<&'static str>>>;

// ─── reader fakes (each logs its level label; optional forced error) ───

struct FakeVector {
    log: Log,
    err: bool,
}
#[async_trait]
impl VectorIndexReader for FakeVector {
    async fn lookup(&self, _a: &str, _q: &[f32]) -> Result<Vec<VectorHit>, PortError> {
        self.log.lock().unwrap().push("L1");
        if self.err {
            return Err(PortError("L1 boom".into()));
        }
        Ok(vec![VectorHit {
            id: "v1".into(),
            score: 0.9,
        }])
    }
}

struct FakeL2 {
    log: Log,
    err: bool,
}
#[async_trait]
impl L2DigestReader for FakeL2 {
    async fn read_digests(&self, _a: &str, _t: &str) -> Result<Vec<TurnDigestForEmbed>, PortError> {
        self.log.lock().unwrap().push("L2");
        if self.err {
            return Err(PortError("L2 boom".into()));
        }
        Ok(vec![TurnDigestForEmbed {
            turn_id: 1,
            digest: "d1".into(),
            collapsed_view: "c1".into(),
        }])
    }
}

struct FakeL3 {
    log: Log,
    err: bool,
}
#[async_trait]
impl L3EpochReader for FakeL3 {
    async fn read_epoch(&self, _a: &str, _t: &str) -> Result<Option<EpochSummary>, PortError> {
        self.log.lock().unwrap().push("L3");
        if self.err {
            return Err(PortError("L3 boom".into()));
        }
        Ok(Some(EpochSummary {
            epoch_id: "e1".into(),
            summary: "epoch 1".into(),
        }))
    }
}

struct FakeL4 {
    log: Log,
    err: bool,
}
#[async_trait]
impl L4TaskSummaryReader for FakeL4 {
    async fn read_task_summary(
        &self,
        _a: &str,
        _t: &str,
    ) -> Result<Option<TaskSummaryView>, PortError> {
        self.log.lock().unwrap().push("L4");
        if self.err {
            return Err(PortError("L4 boom".into()));
        }
        Ok(Some(TaskSummaryView {
            task_id: "task-1".into(),
            summary: "task summary".into(),
        }))
    }
}

struct FakeL5 {
    log: Log,
    err: bool,
}
#[async_trait]
impl L5SynthesisReader for FakeL5 {
    async fn read_syntheses(&self, _a: &str, _t: &str) -> Result<Vec<SynthesisView>, PortError> {
        self.log.lock().unwrap().push("L5");
        if self.err {
            return Err(PortError("L5 boom".into()));
        }
        Ok(vec![SynthesisView {
            task_id: "task-0".into(),
            body: "synthesis".into(),
        }])
    }
}

struct FakeL6 {
    log: Log,
    err: bool,
}
#[async_trait]
impl L6ConsolidationReader for FakeL6 {
    async fn read_global_memory(&self, _a: &str) -> Result<Vec<GlobalMemoryRecord>, PortError> {
        self.log.lock().unwrap().push("L6");
        if self.err {
            return Err(PortError("L6 boom".into()));
        }
        Ok(vec![GlobalMemoryRecord {
            id: "g1".into(),
            body: "global memory".into(),
        }])
    }
}

fn l0_input() -> Vec<L0Entry> {
    vec![
        L0Entry {
            turn_id: 1,
            kind: L0Kind::Read { path: "a".into() },
        },
        L0Entry {
            turn_id: 1,
            kind: L0Kind::Read { path: "a".into() },
        },
    ]
}

// ─── (a)+(b)+(c) happy path: all 6 invoked once, in order, carrier captured ───

#[tokio::test]
async fn all_six_levels_invoked_once_in_spec_order() {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let vector = FakeVector {
        log: log.clone(),
        err: false,
    };
    let l2 = FakeL2 {
        log: log.clone(),
        err: false,
    };
    let l3 = FakeL3 {
        log: log.clone(),
        err: false,
    };
    let l4 = FakeL4 {
        log: log.clone(),
        err: false,
    };
    let l5 = FakeL5 {
        log: log.clone(),
        err: false,
    };
    let l6 = FakeL6 {
        log: log.clone(),
        err: false,
    };
    let readers = MultiLevelReaders {
        vector: &vector,
        l2: &l2,
        l3: &l3,
        l4: &l4,
        l5: &l5,
        l6: &l6,
    };

    let digest = coordinate_processing("agent-1", "task-1", &l0_input(), &[0.1, 0.2], &readers)
        .await
        .unwrap();

    // (b) spec-order: L1→L2→L3→L4→L5→L6 (L0 is the in-module pure step, no log).
    assert_eq!(
        *log.lock().unwrap(),
        vec!["L1", "L2", "L3", "L4", "L5", "L6"]
    );

    // (c) carrier captures each level.
    assert_eq!(digest.l0.len(), 2); // l0_compress produced 2 verdicts
    assert_eq!(digest.l1.len(), 1);
    assert_eq!(digest.l2.len(), 1);
    assert!(digest.l3.is_some());
    assert!(digest.l4.is_some());
    assert_eq!(digest.l5.len(), 1);
    assert_eq!(digest.l6.len(), 1);
}

// ─── (d) one reader errors → matching ProcessingError variant ───

#[tokio::test]
async fn l4_reader_error_propagates_as_processing_error_l4() {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let vector = FakeVector {
        log: log.clone(),
        err: false,
    };
    let l2 = FakeL2 {
        log: log.clone(),
        err: false,
    };
    let l3 = FakeL3 {
        log: log.clone(),
        err: false,
    };
    let l4 = FakeL4 {
        log: log.clone(),
        err: true,
    }; // forced error
    let l5 = FakeL5 {
        log: log.clone(),
        err: false,
    };
    let l6 = FakeL6 {
        log: log.clone(),
        err: false,
    };
    let readers = MultiLevelReaders {
        vector: &vector,
        l2: &l2,
        l3: &l3,
        l4: &l4,
        l5: &l5,
        l6: &l6,
    };

    let err = coordinate_processing("agent-1", "task-1", &l0_input(), &[0.1], &readers)
        .await
        .unwrap_err();
    assert_eq!(err, ProcessingError::L4("L4 boom".into()));

    // Fail-fast: L5/L6 must NOT have run after L4 failed.
    let calls = log.lock().unwrap();
    assert!(calls.contains(&"L4"));
    assert!(!calls.contains(&"L5"));
    assert!(!calls.contains(&"L6"));
}
