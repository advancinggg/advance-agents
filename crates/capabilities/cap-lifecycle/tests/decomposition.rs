//! AC-13 / AC-14 / AC-15 — task decomposition protocol (REQ-050).

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use cap_lifecycle::{
    AgentTreeStore, DecompositionError, DecompositionPlan, DecompositionStore,
    DecompositionStrategy, DefaultDecompositionStore, DelegationTarget, SubtaskSpec, SubtaskStatus,
    MAX_DECOMPOSITION_SUBTASKS,
};
use tempfile::TempDir;

fn setup() -> (TempDir, DefaultDecompositionStore) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let root_ws = tree.workspace_root().join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let store = DefaultDecompositionStore::new(tree);
    (tmp, store)
}

fn spec(title: &str, deps: &[&str]) -> SubtaskSpec {
    SubtaskSpec {
        existing_id: None,
        title: title.into(),
        assignee: "_self".into(),
        template_ref: None,
        prompt: "do it".into(),
        depends_on: deps.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn ac13_submit_writes_yaml() {
    let (_t, s) = setup();
    let r = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("a", &[]), spec("b", &["a"])],
            },
        )
        .unwrap();
    assert_eq!(r.subtask_ids.len(), 2);
    let got = s.get("root", "task-1").unwrap().unwrap();
    assert_eq!(got.subtasks.len(), 2);
}

#[test]
fn ac13_duplicate_title_rejected() {
    let (_t, s) = setup();
    let e = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("dup", &[]), spec("dup", &[])],
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::DuplicateTitle(_)));
}

#[test]
fn ac13_cycle_detected() {
    let (_t, s) = setup();
    let e = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("a", &["b"]), spec("b", &["a"])],
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::DependencyCycle(_)));
}

#[test]
fn ac13_unresolved_dependency() {
    let (_t, s) = setup();
    let e = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("a", &["ghost"])],
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::UnresolvedDependency(_)));
}

#[test]
fn ac13_caller_not_in_tree_permission_denied() {
    let (_t, s) = setup();
    let e = s
        .submit(
            "ghost",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::SelfExecute,
                subtasks: vec![],
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::PermissionDenied(_)));
}

#[test]
fn ac14_existing_id_preserves_subtask_id() {
    let (_t, s) = setup();
    let r1 = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("alpha", &[])],
            },
        )
        .unwrap();
    let id1 = r1.subtask_ids[0].subtask_id.clone();
    // Re-submit WITH existing-id → same id preserved.
    let mut sp = spec("alpha-renamed", &[]);
    sp.existing_id = Some(id1.clone());
    let r2 = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![sp],
            },
        )
        .unwrap();
    assert_eq!(r2.subtask_ids[0].subtask_id, id1);
}

#[test]
fn ac14_same_title_no_existing_id_gets_fresh_uuid() {
    let (_t, s) = setup();
    let r1 = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("same", &[])],
            },
        )
        .unwrap();
    let id1 = r1.subtask_ids[0].subtask_id.clone();
    let r2 = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("same", &[])],
            },
        )
        .unwrap();
    // PRD §4.2.2:539-540 — no existing-id ⇒ NEW id even for same title.
    assert_ne!(r2.subtask_ids[0].subtask_id, id1);
}

#[test]
fn ac14_stale_existing_id_subtask_not_found() {
    let (_t, s) = setup();
    let mut sp = spec("x", &[]);
    // Well-formed UUID v4 (version nibble 4, variant 8) that is simply
    // absent from any prior plan → SubtaskNotFound (NOT InvalidConfig).
    sp.existing_id = Some("st-00000000-0000-4000-8000-000000000000".into());
    let e = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![sp],
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::SubtaskNotFound(_)));
}

#[test]
fn ac14_orphan_status_conditional_per_prd_4_2_2() {
    // PRD §4.2.2 / §1.3.4 merge rules — STATUS CONDITIONAL:
    //   dropped Completed/InProgress → retained with orphaned: true
    //   dropped Pending/Skipped/Failed → REMOVED entirely
    let (_t, s) = setup();
    let r = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("keep", &[]), spec("done", &[]), spec("pend", &[])],
            },
        )
        .unwrap();
    let done_id = r
        .subtask_ids
        .iter()
        .find(|m| m.title == "done")
        .unwrap()
        .subtask_id
        .clone();
    // Mark `done` Completed; `pend` stays Pending.
    s.update_subtask_status(
        "root",
        "task-1",
        &done_id,
        SubtaskStatus::Completed,
        Some("finished".into()),
    )
    .unwrap();
    // Re-submit with ONLY `keep` → drop `done` (Completed) and `pend` (Pending).
    s.submit(
        "root",
        "task-1",
        DecompositionPlan {
            goal: "g".into(),
            strategy: DecompositionStrategy::Decompose,
            subtasks: vec![spec("keep", &[])],
        },
    )
    .unwrap();
    let st = s.get("root", "task-1").unwrap().unwrap();
    // Completed-dropped → retained orphaned, outcome preserved.
    let done_row = st
        .subtasks
        .iter()
        .find(|x| x.title == "done")
        .expect("dropped Completed subtask must be retained as orphaned");
    assert!(done_row.orphaned);
    assert_eq!(done_row.status, SubtaskStatus::Completed);
    assert_eq!(done_row.outcome.as_deref(), Some("finished"));
    // Pending-dropped → REMOVED entirely (NOT present).
    assert!(
        !st.subtasks.iter().any(|x| x.title == "pend"),
        "dropped Pending subtask must be REMOVED, not retained"
    );
    // `keep` is the only live subtask.
    assert!(st.subtasks.iter().any(|x| x.title == "keep" && !x.orphaned));
}

#[test]
fn ac15_three_strategies_round_trip() {
    let (_t, s) = setup();
    for (tid, strat) in [
        ("t-se", DecompositionStrategy::SelfExecute),
        ("t-de", DecompositionStrategy::Decompose),
        (
            "t-dl",
            DecompositionStrategy::DelegateSingle(DelegationTarget {
                assignee: "research".into(),
                template_ref: Some("explorer".into()),
                prompt: "analyze".into(),
            }),
        ),
    ] {
        s.submit(
            "root",
            tid,
            DecompositionPlan {
                goal: "g".into(),
                strategy: strat.clone(),
                subtasks: vec![],
            },
        )
        .unwrap();
        let got = s.get("root", tid).unwrap().unwrap();
        assert_eq!(got.strategy, strat);
    }
}

#[test]
fn ac15_delegate_single_empty_assignee_rejected() {
    let (_t, s) = setup();
    let e = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::DelegateSingle(DelegationTarget {
                    assignee: "".into(),
                    template_ref: None,
                    prompt: "p".into(),
                }),
                subtasks: vec![],
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::InvalidConfig(_)));
}

#[test]
fn ac13_update_subtask_status_mutates() {
    let (_t, s) = setup();
    let r = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![spec("a", &[])],
            },
        )
        .unwrap();
    let id = r.subtask_ids[0].subtask_id.clone();
    s.update_subtask_status(
        "root",
        "task-1",
        &id,
        SubtaskStatus::Completed,
        Some("done".into()),
    )
    .unwrap();
    let st = s.get("root", "task-1").unwrap().unwrap();
    let row = st.subtasks.iter().find(|x| x.subtask_id == id).unwrap();
    assert_eq!(row.status, SubtaskStatus::Completed);
    assert_eq!(row.outcome.as_deref(), Some("done"));
}

#[test]
fn ac13_update_unknown_subtask_not_found() {
    let (_t, s) = setup();
    s.submit(
        "root",
        "task-1",
        DecompositionPlan {
            goal: "g".into(),
            strategy: DecompositionStrategy::SelfExecute,
            subtasks: vec![],
        },
    )
    .unwrap();
    let e = s
        .update_subtask_status("root", "task-1", "st-nope", SubtaskStatus::Failed, None)
        .unwrap_err();
    assert!(matches!(e, DecompositionError::SubtaskNotFound(_)));
}

#[test]
fn ac13_get_missing_task_returns_none() {
    let (_t, s) = setup();
    assert!(s.get("root", "never").unwrap().is_none());
}

#[test]
fn ac13_update_missing_task_not_found() {
    let (_t, s) = setup();
    let e = s
        .update_subtask_status("root", "ghost", "st-x", SubtaskStatus::Failed, None)
        .unwrap_err();
    assert!(matches!(e, DecompositionError::TaskNotFound(_)));
}

#[test]
fn ac13_over_subtask_cap_rejected() {
    let (_t, s) = setup();
    let subtasks: Vec<_> = (0..300).map(|i| spec(&format!("t{i}"), &[])).collect();
    let e = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks,
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::InvalidConfig(_)));
}

#[test]
fn ac13_over_depends_on_count_rejected() {
    // Defence-in-depth amplification cap: a single subtask declaring more than
    // MAX_DECOMPOSITION_SUBTASKS dependency titles is rejected in the per-subtask
    // validation loop, BEFORE dependency resolution / cycle detection allocate
    // per edge.
    let (_t, s) = setup();
    let deps: Vec<String> = (0..=MAX_DECOMPOSITION_SUBTASKS)
        .map(|i| format!("d{i}"))
        .collect();
    let sp = SubtaskSpec {
        existing_id: None,
        title: "a".into(),
        assignee: "_self".into(),
        template_ref: None,
        prompt: "do".into(),
        depends_on: deps,
    };
    let e = s
        .submit(
            "root",
            "task-1",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks: vec![sp],
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::InvalidConfig(_)));
}

#[test]
fn ac13_oversized_rendered_doc_rejected() {
    // SYS-AC-243 product behavior (e2e witness deferred): a valid, ACYCLIC plan
    // whose *rendered* YAML exceeds MAX_DECOMPOSITION_DOC_BYTES (1 MiB) is
    // rejected by write_state with InvalidConfig, and no decomposition.yaml is
    // persisted. Distinct from ac13_over_subtask_cap_rejected (the >256 count
    // cap). 256-subtask DAG (subtask i depends on titles t0..t(i-1)) →
    // Σ(0..255) = 32_640 resolved-id dep lines ≈ 1.4 MiB > 1 MiB.
    let (_t, s) = setup();
    let n = MAX_DECOMPOSITION_SUBTASKS; // 256 (at the count cap, trips the byte cap)
    let titles: Vec<String> = (0..n).map(|i| format!("t{i}")).collect();
    let subtasks: Vec<SubtaskSpec> = (0..n)
        .map(|i| SubtaskSpec {
            existing_id: None,
            title: titles[i].clone(),
            assignee: "_self".into(),
            template_ref: None,
            prompt: "x".into(),
            // depends on every lower-indexed title → acyclic, resolves cleanly.
            depends_on: titles[..i].to_vec(),
        })
        .collect();
    let e = s
        .submit(
            "root",
            "task-big",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::Decompose,
                subtasks,
            },
        )
        .unwrap_err();
    assert!(
        matches!(e, DecompositionError::InvalidConfig(_)),
        "oversized rendered doc → InvalidConfig, got {e:?}"
    );
    // Rejection precedes the tmp-write+rename, so nothing is persisted.
    assert!(
        s.get("root", "task-big").unwrap().is_none(),
        "no decomposition.yaml written on oversized rejection"
    );
}

#[test]
fn ac13_task_id_charset_rejected() {
    let (_t, s) = setup();
    let e = s
        .submit(
            "root",
            "bad/../id",
            DecompositionPlan {
                goal: "g".into(),
                strategy: DecompositionStrategy::SelfExecute,
                subtasks: vec![],
            },
        )
        .unwrap_err();
    assert!(matches!(e, DecompositionError::InvalidConfig(_)));
}
