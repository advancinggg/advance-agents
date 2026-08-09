//! AC-02 (Independent `auto:{agent-id}` namespace + per-agent budget
//! independence), AC-03 (complete-cycle terminal path + terminal-state
//! rejection), AC-08 (Evaluator constraint surface enforced via violating
//! resolver), AC-09 (Evaluator id override format with resolver),
//! AC-14 (fail-fast → crash-path sequence), AC-21 (Draft/Candidate
//! exclusion + SkillPreState restoration joint test).

mod common;

use std::sync::Arc;

use advance_git::{DefaultNamedCheckpoint, DefaultWorkspaceRollback};
use advance_scheduler_auto_loop::{
    config::{MetricSource, Objective, Op, Predicate, Role, SuccessCriteria},
    validate_constraint_surface, AutoLoopDriver, BudgetBreach, BudgetStatus, ConstraintViolation,
    DefaultAutoLoopDriver, DefaultFailFastMonitor, DefaultIterationCheckpoint,
    DefaultIterationRollback, EvaluatedMetric, EvaluatorResolver, FailFastMetric, FailFastOutcome,
    IterationResult, IterationStatus, PerIterationBudget, ResultsWriter, SkillTracker,
};
use advance_shared_types::cost::RunCost;

use common::{
    bootstrap_repo_with_initial_commit, commit_file, MockCostTracker, RecordedCall,
    RecordingSkillRollback, ValidSpecEvaluatorResolver, ViolatingEvaluatorResolver,
};

fn primary_only_criteria_with_budget(budget: Option<PerIterationBudget>) -> SuccessCriteria {
    SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "val-bpb".to_string(),
            role: Role::Primary,
            metric_source: MetricSource::File {
                path: "metrics/bpb.json".to_string(),
                key: "val_bpb".to_string(),
            },
            predicate: Predicate {
                op: Op::Lt,
                threshold: None,
            },
        }],
        per_iteration_budget: budget,
        fail_fast: None,
        safety_valve: None,
    }
}

// MODULE-015-T02-slC — Independent auto:{agent-id} namespace + per-agent
// budget independence observable via check_per_iteration_budget.
#[tokio::test]
async fn auto_namespace_two_agents_isolated_with_budget_check() {
    use std::time::Instant;

    // Use a noop checkpoint/rollback — this test doesn't exercise git.
    use common::{NoopIterationCheckpoint, NoopIterationRollback};

    let cost_tracker = MockCostTracker::new()
        .with_cost(
            "run-a",
            0,
            RunCost {
                tokens_in: 200,
                tokens_out: 0,
                cost_usd: 0.0,
                request_count: 1,
            },
        )
        .with_cost(
            "run-b",
            0,
            RunCost {
                tokens_in: 200,
                tokens_out: 0,
                cost_usd: 0.0,
                request_count: 1,
            },
        );
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
    .with_cost_tracker(Arc::new(cost_tracker));

    // Per-agent budget configs differ: alice has max_tokens=100, bob has 500.
    let alice_criteria = primary_only_criteria_with_budget(Some(PerIterationBudget {
        max_tokens: Some(100),
        max_wall_time_sec: None,
        max_cost_usd: None,
    }));
    let bob_criteria = primary_only_criteria_with_budget(Some(PerIterationBudget {
        max_tokens: Some(500),
        max_wall_time_sec: None,
        max_cost_usd: None,
    }));

    driver
        .start("alice", alice_criteria)
        .await
        .expect("start alice");
    driver.start("bob", bob_criteria).await.expect("start bob");

    // Namespace distinctness (slice-B helper composes the format).
    assert_eq!(driver.auto_namespace_task_id("alice"), "auto:alice");
    assert_eq!(driver.auto_namespace_task_id("bob"), "auto:bob");
    assert_ne!(
        driver.auto_namespace_task_id("alice"),
        driver.auto_namespace_task_id("bob")
    );

    // Per-agent budget independence — cost.tokens=200 means alice (limit
    // 100) breaches but bob (limit 500) does not.
    let t0 = Instant::now();
    let t1 = t0;
    let alice_status = driver.check_per_iteration_budget("alice", "run-a", 0, t0, t1);
    let bob_status = driver.check_per_iteration_budget("bob", "run-b", 0, t0, t1);

    match alice_status {
        BudgetStatus::Breach(BudgetBreach::Tokens { observed, limit }) => {
            assert_eq!(observed, 200);
            assert_eq!(limit, 100);
        }
        other => panic!("expected alice Tokens breach 200/100; got {other:?}"),
    }
    assert_eq!(
        bob_status,
        BudgetStatus::Ok,
        "bob with 200/500 tokens must be Ok"
    );
}

// MODULE-015-T03-slC — complete-cycle action variant + terminal-state
// rejection. record_complete_cycle_request mutates the field (status stays
// Active); transition_status(CompleteCycle) flips to Completed; subsequent
// transition attempts hit terminal-state rejection.
#[tokio::test]
async fn complete_cycle_terminal_path() {
    use advance_scheduler_auto_loop::InvalidTransition;
    use advance_scheduler_auto_loop::{AutoLoopError, AutoStatus, CompletionSummary, Transition};
    use common::{NoopIterationCheckpoint, NoopIterationRollback};

    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    );
    driver
        .start("alice", primary_only_criteria_with_budget(None))
        .await
        .expect("start");

    // record_complete_cycle_request stores the intent WITHOUT transitioning.
    driver
        .record_complete_cycle_request(
            "alice",
            CompletionSummary {
                outcome: "stop-please".to_string(),
                final_metrics: Vec::new(),
            },
        )
        .expect("record_complete_cycle_request");
    assert_eq!(driver.status("alice").await, Some(AutoStatus::Active));

    // transition_status(CompleteCycle) → Completed (terminal).
    let next = driver
        .transition_status("alice", Transition::CompleteCycle)
        .expect("transition CompleteCycle");
    assert_eq!(next, AutoStatus::Completed);
    assert_eq!(driver.status("alice").await, Some(AutoStatus::Completed));

    // Subsequent transition attempts hit terminal-state rejection.
    let err = driver
        .transition_status("alice", Transition::CompleteCycle)
        .expect_err("terminal-state rejection expected");
    match err {
        AutoLoopError::InvalidTransition(InvalidTransition::TerminalState(s)) => {
            assert_eq!(s, AutoStatus::Completed);
        }
        other => panic!("expected TerminalState(Completed); got {other:?}"),
    }
}

// MODULE-015-T08-slC — Evaluator constraint surface enforced. Resolver
// returns a violating EvaluatorManifest; validate_constraint_surface
// rejects with the matching ConstraintViolation variant.
#[tokio::test]
async fn evaluator_pack_constraint_resolution_with_violation() {
    // Wrong component_type → WrongComponentType("agent").
    {
        let resolver = ViolatingEvaluatorResolver::wrong_component_type();
        let spec = resolver
            .resolve_evaluator("research-pack@1.2.0/evaluator-bpb")
            .await
            .expect("resolver returns Ok(spec) with violating manifest");
        let err =
            validate_constraint_surface(&spec.manifest).expect_err("WrongComponentType expected");
        assert_eq!(
            err,
            ConstraintViolation::WrongComponentType("agent".to_string())
        );
    }

    // trigger_present=true → TriggerPresent.
    {
        let resolver = ViolatingEvaluatorResolver::trigger_present();
        let spec = resolver
            .resolve_evaluator("research-pack@1.2.0/evaluator-bpb")
            .await
            .expect("Ok(spec)");
        assert_eq!(
            validate_constraint_surface(&spec.manifest),
            Err(ConstraintViolation::TriggerPresent)
        );
    }

    // has_binary=false → NoBinary.
    {
        let resolver = ViolatingEvaluatorResolver::no_binary();
        let spec = resolver
            .resolve_evaluator("research-pack@1.2.0/evaluator-bpb")
            .await
            .expect("Ok(spec)");
        assert_eq!(
            validate_constraint_surface(&spec.manifest),
            Err(ConstraintViolation::NoBinary)
        );
    }

    // Valid manifest admits.
    {
        let resolver = ValidSpecEvaluatorResolver;
        let spec = resolver
            .resolve_evaluator("research-pack@1.2.0/evaluator-bpb")
            .await
            .expect("Ok(spec)");
        validate_constraint_surface(&spec.manifest).expect("valid manifest must admit");
    }
}

// MODULE-015-T09-slC — Evaluator id override format. evaluator_id_for
// composes `auto-eval:{agent-id}:iter-{n}` exactly, and the override id
// is paired with the resolved spec at the test orchestration boundary.
#[tokio::test]
async fn evaluator_id_override_format_with_resolver() {
    use common::{NoopIterationCheckpoint, NoopIterationRollback};

    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    );
    let resolver = ValidSpecEvaluatorResolver;
    let _spec = resolver
        .resolve_evaluator("research-pack@1.2.0/evaluator-bpb")
        .await
        .expect("Ok(spec)");

    // The override id is composed via evaluator_id_for; integrated loop
    // would assign this as the runtime id of the resolved component.
    let override_id_iter0 = driver.evaluator_id_for("alice", 0);
    let override_id_iter7 = driver.evaluator_id_for("alice", 7);
    let override_id_iter42 = driver.evaluator_id_for("research-agent", 42);

    assert_eq!(override_id_iter0, "auto-eval:alice:iter-0");
    assert_eq!(override_id_iter7, "auto-eval:alice:iter-7");
    assert_eq!(override_id_iter42, "auto-eval:research-agent:iter-42");
}

// MODULE-015-T14-slC — Fail-fast Trigger → crash path sequence:
// bootstrap repo + commit baseline + checkpoint iteration + mutate
// workspace + fail-fast check returns Trigger + rollback restores
// workspace + crash row appended to results.jsonl.
#[tokio::test]
async fn fail_fast_trigger_to_crash_path_sequence() {
    use std::collections::BTreeMap;

    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    commit_file(temp.path(), "work.txt", b"baseline");

    let ckpt =
        DefaultNamedCheckpoint::new(temp.path().to_path_buf()).expect("DefaultNamedCheckpoint");
    let rb =
        DefaultWorkspaceRollback::new(temp.path().to_path_buf()).expect("DefaultWorkspaceRollback");
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(DefaultIterationCheckpoint::new(Arc::new(ckpt))),
        Arc::new(DefaultIterationRollback::new(Arc::new(rb))),
    );

    // Checkpoint iteration 1, then mutate workspace post-checkpoint.
    driver
        .checkpoint_iteration("root", 1)
        .await
        .expect("checkpoint");
    commit_file(temp.path(), "work.txt", b"mutated");

    // Fail-fast check: a numeric reading 0.5 > threshold 0.3 with op=Gt
    // triggers a breach. Outcome reason starts with "fail-fast:".
    let metrics = vec![FailFastMetric {
        metric_source: MetricSource::File {
            path: "metrics/foo.json".to_string(),
            key: "loss".to_string(),
        },
        predicate: Some(Predicate {
            op: Op::Gt,
            threshold: Some(0.3),
        }),
    }];
    let readings = vec![EvaluatedMetric::Value(0.5)];
    let outcome = DefaultFailFastMonitor::check_with_readings(&metrics, &readings);
    match outcome {
        FailFastOutcome::Trigger { reason } => {
            assert!(
                reason.starts_with("fail-fast:"),
                "Trigger reason must start with 'fail-fast:'; got: {reason}"
            );
        }
        FailFastOutcome::Pass => panic!("expected Trigger; got Pass"),
    }

    // Crash path: rollback iteration 1 → workspace restored to baseline.
    driver
        .rollback_iteration("root", 1)
        .await
        .expect("rollback ok");
    assert_eq!(
        std::fs::read(temp.path().join("work.txt")).unwrap(),
        b"baseline",
        "work.txt must be rolled back to baseline"
    );

    // Crash row written to results.jsonl.
    let writer = ResultsWriter::new(temp.path().to_path_buf());
    let crash_row = IterationResult {
        iter: 1,
        checkpoint: "auto-iter-1".to_string(),
        metric: BTreeMap::new(),
        status: IterationStatus::Crash,
        cost_usd: 0.01,
        wall_time_sec: 12,
        summary: None,
    };
    writer.append(&crash_row).await.expect("append crash row");
    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["status"], "crash");
    assert_eq!(parsed["iter"], 1);
}

// MODULE-015-T21-slC — Draft/Candidate exclusion AND SkillPreState
// restoration joint test. Bootstrap + commit work.txt + .agent/_drafts/
// + .agent/memory/_skill_candidates.jsonl + tracker.record_pre_activation
// "reified-skill" Version(2); checkpoint; mutate all; apply_discard with
// RecordingSkillRollback; rollback_iteration → assert workspace state
// and recorder calls.
#[tokio::test]
async fn draft_candidate_excluded_with_skill_state_restored() {
    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    commit_file(temp.path(), "work.txt", b"v1");
    commit_file(temp.path(), ".agent/_drafts/proposal-1.md", b"draft-v1");
    commit_file(
        temp.path(),
        ".agent/memory/_skill_candidates.jsonl",
        b"{\"draft\":\"v1\"}\n",
    );

    let ckpt =
        DefaultNamedCheckpoint::new(temp.path().to_path_buf()).expect("DefaultNamedCheckpoint");
    let rb =
        DefaultWorkspaceRollback::new(temp.path().to_path_buf()).expect("DefaultWorkspaceRollback");
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(DefaultIterationCheckpoint::new(Arc::new(ckpt))),
        Arc::new(DefaultIterationRollback::new(Arc::new(rb))),
    );

    // Pre-activation snapshot: reified-skill is at version 2 before this
    // iteration's first activation.
    let mut tracker = SkillTracker::new();
    tracker.record_pre_activation("reified-skill", Some(2));

    driver
        .checkpoint_iteration("root", 1)
        .await
        .expect("checkpoint");

    // Mutate ALL three files post-checkpoint.
    commit_file(temp.path(), "work.txt", b"v2");
    commit_file(temp.path(), ".agent/_drafts/proposal-1.md", b"draft-v2");
    commit_file(
        temp.path(),
        ".agent/memory/_skill_candidates.jsonl",
        b"{\"draft\":\"v2\"}\n",
    );

    // Discard path: apply_discard for the reified-skill THEN rollback
    // workspace.
    let recorder = RecordingSkillRollback::new();
    tracker
        .apply_discard("root", &recorder)
        .await
        .expect("apply_discard");
    driver
        .rollback_iteration("root", 1)
        .await
        .expect("rollback ok");

    // Workspace assertions:
    // - work.txt reverted to v1 (M003 FullDirectory rollback restored it).
    // - .agent/_drafts/proposal-1.md SURVIVES at v2 (excluded by .agent/**).
    // - .agent/memory/_skill_candidates.jsonl SURVIVES at v2 (excluded).
    assert_eq!(
        std::fs::read(temp.path().join("work.txt")).unwrap(),
        b"v1",
        "work.txt must roll back to v1"
    );
    assert_eq!(
        std::fs::read(temp.path().join(".agent/_drafts/proposal-1.md")).unwrap(),
        b"draft-v2",
        "draft-1 must SURVIVE (excluded from rollback)"
    );
    assert_eq!(
        std::fs::read(temp.path().join(".agent/memory/_skill_candidates.jsonl")).unwrap(),
        b"{\"draft\":\"v2\"}\n",
        "_skill_candidates.jsonl must SURVIVE (excluded from rollback)"
    );

    // SkillTracker recorded the right call.
    assert_eq!(
        recorder.calls(),
        vec![RecordedCall::Rollback {
            agent_id: "root".to_string(),
            skill_id: "reified-skill".to_string(),
            target_version: 2,
        }],
        "tracker.apply_discard must dispatch rollback_skill for the recorded pre-state"
    );
}
