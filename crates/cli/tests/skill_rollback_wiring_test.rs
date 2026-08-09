//! Wave-18 Lane 2 (T-S2-6) — the `wire_capabilities` composition-site guard for
//! the production `SkillRollback` bridge.
//!
//! The Wave-17 strict-hold was raised because the production
//! `build_auto_loop_driver` wired NO `SkillRollback` (a discard fail-closed with
//! `SkillRollbackUnwired`). This test runs the REAL `wire_capabilities` over a
//! git workspace declaring `skills`, then drives an iteration discard through the
//! returned `auto_loop_driver` and proves the bridge is ACTUALLY wired: a
//! recorded pre-state is restored against the REAL cap-skills `SkillStore` (the
//! seeded skill is deleted) instead of the close returning `SkillRollbackUnwired`.
//!
//! This guards the exact `set_skill_rollback(...)` composition site that the
//! Wave-17 split flagged as wired-but-unbuilt — it is the write-side guard. The
//! record-side observer (`with_pre_activation_observer`) is exercised end-to-end
//! by the sys_j12 AC-06 witness through the production coordinator activate path.
//! Here the witness plays the observer (`record_skill_pre_activation`) directly so
//! the assertion isolates the write-side wiring; the bridge ignores `agent_id`, so
//! the driver session runs under the `"root"` sentinel (the workspace-root git
//! resolve) while the coordinator operates on its own bound store.

use std::path::{Path, PathBuf};

use advance_cli::wiring::wire_capabilities;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_scheduler_auto_loop::config::{
    MetricSource, Objective, Op, Predicate, Role, SuccessCriteria,
};
use advance_scheduler_auto_loop::{
    AutoLoopDriver, IterationCloseCtx, IterationOutcome, IterationStatus,
};
use cap_skills::persistence::{DiskSkillStorage, SkillBlob, SkillStorage};
use cap_skills::{Provenance, TrustLevel};
use git2::{Repository, Signature};

const AGENT: &str = "root";

// ── workspace + git helpers ──────────────────────────────────────────────

fn runtime_yaml() -> String {
    r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADV_BRIDGETEST_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

/// Bootstrap a `main` repo with a born HEAD (empty-tree initial commit) so the
/// auto-loop iteration checkpoint/rollback succeeds, then lay down the runtime +
/// capability configs. Returns the canonicalized workspace + config path.
fn fresh_git_workspace(caps_yaml: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let ws = std::fs::canonicalize(dir.path()).expect("canonicalize");

    advance_git::bootstrap_repo_at(&ws).expect("bootstrap_repo_at");
    let repo = Repository::open(&ws).expect("open repo");
    let sig = Signature::now("runtime", "runtime@advance-agents").expect("sig");
    let tree_oid = {
        let mut idx = repo.index().expect("index");
        idx.write_tree().expect("write empty tree")
    };
    let tree = repo.find_tree(tree_oid).expect("find empty tree");
    repo.commit(
        Some("refs/heads/main"),
        &sig,
        &sig,
        "initial commit",
        &tree,
        &[],
    )
    .expect("initial commit");
    repo.set_head("refs/heads/main").expect("set_head");
    repo.checkout_head(None).expect("checkout_head");

    std::fs::create_dir_all(ws.join(".advance")).unwrap();
    std::fs::create_dir_all(ws.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(ws.join(".agent")).unwrap();
    let config_path = ws.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(ws.join(".agent/config.yaml"), caps_yaml).unwrap();
    (dir, ws, config_path)
}

/// Materialize an active skill (SKILL.md + .meta.yaml) at the cap-skills provider
/// root — the SAME `<ws>/.agent` the wire_capabilities skills arm roots the
/// coordinator at (DiskSkillStorage appends `.agent/skills`). Seeded BEFORE
/// wiring so the lazily-built store reads it from disk on `get`.
async fn seed_skill(agent_root: &Path, id: &str) {
    let storage = DiskSkillStorage::with_default_writer(agent_root.to_path_buf());
    storage
        .write_active(&SkillBlob {
            skill_id: id.to_string(),
            version: 1,
            content: format!("---\nname: {id}\ndescription: seeded\n---\n# {id}\n"),
            tags: vec![],
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        })
        .await
        .expect("write_active");
}

fn primary_criteria() -> SuccessCriteria {
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
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    }
}

fn discard_ctx(agent: &str, iter: u32) -> IterationCloseCtx {
    IterationCloseCtx {
        agent_id: agent.to_string(),
        run_id: Some(format!("run-{agent}")),
        iteration: iter,
        checkpoint_label: format!("auto-iter-{iter}"),
        primary_metric: None, // no metric → discard arm
        metrics: std::collections::BTreeMap::new(),
        crashed: false,
        crash_reason: None,
        summary: Some(format!("iter-{iter}")),
        cost_usd: 0.01,
        wall_time_sec: 1,
    }
}

fn skill_exists(agent_root: &Path, id: &str) -> bool {
    // DiskSkillStorage active layout: <agent_root>/.agent/skills/{id}/SKILL.md.
    agent_root
        .join(".agent/skills")
        .join(id)
        .join("SKILL.md")
        .exists()
}

// ── the composition-site guard ────────────────────────────────────────────

/// `wire_capabilities` wires `set_skill_rollback` on the production driver: a
/// discard with a recorded pre-state restores against the REAL store (the seeded
/// skill is deleted) rather than failing `SkillRollbackUnwired`.
#[tokio::test(flavor = "multi_thread")]
async fn skill_rollback_bridge_wired_into_wire_capabilities() {
    // `agent_id: root` is REQUIRED: once `.agent/config.yaml` exists (it must, for
    // the capability gate), the M003 `resolve_agent_root` no longer falls back to
    // the bare `"root"` sentinel — it matches the config's `agent_id` against the
    // session agent_id. The capability parse (`active_capabilities`) is a lenient
    // per-key lookup, so the extra top-level `agent_id` key is tolerated.
    let (_g, ws, cfg) = fresh_git_workspace("agent_id: root\ncapabilities:\n  skills: true\n");
    let agent_root = ws.join(".agent");

    // Seed skill "x" on disk BEFORE wiring → the coordinator's lazily-built store
    // sees it. Its pre-state will be recorded as Absent (created this iteration),
    // so a discard must DELETE it through the bridge.
    seed_skill(&agent_root, "x").await;
    assert!(skill_exists(&agent_root, "x"), "skill x seeded on disk");

    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws)
        .await
        .expect("wire (skills)");

    let driver = handles
        .auto_loop_driver
        .clone()
        .expect("git workspace ⇒ auto_loop_driver Some");

    // Drive a real auto iteration through the WIRED driver.
    driver
        .start(AGENT, primary_criteria())
        .await
        .expect("start");
    driver
        .iteration_start(AGENT, Some(format!("run-{AGENT}")), 1)
        .await
        .expect("iteration_start");
    // Record an Absent pre-state for "x" (the witness plays the observer for this
    // write-side guard; the bridge ignores agent_id). A NON-EMPTY tracker is the
    // discriminator: an unwired driver would now fail `SkillRollbackUnwired`.
    driver.record_skill_pre_activation(AGENT, "x", None);

    let out = driver
        .close_iteration(discard_ctx(AGENT, 1))
        .await
        .expect("close discard MUST be Ok (bridge wired) — not SkillRollbackUnwired");
    assert!(
        matches!(
            out,
            IterationOutcome::Continue {
                status: IterationStatus::Discard,
                ..
            }
        ),
        "discard outcome"
    );

    // REAL effect: the bridge deleted "x" from the cap-skills store on disk. An
    // unwired driver would have errored above AND left "x" in place.
    assert!(
        !skill_exists(&agent_root, "x"),
        "the wired bridge deleted the Absent-pre-state skill on discard"
    );

    drop(host);
    drop(handles);
}
