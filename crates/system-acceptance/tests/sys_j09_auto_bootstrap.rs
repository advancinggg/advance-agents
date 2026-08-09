//! SYS-J-09 — on startup with an auto-bootstrap template, declared child agents are
//! ensured to exist without manual spawning; idempotent re-runs skip; mismatches
//! conflict; a kind:sub entry is rejected. Chain: MODULE-015 → MODULE-005 → MODULE-018
//! → MODULE-002 → MODULE-003.
//!
//! Witness surface (Stage-A harvest): driven through the REAL auto-loop coordination
//! method `DefaultAutoLoopDriver::consult_auto_bootstrap`, which calls the REAL
//! `report_to_event_payloads` translator and emits each `BootstrapEventPayload` to the
//! sink. The applier calls the REAL `cap_lifecycle::{parse_auto_bootstrap,
//! apply_auto_bootstrap}` over a REAL `DefaultSpawner` + `AgentTreeStore` — so the
//! spawn / skip / conflict / sub-reject DECISIONS are product-made (apply_auto_bootstrap),
//! and the event PAYLOADS are product-made (report_to_event_payloads). Every
//! load-bearing assertion binds to PRODUCT output: the sink-recorded payload (what the
//! product emitted) and the real on-disk `AgentTreeStore` node state. A no-op / rejected
//! input produces no spawn and no payload — genuine causation, unlike a fabricated run
//! (the SYS-AC-109 fake-green class). NOT bound to the applier's `BootstrapReport`
//! return nor a preconfigured recording double.
//!
//! Witness-floor disclosure (accepted at the /dev plan gate): per MODULE-015 §3.8 the
//! M005-bound applier impl, the M019-bound sink impl, and the Auto-mode-init invocation
//! of `consult_auto_bootstrap` (startup orchestration) are DOCUMENTED cross-module
//! deferrals. This harness-wiring slice supplies the faithful applier (real
//! apply_auto_bootstrap) + a recording sink and drives `consult_auto_bootstrap` directly;
//! the journey's MODULE-015 + MODULE-005 logic is exercised verbatim. The "version"
//! discriminator in 026's criterion maps onto `template_ref` equality (the product's
//! skip key).

use std::sync::{Arc, Mutex};

use advance_scheduler_auto_loop::{
    AutoBootstrapApplier, AutoBootstrapApplierError, AutoBootstrapEventSink,
    AutoBootstrapSinkError, AutoLoopError, BootstrapEventPayload, ConflictKind,
    DefaultAutoLoopDriver, IterationCheckpoint, IterationRollback, M015BootstrapEntry,
    M015BootstrapOutcome, M015BootstrapReport, SkippedKind,
};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use async_trait::async_trait;
use cap_lifecycle::{
    apply_auto_bootstrap, parse_auto_bootstrap, AgentTreeStore, BootstrapEntry, BootstrapError,
    BootstrapEvent, BootstrapReport, BuiltinTemplateRegistry, DefaultSpawner, SpawnError,
    SpawnerSubsetGate,
};
use tempfile::TempDir;

// --- local no-op iteration hooks (the public Noop* live in auto-loop tests/common,
//     not the crate lib — define our own; consult_auto_bootstrap never invokes them) ---
struct NoopCheckpoint;
#[async_trait]
impl IterationCheckpoint for NoopCheckpoint {
    async fn checkpoint_baseline(&self, _agent_id: &str) -> Result<(), AutoLoopError> {
        Ok(())
    }
    async fn checkpoint_iteration(&self, _agent_id: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}
struct NoopRollback;
#[async_trait]
impl IterationRollback for NoopRollback {
    async fn rollback_iteration(&self, _agent_id: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}

struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

/// Recording sink — the M019 emit surface. Records every payload the PRODUCT
/// (`consult_auto_bootstrap` → `report_to_event_payloads`) emits, in order.
struct RecordingSink {
    calls: Arc<Mutex<Vec<BootstrapEventPayload>>>,
}
#[async_trait]
impl AutoBootstrapEventSink for RecordingSink {
    async fn emit(&self, payload: BootstrapEventPayload) -> Result<(), AutoBootstrapSinkError> {
        self.calls.lock().unwrap().push(payload);
        Ok(())
    }
}

/// Join the product `BootstrapReport` (AgentIds only) back to the parsed entries by
/// alias (the bootstrap alias IS the spawned agent id — apply_auto_bootstrap:272), to
/// reconstruct the per-entry `M015BootstrapEntry{template,target_path,alias,outcome}`.
/// Structural assembly only — the spawn/skip/conflict DECISION is product-made. Entries
/// not in any set (a partial report) are omitted (didn't land).
fn join(entries: &[BootstrapEntry], report: &BootstrapReport) -> Vec<M015BootstrapEntry> {
    entries
        .iter()
        .filter_map(|e| {
            let outcome =
                if report.spawned.iter().any(|a| a.0 == e.alias) {
                    Some(M015BootstrapOutcome::Spawned)
                } else if report.skipped.iter().any(|a| a.0 == e.alias) {
                    Some(M015BootstrapOutcome::Skipped {
                        skip_reason: SkippedKind::AliasExistsTemplateMatches,
                    })
                } else if report.conflicts.iter().any(
                    |c| matches!(c, BootstrapEvent::Conflict { alias, .. } if alias.0 == e.alias),
                ) {
                    // apply_auto_bootstrap pushes to report.conflicts ONLY for the
                    // template_ref-mismatch case (auto_bootstrap.rs:280); path-mismatch /
                    // path-occupied are returned as errors, not conflict entries.
                    Some(M015BootstrapOutcome::Conflict {
                        conflict_type: ConflictKind::TemplateMismatch,
                    })
                } else {
                    None
                };
            outcome.map(|o| M015BootstrapEntry {
                template: e.template.clone(),
                alias: e.alias.clone(),
                target_path: e.target_path.to_string_lossy().into_owned(),
                outcome: o,
            })
        })
        .collect()
}

/// The deferred MODULE-015 → MODULE-005 applier seam, supplied test-side: parses +
/// applies via REAL cap-lifecycle product code over a real spawner + tree.
struct CapLifecycleApplier {
    spawner: DefaultSpawner,
    tree: AgentTreeStore,
}
#[async_trait]
impl AutoBootstrapApplier for CapLifecycleApplier {
    async fn apply(
        &self,
        parent_agent_id: &str,
        raw_yaml: &str,
    ) -> Result<M015BootstrapReport, AutoBootstrapApplierError> {
        let entries = parse_auto_bootstrap(raw_yaml)
            .map_err(|e| AutoBootstrapApplierError::Parse(format!("{e}")))?;
        let parent = AgentId(parent_agent_id.to_string());
        match apply_auto_bootstrap(&entries, &parent, &self.spawner, &self.tree) {
            Ok(report) => Ok(M015BootstrapReport {
                entries: join(&entries, &report),
            }),
            Err(BootstrapError::SubKindRejected { alias, partial }) => {
                let landed = join(&entries, &partial);
                let msg = format!("sub-kind rejected for alias {alias}");
                if landed.is_empty() {
                    Err(AutoBootstrapApplierError::Validation(msg))
                } else {
                    Err(AutoBootstrapApplierError::Dispatch {
                        msg,
                        partial: M015BootstrapReport { entries: landed },
                    })
                }
            }
            Err(other) => Err(AutoBootstrapApplierError::Validation(format!("{other}"))),
        }
    }
}

struct Fixtures {
    _tmp: TempDir,
    tree: AgentTreeStore,
    driver: DefaultAutoLoopDriver,
    calls: Arc<Mutex<Vec<BootstrapEventPayload>>>,
}

fn fixtures() -> Fixtures {
    let tmp = TempDir::new().unwrap();
    let workspace_root = tmp.path().canonicalize().unwrap();
    let tree = AgentTreeStore::new(workspace_root.clone()).unwrap();
    let root_ws = workspace_root.join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner = DefaultSpawner::with_template_resolver(
        tree.clone(),
        Arc::new(AlwaysOkGate),
        Arc::new(BuiltinTemplateRegistry::new()),
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    let driver = DefaultAutoLoopDriver::new(Arc::new(NoopCheckpoint), Arc::new(NoopRollback))
        .with_auto_bootstrap_applier(Arc::new(CapLifecycleApplier {
            spawner,
            tree: tree.clone(),
        }))
        .with_auto_bootstrap_event_sink(Arc::new(RecordingSink {
            calls: calls.clone(),
        }));
    Fixtures {
        _tmp: tmp,
        tree,
        driver,
        calls,
    }
}

fn entry_yaml(template: &str, alias: &str, target: &str, kind: &str) -> String {
    format!(
        "- template: {template}\n  kind: {kind}\n  target-path: {target}\n  alias: {alias}\n  ensure: present\n"
    )
}

/// SYS-AC-025 — ensure:present, alias absent → the declared child is spawned in the
/// tree AND an `auto.bootstrap.spawned` payload is emitted.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_025_ensure_present_absent_alias_spawns_and_emits_spawned() {
    let f = fixtures();
    let yaml = entry_yaml("explorer", "scout", "agents/scout", "child");
    f.driver
        .consult_auto_bootstrap("root", &yaml)
        .await
        .expect("consult ok");

    // Child node really spawned (PRODUCT tree state).
    assert!(
        f.tree.get_node(&AgentId("scout".to_string())).is_some(),
        "the declared child was spawned in the tree"
    );

    // Exactly one auto.bootstrap.spawned payload (PRODUCT-emitted via the sink).
    let payloads = f.calls.lock().unwrap().clone();
    assert_eq!(payloads.len(), 1, "exactly one bootstrap event");
    match payloads.into_iter().next().unwrap() {
        BootstrapEventPayload::Spawned {
            agent_id,
            template,
            alias,
            target_path,
        } => {
            assert_eq!(agent_id, "root", "agent_id = the parent root");
            assert_eq!(template, "explorer");
            assert_eq!(alias, "scout");
            assert_eq!(target_path, "agents/scout");
        }
        other => panic!("expected Spawned, got {other:?}"),
    }
}

/// SYS-AC-026 — re-running with the same alias + same template_ref ("version") yields
/// no new spawn and an `auto.bootstrap.skipped` payload (idempotent).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_026_same_alias_same_template_skips() {
    let f = fixtures();
    let yaml = entry_yaml("explorer", "scout", "agents/scout", "child");
    f.driver
        .consult_auto_bootstrap("root", &yaml)
        .await
        .expect("consult 1 (spawn)");
    // Drop a sentinel into the spawned workspace BEFORE the second consult, to prove the
    // skip path does not RE-MATERIALIZE the workspace (adversarial r8 strengthening).
    let scout_ws = f
        .tree
        .get_node(&AgentId("scout".to_string()))
        .expect("scout spawned")
        .workspace_path;
    let sentinel = scout_ws.join(".agent").join("sentinel-026");
    std::fs::write(&sentinel, b"keep").unwrap();
    f.driver
        .consult_auto_bootstrap("root", &yaml)
        .await
        .expect("consult 2 (skip)");

    let payloads = f.calls.lock().unwrap().clone();
    assert_eq!(payloads.len(), 2, "spawn then skip");
    assert!(
        matches!(payloads[0], BootstrapEventPayload::Spawned { .. }),
        "first consult spawned"
    );
    match payloads[1].clone() {
        BootstrapEventPayload::Skipped {
            agent_id,
            alias,
            target_path,
        } => {
            assert_eq!(agent_id, "root");
            assert_eq!(alias, "scout");
            assert_eq!(target_path, "agents/scout");
        }
        other => panic!("expected Skipped on the second consult, got {other:?}"),
    }
    // No new spawn / no re-materialization: the Skipped payload IS the product's no-spawn
    // decision (apply_auto_bootstrap pushes to report.skipped WITHOUT calling spawn_child;
    // a re-spawn of an existing alias would instead error AlreadyExists), AND the sentinel
    // survives — the skip did not re-initialize the existing workspace.
    assert!(f.tree.get_node(&AgentId("scout".to_string())).is_some());
    assert!(
        sentinel.exists(),
        "the skip did not re-materialize the existing workspace (sentinel survived)"
    );
}

/// SYS-AC-027 — re-running with the same alias/path but a DIFFERENT template_ref yields
/// an `auto.bootstrap.conflict{template_mismatch}` payload and no overwrite.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_027_template_mismatch_conflicts_no_overwrite() {
    let f = fixtures();
    let yaml1 = entry_yaml("explorer", "scout", "agents/scout", "child");
    let yaml2 = entry_yaml("planner", "scout", "agents/scout", "child"); // same alias/path, diff template
    f.driver
        .consult_auto_bootstrap("root", &yaml1)
        .await
        .expect("consult 1 (spawn)");
    f.driver
        .consult_auto_bootstrap("root", &yaml2)
        .await
        .expect("consult 2 (conflict)");

    let payloads = f.calls.lock().unwrap().clone();
    assert_eq!(payloads.len(), 2, "spawn then conflict");
    assert!(matches!(payloads[0], BootstrapEventPayload::Spawned { .. }));
    match payloads[1].clone() {
        BootstrapEventPayload::Conflict {
            agent_id,
            alias,
            target_path,
            conflict_type,
        } => {
            assert_eq!(agent_id, "root");
            assert_eq!(alias, "scout");
            assert_eq!(target_path, "agents/scout");
            assert_eq!(conflict_type, "template_mismatch");
        }
        other => panic!("expected Conflict on the second consult, got {other:?}"),
    }
    // No overwrite: the existing node still carries the ORIGINAL template_ref.
    let scout = f
        .tree
        .get_node(&AgentId("scout".to_string()))
        .expect("scout still exists");
    assert_eq!(
        scout.template_ref.as_deref(),
        Some("explorer"),
        "the conflicting consult did NOT overwrite the existing node's template_ref"
    );

    // Criterion-fidelity (adversarial r8): the criterion lists "alias/path/version
    // mismatch -> conflict event". Only the VERSION (template_ref) mismatch yields an
    // auto.bootstrap.conflict EVENT (asserted above). A PATH mismatch (same alias,
    // DIFFERENT target-path) surfaces as a product ERROR (BootstrapError::AliasPathMismatch,
    // auto_bootstrap.rs:288), NOT a conflict event — witness that real product behavior so
    // the disjunct is covered. (Criterion-wording drift recorded for the next /spec rerun:
    // alias/path mismatch is a product Err, not an auto.bootstrap.conflict event.)
    let before = f.calls.lock().unwrap().len();
    let yaml_pathmm = entry_yaml("explorer", "scout", "agents/relocated", "child"); // same alias, diff path
    let err = f
        .driver
        .consult_auto_bootstrap("root", &yaml_pathmm)
        .await
        .expect_err("an alias/path mismatch is rejected as a product error, not a conflict event");
    assert!(
        matches!(err, AutoLoopError::AutoBootstrap(_)),
        "path mismatch surfaces as a coordination error, got {err:?}"
    );
    assert_eq!(
        f.calls.lock().unwrap().len(),
        before,
        "a path mismatch emits NO new bootstrap event (it is a product Err, not a conflict event)"
    );
    let scout_after = f
        .tree
        .get_node(&AgentId("scout".to_string()))
        .expect("scout still exists after the path-mismatch attempt");
    assert_eq!(
        scout_after.template_ref.as_deref(),
        Some("explorer"),
        "the path-mismatch attempt did NOT overwrite the existing node"
    );
}

/// SYS-AC-200 — an entry declaring kind:sub is rejected at bootstrap apply-time, with
/// no agent spawned and no `auto.bootstrap.spawned` emitted for it.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_200_sub_kind_rejected_no_spawn_no_event() {
    let f = fixtures();
    let yaml = entry_yaml("explorer", "subby", "agents/subby", "sub");
    let err = f
        .driver
        .consult_auto_bootstrap("root", &yaml)
        .await
        .expect_err("a kind:sub entry must be rejected at apply-time");
    // Surfaced as the coordination-layer ApplierFailed (the product apply_auto_bootstrap
    // step-1 SubKindRejected, mapped through the applier).
    assert!(
        matches!(err, AutoLoopError::AutoBootstrap(_)),
        "rejected via the AutoBootstrap coordination error, got {err:?}"
    );
    // No auto.bootstrap.* payload emitted for the rejected sub entry.
    let payloads = f.calls.lock().unwrap().clone();
    assert!(
        payloads.is_empty(),
        "no bootstrap event emitted for a rejected sub entry, got {payloads:?}"
    );
    // No agent spawned.
    assert!(
        f.tree.get_node(&AgentId("subby".to_string())).is_none(),
        "no node spawned for the rejected sub entry"
    );
}
