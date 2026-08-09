//! SYS-J-44 — an agent queries self-stats/child-stats via agent-lifecycle and
//! receives aggregates populated from the observability agent_stats table.
//! Chain: MODULE-005 → MODULE-019 → MODULE-004.
//!
//! Witnesses (harvest-obs slice, 2026-06-10): **SYS-AC-140, SYS-AC-141,
//! SYS-AC-142, SYS-AC-232** — test-local real wiring over the production async
//! `EventBus::new` (the only mode running the M019 stats_aggregator actor):
//! REAL `llm.response` events from the REAL `LlmGateway` (h_loopback scripted
//! backend, the sole allowed double) feed the REAL stats_aggregator → REAL
//! `agent_stats` SQLite rows (1s-tick flush; bounded poll) → REAL
//! `SqliteAgentStatsReader` (CONTRACT-030 handle over the same events.db) →
//! REAL `DefaultStatsController` over a REAL `AgentTreeStore` → the production
//! `register_agent_lifecycle` WIT dispatch lowering the full `agent-stats`
//! record (CONTRACT-041).
//!
//! **Fidelity disclosures (per plan + MODULE-019 §3.6 item 29 + MODULE-005
//! §3.8)**:
//! - `active_tasks`/`completed_tasks` are fed by TEST-EMITTED
//!   `task.created`/`task.completed` events through the real bus, because NO
//!   production emitter for these two event types exists on main (the merged
//!   decomp work emits `task.decomposed`/`task.subtask_updated` — different
//!   events). `llm_tokens_24h` has a REAL producer (the gateway). The producer
//!   is out-of-journey for SYS-J-44 (the chain starts at the M005 query side);
//!   the aggregation/read/lowering legs are 100% real.
//! - Caller identity is host-supplied via a test-built `HostCallContext` —
//!   exactly what production's host-authoritative stamping supplies. What
//!   these tests prove is the BELOW-handler-boundary behavior (real tree
//!   parent_of discrimination, real SQLite reads, real record lowering);
//!   grant-gate authorization and guest-bound identity are NOT claimed
//!   (harness fidelity caveat, system-acceptance lib.rs:1577-1590).

#[path = "h_loopback/mod.rs"]
mod h_loopback;
use h_loopback::{boot, GatewayDeps, ScriptedResponse};

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use advance_database::{DbError, PooledConnection, SqliteIndexHandle};
use advance_event_bus::{EventBus, EventBusConfig};
use advance_run_manager::{RepetitionAction, RepetitionGuard, RunManager};
use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, RunBudget};
use cap_lifecycle::templates::BuiltinTemplateRegistry;
use cap_lifecycle::{
    register_agent_lifecycle, AgentLifecycleBundle, AgentTreeStore, CheckpointEntry, ComponentInfo,
    ComponentState, ComponentSubmitConfig, ComponentSubmitGate, DecompositionError,
    DecompositionPlan, DecompositionReceipt, DecompositionState, DecompositionStore,
    DefaultCheckpointController, DefaultRollbackController, DefaultSpawner, DefaultStatsController,
    DefaultTerminateController, GrantCascadeRevoke, LifecycleError, MailboxCascade,
    NamedCheckpointGate, RollbackModeSpec, RollbackTargetSpec, RunCascade, SpawnError,
    SpawnerSubsetGate, SqliteAgentStatsReader, SubtaskStatus, WorkspaceCleanup,
    WorkspaceRollbackGate, AGENT_LIFECYCLE_CAPABILITY,
};
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmGatewayInternal};
use rusqlite::OpenFlags;
use wasmtime::component::Val;

const PARENT: &str = "obs-a"; // bare ids — cap-lifecycle validate_agent_id rejects colons
const CHILD: &str = "obs-c";
const OTHER: &str = "obs-x"; // exists in the tree, NOT a child of obs-a
const ABSENT: &str = "ghost-z";

// ── bundle stubs (test-local re-declarations; the cap-lifecycle test-crate
//    stubs are private to that binary — plan §3 construction note) ───────────
struct OkGate;
impl SpawnerSubsetGate for OkGate {
    fn check(
        &self,
        _: &[advance_shared_types::agent_tree::Capability],
        _: &[advance_shared_types::agent_tree::Capability],
    ) -> Result<(), SpawnError> {
        Ok(())
    }
}
struct OkCascade;
impl GrantCascadeRevoke for OkCascade {
    fn revoke_for_agent(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
impl MailboxCascade for OkCascade {
    fn flush_mailbox(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn notify_parent_crash(&self, _: &str, _: &str, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
impl RunCascade for OkCascade {
    fn ensure_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn cancel_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
impl WorkspaceCleanup for OkCascade {
    fn remove_sub_workspace(&self, _: &std::path::Path) -> Result<(), LifecycleError> {
        Ok(())
    }
}
struct OkRollbackGate;
impl WorkspaceRollbackGate for OkRollbackGate {
    fn rollback(
        &self,
        _: &str,
        _: RollbackTargetSpec,
        _: RollbackModeSpec,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        Ok(vec![])
    }
    fn rollback_to_checkpoint(&self, _: &str, _: &str) -> Result<Vec<PathBuf>, LifecycleError> {
        Ok(vec![])
    }
}
struct OkCkptGate;
impl NamedCheckpointGate for OkCkptGate {
    fn create(&self, _: &str, _: &str, _: Option<Vec<PathBuf>>) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn list(&self, _: &str) -> Result<Vec<CheckpointEntry>, LifecycleError> {
        Ok(vec![])
    }
}
struct StubSubmit;
#[async_trait::async_trait]
impl ComponentSubmitGate for StubSubmit {
    async fn submit_component(
        &self,
        _: &str,
        _: ComponentSubmitConfig,
    ) -> Result<cap_lifecycle::ComponentId, SpawnError> {
        Err(SpawnError::InvalidConfig("not wired".into()))
    }
    async fn kill_component(&self, _: &str) -> Result<(), SpawnError> {
        Ok(())
    }
    async fn component_status(&self, _: &str) -> Result<ComponentState, SpawnError> {
        Ok(ComponentState::Pending)
    }
    async fn list_components(&self) -> Vec<ComponentInfo> {
        vec![]
    }
}
struct NoopDecomp;
impl DecompositionStore for NoopDecomp {
    fn submit(
        &self,
        _: &str,
        _: &str,
        _: DecompositionPlan,
    ) -> Result<DecompositionReceipt, DecompositionError> {
        Ok(DecompositionReceipt {
            subtask_ids: vec![],
        })
    }
    fn update_subtask_status(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: SubtaskStatus,
        _: Option<String>,
    ) -> Result<SubtaskStatus, DecompositionError> {
        Ok(SubtaskStatus::Pending)
    }
    fn get(&self, _: &str, _: &str) -> Result<Option<DecompositionState>, DecompositionError> {
        Ok(None)
    }
}
struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _e: Event) {}
}

/// Read-only CONTRACT-030 `get_conn` adapter over the M019 events.db.
///
/// Why not the production `R2d2SqliteIndexHandle`: its constructor runs the
/// CONTRACT-030 index migrations and enforces ITS schema `user_version` (1),
/// while the events.db carries the M019 event-bus `user_version` (3) — the two
/// schema owners cannot share one file today (SchemaMismatch{stored:3,
/// expected:1}; pre-existing deployment gap, recorded in MODULE-005 §3.8 /
/// the harvest-obs SUMMARY). `SqliteAgentStatsReader`'s contract consumes ONLY
/// `get_conn` (read-only, sqlite_agent_stats_reader.rs); this adapter supplies
/// REAL pooled connections to the REAL aggregator-written db — the CONTRACT-030
/// index write surface is never invoked and panics loudly if it ever is.
struct EventsDbReadHandle {
    pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
}
impl EventsDbReadHandle {
    fn open(db_path: &std::path::Path) -> Self {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mgr = r2d2_sqlite::SqliteConnectionManager::file(db_path).with_flags(flags);
        let pool = r2d2::Pool::builder()
            .max_size(2)
            .build(mgr)
            .expect("events.db pool");
        Self { pool }
    }
}
impl SqliteIndexHandle for EventsDbReadHandle {
    fn get_conn(&self) -> Result<PooledConnection, DbError> {
        self.pool
            .get()
            .map_err(|e| DbError::InvalidConfig(format!("events.db pool: {e}")))
    }
    fn schema_version(&self) -> u32 {
        3 // the M019 event-bus schema version of the underlying db
    }
    fn run_migrations(&self) -> Result<(), DbError> {
        Ok(()) // db is owned + migrated by the event-bus; read-only here
    }
    fn upsert_content_index(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&[f32]>,
        _: Option<&str>,
    ) -> Result<(), DbError> {
        unreachable!("read-only events.db adapter — index write surface unused")
    }
    fn upsert_meta_index(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&[f32]>,
    ) -> Result<(), DbError> {
        unreachable!("read-only events.db adapter — index write surface unused")
    }
    fn delete_content_index_row(&self, _: &str, _: &str) -> Result<(), DbError> {
        unreachable!("read-only events.db adapter — index write surface unused")
    }
    fn delete_meta_index_row(&self, _: &str, _: &str, _: &str) -> Result<(), DbError> {
        unreachable!("read-only events.db adapter — index write surface unused")
    }
    fn upsert_task_index(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<i64>,
        _: Option<&[f32]>,
    ) -> Result<(), DbError> {
        unreachable!("read-only events.db adapter — index write surface unused")
    }
    #[allow(clippy::too_many_arguments)]
    fn upsert_turn_index(
        &self,
        _: &str,
        _: &str,
        _: u32,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<bool>,
        _: Option<bool>,
        _: Option<bool>,
        _: Option<bool>,
        _: Option<&[f32]>,
        _: Option<i64>,
        _: Option<i64>,
    ) -> Result<(), DbError> {
        unreachable!("read-only events.db adapter — index write surface unused")
    }
    fn bump_turn_reference(&self, _: &str, _: &str, _: u32) -> Result<bool, DbError> {
        unreachable!("read-only events.db adapter — index write surface unused")
    }
}

/// Real tree: obs-root → {obs-a, obs-x}, obs-a → obs-c.
fn build_tree(tmp: &std::path::Path) -> AgentTreeStore {
    let tree = AgentTreeStore::new(tmp.to_path_buf()).unwrap();
    let rws = tree.workspace_root().join("obs-root");
    std::fs::create_dir_all(&rws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("obs-root".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: rws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    for (id, parent, rel) in [
        (PARENT, "obs-root", "obs-root/a"),
        (OTHER, "obs-root", "obs-root/x"),
        (CHILD, PARENT, "obs-root/a/c"),
    ] {
        let ws = tree.workspace_root().join(rel);
        std::fs::create_dir_all(&ws).unwrap();
        tree.insert_child(
            &AgentId(parent.into()),
            AgentNode {
                id: AgentId(id.into()),
                kind: AgentKind::Child,
                parent: Some(AgentId(parent.into())),
                workspace_path: ws,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            },
        )
        .unwrap();
    }
    tree
}

fn bundle(tree: AgentTreeStore, stats: Arc<DefaultStatsController>) -> AgentLifecycleBundle {
    AgentLifecycleBundle {
        tree: tree.clone(),
        spawner: Arc::new(DefaultSpawner::new(tree.clone(), Arc::new(OkGate))),
        rollback: Arc::new(DefaultRollbackController::new(
            tree.clone(),
            Arc::new(OkRollbackGate),
        )),
        checkpoint: Arc::new(DefaultCheckpointController::new(
            tree.clone(),
            Arc::new(OkCkptGate),
            Arc::new(OkRollbackGate),
        )),
        terminate: Arc::new(DefaultTerminateController::new(
            tree.clone(),
            Arc::new(OkCascade),
            Arc::new(OkCascade),
            Arc::new(OkCascade),
            Arc::new(OkCascade),
        )),
        decomposition: Arc::new(NoopDecomp),
        stats,
        templates: Arc::new(BuiltinTemplateRegistry::new()),
        submit_gate: Arc::new(StubSubmit),
        event_bus: Arc::new(NoopBus),
    }
}

fn ctx(caller: &str, op: &str) -> HostCallContext {
    HostCallContext {
        agent_id: caller.into(),
        trace_id: "trace-j44".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: format!("advance:runtime/agent-lifecycle::{op}"),
        run_id: None,
        iteration: None,
    }
}

/// Bounded poll until the agent_stats row for `agent_id` satisfies `pred`.
fn poll_agent_stats<F: Fn(&rusqlite::Row<'_>) -> bool>(
    db: &std::path::Path,
    agent_id: &str,
    what: &str,
    pred: F,
) {
    for _ in 0..1200 {
        if let Ok(conn) = rusqlite::Connection::open_with_flags(
            db,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            let hit = conn
                .query_row(
                    "SELECT active_tasks, completed_tasks, llm_tokens_24h FROM agent_stats \
                     WHERE agent_id = ?1",
                    [agent_id],
                    |r| Ok(pred(r)),
                )
                .unwrap_or(false);
            if hit {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("agent_stats row for {agent_id} never satisfied: {what} (~6s)");
}

fn record_fields(v: &Val) -> &Vec<(String, Val)> {
    let Val::Result(Ok(Some(rec))) = v else {
        panic!("expected Val::Result(Ok(Some(record))), got {v:?}")
    };
    let Val::Record(fields) = rec.as_ref() else {
        panic!("expected Val::Record (agent-stats), got {rec:?}")
    };
    fields
}

fn field<'a>(fields: &'a [(String, Val)], name: &str) -> &'a Val {
    &fields
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("field {name}"))
        .1
}

fn err_variant_name(v: &Val) -> String {
    let Val::Result(Err(Some(b))) = v else {
        panic!("expected Val::Result(Err(Some(variant))), got {v:?}")
    };
    let Val::Variant(case, _) = b.as_ref() else {
        panic!("expected Val::Variant, got {b:?}")
    };
    case.clone()
}

/// One combined journey run (the four SYS-AC share the wired system + the
/// 1s-tick aggregation wait; separate tests would quadruple the wall-clock for
/// no extra witness value — each SYS-AC has its own labelled assertion block).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_140_141_142_232_stats_via_agent_lifecycle_over_real_agent_stats() {
    // ── real async bus (stats_aggregator actor lives only here) ─────────────
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("adv-obs-stats-{nanos}"));
    std::fs::create_dir_all(&base).unwrap();
    let db = base.join("events.db");
    let mut cfg = EventBusConfig::new(base.join("jsonl"), db.clone());
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    let bus = Arc::new(EventBus::new(cfg).await.expect("async EventBus::new"));
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

    // ── REAL llm.response producers: one gateway per agent id ───────────────
    let budget: Arc<dyn RunBudget> = Arc::new(RunManager::new(bus_dyn.clone()).budget());
    let guard = Arc::new(RepetitionGuard::new(64, 100, RepetitionAction::WarnOnly));
    for (agent, tokens_in, tokens_out) in [(PARENT, 300u64, 550u64), (CHILD, 5, 6)] {
        let harness = boot(
            vec![ScriptedResponse::ok_chat("reply", tokens_in, tokens_out)],
            GatewayDeps {
                run_budget: budget.clone(),
                repetition_guard: guard.clone(),
                event_bus: bus_dyn.clone(),
                default_agent_id: agent.into(),
            },
        )
        .await;
        harness
            .gateway
            .chat(
                vec![ChatMessage {
                    role: ChatRole::User,
                    content: "hi".into(),
                }],
                ChatParams::default(),
            )
            .await
            .expect("real gateway call emits llm.response");
    }

    // ── task.* counter feed (TEST-EMITTED; disclosed in the module header —
    //    no production task.created/task.completed emitter exists on main) ───
    bus_dyn.emit(Event::observability(
        "task.created",
        PARENT,
        serde_json::json!({}),
        None,
    ));
    bus_dyn.emit(Event::observability(
        "task.created",
        PARENT,
        serde_json::json!({}),
        None,
    ));
    bus_dyn.emit(Event::observability(
        "task.completed",
        PARENT,
        serde_json::json!({}),
        None,
    ));

    // ── wait for the REAL stats_aggregator 1s-tick flush ────────────────────
    // The predicates demand the COMPLETE final state per agent (conjunction
    // over every fed counter), so a partial flush (e.g. llm.response landing a
    // tick before the task.* events) cannot satisfy them early.
    poll_agent_stats(&db, PARENT, "llm 850 + active 1 + completed 1", |r| {
        r.get::<_, Option<i64>>(0).ok().flatten() == Some(1)
            && r.get::<_, Option<i64>>(1).ok().flatten() == Some(1)
            && r.get::<_, Option<i64>>(2).ok().flatten() == Some(850)
    });
    poll_agent_stats(&db, CHILD, "llm 11", |r| {
        r.get::<_, Option<i64>>(2).ok().flatten() == Some(11)
    });
    // Quiescence guard (audit r9): every event above has been delivered and
    // both rows hold their final values; one extra aggregator tick must leave
    // them byte-identical. This pins "the rows the WIT reads below are stable",
    // killing any flush-race between the polls and the 140/142 assertions.
    let snapshot_rows = |db: &std::path::Path| -> Vec<(String, String)> {
        let conn = rusqlite::Connection::open_with_flags(
            db,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, active_tasks || '|' || completed_tasks || '|' || \
                 llm_tokens_24h || '|' || error_count_24h FROM agent_stats \
                 WHERE agent_id IN (?1, ?2) ORDER BY agent_id",
            )
            .unwrap();
        stmt.query_map([PARENT, CHILD], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    };
    let before = snapshot_rows(&db);
    std::thread::sleep(Duration::from_millis(1200)); // > one aggregator tick
    let after = snapshot_rows(&db);
    assert_eq!(
        before, after,
        "agent_stats rows are quiescent across a full aggregator tick"
    );

    // ── REAL M005 read path over the same events.db (read-only get_conn
    //    adapter — see EventsDbReadHandle doc for why the production R2d2
    //    handle cannot open this db) ────────────────────────────────────────
    let handle = EventsDbReadHandle::open(&db);
    let reader = Arc::new(SqliteAgentStatsReader::new(Arc::new(handle)));
    let tree_tmp = tempfile::TempDir::new().unwrap();
    let tree = build_tree(tree_tmp.path());
    let stats = Arc::new(DefaultStatsController::new(tree.clone(), reader));
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle(tree, stats));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let self_stats = &specs
        .iter()
        .find(|s| s.name == "self-stats")
        .unwrap()
        .handler;
    let child_stats = &specs
        .iter()
        .find(|s| s.name == "child-stats")
        .unwrap()
        .handler;

    // ── SYS-AC-140: self-stats returns the populated record ─────────────────
    let out = HostFunctionHandler::call(self_stats.as_ref(), ctx(PARENT, "self-stats"), vec![], 1)
        .await
        .expect("self-stats dispatch ok");
    let fields = record_fields(&out[0]);
    assert_eq!(
        field(fields, "llm-tokens-24h"),
        &Val::U64(850),
        "REAL llm.response aggregation"
    );
    assert_eq!(
        field(fields, "active-tasks"),
        &Val::U32(1),
        "task.created x2 - completed x1"
    );
    assert_eq!(field(fields, "completed-tasks"), &Val::U32(1));
    let Val::String(last_active) = field(fields, "last-active") else {
        panic!("last-active is a string")
    };
    assert!(
        !last_active.is_empty(),
        "last-active populated from the table"
    );

    // ── SYS-AC-142: every record field matches the SQLite row exactly ───────
    let conn = rusqlite::Connection::open_with_flags(
        &db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let (a, c, avg_t, avg_h, mem, llm, errs, la) = conn
        .query_row(
            "SELECT active_tasks, completed_tasks, avg_turns_per_task, \
             avg_completion_time_hours, memory_entries, llm_tokens_24h, \
             error_count_24h, last_active FROM agent_stats WHERE agent_id = ?1",
            [PARENT],
            |r| {
                Ok((
                    r.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    r.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    r.get::<_, Option<f64>>(2)?.unwrap_or(0.0),
                    r.get::<_, Option<f64>>(3)?.unwrap_or(0.0),
                    r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                    r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                ))
            },
        )
        .expect("the agent_stats row the record must mirror");
    assert_eq!(
        field(fields, "active-tasks"),
        &Val::U32(a as u32),
        "142: active_tasks"
    );
    assert_eq!(
        field(fields, "completed-tasks"),
        &Val::U32(c as u32),
        "142: completed_tasks"
    );
    assert_eq!(
        field(fields, "avg-turns-per-task"),
        &Val::Float32(avg_t as f32),
        "142: avg_turns (NULL→0.0)"
    );
    assert_eq!(
        field(fields, "avg-completion-time-hours"),
        &Val::Float32(avg_h as f32),
        "142: avg_hours (NULL→0.0)"
    );
    assert_eq!(
        field(fields, "memory-entries"),
        &Val::U32(mem as u32),
        "142: memory (NULL→0)"
    );
    assert_eq!(
        field(fields, "llm-tokens-24h"),
        &Val::U64(llm as u64),
        "142: llm tokens"
    );
    assert_eq!(
        field(fields, "error-count-24h"),
        &Val::U32(errs as u32),
        "142: errors"
    );
    assert_eq!(
        field(fields, "last-active"),
        &Val::String(la),
        "142: last_active verbatim"
    );

    // ── SYS-AC-141: child-stats happy leg + permission-denied leg ───────────
    let out = HostFunctionHandler::call(
        child_stats.as_ref(),
        ctx(PARENT, "child-stats"),
        vec![Val::String(CHILD.into())],
        1,
    )
    .await
    .expect("child-stats happy dispatch ok");
    let child_fields = record_fields(&out[0]);
    assert_eq!(
        field(child_fields, "llm-tokens-24h"),
        &Val::U64(11),
        "141: the CHILD's aggregates (5+6 from its real llm.response)"
    );
    let out = HostFunctionHandler::call(
        child_stats.as_ref(),
        ctx(PARENT, "child-stats"),
        vec![Val::String(OTHER.into())],
        1,
    )
    .await
    .expect("child-stats non-child dispatch ok");
    let pd = err_variant_name(&out[0]);
    assert_eq!(
        pd, "permission-denied",
        "141: existing non-child → permission-denied"
    );

    // ── SYS-AC-232: absent id → not-found, DISTINCT from 141's variant ──────
    let out = HostFunctionHandler::call(
        child_stats.as_ref(),
        ctx(PARENT, "child-stats"),
        vec![Val::String(ABSENT.into())],
        1,
    )
    .await
    .expect("child-stats absent dispatch ok");
    let nf = err_variant_name(&out[0]);
    assert_eq!(nf, "not-found", "232: absent agent id → not-found");
    assert_ne!(
        nf, pd,
        "232: not-found is distinguishable from permission-denied"
    );
}
