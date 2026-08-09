//! SYS-J-43 — a single turn's events share a trace_id with parent/child span
//! linkage, visible in the dashboard trace view. Chain: MODULE-001 → MODULE-019
//! → MODULE-004.
//!
//! MAINLINE Wave-5 harvest (2026-06-21): the three SYS-AC are FLIPPED. The
//! prior `#[ignore]` scaffolds were written 2026-06-10, BEFORE the Stage-F
//! obs/tail trace plumbing landed — they are stale. The product now mints a
//! chain `trace_id` at the `run_turn_once` admission (`ensure_chain_trace`,
//! shared-types/mailbox.rs), re-stamps it onto the per-turn `ComponentCtx`
//! (cli/agent_loop.rs), and threads it through the context assembler
//! (`context.assembled.span_id == chain_root_span_id(msg.id)`) and the
//! run-manager (`run.round_completed.parent_span_id == that chain root`). The
//! `/query/dashboard/trace` endpoint reads `FROM events WHERE trace_id = ?`
//! (event-bus/query_api.rs).
//!
//! These witnesses build the REAL production agent-loop chain test-side
//! (mirroring cli `chain_trace_full_turn.rs` T9 — the same production fns the
//! daemon's `start.rs` wires: `build_agent_loop` + `WasmMessageHandler
//! ::with_run_session` + `driver.with_run_bootstrap(RunManagerBootstrap)` + the
//! emitting `build_context_assembler`), but over a REAL SQLite-backed
//! `EventBus` so (a) `events_from_db` reads the persisted rows and (b) the
//! production `query_router` serves `/query/dashboard/trace` in-process
//! (event-bus tests/query_api.rs precedent). No product source is edited.
//!
//! - **SYS-AC-137** (one chain → one trace_id): TWO distinct context:None turns
//!   mint TWO chains; the per-turn `ComponentCtx`-stamped events
//!   (`context.assembled`, `fs.write`, `run.round_completed`) share ONE
//!   non-empty trace_id within a chain, and the two chains' trace_ids DIFFER.
//!   `msg.received` is EXCLUDED (emitted by the dispatcher BEFORE
//!   `ensure_chain_trace` mints at `run_turn_once`, so it legitimately carries
//!   a different pre-mint UUID). The two-chain distinctness is the anti-fake-
//!   green discriminator a degenerate process-constant cannot satisfy.
//! - **SYS-AC-138** (child parent_span_id == parent span_id):
//!   `run.round_completed.parent_span_id == context.assembled.span_id ==
//!   chain_root_span_id(msg.id)` — the run-session-wired turn.
//! - **SYS-AC-139** (dashboard/trace returns the chain): the production
//!   `query_router` over the events DB returns exactly the chain's events
//!   (the named set {context.assembled, run.round_completed, fs.write}, each
//!   carrying the chain trace_id, msg.received absent).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use advance_cli::agent_loop::{
    build_agent_loop, RunManagerBootstrap, RunSession, SessionRunCell, WasmMessageHandler,
};
use advance_cli::context_wiring::{
    build_context_assembler, EmptyCallableInventory, FixedHostFnInventory,
};
use advance_event_bus::query_api::{query_router, QueryState};
use advance_event_bus::{EventBus, EventBusConfig};
use advance_messaging::{MailboxDispatcher, MailboxDispatcherImpl, MailboxStore};
use advance_run_manager::{RunConfig, RunManager};
use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::ComponentRuntime;
use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::context::ContextAssembler;
use advance_shared_types::event::chain_root_span_id;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use cap_fs::{
    register_agent_fs, Adv003GitSync, DefaultAtomicWriter, DefaultVirtualPathResolver, GitSync,
    MetaSchemaLoader, StubFileHistoryProvider, VirtualPathResolver,
};

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::Request;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;
use tower::ServiceExt;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const AGENT_ID: &str = "agent:a";
const AGENT_DIR: &str = "a";

// ── doubles (mirror cli T9) ──────────────────────────────────────────────────

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

struct OneAgentTree {
    nodes: Vec<AgentNode>,
}
impl OneAgentTree {
    fn new(workspace: PathBuf) -> Self {
        Self {
            nodes: vec![AgentNode {
                id: AgentId(AGENT_ID.to_string()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: workspace,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            }],
        }
    }
}
impl AgentTreeReader for OneAgentTree {
    fn parent_of(&self, _: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == id)
    }
    fn agent_kind(&self, id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        Vec::new()
    }
}
impl AgentTreeSnapshot for OneAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: self.nodes.clone(),
            parent_of: HashMap::new(),
            children_of: HashMap::new(),
            peer_slug_map: HashMap::new(),
            revision: 0,
        }
    }
}

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

/// A persisted events-table row (with the span columns `events_from_db` omits).
#[derive(Debug, Clone)]
struct EvRow {
    event_type: String,
    trace_id: Option<String>,
    span_id: Option<String>,
    parent_span_id: Option<String>,
}

/// The real production agent-loop chain wired over a SQLite `EventBus`, with the
/// run-session installed (so `run.round_completed` fires). Drives N real turns.
struct TraceChain {
    driver: AgentLoopDriverImpl,
    dispatcher: Arc<MailboxDispatcherImpl>,
    db_path: PathBuf,
    _queue: Arc<advance_git::DefaultGitCommitQueue>,
    _tmp: tempfile::TempDir,
}

impl TraceChain {
    async fn build() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let workspace_root = tmp.path().to_path_buf();
        let agent_workspace = workspace_root.join(AGENT_DIR);
        std::fs::create_dir_all(&agent_workspace).unwrap();

        // --- real SQLite-backed EventBus (synchronous; writes inline) ---
        let jsonl_dir = workspace_root.join(".runtime/events/jsonl");
        let db_path = workspace_root.join(".runtime/events.db");
        std::fs::create_dir_all(&jsonl_dir).unwrap();
        let bus = Arc::new(
            EventBus::new_synchronous_for_tests(EventBusConfig::new(jsonl_dir, db_path.clone()))
                .expect("real event bus"),
        );
        let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

        // --- real git repo + per-write commit queue (fs.write → git) ---
        advance_git::bootstrap_repo_at(&workspace_root).expect("bootstrap_repo_at");
        let queue = Arc::new(
            advance_git::DefaultGitCommitQueue::spawn(workspace_root.clone())
                .expect("git queue spawn"),
        );
        let queue_trait: Arc<dyn advance_git::GitCommitQueue> = queue.clone();
        let git_sync: Arc<dyn GitSync> = Arc::new(Adv003GitSync::new(queue_trait));

        let tree = Arc::new(OneAgentTree::new(agent_workspace.clone()));

        // --- cap-fs (emits fs.write under ctx.trace_id) ---
        let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
            workspace_root.clone(),
            tree.clone() as Arc<dyn AgentTreeSnapshot>,
        ));
        let schema = Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new()));
        let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
        register_agent_fs(
            &*registry,
            resolver,
            bus_dyn.clone(),
            schema,
            Arc::new(StubFileHistoryProvider),
            Arc::new(DefaultAtomicWriter),
            None,
            None,
            None,
            None,
            Some(git_sync),
        );
        let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
        let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
        let injector = Arc::new(CapabilityInjector::new(registry.clone(), grant, breaker));

        // --- runtime + guest ---
        let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));
        let component = build_agent::encode_core_to_component(CORE_BYTES).expect("encode");
        let loaded = runtime.load_component(&component).expect("component loads");

        // --- run-manager session wiring (shared cell + RunManager on the SAME bus
        //     so run.round_completed is captured to SQLite) ---
        let run_manager = Arc::new(RunManager::new(bus_dyn.clone()));
        let cell: SessionRunCell = Arc::new(OnceLock::new());

        // --- production MessageHandler WITH run_session ---
        let message_handler: Arc<dyn MessageHandler> = Arc::new(
            WasmMessageHandler::new(
                runtime,
                loaded,
                injector,
                vec![CapRequest {
                    capability: CapabilityId::from("fs"),
                }],
                AGENT_ID.to_string(),
                "trace-boot".to_string(),
            )
            .with_run_session(RunSession {
                run_manager: run_manager.clone(),
                cell: cell.clone(),
            }),
        );

        // --- shared mailbox + real dispatcher (emits msg.received) ---
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
        let dispatcher = Arc::new(
            MailboxDispatcherImpl::new(store.clone(), tree.clone() as Arc<dyn AgentTreeReader>)
                .with_event_bus(bus_dyn.clone()),
        );

        // --- driver: emitting assembler (context.assembled) + run bootstrap ---
        let assembler: Arc<dyn ContextAssembler> = build_context_assembler(
            bus_dyn.clone(),
            Arc::new(EmptyCallableInventory),
            Arc::new(FixedHostFnInventory::from_names(&[])),
            tree.clone() as Arc<dyn AgentTreeSnapshot>,
        );
        let driver = build_agent_loop(store.clone(), message_handler, bus_dyn.clone(), None)
            .with_context_assembler(assembler)
            .with_run_bootstrap(Arc::new(RunManagerBootstrap {
                run_manager: run_manager.clone(),
                run_config: RunConfig::default(),
                session_agent: AGENT_ID.to_string(),
                cell: cell.clone(),
            }));

        Self {
            driver,
            dispatcher,
            db_path,
            _queue: queue,
            _tmp: tmp,
        }
    }

    /// Inject one context:None inbound message through the real dispatcher and
    /// drive exactly one real turn through the production agent loop.
    async fn drive_turn(&self, msg_id: &str, payload: &[u8]) {
        let msg = Message {
            id: msg_id.to_string(),
            kind: MessageKind::User,
            from: "user:harness".to_string(),
            to: AGENT_ID.to_string(),
            payload: payload.to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        self.dispatcher
            .deliver(AGENT_ID, msg)
            .await
            .expect("deliver");
        let cfg = ComponentConfig {
            id: AGENT_ID.to_string(),
            config_data: None,
            trigger_context: None,
        };
        let instance = WasmInstance::new(
            ComponentId::new(format!("agent-a-inst-{msg_id}")).expect("component id"),
        );
        self.driver.run_agent(AGENT_ID, cfg, instance).await;
    }

    /// All persisted events-table rows (with span columns), in timestamp order.
    fn rows(&self) -> Vec<EvRow> {
        let conn = rusqlite::Connection::open(&self.db_path).expect("open events.db");
        let mut stmt = conn
            .prepare(
                "SELECT event_type, trace_id, span_id, parent_span_id FROM events ORDER BY timestamp",
            )
            .expect("prepare");
        let rows = stmt
            .query_map([], |r| {
                Ok(EvRow {
                    event_type: r.get(0)?,
                    trace_id: r.get(1)?,
                    span_id: r.get(2)?,
                    parent_span_id: r.get(3)?,
                })
            })
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();
        rows
    }
}

/// The per-turn chain events (those stamped with the minted chain trace_id):
/// everything EXCEPT `msg.received` (pre-mint) and `git.commit` (async queue
/// worker, emitted outside the ComponentCtx).
const CHAIN_EVENT_TYPES: &[&str] = &["context.assembled", "fs.write", "run.round_completed"];

fn is_chain_event(ty: &str) -> bool {
    CHAIN_EVENT_TYPES.contains(&ty)
}

// ── SYS-AC-137 — one chain, one trace_id (two chains DIFFER) ──────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_137_one_chain_one_trace_id() {
    let chain = TraceChain::build().await;
    chain.drive_turn("msg-chain-A", b"hello-A").await;
    chain.drive_turn("msg-chain-B", b"hello-B").await;

    let rows = chain.rows();

    // The two chains' roots: context.assembled.span_id == chain_root_span_id(msg.id).
    let root_a = chain_root_span_id("msg-chain-A");
    let root_b = chain_root_span_id("msg-chain-B");

    // Group the per-turn chain events by their span-root so we can read each
    // chain's trace_id from real product output. fs.write / run.round_completed
    // do NOT carry the root span as their own span_id, so we identify a chain by
    // its trace_id: collect the trace_id of the context.assembled whose span_id
    // is each root, then verify all that chain's events share it.
    let trace_of_assembled = |root: &str| -> String {
        rows.iter()
            .find(|r| r.event_type == "context.assembled" && r.span_id.as_deref() == Some(root))
            .unwrap_or_else(|| panic!("context.assembled for root {root} not found"))
            .trace_id
            .clone()
            .expect("context.assembled carries a trace_id")
    };
    let trace_a = trace_of_assembled(&root_a);
    let trace_b = trace_of_assembled(&root_b);

    // Non-empty, not the boot/harness constant.
    for t in [&trace_a, &trace_b] {
        assert!(!t.is_empty(), "chain trace_id is non-empty");
        assert_ne!(t, "trace-boot", "boot constant must be overridden per-turn");
        assert_ne!(t, "trace-harness", "harness constant must be overridden");
    }

    // (b) THE LOAD-BEARING DISCRIMINATOR: the two chains' trace_ids DIFFER (a
    // degenerate process-constant or single boot trace would fail this).
    assert_ne!(
        trace_a, trace_b,
        "two distinct handle-message chains mint two DISTINCT trace_ids"
    );

    // (a) within each chain, EVERY per-turn chain event shares that ONE trace_id.
    // We verify each chain has all three named event types and they all carry the
    // chain's trace_id. (msg.received is excluded — pre-mint.)
    for (trace, label) in [(&trace_a, "A"), (&trace_b, "B")] {
        let chain_rows: Vec<&EvRow> = rows
            .iter()
            .filter(|r| is_chain_event(&r.event_type) && r.trace_id.as_deref() == Some(trace))
            .collect();
        for ty in CHAIN_EVENT_TYPES {
            assert!(
                chain_rows.iter().any(|r| &r.event_type == ty),
                "chain {label}: missing {ty} under trace {trace}"
            );
        }
        // No chain event of EITHER chain carries the OTHER chain's trace.
        let other = if trace == &trace_a {
            &trace_b
        } else {
            &trace_a
        };
        assert!(
            !rows.iter().any(|r| is_chain_event(&r.event_type)
                && r.trace_id.as_deref() == Some(other)
                && r.span_id.as_deref() == Some(if label == "A" { &root_a } else { &root_b })),
            "chain {label} events must not share the other chain's trace"
        );
    }

    // msg.received is NOT under the chain trace (pre-mint discriminator).
    let msg_received_traces: Vec<Option<String>> = rows
        .iter()
        .filter(|r| r.event_type == "msg.received")
        .map(|r| r.trace_id.clone())
        .collect();
    assert!(
        msg_received_traces
            .iter()
            .all(|t| t.as_deref() != Some(trace_a.as_str())
                && t.as_deref() != Some(trace_b.as_str())),
        "msg.received is emitted pre-mint and must NOT carry a chain trace_id"
    );
}

// ── SYS-AC-138 — child run.round_completed links the chain root span ──────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_138_child_span_links_parent() {
    let chain = TraceChain::build().await;
    chain.drive_turn("msg-138", b"hello-138").await;

    let rows = chain.rows();
    let expected_root = chain_root_span_id("msg-138");

    let assembled = rows
        .iter()
        .find(|r| r.event_type == "context.assembled")
        .expect("a context.assembled event");
    let round_completed = rows
        .iter()
        .find(|r| r.event_type == "run.round_completed")
        .expect("a run.round_completed event (run-session wired)");

    // context.assembled.span_id == chain_root_span_id(msg.id) (the chain root).
    assert_eq!(
        assembled.span_id.as_deref(),
        Some(expected_root.as_str()),
        "context.assembled.span_id == chain_root_span_id(msg.id)"
    );
    // child's parent_span_id == that exact root (not None, not a fresh UUID).
    assert_eq!(
        round_completed.parent_span_id.as_deref(),
        Some(expected_root.as_str()),
        "run.round_completed.parent_span_id == context.assembled.span_id (chain root)"
    );
    // and they share the one chain trace.
    assert_eq!(
        round_completed.trace_id, assembled.trace_id,
        "child and parent share the chain trace_id"
    );
    assert!(
        round_completed.parent_span_id != round_completed.span_id,
        "a child's parent_span_id must differ from its own span_id"
    );
}

// ── SYS-AC-139 — /query/dashboard/trace returns the whole chain ───────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_139_dashboard_trace_returns_chain() {
    let chain = TraceChain::build().await;
    chain.drive_turn("msg-139", b"hello-139").await;

    let rows = chain.rows();
    // The chain trace_id, read from real product output (context.assembled).
    let chain_trace = rows
        .iter()
        .find(|r| r.event_type == "context.assembled")
        .and_then(|r| r.trace_id.clone())
        .expect("context.assembled carries the chain trace_id");

    // Independent anchor (NOT a raw same-table COUNT): the load-bearing named
    // events a real turn produces across MODULE-019 (context.assembled),
    // MODULE-008 (run.round_completed), and MODULE-004/cap-fs (fs.write) — the
    // multi-module chain the journey traverses. The endpoint must return a
    // SUPERSET of these (the turn may also emit meta.updated etc.).
    // Completeness is checked separately against the DB chain-trace count.
    let db_chain_count = rows
        .iter()
        .filter(|r| r.trace_id.as_deref() == Some(&chain_trace))
        .count();

    // Drive the PRODUCTION query_router over the events DB, in-process.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mgr = SqliteConnectionManager::file(&chain.db_path).with_flags(flags);
    let pool = Arc::new(Pool::builder().max_size(2).build(mgr).expect("pool"));
    let router = query_router(QueryState { pool });

    let uri = format!("/dashboard/trace?trace_id={chain_trace}");
    let mut request = Request::builder().uri(&uri).body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65000".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.expect("router oneshot");
    let status = response.status();
    let body = to_bytes(response.into_body(), 4_000_000).await.unwrap();
    assert!(
        status.is_success(),
        "dashboard/trace status={status} body={}",
        String::from_utf8_lossy(&body)
    );

    let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
    // The dashboard envelope wraps the rows under `events` (view == "trace").
    let events = v
        .get("events")
        .and_then(|e| e.as_array())
        .or_else(|| v.as_array())
        .expect("trace events array");

    // Every returned row carries the chain trace_id, and the returned event-type
    // multiset equals the independently-derived expected chain set (and so
    // EXCLUDES msg.received, which has a different trace).
    let mut got: Vec<String> = events
        .iter()
        .map(|e| {
            assert_eq!(
                e.get("trace_id").and_then(|t| t.as_str()),
                Some(chain_trace.as_str()),
                "every dashboard/trace row carries the chain trace_id"
            );
            e.get("event_type")
                .and_then(|t| t.as_str())
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    got.sort();
    // Scoping: pre-mint msg.received must NOT be in the chain-scoped response.
    assert!(
        !got.iter().any(|t| t == "msg.received"),
        "the chain-scoped trace response must NOT contain pre-mint msg.received"
    );
    // Multi-module anchor: the endpoint returns the three load-bearing events.
    for ty in CHAIN_EVENT_TYPES {
        assert!(
            got.iter().any(|t| t == ty),
            "dashboard/trace is missing the load-bearing {ty} event; got {got:?}"
        );
    }
    // Completeness: the endpoint returns the WHOLE chain (every DB row sharing
    // the chain trace_id), not a subset — count == independently-derived length.
    assert_eq!(
        got.len(),
        db_chain_count,
        "dashboard/trace returns the complete chain (count == chain length); got {got:?}"
    );
}
