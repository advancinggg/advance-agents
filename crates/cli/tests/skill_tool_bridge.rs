//! Wave-14 Lane C (SYS-AC-080) — the skill→tool-registry L2 bridge.
//!
//! Two layers of coverage for `advance_cli::wiring::register_skill_tools`:
//!
//! - **Bridge-fn unit** (`btb_*`): over a tempdir, prove the bridge registers
//!   `skill::{name}` from a `tool.wasm` sidecar, skips a skill with no sidecar,
//!   returns 0 on an absent skills dir, and size-gates an oversized sidecar.
//! - **Step-7 auto-wiring** (`btb_wire_capabilities_*`): the e2e system-acceptance
//!   witness (sys_j26) drives `register_skill_tools` directly, so it would NOT
//!   catch a mis-gated/omitted Step-7 call. This test runs the REAL
//!   `wire_capabilities` over a workspace declaring `tools` + `skills` with a
//!   materialized `tool.wasm`, then invokes `skill::{id}` through the wired
//!   `tool-invoke` host-fn — proving the production boot path populates the registry.

use std::path::{Path, PathBuf};

use advance_cli::wiring::{register_skill_tools, wire_capabilities};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::HostCallContext;
use cap_skills::persistence::{DiskSkillStorage, SkillBlob, SkillStorage};
use cap_skills::{Provenance, SkillSidecar, TrustLevel};
use cap_tools::{LazyRegistryConfig, LazyToolRegistry, ToolRegistry};
use wasmtime::component::Val;

/// The committed echo tool COMPONENT (exports `tool-exports`: `describe` +
/// `execute("echo",p)==p`). Real bytes so the Step-7 test actually executes it.
const ECHO_TOOL_COMPONENT: &[u8] =
    include_bytes!("../../capabilities/cap-tools/tests/fixtures/echo_tool.component.wasm");

/// Wave-18 Lane 2 — the committed agent DB tool COMPONENT (MODULE-017-AC-31):
/// exports `tool-exports` and runs REAL SQL (CREATE/INSERT/SELECT) in-wasm.
const DB_TOOL_COMPONENT: &[u8] =
    include_bytes!("../../capabilities/cap-tools/tests/fixtures/db_tool.component.wasm");

const TOOLS_NS: &str = "advance:runtime/agent-tools@0.1.0";
const CAP_AGENT: &str = "default-agent";

// ── helpers ──────────────────────────────────────────────────────────

/// Materialize an active skill (SKILL.md) optionally carrying a `tool.wasm`
/// sidecar, at the cap-skills provider root (`DiskSkillStorage` appends
/// `.agent/skills`). All `SkillBlob` fields explicit (no `Default`).
async fn seed_skill(agent_root: &Path, id: &str, tool_wasm: Option<&[u8]>) {
    let storage = DiskSkillStorage::with_default_writer(agent_root.to_path_buf());
    storage
        .write_active(&SkillBlob {
            skill_id: id.to_string(),
            version: 1,
            content: format!("---\nname: {id}\ndescription: x\n---\n# {id}\n\nA skill.\n"),
            tags: vec![],
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        })
        .await
        .expect("write_active");
    if let Some(bytes) = tool_wasm {
        storage
            .write_skill_sidecar(id, SkillSidecar::ToolWasm, bytes)
            .await
            .expect("write tool.wasm sidecar");
    }
}

async fn registered_ids(registry: &LazyToolRegistry) -> Vec<String> {
    registry.list().await.into_iter().map(|t| t.id).collect()
}

// ── bridge-fn unit tests ─────────────────────────────────────────────

#[tokio::test]
async fn btb_registers_skill_with_tool_sidecar_skips_one_without() {
    let tmp = tempfile::tempdir().unwrap();
    let agent_root = std::fs::canonicalize(tmp.path()).unwrap();
    seed_skill(&agent_root, "echo-skill", Some(ECHO_TOOL_COMPONENT)).await;
    seed_skill(&agent_root, "knowledge-only", None).await; // no tool.wasm

    let registry = LazyToolRegistry::new(LazyRegistryConfig::default());
    let n = register_skill_tools(&registry, &agent_root).await;
    assert_eq!(
        n, 1,
        "exactly the one skill with a tool.wasm sidecar is registered"
    );

    let ids = registered_ids(&registry).await;
    assert!(
        ids.contains(&"skill::echo-skill".to_string()),
        "the tool-bearing skill registers under the PRD §12.4.4 id skill::echo-skill: {ids:?}"
    );
    assert!(
        !ids.contains(&"skill::knowledge-only".to_string()),
        "a skill with no tool.wasm sidecar is NOT registered: {ids:?}"
    );
}

#[tokio::test]
async fn btb_absent_skills_dir_returns_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let agent_root = std::fs::canonicalize(tmp.path()).unwrap(); // no .agent/skills written
    let registry = LazyToolRegistry::new(LazyRegistryConfig::default());
    let n = register_skill_tools(&registry, &agent_root).await;
    assert_eq!(n, 0, "no skills dir → 0 registered, no panic");
    assert!(registered_ids(&registry).await.is_empty());
}

#[tokio::test]
async fn btb_oversized_sidecar_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let agent_root = std::fs::canonicalize(tmp.path()).unwrap();
    // > 16 MiB sidecar → size-gated by the metadata pre-check, never registered.
    let huge = vec![0u8; 16 * 1024 * 1024 + 1];
    seed_skill(&agent_root, "huge-skill", Some(&huge)).await;

    let registry = LazyToolRegistry::new(LazyRegistryConfig::default());
    let n = register_skill_tools(&registry, &agent_root).await;
    assert_eq!(
        n, 0,
        "an oversized tool.wasm sidecar is skipped (bounded boot memory)"
    );
    assert!(
        !registered_ids(&registry)
            .await
            .contains(&"skill::huge-skill".to_string()),
        "the oversized skill tool is not registered"
    );
}

#[tokio::test]
async fn btb_non_regular_sidecar_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let agent_root = std::fs::canonicalize(tmp.path()).unwrap();
    // A non-regular `tool.wasm` (here a directory — portable; a FIFO would also hit this
    // path, but a directory exercises the same `!is_file()` guard without a blocking open).
    // The stat-before-open `symlink_metadata` gate must skip it WITHOUT a blocking read.
    std::fs::create_dir_all(agent_root.join(".agent/skills/dir-skill/tool.wasm")).unwrap();

    let registry = LazyToolRegistry::new(LazyRegistryConfig::default());
    let n = register_skill_tools(&registry, &agent_root).await;
    assert_eq!(
        n, 0,
        "a non-regular tool.wasm (FIFO/device/dir) is skipped — boot can't hang"
    );
    assert!(
        !registered_ids(&registry)
            .await
            .contains(&"skill::dir-skill".to_string()),
        "the non-regular skill tool is not registered"
    );
}

#[tokio::test]
async fn btb_invalid_skill_name_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let agent_root = std::fs::canonicalize(tmp.path()).unwrap();
    // A dir whose name escapes cap-skills' `^[a-z0-9][a-z0-9_-]{0,63}$` skill-name regex
    // (a `.` is not allowed) — it carries a valid regular tool.wasm, but it could not have been
    // produced through a validated materialize, so the bridge's validate_skill_name guard skips it.
    let skill_dir = agent_root.join(".agent/skills/bad.name");
    std::fs::create_dir_all(&skill_dir).unwrap();
    std::fs::write(skill_dir.join("tool.wasm"), ECHO_TOOL_COMPONENT).unwrap();

    let registry = LazyToolRegistry::new(LazyRegistryConfig::default());
    let n = register_skill_tools(&registry, &agent_root).await;
    assert_eq!(
        n, 0,
        "a skill dir with an invalid name is skipped (cap-skills name-discipline parity)"
    );
    assert!(
        !registered_ids(&registry)
            .await
            .contains(&"skill::bad.name".to_string()),
        "the invalid-named skill tool is not registered"
    );
}

// ── Step-7 auto-wiring test ──────────────────────────────────────────

/// Minimal runtime-config (mirrors context_skill_reader.rs); declaring tools+skills
/// leaves `needs_key = false` (no master key / env mutation).
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

fn fresh_workspace(caps_yaml: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), caps_yaml).unwrap();
    (dir, workspace, config_path)
}

fn tool_invoke_ctx() -> HostCallContext {
    HostCallContext {
        agent_id: CAP_AGENT.to_string(),
        trace_id: "tr-bridge".to_string(),
        turn_id: None,
        capability: "tools".to_string(),
        function: format!("{TOOLS_NS}::tool-invoke"),
        run_id: None,
        iteration: None,
    }
}

fn invoke_params(tool_id: &str, method: &str, input: &[u8]) -> Vec<Val> {
    vec![
        Val::String(tool_id.to_string()),
        Val::String(method.to_string()),
        Val::List(input.iter().map(|b| Val::U8(*b)).collect()),
    ]
}

fn ok_bytes(v: &Val) -> Option<Vec<u8>> {
    match v {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::List(items) => Some(
                items
                    .iter()
                    .map(|x| match x {
                        Val::U8(b) => *b,
                        other => panic!("non-u8 in result list: {other:?}"),
                    })
                    .collect(),
            ),
            other => panic!("Ok arm is not a list: {other:?}"),
        },
        _ => None,
    }
}

/// Extract the `result::err` class from a tool-invoke result. The host encodes a
/// failure as a `Val::Variant(error-class, Some(generic-message))` (the detailed
/// component/host message is REDACTED at the WIT boundary — SB-22 discipline), so
/// this returns the error-class case name (e.g. `invocation-failed`,
/// `method-not-found`, `input-validation-failed`).
fn err_class(v: &Val) -> Option<String> {
    match v {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Variant(case, _) => Some(case.clone()),
            Val::String(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// The real production boot path registers a materialized skill's tool.wasm under
/// `skill::{id}` so it is invocable via the wired `tool-invoke` host-fn.
#[tokio::test(flavor = "multi_thread")]
async fn btb_wire_capabilities_registers_skill_tools() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  tools: true\n  skills: true\n");
    // Materialize a skill carrying the echo tool.wasm BEFORE wiring (the bridge
    // scans at wire time). Provider root = <ws>/.agent (DiskSkillStorage appends
    // .agent/skills) — the exact value wire_capabilities computes for skills_root.
    seed_skill(&ws.join(".agent"), "echo-skill", Some(ECHO_TOOL_COMPONENT)).await;

    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws)
        .await
        .expect("wire (tools+skills)");

    // Look up the production-registered tool-invoke host-fn and invoke skill::echo-skill.
    let payload: &[u8] = b"bridge-roundtrip";
    let spec = host
        .host_registry()
        .lookup("tools")
        .into_iter()
        .find(|s| s.namespace == TOOLS_NS && s.name == "tool-invoke")
        .expect("tool-invoke host-fn registered (declares_tools)");
    let out = spec
        .handler
        .call(
            tool_invoke_ctx(),
            invoke_params("skill::echo-skill", "echo", payload),
            1,
        )
        .await
        .expect("tool-invoke dispatch");
    assert_eq!(out.len(), 1, "tool-invoke returns one Val");
    assert_eq!(
        ok_bytes(&out[0]).as_deref(),
        Some(payload),
        "Step-7 wired the bridge: skill::echo-skill resolves to the materialized tool.wasm and executes (echo)"
    );

    drop(host);
    drop(handles);
}

// ── Wave-18 Lane 2 — the agent DB tool (MODULE-017-AC-31 / REQ-160) ──────────

/// T-S1-1 — the SHIPPED DB tool, loaded through the PRODUCTION skill→tool L2
/// bridge as `skill::db`, executes REAL SQL inside its own wasm sandbox: a
/// `CREATE TABLE` + `INSERT` + `SELECT` returns the selected rows. This is the
/// anti-fake-green witness (MODULE-017:1998) — not an echo, not a direct
/// `register_binary`, and not a host SQL fn.
#[tokio::test(flavor = "multi_thread")]
async fn btb_db_tool_runs_real_sql_via_l2_bridge() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  tools: true\n  skills: true\n");
    seed_skill(&ws.join(".agent"), "db", Some(DB_TOOL_COMPONENT)).await;

    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws)
        .await
        .expect("wire (tools+skills)");

    let spec = host
        .host_registry()
        .lookup("tools")
        .into_iter()
        .find(|s| s.namespace == TOOLS_NS && s.name == "tool-invoke")
        .expect("tool-invoke host-fn registered");

    // Multi-statement SQL: create, insert two rows, select the column back.
    let sql: &[u8] = b"CREATE TABLE t(a INT); INSERT INTO t VALUES (1),(2); SELECT a FROM t";
    let out = spec
        .handler
        .call(
            tool_invoke_ctx(),
            invoke_params("skill::db", "query", sql),
            1,
        )
        .await
        .expect("tool-invoke dispatch");
    assert_eq!(
        ok_bytes(&out[0]).as_deref(),
        Some(&b"[[1],[2]]"[..]),
        "skill::db parsed + executed real SQL in-wasm and returned the SELECTed rows"
    );

    // WHERE filter + projection — proves a genuine engine, not a fixed response.
    let sql2: &[u8] =
        b"CREATE TABLE u(id INT, name TEXT); INSERT INTO u VALUES (1,'a'),(2,'b'); SELECT name FROM u WHERE id = 2";
    let out2 = spec
        .handler
        .call(
            tool_invoke_ctx(),
            invoke_params("skill::db", "query", sql2),
            1,
        )
        .await
        .expect("dispatch 2");
    assert_eq!(
        ok_bytes(&out2[0]).as_deref(),
        Some(&b"[[\"b\"]]"[..]),
        "WHERE + projection executed (id=2 → name 'b')"
    );

    drop(host);
    drop(handles);
}

/// T-S1-2 — code-audit: the SQL engine is in-wasm only. No `db`/`sql` host fn is
/// registered, so MODULE-004's `rusqlite` index is never agent-exposed; the tool
/// is reachable ONLY through the L2 ToolRegistry (`skill::db`).
#[tokio::test(flavor = "multi_thread")]
async fn btb_db_tool_no_sql_host_fn_registered() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  tools: true\n  skills: true\n");
    seed_skill(&ws.join(".agent"), "db", Some(DB_TOOL_COMPONENT)).await;

    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    assert!(
        host.host_registry().lookup("db").is_empty(),
        "no `db` host capability is registered (DB tool is in-wasm, not a host fn)"
    );
    assert!(
        host.host_registry().lookup("sql").is_empty(),
        "no `sql` host capability is registered (MODULE-004 rusqlite is agent-invisible)"
    );

    drop(host);
    drop(handles);
}

/// T-S1-3 — malformed SQL and an unknown method fail CLOSED (`result::err`), not
/// a panic and not a host bypass.
#[tokio::test(flavor = "multi_thread")]
async fn btb_db_tool_fails_closed_on_bad_input() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  tools: true\n  skills: true\n");
    seed_skill(&ws.join(".agent"), "db", Some(DB_TOOL_COMPONENT)).await;

    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");
    let spec = host
        .host_registry()
        .lookup("tools")
        .into_iter()
        .find(|s| s.namespace == TOOLS_NS && s.name == "tool-invoke")
        .expect("tool-invoke host-fn");

    // Malformed SQL → fail-closed Err (the host redacts the detail to a generic
    // error class; what matters is NOT Ok, no panic, no host bypass). This is the
    // discriminator against the valid-SQL case above — the engine genuinely
    // distinguishes parseable from unparseable SQL.
    let bad: &[u8] = b"SELECT a FRM";
    let out = spec
        .handler
        .call(
            tool_invoke_ctx(),
            invoke_params("skill::db", "query", bad),
            1,
        )
        .await
        .expect("dispatch (malformed)");
    assert!(
        ok_bytes(&out[0]).is_none() && err_class(&out[0]).is_some(),
        "malformed SQL returns result::err (not Ok, no panic): {:?}",
        out[0]
    );

    // SELECT over an unknown table → fail-closed Err.
    let nosuch: &[u8] = b"SELECT a FROM ghost";
    let out_nt = spec
        .handler
        .call(
            tool_invoke_ctx(),
            invoke_params("skill::db", "query", nosuch),
            1,
        )
        .await
        .expect("dispatch (no table)");
    assert!(
        ok_bytes(&out_nt[0]).is_none() && err_class(&out_nt[0]).is_some(),
        "SELECT from an unknown table fails closed: {:?}",
        out_nt[0]
    );

    // Unknown method → fail-closed Err (the host method-existence check rejects it
    // with method-not-found, or the component rejects it — either way an Err).
    let out2 = spec
        .handler
        .call(
            tool_invoke_ctx(),
            invoke_params("skill::db", "drop-everything", b"x"),
            1,
        )
        .await
        .expect("dispatch (unknown method)");
    assert!(
        ok_bytes(&out2[0]).is_none() && err_class(&out2[0]).is_some(),
        "an unknown method fails closed: {:?}",
        out2[0]
    );

    drop(host);
    drop(handles);
}
