//! Wave-17 Lane 3 — MODULE-005-AC-25 witness: initial agent tree from workspace
//! configuration at startup.
//!
//! Drives the FULL production boot path — `RuntimeHostBuilder::new` →
//! `wire_capabilities(builder, ws)` — over a temp workspace whose
//! `.agent/config.yaml` declares `capabilities: {fs: true}` plus an `agents:`
//! hierarchy block, then reads the resulting tree via the SAME
//! `agent_tree_snapshot` `WiringHandles` exposes (the snapshot a context-assembler
//! consumes). The snapshot is taken at `wire_capabilities` RETURN — i.e. BEFORE any
//! `run_turn` / message — so the witness proves the declared root + children are
//! materialized at startup, not lazily on first message. This exercises the real
//! `agent_config::parse_agents_config` + `wiring::materialize_config_tree` exactly
//! as a daemon boot invokes them.
//!
//! - **T40-a** (the AC-25 witness): a 2-level `agents:` block → the snapshot shows
//!   root `default-agent` (Root, parent None) + each declared child (Child, correct
//!   parent edge, `workspace_path == canon(ws)/<target-path>`, identity = alias,
//!   `template_ref` recorded), with the grandchild nested under its parent (the tree
//!   matches the configured hierarchy).
//! - **T40-b**: an fs config with NO `agents:` block → root-only (byte-identical to
//!   pre-Wave-17 boot).
//! - **T40-c (malformed)**: a present-but-malformed `agents:` block (unknown field) →
//!   `wire_capabilities` returns `CliWiringError::ConfigTree` (fail-closed, not a
//!   silent drop), BEFORE the EventBus is constructed.
//! - **T40-c (territory escape)**: a parseable config whose `target-path` escapes the
//!   workspace (`..`) → `CliWiringError::ConfigTree` (apply_auto_bootstrap's
//!   resolve_under_parent fails closed; no out-of-territory child is materialized).

use std::path::{Path, PathBuf};

use advance_cli::wiring::{wire_capabilities, CliWiringError};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_shared_types::agent_tree::AgentKind;

const ROOT: &str = "default-agent";

/// Minimal `runtime-config.yaml`. Declaring only fs in `.agent/config.yaml` leaves
/// `needs_key = false`, so `load_real_master_key` is never called — no env var /
/// master key, no test-global env mutation. (Mirrors `spawn_wiring_011.rs`.)
fn runtime_yaml() -> String {
    r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers: []

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADV_M005_AC25_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

/// Build a temp workspace with the given `.agent/config.yaml` content. Returns the
/// (guard, canonical workspace path, runtime-config path).
fn fresh_workspace(agent_config_yaml: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), agent_config_yaml).unwrap();
    (dir, workspace, config_path)
}

/// Boot through the real wiring and return the materialized tree snapshot data.
async fn boot_and_snapshot(
    ws: &Path,
    cfg: &Path,
) -> advance_shared_types::agent_tree::AgentTreeSnapshotData {
    let builder = RuntimeHostBuilder::new(cfg, ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, ws).await.expect("wire");
    let snap = handles
        .agent_tree_snapshot
        .clone()
        .expect("fs ⇒ agent_tree_snapshot is Some");
    snap.snapshot()
}

/// Boot and assert it fails closed with `CliWiringError::ConfigTree`. (Hand-rolled
/// match rather than `expect_err` — the `Ok` arm `(RuntimeHost, WiringHandles)` is
/// not `Debug`.)
async fn boot_expect_config_tree_err(ws: &Path, cfg: &Path) {
    let builder = RuntimeHostBuilder::new(cfg, ws).await.expect("builder");
    match wire_capabilities(builder, ws).await {
        Err(CliWiringError::ConfigTree(_)) => {}
        Err(other) => panic!("expected CliWiringError::ConfigTree, got {other:?}"),
        Ok(_) => panic!("expected boot to fail closed (ConfigTree), but it succeeded"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t40a_config_materializes_root_child_and_grandchild_at_boot() {
    let (_g, ws, cfg) = fresh_workspace(
        "\
capabilities:
  fs: true
agents:
  - alias: child-a
    template: explorer
    target-path: children/a
    children:
      - alias: grandchild
        template: planner
        target-path: g
  - alias: child-b
    template: reviewer
    target-path: children/b
",
    );

    let data = boot_and_snapshot(&ws, &cfg).await;
    let node = |id: &str| {
        data.nodes.iter().find(|n| n.id.0 == id).unwrap_or_else(|| {
            panic!(
                "{id} must be materialized at boot; nodes={:?}",
                data.nodes.iter().map(|n| &n.id.0).collect::<Vec<_>>()
            )
        })
    };

    // Root: present, kind Root, no parent.
    let root = node(ROOT);
    assert_eq!(root.kind, AgentKind::Root);
    assert_eq!(root.parent, None);

    // child-a: identity = alias, kind Child, parent = root, workspace under root,
    // template recorded.
    let child_a = node("child-a");
    assert_eq!(child_a.kind, AgentKind::Child);
    assert_eq!(child_a.parent.as_ref().map(|p| p.0.as_str()), Some(ROOT));
    assert_eq!(child_a.workspace_path, ws.join("children/a"));
    assert_eq!(child_a.template_ref.as_deref(), Some("explorer"));

    // child-b: sibling, distinct territory + template.
    let child_b = node("child-b");
    assert_eq!(child_b.kind, AgentKind::Child);
    assert_eq!(child_b.parent.as_ref().map(|p| p.0.as_str()), Some(ROOT));
    assert_eq!(child_b.workspace_path, ws.join("children/b"));
    assert_eq!(child_b.template_ref.as_deref(), Some("reviewer"));

    // grandchild: nested under child-a (its target-path is relative to child-a),
    // proving the FULL configured hierarchy is materialized — not just one level.
    let gc = node("grandchild");
    assert_eq!(gc.kind, AgentKind::Child);
    assert_eq!(gc.parent.as_ref().map(|p| p.0.as_str()), Some("child-a"));
    assert_eq!(gc.workspace_path, ws.join("children/a/g"));
    assert_eq!(gc.template_ref.as_deref(), Some("planner"));

    // The tree matches the configured hierarchy exactly: root + 3 declared agents.
    assert_eq!(
        data.nodes.len(),
        4,
        "root + child-a + child-b + grandchild = 4 nodes; got {:?}",
        data.nodes.iter().map(|n| &n.id.0).collect::<Vec<_>>()
    );

    // Territory materialized on disk (each child got a real workspace).
    assert!(ws.join("children/a").is_dir());
    assert!(ws.join("children/a/g").is_dir());
    assert!(ws.join("children/b").is_dir());
}

#[tokio::test(flavor = "multi_thread")]
async fn t40b_no_agents_block_boots_root_only() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let data = boot_and_snapshot(&ws, &cfg).await;
    assert_eq!(
        data.nodes.len(),
        1,
        "no agents: ⇒ root-only boot; got {:?}",
        data.nodes.iter().map(|n| &n.id.0).collect::<Vec<_>>()
    );
    assert_eq!(data.nodes[0].id.0, ROOT);
    assert_eq!(data.nodes[0].kind, AgentKind::Root);
}

#[tokio::test(flavor = "multi_thread")]
async fn t40c_malformed_agents_block_fails_boot_closed() {
    // deny_unknown_fields: a present-but-malformed `agents:` block aborts boot with
    // ConfigTree (NOT a silent drop), before the EventBus is built.
    let (_g, ws, cfg) = fresh_workspace(
        "\
capabilities:
  fs: true
agents:
  - alias: x
    template: explorer
    target-path: x
    bogus: true
",
    );
    boot_expect_config_tree_err(&ws, &cfg).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn t40c_territory_escaping_target_fails_boot_closed() {
    // A parseable config whose target-path escapes the workspace (`..`) is caught by
    // apply_auto_bootstrap's resolve_under_parent and surfaced as ConfigTree — the
    // materializer fails closed (no out-of-territory child is created).
    let (_g, ws, cfg) = fresh_workspace(
        "\
capabilities:
  fs: true
agents:
  - alias: escapee
    template: explorer
    target-path: ../escape
",
    );
    boot_expect_config_tree_err(&ws, &cfg).await;
    assert!(
        !ws.join("../escape").exists(),
        "no out-of-territory child workspace may be created"
    );
}
