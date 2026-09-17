//! CONTRACT-190 agents family — the PRODUCTION adapter over the real agent tree.
//!
//! Drives the FULL boot path (`RuntimeHostBuilder::new` → `wire_capabilities`) over a temp
//! workspace, then exercises the daemon-composed `ClientApi` (`wiring_handles.client_api_server
//! .api()`, the SAME instance the loopback transport serves) through `handle()`: list / templates /
//! create / conflicts / nested create / update / delete / delete-with-workspace, asserting the REAL
//! effects — tree nodes via the shared `agent_tree_snapshot`, materialized `.agent/` territories
//! on disk, the persisted `agents:` declaration in the root config, display-name files — and the
//! restart leg (a second boot of the same workspace re-materializes client-created agents).
//!
//! Fixture discipline: fs-only `.agent/config.yaml` (`needs_key = false`, no master key, no env
//! mutation), mirroring `agent_tree_from_config.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_cli::agent_config::parse_agents_config;
use advance_cli::client_api_agents::{project_config, AgentAdminAdapter};
use advance_cli::wiring::{wire_capabilities, WiringHandles};
use advance_client_api::agents::WARNING_RESTART_REQUIRED;
use advance_client_api::{
    AgentAdminProvider, ClientAgentDeleteResult, ClientAgentDetail, ClientAgentSummary,
    ClientAgentTemplate, ClientApi, ClientCreateAgentRequest, ClientEnvelope, ClientErrorCode,
    ClientRequest, ClientSession, ClientUpdateAgentRequest, Platform, Principal, ProviderError,
    Scope,
};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use advance_shared_types::capability::{CapParams, CapabilityId};
use cap_lifecycle::terminate::{GrantCascadeRevoke, MailboxCascade, RunCascade, WorkspaceCleanup};
use cap_lifecycle::{
    AgentTreeStore, BuiltinTemplateRegistry, CapGrantSubsetAdapter, DefaultSpawner,
    DefaultTerminateController, LifecycleError,
};
use serde_json::{json, Value};

const ROOT: &str = "root";

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
  env-var-name: ADV_M020_AGENTS_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

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

async fn boot(ws: &Path, cfg: &Path) -> (advance_runtime::bootstrap::RuntimeHost, WiringHandles) {
    let builder = RuntimeHostBuilder::new(cfg, ws).await.expect("builder");
    wire_capabilities(builder, ws).await.expect("wire")
}

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: format!("sess-{token}"),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes,
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

fn get(api: &ClientApi, path: &str) -> ClientEnvelope<Value> {
    api.handle(ClientRequest::get(path).with_session("tok"))
}

fn post(api: &ClientApi, path: &str, body: Value, key: &str) -> ClientEnvelope<Value> {
    api.handle(
        ClientRequest::post(path, body)
            .with_session("tok")
            .with_idempotency_key(key),
    )
}

fn detail(env: &ClientEnvelope<Value>) -> ClientAgentDetail {
    assert!(env.is_ok(), "expected ok, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("detail parses")
}

fn root_declared_aliases(ws: &Path) -> Vec<String> {
    let bytes = std::fs::read(ws.join(".agent/config.yaml")).unwrap();
    let decls = parse_agents_config(Some(&bytes)).expect("root config parses");
    fn walk(decls: &[advance_cli::agent_config::AgentDecl], out: &mut Vec<String>) {
        for d in decls {
            out.push(d.alias.clone());
            walk(&d.children, out);
        }
    }
    let mut out = Vec::new();
    walk(&decls, &mut out);
    out
}

/// A config document with its identity lines (`id:` — a UUID minted per run — and the root's
/// `handle:`) removed, so the rest can be compared verbatim.
fn sans_identity(text: &str) -> String {
    text.lines()
        .filter(|l| !l.starts_with("id: ") && !l.starts_with("handle: "))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// The on-disk config document of `ws` minus its identity lines; asserts the id is present.
fn config_sans_id(ws: &Path) -> String {
    let text = std::fs::read_to_string(ws.join(".agent/config.yaml")).unwrap();
    assert!(
        text.lines().any(|l| l.starts_with("id: ")),
        "config carries the immutable id: {text}"
    );
    sans_identity(&text)
}

fn is_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false)
}

// ── AA-01: the whole CRUD surface over the daemon-composed Client API ────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn aa01_crud_over_production_wiring() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let (_host, handles) = boot(&ws, &cfg).await;
    let server = handles
        .client_api_server
        .as_ref()
        .expect("EventBus up ⇒ Client API bound");
    let api = server.api();
    assert!(
        handles.agent_admin.is_some(),
        "fs ⇒ tree ⇒ agents adapter composed"
    );
    mint(&api, "tok", Scope::operator_default());
    let snapshot = handles.agent_tree_snapshot.clone().expect("fs ⇒ snapshot");

    // list: root only, workspace-relative path, config projection.
    let env = get(&api, "/client/agents");
    let agents: Vec<ClientAgentSummary> =
        serde_json::from_value(env.data.clone().unwrap()["agents"].clone()).unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].agent_id, ROOT);
    assert_eq!(agents[0].kind, "root");
    assert_eq!(agents[0].workspace_path, ".");
    assert!(agents[0].parent.is_none());

    let root = detail(&get(&api, &format!("/client/agents/{ROOT}")));
    assert!(
        uuid::Uuid::parse_str(&root.agent.id).is_ok(),
        "the root's id is a UUID: {}",
        root.agent.id
    );
    assert_eq!(
        root.config
            .config_yaml
            .as_deref()
            .map(sans_identity)
            .as_deref(),
        Some("capabilities:\n  fs: true\n")
    );
    assert_eq!(root.config.capabilities.len(), 1);
    assert_eq!(root.config.capabilities[0].name, "fs");
    assert!(root.config.capabilities[0].enabled);
    assert!(root.children.is_empty());
    assert!(!root.driver_present);

    // templates: the four runtime built-ins.
    let env = get(&api, "/client/agent-templates");
    let templates: Vec<ClientAgentTemplate> =
        serde_json::from_value(env.data.clone().unwrap()["templates"].clone()).unwrap();
    let names: Vec<&str> = templates.iter().map(|t| t.template_ref.as_str()).collect();
    for expected in ["explorer", "general-purpose", "planner", "reviewer"] {
        assert!(names.contains(&expected), "{names:?}");
    }
    assert!(templates
        .iter()
        .find(|t| t.template_ref == "explorer")
        .unwrap()
        .description
        .is_some());

    // create: materializes the territory, records the declaration, sets the display name.
    let env = post(
        &api,
        "/client/agents",
        json!({
            "agent_id": "research",
            "template_ref": "explorer",
            "capabilities": ["fs"],
            "display_name": "Research Desk"
        }),
        "k-create-research",
    );
    let d = detail(&env);
    assert_eq!(d.agent.agent_id, "research");
    assert_eq!(d.agent.kind, "child");
    assert_eq!(d.agent.parent.as_deref(), Some(ROOT));
    assert_eq!(d.agent.workspace_path, "research");
    assert_eq!(d.agent.template_ref.as_deref(), Some("explorer"));
    assert_eq!(d.agent.display_name.as_deref(), Some("Research Desk"));
    assert_eq!(d.agent.status, "active");
    assert!(!d.driver_present, "builtin templates ship no driver");
    assert!(
        !env.warnings
            .iter()
            .any(|w| w.code == WARNING_RESTART_REQUIRED),
        "no config document ⇒ no restart warning"
    );
    let research_ws = ws.join("research");
    assert!(is_dir(&research_ws.join(".agent")));
    assert!(research_ws.join(".agent/config.yaml").is_file());
    assert!(research_ws.join(".agent/AGENTS.md").is_file());
    // The name lives in the config document (`display-name` key); no sidecar file is written.
    let config = std::fs::read_to_string(research_ws.join(".agent/config.yaml")).unwrap();
    assert!(config.contains("display-name: Research Desk"), "{config}");
    assert!(config.contains("template: explorer"), "{config}");
    assert!(
        !config.contains("\nname:"),
        "template `name` must not leak: {config}"
    );
    assert!(!research_ws.join(".agent/display-name").exists());
    assert_eq!(
        advance_home::TopLevelDisplayName::get(&research_ws).as_deref(),
        Some("Research Desk")
    );
    let snap = snapshot.snapshot();
    let node = snap
        .nodes
        .iter()
        .find(|n| snap.handle_of(&n.id) == "research")
        .expect("tree node recorded");
    assert_eq!(node.kind, AgentKind::Child);
    assert_eq!(node.workspace_path, research_ws);
    assert_eq!(node.capabilities.len(), 1);
    assert_eq!(node.capabilities[0].id.as_str(), "fs");
    assert_eq!(root_declared_aliases(&ws), vec!["research".to_string()]);
    assert_eq!(d.capabilities, vec!["fs".to_string()], "live node caps");
    let root = detail(&get(&api, &format!("/client/agents/{ROOT}")));
    assert_eq!(
        root.capabilities,
        vec!["fs".to_string()],
        "root's declared active caps"
    );
    assert_eq!(root.children, vec!["research".to_string()]);
    assert_eq!(root.config.declared_children[0].alias, "research");
    assert_eq!(root.config.declared_children[0].template, "explorer");
    assert_eq!(root.config.declared_children[0].target_path, "research");
    assert_eq!(
        root.config.declared_children[0].capabilities,
        vec!["fs".to_string()],
        "requested capabilities are persisted in the declaration"
    );

    // Persisted capability update: subset-gated, restart-applied, root refused.
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "capabilities": [] }),
        "k-caps-clear",
    );
    let d = detail(&env);
    assert!(env
        .warnings
        .iter()
        .any(|w| w.code == WARNING_RESTART_REQUIRED));
    assert_eq!(
        d.capabilities,
        vec!["fs".to_string()],
        "live node unchanged until restart"
    );
    let root = detail(&get(&api, &format!("/client/agents/{ROOT}")));
    assert!(root.config.declared_children[0].capabilities.is_empty());
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "capabilities": ["fs"] }),
        "k-caps-restore",
    );
    assert!(env.is_ok(), "{:?}", env.error);
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "capabilities": ["llm"] }),
        "k-caps-superset",
    );
    assert_eq!(
        env.error_code(),
        Some(ClientErrorCode::InvalidRequest),
        "a capability the parent does not hold is refused"
    );
    let env = post(
        &api,
        &format!("/client/agents/{ROOT}:update"),
        json!({ "capabilities": ["fs"] }),
        "k-caps-root",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    let root = detail(&get(&api, &format!("/client/agents/{ROOT}")));
    assert_eq!(
        root.config.declared_children[0].capabilities,
        vec!["fs".to_string()],
        "refused updates leave the declaration untouched"
    );

    // conflicts + validation through the real spawner / tree.
    let env = post(
        &api,
        "/client/agents",
        json!({ "agent_id": "research", "template_ref": "explorer" }),
        "k-dup-id",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::AlreadyExists));
    let env = post(
        &api,
        "/client/agents",
        json!({ "agent_id": "other", "workspace_path": "research", "template_ref": "explorer" }),
        "k-dup-path",
    );
    assert_eq!(
        env.error_code(),
        Some(ClientErrorCode::AlreadyExists),
        "an occupied territory is already_exists"
    );
    let env = post(
        &api,
        "/client/agents",
        json!({ "agent_id": "orphan", "parent": "ghost", "template_ref": "explorer" }),
        "k-ghost",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::NotFound));
    let env = post(
        &api,
        "/client/agents",
        json!({ "agent_id": "tpl", "template_ref": "no-such-template" }),
        "k-tpl",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    let env = post(
        &api,
        "/client/agents",
        json!({ "agent_id": "greedy", "template_ref": "explorer", "capabilities": ["llm"] }),
        "k-subset",
    );
    assert_eq!(
        env.error_code(),
        Some(ClientErrorCode::InvalidRequest),
        "a capability the parent does not hold fails the subset gate"
    );
    assert!(
        !ws.join("greedy").exists(),
        "rejected spawn leaves no territory"
    );
    assert_eq!(
        root_declared_aliases(&ws),
        vec!["research".to_string()],
        "a failed spawn rolls its declaration back"
    );

    // nested create under a child: territory under the parent, nested declaration.
    let env = post(
        &api,
        "/client/agents",
        json!({
            "agent_id": "notes",
            "parent": "research",
            "workspace_path": "sub/notes",
            "template_ref": "planner"
        }),
        "k-create-notes",
    );
    let d = detail(&env);
    assert_eq!(d.agent.parent.as_deref(), Some("research"));
    assert_eq!(d.agent.workspace_path, "research/sub/notes");
    assert!(is_dir(&research_ws.join("sub/notes/.agent")));
    let mut declared = root_declared_aliases(&ws);
    declared.sort();
    assert_eq!(declared, vec!["notes".to_string(), "research".to_string()]);
    let research = detail(&get(&api, "/client/agents/research"));
    assert_eq!(research.children, vec!["notes".to_string()]);
    let root = detail(&get(&api, &format!("/client/agents/{ROOT}")));
    assert_eq!(
        root.config.declared_children[0].children[0].alias, "notes",
        "the declaration nests under its parent"
    );
    assert_eq!(
        root.config.declared_children[0].children[0].target_path,
        "sub/notes"
    );

    // update: config document + display name, with the restart warning.
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({
            "display_name": "R&D",
            "config_yaml": "capabilities:\n  fs: true\n  memory:\n    auto-grant: false\n"
        }),
        "k-update",
    );
    let d = detail(&env);
    assert!(env
        .warnings
        .iter()
        .any(|w| w.code == WARNING_RESTART_REQUIRED));
    assert_eq!(d.agent.display_name.as_deref(), Some("R&D"));
    assert_eq!(
        config_sans_id(&research_ws),
        "capabilities:\n  fs: true\n  memory:\n    auto-grant: false\ndisplay-name: R&D\n"
    );

    // update: display name ONLY is not a capability change — no restart warning, and the rest
    // of the document is untouched.
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "display_name": "Research" }),
        "k-update-name",
    );
    let d = detail(&env);
    assert!(
        !env.warnings
            .iter()
            .any(|w| w.code == WARNING_RESTART_REQUIRED),
        "a rename never asks for a restart"
    );
    assert_eq!(d.agent.display_name.as_deref(), Some("Research"));
    assert_eq!(
        config_sans_id(&research_ws),
        "capabilities:\n  fs: true\n  memory:\n    auto-grant: false\ndisplay-name: Research\n"
    );

    // update: a whole-document replace that omits `display-name` carries the name over.
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "config_yaml": "capabilities:\n  fs: true\n" }),
        "k-update-doc-only",
    );
    let d = detail(&env);
    assert_eq!(d.agent.display_name.as_deref(), Some("Research"));
    assert_eq!(
        config_sans_id(&research_ws),
        "capabilities:\n  fs: true\ndisplay-name: Research\n"
    );
    // ...and a replace that carries its own key renames explicitly.
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "config_yaml": "capabilities:\n  fs: true\n  memory:\n    auto-grant: false\ndisplay-name: Desk\n" }),
        "k-update-doc-name",
    );
    let d = detail(&env);
    assert_eq!(d.agent.display_name.as_deref(), Some("Desk"));
    let memory = d
        .config
        .capabilities
        .iter()
        .find(|c| c.name == "memory")
        .unwrap();
    assert!(memory.enabled && !memory.auto_grant);
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "config_yaml": "capabilities: [not, a, mapping]\n" }),
        "k-update-bad",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(
        config_sans_id(&research_ws),
        "capabilities:\n  fs: true\n  memory:\n    auto-grant: false\ndisplay-name: Desk\n",
        "a rejected document never touches the file"
    );
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "config_yaml": "agents:\n  - alias: x\n    bogus: 1\n" }),
        "k-update-bad-agents",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));

    // A root config edit that drops a capability a declared child carries is refused (it would
    // abort the next boot), whether the document carries `agents` or relies on the carry-over.
    let env = post(
        &api,
        &format!("/client/agents/{ROOT}:update"),
        json!({ "config_yaml": "capabilities:\n  llm: true\n" }),
        "k-update-root-drop",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    let root_doc = std::fs::read_to_string(ws.join(".agent/config.yaml")).unwrap();
    assert!(
        root_doc.contains("fs: true") && !root_doc.contains("llm: true"),
        "a refused root edit leaves the document untouched: {root_doc}"
    );
    let root = detail(&get(&api, &format!("/client/agents/{ROOT}")));
    assert!(root.config.capabilities.iter().any(|c| c.name == "fs"));

    // root config edit WITHOUT an `agents` key keeps the declared hierarchy.
    let env = post(
        &api,
        &format!("/client/agents/{ROOT}:update"),
        json!({ "config_yaml": "capabilities:\n  fs: true\n  llm: true\n" }),
        "k-update-root",
    );
    let root = detail(&env);
    assert_eq!(root.config.declared_children.len(), 1);
    assert_eq!(root.config.declared_children[0].alias, "research");
    assert_eq!(
        root_declared_aliases(&ws).len(),
        2,
        "capabilities edit carried the hierarchy over"
    );
    assert!(root.config.capabilities.iter().any(|c| c.name == "llm"));

    // delete: cascade removes the subtree, de-registers it, drops `.agent/` markers, keeps content.
    std::fs::write(research_ws.join("findings.md"), "keep me").unwrap();
    let env = post(
        &api,
        "/client/agents/research:delete",
        Value::Null,
        "k-delete",
    );
    assert!(env.is_ok(), "{:?}", env.error);
    let result: ClientAgentDeleteResult = serde_json::from_value(env.data.unwrap()).unwrap();
    assert_eq!(result.agent_id, "research");
    assert_eq!(
        result.removed_agent_ids,
        vec!["notes".to_string(), "research".to_string()],
        "post-order: descendants first"
    );
    assert!(!result.workspace_removed);
    let snap = snapshot.snapshot();
    assert!(snap
        .nodes
        .iter()
        .all(|n| n.id.0 != "research" && n.id.0 != "notes"));
    assert!(!research_ws.join(".agent").exists(), "marker removed");
    assert!(
        !research_ws.join("sub/notes/.agent").exists(),
        "nested marker removed"
    );
    assert_eq!(
        std::fs::read_to_string(research_ws.join("findings.md")).unwrap(),
        "keep me",
        "content survives a default delete"
    );
    assert!(root_declared_aliases(&ws).is_empty());
    let env = post(
        &api,
        "/client/agents/research:delete",
        Value::Null,
        "k-delete-2",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::NotFound));
    let env = post(
        &api,
        &format!("/client/agents/{ROOT}:delete"),
        Value::Null,
        "k-delete-root",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    assert!(ws.join(".agent/config.yaml").is_file(), "root untouched");

    // the freed territory can be re-created, then removed wholesale.
    let env = post(
        &api,
        "/client/agents",
        json!({ "agent_id": "scratch", "workspace_path": "research", "template_ref": "reviewer" }),
        "k-recreate",
    );
    let d = detail(&env);
    assert_eq!(d.agent.workspace_path, "research");
    let env = post(
        &api,
        "/client/agents/scratch:delete",
        json!({ "remove_workspace": true }),
        "k-delete-ws",
    );
    let result: ClientAgentDeleteResult = serde_json::from_value(env.data.unwrap()).unwrap();
    assert!(result.workspace_removed);
    assert!(
        !research_ws.exists(),
        "remove_workspace deletes the directory"
    );
    assert!(
        ws.join(".agent").is_dir(),
        "the root workspace is never removed"
    );
}

// ── AA-02: a second boot re-materializes client-created agents (adopt leg) ───────────────────
#[tokio::test(flavor = "multi_thread")]
async fn aa02_restart_rematerializes_created_agents() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    {
        let (_host, handles) = boot(&ws, &cfg).await;
        let api = handles.client_api_server.as_ref().unwrap().api();
        mint(&api, "tok", Scope::operator_default());
        detail(&post(
            &api,
            "/client/agents",
            json!({
                "agent_id": "research",
                "template_ref": "explorer",
                "display_name": "R",
                "capabilities": ["fs"]
            }),
            "k1",
        ));
        detail(&post(
            &api,
            "/client/agents",
            json!({
                "agent_id": "notes",
                "parent": "research",
                "template_ref": "planner",
                "capabilities": ["fs"]
            }),
            "k2",
        ));
        std::fs::write(ws.join("research/.agent/skills/.keep"), "").unwrap();
    }
    // Second lifetime: the declared hierarchy is adopted, not re-initialized — capabilities kept.
    let (_host, handles) = boot(&ws, &cfg).await;
    let snap = handles.agent_tree_snapshot.clone().unwrap().snapshot();
    let research = snap
        .nodes
        .iter()
        .find(|n| snap.handle_of(&n.id) == "research")
        .expect("research re-materialized");
    assert_eq!(
        research
            .parent
            .as_ref()
            .map(|p| snap.handle_of(p))
            .as_deref(),
        Some(ROOT)
    );
    assert_eq!(research.workspace_path, ws.join("research"));
    assert_eq!(research.template_ref.as_deref(), Some("explorer"));
    assert_eq!(
        research
            .capabilities
            .iter()
            .map(|c| c.id.as_str())
            .collect::<Vec<_>>(),
        vec!["fs"],
        "created capabilities survive a restart"
    );
    let notes = snap
        .nodes
        .iter()
        .find(|n| snap.handle_of(&n.id) == "notes")
        .expect("nested child re-materialized");
    assert_eq!(
        notes.parent.as_ref().map(|p| snap.handle_of(p)).as_deref(),
        Some("research")
    );
    assert_eq!(notes.workspace_path, ws.join("research/notes"));
    assert_eq!(notes.capabilities.len(), 1);
    assert!(
        ws.join("research/.agent/skills/.keep").is_file(),
        "adoption keeps the earlier lifetime's territory byte-identical"
    );
    let api = handles.client_api_server.as_ref().unwrap().api();
    mint(&api, "tok", Scope::operator_default());
    let d = detail(&get(&api, "/client/agents/research"));
    assert_eq!(d.agent.display_name.as_deref(), Some("R"));
    assert_eq!(d.children, vec!["notes".to_string()]);
    assert_eq!(d.capabilities, vec!["fs".to_string()]);
    // Narrowing a parent below what its declared child carries is refused (it would abort the
    // next boot); narrow the child first, then the parent. Both apply at the NEXT boot.
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "capabilities": [] }),
        "k-caps-too-early",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    let env = post(
        &api,
        "/client/agents/notes:update",
        json!({ "capabilities": [] }),
        "k-caps-notes",
    );
    assert!(env.is_ok(), "{:?}", env.error);
    let env = post(
        &api,
        "/client/agents/research:update",
        json!({ "capabilities": [] }),
        "k-caps",
    );
    assert!(env.is_ok(), "{:?}", env.error);
    drop(api);
    drop(handles);
    let (_host, handles) = boot(&ws, &cfg).await;
    let snap = handles.agent_tree_snapshot.clone().unwrap().snapshot();
    let research = snap
        .nodes
        .iter()
        .find(|n| snap.handle_of(&n.id) == "research")
        .unwrap();
    assert!(
        research.capabilities.is_empty(),
        "the updated capability list is what the third boot materializes"
    );
    let notes = snap
        .nodes
        .iter()
        .find(|n| snap.handle_of(&n.id) == "notes")
        .unwrap();
    assert!(notes.capabilities.is_empty());
    // The adopted agent is fully manageable: delete it and boot again root-only.
    let api = handles.client_api_server.as_ref().unwrap().api();
    mint(&api, "tok", Scope::operator_default());
    let env = post(&api, "/client/agents/research:delete", Value::Null, "k3");
    assert!(env.is_ok(), "{:?}", env.error);
    drop(api);
    drop(handles);
    let (_host, handles) = boot(&ws, &cfg).await;
    let snap = handles.agent_tree_snapshot.clone().unwrap().snapshot();
    assert_eq!(
        snap.nodes.len(),
        1,
        "deleted agents stay deleted across boots"
    );
}

// ── AA-03: no tree ⇒ the family answers module_unavailable ───────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn aa03_no_tree_is_module_unavailable() {
    let (_g, ws, cfg) = fresh_workspace("capabilities: {}\n");
    let (_host, handles) = boot(&ws, &cfg).await;
    assert!(handles.agent_admin.is_none());
    assert!(handles.agent_tree.is_none());
    let api = handles.client_api_server.as_ref().unwrap().api();
    mint(&api, "tok", Scope::operator_default());
    let env = get(&api, "/client/agents");
    assert_eq!(env.error_code(), Some(ClientErrorCode::ModuleUnavailable));
    let env = post(
        &api,
        "/client/agents",
        json!({ "agent_id": "x", "template_ref": "explorer" }),
        "k",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::ModuleUnavailable));
}

// ── AA-04: the adapter alone over a real tree (no daemon), including edge rules ──────────────

struct NoopGrant;
impl GrantCascadeRevoke for NoopGrant {
    fn revoke_for_agent(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
struct NoopMailbox;
impl MailboxCascade for NoopMailbox {
    fn flush_mailbox(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn notify_parent_crash(&self, _: &str, _: &str, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
struct NoopRun;
impl RunCascade for NoopRun {
    fn ensure_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn cancel_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
struct NoopWorkspace;
impl WorkspaceCleanup for NoopWorkspace {
    fn remove_sub_workspace(&self, _: &Path) -> Result<(), LifecycleError> {
        Ok(())
    }
}

fn direct_adapter(ws: &Path) -> (AgentAdminAdapter, AgentTreeStore) {
    let tree = AgentTreeStore::new(ws.to_path_buf()).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId(ROOT.into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: ws.to_path_buf(),
        // Live root holds fs + llm while its config document declares only fs (see aa04):
        // the persisted-consistency check must gate on the document, not the live node.
        capabilities: ["fs", "llm"]
            .into_iter()
            .map(|c| Capability {
                id: CapabilityId::new(c),
                params: CapParams::empty(),
            })
            .collect(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner = DefaultSpawner::with_template_resolver(
        tree.clone(),
        Arc::new(CapGrantSubsetAdapter::new()),
        Arc::new(BuiltinTemplateRegistry::new()),
    );
    let terminator = DefaultTerminateController::new(
        tree.clone(),
        Arc::new(NoopGrant),
        Arc::new(NoopMailbox),
        Arc::new(NoopRun),
        Arc::new(NoopWorkspace),
    );
    // Lane agent-llm-policy: a static runtime config (one provider, `openai`) so the direct
    // adapter can validate `llm.provider` ids without a daemon.
    let cfg: advance_runtime::config::RuntimeConfig =
        serde_yml::from_str(&runtime_yaml().replace(
            "llm-providers: []",
            "llm-providers:\n  - id: openai\n    endpoint: https://api.openai.com\n    api-key-secret: openai-api-key\n    model-aliases:\n      gpt: gpt-4o\n    cost-per-mtoken-in: 2.50\n    cost-per-mtoken-out: 10.00\n    rate-limit:\n      requests-per-minute: 1000\n      tokens-per-minute: 400000",
        ))
        .expect("direct adapter config parses");
    let adapter = AgentAdminAdapter::new(
        tree.clone(),
        Arc::new(spawner),
        Arc::new(terminator),
        Arc::new(BuiltinTemplateRegistry::new()),
        AgentId(ROOT.into()),
        Arc::new(cap_llm::StaticConfig(Arc::new(cfg))),
    );
    (adapter, tree)
}

fn create_req(id: &str, parent: Option<&str>, path: Option<&str>) -> ClientCreateAgentRequest {
    ClientCreateAgentRequest {
        agent_id: Some(id.into()),
        parent: parent.map(str::to_string),
        workspace_path: path.map(str::to_string),
        template_ref: "explorer".into(),
        capabilities: Vec::new(),
        display_name: None,
        config_yaml: None,
        llm: None,
    }
}

#[test]
fn aa04_adapter_edge_rules_over_real_tree() {
    let dir = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::create_dir_all(ws.join(".agent")).unwrap();
    std::fs::write(
        ws.join(".agent/config.yaml"),
        "# operator comment\ncapabilities:\n  fs: true\n",
    )
    .unwrap();
    let (adapter, tree) = direct_adapter(&ws);

    // A capability the live root holds but its config document does not declare is refused:
    // it would be persisted under a root that cannot cover it at the next boot.
    let mut greedy = create_req("greedy", None, None);
    greedy.capabilities = vec!["llm".into()];
    assert!(matches!(
        adapter.create_agent(&greedy),
        Err(ProviderError::InvalidRequest(_))
    ));
    assert!(root_declared_aliases(&ws).is_empty());
    assert!(!ws.join("greedy").exists());

    // A create carrying its own config document writes it after materialization; requested
    // capabilities are persisted in the declaration.
    let mut req = create_req("a", None, None);
    req.config_yaml = Some("capabilities:\n  fs: true\n".into());
    req.capabilities = vec!["fs".into()];
    let d = adapter.create_agent(&req).unwrap();
    assert_eq!(
        d.config
            .config_yaml
            .as_deref()
            .map(sans_identity)
            .as_deref(),
        Some("capabilities:\n  fs: true\n")
    );
    assert_eq!(d.capabilities, vec!["fs".to_string()]);
    assert_eq!(root_declared_aliases(&ws), vec!["a".to_string()]);
    let root = adapter.get_agent(ROOT).unwrap();
    assert_eq!(
        root.config.declared_children[0].capabilities,
        vec!["fs".to_string()]
    );

    // Sub agents are not valid parents; a hidden-name path is rejected by the tree rules.
    // (`a` is a HANDLE; the tree is keyed by the minted id.)
    let a_id = tree.node_by_handle("a").expect("a exists").id;
    tree.insert_child(
        &a_id,
        AgentNode {
            id: AgentId("ephemeral".into()),
            kind: AgentKind::Sub,
            parent: Some(a_id.clone()),
            workspace_path: {
                let p = ws.join("a/.sub/x");
                std::fs::create_dir_all(&p).unwrap();
                p
            },
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    assert!(matches!(
        adapter.create_agent(&create_req("b", Some("ephemeral"), None)),
        Err(ProviderError::InvalidRequest(_))
    ));
    assert!(matches!(
        adapter.create_agent(&create_req("b", Some("a"), Some(".git/x"))),
        Err(ProviderError::InvalidRequest(_))
    ));
    assert!(matches!(
        adapter.create_agent(&create_req("b", Some("nope"), None)),
        Err(ProviderError::NotFound(_))
    ));
    assert_eq!(
        root_declared_aliases(&ws),
        vec!["a".to_string()],
        "rejected creates leave the declaration file untouched"
    );

    // A child of an undeclared (guest-spawned) parent is created live but not persisted.
    std::fs::create_dir_all(ws.join("guest")).unwrap();
    tree.insert_child(
        &AgentId(ROOT.into()),
        AgentNode {
            id: AgentId("guest".into()),
            kind: AgentKind::Child,
            parent: Some(AgentId(ROOT.into())),
            workspace_path: ws.join("guest"),
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    let d = adapter
        .create_agent(&create_req("guest-child", Some("guest"), None))
        .unwrap();
    assert_eq!(d.agent.workspace_path, "guest/guest-child");
    assert!(tree.node_by_handle("guest-child").is_some());
    assert_eq!(root_declared_aliases(&ws), vec!["a".to_string()]);

    // Capabilities: a guest-spawned (undeclared) child cannot persist a capability list; a Sub
    // never can; the root's capabilities are its config document.
    let caps_update = ClientUpdateAgentRequest {
        display_name: None,
        handle: None,
        config_yaml: None,
        capabilities: Some(vec![]),
        llm: None,
    };
    assert!(matches!(
        adapter.update_agent("guest-child", &caps_update),
        Err(ProviderError::InvalidRequest(_))
    ));
    assert!(matches!(
        adapter.update_agent("ephemeral", &caps_update),
        Err(ProviderError::InvalidRequest(_))
    ));
    assert!(matches!(
        adapter.update_agent(ROOT, &caps_update),
        Err(ProviderError::InvalidRequest(_))
    ));

    // Update: an `agents`-carrying document replaces the hierarchy; an invalid one is rejected.
    let bad = ClientUpdateAgentRequest {
        display_name: None,
        handle: None,
        config_yaml: Some(
            "agents:\n  - alias: 'bad alias'\n    template: t\n    target-path: p\n".into(),
        ),
        capabilities: None,
        llm: None,
    };
    assert!(matches!(
        adapter.update_agent(ROOT, &bad),
        Err(ProviderError::InvalidRequest(_))
    ));
    let list = adapter.list_agents().unwrap();
    assert_eq!(list[0].agent_id, ROOT, "root sorts first");
    let ids: Vec<&str> = list.iter().map(|a| a.agent_id.as_str()).collect();
    assert_eq!(ids, vec![ROOT, "a", "ephemeral", "guest", "guest-child"]);

    // Delete the guest parent: the whole subtree goes, markers dropped, no declaration touched.
    let result = adapter.delete_agent("guest", &Default::default()).unwrap();
    assert_eq!(
        result.removed_agent_ids,
        vec!["guest-child".to_string(), "guest".to_string()]
    );
    assert!(!ws.join("guest/guest-child/.agent").exists());
    assert!(ws.join("guest/guest-child").is_dir(), "content dir stays");
    assert_eq!(root_declared_aliases(&ws), vec!["a".to_string()]);

    // Projection helper is reachable for adapters/tests.
    let cfg = project_config(Some("capabilities:\n  fs: false\n"));
    assert!(!cfg.capabilities[0].enabled);
}
