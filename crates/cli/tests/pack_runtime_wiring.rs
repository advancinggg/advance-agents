//! Installed packs over the PRODUCTION wiring: boot a workspace through
//! `RuntimeHostBuilder::new` → `wire_capabilities` and drive the daemon-composed `ClientApi`.
//!
//! - a pack installed before boot is live at boot: `/client/schema` carries its aspect with
//!   the bound operations available, existing records are indexed with the aspect, its skill
//!   tool is registered;
//! - `POST /client/packs:install` takes effect before the response returns, and
//!   `:uninstall` takes the pack's contributions away again (no restart);
//! - an install made by ANOTHER process into the packs dir reaches the running daemon;
//! - the `data` host tool is reachable through the production tool registry with the
//!   caller's identity, and serves an agent that holds an `fs` grant (no grant of its own);
//! - the pack's views and presentation reach `/client/schema` and the agent's `describe`.
//!
//! The same boot composes the MCP client (module `mcp_client` below): a root that declares
//! `mcp` gets the seven `mcp-client` host functions over the operator's server files, each call
//! decided by its `mcp` grant; a root that does not gets nothing MCP at all.
//!
//! Fixture discipline of the pack tests: env-var master key (never read), no network, the
//! agenda skill's `tool.wasm` is the cap-tools clock fixture (any component exporting
//! `tool-exports` passes the installer; the registered id is what the operations bind to).
//! The MCP tests bring their own servers: bash scripts over stdio and an http double on
//! loopback; one of their homes reads a master key from its environment variable.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use advance_cli::wiring::{wire_capabilities, WiringHandles};
use advance_client_api::entities::{ClientAspectOrderKey, ClientEntityPage, ClientSchema};
use advance_client_api::{
    ClientApi, ClientEnvelope, ClientRequest, ClientSession, Platform, Principal, Scope,
};
use advance_pack_manager::{AutoApprove, InMemoryPackRegistry, Installer, PackManifest};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use serde_json::{json, Value};

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
  env-var-name: ADV_PACK_RUNTIME_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

/// The version of the shipped agenda pack, read from its manifest.
fn agenda_version() -> String {
    let text = std::fs::read_to_string(repo().join("packs/agenda/pack.yaml")).unwrap();
    PackManifest::from_yaml(&text).unwrap().version
}

struct Ws {
    _guard: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    agenda_src: PathBuf,
}

/// A workspace declaring fs + tools + grant, one pre-existing agenda record, and a copy of
/// the agenda pack (with a `tool.wasm`) OUTSIDE the workspace to install from.
fn workspace() -> Ws {
    let guard = tempfile::tempdir().expect("tempdir");
    let base = std::fs::canonicalize(guard.path()).unwrap();
    let root = base.join("ws");
    std::fs::create_dir_all(root.join(".advance")).unwrap();
    std::fs::create_dir_all(root.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(root.join(".agent")).unwrap();
    std::fs::create_dir_all(root.join("notes")).unwrap();
    let config = root.join(".advance/runtime-config.yaml");
    std::fs::write(&config, runtime_yaml()).unwrap();
    std::fs::write(
        root.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  tools: true\n  grant: true\n",
    )
    .unwrap();
    std::fs::write(
        root.join("notes/launch.md"),
        "---\nid: e-launch\ntype: work-item\ntitle: Launch\nstatus: todo\n---\nShip it.\n",
    )
    .unwrap();
    let agenda_src = base.join("src/agenda");
    copy_tree(&repo().join("packs/agenda"), &agenda_src);
    std::fs::copy(
        repo().join("crates/capabilities/cap-tools/tests/fixtures/clock_tool.component.wasm"),
        agenda_src.join("skills/agenda/tool.wasm"),
    )
    .unwrap();
    Ws {
        _guard: guard,
        root,
        config,
        agenda_src,
    }
}

/// An installer over the workspace's packs dir with its OWN registry — what a separate
/// `advance pack install` process uses.
fn shell_installer(ws: &Ws) -> Installer {
    let packs_dir = ws.root.join(".advance/packs");
    Installer::new(
        &packs_dir,
        Arc::new(InMemoryPackRegistry::new(packs_dir.clone())),
        env!("CARGO_PKG_VERSION"),
        Arc::new(AutoApprove),
    )
}

async fn boot(ws: &Ws) -> (advance_runtime::bootstrap::RuntimeHost, WiringHandles) {
    let builder = RuntimeHostBuilder::new(&ws.config, &ws.root)
        .await
        .expect("builder");
    wire_capabilities(builder, &ws.root).await.expect("wire")
}

fn operator_api(handles: &WiringHandles) -> Arc<ClientApi> {
    let api = handles
        .client_api_server
        .as_ref()
        .expect("EventBus up ⇒ Client API bound")
        .api();
    api.sessions().insert(
        "tok".to_string(),
        ClientSession {
            session_id: "sess-tok".to_string(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    api
}

fn data<T: serde::de::DeserializeOwned>(env: &ClientEnvelope<Value>) -> T {
    assert!(env.is_ok(), "expected ok, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("payload parses")
}

fn schema(api: &ClientApi) -> ClientSchema {
    data(&api.handle(ClientRequest::get("/client/schema").with_session("tok")))
}

fn agenda_rows(api: &ClientApi, agent: &str) -> ClientEntityPage {
    data(
        &api.handle(
            ClientRequest::post(
                "/client/entities:query",
                json!({ "agent_id": agent, "filter": { "aspect": "agenda" } }),
            )
            .with_session("tok"),
        ),
    )
}

fn post(api: &ClientApi, path: &str, body: Value, key: &str) -> ClientEnvelope<Value> {
    api.handle(
        ClientRequest::post(path, body)
            .with_session("tok")
            .with_idempotency_key(key),
    )
}

async fn has_tool(handles: &WiringHandles, id: &str) -> bool {
    handles
        .tool_registry
        .as_ref()
        .expect("tools declared")
        .list()
        .await
        .iter()
        .any(|t| t.id == id)
}

fn assert_agenda_live(schema: &ClientSchema) {
    let names: Vec<&str> = schema.aspects.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, vec!["agenda"], "{schema:?}");
    let ops = &schema.aspects[0].operations;
    assert_eq!(ops.len(), 2);
    assert!(
        ops.iter().all(|o| o.available && o.tool == "skill::agenda"),
        "{ops:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pack_installed_before_boot_is_live_at_boot() {
    let ws = workspace();
    shell_installer(&ws)
        .install(ws.agenda_src.to_str().unwrap())
        .await
        .expect("install before boot");
    let (_host, handles) = boot(&ws).await;
    let api = operator_api(&handles);

    assert_agenda_live(&schema(&api));
    let rows = agenda_rows(&api, &handles.root_agent_id).rows;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].id, "e-launch");
    assert!(has_tool(&handles, "skill::agenda").await);

    let report = handles.pack_runtime.apply().await;
    assert!(report.presets.is_empty(), "the pack ships no preset");
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
}

// The agenda pack's views and presentation travel from its schema file, through the live
// merge and the data store, to `GET /client/schema` and to an agent's `data.describe`.
#[tokio::test(flavor = "multi_thread")]
async fn the_agenda_views_reach_clients_with_their_presentation() {
    let ws = workspace();
    shell_installer(&ws)
        .install(ws.agenda_src.to_str().unwrap())
        .await
        .expect("install before boot");
    let (_host, handles) = boot(&ws).await;
    let api = operator_api(&handles);

    let live = schema(&api);
    assert_agenda_live(&live);
    let agenda = &live.aspects[0];
    assert_eq!(agenda.label.as_deref(), Some("Agenda"));
    assert_eq!(agenda.icon.as_deref(), Some("calendar-check"));
    assert_eq!(agenda.default_view.as_deref(), Some("list"));
    assert_eq!(agenda.view_order, ["list", "board", "calendar"]);

    let key = |field: &str, ascending: bool| ClientAspectOrderKey {
        field: field.into(),
        ascending,
    };
    let view = |name: &str| agenda.views.iter().find(|v| v.name == name).unwrap();
    let board = view("board");
    assert_eq!(board.group_by.as_deref(), Some("status"));
    assert_eq!(board.order, [key("priority", false), key("due", true)]);
    assert_eq!(
        (board.label.as_deref(), board.icon.as_deref()),
        (Some("Board"), Some("kanban"))
    );
    assert_eq!(
        view("list").columns,
        ["title", "status", "due", "priority", "assignee"]
    );
    assert!(
        view("list").order.is_empty(),
        "the list keeps its query's order"
    );
    let open = agenda.queries.iter().find(|q| q.name == "open").unwrap();
    assert_eq!(open.order, [key("due", true), key("priority", false)]);

    let field = |name: &str| agenda.fields.iter().find(|f| f.name == name).unwrap();
    let status = field("status")
        .display
        .clone()
        .expect("status is presented");
    assert_eq!(status.format.as_deref(), Some("badge"));
    let tones: Vec<(&str, Option<&str>)> = status
        .values
        .iter()
        .map(|v| (v.value.as_str(), v.tone.as_deref()))
        .collect();
    assert_eq!(
        tones,
        [
            ("todo", Some("neutral")),
            ("doing", Some("info")),
            ("done", Some("success")),
            ("cancelled", Some("muted")),
        ]
    );
    let due = field("due").display.clone().expect("due is presented");
    assert_eq!(
        (due.format.as_deref(), due.icon.as_deref()),
        (Some("date"), Some("calendar"))
    );
    let title = field("title");
    assert_eq!(title.r#type, "string");
    assert_eq!(
        title.display.clone().unwrap().label.as_deref(),
        Some("Title")
    );

    // The agent-facing describe carries the same presentation.
    let tools = handles.tool_registry.clone().expect("tools declared");
    let described: Value = serde_json::from_slice(
        &tools
            .invoke_as(&handles.root_agent_id, "data", "describe", b"{}")
            .await
            .expect("describe with the root's fs grant"),
    )
    .unwrap();
    let aspect = &described["aspects"][0];
    assert_eq!(aspect["default_view"], "list");
    assert_eq!(aspect["view_order"], json!(["list", "board", "calendar"]));
    let described_status = aspect["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "status")
        .unwrap();
    assert_eq!(
        described_status["display"],
        serde_json::to_value(&status).unwrap()
    );
}

// A pack that an older runtime installed with the retired `provides: resource-capabilities` key
// (and the `resource-capabilities/` directory it required) does not stop the daemon: it boots,
// the rest of the pack is live, and the key is reported as ignored, once for the pack. A new
// install declaring the key is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_pack_declaring_the_retired_resource_capabilities_key_still_boots() {
    let ws = workspace();
    let installed = shell_installer(&ws)
        .install(ws.agenda_src.to_str().unwrap())
        .await
        .expect("install before boot");
    let manifest = installed.install_path.join("pack.yaml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    let with_key = text.replacen(
        "provides:\n",
        "provides:\n  resource-capabilities:\n    - structured-data\n",
        1,
    );
    assert_ne!(with_key, text);
    std::fs::write(&manifest, &with_key).unwrap();
    // An older runtime required `resource-capabilities/<name>/capability.yaml` for each listed
    // name, at install and at every rescan, so such a pack carries the directory too.
    let legacy = installed
        .install_path
        .join("resource-capabilities/structured-data");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(
        legacy.join("capability.yaml"),
        "id: advance.structured-data\ncanonical_surfaces: [projection-native]\n",
    )
    .unwrap();

    let (_host, handles) = boot(&ws).await;
    let api = operator_api(&handles);
    assert_agenda_live(&schema(&api));
    assert!(has_tool(&handles, "skill::agenda").await);
    let report = handles.pack_runtime.apply().await;
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(
        report.warnings[0].starts_with(&format!(
            "pack {}@{}: `provides: resource-capabilities` is ignored",
            installed.name, installed.version
        )),
        "{:?}",
        report.warnings
    );
    let notes = handles
        .pack_runtime
        .notes_for(&installed.name, &installed.version, &report);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("resource-capabilities"), "{notes:?}");

    let src = ws.root.parent().unwrap().join("src/legacy");
    std::fs::create_dir_all(src.join("behavior-binaries")).unwrap();
    std::fs::write(src.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    let plain = "name: legacy\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\n\
                 trust-level: untrusted\nprovides:\n  behavior-binaries:\n    - dummy\n\
                 checksums:\n  algo: sha256\n  files: {}\n";
    std::fs::write(
        src.join("pack.yaml"),
        plain.replacen("provides:\n", "provides:\n  resource-capabilities: []\n", 1),
    )
    .unwrap();
    let body = json!({ "source": src.to_str().unwrap(), "accepted_capabilities": [] });
    let env = post(
        &api,
        "/client/packs:install",
        body.clone(),
        "install-legacy",
    );
    let error = env.error.expect("the retired key is refused");
    assert_eq!(
        error.code,
        advance_client_api::ClientErrorCode::InvalidRequest,
        "{error:?}"
    );
    assert!(!ws.root.join(".advance/packs/legacy@1.0.0").exists());
    // The same pack without the key installs.
    std::fs::write(src.join("pack.yaml"), plain).unwrap();
    let env = post(&api, "/client/packs:install", body, "install-legacy-2");
    assert!(env.is_ok(), "{:?}", env.error);
}

#[tokio::test(flavor = "multi_thread")]
async fn client_api_install_is_hot_and_uninstall_withdraws() {
    let ws = workspace();
    let (_host, handles) = boot(&ws).await;
    let api = operator_api(&handles);
    assert!(schema(&api).aspects.is_empty());
    assert!(agenda_rows(&api, &handles.root_agent_id).rows.is_empty());

    let env = post(
        &api,
        "/client/packs:install",
        json!({ "source": ws.agenda_src.to_str().unwrap(), "accepted_capabilities": ["tools", "fs"] }),
        "install-1",
    );
    assert!(env.is_ok(), "{:?}", env.error);
    // Effective BEFORE the install response returned: no wait, no restart.
    assert_agenda_live(&schema(&api));
    assert!(has_tool(&handles, "skill::agenda").await);
    assert_eq!(
        agenda_rows(&api, &handles.root_agent_id).rows.len(),
        1,
        "the existing record gained the aspect"
    );

    let env = post(
        &api,
        &format!("/client/packs/agenda@{}:uninstall", agenda_version()),
        json!({}),
        "uninstall-1",
    );
    assert!(env.is_ok(), "{:?}", env.error);
    assert!(schema(&api).aspects.is_empty());
    assert!(!has_tool(&handles, "skill::agenda").await);
    assert!(agenda_rows(&api, &handles.root_agent_id).rows.is_empty());
    let report = handles.pack_runtime.apply().await;
    assert!(report.presets.is_empty() && report.tools.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_install_by_another_process_reaches_the_running_daemon() {
    let ws = workspace();
    let (_host, handles) = boot(&ws).await;
    let api = operator_api(&handles);
    assert!(schema(&api).aspects.is_empty());

    shell_installer(&ws)
        .install(ws.agenda_src.to_str().unwrap())
        .await
        .expect("shell install");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if !schema(&api).aspects.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the daemon did not pick up the install within 15 s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_agenda_live(&schema(&api));
    assert_eq!(agenda_rows(&api, &handles.root_agent_id).rows.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_holding_fs_and_tools_reaches_the_data_tool_through_the_production_registry() {
    let ws = workspace();
    shell_installer(&ws)
        .install(ws.agenda_src.to_str().unwrap())
        .await
        .expect("install before boot");
    let (_host, handles) = boot(&ws).await;
    let root = handles.root_agent_id.clone();
    let tools = handles.tool_registry.clone().expect("tools declared");

    // The caller identity survives the production registry wrapper, and the tool is
    // authorized by the caller's `fs` grant: an identity without one is refused.
    let denied = tools
        .invoke_as("nobody", "data", "describe", b"{}")
        .await
        .expect_err("no fs grant");
    let msg = format!("{denied:?}");
    assert!(msg.contains("needs fs"), "{msg}");

    // A leftover grant of the retired `data` family authorizes nothing.
    handles
        .cap_grant
        .store
        .insert(Grant {
            id: GrantId::new("g-data-nobody"),
            grantee: "nobody".into(),
            capability: "data".into(),
            params: vec![CapParam {
                key: "mode".into(),
                value: "read,write".into(),
            }],
            ttl: GrantTtl::Persistent,
            issuer: GrantIssuer::Config,
            provenance: GrantProvenance::StaticConfig,
            status: GrantStatus::Active,
            created_at: chrono::Utc::now(),
            expires_at: None,
        })
        .expect("insert a legacy data grant");
    tools
        .invoke_as("nobody", "data", "describe", b"{}")
        .await
        .expect_err("a legacy data grant alone does not open the tool");

    // The root declares `fs` and `tools`; that is all the tool needs.
    let described: Value = serde_json::from_slice(
        &tools
            .invoke_as(&root, "data", "describe", b"{}")
            .await
            .expect("describe with the root's fs grant"),
    )
    .unwrap();
    assert_eq!(described["aspects"][0]["name"], "agenda");
    assert!(described["aspects"][0]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|o| o["available"] == true));
    let rows: Value = serde_json::from_slice(
        &tools
            .invoke_as(&root, "data", "query", br#"{"query":"open"}"#)
            .await
            .expect("the agenda `open` query"),
    )
    .unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["id"], "e-launch");
}

// A pack workflow runs through the daemon-composed Client API: `:apply` spawns the child the
// workflow describes, from the pack's own template. The workspace declares `lifecycle` too,
// which is what binds the production workflow executor.
#[tokio::test(flavor = "multi_thread")]
async fn client_api_apply_runs_a_pack_workflow() {
    let ws = workspace();
    std::fs::write(
        ws.root.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  tools: true\n  grant: true\n  lifecycle: true\n",
    )
    .unwrap();
    let src = ws.root.parent().unwrap().join("src/p");
    let t = src.join("agent-templates/researcher");
    std::fs::create_dir_all(&t).unwrap();
    std::fs::write(
        t.join("template.yaml"),
        "name: researcher\nversion: 1.0.0\ndescription: Research template\nbehavior:\n  type: embedded\n  binary: behavior.wasm\n",
    )
    .unwrap();
    std::fs::write(t.join("AGENTS.md"), "# researcher\n").unwrap();
    std::fs::write(t.join("behavior.wasm"), b"\0asm\x01\0\0\0").unwrap();
    std::fs::create_dir_all(src.join("workflows")).unwrap();
    std::fs::write(
        src.join("workflows/team.yaml"),
        "name: team\nsteps:\n  - type: spawn-child\n    template: p@1.0.0/agent-templates/researcher\n    target-path: /research-assistant\n",
    )
    .unwrap();
    std::fs::write(
        src.join("pack.yaml"),
        "name: p\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\ntrust-level: untrusted\nprovides:\n  agent-templates:\n    - researcher\n  workflows:\n    - team\nchecksums:\n  algo: sha256\n  files: {}\n",
    )
    .unwrap();
    // `lifecycle` wires the secret store too, which needs the configured master key.
    std::env::set_var("ADV_PACK_RUNTIME_MK_UNUSED", "11".repeat(32));
    let (_host, handles) = boot(&ws).await;
    let api = operator_api(&handles);

    let env = post(
        &api,
        "/client/packs:install",
        json!({ "source": src.to_str().unwrap(), "accepted_capabilities": [] }),
        "install-p",
    );
    assert!(env.is_ok(), "{:?}", env.error);

    let env = post(
        &api,
        "/client/packs/p@1.0.0:apply",
        json!({ "workflow": "team" }),
        "apply-team",
    );
    assert!(env.is_ok(), "{:?}", env.error);
    let result = env.data.expect("apply result");
    assert_eq!(result["steps_executed"], json!(["spawn-child"]));
    let child = ws.root.join("research-assistant");
    assert!(
        child.join(".agent/AGENTS.md").is_file(),
        "child materialized from the pack template"
    );

    let env = post(
        &api,
        "/client/packs/p@1.0.0:apply",
        json!({ "workflow": "nope" }),
        "apply-nope",
    );
    assert!(!env.is_ok(), "an unknown workflow is refused");
}

// ── The MCP client over the production wiring ───────────────────────────────────────────
//
// An operator server file names a server (a bash script speaking MCP over its stdin and
// stdout, or an http double on loopback), the root declares `mcp`, and the `mcp-client` host
// functions the daemon registered are called the way the capability injector calls them:
// with the caller's agent id in the call context.
#[cfg(unix)]
mod mcp_client {
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use advance_cli::wiring::{wire_capabilities, WiringHandles};
    use advance_event_bus::{EventFilter, ReadNext};
    use advance_runtime::bootstrap::{RuntimeHost, RuntimeHostBuilder};
    use advance_runtime::host_registry::HostCallContext;
    use advance_runtime::ComponentCtx;
    use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
    use cap_grant::data::GrantStatus;
    use serde_json::{json, Value};
    use wasmtime::component::Val;

    use super::runtime_yaml;

    const NAMESPACE: &str = "advance:runtime/mcp-client@0.1.0";

    /// Never set: a home whose master key comes from this variable finds none there.
    const NO_KEY_ENV: &str = "ADV_PACK_RUNTIME_MCP_NO_KEY";
    /// Set by [`with_master_key`], for a home that needs its master key.
    const KEY_ENV: &str = "ADV_PACK_RUNTIME_MCP_KEY";
    const KEY_BYTE: u8 = 0x4d;

    fn with_master_key() {
        static SET: std::sync::Once = std::sync::Once::new();
        SET.call_once(|| std::env::set_var(KEY_ENV, format!("{KEY_BYTE:02x}").repeat(32)));
    }

    struct Home {
        _guard: tempfile::TempDir,
        root: PathBuf,
        config: PathBuf,
        /// Outside the workspace: the server scripts and what they record.
        marks: PathBuf,
    }

    /// A workspace whose `.agent/config.yaml` is `agent_yaml`, and whose runtime config takes
    /// its master key from the environment variable `key_env` and ends with `tail` (more
    /// blocks, such as `mcp:`).
    fn home(agent_yaml: &str, key_env: &str, tail: &str) -> Home {
        let guard = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(guard.path()).unwrap();
        let root = base.join("ws");
        let marks = base.join("marks");
        for dir in [
            root.join(".advance"),
            root.join(".runtime/events/jsonl"),
            root.join(".agent"),
            marks.clone(),
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let config = root.join(".advance/runtime-config.yaml");
        let yaml = runtime_yaml().replace("ADV_PACK_RUNTIME_MK_UNUSED", key_env);
        assert!(yaml.contains(key_env));
        std::fs::write(&config, yaml + tail).unwrap();
        std::fs::write(root.join(".agent/config.yaml"), agent_yaml).unwrap();
        Home {
            _guard: guard,
            root,
            config,
            marks,
        }
    }

    /// A bash MCP server over stdio. It records its pid (`<id>.starts`, one line per start)
    /// and the pid of a process it starts (`<id>.children`), answers `initialize`, takes
    /// `notifications/initialized`, then serves: `tools/list` names `echo`, `echo_twice` and
    /// `rm`; a call of `hang` is recorded (`<id>.unanswered`) and never answered; any other
    /// call is recorded (`<id>.calls`) and answered. `@EXTRA@` runs first. The script uses
    /// builtins and absolute paths only: the server starts with an empty environment.
    const SERVER_SCRIPT: &str = r#"
@EXTRA@
echo $$ >> '@MARKS@/@ID@.starts'
/bin/sleep 300 &
echo $! >> '@MARKS@/@ID@.children'
read -r init
printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"@ID@","version":"1"}}}\n'
read -r initialized
while read -r line; do
  id=${line##*\"id\":}; id=${id%%[!0-9]*}
  case "$line" in
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"Echo"},{"name":"echo_twice","description":"Echo twice"},{"name":"rm","description":"Remove"}]}}\n' "$id" ;;
    *'"name":"hang"'*)
      echo got >> '@MARKS@/@ID@.unanswered' ;;
    *'"method":"tools/call"'*)
      echo called >> '@MARKS@/@ID@.calls'
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"pong from @ID@"}]}}\n' "$id" ;;
    *)
      printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
  esac
done
"#;

    /// Write the operator server file of the stdio server `id`: `/bin/bash <script>`, with
    /// `extra` run first by the script and `tail` appended to the file (more keys).
    fn stdio_server(home: &Home, id: &str, extra: &str, tail: &str) {
        let script = home.marks.join(format!("{id}.sh"));
        std::fs::write(
            &script,
            SERVER_SCRIPT
                .replace("@EXTRA@", extra)
                .replace("@MARKS@", home.marks.to_str().unwrap())
                .replace("@ID@", id),
        )
        .unwrap();
        server_file(
            home,
            id,
            &format!(
                "server-id: {id}\ndescription: {id} tools\ntransport:\n  kind: stdio\n  \
                 command: /bin/bash\n  args: [\"{}\"]\n{tail}",
                script.display()
            ),
        );
    }

    fn server_file(home: &Home, id: &str, body: &str) {
        let dir = home.root.join(".advance/mcp-servers");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.yaml")), body).unwrap();
    }

    /// The lines a server recorded in `<marks>/<name>`.
    fn marks(home: &Home, name: &str) -> Vec<String> {
        std::fs::read_to_string(home.marks.join(name))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// `kill -0 <pid>`: whether the process exists.
    fn pid_alive(pid: &str) -> bool {
        std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Poll `condition` every 20 ms until it holds or `limit` passes.
    async fn wait_until(mut condition: impl FnMut() -> bool, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        condition()
    }

    /// Wait for each of `pids` to be gone; a survivor is killed and fails the test.
    async fn assert_stopped(pids: &[&String], why: &str) {
        for pid in pids {
            let stopped = wait_until(|| !pid_alive(pid), Duration::from_secs(5)).await;
            if !stopped {
                let _ = std::process::Command::new("kill")
                    .args(["-9", pid.as_str()])
                    .status();
            }
            assert!(stopped, "process {pid} is still running: {why}");
        }
    }

    async fn boot(home: &Home) -> (RuntimeHost, WiringHandles) {
        let builder = RuntimeHostBuilder::new(&home.config, &home.root)
            .await
            .expect("builder");
        wire_capabilities(builder, &home.root).await.expect("wire")
    }

    /// The names of the host functions registered under `mcp`.
    fn registered(host: &RuntimeHost) -> BTreeSet<String> {
        host.host_registry()
            .lookup("mcp")
            .into_iter()
            .map(|spec| spec.name)
            .collect()
    }

    /// Link a guest that declares `mcp`, as the agent loop does.
    fn link_mcp(host: &RuntimeHost) -> Result<(), String> {
        let runtime = host.component_runtime();
        let mut linker =
            wasmtime::component::Linker::<ComponentCtx>::new(runtime.host_engine_handle().engine());
        host.capability_injector()
            .inject(
                &mut linker,
                &[CapRequest {
                    capability: CapabilityId::new("mcp"),
                }],
            )
            .map_err(|e| e.to_string())
    }

    /// An `mcp-error`: its arm and its message.
    type McpErr = (String, String);

    /// Start a call of the mcp-client host function `name` as `agent`, with the context the
    /// injector builds for a guest call. The future yields the call's one result, `Err`
    /// holding the `mcp-error`; it borrows nothing, so it can run on a task of its own.
    fn begin(
        host: &RuntimeHost,
        agent: &str,
        name: &str,
        params: Vec<Val>,
    ) -> impl std::future::Future<Output = Result<Val, McpErr>> + Send + 'static {
        let spec = host
            .host_registry()
            .lookup("mcp")
            .into_iter()
            .find(|spec| spec.name == name)
            .unwrap_or_else(|| panic!("mcp-client function {name} is registered"));
        let ctx = HostCallContext {
            agent_id: agent.to_string(),
            trace_id: "trace-mcp".to_string(),
            turn_id: None,
            capability: "mcp".to_string(),
            function: format!("{NAMESPACE}::{name}"),
            run_id: None,
            iteration: None,
        };
        let pending = spec.handler.call(ctx, params, 1);
        let name = name.to_string();
        async move {
            let mut out = pending.await.unwrap_or_else(|e| panic!("{name}: {e}"));
            match out.remove(0) {
                Val::Result(Ok(Some(value))) => Ok(*value),
                Val::Result(Err(Some(error))) => match *error {
                    Val::Variant(arm, Some(message)) => match *message {
                        Val::String(message) => Err((arm, message)),
                        other => panic!("{name}: error payload {other:?}"),
                    },
                    other => panic!("{name}: error {other:?}"),
                },
                other => panic!("{name}: result {other:?}"),
            }
        }
    }

    /// [`begin`] a call and wait for its result.
    async fn call(
        host: &RuntimeHost,
        agent: &str,
        name: &str,
        params: Vec<Val>,
    ) -> Result<Val, McpErr> {
        begin(host, agent, name, params).await
    }

    fn s(text: &str) -> Val {
        Val::String(text.into())
    }

    fn bytes(text: &str) -> Val {
        Val::List(text.bytes().map(Val::U8).collect())
    }

    /// The string field `name` of each record in a listing.
    fn field(listing: Val, name: &str) -> Vec<String> {
        let Val::List(records) = listing else {
            panic!("a listing is a list: {listing:?}");
        };
        records
            .into_iter()
            .map(|record| {
                let Val::Record(fields) = record else {
                    panic!("a listing holds records: {record:?}");
                };
                match fields.into_iter().find(|(key, _)| key == name) {
                    Some((_, Val::String(value))) => value,
                    other => panic!("no string field {name:?}: {other:?}"),
                }
            })
            .collect()
    }

    /// The bytes of a call result, as JSON.
    fn json_result(result: Val) -> Value {
        let Val::List(items) = result else {
            panic!("a call result is a byte list: {result:?}");
        };
        let raw: Vec<u8> = items
            .into_iter()
            .map(|item| match item {
                Val::U8(byte) => byte,
                other => panic!("a byte: {other:?}"),
            })
            .collect();
        serde_json::from_slice(&raw).expect("a call result is JSON")
    }

    async fn servers(host: &RuntimeHost, agent: &str) -> Vec<String> {
        field(
            call(host, agent, "list-mcp-servers", vec![])
                .await
                .expect("list-mcp-servers"),
            "id",
        )
    }

    async fn tools(host: &RuntimeHost, agent: &str, server: &str) -> Result<Vec<String>, McpErr> {
        call(host, agent, "list-mcp-tools", vec![s(server)])
            .await
            .map(|listing| field(listing, "name"))
    }

    async fn invoke(
        host: &RuntimeHost,
        agent: &str,
        server: &str,
        tool: &str,
    ) -> Result<Value, McpErr> {
        call(
            host,
            agent,
            "invoke-mcp-tool",
            vec![s(server), s(tool), bytes("{}")],
        )
        .await
        .map(json_result)
    }

    fn denied(result: Result<impl std::fmt::Debug, McpErr>) -> String {
        let (arm, message) = result.expect_err("refused");
        assert_eq!(arm, "permission-denied", "{message}");
        message
    }

    const SCOPED_ROOT: &str =
        "capabilities:\n  mcp:\n    servers: [srv]\n    tool-patterns: [\"echo*\"]\n";

    // The root declares `mcp` with a grant on one server and its `echo*` tools. The seven
    // host functions are registered and link; the granted tool is called, a tool outside the
    // patterns and a server outside the grant are refused before any server is touched; and
    // no server needs a secret, so the home's secret store is never opened.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_root_that_declares_mcp_calls_what_its_grant_covers() {
        let home = home(SCOPED_ROOT, NO_KEY_ENV, "");
        stdio_server(&home, "srv", "", "");
        stdio_server(&home, "other", "", "");
        let (host, handles) = boot(&home).await;
        let root = handles.root_agent_id.clone();

        assert_eq!(
            registered(&host),
            [
                "list-mcp-servers",
                "list-mcp-tools",
                "list-mcp-prompts",
                "get-mcp-prompt",
                "list-mcp-resources",
                "read-mcp-resource",
                "invoke-mcp-tool",
            ]
            .map(String::from)
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
        let specs = host.host_registry().lookup("mcp");
        assert_eq!(specs.len(), 7);
        assert!(specs
            .iter()
            .all(|spec| spec.capability == "mcp" && spec.namespace == NAMESPACE));
        link_mcp(&host).expect("a guest that declares mcp links mcp-client");

        let mcp = handles.mcp.as_ref().expect("mcp declared");
        assert!(mcp.warnings().is_empty(), "{:?}", mcp.warnings());
        let configured: Vec<String> = mcp
            .client()
            .list_servers()
            .await
            .into_iter()
            .map(|server| server.id)
            .collect();
        assert_eq!(configured, ["other", "srv"]);
        assert!(
            handles.secret_store.is_none(),
            "no server needs secrets: the secret store stays closed"
        );

        // The events of the calls below, off the production bus.
        let mut events = handles
            .observability_read_api
            .clone()
            .expect("read api")
            .subscribe(EventFilter {
                event_type_prefix: Some("mcp.".into()),
                ..Default::default()
            });

        // Listing the servers reads the grant and starts nothing.
        assert_eq!(servers(&host, &root).await, ["srv"]);
        assert!(
            marks(&home, "srv.starts").is_empty(),
            "servers start lazily"
        );

        assert_eq!(
            tools(&host, &root, "srv")
                .await
                .expect("the granted server"),
            ["echo", "echo_twice"]
        );
        let pong = invoke(&host, &root, "srv", "echo")
            .await
            .expect("a tool the grant covers");
        assert_eq!(pong["content"][0]["text"], "pong from srv");

        let message = denied(invoke(&host, &root, "srv", "rm").await);
        assert!(message.contains("\"rm\""), "{message}");
        denied(invoke(&host, &root, "other", "echo").await);
        denied(tools(&host, &root, "other").await);

        assert_eq!(marks(&home, "srv.starts").len(), 1, "one server process");
        assert_eq!(
            marks(&home, "srv.calls").len(),
            1,
            "a refused call never reaches the server"
        );
        assert!(
            marks(&home, "other.starts").is_empty(),
            "a server no grant reaches is never started"
        );

        // The connection, the call and the refusal were reported on the production bus.
        let mut seen: Vec<(String, Value)> = Vec::new();
        while seen.len() < 4 {
            match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
                Ok(ReadNext::Event(event)) => {
                    seen.push((event.event_type.clone(), event.payload.clone()))
                }
                other => panic!("mcp events are missing after {seen:?}: {other:?}"),
            }
        }
        let of = |event_type: &str| -> Vec<&Value> {
            seen.iter()
                .filter(|(name, _)| name == event_type)
                .map(|(_, payload)| payload)
                .collect()
        };
        assert_eq!(
            of("mcp.server_started"),
            [&json!({"server_id": "srv", "transport": "stdio"})]
        );
        let invoked = of("mcp.tool_invoked");
        assert_eq!(invoked.len(), 1, "{seen:?}");
        assert_eq!(invoked[0]["tool_name"], "echo");
        assert_eq!(invoked[0]["agent_id"], json!(root));
        let refused: Vec<(&Value, &Value)> = of("mcp.tool_error")
            .into_iter()
            .map(|payload| (&payload["server_id"], &payload["tool_name"]))
            .collect();
        assert_eq!(
            refused,
            [
                (&json!("srv"), &json!("rm")),
                (&json!("other"), &json!("echo"))
            ]
        );
        assert!(of("mcp.tool_error")
            .iter()
            .all(|payload| payload["error_type"] == "permission-denied"));
    }

    // The gate is asked with the id the runtime stamps on a guest's calls: the agent's
    // immutable id (the daemon gives the root's guest `root_agent_id`), which is also the id
    // its grants are stored under. A listing (the silent grant reader) and a call (the grant
    // check) read the same grants for it. No other spelling of the agent gets as far as the
    // gate, and those that name no grantee find a grant in neither.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_listing_and_a_call_read_the_same_grants_for_the_id_the_runtime_stamps() {
        let home = home(SCOPED_ROOT, NO_KEY_ENV, "");
        stdio_server(&home, "srv", "", "");
        let (host, handles) = boot(&home).await;
        let root = handles.root_agent_id.clone();
        let mailbox = handles.root_mailbox_id.clone();

        // The stamped id is the bare tree id, never the `agent:` mailbox key, and the root's
        // static `mcp` grant is stored under exactly it.
        assert!(!root.contains(':'), "{root}");
        assert_eq!(
            mailbox.strip_prefix("agent:").map(str::is_empty),
            Some(false)
        );
        assert_ne!(mailbox, root);
        let held: Vec<String> = handles
            .cap_grant
            .store
            .list_by_grantee(&root)
            .into_iter()
            .filter(|grant| grant.capability == "mcp" && grant.status == GrantStatus::Active)
            .map(|grant| grant.grantee)
            .collect();
        assert_eq!(held, [root.clone()]);
        assert!(handles.cap_grant.store.list_by_grantee(&mailbox).is_empty());

        // A guest's call reaches a handler only after the injector, with the stamped id and
        // this same grant check, has allowed `mcp`. Only the id the grant is stored under
        // passes: the mailbox key, the handle and the `agent:` spelling of the id are
        // stopped there, before any gate decision.
        let handle = mailbox.trim_start_matches("agent:").to_string();
        let colon_id = format!("agent:{root}");
        let linked = |agent: &str| {
            handles.cap_grant.grant_check.check(
                agent,
                "mcp",
                &format!("{NAMESPACE}::list-mcp-servers"),
                &CapParams::empty(),
            )
        };
        assert_eq!(linked(&root), GrantDecision::Allow);
        for other in [mailbox.as_str(), handle.as_str(), colon_id.as_str()] {
            assert!(matches!(linked(other), GrantDecision::Deny(_)), "{other}");
        }

        // For the stamped id, the listing and the call agree on every entry: the granted
        // server is listed, every tool the listing shows is callable and every tool it hides
        // is refused.
        assert_eq!(servers(&host, &root).await, ["srv"]);
        let shown = tools(&host, &root, "srv").await.expect("granted");
        assert_eq!(shown, ["echo", "echo_twice"]);
        for tool in ["echo", "echo_twice", "rm"] {
            let called = invoke(&host, &root, "srv", tool).await;
            if shown.iter().any(|name| name == tool) {
                called.unwrap_or_else(|e| panic!("{tool} is listed, so it is callable: {e:?}"));
            } else {
                denied(called);
            }
        }
        // The server's prompts and resources fall under no tool pattern, so this grant
        // reaches none of them: their listings and a read are refused alike.
        denied(call(&host, &root, "list-mcp-prompts", vec![s("srv")]).await);
        denied(call(&host, &root, "list-mcp-resources", vec![s("srv")]).await);
        denied(
            call(
                &host,
                &root,
                "read-mcp-resource",
                vec![s("srv"), s("file:///notes")],
            )
            .await,
        );

        // Under the mailbox key, or its handle, nothing is listed and nothing is callable.
        for other in [mailbox.as_str(), handle.as_str(), "agent:nobody", "nobody"] {
            assert!(servers(&host, other).await.is_empty(), "{other}");
            denied(tools(&host, other, "srv").await);
            denied(invoke(&host, other, "srv", "echo").await);
        }
        assert_eq!(marks(&home, "srv.calls").len(), 2);
    }

    // Without `mcp` in the root's config nothing MCP exists: no host function, no runtime,
    // no server process, although a server file is there and the warm-up is on.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_root_that_does_not_declare_mcp_gets_nothing_mcp() {
        let home = home(
            "capabilities:\n  fs: true\n  tools: true\n",
            NO_KEY_ENV,
            "\nmcp:\n  warm-tool-cache: true\n",
        );
        stdio_server(&home, "srv", "", "");
        // A file that would be refused is not even read.
        server_file(&home, "broken", "server-id: [unclosed\n");
        let (host, handles) = boot(&home).await;

        assert!(registered(&host).is_empty());
        assert!(handles.mcp.is_none());
        let error = link_mcp(&host).expect_err("mcp is not registered");
        assert!(error.contains("unknown capability"), "{error}");
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            !home.marks.join("srv.starts").exists(),
            "no server process is started"
        );
    }

    // `mcp` declared with no server file at all: the host functions are registered and a
    // guest links; there is simply no server.
    #[tokio::test(flavor = "multi_thread")]
    async fn mcp_without_server_files_still_links() {
        let home = home("capabilities:\n  mcp: true\n", NO_KEY_ENV, "");
        let (host, handles) = boot(&home).await;
        let root = handles.root_agent_id.clone();

        assert_eq!(registered(&host).len(), 7);
        link_mcp(&host).expect("mcp links with no server configured");
        assert!(handles.mcp.as_ref().expect("mcp").warnings().is_empty());
        assert!(servers(&host, &root).await.is_empty());
        let (arm, message) = invoke(&host, &root, "srv", "echo")
            .await
            .expect_err("no such server");
        assert_eq!(arm, "not-found", "{message}");
        assert!(
            !home.root.join(".advance/mcp-servers").exists(),
            "reading creates nothing"
        );
    }

    // Server files that cannot serve do not stop the daemon: each is skipped with a warning
    // and the good server next to them works. With `allow-stdio: false` no stdio server is
    // loaded at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bad_server_file_is_skipped_and_the_daemon_boots() {
        let home = home("capabilities:\n  mcp: true\n", NO_KEY_ENV, "");
        stdio_server(&home, "srv", "", "");
        server_file(&home, "broken", "server-id: [unclosed\n");
        server_file(
            &home,
            "renamed",
            "server-id: original\ntransport:\n  kind: stdio\n  command: /bin/true\n",
        );
        let (host, handles) = boot(&home).await;
        let root = handles.root_agent_id.clone();

        let warnings = handles.mcp.as_ref().expect("mcp").warnings().to_vec();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("\"broken.yaml\""), "{warnings:?}");
        assert!(warnings[1].contains("\"renamed.yaml\""), "{warnings:?}");
        assert_eq!(servers(&host, &root).await, ["srv"]);
        invoke(&host, &root, "srv", "echo")
            .await
            .expect("the good server serves");
        drop((host, handles));

        let no_stdio = self::home(
            "capabilities:\n  mcp: true\n",
            NO_KEY_ENV,
            "\nmcp:\n  allow-stdio: false\n",
        );
        stdio_server(&no_stdio, "srv", "", "");
        let (host, handles) = boot(&no_stdio).await;
        let warnings = handles.mcp.as_ref().expect("mcp").warnings().to_vec();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("mcp.allow-stdio: false"),
            "{warnings:?}"
        );
        assert!(servers(&host, &handles.root_agent_id).await.is_empty());
        assert_eq!(registered(&host).len(), 7);
    }

    // A stdio server that names `secret-refs` gets each secret in its environment, and is
    // what opens the daemon's secret store here: the root declares neither `secrets` nor
    // `llm`. A server whose secret is missing is skipped.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_server_that_needs_secrets_opens_the_secret_store() {
        with_master_key();
        let home = home("capabilities:\n  mcp: true\n", KEY_ENV, "");
        let storage: Arc<dyn cap_secrets::SecretStorage> = Arc::new(
            cap_secrets::FileSecretStorage::open(home.root.join(".advance/secrets.json"))
                .expect("secrets file"),
        );
        cap_secrets::SecretStore::new(zeroize::Zeroizing::new([KEY_BYTE; 32]), storage)
            .store("mcp-token", "heron-42")
            .expect("provision the secret");
        let record_token = format!(
            "printf '%s' \"$MCP_TOKEN\" > '{}/srv.token'",
            home.marks.display()
        );
        stdio_server(
            &home,
            "srv",
            &record_token,
            "secret-refs:\n  MCP_TOKEN: mcp-token\n",
        );
        stdio_server(
            &home,
            "lacking",
            "",
            "secret-refs:\n  MCP_TOKEN: absent-token\n",
        );
        let (host, handles) = boot(&home).await;
        let root = handles.root_agent_id.clone();

        assert!(handles.secret_store.is_some(), "the secret store is open");
        let warnings = handles.mcp.as_ref().expect("mcp").warnings().to_vec();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("server 'lacking' is skipped")
                && warnings[0].contains("\"absent-token\""),
            "{warnings:?}"
        );
        assert!(warnings.iter().all(|w| !w.contains("heron-42")));
        assert_eq!(servers(&host, &root).await, ["srv"]);
        invoke(&host, &root, "srv", "echo")
            .await
            .expect("srv serves");
        assert_eq!(
            std::fs::read_to_string(home.marks.join("srv.token")).unwrap(),
            "heron-42",
            "the secret is the server's MCP_TOKEN"
        );
    }

    // Shutting the MCP runtime down is what the daemon does when it stops: the stdio server
    // and the process it started are gone at once, with a call still waiting on the server,
    // and nothing starts a server again.
    #[tokio::test(flavor = "multi_thread")]
    async fn mcp_shutdown_stops_the_stdio_servers_with_a_call_in_flight() {
        let home = home("capabilities:\n  mcp: true\n", NO_KEY_ENV, "");
        stdio_server(&home, "srv", "", "");
        let (host, handles) = boot(&home).await;
        let root = handles.root_agent_id.clone();
        invoke(&host, &root, "srv", "echo")
            .await
            .expect("srv serves");
        let server = marks(&home, "srv.starts")[0].clone();
        let child = marks(&home, "srv.children")[0].clone();
        assert!(pid_alive(&server) && pid_alive(&child));

        // A call the server never answers holds its connection for the request timeout.
        let hung = tokio::spawn(begin(
            &host,
            &root,
            "invoke-mcp-tool",
            vec![s("srv"), s("hang"), bytes("{}")],
        ));
        assert!(
            wait_until(
                || !marks(&home, "srv.unanswered").is_empty(),
                Duration::from_secs(5)
            )
            .await,
            "the server read the call it will not answer"
        );

        handles.mcp.as_ref().expect("mcp").shutdown();

        let (arm, _) = tokio::time::timeout(Duration::from_secs(5), hung)
            .await
            .expect("the call ends with the shutdown, not with its timeout")
            .expect("join")
            .expect_err("its connection was closed");
        assert_eq!(arm, "transport-error");
        assert_stopped(&[&child, &server], "the MCP runtime was shut down").await;

        let (arm, message) = invoke(&host, &root, "srv", "echo")
            .await
            .expect_err("nothing is connected after a shutdown");
        assert_eq!(arm, "transport-error", "{message}");
        assert_eq!(marks(&home, "srv.starts").len(), 1);
    }

    // The runtime's last handle going away stops the servers too: a path that leaves the
    // daemon without reaching its shutdown sequence leaves no server behind.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_mcp_runtime_stops_the_stdio_servers() {
        let home = home("capabilities:\n  mcp: true\n", NO_KEY_ENV, "");
        stdio_server(&home, "srv", "", "");
        let (host, mut handles) = boot(&home).await;
        let root = handles.root_agent_id.clone();
        invoke(&host, &root, "srv", "echo")
            .await
            .expect("srv serves");
        let server = marks(&home, "srv.starts")[0].clone();
        let child = marks(&home, "srv.children")[0].clone();
        assert!(pid_alive(&server) && pid_alive(&child));

        drop(handles.mcp.take());

        assert_stopped(&[&child, &server], "the MCP runtime was dropped").await;
        assert!(invoke(&host, &root, "srv", "echo").await.is_err());
    }

    // With `warm-tool-cache: true` the daemon connects, on its own, the servers the root's
    // grant reaches and lists their tools; a server the grant does not reach stays unstarted.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_warm_up_connects_only_the_servers_the_root_grant_reaches() {
        let home = home(
            "capabilities:\n  mcp:\n    servers: [srv]\n",
            NO_KEY_ENV,
            "\nmcp:\n  warm-tool-cache: true\n",
        );
        stdio_server(&home, "srv", "", "");
        stdio_server(&home, "other", "", "");
        let (_host, handles) = boot(&home).await;
        let client = Arc::clone(handles.mcp.as_ref().expect("mcp").client());

        assert!(
            wait_until(
                || !client.cached_tools().is_empty(),
                Duration::from_secs(10)
            )
            .await,
            "the warm-up lists the granted server's tools"
        );
        let cached = client.cached_tools();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].server_id, "srv");
        let names: Vec<&str> = cached[0].tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["echo", "echo_twice", "rm"]);
        assert_eq!(marks(&home, "srv.starts").len(), 1);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            marks(&home, "other.starts").is_empty(),
            "a server no grant reaches is not warmed up"
        );
    }

    // ── An operator http server on loopback ─────────────────────────────────────────────

    /// What reached an http MCP double: the JSON-RPC method of each POST.
    #[derive(Clone, Default)]
    struct Posts(Arc<Mutex<Vec<String>>>);

    impl Posts {
        fn methods(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    /// An http MCP double: what reached it, the tools it lists, and the loopback port of a
    /// second listener it redirects the `hop` tool to.
    #[derive(Clone)]
    struct Double {
        posts: Posts,
        tools: &'static [&'static str],
        elsewhere: u16,
    }

    /// A Streamable HTTP MCP server double: `initialize` gets a session id, a notification
    /// `202`, `tools/list` the double's tools. Calling `hop` answers with a redirect to another
    /// loopback port, calling `slow` answers after fifteen seconds, any other call at once.
    async fn mcp_double(
        axum::extract::State(double): axum::extract::State<Double>,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        use axum::http::{header, StatusCode};
        use axum::response::IntoResponse;

        let message: Value = serde_json::from_slice(&body).unwrap_or_default();
        let method = message["method"].as_str().unwrap_or_default().to_string();
        double.posts.0.lock().unwrap().push(method.clone());
        let Some(id) = message.get("id").cloned() else {
            return StatusCode::ACCEPTED.into_response();
        };
        let answer = |result: Value| {
            (
                [(header::CONTENT_TYPE, "application/json")],
                json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
            )
        };
        match (method.as_str(), message["params"]["name"].as_str()) {
            ("initialize", _) => (
                [("mcp-session-id", "double-session")],
                answer(json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "double", "version": "1"},
                })),
            )
                .into_response(),
            ("tools/list", _) => {
                let tools: Vec<Value> = double
                    .tools
                    .iter()
                    .map(|name| json!({"name": name, "description": "A tool"}))
                    .collect();
                answer(json!({ "tools": tools })).into_response()
            }
            ("tools/call", Some("hop")) => (
                StatusCode::TEMPORARY_REDIRECT,
                [(
                    header::LOCATION,
                    format!("http://127.0.0.1:{}/mcp", double.elsewhere),
                )],
            )
                .into_response(),
            ("tools/call", Some("slow")) => {
                tokio::time::sleep(Duration::from_secs(15)).await;
                answer(json!({"late": true})).into_response()
            }
            _ => answer(json!({"ok": true})).into_response(),
        }
    }

    /// Serve `router` on a loopback port of its own.
    async fn serve(router: axum::Router) -> u16 {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        port
    }

    // An operator file may point an http server at loopback: the daemon reaches exactly that
    // endpoint, through the security chain (the calls are the root's http traffic). A
    // redirect to another loopback port is not followed, and the configured request timeout
    // bounds a call.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_operator_http_server_on_loopback_is_reached_on_its_port_only() {
        // A second loopback listener, which nothing may reach.
        let strays = Posts::default();
        let elsewhere = serve(axum::Router::new().fallback({
            let strays = strays.clone();
            move || {
                strays.0.lock().unwrap().push("stray".to_string());
                async { "stray" }
            }
        }))
        .await;
        let double = Double {
            posts: Posts::default(),
            tools: &["echo"],
            elsewhere,
        };
        let port = serve(
            axum::Router::new()
                .route("/mcp", axum::routing::post(mcp_double))
                .with_state(double.clone()),
        )
        .await;

        let home = home(
            "capabilities:\n  mcp: true\n",
            NO_KEY_ENV,
            "\nmcp:\n  request-timeout-sec: 3\n",
        );
        server_file(
            &home,
            "local",
            &format!(
                "server-id: local\ntransport:\n  kind: http\n  \
                 endpoint-url: http://127.0.0.1:{port}/mcp\n"
            ),
        );
        let (host, handles) = boot(&home).await;
        let root = handles.root_agent_id.clone();
        assert!(handles.mcp.as_ref().expect("mcp").warnings().is_empty());
        let mut http_events = handles
            .observability_read_api
            .clone()
            .expect("read api")
            .subscribe(EventFilter {
                event_type_prefix: Some("http.request".into()),
                ..Default::default()
            });

        assert_eq!(
            tools(&host, &root, "local").await.expect("listed"),
            ["echo"]
        );
        let result = invoke(&host, &root, "local", "echo")
            .await
            .expect("the loopback endpoint of the server file is reachable");
        assert_eq!(result["ok"], true);
        assert_eq!(
            double.posts.methods(),
            [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call"
            ]
        );

        // The traffic went through the chain: its requests are reported, the handshake as
        // the server's and the calls as the root's.
        let mut requesters = Vec::new();
        while requesters.len() < 4 {
            match tokio::time::timeout(Duration::from_secs(5), http_events.recv()).await {
                Ok(ReadNext::Event(event)) => {
                    assert_eq!(event.payload["host"], "127.0.0.1", "{:?}", event.payload);
                    requesters.push(event.agent_id.clone());
                }
                other => panic!("http.request events are missing: {other:?}"),
            }
        }
        assert_eq!(requesters, ["local", "local", root.as_str(), root.as_str()]);

        // A redirect off the endpoint, to another loopback port, is not followed.
        let refused = denied(invoke(&host, &root, "local", "hop").await);
        assert_eq!(refused, "redirect rejected");
        assert!(
            strays.methods().is_empty(),
            "nothing reached the other port"
        );

        // The request timeout of the `mcp:` block ends a call the server sits on.
        let started = Instant::now();
        let (arm, message) = invoke(&host, &root, "local", "slow")
            .await
            .expect_err("the call times out");
        assert_eq!(arm, "transport-error", "{message}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the call ended with the 3 s request timeout, not with the server's answer"
        );
    }

    // The web family tools of an http server also need the `web` grant, and in the `offline`
    // web mode no agent gets them, whatever it holds: the gate is given the web grant only
    // when the mode lets the web family out at all. A refused call never reaches the server.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_web_family_tools_follow_the_web_grant_and_the_web_mode() {
        const WITH_WEB: &str = "capabilities:\n  mcp: true\n  web: true\n";
        const WITHOUT_WEB: &str = "capabilities:\n  mcp: true\n";
        const OFFLINE: &str = "\nweb:\n  mode: offline\n";

        let double = Double {
            posts: Posts::default(),
            tools: &["echo", "web.search"],
            elsewhere: 0,
        };
        let port = serve(
            axum::Router::new()
                .route("/mcp", axum::routing::post(mcp_double))
                .with_state(double.clone()),
        )
        .await;
        let calls = || {
            double
                .posts
                .methods()
                .iter()
                .filter(|method| *method == "tools/call")
                .count()
        };

        // (agent config, runtime config tail, whether the web family is offered)
        for (agent_yaml, runtime_tail, offered) in [
            (WITH_WEB, "", true),
            (WITH_WEB, OFFLINE, false),
            (WITHOUT_WEB, "", false),
        ] {
            let case = format!("{agent_yaml:?} {runtime_tail:?}");
            let home = home(agent_yaml, NO_KEY_ENV, runtime_tail);
            server_file(
                &home,
                "local",
                &format!(
                    "server-id: local\ntransport:\n  kind: http\n  \
                     endpoint-url: http://127.0.0.1:{port}/mcp\n"
                ),
            );
            let (host, handles) = boot(&home).await;
            let root = handles.root_agent_id.clone();

            let listed = tools(&host, &root, "local").await.expect("listed");
            let before = calls();
            let called = invoke(&host, &root, "local", "web.search").await;
            if offered {
                assert_eq!(listed, ["echo", "web.search"], "{case}");
                called.unwrap_or_else(|e| panic!("{case}: web.search is offered: {e:?}"));
                assert_eq!(calls(), before + 1, "{case}");
            } else {
                assert_eq!(listed, ["echo"], "{case}");
                denied(called);
                assert_eq!(calls(), before, "{case}: a refused call reaches no server");
            }
            // The rest of the server is reached under the `mcp` grant alone.
            invoke(&host, &root, "local", "echo")
                .await
                .unwrap_or_else(|e| panic!("{case}: echo needs no web grant: {e:?}"));
        }
    }
}
