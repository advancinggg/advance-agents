//! Installed packs over the PRODUCTION wiring: boot a workspace through
//! `RuntimeHostBuilder::new` → `wire_capabilities` and drive the daemon-composed `ClientApi`.
//!
//! - a pack installed before boot is live at boot: `/client/schema` carries its aspect with
//!   the bound operations available, existing records are indexed with the aspect, its skill
//!   tool is registered and its preset is known to the grant preset registry;
//! - `POST /client/packs:install` takes effect before the response returns, and
//!   `:uninstall` takes the pack's contributions away again (no restart);
//! - an install made by ANOTHER process into the packs dir reaches the running daemon;
//! - the `data` host tool is reachable through the production tool registry with the
//!   caller's identity, and serves an agent that holds a `data` grant.
//!
//! Fixture discipline: env-var master key (never read), no network, the agenda skill's
//! `tool.wasm` is the cap-tools clock fixture (any component exporting `tool-exports` passes
//! the installer; the registered id is what the operations bind to).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use advance_cli::wiring::{wire_capabilities, WiringHandles};
use advance_client_api::entities::{ClientEntityPage, ClientSchema};
use advance_client_api::{
    ClientApi, ClientEnvelope, ClientRequest, ClientSession, Platform, Principal, Scope,
};
use advance_pack_manager::{AutoApprove, InMemoryPackRegistry, Installer};
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
    assert_eq!(report.presets, vec!["agenda-editor"]);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
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
        json!({ "source": ws.agenda_src.to_str().unwrap(), "accepted_capabilities": ["tools"] }),
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
        "/client/packs/agenda@0.1.0:uninstall",
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
async fn an_agent_holding_a_data_grant_reaches_the_data_tool_through_the_production_registry() {
    let ws = workspace();
    shell_installer(&ws)
        .install(ws.agenda_src.to_str().unwrap())
        .await
        .expect("install before boot");
    let (_host, handles) = boot(&ws).await;
    let root = handles.root_agent_id.clone();
    let tools = handles.tool_registry.clone().expect("tools declared");

    // The caller identity survives the production registry wrapper: the refusal comes from
    // the grant check, not from the anonymous path an identity-less call would take.
    let denied = tools
        .invoke_as(&root, "data", "describe", b"{}")
        .await
        .expect_err("no data grant yet");
    let msg = format!("{denied:?}");
    assert!(msg.contains("no active grant covers data"), "{msg}");

    handles
        .cap_grant
        .store
        .insert(Grant {
            id: GrantId::new("g-data-root"),
            grantee: root.clone(),
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
        .expect("grant data to the root agent");

    let described: Value = serde_json::from_slice(
        &tools
            .invoke_as(&root, "data", "describe", b"{}")
            .await
            .expect("describe with a read,write grant"),
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
