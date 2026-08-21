//! MODULE-017 web family CLI wiring (T105-a / T105-e / INV-01 / WIRE-01).

use std::path::PathBuf;

use advance_cli::wiring::wire_capabilities;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::web_search::{WebRunMode, WEB_EXTRACT_TOOL_ID, WEB_SEARCH_TOOL_ID};
use wasmtime::component::Val;

const TOOLS_NS: &str = "advance:runtime/agent-tools@0.1.0";
const CAP_AGENT: &str = "default-agent";

fn runtime_yaml(web_block: &str) -> String {
    format!(
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
  env-var-name: ADV_WEBTEST_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
{web_block}
"#
    )
}

fn fresh_workspace(caps_yaml: &str, web_block: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml(web_block)).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), caps_yaml).unwrap();
    (dir, workspace, config_path)
}

fn tool_invoke_ctx() -> HostCallContext {
    HostCallContext {
        agent_id: CAP_AGENT.to_string(),
        trace_id: "tr-web".to_string(),
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

fn err_class(v: &Val) -> Option<String> {
    match v {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Variant(case, _) => Some(case.clone()),
            _ => None,
        },
        _ => None,
    }
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

#[tokio::test(flavor = "multi_thread")]
async fn t105_e_standard_wires_family_and_search_hits() {
    // MODULE-017-T105-e
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  tools: true\n  web: true\n", "");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let status = handles.web_status.as_ref().expect("web_status");
    assert_eq!(status.mode, WebRunMode::Standard);
    assert_eq!(status.index_cutoff, "local-kb");

    let listed = cap_tools::ToolRegistry::list(
        handles
            .tool_registry
            .as_ref()
            .expect("tool_registry")
            .as_ref(),
    )
    .await;
    assert!(listed.iter().any(|t| t.id == WEB_SEARCH_TOOL_ID));
    assert!(listed.iter().any(|t| t.id == WEB_EXTRACT_TOOL_ID));

    let spec = host
        .host_registry()
        .lookup("tools")
        .into_iter()
        .find(|s| s.namespace == TOOLS_NS && s.name == "tool-invoke")
        .expect("tool-invoke");
    let out = spec
        .handler
        .call(
            tool_invoke_ctx(),
            invoke_params(WEB_SEARCH_TOOL_ID, "search", br#"{"query":"rust"}"#),
            1,
        )
        .await
        .expect("invoke");
    let body = ok_bytes(&out[0]).expect("search ok");
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        parsed["hits"]
            .as_array()
            .map(|h| !h.is_empty())
            .unwrap_or(false),
        "standard mode search returns hits: {parsed}"
    );

    drop(host);
    drop(handles);
}

#[tokio::test(flavor = "multi_thread")]
async fn t105_a_offline_withholds_family_and_leftover_is_permission_denied() {
    // MODULE-017-T105-a
    let (_g, ws, cfg) = fresh_workspace(
        "capabilities:\n  tools: true\n  web: true\n",
        "web:\n  mode: offline\n  kb-index-cutoff: local-kb\n",
    );
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let status = handles.web_status.as_ref().expect("web_status");
    assert_eq!(status.mode, WebRunMode::Offline);
    assert_eq!(status.index_cutoff, "local-kb");

    let listed = cap_tools::ToolRegistry::list(
        handles
            .tool_registry
            .as_ref()
            .expect("tool_registry")
            .as_ref(),
    )
    .await;
    assert!(!listed.iter().any(|t| t.id == WEB_SEARCH_TOOL_ID));
    assert!(!listed.iter().any(|t| t.id == WEB_EXTRACT_TOOL_ID));

    let spec = host
        .host_registry()
        .lookup("tools")
        .into_iter()
        .find(|s| s.namespace == TOOLS_NS && s.name == "tool-invoke")
        .expect("tool-invoke");
    let out = spec
        .handler
        .call(
            tool_invoke_ctx(),
            invoke_params(WEB_SEARCH_TOOL_ID, "search", br#"{"query":"rust"}"#),
            1,
        )
        .await
        .expect("invoke");
    assert_eq!(
        err_class(&out[0]).as_deref(),
        Some("permission-denied"),
        "offline leftover invoke is grant-denied, not not-found"
    );

    drop(host);
    drop(handles);
}
