//! SYS-J-66: CLI late tools install — absent slot is `module_unavailable`;
//! `install_tools_if_real` on a real `CallableInventory` yields an ok list.
//! Also witnesses that production `run_async` calls `install_tools_if_real`.

use std::sync::Arc;

use advance_cli::client_api_adapters::install_tools_if_real;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientErrorCode, ClientRequest, ClientSession, ClientToolInventory,
    Platform, Principal, Scope,
};
use advance_shared_types::capability::ToolEntry;
use cap_tools::CallableInventory;

#[test]
fn late_install_absent_then_real_inventory() {
    let api = ClientApi::new(ClientApiConfig::default());
    api.sessions().insert(
        "tok".into(),
        ClientSession {
            session_id: "s".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );

    let missing = api.handle(ClientRequest::get("/client/tools").with_session("tok"));
    assert_eq!(
        missing.error.as_ref().map(|e| e.code.as_str()),
        Some(ClientErrorCode::ModuleUnavailable.as_str())
    );

    let inventory = Arc::new(CallableInventory::new(
        vec![ToolEntry {
            name: "echo_tool".into(),
            description: "late".into(),
            params_schema: serde_json::json!({}),
        }],
        vec![],
    ));
    install_tools_if_real(&api, Some(inventory), None);

    let ok = api.handle(ClientRequest::get("/client/tools").with_session("tok"));
    assert!(ok.error.is_none(), "{:?}", ok.error);
    let data: ClientToolInventory = serde_json::from_value(ok.data.expect("data")).unwrap();
    assert!(data.wasm.iter().any(|t| t.name == "echo_tool"));
    assert!(data.skills.is_empty());

    install_tools_if_real(&api, None, None);
}

#[test]
fn late_install_reads_bounded_skill_dir() {
    let api = ClientApi::new(ClientApiConfig::default());
    api.sessions().insert(
        "tok".into(),
        ClientSession {
            session_id: "s".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let skill_dir = tmp.path().join(".agent/skills/echo-skill");
    std::fs::create_dir_all(&skill_dir).expect("skill dir");
    std::fs::write(skill_dir.join("SKILL.md"), "# Echo\n").expect("skill md");
    std::fs::write(
        skill_dir.join(".meta.yaml"),
        "skill_id: echo-skill\nversion: 3\nprovenance: Imported\ntrust_level: Trusted\n",
    )
    .expect("meta");

    let inventory = Arc::new(CallableInventory::new(
        vec![ToolEntry {
            name: "echo_tool".into(),
            description: "late".into(),
            params_schema: serde_json::json!({}),
        }],
        vec![],
    ));
    install_tools_if_real(&api, Some(inventory), Some(tmp.path().to_path_buf()));

    let ok = api.handle(ClientRequest::get("/client/tools").with_session("tok"));
    assert!(ok.error.is_none(), "{:?}", ok.error);
    let data: ClientToolInventory = serde_json::from_value(ok.data.expect("data")).unwrap();
    assert_eq!(data.skills.len(), 1);
    assert_eq!(data.skills[0].skill_id, "echo-skill");
    assert_eq!(data.skills[0].version, 3);
    assert_eq!(data.skills[0].provenance, "imported");
    assert_eq!(data.skills[0].trust_level, "trusted");
}

#[test]
fn late_install_skips_yaml_alias_meta() {
    let api = ClientApi::new(ClientApiConfig::default());
    api.sessions().insert(
        "tok".into(),
        ClientSession {
            session_id: "s".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let skill_dir = tmp.path().join(".agent/skills/bomb-skill");
    std::fs::create_dir_all(&skill_dir).expect("skill dir");
    std::fs::write(skill_dir.join("SKILL.md"), "# Bomb\n").expect("skill md");
    std::fs::write(
        skill_dir.join(".meta.yaml"),
        "a: &a [*a]\nskill_id: bomb-skill\nversion: 1\n",
    )
    .expect("meta");

    let inventory = Arc::new(CallableInventory::new(
        vec![ToolEntry {
            name: "echo_tool".into(),
            description: "late".into(),
            params_schema: serde_json::json!({}),
        }],
        vec![],
    ));
    install_tools_if_real(&api, Some(inventory), Some(tmp.path().to_path_buf()));

    let ok = api.handle(ClientRequest::get("/client/tools").with_session("tok"));
    assert!(ok.error.is_none(), "{:?}", ok.error);
    let data: ClientToolInventory = serde_json::from_value(ok.data.expect("data")).unwrap();
    assert!(data.skills.is_empty());
}

#[cfg(unix)]
#[test]
fn late_install_skips_symlinked_skills_root() {
    let api = ClientApi::new(ClientApiConfig::default());
    api.sessions().insert(
        "tok".into(),
        ClientSession {
            session_id: "s".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let real = tmp.path().join("outside/echo-skill");
    std::fs::create_dir_all(&real).expect("outside skill");
    std::fs::write(real.join("SKILL.md"), "# Echo\n").expect("skill md");
    std::fs::write(
        real.join(".meta.yaml"),
        "skill_id: echo-skill\nversion: 1\nprovenance: Imported\ntrust_level: Trusted\n",
    )
    .expect("meta");
    std::fs::create_dir_all(tmp.path().join(".agent")).expect("agent dir");
    std::os::unix::fs::symlink(tmp.path().join("outside"), tmp.path().join(".agent/skills"))
        .expect("skills symlink");

    let inventory = Arc::new(CallableInventory::new(
        vec![ToolEntry {
            name: "echo_tool".into(),
            description: "late".into(),
            params_schema: serde_json::json!({}),
        }],
        vec![],
    ));
    install_tools_if_real(&api, Some(inventory), Some(tmp.path().to_path_buf()));

    let ok = api.handle(ClientRequest::get("/client/tools").with_session("tok"));
    assert!(ok.error.is_none(), "{:?}", ok.error);
    let data: ClientToolInventory = serde_json::from_value(ok.data.expect("data")).unwrap();
    assert!(
        data.skills.is_empty(),
        "symlinked skills root must not leak: {:?}",
        data.skills
    );
}

#[test]
fn run_async_source_calls_install_tools_if_real() {
    let start = include_str!("../src/commands/start.rs");
    assert!(
        start.contains("install_tools_if_real"),
        "production run_async must late-install tools via install_tools_if_real"
    );
    assert!(
        start.contains("wiring_handles.skills_root"),
        "production late-install must pass the CLI bounded skill root"
    );
}
