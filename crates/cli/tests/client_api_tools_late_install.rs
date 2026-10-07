//! MODULE-020-AC-18 / SYS-J-66: the tools view.
//! client-api answers `module_unavailable` for a genuinely empty tools slot (bare `ClientApi`);
//! the composition installs the bind-time view at bind (ADR 2026-10-03 D4);
//! `install_tools_if_real` replaces it when the agent loop spawns with a real inventory
//! and leaves it in place without one.

use std::sync::Arc;

use advance_cli::client_api_adapters::{install_tools_if_real, BindTimeToolsProvider};
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientErrorCode, ClientRequest, ClientSession, ClientToolInventory,
    Platform, Principal, Scope, ToolsProvider,
};
use advance_shared_types::capability::ToolEntry;
use cap_tools::CallableInventory;
use serde_json::json;

fn api_with_session() -> ClientApi {
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
    api
}

fn get_tools(api: &ClientApi) -> ClientToolInventory {
    let ok = api.handle(ClientRequest::get("/client/tools").with_session("tok"));
    assert!(ok.error.is_none(), "{:?}", ok.error);
    serde_json::from_value(ok.data.expect("data")).unwrap()
}

fn echo_inventory() -> Arc<CallableInventory> {
    Arc::new(CallableInventory::new(
        vec![ToolEntry {
            name: "echo_tool".into(),
            description: "late".into(),
            params_schema: serde_json::json!({}),
        }],
        vec![],
    ))
}

fn empty_tools_json() -> serde_json::Value {
    json!({"wasm": [], "mcp": [], "skills": []})
}

#[test]
fn module_020_ac18_bare_api_empty_tools_slot_is_module_unavailable() {
    let api = api_with_session();
    let missing = api.handle(ClientRequest::get("/client/tools").with_session("tok"));
    assert_eq!(
        missing.error.as_ref().map(|e| e.code.as_str()),
        Some(ClientErrorCode::ModuleUnavailable.as_str())
    );
}

#[test]
fn module_020_ac18_bind_time_view_then_late_install_replaces_it() {
    let api = api_with_session();
    api.install_tools_provider(Arc::new(BindTimeToolsProvider::new(None)));
    let bind_time = get_tools(&api);
    assert_eq!(
        serde_json::to_value(&bind_time).unwrap(),
        empty_tools_json()
    );

    install_tools_if_real(&api, None, "agent:root", None);
    let still = get_tools(&api);
    assert_eq!(serde_json::to_value(&still).unwrap(), empty_tools_json());

    install_tools_if_real(&api, Some(echo_inventory()), "agent:root", None);
    let data = get_tools(&api);
    assert!(data.wasm.iter().any(|t| t.name == "echo_tool"));
    assert!(data.skills.is_empty());
}

#[test]
fn module_020_ac18_late_install_reads_bounded_skill_dir() {
    let api = api_with_session();
    let tmp = tempfile::tempdir().expect("tempdir");
    let skill_dir = tmp.path().join(".agent/skills/echo-skill");
    std::fs::create_dir_all(&skill_dir).expect("skill dir");
    std::fs::write(skill_dir.join("SKILL.md"), "# Echo\n").expect("skill md");
    std::fs::write(
        skill_dir.join(".meta.yaml"),
        "skill_id: echo-skill\nversion: 3\nprovenance: Imported\ntrust_level: Trusted\n",
    )
    .expect("meta");

    let bind = BindTimeToolsProvider::new(Some(tmp.path().to_path_buf()))
        .inventory("agent:root")
        .expect("bind-time");
    assert!(bind.wasm.is_empty());
    assert!(bind.mcp.is_empty());
    assert_eq!(bind.skills.len(), 1);
    assert_eq!(bind.skills[0].skill_id, "echo-skill");
    assert_eq!(bind.skills[0].version, 3);
    assert_eq!(bind.skills[0].provenance, "imported");
    assert_eq!(bind.skills[0].trust_level, "trusted");

    install_tools_if_real(
        &api,
        Some(echo_inventory()),
        "agent:root",
        Some(tmp.path().to_path_buf()),
    );

    let ok = get_tools(&api);
    assert_eq!(ok.skills.len(), 1);
    assert_eq!(ok.skills[0].skill_id, "echo-skill");
    assert_eq!(ok.skills[0].version, 3);
    assert_eq!(ok.skills[0].provenance, "imported");
    assert_eq!(ok.skills[0].trust_level, "trusted");
}

#[test]
fn module_020_ac18_late_install_skips_yaml_alias_meta() {
    let api = api_with_session();
    let tmp = tempfile::tempdir().expect("tempdir");
    let skill_dir = tmp.path().join(".agent/skills/bomb-skill");
    std::fs::create_dir_all(&skill_dir).expect("skill dir");
    std::fs::write(skill_dir.join("SKILL.md"), "# Bomb\n").expect("skill md");
    std::fs::write(
        skill_dir.join(".meta.yaml"),
        "a: &a [*a]\nskill_id: bomb-skill\nversion: 1\n",
    )
    .expect("meta");

    let bind = BindTimeToolsProvider::new(Some(tmp.path().to_path_buf()))
        .inventory("agent:root")
        .expect("bind-time");
    assert!(bind.skills.is_empty());

    install_tools_if_real(
        &api,
        Some(echo_inventory()),
        "agent:root",
        Some(tmp.path().to_path_buf()),
    );

    let data = get_tools(&api);
    assert!(data.skills.is_empty());
}

#[cfg(unix)]
#[test]
fn module_020_ac18_late_install_skips_symlinked_skills_root() {
    let api = api_with_session();
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

    let bind = BindTimeToolsProvider::new(Some(tmp.path().to_path_buf()))
        .inventory("agent:root")
        .expect("bind-time");
    assert!(
        bind.skills.is_empty(),
        "symlinked skills root must not leak: {:?}",
        bind.skills
    );

    install_tools_if_real(
        &api,
        Some(echo_inventory()),
        "agent:root",
        Some(tmp.path().to_path_buf()),
    );

    let data = get_tools(&api);
    assert!(
        data.skills.is_empty(),
        "symlinked skills root must not leak: {:?}",
        data.skills
    );
}

#[test]
fn module_020_ac18_production_installs_the_bind_time_view_and_late_installs_tools() {
    let start = include_str!("../../runtime-compose/src/daemon/mod.rs");
    assert!(
        start.contains("install_tools_if_real"),
        "production run_async must late-install tools via install_tools_if_real"
    );
    assert!(
        start.contains("wiring_handles.skills_root"),
        "production late-install must pass the CLI bounded skill root"
    );
    let wiring = include_str!("../../runtime-compose/src/wiring.rs");
    assert_eq!(
        wiring.matches("BindTimeToolsProvider::new(").count(),
        1,
        "production bind installs exactly one bind-time tools view"
    );
    assert_eq!(
        wiring.matches("tools: Some(bind_time_tools)").count(),
        1,
        "production factory moves the bind-time view into FirstPartyClientCompose"
    );
    let factory = wiring
        .find("let factory = move |address")
        .expect("Client API factory");
    let bind = wiring
        .find("bind_local_factory(")
        .expect("bind_local_factory");
    let tools = wiring
        .find("tools: Some(bind_time_tools)")
        .expect("tools: Some(bind_time_tools)");
    assert!(
        factory < tools && tools < bind,
        "the bind-time view is built before the factory and moved into it"
    );
}
