//! MODULE-001-T112 (c) — host-function and native-tool containment, and the
//! capability, host-function and tool startup legs of T112 (e).

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime_compose::agent_config::parse_agents_config_with;
use advance_runtime_compose::effective_capabilities::MAX_EXTENSION_CAPABILITIES;
use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, ext_probe_core, minimal_core, CapDecl, FixtureBreaks, FixtureExtension,
    FixtureHome, FixtureHostFn, FixtureSpec, FixtureTool, Http, ECHO_TOOL, PROBE_CAPABILITY,
    PROBE_FUNCTION, PROBE_NAMESPACE,
};
use advance_runtime_compose::test_support::{link_guest_for_test, ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{
    compose, log_keys, CapabilityRefusal, ComposeError, ExtensionFailure, ExtensionPhase,
    HostFunctionRefusal, ToolError, ToolRefusal,
};
use serde_json::json;

#[path = "support/t112c.rs"]
mod t112c;
use t112c::{
    alive_tasks, api, events, h_c, h_c_min, h_deny, h_nodecl, h_notools, msg, subsequence,
    write_pack, POLL,
};

fn probe_fn(capability: &'static str) -> FixtureHostFn {
    FixtureHostFn {
        capability,
        namespace: PROBE_NAMESPACE,
        name: PROBE_FUNCTION,
    }
}

fn spec(
    capabilities: &'static [&'static str],
    host_functions: Vec<FixtureHostFn>,
    tools: Vec<FixtureTool>,
) -> FixtureSpec {
    FixtureSpec {
        capabilities,
        host_functions,
        tools,
    }
}

fn leaked_caps(n: usize) -> &'static [&'static str] {
    let names: Vec<&'static str> = (0..n)
        .map(|i| &*Box::leak(format!("fixture.n{i:02}").into_boxed_str()))
        .collect();
    Box::leak(names.into_boxed_slice())
}

fn has_data(body: &serde_json::Value) -> bool {
    !body.get("data").is_none_or(serde_json::Value::is_null)
}

fn error_code(body: &serde_json::Value) -> &str {
    body.pointer("/error/code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

fn error_message(body: &serde_json::Value) -> &str {
    body.pointer("/error/message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

fn wasm_names(body: &serde_json::Value) -> Vec<&str> {
    body.pointer("/data/wasm")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("name").and_then(serde_json::Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

fn names(value: Option<&Vec<String>>) -> Vec<&str> {
    value
        .map(|entries| entries.iter().map(String::as_str).collect())
        .unwrap_or_default()
}

fn capability_strings(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_effective_set_reaches_request_set_agents_root_node_and_packs() {
    let home = FixtureHome::new(h_c()).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::standard();
    let rec = ext.record();
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let phases = rec.phases();
    assert!(
        subsequence(&phases, &["capabilities", "host_functions", "tools"]),
        "{phases:?}"
    );
    let probe_rec = probe.record();
    assert_eq!(
        names(probe_rec.root_request_set.as_ref()),
        ["fs", "tools", "fixture.probe"]
    );
    let (status, body) = msg(&probe, "call a").await;
    assert_eq!((status, body.as_str()), (200, "ok:probe:a"), "{body}");

    let (addr, tok) = api(&rt);
    let created = Http::post(addr, "/client/agents")
        .session(&tok)
        .idempotency_key("k1")
        .json(json!({
            "agent_id": "probe-child",
            "template_ref": "explorer",
            "capabilities": ["fixture.probe"]
        }))
        .await;
    assert!(has_data(&created.body), "{:?}", created.body);
    assert_eq!(
        capability_strings(&created.body["data"]["capabilities"]),
        vec!["fixture.probe".to_owned()]
    );
    let updated = Http::post(addr, "/client/agents/probe-child:update")
        .session(&tok)
        .idempotency_key("k2")
        .json(json!({ "capabilities": ["fixture.probe"] }))
        .await;
    assert!(has_data(&updated.body), "{:?}", updated.body);
    assert_eq!(
        capability_strings(&updated.body["data"]["capabilities"]),
        vec!["fixture.probe".to_owned()]
    );
    let unknown = Http::post(addr, "/client/agents")
        .session(&tok)
        .idempotency_key("k3")
        .json(json!({
            "agent_id": "unknown-child",
            "template_ref": "explorer",
            "capabilities": ["fixture.unknown"]
        }))
        .await;
    assert_eq!(error_code(&unknown.body), "invalid_request");
    assert_eq!(error_message(&unknown.body), "invalid capability id");

    let yaml = std::fs::read_to_string(home.home().join(".agent/config.yaml")).expect("root yaml");
    let decls = parse_agents_config_with(
        Some(yaml.as_bytes()),
        probe_rec
            .effective_capabilities
            .as_ref()
            .expect("effective"),
    )
    .expect("parse agents");
    let child = decls
        .iter()
        .find(|decl| decl.alias == "probe-child")
        .expect("probe-child decl");
    assert_eq!(child.capabilities, vec!["fixture.probe".to_owned()]);

    let listed = Http::get(addr, "/client/agents").session(&tok).send().await;
    let agents = listed.body["data"]["agents"]
        .as_array()
        .expect("agents list");
    let root = agents
        .iter()
        .find(|agent| agent["kind"] == "root")
        .expect("root");
    let root_id = root["agent_id"].as_str().expect("root id");
    let detail = Http::get(addr, format!("/client/agents/{root_id}"))
        .session(&tok)
        .send()
        .await;
    let root_caps = capability_strings(&detail.body["data"]["capabilities"]);
    for needed in ["fs", "tools", "fixture.probe"] {
        assert!(root_caps.iter().any(|cap| cap == needed), "{root_caps:?}");
    }

    let tmp = tempfile::tempdir().expect("pack tmp");
    let probe_pack = write_pack(tmp.path(), "probe-pack", &["fixture.probe"]);
    let installed = Http::post(addr, "/client/packs:install")
        .session(&tok)
        .idempotency_key("pack-1")
        .json(json!({
            "source": probe_pack.to_str().unwrap(),
            "accepted_capabilities": ["fixture.probe"]
        }))
        .await;
    assert!(has_data(&installed.body), "{:?}", installed.body);
    assert_eq!(installed.body["data"]["name"], "probe-pack");
    let unknown_pack = write_pack(tmp.path(), "unknown-pack", &["fixture.unknown"]);
    let refused = Http::post(addr, "/client/packs:install")
        .session(&tok)
        .idempotency_key("pack-2")
        .json(json!({
            "source": unknown_pack.to_str().unwrap(),
            "accepted_capabilities": ["fixture.unknown"]
        }))
        .await;
    assert_eq!(error_code(&refused.body), "invalid_request");
    assert!(!has_data(&refused.body), "{:?}", refused.body);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_plain_composition_keeps_v0_1_26_capability_answers() {
    let home = FixtureHome::new(h_c_min()).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), vec![])
        .await
        .expect("compose");
    assert_eq!(
        names(probe.record().root_request_set.as_ref()),
        ["fs", "tools"]
    );
    let (addr, tok) = api(&rt);
    let listed = Http::get(addr, "/client/agents").session(&tok).send().await;
    let agents = listed.body["data"]["agents"]
        .as_array()
        .expect("agents list");
    let root = agents
        .iter()
        .find(|agent| agent["kind"] == "root")
        .expect("root");
    let root_id = root["agent_id"].as_str().expect("root id");
    let detail = Http::get(addr, format!("/client/agents/{root_id}"))
        .session(&tok)
        .send()
        .await;
    let root_caps = capability_strings(&detail.body["data"]["capabilities"]);
    assert!(
        !root_caps.iter().any(|cap| cap == "fixture.probe"),
        "{root_caps:?}"
    );
    let created = Http::post(addr, "/client/agents")
        .session(&tok)
        .idempotency_key("k1")
        .json(json!({
            "agent_id": "probe-child",
            "template_ref": "explorer",
            "capabilities": ["fixture.probe"]
        }))
        .await;
    assert_eq!(error_code(&created.body), "invalid_request");
    assert_eq!(error_message(&created.body), "invalid capability id");
    let tmp = tempfile::tempdir().expect("pack tmp");
    let pack = write_pack(tmp.path(), "probe-pack", &["fixture.probe"]);
    let refused = Http::post(addr, "/client/packs:install")
        .session(&tok)
        .idempotency_key("pack-1")
        .json(json!({
            "source": pack.to_str().unwrap(),
            "accepted_capabilities": ["fixture.probe"]
        }))
        .await;
    assert_eq!(error_code(&refused.body), "invalid_request");
    assert!(!has_data(&refused.body), "{:?}", refused.body);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_declared_child_survives_recompose_only_with_the_extension() {
    let home = FixtureHome::new(h_c()).expect("home");
    let probe = Arc::new(ComposeProbe::new());
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::standard().arc()],
    )
    .await
    .expect("compose");
    let (addr, tok) = api(&rt);
    let created = Http::post(addr, "/client/agents")
        .session(&tok)
        .idempotency_key("k1")
        .json(json!({
            "agent_id": "probe-child",
            "template_ref": "explorer",
            "capabilities": ["fixture.probe"]
        }))
        .await;
    assert!(has_data(&created.body), "{:?}", created.body);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;

    let probe = Arc::new(ComposeProbe::new());
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::standard().arc()],
    )
    .await
    .expect("recompose");
    let (addr, tok) = api(&rt);
    let child = Http::get(addr, "/client/agents/probe-child")
        .session(&tok)
        .send()
        .await;
    assert_eq!(
        capability_strings(&child.body["data"]["capabilities"]),
        vec!["fixture.probe".to_owned()]
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;

    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![],
    )
    .await
    .expect_err("plain compose");
    match error {
        ComposeError::Wiring(ref message)
            if message.starts_with("agent-tree config materialization failure:")
                && message.contains("fixture.probe") => {}
        other => panic!("{other:?}"),
    }
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_l0_import_links_only_for_declaring_guest() {
    let home = FixtureHome::new(h_c()).expect("home");
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::standard().arc()],
    )
    .await
    .expect("compose");
    let rec = probe.record();
    let names = link_guest_for_test(&rec, home.home(), ext_probe_core())
        .await
        .expect("declaring guest");
    assert_eq!(names, vec!["fs", "tools", "fixture.probe"]);

    let tmp = tempfile::tempdir().expect("nodecl");
    let nodecl = tmp.path().join("nodecl");
    std::fs::create_dir_all(nodecl.join(".agent")).expect("nodecl agent");
    std::fs::write(
        nodecl.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  tools: true\n",
    )
    .expect("nodecl yaml");
    let missing = link_guest_for_test(&rec, &nodecl, ext_probe_core())
        .await
        .expect_err("non-declaring guest");
    assert!(missing.contains("fixture:probe/host@0.1.0"), "{missing}");
    let minimal = link_guest_for_test(&rec, &nodecl, minimal_core())
        .await
        .expect("minimal guest");
    assert_eq!(minimal, vec!["fs", "tools"]);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;

    let home = FixtureHome::new(h_nodecl()).expect("nodecl home");
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::standard().arc()],
    )
    .await
    .expect("compose nodecl");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (status, _) = msg(&probe, "call a").await;
        if status == 503 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "root loop did not end; last status {status}"
        );
        tokio::time::sleep(POLL).await;
    }
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_l1_denied_call_refused_then_allowed_call_runs() {
    let home = FixtureHome::new(h_deny()).expect("home");
    let probe_a = Arc::new(ComposeProbe::new());
    let ext_a = FixtureExtension::standard();
    let rec_a = ext_a.record();
    let rt_a = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe_a)),
        vec![ext_a.arc()],
    )
    .await
    .expect("compose A");
    let root = rt_a.root_agent_id().to_owned();
    let (status, _) = msg(&probe_a, "call x").await;
    assert_eq!(status, 502);
    assert_eq!(
        rec_a.host_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    rt_a.shutdown().await.expect("shutdown A");
    let checked: Vec<_> = events(home.home())
        .into_iter()
        .filter(|event| event["event_type"] == "authz.checked")
        .collect();
    assert_eq!(checked.len(), 1, "{checked:?}");
    assert_eq!(checked[0]["payload"]["decision"], "denied");
    assert_eq!(checked[0]["payload"]["capability"], "fixture.probe");
    assert_eq!(
        checked[0]["payload"]["function"],
        "fixture:probe/host@0.1.0::call"
    );
    assert_eq!(checked[0]["payload"]["agent_id"], root);
    assert_gone_for_home(&probe_a, home.home(), None).await;

    home.rewrite_agent_config(&[
        CapDecl::Granted("fs"),
        CapDecl::Granted("tools"),
        CapDecl::Granted("fixture.probe"),
    ])
    .expect("rewrite");
    let probe_b = Arc::new(ComposeProbe::new());
    let ext_b = FixtureExtension::standard();
    let rec_b = ext_b.record();
    let baseline = alive_tasks();
    let rt_b = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe_b)),
        vec![ext_b.arc()],
    )
    .await
    .expect("compose B");
    let (status, body) = msg(&probe_b, "call x").await;
    assert_eq!((status, body.as_str()), (200, "ok:probe:x"), "{body}");
    assert_eq!(
        rec_b.host_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    rt_b.shutdown().await.expect("shutdown B");
    assert_gone_for_home(&probe_b, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_native_tool_registered_and_in_inventory() {
    let home = FixtureHome::new(h_c()).expect("home");
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::standard().arc()],
    )
    .await
    .expect("compose");
    let (addr, tok) = api(&rt);
    let tools = Http::get(addr, "/client/tools").session(&tok).send().await;
    assert!(
        wasm_names(&tools.body)
            .iter()
            .any(|name| *name == ECHO_TOOL),
        "{:?}",
        tools.body
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_host_function_refusals_fail_compose_typed() {
    let home = FixtureHome::new(h_c()).expect("home");
    let rows: [(
        &str,
        Vec<Arc<dyn advance_runtime_compose::ComposeExtension>>,
    ); 9] = [
        (
            "advance namespace",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(
                    &[PROBE_CAPABILITY],
                    vec![FixtureHostFn {
                        capability: PROBE_CAPABILITY,
                        namespace: "advance:runtime/agent-fs@0.1.0",
                        name: PROBE_FUNCTION,
                    }],
                    vec![],
                ))
                .arc()],
        ),
        (
            "wasi namespace",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(
                    &[PROBE_CAPABILITY],
                    vec![FixtureHostFn {
                        capability: PROBE_CAPABILITY,
                        namespace: "wasi:cli/environment@0.2.0",
                        name: PROBE_FUNCTION,
                    }],
                    vec![],
                ))
                .arc()],
        ),
        (
            "duplicate in one extension",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(
                    &[PROBE_CAPABILITY],
                    vec![probe_fn(PROBE_CAPABILITY), probe_fn(PROBE_CAPABILITY)],
                    vec![],
                ))
                .arc()],
        ),
        (
            "duplicate across extensions",
            vec![
                FixtureExtension::standard().arc(),
                FixtureExtension::new("fixture-two")
                    .with_spec(spec(
                        &["fixture-two.x"],
                        vec![probe_fn("fixture-two.x")],
                        vec![],
                    ))
                    .arc(),
            ],
        ),
        (
            "undeclared fixture.other",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(
                    &[PROBE_CAPABILITY],
                    vec![probe_fn("fixture.other")],
                    vec![],
                ))
                .arc()],
        ),
        (
            "undeclared fs",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&[PROBE_CAPABILITY], vec![probe_fn("fs")], vec![]))
                .arc()],
        ),
        (
            "capability without function",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(
                    &[PROBE_CAPABILITY, "fixture.lonely"],
                    vec![probe_fn(PROBE_CAPABILITY)],
                    vec![],
                ))
                .arc()],
        ),
        (
            "malformed namespace",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(
                    &[PROBE_CAPABILITY],
                    vec![FixtureHostFn {
                        capability: PROBE_CAPABILITY,
                        namespace: "fixture-probe",
                        name: PROBE_FUNCTION,
                    }],
                    vec![],
                ))
                .arc()],
        ),
        (
            "malformed name",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(
                    &[PROBE_CAPABILITY],
                    vec![FixtureHostFn {
                        capability: PROBE_CAPABILITY,
                        namespace: PROBE_NAMESPACE,
                        name: "Call",
                    }],
                    vec![],
                ))
                .arc()],
        ),
    ];
    let mut reserved = 0;
    let mut duplicate = 0;
    let mut undeclared = 0;
    let mut lonely = 0;
    let mut malformed = 0;
    for (name, exts) in rows {
        let probe = Arc::new(ComposeProbe::new());
        let error = compose(
            home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
            exts,
        )
        .await
        .expect_err(name);
        match &error {
            ComposeError::HostFunction {
                refusal: HostFunctionRefusal::ReservedNamespace { .. },
                ..
            } => reserved += 1,
            ComposeError::HostFunction {
                refusal:
                    HostFunctionRefusal::Duplicate {
                        owner: "fixture", ..
                    },
                ..
            } => duplicate += 1,
            ComposeError::HostFunction {
                refusal: HostFunctionRefusal::UndeclaredCapability { .. },
                ..
            } => undeclared += 1,
            ComposeError::HostFunction {
                refusal: HostFunctionRefusal::CapabilityWithoutFunction { capability },
                ..
            } if capability == "fixture.lonely" => lonely += 1,
            ComposeError::HostFunction {
                refusal: HostFunctionRefusal::Malformed { .. },
                ..
            } => malformed += 1,
            other => panic!("{name}: {other:?}"),
        }
        assert_gone_for_home(&probe, home.home(), None).await;
    }
    assert_eq!(
        (reserved, duplicate, undeclared, lonely, malformed),
        (2, 2, 2, 1, 2)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_capability_name_refusals_are_capability_collision() {
    let home = FixtureHome::new(h_c()).expect("home");
    let fifty_five = leaked_caps(MAX_EXTENSION_CAPABILITIES + 1);
    let rows: [(
        &str,
        Vec<Arc<dyn advance_runtime_compose::ComposeExtension>>,
    ); 8] = [
        (
            "colon",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&["fixture:probe"], vec![], vec![]))
                .arc()],
        ),
        (
            "known fs",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&["fs"], vec![], vec![]))
                .arc()],
        ),
        (
            "known web",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&["web"], vec![], vec![]))
                .arc()],
        ),
        (
            "known data",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&["data"], vec![], vec![]))
                .arc()],
        ),
        (
            "known mcp.servers",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&["mcp.servers"], vec![], vec![]))
                .arc()],
        ),
        (
            "other extension",
            vec![
                FixtureExtension::standard().arc(),
                FixtureExtension::new("fixture-two")
                    .with_spec(spec(&[PROBE_CAPABILITY], vec![], vec![]))
                    .arc(),
            ],
        ),
        (
            "foreign prefix",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&["fixture-two.probe"], vec![], vec![]))
                .arc()],
        ),
        (
            "too many",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(fifty_five, vec![], vec![]))
                .arc()],
        ),
    ];
    let mut malformed = 0;
    let mut known = 0;
    let mut other = 0;
    let mut foreign = 0;
    let mut too_many = 0;
    for (name, exts) in rows {
        let probe = Arc::new(ComposeProbe::new());
        let error = compose(
            home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
            exts,
        )
        .await
        .expect_err(name);
        match &error {
            ComposeError::CapabilityCollision {
                reason: CapabilityRefusal::Malformed(_),
                ..
            } => malformed += 1,
            ComposeError::CapabilityCollision {
                reason: CapabilityRefusal::Known,
                ..
            } => known += 1,
            ComposeError::CapabilityCollision {
                reason: CapabilityRefusal::OtherExtension { owner: "fixture" },
                ..
            } => other += 1,
            ComposeError::CapabilityCollision {
                reason: CapabilityRefusal::ForeignPrefix,
                ..
            } => foreign += 1,
            ComposeError::CapabilityCollision {
                reason: CapabilityRefusal::TooMany { limit },
                ..
            } if *limit == MAX_EXTENSION_CAPABILITIES => too_many += 1,
            other => panic!("{name}: {other:?}"),
        }
        assert!(
            !reserved_homes_for_test().contains(&home.home().to_path_buf()),
            "{name}: home reserved"
        );
        assert!(
            !home.home().join(".runtime/runtime.lock").exists(),
            "{name}: lock present"
        );
    }
    assert_eq!(
        (malformed, known, other, foreign, too_many),
        (1, 4, 1, 1, 1)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_without_tools_the_tools_callback_is_not_called() {
    let home = FixtureHome::new(h_notools()).expect("home");
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::standard();
    let rec = ext.record();
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let phases = rec.phases();
    assert!(phases.contains(&"capabilities"), "{phases:?}");
    assert!(phases.contains(&"host_functions"), "{phases:?}");
    assert!(!phases.contains(&"tools"), "{phases:?}");
    let probe_rec = probe.record();
    assert!(probe_rec.tool_registry.is_none());
    assert!(probe_rec.lazy_tool_registry.is_none());
    let (status, body) = msg(&probe, "call a").await;
    assert_eq!((status, body.as_str()), (200, "ok:probe:a"), "{body}");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112c_tool_refusals_fail_compose_typed() {
    let home = FixtureHome::new(h_c()).expect("home");
    let rows: [(
        &str,
        Vec<Arc<dyn advance_runtime_compose::ComposeExtension>>,
    ); 4] = [
        (
            "data",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&[], vec![], vec![FixtureTool { id: "data" }]))
                .arc()],
        ),
        (
            "skill",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&[], vec![], vec![FixtureTool { id: "skill::x" }]))
                .arc()],
        ),
        (
            "web.search",
            vec![FixtureExtension::new("fixture")
                .with_spec(spec(&[], vec![], vec![FixtureTool { id: "web.search" }]))
                .arc()],
        ),
        (
            "duplicate",
            vec![
                FixtureExtension::standard().arc(),
                FixtureExtension::new("fixture-two")
                    .with_spec(spec(&[], vec![], vec![FixtureTool { id: ECHO_TOOL }]))
                    .arc(),
            ],
        ),
    ];
    let mut reserved = 0;
    let mut duplicate = 0;
    for (name, exts) in rows {
        let probe = Arc::new(ComposeProbe::new());
        let error = compose(
            home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
            exts,
        )
        .await
        .expect_err(name);
        match &error {
            ComposeError::Tool {
                refusal: ToolRefusal::Reserved { .. },
                ..
            } => reserved += 1,
            ComposeError::Tool {
                extension: "fixture-two",
                refusal: ToolRefusal::Duplicate { .. },
            } => duplicate += 1,
            other => panic!("{name}: {other:?}"),
        }
        let rec = probe.record();
        assert!(
            rec.component_runtime.is_some(),
            "{name}: runtime not recorded"
        );
        assert!(
            rec.capability_injector.is_some(),
            "{name}: injector not recorded"
        );
        assert!(
            rec.lazy_tool_registry.is_some(),
            "{name}: lazy registry not recorded"
        );
        assert!(
            rec.component_runtime
                .as_ref()
                .is_some_and(|weak| weak.upgrade().is_none()),
            "{name}: runtime alive"
        );
        assert!(
            rec.capability_injector
                .as_ref()
                .is_some_and(|weak| weak.upgrade().is_none()),
            "{name}: injector alive"
        );
        assert!(
            rec.lazy_tool_registry
                .as_ref()
                .is_some_and(|weak| weak.upgrade().is_none()),
            "{name}: lazy registry alive"
        );
        assert!(
            rec.step_names().contains(&"holds.packs_poll"),
            "{name}: steps {:?}",
            rec.step_names()
        );
        assert_gone_for_home(&probe, home.home(), None).await;
    }
    assert_eq!((reserved, duplicate), (3, 1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112e_host_function_panic_mid_turn_is_contained_and_next_turn_runs() {
    let home = FixtureHome::new(h_c()).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::standard();
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let failed = "err:extension fixture: host function fixture:probe/host@0.1.0::call failed";
    let (status, body) = msg(&probe, "call panic").await;
    assert_eq!((status, body.as_str()), (200, failed), "{body}");
    let (status, body) = msg(&probe, "call panic-sync").await;
    assert_eq!((status, body.as_str()), (200, failed), "{body}");
    let (status, body) = msg(&probe, "call y").await;
    assert_eq!((status, body.as_str()), (200, "ok:probe:y"), "{body}");
    assert_eq!(log.count(log_keys::EXT_HOST_FUNCTION_PANICKED), 2);
    let lines: Vec<_> = log
        .lines()
        .into_iter()
        .filter(|line| line.key == log_keys::EXT_HOST_FUNCTION_PANICKED)
        .collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert!(line.text.ends_with("; answered in band"), "{}", line.text);
        assert!(
            !line.text.contains("fixture host function panic"),
            "{}",
            line.text
        );
    }
    assert_eq!(rec.host_calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;

    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::standard().arc()],
    )
    .await
    .expect("second compose");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112e_startup_panics_in_capabilities_host_functions_tools_are_typed() {
    let home = FixtureHome::new(h_c()).expect("home");
    for phase in [
        ExtensionPhase::Capabilities,
        ExtensionPhase::HostFunctions,
        ExtensionPhase::Tools,
    ] {
        let probe = Arc::new(ComposeProbe::new());
        let log = MemoryComposeLog::new();
        let error = compose(
            home.options(Arc::new(log.clone()), Arc::clone(&probe)),
            vec![FixtureExtension::standard()
                .with_breaks(FixtureBreaks {
                    panic_in: Some(phase),
                    ..FixtureBreaks::default()
                })
                .arc()],
        )
        .await
        .expect_err("panic");
        match error {
            ComposeError::Extension {
                extension: "fixture",
                phase: got,
                failure: ExtensionFailure::Panicked(ref message),
            } if got == phase
                && message.contains(&format!("fixture panic in {}", phase_label(phase))) => {}
            other => panic!("{phase:?}: {other:?}"),
        }
        assert!(
            log.lines().iter().all(|line| !line.key.starts_with("ext.")),
            "{:?}",
            log.lines()
        );
        if phase == ExtensionPhase::Capabilities {
            assert!(!reserved_homes_for_test().contains(&home.home().to_path_buf()));
            assert!(!home.home().join(".runtime/runtime.lock").exists());
        } else {
            assert_gone_for_home(&probe, home.home(), None).await;
        }
    }
    for phase in [ExtensionPhase::HostFunctions, ExtensionPhase::Tools] {
        let probe = Arc::new(ComposeProbe::new());
        let log = MemoryComposeLog::new();
        let error = compose(
            home.options(Arc::new(log.clone()), Arc::clone(&probe)),
            vec![FixtureExtension::standard()
                .with_breaks(FixtureBreaks {
                    fail_in: Some(phase),
                    ..FixtureBreaks::default()
                })
                .arc()],
        )
        .await
        .expect_err("fail");
        match error {
            ComposeError::Extension {
                extension: "fixture",
                phase: got,
                failure: ExtensionFailure::Failed(ref message),
            } if got == phase
                && message == &format!("fixture failure in {}", phase_label(phase)) => {}
            other => panic!("{phase:?}: {other:?}"),
        }
        assert!(
            log.lines().iter().all(|line| !line.key.starts_with("ext.")),
            "{:?}",
            log.lines()
        );
        assert_gone_for_home(&probe, home.home(), None).await;
    }
}

fn phase_label(phase: ExtensionPhase) -> &'static str {
    match phase {
        ExtensionPhase::Capabilities => "capabilities",
        ExtensionPhase::Inference => "inference",
        ExtensionPhase::HostFunctions => "host_functions",
        ExtensionPhase::Tools => "tools",
        ExtensionPhase::ClientFamilies => "client_families",
        _ => "unknown",
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_containment_native_tool_panic_is_contained() {
    let home = FixtureHome::new(h_c()).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::standard();
    let rec = ext.record();
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let tools = probe
        .record()
        .tool_registry
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .expect("tool registry");
    let agent = rt.root_agent_id().to_owned();
    match tools.invoke_as(&agent, ECHO_TOOL, "panic", b"{}").await {
        Err(ToolError::InvocationFailed(message))
            if message == "extension fixture: tool fixture.echo failed" => {}
        other => panic!("{other:?}"),
    }
    let lines: Vec<_> = log
        .lines()
        .into_iter()
        .filter(|line| line.key == log_keys::EXT_TOOL_PANICKED)
        .collect();
    assert_eq!(lines.len(), 1, "{:?}", log.lines());
    assert!(
        lines[0].text.ends_with("; the call failed"),
        "{}",
        lines[0].text
    );
    assert!(
        !lines[0].text.contains("fixture tool panic"),
        "{}",
        lines[0].text
    );
    let echoed = tools
        .invoke_as(&agent, ECHO_TOOL, "echo", br#"{"x":1}"#)
        .await
        .expect("echo");
    assert_eq!(echoed, br#"{"x":1}"#);
    assert_eq!(rec.tool_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    drop(tools);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
