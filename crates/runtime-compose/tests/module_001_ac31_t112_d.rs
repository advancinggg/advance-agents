//! MODULE-001-T112 (d) — registrar-free ComposeCx / StartedCx lifecycle witnesses.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_event_bus::read_api::EventFilter;
use advance_runtime_compose::extension::{SecretNeedRule, SECRET_NEED_RULE};
use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, FixtureInference, StubInferencePort,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, post_msg, CapDecl, FixtureDriver, FixtureExtension,
    FixtureFamilies, FixtureHome, FixtureHomeSpec, FixtureLifecycle, Http, OnStartedMode,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{
    compose, log_keys, ComposeError, ComposeProfile, EmitError, ExtensionFailure, ExtensionPhase,
    ProcessPolicy, RuntimePhase, TaskRunStatus, ViewError,
};
use advance_shared_types::security_validator::{ScanContext, ScanResult};
use chrono::Utc;
use secrecy::ExposeSecret;
use serde_json::{json, Value};

#[path = "support/t112b.rs"]
mod t112b;

const POLL: Duration = Duration::from_millis(10);

fn fs_spec(driver: FixtureDriver) -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs")],
        driver,
        git: true,
        providers_yaml: None,
    }
}

fn llm_spec(driver: FixtureDriver) -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver,
        git: true,
        providers_yaml: None,
    }
}

fn secrets_spec() -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("secrets")],
        driver: FixtureDriver::None,
        git: true,
        providers_yaml: None,
    }
}

fn inline_one_provider() -> &'static str {
    r#"llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
"#
}

async fn poll_until(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_d1_emitter_stamps_ext_event_and_refuses_oss_types() {
    let home = FixtureHome::new(fs_spec(FixtureDriver::Minimal)).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::new("fixture");
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    let t0_ms = Utc::now().timestamp_millis();
    let receipt = snap
        .cx
        .emitter()
        .emit("ext.fixture.ping", json!({"n": 1}))
        .expect("emit");
    let t1_ms = Utc::now().timestamp_millis();
    assert_eq!(receipt.source, "ext.fixture");
    assert!(matches!(
        snap.cx.emitter().emit("run.completed", json!({})),
        Err(EmitError::ForeignType { .. })
    ));
    assert!(matches!(
        snap.cx.emitter().emit("llm.response", json!({})),
        Err(EmitError::ForeignType { .. })
    ));
    assert!(matches!(
        snap.cx.emitter().emit("ext.fixture-two.ping", json!({})),
        Err(EmitError::ForeignType { .. })
    ));
    assert!(matches!(
        snap.cx.emitter().emit("ext.fixture.", json!({})),
        Err(EmitError::InvalidType { .. })
    ));
    assert!(matches!(
        snap.cx.emitter().emit("ext.fixture.Ping", json!({})),
        Err(EmitError::InvalidType { .. })
    ));
    let too_big = json!("x".repeat(70 * 1024));
    match snap.cx.emitter().emit("ext.fixture.ping", too_big) {
        Err(EmitError::TooLarge {
            field: "payload", ..
        }) => {}
        other => panic!("{other:?}"),
    }

    let bus = probe
        .record()
        .event_bus
        .expect("event bus")
        .upgrade()
        .expect("event bus alive");
    let api = bus.read_api().expect("read api");
    drop(bus);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut rows;
    loop {
        rows = api
            .query(
                &EventFilter {
                    event_type_prefix: Some("ext.fixture.".into()),
                    ..EventFilter::default()
                },
                10,
            )
            .await
            .expect("query");
        if rows.len() == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ext.fixture event was not persisted"
        );
        tokio::time::sleep(POLL).await;
    }
    assert_eq!(rows[0].event.id, receipt.event_id);
    assert_eq!(rows[0].event.agent_id, "ext.fixture");
    let ms = rows[0].event.timestamp.timestamp_millis();
    assert!(t0_ms <= ms && ms <= t1_ms, "t0={t0_ms} ms={ms} t1={t1_ms}");
    assert_eq!(rows[0].event.timestamp, receipt.timestamp);
    assert!(rows[0].event.run_id.is_none());
    assert!(rows[0].event.task_id.is_none());
    assert_eq!(rows[0].event.trace_id, "");
    let by_agent = api
        .query(
            &EventFilter {
                agent_id: Some("ext.fixture".into()),
                ..EventFilter::default()
            },
            10,
        )
        .await
        .expect("query by agent");
    assert_eq!(by_agent.len(), 1);
    assert_eq!(by_agent[0].event.id, receipt.event_id);
    drop(api);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_d2_run_view_reads_runs_and_has_no_controls() {
    let home = FixtureHome::new(fs_spec(FixtureDriver::Minimal)).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::new("fixture");
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    let root = rt.root_agent_id().to_owned();
    let mut runs = Vec::new();
    assert!(
        poll_until(Duration::from_secs(2), || {
            runs = snap.cx.runs().runs().expect("runs");
            !runs.is_empty()
        })
        .await,
        "session run was not minted"
    );
    assert_eq!(runs[0].controller_agent, root);
    let same = snap
        .cx
        .runs()
        .run(&runs[0].run_id)
        .expect("run")
        .expect("found");
    assert_eq!(same, runs[0]);
    assert_eq!(snap.cx.runs().run("missing").expect("missing"), None);
    scan_no_run_controls();
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

fn scan_no_run_controls() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![root.join("api/extension_cx.rs")];
    for entry in std::fs::read_dir(root.join("extension")).expect("extension dir") {
        let path = entry.expect("dirent").path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read");
        for name in [
            "pause_run",
            "cancel_run",
            "resume_run",
            "complete_run",
            "fail_run",
            "suspend_run",
            "cancel_run_for_agent",
        ] {
            assert!(
                !text.contains(name),
                "{} names a run-control method {name}",
                path.display()
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_d3_secret_view_opens_only_own_namespace() {
    let home = FixtureHome::new(secrets_spec()).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::new("fixture").needing_secret_store();
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    let secrets = snap.cx.secrets().expect("secrets view");
    secrets.store("ext/fixture/k", "v1").expect("store");
    assert_eq!(
        secrets
            .resolve("ext/fixture/k")
            .expect("resolve")
            .expose_secret(),
        "v1"
    );
    assert!(matches!(
        secrets.store("ext/fixture-two/k", "x"),
        Err(advance_runtime_compose::SecretViewError::OutsideNamespace { .. })
    ));
    assert!(matches!(
        secrets.resolve("llm/openai"),
        Err(advance_runtime_compose::SecretViewError::OutsideNamespace { .. })
    ));
    assert!(matches!(
        secrets.exists("other"),
        Err(advance_runtime_compose::SecretViewError::OutsideNamespace { .. })
    ));
    assert!(matches!(
        secrets.store("ext/fixture/../k", "x"),
        Err(advance_runtime_compose::SecretViewError::InvalidName { .. })
    ));
    assert_eq!(secrets.names().expect("names"), vec!["ext/fixture/k"]);
    let json =
        std::fs::read_to_string(home.home().join(".advance/secrets.json")).expect("secrets.json");
    assert!(json.contains("ext/fixture/k"), "{json}");
    assert!(!json.contains("ext/fixture-two/k"), "{json}");
    assert!(!json.contains("llm/openai"), "{json}");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_d4_undeclared_fixture_gets_no_secret_store() {
    let home = FixtureHome::new(secrets_spec()).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::new("fixture");
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    assert!(snap.cx.secrets().is_none());
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_d_secret_need_on_storeless_home_follows_rule() {
    #[allow(unreachable_patterns)]
    match SECRET_NEED_RULE {
        SecretNeedRule::BuildOnNeed => {
            let home = FixtureHome::new(fs_spec(FixtureDriver::None)).expect("home");
            let log = MemoryComposeLog::new();
            let probe = Arc::new(ComposeProbe::new());
            let ext = FixtureExtension::new("fixture").needing_secret_store();
            let rec = ext.record();
            let rt = compose(
                home.options(Arc::new(log), Arc::clone(&probe)),
                vec![ext.arc()],
            )
            .await
            .expect("compose");
            let snap = rec
                .started(Duration::from_secs(2))
                .await
                .expect("on_started");
            let secrets = snap.cx.secrets().expect("extension store");
            secrets.store("ext/fixture/k", "v1").expect("store");
            let json = std::fs::read_to_string(home.home().join(".advance/secrets.json"))
                .expect("secrets.json");
            assert!(json.contains("ext/fixture/k"), "{json}");
            let ep = rt.client_api().expect("client api");
            let tok = mint_session(&ep);
            let with_ext = Http::get(ep.socket_addr, "/client/providers")
                .session(tok)
                .send()
                .await;
            rt.shutdown().await.expect("shutdown");
            assert_gone_for_home(&probe, home.home(), None).await;

            let control = FixtureHome::new(fs_spec(FixtureDriver::None)).expect("control");
            let clog = MemoryComposeLog::new();
            let cprobe = Arc::new(ComposeProbe::new());
            let crt = compose(
                control.options(Arc::new(clog), Arc::clone(&cprobe)),
                Vec::new(),
            )
            .await
            .expect("control compose");
            let cep = crt.client_api().expect("control client api");
            let ctok = mint_session(&cep);
            let without = Http::get(cep.socket_addr, "/client/providers")
                .session(ctok)
                .send()
                .await;
            crt.shutdown().await.expect("control shutdown");
            assert_eq!(with_ext.status, without.status);
            assert_eq!(
                with_ext.body.pointer("/error/code"),
                without.body.pointer("/error/code")
            );
            assert_gone_for_home(&cprobe, control.home(), None).await;
        }
        SecretNeedRule::NoView => {
            let home = FixtureHome::new(fs_spec(FixtureDriver::None)).expect("home");
            let log = MemoryComposeLog::new();
            let probe = Arc::new(ComposeProbe::new());
            let ext = FixtureExtension::new("fixture").needing_secret_store();
            let rec = ext.record();
            let rt = compose(
                home.options(Arc::new(log), Arc::clone(&probe)),
                vec![ext.arc()],
            )
            .await
            .expect("compose");
            let snap = rec
                .started(Duration::from_secs(2))
                .await
                .expect("on_started");
            assert!(snap.cx.secrets().is_none());
            assert!(!home.home().join(".advance/secrets.json").exists());
            rt.shutdown().await.expect("shutdown");
            assert_gone_for_home(&probe, home.home(), None).await;
        }
        SecretNeedRule::FailCompose => {
            let home = FixtureHome::new(fs_spec(FixtureDriver::None)).expect("home");
            let log = MemoryComposeLog::new();
            let probe = Arc::new(ComposeProbe::new());
            let error = compose(
                home.options(Arc::new(log), Arc::clone(&probe)),
                vec![FixtureExtension::new("fixture")
                    .needing_secret_store()
                    .arc()],
            )
            .await
            .expect_err("fail compose");
            match error {
                ComposeError::Extension {
                    extension: "fixture",
                    phase: ExtensionPhase::Capabilities,
                    failure: ExtensionFailure::Failed(ref message),
                } if message
                    == "needs a secret store, but the home declares neither `secrets` nor `llm`" => {}
                other => panic!("{other:?}"),
            }
            assert_gone_for_home(&probe, home.home(), None).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_d5_on_started_failure_and_panic_marked_failed_runtime_stays_up() {
    let home = FixtureHome::new(fs_spec(FixtureDriver::Minimal)).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let fail = FixtureExtension::new("fixture").with_lifecycle(FixtureLifecycle {
        on_started: OnStartedMode::Fail,
        ..FixtureLifecycle::default()
    });
    let panic = FixtureExtension::new("fixture-two").with_lifecycle(FixtureLifecycle {
        on_started: OnStartedMode::Panic,
        ..FixtureLifecycle::default()
    });
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![fail.arc(), panic.arc()],
    )
    .await
    .expect("compose");
    assert!(
        poll_until(Duration::from_secs(2), || {
            let health = rt.health();
            health.failed_extensions == ["fixture", "fixture-two"]
        })
        .await,
        "failed_extensions={:?}",
        rt.health().failed_extensions
    );
    let health = rt.health();
    assert_eq!(health.extensions[0].id, "fixture");
    assert!(matches!(
        health.extensions[0].state,
        advance_runtime_compose::ExtensionState::Failed(ExtensionFailure::Failed(ref m))
            if m == "fixture on_started failure"
    ));
    assert_eq!(health.extensions[1].id, "fixture-two");
    assert!(matches!(
        health.extensions[1].state,
        advance_runtime_compose::ExtensionState::Failed(ExtensionFailure::Panicked(ref m))
            if m.contains("fixture on_started panic")
    ));
    assert_eq!(log.count(log_keys::EXT_ON_STARTED_FAILED), 1);
    assert!(log
        .lines()
        .iter()
        .any(|line| line.key == log_keys::EXT_ON_STARTED_FAILED && line.text.contains("fixture")));
    assert_eq!(log.count(log_keys::EXT_ON_STARTED_PANICKED), 1);
    let panicked = log
        .lines()
        .into_iter()
        .find(|line| line.key == log_keys::EXT_ON_STARTED_PANICKED)
        .expect("panicked line");
    assert!(panicked.text.contains("fixture-two"), "{}", panicked.text);
    assert!(
        !panicked.text.contains("fixture on_started panic"),
        "{}",
        panicked.text
    );
    assert_eq!(health.phase, RuntimePhase::Running);
    assert!(health.agent_loop_up);
    let ep = rt.client_api().expect("client api");
    let resp = Http::get(ep.socket_addr, "/client/health").send().await;
    assert_eq!(resp.status, 200);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_d_compose_cx_accessors_reflect_the_composition() {
    let home = FixtureHome::new(fs_spec(FixtureDriver::Minimal)).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::new("fixture");
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    assert_eq!(snap.cx.home(), home.home());
    assert_eq!(snap.cx.profile(), ComposeProfile::Daemon);
    assert_eq!(snap.cx.processes(), ProcessPolicy::Allow);
    let t0_ms = Utc::now().timestamp_millis();
    let now = snap.cx.clock().now_millis() as i64;
    let t1_ms = Utc::now().timestamp_millis();
    assert!(
        t0_ms <= now && now <= t1_ms,
        "t0={t0_ms} now={now} t1={t1_ms}"
    );
    assert!(!matches!(
        snap.cx
            .leak_detector()
            .scan("key AKIAABCDEFGHIJKLMNOP", ScanContext::LogOutput),
        ScanResult::Clean
    ));
    assert!(snap.gateway.is_none());
    assert!(snap
        .cx
        .config()
        .current()
        .expect("config")
        .llm_providers
        .is_empty());
    home.rewrite_providers(inline_one_provider())
        .expect("rewrite providers");
    assert!(
        poll_until(Duration::from_secs(5), || {
            snap.cx
                .config()
                .current()
                .map(|cfg| cfg.llm_providers.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "live config did not pick up the rewritten providers"
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;

    let llm = FixtureHome::new(llm_spec(FixtureDriver::None)).expect("llm home");
    let llog = MemoryComposeLog::new();
    let lprobe = Arc::new(ComposeProbe::new());
    let lext = FixtureExtension::new("fixture");
    let lrec = lext.record();
    let lrt = compose(
        llm.options(Arc::new(llog), Arc::clone(&lprobe)),
        vec![lext.arc()],
    )
    .await
    .expect("llm compose");
    let lsnap = lrec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    let handle = lsnap.gateway.expect("gateway");
    assert!(handle.upgrade().is_some());
    lrt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&lprobe, llm.home(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_d_on_started_spawned_never_blocks_attach() {
    let home = FixtureHome::new(fs_spec(FixtureDriver::Minimal)).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::new("fixture").with_lifecycle(FixtureLifecycle {
        on_started: OnStartedMode::AwaitGate,
        ..FixtureLifecycle::default()
    });
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    assert!(home.home().join(".runtime/client-api").exists());
    let ep = rt.client_api().expect("client api");
    assert_eq!(
        Http::get(ep.socket_addr, "/client/health")
            .send()
            .await
            .status,
        200
    );
    assert!(matches!(
        rt.health().extensions[0].state,
        advance_runtime_compose::ExtensionState::Starting
    ));
    rec.release_on_started();
    assert!(
        poll_until(Duration::from_secs(2), || {
            matches!(
                rt.health().extensions[0].state,
                advance_runtime_compose::ExtensionState::Started
            )
        })
        .await,
        "state={:?}",
        rt.health().extensions[0].state
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_d_on_started_cancelled_by_shutdown_leaves_nothing() {
    let home = FixtureHome::new(fs_spec(FixtureDriver::None)).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let ext = FixtureExtension::new("fixture").with_lifecycle(FixtureLifecycle {
        on_started: OnStartedMode::AwaitGate,
        ..FixtureLifecycle::default()
    });
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let started = Instant::now();
    rt.shutdown().await.expect("shutdown");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "elapsed={elapsed:?} steps={:?} abandoned={} dropped={} returned={}",
        probe.record().step_names(),
        log.count(log_keys::EXT_TASKS_ABANDONED),
        rec.on_started_dropped
            .load(std::sync::atomic::Ordering::SeqCst),
        rec.on_started_returned
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert!(rec
        .on_started_dropped
        .load(std::sync::atomic::Ordering::SeqCst));
    assert!(!rec
        .on_started_returned
        .load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(log.count(log_keys::EXT_TASKS_ABANDONED), 0);
    assert_eq!(log.count(log_keys::EXT_ON_STARTED_FAILED), 0);
    assert_eq!(log.count(log_keys::EXT_ON_STARTED_PANICKED), 0);
    assert!(probe.record().step_names().contains(&"extensions.tasks"));
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_d_cx_views_revoked_and_hold_nothing_after_shutdown() {
    let home = FixtureHome::new(llm_spec(FixtureDriver::Minimal)).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::new("fixture");
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    rt.shutdown().await.expect("shutdown");
    assert!(matches!(
        snap.cx.emitter().emit("ext.fixture.ping", json!({})),
        Err(EmitError::ShutDown)
    ));
    assert!(matches!(snap.cx.runs().runs(), Err(ViewError::ShutDown)));
    assert!(matches!(
        snap.cx.config().current(),
        Err(ViewError::ShutDown)
    ));
    assert!(matches!(
        snap.cx.tasks().spawn(async {}),
        Err(ViewError::ShutDown)
    ));
    assert!(snap.gateway.as_ref().and_then(|g| g.upgrade()).is_none());
    assert!(
        poll_until(Duration::from_secs(2), || probe.record().alive().is_empty()).await,
        "alive={:?} while snapshot is held",
        probe.record().alive()
    );
    drop(snap);
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[test]
fn module_001_ac31_compose_cx_exposes_no_raw_ports() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/extension_cx.rs"),
    )
    .expect("read");
    let mut buf = String::new();
    let mut capturing = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("pub fn ") {
            capturing = true;
            buf.clear();
        }
        if capturing {
            buf.push_str(trimmed);
            buf.push(' ');
            if trimmed.contains('{') || trimmed.ends_with(';') {
                capturing = false;
                let sig = buf.as_str();
                for forbidden in [
                    "Arc<EventBus>",
                    "Arc<SecretStore>",
                    "Arc<RunManager>",
                    "Arc<dyn GrantCheck>",
                    "Weak<ClientApi>",
                    "ClientApiEndpoint",
                ] {
                    assert!(
                        !sig.contains(forbidden),
                        "pub fn exposes {forbidden}: {sig}"
                    );
                }
                if sig.contains("ClientApi") && !sig.contains("client_api_base") {
                    assert!(
                        sig.contains("GatewayHandle::upgrade") || !sig.contains("ClientApi"),
                        "pub fn exposes ClientApi: {sig}"
                    );
                }
                if sig.contains("Arc<cap_llm::LlmGateway>") {
                    assert!(
                        sig.contains("upgrade"),
                        "the only Arc<LlmGateway> is GatewayHandle::upgrade: {sig}"
                    );
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_no_extension_compose_is_unchanged() {
    let home = FixtureHome::new(fs_spec(FixtureDriver::None)).expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        Vec::new(),
    )
    .await
    .expect("compose");
    assert!(log.lines().iter().all(|line| !line.key.starts_with("ext.")));
    assert!(rt.health().extensions.is_empty());
    assert!(probe
        .record()
        .step_names()
        .iter()
        .all(|step| !step.starts_with("extensions.")));
    assert!(!home.home().join(".advance/secrets.json").exists());
    rt.shutdown().await.expect("shutdown");
    assert!(probe
        .record()
        .step_names()
        .iter()
        .all(|step| !step.starts_with("extensions.")));
    assert_gone_for_home(&probe, home.home(), None).await;
}

fn turn_home() -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver: FixtureDriver::LlmNoErr,
        git: false,
        providers_yaml: Some(provider_yaml::llm_providers_block(&[
            provider_yaml::LOCAL_STUB,
        ])),
    })
    .expect("turn home")
}

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn has_data(body: &Value) -> bool {
    !body.get("data").is_none_or(Value::is_null)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_d1_ext_events_absent_from_cost_ledger_after_a_turn() {
    let home = turn_home();
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let ext = FixtureExtension::new("fixture").with_inference(FixtureInference::standard(stub));
    let rec = ext.record();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    snap.cx
        .emitter()
        .emit("ext.fixture.ping", json!({"n": 1}))
        .expect("emit");
    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(addr, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let api_addr = ep.socket_addr;
    drop(ep);
    let root = rt.root_agent_id().to_owned();
    let deadline = Instant::now() + Duration::from_secs(5);
    let agents = loop {
        let resp = Http::get(api_addr, "/client/costs/agents")
            .session(&tok)
            .send()
            .await;
        assert_eq!(resp.status, 200, "{:?}", resp.body);
        let agents = resp
            .body
            .pointer("/data/agents")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !agents.is_empty() {
            break agents;
        }
        if Instant::now() >= deadline {
            panic!("cost ledger stayed empty: {:?}", resp.body);
        }
        tokio::time::sleep(POLL).await;
    };
    assert!(
        agents
            .iter()
            .any(|row| row.get("agent_id").and_then(Value::as_str) == Some(root.as_str())),
        "root agent missing from costs: {agents:?} root={root}"
    );
    assert!(
        agents
            .iter()
            .all(|row| row.get("agent_id").and_then(Value::as_str) != Some("ext.fixture")),
        "ext.fixture appeared in the cost ledger: {agents:?}"
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

/// Through the run view, read the run a turn ran under: the run the gateway stamped on
/// the turn's `llm.response`, read live (the turn's round is in it) and field for field as
/// the operator's `GET /client/runs` reads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_d2_run_view_reads_the_turn_run_as_the_operator_view() {
    let home = turn_home();
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let ext = FixtureExtension::new("fixture").with_inference(FixtureInference::standard(stub));
    let rec = ext.record();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(addr, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    let responses = t112b::wait_events(
        home.home(),
        "llm.response",
        |event| t112b::provider(event) == Some("local-stub") && t112b::run_id(event).is_some(),
        1,
        Duration::from_secs(5),
    )
    .await;
    let run = t112b::run_id(&responses[0]).expect("run_id").to_owned();
    let mut view = None;
    assert!(
        poll_until(Duration::from_secs(5), || {
            view = snap
                .cx
                .runs()
                .run(&run)
                .expect("run view")
                .filter(|info| info.iteration >= 1);
            view.is_some()
        })
        .await,
        "the run view never read the turn's round in run {run}: {:?}",
        snap.cx.runs().runs()
    );
    let view = view.expect("read");
    assert_eq!(view.run_id, run);
    assert_eq!(view.controller_agent, rt.root_agent_id());
    assert_eq!(view.status, TaskRunStatus::Active);

    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let api_addr = ep.socket_addr;
    drop(ep);
    let resp = Http::get(api_addr, "/client/runs")
        .session(&tok)
        .send()
        .await;
    assert_eq!(resp.status, 200, "{:?}", resp.body);
    let rows = resp
        .body
        .pointer("/data/runs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let row = rows
        .iter()
        .find(|row| row.get("run_id").and_then(Value::as_str) == Some(run.as_str()))
        .unwrap_or_else(|| panic!("run {run} missing from GET /client/runs: {rows:?}"));
    assert_eq!(row["task_id"], json!(view.task_id), "{row}");
    assert_eq!(
        row["controller_agent"],
        json!(view.controller_agent),
        "{row}"
    );
    assert_eq!(row["status"], "active", "{row}");
    assert_eq!(row["iteration"], json!(view.iteration), "{row}");
    assert_eq!(row["token_used"], json!(view.token_used), "{row}");
    assert_eq!(row["cost_usd"].as_f64(), Some(view.cost_usd), "{row}");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_d5_failed_extension_keeps_serving() {
    let home = turn_home();
    let stub = StubInferencePort::new("stub-pong", 7, 3);
    let ext = FixtureExtension::new("fixture")
        .with_lifecycle(FixtureLifecycle {
            on_started: OnStartedMode::Fail,
            ..FixtureLifecycle::default()
        })
        .with_families(FixtureFamilies::standard())
        .with_inference(FixtureInference::standard(stub));
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    assert!(
        poll_until(Duration::from_secs(2), || {
            rt.health().failed_extensions == ["fixture"]
        })
        .await,
        "failed_extensions={:?}",
        rt.health().failed_extensions
    );
    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let items = Http::get(ep.socket_addr, "/client/fixture/items")
        .session(&tok)
        .send()
        .await;
    assert_eq!(items.status, 200, "{:?}", items.body);
    assert!(has_data(&items.body), "{:?}", items.body);
    drop(ep);
    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(addr, "llm:hi").await;
    assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
