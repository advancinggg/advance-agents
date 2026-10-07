//! SYS-AC-338: a registration refusal fails compose typed, with no listener.

use std::sync::Arc;

use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, CapDecl, FixtureDriver, FixtureExtension, FixtureFamilies, FixtureHome,
    FixtureHomeSpec, RouteRuleBreak, FIXTURE_ID,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, log_keys, ComposeError, DuplicateOf, RouteRefusalReason};

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn home() -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home")
}

async fn refused(home: &FixtureHome, brk: RouteRuleBreak, check: impl FnOnce(&ComposeError)) {
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let error = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_families(FixtureFamilies::standard().with_break(brk))
            .arc()],
    )
    .await
    .expect_err("registration refused");
    check(&error);
    assert!(
        matches!(error, ComposeError::Registration { .. }),
        "{error:?}"
    );
    assert_eq!(log.count(log_keys::READY), 0);
    assert!(!home.home().join(".runtime/client-api").exists());
    assert!(!home.home().join(".runtime/runtime.lock").exists());
    assert!(
        probe
            .record()
            .listeners
            .iter()
            .all(|(name, _)| *name != "client_api"),
        "{:?}",
        probe.record().listeners
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_j83_sys_ac_338_registration_refusal_fails_compose_typed_with_no_listener() {
    let home = home();

    refused(
        &home,
        RouteRuleBreak::LabelStaticFloor,
        |error| match error {
            ComposeError::Registration {
                extension: "fixture",
                route,
                reason: RouteRefusalReason::ReservedLabel { label },
            } if route == "GET /client/session/x" && label == "session" => {}
            other => panic!("reserved label session: {other:?}"),
        },
    )
    .await;

    refused(&home, RouteRuleBreak::LabelLiveOss, |error| match error {
        ComposeError::Registration {
            extension: "fixture",
            route,
            reason: RouteRefusalReason::ReservedLabel { label },
        } if route == "GET /client/runs/x" && label == "runs" => {}
        other => panic!("reserved label runs: {other:?}"),
    })
    .await;

    refused(
        &home,
        RouteRuleBreak::DuplicateShapeSameExtension,
        |error| match error {
            ComposeError::Registration {
                extension: "fixture",
                route,
                reason:
                    RouteRefusalReason::DuplicateRoute {
                        shape,
                        of: DuplicateOf::Extension("fixture"),
                    },
            } if route == "GET /client/fixture/items/{id}"
                && shape == "/client/fixture/items/{}" => {}
            other => panic!("duplicate route: {other:?}"),
        },
    )
    .await;

    refused(&home, RouteRuleBreak::NoSession, |error| match error {
        ComposeError::Registration {
            extension: "fixture",
            route,
            reason: RouteRefusalReason::NoSession,
        } if route == "GET /client/fixture/x" => {}
        other => panic!("NoSession: {other:?}"),
    })
    .await;

    refused(&home, RouteRuleBreak::NoScope, |error| match error {
        ComposeError::Registration {
            extension: "fixture",
            route,
            reason: RouteRefusalReason::NoScope,
        } if route == "GET /client/fixture/x" => {}
        other => panic!("NoScope: {other:?}"),
    })
    .await;

    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_families(FixtureFamilies::standard())
            .arc()],
    )
    .await
    .expect("plain compose after refusals");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_338_j83_claim_of_oss_bound_entry_fails_typed() {
    use advance_runtime_compose::test_support::fixture::inference::{
        provider_yaml, FixtureInference, SidecarMarker, StubInferencePort,
    };
    use advance_runtime_compose::{InferenceRefusal, InferenceSubject, OssBinding};

    async fn refused(claim: &str, check: impl FnOnce(&ComposeError)) {
        let marker = SidecarMarker::new().expect("marker");
        let side = provider_yaml::side(marker.command());
        let home = FixtureHome::new(FixtureHomeSpec {
            capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
            driver: FixtureDriver::LlmNoErr,
            git: false,
            providers_yaml: Some(provider_yaml::llm_providers_block(&[
                provider_yaml::LOCAL_STUB_PLAIN,
                side.as_str(),
                provider_yaml::CLI,
                provider_yaml::CLOUD_A,
            ])),
        })
        .expect("home");
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let error = compose(
            home.options(Arc::new(log.clone()), Arc::clone(&probe)),
            vec![FixtureExtension::new(FIXTURE_ID)
                .with_inference(
                    FixtureInference::new().claim(claim, StubInferencePort::new("x", 1, 1)),
                )
                .arc()],
        )
        .await
        .expect_err("claim refused");
        check(&error);
        assert!(
            matches!(error, ComposeError::InferenceClaim { .. }),
            "{error:?}"
        );
        assert_eq!(log.count(log_keys::READY), 0);
        assert!(!home.home().join(".runtime/client-api").exists());
        assert!(!marker.ran(), "sidecar ran on a refused compose");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }

    refused("side", |error| match error {
        ComposeError::InferenceClaim {
            extension: "fixture",
            subject: InferenceSubject::Entry(id),
            reason: InferenceRefusal::BoundByOss(OssBinding::LocalSidecar),
        } if id == "side" => {}
        other => panic!("sidecar entry claim: {other:?}"),
    })
    .await;

    refused("cli", |error| match error {
        ComposeError::InferenceClaim {
            extension: "fixture",
            subject: InferenceSubject::Entry(id),
            reason: InferenceRefusal::BoundByOss(OssBinding::AgentCli),
        } if id == "cli" => {}
        other => panic!("agent-cli entry claim: {other:?}"),
    })
    .await;

    refused("cloud-a", |error| match error {
        ComposeError::InferenceClaim {
            extension: "fixture",
            subject: InferenceSubject::Entry(id),
            reason: InferenceRefusal::BoundByOss(OssBinding::CloudWireAdapter),
        } if id == "cloud-a" => {}
        other => panic!("cloud entry claim: {other:?}"),
    })
    .await;
}
