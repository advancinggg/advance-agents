//! MODULE-001-T112 (b) refusals, inference startup containment, and identity legs.

use std::sync::Arc;

use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, stub_profile, text_profile, DropFlag, FixtureInference, StubInferencePort,
    StubMeshDispatch,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, FixtureBreaks, FixtureExtension, FixtureHome, Http, FIXTURE_TWO_ID,
};
use advance_runtime_compose::{
    log_keys, ComposeError, ComposeExtension, ExtensionFailure, ExtensionPhase, InferenceRefusal,
    InferenceSubject, OssBinding,
};
use serde_json::json;

#[path = "support/t112b.rs"]
mod t112b;
use t112b::{api, compose_with, home, msg, restart_required_count, CREATE_LOCAL_TWO};

fn dummy_port() -> Arc<StubInferencePort> {
    StubInferencePort::new("stub-pong", 1, 1)
}

fn dummy_mesh() -> Arc<StubMeshDispatch> {
    StubMeshDispatch::new("mesh-pong")
}

fn inference_count(phases: &[&str]) -> usize {
    phases.iter().filter(|phase| **phase == "inference").count()
}

#[cfg(unix)]
fn sidecar_list(command: &std::path::Path) -> (String, [&'static str; 5]) {
    (
        provider_yaml::side(command),
        [
            provider_yaml::LOCAL_STUB_PLAIN,
            provider_yaml::LOCAL_FREE,
            provider_yaml::CLI,
            provider_yaml::CLOUD_A,
            provider_yaml::MESH_STUB,
        ],
    )
}

#[cfg(unix)]
fn providers_with_side<'a>(side: &'a str, rest: [&'a str; 5]) -> [&'a str; 6] {
    [rest[0], rest[1], side, rest[2], rest[3], rest[4]]
}

#[cfg(unix)]
async fn refused(
    home: &FixtureHome,
    exts: Vec<Arc<dyn ComposeExtension>>,
    check: impl FnOnce(&ComposeError),
    marker: &advance_runtime_compose::test_support::fixture::inference::SidecarMarker,
    hold: Option<&DropFlag>,
) {
    let (result, log, probe, baseline) = compose_with(home, exts).await;
    let error = result.expect_err("refused");
    check(&error);
    assert_eq!(log.count(log_keys::READY), 0);
    assert!(!home.home().join(".runtime/client-api").exists());
    if let Some(flag) = hold {
        assert!(flag.dropped(), "hold survived a refused compose");
    }
    assert!(!marker.ran(), "sidecar ran on a refused compose");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112b_refused_claims_profiles_and_dispatches_fail_compose_typed() {
    use advance_runtime_compose::test_support::fixture::inference::SidecarMarker;

    {
        let marker = SidecarMarker::new().expect("marker");
        let (side, rest) = sidecar_list(marker.command());
        let providers = providers_with_side(&side, rest);
        let home = home(&["fs", "llm"], &providers);
        let (result, _log, probe, baseline) = compose_with(
            &home,
            vec![FixtureExtension::new("fixture")
                .with_inference(FixtureInference::new())
                .arc()],
        )
        .await;
        let rt = result.expect("sidecar control");
        assert!(marker.ran(), "sidecar script should have run");
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }

    async fn case(
        check: impl FnOnce(&ComposeError),
        hold: Option<&DropFlag>,
        exts: Vec<Arc<dyn ComposeExtension>>,
    ) {
        let marker = SidecarMarker::new().expect("marker");
        let (side, rest) = sidecar_list(marker.command());
        let providers = providers_with_side(&side, rest);
        let home = home(&["fs", "llm"], &providers);
        refused(&home, exts, check, &marker, hold).await;
    }

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture",
                        subject: InferenceSubject::Entry(id),
                        reason: InferenceRefusal::AbsentEntry,
                    } if id == "ghost"
                ),
                "{error:?}"
            );
            assert_eq!(
                error.to_string(),
                "extension fixture: inference claim on entry \"ghost\" refused: no such entry in the home's llm-providers"
            );
        },
        None,
        vec![FixtureExtension::new("fixture")
            .with_inference(FixtureInference::new().claim("ghost", dummy_port()))
            .arc()],
    )
    .await;

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture",
                        subject: InferenceSubject::Entry(id),
                        reason: InferenceRefusal::BoundByOss(OssBinding::LocalSidecar),
                    } if id == "side"
                ),
                "{error:?}"
            );
        },
        None,
        vec![FixtureExtension::new("fixture")
            .with_inference(FixtureInference::new().claim("side", dummy_port()))
            .arc()],
    )
    .await;

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture",
                        subject: InferenceSubject::Entry(id),
                        reason: InferenceRefusal::BoundByOss(OssBinding::AgentCli),
                    } if id == "cli"
                ),
                "{error:?}"
            );
        },
        None,
        vec![FixtureExtension::new("fixture")
            .with_inference(FixtureInference::new().claim("cli", dummy_port()))
            .arc()],
    )
    .await;

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture",
                        subject: InferenceSubject::Entry(id),
                        reason: InferenceRefusal::BoundByOss(OssBinding::CloudWireAdapter),
                    } if id == "cloud-a"
                ),
                "{error:?}"
            );
        },
        None,
        vec![FixtureExtension::new("fixture")
            .with_inference(FixtureInference::new().claim("cloud-a", dummy_port()))
            .arc()],
    )
    .await;

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture",
                        subject: InferenceSubject::Entry(id),
                        reason: InferenceRefusal::MeshRemoteEntry,
                    } if id == "mesh-stub"
                ),
                "{error:?}"
            );
        },
        None,
        vec![FixtureExtension::new("fixture")
            .with_inference(FixtureInference::new().claim("mesh-stub", dummy_port()))
            .arc()],
    )
    .await;

    {
        let flag = DropFlag::default();
        case(
            |error| {
                assert!(
                    matches!(
                        error,
                        ComposeError::InferenceClaim {
                            extension: "fixture-two",
                            subject: InferenceSubject::Entry(id),
                            reason: InferenceRefusal::AlreadyClaimed { by: "fixture" },
                        } if id == "local-stub"
                    ),
                    "{error:?}"
                );
            },
            Some(&flag),
            vec![
                FixtureExtension::new("fixture")
                    .with_inference(
                        FixtureInference::new()
                            .claim("local-stub", dummy_port())
                            .hold(&flag),
                    )
                    .arc(),
                FixtureExtension::new(FIXTURE_TWO_ID)
                    .with_inference(FixtureInference::new().claim("local-stub", dummy_port()))
                    .arc(),
            ],
        )
        .await;
    }

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture",
                        subject: InferenceSubject::Entry(id),
                        reason: InferenceRefusal::AlreadyClaimed { by: "fixture" },
                    } if id == "local-stub"
                ),
                "{error:?}"
            );
        },
        None,
        vec![FixtureExtension::new("fixture")
            .with_inference(
                FixtureInference::new()
                    .claim("local-stub", dummy_port())
                    .claim("local-stub", dummy_port()),
            )
            .arc()],
    )
    .await;

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture-two",
                        subject: InferenceSubject::Profile(id),
                        reason: InferenceRefusal::DuplicateProfile { by: "fixture" },
                    } if id == "p1"
                ),
                "{error:?}"
            );
        },
        None,
        vec![
            FixtureExtension::new("fixture")
                .with_inference(FixtureInference::new().profile("p1", stub_profile()))
                .arc(),
            FixtureExtension::new(FIXTURE_TWO_ID)
                .with_inference(FixtureInference::new().profile("p1", stub_profile()))
                .arc(),
        ],
    )
    .await;

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture",
                        subject: InferenceSubject::Profile(id),
                        reason: InferenceRefusal::DuplicateProfile { by: "fixture" },
                    } if id == "p1"
                ),
                "{error:?}"
            );
        },
        None,
        vec![FixtureExtension::new("fixture")
            .with_inference(
                FixtureInference::new()
                    .profile("p1", stub_profile())
                    .profile("p1", stub_profile()),
            )
            .arc()],
    )
    .await;

    {
        let mut profile = text_profile("p2");
        profile.licence.clear();
        case(
            |error| {
                assert!(
                    matches!(
                        error,
                        ComposeError::InferenceClaim {
                            extension: "fixture",
                            subject: InferenceSubject::Profile(id),
                            reason: InferenceRefusal::InvalidProfile(message),
                        } if id == "p2" && message == "catalog profile missing licence"
                    ),
                    "{error:?}"
                );
                assert!(
                    error.to_string().ends_with(
                        "the catalog refused the profile: catalog profile missing licence"
                    ),
                    "{error}"
                );
            },
            None,
            vec![FixtureExtension::new("fixture")
                .with_inference(FixtureInference::new().profile("p2", profile))
                .arc()],
        )
        .await;
    }

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture-two",
                        subject: InferenceSubject::MeshDispatch,
                        reason: InferenceRefusal::SecondMeshDispatch { first: "fixture" },
                    }
                ),
                "{error:?}"
            );
        },
        None,
        vec![
            FixtureExtension::new("fixture")
                .with_inference(FixtureInference::new().mesh_dispatch(dummy_mesh()))
                .arc(),
            FixtureExtension::new(FIXTURE_TWO_ID)
                .with_inference(FixtureInference::new().mesh_dispatch(dummy_mesh()))
                .arc(),
        ],
    )
    .await;

    case(
        |error| {
            assert!(
                matches!(
                    error,
                    ComposeError::InferenceClaim {
                        extension: "fixture",
                        subject: InferenceSubject::MeshDispatch,
                        reason: InferenceRefusal::SecondMeshDispatch { first: "fixture" },
                    }
                ),
                "{error:?}"
            );
        },
        None,
        vec![FixtureExtension::new("fixture")
            .with_inference(
                FixtureInference::new()
                    .mesh_dispatch(dummy_mesh())
                    .mesh_dispatch(dummy_mesh()),
            )
            .arc()],
    )
    .await;

    {
        let home = home(
            &["fs", "llm"],
            &[provider_yaml::LOCAL_STUB_PLAIN, provider_yaml::CLOUD_A],
        );
        let (result, _log, probe, baseline) = compose_with(
            &home,
            vec![FixtureExtension::new("fixture")
                .with_inference(FixtureInference::new().claim("local-stub", dummy_port()))
                .arc()],
        )
        .await;
        let rt = result.expect("recovery after the refusals");
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112e_inference_callback_failure_and_panic_are_typed() {
    let providers = [provider_yaml::LOCAL_STUB_PLAIN, provider_yaml::CLOUD_A];

    {
        let home = home(&["fs", "llm"], &providers);
        let (result, _log, probe, baseline) = compose_with(
            &home,
            vec![FixtureExtension::new("fixture")
                .with_breaks(FixtureBreaks {
                    fail_in: Some(ExtensionPhase::Inference),
                    ..FixtureBreaks::default()
                })
                .arc()],
        )
        .await;
        match result.expect_err("inference failure") {
            ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::Inference,
                failure: ExtensionFailure::Failed(message),
            } if message == "fixture failure in inference" => {}
            other => panic!("{other:?}"),
        }
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }

    {
        let home = home(&["fs", "llm"], &providers);
        let (result, _log, probe, baseline) = compose_with(
            &home,
            vec![FixtureExtension::new("fixture")
                .with_breaks(FixtureBreaks {
                    panic_in: Some(ExtensionPhase::Inference),
                    ..FixtureBreaks::default()
                })
                .arc()],
        )
        .await;
        match result.expect_err("inference panic") {
            ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::Inference,
                failure: ExtensionFailure::Panicked(message),
            } if message.contains("fixture panic in inference") => {}
            other => panic!("{other:?}"),
        }
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }

    {
        let home = home(&["fs", "llm"], &providers);
        let flag = DropFlag::default();
        let (result, _log, probe, baseline) = compose_with(
            &home,
            vec![
                FixtureExtension::new("fixture")
                    .with_inference(
                        FixtureInference::new()
                            .claim("local-stub", dummy_port())
                            .hold(&flag),
                    )
                    .arc(),
                FixtureExtension::new(FIXTURE_TWO_ID)
                    .with_breaks(FixtureBreaks {
                        panic_in: Some(ExtensionPhase::Inference),
                        ..FixtureBreaks::default()
                    })
                    .arc(),
            ],
        )
        .await;
        match result.expect_err("a later panic releases the earlier hold") {
            ComposeError::Extension {
                extension: "fixture-two",
                phase: ExtensionPhase::Inference,
                failure: ExtensionFailure::Panicked(_),
            } => {}
            other => panic!("{other:?}"),
        }
        assert!(flag.dropped());
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }

    {
        let home = home(&["fs", "llm"], &providers);
        let stub = dummy_port();
        let (result, _log, probe, baseline) = compose_with(
            &home,
            vec![FixtureExtension::new("fixture")
                .with_inference(FixtureInference::new().claim("local-stub", stub.clone()))
                .arc()],
        )
        .await;
        let rt = result.expect("recovery after the failures");
        let (status, body) = msg(&probe, "llm:hi").await;
        assert_eq!((status, body.as_str()), (200, "llm-ok:stub-pong"), "{body}");
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112b_without_llm_inference_is_not_called() {
    let stub = dummy_port();
    let mesh = dummy_mesh();
    let flag = DropFlag::default();
    let home = home(
        &["fs"],
        &[
            provider_yaml::LOCAL_STUB_PLAIN,
            provider_yaml::LOCAL_FREE,
            provider_yaml::CLOUD_A,
        ],
    );
    let ext = FixtureExtension::new("fixture").with_inference(
        FixtureInference::new()
            .claim("local-stub", stub.clone())
            .profile("p1", stub_profile())
            .hold(&flag)
            .mesh_dispatch(mesh.clone()),
    );
    let rec = ext.record();
    let (result, _log, probe, baseline) = compose_with(&home, vec![ext.arc()]).await;
    let rt = result.expect("compose without llm");
    assert_eq!(inference_count(&rec.phases()), 0, "{:?}", rec.phases());
    assert_eq!(stub.calls(), 0);
    assert_eq!(mesh.calls(), 0);
    let probe_rec = probe.record();
    assert!(probe_rec.llm_gateway.is_none());
    assert!(probe_rec.vlm_catalog.is_none());
    assert!(probe_rec.gateway_catalog.is_none());
    rt.shutdown().await.expect("shutdown");
    let steps = probe.record().step_names();
    assert!(!steps.contains(&"holds.extension_holds"), "{steps:?}");
    assert!(!flag.dropped());
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112b_without_inference_contributor_admin_answers_as_v0_1_26() {
    async fn admin_identity(rt: &advance_runtime_compose::ComposedRuntime) {
        let (addr, tok) = api(rt);
        let created = Http::post(addr, "/client/providers")
            .session(&tok)
            .idempotency_key("k-c2")
            .json(serde_json::from_str(CREATE_LOCAL_TWO).expect("create body"))
            .await;
        assert!(created.body.get("data").is_some(), "{:?}", created.body);
        assert_eq!(restart_required_count(&created), 0, "{:?}", created.body);
        let updated = Http::post(addr, "/client/providers/cloud-a:update")
            .session(&tok)
            .idempotency_key("k-u1")
            .json(json!({ "backend_class": "local" }))
            .await;
        assert!(updated.body.get("data").is_some(), "{:?}", updated.body);
        assert_eq!(restart_required_count(&updated), 0, "{:?}", updated.body);
        let preflight = Http::post(addr, "/client/providers/local-free:preflight")
            .session(&tok)
            .idempotency_key("k-pf-free")
            .send()
            .await;
        assert_eq!(
            preflight.body["data"]["reason"], "unsupported-backend-class",
            "{:?}",
            preflight.body
        );
    }

    let providers = [provider_yaml::LOCAL_FREE, provider_yaml::CLOUD_A];
    {
        let home = home(&["fs", "llm"], &providers);
        let ext = FixtureExtension::new("fixture").with_inference(FixtureInference::new());
        let rec = ext.record();
        let (result, _log, probe, baseline) = compose_with(&home, vec![ext.arc()]).await;
        let rt = result.expect("compose empty contributor");
        assert_eq!(inference_count(&rec.phases()), 1, "{:?}", rec.phases());
        admin_identity(&rt).await;
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
    {
        let home = home(&["fs", "llm"], &providers);
        let (result, _log, probe, baseline) = compose_with(&home, vec![]).await;
        let rt = result.expect("compose no extensions");
        admin_identity(&rt).await;
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
}
