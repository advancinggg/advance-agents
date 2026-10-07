//! MODULE-001-T112 callback-order binary. It starts with the client-families
//! pre-bind witness; the remaining order legs follow.

use std::sync::Arc;

use advance_runtime_compose::compose;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, CapDecl, FixtureDriver, FixtureExtension, FixtureFamilies, FixtureHome,
    FixtureHomeSpec, FIXTURE_ID, FIXTURE_TWO_ID,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_a_client_families_runs_before_bind() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let fixture = FixtureExtension::new(FIXTURE_ID).with_families(FixtureFamilies::standard());
    let rec = fixture.record();
    let two = FixtureExtension::new(FIXTURE_TWO_ID)
        .with_families(FixtureFamilies::standard_with_label(FIXTURE_TWO_ID))
        .sharing(&rec);
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![fixture.arc(), two.arc()],
    )
    .await
    .expect("compose");

    let family_calls: Vec<_> = rec
        .calls()
        .into_iter()
        .filter(|call| call.phase == "client_families")
        .collect();
    assert_eq!(
        family_calls
            .iter()
            .map(|call| call.extension)
            .collect::<Vec<_>>(),
        [FIXTURE_ID, FIXTURE_TWO_ID]
    );
    assert!(
        family_calls.iter().all(|call| !call.discovery_present),
        "{family_calls:?}"
    );
    assert!(home.home().join(".runtime/client-api").exists());

    let ep = rt.client_api().expect("client api");
    {
        let api = ep.api.upgrade().expect("client api alive");
        let table = api.route_table();
        assert!(
            table
                .iter()
                .any(|row| row.path == "/client/fixture/status" && !row.templated),
            "{table:?}"
        );
        assert!(
            table
                .iter()
                .any(|row| row.path == "/client/fixture-two/status" && !row.templated),
            "{table:?}"
        );
        let stats = api.extension_budget_stats();
        assert_eq!(stats.len(), 2, "{stats:?}");
        assert_eq!(stats[0].extension, FIXTURE_ID);
        assert_eq!(stats[0].labels, vec!["fixture".to_owned()]);
        assert_eq!(stats[1].extension, FIXTURE_TWO_ID);
        assert_eq!(stats[1].labels, vec!["fixture-two".to_owned()]);
    }
    drop(ep);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
