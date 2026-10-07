//! MODULE-001-T112 (d) grant check bound to the host-call context.

use std::sync::Arc;

use advance_runtime_compose::compose;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, ext_probe_core, post_msg, CapDecl, FixtureDriver, FixtureExtension,
    FixtureHome, FixtureHomeSpec,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_d_grant_check_bound_to_host_call_context() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("fixture.probe")],
        driver: FixtureDriver::Core(ext_probe_core()),
        git: true,
        providers_yaml: None,
    })
    .expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![FixtureExtension::standard().arc()],
    )
    .await
    .expect("compose");
    let root = rt.root_agent_id().to_owned();
    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(addr, "call grant:fixture.probe").await;
    let allow = format!("ok:probe:grant:fixture.probe=allow agent={root}");
    assert_eq!((status, body.as_str()), (200, allow.as_str()), "{body}");
    let (status, body) = post_msg(addr, "call grant:tools").await;
    let deny = format!("ok:probe:grant:tools=deny agent={root}");
    assert_eq!((status, body.as_str()), (200, deny.as_str()), "{body}");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
