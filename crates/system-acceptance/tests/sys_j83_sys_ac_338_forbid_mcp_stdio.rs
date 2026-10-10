//! SYS-AC-338 (MODULE-001-AC-32), the MCP stdio leg on the production compose path: an `mcp`
//! root with an operator stdio server file composes under `Forbid`, and the path that would
//! start the server — the tool-cache warm-up `compose_mcp` runs on the daemon runtime —
//! answers the typed refusal: the server never starts, the refusal is counted at
//! `SpawnSite::McpStdio`, the listing warning names it, and nothing of the composition
//! survives shutdown. Under `Allow` the same home starts the server and lists its tools (the
//! Client API tools view shows them: MODULE-020-AC-18 on an `mcp` home without `tools`), and
//! the teardown joins the background listings and stops the server's process group
//! (MODULE-001-AC-30 / T111 (6) on an `mcp` home). Own binary: the spawn counter is
//! process-global.

#![cfg(unix)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime_compose::compose;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec,
    Http, McpStdioServerMarker,
};
use advance_runtime_compose::test_support::proc_self::child_pids;
use advance_runtime_compose::test_support::{spawn_counter, ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{log_keys, ProcessPolicy};
use advance_shared_types::process_policy::SpawnSite;
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(50);

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

/// An `mcp` root (the capability granted, so the warm-up reaches every server) with the
/// marker as its one operator stdio server and the tool-cache warm-up on.
fn mcp_home(marker: &McpStdioServerMarker) -> FixtureHome {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("mcp")],
        driver: FixtureDriver::Minimal,
        git: false,
        providers_yaml: None,
    })
    .expect("home");
    home.write_mcp_stdio_server("srv", marker.command(), &[])
        .expect("server file");
    home.append_runtime_config("mcp:\n  warm-tool-cache: true\n")
        .expect("mcp config");
    home
}

async fn wait_until(what: &str, mut holds: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !holds() {
        assert!(Instant::now() < deadline, "{what} did not hold within {WAIT:?}");
        tokio::time::sleep(POLL).await;
    }
}

/// `kill -0 <pid>`: whether the process exists.
fn pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_338_j83_forbid_refuses_the_composed_mcp_stdio_server() {
    let s0 = spawn_counter::snapshot();
    let marker = McpStdioServerMarker::new().expect("marker");
    let home = mcp_home(&marker);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();

    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe))
            .with_processes(ProcessPolicy::Forbid),
        vec![],
    )
    .await
    .expect("compose an mcp home under Forbid");

    // The warm-up runs on the daemon runtime right after compose_mcp: its listing is what
    // would start the server, and the policy refuses it at the spawn site.
    wait_until("the McpStdio refusal is counted", || {
        spawn_counter::snapshot().since(&s0).refused(SpawnSite::McpStdio) >= 1
    })
    .await;
    wait_until("the listing warning names the refusal", || {
        log.lines().iter().any(|line| {
            line.key == log_keys::MCP_LISTING_FAILED && line.text.contains("process_forbidden")
        })
    })
    .await;
    let delta = spawn_counter::snapshot().since(&s0);
    assert_eq!(delta.admitted_total(), 0, "{delta:?}");
    assert!(!marker.ran(), "the stdio server ran under Forbid");
    assert_eq!(marker.pids(), Vec::<u32>::new());
    if let Some(pids) = child_pids() {
        assert_eq!(pids, Vec::<u32>::new());
    }

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    assert!(!marker.ran(), "the stdio server ran during shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_t111_6_mcp_listings_are_joined_and_the_server_group_stopped() {
    let s0 = spawn_counter::snapshot();
    let marker = McpStdioServerMarker::new().expect("marker");
    let home = mcp_home(&marker);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();

    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![],
    )
    .await
    .expect("compose an mcp home under Allow");

    // The warm-up starts the server and lists its tools.
    wait_until("the warm-up listed the server's tools", || {
        marker.listings() >= 1
    })
    .await;
    let delta = spawn_counter::snapshot().since(&s0);
    assert!(delta.admitted(SpawnSite::McpStdio) >= 1, "{delta:?}");
    assert_eq!(delta.refused_total(), 0, "{delta:?}");
    let pids = marker.pids();
    assert_eq!(pids.len(), 2, "server and sleep pids: {pids:?}");
    assert!(pids.iter().all(|pid| pid_alive(*pid)), "{pids:?}");

    // The listing filled the tool cache; the Client API tools view of this `mcp` home (no
    // `tools` declared) shows the server's tool as the model sees it.
    let ep = rt.client_api().expect("client api");
    let token = mint_session(&ep);
    let addr = ep.socket_addr;
    let deadline = Instant::now() + WAIT;
    let mcp_tools = loop {
        let resp = Http::get(addr, "/client/tools").session(&token).send().await;
        assert_eq!(resp.status, 200, "{:?}", resp.body);
        let tools = resp
            .body
            .pointer("/data/mcp")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !tools.is_empty() {
            break tools;
        }
        assert!(
            Instant::now() < deadline,
            "the tools view never showed the mcp tool: {:?}",
            resp.body
        );
        tokio::time::sleep(POLL).await;
    };
    let names: Vec<&str> = mcp_tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(names, vec!["srv__echo"], "{mcp_tools:?}");

    rt.shutdown().await.expect("shutdown");
    // The teardown awaited the background listings (the composition's tasks are back to the
    // baseline) and stopped the server's process group, the `sleep` it started included.
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    wait_until("the server's process group is stopped", || {
        pids.iter().all(|pid| !pid_alive(*pid))
    })
    .await;
    if let Some(children) = child_pids() {
        assert_eq!(children, Vec::<u32>::new());
    }
}
