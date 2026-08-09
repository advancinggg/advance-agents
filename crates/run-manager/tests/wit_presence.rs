//! Slice C AC-12 tests (T85, T85b): wit_parser parses `agent-run`
//! interface from the host `advance.wit`; `world advance-host` does NOT
//! import or export agent-run (M001-T47 invariant).

use std::path::PathBuf;
use wit_parser::Resolve;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for tests is the crate dir (crates/run-manager);
    // climb two levels to reach the repo root.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // repo root
    p
}

/// T85 — `interface agent-run` exists in advance.wit with 7 funcs:
/// ensure-run, complete-round, complete-run, pause-run, resume-run,
/// cancel-run, run-status.
#[test]
fn t85_agent_run_interface_declares_seven_funcs() {
    let mut resolve = Resolve::default();
    let wit_path = repo_root().join("crates/runtime/wit/advance.wit");
    let (pkg_id, _files) = resolve.push_path(&wit_path).expect("push_path");

    let pkg = &resolve.packages[pkg_id];
    let iface_id = pkg
        .interfaces
        .get("agent-run")
        .copied()
        .expect("interface agent-run must exist");

    let iface = &resolve.interfaces[iface_id];
    let funcs: Vec<&str> = iface.functions.keys().map(|s| s.as_str()).collect();
    let expected = [
        "ensure-run",
        "complete-round",
        "complete-run",
        "pause-run",
        "resume-run",
        "cancel-run",
        "run-status",
    ];
    for name in expected {
        assert!(
            funcs.iter().any(|f| *f == name),
            "agent-run must declare func {:?}; got {:?}",
            name,
            funcs
        );
    }
}

/// T85b — Architectural invariant: `world advance-host` exports ONLY
/// `message-driven` + `runnable` — agent-run NOT imported or exported.
#[test]
fn t85b_advance_host_world_does_not_export_agent_run() {
    let mut resolve = Resolve::default();
    let wit_path = repo_root().join("crates/runtime/wit/advance.wit");
    let (pkg_id, _files) = resolve.push_path(&wit_path).expect("push_path");

    let pkg = &resolve.packages[pkg_id];
    let world_id = pkg
        .worlds
        .get("advance-host")
        .copied()
        .expect("world advance-host must exist");
    let world = &resolve.worlds[world_id];

    // Collect import + export interface names for agent-run.
    let mut found_agent_run = false;
    for (key, _) in world.imports.iter().chain(world.exports.iter()) {
        if let wit_parser::WorldKey::Interface(iface_id) = key {
            let iface = &resolve.interfaces[*iface_id];
            if let Some(name) = &iface.name {
                if name == "agent-run" {
                    found_agent_run = true;
                }
            }
        }
    }
    assert!(
        !found_agent_run,
        "world advance-host must NOT import or export agent-run (M001-T47 invariant)"
    );
}
