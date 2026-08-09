//! MODULE-006-AC-01 (REQ-171) — agent-messaging WIT surface (parse-presence).
//!
//! Parse-presence half of AC-01: the shipped `crates/runtime/wit/advance.wit`
//! `interface agent-messaging` declares EXACTLY `send` / `await-replies` /
//! `heartbeat` and does NOT declare `reply` / `wait-for`. `reply` is the
//! runtime-trait `MailboxDispatcher::reply` action surface (behaviour covered
//! by the PASSED AC-06/AC-07), NOT a guest WIT method — so the reworded §1.5
//! criterion drops it from the WIT enumeration (a mis-spec fix, not a
//! weakening). The CALLABILITY half of AC-01 is the passing e2e
//! SYS-AC-014/018/251 (`system-acceptance/tests/sys_j05_await_park_e2e.rs`),
//! where a real guest calls `send` + `await-replies` end-to-end through the
//! production wiring (host-fns registered at `reply-tracker/src/host_fn.rs`,
//! composed at `cli/src/wiring.rs`).
//!
//! Mirrors the M007-AC-01 `wit_parser::Resolve` precedent
//! (`run-manager/tests/wit_presence.rs`). Witnesses MODULE-006-AC-01 (T-W17-01).

use std::path::PathBuf;
use wit_parser::Resolve;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for tests is the crate dir (crates/messaging);
    // climb two levels to reach the repo root.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // repo root
    p
}

/// Parse the shipped `advance.wit` and return the function names declared by
/// the `agent-messaging` interface.
fn agent_messaging_funcs() -> Vec<String> {
    let mut resolve = Resolve::default();
    let wit_path = repo_root().join("crates/runtime/wit/advance.wit");
    let (pkg_id, _files) = resolve.push_path(&wit_path).expect("push_path advance.wit");

    let pkg = &resolve.packages[pkg_id];
    let iface_id = pkg
        .interfaces
        .get("agent-messaging")
        .copied()
        .expect("interface agent-messaging must exist in advance.wit");

    resolve.interfaces[iface_id]
        .functions
        .keys()
        .map(|s| s.to_string())
        .collect()
}

/// T-W17-01a — the shipped agent-messaging WIT declares the 3 methods the
/// reworded AC-01 criterion enumerates: `send` / `await-replies` / `heartbeat`.
#[test]
fn ac01_agent_messaging_declares_send_await_replies_heartbeat() {
    let funcs = agent_messaging_funcs();
    for name in ["send", "await-replies", "heartbeat"] {
        assert!(
            funcs.iter().any(|f| f == name),
            "agent-messaging must declare func {name:?}; got {funcs:?}"
        );
    }
}

/// T-W17-01b — anti-fake-green discriminator: `reply` (and `wait-for`) are NOT
/// WIT methods of agent-messaging. `reply` is the runtime-trait
/// `MailboxDispatcher::reply` action surface (covered by AC-06/07). The
/// reworded criterion drops `reply` from the WIT enumeration; the shipped WIT
/// confirms it was never there. If a future slice ADDED `reply` as a WIT
/// method, this test fails and forces a criterion re-review.
#[test]
fn ac01_agent_messaging_does_not_declare_reply_or_wait_for() {
    let funcs = agent_messaging_funcs();
    assert!(
        !funcs.iter().any(|f| f == "reply"),
        "agent-messaging must NOT declare `reply` (it is the runtime-trait \
         MailboxDispatcher::reply action surface, covered by AC-06/07); got {funcs:?}"
    );
    assert!(
        !funcs.iter().any(|f| f == "wait-for"),
        "agent-messaging must NOT declare `wait-for`; got {funcs:?}"
    );
}

/// T-W17-01c — the agent-messaging WIT surface is EXACTLY those 3 methods (no
/// more, no fewer) — pins the surface so an accidental future addition/removal
/// is caught and the §1.5 criterion stays in sync with the shipped contract.
#[test]
fn ac01_agent_messaging_surface_is_exactly_three_methods() {
    let mut funcs = agent_messaging_funcs();
    funcs.sort();
    assert_eq!(
        funcs,
        vec![
            "await-replies".to_string(),
            "heartbeat".to_string(),
            "send".to_string(),
        ],
        "agent-messaging WIT surface must be EXACTLY send/await-replies/heartbeat \
         (reply = runtime-trait, not WIT; notify lives in a separate `interface notify`)"
    );
}
