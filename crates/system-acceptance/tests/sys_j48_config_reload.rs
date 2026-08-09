//! Lifecycle-harvest — SYS-J-48 runtime-config hot-reload e2e witnesses
//! (SYS-AC-152 / 153 / 154 / 237).
//!
//! Wired system: the harness `.with_runtime_config_watch()` axis — the
//! production `RuntimeConfigWatcher` (M001: notify-backed file watch,
//! parse + validate fail-closed, subscriber fan-out, `runtime.config_reloaded`
//! emission) over a real seeded `<ws>/.advance/runtime-config.yaml`, with the
//! SUT event sink installed as the emitter so the reload event is observable
//! via `events()`.
//!
//! Witness-strength disclosure (SYS-AC-152, per the plan-gate design): the
//! "subsequent operation uses the new value" proof rests on the **database
//! leg** — `RuntimeConfigDatabaseTunables` (bootstrap.rs), the REAL production
//! adapter database operations consult on EVERY call (read-through-snapshot,
//! never cached), returns the new `database.recall-max-depth` after the
//! reload. This is the established test-local-real-wiring bar: the adapter is
//! production code (not a mock) constructed over the SUT's REAL wired watcher
//! (`sut.runtime_config_watcher()`) — the same per-call read-through path a
//! recall operation consults. It does NOT drive a full wired recall (the
//! `.with_runtime_config_watch()` axis attaches the watcher to the SUT event
//! sink only; MODULE-009/recall is not in this journey's harness wiring), so
//! the proof is "the real per-call consumer serves the reloaded value", one
//! call short of an end-to-end recall. The criterion's named `cron` section is
//! additionally edited in the same write and asserted via the provider's
//! `current()` snapshot (corroboration — no production cron consumer reads the
//! provider back in-harness).
//!
//! Same-PID legs (153/154/237): everything runs in this test process —
//! `std::process::id()` is asserted unchanged across the reload and no
//! `runtime.shutdown` event is emitted (the criterion's "runtime process
//! never stopping").

use std::sync::Arc;
use std::time::Duration;

use advance_database::TunablesProvider;
use advance_runtime::bootstrap::RuntimeConfigDatabaseTunables;
use advance_runtime::config::RuntimeConfigProvider;
use system_acceptance::SystemUnderTest;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// A full valid config matching the harness seed, with the `cron` jitter and
/// `database.recall-max-depth` values parameterized (the dual-section edit).
fn config_yaml(jitter: f64, recall_depth: u32) -> String {
    format!(
        r#"
wasm:
  max_memory_pages: 512
  epoch_interruption_ms: 50
  fuel_enabled: true
llm-providers: []
cron:
  max_jitter_ratio: {jitter}
git:
  gc_interval_hours: 12
  max_tracked_file_mb: 5
circuit-breakers: []
secrets:
  master-key-source: env-var
  env-var-name: MY_KEY
users: []
post-processor:
  llm-model: fast
  llm-failure-cooldown-seconds: 300
database:
  db-path: .runtime/index.db
  pool-size: 4
  recall-max-depth: {recall_depth}
"#
    )
}

/// Atomic-rename write (temp + rename) — the recommended writer pattern; keeps
/// event-count assertions torn-read-free.
fn write_config(path: &std::path::Path, content: &str) {
    let tmp = path.with_extension("tmp-write");
    std::fs::write(&tmp, content).expect("write tmp config");
    std::fs::rename(&tmp, path).expect("rename config into place");
}

// ── SYS-AC-152 + 153 + 154 — one wired journey ─────────────────────────────
// (One reload exercise covers the three criteria's legs: applied-without-
// restart + consumed value (152), event payload (153), <1s SLO + same PID
// (154). Separate tests would re-run the identical reload for no extra
// witness value; each SYS-AC has its own labelled assertion block.)
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_152_153_154_reload_applied_event_and_slo() {
    let pid_before = std::process::id();
    let sut = SystemUnderTest::builder()
        .with_runtime_config_watch()
        .build(CORE_BYTES)
        .await;
    let watcher = sut.runtime_config_watcher().clone();

    // Production per-call consumer (the adapter real database ops consult).
    let tunables = RuntimeConfigDatabaseTunables(watcher.clone() as Arc<dyn RuntimeConfigProvider>);
    assert_eq!(tunables.current().recall_max_depth, 2, "seeded baseline");
    assert!((watcher.current().cron.max_jitter_ratio - 0.05).abs() < 1e-9);

    let mut rx = watcher.subscribe();

    // ── the live edit: cron jitter 0.05→0.20 AND database depth 2→5 ────────
    let edit_start = std::time::Instant::now();
    write_config(sut.runtime_config_path(), &config_yaml(0.20, 5));

    // SYS-AC-154: picked up within the <1s hot-reload SLO.
    let reloaded = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("reload notification within the 1s SLO")
        .expect("watcher alive");
    let elapsed = edit_start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "SLO: reload in {elapsed:?}"
    );

    // SYS-AC-152: applied without a restart — a subsequent operation uses the
    // new value. (a) The production per-call database consumer:
    assert_eq!(
        tunables.current().recall_max_depth,
        5,
        "RuntimeConfigDatabaseTunables reads the new database value per call"
    );
    // (b) the named cron section (snapshot corroboration):
    assert!((reloaded.cron.max_jitter_ratio - 0.20).abs() < 1e-9);
    assert!((watcher.current().cron.max_jitter_ratio - 0.20).abs() < 1e-9);

    // SYS-AC-153: runtime.config_reloaded names the edited sections. The
    // bridge emits AFTER the subscriber fan-out (config.rs: swap → fan-out →
    // emit), so the recv above does not guarantee the event has landed yet —
    // bounded poll for it (the <1s SLO was measured on the notification).
    let mut events = sut.events();
    for _ in 0..200 {
        if events
            .iter()
            .any(|e| e.event_type == "runtime.config_reloaded")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        events = sut.events();
    }
    let reload_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "runtime.config_reloaded")
        .collect();
    assert_eq!(
        reload_events.len(),
        1,
        "exactly one reload event: {events:?}"
    );
    let sections: Vec<&str> = reload_events[0].payload["sections_changed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        sections.contains(&"cron"),
        "sections_changed names cron: {sections:?}"
    );
    assert!(
        sections.contains(&"database"),
        "sections_changed names database: {sections:?}"
    );
    assert_eq!(reload_events[0].agent_id, "runtime");

    // SYS-AC-154: same PID, no shutdown — the runtime process never stopped.
    assert_eq!(std::process::id(), pid_before, "same PID across the reload");
    assert!(
        !events.iter().any(|e| e.event_type == "runtime.shutdown"),
        "no runtime.shutdown emitted"
    );
    assert!(
        watcher.last_error().is_none(),
        "clean reload leaves no error"
    );
}

// ── SYS-AC-237 — invalid edit is rejected fail-closed ──────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_237_invalid_config_rejected_fail_closed() {
    let pid_before = std::process::id();
    let sut = SystemUnderTest::builder()
        .with_runtime_config_watch()
        .build(CORE_BYTES)
        .await;
    let watcher = sut.runtime_config_watcher().clone();
    let tunables = RuntimeConfigDatabaseTunables(watcher.clone() as Arc<dyn RuntimeConfigProvider>);
    let mut rx = watcher.subscribe();

    // Malformed YAML → the reload is rejected; the prior config stays live.
    write_config(
        sut.runtime_config_path(),
        "wasm: [not, a, mapping\n  ::: garbage",
    );

    // Bounded wait for the watcher to observe + reject the edit (last_error
    // is the observable; no notification fires on a rejected reload).
    let mut saw_error = false;
    for _ in 0..200 {
        if watcher.last_error().is_some() {
            saw_error = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(saw_error, "rejected reload recorded in last_error()");

    // NOT applied: the previously-loaded valid config remains in effect for a
    // subsequent operation (the production per-call consumer still reads the
    // seeded value), no notification, no reload event.
    assert_eq!(
        tunables.current().recall_max_depth,
        2,
        "prior value still live"
    );
    assert!((watcher.current().cron.max_jitter_ratio - 0.05).abs() < 1e-9);
    assert!(
        rx.try_recv().is_err(),
        "no subscriber notification for a rejected reload"
    );
    assert!(
        !sut.events()
            .iter()
            .any(|e| e.event_type == "runtime.config_reloaded"),
        "no runtime.config_reloaded for a rejected reload"
    );

    // Runtime keeps running (same PID, no shutdown) and RECOVERS on the next
    // valid write — the watcher was not killed by the bad edit.
    assert_eq!(std::process::id(), pid_before);
    assert!(
        !sut.events()
            .iter()
            .any(|e| e.event_type == "runtime.shutdown"),
        "no runtime.shutdown"
    );
    write_config(sut.runtime_config_path(), &config_yaml(0.10, 3));
    let recovered = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("recovery reload lands")
        .expect("watcher alive");
    assert!((recovered.cron.max_jitter_ratio - 0.10).abs() < 1e-9);
    assert_eq!(
        tunables.current().recall_max_depth,
        3,
        "recovery value live"
    );
}
