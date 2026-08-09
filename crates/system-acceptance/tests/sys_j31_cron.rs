//! SYS-J-31 cron journey witnesses (SYS-AC-098, 099, 100).
//!
//! Real product: the production `CronDriver::run_periodic_with_emitter` (scheduler
//! `cron.rs`) fires on its real `tokio` tick loop and emits `trigger.fired`
//! (`trigger_type=="cron"`) + `component.started`/`component.finished` through the
//! SUT's REAL event sink (MODULE-014→MODULE-001→MODULE-019); `compute_jitter` is the
//! deterministic anti-thundering-herd offset the driver applies. Driven through the
//! harness `.with_triggers()` seam (`drive_cron_fire` / `drive_cron_run` /
//! `cron_jitter`).
//!
//! SYS-AC-098 is witnessed on the FULL real chain (sched-harvest 1B): the cron tick
//! invokes the PRODUCTION `WasmRunnableHook` (cli `runnable_hook.rs` — the P-runnable
//! edge: fresh instantiate + `runnable.run(config)` on the real guest component), with
//! `trigger_context: None` (the criterion's cron shape), observable as
//! `component.started` → `component.finished` in SINK EMIT ORDER (never
//! `Event.timestamp` — a sub-ms hook can stamp equal timestamps), with
//! `component.finished` observed BEFORE the driver is cancelled (orphan `started` is
//! the normal cancel-mid-hook outcome; the §3 hand-off sequencing contract).

use std::time::Duration;

use system_acceptance::SystemUnderTest;

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

// SYS-AC-099 — a real cron fire emits a `trigger.fired` event with `trigger_type=="cron"`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_099_cron_fire_emits_trigger_fired_cron() {
    let sut = SystemUnderTest::builder()
        .with_triggers()
        .build(J01_SKELETON)
        .await;

    // A real CronDriver tick (10ms interval) fires the real runnable hook and emits
    // trigger.fired. `fires` is the captured trigger.fired count (the SYS-AC-099 witness
    // quantity — race-free; see drive_cron_fire docs).
    let fires = sut
        .drive_cron_fire("cron-099", Duration::from_millis(10))
        .await;
    assert!(
        fires >= 1,
        "the cron driver emitted at least one trigger.fired; got {fires}"
    );

    // The fire emitted trigger.fired{trigger_type="cron"} through the shared event sink.
    let ev = sut.assert_event("trigger.fired", |e| {
        e.payload.get("trigger_type").and_then(|v| v.as_str()) == Some("cron")
    });
    assert_eq!(
        ev.agent_id, "cron-099",
        "trigger.fired stamps the firing cron component id"
    );
    assert_eq!(
        ev.payload.get("component_id").and_then(|v| v.as_str()),
        Some("cron-099"),
        "trigger.fired payload echoes the component id"
    );
}

// SYS-AC-098 — a cron component fires at its scheduled tick and its run(config)
// EXECUTES in the real guest (PRODUCTION WasmRunnableHook: fresh instantiate +
// runnable.run on the real WASM component; trigger-context==None for cron),
// observable as component.started → component.finished in sink emit order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_098_cron_tick_runs_real_guest_started_then_finished() {
    let sut = SystemUnderTest::builder()
        .with_triggers()
        .build(J01_SKELETON)
        .await;

    // The PRODUCTION runnable bridge over THIS SUT's real guest component.
    let hook = sut.wasm_runnable_hook("cron-098");
    let outdir = tempfile::tempdir().expect("outdir");
    let finished = sut
        .drive_cron_run(
            "cron-098",
            Duration::from_millis(10),
            hook,
            Some(outdir.path().to_path_buf()),
        )
        .await;
    assert!(
        finished >= 1,
        "at least one real guest run completed; got {finished}"
    );

    // The criterion's "(trigger-context==None for cron)" clause, OBSERVED not
    // merely constructed (adversarial-round F12): the guest echoes a received
    // trigger-context into RunResult.output (→ result.bin); a None context
    // echoes nothing → NO result.bin. A context-injecting regression on the
    // cron path would materialize the file and fail here.
    assert!(
        !outdir.path().join("result.bin").exists(),
        "the real guest received trigger_context == None (no echo written)"
    );

    // Sink-emit-order pairing (the §3 sequencing contract — never Event.timestamp):
    // the first component.finished for this id is strictly dominated by a
    // component.started for this id earlier in the captured sequence.
    let events = sut.events();
    let id_of = |e: &advance_shared_types::event::Event| {
        e.payload
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let started_pos = events
        .iter()
        .position(|e| {
            e.event_type == "component.started" && id_of(e).as_deref() == Some("cron-098")
        })
        .expect("a component.started for cron-098 was captured");
    let finished_pos = events
        .iter()
        .position(|e| {
            e.event_type == "component.finished" && id_of(e).as_deref() == Some("cron-098")
        })
        .expect("a component.finished for cron-098 was captured");
    assert!(
        started_pos < finished_pos,
        "component.started (pos {started_pos}) precedes component.finished (pos {finished_pos}) in sink emit order"
    );

    // The finished payload carries the PRD §15.3.14 fields: the run completed on
    // the real guest (RunStatus::Completed) under the cron driver.
    let fin = &events[finished_pos];
    assert_eq!(
        fin.payload.get("component_type").and_then(|v| v.as_str()),
        Some("cron")
    );
    assert_eq!(
        fin.payload.get("status").and_then(|v| v.as_str()),
        Some("completed"),
        "the real guest run returned RunStatus::Completed"
    );
    assert!(
        fin.payload.get("duration_ms").is_some(),
        "finished stamps duration_ms"
    );

    // The tick itself also emitted trigger.fired{trigger_type="cron"} (the fire leg).
    sut.assert_event("trigger.fired", |e| {
        e.payload.get("trigger_type").and_then(|v| v.as_str()) == Some("cron")
            && e.agent_id == "cron-098"
    });
}

// SYS-AC-100 — two cron components on the same schedule fire at deterministically
// different offsets, each bounded by `cron.max_jitter_ratio` (0.1) of the period
// (capped at the canonical 900_000 ms ceiling).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_100_cron_jitter_deterministic_distinct_bounded() {
    let sut = SystemUnderTest::builder()
        .with_triggers()
        .build(J01_SKELETON)
        .await;

    let period_ms = 300_000u64;
    // schedule "" is the literal the CronDriver passes (cron.rs:110); the asserted
    // property is schedule-agnostic, but "" exercises the exact value path.
    let a = sut.cron_jitter("cron-a", "", period_ms);
    let b = sut.cron_jitter("cron-b", "", period_ms);

    // Determinism: the same (id, schedule, period) reproduces the same offset.
    assert_eq!(
        a,
        sut.cron_jitter("cron-a", "", period_ms),
        "jitter is deterministic"
    );

    // Two distinct ids on the SAME schedule → different offsets (anti-thundering-herd).
    assert_ne!(
        a, b,
        "two cron ids on the same schedule fire at different offsets"
    );

    // Each offset is bounded by ratio (0.1) × period and by the 900_000 ms ceiling.
    let ratio_bound = Duration::from_millis(((period_ms as f64) * 0.1) as u64);
    assert!(
        a < ratio_bound && b < ratio_bound,
        "offsets within 0.1×period: a={a:?} b={b:?}"
    );
    let ceiling = Duration::from_millis(900_000);
    assert!(
        a < ceiling && b < ceiling,
        "offsets within the 900_000 ms ceiling"
    );
}
