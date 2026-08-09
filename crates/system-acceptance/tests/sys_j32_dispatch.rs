//! SYS-J-32 trigger-dispatch journey witnesses (SYS-AC-102, 103, 104; SYS-AC-101 partial).
//!
//! Real product: the production `TriggerBusDispatchImpl` (scheduler `trigger_bus.rs`) —
//! 12-event whitelist projection, visited-set cycle prevention, and max-chain-depth
//! rejection — plus the production `InMemoryComponentSubmitApi` admission rule 4
//! (MODULE-014). Driven through the harness `.with_triggers()` seam
//! (`sut.trigger_bus()` / `sut.submit_api()`); the witnesses exercise the real bus and
//! the real submit admission (no mock).
//!
//! SYS-AC-101 is witnessed FULLY (sched-harvest 1B): the dispatch + populated
//! trigger-context (`DispatchedEntry.chain_id` / `next_depth`) leg on the real bus
//! (`sys_ac_101_whitelisted_event_dispatched_with_populated_context`), AND the
//! "run(config) executes with a populated trigger-context" leg on the real
//! dispatch→run edge (`sys_ac_101_dispatch_runs_real_guest_with_populated_context`):
//! the production `TriggerEventSource` drains the dispatched entry, projects it via
//! `DispatchedEntry::to_trigger_context` (the 1B chain-context fill), the unified
//! `WatcherDriver::run_with_trigger_source_with_emitter` passes it into
//! `ComponentConfig`, and the PRODUCTION `WasmRunnableHook` carries it field-for-field
//! into the real guest's `runnable.run(config)` — which ECHOES
//! `event_type|chain_id|depth` into `RunResult.output` (→ `{output_dir}/result.bin`),
//! so a host-side conversion that silently dropped the context cannot pass.
//!
//! SYS-AC-104 is witnessed VERBATIM at the submit-component admission surface the
//! criterion names (ADJUDICATED 2026-06-10, ADR
//! `2026-06-10-trigger-whitelist-submit-admission-gate`: PRD §3.8 mandates rejection at
//! submit admission, and CONTRACT-131 `subscribe()` has no Result channel — the
//! submit-side gate is the only user-observable rejection). The two-gate architecture
//! per that ADR is fully built: the submit-admission whitelist (sched-residue 2026-06-12,
//! `submit.rs` rule 4 — `find_non_whitelisted_trigger_event` over the SAME
//! `is_event_whitelisted` predicate as the bus gate, ALL component types, AnyOf
//! fail-closed, `InvalidConfig` BEFORE registry persistence) is witnessed by
//! `sys_ac_104_*` below; the trigger-bus subscription-admission gate
//! (`validate_subscription`) is retained as regression coverage by
//! `trigger_bus_subscription_*`.

use advance_scheduler::trigger_bus::CycleRejection;
use advance_scheduler::types::{SpawnError, SubscriptionId, TriggerConfig, TriggerSubscription};
use advance_scheduler::watcher::WatcherDriver;
use advance_scheduler::{
    ComponentSubmitApi, ComponentSubmitConfig, TriggerBusDispatch, TriggerEventSource,
};
use advance_shared_types::component::ComponentType;
use advance_shared_types::event::Event;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use system_acceptance::SystemUnderTest;

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

fn sub(event_type: &str) -> TriggerSubscription {
    TriggerSubscription {
        event_type: event_type.into(),
        filter: None,
        debounce_ms: None,
    }
}

fn evt(event_type: &str, payload: serde_json::Value) -> Event {
    Event::observability(event_type, "sys-j32", payload, None)
}

async fn triggers_sut() -> SystemUnderTest {
    SystemUnderTest::builder()
        .with_triggers()
        .build(J01_SKELETON)
        .await
}

// SYS-AC-101 (partial) — emitting a whitelisted event a runnable subscribed to dispatches
// it to that subscriber WITH a populated trigger-context (chain_id + next_depth). The
// "run executes" clause is deferred to §3 (see module docs).
#[tokio::test]
async fn sys_ac_101_whitelisted_event_dispatched_with_populated_context() {
    let sut = triggers_sut().await;
    let bus = sut.trigger_bus();
    let sub_id = bus.subscribe(sub("grant.issued"));
    assert_ne!(
        sub_id,
        SubscriptionId::REJECTED,
        "the runnable subscribed to a whitelisted event"
    );

    bus.dispatch(evt(
        "grant.issued",
        json!({ "trigger_chain_id": "chain-101", "chain_depth": 0 }),
    ));

    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(
        drained.len(),
        1,
        "the whitelisted event was dispatched to the subscriber"
    );
    assert_eq!(drained[0].subscription_id, sub_id);
    // Populated trigger-context: the chain id + advanced depth the runnable would receive.
    assert_eq!(
        drained[0].chain_id.0, "chain-101",
        "populated trigger-context: chain id"
    );
    assert_eq!(
        drained[0].next_depth, 1,
        "populated trigger-context: next chain depth"
    );
}

// SYS-AC-101 (run-executes leg) — a whitelisted EventBus event a runnable subscribed
// to via trigger-event causes the runnable's run(config) to EXECUTE in the real guest
// WITH a populated trigger-context: real bus dispatch → production TriggerEventSource
// drain (DispatchedEntry::to_trigger_context) → unified WatcherDriver run path →
// PRODUCTION WasmRunnableHook → real guest runnable.run, which echoes
// `event_type|chain_id|depth` into RunResult.output → {output_dir}/result.bin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_101_dispatch_runs_real_guest_with_populated_context() {
    let sut = triggers_sut().await;
    let bus = sut.trigger_bus().clone();
    let outdir = tempfile::tempdir().expect("outdir");

    // The PRODUCTION runnable bridge over THIS SUT's real guest component, driven by
    // the production unified watcher path over the production trigger-event source.
    let hook = sut.wasm_runnable_hook("w-101");
    let source = TriggerEventSource {
        sub: sub("git.commit"),
        dispatcher: bus.clone(),
    };
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let emitter = sut.event_emitter();
    let out_path = outdir.path().to_path_buf();
    let watcher = tokio::spawn(async move {
        WatcherDriver::run_with_trigger_source_with_emitter(
            "w-101",
            Box::new(source),
            hook,
            Some(out_path),
            Some(emitter),
            cancel_clone,
        )
        .await
    });

    // The source subscribes inside the spawned task; an event dispatched before the
    // subscription lands would simply find no subscriber. Deterministic without a
    // subscription probe: retry-dispatch with a FRESH chain id per attempt (no
    // visited-set interference between attempts) until the first real guest run
    // completes — depth 2 in the dispatched payload means the runnable must receive
    // the ADVANCED depth 3.
    let finished_for_id = |e: &Event| {
        e.event_type == "component.finished"
            && e.payload.get("id").and_then(|v| v.as_str()) == Some("w-101")
    };
    for i in 0..2000u32 {
        if sut.events().iter().any(|e| finished_for_id(e)) {
            break;
        }
        bus.dispatch(evt(
            "git.commit",
            json!({ "trigger_chain_id": format!("chain-101-e2e-{i}"), "chain_depth": 2 }),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        sut.events().iter().any(|e| finished_for_id(e)),
        "a dispatched whitelisted event drove a real guest run to completion"
    );
    cancel.cancel();
    let _ = watcher.await;

    // Sink-emit-order pairing for the watcher id (started strictly precedes finished).
    let events = sut.events();
    let started_pos = events
        .iter()
        .position(|e| {
            e.event_type == "component.started"
                && e.payload.get("id").and_then(|v| v.as_str()) == Some("w-101")
        })
        .expect("component.started for w-101 captured");
    let finished_pos = events
        .iter()
        .position(|e| finished_for_id(e))
        .expect("finished pos");
    assert!(
        started_pos < finished_pos,
        "started precedes finished in sink emit order"
    );

    // THE populated-trigger-context proof: the guest echoed what it RECEIVED into
    // result.bin — event_type, the dispatched chain id, and the ADVANCED depth (2+1).
    let echoed = std::fs::read(outdir.path().join("result.bin"))
        .expect("the real guest run's output was written to {output_dir}/result.bin");
    let echoed = String::from_utf8(echoed).expect("utf8 echo");
    let parts: Vec<&str> = echoed.split('|').collect();
    assert_eq!(
        parts.len(),
        3,
        "echo shape event_type|chain_id|depth; got {echoed:?}"
    );
    assert_eq!(
        parts[0], "git.commit",
        "the guest received the triggering event_type"
    );
    assert!(
        parts[1].starts_with("chain-101-e2e-"),
        "the guest received the dispatched trigger_chain_id; got {:?}",
        parts[1]
    );
    assert_eq!(
        parts[2], "3",
        "the guest received the ADVANCED chain depth (2+1)"
    );
}

// SYS-AC-102 — a component re-entered within the same trigger-chain-id (already in the
// visited-set) is not dispatched a second time (cycle prevented). Dispatch the same
// (chain_id, sub) twice WITHOUT an intervening drain (drain reclaims the visited slot).
#[tokio::test]
async fn sys_ac_102_visited_set_prevents_reentry() {
    let sut = triggers_sut().await;
    let bus = sut.trigger_bus();
    let sub_id = bus.subscribe(sub("git.commit"));

    bus.dispatch(evt(
        "git.commit",
        json!({ "trigger_chain_id": "chain-A", "chain_depth": 0 }),
    ));
    bus.dispatch(evt(
        "git.commit",
        json!({ "trigger_chain_id": "chain-A", "chain_depth": 0 }),
    ));

    assert_eq!(
        bus.rejection_counts().already_visited,
        1,
        "the cycle re-entry was rejected once"
    );
    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(
        drained.len(),
        1,
        "only the first chain entry was dispatched"
    );
    assert!(
        bus.cycle_rejected_log()
            .iter()
            .any(|r| matches!(r, CycleRejection::AlreadyVisited { .. })),
        "an AlreadyVisited rejection was logged"
    );
}

// SYS-AC-103 — a trigger chain exceeding max-chain-depth (default 10) is rejected
// without dispatch (cycle-rejected entry carrying chain_id + depth).
#[tokio::test]
async fn sys_ac_103_max_chain_depth_rejected_without_dispatch() {
    let sut = triggers_sut().await;
    let bus = sut.trigger_bus();
    let _sub_id = bus.subscribe(sub("git.commit"));

    // chain_depth 10 → next_depth 11 > max=10 → reject.
    bus.dispatch(evt(
        "git.commit",
        json!({ "trigger_chain_id": "deep-chain", "chain_depth": 10 }),
    ));

    assert_eq!(
        bus.pending_total(),
        0,
        "the over-depth chain is not dispatched"
    );
    assert!(
        bus.cycle_rejected_log()
            .iter()
            .any(|r| matches!(r, CycleRejection::MaxDepthExceeded { depth: 11, .. })),
        "expected a MaxDepthExceeded rejection with depth=11"
    );
}

// Trigger-bus subscription-admission whitelist (Gate-2 of the adjudicated two-gate
// architecture) — retained regression coverage: a subscription to a non-whitelisted
// event (fs.write) is rejected at subscription admission; dispatch of it enqueues
// nothing. (The SYS-AC-104 criterion itself names the SUBMIT-admission gate — see
// sys_ac_104_* below.)
#[tokio::test]
async fn trigger_bus_subscription_non_whitelisted_rejected_at_admission() {
    let sut = triggers_sut().await;
    let bus = sut.trigger_bus();

    assert_eq!(
        bus.subscribe(sub("fs.write")),
        SubscriptionId::REJECTED,
        "a subscription to the non-whitelisted fs.write is rejected at admission"
    );

    bus.dispatch(evt("fs.write", json!({})));
    assert_eq!(
        bus.pending_total(),
        0,
        "a non-whitelisted dispatch enqueues nothing"
    );
    assert!(
        bus.cycle_rejected_log()
            .iter()
            .any(|r| matches!(r, CycleRejection::EventTypeNotWhitelisted { .. })),
        "an EventTypeNotWhitelisted rejection was logged"
    );
}

fn watcher_cfg(id: &str, trigger: TriggerConfig) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: ComponentType::Watcher,
        binary: Vec::new(),
        capabilities: vec![],
        output_dir: None,
        trigger: Some(trigger),
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

// SYS-AC-104 — a SubmitComponent whose trigger subscribes to a non-whitelisted event
// (fs.write) is rejected AT SUBMIT-COMPONENT ADMISSION with
// spawn-error::invalid-config (submit.rs admission rule 4, BEFORE registry
// persistence), and nothing is persisted: the rejected component appears in neither
// the in-memory admission view nor the durable ComponentRegistry.
#[tokio::test]
async fn sys_ac_104_non_whitelisted_trigger_event_rejected_at_submit_admission() {
    let sut = triggers_sut().await;
    let api = sut.submit_api();

    // Direct TriggerEvent leaf on a Watcher (the general rule-4 surface, not the
    // daemon-specific rule 3).
    let err = api
        .submit_component(
            "agent:root",
            watcher_cfg("w-104", TriggerConfig::TriggerEvent(sub("fs.write"))),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, SpawnError::InvalidConfig(_)),
        "non-whitelisted trigger-event submit → InvalidConfig at admission; got {err:?}"
    );

    // AnyOf fail-closed: one offending leaf nested under AnyOf rejects the whole
    // config (the whitelisted git.commit sibling does not rescue it).
    let err2 = api
        .submit_component(
            "agent:root",
            watcher_cfg(
                "w-104-anyof",
                TriggerConfig::AnyOf(vec![
                    TriggerConfig::TriggerEvent(sub("git.commit")),
                    TriggerConfig::TriggerEvent(sub("fs.write")),
                ]),
            ),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err2, SpawnError::InvalidConfig(_)),
        "AnyOf with one non-whitelisted leaf → InvalidConfig (fail-closed); got {err2:?}"
    );

    // Nothing persisted: neither rejected submit reached the in-memory admission
    // view nor the durable registry (rule 4 runs BEFORE the rule-6 critical
    // section's registry write).
    let listed = api.list_components().await;
    assert!(
        !listed.iter().any(|c| c.id.as_str().starts_with("w-104")),
        "rejected submits are absent from the admission view"
    );
    let persisted = api.list_components_persisted().await.expect("durable read");
    assert!(
        !persisted.iter().any(|r| r.id.as_str().starts_with("w-104")),
        "rejected submits persist nothing to the ComponentRegistry"
    );

    // The same config with a WHITELISTED trigger-event admits (the gate rejects
    // the event type, not the component shape) — rule 4 is live, not vacuous.
    api.submit_component(
        "agent:root",
        watcher_cfg("w-104-ok", TriggerConfig::TriggerEvent(sub("git.commit"))),
    )
    .await
    .expect("a whitelisted trigger-event watcher admits");
}
