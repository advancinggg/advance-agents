//! The body of MODULE-001-T111 (6), run by two binaries: on a current-thread runtime (the
//! daemon's flavour) and on a multi-thread runtime (an embedder's).
//!
//! Included after `t111`: `#[path = "support/recompose.rs"] mod recompose;`.

use std::sync::Arc;
use std::time::Duration;

use advance_runtime_compose::test_support::{
    ComposeFailpoints, ComposeProbe, MemoryComposeLog, TurnGate,
};
use advance_runtime_compose::{compose, log_keys};

use crate::t111::{
    alive_tasks, assert_composition_gone, assert_steps, assert_ws_closed, head_commits, head_file,
    head_paths, join_thread, mint_session, open_events_ws, poll_until, serial, spawn_post_msg,
    T111Home, J01_FILE, J01_REPLY,
};

/// How long a message turn may take to reach the gate, or to complete.
const TURN_BUDGET: Duration = Duration::from_secs(60);
/// How long the turn's commit may take to land after its reply.
const COMMIT_BUDGET: Duration = Duration::from_secs(10);

/// The D1 sequence on this home, in dependency order: every step whose part this home has.
const MANDATORY_STEPS: &[&str] = &[
    "ingress.client_api",
    "ingress.post_msg",
    "loops.root",
    "loops.llm_stream_reaper",
    "holds.selected_provider",
    "holds.watchers",
    "holds.packs_poll",
    "holds.cap_grant_sweeper",
    "holds.git_queue",
    "holds.client_api_slots",
    "holds.event_bus",
    "holds.drop_graph",
    "guard",
];

/// On a home that declares `fs`, `llm` and `lifecycle` and is a git repository (so the
/// CONTRACT-218 custody, the git commit queue and the LLM gateway all exist): with
/// `/client/events/stream` open and a message turn in flight, two clones of the shutdown
/// handle are fired and the shutdown awaited. The second trigger is a no-op; the
/// WebSocket is closed, the in-flight `POST /msg` answered 503, the D1 steps ran in
/// order, and nothing of the composition is left. A second composition of the same home
/// then serves a turn whose write is committed to git, and stops just as cleanly.
pub async fn t111_6_recompose_after_ordered_shutdown() {
    let _serial = serial();
    let home = T111Home::new(&["fs", "llm", "lifecycle"], true);
    let baseline = alive_tasks();

    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let gate = TurnGate::new();
    let runtime = compose(
        home.options(Arc::new(log.clone()))
            .with_failpoints(ComposeFailpoints {
                turn_gate: Some(gate.clone()),
                probe: Some(Arc::clone(&probe)),
                ..ComposeFailpoints::default()
            }),
        Vec::new(),
    )
    .await
    .expect("compose the T111 home");
    let record = probe.record();
    assert!(
        record.turn_gate_installed,
        "the home declares llm, so the root loop assembles through the gateway and is gated"
    );
    // Non-vacuity of the end-state check: the objects it requires dead are alive now.
    for name in [
        "client_api",
        "event_bus",
        "llm_gateway",
        "git_queue",
        "run_manager",
        "component_runtime",
    ] {
        assert!(
            record.alive().contains(&name),
            "{name} is recorded and alive while composed: {:?}",
            record.alive()
        );
    }
    assert!(
        !advance_runtime_compose::contract218_anchor::custody_paths_for_test().is_empty(),
        "the lifecycle home holds CONTRACT-218 custody while composed"
    );
    assert!(
        !advance_git::commit_queue::active_queue_paths_for_test().is_empty(),
        "the git home has an active commit queue while composed"
    );

    // An operator keeps /client/events/stream open.
    let endpoint = runtime.client_api().expect("the Client API is bound");
    let token = mint_session(&endpoint);
    let (mut events, seed) = open_events_ws(&endpoint, &token).await;
    let seed: serde_json::Value = serde_json::from_str(&seed).expect("the seed is JSON");
    assert!(
        seed.get("error").is_none_or(serde_json::Value::is_null),
        "the events seed is not an error: {seed}"
    );

    // A message turn in flight, held before its context is assembled.
    let post_msg = record.listener("post_msg").expect("POST /msg is bound");
    let in_flight = spawn_post_msg(post_msg, "t111");
    tokio::time::timeout(TURN_BUDGET, gate.entered())
        .await
        .expect("the turn reaches the gate");

    // Two clones of the handle: only the first trigger starts the sequence.
    let first = runtime.shutdown_handle();
    let second = first.clone();
    assert!(first.trigger(), "the first trigger starts the shutdown");
    assert!(!second.trigger(), "the second trigger is a no-op");
    runtime.shutdown().await.expect("shutdown");

    assert_eq!(
        log.count(log_keys::SHUTTING_DOWN),
        1,
        "the sequence ran once"
    );
    assert_ws_closed(&mut events, Duration::from_secs(2)).await;
    drop(events);
    let (status, _) = join_thread(in_flight, Duration::from_secs(10)).await;
    assert_eq!(
        status, 503,
        "the shutdown answers the in-flight POST /msg 503"
    );
    assert_steps(&probe.record(), MANDATORY_STEPS);
    assert_composition_gone(baseline, &probe, &home.home).await;

    // The same home composes again in this process, serves a turn and commits it.
    let probe = Arc::new(ComposeProbe::new());
    let runtime = compose(
        home.options(Arc::new(MemoryComposeLog::new()))
            .with_failpoints(ComposeFailpoints {
                probe: Some(Arc::clone(&probe)),
                ..ComposeFailpoints::default()
            }),
        Vec::new(),
    )
    .await
    .expect("the second compose of the same home succeeds");
    let post_msg = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound again");
    let commits = head_commits(&home.home);
    let payload = "t111-second-turn";
    let (status, body) = join_thread(spawn_post_msg(post_msg, payload), TURN_BUDGET).await;
    assert_eq!(
        (status, body.as_slice()),
        (200, J01_REPLY),
        "the turn replies"
    );
    let committed = poll_until(COMMIT_BUDGET, || {
        head_commits(&home.home) > commits
            && head_file(&home.home, J01_FILE).is_some_and(|(_, bytes)| bytes == payload.as_bytes())
    })
    .await;
    assert!(
        committed,
        "the turn's write is committed: HEAD holds {J01_FILE} = {payload:?} \
         ({} commits, {} before the turn; HEAD tree: {:?}; {J01_FILE} in the home: {:?})",
        head_commits(&home.home),
        commits,
        head_paths(&home.home),
        std::fs::read_to_string(home.home.join(J01_FILE)).ok(),
    );
    runtime.shutdown().await.expect("second shutdown");
    assert_steps(
        &probe.record(),
        &["holds.git_queue", "holds.event_bus", "guard"],
    );
    assert_composition_gone(baseline, &probe, &home.home).await;
}
