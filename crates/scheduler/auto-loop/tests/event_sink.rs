//! Stage-D `AutoIterationEventSink` / `NotifySink` surface: payload→event_type
//! mapping, agent_id accessor, reason strings, and the Noop default impls.

use advance_scheduler_auto_loop::{
    event_sink::event_type, AutoIterationEventPayload, AutoIterationEventSink, DegradeReason,
    HaltReason, IterationStatus, NoopAutoIterationEventSink, NoopNotifySink, NotifySink,
};

#[test]
fn payload_event_type_mapping_is_stable() {
    let started = AutoIterationEventPayload::Started {
        agent_id: "a".into(),
        run_id: Some("r".into()),
        iteration: 1,
    };
    assert_eq!(started.event_type(), event_type::ITERATION_STARTED);
    assert_eq!(started.agent_id(), "a");

    let kept = AutoIterationEventPayload::Kept {
        agent_id: "a".into(),
        run_id: None,
        iteration: 2,
        metric: Some(0.5),
    };
    assert_eq!(kept.event_type(), event_type::ITERATION_KEPT);

    let discarded = AutoIterationEventPayload::Discarded {
        agent_id: "a".into(),
        run_id: None,
        iteration: 2,
        metric: Some(0.9),
    };
    assert_eq!(discarded.event_type(), event_type::ITERATION_DISCARDED);

    let crashed = AutoIterationEventPayload::Crashed {
        agent_id: "a".into(),
        run_id: None,
        iteration: 2,
        reason: "boom".into(),
    };
    assert_eq!(crashed.event_type(), event_type::ITERATION_CRASHED);

    let completed = AutoIterationEventPayload::Completed {
        agent_id: "a".into(),
        run_id: None,
        iteration: 2,
        status: IterationStatus::Keep,
    };
    assert_eq!(completed.event_type(), event_type::ITERATION_COMPLETED);

    let degraded = AutoIterationEventPayload::Degraded {
        agent_id: "a".into(),
        reason: DegradeReason::NoProgress,
    };
    assert_eq!(degraded.event_type(), event_type::DEGRADED);

    let halted = AutoIterationEventPayload::Halted {
        agent_id: "a".into(),
        reason: HaltReason::MaxCostUsd,
    };
    assert_eq!(halted.event_type(), event_type::HALTED);
}

#[test]
fn reason_strings() {
    assert_eq!(DegradeReason::NoProgress.as_str(), "no-progress-limit");
    assert_eq!(DegradeReason::LlmErrors.as_str(), "llm-error-limit");
    assert!(HaltReason::MaxIterations
        .as_str()
        .contains("max_iterations"));
    assert!(HaltReason::MaxCostUsd.as_str().contains("max_cost_usd"));
    assert!(HaltReason::MaxWallTime.as_str().contains("max_wall_time"));
}

#[tokio::test]
async fn noop_sinks_return_ok() {
    let s = NoopAutoIterationEventSink;
    s.emit(AutoIterationEventPayload::Started {
        agent_id: "a".into(),
        run_id: None,
        iteration: 0,
    })
    .await
    .expect("noop iteration sink Ok");

    let n = NoopNotifySink;
    n.notify("a", "msg").await.expect("noop notify sink Ok");
}
