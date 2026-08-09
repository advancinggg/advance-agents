//! AC-02 (MODULE-014-AC-02 / REQ-022, T02) verification: `AnyOfTriggerSource`
//! OR fan-in semantics.
//!
//! `AnyOfTriggerSource`'s OR fan-in shipped in Slice C; Slice E adds only
//! these verifying tests (no `trigger_source.rs` change). Tests construct
//! `AnyOfTriggerSource` **directly** with in-test public-trait `TagSource`
//! mocks emitting distinct `trigger_type` tags, so the assertions prove OR
//! fan-in from BOTH children (not aggregate-≥2 where one child could
//! starve). The `resolve_trigger` router path is AC-14-covered by Slice C
//! `trigger_variants.rs` T32, so no `FileWatchSource`/`WebhookSource` mocks
//! are needed here.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use advance_scheduler::hook::HookError;
use advance_scheduler::trigger_source::{
    AnyOfTriggerSource, ScheduleTriggerSource, TriggerFireEvent, TriggerSource,
};

/// In-test mock: emits a `TriggerFireEvent` tagged with `tag` every `period`
/// until cancelled or the receiver drops. The distinct `trigger_type` tag
/// lets the drain loop attribute each fire to a specific child.
struct TagSource {
    tag: &'static str,
    period: Duration,
}

#[async_trait]
impl TriggerSource for TagSource {
    async fn run(
        &self,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        let mut ticker = tokio::time::interval(self.period);
        // Consume the immediate first tick so callers see period-then-fire.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = ticker.tick() => {
                    if tx
                        .send(TriggerFireEvent { trigger_type: self.tag, trigger_context: None })
                        .await
                        .is_err()
                    {
                        return Ok(()); // receiver dropped
                    }
                }
            }
        }
    }
}

// T02.a — OR fan-in: BOTH same-cadence children must independently fire.
#[tokio::test]
async fn t02a_anyof_or_fanin_both_children_fire() {
    let any = AnyOfTriggerSource {
        children: vec![
            Arc::new(TagSource {
                tag: "src-a",
                period: Duration::from_millis(40),
            }),
            Arc::new(TagSource {
                tag: "src-b",
                period: Duration::from_millis(40),
            }),
        ],
    };
    let (tx, mut rx) = mpsc::channel::<TriggerFireEvent>(64);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let h = tokio::spawn(async move { any.run(tx, cancel2).await });

    let mut saw_a = false;
    let mut saw_b = false;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    while tokio::time::Instant::now() < deadline && !(saw_a && saw_b) {
        match tokio::time::timeout(Duration::from_millis(60), rx.recv()).await {
            Ok(Some(ev)) => {
                if ev.trigger_type == "src-a" {
                    saw_a = true;
                }
                if ev.trigger_type == "src-b" {
                    saw_b = true;
                }
            }
            Ok(None) => break,
            Err(_) => {} // slice timeout — keep waiting until the deadline
        }
    }
    cancel.cancel();
    let _ = h.await;
    assert!(
        saw_a,
        "child src-a never fired (OR fan-in must reach BOTH children)"
    );
    assert!(
        saw_b,
        "child src-b never fired (OR fan-in must reach BOTH children)"
    );
}

// T02.b — distinct cadences: both fire; the faster child fires more often
// (independent per-child scheduling, not lock-step).
#[tokio::test]
async fn t02b_anyof_distinct_cadences_both_fire() {
    let any = AnyOfTriggerSource {
        children: vec![
            Arc::new(TagSource {
                tag: "fast",
                period: Duration::from_millis(40),
            }),
            Arc::new(TagSource {
                tag: "slow",
                period: Duration::from_millis(90),
            }),
        ],
    };
    let (tx, mut rx) = mpsc::channel::<TriggerFireEvent>(64);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let h = tokio::spawn(async move { any.run(tx, cancel2).await });

    let mut fast = 0usize;
    let mut slow = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(80), rx.recv()).await {
            Ok(Some(ev)) => match ev.trigger_type {
                "fast" => fast += 1,
                "slow" => slow += 1,
                _ => {}
            },
            Ok(None) => break,
            Err(_) => {}
        }
    }
    cancel.cancel();
    let _ = h.await;
    assert!(fast >= 1, "fast child never fired");
    assert!(slow >= 1, "slow child never fired");
    assert!(
        fast > slow,
        "faster cadence should fire more often (fast={fast}, slow={slow})"
    );
}

// T02.c — empty AnyOf returns Ok immediately (documented no-hang path).
#[tokio::test]
async fn t02c_empty_anyof_returns_ok_immediately() {
    let any = AnyOfTriggerSource { children: vec![] };
    let (tx, _rx) = mpsc::channel::<TriggerFireEvent>(1);
    let cancel = CancellationToken::new();
    let r = tokio::time::timeout(Duration::from_millis(500), any.run(tx, cancel)).await;
    assert!(r.is_ok(), "empty AnyOf must return promptly, not hang");
    assert!(r.unwrap().is_ok(), "empty AnyOf must return Ok(())");
}

// T02.d — sibling isolation: a synchronously-erroring child does NOT kill
// the healthy child; after draining the error and cancelling, `run`
// surfaces the child's `Err(HookError::Failure)`.
#[tokio::test]
async fn t02d_sibling_error_does_not_kill_healthy_child() {
    // `ScheduleTriggerSource { interval: Duration::ZERO }` returns
    // `Err(HookError::Failure)` synchronously, before any `.await`.
    let any = AnyOfTriggerSource {
        children: vec![
            Arc::new(TagSource {
                tag: "ok",
                period: Duration::from_millis(40),
            }),
            Arc::new(ScheduleTriggerSource {
                interval: Duration::ZERO,
            }),
        ],
    };
    let (tx, mut rx) = mpsc::channel::<TriggerFireEvent>(64);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let h = tokio::spawn(async move { any.run(tx, cancel2).await });

    // The healthy child must still fire ≥1 despite the sibling's immediate
    // error (sibling isolation).
    let first = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
    assert!(
        matches!(&first, Ok(Some(ev)) if ev.trigger_type == "ok"),
        "healthy child must fire despite sibling error (got {first:?})"
    );
    // Drain-before-cancel: give the AnyOf select-loop a slice to consume
    // child-B's synchronous Err into `first_err` BEFORE we cancel (the
    // post-loop handles.abort() block only converts panics, not channel
    // Errs — so the Err must already be recorded pre-cancel).
    tokio::time::sleep(Duration::from_millis(60)).await;
    cancel.cancel();
    let outcome = tokio::time::timeout(Duration::from_millis(500), h)
        .await
        .expect("run must return promptly after cancel")
        .expect("spawned task joined");
    assert!(
        matches!(outcome, Err(HookError::Failure(_))),
        "AnyOf must surface child-B's Err(HookError::Failure) (got {outcome:?})"
    );
}
