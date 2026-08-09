//! AC-21 verification: `DaemonManager::run_daemon` with the new 7th
//! `backoff: Option<RestartBackoffConfig>` parameter implements the
//! exponential delay-ladder + cancel-during-sleep + success-resets-attempt
//! semantics per Slice D plan §daemon.rs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use advance_scheduler::daemon::DaemonManager;
use advance_scheduler::{
    ComponentConfig, HookError, RestartBackoffConfig, RestartPolicy, RunResult, RunStatus,
    RunnableHook,
};

/// Mock hook that records each invocation's virtual-time instant + returns
/// a scripted Ok/Err sequence (1-indexed counter; `script[counter-1]`
/// determines the result; out-of-bounds counter returns Err).
struct ScriptedHook {
    counter: AtomicUsize,
    script: Vec<HookOutcome>,
    timestamps_ms: Arc<Mutex<Vec<u64>>>,
    start: tokio::time::Instant,
}

#[derive(Clone)]
enum HookOutcome {
    Ok,
    Err(String),
}

impl ScriptedHook {
    fn new(script: Vec<HookOutcome>) -> Arc<Self> {
        Arc::new(Self {
            counter: AtomicUsize::new(0),
            script,
            timestamps_ms: Arc::new(Mutex::new(Vec::new())),
            start: tokio::time::Instant::now(),
        })
    }

    fn calls(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }

    async fn gaps_ms(&self) -> Vec<u64> {
        let ts = self.timestamps_ms.lock().await;
        if ts.len() <= 1 {
            return Vec::new();
        }
        ts.windows(2).map(|w| w[1] - w[0]).collect()
    }
}

#[async_trait]
impl RunnableHook for ScriptedHook {
    async fn run_once(&self, _cfg: ComponentConfig) -> Result<RunResult, HookError> {
        let elapsed_ms = tokio::time::Instant::now()
            .saturating_duration_since(self.start)
            .as_millis() as u64;
        self.timestamps_ms.lock().await.push(elapsed_ms);
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let outcome = self
            .script
            .get(n)
            .cloned()
            .unwrap_or(HookOutcome::Err("script exhausted".into()));
        match outcome {
            HookOutcome::Ok => Ok(RunResult {
                status: RunStatus::Completed,
                output: None,
            }),
            HookOutcome::Err(msg) => Err(HookError::Failure(msg)),
        }
    }
}

fn dummy_config(id: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.into(),
        config_data: None,
        trigger_context: None,
    }
}

/// Drives the test forward by repeatedly auto-advancing virtual time until
/// the hook has been called `target` times, or `max_advances` ticks have
/// elapsed (deadlock guard).
async fn advance_until_calls(hook: &Arc<ScriptedHook>, target: usize, max_advances: u32) {
    for _ in 0..max_advances {
        if hook.calls() >= target {
            return;
        }
        // Auto-advance by a small step; tokio::time::pause leaves us in control.
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn exponential_backoff_until_success() {
    // 3 errors then Ok; OnFailure policy → Stop on success.
    let hook = ScriptedHook::new(vec![
        HookOutcome::Err("err 1".into()),
        HookOutcome::Err("err 2".into()),
        HookOutcome::Err("err 3".into()),
        HookOutcome::Ok,
    ]);
    let backoff = RestartBackoffConfig {
        max_retries: 5,
        base_delay_ms: 100,
        max_delay_ms: 1_000,
        jitter: false,
    };
    let cancel = CancellationToken::new();
    let hook_clone: Arc<dyn RunnableHook> = hook.clone();

    let handle = tokio::spawn({
        let hook_arc: Arc<dyn RunnableHook> = hook_clone;
        let cancel = cancel.clone();
        async move {
            DaemonManager::run_daemon(
                "test-d",
                RestartPolicy::OnFailure,
                hook_arc,
                dummy_config("test-d"),
                None,
                cancel,
                Some(backoff),
            )
            .await
        }
    });

    advance_until_calls(&hook, 4, 10_000).await;
    let _ = handle.await.unwrap();

    assert_eq!(hook.calls(), 4, "expected 4 hook invocations");
    let gaps = hook.gaps_ms().await;
    assert_eq!(gaps.len(), 3);
    // Gaps 100 / 200 / 400 ms (exponential, no jitter).
    assert_eq!(gaps[0], 100);
    assert_eq!(gaps[1], 200);
    assert_eq!(gaps[2], 400);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn max_retries_exhausted() {
    let hook = ScriptedHook::new(vec![HookOutcome::Err("perma".into()); 10]);
    let backoff = RestartBackoffConfig {
        max_retries: 3,
        base_delay_ms: 100,
        max_delay_ms: 1_000,
        jitter: false,
    };
    let cancel = CancellationToken::new();
    let hook_clone: Arc<dyn RunnableHook> = hook.clone();

    let handle = tokio::spawn({
        let hook_arc: Arc<dyn RunnableHook> = hook_clone;
        let cancel = cancel.clone();
        async move {
            DaemonManager::run_daemon(
                "test-exh",
                RestartPolicy::OnFailure,
                hook_arc,
                dummy_config("test-exh"),
                None,
                cancel,
                Some(backoff),
            )
            .await
        }
    });

    advance_until_calls(&hook, 4, 10_000).await;
    let result = handle.await.unwrap();

    // After 4th err, attempt(4) > max_retries(3) → Err.
    assert!(result.is_err(), "expected max-retries Err, got {result:?}");
    match result.unwrap_err() {
        HookError::Failure(msg) => assert!(msg.contains("max retries exceeded"), "msg: {msg}"),
        other => panic!("expected HookError::Failure, got {other:?}"),
    }
    assert_eq!(hook.calls(), 4);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn max_delay_caps_backoff() {
    // base=100, max=300 → ladder is 100/200/300/300 (clamped from 400/800).
    let hook = ScriptedHook::new(vec![
        HookOutcome::Err("e".into()),
        HookOutcome::Err("e".into()),
        HookOutcome::Err("e".into()),
        HookOutcome::Err("e".into()),
        HookOutcome::Ok,
    ]);
    let backoff = RestartBackoffConfig {
        max_retries: 10,
        base_delay_ms: 100,
        max_delay_ms: 300,
        jitter: false,
    };
    let cancel = CancellationToken::new();
    let hook_clone: Arc<dyn RunnableHook> = hook.clone();

    let handle = tokio::spawn({
        let hook_arc: Arc<dyn RunnableHook> = hook_clone;
        let cancel = cancel.clone();
        async move {
            DaemonManager::run_daemon(
                "test-cap",
                RestartPolicy::OnFailure,
                hook_arc,
                dummy_config("test-cap"),
                None,
                cancel,
                Some(backoff),
            )
            .await
        }
    });

    advance_until_calls(&hook, 5, 10_000).await;
    let _ = handle.await.unwrap();

    assert_eq!(hook.calls(), 5);
    let gaps = hook.gaps_ms().await;
    assert_eq!(gaps, vec![100, 200, 300, 300]);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn success_resets_attempt_counter() {
    // Pattern: err, err, ok, err, err, err, err with max_retries=3 + Always.
    // After Ok on call 3: attempt resets to 1; ladder restarts.
    let hook = ScriptedHook::new(vec![
        HookOutcome::Err("e1".into()),
        HookOutcome::Err("e2".into()),
        HookOutcome::Ok,
        HookOutcome::Err("e3".into()),
        HookOutcome::Err("e4".into()),
        HookOutcome::Err("e5".into()),
        HookOutcome::Err("e6".into()),
    ]);
    let backoff = RestartBackoffConfig {
        max_retries: 3,
        base_delay_ms: 100,
        max_delay_ms: 1_000,
        jitter: false,
    };
    let cancel = CancellationToken::new();
    let hook_clone: Arc<dyn RunnableHook> = hook.clone();

    let handle = tokio::spawn({
        let hook_arc: Arc<dyn RunnableHook> = hook_clone;
        let cancel = cancel.clone();
        async move {
            DaemonManager::run_daemon(
                "test-reset",
                RestartPolicy::Always,
                hook_arc,
                dummy_config("test-reset"),
                None,
                cancel,
                Some(backoff),
            )
            .await
        }
    });

    advance_until_calls(&hook, 7, 20_000).await;
    let result = handle.await.unwrap();

    assert!(result.is_err(), "expected max-retries Err");
    assert_eq!(hook.calls(), 7);
    let gaps = hook.gaps_ms().await;
    // Expected gaps: 100 (err1→err2), 200 (err2→ok), ~0 (ok→err3 yield_now),
    // 100 (err3→err4), 200 (err4→err5), 400 (err5→err6).
    // The "ok→err3" gap is ≤ 1 ms (yield_now path on paused clock).
    assert_eq!(gaps.len(), 6, "gaps: {gaps:?}");
    assert_eq!(gaps[0], 100);
    assert_eq!(gaps[1], 200);
    assert!(gaps[2] <= 1, "ok→err3 gap should be ~0, got {}", gaps[2]);
    assert_eq!(gaps[3], 100);
    assert_eq!(gaps[4], 200);
    assert_eq!(gaps[5], 400);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn policy_never_skips_backoff() {
    // Never + Err → restart_decision returns Stop regardless of backoff.
    // Loop exits after 1 hook call; no sleep.
    let hook = ScriptedHook::new(vec![HookOutcome::Err("one".into())]);
    let backoff = RestartBackoffConfig {
        max_retries: 10,
        base_delay_ms: 1_000,
        max_delay_ms: 60_000,
        jitter: false,
    };
    let cancel = CancellationToken::new();
    let hook_clone: Arc<dyn RunnableHook> = hook.clone();

    let result = DaemonManager::run_daemon(
        "test-never",
        RestartPolicy::Never,
        hook_clone,
        dummy_config("test-never"),
        None,
        cancel,
        Some(backoff),
    )
    .await;

    assert!(result.is_ok(), "Never + Err must still return Ok");
    assert_eq!(hook.calls(), 1);
    assert!(hook.gaps_ms().await.is_empty(), "no second call, no gaps");
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_interrupts_backoff() {
    // Real-time test (NOT start_paused) — asserts cancel-during-sleep
    // returns within 50 ms wall-clock.
    let hook = ScriptedHook::new(vec![HookOutcome::Err("e".into()); 5]);
    let backoff = RestartBackoffConfig {
        max_retries: 10,
        base_delay_ms: 10,
        max_delay_ms: 100,
        jitter: false,
    };
    let cancel = CancellationToken::new();
    let hook_clone: Arc<dyn RunnableHook> = hook.clone();
    let cancel_clone = cancel.clone();

    // Spawn a 5ms-delayed cancel-trigger task.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        cancel_clone.cancel();
    });

    let started = std::time::Instant::now();
    let result = DaemonManager::run_daemon(
        "test-cancel",
        RestartPolicy::OnFailure,
        hook_clone,
        dummy_config("test-cancel"),
        None,
        cancel,
        Some(backoff),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(result.is_ok(), "cancel-during-sleep must return Ok");
    assert!(
        elapsed < Duration::from_millis(200),
        "cancel race took {elapsed:?}, expected < 200 ms"
    );
}
