//! Slice C `TriggerSource` trait + 5 concrete impls + `resolve_trigger`
//! pure router + `parse_schedule_string` minimal parser. Implements AC-14
//! (5 trigger-config variants route correctly).
//!
//! Each `TriggerConfig` variant from PRD §9.5 (Schedule / FileWatch /
//! Webhook / AnyOf / TriggerEvent) maps to a `Box<dyn TriggerSource>` via
//! the pure `resolve_trigger` router. The unified `WatcherDriver
//! ::run_with_trigger_source` (see `watcher.rs`) drives the resolved
//! source, sending each `TriggerFireEvent` through to the runnable hook.
//!
//! Iron Rule §3 scope discipline: Slice C ships the trait surfaces +
//! mock-driven verification only. Real notify-crate-backed FileWatch +
//! real HTTP-listener-backed Webhook + full 5-field cron-expression
//! parser are all formally declared in `waived_scope`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::contracts::TriggerBusDispatch;
use crate::hook::{FileWatchSource, HookError, WebhookSource};
use crate::trigger_bus::TriggerBusDispatchImpl;
use crate::types::{
    SpawnError, SubscriptionId, TriggerConfig, TriggerContext, TriggerSubscription, WebhookConfig,
};

/// Event delivered by a `TriggerSource` to the watcher's drain loop.
/// `trigger_type` is one of "schedule" / "file-watch" / "webhook" /
/// "trigger-event" (used by observability + downstream emit telemetry).
/// `trigger_context` is None for Schedule (no event-payload context);
/// FileWatch / Webhook / TriggerEvent producer impls populate it with
/// the originating-event metadata when available (Slice C: test mocks
/// can leave as None).
#[derive(Debug, Clone)]
pub struct TriggerFireEvent {
    pub trigger_type: &'static str,
    pub trigger_context: Option<TriggerContext>,
}

/// Slice C scheduler-local trait. Each `TriggerConfig` variant has a
/// concrete impl that runs a producer task sending `TriggerFireEvent`
/// records to `tx`. Cancellation via the shared `CancellationToken`.
/// Returns `Err(HookError)` on non-cancel terminal failure (e.g.
/// non-whitelisted subscription rejection in `TriggerEventSource`).
#[async_trait]
pub trait TriggerSource: Send + Sync {
    async fn run(
        &self,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError>;
}

// ---- 5 concrete impls ----

/// Schedule variant: real `tokio::time::interval` periodic firing. The
/// `Duration` is parsed from the `Schedule(string)` config by
/// `parse_schedule_string` (Slice C accepts every-Nms/Ns/Nm/Nh literals;
/// 5-field cron strings are explicitly rejected at parse time).
pub struct ScheduleTriggerSource {
    pub interval: Duration,
}

#[async_trait]
impl TriggerSource for ScheduleTriggerSource {
    async fn run(
        &self,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        // `parse_schedule_string` rejects zero-duration at parse time;
        // defense in depth: also reject here so direct construction
        // doesn't panic `tokio::time::interval`.
        if self.interval.is_zero() {
            return Err(HookError::Failure(
                "ScheduleTriggerSource interval must be > Duration::ZERO".into(),
            ));
        }
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // First tick fires immediately; consume so callers see delay-then-fire.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = ticker.tick() => {
                    let evt = TriggerFireEvent {
                        trigger_type: "schedule",
                        trigger_context: None,
                    };
                    if tx.send(evt).await.is_err() {
                        // Receiver dropped — watcher exited; we're done.
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// FileWatch variant: delegates to a `FileWatchSource` plug-in. Slice C
/// ships only the trait + this thin adapter; real notify-crate impl is
/// formally declared in `waived_scope`. Production callers inject a
/// concrete `Arc<dyn FileWatchSource>` (test code uses a synthetic mock
/// that emits canned events).
pub struct FileWatchTriggerSource {
    pub glob: String,
    pub source: Arc<dyn FileWatchSource>,
}

#[async_trait]
impl TriggerSource for FileWatchTriggerSource {
    async fn run(
        &self,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        self.source.run(self.glob.clone(), tx, cancel).await
    }
}

/// Webhook variant: delegates to a `WebhookSource` plug-in. Slice C ships
/// only the trait + this thin adapter; real HTTP-listener impl is
/// formally declared in `waived_scope`.
pub struct WebhookTriggerSource {
    pub cfg: WebhookConfig,
    pub source: Arc<dyn WebhookSource>,
}

#[async_trait]
impl TriggerSource for WebhookTriggerSource {
    async fn run(
        &self,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        self.source.run(self.cfg.clone(), tx, cancel).await
    }
}

/// AnyOf variant: composes N child sources. Each child runs in its own
/// `tokio::spawn`-ed task with a clone of the shared `tx`; any child's
/// fire reaches the watcher's drain loop.
///
/// **Semantics** (Slice C):
/// - Sibling children run independently — one child's error does NOT
///   terminate siblings; the producer side stays alive as long as at
///   least one child is alive.
/// - When ALL children have completed (Ok or Err), AnyOf::run also
///   returns. If at least one child returned `Err(HookError)`, the
///   first observed child error is propagated to the caller; otherwise
///   `Ok(())`. This closes the silent-stuck-watcher bug that an empty
///   AnyOf or an AnyOf of all-failing children would otherwise create
///   (every child Err → silent infinite cancel-await).
/// - On caller cancel, all child handles are aborted and AnyOf::run
///   returns `Ok(())`.
///
/// Children are `Arc<dyn TriggerSource>` (NOT `Box`) so the spawned task
/// can satisfy `'static` lifetime without consuming `&self`. The
/// `resolve_trigger` router constructs `Arc::from(boxed)` per child.
pub struct AnyOfTriggerSource {
    pub children: Vec<Arc<dyn TriggerSource>>,
}

#[async_trait]
impl TriggerSource for AnyOfTriggerSource {
    async fn run(
        &self,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        // Empty AnyOf: nothing to do; return Ok immediately.
        if self.children.is_empty() {
            return Ok(());
        }
        // Spawn children with a one-shot result channel each so the
        // parent can observe completions + collect terminal errors.
        let mut handles = Vec::with_capacity(self.children.len());
        let (result_tx, mut result_rx) =
            mpsc::channel::<Result<(), HookError>>(self.children.len());
        for child in &self.children {
            let child = Arc::clone(child);
            let tx = tx.clone();
            let cancel = cancel.clone();
            let result_tx = result_tx.clone();
            let handle = tokio::spawn(async move {
                let outcome = child.run(tx, cancel).await;
                let _ = result_tx.send(outcome).await; // best-effort
            });
            handles.push(handle);
        }
        // Drop our own clone so result_rx closes once all children exit.
        drop(result_tx);
        let mut first_err: Option<HookError> = None;
        let mut completed = 0usize;
        let total = self.children.len();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                next = result_rx.recv() => {
                    match next {
                        Some(Ok(())) => {
                            completed += 1;
                            if completed >= total { break; }
                        }
                        Some(Err(e)) => {
                            // Sibling continues running; record first
                            // error so the caller can surface it when
                            // all siblings have exited.
                            if first_err.is_none() {
                                first_err = Some(e);
                            }
                            completed += 1;
                            if completed >= total { break; }
                        }
                        None => break, // all child senders dropped
                    }
                }
            }
        }
        // Slice C adversarial round 1 fix: surface child panics by
        // checking JoinHandle::Err(is_panic) after abort. A panicked
        // child's `result_tx.send` never fires (the task unwinds before
        // reaching it), so the result-channel path silently drops the
        // panic. We catch it via the JoinHandle's terminal state here.
        // - Aborted siblings → JoinError::is_cancelled (ignored).
        // - Panicked siblings → JoinError::is_panic (record as
        //   first_err if not already set).
        // - Normally-completed siblings → Ok (their result_tx send
        //   already surfaced via the loop above).
        for h in handles {
            h.abort();
            match h.await {
                Err(join_err) if join_err.is_panic() => {
                    if first_err.is_none() {
                        first_err = Some(HookError::Failure(format!(
                            "AnyOfTriggerSource child panicked: {join_err}"
                        )));
                    }
                }
                _ => {}
            }
        }
        // Surface any error observed during the lifetime (whether
        // pre-cancel or post-loop). Cancel-only-no-error → Ok. Cancel
        // with a prior error recorded → Err (closes the
        // adversarial-round Warning that hid in-flight rejections).
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// TriggerEvent variant: wraps an existing Slice B
/// `TriggerBusDispatchImpl` subscription. On REJECTED (non-whitelisted
/// event or over-cap), returns `Err(HookError::Failure(...))` so the
/// watcher caller can surface admission failures.
pub struct TriggerEventSource {
    pub sub: TriggerSubscription,
    pub dispatcher: Arc<TriggerBusDispatchImpl>,
}

#[async_trait]
impl TriggerSource for TriggerEventSource {
    async fn run(
        &self,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        let sub_id = self.dispatcher.subscribe(self.sub.clone());
        if sub_id == SubscriptionId::REJECTED {
            return Err(HookError::Failure(
                "TriggerEventSource subscription rejected (non-whitelisted event_type or over-cap)"
                    .into(),
            ));
        }
        // RAII unsubscribe on drop (any exit path).
        let _guard = UnsubscribeOnDrop {
            dispatcher: Arc::clone(&self.dispatcher),
            sub_id,
        };
        let poll_interval = Duration::from_millis(25);
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let drained = self.dispatcher.drain_for_subscription(sub_id);
            for entry in drained {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                let evt = TriggerFireEvent {
                    trigger_type: "trigger-event",
                    // sched-harvest 1B (SYS-AC-101): the drained entry's
                    // chain context now flows through the unified watcher
                    // path into the runnable's `ComponentConfig`
                    // (run_with_trigger_source passes it verbatim). See
                    // `DispatchedEntry::to_trigger_context` for the
                    // bounded-echo payload discipline.
                    trigger_context: Some(entry.to_trigger_context()),
                };
                if tx.send(evt).await.is_err() {
                    return Ok(()); // receiver dropped
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(poll_interval) => {}
            }
        }
    }
}

/// RAII unsubscribe guard for `TriggerEventSource`. On any exit path
/// (Ok, Err, panic unwind, cancel), the subscription is cleaned up.
struct UnsubscribeOnDrop {
    dispatcher: Arc<TriggerBusDispatchImpl>,
    sub_id: SubscriptionId,
}

impl Drop for UnsubscribeOnDrop {
    fn drop(&mut self) {
        self.dispatcher.unsubscribe(self.sub_id);
    }
}

// ---- Pure router function ----

/// Parse a "schedule string" into a `Duration`. Accepts:
/// - `"every-Nms"` → N milliseconds
/// - `"every-Ns"`  → N seconds
/// - `"every-Nm"`  → N minutes
/// - `"every-Nh"`  → N hours
///
/// Suffix matching is **longest-first** (ms matches before s) to
/// disambiguate `every-100ms` from `every-100s`.
///
/// Defensive rejections:
/// - Missing `every-` prefix → `InvalidConfig` (e.g. 5-field cron
///   strings like `"*/5 * * * *"`).
/// - Unrecognized suffix → `InvalidConfig`.
/// - Non-numeric integer prefix → `InvalidConfig`.
/// - Zero duration (would panic `tokio::time::interval`) → `InvalidConfig`.
/// - u64 multiplier overflow → `InvalidConfig`.
///
/// Full 5-field cron-expression parser is formally declared in
/// `waived_scope` — a follow-up slice's concern.
pub fn parse_schedule_string(s: &str) -> Result<Duration, SpawnError> {
    let body = s.strip_prefix("every-").ok_or_else(|| {
        SpawnError::InvalidConfig(format!(
            "schedule string {:?} must start with \"every-\" (5-field cron expressions \
             like \"*/5 * * * *\" are not supported; full cron parser deferred to a \
             follow-up slice)",
            s
        ))
    })?;
    // Inline helper: parse u64 then convert via multiplier (ms) to
    // Duration with zero + overflow rejection.
    fn make_duration(
        n_str: &str,
        multiplier_ms: u64,
        unit: &str,
        full_s: &str,
    ) -> Result<Duration, SpawnError> {
        let n: u64 = n_str.parse().map_err(|_| {
            SpawnError::InvalidConfig(format!(
                "schedule {:?}: invalid integer prefix before {:?} suffix",
                full_s, unit
            ))
        })?;
        if n == 0 {
            return Err(SpawnError::InvalidConfig(format!(
                "schedule {:?}: zero-duration not allowed (would panic tokio::time::interval)",
                full_s
            )));
        }
        let total_ms = n.checked_mul(multiplier_ms).ok_or_else(|| {
            SpawnError::InvalidConfig(format!(
                "schedule {:?}: duration {}{} overflows u64 milliseconds",
                full_s, n, unit
            ))
        })?;
        Ok(Duration::from_millis(total_ms))
    }
    // Longest-suffix-first: ms before s.
    if let Some(n_str) = body.strip_suffix("ms") {
        return make_duration(n_str, 1, "ms", s);
    }
    if let Some(n_str) = body.strip_suffix('s') {
        return make_duration(n_str, 1_000, "s", s);
    }
    if let Some(n_str) = body.strip_suffix('m') {
        return make_duration(n_str, 60_000, "m", s);
    }
    if let Some(n_str) = body.strip_suffix('h') {
        return make_duration(n_str, 3_600_000, "h", s);
    }
    Err(SpawnError::InvalidConfig(format!(
        "schedule {:?}: unrecognized suffix; expected ms/s/m/h",
        s
    )))
}

/// Maximum nesting depth for `TriggerConfig::AnyOf` recursion in
/// `resolve_trigger`. Slice C: a hard fail-closed cap protects the host
/// stack against programmatic (non-serde) callers passing deeply nested
/// `AnyOf` trees. The serde Deserialize path already caps `AnyOf` width
/// at `MAX_ANY_OF` (per `crates/scheduler/src/types.rs`); this depth cap
/// extends the protection to in-process callers that build
/// `TriggerConfig` programmatically (no serde gate). 8 levels is well
/// beyond any plausible scheduling topology; deeper trees fail with
/// `SpawnError::InvalidConfig`.
pub const MAX_TRIGGER_NESTING_DEPTH: usize = 8;

/// Pure router. Resolves a `TriggerConfig` to a concrete
/// `Box<dyn TriggerSource>`. Recursive for `AnyOf(children)`; depth
/// bounded by `MAX_TRIGGER_NESTING_DEPTH` (fail-closed).
///
/// Conversions:
/// - Each child of `AnyOf` is recursively resolved to
///   `Box<dyn TriggerSource>`, then converted to `Arc<dyn TriggerSource>`
///   via the std-library `impl<T: ?Sized> From<Box<T>> for Arc<T>` so
///   `AnyOfTriggerSource::run` can `tokio::spawn`-clone them.
pub fn resolve_trigger(
    cfg: TriggerConfig,
    dispatcher: Arc<TriggerBusDispatchImpl>,
    file_source: Arc<dyn FileWatchSource>,
    webhook_source: Arc<dyn WebhookSource>,
) -> Result<Box<dyn TriggerSource>, SpawnError> {
    resolve_trigger_at_depth(cfg, dispatcher, file_source, webhook_source, 0)
}

fn resolve_trigger_at_depth(
    cfg: TriggerConfig,
    dispatcher: Arc<TriggerBusDispatchImpl>,
    file_source: Arc<dyn FileWatchSource>,
    webhook_source: Arc<dyn WebhookSource>,
    depth: usize,
) -> Result<Box<dyn TriggerSource>, SpawnError> {
    if depth > MAX_TRIGGER_NESTING_DEPTH {
        return Err(SpawnError::InvalidConfig(format!(
            "TriggerConfig::AnyOf nesting depth {} exceeds MAX_TRIGGER_NESTING_DEPTH {} (host stack guard)",
            depth, MAX_TRIGGER_NESTING_DEPTH
        )));
    }
    match cfg {
        TriggerConfig::Schedule(s) => {
            let interval = parse_schedule_string(&s)?;
            Ok(Box::new(ScheduleTriggerSource { interval }))
        }
        TriggerConfig::FileWatch(glob) => Ok(Box::new(FileWatchTriggerSource {
            glob,
            source: file_source,
        })),
        TriggerConfig::Webhook(cfg) => Ok(Box::new(WebhookTriggerSource {
            cfg,
            source: webhook_source,
        })),
        TriggerConfig::AnyOf(children) => {
            let resolved: Result<Vec<Arc<dyn TriggerSource>>, SpawnError> = children
                .into_iter()
                .map(|c| {
                    resolve_trigger_at_depth(
                        c,
                        Arc::clone(&dispatcher),
                        Arc::clone(&file_source),
                        Arc::clone(&webhook_source),
                        depth + 1,
                    )
                    .map(|boxed| -> Arc<dyn TriggerSource> { Arc::from(boxed) })
                })
                .collect();
            Ok(Box::new(AnyOfTriggerSource {
                children: resolved?,
            }))
        }
        TriggerConfig::TriggerEvent(sub) => Ok(Box::new(TriggerEventSource { sub, dispatcher })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_every_ms_returns_milliseconds() {
        assert_eq!(
            parse_schedule_string("every-50ms").unwrap(),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn parse_every_s_returns_seconds() {
        assert_eq!(
            parse_schedule_string("every-5s").unwrap(),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn parse_every_m_returns_minutes() {
        assert_eq!(
            parse_schedule_string("every-5m").unwrap(),
            Duration::from_secs(5 * 60)
        );
    }

    #[test]
    fn parse_every_h_returns_hours() {
        assert_eq!(
            parse_schedule_string("every-2h").unwrap(),
            Duration::from_secs(2 * 3600)
        );
    }

    #[test]
    fn parse_5_field_cron_rejected() {
        let err = parse_schedule_string("*/5 * * * *").unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn parse_missing_every_prefix_rejected() {
        let err = parse_schedule_string("50ms").unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn parse_invalid_integer_rejected() {
        let err = parse_schedule_string("every-abcms").unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn parse_zero_duration_rejected_ms() {
        let err = parse_schedule_string("every-0ms").unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn parse_zero_duration_rejected_s() {
        let err = parse_schedule_string("every-0s").unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn parse_unrecognized_suffix_rejected() {
        let err = parse_schedule_string("every-5d").unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn parse_longest_suffix_first_disambiguates_ms_vs_s() {
        // "every-100ms" → ms arm (100 ms), NOT s arm (would be 100 s).
        assert_eq!(
            parse_schedule_string("every-100ms").unwrap(),
            Duration::from_millis(100)
        );
        assert_eq!(
            parse_schedule_string("every-100s").unwrap(),
            Duration::from_secs(100)
        );
    }
}
