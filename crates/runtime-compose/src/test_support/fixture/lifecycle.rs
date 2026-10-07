//! Lifecycle knobs of the neutral fixture.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::api::{BoxFuture, ExtensionError, StartedCx, ViewError};

use super::{FixtureCall, FixtureExtension, FixtureRecord, StartedSnapshot};

#[derive(Clone, Copy, Debug, Default)]
pub struct FixtureLifecycle {
    pub on_started: OnStartedMode,
    pub shutdown: ShutdownMode,
    pub spawn_ticker: bool,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub enum OnStartedMode {
    #[default]
    Record,
    Fail,
    Panic,
    AwaitGate,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub enum ShutdownMode {
    #[default]
    Record,
    Hang,
    Panic,
}

struct TickerGuard(Arc<FixtureRecord>);

impl Drop for TickerGuard {
    fn drop(&mut self) {
        self.0.ticker_dropped.store(true, Ordering::SeqCst);
    }
}

struct OnStartedGuard(Arc<FixtureRecord>);

impl Drop for OnStartedGuard {
    fn drop(&mut self) {
        if !self.0.on_started_returned.load(Ordering::SeqCst) {
            self.0.on_started_dropped.store(true, Ordering::SeqCst);
        }
    }
}

impl FixtureExtension {
    pub(super) fn run_on_started<'a>(
        &'a self,
        cx: &'a StartedCx,
    ) -> BoxFuture<'a, Result<(), ExtensionError>> {
        Box::pin(async move {
            self.push_on_started_call(cx);
            match self.lifecycle.on_started {
                OnStartedMode::Record => {
                    self.store_started(cx);
                    if self.lifecycle.spawn_ticker {
                        self.spawn_ticker(cx)?;
                    }
                    Ok(())
                }
                OnStartedMode::Fail => Err(ExtensionError::new("fixture on_started failure")),
                OnStartedMode::Panic => panic!("fixture on_started panic"),
                OnStartedMode::AwaitGate => {
                    let _guard = OnStartedGuard(Arc::clone(&self.record));
                    self.record.gate.notified().await;
                    self.record
                        .on_started_returned
                        .store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
    }

    pub(super) fn run_shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.record
                .hooks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(self.id);
            match self.lifecycle.shutdown {
                ShutdownMode::Record => {}
                ShutdownMode::Hang => std::future::pending::<()>().await,
                ShutdownMode::Panic => panic!("fixture shutdown panic"),
            }
        })
    }

    fn push_on_started_call(&self, cx: &StartedCx) {
        self.record
            .order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(FixtureCall {
                extension: self.id,
                phase: "on_started",
                at: std::time::Instant::now(),
                discovery_present: cx.home().join(".runtime/client-api").exists(),
                client_api_base: cx.client_api_base().map(str::to_owned),
            });
    }

    fn store_started(&self, cx: &StartedCx) {
        *self
            .record
            .started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(StartedSnapshot {
            cx: cx.cx().clone(),
            client_api_base: cx.client_api_base().map(str::to_owned),
            gateway: cx.gateway().cloned(),
        });
    }

    fn spawn_ticker(&self, cx: &StartedCx) -> Result<(), ViewError> {
        let record = Arc::clone(&self.record);
        cx.tasks().spawn(async move {
            let _guard = TickerGuard(Arc::clone(&record));
            let mut interval = tokio::time::interval(Duration::from_millis(20));
            loop {
                interval.tick().await;
                record.ticks.fetch_add(1, Ordering::SeqCst);
                if record.panic_ticker.swap(false, Ordering::SeqCst) {
                    panic!("fixture ticker panic");
                }
            }
        })
    }
}
