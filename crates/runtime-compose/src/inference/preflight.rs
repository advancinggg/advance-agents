//! Claimed-entry preflight through the composed gateway (CONTRACT-244 D2(b)).

use std::collections::BTreeSet;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use advance_home::provider_admin::ClaimedEntryPreflight;
use advance_home::{CancelToken, PreflightFail};
use cap_llm::LlmGateway;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

struct PreflightShared {
    tracker: TaskTracker,
    stop: CancellationToken,
    /// Held across the closed-check and `spawn_on`, and across close: `TaskTracker`
    /// still spawns after `close()`, so without this mutex a preflight could pass
    /// the check, the stopper could finish `wait()` on an empty tracker, and the
    /// task would then hold a strong `Arc<LlmGateway>` past step 1.
    closed: Mutex<bool>,
}

/// `:preflight` of claimed local entries, dispatched on the composition runtime.
pub(crate) struct ComposedClaimedPreflight {
    gateway: Weak<LlmGateway>,
    claimed: BTreeSet<String>,
    rt: Handle,
    shared: Arc<PreflightShared>,
}

/// Shutdown step 1: refuse new preflights, cancel running ones, await them (bounded).
pub(crate) struct ClaimedPreflightStopper {
    shared: Arc<PreflightShared>,
}

const PREFLIGHT_GRACE: Duration = Duration::from_secs(1);

impl ComposedClaimedPreflight {
    pub(crate) fn new(
        gateway: &Arc<LlmGateway>,
        claimed: BTreeSet<String>,
    ) -> (Self, ClaimedPreflightStopper) {
        let shared = Arc::new(PreflightShared {
            tracker: TaskTracker::new(),
            stop: CancellationToken::new(),
            closed: Mutex::new(false),
        });
        (
            Self {
                gateway: Arc::downgrade(gateway),
                claimed,
                rt: Handle::current(),
                shared: Arc::clone(&shared),
            },
            ClaimedPreflightStopper { shared },
        )
    }

    #[cfg(test)]
    fn tracker_len(&self) -> usize {
        self.shared.tracker.len()
    }
}

impl ClaimedPreflightStopper {
    /// Shutdown step 1: refuse new preflights, cancel running ones, await them (bounded).
    pub(crate) async fn stop(self, bound: Duration) -> bool {
        *self
            .shared
            .closed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        self.shared.stop.cancel();
        self.shared.tracker.close();
        tokio::time::timeout(bound, self.shared.tracker.wait())
            .await
            .is_ok()
    }
}

/// Resolves once `t` is cancelled (the admin's deadline timer or the caller).
async fn until_cancelled(t: &CancelToken) {
    while !t.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

impl ClaimedEntryPreflight for ComposedClaimedPreflight {
    fn is_claimed(&self, id: &str) -> bool {
        self.claimed.contains(id)
    }

    fn preflight(
        &self,
        id: &str,
        cancel: &CancelToken,
        budget: Duration,
    ) -> Result<(), PreflightFail> {
        let (tx, rx) = mpsc::sync_channel(1);
        {
            let closed = self
                .shared
                .closed
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *closed {
                return Err(PreflightFail::Cancelled);
            }
            let Some(gateway) = self.gateway.upgrade() else {
                return Err(PreflightFail::Cancelled);
            };
            let (id, flag, stop) = (id.to_string(), cancel.clone(), self.shared.stop.clone());
            self.shared.tracker.spawn_on(
                async move {
                    let verdict = tokio::select! {
                        biased;
                        _ = stop.cancelled() => Err(PreflightFail::Cancelled),
                        _ = until_cancelled(&flag) => Err(PreflightFail::Cancelled),
                        r = gateway.preflight_provider(&id, flag.as_atomic()) => match r {
                            Ok(()) => Ok(()),
                            Err(_) if flag.is_cancelled() => Err(PreflightFail::Cancelled),
                            Err(e) => Err(PreflightFail::ProviderRejected {
                                reason: e.variant_name().to_string(),
                            }),
                        },
                    };
                    drop(gateway);
                    let _ = tx.send(verdict);
                },
                &self.rt,
            );
        }
        rx.recv_timeout(budget + PREFLIGHT_GRACE)
            .unwrap_or(Err(PreflightFail::Cancelled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Instant;

    use advance_runtime::config::RuntimeConfig;
    use advance_shared_types::inference::{
        InferenceBackendError, InferenceBackendPort, InferenceChatRequest, InferenceChatResponse,
        InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream, InferenceStreamHead,
    };
    use advance_shared_types::security_validator::{
        HttpCapability, HttpError, HttpRequest, HttpResponse, HttpResponseHead, HttpStreamingChain,
        LeakDetector, ScanContext, ScanResult, TransportErrorKind,
    };
    use advance_shared_types::traits::{EventBusEmit, LlmDeltaSink, RepetitionGuardCheck};
    use async_trait::async_trait;
    use cap_llm::{LlmGateway, StaticConfig};

    use crate::wiring::{build_llm_gateway_with, GatewayInference};

    const LOCAL_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: local-a
    endpoint: ""
    api-key-secret: local-a-api-key
    model-aliases:
      llama: llama
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    backend-class: local
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
circuit-breakers: []
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
users: []
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

    struct StubChain;

    #[async_trait]
    impl advance_shared_types::security_validator::HttpSecurityChain for StubChain {
        async fn execute(
            &self,
            _agent_id: &str,
            _req: HttpRequest,
            _cap: &HttpCapability,
        ) -> Result<HttpResponse, HttpError> {
            Err(HttpError::Transport(TransportErrorKind::Other))
        }
    }

    #[async_trait]
    impl HttpStreamingChain for StubChain {
        async fn execute_streaming(
            &self,
            _agent_id: &str,
            _req: HttpRequest,
            _cap: &HttpCapability,
        ) -> Result<
            (
                HttpResponseHead,
                Box<dyn advance_shared_types::security_validator::HttpBodyStream>,
            ),
            HttpError,
        > {
            Err(HttpError::Transport(TransportErrorKind::Other))
        }
    }

    struct StubLeak;

    impl LeakDetector for StubLeak {
        fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
            ScanResult::Clean
        }
        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    fn ok_chat() -> InferenceChatResponse {
        InferenceChatResponse {
            text: "pong".into(),
            model: "llama".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
        }
    }

    struct RecordingPort {
        calls: AtomicUsize,
        last: Mutex<Option<InferenceChatRequest>>,
        hang: bool,
    }

    #[async_trait]
    impl InferenceBackendPort for RecordingPort {
        async fn chat(
            &self,
            req: InferenceChatRequest,
        ) -> Result<InferenceChatResponse, InferenceBackendError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().unwrap() = Some(req);
            if self.hang {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Ok(ok_chat())
        }
        async fn embed(
            &self,
            _req: InferenceEmbedRequest,
        ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
            Err(InferenceBackendError::Unwired)
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError>
        {
            Err(InferenceBackendError::Unwired)
        }
        fn is_wired(&self) -> bool {
            true
        }
    }

    fn boot() -> Arc<RuntimeConfig> {
        Arc::new(serde_yml::from_str(LOCAL_YAML).expect("fixture RuntimeConfig parses"))
    }

    fn gateway_with(port: Arc<RecordingPort>) -> Arc<LlmGateway> {
        let mut claims = std::collections::BTreeMap::new();
        claims.insert(
            "local-a".to_string(),
            Arc::clone(&port) as Arc<dyn InferenceBackendPort>,
        );
        let chain = Arc::new(StubChain);
        build_llm_gateway_with(
            Arc::new(StaticConfig(boot())),
            chain.clone(),
            chain,
            Arc::new(StubLeak),
            Arc::new(cap_llm::PreflightAllowBudget),
            Arc::new(cap_llm::DiscardEventBus) as Arc<dyn EventBusEmit>,
            Arc::new(cap_llm::NoopRepetition) as Arc<dyn RepetitionGuardCheck>,
            "root".into(),
            Arc::new(advance_shared_types::traits::NotWiredDeltaSink) as Arc<dyn LlmDeltaSink>,
            None,
            None,
            GatewayInference {
                claims,
                ..GatewayInference::none()
            },
        )
    }

    fn recording(hang: bool) -> Arc<RecordingPort> {
        Arc::new(RecordingPort {
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
            hang,
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn module_001_ac31_claimed_preflight_runs_on_the_composed_gateway() {
        let inner = recording(false);
        let gateway = gateway_with(Arc::clone(&inner));
        let claimed = BTreeSet::from(["local-a".to_string()]);
        let (port, stopper) = ComposedClaimedPreflight::new(&gateway, claimed);
        let port = Arc::new(port);
        assert!(port.is_claimed("local-a"));
        assert!(!port.is_claimed("other"));
        let called = Arc::clone(&port);
        let verdict = std::thread::spawn(move || {
            called.preflight("local-a", &CancelToken::new(), Duration::from_secs(5))
        })
        .join()
        .expect("std thread");
        assert_eq!(verdict, Ok(()));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        let last = inner.last.lock().unwrap();
        assert_eq!(
            last.as_ref().map(|r| r.provider_id.as_str()),
            Some("local-a")
        );
        assert!(stopper.stop(Duration::from_secs(1)).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn module_001_ac31_claimed_preflight_cancel_token_and_stop_end_the_task() {
        let inner = recording(true);
        let gateway = gateway_with(Arc::clone(&inner));
        let (port, stopper) =
            ComposedClaimedPreflight::new(&gateway, BTreeSet::from(["local-a".to_string()]));
        let port = Arc::new(port);
        let cancel = CancelToken::new();
        let flag = cancel.clone();
        let called = Arc::clone(&port);
        let join =
            std::thread::spawn(move || called.preflight("local-a", &flag, Duration::from_secs(5)));
        let started = Instant::now();
        while inner.calls.load(Ordering::SeqCst) == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "hanging port was never entered"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancel.cancel();
        assert_eq!(
            join.join().expect("std thread"),
            Err(PreflightFail::Cancelled)
        );
        assert!(stopper.stop(Duration::from_secs(1)).await);
        assert_eq!(port.tracker_len(), 0);
        let calls = inner.calls.load(Ordering::SeqCst);
        assert_eq!(
            port.preflight("local-a", &CancelToken::new(), Duration::from_secs(1)),
            Err(PreflightFail::Cancelled)
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), calls);
        assert_eq!(port.tracker_len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn module_001_ac31_claimed_preflight_is_bounded_when_called_on_the_runtime_worker() {
        let inner = recording(false);
        let gateway = gateway_with(Arc::clone(&inner));
        let (port, stopper) =
            ComposedClaimedPreflight::new(&gateway, BTreeSet::from(["local-a".to_string()]));
        let start = Instant::now();
        let verdict = port.preflight("local-a", &CancelToken::new(), Duration::from_millis(50));
        let elapsed = start.elapsed();
        assert_eq!(verdict, Err(PreflightFail::Cancelled));
        assert!(
            elapsed >= Duration::from_millis(1000) && elapsed < Duration::from_secs(2),
            "expected about 1.05s, got {elapsed:?}"
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
        assert!(stopper.stop(Duration::from_secs(1)).await);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    }
}
