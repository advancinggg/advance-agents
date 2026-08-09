//! S4 composition-root witness (MODULE-009-AC-20, plan §1 "CLI composition
//! identity"): the production wiring MUST install the live streaming path, with
//! the decoded layer receiving the SAME detector instance as the security chain.
//!
//! This is the third anti-fake-green anchor: with the WIT stream path live-ONLY,
//! deleting `install_live_streaming` from `wiring.rs` — precisely how both earlier
//! S4 attempts were withdrawn — makes every production `stream()` return
//! `provider-error("streaming transport not wired")`. Before this test, that
//! one-line regression broke nothing in CI.

use std::sync::Arc;

use advance_shared_types::security_validator::{HttpStreamingChain, LeakDetector};
use advance_shared_types::traits::EventBusEmit;

#[test]
fn s4_production_composition_installs_live_streaming_with_shared_detector() {
    // Build the same objects the composition root builds, then run the PRODUCTION
    // installer function on them.
    let (leak, ssrf, rate) = advance_cli::channels_boot::live_security_components(None);
    let detector_for_gateway: Arc<dyn LeakDetector> = leak.clone();
    // ONE concrete executor coerced to both traits, exactly as the composition
    // root does it.
    let executor = Arc::new(cap_http::ReqwestHttpExecutor::new());
    let chain = Arc::new(
        cap_http::DefaultHttpSecurityChain::new(
            test_secret_store(),
            leak,
            ssrf,
            rate,
            executor.clone() as Arc<dyn cap_http::HttpExecutor>,
        )
        .with_stream_executor(executor as Arc<dyn cap_http::executor::HttpStreamExecutor>),
    );

    // Call THE production constructor — the composition root has no other path to
    // a gateway, so this witnesses the real wiring rather than re-implementing it.
    let wired = advance_cli::wiring::build_llm_gateway(
        Arc::new(StubConfig),
        chain.clone(),
        chain as Arc<dyn HttpStreamingChain>,
        detector_for_gateway.clone(),
        Arc::new(StubBudget),
        Arc::new(StubBus) as Arc<dyn EventBusEmit>,
        Arc::new(StubRep),
        "default-agent".to_string(),
        Arc::new(advance_shared_types::traits::NotWiredDeltaSink)
            as Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
    );
    assert!(
        wired.has_live_streaming(),
        "the production gateway constructor MUST install the live streaming path — \
         deleting install_live_streaming from wiring.rs must fail here"
    );
    assert!(
        wired.decoded_detector_is(&detector_for_gateway),
        "the decoded layer must receive the SAME detector instance as the chain \
         (single scan authority)"
    );

    // And a gateway built without it is unwired (so the assertion above is not
    // vacuously true for every gateway).
    let bare = cap_llm::LlmGateway::new(
        Arc::new(StubConfig),
        Arc::new(cap_http::DefaultHttpSecurityChain::new(
            test_secret_store(),
            Arc::new(cap_http::DefaultLeakDetector::new()),
            Arc::new(cap_http::DefaultSsrfGuard::new()),
            Arc::new(AlwaysAllowRl),
            Arc::new(cap_http::ReqwestHttpExecutor::new()),
        )),
        Arc::new(StubBudget),
        Arc::new(StubBus) as Arc<dyn EventBusEmit>,
        Arc::new(StubRep),
        "default-agent".to_string(),
    );
    assert!(!bare.has_live_streaming());
}

struct AlwaysAllowRl;
impl cap_http::rate_limit::RateLimiter for AlwaysAllowRl {
    fn check(&self, _agent_id: &str, _host: &str) -> Result<(), u64> {
        Ok(())
    }
}

fn test_secret_store() -> Arc<cap_secrets::SecretStore> {
    use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    Arc::new(SecretStore::new(
        zeroize::Zeroizing::new([7u8; 32]),
        storage,
    ))
}

const MIN_CONFIG_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers: []
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

struct StubConfig;
impl advance_runtime::config::RuntimeConfigProvider for StubConfig {
    fn current(&self) -> Arc<advance_runtime::config::RuntimeConfig> {
        Arc::new(serde_yml::from_str(MIN_CONFIG_YAML).expect("fixture config parses"))
    }
    fn subscribe(
        &self,
    ) -> tokio::sync::mpsc::Receiver<Arc<advance_runtime::config::RuntimeConfig>> {
        tokio::sync::mpsc::channel(1).1
    }
    fn last_error(&self) -> Option<String> {
        None
    }
}

struct StubBudget;
impl advance_shared_types::traits::RunBudget for StubBudget {
    fn check(
        &self,
        _r: &str,
        _t: u64,
        _c: f64,
    ) -> advance_shared_types::capability::BudgetDecision {
        advance_shared_types::capability::BudgetDecision::Allow
    }
    fn commit(&self, _r: &str, _t: u64, _c: f64) {}
}

struct StubBus;
impl EventBusEmit for StubBus {
    fn emit(&self, _event: advance_shared_types::event::Event) {}
}

struct StubRep;
impl advance_shared_types::traits::RepetitionGuardCheck for StubRep {
    fn record_tool_call(
        &self,
        _a: &str,
        _s: advance_shared_types::repetition::ToolCallSignature,
    ) -> advance_shared_types::repetition::RepetitionDecision {
        advance_shared_types::repetition::RepetitionDecision::Pass
    }
    fn record_output(
        &self,
        _a: &str,
        _h: advance_shared_types::repetition::OutputHash,
    ) -> advance_shared_types::repetition::RepetitionDecision {
        advance_shared_types::repetition::RepetitionDecision::Pass
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MODULE-009-T120 — turn-end reap through BOTH production observer wiring
// paths (ADR 2026-07-22 D5, tee slice T3; BUILD-AND-HOLD — witness recorded,
// no ledger flip).
//
// The reap seam has two independent production call sites and each case here is
// built to fail on exactly one of them:
//   (i)  `try_spawn_agent_loop`'s root composite (commands/start.rs) — case 1;
//   (ii) the per-child serve loop's composite (perchild_daemon.rs)   — case 2.
// A live stream is planted through the REAL registered `stream` host function
// (a `MockHttpExecutor` gated stream that never yields, so it stays IN-FLIGHT
// across the turn), and the CONTRACT-234 frames are observed on a recording
// sink installed via `LlmGateway::with_delta_sink`.
mod t120 {
    use std::net::IpAddr;
    use std::num::NonZeroUsize;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use advance_cli::commands::start::spawn_test_agent_loop;
    use advance_cli::perchild_daemon::{KeyResolver, PerChildLoopManager};
    use advance_cli::reap::ReapTurnObserver;
    use advance_cli::wiring::wire_capabilities;
    use advance_messaging::{AgentIdBridge, DynamicRouting, MailboxStore};
    use advance_runtime::bootstrap::RuntimeHostBuilder;
    use advance_runtime::capability_injector::CapabilityInjector;
    use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
    use advance_runtime::config::WasmConfig;
    use advance_runtime::host_registry::{
        HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
    };
    use advance_runtime::ComponentRuntime;
    use advance_scheduler::TurnObserver as _;
    use advance_shared_types::agent_tree::{
        AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader,
    };
    use advance_shared_types::capability::{BudgetDecision, CapParams, GrantDecision};
    use advance_shared_types::mailbox::{Message, MessageKind};
    use advance_shared_types::security_validator::{
        HttpResponseHead, HttpStreamingChain, LeakDetector, SsrfGuard,
    };
    use advance_shared_types::traits::{
        EventBusEmit, GrantCheck, LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink, LlmTerminalReason,
        RunBudget,
    };
    use cap_http::executor::{HttpStreamExecutor, StreamGate};
    use cap_http::{
        DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, MockHttpExecutor,
        MockResolver,
    };
    use cap_lifecycle::{
        AgentTreeStore, DefaultSpawner, SpawnChildConfig, SpawnError, SpawnObserver, Spawner,
        SpawnerSubsetGate,
    };
    use cap_llm::{register_agent_llm_with_turn_cost, AgentStreamReaper, LlmGateway};
    use tempfile::TempDir;
    use wasmtime::component::Val;
    use wit_component::ComponentEncoder;

    const SKELETON_CORE: &[u8] =
        include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
    // Import-free child guest: instantiates with EMPTY caps and serves
    // `handle-message` turns (the sys_j68 per-child precedent driver).
    const CHILD_CORE: &[u8] =
        include_bytes!("../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");

    const ROOT_BARE: &str = "default-agent";
    const ROOT_COLON: &str = "agent:default";
    const CHILD_BARE: &str = "tchild";
    const CHILD_COLON: &str = "agent:tchild";

    // ── the tee-side rig: recording sink + gated live stream + real host fns ──

    /// Records every published frame. `is_wired` stays the default `true` and is
    /// constant for the sink's lifetime (trait invariant 3b).
    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<LlmDeltaEvent>>);

    impl RecordingSink {
        fn frames(&self) -> Vec<LlmDeltaEvent> {
            self.0.lock().unwrap().clone()
        }
        fn terminals_for(&self, agent: &str) -> Vec<LlmDeltaEvent> {
            self.frames()
                .into_iter()
                .filter(|e| {
                    &*e.agent_id == agent && matches!(e.frame, LlmDeltaFrame::Terminal { .. })
                })
                .collect()
        }
        async fn wait_terminal(&self, agent: &str, max: Duration) -> Option<LlmDeltaEvent> {
            let deadline = std::time::Instant::now() + max;
            loop {
                if let Some(t) = self.terminals_for(agent).into_iter().next() {
                    return Some(t);
                }
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }

    impl LlmDeltaSink for RecordingSink {
        fn publish(&self, event: LlmDeltaEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    /// Counts `RunBudget::commit` calls so "billing settled ONCE" is assertable.
    #[derive(Default)]
    struct CountingBudget(AtomicUsize);

    impl CountingBudget {
        fn commits(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl RunBudget for CountingBudget {
        fn check(&self, _r: &str, _t: u64, _c: f64) -> BudgetDecision {
            BudgetDecision::Allow
        }
        fn commit(&self, _r: &str, _t: u64, _c: f64) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    const TEE_CONFIG_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt4o: gpt-4o-2024-08-06
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
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

    struct TeeConfig;
    impl advance_runtime::config::RuntimeConfigProvider for TeeConfig {
        fn current(&self) -> Arc<advance_runtime::config::RuntimeConfig> {
            Arc::new(serde_yml::from_str(TEE_CONFIG_YAML).expect("tee fixture config parses"))
        }
        fn subscribe(
            &self,
        ) -> tokio::sync::mpsc::Receiver<Arc<advance_runtime::config::RuntimeConfig>> {
            tokio::sync::mpsc::channel(1).1
        }
        fn last_error(&self) -> Option<String> {
            None
        }
    }

    struct TeeRig {
        reaper: Arc<AgentStreamReaper>,
        stream_h: Arc<dyn HostFunctionHandler>,
        poll_h: Arc<dyn HostFunctionHandler>,
        sink: Arc<RecordingSink>,
        budget: Arc<CountingBudget>,
        gateway: Arc<LlmGateway>,
        /// Never released: the mock stream stays IN-FLIGHT for the whole test, so
        /// the planted handle is a genuinely live abandoned stream at turn end.
        _gate: StreamGate,
    }

    /// A REAL live-path gateway (production `DefaultHttpSecurityChain`, mock wire)
    /// with the recording sink installed at construction, registered through THE
    /// production `register_agent_llm_with_turn_cost` so `reaper`, `stream_h` and
    /// `poll_h` all share one crate-internal `StreamRegistry`.
    fn tee_rig() -> TeeRig {
        let sink = Arc::new(RecordingSink::default());
        let budget = Arc::new(CountingBudget::default());
        let (exec, gate) = MockHttpExecutor::new().with_gated_stream(
            "https://api.openai.com",
            HttpResponseHead {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            },
            vec![b"data: {}\n\n".to_vec()],
        );
        let exec = Arc::new(exec);
        let leak: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
        let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(
            MockResolver::new().with("api.openai.com", vec!["8.8.8.8".parse::<IpAddr>().unwrap()]),
        )));
        let secrets = {
            use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
            let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
            let s = SecretStore::new(zeroize::Zeroizing::new([7u8; 32]), storage);
            s.store("openai-api-key", "test-secret-value").unwrap();
            Arc::new(s)
        };
        let chain = Arc::new(
            DefaultHttpSecurityChain::new(
                secrets,
                leak.clone(),
                ssrf,
                Arc::new(super::AlwaysAllowRl),
                exec.clone() as Arc<dyn cap_http::HttpExecutor>,
            )
            .with_stream_executor(exec as Arc<dyn HttpStreamExecutor>),
        );
        let gateway = Arc::new(
            LlmGateway::new(
                Arc::new(TeeConfig),
                chain.clone(),
                budget.clone(),
                Arc::new(super::StubBus) as Arc<dyn EventBusEmit>,
                Arc::new(super::StubRep),
                ROOT_BARE.to_string(),
            )
            .with_live_streaming(chain as Arc<dyn HttpStreamingChain>, leak)
            .with_delta_sink(sink.clone() as Arc<dyn LlmDeltaSink>),
        );
        let reg = InMemoryHostRegistry::new();
        let reaper = register_agent_llm_with_turn_cost(&reg, gateway.clone(), None);
        let specs = reg.lookup("llm");
        let handler_named = |name: &str| {
            specs
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("registered host fn {name}"))
                .handler
                .clone()
        };
        let stream_h = handler_named("stream");
        let poll_h = handler_named("poll-stream");
        TeeRig {
            reaper,
            stream_h,
            poll_h,
            sink,
            budget,
            gateway,
            _gate: gate,
        }
    }

    fn ctx(agent: &str) -> HostCallContext {
        HostCallContext {
            agent_id: agent.into(),
            trace_id: "t120-trace".into(),
            turn_id: None,
            capability: "llm".into(),
            function: "agent-llm::stream".into(),
            // A wired run_id (with the rig's budget) makes the reap's settlement
            // ledger-committed, so `Terminal.usage` must be `Some`.
            run_id: Some("run-t120".into()),
            iteration: None,
        }
    }

    fn handle_from(vals: &[Val]) -> u64 {
        match &vals[0] {
            Val::Result(Ok(Some(b))) => match &**b {
                Val::U64(h) => *h,
                other => panic!("stream result payload not a handle: {other:?}"),
            },
            other => panic!("stream did not return ok(handle): {other:?}"),
        }
    }

    fn begins_for(rig: &TeeRig, agent: &str) -> usize {
        rig.sink
            .frames()
            .iter()
            .filter(|e| &*e.agent_id == agent && matches!(e.frame, LlmDeltaFrame::Begin { .. }))
            .count()
    }

    /// Drive the registered `stream` host fn for `agent` — a live gated stream
    /// lands in the SAME registry the rig's reaper covers. Returns only after a
    /// NEW `Begin` for that agent is observed — a PER-AGENT count, not a
    /// per-stream correlation, so callers must plant serially for any one agent
    /// (every call site here does). The wait closes the reap-before-`Begin` park
    /// window: reaping in the handle-returned-but-`Begin`-unpublished window parks
    /// the terminal forever (benign in production — no consumer ever saw the
    /// stream — but a witness reaping there would wait on a frame that
    /// structurally cannot arrive).
    async fn plant_live_stream(rig: &TeeRig, agent: &str) -> u64 {
        let before = begins_for(rig, agent);
        let out = rig
            .stream_h
            .call(ctx(agent), vec![Val::String("hi".into())], 1)
            .await
            .expect("stream host fn call");
        let handle = handle_from(&out);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while begins_for(rig, agent) <= before {
            assert!(
                std::time::Instant::now() < deadline,
                "the owner task must publish Begin after handing back the handle"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle
    }

    fn deliver(store: &Arc<MailboxStore>, to: &str, id: &str) {
        store
            .get_or_create(to)
            .expect("mailbox")
            .deliver(Message {
                id: id.to_string(),
                kind: MessageKind::Agent,
                from: "user:t120".to_string(),
                to: to.to_string(),
                payload: vec![0x01],
                context: None,
                timestamp: std::time::SystemTime::now(),
                origin: None,
            })
            .expect("deliver turn message");
    }

    fn assert_reaped(term: &LlmDeltaEvent) {
        match &term.frame {
            LlmDeltaFrame::Terminal { reason, usage, .. } => {
                assert_eq!(
                    *reason,
                    LlmTerminalReason::Reaped,
                    "turn-end reap must label the terminal Reaped"
                );
                assert!(
                    usage.is_some(),
                    "budget + run_id are wired, so the settlement is ledger-committed \
                     and usage must be Some"
                );
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    // ── case 1 helpers: the sys_j65 production-wiring workspace ──

    const MINIMAL_RUNTIME_YAML: &str = "\
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers: []

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
";

    const TEST_MASTER_KEY_HEX: &str =
        "30415263748596a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f";

    fn ensure_test_master_key() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| std::env::set_var("SECRETS_MASTER_KEY", TEST_MASTER_KEY_HEX));
    }

    fn component_bytes(core: &[u8]) -> Vec<u8> {
        ComponentEncoder::default()
            .validate(true)
            .module(core)
            .expect("core module wraps")
            .encode()
            .expect("component encoded")
    }

    fn fresh_workspace() -> (TempDir, PathBuf, PathBuf) {
        ensure_test_master_key();
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
        std::fs::create_dir_all(workspace.join(".advance")).unwrap();
        std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
        std::fs::create_dir_all(workspace.join(".agent")).unwrap();
        std::fs::write(
            workspace.join(".agent/config.yaml"),
            // `llm: true` so wire_capabilities builds THE production gateway +
            // reap handle (the `declares_llm` wiring leg case 1 witnesses).
            "capabilities:\n  fs: true\n  messaging: true\n  llm: true\n",
        )
        .unwrap();
        std::fs::write(
            workspace.join(".agent/behavior.component.wasm"),
            component_bytes(SKELETON_CORE),
        )
        .unwrap();
        let config_path = workspace.join(".advance/runtime-config.yaml");
        std::fs::write(&config_path, MINIMAL_RUNTIME_YAML).unwrap();
        (dir, workspace, config_path)
    }

    /// T120 case 1 — observer path (i): the PRODUCTION root serve loop (spawned
    /// through `try_spawn_agent_loop` via the test-support wrapper) reaps a live
    /// abandoned stream at turn end and the sink receives `Terminal(Reaped)`.
    ///
    /// Mutation gate: deleting the root `CompositeTurnObserver` fan-out in
    /// `commands/start.rs` (observer = watch-only) MUST fail this case and MUST
    /// NOT fail case 2.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t120_root_path_reaps_and_emits_reaped() {
        let rig = tee_rig();
        let (_tmp, workspace, config_path) = fresh_workspace();
        let builder = RuntimeHostBuilder::new(&config_path, &workspace)
            .await
            .expect("runtime host builder");
        let (host, mut handles) = wire_capabilities(builder, &workspace)
            .await
            .expect("production wire_capabilities");
        // Tee T2 delivered: the production wiring now injects the REAL LlmDeltaHub
        // as the gateway's delta_sink (CONTRACT-234 Provider = MODULE-020).
        assert!(
            handles
                .llm_gateway
                .as_ref()
                .expect("wire_capabilities builds the production gateway")
                .delta_sink()
                .is_wired(),
            "wire_capabilities must wire the delta sink to the LlmDeltaHub (tee T2)"
        );
        // The plumbing site is a mutation target too: wire_capabilities must have
        // CREATED and RETAINED a reap handle (register_agent_llm_with_turn_cost's
        // return captured into WiringHandles.llm_stream_reaper). Without this
        // assertion, deleting that capture leaves the composite's None arm live —
        // production reaps nothing on any turn — while this witness stays green.
        assert!(
            handles.llm_stream_reaper.is_some(),
            "wire_capabilities must retain the reap handle (wiring.rs plumbing site)"
        );
        // Install the rig's reaper as THE composition's reap handle before the
        // serve loop spawns (exactly where production installs its own).
        handles.llm_stream_reaper = Some(rig.reaper.clone());
        let store = handles
            .messaging_store
            .clone()
            .expect("messaging:true yields a shared MailboxStore");
        let serve = spawn_test_agent_loop(&host, &workspace, &handles, store.clone())
            .await
            .expect("spawn production serve loop")
            .expect("deployed skeleton component starts a serve loop");
        assert_eq!(serve.agent_id(), ROOT_COLON);

        // A live abandoned stream owned by the root's BARE cap-id, plus a
        // bystander stream the root's turn must NOT settle.
        let _handle = plant_live_stream(&rig, ROOT_BARE).await;
        let _bystander = plant_live_stream(&rig, "bystander-agent").await;

        deliver(&store, ROOT_COLON, "t120-turn-1");
        let term = rig
            .sink
            .wait_terminal(ROOT_BARE, Duration::from_secs(30))
            .await
            .expect(
                "the root serve loop's turn end must reap the abandoned live stream \
                 (observer path (i) — try_spawn_agent_loop's CompositeTurnObserver)",
            );
        assert_reaped(&term);

        // Begin preceded Terminal for that stream (trait invariant 4).
        let frames = rig.sink.frames();
        let begin_idx = frames
            .iter()
            .position(|e| {
                e.stream_key == term.stream_key && matches!(e.frame, LlmDeltaFrame::Begin { .. })
            })
            .expect("a Begin was published for the reaped stream");
        let term_idx = frames
            .iter()
            .position(|e| {
                e.stream_key == term.stream_key && matches!(e.frame, LlmDeltaFrame::Terminal { .. })
            })
            .unwrap();
        assert!(begin_idx < term_idx, "Begin must precede Terminal");

        assert_eq!(rig.budget.commits(), 1, "billing settled exactly once");
        assert!(
            rig.sink.terminals_for("bystander-agent").is_empty(),
            "the root's turn must not settle another agent's live stream"
        );

        // Turn 2, with a FRESH live stream planted: the second reap is its own
        // liveness oracle (a fixed sleep proves nothing — "no new Terminal" must
        // not be satisfiable by the turn never running). Per-stream exactly-once:
        // the new stream gets its own Terminal; the FIRST stream's count stays 1.
        // (Eviction-vs-latch is NOT distinguishable here: the exactly-once CAS and
        // settle-once finalize produce identical observations either way.)
        let _handle2 = plant_live_stream(&rig, ROOT_BARE).await;
        deliver(&store, ROOT_COLON, "t120-turn-2");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while rig.sink.terminals_for(ROOT_BARE).len() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "turn 2 must run and reap the second planted stream (liveness oracle)"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let terms = rig.sink.terminals_for(ROOT_BARE);
        assert_eq!(terms.len(), 2, "one Terminal per stream across two turns");
        assert!(
            terms.iter().any(|t| t.stream_key == term.stream_key)
                && terms.iter().any(|t| t.stream_key != term.stream_key),
            "the second Terminal belongs to the SECOND stream; the first stream's \
             Terminal stays exactly one"
        );
        let term2 = terms
            .iter()
            .find(|t| t.stream_key != term.stream_key)
            .expect("second stream's terminal");
        assert_reaped(term2);
        assert_eq!(
            rig.budget.commits(),
            2,
            "exactly one commit per stream — the first stream is not re-billed"
        );
        drop(serve);
        drop(host);
    }

    // ── case 2 helpers: the sys_j68 per-child rig, trimmed to the reap seam ──

    struct AllowAllGrant;
    impl GrantCheck for AllowAllGrant {
        fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
            GrantDecision::Allow
        }
    }

    struct AllowAllSubset;
    impl SpawnerSubsetGate for AllowAllSubset {
        fn check(
            &self,
            _p: &[advance_shared_types::agent_tree::Capability],
            _c: &[advance_shared_types::agent_tree::Capability],
        ) -> Result<(), SpawnError> {
            Ok(())
        }
    }

    /// T120 case 2 — observer path (ii): a REAL production `spawn_child` through
    /// `PerChildLoopManager` serves the child's turn, and the child serve loop's
    /// composed observer reaps the child's live abandoned stream at turn end.
    ///
    /// Mutation gate: deleting the per-child `CompositeTurnObserver` fan-out in
    /// `perchild_daemon.rs` (obs = recording-only) MUST fail this case and MUST
    /// NOT fail case 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t120_perchild_serve_path_reaps() {
        let rig = tee_rig();
        let ws = TempDir::new().expect("tempdir");
        let ws_path = std::fs::canonicalize(ws.path()).expect("canonicalize");
        let territory = ws_path.join(ROOT_BARE);
        std::fs::create_dir_all(&territory).expect("territory");

        let tree = AgentTreeStore::new(ws_path.clone()).expect("bare store");
        tree.insert_root(AgentNode {
            id: AgentId(ROOT_BARE.to_string()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: territory,
            capabilities: vec![],
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("insert root");

        let routing = Arc::new(DynamicRouting::new(
            Arc::new(tree.clone()) as Arc<dyn AgentTreeReader>
        ));
        routing.seed_root(ROOT_COLON);
        let bridge = Arc::new(AgentIdBridge::from_pairs([(ROOT_COLON, ROOT_BARE)]));
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));

        let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
        let injector = Arc::new(CapabilityInjector::new(
            registry,
            Arc::new(AllowAllGrant),
            Arc::new(DefaultCircuitBreakerBus::new()),
        ));
        let runtime = Arc::new(
            ComponentRuntime::new(&WasmConfig {
                max_memory_pages: 256,
                epoch_interruption_ms: 100,
                fuel_enabled: false,
            })
            .expect("runtime"),
        );

        let key_resolver: KeyResolver = Arc::new(|bare: &str| {
            if bare == ROOT_BARE {
                ROOT_COLON.to_string()
            } else {
                format!("agent:{bare}")
            }
        });
        let mgr = Arc::new(PerChildLoopManager::new(
            store.clone(),
            Arc::new(super::StubBus) as Arc<dyn EventBusEmit>,
            routing,
            bridge,
            None,
            tree.clone(),
            tokio::runtime::Handle::current(),
            key_resolver,
        ));
        mgr.bind_runtime(runtime, injector);
        // The reap handle is installed BEFORE the child spawns — the production
        // install point (`set_llm_stream_reaper` precedes serve-loop creation).
        mgr.set_llm_stream_reaper(rig.reaper.clone());

        let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AllowAllSubset))
            .with_spawn_observer(mgr.clone() as Arc<dyn SpawnObserver>);
        spawner
            .spawn_child(SpawnChildConfig {
                parent_id: AgentId(ROOT_BARE.to_string()),
                child_id: AgentId(CHILD_BARE.to_string()),
                child_workspace_path: PathBuf::from("children").join(CHILD_BARE),
                capabilities: vec![],
                template_ref: None,
                binary: Some(CHILD_CORE.to_vec()),
            })
            .expect("spawn_child");
        // Let the spawned serve loop bootstrap + park on its mailbox.
        tokio::time::sleep(Duration::from_millis(400)).await;

        let _handle = plant_live_stream(&rig, CHILD_BARE).await;
        deliver(&store, CHILD_COLON, "t120-child-turn-1");
        let term = rig
            .sink
            .wait_terminal(CHILD_BARE, Duration::from_secs(30))
            .await
            .expect(
                "the child serve loop's turn end must reap the abandoned live stream \
                 (observer path (ii) — perchild_daemon's CompositeTurnObserver)",
            );
        assert_reaped(&term);
        assert!(
            mgr.child_turns(CHILD_COLON) >= 1,
            "liveness oracle: the child really served a turn"
        );
        assert_eq!(rig.budget.commits(), 1, "turn 1 settled exactly one bill");
        // Exactly-once, mirrored on case 1's design (round 13: a turn-counter
        // oracle fires BEFORE the reap observer — recording is index 0 of the
        // composite — and turn 1's reap EVICTED the only victim, so waiting on the
        // counter gated nothing): plant a FRESH stream, drive turn 2, and wait on
        // the SECOND stream's own Terminal, which is causally downstream of the
        // reap it gates.
        let _handle2 = plant_live_stream(&rig, CHILD_BARE).await;
        deliver(&store, CHILD_COLON, "t120-child-turn-2");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while rig.sink.terminals_for(CHILD_BARE).len() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "turn 2 must run and reap the second planted stream (liveness oracle)"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let terms = rig.sink.terminals_for(CHILD_BARE);
        assert_eq!(
            terms.len(),
            2,
            "one Terminal per stream across two served turns"
        );
        assert!(
            terms.iter().any(|t| t.stream_key == term.stream_key)
                && terms.iter().any(|t| t.stream_key != term.stream_key),
            "the second Terminal belongs to the SECOND stream; the first stream's \
             Terminal stays exactly one"
        );
        for t in &terms {
            assert_reaped(t);
        }
        assert_eq!(
            rig.budget.commits(),
            2,
            "exactly one commit per stream — the first stream is not re-billed"
        );
        mgr.drain();
    }

    /// T120 case 3 — serve-key→cap-id mapping through the same TYPE the
    /// composition wires (`ReapTurnObserver` + the rig's reaper: function
    /// identity, NOT composition identity — the composition gates are cases 1
    /// and 2). REDESIGNED with the §5.2-item-5 fix: the observer holds an exact
    /// authoritative `(serve-key, cap-id)` pair injected at construction
    /// (`for_agent`), so `agent:default` reaps the BARE `default-agent` stream
    /// via the injected root pair, a second observer reaps its own agent via its
    /// own pair, and any NON-matching id — another agent's key, a malformed id,
    /// the empty string — reaps NOTHING by exact compare: there is no derivation
    /// left to guess with (this case pins the mismatch→0 arm; the arm is not
    /// unit-testable from `reap.rs` because `AgentStreamReaper` construction
    /// needs the cap-llm factory). A reap for one agent never settles another
    /// agent's stream.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t120_colon_serve_id_resolves_to_bare_cap_id() {
        let rig = tee_rig();
        let _root = plant_live_stream(&rig, ROOT_BARE).await;
        let _other = plant_live_stream(&rig, "other-agent").await;
        let obs = ReapTurnObserver::for_agent(rig.reaper.clone(), ROOT_COLON, ROOT_BARE);

        assert_eq!(obs.reap_now("agent:"), 0, "malformed id reaps nothing");
        assert_eq!(obs.reap_now(""), 0, "empty id reaps nothing");
        assert_eq!(
            obs.reap_now("agent:other-agent"),
            0,
            "another agent's serve key must NOT match the root observer's pair"
        );
        assert_eq!(
            obs.reap_now(ROOT_COLON),
            1,
            "the injected root pair reaps the BARE default-agent stream"
        );
        let term = rig
            .sink
            .wait_terminal(ROOT_BARE, Duration::from_secs(5))
            .await
            .expect("reaped root stream publishes Terminal");
        assert_reaped(&term);
        assert!(
            rig.sink.terminals_for("other-agent").is_empty(),
            "reaping agent:default must not settle other-agent's stream"
        );
        let obs_other =
            ReapTurnObserver::for_agent(rig.reaper.clone(), "agent:other-agent", "other-agent");
        assert_eq!(
            obs_other.reap_now("agent:other-agent"),
            1,
            "an observer reaps its own agent via its own injected pair"
        );
        let term2 = rig
            .sink
            .wait_terminal("other-agent", Duration::from_secs(5))
            .await
            .expect("reaped other-agent stream publishes Terminal");
        assert_reaped(&term2);
    }

    /// T120 case 3b (round 23; claim NARROWED at round 24) — the turn-boundary
    /// dispatch delivers settlement on the PRODUCTION runtime flavor. `advance
    /// start` builds a CURRENT-THREAD runtime (`commands/start.rs::run`), and the
    /// round-23 adversarial review proved the earlier `block_in_place` arm was
    /// dead code there. This case runs the observer's real `on_turn_complete`
    /// under `#[tokio::test]`'s default current-thread runtime and waits for the
    /// `Terminal(Reaped)`. WHAT IT KILLS: a dispatch that silently drops or
    /// never settles the batch on this flavor. WHAT IT DOES NOT DISCRIMINATE
    /// (round 24, both reviewers): deferral itself — a mutant that settles the
    /// batch INLINE on the runtime thread publishes the terminal before the
    /// await and passes identically. No case observes thread residency; that the
    /// settle actually runs on the blocking pool is inspection-verified
    /// (recorded in MODULE-009 §3.6.6).
    #[tokio::test]
    async fn t120_deferred_settle_works_on_the_production_current_thread_flavor() {
        let rig = tee_rig();
        let _h = plant_live_stream(&rig, ROOT_BARE).await;
        let obs = ReapTurnObserver::for_agent(rig.reaper.clone(), ROOT_COLON, ROOT_BARE);
        obs.on_turn_complete(ROOT_COLON);
        let term = rig
            .sink
            .wait_terminal(ROOT_BARE, Duration::from_secs(5))
            .await
            .expect(
                "deferred settlement must land on the blocking pool while the \
                 single runtime thread only awaits",
            );
        assert_reaped(&term);
    }

    /// T120 case 4 — reap settles BEFORE evicting: a poller already parked inside
    /// `poll-stream` WAKES in bounded time (a settle that evicted without
    /// notifying would leave the parked poller waiting toward the 300-second
    /// stream deadline and fail this case's 5-second timeout) and receives the
    /// enum-coded `provider-error` result, not a success chunk. HONEST BOUND: the
    /// WIT boundary redacts error payloads to fixed class strings AND the evicted
    /// path's "expired or unknown" error encodes to the SAME `provider-error`
    /// case, so settled-vs-evicted is indistinguishable at this altitude in both
    /// message and class; what this case witnesses is the wake plus the error
    /// class. The below-WIT settled-error-vs-`Unknown` discipline stays with
    /// cap-llm's unit suite.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t120_reap_settles_before_evicting() {
        let rig = tee_rig();
        let handle = plant_live_stream(&rig, ROOT_BARE).await;
        let poll_h = rig.poll_h.clone();
        let poller =
            tokio::spawn(
                async move { poll_h.call(ctx(ROOT_BARE), vec![Val::U64(handle)], 1).await },
            );
        // Let the poller reach the live stream's notify and park (the gated mock
        // yields nothing, so there is no delta to claim).
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(rig.reaper.reap_agent(ROOT_BARE), 1, "reap finds the stream");
        let out = tokio::time::timeout(Duration::from_secs(5), poller)
            .await
            .expect(
                "a parked poller MUST wake: settlement publishes the terminal phase \
                 and notifies BEFORE eviction",
            )
            .expect("poller task join")
            .expect("poll host fn call");
        match &out[0] {
            Val::Result(Err(Some(b))) => match &**b {
                Val::Variant(case, _) => assert_eq!(
                    case, "provider-error",
                    "the woken poller receives the enum-coded error class"
                ),
                other => panic!("expected llm-error variant, got {other:?}"),
            },
            other => panic!("expected result::err(llm-error), got {other:?}"),
        }
        // And the sink saw the reap's exactly-once Terminal.
        let term = rig
            .sink
            .wait_terminal(ROOT_BARE, Duration::from_secs(5))
            .await
            .expect("Terminal(Reaped) published");
        assert_reaped(&term);
    }

    /// T120 case 5 — composition identity: `LlmGateway::delta_sink()` returns the
    /// EXACT `Arc` installed via `with_delta_sink` (`Arc::ptr_eq`), and a gateway
    /// built WITHOUT the builder holds the genuinely-unwired default.
    #[test]
    fn t120_composed_gateway_sink_is_the_installed_arc() {
        let rig = tee_rig();
        assert!(
            Arc::ptr_eq(
                &rig.gateway.delta_sink(),
                &(rig.sink.clone() as Arc<dyn LlmDeltaSink>)
            ),
            "delta_sink() must be the installed Arc, not a copy or a re-wrap"
        );
        assert!(rig.gateway.delta_sink().is_wired());

        let bare = LlmGateway::new(
            Arc::new(TeeConfig),
            Arc::new(DefaultHttpSecurityChain::new(
                super::test_secret_store(),
                Arc::new(DefaultLeakDetector::new()),
                Arc::new(DefaultSsrfGuard::new()),
                Arc::new(super::AlwaysAllowRl),
                Arc::new(cap_http::ReqwestHttpExecutor::new()),
            )),
            Arc::new(super::StubBudget),
            Arc::new(super::StubBus) as Arc<dyn EventBusEmit>,
            Arc::new(super::StubRep),
            ROOT_BARE.to_string(),
        );
        assert!(
            !bare.delta_sink().is_wired(),
            "the un-built default must be the NotWired sink (headless zero-cost clause)"
        );
    }
}
