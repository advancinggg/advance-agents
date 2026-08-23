//! SYS-J-74 — daemon-altitude local-sidecar witnesses.
//!
//! AC → test mapping (along bookkeeping handoff; this tree does not flip ledgers):
//!
//! | AC | Tests | Bytes prove |
//! | --- | --- | --- |
//! | SYS-AC-313 | `sys_ac_313_local_chat_budget_attribution` | PORT hand-off; guest `chat` → `"pong"`; `llm.response` input/output tokens + cost; cloud mock delta 0 after a live sentinel probe |
//! | SYS-AC-314 | `sys_ac_314_kill_sidecar_mid_turn_no_cloud_fallback` + `sys_ac_314_supervision_absent` + `sys_ac_314_shutdown_no_orphan` | host `local transport:`; guest no actions / no sentinel; fixture pid/addr gone on Drop |
//! | SYS-AC-315 | `sys_ac_315_literal_loopback_blocked_at_chain` + `sys_ac_315_rfc1918_blocked_at_chain` + `sys_ac_315_connect_time_literal_blocked` + `sys_ac_315_connect_time_localhost_rebinding_blocked` | cloud-http provider `chat()`: chain-step `SsrfBlocked` non-retryable (a/b); connect-time `"transport error"` + mock 0 (c/d) |
//! | REQ-404 | union of the three SYS-ACs | sidecar e2e leg; in-process half is product SYS-J-81 |
//!
//! REQ-404 Verified only if all three SYS-ACs pass (along bookkeeping).

use std::net::TcpStream;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, RunBudget};
use cap_llm::{
    ChatMessage, ChatParams, ChatRole, LlmError, LlmGateway, LlmGatewayInternal, LLM_ERROR,
    LLM_REQUEST, LLM_RESPONSE, LLM_RETRY,
};
use system_acceptance::llm_loopback::{ScriptedResponse, CLOUD_FALLBACK_SENTINEL};
use system_acceptance::{Cap, LlmMode, SidecarLaunch, SystemUnderTest};

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const FIXTURE_PONG: &str = "pong";

struct NullBus;
impl EventBusEmit for NullBus {
    fn emit(&self, _event: Event) {}
}

struct CountingBudget {
    inner: Arc<dyn RunBudget>,
    checks: Arc<AtomicU64>,
    commits: Arc<AtomicU64>,
    last_commit_tokens: Arc<AtomicU64>,
    last_commit_cost_bits: Arc<AtomicU64>,
}

impl RunBudget for CountingBudget {
    fn check(&self, run_id: &str, additional_tokens: u64, additional_cost: f64) -> BudgetDecision {
        self.checks.fetch_add(1, Ordering::SeqCst);
        self.inner.check(run_id, additional_tokens, additional_cost)
    }
    fn commit(&self, run_id: &str, tokens: u64, cost: f64) {
        self.inner.commit(run_id, tokens, cost);
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.last_commit_tokens.store(tokens, Ordering::SeqCst);
        self.last_commit_cost_bits
            .store(cost.to_bits(), Ordering::SeqCst);
    }
}

fn user_msg(text: &str) -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: ChatRole::User,
        content: text.into(),
    }]
}

fn dummy_script() -> Vec<ScriptedResponse> {
    vec![ScriptedResponse::ok_chat("never-reached", 1, 1)]
}

struct LocalHarness {
    sut: SystemUnderTest,
    budget_checks: Arc<AtomicU64>,
    budget_commits: Arc<AtomicU64>,
    last_commit_tokens: Arc<AtomicU64>,
    last_commit_cost_bits: Arc<AtomicU64>,
}

async fn local_sut(launch: SidecarLaunch) -> LocalHarness {
    let rm = Arc::new(RunManager::new(Arc::new(NullBus)));
    let checks = Arc::new(AtomicU64::new(0));
    let commits = Arc::new(AtomicU64::new(0));
    let last_tokens = Arc::new(AtomicU64::new(0));
    let last_cost = Arc::new(AtomicU64::new(0));
    let budget = Arc::new(CountingBudget {
        inner: Arc::new(rm.budget()),
        checks: checks.clone(),
        commits: commits.clone(),
        last_commit_tokens: last_tokens.clone(),
        last_commit_cost_bits: last_cost.clone(),
    });
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .grant_run_session(rm, RunConfig::default())
        .budget(budget)
        .with_reply_capture()
        .llm(LlmMode::LocalSidecar { launch })
        .build(HELLO_LLM_CORE)
        .await;
    LocalHarness {
        sut,
        budget_checks: checks,
        budget_commits: commits,
        last_commit_tokens: last_tokens,
        last_commit_cost_bits: last_cost,
    }
}

async fn chat(gw: &LlmGateway, model: Option<&str>, text: &str) -> Result<String, LlmError> {
    let mut params = ChatParams::default();
    params.model = model.map(str::to_string);
    gw.chat(user_msg(text), params).await.map(|r| r.text)
}

fn err_msg(err: &LlmError) -> String {
    match err {
        LlmError::ProviderError(m) => m.clone(),
        other => other.to_string(),
    }
}

fn payload_f64(e: &Event, key: &str) -> Option<f64> {
    e.payload.get(key).and_then(|v| v.as_f64())
}

fn signal_kill(pid: u32) {
    let _ = Command::new("kill")
        .args(["-s", "KILL", &pid.to_string()])
        .status();
}

fn wait_port_closed(addr: std::net::SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_err() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "listen {addr} still open"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_313_local_chat_budget_attribution() {
    let h = local_sut(SidecarLaunch::Fixture).await;
    let sut = &h.sut;
    let pid = sut.sidecar_pid().expect("fixture pid after spawn");
    let addr = sut.sidecar_addr().expect("fixture listen addr");
    assert_eq!(
        addr.ip().to_string(),
        "127.0.0.1",
        "PORT hand-off is loopback"
    );
    assert!(pid > 0);
    TcpStream::connect_timeout(&addr, Duration::from_secs(1))
        .unwrap_or_else(|e| panic!("fixture must accept on {addr} (pid {pid}): {e}"));

    let gw = sut.llm_gateway().expect("production gateway");
    let cloud = chat(&gw, Some("gpt-4o-mini"), "cloud-probe")
        .await
        .expect("reachable cloud");
    assert_eq!(cloud, CLOUD_FALLBACK_SENTINEL);
    let cloud_hits = sut.llm_chat_request_count();
    assert!(cloud_hits >= 1, "cloud mock recorded the probe");

    let local = chat(&gw, None, "local-probe")
        .await
        .expect("local fixture chat");
    assert_eq!(local, FIXTURE_PONG, "llm_gateway() is production local");

    let responses_before = sut.events_of_types(&[LLM_RESPONSE]).len();
    let requests_before = sut.events_of_types(&[LLM_REQUEST]).len();
    let errors_before = sut.events_of_types(&[LLM_ERROR]).len();
    let commits_before = h.budget_commits.load(Ordering::SeqCst);
    let checks_before = h.budget_checks.load(Ordering::SeqCst);

    sut.inject_message("h", b"hello from j74").await;
    sut.run_turn().await;

    let replies = sut.delivered_replies();
    assert!(
        replies.iter().any(|r| r == FIXTURE_PONG.as_bytes()),
        "guest turn reply is fixture pong, not sentinel; got {replies:?}"
    );
    assert!(
        replies
            .iter()
            .all(|r| r != CLOUD_FALLBACK_SENTINEL.as_bytes()),
        "guest must not surface the cloud sentinel"
    );
    assert_eq!(
        sut.llm_chat_request_count(),
        cloud_hits,
        "local guest turn must not dial the cloud mock"
    );

    let responses: Vec<_> = sut.events_of_types(&[LLM_RESPONSE]);
    assert!(
        responses.len() > responses_before,
        "guest turn emits llm.response"
    );
    let p = &responses.last().expect("guest llm.response").payload;
    assert_eq!(p.get("model").and_then(|v| v.as_str()), Some("llama"));
    assert_eq!(p.get("input_tokens").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(p.get("output_tokens").and_then(|v| v.as_u64()), Some(1));
    let cost = payload_f64(responses.last().unwrap(), "cost_usd").expect("cost_usd");
    assert!(
        (cost - 2.0e-9).abs() < 1e-15,
        "cost = rates 0.001 × (1+1)/1e6, got {cost}"
    );
    let requests = sut.events_of_types(&[LLM_REQUEST]);
    assert!(
        requests.len() > requests_before,
        "guest turn emits llm.request"
    );
    assert_eq!(
        requests
            .last()
            .expect("guest llm.request")
            .payload
            .get("model")
            .and_then(|v| v.as_str()),
        Some("llama")
    );
    assert_eq!(
        sut.events_of_types(&[LLM_ERROR]).len(),
        errors_before,
        "successful local guest turn must not emit llm.error"
    );
    assert!(
        h.budget_checks.load(Ordering::SeqCst) > checks_before,
        "guest generate_via_local must RunBudget::check"
    );
    assert!(
        h.budget_commits.load(Ordering::SeqCst) > commits_before,
        "guest generate_via_local must RunBudget::commit"
    );
    assert_eq!(
        h.last_commit_tokens.load(Ordering::SeqCst),
        2,
        "t128 pattern: fixture usage 1+1 committed after inner.commit"
    );
    let committed_cost = f64::from_bits(h.last_commit_cost_bits.load(Ordering::SeqCst));
    assert!(
        (committed_cost - 2.0e-9).abs() < 1e-15,
        "commit cost must be rates × tokens, got {committed_cost}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_314_kill_sidecar_mid_turn_no_cloud_fallback() {
    let h = local_sut(SidecarLaunch::Fixture).await;
    let sut = &h.sut;
    let gw = sut.llm_gateway().expect("gateway");
    assert_eq!(
        chat(&gw, Some("gpt-4o-mini"), "cloud-probe")
            .await
            .expect("cloud reachable"),
        CLOUD_FALLBACK_SENTINEL,
        "314a reachable-cloud trap must be the mock sentinel, not fixture pong"
    );
    let cloud_hits = sut.llm_chat_request_count();
    assert!(cloud_hits >= 1, "cloud mock recorded the 314a probe");
    assert_eq!(
        chat(&gw, None, "hi").await.expect("pre-kill local"),
        FIXTURE_PONG
    );

    let pid = sut.sidecar_pid().expect("fixture pid");
    let addr = sut.sidecar_addr().expect("fixture addr");
    // Occupy the fixture's single accept/read so the next chat is mid-HTTP
    // when we SIGKILL (no SIGSTOP: waitid on a stopped child races killpg).
    let _hold = TcpStream::connect_timeout(&addr, Duration::from_secs(1))
        .expect("hold the fixture accept/read");
    let gw2 = gw.clone();
    let inflight = tokio::spawn(async move { chat(&gw2, None, "in-flight").await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    signal_kill(pid);
    let inflight_res = inflight.await.expect("join inflight");
    wait_port_closed(addr);
    let err = inflight_res.expect_err("in-flight chat must not complete as pong");
    assert!(
        !matches!(err, LlmError::BudgetExceeded(_))
            && err_msg(&err).starts_with("local transport:"),
        "typed C238 on in-flight future; got {err:?}"
    );
    assert_ne!(err_msg(&err), CLOUD_FALLBACK_SENTINEL);

    let errors_before_guest = sut.events_of_types(&[LLM_ERROR]).len();
    sut.inject_message("h", b"after-kill").await;
    sut.run_turn().await;
    assert!(
        sut.delivered_replies().is_empty(),
        "guest must not present a success payload after sidecar kill; got {:?}",
        sut.delivered_replies()
    );
    let errors = sut.events_of_types(&[LLM_ERROR]);
    assert!(
        errors.len() > errors_before_guest,
        "guest generate must emit llm.error after kill; before={errors_before_guest} after={}",
        errors.len()
    );
    assert!(
        errors[errors_before_guest..].iter().any(|e| {
            e.payload.get("error_type").and_then(|v| v.as_str()) == Some("provider-error")
        }),
        "guest-turn llm.error must be provider-error; guest rows {:?}",
        &errors[errors_before_guest..]
    );
    assert_eq!(
        sut.llm_chat_request_count(),
        cloud_hits,
        "no silent cloud fallback after kill"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_314_supervision_absent() {
    let h = local_sut(SidecarLaunch::Absent).await;
    let sut = &h.sut;
    let gw = sut.llm_gateway().expect("gateway");
    assert_eq!(
        chat(&gw, Some("gpt-4o-mini"), "cloud-probe")
            .await
            .expect("cloud reachable without sidecar"),
        CLOUD_FALLBACK_SENTINEL
    );
    let cloud_hits = sut.llm_chat_request_count();
    let err = chat(&gw, None, "hi").await.expect_err("local unwired");
    let msg = err_msg(&err);
    assert!(
        msg.starts_with("local transport:"),
        "NotWired C238, got {err:?}"
    );

    sut.inject_message("h", b"absent").await;
    sut.run_turn().await;
    assert!(
        sut.delivered_replies().is_empty(),
        "no success payload when supervision is absent"
    );
    assert_eq!(sut.llm_chat_request_count(), cloud_hits);
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_314_shutdown_no_orphan() {
    let h = local_sut(SidecarLaunch::Fixture).await;
    let pid = h.sut.sidecar_pid().expect("pid");
    let addr = h.sut.sidecar_addr().expect("addr");
    TcpStream::connect_timeout(&addr, Duration::from_secs(1))
        .unwrap_or_else(|e| panic!("pre-drop fixture listen {addr} pid {pid}: {e}"));
    drop(h.sut);
    let still = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("kill -0");
    assert!(
        !still.success(),
        "fixture pid {pid} must not survive SUT drop"
    );
    wait_port_closed(addr);
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_315_literal_loopback_blocked_at_chain() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::ProductionSsrf {
            origin: "http://127.0.0.1".into(),
            script: dummy_script(),
        })
        .build(HELLO_LLM_CORE)
        .await;
    let gw = sut.llm_gateway().expect("gateway");
    let err = chat(&gw, None, "ssrf").await.expect_err("loopback blocked");
    assert_eq!(err_msg(&err), "ssrf blocked");
    assert_eq!(sut.llm_chat_request_count(), 0);
    assert!(sut.events_of_types(&[LLM_RETRY]).is_empty());
    let blocked = sut.events_of_types(&["security.ssrf_blocked"]);
    assert!(
        blocked.iter().any(|e| {
            e.payload
                .get("cidr_class")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("Loopback"))
        }),
        "chain-step Loopback class; got {blocked:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_315_rfc1918_blocked_at_chain() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::ProductionSsrf {
            origin: "https://10.0.0.1".into(),
            script: dummy_script(),
        })
        .build(HELLO_LLM_CORE)
        .await;
    let gw = sut.llm_gateway().expect("gateway");
    let err = chat(&gw, None, "ssrf").await.expect_err("rfc1918 blocked");
    assert_eq!(err_msg(&err), "ssrf blocked");
    assert!(sut.events_of_types(&[LLM_RETRY]).is_empty());
    let blocked = sut.events_of_types(&["security.ssrf_blocked"]);
    assert!(
        blocked.iter().any(|e| {
            let class = e.payload.get("cidr_class").and_then(|v| v.as_str());
            let host = e.payload.get("host").and_then(|v| v.as_str());
            class.is_some_and(|s| s.contains("PrivateIpv4")) && host == Some("10.0.0.1")
        }),
        "RFC1918 discriminator; got {blocked:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_315_connect_time_literal_blocked() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::FooledSsrf {
            mapped_host: "127.0.0.1".into(),
            script: dummy_script(),
        })
        .build(HELLO_LLM_CORE)
        .await;
    let gw = sut.llm_gateway().expect("gateway");
    let err = chat(&gw, None, "ssrf").await.expect_err("executor literal");
    assert_eq!(err_msg(&err), "transport error");
    assert_eq!(sut.llm_chat_request_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_315_connect_time_localhost_rebinding_blocked() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::FooledSsrf {
            mapped_host: "localhost".into(),
            script: dummy_script(),
        })
        .build(HELLO_LLM_CORE)
        .await;
    let gw = sut.llm_gateway().expect("gateway");
    let err = chat(&gw, None, "ssrf")
        .await
        .expect_err("ssrf dns resolver");
    assert_eq!(err_msg(&err), "transport error");
    assert_eq!(sut.llm_chat_request_count(), 0);
}

#[test]
fn local_transport_prefix_is_stable() {
    assert_eq!(
        advance_shared_types::inference::LOCAL_TRANSPORT_PREFIX,
        "local transport:"
    );
}
