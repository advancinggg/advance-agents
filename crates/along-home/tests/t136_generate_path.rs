//! T136 / T137 — MODULE-009-AC-31 real composition (mock executor / hang).

use std::sync::Arc;
use std::time::Duration;

use advance_along_home::{
    write_recognizable_home, AlongHomeFirstOpen, CancelToken, GeneratePathPreflight, HostAlongHome,
    PreflightFail, SecretBytes,
};
use advance_shared_types::security_validator::HttpResponse;
use cap_http::{DefaultSsrfGuard, MockHttpExecutor, MockResolver};
use cap_llm::DiscardEventBus;
use cap_secrets::{
    ensure_master_key, DefaultEntryProvider, FileSecretStorage, MasterKeyConfig, SecretStore,
};

fn openai_ok_body() -> Vec<u8> {
    br#"{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1},"model":"gpt-4o"}"#
        .to_vec()
}

fn openai_resolver() -> Arc<dyn advance_shared_types::security_validator::SsrfGuard> {
    Arc::new(DefaultSsrfGuard::with_resolver(Box::new(
        MockResolver::new().with(
            "api.openai.com",
            vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()],
        ),
    )))
}

fn host_with_exec(exec: Arc<MockHttpExecutor>) -> HostAlongHome {
    let pre = GeneratePathPreflight {
        executor: exec,
        ssrf: openai_resolver(),
        event_bus: Arc::new(DiscardEventBus),
    };
    HostAlongHome::with_ports(
        Arc::new(pre),
        Arc::new(advance_along_home::ProcessLauncher),
        Arc::new(OkAdopt),
    )
}

fn committed_secret(home: &std::path::Path, name: &str) -> Option<String> {
    let mk = MasterKeyConfig::EnvVar("SECRETS_MASTER_KEY".into());
    let master = ensure_master_key(home, &mk, &DefaultEntryProvider).ok()?;
    let store = SecretStore::new(
        master,
        Arc::new(FileSecretStorage::open(home.join(".advance").join("secrets.json")).ok()?),
    );
    use secrecy::ExposeSecret;
    store
        .resolve(name)
        .ok()
        .map(|s| s.expose_secret().to_string())
}

#[test]
fn t136_openai_while_anthropic_is_first() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let key_ok = "sk-test-T136-openai";
    let exec = Arc::new(MockHttpExecutor::new().with_response(
        "https://api.openai.com",
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: openai_ok_body(),
        },
    ));
    let h = host_with_exec(Arc::clone(&exec));
    let handle = h.open(&path).unwrap();
    let pass = h
        .store_and_preflight(
            &handle,
            "openai",
            SecretBytes::new(key_ok),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(pass.provider_id, "openai");
    let cfg =
        advance_runtime::config::load_config(&path.join(".advance").join("runtime-config.yaml"))
            .unwrap();
    assert_eq!(cfg.llm_providers[0].id, "openai");
    let recorded = exec.recorded_requests.lock().unwrap();
    assert!(
        recorded.iter().any(|(u, _)| u.contains("api.openai.com")),
        "{recorded:?}"
    );
    assert!(
        !recorded.iter().any(|(u, _)| u.contains("anthropic")),
        "{recorded:?}"
    );
    drop(recorded);
    assert_eq!(
        committed_secret(&path, "openai-api-key").as_deref(),
        Some(key_ok)
    );

    let key_bad = "sk-test-T136-openai-bad";
    let exec401 = Arc::new(MockHttpExecutor::new().with_response(
        "https://api.openai.com",
        HttpResponse {
            status: 401,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"error":{"message":"unauthorized"}}"#.to_vec(),
        },
    ));
    let h_fail = host_with_exec(exec401);
    let handle = h_fail.open(&path).unwrap();
    let err = h_fail
        .store_and_preflight(
            &handle,
            "openai",
            SecretBytes::new(key_bad),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert_eq!(
        err,
        PreflightFail::ProviderRejected {
            reason: "provider-error".into()
        }
    );
    assert!(!format!("{err}").contains(key_bad));
    assert!(!format!("{err:?}").contains(key_bad));
    assert_eq!(
        committed_secret(&path, "openai-api-key").as_deref(),
        Some(key_ok)
    );
}

struct OkAdopt;
impl advance_along_home::AdoptPort for OkAdopt {
    fn wait_adopted(
        &self,
        _h: &std::path::Path,
        _e: &str,
        _c: &CancelToken,
    ) -> Result<(), advance_along_home::AdoptError> {
        Ok(())
    }
}

struct HangExec;
#[async_trait::async_trait]
impl cap_http::HttpExecutor for HangExec {
    async fn execute(
        &self,
        _req: &advance_shared_types::security_validator::HttpRequest,
        _redirect_check: std::sync::Arc<
            dyn advance_shared_types::security_validator::RedirectCheck,
        >,
    ) -> Result<HttpResponse, cap_http::ExecutorError> {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Err(cap_http::ExecutorError::Transport)
    }
}

#[test]
fn t137_cancel_hanging_executor() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let key = "sk-test-T137-hang";
    let pre = GeneratePathPreflight {
        executor: Arc::new(HangExec),
        ssrf: openai_resolver(),
        event_bus: Arc::new(DiscardEventBus),
    };
    let h = HostAlongHome::with_ports(
        Arc::new(pre),
        Arc::new(advance_along_home::ProcessLauncher),
        Arc::new(OkAdopt),
    );
    let handle = h.open(&path).unwrap();
    let cancel = CancelToken::new();
    let cancel2 = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        cancel2.cancel();
    });
    let err = h
        .store_and_preflight(&handle, "openai", SecretBytes::new(key), &cancel)
        .unwrap_err();
    assert_eq!(err, PreflightFail::Cancelled);
    assert!(!format!("{err}").contains(key));
    assert!(!format!("{err:?}").contains(key));
    assert!(committed_secret(&path, "openai-api-key").is_none());
    let cfg =
        advance_runtime::config::load_config(&path.join(".advance").join("runtime-config.yaml"))
            .unwrap();
    assert_eq!(cfg.llm_providers[0].id, "anthropic");
}
