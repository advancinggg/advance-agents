//! T33–T36 — MODULE-012-AC-25/26

use std::fs;
use std::sync::{Arc, Mutex};

use advance_along_home::{
    write_recognizable_home, AlongHomeFirstOpen, CancelToken, GeneratePathPreflight, HostAlongHome,
    PreflightFail, PreflightPass, ProviderStatus, SecretBytes,
};
use advance_runtime::config::LlmProviderConfig;
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::HttpResponse;
use advance_shared_types::traits::EventBusEmit;
use cap_http::{DefaultSsrfGuard, MockHttpExecutor, MockResolver};
use cap_secrets::{
    ensure_master_key, DefaultEntryProvider, FileSecretStorage, MasterKeyConfig, SecretStore,
};

struct Pass;
impl advance_along_home::PreflightPort for Pass {
    fn preflight(
        &self,
        _home: &std::path::Path,
        _provider: &LlmProviderConfig,
        _key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        if cancel.is_cancelled() {
            return Err(PreflightFail::Cancelled);
        }
        Ok(())
    }
}

struct Fail;
impl advance_along_home::PreflightPort for Fail {
    fn preflight(
        &self,
        _home: &std::path::Path,
        _provider: &LlmProviderConfig,
        _key: &SecretBytes,
        _cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        Err(PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        })
    }
}

struct NoLaunch;
impl advance_along_home::RuntimeLauncher for NoLaunch {
    fn start(
        &self,
        _home: &std::path::Path,
        _cancel: &CancelToken,
    ) -> Result<(), advance_along_home::ConnectError> {
        Ok(())
    }
}
struct NoAdopt;
impl advance_along_home::AdoptPort for NoAdopt {
    fn wait_adopted(
        &self,
        _home: &std::path::Path,
        _e: &str,
        _c: &CancelToken,
    ) -> Result<(), advance_along_home::AdoptError> {
        Ok(())
    }
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
fn t33_store_ciphertext_only() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let key = "sk-test-KEY-T33-plaintext";
    let h = HostAlongHome::with_ports(Arc::new(Pass), Arc::new(NoLaunch), Arc::new(NoAdopt));
    let handle = h.open(&path).unwrap();
    let pass = h
        .store_and_preflight(
            &handle,
            "anthropic",
            SecretBytes::new(key),
            &CancelToken::new(),
        )
        .unwrap();
    assert!(!format!("{pass:?}").contains(key));
    let secrets = fs::read_to_string(path.join(".advance").join("secrets.json")).unwrap();
    assert!(!secrets.contains(key), "plaintext leaked into secrets.json");
    assert_eq!(
        committed_secret(&path, "anthropic-api-key").as_deref(),
        Some(key)
    );
}

#[test]
fn t34_fail_leaves_previous() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let a = "sk-test-KEY-T34-A";
    let b = "sk-test-KEY-T34-B";
    let pass = HostAlongHome::with_ports(Arc::new(Pass), Arc::new(NoLaunch), Arc::new(NoAdopt));
    let handle = pass.open(&path).unwrap();
    pass.store_and_preflight(
        &handle,
        "anthropic",
        SecretBytes::new(a),
        &CancelToken::new(),
    )
    .unwrap();
    assert_eq!(
        committed_secret(&path, "anthropic-api-key").as_deref(),
        Some(a)
    );

    let fail = HostAlongHome::with_ports(Arc::new(Fail), Arc::new(NoLaunch), Arc::new(NoAdopt));
    let handle = fail.open(&path).unwrap();
    let err = fail
        .store_and_preflight(
            &handle,
            "anthropic",
            SecretBytes::new(b),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(!format!("{err}").contains(b));
    assert_eq!(
        committed_secret(&path, "anthropic-api-key").as_deref(),
        Some(a)
    );

    let cxl = CancelToken::new();
    cxl.cancel();
    let cancelled = fail
        .store_and_preflight(&handle, "anthropic", SecretBytes::new(b), &cxl)
        .unwrap_err();
    assert_eq!(cancelled, PreflightFail::Cancelled);
    assert_eq!(
        committed_secret(&path, "anthropic-api-key").as_deref(),
        Some(a)
    );
}

struct RecBus(Mutex<Vec<Event>>);
impl EventBusEmit for RecBus {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}

fn assert_home_has_no_plaintext(root: &std::path::Path, key: &str) {
    fn walk(dir: &std::path::Path, key: &str) {
        let Ok(rd) = fs::read_dir(dir) else {
            return;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                walk(&p, key);
            } else if let Ok(bytes) = fs::read(&p) {
                assert!(
                    !bytes.windows(key.len()).any(|w| w == key.as_bytes()),
                    "plaintext key leaked into {}",
                    p.display()
                );
            }
        }
    }
    walk(root, key);
}

fn openai_ok_body() -> Vec<u8> {
    br#"{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1},"model":"gpt-4o"}"#
        .to_vec()
}

#[test]
fn t35_t36_no_key_on_error_or_types() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let key = "sk-test-KEY-T35-leak";
    let rec = Arc::new(RecBus(Mutex::new(Vec::new())));
    let exec = Arc::new(MockHttpExecutor::new().with_response(
        "https://api.openai.com",
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: openai_ok_body(),
        },
    ));
    let pre = GeneratePathPreflight {
        executor: exec,
        ssrf: Arc::new(DefaultSsrfGuard::with_resolver(Box::new(
            MockResolver::new().with(
                "api.openai.com",
                vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()],
            ),
        ))),
        event_bus: Arc::clone(&rec) as Arc<dyn EventBusEmit>,
    };
    let h = HostAlongHome::with_ports(Arc::new(pre), Arc::new(NoLaunch), Arc::new(NoAdopt));
    let handle = h.open(&path).unwrap();
    let pass = h
        .store_and_preflight(
            &handle,
            "openai",
            SecretBytes::new(key),
            &CancelToken::new(),
        )
        .unwrap();
    assert!(!format!("{pass:?}").contains(key));
    for ev in rec.0.lock().unwrap().iter() {
        assert!(!format!("{ev:?}").contains(key), "{ev:?}");
        assert!(!ev.payload.to_string().contains(key));
    }
    assert_home_has_no_plaintext(&path, key);
    let status = format!("{:?}", h.provider_status(&handle));
    assert!(!status.contains(key));
    assert_eq!(h.current_display_name(&handle), None);

    let exec401 = Arc::new(MockHttpExecutor::new().with_response(
        "https://api.openai.com",
        HttpResponse {
            status: 401,
            headers: vec![("content-type".into(), "application/json".into())],
            body: openai_ok_body(),
        },
    ));
    let rec2 = Arc::new(RecBus(Mutex::new(Vec::new())));
    let pre_fail = GeneratePathPreflight {
        executor: exec401,
        ssrf: Arc::new(DefaultSsrfGuard::with_resolver(Box::new(
            MockResolver::new().with(
                "api.openai.com",
                vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()],
            ),
        ))),
        event_bus: Arc::clone(&rec2) as Arc<dyn EventBusEmit>,
    };
    let h2 = HostAlongHome::with_ports(Arc::new(pre_fail), Arc::new(NoLaunch), Arc::new(NoAdopt));
    let handle = h2.open(&path).unwrap();
    let fail = h2
        .store_and_preflight(
            &handle,
            "openai",
            SecretBytes::new(key),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(!format!("{fail}").contains(key));
    assert!(!format!("{fail:?}").contains(key));
    for ev in rec2.0.lock().unwrap().iter() {
        assert!(!format!("{ev:?}").contains(key));
    }

    let bytes = SecretBytes::new(key);
    assert!(!format!("{bytes:?}").contains(key));
    drop(bytes);
    assert_home_has_no_plaintext(&path, key);

    let crash_src = include_str!("../src/contract.rs");
    assert!(!crash_src.to_ascii_lowercase().contains("crash_report"));
    assert!(!crash_src.to_ascii_lowercase().contains("crash-report"));

    let src = include_str!("../src/contract.rs");
    for ty in [
        "pub struct PreflightPass",
        "pub enum ProviderStatus",
        "pub struct AlongHomeHandle",
        "pub struct ConnectedAlong",
    ] {
        let idx = src.find(ty).expect(ty);
        let chunk = &src[idx..idx + 180];
        assert!(
            !chunk.contains("api_key")
                && !chunk.contains("SecretBytes")
                && !chunk.contains("secret:"),
            "{ty} has a key-like field: {chunk}"
        );
    }
    let _status: ProviderStatus = ProviderStatus::Absent;
    let _pass = PreflightPass {
        provider_id: "openai".into(),
    };
    let name = h2.current_display_name(&handle);
    let _: Option<String> = name;
}
