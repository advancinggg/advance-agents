//! T104 / T108 — MODULE-001-AC-25

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use advance_along_home::{
    write_recognizable_home, AlongHomeFirstOpen, CancelToken, HostAlongHome, PreflightFail,
    PreflightPort, ProviderStatus, SecretBytes,
};
use advance_runtime::config::LlmProviderConfig;
use cap_secrets::{
    ensure_master_key, DefaultEntryProvider, FileSecretStorage, MasterKeyConfig, SecretStore,
};

struct ScriptedPreflight {
    next: AtomicUsize,
    outcomes: Vec<Result<(), PreflightFail>>,
}

impl PreflightPort for ScriptedPreflight {
    fn preflight(
        &self,
        _home: &Path,
        _provider: &LlmProviderConfig,
        _key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        if cancel.is_cancelled() {
            return Err(PreflightFail::Cancelled);
        }
        let i = self.next.fetch_add(1, Ordering::SeqCst);
        self.outcomes.get(i).cloned().unwrap_or(Ok(()))
    }
}

fn home_with_ports(preflight: ScriptedPreflight) -> HostAlongHome {
    home_with_ports_custom(preflight)
}

fn home_with_ports_custom(preflight: impl PreflightPort + 'static) -> HostAlongHome {
    HostAlongHome::with_ports(
        Arc::new(preflight),
        Arc::new(advance_along_home::ProcessLauncher),
        Arc::new(NeverAdopt),
    )
}

struct MidCancel {
    started: Arc<std::sync::Barrier>,
}

impl PreflightPort for MidCancel {
    fn preflight(
        &self,
        _home: &Path,
        _provider: &LlmProviderConfig,
        _key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        self.started.wait();
        while !cancel.is_cancelled() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Err(PreflightFail::Cancelled)
    }
}

struct NeverAdopt;
impl advance_along_home::AdoptPort for NeverAdopt {
    fn wait_adopted(
        &self,
        _home: &Path,
        _expected_provider: &str,
        _cancel: &CancelToken,
    ) -> Result<(), advance_along_home::AdoptError> {
        Ok(())
    }
}

#[test]
fn t104_replace_only_on_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let key_a = "sk-test-KEY-A-unique";
    let key_b = "sk-test-KEY-B-unique";
    let key_c = "sk-test-KEY-C-unique";

    let pre = ScriptedPreflight {
        next: AtomicUsize::new(0),
        outcomes: vec![
            Ok(()),
            Err(PreflightFail::ProviderRejected {
                reason: "provider-error".into(),
            }),
            Ok(()),
        ],
    };
    let h = home_with_ports(pre);
    let handle = h.open(&path).unwrap();
    let cancel = CancelToken::new();

    let pass = h
        .store_and_preflight(&handle, "anthropic", SecretBytes::new(key_a), &cancel)
        .unwrap();
    assert_eq!(pass.provider_id, "anthropic");
    assert!(!format!("{pass:?}").contains(key_a));

    let fail = h
        .store_and_preflight(&handle, "anthropic", SecretBytes::new(key_b), &cancel)
        .unwrap_err();
    assert!(!format!("{fail:?}").contains(key_b));
    assert!(!format!("{fail}").contains(key_b));
    assert_eq!(committed_secret(&path), key_a);

    let started = Arc::new(std::sync::Barrier::new(2));
    let mid_port = MidCancel {
        started: Arc::clone(&started),
    };
    let h_mid = home_with_ports_custom(mid_port);
    let handle_mid = h_mid.open(&path).unwrap();
    let cxl = CancelToken::new();
    let cxl2 = cxl.clone();
    let started2 = Arc::clone(&started);
    let join = std::thread::spawn(move || {
        started2.wait();
        cxl2.cancel();
    });
    let cancelled = h_mid
        .store_and_preflight(&handle_mid, "anthropic", SecretBytes::new(key_b), &cxl)
        .unwrap_err();
    join.join().unwrap();
    assert_eq!(cancelled, PreflightFail::Cancelled);
    assert!(!format!("{cancelled}").contains(key_b));
    assert_eq!(committed_secret(&path), key_a);

    h.store_and_preflight(&handle, "anthropic", SecretBytes::new(key_c), &cancel)
        .unwrap();
    assert_eq!(committed_secret(&path), key_c);
}

#[test]
fn t108_provider_status_and_select() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let h = HostAlongHome::production();
    let handle = h.open(&path).unwrap();
    assert_eq!(h.provider_status(&handle), ProviderStatus::Absent);
    let missing = h
        .confirm_existing_provider(&handle, &CancelToken::new())
        .unwrap_err();
    assert_eq!(missing, PreflightFail::MissingProvider);

    let mk = MasterKeyConfig::EnvVar("SECRETS_MASTER_KEY".into());
    let master = ensure_master_key(&path, &mk, &DefaultEntryProvider).unwrap();
    let store = SecretStore::new(
        master,
        Arc::new(FileSecretStorage::open(path.join(".advance").join("secrets.json")).unwrap()),
    );
    store
        .store("anthropic-api-key", "sk-test-init-present")
        .unwrap();
    match h.provider_status(&handle) {
        ProviderStatus::Present { provider_id } => assert_eq!(provider_id, "anthropic"),
        other => panic!("{other:?}"),
    }

    let h_sel = home_with_ports(ScriptedPreflight {
        next: AtomicUsize::new(0),
        outcomes: vec![Ok(())],
    });
    let handle = h_sel.open(&path).unwrap();
    h_sel
        .store_and_preflight(
            &handle,
            "openai",
            SecretBytes::new("sk-test-T108-select"),
            &CancelToken::new(),
        )
        .unwrap();
    let cfg =
        advance_runtime::config::load_config(&path.join(".advance").join("runtime-config.yaml"))
            .unwrap();
    assert_eq!(cfg.llm_providers[0].id, "openai");
    assert_eq!(cfg.llm_providers[0].api_key_secret, "openai-api-key");
    assert_eq!(
        cap_llm::resolve_provider_and_model(&cfg.llm_providers, None)
            .unwrap()
            .id,
        "openai"
    );
}

fn committed_secret(home: &Path) -> String {
    let mk = MasterKeyConfig::EnvVar("SECRETS_MASTER_KEY".into());
    let master = ensure_master_key(home, &mk, &DefaultEntryProvider).unwrap();
    let store = SecretStore::new(
        master,
        Arc::new(FileSecretStorage::open(home.join(".advance").join("secrets.json")).unwrap()),
    );
    use secrecy::ExposeSecret;
    store
        .resolve("anthropic-api-key")
        .unwrap()
        .expose_secret()
        .to_string()
}
