//! provider_status / store_and_preflight / confirm / YAML selected-provider rewrite.

use std::path::Path;
use std::sync::Arc;

use advance_runtime::config::{load_config, LlmProviderConfig, MasterKeySource, RuntimeConfig};
use cap_http::{DefaultHttpSecurityChain, DefaultLeakDetector, DefaultRateLimiter};
use cap_llm::{chat_preflight, resolve_provider_and_model, StaticConfig};
use cap_secrets::{
    ensure_master_key, DefaultEntryProvider, FileSecretStorage, InMemorySecretStorage,
    MasterKeyConfig, SecretStore, DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE,
};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::cancel::CancelToken;
use crate::contract::{PreflightFail, PreflightPass, ProviderStatus};
use crate::discovery::block_on_io;
use crate::ports::{GeneratePathPreflight, PreflightPort};
use crate::scaffold::MINIMAL_STARTER;
use crate::secret_bytes::SecretBytes;

pub fn provider_status(home: &Path) -> ProviderStatus {
    let cfg_path = home.join(".advance").join("runtime-config.yaml");
    let Ok(cfg) = load_config(&cfg_path) else {
        return ProviderStatus::Absent;
    };
    let Some(first) = cfg.llm_providers.first() else {
        return ProviderStatus::Absent;
    };
    let Ok(store) = open_file_store(home, &cfg) else {
        return ProviderStatus::Absent;
    };
    match store.exists(&first.api_key_secret) {
        Ok(true) => ProviderStatus::Present {
            provider_id: first.id.clone(),
        },
        _ => ProviderStatus::Absent,
    }
}

pub fn store_and_preflight(
    home: &Path,
    provider_id: &str,
    key: SecretBytes,
    cancel: &CancelToken,
    port: &dyn PreflightPort,
) -> Result<PreflightPass, PreflightFail> {
    if cancel.is_cancelled() {
        return Err(PreflightFail::Cancelled);
    }
    if provider_id.trim().is_empty() {
        return Err(PreflightFail::ProviderRejected {
            reason: "unknown-provider".into(),
        });
    }
    let cfg_path = home.join(".advance").join("runtime-config.yaml");
    let cfg = load_config(&cfg_path).map_err(|_| PreflightFail::ProviderRejected {
        reason: "unknown-provider".into(),
    })?;
    let named = find_or_starter_provider(&cfg, provider_id)?;
    port.preflight(home, &named, &key, cancel)?;
    commit_secret_and_select(home, &cfg, &named, key.expose())?;
    Ok(PreflightPass {
        provider_id: named.id,
    })
}

pub fn confirm_existing_provider(
    home: &Path,
    cancel: &CancelToken,
    port: &dyn PreflightPort,
) -> Result<PreflightPass, PreflightFail> {
    if cancel.is_cancelled() {
        return Err(PreflightFail::Cancelled);
    }
    match provider_status(home) {
        ProviderStatus::Absent => Err(PreflightFail::MissingProvider),
        ProviderStatus::Present { provider_id } => {
            let cfg_path = home.join(".advance").join("runtime-config.yaml");
            let cfg = load_config(&cfg_path).map_err(|_| PreflightFail::MissingProvider)?;
            let named = find_or_starter_provider(&cfg, &provider_id)?;
            let store = open_file_store(home, &cfg).map_err(|_| PreflightFail::MissingProvider)?;
            let secret = store
                .resolve(&named.api_key_secret)
                .map_err(|_| PreflightFail::MissingProvider)?;
            let key = SecretBytes::new(secret.expose_secret().to_string());
            port.preflight(home, &named, &key, cancel)?;
            Ok(PreflightPass { provider_id })
        }
    }
}

fn find_or_starter_provider(
    cfg: &RuntimeConfig,
    provider_id: &str,
) -> Result<LlmProviderConfig, PreflightFail> {
    if let Some(p) = cfg.llm_providers.iter().find(|p| p.id == provider_id) {
        return Ok(p.clone());
    }
    starter_provider(provider_id).ok_or(PreflightFail::ProviderRejected {
        reason: "unknown-provider".into(),
    })
}

pub fn starter_provider(provider_id: &str) -> Option<LlmProviderConfig> {
    let parsed: serde_yml::Value = serde_yml::from_str(MINIMAL_STARTER).ok()?;
    let seq = parsed.get("llm-providers")?.as_sequence()?;
    for item in seq {
        if item.get("id")?.as_str() == Some(provider_id) {
            return serde_yml::from_value(item.clone()).ok();
        }
    }
    None
}

fn commit_secret_and_select(
    home: &Path,
    cfg: &RuntimeConfig,
    named: &LlmProviderConfig,
    key: &str,
) -> Result<(), PreflightFail> {
    let store = open_file_store(home, cfg).map_err(|_| PreflightFail::ProviderRejected {
        reason: "provider-error".into(),
    })?;
    store
        .store(&named.api_key_secret, key)
        .map_err(|_| PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        })?;
    rewrite_selected_provider_yaml(home, &named.id)?;
    Ok(())
}

fn rewrite_selected_provider_yaml(home: &Path, provider_id: &str) -> Result<(), PreflightFail> {
    let cfg_path = home.join(".advance").join("runtime-config.yaml");
    let raw = crate::scaffold::read_small_regular(&cfg_path, 64 * 1024).ok_or(
        PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        },
    )?;
    let mut value: serde_yml::Value =
        serde_yml::from_str(&raw).map_err(|_| PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        })?;
    let seq = value
        .get_mut("llm-providers")
        .and_then(|v| v.as_sequence_mut())
        .ok_or(PreflightFail::ProviderRejected {
            reason: "unknown-provider".into(),
        })?;
    if let Some(idx) = seq
        .iter()
        .position(|e| e.get("id").and_then(|i| i.as_str()) == Some(provider_id))
    {
        let entry = seq.remove(idx);
        seq.insert(0, entry);
    } else if let Some(entry) = starter_provider_value(provider_id) {
        seq.insert(0, entry);
    } else {
        return Err(PreflightFail::ProviderRejected {
            reason: "unknown-provider".into(),
        });
    }
    let rendered = serde_yml::to_string(&value).map_err(|_| PreflightFail::ProviderRejected {
        reason: "provider-error".into(),
    })?;
    let tmp = home.join(".advance").join("runtime-config.yaml.tmp");
    crate::scaffold::write_0600_nofollow(&tmp, rendered.as_bytes()).map_err(|_| {
        PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        }
    })?;
    load_config(&tmp).map_err(|_| {
        let _ = std::fs::remove_file(&tmp);
        PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        }
    })?;
    std::fs::rename(&tmp, &cfg_path).map_err(|_| PreflightFail::ProviderRejected {
        reason: "provider-error".into(),
    })?;
    let cfg = load_config(&cfg_path).map_err(|_| PreflightFail::ProviderRejected {
        reason: "provider-error".into(),
    })?;
    let _ = resolve_provider_and_model(&cfg.llm_providers, None);
    Ok(())
}

fn starter_provider_value(provider_id: &str) -> Option<serde_yml::Value> {
    let parsed: serde_yml::Value = serde_yml::from_str(MINIMAL_STARTER).ok()?;
    parsed
        .get("llm-providers")?
        .as_sequence()?
        .iter()
        .find(|e| e.get("id").and_then(|i| i.as_str()) == Some(provider_id))
        .cloned()
}

fn open_file_store(home: &Path, cfg: &RuntimeConfig) -> Result<SecretStore, String> {
    let mk = master_key_config(cfg);
    let key = ensure_master_key(home, &mk, &DefaultEntryProvider).map_err(|e| e.to_string())?;
    let storage = FileSecretStorage::open(home.join(".advance").join("secrets.json"))
        .map_err(|e| e.to_string())?;
    Ok(SecretStore::new(key, Arc::new(storage)))
}

fn master_key_config(cfg: &RuntimeConfig) -> MasterKeyConfig {
    match cfg.secrets.master_key_source {
        MasterKeySource::EnvVar => MasterKeyConfig::EnvVar(cfg.secrets.env_var_name.clone()),
        MasterKeySource::Keychain => MasterKeyConfig::Keychain {
            service: DEFAULT_KEYCHAIN_SERVICE.to_string(),
            account: DEFAULT_KEYCHAIN_ACCOUNT.to_string(),
            fallback_env_var: Some(cfg.secrets.env_var_name.clone()),
        },
    }
}

impl PreflightPort for GeneratePathPreflight {
    fn preflight(
        &self,
        home: &Path,
        provider: &LlmProviderConfig,
        key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        if cancel.is_cancelled() {
            return Err(PreflightFail::Cancelled);
        }
        let cfg_path = home.join(".advance").join("runtime-config.yaml");
        let mut cfg = load_config(&cfg_path).map_err(|_| PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        })?;
        cfg.llm_providers = vec![provider.clone()];
        let overlay_storage = Arc::new(InMemorySecretStorage::default());
        let master = Zeroizing::new([0x11u8; 32]);
        let overlay = SecretStore::new(master, overlay_storage);
        overlay
            .store(&provider.api_key_secret, key.expose())
            .map_err(|_| PreflightFail::ProviderRejected {
                reason: "provider-error".into(),
            })?;
        let chain = Arc::new(DefaultHttpSecurityChain::new(
            Arc::new(overlay),
            Arc::new(DefaultLeakDetector::new()),
            Arc::clone(&self.ssrf),
            Arc::new(DefaultRateLimiter::new()),
            Arc::clone(&self.executor),
        ));
        let config = Arc::new(StaticConfig(Arc::new(cfg)));
        let event_bus = Arc::clone(&self.event_bus);
        let cancelled = cancel.is_cancelled();
        let result = block_on_io({
            let flag = cancel.clone();
            async move {
                tokio::select! {
                    r = chat_preflight(config, chain, event_bus, flag.as_atomic()) => r,
                    _ = async {
                        while !flag.is_cancelled() {
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    } => Err(cap_llm::LlmError::ProviderError("cancelled".into())),
                }
            }
        });
        if cancel.is_cancelled() || cancelled {
            return Err(PreflightFail::Cancelled);
        }
        match result {
            Ok(()) => Ok(()),
            Err(e)
                if e.variant_name() == "provider-error" && format!("{e}").contains("cancelled") =>
            {
                Err(PreflightFail::Cancelled)
            }
            Err(e) => Err(PreflightFail::ProviderRejected {
                reason: e.variant_name().to_string(),
            }),
        }
    }
}
