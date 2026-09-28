//! The production `ProviderAdminProvider` (CONTRACT-190 providers family) over the workspace's
//! `runtime-config.yaml` (advance-home's shared `llm-providers` writer), the daemon's LIVE
//! `SecretStore`, the config watcher, and the first-open preflight port
//! (lane providers-family, 2026-09-16). Hoisted from `advance-cli` into this lib crate on
//! 2026-09-28 (OPEN-CORE-BOUNDARY §7.4) so a product composition root — e.g. Along's bundled
//! `engine-host` — can serve the same family without depending on the CLI binary crate;
//! `advance_cli::client_api_providers` re-exports it unchanged.
//!
//! Invariants this adapter owns:
//! - **Keys go through the live store.** `FileSecretStorage` caches the whole file at `open`
//!   and rewrites it on every mutation, so a second instance would neither see the daemon's
//!   view nor be seen by it (and the daemon's next write would drop the key). `set_key` /
//!   `clear_key` / `key.present` use the `Arc<SecretStore>` wiring built for the LLM egress
//!   chain; only a daemon that has no live store (no `llm` / `secrets` declaration) opens the
//!   file itself.
//! - **Preflight before store.** A `cloud-http` key is verified through the SAME overlay
//!   preflight the Landing first-open flow uses (`crate::GeneratePathPreflight`: an
//!   in-memory `SecretStore` overlay + `chat_preflight`), bounded by [`PREFLIGHT_TIMEOUT`]. A
//!   failed / timed-out preflight leaves the previous key untouched and is reported as data.
//! - **Every YAML write waits for the applied reload** (≤ [`RELOAD_WAIT`]) on a subscription
//!   taken BEFORE the write; a miss is the `reload_pending` advisory, never an error.
//! - `ClientApi::handle()` is SYNC and may run on a tokio worker; the reload wait therefore
//!   runs on an OWNED current-thread runtime on a scoped thread (never `Handle::block_on`).
//! - Nothing here formats key material: summaries carry the secret NAME + presence, preflight
//!   verdicts carry a fixed reason vocabulary, and `ProviderError` inner strings are ids.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    CancelToken, PreflightFail, PreflightPort, ProviderWriteError, SecretBytes, UpsertMode,
};
use advance_client_api::provider_admin::{
    ClientCreateProviderRequest, ClientProviderAgentCli, ClientProviderCost,
    ClientProviderDeleteResult, ClientProviderKey, ClientProviderKeyResult,
    ClientProviderPreflightResult, ClientProviderRateLimit, ClientProviderRetry,
    ClientProviderSidecar, ClientProviderSummary, ClientUpdateProviderRequest,
    ProviderAdminOutcome, ProviderAdminWarning, DEFAULT_BACKEND_CLASS,
};
use advance_client_api::{ClientApi, ProviderAdminProvider, ProviderError};
use advance_runtime::config::{
    AgentCliSpec, AuthScheme, InferenceBackendClass, LlmProviderConfig, ProviderBackend,
    RuntimeConfig, RuntimeConfigProvider,
};
use cap_llm::backend_cli::{AgentCliAuthProbe, ProcessAuthProbe};
use cap_secrets::{SecretError, SecretStore};
use secrecy::ExposeSecret;
use serde_yml::{Mapping, Value};

/// How long a YAML write waits for the config watcher to report the applied reload.
pub const RELOAD_WAIT: Duration = Duration::from_secs(2);
/// Bound on one preflight (the cancel token fires at the deadline; reason `timeout`).
pub const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(30);

const REASON_TIMEOUT: &str = "timeout";
const REASON_CANCELLED: &str = "cancelled";
const REASON_MISSING_KEY: &str = "missing-key";
const REASON_MISSING_PROVIDER: &str = "missing-provider";
/// The placeholder an `agent-cli` entry holds under its secret name: the runtime treats a
/// keyless entry as unusable, while the backend never reads the value (the vendor CLI
/// carries its own sign-in).
pub const AGENT_CLI_PLACEHOLDER_SECRET: &str = "agent-cli";
const REASON_UNSUPPORTED_CLASS: &str = "unsupported-backend-class";

/// Which agents pin a provider through their `.agent/config.yaml` `llm.provider` (lane
/// agent-llm-policy). A delete is refused while the list is non-empty. This lane ships only
/// [`NoReferences`]; the tree-walking cli implementation is wired after the policy lane merges.
pub trait ProviderReferenceCheck: Send + Sync {
    /// Agent ids whose `llm.provider` names `provider_id`; empty = free to delete.
    fn referenced_by(&self, provider_id: &str) -> Vec<String>;
}

/// The default reference check: nothing pins a provider.
pub struct NoReferences;

impl ProviderReferenceCheck for NoReferences {
    fn referenced_by(&self, _provider_id: &str) -> Vec<String> {
        Vec::new()
    }
}

/// The production `ProviderAdminProvider`.
pub struct WiredProviderAdmin {
    home: PathBuf,
    config: Arc<dyn RuntimeConfigProvider>,
    store: Option<Arc<SecretStore>>,
    preflight: Arc<dyn PreflightPort>,
    references: Arc<dyn ProviderReferenceCheck>,
    /// ADR 2026-09-28: the sign-in probe behind `:preflight` for `agent-cli` entries.
    agent_cli_probe: Arc<dyn AgentCliAuthProbe>,
    /// Serializes every mutation: YAML rewrites + key writes must not interleave.
    write_lock: Mutex<()>,
    /// The last preflight verdict per provider id (in-memory; cleared at restart).
    last_preflight: Mutex<HashMap<String, ClientProviderPreflightResult>>,
    reload_wait: Duration,
    preflight_timeout: Duration,
}

impl WiredProviderAdmin {
    pub fn new(
        home: impl Into<PathBuf>,
        config: Arc<dyn RuntimeConfigProvider>,
        store: Option<Arc<SecretStore>>,
        preflight: Arc<dyn PreflightPort>,
        references: Arc<dyn ProviderReferenceCheck>,
    ) -> Self {
        Self {
            home: home.into(),
            config,
            store,
            preflight,
            references,
            agent_cli_probe: Arc::new(ProcessAuthProbe::default()),
            write_lock: Mutex::new(()),
            last_preflight: Mutex::new(HashMap::new()),
            reload_wait: RELOAD_WAIT,
            preflight_timeout: PREFLIGHT_TIMEOUT,
        }
    }

    /// Override the `agent-cli` sign-in probe (tests / product composition roots).
    pub fn with_agent_cli_probe(mut self, probe: Arc<dyn AgentCliAuthProbe>) -> Self {
        self.agent_cli_probe = probe;
        self
    }

    /// Override the reload wait (tests).
    pub fn with_reload_wait(mut self, wait: Duration) -> Self {
        self.reload_wait = wait;
        self
    }

    /// Override the preflight deadline (tests).
    pub fn with_preflight_timeout(mut self, timeout: Duration) -> Self {
        self.preflight_timeout = timeout;
        self
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Whether the adapter writes keys through a daemon-owned live store (vs. opening the file).
    pub fn has_live_store(&self) -> bool {
        self.store.is_some()
    }

    // ── reads ────────────────────────────────────────────────────────────────────────────────

    /// The entries of the on-disk document (the source of truth right after a write; the
    /// watcher's `current()` catches up within a tick).
    fn entries(&self) -> Result<Vec<LlmProviderConfig>, ProviderError> {
        crate::list_provider_entries(&self.home).map_err(write_error)
    }

    fn find(&self, provider_id: &str) -> Result<(usize, LlmProviderConfig), ProviderError> {
        self.entries()?
            .into_iter()
            .enumerate()
            .find(|(_, p)| p.id == provider_id)
            .ok_or_else(|| ProviderError::NotFound(provider_id.to_string()))
    }

    /// The store keys are read from / written to: the daemon's live instance, else a fresh
    /// file-backed one over the same master-key source (only when no live store exists).
    fn key_store(&self) -> Result<Arc<SecretStore>, ProviderError> {
        if let Some(store) = &self.store {
            return Ok(Arc::clone(store));
        }
        let cfg = self.config.current();
        crate::open_home_secret_store(&self.home, &cfg)
            .map(Arc::new)
            .map_err(|e| ProviderError::Unavailable(format!("secret store: {e}")))
    }

    fn key_present(&self, secret_name: &str) -> bool {
        self.key_store()
            .ok()
            .and_then(|store| store.exists(secret_name).ok())
            .unwrap_or(false)
    }

    fn summary(&self, entry: &LlmProviderConfig, selected: bool) -> ClientProviderSummary {
        let last_preflight = self
            .last_preflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&entry.id)
            .cloned();
        ClientProviderSummary {
            provider_id: entry.id.clone(),
            backend_class: backend_class_str(entry.backend_class).to_string(),
            backend: entry.backend.map(|b| backend_str(b).to_string()),
            endpoint: entry.endpoint.clone(),
            model_aliases: entry
                .model_aliases
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            embedding_model: entry.embedding_model.clone(),
            auth_scheme: entry.auth_scheme.map(|a| auth_scheme_str(a).to_string()),
            cost: ClientProviderCost {
                input_per_mtoken: entry.cost_per_mtoken_in,
                output_per_mtoken: entry.cost_per_mtoken_out,
                cache_read_per_mtoken: entry.cost_per_mtoken_cache_read,
                cache_write_per_mtoken: entry.cost_per_mtoken_cache_write,
                cache_write_1h_per_mtoken: entry.cost_per_mtoken_cache_write_1h,
            },
            rate_limit: entry.rate_limit.as_ref().map(|rl| ClientProviderRateLimit {
                requests_per_minute: rl.requests_per_minute,
                tokens_per_minute: rl.tokens_per_minute,
            }),
            retry_default: entry.retry_default.as_ref().map(|r| ClientProviderRetry {
                max_retries: r.max_retries,
                base_delay_ms: r.base_delay_ms,
                max_delay_ms: r.max_delay_ms,
            }),
            profile_id: entry.profile_id.clone(),
            device_id: entry.device_id.clone(),
            sidecar_present: entry.sidecar.is_some(),
            agent_cli: entry.agent_cli.as_ref().map(|a| ClientProviderAgentCli {
                vendor: a.vendor.as_str().to_string(),
                command: a.command.clone(),
                args: a.args.clone(),
            }),
            key: ClientProviderKey {
                secret_name: entry.api_key_secret.clone(),
                present: self.key_present(&entry.api_key_secret),
            },
            selected,
            last_preflight,
        }
    }

    fn summary_of(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        let (idx, entry) = self.find(provider_id)?;
        Ok(self.summary(&entry, idx == 0))
    }

    // ── reload wait ──────────────────────────────────────────────────────────────────────────

    /// Wait (≤ `reload_wait`) for the watcher to publish a config satisfying `pred`. The
    /// subscription must have been taken BEFORE the write so the reload cannot be missed.
    /// Returns `true` when observed (or already current), `false` when the wait expired.
    fn wait_reload<F>(
        &self,
        mut rx: tokio::sync::mpsc::Receiver<Arc<RuntimeConfig>>,
        pred: F,
    ) -> bool
    where
        F: Fn(&RuntimeConfig) -> bool + Send + Sync,
    {
        if pred(&self.config.current()) {
            return true;
        }
        let wait = self.reload_wait;
        let observed = std::thread::scope(|s| {
            s.spawn(|| {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return false;
                };
                runtime.block_on(async {
                    tokio::time::timeout(wait, async {
                        while let Some(cfg) = rx.recv().await {
                            if pred(&cfg) {
                                return true;
                            }
                        }
                        false
                    })
                    .await
                    .unwrap_or(false)
                })
            })
            .join()
            .unwrap_or(false)
        });
        observed || pred(&self.config.current())
    }

    // ── preflight ────────────────────────────────────────────────────────────────────────────

    /// Run the overlay preflight for `entry` with `key`, bounded by `preflight_timeout`.
    fn run_preflight(&self, entry: &LlmProviderConfig, key: &str) -> ClientProviderPreflightResult {
        let cancel = CancelToken::new();
        let deadline_cancel = cancel.clone();
        let deadline = self.preflight_timeout;
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let timer = std::thread::spawn(move || {
            // A `recv_timeout` miss means the preflight is still running at the deadline.
            if done_rx.recv_timeout(deadline).is_err() {
                deadline_cancel.cancel();
                true
            } else {
                false
            }
        });
        let key = SecretBytes::new(key.to_string());
        let outcome = self.preflight.preflight(&self.home, entry, &key, &cancel);
        let _ = done_tx.send(());
        let timed_out = timer.join().unwrap_or(false);
        let reason = match outcome {
            Ok(()) => None,
            Err(PreflightFail::Cancelled) if timed_out => Some(REASON_TIMEOUT.to_string()),
            Err(PreflightFail::Cancelled) => Some(REASON_CANCELLED.to_string()),
            Err(PreflightFail::MissingProvider) => Some(REASON_MISSING_PROVIDER.to_string()),
            Err(PreflightFail::ProviderRejected { reason }) => Some(reason),
        };
        ClientProviderPreflightResult {
            ok: reason.is_none(),
            checked_at_ms: now_ms(),
            reason,
        }
    }

    /// `agent-cli`: the verdict is the vendor CLI's own sign-in status (no key involved).
    fn run_agent_cli_preflight(&self, spec: &AgentCliSpec) -> ClientProviderPreflightResult {
        let probe = self.agent_cli_probe.probe(spec);
        let reason = if probe.signed_in {
            None
        } else if !probe.cli_present {
            Some("cli-not-found".to_string())
        } else if probe.detail == "timeout" || probe.detail == "cancelled" {
            Some(probe.detail.clone())
        } else if probe.detail == "daemon-identity-unknown" {
            Some(probe.detail.clone())
        } else if probe.detail == "cli-failed" {
            Some(probe.detail.clone())
        } else {
            Some("not-signed-in".to_string())
        };
        ClientProviderPreflightResult {
            ok: probe.signed_in,
            checked_at_ms: now_ms(),
            reason,
        }
    }

    /// An `agent-cli` entry is created with its placeholder secret so the "no key, no
    /// provider" rule reads it as usable; nothing ever resolves the value.
    fn store_agent_cli_placeholder(&self, entry: &LlmProviderConfig) {
        if let Some(store) = self.store.as_ref() {
            if !self.key_present(&entry.api_key_secret) {
                let _ = store.store(&entry.api_key_secret, AGENT_CLI_PLACEHOLDER_SECRET);
            }
        }
    }

    fn record_preflight(&self, provider_id: &str, result: &ClientProviderPreflightResult) {
        self.last_preflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(provider_id.to_string(), result.clone());
    }
}

impl ProviderAdminProvider for WiredProviderAdmin {
    fn list_providers(&self) -> Result<Vec<ClientProviderSummary>, ProviderError> {
        Ok(self
            .entries()?
            .iter()
            .enumerate()
            .map(|(idx, entry)| self.summary(entry, idx == 0))
            .collect())
    }

    fn get_provider(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        self.summary_of(provider_id)
    }

    fn create_provider(
        &self,
        request: &ClientCreateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let rx = self.config.subscribe();
        crate::upsert_provider_entry(&self.home, create_mapping(request), UpsertMode::Create)
            .map_err(write_error)?;
        let (idx, entry) = self.find(&request.provider_id)?;
        let mut outcome = ProviderAdminOutcome::new(self.summary(&entry, idx == 0));
        let applied = entry.clone();
        if !self.wait_reload(rx, move |cfg| {
            cfg.llm_providers.iter().any(|p| *p == applied)
        }) {
            outcome = outcome.with_warning(ProviderAdminWarning::ReloadPending);
        }
        if outcome.value.sidecar_present && outcome.value.backend_class == "local" {
            outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
        }
        if let (InferenceBackendClass::AgentCli, Some(spec)) =
            (entry.backend_class, &entry.agent_cli)
        {
            // The backend registry is built at daemon boot; the sign-in probe answers now.
            self.store_agent_cli_placeholder(&entry);
            let verdict = self.run_agent_cli_preflight(spec);
            self.record_preflight(&request.provider_id, &verdict);
            outcome.value = self.summary(&entry, idx == 0);
            outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
        }
        Ok(outcome)
    }

    fn update_provider(
        &self,
        provider_id: &str,
        request: &ClientUpdateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.find(provider_id)?;
        let rx = self.config.subscribe();
        crate::upsert_provider_entry(
            &self.home,
            update_mapping(provider_id, request),
            UpsertMode::Update,
        )
        .map_err(write_error)?;
        let (idx, entry) = self.find(provider_id)?;
        let mut outcome = ProviderAdminOutcome::new(self.summary(&entry, idx == 0));
        let applied = entry.clone();
        if !self.wait_reload(rx, move |cfg| {
            cfg.llm_providers.iter().any(|p| *p == applied)
        }) {
            outcome = outcome.with_warning(ProviderAdminWarning::ReloadPending);
        }
        if request.sidecar.is_some() && outcome.value.backend_class == "local" {
            outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
        }
        if request.agent_cli.is_some() && entry.backend_class == InferenceBackendClass::AgentCli {
            outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
        }
        Ok(outcome)
    }

    fn delete_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderDeleteResult>, ProviderError> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let entries = self.entries()?;
        if !entries.iter().any(|p| p.id == provider_id) {
            return Err(ProviderError::NotFound(provider_id.to_string()));
        }
        if entries.len() <= 1 {
            return Err(ProviderError::InvalidState("last-provider".into()));
        }
        if !self.references.referenced_by(provider_id).is_empty() {
            return Err(ProviderError::InvalidState("referenced-by-agent".into()));
        }
        let removed = entries.iter().find(|p| p.id == provider_id).cloned();
        let rx = self.config.subscribe();
        crate::remove_provider_entry(&self.home, provider_id).map_err(write_error)?;
        // An `agent-cli` entry owned only its placeholder secret: drop it with the entry so
        // nothing accumulates in the store (a real key of another class stays, as before).
        if let (Some(entry), Some(store)) = (removed.as_ref(), self.store.as_ref()) {
            if entry.backend_class == InferenceBackendClass::AgentCli {
                let is_placeholder = store
                    .resolve(&entry.api_key_secret)
                    .map(|v| v.expose_secret() == AGENT_CLI_PLACEHOLDER_SECRET)
                    .unwrap_or(false);
                if is_placeholder {
                    let _ = store.remove(&entry.api_key_secret);
                }
            }
        }
        let remaining = self.entries()?;
        let result = ClientProviderDeleteResult {
            provider_id: provider_id.to_string(),
            selected_provider_id: remaining.first().map(|p| p.id.clone()),
        };
        let gone = provider_id.to_string();
        let mut outcome = ProviderAdminOutcome::new(result);
        if !self.wait_reload(rx, move |cfg| {
            !cfg.llm_providers.iter().any(|p| p.id == gone)
        }) {
            outcome = outcome.with_warning(ProviderAdminWarning::ReloadPending);
        }
        Ok(outcome)
    }

    fn set_key(
        &self,
        provider_id: &str,
        key: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderKeyResult>, ProviderError> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (_, entry) = self.find(provider_id)?;
        let store = self.key_store()?;
        let mut outcome = ProviderAdminOutcome::new(ClientProviderKeyResult::default());
        let preflight = if entry.backend_class == InferenceBackendClass::CloudHttp {
            let verdict = self.run_preflight(&entry, key);
            self.record_preflight(provider_id, &verdict);
            if !verdict.ok {
                // The previous key (if any) stays; the verdict is the answer.
                outcome.value = ClientProviderKeyResult {
                    stored: false,
                    preflight: Some(verdict),
                };
                return Ok(outcome);
            }
            Some(verdict)
        } else {
            outcome = outcome.with_warning(ProviderAdminWarning::PreflightSkipped);
            None
        };
        store
            .store(&entry.api_key_secret, key)
            .map_err(|_| ProviderError::Unavailable("secret store write".into()))?;
        outcome.value = ClientProviderKeyResult {
            stored: true,
            preflight,
        };
        Ok(outcome)
    }

    fn clear_key(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (idx, entry) = self.find(provider_id)?;
        let store = self.key_store()?;
        store
            .remove(&entry.api_key_secret)
            .map_err(|_| ProviderError::Unavailable("secret store write".into()))?;
        Ok(self.summary(&entry, idx == 0))
    }

    fn preflight(&self, provider_id: &str) -> Result<ClientProviderPreflightResult, ProviderError> {
        let (_, entry) = self.find(provider_id)?;
        if let (InferenceBackendClass::AgentCli, Some(spec)) =
            (entry.backend_class, &entry.agent_cli)
        {
            let verdict = self.run_agent_cli_preflight(spec);
            self.record_preflight(provider_id, &verdict);
            return Ok(verdict);
        }
        let verdict = if entry.backend_class != InferenceBackendClass::CloudHttp {
            ClientProviderPreflightResult {
                ok: false,
                checked_at_ms: now_ms(),
                reason: Some(REASON_UNSUPPORTED_CLASS.to_string()),
            }
        } else {
            let store = self.key_store()?;
            match store.resolve(&entry.api_key_secret) {
                Ok(secret) => self.run_preflight(&entry, secret.expose_secret()),
                Err(SecretError::NotFound(_)) => ClientProviderPreflightResult {
                    ok: false,
                    checked_at_ms: now_ms(),
                    reason: Some(REASON_MISSING_KEY.to_string()),
                },
                Err(_) => {
                    return Err(ProviderError::Unavailable("secret store read".into()));
                }
            }
        };
        self.record_preflight(provider_id, &verdict);
        Ok(verdict)
    }

    fn select_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.find(provider_id)?;
        let rx = self.config.subscribe();
        crate::select_provider(&self.home, provider_id).map_err(write_error)?;
        // Keep the Landing adopt file consistent with the document even before the daemon's
        // own reload subscriber (start.rs) rewrites it.
        let _ = crate::write_selected_provider(&self.home, std::process::id(), provider_id);
        let (_, entry) = self.find(provider_id)?;
        let mut outcome = ProviderAdminOutcome::new(self.summary(&entry, true));
        let id = provider_id.to_string();
        if !self.wait_reload(rx, move |cfg| {
            cfg.llm_providers.first().map(|p| p.id.as_str()) == Some(id.as_str())
        }) {
            outcome = outcome.with_warning(ProviderAdminWarning::ReloadPending);
        }
        Ok(outcome)
    }
}

/// Late-install the providers adapter into an already-bound `Arc<ClientApi>` (tests mount an
/// adapter with a mock preflight port onto the daemon-composed API).
pub fn install_provider_admin(api: &ClientApi, adapter: Arc<WiredProviderAdmin>) {
    api.install_provider_admin(adapter);
}

// ── YAML mapping builders (runtime kebab-case spellings) ─────────────────────────────────────

fn key(s: &str) -> Value {
    Value::String(s.to_string())
}

fn cost_into(m: &mut Mapping, cost: &ClientProviderCost) {
    m.insert(
        key("cost-per-mtoken-in"),
        Value::from(cost.input_per_mtoken),
    );
    m.insert(
        key("cost-per-mtoken-out"),
        Value::from(cost.output_per_mtoken),
    );
    for (name, value) in [
        ("cost-per-mtoken-cache-read", cost.cache_read_per_mtoken),
        ("cost-per-mtoken-cache-write", cost.cache_write_per_mtoken),
        (
            "cost-per-mtoken-cache-write-1h",
            cost.cache_write_1h_per_mtoken,
        ),
    ] {
        // `null` = "no such key": dropped on create, removes the stored key on update — the
        // cost group is replaced wholesale, never merged.
        m.insert(
            key(name),
            match value {
                Some(v) => Value::from(v),
                None => Value::Null,
            },
        );
    }
}

fn rate_limit_value(rl: &ClientProviderRateLimit) -> Value {
    let mut m = Mapping::new();
    m.insert(
        key("requests-per-minute"),
        Value::from(rl.requests_per_minute),
    );
    m.insert(key("tokens-per-minute"), Value::from(rl.tokens_per_minute));
    Value::Mapping(m)
}

fn retry_value(r: &ClientProviderRetry) -> Value {
    let mut m = Mapping::new();
    m.insert(key("max-retries"), Value::from(r.max_retries));
    m.insert(key("base-delay-ms"), Value::from(r.base_delay_ms));
    m.insert(key("max-delay-ms"), Value::from(r.max_delay_ms));
    Value::Mapping(m)
}

fn agent_cli_value(a: &ClientProviderAgentCli) -> Value {
    let mut m = Mapping::new();
    m.insert(key("vendor"), key(&a.vendor));
    m.insert(key("command"), key(&a.command));
    if !a.args.is_empty() {
        m.insert(
            key("args"),
            Value::Sequence(a.args.iter().map(|s| key(s)).collect()),
        );
    }
    Value::Mapping(m)
}

fn sidecar_value(s: &ClientProviderSidecar) -> Value {
    let mut m = Mapping::new();
    m.insert(key("command"), key(&s.command));
    m.insert(
        key("args"),
        Value::Sequence(s.args.iter().map(|a| key(a)).collect()),
    );
    Value::Mapping(m)
}

fn aliases_value(aliases: &std::collections::BTreeMap<String, String>) -> Value {
    let mut m = Mapping::new();
    for (k, v) in aliases {
        m.insert(key(k), key(v));
    }
    Value::Mapping(m)
}

/// The YAML mapping of a create request (the runtime's `LlmProviderConfigRaw` spelling).
fn create_mapping(req: &ClientCreateProviderRequest) -> Value {
    let mut m = Mapping::new();
    m.insert(key("id"), key(&req.provider_id));
    let class = req
        .backend_class
        .as_deref()
        .unwrap_or(DEFAULT_BACKEND_CLASS);
    if class != DEFAULT_BACKEND_CLASS {
        m.insert(key("backend-class"), key(class));
    }
    if let Some(backend) = &req.backend {
        m.insert(key("backend"), key(backend));
    }
    if let Some(endpoint) = &req.endpoint {
        m.insert(key("endpoint"), key(endpoint));
    }
    let secret = req
        .api_key_secret
        .clone()
        .unwrap_or_else(|| format!("{}-api-key", req.provider_id));
    m.insert(key("api-key-secret"), key(&secret));
    m.insert(key("model-aliases"), aliases_value(&req.model_aliases));
    if let Some(model) = &req.embedding_model {
        m.insert(key("embedding-model"), key(model));
    }
    if let Some(scheme) = &req.auth_scheme {
        m.insert(key("auth-scheme"), key(scheme));
    }
    cost_into(&mut m, &req.cost);
    m.insert(key("rate-limit"), rate_limit_value(&req.rate_limit));
    if let Some(retry) = &req.retry_default {
        m.insert(key("retry-default"), retry_value(retry));
    }
    if let Some(sidecar) = &req.sidecar {
        m.insert(key("sidecar"), sidecar_value(sidecar));
    }
    if let Some(agent_cli) = &req.agent_cli {
        m.insert(key("agent-cli"), agent_cli_value(agent_cli));
    }
    if let Some(profile) = &req.profile_id {
        m.insert(key("profile-id"), key(profile));
    }
    if let Some(device) = &req.device_id {
        m.insert(key("device-id"), key(device));
    }
    Value::Mapping(m)
}

/// The YAML mapping of an update: only the fields the request names (plus `id`).
fn update_mapping(provider_id: &str, req: &ClientUpdateProviderRequest) -> Value {
    let mut m = Mapping::new();
    m.insert(key("id"), key(provider_id));
    if let Some(class) = &req.backend_class {
        m.insert(key("backend-class"), key(class));
    }
    if let Some(backend) = &req.backend {
        m.insert(key("backend"), key(backend));
    }
    if let Some(endpoint) = &req.endpoint {
        m.insert(key("endpoint"), key(endpoint));
    }
    if let Some(aliases) = &req.model_aliases {
        m.insert(key("model-aliases"), aliases_value(aliases));
    }
    if let Some(model) = &req.embedding_model {
        m.insert(key("embedding-model"), key(model));
    }
    if let Some(scheme) = &req.auth_scheme {
        m.insert(key("auth-scheme"), key(scheme));
    }
    if let Some(secret) = &req.api_key_secret {
        m.insert(key("api-key-secret"), key(secret));
    }
    if let Some(cost) = &req.cost {
        cost_into(&mut m, cost);
    }
    if let Some(rl) = &req.rate_limit {
        m.insert(key("rate-limit"), rate_limit_value(rl));
    }
    if let Some(retry) = &req.retry_default {
        m.insert(key("retry-default"), retry_value(retry));
    }
    if let Some(sidecar) = &req.sidecar {
        m.insert(key("sidecar"), sidecar_value(sidecar));
    }
    if let Some(agent_cli) = &req.agent_cli {
        m.insert(key("agent-cli"), agent_cli_value(agent_cli));
    }
    if let Some(profile) = &req.profile_id {
        m.insert(key("profile-id"), key(profile));
    }
    if let Some(device) = &req.device_id {
        m.insert(key("device-id"), key(device));
    }
    Value::Mapping(m)
}

fn write_error(e: ProviderWriteError) -> ProviderError {
    match e {
        ProviderWriteError::NotFound => ProviderError::NotFound("provider".into()),
        ProviderWriteError::AlreadyExists => ProviderError::AlreadyExists("provider".into()),
        ProviderWriteError::Invalid(m) => ProviderError::InvalidRequest(m),
        ProviderWriteError::Io(m) => ProviderError::Unavailable(m),
    }
}

fn backend_class_str(class: InferenceBackendClass) -> &'static str {
    match class {
        InferenceBackendClass::CloudHttp => "cloud-http",
        InferenceBackendClass::Local => "local",
        InferenceBackendClass::MeshRemote => "mesh-remote",
        InferenceBackendClass::AgentCli => "agent-cli",
    }
}

fn backend_str(backend: ProviderBackend) -> &'static str {
    match backend {
        ProviderBackend::OpenAiChat => "openai-chat",
        ProviderBackend::OpenAiResponses => "openai-responses",
        ProviderBackend::AnthropicMessages => "anthropic-messages",
    }
}

fn auth_scheme_str(scheme: AuthScheme) -> &'static str {
    match scheme {
        AuthScheme::Bearer => "bearer",
        AuthScheme::XApiKey => "x-api-key",
        AuthScheme::ApiKey => "api-key",
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_mapping_uses_runtime_spellings_and_secret_default() {
        let req = ClientCreateProviderRequest {
            provider_id: "anthropic".into(),
            backend: Some("anthropic-messages".into()),
            endpoint: Some("https://api.anthropic.com".into()),
            model_aliases: [("sonnet".to_string(), "claude-sonnet-4-5".to_string())]
                .into_iter()
                .collect(),
            cost: ClientProviderCost {
                input_per_mtoken: 3.0,
                output_per_mtoken: 15.0,
                cache_read_per_mtoken: Some(0.3),
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 100,
                tokens_per_minute: 1000,
            },
            ..Default::default()
        };
        let v = create_mapping(&req);
        assert_eq!(v["id"], "anthropic");
        assert!(v.get("backend-class").is_none(), "default class is omitted");
        assert_eq!(v["backend"], "anthropic-messages");
        assert_eq!(v["api-key-secret"], "anthropic-api-key");
        assert_eq!(v["model-aliases"]["sonnet"], "claude-sonnet-4-5");
        assert_eq!(v["cost-per-mtoken-cache-read"], 0.3);
        // Absent optional prices travel as `null` (the writer drops them on create and
        // removes the stored key on update — the cost group is never merged).
        assert!(v["cost-per-mtoken-cache-write"].is_null());
        assert!(v["cost-per-mtoken-cache-write-1h"].is_null());
        assert_eq!(v["rate-limit"]["requests-per-minute"], 100);
        // The rendered mapping parses as a runtime provider entry.
        let parsed: LlmProviderConfig = serde_yml::from_value(v).expect("runtime parses");
        assert_eq!(parsed.id, "anthropic");
        assert_eq!(parsed.backend, Some(ProviderBackend::AnthropicMessages));
    }

    #[test]
    fn update_mapping_carries_only_named_fields() {
        let req = ClientUpdateProviderRequest {
            endpoint: Some("https://proxy.example".into()),
            ..Default::default()
        };
        let v = update_mapping("openai", &req);
        let m = v.as_mapping().unwrap();
        assert_eq!(m.len(), 2, "id + endpoint only: {m:?}");
        assert_eq!(v["endpoint"], "https://proxy.example");
    }

    #[test]
    fn write_error_projection() {
        assert!(matches!(
            write_error(ProviderWriteError::NotFound),
            ProviderError::NotFound(_)
        ));
        assert!(matches!(
            write_error(ProviderWriteError::AlreadyExists),
            ProviderError::AlreadyExists(_)
        ));
        assert!(matches!(
            write_error(ProviderWriteError::Invalid("x".into())),
            ProviderError::InvalidRequest(_)
        ));
        assert!(matches!(
            write_error(ProviderWriteError::Io("x".into())),
            ProviderError::Unavailable(_)
        ));
    }
}
