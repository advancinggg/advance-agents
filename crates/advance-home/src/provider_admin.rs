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
//! - **A sign-in entry holds no operator key.** An `auth-source: chatgpt-oauth` entry is served
//!   through the injected [`ChatGptSignInPort`] (the daemon shares ONE sign-in object between
//!   this adapter and the LLM gateway): create writes the source and the `openai-responses`
//!   dialect and stores nothing (an unnamed secret defaults to
//!   `<provider_id>-chatgpt-<first 8 hex digits of this host's id>`, so devices sharing a
//!   synchronized secret namespace never share a session name; a NAMED secret that already holds
//!   a value, or whose reserved record name does, refuses the create with `AlreadyExists`);
//!   `:preflight` is the port's verify (never the chat preflight), bounded by the preflight
//!   deadline and cached like every verdict; `usage` answers
//!   `not-provided`; delete makes the port forget the session after the entry is gone; the
//!   summary carries the port's sign-in state. Its secret name is fixed once created, the key
//!   routes answer `AuthSourceMismatch` on it, and the sign-in routes answer the same on every
//!   other entry. Without a port such an entry cannot be created and the sign-in routes answer
//!   `Unavailable`. The port's sync methods may wait on the network; they run on the Client
//!   API's blocking-pool thread like every handler here.
//! - **Claimed entries.** With [`WiredProviderAdmin::with_claimable_local_entries`], creating a
//!   `local` entry without a sidecar (or changing an entry's backend class or sidecar) answers
//!   `restart_required`: some runtime extension may claim it, and the backend registry is
//!   fixed at boot. [`WiredProviderAdmin::with_claimed_preflight`] serves `:preflight` of those
//!   claimed entries through the composed gateway; without it they keep
//!   `unsupported-backend-class`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::chatgpt_sign_in::{
    ChatGptSignInPort, SignInRefusal, SignInStatus, REASON_UNAVAILABLE as SIGN_IN_UNAVAILABLE,
};
use crate::{
    CancelToken, PreflightFail, PreflightPort, ProviderWriteError, SecretBytes, UpsertMode,
};
use advance_client_api::provider_admin::{
    ClientCreateProviderRequest, ClientProviderAgentCli, ClientProviderCost,
    ClientProviderDeleteResult, ClientProviderKey, ClientProviderKeyResult,
    ClientProviderPreflightResult, ClientProviderRateLimit, ClientProviderRetry,
    ClientProviderSidecar, ClientProviderSignIn, ClientProviderSignInModel,
    ClientProviderSignInStart, ClientProviderSignOut, ClientProviderSummary, ClientProviderUsage,
    ClientProviderUsageWindow, ClientUpdateProviderRequest, ProviderAdminOutcome,
    ProviderAdminWarning, AGENT_CLI_BACKEND_CLASS, CHATGPT_OAUTH_AUTH_SOURCE,
    CHATGPT_OAUTH_BACKEND, DEFAULT_BACKEND_CLASS,
};
use advance_client_api::{ClientApi, ProviderAdminProvider, ProviderError};
use advance_runtime::config::{
    AgentCliSpec, AuthScheme, InferenceBackendClass, LlmProviderConfig, ProviderAuthSource,
    ProviderBackend, RuntimeConfig, RuntimeConfigProvider, CHATGPT_OAUTH_RECORD_SUFFIX,
};
use advance_shared_types::process_policy::{ProcessPolicy, SpawnSite};
use cap_llm::backend_cli::{
    AgentCliAuthProbe, AgentCliUsageProbe, ProcessAuthProbe, ProcessUsageProbe,
};
use cap_secrets::{SecretError, SecretStore};
use secrecy::ExposeSecret;
use serde_yml::{Mapping, Value};

/// How long a YAML write waits for the config watcher to report the applied reload.
pub const RELOAD_WAIT: Duration = Duration::from_secs(2);
/// Bound on one preflight, the check of a sign-in entry included (the cancel token fires at the
/// deadline; reason `timeout`).
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
/// The usage reason of a sign-in entry: the plan's allowance has no API (clients link to the
/// vendor's own usage page).
const REASON_NOT_PROVIDED: &str = "not-provided";
/// The `ProviderError::Unavailable` id of every sign-in refusal (log-only).
const SIGN_IN_ID: &str = "sign-in";
/// The `ProviderError::AlreadyExists` id of an occupied sign-in secret name (log-only).
const SECRET_NAME_ID: &str = "api-key-secret";

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

/// A composer-supplied view of the `local` entries a runtime extension serves (CONTRACT-244
/// D2(b)). Implemented by runtime-compose over its composed gateway.
pub trait ClaimedEntryPreflight: Send + Sync {
    /// Whether `provider_id` was claimed at boot (fixed for the runtime's life).
    fn is_claimed(&self, provider_id: &str) -> bool;
    /// One preflight of `provider_id` through the composed gateway. `cancel` fires at the
    /// admin's deadline. Returns within `budget` plus a one-second grace even when the runtime
    /// cannot make progress. Must not be called on a worker thread of the composition's
    /// runtime: on a current-thread runtime that blocks the only worker (every loop stalls)
    /// until the bound, then answers `Cancelled`. The Client API transport calls it under
    /// `spawn_blocking`; in-process callers (the CONTRACT-210 bridge, tests calling
    /// `ClientApi::handle` directly) must do the same.
    fn preflight(
        &self,
        provider_id: &str,
        cancel: &CancelToken,
        budget: Duration,
    ) -> Result<(), PreflightFail>;
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
    /// The allowance read behind `GET …/usage` for `agent-cli` entries.
    agent_cli_usage_probe: Arc<dyn AgentCliUsageProbe>,
    /// The sign-in behind `auth-source: chatgpt-oauth` entries; `None` = not served here.
    chatgpt_sign_in: Option<Arc<dyn ChatGptSignInPort>>,
    /// Serializes every mutation: YAML rewrites + key writes must not interleave.
    write_lock: Mutex<()>,
    /// The last preflight verdict per provider id (in-memory; cleared at restart).
    last_preflight: Mutex<HashMap<String, ClientProviderPreflightResult>>,
    /// The last allowance read per provider id (in-memory; cleared at restart).
    last_usage: Mutex<HashMap<String, ClientProviderUsage>>,
    reload_wait: Duration,
    preflight_timeout: Duration,
    /// CONTRACT-244 D2(b): some runtime extension contributes inference, so `local`
    /// entries without a sidecar are claimable and the backend registry is fixed at boot.
    claimable_local: bool,
    claimed_preflight: Option<Arc<dyn ClaimedEntryPreflight>>,
    process_policy: ProcessPolicy,
    hot_reload: bool,
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
            agent_cli_usage_probe: Arc::new(ProcessUsageProbe::default()),
            chatgpt_sign_in: None,
            write_lock: Mutex::new(()),
            last_preflight: Mutex::new(HashMap::new()),
            last_usage: Mutex::new(HashMap::new()),
            reload_wait: RELOAD_WAIT,
            preflight_timeout: PREFLIGHT_TIMEOUT,
            claimable_local: false,
            claimed_preflight: None,
            process_policy: ProcessPolicy::Allow,
            hot_reload: true,
        }
    }

    /// Override the `agent-cli` sign-in probe (tests / product composition roots).
    pub fn with_agent_cli_probe(mut self, probe: Arc<dyn AgentCliAuthProbe>) -> Self {
        self.agent_cli_probe = probe;
        self
    }

    /// Override the `agent-cli` allowance read (tests / product composition roots).
    pub fn with_agent_cli_usage_probe(mut self, probe: Arc<dyn AgentCliUsageProbe>) -> Self {
        self.agent_cli_usage_probe = probe;
        self
    }

    /// Serve `auth-source: chatgpt-oauth` entries through `port`. Share the ONE sign-in object
    /// the LLM gateway uses as its credential source, so sign-in completion, renewal and
    /// sign-out are serialized against each other.
    pub fn with_chatgpt_sign_in(mut self, port: Arc<dyn ChatGptSignInPort>) -> Self {
        self.chatgpt_sign_in = Some(port);
        self
    }

    /// Whether `auth-source: chatgpt-oauth` entries are served (composition witness).
    pub fn has_chatgpt_sign_in(&self) -> bool {
        self.chatgpt_sign_in.is_some()
    }

    /// Whether the sign-in served here is the SAME object as `other` (pointer identity;
    /// composition witness for the one sign-in shared with the LLM gateway).
    pub fn chatgpt_sign_in_is(&self, other: &Arc<dyn ChatGptSignInPort>) -> bool {
        self.chatgpt_sign_in
            .as_ref()
            .is_some_and(|port| Arc::ptr_eq(port, other))
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

    /// CONTRACT-244 D2(b): some runtime extension contributes inference, so `local` entries
    /// without a sidecar are claimable and the backend registry is fixed at boot. With it,
    /// creating such an entry, or changing an entry's backend class or sidecar, also answers
    /// `restart_required`. Default `false` (the v0.1.26 behaviour).
    pub fn with_claimable_local_entries(mut self, on: bool) -> Self {
        self.claimable_local = on;
        self
    }

    /// Serve `:preflight` of claimed entries through `port` (the composed gateway). Default none:
    /// such an entry answers `unsupported-backend-class`, as at v0.1.26. See
    /// [`ClaimedEntryPreflight::preflight`] for the thread rule.
    pub fn with_claimed_preflight(mut self, port: Arc<dyn ClaimedEntryPreflight>) -> Self {
        self.claimed_preflight = Some(port);
        self
    }

    /// Composition witnesses.
    pub fn marks_local_entries_claimable(&self) -> bool {
        self.claimable_local
    }

    pub fn has_claimed_preflight(&self) -> bool {
        self.claimed_preflight.is_some()
    }

    /// Under `Forbid`: `create_provider` of an `agent-cli` entry, and `preflight` / `usage` of an
    /// `agent-cli` entry, answer `ProviderError::ProcessForbidden` before any write or probe.
    pub fn with_process_policy(mut self, process_policy: ProcessPolicy) -> Self {
        self.process_policy = process_policy;
        self
    }

    /// `false`: create / update / delete / select do not wait for the config watcher; each
    /// answers `ProviderAdminWarning::RestartRequired` (deduplicated), and select does not rewrite
    /// `.runtime/selected-provider` (the runtime has not adopted the change).
    pub fn with_hot_reload(mut self, hot_reload: bool) -> Self {
        self.hot_reload = hot_reload;
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
        let last_usage = self
            .last_usage
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
            auth_source: (entry.auth_source != ProviderAuthSource::ApiKey)
                .then(|| entry.auth_source.as_str().to_string()),
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
            last_usage,
            // Read without touching the network; absent when no sign-in is served here.
            sign_in: match (entry.uses_chatgpt_sign_in(), self.chatgpt_sign_in.as_ref()) {
                (true, Some(port)) => Some(project_sign_in(
                    port.status(&entry.api_key_secret),
                    now_ms(),
                )),
                _ => None,
            },
        }
    }

    fn summary_of(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        let (idx, entry) = self.find(provider_id)?;
        Ok(self.summary(&entry, idx == 0))
    }

    // ── sign-in entries ──────────────────────────────────────────────────────────────────────

    fn sign_in_port(&self) -> Result<&Arc<dyn ChatGptSignInPort>, ProviderError> {
        self.chatgpt_sign_in
            .as_ref()
            .ok_or_else(|| ProviderError::Unavailable(SIGN_IN_ID.into()))
    }

    /// The port and the entry a sign-in route acts on: `Unavailable` without a port,
    /// `NotFound` for an unknown id, `AuthSourceMismatch` for an entry that does not sign in.
    fn sign_in_entry(
        &self,
        provider_id: &str,
    ) -> Result<(Arc<dyn ChatGptSignInPort>, LlmProviderConfig), ProviderError> {
        let port = Arc::clone(self.sign_in_port()?);
        let (_, entry) = self.find(provider_id)?;
        if !entry.uses_chatgpt_sign_in() {
            return Err(ProviderError::AuthSourceMismatch(provider_id.to_string()));
        }
        Ok((port, entry))
    }

    /// The `api-key-secret` a create writes: the named one, else `<provider_id>-api-key` for
    /// an API-key entry, else `<provider_id>-chatgpt-<first 8 hex digits of this host's id>`
    /// for a sign-in entry (the host id is asked for only then).
    fn create_secret_name(
        &self,
        request: &ClientCreateProviderRequest,
    ) -> Result<String, ProviderError> {
        if let Some(name) = &request.api_key_secret {
            return Ok(name.clone());
        }
        if !is_sign_in_request(request) {
            return Ok(default_key_secret_name(&request.provider_id));
        }
        let host_id = self.sign_in_port()?.host_id().map_err(sign_in_refusal)?;
        sign_in_secret_name(&request.provider_id, &host_id)
            .ok_or_else(|| ProviderError::Unavailable(SIGN_IN_ID.into()))
    }

    /// A sign-in entry that names its secret must name a free one. A completed sign-in writes
    /// its access token under the name, so a value already stored there (an earlier entry's key,
    /// a secret something else reads by name) or a record under the name's reserved companion
    /// (another installation's sign-in, a session no entry names any more) refuses the create
    /// with `AlreadyExists`, before the document changes. The default name is derived from this
    /// host's id and is not checked.
    fn refuse_occupied_sign_in_name(&self, name: &str) -> Result<(), ProviderError> {
        let store = self.key_store()?;
        let record = format!("{name}{CHATGPT_OAUTH_RECORD_SUFFIX}");
        for candidate in [name, record.as_str()] {
            match store.exists(candidate) {
                Ok(false) => {}
                Ok(true) => return Err(ProviderError::AlreadyExists(SECRET_NAME_ID.into())),
                Err(_) => return Err(ProviderError::Unavailable("secret store read".into())),
            }
        }
        Ok(())
    }

    /// A sign-in entry's check: the port renews the access token when needed and lists the
    /// models with it. Never the chat preflight. Bounded by `preflight_timeout` like every
    /// preflight (reason `timeout`): the check runs on its own thread, and a renewal it started
    /// keeps running and persists after the deadline.
    fn run_sign_in_preflight(&self, entry: &LlmProviderConfig) -> ClientProviderPreflightResult {
        let failed = |reason: &str| ClientProviderPreflightResult {
            ok: false,
            checked_at_ms: now_ms(),
            reason: Some(reason.to_string()),
        };
        let Some(port) = self.chatgpt_sign_in.as_ref() else {
            return failed(SIGN_IN_UNAVAILABLE);
        };
        let port = Arc::clone(port);
        let secret_name = entry.api_key_secret.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("sign-in-preflight".into())
            .spawn(move || {
                let _ = done_tx.send(port.verify(&secret_name));
            });
        if spawned.is_err() {
            return failed(SIGN_IN_UNAVAILABLE);
        }
        match done_rx.recv_timeout(self.preflight_timeout) {
            Ok(checked) => ClientProviderPreflightResult {
                ok: checked.ok,
                checked_at_ms: now_ms(),
                reason: (!checked.ok)
                    .then(|| checked.reason.unwrap_or(SIGN_IN_UNAVAILABLE).to_string()),
            },
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => failed(REASON_TIMEOUT),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => failed(SIGN_IN_UNAVAILABLE),
        }
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

    fn subscribe_if_watching(&self) -> Option<tokio::sync::mpsc::Receiver<Arc<RuntimeConfig>>> {
        self.hot_reload.then(|| self.config.subscribe())
    }

    fn after_yaml_write<T, F>(
        &self,
        mut outcome: ProviderAdminOutcome<T>,
        rx: Option<tokio::sync::mpsc::Receiver<Arc<RuntimeConfig>>>,
        pred: F,
    ) -> ProviderAdminOutcome<T>
    where
        F: Fn(&RuntimeConfig) -> bool + Send + Sync,
    {
        match rx {
            Some(rx) => {
                if !self.wait_reload(rx, pred) {
                    outcome = outcome.with_warning(ProviderAdminWarning::ReloadPending);
                }
            }
            None => {
                if !outcome
                    .warnings
                    .contains(&ProviderAdminWarning::RestartRequired)
                {
                    outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
                }
            }
        }
        outcome
    }

    fn refuse_forbidden_agent_cli(&self) -> Result<(), ProviderError> {
        self.process_policy
            .check(SpawnSite::AgentCli)
            .map_err(|_| ProviderError::ProcessForbidden("agent-cli".into()))
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

    fn claimed_port_for(
        &self,
        entry: &LlmProviderConfig,
    ) -> Option<Arc<dyn ClaimedEntryPreflight>> {
        self.claimed_preflight
            .as_ref()
            .filter(|p| {
                entry.backend_class == InferenceBackendClass::Local
                    && entry.sidecar.is_none()
                    && p.is_claimed(&entry.id)
            })
            .cloned()
    }

    fn run_claimed_preflight(
        &self,
        port: &dyn ClaimedEntryPreflight,
        entry: &LlmProviderConfig,
    ) -> ClientProviderPreflightResult {
        let cancel = CancelToken::new();
        let deadline_cancel = cancel.clone();
        let deadline = self.preflight_timeout;
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let timer = std::thread::spawn(move || {
            if done_rx.recv_timeout(deadline).is_err() {
                deadline_cancel.cancel();
                true
            } else {
                false
            }
        });
        let outcome = port.preflight(&entry.id, &cancel, self.preflight_timeout);
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

    /// `agent-cli`: the vendor CLI's own allowance, projected onto the wire shape. The probe's
    /// fixed tokens become `reason`; `ok` carries the windows.
    fn run_agent_cli_usage(&self, spec: &AgentCliSpec) -> ClientProviderUsage {
        project_usage(self.agent_cli_usage_probe.probe_usage(spec), now_ms())
    }

    fn record_usage(&self, provider_id: &str, usage: &ClientProviderUsage) {
        self.last_usage
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(provider_id.to_string(), usage.clone());
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

/// The wire shape of a usage probe: the probe's fixed token becomes `reason` when it failed.
pub fn project_usage(
    probe: cap_llm::backend_cli::UsageProbe,
    checked_at_ms: u64,
) -> ClientProviderUsage {
    ClientProviderUsage {
        ok: probe.ok,
        checked_at_ms,
        reason: if probe.ok { None } else { Some(probe.detail) },
        plan: probe.plan,
        account: probe.account,
        windows: probe
            .windows
            .into_iter()
            .map(|w| ClientProviderUsageWindow {
                kind: w.kind,
                label: w.label,
                model: w.model,
                used_percent: w.used_percent,
                resets_at_ms: w.resets_at_ms,
                resets_label: w.resets_label,
                window_minutes: w.window_minutes,
            })
            .collect(),
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
        if request.backend_class.as_deref() == Some(AGENT_CLI_BACKEND_CLASS) {
            self.refuse_forbidden_agent_cli()?;
        }
        if is_sign_in_request(request) {
            // Nothing could ever sign the entry in: refuse before the document changes.
            self.sign_in_port()?;
            if let Some(name) = &request.api_key_secret {
                self.refuse_occupied_sign_in_name(name)?;
            }
        }
        let secret = self.create_secret_name(request)?;
        let rx = self.subscribe_if_watching();
        crate::upsert_provider_entry(
            &self.home,
            create_mapping(request, &secret),
            UpsertMode::Create,
        )
        .map_err(write_error)?;
        let (idx, entry) = self.find(&request.provider_id)?;
        let applied = entry.clone();
        let mut outcome = self.after_yaml_write(
            ProviderAdminOutcome::new(self.summary(&entry, idx == 0)),
            rx,
            move |cfg| cfg.llm_providers.iter().any(|p| *p == applied),
        );
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
        if self.claimable_local
            && entry.backend_class == InferenceBackendClass::Local
            && entry.sidecar.is_none()
            && !outcome
                .warnings
                .contains(&ProviderAdminWarning::RestartRequired)
        {
            // CONTRACT-244 D2(b): an extension may claim this entry, but the registry is fixed at boot.
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
        let (_, current) = self.find(provider_id)?;
        if current.uses_chatgpt_sign_in()
            && request
                .api_key_secret
                .as_ref()
                .is_some_and(|name| *name != current.api_key_secret)
        {
            // The session (and its record) live under the name: moving it would orphan them.
            return Err(ProviderError::InvalidRequest(
                "sign-in secret name is fixed".into(),
            ));
        }
        let rx = self.subscribe_if_watching();
        crate::upsert_provider_entry(
            &self.home,
            update_mapping(provider_id, request),
            UpsertMode::Update,
        )
        .map_err(write_error)?;
        let (idx, entry) = self.find(provider_id)?;
        let applied = entry.clone();
        let mut outcome = self.after_yaml_write(
            ProviderAdminOutcome::new(self.summary(&entry, idx == 0)),
            rx,
            move |cfg| cfg.llm_providers.iter().any(|p| *p == applied),
        );
        if request.sidecar.is_some() && outcome.value.backend_class == "local" {
            outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
        }
        if request.agent_cli.is_some() && entry.backend_class == InferenceBackendClass::AgentCli {
            outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
        }
        if self.claimable_local
            && (current.backend_class != entry.backend_class || current.sidecar != entry.sidecar)
            && !outcome
                .warnings
                .contains(&ProviderAdminWarning::RestartRequired)
        {
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
        let rx = self.subscribe_if_watching();
        crate::remove_provider_entry(&self.home, provider_id).map_err(write_error)?;
        // A sign-in entry's session goes with it, once nothing names it any more (revoked
        // best-effort, both secret names removed).
        if let (Some(entry), Some(port)) = (removed.as_ref(), self.chatgpt_sign_in.as_ref()) {
            if entry.uses_chatgpt_sign_in() {
                port.forget(&entry.api_key_secret);
            }
        }
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
        let outcome = self.after_yaml_write(ProviderAdminOutcome::new(result), rx, move |cfg| {
            !cfg.llm_providers.iter().any(|p| p.id == gone)
        });
        Ok(outcome)
    }

    fn set_key(
        &self,
        provider_id: &str,
        key: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderKeyResult>, ProviderError> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (_, entry) = self.find(provider_id)?;
        if entry.uses_chatgpt_sign_in() {
            // The value under the name is the session's access token, written by the sign-in.
            return Err(ProviderError::AuthSourceMismatch(provider_id.to_string()));
        }
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
        if entry.uses_chatgpt_sign_in() {
            // Removing the access token alone would not end the session: that is `:sign-out`.
            return Err(ProviderError::AuthSourceMismatch(provider_id.to_string()));
        }
        let store = self.key_store()?;
        store
            .remove(&entry.api_key_secret)
            .map_err(|_| ProviderError::Unavailable("secret store write".into()))?;
        Ok(self.summary(&entry, idx == 0))
    }

    fn usage(&self, provider_id: &str) -> Result<ClientProviderUsage, ProviderError> {
        let (_, entry) = self.find(provider_id)?;
        if entry.backend_class == InferenceBackendClass::AgentCli {
            self.refuse_forbidden_agent_cli()?;
        }
        let usage = match (entry.backend_class, &entry.agent_cli) {
            (InferenceBackendClass::AgentCli, Some(spec)) => self.run_agent_cli_usage(spec),
            _ if entry.uses_chatgpt_sign_in() => ClientProviderUsage {
                ok: false,
                checked_at_ms: now_ms(),
                reason: Some(REASON_NOT_PROVIDED.to_string()),
                ..ClientProviderUsage::default()
            },
            _ => ClientProviderUsage {
                ok: false,
                checked_at_ms: now_ms(),
                reason: Some(REASON_UNSUPPORTED_CLASS.to_string()),
                ..ClientProviderUsage::default()
            },
        };
        self.record_usage(provider_id, &usage);
        Ok(usage)
    }

    fn preflight(&self, provider_id: &str) -> Result<ClientProviderPreflightResult, ProviderError> {
        let (_, entry) = self.find(provider_id)?;
        if entry.backend_class == InferenceBackendClass::AgentCli {
            self.refuse_forbidden_agent_cli()?;
        }
        if let (InferenceBackendClass::AgentCli, Some(spec)) =
            (entry.backend_class, &entry.agent_cli)
        {
            let verdict = self.run_agent_cli_preflight(spec);
            self.record_preflight(provider_id, &verdict);
            return Ok(verdict);
        }
        let verdict = if entry.uses_chatgpt_sign_in() {
            self.run_sign_in_preflight(&entry)
        } else if let Some(port) = self.claimed_port_for(&entry) {
            // CONTRACT-244 D2(b): an extension serves this entry — through the composed gateway.
            self.run_claimed_preflight(port.as_ref(), &entry)
        } else if entry.backend_class != InferenceBackendClass::CloudHttp {
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
        let rx = self.subscribe_if_watching();
        crate::select_provider(&self.home, provider_id).map_err(write_error)?;
        // Keep the Landing adopt file consistent with the document even before the daemon's
        // own reload subscriber (start.rs) rewrites it.
        if self.hot_reload {
            let _ = crate::write_selected_provider(&self.home, std::process::id(), provider_id);
        }
        let (_, entry) = self.find(provider_id)?;
        let id = provider_id.to_string();
        let outcome = self.after_yaml_write(
            ProviderAdminOutcome::new(self.summary(&entry, true)),
            rx,
            move |cfg| cfg.llm_providers.first().map(|p| p.id.as_str()) == Some(id.as_str()),
        );
        Ok(outcome)
    }

    fn sign_in_start(&self, provider_id: &str) -> Result<ClientProviderSignInStart, ProviderError> {
        // Under the write lock, so a concurrent delete cannot leave an attempt for a name no
        // entry uses any more.
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (port, entry) = self.sign_in_entry(provider_id)?;
        let started = port.start(&entry.api_key_secret).map_err(sign_in_refusal)?;
        Ok(ClientProviderSignInStart {
            authorize_url: started.authorize_url,
            expires_at_ms: started.expires_at_ms,
        })
    }

    fn sign_in_status(&self, provider_id: &str) -> Result<ClientProviderSignIn, ProviderError> {
        let (port, entry) = self.sign_in_entry(provider_id)?;
        Ok(project_sign_in(
            port.status(&entry.api_key_secret),
            now_ms(),
        ))
    }

    fn sign_in_cancel(&self, provider_id: &str) -> Result<ClientProviderSignIn, ProviderError> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (port, entry) = self.sign_in_entry(provider_id)?;
        Ok(project_sign_in(
            port.cancel(&entry.api_key_secret),
            now_ms(),
        ))
    }

    fn sign_out(&self, provider_id: &str) -> Result<ClientProviderSignOut, ProviderError> {
        // Removes the access token: a key write, serialized like every other.
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (port, entry) = self.sign_in_entry(provider_id)?;
        let outcome = port.sign_out(&entry.api_key_secret);
        Ok(ClientProviderSignOut {
            signed_out: outcome.signed_out,
            revocation_confirmed: outcome.revocation_confirmed,
        })
    }
}

/// The wire shape of a sign-in state, read at `checked_at_ms`.
pub fn project_sign_in(status: SignInStatus, checked_at_ms: u64) -> ClientProviderSignIn {
    ClientProviderSignIn {
        state: status.state.to_string(),
        checked_at_ms,
        reason: status.reason.map(str::to_string),
        account: status.account,
        plan_usage: status.plan_usage,
        expires_at_ms: status.expires_at_ms,
        models: status
            .models
            .into_iter()
            .map(|m| ClientProviderSignInModel {
                id: m.id,
                display_name: m.display_name,
            })
            .collect(),
    }
}

fn is_sign_in_request(request: &ClientCreateProviderRequest) -> bool {
    request.auth_source.as_deref() == Some(CHATGPT_OAUTH_AUTH_SOURCE)
}

fn default_key_secret_name(provider_id: &str) -> String {
    format!("{provider_id}-api-key")
}

/// `<provider_id>-chatgpt-<first 8 hex digits of the host id's UUID>`; `None` when `host_id`
/// is not a UUID (`urn:uuid:<hyphenated>` or a bare UUID).
fn sign_in_secret_name(provider_id: &str, host_id: &str) -> Option<String> {
    let host = uuid::Uuid::parse_str(host_id.trim()).ok()?;
    let digits = host.simple().to_string();
    Some(format!("{provider_id}-chatgpt-{}", &digits[..8]))
}

/// A sign-in refusal is a fixed token; it only ever reaches the log-only inner string.
fn sign_in_refusal(refusal: SignInRefusal) -> ProviderError {
    ProviderError::Unavailable(format!("{SIGN_IN_ID}: {refusal}"))
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

/// The YAML mapping of a create request (the runtime's `LlmProviderConfigRaw` spelling) whose
/// `api-key-secret` is `secret`. A sign-in request also writes its source and the one dialect
/// such an entry speaks.
fn create_mapping(req: &ClientCreateProviderRequest, secret: &str) -> Value {
    let sign_in = is_sign_in_request(req);
    let mut m = Mapping::new();
    m.insert(key("id"), key(&req.provider_id));
    let class = req
        .backend_class
        .as_deref()
        .unwrap_or(DEFAULT_BACKEND_CLASS);
    if class != DEFAULT_BACKEND_CLASS {
        m.insert(key("backend-class"), key(class));
    }
    if let Some(backend) = req
        .backend
        .as_deref()
        .or(sign_in.then_some(CHATGPT_OAUTH_BACKEND))
    {
        m.insert(key("backend"), key(backend));
    }
    if sign_in {
        m.insert(key("auth-source"), key(CHATGPT_OAUTH_AUTH_SOURCE));
    }
    if let Some(endpoint) = &req.endpoint {
        m.insert(key("endpoint"), key(endpoint));
    }
    m.insert(key("api-key-secret"), key(secret));
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
        let v = create_mapping(&req, &default_key_secret_name(&req.provider_id));
        assert_eq!(v["id"], "anthropic");
        assert!(v.get("backend-class").is_none(), "default class is omitted");
        assert_eq!(v["backend"], "anthropic-messages");
        assert!(
            v.get("auth-source").is_none(),
            "the default source is omitted"
        );
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
    fn usage_projection_keeps_windows_and_names_the_failure() {
        use cap_llm::backend_cli::{UsageProbe, UsageWindow};
        let ok = project_usage(
            UsageProbe {
                ok: true,
                detail: "ok".into(),
                plan: Some("max".into()),
                account: Some("me@example.com".into()),
                windows: vec![UsageWindow {
                    kind: "week".into(),
                    label: "Current week (all models)".into(),
                    model: None,
                    used_percent: 69.0,
                    resets_at_ms: None,
                    resets_label: Some("Sep 30 at 3pm (America/Los_Angeles)".into()),
                    window_minutes: None,
                }],
            },
            42,
        );
        assert!(ok.ok);
        assert_eq!(ok.checked_at_ms, 42);
        assert_eq!(ok.reason, None);
        assert_eq!(ok.plan.as_deref(), Some("max"));
        assert_eq!(ok.windows.len(), 1);
        assert_eq!(ok.windows[0].kind, "week");
        assert_eq!(ok.windows[0].used_percent, 69.0);
        assert_eq!(
            ok.windows[0].resets_label.as_deref(),
            Some("Sep 30 at 3pm (America/Los_Angeles)")
        );

        let failed = project_usage(
            UsageProbe {
                ok: false,
                detail: "not-signed-in".into(),
                plan: None,
                account: None,
                windows: Vec::new(),
            },
            7,
        );
        assert!(!failed.ok);
        assert_eq!(failed.reason.as_deref(), Some("not-signed-in"));
        assert!(failed.windows.is_empty());
    }

    #[test]
    fn client_api_sign_in_vocabulary_is_the_runtime_loaders() {
        use advance_client_api::provider_admin::{
            AUTH_SOURCES, CHATGPT_OAUTH_AUTH_SOURCE, DEFAULT_AUTH_SOURCE, RESERVED_SECRET_SUFFIX,
        };
        use advance_runtime::config::{ProviderAuthSource, CHATGPT_OAUTH_RECORD_SUFFIX};
        for spelling in AUTH_SOURCES {
            assert!(ProviderAuthSource::parse(spelling).is_some(), "{spelling}");
        }
        assert_eq!(ProviderAuthSource::ApiKey.as_str(), DEFAULT_AUTH_SOURCE);
        assert_eq!(
            ProviderAuthSource::ChatGptOAuth.as_str(),
            CHATGPT_OAUTH_AUTH_SOURCE
        );
        assert_eq!(RESERVED_SECRET_SUFFIX, CHATGPT_OAUTH_RECORD_SUFFIX);
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

/// `auth-source: chatgpt-oauth` entries over a scripted sign-in port, a real home document and
/// an in-memory live store.
#[cfg(test)]
mod sign_in_entry_tests {
    use super::*;
    use crate::chatgpt_sign_in::{
        SignInModel, SignInStarted, SignOutOutcome, VerifyOutcome, STATE_PENDING, STATE_SIGNED_IN,
        STATE_SIGNED_OUT,
    };
    use cap_secrets::InMemorySecretStorage;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zeroize::Zeroizing;

    const HOST_ID: &str = "urn:uuid:0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    const SIGN_IN_SECRET: &str = "openai-plan-chatgpt-0a1b2c3d";
    const RUNTIME_YAML: &str = "\
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADV_HOME_SIGN_IN_ENTRY_MK

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
";

    /// A sign-in port whose answers the test sets. Records every call with the secret name it
    /// was asked about, and for each `forget` whether the document still named that secret.
    struct ScriptedSignIn {
        home: PathBuf,
        calls: Mutex<Vec<(&'static str, String)>>,
        status: Mutex<SignInStatus>,
        verify: Mutex<VerifyOutcome>,
        /// How long `verify` takes before it answers.
        verify_delay: Mutex<Duration>,
        start: Mutex<Result<SignInStarted, SignInRefusal>>,
        forgotten_while_named: Mutex<Vec<bool>>,
    }

    impl ScriptedSignIn {
        fn record(&self, call: &'static str, secret_name: &str) {
            self.calls
                .lock()
                .unwrap()
                .push((call, secret_name.to_string()));
        }

        fn calls_of(&self, call: &str) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| *c == call)
                .map(|(_, name)| name.clone())
                .collect()
        }
    }

    fn signed_out(reason: Option<&'static str>) -> SignInStatus {
        SignInStatus {
            state: STATE_SIGNED_OUT,
            reason,
            account: None,
            plan_usage: None,
            expires_at_ms: None,
            models: Vec::new(),
        }
    }

    impl ChatGptSignInPort for ScriptedSignIn {
        fn host_id(&self) -> Result<String, SignInRefusal> {
            self.record("host_id", "");
            Ok(HOST_ID.to_string())
        }
        fn start(&self, secret_name: &str) -> Result<SignInStarted, SignInRefusal> {
            self.record("start", secret_name);
            self.start.lock().unwrap().clone()
        }
        fn status(&self, secret_name: &str) -> SignInStatus {
            self.record("status", secret_name);
            self.status.lock().unwrap().clone()
        }
        fn cancel(&self, secret_name: &str) -> SignInStatus {
            self.record("cancel", secret_name);
            signed_out(Some("cancelled"))
        }
        fn sign_out(&self, secret_name: &str) -> SignOutOutcome {
            self.record("sign_out", secret_name);
            SignOutOutcome {
                signed_out: true,
                revocation_confirmed: false,
            }
        }
        fn verify(&self, secret_name: &str) -> VerifyOutcome {
            self.record("verify", secret_name);
            let delay = *self.verify_delay.lock().unwrap();
            std::thread::sleep(delay);
            self.verify.lock().unwrap().clone()
        }
        fn forget(&self, secret_name: &str) {
            self.record("forget", secret_name);
            let named = crate::list_provider_entries(&self.home)
                .map(|entries| entries.iter().any(|e| e.api_key_secret == secret_name))
                .unwrap_or(true);
            self.forgotten_while_named.lock().unwrap().push(named);
        }
    }

    /// Counts chat preflights: a sign-in entry must never reach one.
    struct CountingPreflight(AtomicUsize);

    impl PreflightPort for CountingPreflight {
        fn preflight(
            &self,
            _home: &Path,
            _provider: &LlmProviderConfig,
            _key: &SecretBytes,
            _cancel: &CancelToken,
        ) -> Result<(), PreflightFail> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        store: Arc<SecretStore>,
        port: Arc<ScriptedSignIn>,
        preflight: Arc<CountingPreflight>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let home = dir.path().to_path_buf();
            std::fs::create_dir_all(home.join(".advance")).unwrap();
            std::fs::write(home.join(".advance/runtime-config.yaml"), RUNTIME_YAML).unwrap();
            let store = Arc::new(SecretStore::new(
                Zeroizing::new([7u8; 32]),
                Arc::new(InMemorySecretStorage::default()),
            ));
            let port = Arc::new(ScriptedSignIn {
                home: home.clone(),
                calls: Mutex::new(Vec::new()),
                status: Mutex::new(signed_out(None)),
                verify: Mutex::new(VerifyOutcome {
                    ok: true,
                    reason: None,
                    models: Vec::new(),
                }),
                verify_delay: Mutex::new(Duration::ZERO),
                start: Mutex::new(Err(SignInRefusal(SIGN_IN_UNAVAILABLE))),
                forgotten_while_named: Mutex::new(Vec::new()),
            });
            Self {
                _dir: dir,
                home,
                store,
                port,
                preflight: Arc::new(CountingPreflight(AtomicUsize::new(0))),
            }
        }

        fn admin_without_sign_in(&self) -> WiredProviderAdmin {
            let cfg = advance_runtime::config::load_config(
                &self.home.join(".advance/runtime-config.yaml"),
            )
            .expect("fixture parses");
            WiredProviderAdmin::new(
                self.home.clone(),
                Arc::new(cap_llm::StaticConfig(Arc::new(cfg))),
                Some(Arc::clone(&self.store)),
                self.preflight.clone(),
                Arc::new(NoReferences),
            )
            .with_reload_wait(Duration::from_millis(1))
        }

        fn admin(&self) -> WiredProviderAdmin {
            self.admin_without_sign_in()
                .with_chatgpt_sign_in(self.port.clone())
        }

        fn entry(&self, provider_id: &str) -> Option<LlmProviderConfig> {
            crate::list_provider_entries(&self.home)
                .expect("document parses")
                .into_iter()
                .find(|e| e.id == provider_id)
        }

        fn ids(&self) -> Vec<String> {
            crate::list_provider_entries(&self.home)
                .expect("document parses")
                .into_iter()
                .map(|e| e.id)
                .collect()
        }

        fn chat_preflights(&self) -> usize {
            self.preflight.0.load(Ordering::SeqCst)
        }
    }

    fn sign_in_request() -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: "openai-plan".into(),
            endpoint: Some("https://api.openai.com".into()),
            auth_source: Some(CHATGPT_OAUTH_AUTH_SOURCE.into()),
            model_aliases: [("gpt".to_string(), "gpt-5".to_string())]
                .into_iter()
                .collect(),
            cost: ClientProviderCost {
                input_per_mtoken: 0.01,
                output_per_mtoken: 0.01,
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 60,
                tokens_per_minute: 100_000,
            },
            ..Default::default()
        }
    }

    fn with_secret(provider_id: &str, secret: &str) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: provider_id.into(),
            api_key_secret: Some(secret.into()),
            ..sign_in_request()
        }
    }

    #[test]
    fn sign_in_secret_name_takes_the_host_uuid_prefix() {
        assert_eq!(
            sign_in_secret_name("p", "urn:uuid:0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D").as_deref(),
            Some("p-chatgpt-0a1b2c3d")
        );
        assert_eq!(
            sign_in_secret_name("p", "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d").as_deref(),
            Some("p-chatgpt-0a1b2c3d")
        );
        assert_eq!(sign_in_secret_name("p", "host-1"), None);
        assert_eq!(sign_in_secret_name("p", ""), None);
    }

    #[test]
    fn sign_in_create_writes_source_and_dialect_and_stores_no_key() {
        let f = Fixture::new();
        let admin = f.admin();
        let outcome = admin.create_provider(&sign_in_request()).expect("created");
        let summary = &outcome.value;
        assert_eq!(summary.auth_source.as_deref(), Some("chatgpt-oauth"));
        assert_eq!(summary.backend.as_deref(), Some("openai-responses"));
        assert_eq!(summary.key.secret_name, SIGN_IN_SECRET);
        assert!(!summary.key.present);
        assert_eq!(
            summary.sign_in.as_ref().map(|s| s.state.as_str()),
            Some(STATE_SIGNED_OUT)
        );
        assert!(
            !outcome
                .warnings
                .contains(&ProviderAdminWarning::RestartRequired),
            "the gateway reads the entry live"
        );

        // The document names the source and the dialect; the strict loader reads it back.
        let text = std::fs::read_to_string(f.home.join(".advance/runtime-config.yaml")).unwrap();
        assert!(text.contains("auth-source: chatgpt-oauth"), "{text}");
        assert!(text.contains("backend: openai-responses"), "{text}");
        let entry = f.entry("openai-plan").expect("on disk");
        assert!(entry.uses_chatgpt_sign_in());
        assert_eq!(entry.backend, Some(ProviderBackend::OpenAiResponses));
        assert_eq!(entry.api_key_secret, SIGN_IN_SECRET);

        // Nothing was stored and nothing was preflighted.
        assert!(f.store.names().is_empty(), "{:?}", f.store.names());
        assert_eq!(f.chat_preflights(), 0);

        // A named secret is used as given; the host id is asked for only without one.
        let named = admin
            .create_provider(&with_secret("openai-plan-2", "plan-token"))
            .expect("created");
        assert_eq!(named.value.key.secret_name, "plan-token");
        assert_eq!(f.port.calls_of("host_id").len(), 1);
        // An API-key entry keeps its own default and never asks for the host id.
        let keyed = admin
            .create_provider(&ClientCreateProviderRequest {
                provider_id: "openai-key".into(),
                auth_source: None,
                ..sign_in_request()
            })
            .expect("created");
        assert_eq!(keyed.value.key.secret_name, "openai-key-api-key");
        assert_eq!(keyed.value.auth_source, None);
        assert_eq!(keyed.value.sign_in, None);
        assert!(!f.entry("openai-key").unwrap().uses_chatgpt_sign_in());
        assert_eq!(f.port.calls_of("host_id").len(), 1);
    }

    #[test]
    fn sign_in_without_a_port_refuses_create_and_routes() {
        let f = Fixture::new();
        let admin = f.admin_without_sign_in();
        assert!(!admin.has_chatgpt_sign_in());
        assert!(matches!(
            admin.create_provider(&sign_in_request()),
            Err(ProviderError::Unavailable(_))
        ));
        assert!(matches!(
            admin.create_provider(&with_secret("openai-plan", "plan-token")),
            Err(ProviderError::Unavailable(_))
        ));
        assert_eq!(f.ids(), vec!["openai"], "nothing was written");

        // An entry written by hand: the routes cannot serve it and its check is a verdict that
        // never reaches the chat preflight, even with a value under its name.
        crate::upsert_provider_entry(
            &f.home,
            create_mapping(&sign_in_request(), SIGN_IN_SECRET),
            UpsertMode::Create,
        )
        .unwrap();
        f.store.store(SIGN_IN_SECRET, "stored-value").unwrap();
        for id in ["openai-plan", "openai"] {
            assert!(matches!(
                admin.sign_in_start(id),
                Err(ProviderError::Unavailable(_))
            ));
            assert!(matches!(
                admin.sign_in_status(id),
                Err(ProviderError::Unavailable(_))
            ));
            assert!(matches!(
                admin.sign_in_cancel(id),
                Err(ProviderError::Unavailable(_))
            ));
            assert!(matches!(
                admin.sign_out(id),
                Err(ProviderError::Unavailable(_))
            ));
        }
        let verdict = admin.preflight("openai-plan").expect("a verdict");
        assert!(!verdict.ok);
        assert_eq!(verdict.reason.as_deref(), Some(SIGN_IN_UNAVAILABLE));
        assert_eq!(f.chat_preflights(), 0);
        let summary = admin.get_provider("openai-plan").unwrap();
        assert_eq!(summary.auth_source.as_deref(), Some("chatgpt-oauth"));
        assert_eq!(summary.sign_in, None, "no state is claimed without a port");
    }

    #[test]
    fn sign_in_summary_projects_the_port_state() {
        let f = Fixture::new();
        let admin = f.admin();
        admin.create_provider(&sign_in_request()).unwrap();
        *f.port.status.lock().unwrap() = SignInStatus {
            state: STATE_SIGNED_IN,
            reason: None,
            account: Some("me@example.com".into()),
            plan_usage: Some(true),
            expires_at_ms: Some(1_900_000_000_000),
            models: vec![
                SignInModel {
                    id: "gpt-5".into(),
                    display_name: Some("GPT-5".into()),
                },
                SignInModel {
                    id: "gpt-5-mini".into(),
                    display_name: None,
                },
            ],
        };
        let before = now_ms();
        let summary = admin.get_provider("openai-plan").unwrap();
        let after = now_ms();
        let sign_in = summary.sign_in.expect("projected");
        assert_eq!(sign_in.state, STATE_SIGNED_IN);
        assert_eq!(sign_in.reason, None);
        assert_eq!(sign_in.account.as_deref(), Some("me@example.com"));
        assert_eq!(sign_in.plan_usage, Some(true));
        assert_eq!(sign_in.expires_at_ms, Some(1_900_000_000_000));
        assert!((before..=after).contains(&sign_in.checked_at_ms));
        assert_eq!(
            sign_in.models,
            vec![
                ClientProviderSignInModel {
                    id: "gpt-5".into(),
                    display_name: Some("GPT-5".into()),
                },
                ClientProviderSignInModel {
                    id: "gpt-5-mini".into(),
                    display_name: None,
                },
            ]
        );

        // The API-key entry carries neither, and the port is never asked about its secret.
        let listed = admin.list_providers().unwrap();
        let keyed = listed.iter().find(|s| s.provider_id == "openai").unwrap();
        assert_eq!(keyed.auth_source, None);
        assert_eq!(keyed.sign_in, None);
        assert!(f
            .port
            .calls_of("status")
            .iter()
            .all(|name| name == SIGN_IN_SECRET));
    }

    #[test]
    fn sign_in_preflight_is_the_port_verify_and_is_cached() {
        let f = Fixture::new();
        let admin = f.admin();
        admin.create_provider(&sign_in_request()).unwrap();
        // A value under the name would feed the chat preflight; a sign-in entry never uses it.
        f.store.store(SIGN_IN_SECRET, "stored-value").unwrap();

        let verdict = admin.preflight("openai-plan").unwrap();
        assert!(verdict.ok && verdict.reason.is_none(), "{verdict:?}");
        assert_eq!(f.port.calls_of("verify"), vec![SIGN_IN_SECRET.to_string()]);
        assert_eq!(f.chat_preflights(), 0);
        let cached = admin.get_provider("openai-plan").unwrap().last_preflight;
        assert_eq!(cached, Some(verdict));

        *f.port.verify.lock().unwrap() = VerifyOutcome {
            ok: false,
            reason: Some("not-signed-in"),
            models: Vec::new(),
        };
        let verdict = admin.preflight("openai-plan").unwrap();
        assert!(!verdict.ok);
        assert_eq!(verdict.reason.as_deref(), Some("not-signed-in"));
        assert_eq!(
            admin
                .get_provider("openai-plan")
                .unwrap()
                .last_preflight
                .and_then(|v| v.reason),
            Some("not-signed-in".to_string())
        );
        assert_eq!(f.chat_preflights(), 0);
    }

    #[test]
    fn sign_in_preflight_is_bounded_by_the_preflight_deadline() {
        let f = Fixture::new();
        let admin = f.admin().with_preflight_timeout(Duration::from_millis(100));
        admin.create_provider(&sign_in_request()).unwrap();
        *f.port.verify_delay.lock().unwrap() = Duration::from_secs(3);
        let started = std::time::Instant::now();
        let verdict = admin.preflight("openai-plan").unwrap();
        let waited = started.elapsed();
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        assert!(!verdict.ok);
        assert_eq!(verdict.reason.as_deref(), Some(REASON_TIMEOUT));
        assert_eq!(
            admin
                .get_provider("openai-plan")
                .unwrap()
                .last_preflight
                .and_then(|v| v.reason),
            Some(REASON_TIMEOUT.to_string()),
            "a timed-out check is cached like every verdict"
        );
        assert_eq!(f.port.calls_of("verify"), vec![SIGN_IN_SECRET.to_string()]);

        // Inside the deadline the port's verdict is the answer.
        *f.port.verify_delay.lock().unwrap() = Duration::from_millis(10);
        let admin = admin.with_preflight_timeout(Duration::from_secs(10));
        assert!(admin.preflight("openai-plan").unwrap().ok);
    }

    #[test]
    fn sign_in_create_refuses_a_named_secret_that_already_holds_a_value() {
        let f = Fixture::new();
        let admin = f.admin();
        // A key an API-key entry left behind, and a sign-in record no entry names any more.
        f.store.store("legacy-key", "sk-left-behind").unwrap();
        f.store.store("orphan.chatgpt-oauth", "{\"v\":1}").unwrap();
        for name in ["legacy-key", "orphan"] {
            assert!(
                matches!(
                    admin.create_provider(&with_secret("openai-plan", name)),
                    Err(ProviderError::AlreadyExists(_))
                ),
                "{name}"
            );
        }
        assert_eq!(f.ids(), vec!["openai"], "nothing was written");
        assert_eq!(
            f.store.resolve("legacy-key").unwrap().expose_secret(),
            "sk-left-behind"
        );
        assert!(
            f.port.calls.lock().unwrap().is_empty(),
            "the port is not asked"
        );

        // A free name is taken as given; an API-key entry may still name an existing secret.
        admin
            .create_provider(&with_secret("openai-plan", "free-name"))
            .expect("a free name");
        admin
            .create_provider(&ClientCreateProviderRequest {
                provider_id: "openai-keyed".into(),
                auth_source: None,
                ..with_secret("openai-keyed", "legacy-key")
            })
            .expect("an API-key entry reuses its key");
    }

    #[test]
    fn sign_in_usage_is_not_provided() {
        let f = Fixture::new();
        let admin = f.admin();
        admin.create_provider(&sign_in_request()).unwrap();
        let usage = admin.usage("openai-plan").unwrap();
        assert!(!usage.ok);
        assert_eq!(usage.reason.as_deref(), Some(REASON_NOT_PROVIDED));
        assert!(usage.windows.is_empty());
        assert_eq!(
            admin
                .get_provider("openai-plan")
                .unwrap()
                .last_usage
                .and_then(|u| u.reason),
            Some(REASON_NOT_PROVIDED.to_string())
        );
        // An API-key cloud entry keeps its own answer.
        assert_eq!(
            admin.usage("openai").unwrap().reason.as_deref(),
            Some(REASON_UNSUPPORTED_CLASS)
        );
    }

    #[test]
    fn sign_in_delete_forgets_the_session_after_the_entry_is_gone() {
        let f = Fixture::new();
        let admin = f.admin();
        admin.create_provider(&sign_in_request()).unwrap();
        admin
            .create_provider(&with_secret("openai-plan-2", "plan-token"))
            .unwrap();

        // Deleting an API-key entry forgets nothing.
        admin.delete_provider("openai").expect("deleted");
        assert!(f.port.calls_of("forget").is_empty());

        admin.delete_provider("openai-plan").expect("deleted");
        assert_eq!(f.ids(), vec!["openai-plan-2"]);
        assert_eq!(f.port.calls_of("forget"), vec![SIGN_IN_SECRET.to_string()]);
        assert_eq!(
            f.port.forgotten_while_named.lock().unwrap().as_slice(),
            &[false],
            "forgotten only once the document no longer names the secret"
        );
    }

    #[test]
    fn key_routes_and_sign_in_routes_refuse_the_other_source() {
        let f = Fixture::new();
        let admin = f.admin();
        admin.create_provider(&sign_in_request()).unwrap();
        f.store.store(SIGN_IN_SECRET, "access-value").unwrap();

        // Key routes on the sign-in entry: refused, the stored value untouched.
        assert!(matches!(
            admin.set_key("openai-plan", "sk-typed-by-hand"),
            Err(ProviderError::AuthSourceMismatch(_))
        ));
        assert!(matches!(
            admin.clear_key("openai-plan"),
            Err(ProviderError::AuthSourceMismatch(_))
        ));
        assert_eq!(
            f.store.resolve(SIGN_IN_SECRET).unwrap().expose_secret(),
            "access-value"
        );
        assert_eq!(f.chat_preflights(), 0);

        // Sign-in routes on the API-key entry: refused before the port is asked.
        let asked_before = f.port.calls.lock().unwrap().len();
        assert!(matches!(
            admin.sign_in_start("openai"),
            Err(ProviderError::AuthSourceMismatch(_))
        ));
        assert!(matches!(
            admin.sign_in_status("openai"),
            Err(ProviderError::AuthSourceMismatch(_))
        ));
        assert!(matches!(
            admin.sign_in_cancel("openai"),
            Err(ProviderError::AuthSourceMismatch(_))
        ));
        assert!(matches!(
            admin.sign_out("openai"),
            Err(ProviderError::AuthSourceMismatch(_))
        ));
        assert_eq!(f.port.calls.lock().unwrap().len(), asked_before);
        assert!(matches!(
            admin.sign_in_status("ghost"),
            Err(ProviderError::NotFound(_))
        ));
        // The key routes still serve the API-key entry.
        admin.set_key("openai", "sk-live").expect("stored");
        assert_eq!(f.chat_preflights(), 1);
    }

    #[test]
    fn sign_in_update_keeps_the_secret_name() {
        let f = Fixture::new();
        let admin = f.admin();
        admin.create_provider(&sign_in_request()).unwrap();
        let moved = ClientUpdateProviderRequest {
            api_key_secret: Some("elsewhere".into()),
            ..Default::default()
        };
        assert!(matches!(
            admin.update_provider("openai-plan", &moved),
            Err(ProviderError::InvalidRequest(_))
        ));
        assert_eq!(
            f.entry("openai-plan").unwrap().api_key_secret,
            SIGN_IN_SECRET
        );

        // Naming the same secret, or any other field, goes through.
        let same = ClientUpdateProviderRequest {
            api_key_secret: Some(SIGN_IN_SECRET.into()),
            model_aliases: Some(
                [("gpt".to_string(), "gpt-5.1".to_string())]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        };
        admin
            .update_provider("openai-plan", &same)
            .expect("updated");
        let entry = f.entry("openai-plan").unwrap();
        assert!(entry.uses_chatgpt_sign_in());
        assert_eq!(
            entry.model_aliases.get("gpt").map(String::as_str),
            Some("gpt-5.1")
        );

        // An API-key entry may still move its secret.
        admin
            .update_provider("openai", &moved)
            .expect("an API-key entry moves its secret");
        assert_eq!(f.entry("openai").unwrap().api_key_secret, "elsewhere");
    }

    #[test]
    fn sign_in_routes_drive_the_port_with_the_entry_secret() {
        let f = Fixture::new();
        let admin = f.admin();
        assert!(admin.has_chatgpt_sign_in());
        admin.create_provider(&sign_in_request()).unwrap();

        // A refusal is `Unavailable`.
        assert!(matches!(
            admin.sign_in_start("openai-plan"),
            Err(ProviderError::Unavailable(_))
        ));

        *f.port.start.lock().unwrap() = Ok(SignInStarted {
            authorize_url: "https://auth.example.test/authorize?state=s".into(),
            expires_at_ms: 1_800_000_000_000,
        });
        let started = admin.sign_in_start("openai-plan").expect("started");
        assert_eq!(
            started,
            ClientProviderSignInStart {
                authorize_url: "https://auth.example.test/authorize?state=s".into(),
                expires_at_ms: 1_800_000_000_000,
            }
        );

        *f.port.status.lock().unwrap() = SignInStatus {
            state: STATE_PENDING,
            reason: None,
            account: None,
            plan_usage: None,
            expires_at_ms: Some(1_800_000_000_000),
            models: Vec::new(),
        };
        let polled = admin.sign_in_status("openai-plan").expect("status");
        assert_eq!(polled.state, STATE_PENDING);
        assert_eq!(polled.expires_at_ms, Some(1_800_000_000_000));
        assert!(polled.checked_at_ms > 0);

        let cancelled = admin.sign_in_cancel("openai-plan").expect("cancelled");
        assert_eq!(cancelled.state, STATE_SIGNED_OUT);
        assert_eq!(cancelled.reason.as_deref(), Some("cancelled"));

        let out = admin.sign_out("openai-plan").expect("signed out");
        assert_eq!(
            out,
            ClientProviderSignOut {
                signed_out: true,
                revocation_confirmed: false,
            }
        );
        for call in ["start", "status", "cancel", "sign_out"] {
            assert!(
                f.port
                    .calls_of(call)
                    .iter()
                    .all(|name| name == SIGN_IN_SECRET),
                "{call}"
            );
            assert!(!f.port.calls_of(call).is_empty(), "{call}");
        }
    }

    fn local_create(id: &str) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: id.into(),
            backend_class: Some("local".into()),
            backend: None,
            endpoint: None,
            model_aliases: [("llama".to_string(), "llama".to_string())]
                .into_iter()
                .collect(),
            embedding_model: None,
            auth_scheme: None,
            api_key_secret: None,
            auth_source: None,
            cost: ClientProviderCost {
                input_per_mtoken: 0.001,
                output_per_mtoken: 0.001,
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 100,
                tokens_per_minute: 1000,
            },
            retry_default: None,
            sidecar: None,
            profile_id: None,
            device_id: None,
            agent_cli: None,
        }
    }

    fn restart_count(outcome: &ProviderAdminOutcome<ClientProviderSummary>) -> usize {
        outcome
            .warnings
            .iter()
            .filter(|w| **w == ProviderAdminWarning::RestartRequired)
            .count()
    }

    struct FakeClaimed {
        claimed: Vec<String>,
        outcome: Mutex<Result<(), PreflightFail>>,
        stall: Mutex<Duration>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeClaimed {
        fn new(claimed: &[&str], outcome: Result<(), PreflightFail>) -> Arc<Self> {
            Arc::new(Self {
                claimed: claimed.iter().map(|s| (*s).to_string()).collect(),
                outcome: Mutex::new(outcome),
                stall: Mutex::new(Duration::ZERO),
                calls: Mutex::new(Vec::new()),
            })
        }
    }

    impl ClaimedEntryPreflight for FakeClaimed {
        fn is_claimed(&self, provider_id: &str) -> bool {
            self.claimed.iter().any(|id| id == provider_id)
        }
        fn preflight(
            &self,
            provider_id: &str,
            cancel: &CancelToken,
            _budget: Duration,
        ) -> Result<(), PreflightFail> {
            self.calls.lock().unwrap().push(provider_id.to_string());
            let stall = *self.stall.lock().unwrap();
            if !stall.is_zero() {
                let start = std::time::Instant::now();
                while start.elapsed() < stall {
                    if cancel.is_cancelled() {
                        return Err(PreflightFail::Cancelled);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            self.outcome.lock().unwrap().clone()
        }
    }

    #[test]
    fn module_001_ac31_claimable_off_keeps_v0_1_26_warnings() {
        let f = Fixture::new();
        let admin = f.admin();
        assert!(!admin.marks_local_entries_claimable());
        assert!(!admin.has_claimed_preflight());
        let created = admin.create_provider(&local_create("local-a")).unwrap();
        assert_eq!(restart_count(&created), 0);
        let updated = admin
            .update_provider(
                "local-a",
                &ClientUpdateProviderRequest {
                    backend_class: Some("cloud-http".into()),
                    endpoint: Some("https://api.example".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(restart_count(&updated), 0);
    }

    #[test]
    fn module_001_ac31_claimable_on_warns_create_local_without_sidecar() {
        let f = Fixture::new();
        let admin = f.admin().with_claimable_local_entries(true);
        assert!(admin.marks_local_entries_claimable());
        let created = admin.create_provider(&local_create("local-a")).unwrap();
        assert_eq!(restart_count(&created), 1);
    }

    #[test]
    fn module_001_ac31_claimable_on_warns_backend_class_or_sidecar_change_once() {
        let f = Fixture::new();
        let admin = f.admin().with_claimable_local_entries(true);
        admin.create_provider(&local_create("local-a")).unwrap();
        let sidecar = admin
            .update_provider(
                "local-a",
                &ClientUpdateProviderRequest {
                    sidecar: Some(ClientProviderSidecar {
                        command: "/bin/true".into(),
                        args: vec![],
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(restart_count(&sidecar), 1);

        let f2 = Fixture::new();
        let admin = f2.admin().with_claimable_local_entries(true);
        admin.create_provider(&local_create("local-b")).unwrap();
        let class = admin
            .update_provider(
                "local-b",
                &ClientUpdateProviderRequest {
                    backend_class: Some("cloud-http".into()),
                    endpoint: Some("https://api.example".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(restart_count(&class), 1);
    }

    #[test]
    fn module_001_ac31_claimed_preflight_routes_only_claimed_local_entries() {
        let f = Fixture::new();
        let port = FakeClaimed::new(&["local-a"], Ok(()));
        let admin = f
            .admin()
            .with_claimed_preflight(port.clone() as Arc<dyn ClaimedEntryPreflight>);
        admin.create_provider(&local_create("local-a")).unwrap();
        admin.create_provider(&local_create("local-b")).unwrap();

        let unclaimed = admin.preflight("local-b").unwrap();
        assert!(!unclaimed.ok);
        assert_eq!(unclaimed.reason.as_deref(), Some(REASON_UNSUPPORTED_CLASS));
        assert!(port.calls.lock().unwrap().is_empty());

        let claimed = admin.preflight("local-a").unwrap();
        assert!(claimed.ok && claimed.reason.is_none(), "{claimed:?}");
        assert_eq!(*port.calls.lock().unwrap(), vec!["local-a".to_string()]);

        admin
            .update_provider(
                "local-a",
                &ClientUpdateProviderRequest {
                    backend_class: Some("cloud-http".into()),
                    endpoint: Some("https://api.openai.com".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        f.store.store("local-a-api-key", "k").unwrap();
        let cloud = admin.preflight("local-a").unwrap();
        assert!(cloud.ok, "{cloud:?}");
        assert_eq!(*port.calls.lock().unwrap(), vec!["local-a".to_string()]);
        assert_eq!(f.chat_preflights(), 1);

        let none = f.admin();
        let without = none.preflight("local-b").unwrap();
        assert_eq!(without.reason.as_deref(), Some(REASON_UNSUPPORTED_CLASS));
    }

    #[test]
    fn module_001_ac31_claimed_preflight_verdict_mapping() {
        let f = Fixture::new();
        let port = FakeClaimed::new(&["local-a"], Ok(()));
        let admin = f
            .admin()
            .with_claimed_preflight(port.clone() as Arc<dyn ClaimedEntryPreflight>);
        admin.create_provider(&local_create("local-a")).unwrap();
        let ok = admin.preflight("local-a").unwrap();
        assert!(ok.ok && ok.reason.is_none());

        *port.outcome.lock().unwrap() = Err(PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        });
        let rejected = admin.preflight("local-a").unwrap();
        assert!(!rejected.ok);
        assert_eq!(rejected.reason.as_deref(), Some("provider-error"));

        *port.outcome.lock().unwrap() = Err(PreflightFail::Cancelled);
        let cancelled = admin.preflight("local-a").unwrap();
        assert!(!cancelled.ok);
        assert_eq!(cancelled.reason.as_deref(), Some(REASON_CANCELLED));

        *port.stall.lock().unwrap() = Duration::from_secs(3);
        *port.outcome.lock().unwrap() = Ok(());
        let admin = admin.with_preflight_timeout(Duration::from_millis(100));
        let started = std::time::Instant::now();
        let timed = admin.preflight("local-a").unwrap();
        let waited = started.elapsed();
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        assert!(!timed.ok);
        assert_eq!(timed.reason.as_deref(), Some(REASON_TIMEOUT));
    }

    #[test]
    fn module_001_ac31_claimed_preflight_verdict_is_recorded_in_the_summary() {
        let f = Fixture::new();
        let port = FakeClaimed::new(
            &["local-a"],
            Err(PreflightFail::ProviderRejected {
                reason: "provider-error".into(),
            }),
        );
        let admin = f
            .admin()
            .with_claimed_preflight(port as Arc<dyn ClaimedEntryPreflight>);
        admin.create_provider(&local_create("local-a")).unwrap();
        let verdict = admin.preflight("local-a").unwrap();
        assert_eq!(verdict.reason.as_deref(), Some("provider-error"));
        assert_eq!(
            admin.get_provider("local-a").unwrap().last_preflight,
            Some(verdict)
        );
    }
}

#[cfg(test)]
mod module_001_ac32_tests {
    use super::*;
    use advance_shared_types::process_policy::spawn_counter;
    use cap_secrets::InMemorySecretStorage;
    use std::time::Instant;
    use zeroize::Zeroizing;

    const HOME_YAML: &str = "\
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
  - id: claude-sub
    api-key-secret: claude-sub-api-key
    backend-class: agent-cli
    agent-cli:
      vendor: claude
      command: /nonexistent/claude
    model-aliases:
      sonnet: sonnet
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    rate-limit:
      requests-per-minute: 6
      tokens-per-minute: 60000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADV_HOME_AC32_MK

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
";

    struct PanicAuth;
    impl AgentCliAuthProbe for PanicAuth {
        fn probe(&self, _spec: &AgentCliSpec) -> cap_llm::backend_cli::AuthProbe {
            panic!("agent-cli auth probe must not run under Forbid");
        }
    }

    struct PanicUsage;
    impl AgentCliUsageProbe for PanicUsage {
        fn probe_usage(&self, _spec: &AgentCliSpec) -> cap_llm::backend_cli::UsageProbe {
            panic!("agent-cli usage probe must not run under Forbid");
        }
    }

    struct PassPreflight;
    impl PreflightPort for PassPreflight {
        fn preflight(
            &self,
            _home: &Path,
            _provider: &LlmProviderConfig,
            _key: &SecretBytes,
            _cancel: &CancelToken,
        ) -> Result<(), crate::PreflightFail> {
            Ok(())
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        store: Arc<SecretStore>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let home = dir.path().to_path_buf();
            std::fs::create_dir_all(home.join(".advance")).unwrap();
            std::fs::write(home.join(".advance/runtime-config.yaml"), HOME_YAML).unwrap();
            let store = Arc::new(SecretStore::new(
                Zeroizing::new([7u8; 32]),
                Arc::new(InMemorySecretStorage::default()),
            ));
            Self {
                _dir: dir,
                home,
                store,
            }
        }

        fn admin(&self) -> WiredProviderAdmin {
            let cfg = advance_runtime::config::load_config(
                &self.home.join(".advance/runtime-config.yaml"),
            )
            .expect("fixture parses");
            WiredProviderAdmin::new(
                self.home.clone(),
                Arc::new(cap_llm::StaticConfig(Arc::new(cfg))),
                Some(Arc::clone(&self.store)),
                Arc::new(PassPreflight),
                Arc::new(NoReferences),
            )
        }

        fn yaml_bytes(&self) -> Vec<u8> {
            std::fs::read(self.home.join(".advance/runtime-config.yaml")).expect("yaml")
        }
    }

    fn cloud_http(id: &str) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: id.into(),
            backend_class: Some("cloud-http".into()),
            endpoint: Some("https://api.example.com".into()),
            model_aliases: [("m".to_string(), "m".to_string())].into_iter().collect(),
            cost: ClientProviderCost {
                input_per_mtoken: 1.0,
                output_per_mtoken: 1.0,
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 10,
                tokens_per_minute: 1000,
            },
            ..Default::default()
        }
    }

    fn agent_cli(id: &str) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: id.into(),
            backend_class: Some(AGENT_CLI_BACKEND_CLASS.into()),
            agent_cli: Some(ClientProviderAgentCli {
                vendor: "claude".into(),
                command: "/nonexistent/claude".into(),
                args: Vec::new(),
            }),
            model_aliases: [("sonnet".to_string(), "sonnet".to_string())]
                .into_iter()
                .collect(),
            cost: ClientProviderCost {
                input_per_mtoken: 0.001,
                output_per_mtoken: 0.001,
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 6,
                tokens_per_minute: 60_000,
            },
            ..Default::default()
        }
    }

    fn is_process_forbidden(err: ProviderError) -> bool {
        matches!(err, ProviderError::ProcessForbidden(inner) if inner == "agent-cli")
    }

    #[test]
    fn module_001_ac32_provider_admin_refuses_agent_cli_under_forbid() {
        let f = Fixture::new();
        f.store.store("keep", "v").unwrap();
        let admin = f
            .admin()
            .with_process_policy(ProcessPolicy::Forbid)
            .with_agent_cli_probe(Arc::new(PanicAuth))
            .with_agent_cli_usage_probe(Arc::new(PanicUsage))
            .with_reload_wait(Duration::from_millis(1));
        let yaml_before = f.yaml_bytes();
        let names_before = f.store.names();
        let w0 = spawn_counter::snapshot();

        assert!(is_process_forbidden(
            admin.create_provider(&agent_cli("cli-b")).unwrap_err()
        ));
        assert!(is_process_forbidden(
            admin.preflight("claude-sub").unwrap_err()
        ));
        assert!(is_process_forbidden(admin.usage("claude-sub").unwrap_err()));

        assert_eq!(f.yaml_bytes(), yaml_before);
        assert_eq!(f.store.names(), names_before);
        let delta = spawn_counter::snapshot().since(&w0);
        assert_eq!(delta.refused(SpawnSite::AgentCli), 3);

        admin
            .create_provider(&cloud_http("cloud-b"))
            .expect("cloud-http create under Forbid");
        assert!(crate::list_provider_entries(&f.home)
            .unwrap()
            .iter()
            .any(|e| e.id == "cloud-b"));
    }

    #[test]
    fn module_001_ac32_d3_provider_admin_without_hot_reload_answers_restart_required() {
        let f = Fixture::new();
        let admin = f
            .admin()
            .with_hot_reload(false)
            .with_reload_wait(Duration::from_secs(2));
        let selected = f.home.join(".runtime").join("selected-provider");
        assert!(!selected.exists());

        let started = Instant::now();
        let created = admin
            .create_provider(&cloud_http("cloud-b"))
            .expect("create");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(created.warnings, [ProviderAdminWarning::RestartRequired]);

        let started = Instant::now();
        let updated = admin
            .update_provider(
                "cloud-b",
                &ClientUpdateProviderRequest {
                    endpoint: Some("https://api.example.com/v2".into()),
                    ..Default::default()
                },
            )
            .expect("update");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(updated.warnings, [ProviderAdminWarning::RestartRequired]);

        let started = Instant::now();
        let selected_out = admin.select_provider("cloud-b").expect("select");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            selected_out.warnings,
            [ProviderAdminWarning::RestartRequired]
        );
        assert!(!selected.exists());

        let started = Instant::now();
        let deleted = admin.delete_provider("cloud-b").expect("delete");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(deleted.warnings, [ProviderAdminWarning::RestartRequired]);
    }
}
