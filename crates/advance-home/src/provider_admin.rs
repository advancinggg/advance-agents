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
//!   in-memory `SecretStore` overlay + `chat_preflight`), bounded by [`PREFLIGHT_TIMEOUT`], or
//!   by the entry's own `generate-timeout-secs` when it sets one (the bound its generate hop
//!   has, so a slow model the entry allows is not reported as a timeout). The check runs
//!   outside the write lock, so other mutations are not held up by it; the key is stored only
//!   when the entry is unchanged afterwards (otherwise the answer is `stored: false` with the
//!   reason `cancelled`). A failed / timed-out preflight leaves the previous key untouched and
//!   is reported as data.
//! - **Generate budget, reasoning setting, system-message mode.** `generate_timeout_secs` /
//!   `reasoning_effort` / `system_messages` are written as the entry's `generate-timeout-secs`
//!   / `reasoning-effort` / `system-messages`; an update's explicit `null` removes the key.
//!   Before any write, the entry as it would be after the mutation is checked with the runtime
//!   loader's own rules, and a setting it cannot take is refused as `InvalidRequest` carrying
//!   the setting's detail token (`generate_timeout_unsupported`,
//!   `reasoning_effort_unsupported`, `system_messages_unsupported`, or
//!   `invalid_generate_timeout` / `invalid_reasoning_effort` / `invalid_system_messages` for a
//!   value out of range).
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
//! - **Live sidecars.** With [`WiredProviderAdmin::with_local_sidecar_binder`], creating,
//!   updating, or selecting a sidecar-backed `local` entry starts that sidecar in this
//!   process (the same command keeps the process already running). Delete stops it. Those
//!   mutations do not answer `restart_required`. Without a binder they still do: the
//!   registry would otherwise keep the boot-time set.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use advance_client_api::{
    ClientApi, ProviderAdminProvider, ProviderError, GENERATE_TIMEOUT_UNSUPPORTED_DETAIL,
    INVALID_GENERATE_TIMEOUT_DETAIL, INVALID_REASONING_EFFORT_DETAIL,
    INVALID_SYSTEM_MESSAGES_DETAIL, REASONING_EFFORT_UNSUPPORTED_DETAIL,
    SYSTEM_MESSAGES_UNSUPPORTED_DETAIL,
};
use advance_runtime::config::{
    effective_backend, generate_timeout_refusal, max_generate_timeout_secs,
    reasoning_effort_refusal, system_messages_refusal, AgentCliSpec, AuthScheme,
    InferenceBackendClass, LlmProviderConfig, ProviderAuthSource, ProviderBackend, ReasoningEffort,
    RuntimeConfig, RuntimeConfigProvider, SystemMessages, CHATGPT_OAUTH_RECORD_SUFFIX,
    MAX_GENERATE_TIMEOUT_SECS, MIN_GENERATE_TIMEOUT_SECS,
};
use advance_shared_types::process_policy::{ProcessPolicy, SpawnSite};
use advance_shared_types::security_validator::{HttpError, HttpSecurityChain};
use cap_llm::backend_cli::{
    AgentCliAuthProbe, AgentCliModelsProbe, AgentCliUsageProbe, NoopModelsProbe, ProcessAuthProbe,
    ProcessUsageProbe,
};
use cap_llm::models_list::{
    build_models_list_capability, build_models_list_request, catalog_page_cursor, drop_key_rows,
    follows_catalog_pages, parse_models_catalog_page, CatalogPage, ListedModel,
};
use cap_llm::LocalSidecarBinder;
use cap_secrets::{SecretError, SecretStore};
use secrecy::ExposeSecret;
use serde_yml::{Mapping, Value};

/// How long a YAML write waits for the config watcher to report the applied reload.
pub const RELOAD_WAIT: Duration = Duration::from_secs(2);
/// Bound on one preflight, the check of a sign-in entry included (the cancel token fires at the
/// deadline; reason `timeout`). The chat preflight of an entry that sets its own
/// `generate-timeout-secs` is bounded by that budget instead.
pub const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on one catalog probe and on a whole `list_providers` walk.
pub const MODELS_LIST_TIMEOUT: Duration = Duration::from_secs(8);

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
const MODELS_AGENT_ID: &str = "advance-home/provider-models";
const MAX_MODEL_PAGES: usize = 8;
const MAX_CATALOG_MODELS: usize = 256;

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

/// How `WiredProviderAdmin` fills agent-cli / cloud-http catalogs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelProbeInstallation {
    Noop,
    Scripted,
    Process,
}

/// GET catalog fill: models for this read, and whether the result may be cached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogFill {
    pub models: Vec<ClientProviderSignInModel>,
    pub complete: bool,
}

impl CatalogFill {
    fn complete(models: Vec<ClientProviderSignInModel>) -> Self {
        Self {
            models,
            complete: true,
        }
    }

    fn incomplete(models: Vec<ClientProviderSignInModel>) -> Self {
        Self {
            models,
            complete: false,
        }
    }

    fn empty_complete() -> Self {
        Self {
            models: Vec::new(),
            complete: true,
        }
    }
}

/// Seam for cloud-http API-key catalog GET. Default noop; production injects a live chain.
pub trait CloudHttpModelsProbe: Send + Sync {
    fn list_models(&self, entry: &LlmProviderConfig) -> CatalogFill;
}

/// Always a complete empty catalog.
pub struct NoopCloudHttpModelsProbe;

impl CloudHttpModelsProbe for NoopCloudHttpModelsProbe {
    fn list_models(&self, _entry: &LlmProviderConfig) -> CatalogFill {
        CatalogFill::empty_complete()
    }
}

/// Vendor `GET /v1/models` through an injected LLM egress chain.
pub struct ProcessCloudHttpModelsProbe {
    chain: Arc<dyn HttpSecurityChain>,
    store: Arc<SecretStore>,
    deadline: Duration,
}

impl ProcessCloudHttpModelsProbe {
    pub fn new(
        chain: Arc<dyn HttpSecurityChain>,
        store: Arc<SecretStore>,
        deadline: Duration,
    ) -> Self {
        Self {
            chain,
            store,
            deadline,
        }
    }
}

impl CloudHttpModelsProbe for ProcessCloudHttpModelsProbe {
    fn list_models(&self, entry: &LlmProviderConfig) -> CatalogFill {
        if entry.uses_chatgpt_sign_in() {
            return CatalogFill::empty_complete();
        }
        let Ok(secret) = self.store.resolve(&entry.api_key_secret) else {
            return CatalogFill::empty_complete();
        };
        let key = secret.expose_secret().to_string();
        let Ok(cap) = build_models_list_capability(entry) else {
            return CatalogFill::incomplete(Vec::new());
        };
        let deadline = Instant::now() + self.deadline;
        let chain = Arc::clone(&self.chain);
        let secret_name = entry.api_key_secret.clone();
        let entry = entry.clone();
        let snapshot = key.clone();
        let fill = crate::discovery::block_on_io(async move {
            list_cloud_http_models(chain.as_ref(), &cap, &entry, &key, deadline).await
        });
        let latest = self
            .store
            .resolve(&secret_name)
            .ok()
            .map(|s| s.expose_secret().to_string());
        CatalogFill {
            models: drop_client_key_rows(
                drop_client_key_rows(fill.models, &snapshot),
                latest.as_deref().unwrap_or(&snapshot),
            ),
            complete: fill.complete,
        }
    }
}

fn drop_client_key_rows(
    models: Vec<ClientProviderSignInModel>,
    key: &str,
) -> Vec<ClientProviderSignInModel> {
    listed_to_client(drop_key_rows(
        models
            .into_iter()
            .map(|m| ListedModel {
                id: m.id,
                display_name: m.display_name,
            })
            .collect(),
        key,
    ))
}

fn listed_to_client(models: Vec<ListedModel>) -> Vec<ClientProviderSignInModel> {
    models
        .into_iter()
        .map(|m| ClientProviderSignInModel {
            id: m.id,
            display_name: m.display_name,
        })
        .collect()
}

fn unique_local_models(
    aliases: &std::collections::HashMap<String, String>,
) -> Vec<ClientProviderSignInModel> {
    let mut ids: Vec<String> = aliases.values().cloned().collect();
    ids.sort();
    ids.dedup();
    ids.into_iter()
        .map(|id| ClientProviderSignInModel {
            id,
            display_name: None,
        })
        .collect()
}

fn is_cacheable_empty_status(status: u16) -> bool {
    matches!(status, 401 | 403 | 404)
}

fn fill_for_cacheable_empty(page: usize, collected: Vec<ListedModel>) -> CatalogFill {
    if page == 0 {
        CatalogFill::empty_complete()
    } else {
        CatalogFill::incomplete(listed_to_client(collected))
    }
}

async fn list_cloud_http_models(
    chain: &dyn HttpSecurityChain,
    cap: &advance_shared_types::security_validator::HttpCapability,
    entry: &LlmProviderConfig,
    key: &str,
    deadline: Instant,
) -> CatalogFill {
    let mut collected: Vec<ListedModel> = Vec::new();
    let mut after_id: Option<String> = None;
    let follows_pages = follows_catalog_pages(entry);
    for page in 0..MAX_MODEL_PAGES {
        if Instant::now() >= deadline || collected.len() >= MAX_CATALOG_MODELS {
            return CatalogFill::incomplete(listed_to_client(collected));
        }
        let Ok(req) = build_models_list_request(entry, after_id.as_deref()) else {
            return CatalogFill::incomplete(listed_to_client(collected));
        };
        match execute_models_page(chain, cap, req, deadline).await {
            PageOutcome::RetrySame => {
                let Ok(req) = build_models_list_request(entry, after_id.as_deref()) else {
                    return CatalogFill::incomplete(listed_to_client(collected));
                };
                match execute_models_page(chain, cap, req, deadline).await {
                    PageOutcome::Ok(resp) => {
                        match apply_models_page(
                            resp,
                            page,
                            &mut collected,
                            &mut after_id,
                            follows_pages,
                            key,
                        ) {
                            PageApply::Continue => {}
                            PageApply::Done(fill) => return fill,
                        }
                    }
                    PageOutcome::CacheableEmpty => {
                        return fill_for_cacheable_empty(page, collected);
                    }
                    _ => return CatalogFill::incomplete(listed_to_client(collected)),
                }
            }
            PageOutcome::Ok(resp) => {
                match apply_models_page(
                    resp,
                    page,
                    &mut collected,
                    &mut after_id,
                    follows_pages,
                    key,
                ) {
                    PageApply::Continue => {}
                    PageApply::Done(fill) => return fill,
                }
            }
            PageOutcome::CacheableEmpty => {
                return fill_for_cacheable_empty(page, collected);
            }
            PageOutcome::Incomplete => {
                return CatalogFill::incomplete(listed_to_client(collected));
            }
        }
    }
    CatalogFill::incomplete(listed_to_client(collected))
}

enum PageOutcome {
    Ok(advance_shared_types::security_validator::HttpResponse),
    RetrySame,
    CacheableEmpty,
    Incomplete,
}

enum PageApply {
    Continue,
    Done(CatalogFill),
}

async fn execute_models_page(
    chain: &dyn HttpSecurityChain,
    cap: &advance_shared_types::security_validator::HttpCapability,
    req: advance_shared_types::security_validator::HttpRequest,
    deadline: Instant,
) -> PageOutcome {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return PageOutcome::Incomplete;
    }
    match tokio::time::timeout(remaining, chain.execute(MODELS_AGENT_ID, req, cap)).await {
        Err(_) => PageOutcome::Incomplete,
        Ok(Err(HttpError::RateLimited { retry_after_ms })) => {
            if retry_after_ms == 0 {
                return PageOutcome::Incomplete;
            }
            let wait = Duration::from_millis(retry_after_ms)
                .min(deadline.saturating_duration_since(Instant::now()));
            if wait.is_zero() {
                return PageOutcome::Incomplete;
            }
            tokio::time::sleep(wait).await;
            PageOutcome::RetrySame
        }
        Ok(Err(_)) => PageOutcome::Incomplete,
        Ok(Ok(resp)) if is_cacheable_empty_status(resp.status) => PageOutcome::CacheableEmpty,
        Ok(Ok(resp)) if (200..300).contains(&resp.status) => PageOutcome::Ok(resp),
        Ok(Ok(_)) => PageOutcome::Incomplete,
    }
}

fn apply_models_page(
    resp: advance_shared_types::security_validator::HttpResponse,
    page: usize,
    collected: &mut Vec<ListedModel>,
    after_id: &mut Option<String>,
    follows_pages: bool,
    key: &str,
) -> PageApply {
    match parse_models_catalog_page(&resp.body) {
        CatalogPage::EmptySuccess => {
            if page == 0 {
                PageApply::Done(CatalogFill::empty_complete())
            } else {
                PageApply::Done(CatalogFill::complete(listed_to_client(std::mem::take(
                    collected,
                ))))
            }
        }
        CatalogPage::Unparseable => PageApply::Done(CatalogFill::incomplete(listed_to_client(
            std::mem::take(collected),
        ))),
        CatalogPage::Parsed {
            models,
            has_more,
            last_id,
        } => {
            collected.extend(drop_key_rows(models, key));
            collected.truncate(MAX_CATALOG_MODELS);
            let next = follows_pages
                .then(|| catalog_page_cursor(last_id.as_deref(), key))
                .flatten();
            if !has_more || collected.len() >= MAX_CATALOG_MODELS || next.is_none() {
                PageApply::Done(CatalogFill::complete(listed_to_client(std::mem::take(
                    collected,
                ))))
            } else {
                *after_id = next;
                PageApply::Continue
            }
        }
    }
}

struct CachedModels {
    fingerprint: u64,
    complete: bool,
    models: Vec<ClientProviderSignInModel>,
}

enum WaiterState {
    Pending,
    Ready(CatalogFill),
}

struct Waiter {
    fingerprint: u64,
    pending: AtomicBool,
    state: Mutex<WaiterState>,
    cv: Condvar,
}

fn new_models_waiter(fp: u64) -> Arc<Waiter> {
    Arc::new(Waiter {
        fingerprint: fp,
        pending: AtomicBool::new(true),
        state: Mutex::new(WaiterState::Pending),
        cv: Condvar::new(),
    })
}

fn publish_models_waiter(waiter: &Waiter, fill: CatalogFill) {
    waiter.pending.store(false, Ordering::Release);
    let mut state = waiter.state.lock().unwrap_or_else(|e| e.into_inner());
    *state = WaiterState::Ready(fill);
    waiter.cv.notify_all();
}

struct LeaderPublishGuard {
    waiter: Arc<Waiter>,
    published: bool,
}

impl Drop for LeaderPublishGuard {
    fn drop(&mut self) {
        if !self.published && self.waiter.pending.load(Ordering::Acquire) {
            publish_models_waiter(&self.waiter, CatalogFill::incomplete(Vec::new()));
        }
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
    /// The allowance read behind `GET …/usage` for `agent-cli` entries.
    agent_cli_usage_probe: Arc<dyn AgentCliUsageProbe>,
    /// The sign-in behind `auth-source: chatgpt-oauth` entries; `None` = not served here.
    chatgpt_sign_in: Option<Arc<dyn ChatGptSignInPort>>,
    /// Serializes every mutation: YAML rewrites + key writes must not interleave. The network
    /// check of a key runs outside it (`set_key`).
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
    /// When set, a sidecar-backed local entry starts in this process instead of at the next
    /// daemon start.
    sidecar_binder: Option<Arc<dyn LocalSidecarBinder>>,
    agent_cli_models_probe: Arc<dyn AgentCliModelsProbe>,
    cloud_http_models_probe: Arc<dyn CloudHttpModelsProbe>,
    agent_cli_models_kind: ModelProbeInstallation,
    cloud_http_models_kind: ModelProbeInstallation,
    models_generation: Mutex<HashMap<String, u64>>,
    available_models_cache: Mutex<HashMap<String, CachedModels>>,
    inflight: Mutex<HashMap<String, Arc<Waiter>>>,
    fallback_store: OnceLock<Result<Arc<SecretStore>, String>>,
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
            sidecar_binder: None,
            agent_cli_models_probe: Arc::new(NoopModelsProbe),
            cloud_http_models_probe: Arc::new(NoopCloudHttpModelsProbe),
            agent_cli_models_kind: ModelProbeInstallation::Noop,
            cloud_http_models_kind: ModelProbeInstallation::Noop,
            models_generation: Mutex::new(HashMap::new()),
            available_models_cache: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            fallback_store: OnceLock::new(),
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

    /// Start and stop sidecar-backed local entries in this process. The production gateway
    /// is the binder. Without one, those entries still answer `restart_required`.
    pub fn with_local_sidecar_binder(mut self, binder: Arc<dyn LocalSidecarBinder>) -> Self {
        self.sidecar_binder = Some(binder);
        self
    }

    /// Scripted agent-cli catalog probe (tests).
    pub fn with_agent_cli_models_probe(mut self, probe: Arc<dyn AgentCliModelsProbe>) -> Self {
        self.agent_cli_models_probe = probe;
        self.agent_cli_models_kind = ModelProbeInstallation::Scripted;
        self
    }

    /// Live agent-cli catalog probe (production attach).
    pub fn with_process_agent_cli_models_probe(
        mut self,
        probe: Arc<dyn AgentCliModelsProbe>,
    ) -> Self {
        self.agent_cli_models_probe = probe;
        self.agent_cli_models_kind = ModelProbeInstallation::Process;
        self
    }

    /// Scripted cloud-http catalog probe (tests).
    pub fn with_cloud_http_models_probe(mut self, probe: Arc<dyn CloudHttpModelsProbe>) -> Self {
        self.cloud_http_models_probe = probe;
        self.cloud_http_models_kind = ModelProbeInstallation::Scripted;
        self
    }

    /// Live cloud-http catalog probe (production attach).
    pub fn with_process_cloud_http_models_probe(
        mut self,
        probe: Arc<dyn CloudHttpModelsProbe>,
    ) -> Self {
        self.cloud_http_models_probe = probe;
        self.cloud_http_models_kind = ModelProbeInstallation::Process;
        self
    }

    pub fn model_probe_installation(&self) -> (ModelProbeInstallation, ModelProbeInstallation) {
        (self.agent_cli_models_kind, self.cloud_http_models_kind)
    }

    #[cfg(test)]
    pub fn models_generation_of(&self, provider_id: &str) -> u64 {
        self.models_generation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(provider_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn process_policy(&self) -> ProcessPolicy {
        self.process_policy
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
    pub fn key_store(&self) -> Result<Arc<SecretStore>, ProviderError> {
        if let Some(store) = &self.store {
            return Ok(Arc::clone(store));
        }
        match self.fallback_store.get_or_init(|| {
            let cfg = self.config.current();
            crate::open_home_secret_store(&self.home, &cfg)
                .map(Arc::new)
                .map_err(|e| format!("{e}"))
        }) {
            Ok(store) => Ok(Arc::clone(store)),
            Err(e) => Err(ProviderError::Unavailable(format!("secret store: {e}"))),
        }
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
        let sign_in = match (entry.uses_chatgpt_sign_in(), self.chatgpt_sign_in.as_ref()) {
            (true, Some(port)) => Some(project_sign_in(
                port.status(&entry.api_key_secret),
                now_ms(),
            )),
            _ => None,
        };
        let available_models = match sign_in.as_ref() {
            Some(projected) => projected.models.clone(),
            None => self.cheap_available_models(entry),
        };
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
            generate_timeout_secs: entry.generate_timeout_secs,
            reasoning_effort: entry.reasoning_effort.map(|e| e.as_str().to_string()),
            system_messages: entry.system_messages.map(|m| m.as_str().to_string()),
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
            sign_in,
            available_models,
        }
    }

    fn cheap_available_models(&self, entry: &LlmProviderConfig) -> Vec<ClientProviderSignInModel> {
        if entry.uses_chatgpt_sign_in() {
            return Vec::new();
        }
        match entry.backend_class {
            InferenceBackendClass::Local => unique_local_models(&entry.model_aliases),
            InferenceBackendClass::MeshRemote => Vec::new(),
            InferenceBackendClass::AgentCli | InferenceBackendClass::CloudHttp => {
                self.cached_available_models(entry)
            }
        }
    }

    fn cached_available_models(&self, entry: &LlmProviderConfig) -> Vec<ClientProviderSignInModel> {
        let fp = self.fingerprint(entry);
        self.available_models_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&entry.id)
            .filter(|c| c.fingerprint == fp && c.complete)
            .map(|c| c.models.clone())
            .unwrap_or_default()
    }

    fn summary_for_get(
        &self,
        entry: &LlmProviderConfig,
        selected: bool,
        list_budget: Option<Instant>,
    ) -> ClientProviderSummary {
        let mut s = self.summary(entry, selected);
        if entry.backend_class == InferenceBackendClass::AgentCli
            || (entry.backend_class == InferenceBackendClass::CloudHttp
                && !entry.uses_chatgpt_sign_in())
        {
            s.available_models = if list_budget.is_some_and(|deadline| Instant::now() >= deadline) {
                self.cheap_available_models(entry)
            } else {
                self.ensure_models_cached(entry).models
            };
        }
        s
    }

    fn fingerprint(&self, entry: &LlmProviderConfig) -> u64 {
        let gen = self
            .models_generation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&entry.id)
            .copied()
            .unwrap_or(0);
        let mut hasher = DefaultHasher::new();
        entry.id.hash(&mut hasher);
        gen.hash(&mut hasher);
        match entry.backend_class {
            InferenceBackendClass::AgentCli => {
                if let Some(spec) = &entry.agent_cli {
                    spec.vendor.as_str().hash(&mut hasher);
                    spec.command.hash(&mut hasher);
                    spec.args.len().hash(&mut hasher);
                }
            }
            InferenceBackendClass::CloudHttp => {
                entry.api_key_secret.hash(&mut hasher);
                self.key_present(&entry.api_key_secret).hash(&mut hasher);
                entry.endpoint.hash(&mut hasher);
                entry
                    .backend
                    .map(|b| backend_str(b))
                    .unwrap_or("")
                    .hash(&mut hasher);
                entry
                    .auth_scheme
                    .map(|a| auth_scheme_str(a))
                    .unwrap_or("")
                    .hash(&mut hasher);
            }
            _ => {}
        }
        hasher.finish()
    }

    fn invalidate_models(&self, provider_id: &str) {
        {
            let mut gens = self
                .models_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let slot = gens.entry(provider_id.to_string()).or_insert(0);
            *slot = slot.saturating_add(1);
            if *slot == 0 {
                *slot = 1;
            }
        }
        self.available_models_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(provider_id);
        let waiter = self
            .inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(provider_id)
            .cloned();
        if let Some(waiter) = waiter {
            publish_models_waiter(&waiter, CatalogFill::empty_complete());
        }
    }

    fn drop_models_generation(&self, provider_id: &str) {
        self.invalidate_models(provider_id);
        self.models_generation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(provider_id);
    }

    fn probe_models_entry(&self, entry: &LlmProviderConfig) -> CatalogFill {
        match entry.backend_class {
            InferenceBackendClass::AgentCli => {
                if self.process_policy.is_forbid() {
                    return CatalogFill::empty_complete();
                }
                match &entry.agent_cli {
                    Some(spec) => {
                        let fill = self.agent_cli_models_probe.list_models(spec);
                        CatalogFill {
                            models: listed_to_client(
                                fill.models
                                    .into_iter()
                                    .map(|m| ListedModel {
                                        id: m.id,
                                        display_name: m.display_name,
                                    })
                                    .collect(),
                            ),
                            complete: fill.complete,
                        }
                    }
                    None => CatalogFill::empty_complete(),
                }
            }
            InferenceBackendClass::CloudHttp if !entry.uses_chatgpt_sign_in() => {
                if self.key_store().is_err() || !self.key_present(&entry.api_key_secret) {
                    return CatalogFill::empty_complete();
                }
                self.cloud_http_models_probe.list_models(entry)
            }
            _ => CatalogFill::empty_complete(),
        }
    }

    fn claim_models_waiter(&self, provider_id: &str, fp: u64) -> (bool, Arc<Waiter>) {
        let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = inflight.get(provider_id).cloned() {
            if existing.fingerprint == fp && existing.pending.load(Ordering::Acquire) {
                return (false, existing);
            }
        }
        let waiter = new_models_waiter(fp);
        inflight.insert(provider_id.to_string(), Arc::clone(&waiter));
        (true, waiter)
    }

    fn ensure_models_cached(&self, entry: &LlmProviderConfig) -> CatalogFill {
        let fp = self.fingerprint(entry);
        {
            let cache = self
                .available_models_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(hit) = cache.get(&entry.id) {
                if hit.fingerprint == fp && hit.complete {
                    return CatalogFill::complete(hit.models.clone());
                }
            }
        }
        let (leader, waiter) = self.claim_models_waiter(&entry.id, fp);
        if !leader {
            let ready = {
                let mut state = waiter.state.lock().unwrap_or_else(|e| e.into_inner());
                while matches!(*state, WaiterState::Pending) {
                    state = waiter.cv.wait(state).unwrap_or_else(|e| e.into_inner());
                }
                match &*state {
                    WaiterState::Ready(fill) => fill.clone(),
                    WaiterState::Pending => CatalogFill::empty_complete(),
                }
            };
            return if self.fingerprint(entry) != fp {
                CatalogFill::empty_complete()
            } else {
                ready
            };
        }
        let mut guard = LeaderPublishGuard {
            waiter: Arc::clone(&waiter),
            published: false,
        };
        let fill = match catch_unwind(AssertUnwindSafe(|| self.probe_models_entry(entry))) {
            Ok(fill) => fill,
            Err(_) => CatalogFill::incomplete(Vec::new()),
        };
        let published = if self.fingerprint(entry) == fp {
            fill.clone()
        } else {
            CatalogFill::empty_complete()
        };
        publish_models_waiter(&waiter, published);
        guard.published = true;
        if self.fingerprint(entry) != fp {
            publish_models_waiter(&waiter, CatalogFill::empty_complete());
            self.drop_inflight_if(&entry.id, fp);
            return CatalogFill::empty_complete();
        }
        if fill.complete {
            let mut cache = self
                .available_models_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.insert(
                entry.id.clone(),
                CachedModels {
                    fingerprint: fp,
                    complete: true,
                    models: fill.models.clone(),
                },
            );
        }
        self.drop_inflight_if(&entry.id, fp);
        if self.fingerprint(entry) != fp {
            CatalogFill::empty_complete()
        } else {
            fill
        }
    }

    fn drop_inflight_if(&self, provider_id: &str, fp: u64) {
        let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if inflight
            .get(provider_id)
            .is_some_and(|w| w.fingerprint == fp)
        {
            inflight.remove(provider_id);
        }
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

    /// Refuse, before the document changes, a generate budget, reasoning setting or
    /// system-message mode the entry cannot take once `written` is applied under `mode` (see
    /// [`check_entry_settings`]): the
    /// check reads the entry exactly as the writer would leave it. A write the writer itself
    /// refuses (a taken or missing id) is left to it.
    fn refuse_unappliable_settings(
        &self,
        written: &Value,
        mode: UpsertMode,
    ) -> Result<(), ProviderError> {
        match crate::provider::provider_entry_after_upsert(&self.home, written.clone(), mode) {
            Ok(entry) => check_entry_settings(&entry),
            Err(_) => Ok(()),
        }
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

    /// The bound of one chat preflight of `entry` (overlay or claimed): its own
    /// `generate-timeout-secs` when it sets one (the bound of its generate hop), else the
    /// preflight deadline. The check of a sign-in entry keeps the preflight deadline.
    fn preflight_budget(&self, entry: &LlmProviderConfig) -> Duration {
        entry.generate_timeout().unwrap_or(self.preflight_timeout)
    }

    /// Run the overlay preflight for `entry` with `key`, bounded by
    /// [`Self::preflight_budget`].
    fn run_preflight(&self, entry: &LlmProviderConfig, key: &str) -> ClientProviderPreflightResult {
        let cancel = CancelToken::new();
        let deadline_cancel = cancel.clone();
        let deadline = self.preflight_budget(entry);
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
        let deadline = self.preflight_budget(entry);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let timer = std::thread::spawn(move || {
            if done_rx.recv_timeout(deadline).is_err() {
                deadline_cancel.cancel();
                true
            } else {
                false
            }
        });
        let outcome = port.preflight(&entry.id, &cancel, deadline);
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SidecarSync {
    /// No binder: the boot-time registry is unchanged until the next daemon start.
    Unbound,
    Applied,
    Failed,
}

impl WiredProviderAdmin {
    /// Start, replace, or stop the entry's sidecar. `Failed` records `sidecar-not-started`.
    fn sync_sidecar(&self, entry: &LlmProviderConfig) -> SidecarSync {
        let Some(binder) = self.sidecar_binder.as_ref() else {
            return SidecarSync::Unbound;
        };
        match entry.sidecar.as_ref() {
            Some(sc) => match binder.apply_local_sidecar(
                &entry.id,
                &sc.command,
                &sc.args,
                entry.embedding_model.as_deref(),
                self.process_policy,
            ) {
                Ok(()) => SidecarSync::Applied,
                Err(()) => {
                    self.record_preflight(
                        &entry.id,
                        &ClientProviderPreflightResult {
                            ok: false,
                            checked_at_ms: now_ms(),
                            reason: Some("sidecar-not-started".into()),
                        },
                    );
                    SidecarSync::Failed
                }
            },
            None => {
                binder.release_local_sidecar(&entry.id);
                SidecarSync::Applied
            }
        }
    }
}

impl ProviderAdminProvider for WiredProviderAdmin {
    fn list_providers(&self) -> Result<Vec<ClientProviderSummary>, ProviderError> {
        let budget = Instant::now() + MODELS_LIST_TIMEOUT;
        Ok(self
            .entries()?
            .iter()
            .enumerate()
            .map(|(idx, entry)| self.summary_for_get(entry, idx == 0, Some(budget)))
            .collect())
    }

    fn get_provider(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        let (idx, entry) = self.find(provider_id)?;
        Ok(self.summary_for_get(&entry, idx == 0, None))
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
        let written = create_mapping(request, &secret);
        self.refuse_unappliable_settings(&written, UpsertMode::Create)?;
        let rx = self.subscribe_if_watching();
        crate::upsert_provider_entry(&self.home, written, UpsertMode::Create)
            .map_err(write_error)?;
        let (idx, entry) = self.find(&request.provider_id)?;
        if matches!(
            entry.backend_class,
            InferenceBackendClass::AgentCli | InferenceBackendClass::CloudHttp
        ) {
            self.invalidate_models(&entry.id);
        }
        let applied = entry.clone();
        let mut outcome = self.after_yaml_write(
            ProviderAdminOutcome::new(self.summary(&entry, idx == 0)),
            rx,
            move |cfg| cfg.llm_providers.iter().any(|p| *p == applied),
        );
        if outcome.value.sidecar_present && outcome.value.backend_class == "local" {
            match self.sync_sidecar(&entry) {
                SidecarSync::Applied => {}
                SidecarSync::Failed => {
                    outcome.value = self.summary(&entry, idx == 0);
                }
                SidecarSync::Unbound => {
                    outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
                }
            }
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
        let written = update_mapping(provider_id, request);
        self.refuse_unappliable_settings(&written, UpsertMode::Update)?;
        let rx = self.subscribe_if_watching();
        crate::upsert_provider_entry(&self.home, written, UpsertMode::Update)
            .map_err(write_error)?;
        let (idx, entry) = self.find(provider_id)?;
        if request.agent_cli.is_some()
            || request.endpoint.is_some()
            || request.backend.is_some()
            || request.auth_scheme.is_some()
            || request.api_key_secret.is_some()
        {
            self.invalidate_models(provider_id);
        }
        let applied = entry.clone();
        let mut outcome = self.after_yaml_write(
            ProviderAdminOutcome::new(self.summary(&entry, idx == 0)),
            rx,
            move |cfg| cfg.llm_providers.iter().any(|p| *p == applied),
        );
        let mut sidecar_live = false;
        if request.sidecar.is_some() && entry.backend_class == InferenceBackendClass::Local {
            match self.sync_sidecar(&entry) {
                SidecarSync::Applied => sidecar_live = entry.sidecar.is_some(),
                SidecarSync::Failed => {
                    outcome.value = self.summary(&entry, idx == 0);
                }
                SidecarSync::Unbound => {
                    outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
                }
            }
        }
        if request.agent_cli.is_some() && entry.backend_class == InferenceBackendClass::AgentCli {
            outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
        }
        if self.claimable_local
            && (current.backend_class != entry.backend_class || current.sidecar != entry.sidecar)
            && !sidecar_live
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
        if let Some(entry) = removed.as_ref() {
            if entry.sidecar.is_some() {
                if let Some(binder) = self.sidecar_binder.as_ref() {
                    binder.release_local_sidecar(&entry.id);
                }
            }
        }
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
        self.drop_models_generation(provider_id);
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
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (_, entry) = self.find(provider_id)?;
        if entry.uses_chatgpt_sign_in() {
            // The value under the name is the session's access token, written by the sign-in.
            return Err(ProviderError::AuthSourceMismatch(provider_id.to_string()));
        }
        let store = self.key_store()?;
        if entry.backend_class != InferenceBackendClass::CloudHttp {
            store
                .store(&entry.api_key_secret, key)
                .map_err(|_| ProviderError::Unavailable("secret store write".into()))?;
            self.invalidate_models(provider_id);
            return Ok(ProviderAdminOutcome::new(ClientProviderKeyResult {
                stored: true,
                preflight: None,
            })
            .with_warning(ProviderAdminWarning::PreflightSkipped));
        }
        // The check may run as long as the entry's own generate budget, so it runs without the
        // write lock: every other mutation goes on meanwhile, and the key is stored only if the
        // entry is still the one that was checked.
        drop(guard);
        let verdict = self.run_preflight(&entry, key);
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (_, current) = self.find(provider_id)?;
        if current != entry {
            // The entry changed while its key was being checked: the verdict is about settings
            // that are gone, so nothing is stored or recorded.
            return Ok(ProviderAdminOutcome::new(ClientProviderKeyResult {
                stored: false,
                preflight: Some(ClientProviderPreflightResult {
                    ok: false,
                    checked_at_ms: now_ms(),
                    reason: Some(REASON_CANCELLED.to_string()),
                }),
            }));
        }
        self.record_preflight(provider_id, &verdict);
        if !verdict.ok {
            // The previous key (if any) stays; the verdict is the answer.
            return Ok(ProviderAdminOutcome::new(ClientProviderKeyResult {
                stored: false,
                preflight: Some(verdict),
            }));
        }
        store
            .store(&entry.api_key_secret, key)
            .map_err(|_| ProviderError::Unavailable("secret store write".into()))?;
        self.invalidate_models(provider_id);
        Ok(ProviderAdminOutcome::new(ClientProviderKeyResult {
            stored: true,
            preflight: Some(verdict),
        }))
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
        self.invalidate_models(provider_id);
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
            self.invalidate_models(provider_id);
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
        if entry.backend_class == InferenceBackendClass::CloudHttp && !entry.uses_chatgpt_sign_in()
        {
            self.invalidate_models(provider_id);
        }
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
        let mut outcome = self.after_yaml_write(
            ProviderAdminOutcome::new(self.summary(&entry, true)),
            rx,
            move |cfg| cfg.llm_providers.first().map(|p| p.id.as_str()) == Some(id.as_str()),
        );
        if entry.backend_class == InferenceBackendClass::Local && entry.sidecar.is_some() {
            if self.sync_sidecar(&entry) == SidecarSync::Failed {
                outcome.value = self.summary(&entry, true);
            }
        }
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

/// Refuse a generate budget, reasoning setting or system-message mode `entry` (an entry's YAML
/// mapping) cannot take — by the runtime loader's own rules, read off the entry itself — as
/// `InvalidRequest` carrying the setting's detail token. The loader refuses such a document
/// without saying which setting is at fault. An entry whose other keys the loader refuses is
/// left to the write's own validation.
fn check_entry_settings(entry: &Mapping) -> Result<(), ProviderError> {
    let refuse = |detail: &str| Err(ProviderError::InvalidRequest(detail.into()));
    let secs = match entry.get(GENERATE_TIMEOUT_KEY) {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_u64().and_then(|secs| u32::try_from(secs).ok()) {
            Some(secs)
                if (MIN_GENERATE_TIMEOUT_SECS..=MAX_GENERATE_TIMEOUT_SECS).contains(&secs) =>
            {
                Some(secs)
            }
            _ => return refuse(INVALID_GENERATE_TIMEOUT_DETAIL),
        },
    };
    let effort = match entry.get(REASONING_EFFORT_KEY) {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_str().and_then(ReasoningEffort::parse) {
            Some(effort) => Some(effort),
            None => return refuse(INVALID_REASONING_EFFORT_DETAIL),
        },
    };
    let system_messages = match entry.get(SYSTEM_MESSAGES_KEY) {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_str().and_then(SystemMessages::parse) {
            Some(mode) => Some(mode),
            None => return refuse(INVALID_SYSTEM_MESSAGES_DETAIL),
        },
    };
    if secs.is_none() && effort.is_none() && system_messages.is_none() {
        return Ok(());
    }
    // What decides whether the entry can take them, as the loader reads it from the entry
    // without them (the backend class, the dialect, the credential source).
    let mut rest = entry.clone();
    rest.remove(GENERATE_TIMEOUT_KEY);
    rest.remove(REASONING_EFFORT_KEY);
    rest.remove(SYSTEM_MESSAGES_KEY);
    let Ok(base) = serde_yml::from_value::<LlmProviderConfig>(Value::Mapping(rest)) else {
        return Ok(());
    };
    if let Some(secs) = secs {
        if secs > max_generate_timeout_secs(base.auth_source) {
            return refuse(INVALID_GENERATE_TIMEOUT_DETAIL);
        }
        if generate_timeout_refusal(base.backend_class).is_some() {
            return refuse(GENERATE_TIMEOUT_UNSUPPORTED_DETAIL);
        }
    }
    if effort.is_some()
        && reasoning_effort_refusal(
            base.backend_class,
            effective_backend(&base.id, base.backend),
            base.auth_source,
        )
        .is_some()
    {
        return refuse(REASONING_EFFORT_UNSUPPORTED_DETAIL);
    }
    if system_messages.is_some()
        && system_messages_refusal(
            base.backend_class,
            effective_backend(&base.id, base.backend),
            base.auth_source,
        )
        .is_some()
    {
        return refuse(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL);
    }
    Ok(())
}

const GENERATE_TIMEOUT_KEY: &str = "generate-timeout-secs";
const REASONING_EFFORT_KEY: &str = "reasoning-effort";
const SYSTEM_MESSAGES_KEY: &str = "system-messages";

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
    if let Some(secs) = req.generate_timeout_secs {
        m.insert(key("generate-timeout-secs"), Value::from(secs));
    }
    if let Some(effort) = &req.reasoning_effort {
        m.insert(key("reasoning-effort"), key(effort));
    }
    if let Some(mode) = &req.system_messages {
        m.insert(key(SYSTEM_MESSAGES_KEY), key(mode));
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
    // An explicit null clears the setting: the writer removes a key whose value is null.
    if let Some(secs) = req.generate_timeout_secs {
        m.insert(
            key("generate-timeout-secs"),
            secs.map_or(Value::Null, Value::from),
        );
    }
    if let Some(effort) = &req.reasoning_effort {
        m.insert(
            key("reasoning-effort"),
            effort.as_deref().map_or(Value::Null, key),
        );
    }
    if let Some(mode) = &req.system_messages {
        m.insert(
            key(SYSTEM_MESSAGES_KEY),
            mode.as_deref().map_or(Value::Null, key),
        );
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
    fn create_mapping_writes_the_generate_budget_and_reasoning_setting_only_when_set() {
        let base = ClientCreateProviderRequest {
            provider_id: "reasoner".into(),
            endpoint: Some("https://api.example.com".into()),
            model_aliases: [("think".to_string(), "reasoner-large".to_string())]
                .into_iter()
                .collect(),
            cost: ClientProviderCost {
                input_per_mtoken: 1.0,
                output_per_mtoken: 2.0,
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 100,
                tokens_per_minute: 1000,
            },
            ..Default::default()
        };
        let plain = create_mapping(&base, "reasoner-api-key");
        assert!(plain.get("generate-timeout-secs").is_none(), "{plain:?}");
        assert!(plain.get("reasoning-effort").is_none(), "{plain:?}");

        let req = ClientCreateProviderRequest {
            generate_timeout_secs: Some(120),
            reasoning_effort: Some("low".into()),
            ..base
        };
        let v = create_mapping(&req, "reasoner-api-key");
        assert_eq!(v["generate-timeout-secs"], 120);
        assert!(
            v["generate-timeout-secs"].is_u64(),
            "a number, not a string"
        );
        assert_eq!(v["reasoning-effort"], "low");
        let parsed: LlmProviderConfig = serde_yml::from_value(v).expect("runtime parses");
        assert_eq!(parsed.generate_timeout_secs, Some(120));
        assert_eq!(parsed.reasoning_effort, Some(ReasoningEffort::Low));
    }

    #[test]
    fn update_mapping_sets_and_clears_the_generate_budget_and_reasoning_setting() {
        let set = update_mapping(
            "reasoner",
            &ClientUpdateProviderRequest {
                generate_timeout_secs: Some(Some(300)),
                reasoning_effort: Some(Some("high".into())),
                ..Default::default()
            },
        );
        assert_eq!(set["generate-timeout-secs"], 300);
        assert_eq!(set["reasoning-effort"], "high");
        // An explicit null travels as `null`, which the writer turns into removing the key.
        let cleared = update_mapping(
            "reasoner",
            &ClientUpdateProviderRequest {
                generate_timeout_secs: Some(None),
                reasoning_effort: Some(None),
                ..Default::default()
            },
        );
        let m = cleared.as_mapping().unwrap();
        assert_eq!(m.len(), 3, "id + the two cleared keys: {m:?}");
        assert!(cleared["generate-timeout-secs"].is_null());
        assert!(cleared["reasoning-effort"].is_null());
        // An absent field names nothing.
        let untouched = update_mapping(
            "reasoner",
            &ClientUpdateProviderRequest {
                endpoint: Some("https://proxy.example".into()),
                ..Default::default()
            },
        );
        assert!(untouched.get("generate-timeout-secs").is_none());
        assert!(untouched.get("reasoning-effort").is_none());
    }

    #[test]
    fn create_and_update_mappings_write_the_system_message_mode_only_when_named() {
        let base = ClientCreateProviderRequest {
            provider_id: "joiner".into(),
            endpoint: Some("https://api.example.com".into()),
            model_aliases: [("m".to_string(), "model".to_string())]
                .into_iter()
                .collect(),
            cost: ClientProviderCost {
                input_per_mtoken: 1.0,
                output_per_mtoken: 2.0,
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 100,
                tokens_per_minute: 1000,
            },
            ..Default::default()
        };
        let plain = create_mapping(&base, "joiner-api-key");
        assert!(plain.get("system-messages").is_none(), "{plain:?}");
        let parsed: LlmProviderConfig = serde_yml::from_value(plain).expect("runtime parses");
        assert_eq!(parsed.system_messages, None);
        for mode in SystemMessages::ALL {
            let v = create_mapping(
                &ClientCreateProviderRequest {
                    system_messages: Some(mode.as_str().into()),
                    ..base.clone()
                },
                "joiner-api-key",
            );
            assert_eq!(v["system-messages"], mode.as_str());
            let parsed: LlmProviderConfig = serde_yml::from_value(v).expect("runtime parses");
            assert_eq!(parsed.system_messages, Some(mode));
        }

        let set = update_mapping(
            "joiner",
            &ClientUpdateProviderRequest {
                system_messages: Some(Some("merge".into())),
                ..Default::default()
            },
        );
        assert_eq!(set["system-messages"], "merge");
        // An explicit null travels as `null`, which the writer turns into removing the key.
        let cleared = update_mapping(
            "joiner",
            &ClientUpdateProviderRequest {
                system_messages: Some(None),
                ..Default::default()
            },
        );
        let m = cleared.as_mapping().unwrap();
        assert_eq!(m.len(), 2, "id + the cleared key: {m:?}");
        assert!(cleared["system-messages"].is_null());
        let untouched = update_mapping(
            "joiner",
            &ClientUpdateProviderRequest {
                endpoint: Some("https://proxy.example".into()),
                ..Default::default()
            },
        );
        assert!(untouched.get("system-messages").is_none());
    }

    /// The pre-write check refuses exactly the entries the runtime loader refuses, with the token
    /// of the setting at fault: it reads the class, dialect and credential source off the entry
    /// the way the loader does.
    #[test]
    fn unappliable_settings_are_refused_with_their_detail_by_the_loaders_rules() {
        let entry = |id: &str, extra: &str| -> Mapping {
            serde_yml::from_str(&format!(
                "id: {id}\nendpoint: https://api.example.com\napi-key-secret: {id}-api-key\n\
                 model-aliases:\n  m: model\ncost-per-mtoken-in: 1.0\ncost-per-mtoken-out: 1.0\n\
                 rate-limit:\n  requests-per-minute: 10\n  tokens-per-minute: 1000\n{extra}"
            ))
            .expect("entry yaml")
        };
        let agent_cli =
            "backend-class: agent-cli\nagent-cli:\n  vendor: claude\n  command: /nonexistent/claude\n";
        let mesh = "backend-class: mesh-remote\ndevice-id: peer\n";
        let sign_in = "auth-source: chatgpt-oauth\n";
        let refused = |detail: &str| Err(ProviderError::InvalidRequest(detail.into()));
        for (id, extra, expected, why) in [
            ("gw", String::new(), Ok(()), "nothing set"),
            (
                "gw",
                "backend: openai-chat\ngenerate-timeout-secs: 5\nreasoning-effort: none\n".into(),
                Ok(()),
                "chat",
            ),
            (
                "gw",
                "backend-class: local\ngenerate-timeout-secs: 900\nreasoning-effort: xhigh\n"
                    .into(),
                Ok(()),
                "local",
            ),
            (
                "gw",
                "backend: openai-responses\ngenerate-timeout-secs: 60\nreasoning-effort: low\n"
                    .into(),
                Ok(()),
                "responses",
            ),
            (
                "signed-in",
                format!("{sign_in}generate-timeout-secs: 300\n"),
                Ok(()),
                "sign-in budget at its ceiling",
            ),
            (
                "signed-in",
                format!("{sign_in}generate-timeout-secs: 301\n"),
                refused(INVALID_GENERATE_TIMEOUT_DETAIL),
                "sign-in budget above its ceiling",
            ),
            (
                "gw",
                "generate-timeout-secs: 4\n".into(),
                refused(INVALID_GENERATE_TIMEOUT_DETAIL),
                "below",
            ),
            (
                "gw",
                "generate-timeout-secs: 901\n".into(),
                refused(INVALID_GENERATE_TIMEOUT_DETAIL),
                "above",
            ),
            (
                "gw",
                format!("{agent_cli}generate-timeout-secs: 60\n"),
                refused(GENERATE_TIMEOUT_UNSUPPORTED_DETAIL),
                "agent-cli budget",
            ),
            (
                "gw",
                format!("{mesh}generate-timeout-secs: 60\n"),
                refused(GENERATE_TIMEOUT_UNSUPPORTED_DETAIL),
                "mesh budget",
            ),
            (
                "gw",
                "reasoning-effort: max\n".into(),
                refused(INVALID_REASONING_EFFORT_DETAIL),
                "spelling",
            ),
            (
                "gw",
                "backend: anthropic-messages\nreasoning-effort: low\n".into(),
                refused(REASONING_EFFORT_UNSUPPORTED_DETAIL),
                "messages dialect",
            ),
            (
                "anthropic",
                "reasoning-effort: low\n".into(),
                refused(REASONING_EFFORT_UNSUPPORTED_DETAIL),
                "anthropic id",
            ),
            (
                "anthropic",
                "backend: openai-chat\nreasoning-effort: low\n".into(),
                Ok(()),
                "anthropic id on chat",
            ),
            (
                "anthropic",
                "backend-class: local\nreasoning-effort: low\n".into(),
                Ok(()),
                "anthropic id on a local entry, which speaks openai-chat",
            ),
            (
                "anthropic",
                "backend: local\nreasoning-effort: low\n".into(),
                Ok(()),
                "anthropic id on the local backend",
            ),
            (
                "gw",
                format!("{agent_cli}reasoning-effort: low\n"),
                refused(REASONING_EFFORT_UNSUPPORTED_DETAIL),
                "agent-cli effort",
            ),
            (
                "gw",
                format!("{mesh}reasoning-effort: low\n"),
                refused(REASONING_EFFORT_UNSUPPORTED_DETAIL),
                "mesh effort",
            ),
            (
                "signed-in",
                format!("{sign_in}reasoning-effort: low\n"),
                refused(REASONING_EFFORT_UNSUPPORTED_DETAIL),
                "sign-in effort",
            ),
            (
                "gw",
                "system-messages: merge\n".into(),
                Ok(()),
                "merge on the id's chat dialect",
            ),
            (
                "gw",
                "backend: openai-chat\nsystem-messages: separate\n".into(),
                Ok(()),
                "separate on chat",
            ),
            (
                "gw",
                "backend-class: local\ngenerate-timeout-secs: 60\nsystem-messages: merge\n".into(),
                Ok(()),
                "merge on a local entry",
            ),
            (
                "anthropic",
                "backend-class: local\nsystem-messages: merge\n".into(),
                Ok(()),
                "anthropic id on a local entry, which speaks openai-chat",
            ),
            (
                "gw",
                "system-messages: joined\n".into(),
                refused(INVALID_SYSTEM_MESSAGES_DETAIL),
                "system-messages spelling",
            ),
            (
                "gw",
                "system-messages: 1\n".into(),
                refused(INVALID_SYSTEM_MESSAGES_DETAIL),
                "system-messages is a spelling",
            ),
            (
                "gw",
                "backend: openai-responses\nsystem-messages: merge\n".into(),
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "responses dialect merge",
            ),
            (
                "gw",
                "backend: openai-responses\nsystem-messages: separate\n".into(),
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "responses dialect separate",
            ),
            (
                "gw",
                "backend: anthropic-messages\nsystem-messages: merge\n".into(),
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "messages dialect merge",
            ),
            (
                "anthropic",
                "system-messages: merge\n".into(),
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "anthropic id merge",
            ),
            (
                "gw",
                format!("{agent_cli}system-messages: merge\n"),
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "agent-cli merge",
            ),
            (
                "gw",
                format!("{mesh}system-messages: merge\n"),
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "mesh merge",
            ),
            (
                "signed-in",
                format!("{sign_in}system-messages: merge\n"),
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "sign-in merge",
            ),
        ] {
            let entry = entry(id, &extra);
            assert_eq!(check_entry_settings(&entry), expected, "{why}");
            assert_eq!(
                serde_yml::from_value::<LlmProviderConfig>(Value::Mapping(entry)).is_ok(),
                expected.is_ok(),
                "{why}: the loader agrees"
            );
        }
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
    fn client_api_provider_setting_vocabulary_is_the_runtime_loaders() {
        use advance_client_api::provider_admin::{
            effective_backend as client_effective_backend, entry_backend, BACKENDS,
            BACKEND_CLASSES, MAX_GENERATE_TIMEOUT_SECS as CLIENT_MAX,
            MAX_SIGN_IN_GENERATE_TIMEOUT_SECS as CLIENT_SIGN_IN_MAX,
            MIN_GENERATE_TIMEOUT_SECS as CLIENT_MIN, PROVIDER_KNOB_BACKEND_CLASSES,
            REASONING_EFFORTS, REASONING_EFFORT_BACKENDS, SYSTEM_MESSAGES_BACKENDS,
            SYSTEM_MESSAGES_MODES,
        };
        use advance_runtime::config::MAX_SIGN_IN_GENERATE_TIMEOUT_SECS;
        use InferenceBackendClass::{AgentCli, CloudHttp, Local, MeshRemote};
        let runtime: Vec<&str> = ReasoningEffort::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(REASONING_EFFORTS, runtime.as_slice());
        for spelling in REASONING_EFFORTS {
            assert_eq!(
                ReasoningEffort::parse(spelling).map(ReasoningEffort::as_str),
                Some(*spelling)
            );
        }
        let runtime: Vec<&str> = SystemMessages::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(SYSTEM_MESSAGES_MODES, runtime.as_slice());
        for spelling in SYSTEM_MESSAGES_MODES {
            assert_eq!(
                SystemMessages::parse(spelling).map(SystemMessages::as_str),
                Some(*spelling)
            );
        }
        assert_eq!(
            (CLIENT_MIN, CLIENT_MAX, CLIENT_SIGN_IN_MAX),
            (
                MIN_GENERATE_TIMEOUT_SECS,
                MAX_GENERATE_TIMEOUT_SECS,
                MAX_SIGN_IN_GENERATE_TIMEOUT_SECS
            )
        );
        assert_eq!(
            CLIENT_SIGN_IN_MAX,
            max_generate_timeout_secs(ProviderAuthSource::ChatGptOAuth)
        );
        let classes = [CloudHttp, Local, MeshRemote, AgentCli];
        assert_eq!(BACKEND_CLASSES.len(), classes.len());
        for class in classes {
            let spelling = backend_class_str(class);
            assert!(BACKEND_CLASSES.contains(&spelling), "{spelling}");
            assert_eq!(
                PROVIDER_KNOB_BACKEND_CLASSES.contains(&spelling),
                generate_timeout_refusal(class).is_none(),
                "{spelling}"
            );
            assert_eq!(
                PROVIDER_KNOB_BACKEND_CLASSES.contains(&spelling),
                system_messages_refusal(
                    class,
                    ProviderBackend::OpenAiChat,
                    ProviderAuthSource::ApiKey
                )
                .is_none(),
                "{spelling}"
            );
        }
        let backends = [
            ProviderBackend::OpenAiChat,
            ProviderBackend::OpenAiResponses,
            ProviderBackend::AnthropicMessages,
        ];
        assert_eq!(BACKENDS.len(), backends.len());
        for backend in backends {
            let spelling = backend_str(backend);
            assert!(BACKENDS.contains(&spelling), "{spelling}");
            assert_eq!(
                REASONING_EFFORT_BACKENDS.contains(&spelling),
                reasoning_effort_refusal(CloudHttp, backend, ProviderAuthSource::ApiKey).is_none(),
                "{spelling}"
            );
            for class in [CloudHttp, Local] {
                assert_eq!(
                    SYSTEM_MESSAGES_BACKENDS.contains(&spelling),
                    system_messages_refusal(class, backend, ProviderAuthSource::ApiKey).is_none(),
                    "{spelling}"
                );
            }
            assert!(
                system_messages_refusal(CloudHttp, backend, ProviderAuthSource::ChatGptOAuth)
                    .is_some(),
                "{spelling}"
            );
        }
        for id in ["anthropic", "openai", "gw"] {
            assert_eq!(
                client_effective_backend(id, None),
                backend_str(effective_backend(id, None)),
                "{id}"
            );
        }
        // The dialect the client-side check reads for an entry that names none is the one the
        // loader gives it.
        let entry = |id: &str, extra: &str| -> LlmProviderConfig {
            serde_yml::from_str(&format!(
                "id: {id}\nendpoint: https://api.example.com\napi-key-secret: {id}-api-key\n\
                 model-aliases:\n  m: model\ncost-per-mtoken-in: 1.0\ncost-per-mtoken-out: 1.0\n\
                 rate-limit:\n  requests-per-minute: 10\n  tokens-per-minute: 1000\n{extra}"
            ))
            .expect("entry yaml")
        };
        for (class, extra) in [
            (CloudHttp, ""),
            (Local, "backend-class: local\n"),
            (MeshRemote, "backend-class: mesh-remote\ndevice-id: peer\n"),
            (
                AgentCli,
                "backend-class: agent-cli\nagent-cli:\n  vendor: claude\n  command: /nonexistent/claude\n",
            ),
        ] {
            for id in ["anthropic", "gw"] {
                let loaded = entry(id, extra);
                assert_eq!(loaded.backend_class, class);
                assert_eq!(
                    entry_backend(id, backend_class_str(class), None),
                    backend_str(effective_backend(&loaded.id, loaded.backend)),
                    "{id} on {}",
                    backend_class_str(class)
                );
            }
        }
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
    use advance_runtime::config::MAX_SIGN_IN_GENERATE_TIMEOUT_SECS;
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
        let status_before = f.port.calls_of("status").len();
        let before = now_ms();
        let summary = admin.get_provider("openai-plan").unwrap();
        let after = now_ms();
        assert_eq!(f.port.calls_of("status").len(), status_before + 1);
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
        assert_eq!(summary.available_models, sign_in.models);
        assert_eq!(
            summary.model_aliases.get("gpt").map(String::as_str),
            Some("gpt-5")
        );

        *f.port.status.lock().unwrap() = signed_out(None);
        let signed_out_summary = admin.get_provider("openai-plan").unwrap();
        let signed_out_state = signed_out_summary.sign_in.expect("projected");
        assert_eq!(signed_out_state.state, STATE_SIGNED_OUT);
        assert!(signed_out_state.models.is_empty());
        assert!(signed_out_summary.available_models.is_empty());

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
            generate_timeout_secs: None,
            reasoning_effort: None,
            system_messages: None,
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
        budgets: Mutex<Vec<Duration>>,
    }

    impl FakeClaimed {
        fn new(claimed: &[&str], outcome: Result<(), PreflightFail>) -> Arc<Self> {
            Arc::new(Self {
                claimed: claimed.iter().map(|s| (*s).to_string()).collect(),
                outcome: Mutex::new(outcome),
                stall: Mutex::new(Duration::ZERO),
                calls: Mutex::new(Vec::new()),
                budgets: Mutex::new(Vec::new()),
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
            budget: Duration,
        ) -> Result<(), PreflightFail> {
            self.calls.lock().unwrap().push(provider_id.to_string());
            self.budgets.lock().unwrap().push(budget);
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

    struct RecBinder {
        applied: Mutex<Vec<String>>,
        released: Mutex<Vec<String>>,
        fail: Mutex<bool>,
    }

    impl LocalSidecarBinder for RecBinder {
        fn apply_local_sidecar(
            &self,
            provider_id: &str,
            _command: &str,
            _args: &[String],
            _embedding_model: Option<&str>,
            _policy: ProcessPolicy,
        ) -> Result<(), ()> {
            self.applied.lock().unwrap().push(provider_id.to_string());
            if *self.fail.lock().unwrap() {
                Err(())
            } else {
                Ok(())
            }
        }

        fn release_local_sidecar(&self, provider_id: &str) {
            self.released.lock().unwrap().push(provider_id.to_string());
        }
    }

    fn sidecar_create(id: &str) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            sidecar: Some(ClientProviderSidecar {
                command: "/bin/true".into(),
                args: vec!["--model".into()],
            }),
            ..local_create(id)
        }
    }

    #[test]
    fn a_live_binder_starts_a_local_sidecar_without_waiting_for_the_next_start() {
        let f = Fixture::new();
        let binder = Arc::new(RecBinder {
            applied: Mutex::new(Vec::new()),
            released: Mutex::new(Vec::new()),
            fail: Mutex::new(false),
        });
        let admin = f
            .admin()
            .with_local_sidecar_binder(binder.clone() as Arc<dyn LocalSidecarBinder>)
            .with_claimable_local_entries(true);

        let created = admin.create_provider(&sidecar_create("local-a")).unwrap();
        assert_eq!(restart_count(&created), 0, "{:?}", created.warnings);
        assert!(created.value.last_preflight.is_none());

        let selected = admin.select_provider("local-a").unwrap();
        assert_eq!(restart_count(&selected), 0);
        assert_eq!(
            binder.applied.lock().unwrap().as_slice(),
            ["local-a".to_string(), "local-a".to_string()]
        );

        let updated = admin
            .update_provider(
                "local-a",
                &ClientUpdateProviderRequest {
                    sidecar: Some(ClientProviderSidecar {
                        command: "/bin/true".into(),
                        args: vec!["--other".into()],
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            restart_count(&updated),
            0,
            "a started sidecar is not a restart"
        );

        admin.delete_provider("local-a").unwrap();
        assert_eq!(
            binder.released.lock().unwrap().as_slice(),
            ["local-a".to_string()]
        );
    }

    #[test]
    fn a_live_binder_that_cannot_start_does_not_claim_the_next_start() {
        let f = Fixture::new();
        let binder = Arc::new(RecBinder {
            applied: Mutex::new(Vec::new()),
            released: Mutex::new(Vec::new()),
            fail: Mutex::new(true),
        });
        let admin = f
            .admin()
            .with_local_sidecar_binder(binder as Arc<dyn LocalSidecarBinder>);
        let created = admin.create_provider(&sidecar_create("local-a")).unwrap();
        assert_eq!(restart_count(&created), 0);
        assert_eq!(
            created.value.last_preflight.and_then(|p| p.reason),
            Some("sidecar-not-started".into())
        );
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

    // ── an entry's own generate budget and reasoning setting ─────────────────────────────────

    fn keyed_create(id: &str) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: id.into(),
            auth_source: None,
            endpoint: Some("https://api.example.com".into()),
            ..sign_in_request()
        }
    }

    fn document(f: &Fixture) -> String {
        std::fs::read_to_string(f.home.join(".advance/runtime-config.yaml")).unwrap()
    }

    fn update(
        admin: &WiredProviderAdmin,
        id: &str,
        request: ClientUpdateProviderRequest,
    ) -> Result<ClientProviderSummary, ProviderError> {
        admin
            .update_provider(id, &request)
            .map(|outcome| outcome.value)
    }

    /// Both settings are written under the runtime's spelling, read back by the strict loader,
    /// echoed by the summary, replaced by a value, kept by an update that does not name them,
    /// and removed by an explicit null.
    #[test]
    fn provider_settings_round_trip_through_create_update_and_the_summary() {
        let f = Fixture::new();
        let admin = f.admin();
        let created = admin
            .create_provider(&ClientCreateProviderRequest {
                generate_timeout_secs: Some(120),
                reasoning_effort: Some("low".into()),
                ..keyed_create("reasoner")
            })
            .expect("created")
            .value;
        assert_eq!(created.generate_timeout_secs, Some(120));
        assert_eq!(created.reasoning_effort.as_deref(), Some("low"));
        let text = document(&f);
        assert!(text.contains("generate-timeout-secs: 120"), "{text}");
        assert!(text.contains("reasoning-effort: low"), "{text}");
        let entry = f.entry("reasoner").expect("on disk");
        assert_eq!(entry.generate_timeout(), Some(Duration::from_secs(120)));
        assert_eq!(entry.reasoning_effort, Some(ReasoningEffort::Low));
        assert_eq!(admin.get_provider("reasoner").unwrap(), created);

        let replaced = update(
            &admin,
            "reasoner",
            ClientUpdateProviderRequest {
                generate_timeout_secs: Some(Some(600)),
                reasoning_effort: Some(Some("xhigh".into())),
                ..Default::default()
            },
        )
        .expect("replaced");
        assert_eq!(replaced.generate_timeout_secs, Some(600));
        assert_eq!(replaced.reasoning_effort.as_deref(), Some("xhigh"));

        let kept = update(
            &admin,
            "reasoner",
            ClientUpdateProviderRequest {
                endpoint: Some("https://proxy.example.com".into()),
                ..Default::default()
            },
        )
        .expect("kept");
        assert_eq!(kept.generate_timeout_secs, Some(600));
        assert_eq!(kept.reasoning_effort.as_deref(), Some("xhigh"));

        let cleared = update(
            &admin,
            "reasoner",
            ClientUpdateProviderRequest {
                generate_timeout_secs: Some(None),
                reasoning_effort: Some(None),
                ..Default::default()
            },
        )
        .expect("cleared");
        assert_eq!(cleared.generate_timeout_secs, None);
        assert_eq!(cleared.reasoning_effort, None);
        let entry = f.entry("reasoner").unwrap();
        assert_eq!(entry.generate_timeout_secs, None);
        assert_eq!(entry.reasoning_effort, None);
        let text = document(&f);
        assert!(!text.contains("generate-timeout-secs"), "{text}");
        assert!(!text.contains("reasoning-effort"), "{text}");
        let wire = serde_json::to_value(&cleared).unwrap();
        assert!(wire.get("generate_timeout_secs").is_none(), "{wire}");
        assert!(wire.get("reasoning_effort").is_none(), "{wire}");

        // A local entry takes both.
        let local = admin
            .create_provider(&ClientCreateProviderRequest {
                generate_timeout_secs: Some(900),
                reasoning_effort: Some("high".into()),
                ..local_create("local-reasoner")
            })
            .expect("local")
            .value;
        assert_eq!(local.generate_timeout_secs, Some(900));
        assert_eq!(local.reasoning_effort.as_deref(), Some("high"));
    }

    /// A setting the entry would not be able to take is refused before the document changes,
    /// with the setting's detail token — also when the update changes what decides it.
    #[test]
    fn a_setting_the_entry_cannot_take_is_refused_with_its_detail_before_any_write() {
        let f = Fixture::new();
        let admin = f.admin();
        admin
            .create_provider(&ClientCreateProviderRequest {
                reasoning_effort: Some("low".into()),
                ..keyed_create("reasoner")
            })
            .expect("created");
        let before = document(&f);
        let refused = |detail: &str| Err(ProviderError::InvalidRequest(detail.into()));

        for (request, expected, why) in [
            (
                ClientCreateProviderRequest {
                    generate_timeout_secs: Some(4),
                    ..keyed_create("c1")
                },
                refused(INVALID_GENERATE_TIMEOUT_DETAIL),
                "below the bound",
            ),
            (
                ClientCreateProviderRequest {
                    reasoning_effort: Some("turbo".into()),
                    ..keyed_create("c2")
                },
                refused(INVALID_REASONING_EFFORT_DETAIL),
                "unknown spelling",
            ),
            (
                ClientCreateProviderRequest {
                    backend: Some("anthropic-messages".into()),
                    reasoning_effort: Some("low".into()),
                    ..keyed_create("c3")
                },
                refused(REASONING_EFFORT_UNSUPPORTED_DETAIL),
                "messages dialect",
            ),
            (
                ClientCreateProviderRequest {
                    reasoning_effort: Some("low".into()),
                    ..keyed_create("anthropic")
                },
                refused(REASONING_EFFORT_UNSUPPORTED_DETAIL),
                "the anthropic id",
            ),
            (
                ClientCreateProviderRequest {
                    backend_class: Some("mesh-remote".into()),
                    device_id: Some("peer".into()),
                    generate_timeout_secs: Some(60),
                    ..keyed_create("c4")
                },
                refused(GENERATE_TIMEOUT_UNSUPPORTED_DETAIL),
                "mesh-remote budget",
            ),
        ] {
            assert_eq!(
                admin.create_provider(&request).map(|o| o.value.provider_id),
                expected.map(|()| String::new()),
                "{why}"
            );
            assert_eq!(document(&f), before, "{why}: the document is unchanged");
        }

        // The stored setting meets the update's new dialect.
        let to_messages = ClientUpdateProviderRequest {
            backend: Some("anthropic-messages".into()),
            ..Default::default()
        };
        assert_eq!(
            update(&admin, "reasoner", to_messages.clone()).map(|_| ()),
            refused(REASONING_EFFORT_UNSUPPORTED_DETAIL)
        );
        assert_eq!(
            update(
                &admin,
                "reasoner",
                ClientUpdateProviderRequest {
                    generate_timeout_secs: Some(Some(901)),
                    ..Default::default()
                }
            )
            .map(|_| ()),
            refused(INVALID_GENERATE_TIMEOUT_DETAIL)
        );
        assert_eq!(
            update(
                &admin,
                "openai",
                ClientUpdateProviderRequest {
                    backend_class: Some("mesh-remote".into()),
                    device_id: Some("peer".into()),
                    generate_timeout_secs: Some(Some(60)),
                    ..Default::default()
                }
            )
            .map(|_| ()),
            refused(GENERATE_TIMEOUT_UNSUPPORTED_DETAIL)
        );
        assert_eq!(document(&f), before, "refused updates leave the document");

        // Clearing the setting in the same update makes the change legal.
        let moved = update(
            &admin,
            "reasoner",
            ClientUpdateProviderRequest {
                reasoning_effort: Some(None),
                ..to_messages
            },
        )
        .expect("the setting goes with the dialect");
        assert_eq!(moved.backend.as_deref(), Some("anthropic-messages"));
        assert_eq!(moved.reasoning_effort, None);
    }

    /// The pre-write check reads the dialect the way the loader does: a `local` entry speaks
    /// `openai-chat` whatever its id, and an update that moves such an entry to `cloud-http`
    /// gives it the dialect its id implies there.
    #[test]
    fn the_pre_write_check_reads_the_dialect_the_way_the_loader_does() {
        let f = Fixture::new();
        let admin = f.admin();
        let created = admin
            .create_provider(&ClientCreateProviderRequest {
                reasoning_effort: Some("low".into()),
                ..local_create("anthropic")
            })
            .expect("a local entry takes a reasoning setting whatever its id")
            .value;
        assert_eq!(created.reasoning_effort.as_deref(), Some("low"));
        let before = document(&f);
        let to_cloud = ClientUpdateProviderRequest {
            backend_class: Some("cloud-http".into()),
            endpoint: Some("https://api.example.com".into()),
            ..Default::default()
        };
        assert_eq!(
            update(&admin, "anthropic", to_cloud.clone()).map(|_| ()),
            Err(ProviderError::InvalidRequest(
                REASONING_EFFORT_UNSUPPORTED_DETAIL.into()
            ))
        );
        assert_eq!(document(&f), before, "the document is unchanged");
        // Naming a dialect that carries the setting in the same update makes the move legal.
        let moved = update(
            &admin,
            "anthropic",
            ClientUpdateProviderRequest {
                backend: Some("openai-chat".into()),
                ..to_cloud
            },
        )
        .expect("moved");
        assert_eq!(moved.backend_class, "cloud-http");
        assert_eq!(moved.reasoning_effort.as_deref(), Some("low"));
    }

    /// The system-message mode is written under the runtime's spelling, read back by the strict
    /// loader, echoed by the summary, replaced, kept by an update that does not name it, and
    /// removed by an explicit null; a mode the entry could not apply is refused before any
    /// write, with its detail token — also when an update changes what decides it.
    #[test]
    fn the_system_message_mode_round_trips_and_is_refused_where_it_cannot_apply() {
        let f = Fixture::new();
        let admin = f.admin();
        let created = admin
            .create_provider(&ClientCreateProviderRequest {
                system_messages: Some("merge".into()),
                ..keyed_create("joiner")
            })
            .expect("created")
            .value;
        assert_eq!(created.system_messages.as_deref(), Some("merge"));
        assert!(document(&f).contains("system-messages: merge"));
        let entry = f.entry("joiner").expect("on disk");
        assert_eq!(entry.system_messages, Some(SystemMessages::Merge));
        assert!(entry.merges_system_messages());
        assert_eq!(admin.get_provider("joiner").unwrap(), created);

        let replaced = update(
            &admin,
            "joiner",
            ClientUpdateProviderRequest {
                system_messages: Some(Some("separate".into())),
                ..Default::default()
            },
        )
        .expect("replaced");
        assert_eq!(replaced.system_messages.as_deref(), Some("separate"));
        assert!(!f.entry("joiner").unwrap().merges_system_messages());
        let kept = update(
            &admin,
            "joiner",
            ClientUpdateProviderRequest {
                endpoint: Some("https://proxy.example.com".into()),
                ..Default::default()
            },
        )
        .expect("kept");
        assert_eq!(kept.system_messages.as_deref(), Some("separate"));
        let cleared = update(
            &admin,
            "joiner",
            ClientUpdateProviderRequest {
                system_messages: Some(None),
                ..Default::default()
            },
        )
        .expect("cleared");
        assert_eq!(cleared.system_messages, None);
        assert_eq!(f.entry("joiner").unwrap().system_messages, None);
        let text = document(&f);
        assert!(!text.contains("system-messages"), "{text}");
        let wire = serde_json::to_value(&cleared).unwrap();
        assert!(wire.get("system_messages").is_none(), "{wire}");

        // A local entry takes it whatever its id.
        let local = admin
            .create_provider(&ClientCreateProviderRequest {
                system_messages: Some("merge".into()),
                ..local_create("anthropic")
            })
            .expect("local")
            .value;
        assert_eq!(local.system_messages.as_deref(), Some("merge"));

        let merged = admin
            .create_provider(&ClientCreateProviderRequest {
                system_messages: Some("merge".into()),
                ..keyed_create("merged")
            })
            .expect("merged")
            .value;
        assert_eq!(merged.system_messages.as_deref(), Some("merge"));
        let refused = |detail: &str| Err(ProviderError::InvalidRequest(detail.into()));
        for (request, expected, why) in [
            (
                ClientCreateProviderRequest {
                    system_messages: Some("joined".into()),
                    ..keyed_create("c1")
                },
                refused(INVALID_SYSTEM_MESSAGES_DETAIL),
                "unknown spelling",
            ),
            (
                ClientCreateProviderRequest {
                    backend: Some("openai-responses".into()),
                    system_messages: Some("merge".into()),
                    ..keyed_create("c2")
                },
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "responses dialect",
            ),
            (
                ClientCreateProviderRequest {
                    system_messages: Some("merge".into()),
                    ..keyed_create("anthropic-cloud")
                },
                Ok(()),
                "another id speaks openai-chat",
            ),
            (
                ClientCreateProviderRequest {
                    backend: Some("anthropic-messages".into()),
                    system_messages: Some("merge".into()),
                    ..keyed_create("c3")
                },
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "messages dialect",
            ),
            (
                ClientCreateProviderRequest {
                    backend_class: Some("mesh-remote".into()),
                    device_id: Some("peer".into()),
                    system_messages: Some("merge".into()),
                    ..keyed_create("c4")
                },
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "mesh-remote entry",
            ),
            (
                ClientCreateProviderRequest {
                    system_messages: Some("merge".into()),
                    ..sign_in_request()
                },
                refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL),
                "sign-in entry",
            ),
        ] {
            let before = document(&f);
            let outcome = admin.create_provider(&request).map(|_| ());
            assert_eq!(outcome, expected, "{why}");
            if expected.is_err() {
                assert_eq!(document(&f), before, "{why}: the document is unchanged");
            }
        }
        let before = document(&f);

        // The stored mode meets the update's new dialect.
        let to_responses = ClientUpdateProviderRequest {
            backend: Some("openai-responses".into()),
            ..Default::default()
        };
        assert_eq!(
            update(&admin, "merged", to_responses.clone()).map(|_| ()),
            refused(SYSTEM_MESSAGES_UNSUPPORTED_DETAIL)
        );
        assert_eq!(
            update(
                &admin,
                "merged",
                ClientUpdateProviderRequest {
                    system_messages: Some(Some("all".into())),
                    ..Default::default()
                }
            )
            .map(|_| ()),
            refused(INVALID_SYSTEM_MESSAGES_DETAIL)
        );
        assert_eq!(document(&f), before, "refused updates leave the document");
        // Clearing the mode in the same update makes the move legal.
        let moved = update(
            &admin,
            "merged",
            ClientUpdateProviderRequest {
                system_messages: Some(None),
                ..to_responses
            },
        )
        .expect("the mode goes with the dialect");
        assert_eq!(moved.backend.as_deref(), Some("openai-responses"));
        assert_eq!(moved.system_messages, None);
    }

    /// A sign-in entry sends only what its route accepts: a reasoning setting is refused on
    /// create and on update, while its own generate budget (at most the streamed-exchange
    /// lifetime) is kept. Its `:preflight` (the sign-in's verify, not a generate hop) keeps the
    /// preflight deadline.
    #[test]
    fn a_sign_in_entry_refuses_a_reasoning_setting_and_keeps_its_generate_budget() {
        let f = Fixture::new();
        let admin = f.admin().with_preflight_timeout(Duration::from_millis(100));
        let refused = Err(ProviderError::InvalidRequest(
            REASONING_EFFORT_UNSUPPORTED_DETAIL.into(),
        ));
        assert_eq!(
            admin
                .create_provider(&ClientCreateProviderRequest {
                    reasoning_effort: Some("low".into()),
                    ..sign_in_request()
                })
                .map(|o| o.value),
            refused.clone()
        );
        assert!(f.entry("openai-plan").is_none());
        // Its requests are streamed exchanges, which end after the streamed-exchange lifetime.
        let too_long = Err(ProviderError::InvalidRequest(
            INVALID_GENERATE_TIMEOUT_DETAIL.into(),
        ));
        assert_eq!(
            admin
                .create_provider(&ClientCreateProviderRequest {
                    generate_timeout_secs: Some(MAX_SIGN_IN_GENERATE_TIMEOUT_SECS + 1),
                    ..sign_in_request()
                })
                .map(|o| o.value),
            too_long.clone()
        );
        assert!(f.entry("openai-plan").is_none());

        let created = admin
            .create_provider(&ClientCreateProviderRequest {
                generate_timeout_secs: Some(120),
                ..sign_in_request()
            })
            .expect("created")
            .value;
        assert_eq!(created.generate_timeout_secs, Some(120));
        assert_eq!(
            f.entry("openai-plan").unwrap().generate_timeout_secs,
            Some(120)
        );
        let budget = |secs| ClientUpdateProviderRequest {
            generate_timeout_secs: Some(Some(secs)),
            ..Default::default()
        };
        assert_eq!(
            update(
                &admin,
                "openai-plan",
                budget(MAX_SIGN_IN_GENERATE_TIMEOUT_SECS + 1)
            ),
            too_long
        );
        let at_ceiling = update(
            &admin,
            "openai-plan",
            budget(MAX_SIGN_IN_GENERATE_TIMEOUT_SECS),
        )
        .expect("the ceiling itself is accepted");
        assert_eq!(
            at_ceiling.generate_timeout_secs,
            Some(MAX_SIGN_IN_GENERATE_TIMEOUT_SECS)
        );
        assert_eq!(
            update(
                &admin,
                "openai-plan",
                ClientUpdateProviderRequest {
                    reasoning_effort: Some(Some("low".into())),
                    ..Default::default()
                }
            ),
            refused
        );

        *f.port.verify_delay.lock().unwrap() = Duration::from_secs(3);
        let started = std::time::Instant::now();
        let verdict = admin.preflight("openai-plan").unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(verdict.reason.as_deref(), Some(REASON_TIMEOUT));
    }

    /// A chat preflight that answers after `delay` (or `Cancelled` when its deadline fires
    /// first), recording the entry it was handed.
    struct SlowPreflight {
        delay: Duration,
        seen: Mutex<Vec<(Option<u32>, Option<ReasoningEffort>)>>,
    }

    impl PreflightPort for SlowPreflight {
        fn preflight(
            &self,
            _home: &Path,
            provider: &LlmProviderConfig,
            _key: &SecretBytes,
            cancel: &CancelToken,
        ) -> Result<(), PreflightFail> {
            self.seen
                .lock()
                .unwrap()
                .push((provider.generate_timeout_secs, provider.reasoning_effort));
            let started = std::time::Instant::now();
            while started.elapsed() < self.delay {
                if cancel.is_cancelled() {
                    return Err(PreflightFail::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        }
    }

    /// The chat preflight of an entry with its own generate budget (`:set-key` and
    /// `:preflight`) is bounded by that budget instead of the preflight deadline, and is handed
    /// the entry with its settings; without the key the deadline still applies.
    #[test]
    fn the_chat_preflight_of_an_entry_is_bounded_by_its_own_generate_budget() {
        let f = Fixture::new();
        let slow = Arc::new(SlowPreflight {
            delay: Duration::from_millis(300),
            seen: Mutex::new(Vec::new()),
        });
        let cfg =
            advance_runtime::config::load_config(&f.home.join(".advance/runtime-config.yaml"))
                .expect("fixture parses");
        let admin = WiredProviderAdmin::new(
            f.home.clone(),
            Arc::new(cap_llm::StaticConfig(Arc::new(cfg))),
            Some(Arc::clone(&f.store)),
            slow.clone(),
            Arc::new(NoReferences),
        )
        .with_reload_wait(Duration::from_millis(1))
        .with_preflight_timeout(Duration::from_millis(100));
        admin
            .create_provider(&ClientCreateProviderRequest {
                generate_timeout_secs: Some(5),
                reasoning_effort: Some("minimal".into()),
                ..keyed_create("slow")
            })
            .unwrap();
        admin.create_provider(&keyed_create("plain")).unwrap();

        let stored = admin.set_key("slow", "sk-test-slow").unwrap().value;
        assert!(stored.stored, "{stored:?}");
        assert!(stored.preflight.as_ref().unwrap().ok, "{stored:?}");
        assert!(admin.preflight("slow").unwrap().ok);

        let refused = admin.set_key("plain", "sk-test-plain").unwrap().value;
        assert!(!refused.stored);
        assert_eq!(
            refused.preflight.unwrap().reason.as_deref(),
            Some(REASON_TIMEOUT)
        );
        assert_eq!(
            *slow.seen.lock().unwrap(),
            vec![
                (Some(5), Some(ReasoningEffort::Minimal)),
                (Some(5), Some(ReasoningEffort::Minimal)),
                (None, None),
            ]
        );
    }

    /// A claimed entry's preflight is handed (and bounded by) the entry's own generate budget.
    #[test]
    fn the_claimed_preflight_budget_is_the_entry_generate_budget() {
        let f = Fixture::new();
        let port = FakeClaimed::new(&["local-a", "local-b"], Ok(()));
        *port.stall.lock().unwrap() = Duration::from_millis(300);
        let admin = f
            .admin()
            .with_claimed_preflight(port.clone() as Arc<dyn ClaimedEntryPreflight>)
            .with_preflight_timeout(Duration::from_millis(100));
        admin
            .create_provider(&ClientCreateProviderRequest {
                generate_timeout_secs: Some(5),
                ..local_create("local-a")
            })
            .unwrap();
        admin.create_provider(&local_create("local-b")).unwrap();
        assert!(admin.preflight("local-a").unwrap().ok);
        assert_eq!(
            admin.preflight("local-b").unwrap().reason.as_deref(),
            Some(REASON_TIMEOUT)
        );
        assert_eq!(
            *port.budgets.lock().unwrap(),
            vec![Duration::from_secs(5), Duration::from_millis(100)]
        );
    }

    /// A chat preflight that holds until the test opens its gate (or its deadline cancels it),
    /// telling the test each time one starts. It gives up by itself after a while, so a check
    /// that blocks the test fails it instead of hanging it.
    struct GatedPreflight {
        started: Mutex<std::sync::mpsc::Sender<()>>,
        open: Mutex<bool>,
        opened: Condvar,
    }

    impl GatedPreflight {
        fn open_gate(&self) {
            *self.open.lock().unwrap() = true;
            self.opened.notify_all();
        }

        fn close_gate(&self) {
            *self.open.lock().unwrap() = false;
        }
    }

    impl PreflightPort for GatedPreflight {
        fn preflight(
            &self,
            _home: &Path,
            _provider: &LlmProviderConfig,
            _key: &SecretBytes,
            cancel: &CancelToken,
        ) -> Result<(), PreflightFail> {
            let _ = self.started.lock().unwrap().send(());
            let give_up = std::time::Instant::now() + Duration::from_secs(10);
            let mut open = self.open.lock().unwrap();
            while !*open {
                if cancel.is_cancelled() {
                    return Err(PreflightFail::Cancelled);
                }
                if std::time::Instant::now() >= give_up {
                    return Err(PreflightFail::ProviderRejected {
                        reason: "gate-never-opened".into(),
                    });
                }
                open = self
                    .opened
                    .wait_timeout(open, Duration::from_millis(20))
                    .unwrap()
                    .0;
            }
            Ok(())
        }
    }

    /// A key's check, which may run as long as the entry's own generate budget, does not hold
    /// other mutations up; a key checked against settings that changed (or an entry that went)
    /// meanwhile is not stored.
    #[test]
    fn a_key_check_does_not_hold_up_other_mutations() {
        let f = Fixture::new();
        let (started_tx, started) = std::sync::mpsc::channel();
        let gate = Arc::new(GatedPreflight {
            started: Mutex::new(started_tx),
            open: Mutex::new(false),
            opened: Condvar::new(),
        });
        let cfg =
            advance_runtime::config::load_config(&f.home.join(".advance/runtime-config.yaml"))
                .expect("fixture parses");
        let admin = WiredProviderAdmin::new(
            f.home.clone(),
            Arc::new(cap_llm::StaticConfig(Arc::new(cfg))),
            Some(Arc::clone(&f.store)),
            gate.clone(),
            Arc::new(NoReferences),
        )
        .with_reload_wait(Duration::from_millis(1));
        admin
            .create_provider(&ClientCreateProviderRequest {
                generate_timeout_secs: Some(600),
                ..keyed_create("slow")
            })
            .unwrap();
        let secret = f.entry("slow").unwrap().api_key_secret;
        let wait_started = || {
            started
                .recv_timeout(Duration::from_secs(10))
                .expect("the key check started")
        };

        // An update while the key is being checked goes through at once and voids the check.
        let answer = std::thread::scope(|s| {
            let pending = s.spawn(|| admin.set_key("slow", "sk-test-slow"));
            wait_started();
            let moved = update(
                &admin,
                "slow",
                ClientUpdateProviderRequest {
                    endpoint: Some("https://moved.example.com".into()),
                    ..Default::default()
                },
            )
            .expect("the update does not wait for the check");
            assert_eq!(moved.endpoint, "https://moved.example.com");
            assert!(
                !pending.is_finished(),
                "the update finished while the key was still being checked"
            );
            gate.open_gate();
            pending.join().unwrap()
        })
        .expect("answered")
        .value;
        assert!(!answer.stored, "{answer:?}");
        assert_eq!(
            answer.preflight.unwrap().reason.as_deref(),
            Some(REASON_CANCELLED)
        );
        assert!(f.store.resolve(&secret).is_err(), "nothing was stored");

        // A check nothing overlaps stores the key.
        let stored = admin.set_key("slow", "sk-test-slow").unwrap().value;
        wait_started();
        assert!(stored.stored, "{stored:?}");
        assert!(stored.preflight.unwrap().ok);
        assert_eq!(
            f.store.resolve(&secret).unwrap().expose_secret(),
            "sk-test-slow"
        );

        // An entry deleted while its key is being checked answers as gone; the key it held
        // before stays as the delete left it.
        gate.close_gate();
        let answer = std::thread::scope(|s| {
            let pending = s.spawn(|| admin.set_key("slow", "sk-test-other"));
            wait_started();
            admin
                .delete_provider("slow")
                .expect("the delete does not wait");
            gate.open_gate();
            pending.join().unwrap()
        });
        assert_eq!(
            answer.map(|o| o.value),
            Err(ProviderError::NotFound("slow".into()))
        );
        assert!(f.entry("slow").is_none());
        assert_ne!(
            f.store
                .resolve(&secret)
                .ok()
                .map(|key| key.expose_secret().to_string())
                .as_deref(),
            Some("sk-test-other"),
            "the key checked for the deleted entry was not stored"
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

    #[test]
    fn am_t19_forbid_get_is_200_without_spawn_or_counter() {
        let f = Fixture::new();
        let admin = f
            .admin()
            .with_process_policy(ProcessPolicy::Forbid)
            .with_agent_cli_probe(Arc::new(PanicAuth))
            .with_reload_wait(Duration::from_millis(1));
        let w0 = spawn_counter::snapshot();
        let listed = admin.list_providers().expect("list under Forbid");
        let cli = listed
            .iter()
            .find(|s| s.provider_id == "claude-sub")
            .expect("agent-cli row");
        assert!(cli.available_models.is_empty());
        let got = admin.get_provider("claude-sub").expect("get under Forbid");
        assert!(got.available_models.is_empty());
        let delta = spawn_counter::snapshot().since(&w0);
        assert_eq!(delta.refused(SpawnSite::AgentCli), 0);
    }
}

#[cfg(test)]
mod available_models_tests {
    use super::*;
    use advance_shared_types::security_validator::{
        HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
    };
    use async_trait::async_trait;
    use cap_llm::backend_cli::AgentCliModelsProbe;
    use cap_llm::{CatalogFill as CliCatalogFill, ListedModel};
    use cap_secrets::InMemorySecretStorage;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;
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
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 100
      tokens-per-minute: 1000
  - id: mesh-a
    endpoint: ''
    api-key-secret: mesh-a-api-key
    model-aliases:
      m: m
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    backend-class: mesh-remote
    device-id: device-a
    rate-limit:
      requests-per-minute: 10
      tokens-per-minute: 1000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADV_HOME_AM_MK

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
";

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

    struct CountingCli {
        calls: AtomicUsize,
        fill: Mutex<CliCatalogFill>,
        hold: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl CountingCli {
        fn with(models: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                fill: Mutex::new(CliCatalogFill::complete(
                    models
                        .iter()
                        .map(|id| ListedModel {
                            id: (*id).into(),
                            display_name: None,
                        })
                        .collect(),
                )),
                hold: Mutex::new(None),
            })
        }
    }

    impl AgentCliModelsProbe for CountingCli {
        fn list_models(&self, _spec: &AgentCliSpec) -> CliCatalogFill {
            if let Some(rx) = self.hold.lock().unwrap().as_ref() {
                let _ = rx.recv_timeout(Duration::from_secs(2));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.fill.lock().unwrap().clone()
        }
    }

    struct CountingHttp {
        calls: AtomicUsize,
        fill: Mutex<CatalogFill>,
    }

    impl CountingHttp {
        fn with(models: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                fill: Mutex::new(CatalogFill::complete(
                    models
                        .iter()
                        .map(|id| ClientProviderSignInModel {
                            id: (*id).into(),
                            display_name: None,
                        })
                        .collect(),
                )),
            })
        }
    }

    impl CloudHttpModelsProbe for CountingHttp {
        fn list_models(&self, _entry: &LlmProviderConfig) -> CatalogFill {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.fill.lock().unwrap().clone()
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
                Zeroizing::new([3u8; 32]),
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
            .with_reload_wait(Duration::from_millis(1))
        }
    }

    fn local_req(id: &str, aliases: &[(&str, &str)]) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: id.into(),
            backend_class: Some("local".into()),
            model_aliases: aliases
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            cost: ClientProviderCost {
                input_per_mtoken: 0.001,
                output_per_mtoken: 0.001,
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 10,
                tokens_per_minute: 1000,
            },
            ..Default::default()
        }
    }

    fn grok_req(id: &str) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: id.into(),
            backend_class: Some(AGENT_CLI_BACKEND_CLASS.into()),
            agent_cli: Some(ClientProviderAgentCli {
                vendor: "grok".into(),
                command: "/nonexistent/grok".into(),
                args: Vec::new(),
            }),
            model_aliases: [("fast".into(), "grok-4".into())].into_iter().collect(),
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

    fn cloud_req(id: &str) -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: id.into(),
            backend_class: Some("cloud-http".into()),
            endpoint: Some("https://api.example.com".into()),
            model_aliases: [("m".into(), "m".into())].into_iter().collect(),
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

    #[test]
    fn am_t13_local_unique_alias_values_keep_spaces() {
        let f = Fixture::new();
        let admin = f.admin();
        admin
            .create_provider(&local_req(
                "tiny",
                &[("tiny", "qwen2.5-0.5b"), ("alias", "qwen2.5-0.5b")],
            ))
            .unwrap();
        admin
            .create_provider(&local_req("spaced", &[("a", "my model")]))
            .unwrap();
        let tiny = admin.get_provider("tiny").unwrap();
        assert_eq!(
            tiny.available_models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["qwen2.5-0.5b"]
        );
        let spaced = admin.get_provider("spaced").unwrap();
        assert_eq!(spaced.available_models[0].id, "my model");
    }

    #[test]
    fn am_t16_mesh_remote_empty() {
        let f = Fixture::new();
        let admin = f.admin();
        assert!(admin
            .get_provider("mesh-a")
            .unwrap()
            .available_models
            .is_empty());
    }

    #[test]
    fn am_t15_cache_singleflight_and_invalidate() {
        let f = Fixture::new();
        let probe = CountingCli::with(&["grok-4.6"]);
        let admin = f
            .admin()
            .with_agent_cli_models_probe(Arc::clone(&probe) as Arc<dyn AgentCliModelsProbe>);
        let created = admin.create_provider(&grok_req("grok-a")).unwrap();
        assert!(created.value.available_models.is_empty());
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        let gen_after_create = admin.models_generation_of("grok-a");
        assert!(gen_after_create >= 1);

        let (tx_cold, rx_cold) = std::sync::mpsc::channel();
        *probe.hold.lock().unwrap() = Some(rx_cold);
        let admin = Arc::new(admin);
        let cold_a = Arc::clone(&admin);
        let cold_b = Arc::clone(&admin);
        let cold_one = thread::spawn(move || cold_a.get_provider("grok-a"));
        let cold_two = thread::spawn(move || cold_b.get_provider("grok-a"));
        thread::sleep(Duration::from_millis(30));
        drop(tx_cold);
        let first = cold_one.join().expect("thread").unwrap();
        let second = cold_two.join().expect("thread").unwrap();
        assert_eq!(first.available_models[0].id, "grok-4.6");
        assert_eq!(second.available_models[0].id, "grok-4.6");
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        let _ = admin.get_provider("grok-a").unwrap();
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);

        admin.preflight("grok-a").unwrap();
        assert!(admin.models_generation_of("grok-a") > gen_after_create);

        let (tx, rx) = std::sync::mpsc::channel();
        *probe.hold.lock().unwrap() = Some(rx);
        let waiter_admin = Arc::clone(&admin);
        let join = thread::spawn(move || waiter_admin.get_provider("grok-a"));
        thread::sleep(Duration::from_millis(30));
        let cleared = admin.clear_key("grok-a").expect("clear-key of placeholder");
        assert!(cleared.available_models.is_empty());
        drop(tx);
        let woken = join.join().expect("thread");
        assert!(woken.unwrap().available_models.is_empty());
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn am_t15_probe_panic_does_not_stick_inflight() {
        struct PanicThenOk {
            calls: AtomicUsize,
        }
        impl CloudHttpModelsProbe for PanicThenOk {
            fn list_models(&self, _entry: &LlmProviderConfig) -> CatalogFill {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("probe boom");
                }
                CatalogFill::complete(vec![ClientProviderSignInModel {
                    id: "gpt-4o".into(),
                    display_name: None,
                }])
            }
        }
        let f = Fixture::new();
        f.store.store("openai-api-key", "sk-abcdefgh").unwrap();
        let probe = Arc::new(PanicThenOk {
            calls: AtomicUsize::new(0),
        });
        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::clone(&probe) as Arc<dyn CloudHttpModelsProbe>);
        let first = admin.get_provider("openai").unwrap();
        assert!(first.available_models.is_empty());
        let second = admin.get_provider("openai").unwrap();
        assert_eq!(second.available_models[0].id, "gpt-4o");
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn am_t12_missing_key_skips_http_probe() {
        let f = Fixture::new();
        let probe = CountingHttp::with(&["gpt-4o"]);
        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::clone(&probe) as Arc<dyn CloudHttpModelsProbe>);
        admin.create_provider(&cloud_req("cloud-a")).unwrap();
        let missing = admin.get_provider("cloud-a").unwrap();
        assert!(missing.available_models.is_empty());
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);

        admin.set_key("cloud-a", "sk-test-key-abcdef").unwrap();
        let got = admin.get_provider("cloud-a").unwrap();
        assert_eq!(got.available_models[0].id, "gpt-4o");
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        let env = serde_json::to_string(&got).unwrap();
        assert!(!env.contains("sk-test-key-abcdef"));
    }

    #[test]
    fn am_t20_missing_key_is_instant() {
        let f = Fixture::new();
        let probe = CountingHttp::with(&["gpt-4o"]);
        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::clone(&probe) as Arc<dyn CloudHttpModelsProbe>)
            .with_preflight_timeout(Duration::from_secs(30));
        admin.create_provider(&cloud_req("cloud-b")).unwrap();
        let started = Instant::now();
        let got = admin.get_provider("cloud-b").unwrap();
        assert!(started.elapsed() < Duration::from_millis(200));
        assert!(got.available_models.is_empty());
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    struct ScriptedChain {
        pages: Mutex<Vec<Result<HttpResponse, HttpError>>>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl HttpSecurityChain for ScriptedChain {
        async fn execute(
            &self,
            _agent_id: &str,
            _req: HttpRequest,
            _cap: &HttpCapability,
        ) -> Result<HttpResponse, HttpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut pages = self.pages.lock().unwrap();
            if pages.is_empty() {
                return Err(HttpError::Transport(
                    advance_shared_types::security_validator::TransportErrorKind::Other,
                ));
            }
            pages.remove(0)
        }
    }

    fn models_json(ids: &[&str], has_more: bool) -> Vec<u8> {
        let data: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| serde_json::json!({ "id": id }))
            .collect();
        serde_json::to_vec(&serde_json::json!({ "data": data, "has_more": has_more })).unwrap()
    }

    fn page_ok(ids: &[&str], has_more: bool) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: models_json(ids, has_more),
        })
    }

    fn page_status(status: u16) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        })
    }

    fn incomplete_page_pair(ids: &[&str]) -> Vec<Result<HttpResponse, HttpError>> {
        vec![
            page_ok(ids, true),
            Err(HttpError::RateLimited { retry_after_ms: 0 }),
        ]
    }

    fn openai_entry(home: &Path) -> LlmProviderConfig {
        fixture_entry(home, "openai")
    }

    fn anthropic_entry(home: &Path) -> LlmProviderConfig {
        fixture_entry(home, "anthropic")
    }

    fn fixture_entry(home: &Path, id: &str) -> LlmProviderConfig {
        let cfg = advance_runtime::config::load_config(&home.join(".advance/runtime-config.yaml"))
            .unwrap();
        cfg.llm_providers
            .into_iter()
            .find(|p| p.id == id)
            .unwrap_or_else(|| panic!("{id} fixture"))
    }

    #[test]
    fn am_t22_incomplete_partial_is_returned_not_cached() {
        let ids: Vec<String> = (0..40).map(|i| format!("m{i}")).collect();
        let first: Vec<&str> = ids.iter().map(String::as_str).collect();
        let chain = Arc::new(ScriptedChain {
            pages: Mutex::new(incomplete_page_pair(&first)),
            calls: AtomicUsize::new(0),
        });
        let f = Fixture::new();
        let probe = ProcessCloudHttpModelsProbe::new(
            chain.clone(),
            Arc::clone(&f.store),
            Duration::from_millis(200),
        );
        f.store.store("anthropic-api-key", "sk-abcdefgh").unwrap();
        let entry = anthropic_entry(&f.home);
        let sample = models_json(&first, true);
        match parse_models_catalog_page(&sample) {
            CatalogPage::Parsed {
                models, has_more, ..
            } => {
                assert_eq!(models.len(), 40, "parser dropped ids");
                assert!(has_more);
            }
            other => panic!("expected parsed page, got {other:?}"),
        }
        let fill = probe.list_models(&entry);
        assert!(
            !fill.complete,
            "expected incomplete, got {fill:?} after {} calls",
            chain.calls.load(Ordering::SeqCst)
        );
        assert_eq!(
            fill.models.len(),
            40,
            "fill={fill:?} calls={}",
            chain.calls.load(Ordering::SeqCst)
        );
        assert_eq!(chain.calls.load(Ordering::SeqCst), 2);

        {
            let mut pages = chain.pages.lock().unwrap();
            *pages = {
                let mut seeded = incomplete_page_pair(&first);
                seeded.extend(incomplete_page_pair(&first));
                seeded
            };
        }

        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::new(probe) as Arc<dyn CloudHttpModelsProbe>);
        let got = admin.get_provider("anthropic").unwrap();
        assert_eq!(got.available_models.len(), 40);
        let again = admin.get_provider("anthropic").unwrap();
        assert_eq!(again.available_models.len(), 40);
        assert_eq!(chain.calls.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn am_t22_first_page_401_is_complete_empty() {
        let chain = Arc::new(ScriptedChain {
            pages: Mutex::new(vec![page_status(401)]),
            calls: AtomicUsize::new(0),
        });
        let f = Fixture::new();
        f.store.store("openai-api-key", "sk-abcdefgh").unwrap();
        let probe = ProcessCloudHttpModelsProbe::new(
            chain.clone(),
            Arc::clone(&f.store),
            Duration::from_millis(200),
        );
        let fill = probe.list_models(&openai_entry(&f.home));
        assert!(fill.complete);
        assert!(fill.models.is_empty());

        {
            let mut pages = chain.pages.lock().unwrap();
            *pages = vec![page_status(401)];
        }
        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::new(probe) as Arc<dyn CloudHttpModelsProbe>);
        let got = admin.get_provider("openai").unwrap();
        assert!(got.available_models.is_empty());
        let again = admin.get_provider("openai").unwrap();
        assert!(again.available_models.is_empty());
        assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn am_t22_first_page_503_is_incomplete_not_cached() {
        let chain = Arc::new(ScriptedChain {
            pages: Mutex::new(vec![page_status(503), page_status(503)]),
            calls: AtomicUsize::new(0),
        });
        let f = Fixture::new();
        f.store.store("openai-api-key", "sk-abcdefgh").unwrap();
        let probe = ProcessCloudHttpModelsProbe::new(
            chain.clone(),
            Arc::clone(&f.store),
            Duration::from_millis(200),
        );
        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::new(probe) as Arc<dyn CloudHttpModelsProbe>);
        let first = admin.get_provider("openai").unwrap();
        assert!(first.available_models.is_empty());
        assert_eq!(chain.calls.load(Ordering::SeqCst), 1);
        let second = admin.get_provider("openai").unwrap();
        assert!(second.available_models.is_empty());
        assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn am_t22_later_page_401_keeps_partial_uncached() {
        let ids: Vec<String> = (0..40).map(|i| format!("m{i}")).collect();
        let first: Vec<&str> = ids.iter().map(String::as_str).collect();
        let chain = Arc::new(ScriptedChain {
            pages: Mutex::new(vec![
                page_ok(&first, true),
                page_status(401),
                page_ok(&first, true),
                page_status(401),
            ]),
            calls: AtomicUsize::new(0),
        });
        let f = Fixture::new();
        f.store.store("anthropic-api-key", "sk-abcdefgh").unwrap();
        let probe = ProcessCloudHttpModelsProbe::new(
            chain.clone(),
            Arc::clone(&f.store),
            Duration::from_millis(200),
        );
        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::new(probe) as Arc<dyn CloudHttpModelsProbe>);
        let got = admin.get_provider("anthropic").unwrap();
        assert_eq!(got.available_models.len(), 40);
        assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
        let again = admin.get_provider("anthropic").unwrap();
        assert_eq!(again.available_models.len(), 40);
        assert_eq!(chain.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn am_t22_openai_has_more_stops_after_first_page() {
        let ids: Vec<String> = (0..40).map(|i| format!("m{i}")).collect();
        let first: Vec<&str> = ids.iter().map(String::as_str).collect();
        let chain = Arc::new(ScriptedChain {
            pages: Mutex::new(vec![
                page_ok(&first, true),
                page_ok(&["should-not-run"], false),
            ]),
            calls: AtomicUsize::new(0),
        });
        let f = Fixture::new();
        f.store.store("openai-api-key", "sk-abcdefgh").unwrap();
        let probe = ProcessCloudHttpModelsProbe::new(
            chain.clone(),
            Arc::clone(&f.store),
            Duration::from_millis(200),
        );
        let fill = probe.list_models(&openai_entry(&f.home));
        assert!(fill.complete, "{fill:?}");
        assert_eq!(fill.models.len(), 40);
        assert_eq!(chain.calls.load(Ordering::SeqCst), 1);

        {
            let mut pages = chain.pages.lock().unwrap();
            *pages = vec![page_ok(&first, true), page_ok(&["should-not-run"], false)];
        }

        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::new(probe) as Arc<dyn CloudHttpModelsProbe>);
        let got = admin.get_provider("openai").unwrap();
        assert_eq!(got.available_models.len(), 40);
        let again = admin.get_provider("openai").unwrap();
        assert_eq!(again.available_models.len(), 40);
        assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn am_t08_claude_aliases_do_not_fill_catalog() {
        let f = Fixture::new();
        let admin = f.admin();
        let mut req = grok_req("claude-a");
        req.agent_cli = Some(ClientProviderAgentCli {
            vendor: "claude".into(),
            command: "/nonexistent/claude".into(),
            args: Vec::new(),
        });
        req.model_aliases = [("sonnet".into(), "sonnet".into())].into_iter().collect();
        admin.create_provider(&req).unwrap();
        let listed = admin.get_provider("claude-a").unwrap();
        assert_eq!(
            listed.model_aliases.get("sonnet").map(String::as_str),
            Some("sonnet")
        );
        assert!(listed.available_models.is_empty());
    }

    #[test]
    fn am_t18_key_substring_dropped_from_catalog() {
        let key = "sk-abcdefgh";
        let chain = Arc::new(ScriptedChain {
            pages: Mutex::new(vec![page_ok(&[key, "gpt-4o"], false)]),
            calls: AtomicUsize::new(0),
        });
        let f = Fixture::new();
        f.store.store("openai-api-key", key).unwrap();
        let probe = ProcessCloudHttpModelsProbe::new(
            chain.clone(),
            Arc::clone(&f.store),
            Duration::from_millis(200),
        );
        let admin = f
            .admin()
            .with_cloud_http_models_probe(Arc::new(probe) as Arc<dyn CloudHttpModelsProbe>);
        let got = admin.get_provider("openai").unwrap();
        assert_eq!(
            got.available_models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["gpt-4o"]
        );
        let env = serde_json::to_string(&got).unwrap();
        assert!(!env.contains(key));
        assert_eq!(chain.calls.load(Ordering::SeqCst), 1);
    }

    struct RotateKeyChain {
        store: Arc<SecretStore>,
        secret_name: String,
        next_key: String,
        pages: Mutex<Vec<Result<HttpResponse, HttpError>>>,
    }

    #[async_trait]
    impl HttpSecurityChain for RotateKeyChain {
        async fn execute(
            &self,
            _agent_id: &str,
            _req: HttpRequest,
            _cap: &HttpCapability,
        ) -> Result<HttpResponse, HttpError> {
            self.store
                .store(&self.secret_name, &self.next_key)
                .expect("rotate");
            let mut pages = self.pages.lock().unwrap();
            pages.remove(0)
        }
    }

    #[test]
    fn late_resolved_key_is_dropped_from_catalog() {
        let first = "sk-firstkey1";
        let second = "sk-secondkey2";
        let f = Fixture::new();
        f.store.store("openai-api-key", first).unwrap();
        let chain = Arc::new(RotateKeyChain {
            store: Arc::clone(&f.store),
            secret_name: "openai-api-key".into(),
            next_key: second.into(),
            pages: Mutex::new(vec![page_ok(&[second, "gpt-4o"], false)]),
        });
        let probe = ProcessCloudHttpModelsProbe::new(
            chain,
            Arc::clone(&f.store),
            Duration::from_millis(200),
        );
        let fill = probe.list_models(&openai_entry(&f.home));
        assert_eq!(
            fill.models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["gpt-4o"]
        );
        let joined = fill
            .models
            .iter()
            .map(|m| format!("{}{}", m.id, m.display_name.as_deref().unwrap_or("")))
            .collect::<String>();
        assert!(!joined.contains(first));
        assert!(!joined.contains(second));
    }
}
