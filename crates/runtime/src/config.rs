//! RuntimeConfig loader + hot-reload (CONTRACT-003).
//!
//! Parses `/.advance/runtime-config.yaml` with strict mode (`deny_unknown_fields`),
//! watches for file changes via `notify`, and publishes updates to subscribers via
//! `tokio::sync::mpsc`.

use std::collections::{hash_map::DefaultHasher, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

// `notify::Event` owns the bare `Event` name in this file; the shared-types
// event is aliased to `BusEvent` (hotreload pre-build, 2026-06-10).
use advance_shared_types::event::Event as BusEvent;
use advance_shared_types::traits::EventBusEmit;
use notify::event::{DataChange, ModifyKind};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

/// Per-subscriber channel capacity. Bounded to prevent unbounded memory growth when
/// a subscriber stalls or leaks. Drop-oldest semantics via try_send — a stalled
/// subscriber will miss updates but not starve the runtime.
pub const SUBSCRIBER_CHANNEL_CAPACITY: usize = 64;

/// Maximum number of concurrent subscribers. Prevents a hostile in-process
/// consumer from creating unbounded subscriptions that permanently inflate
/// reload fan-out cost (R15 Warning).
pub const MAX_SUBSCRIBERS: usize = 256;

/// Internal notify-event bridge channel capacity. Bounded so that a rapid-rewrite
/// attack on the watched file cannot accumulate unbounded events before the async
/// bridge task drains them. Excess events are coalesced naturally (each reload
/// re-reads the full file) so dropping is safe.
pub const EVENT_BRIDGE_CHANNEL_CAPACITY: usize = 128;

/// Maximum size of `/.advance/runtime-config.yaml` in bytes (64 KiB). Larger files are
/// rejected to prevent OOM attacks and mitigate YAML-bomb (billion-laughs) exploits.
/// Real configs are < 10 KB; 64 KiB is ~6× headroom while bounding the input surface
/// for YAML anchor/alias expansion attacks. Enforced via streaming read (not
/// `metadata().len()`) so special files (FIFOs, devices) and TOCTOU attacks cannot
/// bypass the cap.
pub const MAX_CONFIG_SIZE: u64 = 64 << 10;

// ---------------------------------------------------------------------------
// ConfigError
// ---------------------------------------------------------------------------

/// Errors from config loading and watching.
#[derive(Debug)]
pub enum ConfigError {
    ParseFailure {
        path: PathBuf,
        source: serde_yml::Error,
    },
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    WatchError {
        source: notify::Error,
    },
    /// Config file exceeds `MAX_CONFIG_SIZE`. Prevents OOM / YAML-bomb attacks.
    FileTooLarge {
        path: PathBuf,
        size: u64,
        max: u64,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // ParseFailure intentionally does NOT include the underlying serde error
        // in Display: serde_yml::Error echoes source tokens around the failure
        // point, which could leak secrets if an operator temporarily pasted an
        // API key into the YAML (R13 finding). Use `source()` to traverse the
        // error chain when full detail is needed at a trusted boundary.
        match self {
            ConfigError::ParseFailure { path, .. } => {
                write!(
                    f,
                    "config parse failure at {} (see error source() for detail)",
                    path.display()
                )
            }
            ConfigError::IoError { path, source } => {
                write!(f, "config I/O error at {}: {}", path.display(), source)
            }
            ConfigError::WatchError { source } => {
                write!(f, "config watch error: {source}")
            }
            ConfigError::FileTooLarge { path, size, max } => write!(
                f,
                "config file {} exceeds max size: {size} bytes > {max} bytes",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::ParseFailure { source, .. } => Some(source),
            ConfigError::IoError { source, .. } => Some(source),
            ConfigError::WatchError { source } => Some(source),
            ConfigError::FileTooLarge { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// RuntimeConfig + sub-structs
// ---------------------------------------------------------------------------

/// Top-level runtime configuration parsed from `/.advance/runtime-config.yaml`.
///
/// `deny_unknown_fields` enforces §1.7 strict mode: any YAML key not mapped to a
/// Rust field causes a parse error. Future modules add their config sections by
/// adding fields to this struct in their respective slices.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub wasm: WasmConfig,
    #[serde(rename = "llm-providers", default)]
    pub llm_providers: Vec<LlmProviderConfig>,
    pub cron: CronConfig,
    pub git: GitConfig,
    #[serde(rename = "circuit-breakers", default)]
    pub circuit_breakers: Vec<CircuitBreakerSpec>,
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub users: Vec<UserMapping>,
    #[serde(rename = "post-processor")]
    pub post_processor: PostProcessorConfig,
    #[serde(rename = "auto-loop-defaults", default)]
    pub auto_loop_defaults: AutoLoopDefaults,
    /// Slice AE (2026-05-09) — per-workspace SQLite index handle config.
    /// `#[serde(default)]` for back-compat: existing runtime-config.yaml files
    /// (post `advance init` from prior slices) lack this block; omitting it
    /// produces `DatabaseConfig::default()` (`db-path: ".runtime/index.db"`,
    /// `pool-size: 4`). serde semantics for this attribute combo:
    /// `deny_unknown_fields` rejects unrecognized keys but does not require
    /// recognized keys to be present, so the field is optional in YAML.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Slice m017-B (2026-05-14) — MODULE-017 tool registry tunables
    /// (per §2.10). `#[serde(default)]` per the `database` precedent:
    /// existing YAML configs without `tools:` continue to parse, falling
    /// back to `ToolsConfig::default()` (`max-tool-instances: 20`,
    /// `lazy-load-timeout-sec: 30`, `max-result-bytes: 16777216`).
    #[serde(default)]
    pub tools: ToolsConfig,
    /// /dev Phase-2 Step-3 (2026-06-05) — MODULE-016 channel-system config
    /// (the shared `/hooks/{path}` webhook listener + per-channel adapter /
    /// secret / route / user-mappings). `#[serde(default)]` per the `database` /
    /// `tools` precedent: existing `runtime-config.yaml` files without a
    /// `channels:` block parse cleanly under `deny_unknown_fields`, producing
    /// `ChannelsConfig::default()` (no listener, no channels → no pump).
    #[serde(default)]
    pub channels: ChannelsConfig,
    /// /dev Phase-3 kickoff (2026-06-06) — MODULE-008 per-run budget defaults
    /// (CONTRACT-003 additive extension). `#[serde(default)]` per the
    /// `database` / `tools` / `channels` precedent: existing
    /// `runtime-config.yaml` files without a `run-budget:` block parse cleanly
    /// under `deny_unknown_fields`, producing `RunBudgetConfig::default()` (all
    /// `None` → no per-run caps, identical to prior behavior). Read only by the
    /// cli composition root to seed the live `RunManager` session budget; no
    /// existing consumer reads it, so `affected_downstream_modules` is empty.
    #[serde(rename = "run-budget", default)]
    pub run_budget: RunBudgetConfig,
    /// Wave-16 Lane-4 (2026-06-25) — MODULE-012 security tunables (AC-17,
    /// CONTRACT-003 additive extension). `#[serde(default)]` per the `database` /
    /// `tools` / `channels` / `run-budget` precedent: existing `runtime-config.yaml`
    /// files without a `security:` block parse cleanly under `deny_unknown_fields`,
    /// producing `SecurityConfig::default()` (= the cap-http compile-time constants,
    /// so prior behaviour is reproduced byte-for-byte). The cli composition root
    /// reads it and injects live closures into the production HTTP security chains;
    /// four keys hot-reload live, `action_validator.max_message_size` is a
    /// construction snapshot (CONTRACT-113 determinism). Keys are snake_case to
    /// match the MODULE-012 §1.5 AC-17 criterion text.
    #[serde(default)]
    pub security: SecurityConfig,
}

/// /dev Phase-3 kickoff (2026-06-06) — per-run budget caps seeded into the live
/// `advance start` session `RunManager` (CONTRACT-003 additive block). All three
/// limits are optional; `None` means "no limit on that dimension" (the prior
/// default behavior). The cli composition root maps these into
/// `advance_run_manager::RunConfig` for `ensure_run`.
///
/// **Enforcement note** (MODULE-008 §2.11): on the single-LLM-call-per-turn
/// daemon path, `default-cost-limit-usd` (trailing, via the EventBus `CostTracker`)
/// and `default-rounds-limit` (universal, via `complete_round`) are the enforcing
/// gates; `default-token-limit` is mapped through for multi-step forward-compat
/// but is non-enforcing there (the gateway preflight reserves 0 tokens).
#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct RunBudgetConfig {
    /// Default per-run token limit (`RunConfig.token_limit`). `None` = no limit.
    #[serde(rename = "default-token-limit", default)]
    pub default_token_limit: Option<u64>,
    /// Default per-run USD cost limit (`RunConfig.cost_usd_limit`). `None` = no
    /// limit. The enforcing per-session spend cap on the daemon path.
    #[serde(rename = "default-cost-limit-usd", default)]
    pub default_cost_limit_usd: Option<f64>,
    /// Default per-run rounds limit (`RunConfig.rounds_limit`). `None` = no
    /// limit. The universal per-session turn-count bound.
    #[serde(rename = "default-rounds-limit", default)]
    pub default_rounds_limit: Option<u32>,
}

/// /dev Phase-2 Step-3 — `channels.*` configuration section (MODULE-016 §2.10).
#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ChannelsConfig {
    /// Bind address for the shared `/hooks/{path}` webhook listener (e.g.
    /// `127.0.0.1:8080`). `None` → no listener bound (no host-pump channels).
    #[serde(rename = "webhook-listen-addr", default)]
    pub webhook_listen_addr: Option<String>,
    /// Configured channels (each subscribes a `HostPump` subscription at boot).
    #[serde(default)]
    pub channels: Vec<ChannelEntry>,
    /// Wave-6 Lane C (2026-06-21) — OPTIONAL operator notify-channel destination for
    /// MODULE-015 auto-loop degrade/halt notifications (SYS-AC-257). `None` (absent
    /// `notify:` block) → no cap-channel notify install (the auto driver keeps its
    /// `EventBusNotifySink` → `auto.notify` default; back-compat preserved). The cli
    /// composition root sources a standalone outbound notify `Subscription` +
    /// `OutboundTarget` from this block (see `advance_cli::channel_notify_sink`). The
    /// sole consumer is the cli root; no other module reads it.
    #[serde(default)]
    pub notify: Option<NotifyChannelConfig>,
}

/// Wave-6 Lane C (2026-06-21) — `channels.notify` block (MODULE-016 §2.10). The
/// operator notify destination the auto-loop degrade/halt `CapChannelNotifySink`
/// egresses to. Built into a standalone outbound notify `Subscription` (the
/// `url_template` preset) + an `OutboundTarget::ChatReply` (`conversation_id` +
/// `reply_address` bag) by the cli `build_channel_notify_sink`.
#[derive(Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NotifyChannelConfig {
    /// Adapter type string — `telegram` (the only send-capable Step-3 adapter; the
    /// cli rejects other adapters at build).
    pub adapter: String,
    /// The outbound preset base URL (host stays preset-allowlisted; carries the bot
    /// token — credential, redacted in `Debug`). e.g.
    /// `https://api.telegram.org/bot<token>/sendMessage`.
    #[serde(rename = "url-template")]
    pub url_template: String,
    /// The operator chat/thread id the notification is delivered to
    /// (`OutboundTarget::ChatReply.conversation_id`).
    #[serde(rename = "conversation-id")]
    pub conversation_id: String,
    /// The `channel.reply_address.*` bag (e.g. `{chat_id: "98765"}`) →
    /// `OutboundTarget::ChatReply.reply_address`. Defaults empty.
    #[serde(rename = "reply-address", default)]
    pub reply_address: Vec<NotifyReplyAddr>,
}

/// Manual `Debug` (mirrors `ChannelEntry`): `url_template` carries the outbound bot
/// token — redact it so a `{:?}` of `NotifyChannelConfig` / `ChannelsConfig` /
/// `RuntimeConfig` never leaks the credential into logs.
impl std::fmt::Debug for NotifyChannelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyChannelConfig")
            .field("adapter", &self.adapter)
            .field("url_template", &"[redacted: contains credential]")
            .field("conversation_id", &self.conversation_id)
            .field("reply_address", &self.reply_address)
            .finish()
    }
}

/// One `channel.reply_address.*` key/value pair for `NotifyChannelConfig`. Matches
/// the `(String, String)` shape `OutboundTarget::ChatReply.reply_address` expects.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NotifyReplyAddr {
    pub key: String,
    pub value: String,
}

/// One configured channel (Step-3 ships Telegram). The daemon `subscribe_host_pump`s
/// it at boot, registers its `/hooks/{route}` on the shared listener with a
/// channel-specific `InboundVerifier`, and wires its `user_mappings` into the
/// `IdentityResolver`.
#[derive(Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChannelEntry {
    /// Operator-facing channel name (diagnostic).
    pub name: String,
    /// Adapter type string — `telegram` (the only send-capable Step-3 adapter).
    pub adapter: String,
    /// Inbound verification secret (Telegram secret-token; the
    /// `X-Telegram-Bot-Api-Secret-Token` header value).
    pub secret: String,
    /// The `/hooks/{route}` path segment this channel listens on.
    pub route: String,
    /// The outbound preset base URL (host stays preset-allowlisted; e.g.
    /// `https://api.telegram.org/bot<token>/sendMessage`).
    #[serde(rename = "url-template")]
    pub url_template: String,
    /// WHO map entries (`{channel_kind, sender_id} → user`) for the
    /// `IdentityResolver`. Keyed on the SENDER id (e.g. Telegram `from.id`), NOT
    /// the conversation id.
    #[serde(rename = "user-mappings", default)]
    pub user_mappings: Vec<ChannelUserMapping>,
}

/// Manual `Debug` (audit r5 Warning): `secret` (inbound verifier token) and
/// `url_template` (carries the outbound bot token) are credentials — redact them
/// so a `{:?}` of `ChannelEntry`/`ChannelsConfig`/`RuntimeConfig` never leaks the
/// token into logs. Mirrors the redaction the LLM-provider config already applies.
impl std::fmt::Debug for ChannelEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelEntry")
            .field("name", &self.name)
            .field("adapter", &self.adapter)
            .field("secret", &"[redacted]")
            .field("route", &self.route)
            .field("url_template", &"[redacted: contains credential]")
            .field("user_mappings", &self.user_mappings)
            .finish()
    }
}

/// A single channel WHO mapping: `(channel_kind, sender_id) → user`.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChannelUserMapping {
    #[serde(rename = "channel-kind")]
    pub channel_kind: String,
    #[serde(rename = "sender-id")]
    pub sender_id: String,
    /// The unified id (`user:alice`).
    pub user: String,
}

/// Slice m017-B (2026-05-14) — `tools.*` configuration section.
/// Mirrors MODULE-017 §2.10. All fields are `#[serde(default)]` so a
/// `tools:` block declaring only a subset still deserializes cleanly.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolsConfig {
    /// Slice m017-B — LRU cap (per §2.10 `tools.max_tool_instances`).
    /// Default 20.
    #[serde(rename = "max-tool-instances", default = "default_max_tool_instances")]
    pub max_tool_instances: usize,
    /// Slice m017-B — WASM load timeout in seconds (per §2.10
    /// `tools.lazy_load_timeout_sec`). Default 30.
    #[serde(
        rename = "lazy-load-timeout-sec",
        default = "default_lazy_load_timeout_sec"
    )]
    pub lazy_load_timeout_sec: u64,
    /// Slice m017-B — per-invoke max bytes returned from WASM `execute`
    /// (per §2.10 `tools.max_result_bytes`). Default 16 MiB. Exceeding
    /// this fails closed with `tool-error::output-validation-failed`
    /// — no silent truncation.
    #[serde(rename = "max-result-bytes", default = "default_max_result_bytes")]
    pub max_result_bytes: usize,
    /// Slice m017-C (2026-05-16, adversarial round 1 fix for C4) —
    /// wall-clock backstop for in-WASM `execute()` calls. Default 5
    /// seconds. Bounds I/O-aware guests; does NOT bound CPU-bound
    /// infinite loops (those require `tool_fuel_per_call` + engine
    /// `consume_fuel(true)`, or a future `tool_engine` ticker —
    /// MODULE-017 §3.6 known gap (a)).
    #[serde(
        rename = "tool-invoke-timeout-sec",
        default = "default_tool_invoke_timeout_sec"
    )]
    pub tool_invoke_timeout_sec: u64,
    /// Slice m017-C (2026-05-16, adversarial round 1 fix for C4) —
    /// optional Wasmtime fuel budget per `execute()` call. `None` means
    /// fuel-based interruption is disabled (default — preserves the
    /// Slice B behaviour where fuel isn't required). Setting `Some(N)`
    /// requires the tool engine to be built with `consume_fuel(true)`
    /// (controlled by `wasm.fuel_enabled`); otherwise `Store::set_fuel`
    /// silently no-ops. With fuel + a CPU-bound guest, fuel exhaustion
    /// injects a trap point and bounds runaway execution even without
    /// epoch interruption. Recommended operator action: set this in
    /// adversarial-tool scenarios.
    #[serde(rename = "tool-fuel-per-call", default)]
    pub tool_fuel_per_call: Option<u64>,
    /// Slice m017-C (2026-05-16, adversarial round 1 fix for C4) —
    /// timeout for the `tool-exports.describe()` call during cold-load.
    /// Default 2 seconds — shorter than invoke because describe is
    /// expected to be a constant-time function returning a small struct.
    #[serde(
        rename = "bring-up-describe-timeout-sec",
        default = "default_bring_up_describe_timeout_sec"
    )]
    pub bring_up_describe_timeout_sec: u64,
}

fn default_max_tool_instances() -> usize {
    20
}

fn default_lazy_load_timeout_sec() -> u64 {
    30
}

fn default_max_result_bytes() -> usize {
    16 * 1024 * 1024
}

fn default_tool_invoke_timeout_sec() -> u64 {
    5
}

fn default_bring_up_describe_timeout_sec() -> u64 {
    2
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            max_tool_instances: default_max_tool_instances(),
            lazy_load_timeout_sec: default_lazy_load_timeout_sec(),
            max_result_bytes: default_max_result_bytes(),
            tool_invoke_timeout_sec: default_tool_invoke_timeout_sec(),
            tool_fuel_per_call: None,
            bring_up_describe_timeout_sec: default_bring_up_describe_timeout_sec(),
        }
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmConfig {
    pub max_memory_pages: u32,
    pub epoch_interruption_ms: u64,
    pub fuel_enabled: bool,
}

/// Upstream wire-protocol family for an LLM provider (per ADR 2026-07-22
/// `real-per-token-sse-streaming-three-endpoint-provider`, Decision D4).
///
/// Absent from config (`None` on `LlmProviderConfig.backend`) → the resolver
/// infers it via `backend_of` byte-compatibly with the historical id-based
/// routing: `id == "anthropic"` → `AnthropicMessages`, else `OpenAiChat`.
/// Variant renames are EXPLICIT (not `rename_all`) because the ADR pins the
/// exact wire spellings `openai-chat` / `openai-responses` /
/// `anthropic-messages`.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum ProviderBackend {
    #[serde(rename = "openai-chat")]
    OpenAiChat,
    #[serde(rename = "openai-responses")]
    OpenAiResponses,
    #[serde(rename = "anthropic-messages")]
    AnthropicMessages,
}

/// Credential-position scheme, orthogonal to `ProviderBackend` (ADR 2026-07-22
/// fork f). Absent → the backend's default applies (`OpenAiChat`/
/// `OpenAiResponses` → `Bearer`; `AnthropicMessages` → `XApiKey`).
/// `ApiKey` covers Azure-OpenAI-style `api-key` header deployments.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum AuthScheme {
    #[serde(rename = "bearer")]
    Bearer,
    #[serde(rename = "x-api-key")]
    XApiKey,
    #[serde(rename = "api-key")]
    ApiKey,
}

#[derive(Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LlmProviderConfig {
    pub id: String,
    pub endpoint: String,
    /// Secret *reference name* (not the actual key). Redacted in `Debug` output to
    /// prevent accidental leakage via panic messages or log statements.
    #[serde(rename = "api-key-secret")]
    pub api_key_secret: String,
    #[serde(rename = "model-aliases")]
    pub model_aliases: HashMap<String, String>,
    #[serde(rename = "cost-per-mtoken-in")]
    pub cost_per_mtoken_in: f64,
    #[serde(rename = "cost-per-mtoken-out")]
    pub cost_per_mtoken_out: f64,
    #[serde(rename = "rate-limit", default)]
    pub rate_limit: Option<RateLimit>,
    #[serde(rename = "retry-default", default)]
    pub retry_default: Option<RetryDefaults>,
    /// Wire-protocol family (ADR 2026-07-22 D4). `None` → resolver-side
    /// inference byte-compatible with historical id-based routing.
    #[serde(default)]
    pub backend: Option<ProviderBackend>,
    /// Credential-position override (ADR 2026-07-22 fork f). `None` → the
    /// backend's default credential position.
    #[serde(rename = "auth-scheme", default)]
    pub auth_scheme: Option<AuthScheme>,
}

impl fmt::Debug for LlmProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmProviderConfig")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .field("api_key_secret", &"<REDACTED>")
            .field("model_aliases", &self.model_aliases)
            .field("cost_per_mtoken_in", &self.cost_per_mtoken_in)
            .field("cost_per_mtoken_out", &self.cost_per_mtoken_out)
            .field("rate_limit", &self.rate_limit)
            .field("retry_default", &self.retry_default)
            .field("backend", &self.backend)
            .field("auth_scheme", &self.auth_scheme)
            .finish()
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    #[serde(rename = "requests-per-minute")]
    pub requests_per_minute: u64,
    #[serde(rename = "tokens-per-minute")]
    pub tokens_per_minute: u64,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RetryDefaults {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CronConfig {
    pub max_jitter_ratio: f64,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GitConfig {
    pub gc_interval_hours: u64,
    pub max_tracked_file_mb: u64,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum CircuitBreakerScope {
    Capability,
    ComponentType,
    Agent,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum CircuitBreakerState {
    Open,
    Closed,
    HalfOpen,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerSpec {
    pub scope: CircuitBreakerScope,
    pub target: String,
    pub state: CircuitBreakerState,
    #[serde(rename = "kill-existing", default)]
    pub kill_existing: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum MasterKeySource {
    Keychain,
    EnvVar,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    #[serde(rename = "master-key-source")]
    pub master_key_source: MasterKeySource,
    #[serde(rename = "env-var-name")]
    pub env_var_name: String,
    /// AC-15 caller-dependency allowlist (Wave-18 Lane-3, additive — CONTRACT-003).
    /// Maps a BARE cap agent-id (`HostCallContext.agent_id`, e.g. the
    /// production-stamped `default-agent`) to the secret names that agent has
    /// declared a dependency on. When non-empty, the cli composition root
    /// (`register_secrets_capability`) registers the GATED `secret-exists`
    /// handler over a `DeclaredDependencyPolicy`, so a caller whose `agent_id`
    /// is absent (or whose requested name is not in its list) gets
    /// `secret-error::permission-denied`. Empty (the `#[serde(default)]`) →
    /// the permissive handler, byte-identical to pre-Wave-18 behaviour (the
    /// gate is operator-opt-in). Read once at boot; not hot-reloaded.
    #[serde(default)]
    pub dependencies: HashMap<String, Vec<String>>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UserMapping {
    pub id: String,
    pub channels: Vec<HashMap<String, String>>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PostProcessorConfig {
    #[serde(rename = "llm-model")]
    pub llm_model: String,
    #[serde(rename = "llm-failure-cooldown-seconds")]
    pub llm_failure_cooldown_seconds: u64,
}

/// Auto-loop defaults (MODULE-015). Empty struct with `deny_unknown_fields` per §1.7
/// strict mode. Fields are added when MODULE-015 stabilizes its config schema.
#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct AutoLoopDefaults {}

/// Slice AE (2026-05-09) — per-workspace SQLite index handle config.
/// Consumed by `bootstrap::RuntimeHost::new` to construct
/// `R2d2SqliteIndexHandle::with_tunables(workspace.join(db_path), pool_size, tunables)`.
///
/// Slice G (2026-05-09) extends the block with `wal-mode`, `embedding-dim`,
/// `recall-max-depth` for AC-19 hot-reload coverage. Each new field has a
/// `#[serde(default)]` function-form so omitting an individual subfield within
/// a present `database:` block yields the canonical default.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Path to the SQLite index database file. Resolves from the workspace
    /// root. `validate_config` rejects two specific shapes (Adversarial R1 W2 —
    /// prevents tampered-config redirection to attacker-chosen filesystem
    /// locations): (1) any path where `Path::is_absolute()` is true, and (2)
    /// any path containing a `..` segment. Other non-canonical relative
    /// shapes (e.g. paths with leading `./` or repeated separators) are
    /// accepted by the validator and resolved by `Path::join` semantics.
    /// Bootstrap rejects symlinks at this path (existing or dangling).
    #[serde(rename = "db-path")]
    pub db_path: String,
    /// r2d2 connection pool size. Range `1..=256` per `validate_config`.
    #[serde(rename = "pool-size")]
    pub pool_size: u32,
    /// Slice G (AC-19): when `true`, `R2d2SqliteIndexHandle::with_tunables`
    /// reads at pool build and threads into `PragmaCustomizer::new(true)`
    /// → `PRAGMA journal_mode = WAL`. When `false`, `PRAGMA journal_mode =
    /// MEMORY`. Hot-reload is snapshot-observable but does NOT re-pragma
    /// live connections (PragmaCustomizer is per-pool, not per-checkout) —
    /// MODULE-001 §2.10 documents this honestly.
    #[serde(rename = "wal-mode", default = "default_wal_mode")]
    pub wal_mode: bool,
    /// Slice G (AC-19): dimension count for sqlite-vec virtual tables.
    /// Range `1..=8192`. Hot-reloadable per call: all 4 R2d2 impls in the
    /// database crate read `tunables.current().embedding_dim` per write
    /// (handle.upsert_*), per query (recall, unified_search), and per
    /// rebuild (rebuild.embed_or_skip). Operator note: vec0 columns are
    /// dimension-typed at CREATE time, so changing this value at runtime
    /// requires also rebuilding the vector index.
    #[serde(rename = "embedding-dim", default = "default_embedding_dim")]
    pub embedding_dim: u32,
    /// Slice G (AC-19): max ancestor-walk depth for recall directory
    /// aggregation (PRD §8.3.4). Range `1..=10` (PRD-default 3; ceiling
    /// caps the path-explosion factor). Hot-reloadable per call:
    /// `R2d2RecallImpl::recall` reads `tunables.current().recall_max_depth`
    /// and threads through `recall_blocking` + `descend_into_dirs`.
    #[serde(rename = "recall-max-depth", default = "default_recall_max_depth")]
    pub recall_max_depth: u32,
}

fn default_wal_mode() -> bool {
    true
}
fn default_embedding_dim() -> u32 {
    768
}
fn default_recall_max_depth() -> u32 {
    3
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            db_path: ".runtime/index.db".to_string(),
            pool_size: 4,
            wal_mode: default_wal_mode(),
            embedding_dim: default_embedding_dim(),
            recall_max_depth: default_recall_max_depth(),
        }
    }
}

// ---------------------------------------------------------------------------
// SecurityConfig (Wave-16 Lane-4, 2026-06-25) — MODULE-012 AC-17.
// CONTRACT-003 additive `security:` block. Snake_case keys match the §1.5 AC-17
// criterion. Each sub-struct's Default mirrors the cap-http compile-time constant
// exactly, so an absent `security:` block reproduces prior behaviour byte-for-byte.
// `validate_config` bounds every knob (lower AND upper) fail-closed.
// ---------------------------------------------------------------------------

/// `security.leak_detector.*` — LeakDetector scan cap (hot-reload **live**:
/// read per-scan via the injected `with_scan_cap_source` closure at the cli site).
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LeakDetectorConfig {
    /// Max bytes scanned per input. Range `[1, 64 MiB]` (`validate_config`).
    /// Default mirrors `cap_http::leak_detector::MAX_SCAN_BYTES` (1 MiB).
    #[serde(default = "default_max_scan_bytes")]
    pub max_scan_bytes: usize,
}

fn default_max_scan_bytes() -> usize {
    1024 * 1024
}

impl Default for LeakDetectorConfig {
    fn default() -> Self {
        Self {
            max_scan_bytes: default_max_scan_bytes(),
        }
    }
}

/// `security.ssrf.*` — SSRF DNS tunables (hot-reload **live**: timeout read
/// per-resolve, ttl read per-lookup at the freshness check).
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SsrfConfig {
    /// DNS resolution cache TTL (seconds). Range `[0, 86_400]`. Default mirrors
    /// `cap_http::ssrf::DEFAULT_DNS_CACHE_TTL_SECS` (300).
    #[serde(default = "default_dns_cache_ttl_seconds")]
    pub dns_cache_ttl_seconds: u64,
    /// DNS lookup timeout (ms). Range `[1, 60_000]`. Default mirrors
    /// `cap_http::ssrf::DEFAULT_DNS_TIMEOUT_MS` (50).
    #[serde(default = "default_dns_timeout_ms")]
    pub dns_timeout_ms: u64,
}

fn default_dns_cache_ttl_seconds() -> u64 {
    300
}
fn default_dns_timeout_ms() -> u64 {
    50
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            dns_cache_ttl_seconds: default_dns_cache_ttl_seconds(),
            dns_timeout_ms: default_dns_timeout_ms(),
        }
    }
}

/// `security.rate_limit.*` — per-component HTTP rate limit (hot-reload **live**:
/// read per-check). NOTE: the limiter divides by `per_component_rps`, so
/// `validate_config` requires it finite & in `(0, MAX_RPS]` (fail-closed).
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Requests/sec per component. Range `(0, 1_000_000]`, must be finite.
    /// Default mirrors `cap_http::rate_limit::DEFAULT_PER_COMPONENT_RPS` (10.0).
    #[serde(default = "default_per_component_rps")]
    pub per_component_rps: f64,
}

fn default_per_component_rps() -> f64 {
    10.0
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_component_rps: default_per_component_rps(),
        }
    }
}

/// `security.action_validator.*` — oversized-action threshold. **SNAPSHOT**
/// (read once at agent-loop construction, NOT live) to preserve the CONTRACT-113
/// `ActionValidator` determinism invariant (same input → same output).
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionValidatorConfig {
    /// Max `AgentAction.payload` bytes. Range `[1, 64 MiB]`. Default mirrors
    /// `cap_http::action_validator::DEFAULT_MAX_MESSAGE_SIZE_BYTES` (1 MiB).
    #[serde(default = "default_action_max_message_size")]
    pub max_message_size: usize,
}

fn default_action_max_message_size() -> usize {
    1024 * 1024
}

impl Default for ActionValidatorConfig {
    fn default() -> Self {
        Self {
            max_message_size: default_action_max_message_size(),
        }
    }
}

/// `security:` block — MODULE-012 AC-17 (CONTRACT-003 additive extension).
#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub leak_detector: LeakDetectorConfig,
    #[serde(default)]
    pub ssrf: SsrfConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub action_validator: ActionValidatorConfig,
}

// ---------------------------------------------------------------------------
// RuntimeConfigProvider trait (CONTRACT-003)
// ---------------------------------------------------------------------------

// CONTRACT-003 — RuntimeConfigProvider
/// Provides access to the current runtime configuration and a subscription
/// channel for hot-reload notifications.
pub trait RuntimeConfigProvider: Send + Sync {
    /// Returns the current configuration snapshot.
    fn current(&self) -> Arc<RuntimeConfig>;

    /// Subscribes to configuration change notifications. Each time the config
    /// file is modified and successfully re-parsed with a different value, the
    /// new `Arc<RuntimeConfig>` is sent through the returned receiver.
    ///
    /// The channel is bounded (`SUBSCRIBER_CHANNEL_CAPACITY`); subscribers that
    /// fall behind will lose updates (try_send drops on full) instead of causing
    /// unbounded memory growth. Always call `current()` after receiving an update
    /// to reconcile with the latest config.
    fn subscribe(&self) -> mpsc::Receiver<Arc<RuntimeConfig>>;

    /// Returns the last load or parse error that occurred during a hot-reload
    /// attempt (or `None` if the last reload succeeded). Provides observability
    /// for adversarial tampering / corrupted config files — no more silent drops.
    ///
    /// Hotreload pre-build (2026-06-10): ALSO records a reload-event emitter
    /// panic (see `RuntimeConfigWatcher::set_event_emitter`). In that case the
    /// reload itself SUCCEEDED (the new config is applied); the record reports
    /// the emission failure, and the next clean reload clears it.
    fn last_error(&self) -> Option<String>;
}

// ---------------------------------------------------------------------------
// Reload-event emission (hotreload pre-build, 2026-06-10)
// ---------------------------------------------------------------------------

/// Canonical event type emitted on every APPLIED runtime-config hot-reload.
///
/// MUST stay byte-identical to `taxonomy::extensions::RUNTIME_CONFIG_RELOADED`
/// in `crates/event-bus/src/taxonomy.rs` (the source of truth). The constant is
/// redefined locally — NOT imported — because runtime deliberately takes no
/// dependency edge on event-bus (the `trigger_emit.rs` dependency-avoidance
/// precedent); there is no compile-time cross-crate guard, so drift would only
/// surface in the event-bus taxonomy-coverage tests.
pub const RUNTIME_CONFIG_RELOADED_EVENT_TYPE: &str = "runtime.config_reloaded";

/// Names of the top-level `runtime-config.yaml` sections that differ between
/// two parsed configs, in canonical kebab-case YAML spelling.
///
/// Exhaustively destructures [`RuntimeConfig`] so that adding a 14th section
/// without extending this diff is a COMPILE ERROR, not a silent payload gap.
pub fn config_sections_changed(old: &RuntimeConfig, new: &RuntimeConfig) -> Vec<&'static str> {
    let RuntimeConfig {
        wasm,
        llm_providers,
        cron,
        git,
        circuit_breakers,
        secrets,
        users,
        post_processor,
        auto_loop_defaults,
        database,
        tools,
        channels,
        run_budget,
        security,
    } = old;
    let mut changed = Vec::new();
    if wasm != &new.wasm {
        changed.push("wasm");
    }
    if llm_providers != &new.llm_providers {
        changed.push("llm-providers");
    }
    if cron != &new.cron {
        changed.push("cron");
    }
    if git != &new.git {
        changed.push("git");
    }
    if circuit_breakers != &new.circuit_breakers {
        changed.push("circuit-breakers");
    }
    if secrets != &new.secrets {
        changed.push("secrets");
    }
    if users != &new.users {
        changed.push("users");
    }
    if post_processor != &new.post_processor {
        changed.push("post-processor");
    }
    if auto_loop_defaults != &new.auto_loop_defaults {
        changed.push("auto-loop-defaults");
    }
    if database != &new.database {
        changed.push("database");
    }
    if tools != &new.tools {
        changed.push("tools");
    }
    if channels != &new.channels {
        changed.push("channels");
    }
    if run_budget != &new.run_budget {
        changed.push("run-budget");
    }
    if security != &new.security {
        changed.push("security");
    }
    changed
}

/// Convert a caught panic payload into a diagnostic message, neutralizing
/// hostile payloads: `String`/`&str` payloads are extracted and dropped
/// normally (their `Drop` cannot panic); UNKNOWN payload types are
/// `mem::forget`-ten — a `panic_any` payload whose own `Drop` panics would
/// otherwise re-panic outside the enclosing `catch_unwind` and kill the
/// bridge task. The forget leaks at most one small allocation per panicking
/// emit, rate-limited by real config-file changes (disclosed residual; the
/// no-leak property holds only for the common `String`/`&str` case).
fn panic_payload_to_message(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(s) => *s,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(s) => (*s).to_string(),
            Err(payload) => {
                std::mem::forget(payload);
                "non-string panic payload (forgotten)".to_string()
            }
        },
    }
}

// ---------------------------------------------------------------------------
// RuntimeConfigWatcher
// ---------------------------------------------------------------------------

/// Shared state between the `RuntimeConfigWatcher` owner and the bridge task.
struct WatcherInner {
    path: PathBuf,
    current: RwLock<Arc<RuntimeConfig>>,
    subscribers: Mutex<Vec<mpsc::Sender<Arc<RuntimeConfig>>>>,
    /// Last reload failure (None if the most recent reload succeeded). Surfaces
    /// adversarial tampering / corrupted config to operators via `last_error()`.
    /// Hotreload pre-build (2026-06-10): ALSO records reload-event emitter
    /// panics (an emitter panic does not fail the reload itself — the new
    /// config is already applied — but it is operator-visible here).
    last_error: Mutex<Option<String>>,
    /// Optional `runtime.config_reloaded` sink (hotreload pre-build,
    /// 2026-06-10). `None` until [`RuntimeConfigWatcher::set_event_emitter`]
    /// is called; the bridge task emits on every APPLIED reload while set.
    /// Locked with poison-RECOVERY (`unwrap_or_else(into_inner)`) — never
    /// `.expect` — so no panic path can brick the bridge through this Mutex.
    emitter: Mutex<Option<Arc<dyn EventBusEmit>>>,
    /// Drop-gate for the emitter (hotreload pre-build, 2026-06-10): set
    /// `false` by `RuntimeConfigWatcher::drop`. After the watcher owner drops,
    /// the bridge task drains up to `EVENT_BRIDGE_CHANNEL_CAPACITY` queued
    /// filesystem events before exiting; this gate keeps that post-drop drain
    /// from publishing phantom `runtime.config_reloaded` events. Check-then-act:
    /// at most ONE in-flight emit whose gate check passed before the store can
    /// still land after drop — consumers must not assert zero-post-drop events.
    emitter_live: AtomicBool,
}

/// Watches `/.advance/runtime-config.yaml` for changes and publishes updates.
///
/// The `notify::RecommendedWatcher` watches the parent directory to support
/// atomic rename/create patterns (editors that write to a temp file then rename).
///
/// Debug impl omits the watcher/abort internals (not useful for diagnostics).
pub struct RuntimeConfigWatcher {
    inner: Arc<WatcherInner>,
    _watcher: RecommendedWatcher,
    _bridge_abort: AbortHandle,
    _poll_abort: AbortHandle,
}

impl fmt::Debug for RuntimeConfigWatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeConfigWatcher")
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}

impl RuntimeConfigWatcher {
    /// Parse the config file at `path` and start watching for changes.
    pub async fn new(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();

        // Must be absolute — relative paths have no stable ancestor chain to audit.
        if !path.is_absolute() {
            return Err(ConfigError::IoError {
                path: path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "config path must be absolute",
                ),
            });
        }

        // Reject a symlink at the leaf BEFORE canonicalize (R12): canonicalize
        // would follow it and erase the evidence. This catches the leaf-swap case.
        let lmeta = std::fs::symlink_metadata(&path).map_err(io_err(&path))?;
        check_is_regular_file(&path, lmeta.file_type())?;

        // Canonicalize to resolve system-managed structural symlinks (e.g.,
        // /var → /private/var on macOS), then reject if the CANONICAL path has
        // any ancestor symlinks. This closes the parent-directory symlink-swap
        // attack (R13 Critical) while tolerating legitimate system symlinks.
        let canonical = std::fs::canonicalize(&path).map_err(io_err(&path))?;
        let path = canonical;
        check_no_ancestor_symlinks_parents(&path)?;

        let config = load_config(&path)?;

        let inner = Arc::new(WatcherInner {
            path: path.clone(),
            current: RwLock::new(Arc::new(config)),
            subscribers: Mutex::new(Vec::new()),
            last_error: Mutex::new(None),
            emitter: Mutex::new(None),
            emitter_live: AtomicBool::new(true),
        });

        // Bridge: notify callback → tokio::sync::mpsc → bridge task.
        // The callback filters events by path before enqueueing. Channel is
        // BOUNDED so a rapid-rewrite attack cannot accumulate unbounded events
        // before the bridge drains (R13 Critical). On full, events are dropped
        // and last_error is set so the operator can observe the DoS.
        let (event_tx, mut event_rx) = mpsc::channel::<Event>(EVENT_BRIDGE_CHANNEL_CAPACITY);

        let poll_tx = event_tx.clone();
        let poll_path = path.clone();
        let poll_inner = Arc::clone(&inner);
        let config_path = path.clone();
        let callback_inner = Arc::clone(&inner);
        let mut watcher = RecommendedWatcher::new(
            move |result: Result<Event, notify::Error>| match result {
                Ok(event) => {
                    if is_relevant_event(&event, &config_path) {
                        // try_send: drop on full to cap memory; record saturation.
                        if let Err(mpsc::error::TrySendError::Full(_)) = event_tx.try_send(event) {
                            *callback_inner.last_error.lock().expect("Mutex poisoned") = Some(
                                "event bridge saturated; filesystem events are being dropped"
                                    .to_string(),
                            );
                        }
                    }
                }
                Err(e) => {
                    *callback_inner.last_error.lock().expect("Mutex poisoned") =
                        Some(format!("notify backend error: {e}"));
                }
            },
            notify::Config::default(),
        )
        .map_err(|e| ConfigError::WatchError { source: e })?;

        // Watch the parent directory to catch rename/create patterns.
        let watch_dir = path.parent().unwrap_or_else(|| Path::new("/"));
        watcher
            .watch(watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| ConfigError::WatchError { source: e })?;

        // Secondary file-fingerprint poll: platform notify backends may miss
        // same-path rewrites under isolated temp dirs. Polling feeds the same
        // bounded bridge so reload validation, dedup, and fail-closed errors
        // remain single-sourced.
        let poll_handle = tokio::spawn(async move {
            let mut last = config_file_fingerprint(&poll_path);
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                let current = config_file_fingerprint(&poll_path);
                if current == last {
                    continue;
                }
                last = current;

                let event = Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Any)))
                    .add_path(poll_path.clone());
                match poll_tx.try_send(event) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        *poll_inner.last_error.lock().expect("Mutex poisoned") = Some(
                            "event bridge saturated; filesystem events are being dropped"
                                .to_string(),
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        });

        // Spawn the bridge task that processes filesystem events.
        let bridge_inner = Arc::clone(&inner);
        let bridge_handle = tokio::spawn(async move {
            while let Some(_event) = event_rx.recv().await {
                // Event already filtered by path in the notify callback.
                // Re-parse asynchronously; on failure, record the error so operators
                // can observe tampering/corruption instead of silently retaining stale config.
                // Re-check ancestor symlinks on every reload — the startup check
                // alone doesn't prevent a post-startup attacker from swapping an
                // ancestor to a symlink (R14 Critical). This uses blocking fs ops
                // inside the async task, but they're <1ms on typical filesystems
                // and bounded by ancestor count.
                let ancestor_result = {
                    let path_ref = bridge_inner.path.clone();
                    tokio::task::spawn_blocking(move || {
                        check_no_ancestor_symlinks_parents(&path_ref)
                    })
                    .await
                    .unwrap_or_else(|e| {
                        Err(ConfigError::IoError {
                            path: bridge_inner.path.clone(),
                            source: std::io::Error::other(e.to_string()),
                        })
                    })
                };
                if let Err(e) = ancestor_result {
                    *bridge_inner.last_error.lock().expect("Mutex poisoned") = Some(e.to_string());
                    continue;
                }

                let new_config = match load_config_async(&bridge_inner.path).await {
                    Ok(c) => {
                        *bridge_inner.last_error.lock().expect("Mutex poisoned") = None;
                        c
                    }
                    Err(e) => {
                        *bridge_inner.last_error.lock().expect("Mutex poisoned") =
                            Some(e.to_string());
                        continue;
                    }
                };

                let current_arc = {
                    let guard = bridge_inner.current.read().expect("RwLock poisoned");
                    Arc::clone(&guard)
                };

                if *current_arc == new_config {
                    continue;
                }

                let new_arc = Arc::new(new_config);

                // Update `current` under a short write-lock critical section,
                // then release before fan-out so subscribers iterating over N
                // channels don't block readers on `current()` (R13 Warning).
                {
                    let mut current_guard = bridge_inner.current.write().expect("RwLock poisoned");
                    *current_guard = Arc::clone(&new_arc);
                }
                // Now fan-out with only the subscribers mutex held.
                {
                    let mut subs = bridge_inner.subscribers.lock().expect("Mutex poisoned");
                    subs.retain(|tx| match tx.try_send(Arc::clone(&new_arc)) {
                        Ok(()) => true,
                        Err(mpsc::error::TrySendError::Full(_)) => true,
                        Err(mpsc::error::TrySendError::Closed(_)) => false,
                    });
                }

                // Hotreload pre-build (2026-06-10): emit `runtime.config_reloaded`
                // AFTER swap + fan-out (existing hardened logic above is
                // untouched). `current_arc` (pre-swap) and `new_arc` are both
                // in scope, and this bridge task is the SOLE `current` writer,
                // so the diff is exact. The dedup `continue` above guarantees
                // a non-empty diff in practice; the is_empty skip is defensive.
                {
                    // Clone the emitter out under the guard, then RELEASE the
                    // guard before any emit/drop — a panicking emitter must
                    // never poison this Mutex (it is also locked with poison
                    // recovery as a second line of defense).
                    let emitter = {
                        let guard = bridge_inner
                            .emitter
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        guard.clone()
                    };
                    if let Some(em) = emitter {
                        let sections = config_sections_changed(&current_arc, &new_arc);
                        // Drop-gate checked immediately before emit (see
                        // `emitter_live` field docs for the one-in-flight
                        // residual disclosure).
                        if !sections.is_empty() && bridge_inner.emitter_live.load(Ordering::Acquire)
                        {
                            let event = BusEvent::observability(
                                RUNTIME_CONFIG_RELOADED_EVENT_TYPE,
                                "runtime",
                                json!({ "sections_changed": sections }),
                                None,
                            );
                            // Catch #1: the emit itself, `em` captured by
                            // REFERENCE (emit takes &self via Arc deref).
                            // A panicking emitter is contained and recorded.
                            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| em.emit(event)))
                            {
                                let msg = format!(
                                    "config-reload event emitter panicked: {}",
                                    panic_payload_to_message(payload)
                                );
                                // Poison-RECOVERY (not .expect) on the emit
                                // path — parity with the emitter Mutex and the
                                // cap-fs watcher: nothing on this seam may
                                // brick the bridge, even via an unforeseen
                                // poison of last_error.
                                *bridge_inner
                                    .last_error
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner()) = Some(msg);
                            }
                            // Catch #2: the possibly-LAST-REF Arc drop in its
                            // OWN catch. A concurrent set_event_emitter can
                            // make `em` the last reference; folding this drop
                            // into catch #1 would run a panicking Drop DURING
                            // the emit-panic unwind — panic-in-destructor =
                            // process abort. Sequential catches keep the drop
                            // on a normal path.
                            if let Err(payload) = catch_unwind(AssertUnwindSafe(move || drop(em))) {
                                let msg = format!(
                                    "config-reload event emitter Drop panicked: {}",
                                    panic_payload_to_message(payload)
                                );
                                *bridge_inner
                                    .last_error
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner()) = Some(msg);
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            inner,
            _watcher: watcher,
            _bridge_abort: bridge_handle.abort_handle(),
            _poll_abort: poll_handle.abort_handle(),
        })
    }

    /// Install (or replace) the `runtime.config_reloaded` event sink
    /// (hotreload pre-build, 2026-06-10). On every APPLIED hot-reload the
    /// bridge task emits one `runtime.config_reloaded` event whose payload is
    /// `{"sections_changed": [..]}` — top-level section NAMES only, never
    /// config values.
    ///
    /// **Emitter contract (CONTRACT-180)**: `emit` MUST be non-blocking and
    /// MUST NOT panic. A blocking emitter wedges the serial bridge loop —
    /// stopping reload APPLICATION, not just emission — so
    /// `EventBus::new_synchronous_for_tests` buses (blocking file/SQLite I/O
    /// per emit; their own rustdoc forbids async-executor threads) are
    /// FORBIDDEN on this seam. A panicking emitter is contained (recorded in
    /// `last_error()`; the bridge survives), at the cost of a possible small
    /// payload leak for non-string `panic_any` payloads.
    ///
    /// Replacement semantics: the previously-installed emitter (if any) is
    /// dropped AFTER the internal lock is released. If the replaced Arc is
    /// the last reference and its `Drop` panics, that panic propagates in
    /// THIS caller's frame (normal unwinding path, no lock held — no poison,
    /// no bridge impact); an emitter whose `Drop` panics already violates the
    /// implementer invariants.
    ///
    /// Shutdown semantics: dropping the watcher gates further emission, but
    /// at most ONE in-flight emit may still land after `drop` returns —
    /// do not assert zero-post-drop events.
    pub fn set_event_emitter(&self, emitter: Arc<dyn EventBusEmit>) {
        let old = {
            let mut guard = self.inner.emitter.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *guard, Some(emitter))
        };
        // Replaced emitter dropped here, OUTSIDE the guard: a panicking
        // last-ref `Drop` under a held guard would poison the Mutex.
        drop(old);
    }
}

impl Drop for RuntimeConfigWatcher {
    fn drop(&mut self) {
        // Gate the bridge task's post-drop drain (up to
        // EVENT_BRIDGE_CHANNEL_CAPACITY queued events) from publishing
        // phantom `runtime.config_reloaded` events for a dead watcher.
        // Subscriber fan-out during the drain is deliberately UNCHANGED —
        // only the new emit is gated. Runs before the automatic field drops,
        // so the gate closes before `_watcher` drops `event_tx` and the
        // drain begins.
        self.inner.emitter_live.store(false, Ordering::Release);
        self._poll_abort.abort();
    }
}

impl RuntimeConfigProvider for RuntimeConfigWatcher {
    fn current(&self) -> Arc<RuntimeConfig> {
        // Recover from poisoning instead of panicking — `current` only ever holds
        // an immutable `Arc<RuntimeConfig>`, so the inner data cannot be mid-update.
        // Panicking here would cascade to every reader and brick the runtime.
        let guard = self.inner.current.read().unwrap_or_else(|e| e.into_inner());
        Arc::clone(&guard)
    }

    fn subscribe(&self) -> mpsc::Receiver<Arc<RuntimeConfig>> {
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        let mut subs = self
            .inner
            .subscribers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Prune closed senders opportunistically on subscribe so the vec does not
        // grow unbounded if config changes are rare (adversarial round 10 finding).
        subs.retain(|existing| !existing.is_closed());
        // Cap subscribers to prevent subscription-flood DoS (R15). If at cap,
        // record it in last_error and return an immediately-closed receiver
        // by dropping `tx` without storing it.
        if subs.len() >= MAX_SUBSCRIBERS {
            drop(subs);
            *self
                .inner
                .last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner()) =
                Some(format!("subscriber limit reached ({MAX_SUBSCRIBERS})"));
            return rx; // rx receives nothing because tx is dropped at end of function
        }
        subs.push(tx);
        rx
    }

    fn last_error(&self) -> Option<String> {
        self.inner
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map an io::Error into ConfigError::IoError.
fn io_err(path: &Path) -> impl Fn(std::io::Error) -> ConfigError + '_ {
    move |source| ConfigError::IoError {
        path: path.to_path_buf(),
        source,
    }
}

/// Walk every parent ancestor of an already-canonicalized path and reject if
/// any parent directory is a symlink. Assumes the caller has already validated
/// the leaf is not a symlink (via `check_is_regular_file` on `symlink_metadata`).
///
/// Since the input is canonical, system-managed symlinks like `/var → /private/var`
/// are already resolved — any remaining symlinks in the ancestor chain indicate
/// user-visible tampering.
/// NOTE: consumed by `crates/cli` — do not change signature without cross-crate update.
pub fn check_no_ancestor_symlinks_parents(path: &Path) -> Result<(), ConfigError> {
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let meta = match std::fs::symlink_metadata(ancestor) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(io_err(ancestor)(e)),
        };
        if meta.file_type().is_symlink() {
            return Err(ConfigError::IoError {
                path: ancestor.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ancestor directory is a symlink (symlink-swap attack surface)",
                ),
            });
        }
    }
    Ok(())
}

/// Reject paths that are not regular files (FIFOs, sockets, devices, symlinks).
/// `metadata().len()` returns 0 for these, which would bypass the size cap.
fn check_is_regular_file(path: &Path, file_type: std::fs::FileType) -> Result<(), ConfigError> {
    if file_type.is_file() {
        Ok(())
    } else {
        Err(ConfigError::IoError {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "config path is not a regular file",
            ),
        })
    }
}

/// Check that bytes read does not exceed MAX_CONFIG_SIZE.
fn check_size(path: &Path, read: u64) -> Result<(), ConfigError> {
    if read > MAX_CONFIG_SIZE {
        Err(ConfigError::FileTooLarge {
            path: path.to_path_buf(),
            size: read,
            max: MAX_CONFIG_SIZE,
        })
    } else {
        Ok(())
    }
}

/// Maximum number of YAML anchor definitions (`&name`) and alias references
/// (`*name`) combined. Guards against billion-laughs alias-expansion attacks
/// that bypass the 64 KiB byte cap by expanding exponentially at parse time.
/// Canonical configs use zero anchors; 16 is enough headroom for reasonable
/// uses (DRY'ing a handful of shared values) while preventing exponential
/// expansion even with nested anchors. (A single anchor referencing itself
/// N times compounds at depth; limit = N. Total expansion ≤ 2^N nodes for
/// N-level nesting; at N=16 that caps at ~65k nodes — safe.)
pub const MAX_YAML_ANCHORS_AND_ALIASES: usize = 16;

/// Reject YAML with excessive anchor/alias usage before parsing. `serde_yml`
/// 0.0.12 has no alias-depth limit, so a small file with `&a [*a,*a,...]` 20
/// levels deep expands to GBs at parse time. Pre-scan rejects that.
fn check_yaml_alias_budget(path: &Path, content: &str) -> Result<(), ConfigError> {
    let mut count = 0usize;
    let bytes = content.as_bytes();
    let mut in_string = false;
    let mut string_delim = 0u8;
    let mut prev_backslash = false;
    for &b in bytes {
        // Track whether we're inside a quoted scalar — anchors/aliases there
        // are literal characters, not YAML metadata.
        if in_string {
            if prev_backslash {
                prev_backslash = false;
            } else if b == b'\\' {
                prev_backslash = true;
            } else if b == string_delim {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' | b'\'' => {
                in_string = true;
                string_delim = b;
            }
            b'&' | b'*' => {
                count += 1;
                if count > MAX_YAML_ANCHORS_AND_ALIASES {
                    return Err(ConfigError::IoError {
                        path: path.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "YAML uses >{} anchors/aliases (billion-laughs attack surface)",
                                MAX_YAML_ANCHORS_AND_ALIASES
                            ),
                        ),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse YAML, mapping errors to ConfigError::ParseFailure, then validate
/// numeric field ranges to reject NaN/Inf and zero/out-of-range values that
/// would cause downstream footguns (division by zero, NaN propagation,
/// oversized memory requests, disabled safety limits).
fn parse_yaml(path: &Path, content: String) -> Result<RuntimeConfig, ConfigError> {
    check_yaml_alias_budget(path, &content)?;
    let config: RuntimeConfig =
        serde_yml::from_str(&content).map_err(|source| ConfigError::ParseFailure {
            path: path.to_path_buf(),
            source,
        })?;
    validate_config(path, &config)?;
    Ok(config)
}

/// Validate parsed config values. Rejects NaN/Inf, zero-disables-safety values,
/// excessive upper bounds (u64::MAX is equivalent to disabling), duplicate IDs
/// that enable provider-shadowing, and empty/whitespace strings on load-bearing
/// identity fields.
fn validate_config(path: &Path, cfg: &RuntimeConfig) -> Result<(), ConfigError> {
    let invalid = |msg: &str| -> Result<(), ConfigError> {
        Err(ConfigError::IoError {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string()),
        })
    };
    let check_nonempty = |field: &str, v: &str| -> Result<(), ConfigError> {
        if v.trim().is_empty() || v.contains('\0') {
            return Err(ConfigError::IoError {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{field} must be non-empty, non-whitespace, and contain no NUL bytes"),
                ),
            });
        }
        Ok(())
    };

    // --- WasmConfig: pages/ms 0 disables; set sane upper bounds ---
    // 1M pages = 64 GiB memory cap (Wasmtime max is ~4 GiB per instance anyway).
    const WASM_MAX_PAGES_LIMIT: u32 = 1_048_576;
    // 60s upper bound on epoch interruption — longer than this is effectively "disabled".
    const EPOCH_MS_MAX: u64 = 60_000;
    if cfg.wasm.max_memory_pages == 0 || cfg.wasm.max_memory_pages > WASM_MAX_PAGES_LIMIT {
        return invalid("wasm.max_memory_pages must be in (0, 1_048_576]");
    }
    if cfg.wasm.epoch_interruption_ms == 0 || cfg.wasm.epoch_interruption_ms > EPOCH_MS_MAX {
        return invalid("wasm.epoch_interruption_ms must be in (0, 60_000]");
    }

    // --- CronConfig: jitter ratio finite in [0, 1] ---
    let j = cfg.cron.max_jitter_ratio;
    if !j.is_finite() || !(0.0..=1.0).contains(&j) {
        return invalid("cron.max_jitter_ratio must be finite in [0, 1]");
    }

    // --- LLM providers: duplicate id detection + string/numeric validation ---
    let mut seen_ids = std::collections::HashSet::new();
    for p in &cfg.llm_providers {
        check_nonempty("llm-providers[].id", &p.id)?;
        check_nonempty("llm-providers[].endpoint", &p.endpoint)?;
        check_nonempty("llm-providers[].api-key-secret", &p.api_key_secret)?;
        if !seen_ids.insert(&p.id) {
            return invalid("duplicate llm-providers[].id (provider-shadowing attack surface)");
        }
        // Endpoint must be https:// except for localhost/127.0.0.1 (dev proxies).
        // Cleartext http:// to external hosts would expose LLM prompts (potentially
        // PII/secrets) to on-path interception. Bare prefix matching is unsafe —
        // `http://localhost.evil.example` starts with `http://localhost` but
        // resolves to an external host (R15 finding). Parse host boundary strictly.
        let ok = if let Some(rest) = p.endpoint.strip_prefix("https://") {
            !rest.is_empty()
        } else if let Some(rest) = p.endpoint.strip_prefix("http://") {
            // Per RFC 3986 URL semantics, `@` separates userinfo from host:
            // `http://user@realhost/path`. If `@` appears before `/`, skip past
            // it to find the real host. `http://localhost@evil.example` would
            // otherwise bypass the localhost check (R16 finding).
            let authority_end = rest.find('/').unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            let host_region = match authority.rfind('@') {
                Some(i) => &authority[i + 1..],
                None => authority,
            };
            // Strip port (:NNNN) from host, handling IPv6 brackets.
            let host = if host_region.starts_with('[') {
                // IPv6: [::1]:8080 → [::1]
                match host_region.find(']') {
                    Some(i) => &host_region[..=i],
                    None => host_region, // malformed; reject below
                }
            } else {
                match host_region.find(':') {
                    Some(i) => &host_region[..i],
                    None => host_region,
                }
            };
            host == "localhost" || host == "127.0.0.1" || host == "[::1]"
        } else {
            false
        };
        if !ok {
            return invalid(
                "llm-providers[].endpoint must be https:// (http:// only for bare localhost/127.0.0.1/[::1] host)",
            );
        }
        if !p.cost_per_mtoken_in.is_finite() || p.cost_per_mtoken_in <= 0.0 {
            return invalid(
                "llm-providers[].cost-per-mtoken-in must be finite and > 0 (0 disables cost caps)",
            );
        }
        if !p.cost_per_mtoken_out.is_finite() || p.cost_per_mtoken_out <= 0.0 {
            return invalid("llm-providers[].cost-per-mtoken-out must be finite and > 0");
        }
        // rate-limit is REQUIRED to prevent silent budget bypass via omission.
        match &p.rate_limit {
            None => {
                return invalid(
                    "llm-providers[].rate-limit is required (omission would disable the limiter)",
                )
            }
            Some(rl) => {
                if rl.requests_per_minute == 0 || rl.tokens_per_minute == 0 {
                    return invalid("llm-providers[].rate-limit values must be > 0");
                }
            }
        }
        // retry-default bounds (when present): operator-misconfiguration footgun guards
        // per MODULE-009 §1.4.3c. Block can be omitted entirely; if present, all three
        // subfields are required (struct deserialization enforces) and must be sensible.
        if let Some(rd) = &p.retry_default {
            if rd.max_retries == 0 {
                return invalid("llm-providers[].retry-default.max-retries must be > 0 (omitting retry-default falls back to RetryConfig::default() with max_retries=3 — there is no zero-retries setting at the provider tier; configure agent / run tiers if a different policy is needed)");
            }
            if rd.max_retries > 100 {
                return invalid("llm-providers[].retry-default.max-retries must be <= 100");
            }
            if rd.base_delay_ms == 0 {
                return invalid("llm-providers[].retry-default.base-delay-ms must be > 0 (zero would defeat exponential backoff and produce a tight retry storm)");
            }
            if rd.base_delay_ms > rd.max_delay_ms {
                return invalid(
                    "llm-providers[].retry-default.base-delay-ms must be <= max-delay-ms",
                );
            }
            if rd.max_delay_ms > 600_000 {
                return invalid("llm-providers[].retry-default.max-delay-ms must be <= 600000 (10 min upper bound)");
            }
        }
    }

    // --- Circuit breakers: duplicate (scope, target) detection ---
    let mut seen_breakers = std::collections::HashSet::new();
    for b in &cfg.circuit_breakers {
        check_nonempty("circuit-breakers[].target", &b.target)?;
        if !seen_breakers.insert((b.scope.clone(), b.target.clone())) {
            return invalid("duplicate circuit-breakers[] (scope, target) pair");
        }
    }

    // --- Run budget (Phase-3 kickoff): cost limit must be finite and >= 0 ---
    // Defense-in-depth (RunManager::ensure_run also guards a non-finite/negative
    // cost limit); a NaN/Inf/negative here would otherwise produce a meaningless
    // cost gate. token/rounds limits are Option<u64>/Option<u32> — no NaN risk.
    if let Some(c) = cfg.run_budget.default_cost_limit_usd {
        if !c.is_finite() || c < 0.0 {
            return invalid("run-budget.default-cost-limit-usd must be finite and >= 0");
        }
    }

    // --- Users: duplicate id + duplicate (channel-kind, channel-id) pairs ---
    let mut seen_users = std::collections::HashSet::new();
    let mut seen_channels = std::collections::HashSet::new();
    for u in &cfg.users {
        check_nonempty("users[].id", &u.id)?;
        if !seen_users.insert(&u.id) {
            return invalid("duplicate users[].id");
        }
        for channel_map in &u.channels {
            // Each list element must be a single-key map per the canonical YAML shape.
            if channel_map.len() != 1 {
                return invalid(
                    "users[].channels entries must be single-key maps (e.g., '- telegram: \"id\"')",
                );
            }
            for (kind, id) in channel_map {
                check_nonempty("users[].channels[].kind", kind)?;
                check_nonempty("users[].channels[].id", id)?;
                // Reject duplicate (channel_kind, channel_id) pairs across all users
                // (IdentityResolver maps these to user_id — duplicate entries let one
                // user impersonate another via overwrite semantics, R14 Warning).
                if !seen_channels.insert((kind.clone(), id.clone())) {
                    return invalid(
                        "duplicate (channel-kind, channel-id) pair across users[] (identity-spoofing attack surface)",
                    );
                }
            }
        }
    }

    // --- Secrets: env-var-name must be a plausible env var name and not OS-reserved ---
    check_nonempty("secrets.env-var-name", &cfg.secrets.env_var_name)?;
    let name = cfg.secrets.env_var_name.as_str();
    if !name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return invalid("secrets.env-var-name must contain only A-Z, 0-9, underscore");
    }
    if name.len() > 256 {
        return invalid("secrets.env-var-name must be <= 256 characters");
    }
    // Deny OS-reserved names that an attacker could target to misdirect key lookup.
    const RESERVED: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "PWD",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "RUST_BACKTRACE",
    ];
    if RESERVED.contains(&name) {
        return invalid("secrets.env-var-name must not be an OS-reserved name");
    }

    // --- PostProcessor: non-empty model + cooldown bounded ---
    check_nonempty("post-processor.llm-model", &cfg.post_processor.llm_model)?;
    if cfg.post_processor.llm_failure_cooldown_seconds > 86_400 {
        return invalid("post-processor.llm-failure-cooldown-seconds must be <= 86400 (1 day)");
    }

    // --- GitConfig: gc interval and tracked-file threshold bounded ---
    if cfg.git.gc_interval_hours == 0 || cfg.git.gc_interval_hours > 8_760 {
        return invalid("git.gc_interval_hours must be in (0, 8760] (1 year)");
    }
    if cfg.git.max_tracked_file_mb == 0 || cfg.git.max_tracked_file_mb > 4096 {
        return invalid("git.max_tracked_file_mb must be in (0, 4096]");
    }

    // --- DatabaseConfig (Slice AE): db-path non-empty/non-whitespace/no-NUL
    //     via check_nonempty + Path::is_absolute() rejection + `..` segment
    //     rejection (Adversarial R1 W2); pool-size 1..=256. ---
    // The 256 cap is a defensive ceiling. Typical SQLite advice is 4-50
    // simultaneous connections (rusqlite default pool size = 10); 256 is ~5×
    // headroom while preventing pathological config from exhausting fd limits
    // or contention. Not a PRD-imposed bound; a Slice-AE policy choice.
    check_nonempty("database.db-path", &cfg.database.db_path)?;
    // Adversarial R1 W2: reject absolute paths and `..` traversal segments.
    // A tampered runtime-config.yaml could otherwise redirect SQLite to any
    // attacker-chosen filesystem location (`/etc/index.db`, `../../../...`).
    // The bootstrap layer joins db-path onto the workspace root, but
    // `Path::join` with an absolute argument REPLACES the root, so the cap
    // must live in the validation layer.
    if std::path::Path::new(&cfg.database.db_path).is_absolute() {
        return invalid("database.db-path must be relative to the workspace root (absolute paths are rejected to prevent tampered-config redirection)");
    }
    if cfg
        .database
        .db_path
        .split(['/', '\\'])
        .any(|seg| seg == "..")
    {
        return invalid("database.db-path must not contain `..` segments (path traversal is rejected to prevent tampered-config redirection)");
    }
    if cfg.database.pool_size == 0 || cfg.database.pool_size > 256 {
        return invalid("database.pool-size must be in [1, 256]");
    }

    // Slice G (AC-19): bounds for the new tunable knobs.
    // 8192 is a defensive upper bound on embedding dimensions; production
    // models max around 4096 dims (Anthropic Voyage). 8192 is ~2× headroom
    // and far below sqlite-vec's BLOB size cap (~268M f32 components).
    if cfg.database.embedding_dim == 0 || cfg.database.embedding_dim > 8192 {
        return invalid("database.embedding-dim must be in [1, 8192]");
    }
    // 10 caps the path-explosion factor and ancestor-fold worst-case
    // allocation in recall.rs. PRD §8.3.4 default is 3.
    if cfg.database.recall_max_depth == 0 || cfg.database.recall_max_depth > 10 {
        return invalid("database.recall-max-depth must be in [1, 10]");
    }

    // --- ToolsConfig (Slice m017-B): all three numeric fields must be > 0.
    // Defense-in-depth against a tampered runtime-config.yaml supplying 0 for
    // any of these:
    //   - max-tool-instances: 0 would panic at `NonZeroUsize::new(0).expect(...)`
    //     when LazyToolRegistry constructs its LRU cache.
    //   - lazy-load-timeout-sec: 0 makes every `tokio::time::timeout` fire
    //     immediately and every WASM load surface as "load timeout".
    //   - max-result-bytes: 0 rejects every non-empty tool result with
    //     `OutputValidationFailed`, silently disabling all tool I/O.
    // Each is a config-supplied DoS knob. The upper bounds mirror per-field
    // sanity ceilings: max-tool-instances at 1024 (well above the §2.10
    // default of 20), lazy-load-timeout-sec at 600 (10 minutes — anything
    // longer breaks the runtime's responsiveness contract),
    // max-result-bytes at 1 GiB (well above the §2.10 default of 16 MiB
    // and any reasonable WASM result payload).
    if cfg.tools.max_tool_instances == 0 || cfg.tools.max_tool_instances > 1024 {
        return invalid("tools.max-tool-instances must be in [1, 1024]");
    }
    if cfg.tools.lazy_load_timeout_sec == 0 || cfg.tools.lazy_load_timeout_sec > 600 {
        return invalid("tools.lazy-load-timeout-sec must be in [1, 600]");
    }
    if cfg.tools.max_result_bytes == 0 || cfg.tools.max_result_bytes > 1024 * 1024 * 1024 {
        return invalid("tools.max-result-bytes must be in [1, 1073741824] (1 GiB)");
    }
    // Slice m017-C — bound the Slice C additive fields (adversarial round
    // 1 fix C4). `tool-invoke-timeout-sec` capped at 600 (same ceiling as
    // lazy-load); `bring-up-describe-timeout-sec` shorter at 60 (describe
    // is expected to be near-constant-time). `tool-fuel-per-call` is
    // Option<u64> — None means disabled; Some(N) must be > 0.
    if cfg.tools.tool_invoke_timeout_sec == 0 || cfg.tools.tool_invoke_timeout_sec > 600 {
        return invalid("tools.tool-invoke-timeout-sec must be in [1, 600]");
    }
    if cfg.tools.bring_up_describe_timeout_sec == 0 || cfg.tools.bring_up_describe_timeout_sec > 60
    {
        return invalid("tools.bring-up-describe-timeout-sec must be in [1, 60]");
    }
    if let Some(fuel) = cfg.tools.tool_fuel_per_call {
        if fuel == 0 {
            return invalid("tools.tool-fuel-per-call must be > 0 when set (use null to disable)");
        }
    }

    // --- SecurityConfig (Wave-16 Lane-4, MODULE-012 AC-17): bounded ranges
    // (lower AND upper) on every knob, fail-closed. These are DoS safety
    // CEILINGS — a hot-reloaded over-large value would defeat the protection,
    // so each carries a sane upper bound, not just `> 0`. Mirrors the database /
    // tools range-validation idiom above.
    //
    // 64 MiB ceiling on scan/message caps: well above the 1 MiB defaults and any
    // realistic payload, far below a memory-DoS regime.
    const SECURITY_MAX_BYTES_CEILING: usize = 64 * 1024 * 1024;
    // 60s ceiling on the DNS timeout (longer hangs every resolve).
    const SECURITY_DNS_TIMEOUT_MS_CEILING: u64 = 60_000;
    // 24h ceiling on the DNS cache TTL.
    const SECURITY_DNS_CACHE_TTL_CEILING: u64 = 86_400;
    // 1M rps ceiling — effectively unlimited but rejects absurd / overflow values.
    const SECURITY_MAX_RPS: f64 = 1_000_000.0;
    if cfg.security.leak_detector.max_scan_bytes == 0
        || cfg.security.leak_detector.max_scan_bytes > SECURITY_MAX_BYTES_CEILING
    {
        return invalid("security.leak_detector.max_scan_bytes must be in [1, 67108864] (64 MiB)");
    }
    if cfg.security.ssrf.dns_timeout_ms == 0
        || cfg.security.ssrf.dns_timeout_ms > SECURITY_DNS_TIMEOUT_MS_CEILING
    {
        return invalid("security.ssrf.dns_timeout_ms must be in [1, 60_000]");
    }
    if cfg.security.ssrf.dns_cache_ttl_seconds > SECURITY_DNS_CACHE_TTL_CEILING {
        return invalid("security.ssrf.dns_cache_ttl_seconds must be in [0, 86_400]");
    }
    // The rate limiter divides the refill interval by `per_component_rps`
    // (`rate_limit.rs`), so 0 / negative / NaN / ∞ is a panic/DoS hazard.
    let rps = cfg.security.rate_limit.per_component_rps;
    if !rps.is_finite() || rps <= 0.0 || rps > SECURITY_MAX_RPS {
        return invalid(
            "security.rate_limit.per_component_rps must be finite and in (0, 1_000_000]",
        );
    }
    if cfg.security.action_validator.max_message_size == 0
        || cfg.security.action_validator.max_message_size > SECURITY_MAX_BYTES_CEILING
    {
        return invalid(
            "security.action_validator.max_message_size must be in [1, 67108864] (64 MiB)",
        );
    }

    Ok(())
}

/// OpenOptions with `O_NOFOLLOW` + `O_NONBLOCK` on Unix to defeat symlink-swap
/// attacks during the TOCTOU window between metadata check and open. Falls back
/// to plain read-only OpenOptions on non-Unix. Leaf-only protection; use
/// `open_file_hardened` on Linux for full-path NO_SYMLINKS resolution.
fn open_options_hardened() -> std::fs::OpenOptions {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    opts
}

/// Open a config file with strongest-available symlink protection.
///
/// On **Linux 5.6+**: uses `openat2(RESOLVE_NO_SYMLINKS)` which atomically refuses
/// to resolve any symlink component — leaf OR ancestor. This closes the parent-
/// directory TOCTOU window that `O_NOFOLLOW` (leaf-only) cannot cover: even if
/// an attacker swaps an ancestor directory to a symlink between the ancestor
/// check and open, the kernel refuses and returns `ELOOP`.
///
/// On **older Linux / macOS / other Unix**: falls back to `OpenOptions` with
/// `O_NOFOLLOW | O_NONBLOCK`. The residual parent-dir TOCTOU gap is documented
/// and accepted (no equivalent primitive on macOS; `openat2` returns `ENOSYS`
/// on pre-5.6 Linux and triggers the fallback).
fn open_file_hardened(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{openat2, Mode, OFlags, ResolveFlags, CWD};
        match openat2(
            CWD,
            path,
            // NONBLOCK preserves the macOS-fallback FIFO-don't-hang guarantee:
            // if an attacker swaps the file to a FIFO between symlink_metadata
            // and this open, open would block waiting for a writer. NOFOLLOW
            // is redundant with NO_SYMLINKS but documents intent. CLOEXEC
            // prevents fd leaking to child processes.
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(fd) => return Ok(std::fs::File::from(fd)),
            Err(e) if e.raw_os_error() == libc::ENOSYS => {
                // openat2 not supported on this kernel; fall through to fallback.
            }
            Err(e) => return Err(std::io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }
    open_options_hardened().open(path)
}

/// Open a directory for use as a pinned parent fd for subsequent `*at`
/// syscalls. Uses `openat2(RESOLVE_NO_SYMLINKS)` which atomically refuses
/// any symlink anywhere in the path — including ancestors — eliminating
/// the canonicalize-follows-symlink attack surface.
///
/// Returns `Err(ErrorKind::Unsupported)` on pre-5.6 Linux (ENOSYS) so the
/// caller can detect and fall back to a pathname-based path.
///
/// NOTE: consumed by crates/cli — do not change signature without cross-
/// crate update.
#[cfg(target_os = "linux")]
pub fn open_dir_hardened(path: &Path) -> std::io::Result<std::fs::File> {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags, CWD};
    match openat2(
        CWD,
        path,
        // NONBLOCK preserves open_file_hardened parity — if an attacker
        // swaps the target to a FIFO between symlink_metadata and this
        // open, NONBLOCK prevents the process from blocking waiting for
        // a writer. O_DIRECTORY would also refuse a FIFO with ENOTDIR,
        // but NONBLOCK makes the contract explicit and uniform.
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(fd) => Ok(std::fs::File::from(fd)),
        Err(e) if e.raw_os_error() == libc::ENOSYS => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "openat2 unavailable (Linux <5.6)",
        )),
        Err(e) => Err(std::io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

/// Load and parse a RuntimeConfig from the given path (sync, used at startup).
///
/// Hardening against the R10–R12 adversarial findings:
///   - `symlink_metadata` (not `metadata`) so a symlink at the path is detected,
///     not followed — defeats the symlink-swap reload attack.
///   - `check_is_regular_file` on symlink_metadata rejects FIFOs/devices/symlinks
///     BEFORE open (open on FIFO blocks waiting for a writer).
///   - `O_NOFOLLOW | O_NONBLOCK` on open closes the TOCTOU window between
///     metadata check and open (symlink/FIFO injected in the race).
///   - Post-open `file.metadata()` re-verifies `is_file()` on the actual fd to
///     catch any residual race.
///   - `take(MAX+1)` streaming read bounds memory regardless of file size.
pub fn load_config(path: &Path) -> Result<RuntimeConfig, ConfigError> {
    use std::io::Read;

    let lmeta = std::fs::symlink_metadata(path).map_err(io_err(path))?;
    check_is_regular_file(path, lmeta.file_type())?;

    let file = open_file_hardened(path).map_err(io_err(path))?;
    // Re-verify on the actual fd: nothing was swapped in under us.
    let fmeta = file.metadata().map_err(io_err(path))?;
    check_is_regular_file(path, fmeta.file_type())?;

    let mut content = String::new();
    let read = file
        .take(MAX_CONFIG_SIZE + 1)
        .read_to_string(&mut content)
        .map_err(io_err(path))?;
    check_size(path, read as u64)?;
    parse_yaml(path, content)
}

/// Async version of `load_config` for use inside `tokio::spawn` tasks.
async fn load_config_async(path: &Path) -> Result<RuntimeConfig, ConfigError> {
    use tokio::io::AsyncReadExt;

    let lmeta = tokio::fs::symlink_metadata(path)
        .await
        .map_err(io_err(path))?;
    check_is_regular_file(path, lmeta.file_type())?;

    // Use hardened open (Linux: openat2 NO_SYMLINKS; else O_NOFOLLOW) and
    // convert to tokio File to keep the kernel-level protection.
    let std_file = open_file_hardened(path).map_err(io_err(path))?;
    let file = tokio::fs::File::from_std(std_file);
    let fmeta = file.metadata().await.map_err(io_err(path))?;
    check_is_regular_file(path, fmeta.file_type())?;

    let mut content = String::new();
    let read = file
        .take(MAX_CONFIG_SIZE + 1)
        .read_to_string(&mut content)
        .await
        .map_err(io_err(path))?;
    check_size(path, read as u64)?;
    parse_yaml(path, content)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileFingerprint {
    modified: Option<SystemTime>,
    len: u64,
    content_hash: u64,
}

fn config_file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    use std::io::Read;

    let lmeta = std::fs::symlink_metadata(path).ok()?;
    check_is_regular_file(path, lmeta.file_type()).ok()?;
    let canonical = std::fs::canonicalize(path).ok()?;
    check_no_ancestor_symlinks_parents(&canonical).ok()?;
    let file = open_file_hardened(&canonical).ok()?;
    let metadata = file.metadata().ok()?;
    check_is_regular_file(&canonical, metadata.file_type()).ok()?;
    let mut bytes = Vec::new();
    let _ = file
        .take(MAX_CONFIG_SIZE + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    Some(FileFingerprint {
        modified: metadata.modified().ok(),
        len: metadata.len(),
        content_hash: hasher.finish(),
    })
}

#[cfg(test)]
mod tests {
    use super::config_file_fingerprint;

    #[test]
    fn fingerprint_changes_for_same_length_content_rewrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("runtime-config.yaml");

        std::fs::write(&path, b"max_memory_pages: 512\n").expect("write first");
        let first = config_file_fingerprint(&path).expect("first fingerprint");

        std::fs::write(&path, b"max_memory_pages: 513\n").expect("write second");
        let second = config_file_fingerprint(&path).expect("second fingerprint");

        assert_eq!(first.len, second.len, "fixture must stay same-length");
        assert_ne!(
            first, second,
            "content hash must distinguish same-length rewrites even if mtime granularity is coarse"
        );
    }

    #[test]
    #[cfg(unix)]
    fn fingerprint_rejects_leaf_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real-config.yaml");
        let link = dir.path().join("runtime-config.yaml");
        std::fs::write(&real, b"max_memory_pages: 512\n").expect("write config");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        assert!(
            config_file_fingerprint(&link).is_none(),
            "poll fingerprint must not follow config-path symlinks"
        );
    }
}

/// Check whether a filesystem event is relevant to the watched config file.
fn is_relevant_event(event: &Event, config_path: &Path) -> bool {
    match event.kind {
        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) => {}
        _ => return false,
    }
    event.paths.iter().any(|p| p == config_path)
}
