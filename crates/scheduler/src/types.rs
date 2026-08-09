//! WIT-shaped Rust data models for MODULE-014 (Slice A).
//!
//! Sources:
//! - PRD §3.3 `runnable` interface (`component-config`, `trigger-context`,
//!   `run-result`, `run-status`).
//! - PRD §9.5 `agent-lifecycle` types (`component-submit-config`,
//!   `trigger-config`, `webhook-config`, `trigger-subscription`,
//!   `trigger-filter`, `restart-policy`, `component-state`, `spawn-error`,
//!   `component-info`, `spawned-kind`).
//!
//! All records use `serde(rename_all = "kebab-case",
//! deny_unknown_fields)`; variants use `serde(rename_all =
//! "kebab-case")`. Wire-format round-trips are locked from day one
//! (Slice A precedent from MODULE-017 `tool-info` / `method-info`).
//!
//! **Acknowledged Slice A deviations from PRD §9.5** (reconciled in
//! Slice B; see plan + MODULE-014 §3.7):
//! - `ComponentType` reuses the 5-variant
//!   `advance_shared_types::component::ComponentType` including the
//!   `Agent` variant, even though PRD §9.5 `submit-component` forbids
//!   `agent`. Admission-time rejection is deferred to Slice B.
//! - `CapRequest` reuses the 1-field
//!   `advance_shared_types::capability::CapRequest` (`{ capability:
//!   CapabilityId }`) lacking PRD §9.5's
//!   `params: option<list<cap-param>>`.
//! - `GrantDraft` and `RetryConfig` collapse to opaque
//!   `serde_json::Value` newtypes pending Slice B reconciliation with
//!   MODULE-013 and MODULE-009 canonical records.
//!
//! Placeholder types (`WasmInstance`, `TrapError`, `SchedulerTick`,
//! `ComponentEvent`) all carry `#[non_exhaustive]` so Slice B can grow
//! their field sets without a breaking change.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use advance_shared_types::capability::CapRequest;
use advance_shared_types::component::ComponentType;
use serde::{Deserialize, Deserializer, Serialize};

// ---- Slice D timestamp helpers (used by submit.rs admission + registry.rs) ----

/// Wall-clock unix-ms reading. Uses `std::time` only; chrono is reserved for
/// the RFC3339 formatter (kept out of the prod `clock` feature so we don't
/// pull `iana-time-zone` / `android-tzdata` into the prod dep graph).
///
/// Returns `0` if `SystemTime::now()` is before `UNIX_EPOCH` (unreachable on
/// any conformant clock; fail-safe rather than panic).
pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Format a unix-millisecond timestamp as an RFC3339 string with millisecond
/// precision and `Z` UTC suffix (e.g. `"2026-05-15T08:00:00.000Z"`).
///
/// Semantics (per Slice D round-3 evaluator correction):
/// - Moderate negative inputs produce VALID pre-1970 datetimes
///   (`format_rfc3339_ms(-1)` → `"1969-12-31T23:59:59.999Z"`).
/// - The epoch fallback fires ONLY for genuinely out-of-range values that
///   exceed chrono's `NaiveDateTime` ±262143-year span — in practice near
///   `i64::MAX` and `i64::MIN` (~292 million years from epoch).
pub fn format_rfc3339_ms(unix_ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_ms)
        .unwrap_or_else(|| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0)
                .expect("epoch is always representable")
        })
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ---- Bounded-Deserialize helpers ----
// Adversarial evaluator Round 1 surfaced that bare-`String` /
// `list<u8>` wire fields lacked Deserialize-time caps; without
// validation an attacker controlling JSON could allocate
// arbitrary-sized strings or byte buffers BEFORE any admission code
// runs. These helpers add fail-closed caps used by every wire-shape
// record's custom Deserialize.

fn deserialize_bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_WIRE_STRING_LEN {
        return Err(serde::de::Error::custom(format!(
            "string field length {} exceeds MAX_WIRE_STRING_LEN {}",
            s.len(),
            MAX_WIRE_STRING_LEN
        )));
    }
    Ok(s)
}

fn deserialize_bounded_string_opt<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    if let Some(ref inner) = s {
        if inner.len() > MAX_WIRE_STRING_LEN {
            return Err(serde::de::Error::custom(format!(
                "optional string field length {} exceeds MAX_WIRE_STRING_LEN {}",
                inner.len(),
                MAX_WIRE_STRING_LEN
            )));
        }
    }
    Ok(s)
}

fn deserialize_bounded_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let b = Vec::<u8>::deserialize(deserializer)?;
    if b.len() > MAX_WIRE_BYTES_LEN {
        return Err(serde::de::Error::custom(format!(
            "byte field length {} exceeds MAX_WIRE_BYTES_LEN {}",
            b.len(),
            MAX_WIRE_BYTES_LEN
        )));
    }
    Ok(b)
}

fn deserialize_bounded_bytes_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let b: Option<Vec<u8>> = Option::deserialize(deserializer)?;
    if let Some(ref inner) = b {
        if inner.len() > MAX_WIRE_BYTES_LEN {
            return Err(serde::de::Error::custom(format!(
                "optional byte field length {} exceeds MAX_WIRE_BYTES_LEN {}",
                inner.len(),
                MAX_WIRE_BYTES_LEN
            )));
        }
    }
    Ok(b)
}

fn deserialize_bounded_chain_depth<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let n = u32::deserialize(deserializer)?;
    if n > MAX_TRIGGER_CHAIN_DEPTH {
        return Err(serde::de::Error::custom(format!(
            "chain_depth {} exceeds MAX_TRIGGER_CHAIN_DEPTH {}",
            n, MAX_TRIGGER_CHAIN_DEPTH
        )));
    }
    Ok(n)
}

fn deserialize_bounded_debounce<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    let n: Option<u32> = Option::deserialize(deserializer)?;
    if let Some(ms) = n {
        if ms > MAX_DEBOUNCE_MS {
            return Err(serde::de::Error::custom(format!(
                "debounce_ms {} exceeds MAX_DEBOUNCE_MS {}",
                ms, MAX_DEBOUNCE_MS
            )));
        }
    }
    Ok(n)
}

/// Slice C adversarial round 2 fix (W5): cap `ComponentSubmitConfig.delay`
/// at Deserialize time so an attacker submitting `delay: u64::MAX` cannot
/// pin a TaskRunner task indefinitely (`Duration::from_millis(u64::MAX)`
/// ≈ 584 million years). 7-day ceiling matches the practical
/// operational ceiling for delayed-task admission.
fn deserialize_bounded_delay<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let n: Option<u64> = Option::deserialize(deserializer)?;
    if let Some(ms) = n {
        if ms > MAX_TASK_DELAY_MS {
            return Err(serde::de::Error::custom(format!(
                "delay {} ms exceeds MAX_TASK_DELAY_MS {}",
                ms, MAX_TASK_DELAY_MS
            )));
        }
    }
    Ok(n)
}

fn deserialize_bounded_paths<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Option<Vec<String>> = Option::deserialize(deserializer)?;
    if let Some(ref paths) = v {
        if paths.len() > MAX_AFFECTED_PATHS {
            return Err(serde::de::Error::custom(format!(
                "affected_paths length {} exceeds MAX_AFFECTED_PATHS {}",
                paths.len(),
                MAX_AFFECTED_PATHS
            )));
        }
        for p in paths {
            if p.len() > MAX_WIRE_STRING_LEN {
                return Err(serde::de::Error::custom(format!(
                    "affected_paths entry length {} exceeds MAX_WIRE_STRING_LEN {}",
                    p.len(),
                    MAX_WIRE_STRING_LEN
                )));
            }
        }
    }
    Ok(v)
}

fn deserialize_bounded_capabilities<'de, D>(deserializer: D) -> Result<Vec<CapRequest>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<CapRequest> = Vec::deserialize(deserializer)?;
    if v.len() > MAX_CAPABILITIES {
        return Err(serde::de::Error::custom(format!(
            "capabilities length {} exceeds MAX_CAPABILITIES {}",
            v.len(),
            MAX_CAPABILITIES
        )));
    }
    for c in &v {
        // CapabilityId is `#[serde(transparent)]` over `String` in
        // shared-types; the scheduler enforces a length cap here per
        // adversarial Round 2 finding W6 (shared-types lacks the cap
        // and Slice B may push it upstream).
        if c.capability.as_ref().len() > MAX_CAPABILITY_ID_LEN {
            return Err(serde::de::Error::custom(format!(
                "capabilities[].capability length {} exceeds MAX_CAPABILITY_ID_LEN {}",
                c.capability.as_ref().len(),
                MAX_CAPABILITY_ID_LEN
            )));
        }
    }
    Ok(v)
}

/// Wave-20 (MODULE-012-AC-10 source): bounded deserialize for
/// `ComponentSubmitConfig.sensitive_params`. Mirrors the
/// `deserialize_bounded_capabilities` discipline — fail-closed caps on BOTH the
/// list width ([`MAX_SENSITIVE_PARAMS`]) and per-entry name length
/// ([`MAX_SENSITIVE_PARAM_NAME_LEN`]), rejecting oversize at deserialize time
/// (NOT truncating). This externally-supplied wire field would otherwise allow
/// unbounded `Vec<String>` allocation before any admission code runs.
fn deserialize_bounded_sensitive_params<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<String> = Vec::deserialize(deserializer)?;
    if v.len() > MAX_SENSITIVE_PARAMS {
        return Err(serde::de::Error::custom(format!(
            "sensitive_params length {} exceeds MAX_SENSITIVE_PARAMS {}",
            v.len(),
            MAX_SENSITIVE_PARAMS
        )));
    }
    for name in &v {
        if name.len() > MAX_SENSITIVE_PARAM_NAME_LEN {
            return Err(serde::de::Error::custom(format!(
                "sensitive_params[].name length {} exceeds MAX_SENSITIVE_PARAM_NAME_LEN {}",
                name.len(),
                MAX_SENSITIVE_PARAM_NAME_LEN
            )));
        }
    }
    Ok(v)
}

fn deserialize_bounded_initial_grants<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<GrantDraft>>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Option<Vec<GrantDraft>> = Option::deserialize(deserializer)?;
    if let Some(ref grants) = v {
        if grants.len() > MAX_INITIAL_GRANTS {
            return Err(serde::de::Error::custom(format!(
                "initial_grants length {} exceeds MAX_INITIAL_GRANTS {}",
                grants.len(),
                MAX_INITIAL_GRANTS
            )));
        }
    }
    Ok(v)
}

fn deserialize_bounded_any_of<'de, D>(deserializer: D) -> Result<Vec<TriggerConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<TriggerConfig> = Vec::deserialize(deserializer)?;
    if v.len() > MAX_ANY_OF {
        return Err(serde::de::Error::custom(format!(
            "any_of length {} exceeds MAX_ANY_OF {}",
            v.len(),
            MAX_ANY_OF
        )));
    }
    Ok(v)
}

// ---- Type aliases ----

/// Slice A-local alias: keeps storage shape readable. Slice B may
/// promote to a newtype if MODULE-019's EventBus formalizes one.
pub type EventType = String;

// ---- Cap constants ----

/// Per-event-type subscription cap. Defends against a single
/// pathological event-type filling the by-event index.
pub const MAX_SUBSCRIPTIONS_PER_EVENT_TYPE: usize = 10_000;

/// Distinct-event-type cap. Defends against attackers proliferating
/// fresh event-types to exhaust the HashMap bucket count.
pub const MAX_EVENT_TYPES: usize = 1_024;

/// Hard cap on caller-supplied `max_chain_depth`. Caller-supplied
/// values above this are clamped (defense against `u32::MAX` exhausting
/// visited-set memory).
pub const MAX_CHAIN_DEPTH_HARD_CAP: u32 = 1_000;

/// Maximum permitted UTF-8 byte length of an event-type string.
/// Subscriptions with longer event_type fields are rejected
/// fail-closed by `validate_subscription`. Slice A pins **bytes** (not
/// grapheme clusters); the 12 PRD §3.8 whitelist entries are all ASCII
/// so byte-length and char-length agree there. Slice B may switch the
/// unit if non-ASCII event types are introduced.
pub const MAX_EVENT_TYPE_LEN: usize = 128;

/// Maximum permitted UTF-8 byte length of a component ID.
/// `ComponentId::new` fail-closed rejects longer values. Bytes, not
/// grapheme clusters — same rationale as `MAX_EVENT_TYPE_LEN`.
pub const MAX_COMPONENT_ID_LEN: usize = 256;

/// Maximum permitted UTF-8 byte length of any bare `String` wire field
/// on a Slice A WIT-shaped record (e.g. `ComponentConfig.id`,
/// `TriggerContext.trigger_chain_id`, `TriggerFilter.*`,
/// `ComponentSubmitConfig.id`, `WebhookConfig.path/secret`,
/// `ComponentInfo.created_at`, `TriggerConfig::Schedule/FileWatch`
/// payloads, `SpawnError::*(String)` / `ComponentState::Failed(String)`
/// / `RunStatus::Failed(String)` variants). Custom Deserialize on
/// each record enforces this cap fail-closed.
/// Bytes, not grapheme clusters.
pub const MAX_WIRE_STRING_LEN: usize = 4_096;

/// Maximum permitted byte length of any `list<u8>` wire field
/// (`TriggerContext.payload`, `ComponentSubmitConfig.binary`,
/// `RunResult.output`, `ComponentConfig.config_data`). Custom
/// Deserialize on each record enforces this cap fail-closed.
/// 64 MiB is enough to ship a moderate WASM binary while preventing
/// the gigabyte-scale serde_json allocation attack identified by the
/// adversarial evaluator. Slice B may revisit per workload data.
pub const MAX_WIRE_BYTES_LEN: usize = 64 * 1024 * 1024;

/// Maximum permitted `trigger_chain_id` chain depth on the wire.
/// Reuses `MAX_CHAIN_DEPTH_HARD_CAP` (1 000) as the hard ceiling —
/// even though `check_chain` already clamps, the wire field is bounded
/// at Deserialize time to prevent attacker-chosen `u32::MAX` flowing
/// into Slice B's chain-increment logic where `+1` would wrap.
pub const MAX_TRIGGER_CHAIN_DEPTH: u32 = MAX_CHAIN_DEPTH_HARD_CAP;

/// Maximum permitted `debounce_ms` on a `TriggerSubscription`. Caps
/// the debounce at 1 hour to prevent attacker "subscribe and silently
/// swallow events for 49 days" via `u32::MAX` (the adversarial
/// evaluator finding W12). Slice B may revisit if longer debounces
/// are needed.
pub const MAX_DEBOUNCE_MS: u32 = 3_600_000;

/// Slice C adversarial round 2 fix (W5): 7-day ceiling on
/// `ComponentSubmitConfig.delay`. The bounded-deserialize helper rejects
/// configs whose `delay` exceeds this cap with a fail-closed Serde error,
/// preventing the `Duration::from_millis(u64::MAX)` ≈ 584M-year sleep
/// pin. 7 days matches the practical operational ceiling for
/// delayed-task admission.
pub const MAX_TASK_DELAY_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Maximum permitted entries in a `TriggerFilter.affected_paths` list.
/// Defends against per-subscription memory amplification — the bus's
/// MAX_SUBSCRIPTIONS_PER_EVENT_TYPE × MAX_EVENT_TYPES caps only count
/// subscriptions, not their payload sizes (adversarial evaluator
/// finding W7).
pub const MAX_AFFECTED_PATHS: usize = 1_024;

/// Maximum permitted entries in a `ComponentSubmitConfig.capabilities`
/// list. Defends against `Vec<CapRequest>` width DoS at Deserialize
/// time (adversarial Round 2 finding C1).
pub const MAX_CAPABILITIES: usize = 256;

/// Maximum permitted entries in a `ComponentSubmitConfig.initial_grants`
/// list. Defends against `Vec<GrantDraft>` width DoS at Deserialize
/// time (adversarial Round 2 finding C1).
pub const MAX_INITIAL_GRANTS: usize = 256;

/// Maximum permitted entries in a `ComponentSubmitConfig.sensitive_params`
/// list (Wave-20, MODULE-012-AC-10 source). Width-DoS cap at Deserialize time.
pub const MAX_SENSITIVE_PARAMS: usize = 64;

/// Maximum permitted byte length of a single `sensitive_params` entry name
/// (Wave-20). Per-entry length cap at Deserialize time.
pub const MAX_SENSITIVE_PARAM_NAME_LEN: usize = 128;

/// Maximum permitted entries in a `TriggerConfig::AnyOf` vector.
/// Defends against unbounded-width recursive enum allocation
/// (adversarial Round 2 finding C2).
pub const MAX_ANY_OF: usize = 64;

/// Maximum permitted total subscriptions across the entire
/// `TriggerBusDispatchImpl` (aggregate across all event types).
/// Defends against memory amplification via the cartesian product of
/// per-event and distinct-event caps with per-record payload (W3).
pub const MAX_TOTAL_SUBSCRIPTIONS: usize = 100_000;

/// Maximum permitted UTF-8 byte length of a `CapabilityId` inside
/// `ComponentSubmitConfig.capabilities`. The shared-types
/// `CapabilityId` Deserialize is transparent + uncapped; the
/// scheduler enforces this cap when consuming the field
/// (adversarial Round 2 finding W6). Slice B may push the cap into
/// shared-types once a workspace policy emerges.
pub const MAX_CAPABILITY_ID_LEN: usize = 256;

/// Maximum serialized byte size of a `GrantDraft` or `RetryConfig`
/// opaque `serde_json::Value` payload. Defends against unbounded
/// `Value::deserialize` allocation at deserialize time (adversarial
/// Round 3 finding C1) — without this cap an attacker could submit
/// a `ComponentSubmitConfig` with 256 grant drafts each containing
/// a multi-GB nested JSON value. The check runs after Value parsing
/// (so peak parse memory is unbounded), but the stored value is
/// bounded — Slice B will move this check earlier via a
/// streaming-deserializer or a typed grant-draft schema.
pub const MAX_OPAQUE_VALUE_BYTES: usize = 16 * 1024; // 16 KiB

/// Default per-agent `max-scheduled-components` quota (REQ-057 / MODULE-014
/// §1.5 AC-09). Mirrors §2.10 config key
/// `scheduler.max_scheduled_components_default` = 20. `InMemoryComponentSubmitApi`
/// rejects a submitter's submit once their in-memory admission-store row count
/// reaches this cap (`SpawnError::ResourceLimit`). Slice E (m014-slice-e).
pub const DEFAULT_MAX_SCHEDULED_COMPONENTS: usize = 20;

/// Default expired-task catch-up concurrency cap (REQ-058 / MODULE-014 §1.5
/// AC-10). Mirrors §2.10 config key `scheduler.max_concurrent_catchup` = 3.
/// `TaskRunner::run_expired_catchup_default` binds this value into the
/// `tokio::sync::Semaphore` bound so at most this many overdue rows are
/// dispatched concurrently per catch-up invocation. Slice E (m014-slice-e).
pub const DEFAULT_MAX_CONCURRENT_CATCHUP: usize = 3;

// ---- Newtypes ----

/// Stable identifier for components managed by the scheduler.
/// `Hash + Eq` so it can key HashMaps / HashSets.
///
/// **Deserialize honors `MAX_COMPONENT_ID_LEN`** — the custom impl
/// below runs the same length cap as `ComponentId::new`, closing the
/// audit-Round-5 finding that derived `#[serde(transparent)]
/// Deserialize` bypassed the fail-closed constructor when input came
/// from JSON (e.g. attacker-controlled `ComponentInfo.id` over the
/// wire).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ComponentId(pub String);

impl ComponentId {
    /// Fail-closed construction: rejects strings longer than
    /// `MAX_COMPONENT_ID_LEN`.
    pub fn new(s: String) -> Result<Self, SpawnError> {
        if s.len() > MAX_COMPONENT_ID_LEN {
            return Err(SpawnError::InvalidConfig(format!(
                "component id length {} exceeds MAX_COMPONENT_ID_LEN {}",
                s.len(),
                MAX_COMPONENT_ID_LEN
            )));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ComponentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(|e| match e {
            SpawnError::InvalidConfig(m) => serde::de::Error::custom(m),
            _ => serde::de::Error::custom("invalid component id"),
        })
    }
}

/// Identifies a single trigger chain across the visited-set cycle
/// detection. Hash + Eq for HashMap usage.
///
/// **Deserialize honors a length cap reusing `MAX_COMPONENT_ID_LEN`**
/// — trigger-chain ids are similar-shape opaque strings; capping at
/// the same boundary prevents an attacker who controls the wire
/// payload from filling the visited-set HashMap with arbitrary-length
/// keys. Slice B may introduce a distinct `MAX_TRIGGER_CHAIN_ID_LEN`
/// constant if the cap shapes diverge.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TriggerChainId(pub String);

impl TriggerChainId {
    /// Fail-closed construction: rejects strings longer than
    /// `MAX_COMPONENT_ID_LEN` (reused as the trigger-chain-id ceiling
    /// in Slice A).
    pub fn new(s: String) -> Result<Self, SpawnError> {
        if s.len() > MAX_COMPONENT_ID_LEN {
            return Err(SpawnError::InvalidConfig(format!(
                "trigger chain id length {} exceeds MAX_COMPONENT_ID_LEN {}",
                s.len(),
                MAX_COMPONENT_ID_LEN
            )));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TriggerChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(|e| match e {
            SpawnError::InvalidConfig(m) => serde::de::Error::custom(m),
            _ => serde::de::Error::custom("invalid trigger chain id"),
        })
    }
}

/// Stable identifier for a `TriggerBusDispatch` subscription, returned
/// by `subscribe` and consumed by `unsubscribe`. Hash + Eq + Copy
/// (small u64) for HashMap usage.
///
/// Slice A reserves `SubscriptionId::REJECTED` (`u64::MAX`) as the
/// sentinel returned by `TriggerBusDispatch::subscribe` on admission
/// failure — the canonical CONTRACT-131 signature has no error channel,
/// so the sentinel is the only way to surface rejection. Callers MUST
/// compare against `SubscriptionId::REJECTED` before relying on the
/// returned ID. Slice B widens the trait to `Result<SubscriptionId,
/// SpawnError>` via /spec, after which this sentinel is removed.
///
/// **Deserialize rejects `u64::MAX`** so attacker-controlled wire
/// input cannot forge the REJECTED sentinel and confuse callers
/// (adversarial evaluator Round 1 finding C3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SubscriptionId(pub u64);

impl SubscriptionId {
    /// Sentinel value returned by `TriggerBusDispatch::subscribe` when
    /// admission fails. Removed in Slice B once the trait widens to
    /// `Result<SubscriptionId, SpawnError>`.
    pub const REJECTED: SubscriptionId = SubscriptionId(u64::MAX);
}

impl<'de> Deserialize<'de> for SubscriptionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let n = u64::deserialize(deserializer)?;
        if n == u64::MAX {
            return Err(serde::de::Error::custom(
                "SubscriptionId(u64::MAX) is reserved as the REJECTED sentinel",
            ));
        }
        Ok(Self(n))
    }
}

// ---- PRD §3.3 runnable types ----

/// PRD §3.3 `component-config`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ComponentConfig {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub id: String,
    #[serde(deserialize_with = "deserialize_bounded_bytes_opt", default)]
    pub config_data: Option<Vec<u8>>,
    pub trigger_context: Option<TriggerContext>,
}

/// PRD §3.3 `trigger-context`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TriggerContext {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub event_type: String,
    pub timestamp: u64,
    #[serde(deserialize_with = "deserialize_bounded_bytes")]
    pub payload: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub trigger_chain_id: String,
    #[serde(deserialize_with = "deserialize_bounded_chain_depth")]
    pub chain_depth: u32,
}

/// PRD §3.3 `run-result`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RunResult {
    pub status: RunStatus,
    #[serde(deserialize_with = "deserialize_bounded_bytes_opt", default)]
    pub output: Option<Vec<u8>>,
}

/// PRD §3.3 `run-status` variant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    Completed,
    Failed(String),
}

// ---- PRD §9.5 agent-lifecycle types ----

/// PRD §9.5 `component-submit-config`. **Slice A deviations**: see
/// module-level rustdoc — `component_type` allows the `Agent` variant
/// at wire-shape level despite PRD forbidding it; `capabilities` uses
/// the 1-field shared-types `CapRequest`; `initial_grants` / `retry`
/// collapse to opaque JSON newtypes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ComponentSubmitConfig {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub id: String,
    pub component_type: ComponentType,
    #[serde(deserialize_with = "deserialize_bounded_bytes")]
    pub binary: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bounded_capabilities")]
    pub capabilities: Vec<CapRequest>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub output_dir: Option<String>,
    pub trigger: Option<TriggerConfig>,
    pub restart_policy: Option<RestartPolicy>,
    #[serde(deserialize_with = "deserialize_bounded_delay", default)]
    pub delay: Option<u64>,
    #[serde(deserialize_with = "deserialize_bounded_initial_grants", default)]
    pub initial_grants: Option<Vec<GrantDraft>>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub preset: Option<String>,
    pub retry: Option<RetryConfig>,
    /// Wave-20 (MODULE-012-AC-10 source): parameter names whose values are
    /// redacted to `[REDACTED]` on the MODULE-019 EventBus observability sinks
    /// (debug-logs / audit-records / dashboard-events). Additive + back-compat:
    /// absent in older configs → empty default under `deny_unknown_fields`.
    /// Bounded-deserialized (width + per-name length). CONTRACT-217 v0.2 carries
    /// the list through the M005 WIT boundary; the production scheduler bridge
    /// persists it and publishes the committed declaration to EventBus.
    #[serde(deserialize_with = "deserialize_bounded_sensitive_params", default)]
    pub sensitive_params: Vec<String>,
}

/// PRD §9.5 `trigger-config` variant.
///
/// Clippy's `large_enum_variant` lint is silenced here: the WIT wire
/// shape declared in PRD §9.5 is unboxed (5 sibling variants forming
/// the `trigger-config` sum type), and boxing `TriggerEvent` to
/// shrink the enum would change the serde representation in a way
/// that breaks round-trip compatibility with PRD-spec'd JSON. Slice B
/// may revisit if the size pressure (≈256 bytes per variant) becomes
/// measurable in production; the smaller of two evils is to keep
/// the wire shape faithful and accept the discriminator size.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriggerConfig {
    Schedule(String),
    FileWatch(String),
    Webhook(WebhookConfig),
    AnyOf(#[serde(deserialize_with = "deserialize_bounded_any_of")] Vec<TriggerConfig>),
    TriggerEvent(TriggerSubscription),
}

/// PRD §9.5 `webhook-config`.
///
/// **`secret` is redacted in Debug** (adversarial Round 1 finding W6)
/// — the field is excluded via a custom Debug impl so accidental
/// logging via `tracing` / `eprintln!("{:?}", config)` does not leak
/// the HMAC secret to stdout / stderr / log aggregators. Slice B may
/// upgrade to `secrecy::SecretString` if the workspace adds that dep.
///
/// **Serialize is NOT redacted** (adversarial Round 3 finding W3,
/// accepted-with-rustdoc-warning): the PRD §9.5 wire shape includes
/// `secret`, so `serde_json::to_string(&config)` must round-trip
/// faithfully for component-registry persistence (Slice B). The
/// asymmetry — Debug redacts but Serialize doesn't — means callers
/// must NOT serialize a `WebhookConfig` to a transport that does
/// not enforce ciphertext-at-rest. Production code paths that
/// persist or transmit `ComponentSubmitConfig` MUST encrypt the
/// payload BEFORE Serialize, or Slice B must move the secret into
/// a separate vault-backed reference.
#[allow(clippy::doc_markdown)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct WebhookConfig {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub path: String,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub secret: Option<String>,
}

impl std::fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("path", &self.path)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// PRD §9.5 `trigger-subscription` (verbatim field set — no
/// `component_id` field; the MODULE-014 §1.4.3 pseudocode reference to
/// `sub.component_id` is reconciled in Slice B).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TriggerSubscription {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub event_type: String,
    pub filter: Option<TriggerFilter>,
    #[serde(deserialize_with = "deserialize_bounded_debounce", default)]
    pub debounce_ms: Option<u32>,
}

/// PRD §9.5 `trigger-filter`. All fields optional per the canonical
/// record shape. All string fields and the `affected_paths` list are
/// bounded at Deserialize time (adversarial Round 1 findings C1 / W7).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TriggerFilter {
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub id: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub parent_id: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub child_id: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub agent_id: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub run_id: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub component_id: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub capability: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_string_opt", default)]
    pub trigger_type: Option<String>,
    pub component_type: Option<ComponentType>,
    pub spawned_kind: Option<SpawnedKind>,
    #[serde(deserialize_with = "deserialize_bounded_paths", default)]
    pub affected_paths: Option<Vec<String>>,
}

/// PRD §9.5 `restart-policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    Never,
    OnFailure,
    Always,
}

/// PRD §9.5 `component-state`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentState {
    Pending,
    Running,
    Completed,
    Failed(String),
    Killed,
}

/// PRD §9.5 `spawn-error`. All 5 variants per the canonical shape.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpawnError {
    CapabilityDenied(String),
    InvalidConfig(String),
    ResourceLimit(String),
    AlreadyExists(String),
    SubsetViolation(String),
}

/// PRD §9.5 `component-info`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ComponentInfo {
    pub id: ComponentId,
    pub component_type: ComponentType,
    pub status: ComponentState,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub created_at: String,
}

/// PRD §9.5 `spawned-kind` (used by `component.spawned` event filter).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpawnedKind {
    Child,
    Sub,
    Component,
}

// ---- Slice A nested-record placeholders ----

/// Slice A placeholder for PRD §9.5 `grant-draft`. Real shape reconciles
/// with MODULE-013 in Slice B.
///
/// **Custom Deserialize bounds the opaque Value payload at
/// `MAX_OPAQUE_VALUE_BYTES` (16 KiB serialized)** — without the cap an
/// attacker could submit a multi-GB nested JSON value at Deserialize
/// time (adversarial Round 3 finding C1).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GrantDraft(pub serde_json::Value);

impl<'de> Deserialize<'de> for GrantDraft {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer)?;
        let size = v.to_string().len();
        if size > MAX_OPAQUE_VALUE_BYTES {
            return Err(serde::de::Error::custom(format!(
                "GrantDraft payload size {} exceeds MAX_OPAQUE_VALUE_BYTES {}",
                size, MAX_OPAQUE_VALUE_BYTES
            )));
        }
        Ok(GrantDraft(v))
    }
}

/// Slice A placeholder for PRD §9.5 `retry-config`. Real shape
/// reconciles with MODULE-009 cap-llm `retry-config` in Slice B.
///
/// **Custom Deserialize bounds the opaque Value payload at
/// `MAX_OPAQUE_VALUE_BYTES` (16 KiB serialized)** — same rationale as
/// `GrantDraft`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RetryConfig(pub serde_json::Value);

impl<'de> Deserialize<'de> for RetryConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer)?;
        let size = v.to_string().len();
        if size > MAX_OPAQUE_VALUE_BYTES {
            return Err(serde::de::Error::custom(format!(
                "RetryConfig payload size {} exceeds MAX_OPAQUE_VALUE_BYTES {}",
                size, MAX_OPAQUE_VALUE_BYTES
            )));
        }
        Ok(RetryConfig(v))
    }
}

// ---- Placeholder types for trait parameters ----

/// Slice A placeholder: real shape is a `wasmtime` instance handle
/// owned by MODULE-001 runtime. `AgentLoopDriver` receives this as an
/// opaque value in Slice A and does not inspect it.
#[derive(Debug)]
#[non_exhaustive]
pub struct WasmInstance {
    pub component_id: ComponentId,
}

impl WasmInstance {
    /// Slice B: public constructor so external test crates can build a
    /// placeholder instance for trait/driver wiring tests. The real
    /// wasmtime handle is part of the MODULE-001 runtime integration
    /// scaffolding declared in `waived_scope` alongside the AC-13 /
    /// AC-14 / AC-15 / AC-19 driver-loop integration points.
    pub fn new(component_id: ComponentId) -> Self {
        Self { component_id }
    }
}

/// Slice A placeholder: trap classification refined when Slice B wires
/// the real trap handler.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum TrapError {
    Crash(String),
    Cancelled,
}

/// Slice A placeholder: scheduler-extension tick payload.
/// MODULE-015 AutoLoopDriver consumes this in its own slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SchedulerTick {
    pub now_ms: u64,
}

impl SchedulerTick {
    /// Slice m015-A: public constructor so the out-of-crate
    /// `advance-scheduler-auto-loop` test crate can build a tick despite
    /// `#[non_exhaustive]` (cross-crate struct-literal is forbidden —
    /// rustc E0639). Mirrors the existing `WasmInstance::new` precedent.
    /// Additive — no breaking change.
    pub fn new(now_ms: u64) -> Self {
        Self { now_ms }
    }
}

/// Slice A placeholder: component lifecycle events delivered to
/// `SchedulerExtension::on_component_event`. Refined as MODULE-015
/// adds dependencies.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum ComponentEvent {
    Started(ComponentId),
    Finished(ComponentId),
    Failed(ComponentId, String),
}

impl ComponentEvent {
    /// Slice m015-A: public constructors so the out-of-crate
    /// `advance-scheduler-auto-loop` test crate can build variants
    /// despite `#[non_exhaustive]` (cross-crate enum-variant
    /// construction is forbidden — rustc E0639). Additive.
    pub fn started(id: ComponentId) -> Self {
        Self::Started(id)
    }
    pub fn finished(id: ComponentId) -> Self {
        Self::Finished(id)
    }
    pub fn failed(id: ComponentId, msg: String) -> Self {
        Self::Failed(id, msg)
    }
}

// ---- Subscription-ID minting helper ----

/// Slice A monotonic counter helper: implementations of
/// `TriggerBusDispatch` use this to mint fresh `SubscriptionId`s. Held
/// inside the impl, not exposed in the trait signature.
#[derive(Debug, Default)]
pub struct SubscriptionIdCounter {
    inner: AtomicU64,
}

impl SubscriptionIdCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a fresh SubscriptionId.
    ///
    /// Relaxed ordering is sufficient because the only invariant is
    /// uniqueness within a single counter instance — there is no
    /// read-after-write happens-before requirement on this counter.
    /// (If Slice B creates multiple `TriggerBusDispatchImpl`
    /// instances, each carries its own counter; IDs are unique
    /// per-instance only — adversarial Round 1 finding W10.)
    ///
    /// **Skips `u64::MAX` to avoid colliding with
    /// `SubscriptionId::REJECTED`** (adversarial Round 1 finding W5).
    /// Reaching the wraparound point requires 2^64 successful
    /// subscribes — practically unreachable — but defense-in-depth
    /// is cheap. After wraparound the next legitimate ID is 0; ID
    /// reuse across the full lifetime of a single counter instance
    /// is still theoretically possible but again practically
    /// unreachable.
    pub fn next(&self) -> SubscriptionId {
        let candidate = self.inner.fetch_add(1, Ordering::Relaxed);
        if candidate == u64::MAX {
            // Counter just produced u64::MAX, which collides with
            // REJECTED. Advance once more (consuming the sentinel
            // slot) and return the next value.
            return SubscriptionId(self.inner.fetch_add(1, Ordering::Relaxed));
        }
        SubscriptionId(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_id_new_under_limit() {
        let id = "x".repeat(256);
        assert!(ComponentId::new(id).is_ok());
    }

    #[test]
    fn component_id_new_over_limit() {
        let id = "x".repeat(257);
        let err = ComponentId::new(id).unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn subscription_counter_monotonic() {
        let c = SubscriptionIdCounter::new();
        let a = c.next();
        let b = c.next();
        assert_ne!(a, b);
        assert_eq!(b.0, a.0 + 1);
    }

    #[test]
    fn component_id_deserialize_rejects_over_limit() {
        // Audit Round 5 fix: derived #[serde(transparent)] Deserialize
        // previously bypassed the constructor cap. Custom Deserialize
        // now runs the same check.
        let too_long = "x".repeat(MAX_COMPONENT_ID_LEN + 1);
        let json = format!("\"{too_long}\"");
        let r: Result<ComponentId, _> = serde_json::from_str(&json);
        assert!(r.is_err(), "over-limit ComponentId must reject");
    }

    #[test]
    fn component_id_deserialize_accepts_at_limit() {
        let exact = "y".repeat(MAX_COMPONENT_ID_LEN);
        let json = format!("\"{exact}\"");
        let r: Result<ComponentId, _> = serde_json::from_str(&json);
        assert!(r.is_ok(), "at-limit ComponentId must pass");
    }

    #[test]
    fn trigger_chain_id_deserialize_rejects_over_limit() {
        let too_long = "x".repeat(MAX_COMPONENT_ID_LEN + 1);
        let json = format!("\"{too_long}\"");
        let r: Result<TriggerChainId, _> = serde_json::from_str(&json);
        assert!(r.is_err(), "over-limit TriggerChainId must reject");
    }

    #[test]
    fn trigger_chain_id_deserialize_accepts_at_limit() {
        let exact = "y".repeat(MAX_COMPONENT_ID_LEN);
        let json = format!("\"{exact}\"");
        let r: Result<TriggerChainId, _> = serde_json::from_str(&json);
        assert!(r.is_ok());
    }

    #[test]
    fn trigger_chain_id_new_rejects_over_limit() {
        let s = "x".repeat(MAX_COMPONENT_ID_LEN + 1);
        let err = TriggerChainId::new(s).unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    // ---- Slice D format_rfc3339_ms tests ----

    #[test]
    fn format_rfc3339_ms_zero_is_epoch() {
        assert_eq!(format_rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn format_rfc3339_ms_2025_01_01() {
        // 2025-01-01T00:00:00.000Z = 1735689600000 ms
        assert_eq!(
            format_rfc3339_ms(1_735_689_600_000),
            "2025-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn format_rfc3339_ms_2099_12_31() {
        // 2099-12-31T23:59:59.999Z = 4102444799999 ms
        assert_eq!(
            format_rfc3339_ms(4_102_444_799_999),
            "2099-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn format_rfc3339_ms_minus_one_is_pre_epoch() {
        // chrono accepts moderate negative i64; round-3 correction: NOT epoch.
        assert_eq!(format_rfc3339_ms(-1), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn format_rfc3339_ms_i64_max_clamps_to_epoch() {
        // i64::MAX milliseconds (~292 million years) exceeds chrono's range
        // → from_timestamp_millis returns None → epoch fallback fires.
        assert_eq!(format_rfc3339_ms(i64::MAX), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn format_rfc3339_ms_i64_min_clamps_to_epoch() {
        assert_eq!(format_rfc3339_ms(i64::MIN), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn now_unix_ms_is_positive() {
        let now = now_unix_ms();
        // Reading the wall clock should produce a 13-digit ms-since-epoch
        // value in the ballpark of the test's wall-clock year.
        assert!(
            now > 1_700_000_000_000,
            "now_unix_ms() = {now} is too small"
        );
        assert!(
            now < 5_000_000_000_000,
            "now_unix_ms() = {now} is too large"
        );
    }
}
