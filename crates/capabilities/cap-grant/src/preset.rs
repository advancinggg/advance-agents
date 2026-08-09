//! `PresetRegistry` (MODULE-013 §1.4.4 / PRD §5.7.5).
//!
//! Slice B ships:
//! - 3 built-in presets: `restrict`, `supervised`, `autonomous` — each is a
//!   `Preset { resolver_chain_names, default_ttl, grants }` record.
//! - Custom-preset YAML loader for `/{workspace}/.agent/presets/*.yaml`,
//!   reusing Slice A's compile.rs safety posture (1 MiB size cap, charset
//!   gates, empty-string rejection) plus per-grant ttl/key/value gates and
//!   a 16-level YAML recursion-depth post-parse processing-cost gate.
//! - `apply_preset` implementing §1.4.4 steps 1-4 + 6 of the 7-step flow
//!   (steps 5 "set target's resolver-chain" and 7 "persist + commit"
//!   deferred to Slice D — step 5 needs per-agent runtime state, step 7
//!   needs CONTRACT-020 GitCommitQueue from M003).
//!
//! Built-in chain compositions (per spec §1.4.4 table):
//! - `restrict`: `[AutoDeny]` — single-resolver chain that denies all
//!   non-static requests.
//! - `supervised`: `[SubsetAutoApprove, BudgetCheck, ParentApproval, Channel,
//!   AutoDeny]` — full 5-resolver chain with human-in-the-loop fallback.
//! - `autonomous`: `[SubsetAutoApprove, BudgetCheck, AutoDeny]` — auto-approve
//!   within parent bounds; no human gate.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_yml::Value;

use crate::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use crate::error::{CapGrantError, Result};
use crate::events::preset_applied_event;
use crate::store::GrantStore;
use crate::subset::SubsetValidator;

/// 1 MiB cap on preset YAML input (mirrors compile.rs Slice-A posture).
pub const MAX_PRESET_YAML_BYTES: u64 = 1 << 20;

/// Maximum YAML structural depth (Round 4 Warning 6 / Round 5 Warning 5
/// fix). Mirrors `agent_tree.rs:32-38` rustdoc invariant for `Capability`
/// deserialization from untrusted JSON.
pub const MAX_PRESET_YAML_DEPTH: usize = 16;

/// Maximum number of grants in a single preset (Audit-fix R4 Adversarial
/// W15). Caps `apply_preset` fan-out: preset grants are committed in one
/// store batch, but an unbounded preset would still amplify validation,
/// SQLite write, event, and recovery work. 100 is well above any realistic
/// preset (the spec example uses 2 grants); a future slice may make this
/// configurable.
pub const MAX_PRESET_GRANTS: usize = 100;

/// Built-in preset name.
pub const PRESET_RESTRICT: &str = "restrict";
/// Built-in preset name.
pub const PRESET_SUPERVISED: &str = "supervised";
/// Built-in preset name.
pub const PRESET_AUTONOMOUS: &str = "autonomous";

/// 5 built-in resolver names (per spec §1.4.2 / Architecture Decision §F).
const VALID_RESOLVER_NAMES: &[&str] = &[
    "SubsetAutoApprove",
    "BudgetCheck",
    "ParentApproval",
    "Channel",
    "AutoDeny",
];

/// A preset is a (chain composition + default TTL for dynamic grants +
/// optional grants list) tuple. Maps to spec §1.4.4 schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preset {
    pub name: String,
    /// Names of resolvers in chain order. Each must match a built-in
    /// (`SubsetAutoApprove` / `BudgetCheck` / `ParentApproval` / `Channel`
    /// / `AutoDeny`) or a registered custom resolver. Slice B validates
    /// against the 5 built-ins only.
    pub resolver_chain_names: Vec<String>,
    /// Default TTL for dynamic grants issued under this preset.
    pub default_ttl: GrantTtl,
    /// Optional pre-defined grants applied during `apply_preset`.
    pub grants: Vec<PresetGrant>,
}

/// A grant spec inside a preset's `grants:` list (spec §1.4.4 schema).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetGrant {
    pub capability: String,
    pub params: Vec<CapParam>,
    pub ttl: GrantTtl,
}

/// Result of `apply_preset` (returned to caller; the WIT layer in Slice D
/// will project `created` to its `result<list<grant-id>>` return).
#[derive(Clone, Debug)]
pub struct ApplyPresetResult {
    pub revoked: Vec<GrantId>,
    pub created: Vec<GrantId>,
}

/// Registry of built-in + custom presets.
pub struct PresetRegistry {
    presets: HashMap<String, Preset>,
}

impl PresetRegistry {
    /// Build the registry pre-populated with the 3 built-in presets.
    pub fn with_builtins() -> Self {
        let mut presets = HashMap::new();
        presets.insert(
            PRESET_RESTRICT.to_string(),
            Preset {
                name: PRESET_RESTRICT.to_string(),
                resolver_chain_names: vec!["AutoDeny".to_string()],
                default_ttl: GrantTtl::Once,
                grants: Vec::new(),
            },
        );
        presets.insert(
            PRESET_SUPERVISED.to_string(),
            Preset {
                name: PRESET_SUPERVISED.to_string(),
                resolver_chain_names: vec![
                    "SubsetAutoApprove".to_string(),
                    "BudgetCheck".to_string(),
                    "ParentApproval".to_string(),
                    "Channel".to_string(),
                    "AutoDeny".to_string(),
                ],
                default_ttl: GrantTtl::Once,
                grants: Vec::new(),
            },
        );
        presets.insert(
            PRESET_AUTONOMOUS.to_string(),
            Preset {
                name: PRESET_AUTONOMOUS.to_string(),
                resolver_chain_names: vec![
                    "SubsetAutoApprove".to_string(),
                    "BudgetCheck".to_string(),
                    "AutoDeny".to_string(),
                ],
                default_ttl: GrantTtl::Lifecycle,
                grants: Vec::new(),
            },
        );
        Self { presets }
    }

    pub fn get(&self, name: &str) -> Option<&Preset> {
        self.presets.get(name)
    }

    pub fn names(&self) -> Vec<&str> {
        self.presets.keys().map(|s| s.as_str()).collect()
    }

    /// Load a custom preset from a YAML file at `path`. Reuses Slice A's
    /// compile.rs safety posture (1 MiB cap + charset gates) and adds a
    /// 16-level structural-depth gate on the parsed `serde_yml::Value` tree.
    ///
    /// Audit-fix R4 (Adversarial Critical 4): refuses to overwrite the 3
    /// built-in preset names (`restrict`, `supervised`, `autonomous`). A
    /// workspace-writer who could otherwise drop a custom YAML file named
    /// `restrict.yaml` with a permissive chain would silently downgrade
    /// the security baseline; this gate forces custom presets to use a
    /// distinct name.
    pub fn load_custom_yaml(&mut self, path: &Path) -> Result<&Preset> {
        let meta = std::fs::metadata(path)
            .map_err(|e| CapGrantError::InvalidConfig(format!("stat {path:?}: {e}")))?;
        if meta.len() > MAX_PRESET_YAML_BYTES {
            return Err(CapGrantError::InvalidConfig(format!(
                "preset yaml > {MAX_PRESET_YAML_BYTES} bytes: {} bytes",
                meta.len()
            )));
        }
        let bytes = std::fs::read(path)
            .map_err(|e| CapGrantError::InvalidConfig(format!("read {path:?}: {e}")))?;
        if bytes.len() as u64 > MAX_PRESET_YAML_BYTES {
            return Err(CapGrantError::InvalidConfig(format!(
                "preset yaml > {MAX_PRESET_YAML_BYTES} bytes (post-read): {}",
                bytes.len()
            )));
        }
        let root: Value = serde_yml::from_slice(&bytes)?;
        check_yaml_depth(&root, 0)?;
        let preset = parse_preset(&root)?;
        reject_builtin_shadow(&preset.name)?;
        let name = preset.name.clone();
        self.presets.insert(name.clone(), preset);
        Ok(self.presets.get(&name).expect("just inserted"))
    }

    /// Direct-from-Value form, used by tests that build a Value in-process.
    #[doc(hidden)]
    pub fn load_custom_value(&mut self, root: &Value) -> Result<&Preset> {
        check_yaml_depth(root, 0)?;
        let preset = parse_preset(root)?;
        reject_builtin_shadow(&preset.name)?;
        let name = preset.name.clone();
        self.presets.insert(name.clone(), preset);
        Ok(self.presets.get(&name).expect("just inserted"))
    }

    /// `apply_preset` (MODULE-013 §1.4.4 steps 1-4 + 6).
    ///
    /// Step 5 (set target's resolver-chain) requires per-agent runtime
    /// state which doesn't exist in Slice B; deferred to Slice D.
    /// Step 7 (persist + commit) requires CONTRACT-020 GitCommitQueue
    /// from M003; deferred to Slice D.
    ///
    /// `caller_id`: identity of the caller invoking apply-preset. The
    /// caller's currently active grants are looked up internally via
    /// `store.list_by_grantee(caller_id)` and used in step 2 to validate
    /// that every preset-defined grant is a subset of some grant the
    /// caller actually holds. Audit-fix R4 (Adversarial Critical 2):
    /// taking the caller's grants from a caller-supplied parameter
    /// would let an attacker pass a forged "wide" grant set; looking
    /// them up from `store` keyed by caller_id closes that bypass.
    ///
    /// **Adversarial-fix R25 — atomic revoke/create**: step 3 revocation and
    /// step 4 preset-grant creation commit through one `GrantStore` primitive.
    /// If any preflight or SQLite write fails, no old dynamic grant is revoked
    /// and no `grant.revoked`, `grant.issued`, or `preset.applied` event emits.
    /// On success, readers of `active-grants` see either the pre-apply state or
    /// the post-apply preset state; the revoke-before-create gap is not visible.
    pub fn apply_preset(
        &self,
        name: &str,
        target_grantee: &str,
        store: &GrantStore,
        validator: &dyn SubsetValidator,
        caller_id: &str,
    ) -> Result<ApplyPresetResult> {
        // Adversarial-fix R17 W2: validate preset `name` symmetric with the
        // identifier gates below. On miss, CapGrantError::PresetNotFound(name)
        // echoes raw via Display to logs + WIT-mapped errors. Without the
        // gate, a multi-MB / control-byte / bidi name amplifies log payload
        // + spoofs line-rendered downstream consumers.
        if name.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "apply_preset: name must not be empty".to_string(),
            ));
        }
        if name.len() > 256 {
            return Err(CapGrantError::InvalidConfig(format!(
                "apply_preset: name exceeds 256-byte cap (got {} bytes)",
                name.len()
            )));
        }
        if name.chars().any(|c| c.is_control()) {
            return Err(CapGrantError::InvalidConfig(
                "apply_preset: name contains ASCII control bytes — \
                 forbidden for log + error payload safety"
                    .to_string(),
            ));
        }

        // Adversarial-fix R16 W1: identifier validation symmetric with
        // delegate_grant + narrow caller_id gates. target_grantee + caller_id
        // flow into Grant.grantee, by_grantee index key, preset.applied event
        // payload + Event.actor, and revoke_dynamic_for_grantee's revoked_by
        // string. Without these gates, multi-MB / control-byte / `:` chars
        // would amplify event payload + log-spoof downstream consumers.
        for (label, id) in [("caller_id", caller_id), ("target_grantee", target_grantee)] {
            if id.is_empty() {
                return Err(CapGrantError::InvalidConfig(format!(
                    "apply_preset: {label} must not be empty"
                )));
            }
            if id.len() > 256 {
                return Err(CapGrantError::InvalidConfig(format!(
                    "apply_preset: {label} exceeds 256-byte cap (got {} bytes)",
                    id.len()
                )));
            }
            // Colon-id reconciliation (2026-06-06): accept a bare colon-free id OR the
            // canonical `agent:<slug>` form for caller_id + target_grantee (reject `user:` /
            // multi-colon / malformed). Lets a guest apply a preset to itself as
            // `agent:harness`. See `crate::store::is_agent_or_bare_id`.
            if !crate::store::is_agent_or_bare_id(id) {
                return Err(CapGrantError::InvalidConfig(format!(
                    "apply_preset: {label} must be a bare id or a canonical `agent:<body>` id"
                )));
            }
            if id.chars().any(|c| c.is_control()) {
                return Err(CapGrantError::InvalidConfig(format!(
                    "apply_preset: {label} contains ASCII control bytes — \
                     forbidden for persistent identifiers"
                )));
            }
        }

        // Audit-fix R5 (Adversarial Warning 3): caller authorization gate.
        // Slice-B model: the agent applies a preset to itself
        // (caller_id == target_grantee). Cross-agent preset application
        // (parent applies preset to child, admin applies preset to any
        // agent) is Slice D's WIT-layer policy concern; cap-grant has no
        // hierarchy data and no admin role to consult here.
        if caller_id != target_grantee {
            // Slice C: migrated from SubsetViolation → PermissionDenied to align
            // with M013 §2.8 spec'd `grant-error::permission-denied`.
            return Err(CapGrantError::PermissionDenied(format!(
                "apply_preset: caller {caller_id:?} is not the target {target_grantee:?}; \
                 Slice B only permits self-applied presets. Cross-agent preset application \
                 is the WIT-layer admin gate (Slice D)."
            )));
        }

        // Step 1: validate name.
        let preset = self
            .presets
            .get(name)
            .ok_or_else(|| CapGrantError::PresetNotFound(name.to_string()))?;

        // Step 2: subset-check each preset grant against caller's grants.
        // Audit-fix R4 (Adversarial Critical 2): caller's grants are
        // looked up from `store` keyed by `caller_id` rather than supplied
        // by the caller as a parameter — closes the auth-bypass surface
        // where a malicious caller could pass `vec![full-grant]` to
        // trivially satisfy the subset check.
        //
        // Audit-fix R7 (Adversarial R4 Warning 3) — documented design intent:
        // the snapshot taken here is used only to verify preset grants
        // are AT-APPLY-TIME subset of caller's authorizations. The new
        // preset grants are issued with `provenance: Preset(name)` (NOT
        // `Delegated(parent_id)`), so they are NEW authorizations that
        // do not depend on the snapshot's parent grants for their
        // continued validity. If an external admin revokes a caller's
        // wide grant W concurrently with `apply_preset`, the preset
        // grants that subset-passed against W still survive — by design
        // per PRD §5.7.5 ("Preset 控制 ResolverChain 的行为 和 动态签发
        // grant 的默认 TTL 策略"). Preset application is a
        // privilege-replacement operation, not a privilege-delegation
        // operation. The caller-grant subset check is a one-shot
        // "the caller had authority to define this preset at apply
        // time" gate, not a continuous-subset invariant.
        // Adversarial-fix R7 W1: defense-in-depth `expires_at > now` filter
        // closes the orphan-window privilege-extension race. Without it, a
        // caller's Active-but-pre-sweeper-expired grant (deadline already
        // passed but status not yet flipped) could satisfy the subset check
        // here, and step 4 would mint fresh preset grants whose `expires_at`
        // is derived ONLY from `pg.ttl` (NOT clamped to parent deadline) —
        // laundering near-dead authorization into Persistent preset grants.
        // Symmetric with check.rs Step 2 + delegate_grant Step 3 filters.
        let now = Utc::now();
        let caller_grants: Vec<Grant> = store.list_by_grantee(caller_id);
        for pg in &preset.grants {
            let draft = GrantDraft {
                capability: pg.capability.clone(),
                params: pg.params.clone(),
                ttl: pg.ttl.clone(),
            };
            let mut covered = false;
            for parent in &caller_grants {
                if parent.status != GrantStatus::Active {
                    continue;
                }
                if parent.expires_at.is_some_and(|t| t <= now) {
                    continue;
                }
                if parent.capability != pg.capability {
                    continue;
                }
                if validator.validate(parent, &draft).is_ok() {
                    covered = true;
                    break;
                }
            }
            if !covered {
                return Err(CapGrantError::SubsetViolation(format!(
                    "preset {name:?} grant for {:?} not covered by any caller grant",
                    pg.capability
                )));
            }
        }

        // Step 3 + 4: atomically revoke target's existing dynamic grants and
        // create new grants per preset. The store primitive batches SQLite and
        // in-memory visibility, so a failed/non-empty preset apply cannot leave
        // old grants revoked without the preset grants installed.
        let mut new_grants = Vec::with_capacity(preset.grants.len());
        for pg in &preset.grants {
            let new_id = GrantId::new(uuid::Uuid::new_v4().to_string());
            let new_grant = Grant {
                id: new_id.clone(),
                grantee: target_grantee.to_string(),
                capability: pg.capability.clone(),
                params: pg.params.clone(),
                ttl: pg.ttl.clone(),
                issuer: GrantIssuer::Resolver(format!("preset:{name}")),
                provenance: GrantProvenance::Preset(name.to_string()),
                status: GrantStatus::Active,
                created_at: Utc::now(),
                expires_at: compute_expires_at(&pg.ttl),
            };
            new_grants.push(new_grant);
        }
        let (revoked, created) =
            store.apply_preset_atomic_for_grantee(target_grantee, new_grants)?;

        // Step 6: emit `preset.applied` event with PRD §15.3.18 4-field
        // payload using SCALAR COUNTS for grants_revoked / grants_created
        // (matches `cascade_count` precedent in `grant.revoked`).
        store.event_bus().emit(preset_applied_event(
            target_grantee,
            name,
            revoked.len(),
            created.len(),
        ));

        // Steps 5 + 7: deferred to Slice D — see method rustdoc.

        Ok(ApplyPresetResult { revoked, created })
    }
}

fn compute_expires_at(ttl: &GrantTtl) -> Option<DateTime<Utc>> {
    match ttl {
        GrantTtl::Once | GrantTtl::Lifecycle | GrantTtl::Persistent => None,
        GrantTtl::Duration(ms) => {
            // Adversarial-fix R6 W1: saturating arithmetic (matches narrow +
            // delegate_grant patterns). Without this, a custom-preset YAML
            // with `Duration(u64::MAX)` ttl panics on chrono overflow inside
            // `apply_preset` step 4.
            let dur_ms = i64::try_from(*ms).unwrap_or(i64::MAX);
            let dt = chrono::Duration::try_milliseconds(dur_ms)
                .and_then(|d| Utc::now().checked_add_signed(d))
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
            Some(dt)
        }
        GrantTtl::Until(t) => Some(*t),
    }
}

fn reject_builtin_shadow(name: &str) -> Result<()> {
    // Exact-byte match.
    if matches!(
        name,
        PRESET_RESTRICT | PRESET_SUPERVISED | PRESET_AUTONOMOUS
    ) {
        return Err(CapGrantError::InvalidConfig(format!(
            "custom preset name {name:?} shadows a built-in preset; \
             use a distinct name (built-ins are immutable)"
        )));
    }
    // Audit-fix R5 (Adversarial Warning 2): also reject case-folded match
    // and whitespace-trimmed match. A YAML name `Restrict ` / `RESTRICT` /
    // `\u{200B}restrict` / `restrict\t` would otherwise insert a NEW key
    // into the registry that an operator typo or case-insensitive lookup
    // could resolve to in place of the strict baseline. Slice B refuses
    // all near-misses at the YAML loader level.
    // Audit-fix R7 (Adversarial R4 Warning 2): broaden the strip set to
    // cover the full Unicode `Cf` (Format) category surface most likely
    // to be abused in a built-in-shadow attack. Hand-curated list across
    // 4 sub-ranges + scattered codepoints; all visually-zero-width or
    // visually-equivalent to a non-marking codepoint:
    // - Existing R5/R6: ZWSP (U+200B), ZWNJ (U+200C), ZWJ (U+200D), BOM
    //   (U+FEFF), Word Joiner (U+2060), Mongolian Vowel Sep (U+180E),
    //   Soft Hyphen (U+00AD), invisible math (U+2061-U+2064), bidi
    //   controls (U+202A-U+202E).
    // - R7 additions:
    //   * LRM (U+200E), RLM (U+200F) — bidi marks
    //   * LRI/RLI/FSI/PDI (U+2066-U+2069) — directional isolates
    //   * Variation selectors (U+FE00-U+FE0F)
    //   * Tag chars (U+E0000-U+E007F)
    let normalized: String = name
        .chars()
        .filter(|c| {
            if c.is_whitespace() {
                return false;
            }
            let cp = *c as u32;
            // Range checks for variation selectors + tag chars.
            if (0xFE00..=0xFE0F).contains(&cp) || (0xE0000..=0xE007F).contains(&cp) {
                return false;
            }
            !matches!(
                *c,
                '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
                    | '\u{FEFF}'
                    | '\u{2060}'
                    | '\u{180E}'
                    | '\u{00AD}'
                    | '\u{2061}'
                    | '\u{2062}'
                    | '\u{2063}'
                    | '\u{2064}'
                    | '\u{202A}'
                    | '\u{202B}'
                    | '\u{202C}'
                    | '\u{202D}'
                    | '\u{202E}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{2066}'
                    | '\u{2067}'
                    | '\u{2068}'
                    | '\u{2069}'
            )
        })
        .flat_map(|c| c.to_lowercase())
        .collect();
    if matches!(
        normalized.as_str(),
        PRESET_RESTRICT | PRESET_SUPERVISED | PRESET_AUTONOMOUS
    ) {
        return Err(CapGrantError::InvalidConfig(format!(
            "custom preset name {name:?} shadows a built-in preset after \
             whitespace/case normalization (normalized to {normalized:?}); \
             use a clearly-distinct name (built-ins are immutable)"
        )));
    }
    Ok(())
}

fn check_yaml_depth(v: &Value, depth: usize) -> Result<()> {
    if depth > MAX_PRESET_YAML_DEPTH {
        return Err(CapGrantError::InvalidConfig(format!(
            "preset YAML structural depth > {MAX_PRESET_YAML_DEPTH}"
        )));
    }
    match v {
        Value::Mapping(m) => {
            for (_k, vv) in m {
                check_yaml_depth(vv, depth + 1)?;
            }
        }
        Value::Sequence(seq) => {
            for item in seq {
                check_yaml_depth(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_preset(root: &Value) -> Result<Preset> {
    let map = root
        .as_mapping()
        .ok_or_else(|| CapGrantError::InvalidConfig("preset yaml root must be a mapping".into()))?;

    let name = map
        .get(Value::String("name".into()))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CapGrantError::InvalidConfig("preset yaml: missing `name:` field".into()))?;
    if name.is_empty() {
        return Err(CapGrantError::InvalidConfig(
            "preset name must not be empty".into(),
        ));
    }
    if name.contains(':') {
        return Err(CapGrantError::InvalidConfig(format!(
            "preset name contains forbidden character ':' (got: {name:?})"
        )));
    }

    let resolver_chain_names = map
        .get(Value::String("resolver-chain".into()))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| {
                            // Allow `SomeResolver: { config }` mapping form per §1.4.4 schema.
                            v.as_mapping()
                                .and_then(|m| m.iter().next())
                                .and_then(|(k, _)| k.as_str().map(|s| s.to_string()))
                        })
                        .ok_or_else(|| {
                            CapGrantError::InvalidConfig(format!(
                                "resolver-chain entry must be a string or mapping; got: {v:?}"
                            ))
                        })
                })
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    for r in &resolver_chain_names {
        if !VALID_RESOLVER_NAMES.contains(&r.as_str()) {
            return Err(CapGrantError::InvalidConfig(format!(
                "preset {name:?} resolver-chain has unknown resolver name: {r:?}; \
                 must be one of {VALID_RESOLVER_NAMES:?}"
            )));
        }
    }

    let default_ttl =
        parse_ttl(map.get(Value::String("default-ttl".into()))).ok_or_else(|| {
            CapGrantError::InvalidConfig(format!(
                "preset {name:?} missing or unparseable `default-ttl`"
            ))
        })??;

    let grants = match map.get(Value::String("grants".into())) {
        Some(g) => parse_grants(g)?,
        None => Vec::new(),
    };
    if grants.len() > MAX_PRESET_GRANTS {
        return Err(CapGrantError::InvalidConfig(format!(
            "preset {name:?} has {} grants exceeding MAX_PRESET_GRANTS = {}",
            grants.len(),
            MAX_PRESET_GRANTS
        )));
    }

    Ok(Preset {
        name,
        resolver_chain_names,
        default_ttl,
        grants,
    })
}

fn parse_ttl(v: Option<&Value>) -> Option<Result<GrantTtl>> {
    let v = v?;
    Some(parse_ttl_value(v))
}

fn parse_ttl_value(v: &Value) -> Result<GrantTtl> {
    if let Some(s) = v.as_str() {
        return match s {
            "once" => Ok(GrantTtl::Once),
            "lifecycle" => Ok(GrantTtl::Lifecycle),
            "persistent" => Ok(GrantTtl::Persistent),
            other => Err(CapGrantError::InvalidConfig(format!(
                "invalid ttl literal: {other:?}; expected once|lifecycle|persistent or {{duration|until}} mapping"
            ))),
        };
    }
    if let Some(m) = v.as_mapping() {
        // duration: <ms>
        if let Some(ms) = m
            .get(Value::String("duration".into()))
            .and_then(|v| v.as_u64())
        {
            return Ok(GrantTtl::Duration(ms));
        }
        // until: <iso8601>
        if let Some(t) = m
            .get(Value::String("until".into()))
            .and_then(|v| v.as_str())
        {
            let parsed = chrono::DateTime::parse_from_rfc3339(t).map_err(|e| {
                CapGrantError::InvalidConfig(format!("ttl until: invalid RFC3339 {t:?}: {e}"))
            })?;
            return Ok(GrantTtl::Until(parsed.with_timezone(&Utc)));
        }
    }
    Err(CapGrantError::InvalidConfig(format!(
        "invalid ttl shape: {v:?}; expected string or {{duration|until}} mapping"
    )))
}

fn parse_grants(v: &Value) -> Result<Vec<PresetGrant>> {
    let seq = v.as_sequence().ok_or_else(|| {
        CapGrantError::InvalidConfig(format!("preset grants must be a sequence; got: {v:?}"))
    })?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let m = item.as_mapping().ok_or_else(|| {
            CapGrantError::InvalidConfig(format!("grant entry must be a mapping; got: {item:?}"))
        })?;
        let capability = m
            .get(Value::String("capability".into()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                CapGrantError::InvalidConfig("grant entry missing `capability:`".into())
            })?;
        if capability.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "grant capability must not be empty".into(),
            ));
        }
        if capability.contains(':') {
            return Err(CapGrantError::InvalidConfig(format!(
                "grant capability contains forbidden character ':' (got: {capability:?})"
            )));
        }
        let params = match m.get(Value::String("params".into())) {
            Some(pv) => parse_params(pv)?,
            None => Vec::new(),
        };
        let ttl = parse_ttl(m.get(Value::String("ttl".into()))).ok_or_else(|| {
            CapGrantError::InvalidConfig(format!(
                "grant entry for {capability:?} missing or unparseable `ttl`"
            ))
        })??;
        out.push(PresetGrant {
            capability,
            params,
            ttl,
        });
    }
    Ok(out)
}

fn parse_params(v: &Value) -> Result<Vec<CapParam>> {
    let seq = v.as_sequence().ok_or_else(|| {
        CapGrantError::InvalidConfig(format!("params must be a sequence; got: {v:?}"))
    })?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let m = item.as_mapping().ok_or_else(|| {
            CapGrantError::InvalidConfig(format!("param entry must be a mapping; got: {item:?}"))
        })?;
        let key = m
            .get(Value::String("key".into()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CapGrantError::InvalidConfig("param entry missing `key:`".into()))?;
        if key.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "param key must not be empty".into(),
            ));
        }
        if key.len() > 256 {
            return Err(CapGrantError::InvalidConfig(format!(
                "param key > 256 bytes: {} bytes",
                key.len()
            )));
        }
        if !key.is_ascii() {
            return Err(CapGrantError::InvalidConfig(format!(
                "param key must be ASCII-printable: {key:?}"
            )));
        }
        let value_str = match m.get(Value::String("value".into())) {
            Some(Value::String(s)) => s.clone(),
            Some(other) => serde_yml::to_string(other)
                .map_err(CapGrantError::Yaml)?
                .trim_end_matches('\n')
                .to_string(),
            None => {
                return Err(CapGrantError::InvalidConfig(
                    "param entry missing `value:`".into(),
                ));
            }
        };
        if value_str.len() > 4096 {
            return Err(CapGrantError::InvalidConfig(format!(
                "param value > 4096 bytes: {} bytes",
                value_str.len()
            )));
        }
        out.push(CapParam {
            key,
            value: value_str,
        });
    }
    Ok(out)
}
