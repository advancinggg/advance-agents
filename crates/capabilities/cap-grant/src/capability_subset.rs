//! Capability-first SubsetValidator entry (CONTRACT-122, MODULE-013-AC-15 facet).
//!
//! Provides [`validate_capability_subset`] — a free function that projects each
//! `shared_types::Capability` into a transient `cap_grant::GrantDraft` via a
//! fail-closed projection helper, then invokes the existing
//! [`SubsetValidatorImpl::validate`] for the actual subset check.
//!
//! Fail-closed posture (PRD §5.7.4 "Subset rules enforced unconditionally; no
//! bypass path") covers every observed shape:
//! - Unknown capability id → `SubsetViolation`.
//! - Top-level params not a JSON object (except `Value::Null` or empty
//!   `Value::Object` which are treated as the "whole capability" semantic) →
//!   `SubsetViolation`.
//! - Param key not in the per-family whitelist (the load-bearing rule that
//!   closes the original fail-open vector) → `SubsetViolation`.
//! - Value is `Object`, nested-non-scalar `Array`, or `Null` for a known
//!   key → `SubsetViolation`.
//! - Numeric value that is not a non-negative u64 → `SubsetViolation`
//!   (cap-grant's numeric `≤` consumer is `u64`-only; routing a float
//!   through `to_string` would land in `parse::<u64>()` as a misleading
//!   downstream error).
//! - Array element containing `,`, leading/trailing whitespace, or empty
//!   string → `SubsetViolation` (cap-grant's `parse_csv` would split or
//!   strip such elements, silently widening the granted set — closes the
//!   CSV-identity-loss fail-open vector identified in plan round 1).
//! - Multiple parent capabilities with the same `id` (ambiguous which one
//!   the child requests against) → `SubsetViolation`.
//!
//! Per-family whitelist mirrors `SubsetValidatorImpl::validate`'s dispatch
//! exactly. `channel` is intentionally absent — cap-grant's own validator
//! has no `channel` arm either; both fail-closed via the wildcard branch.

use serde_json::Value;

use crate::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use crate::error::CapGrantError;
use crate::subset::{SubsetValidator, SubsetValidatorImpl};

use advance_shared_types::agent_tree::Capability;

/// Hard upper bound on parent + child capability slice lengths accepted by
/// [`validate_capability_subset`]. Defense-in-depth against unbounded inputs
/// flowing through the Rust-API entry points (e.g.,
/// `SubsetCheckedComponentSubmit::submit_component_with_subset` accepts
/// caller-supplied `Vec<Capability>` with no upstream cap of its own — the
/// spawn-child / spawn-sub paths already bound to `MAX_CAPABILITIES = 64`
/// upstream in cap-lifecycle's `spawn.rs`, but the wrapper Rust-API has no
/// such gate). 256 leaves comfortable headroom over the upstream 64 cap.
pub const MAX_CAPABILITIES_PER_CALL: usize = 256;

/// Hard upper bound on per-`Capability.params` Object key count. Per-family
/// whitelists carry at most 3 keys (messaging.{targets,max-fanout,max-depth});
/// 16 leaves huge headroom for future-slice additions while keeping
/// projection cost bounded.
pub const MAX_PARAMS_KEYS_PER_CAPABILITY: usize = 16;

/// Hard upper bound on per-value JSON `Array` element count. Matches the
/// `MAX_CAPABILITIES_PER_CALL` envelope; legitimate set-subset families
/// (secrets.names, tools.ids, etc.) carry small lists in practice.
pub const MAX_PARAMS_ARRAY_LEN: usize = 256;

/// Hard upper bound on per-value string byte length. Matches cap-grant's
/// `MAX_PARAMS_BYTES = 4096` in `delegate_grant` (store.rs:1148).
pub const MAX_PARAMS_STRING_BYTES: usize = 4096;

/// Whitelist of param keys per capability family. Matches the
/// `SubsetValidatorImpl::validate` match dispatch in `subset.rs` exactly.
fn allowed_param_keys(capability: &str) -> Option<&'static [&'static str]> {
    match capability {
        "fs" => Some(&["read-paths", "write-paths"]),
        "http" => Some(&["allowlist"]),
        "messaging" => Some(&["targets", "max-fanout", "max-depth"]),
        "lifecycle" => Some(&["spawn-child", "spawn-sub"]),
        "llm" => Some(&["models", "max-tokens-per-call"]),
        "secrets" => Some(&["names"]),
        "tools" => Some(&["ids"]),
        "notify" => Some(&["targets"]),
        "mcp" => Some(&["servers", "tool-patterns"]),
        "skills" => Some(&["allowed-actions", "max-active-skills"]),
        _ => None,
    }
}

/// Shared identity-loss rejection (round-2 adversarial fix). Any string-shaped
/// value flowing through the projection's CSV-serialized output MUST survive
/// a round-trip through cap-grant's `parse_csv` (subset.rs:107-113) intact;
/// `parse_csv` splits on `,`, trims whitespace, and drops empty tokens.
/// Without this guard, a single string carrying `,` would silently split
/// into multiple tokens on the cap-grant side (widening the granted set), an
/// empty string would silently drop (vacuously satisfying the subset check),
/// and a whitespace-bracketed string would project to a different token than
/// the input (identity loss).
///
/// Defense-in-depth: ASCII control bytes (0x00-0x1F, 0x7F) are also rejected.
/// Rationale matches `subset.rs:257-263`'s URL-pattern guard — control bytes
/// canonicalize unpredictably across downstream consumers (NUL truncates
/// C-string sinks; LF/CR forge log lines; ESC can drive terminal-escape
/// attacks on console viewers). High-bit Unicode characters (0x80+) are
/// intentionally allowed because legitimate identifiers (e.g., a tool id
/// containing `é`) must work; only ASCII control bytes are identity-
/// destroying for cap-grant's downstream consumers.
fn check_parse_csv_safe(
    s: &str,
    cap_id: &str,
    key: &str,
    where_: &str,
) -> Result<(), CapGrantError> {
    if s.contains(',') {
        return Err(CapGrantError::SubsetViolation(format!(
            "{cap_id}.{key}: {where_} {s:?} contains `,` — fail-closed; \
             cap-grant's parse_csv would split this into multiple tokens, \
             silently widening the granted set"
        )));
    }
    if s.is_empty() {
        return Err(CapGrantError::SubsetViolation(format!(
            "{cap_id}.{key}: empty {where_} rejected — parse_csv strips empty \
             tokens, vacuously satisfying the subset check"
        )));
    }
    if s.trim() != s {
        return Err(CapGrantError::SubsetViolation(format!(
            "{cap_id}.{key}: {where_} {s:?} has leading/trailing whitespace; \
             parse_csv trims, yielding a token that does not match the input"
        )));
    }
    if let Some(bad) = s.bytes().find(|b| *b < 0x20 || *b == 0x7F) {
        return Err(CapGrantError::SubsetViolation(format!(
            "{cap_id}.{key}: {where_} contains ASCII control byte 0x{bad:02x} \
             (NUL truncates C-string sinks; LF/CR forge log lines; ESC drives \
             terminal-escape attacks). Reject rather than sanitize because \
             the param flows verbatim into downstream consumers."
        )));
    }
    // Round-3 adversarial fix (m013-slice-e): reject Unicode confusables —
    // zero-width chars, BiDi controls, variation selectors, tag chars, soft
    // hyphen, invisible math operators, BOM. These bytes are visually
    // identical to surrounding characters but byte-distinct, allowing a
    // malicious config author to register identifiers that operators read
    // as one string but the system stores as another (e.g.,
    // `tool-evil\u{200B}` displays as `tool-evil`). Identifiers granted to
    // distinct byte sequences flow through `parse_csv` + set-membership
    // checks intact, defeating operator review. High-bit ASCII / Latin /
    // CJK / Cyrillic characters remain accepted — only true visually-
    // confusable codepoints are rejected. Curated list matches cap-grant's
    // `preset.rs::reject_builtin_shadow` strip set (Slice B adversarial-
    // round 4 W2 precedent).
    if let Some(bad) = s.chars().find(|c| is_unicode_confusable(*c)) {
        return Err(CapGrantError::SubsetViolation(format!(
            "{cap_id}.{key}: {where_} contains Unicode confusable U+{:04X} \
             (zero-width / BiDi control / variation selector / tag char). \
             Reject because the codepoint is invisible or visually identical \
             to surrounding chars, allowing operator-spoofing on grant \
             review.",
            bad as u32
        )));
    }
    Ok(())
}

/// Curated set of Unicode confusable codepoints rejected from cap-grant
/// param values. Matches the strip set in `preset.rs::reject_builtin_shadow`
/// (Slice B adversarial round 4 W2 precedent) so identifier policy is
/// uniform across the cap-grant surface.
///
/// Categories:
/// - Soft hyphen (display-merged with surrounding text): U+00AD
/// - Mongolian Vowel Separator (zero-width): U+180E
/// - Bidi marks (LRM, RLM): U+200E, U+200F
/// - Zero-width chars (ZWSP, ZWNJ, ZWJ): U+200B-U+200D
/// - BiDi controls (LRE, RLE, PDF, LRO, RLO): U+202A-U+202E
/// - Invisible math operators (FUNCTION APPLICATION etc.): U+2061-U+2064
/// - Word Joiner: U+2060
/// - Directional isolates (LRI, RLI, FSI, PDI): U+2066-U+2069
/// - Variation selectors: U+FE00-U+FE0F (VS1-VS16)
/// - BOM / Zero-width no-break space: U+FEFF
/// - Tag chars: U+E0000-U+E007F (legacy Plane 14)
fn is_unicode_confusable(c: char) -> bool {
    let u = c as u32;
    matches!(
        u,
        0x00AD // SOFT HYPHEN
        | 0x180E // MONGOLIAN VOWEL SEPARATOR
        | 0x200B..=0x200F // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | 0x202A..=0x202E // LRE, RLE, PDF, LRO, RLO
        | 0x2060 // WORD JOINER
        | 0x2061..=0x2064 // FUNCTION APPLICATION etc.
        | 0x2066..=0x2069 // LRI, RLI, FSI, PDI
        | 0xFE00..=0xFE0F // VARIATION SELECTOR-1..16
        | 0xFEFF // ZERO WIDTH NO-BREAK SPACE / BOM
        | 0xE0000..=0xE007F // TAG chars
    )
}

/// Project a single JSON value into the CSV-serialized string form cap-grant
/// helpers consume. Fail-closed on every shape that would lose identity
/// through `parse_csv` / `parse_bool` / `parse::<u64>()`. Round-2 adversarial
/// fix: applies the same identity-loss rejection
/// ([`check_parse_csv_safe`]) to top-level `Value::String` as already
/// enforced on array elements — closes the asymmetric fail-open vector where
/// a top-level string containing `,` or whitespace silently widened on the
/// parent side (and a top-level empty string silently bypassed on the child
/// side).
fn value_to_param_string(value: &Value, cap_id: &str, key: &str) -> Result<String, CapGrantError> {
    match value {
        Value::String(s) => {
            if s.len() > MAX_PARAMS_STRING_BYTES {
                return Err(CapGrantError::SubsetViolation(format!(
                    "{cap_id}.{key}: string value length {} exceeds \
                     MAX_PARAMS_STRING_BYTES={MAX_PARAMS_STRING_BYTES} (fail-closed)",
                    s.len()
                )));
            }
            check_parse_csv_safe(s, cap_id, key, "string value")?;
            Ok(s.clone())
        }
        Value::Number(n) => match n.as_u64() {
            Some(u) => Ok(u.to_string()),
            None => Err(CapGrantError::SubsetViolation(format!(
                "{cap_id}.{key}: numeric param must be a non-negative integer \
                 fitting u64 (got {n}); fractional / negative / out-of-range \
                 values are not supported by cap-grant's numeric ≤ rule"
            ))),
        },
        Value::Bool(b) => Ok(b.to_string()),
        Value::Array(arr) => {
            if arr.len() > MAX_PARAMS_ARRAY_LEN {
                return Err(CapGrantError::SubsetViolation(format!(
                    "{cap_id}.{key}: array length {} exceeds \
                     MAX_PARAMS_ARRAY_LEN={MAX_PARAMS_ARRAY_LEN} (fail-closed)",
                    arr.len()
                )));
            }
            let mut tokens: Vec<String> = Vec::with_capacity(arr.len());
            for elem in arr {
                tokens.push(array_element_to_string(elem, cap_id, key)?);
            }
            Ok(tokens.join(","))
        }
        Value::Object(_) => Err(CapGrantError::SubsetViolation(format!(
            "{cap_id}.{key}: param value must be a scalar / array of scalars; \
             nested objects are rejected (fail-closed)"
        ))),
        Value::Null => Err(CapGrantError::SubsetViolation(format!(
            "{cap_id}.{key}: null value forbidden for a known param key — \
             omit the key to mean 'unrestricted', do not encode it as null"
        ))),
    }
}

/// Convert a single array element to a `parse_csv`-safe token. Rejects any
/// element that would survive projection but lose identity through cap-grant's
/// `parse_csv` (subset.rs:107-113) via [`check_parse_csv_safe`].
fn array_element_to_string(
    value: &Value,
    cap_id: &str,
    key: &str,
) -> Result<String, CapGrantError> {
    let s = match value {
        Value::String(s) => {
            if s.len() > MAX_PARAMS_STRING_BYTES {
                return Err(CapGrantError::SubsetViolation(format!(
                    "{cap_id}.{key}: array element length {} exceeds \
                     MAX_PARAMS_STRING_BYTES={MAX_PARAMS_STRING_BYTES} (fail-closed)",
                    s.len()
                )));
            }
            s.clone()
        }
        Value::Number(n) => n.as_u64().map(|u| u.to_string()).ok_or_else(|| {
            CapGrantError::SubsetViolation(format!(
                "{cap_id}.{key}: array element must be a non-negative \
                     integer fitting u64 (got {n})"
            ))
        })?,
        Value::Bool(b) => b.to_string(),
        Value::Array(_) | Value::Object(_) | Value::Null => {
            return Err(CapGrantError::SubsetViolation(format!(
                "{cap_id}.{key}: array element must be string / integer / \
                 bool — nested arrays / objects / null are rejected \
                 (fail-closed)"
            )))
        }
    };
    check_parse_csv_safe(&s, cap_id, key, "array element")?;
    Ok(s)
}

/// Project a `shared_types::Capability` into a `Vec<CapParam>` (cap-grant's
/// per-family helpers' input shape). Returns `Ok(vec![])` for whole-capability
/// semantics (`Value::Null` or `Value::Object({})`).
fn project_capability_params(capability: &Capability) -> Result<Vec<CapParam>, CapGrantError> {
    project_params(capability.id.as_str(), capability.params.as_value())
}

/// Project a raw capability-`params` JSON value (the same shape carried by a
/// `shared_types::Capability.params` and by a CONTRACT-121 `CapParams`) into the
/// `Vec<CapParam>` shape cap-grant's per-family subset helpers consume, applying
/// the IDENTICAL fail-closed whitelist + identity-loss guards as the
/// Capability-first projection. Shared by [`validate_capability_subset`] (the
/// spawn-child / spawn-sub / submit-component admission gate) AND the L1
/// invocation gate (`check.rs::GrantCheckImpl::check`, MODULE-013-AC-23) so both
/// enforcement points apply byte-identical subset semantics — a single
/// projection means one gate can never accept what the other rejects.
pub(crate) fn project_params(cap_id: &str, value: &Value) -> Result<Vec<CapParam>, CapGrantError> {
    if allowed_param_keys(cap_id).is_none() {
        return Err(CapGrantError::SubsetViolation(format!(
            "unknown capability {cap_id:?} — projection whitelist excludes \
             it (cap-grant's SubsetValidatorImpl also fails closed on unknown \
             capability names; the projection mirrors that posture)"
        )));
    }
    let allowed = allowed_param_keys(cap_id).expect("checked above");
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Object(map) if map.is_empty() => Ok(Vec::new()),
        Value::Object(map) => {
            if map.len() > MAX_PARAMS_KEYS_PER_CAPABILITY {
                return Err(CapGrantError::SubsetViolation(format!(
                    "{cap_id}: params object has {} keys, exceeding \
                     MAX_PARAMS_KEYS_PER_CAPABILITY={MAX_PARAMS_KEYS_PER_CAPABILITY} \
                     (fail-closed)",
                    map.len()
                )));
            }
            let mut params = Vec::with_capacity(map.len());
            for (key, val) in map {
                if !allowed.iter().any(|k| *k == key.as_str()) {
                    return Err(CapGrantError::SubsetViolation(format!(
                        "{cap_id}.{key:?}: unrecognized param key — fail-closed \
                         (the cap-grant subset helper does not enumerate this \
                         key; allowing it would silently widen the granted set)"
                    )));
                }
                let value_str = value_to_param_string(val, cap_id, key)?;
                params.push(CapParam {
                    key: key.clone(),
                    value: value_str,
                });
            }
            Ok(params)
        }
        _ => Err(CapGrantError::SubsetViolation(format!(
            "{cap_id}: top-level params must be a JSON object or null/{{}} \
             (got non-object value); fail-closed"
        ))),
    }
}

/// Internal: build a synthetic `Grant` from a projected parent capability.
/// Most fields are unconsulted by [`SubsetValidatorImpl::validate`] (which
/// only reads `capability` + `params`), so we fill them with deterministic
/// placeholders. The placeholders must satisfy `Grant`'s field types but
/// never leak outside this projection's scope.
fn synthetic_parent_grant(capability_id: String, params: Vec<CapParam>) -> Grant {
    Grant {
        id: GrantId::new("__capability_subset_projection__"),
        grantee: String::new(),
        capability: capability_id,
        params,
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Admin,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: chrono::Utc::now(),
        expires_at: None,
    }
}

fn synthetic_child_draft(capability_id: String, params: Vec<CapParam>) -> GrantDraft {
    GrantDraft {
        capability: capability_id,
        params,
        ttl: GrantTtl::Persistent,
    }
}

/// Validate that every child capability is a subset of a matching parent
/// capability using cap-grant's per-family subset rules (CONTRACT-122).
///
/// Fail-closed on every shape that would otherwise widen the granted set
/// (see module rustdoc for the full enumeration). Capability id matching is
/// case-sensitive (`"fs" != "FS"` — different capability ids fail closed).
///
/// On the first failing child the function returns immediately with that
/// `SubsetViolation`; later children are not inspected (deterministic
/// short-circuit; callers seeking exhaustive errors should drive the check
/// per-capability).
pub fn validate_capability_subset(
    parent: &[Capability],
    child: &[Capability],
) -> Result<(), CapGrantError> {
    // Round-2 adversarial Warning 3: defense-in-depth input-size cap. Spawn
    // paths bound at MAX_CAPABILITIES=64 upstream; submit-component's
    // Rust-API wrapper has no such cap. Reject extreme slices here so a
    // caller bug or compromised upstream cannot drive unbounded allocation
    // in the projection.
    if parent.len() > MAX_CAPABILITIES_PER_CALL {
        return Err(CapGrantError::SubsetViolation(format!(
            "parent capability slice length {} exceeds MAX_CAPABILITIES_PER_CALL={MAX_CAPABILITIES_PER_CALL} (fail-closed)",
            parent.len()
        )));
    }
    if child.len() > MAX_CAPABILITIES_PER_CALL {
        return Err(CapGrantError::SubsetViolation(format!(
            "child capability slice length {} exceeds MAX_CAPABILITIES_PER_CALL={MAX_CAPABILITIES_PER_CALL} (fail-closed)",
            child.len()
        )));
    }
    let validator = SubsetValidatorImpl::new();
    for child_cap in child {
        let child_cap_id = child_cap.id.as_str();
        let mut matching_parents = parent.iter().filter(|p| p.id.as_str() == child_cap_id);
        let parent_cap = match matching_parents.next() {
            Some(p) => p,
            None => {
                return Err(CapGrantError::SubsetViolation(format!(
                    "child requests capability {child_cap_id:?} but parent \
                     grant set does not include it (fail-closed)"
                )));
            }
        };
        if matching_parents.next().is_some() {
            return Err(CapGrantError::SubsetViolation(format!(
                "parent grant set contains duplicate capability id \
                 {child_cap_id:?} — ambiguous which one to subset against; \
                 fail-closed (operator should ensure parent capabilities \
                 have unique ids)"
            )));
        }

        let parent_params = project_capability_params(parent_cap)?;
        let child_params = project_capability_params(child_cap)?;
        let parent_grant = synthetic_parent_grant(child_cap_id.to_string(), parent_params);
        let child_draft = synthetic_child_draft(child_cap_id.to_string(), child_params);
        validator.validate(&parent_grant, &child_draft)?;
    }
    Ok(())
}
