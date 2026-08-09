//! `IdentityResolver` (CONTRACT-151) — channel-specific sender id →
//! unified `user:alice` id.
//!
//! Per MODULE-006 §1.3.4 + §2.3 (CONTRACT-151, provider MODULE-006). The
//! resolver is constructed from a `&[UserChannelMapping]` slice and answers
//! `resolve(channel_kind, channel_id) -> Option<String>` (the mapped unified
//! id) in O(1).
//!
//! # Why a local DTO and not `runtime::config::UserMapping`
//!
//! `crates/messaging` must not depend on `crates/runtime` (would create a
//! dependency cycle: runtime → messaging → runtime). [`UserChannelMapping`]
//! is the resolver's own input DTO, structurally identical to runtime's
//! `UserMapping` (`{ id: String, channels: Vec<HashMap<String, String>> }`,
//! each channel map a single `{kind: id}` entry). The runtime crate adapts
//! its `RuntimeConfig.users` into this at bootstrap-wiring time — a follow-on
//! slice (MODULE-006 §3.6). AC-05's canonical verification is a **unit test**
//! (§1.4 verification column "unit test"; §3.3 T06 "Unit | telegram:user123 →
//! user:alice"), satisfied by this primitive; the production bootstrap call
//! site is explicitly out of slice-B scope.
//!
//! # PII discipline
//!
//! Errors are typed variants with no embedded ids/values — no caller-supplied
//! content flows into a `String` payload.

use std::collections::HashMap;

use crate::id_validation::is_safe_id;

/// Hard upper bound on the resolver map size — deterministic operational
/// guarantee, mirrors the `MAX_MAILBOXES` precedent.
pub const MAX_IDENTITY_MAPPINGS: usize = 10_000;

const USER_PREFIX: &str = "user:";

/// Resolver-input DTO. Deliberately distinct from `runtime::config::UserMapping`
/// (see module rustdoc). `channels` is a list of single-entry maps, mirroring
/// the runtime YAML shape `- telegram: "user123"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserChannelMapping {
    /// Unified id, e.g. `user:alice`. MUST be `is_safe_id` + `user:`-prefixed.
    pub id: String,
    /// Each entry is one `{channel_kind: channel_id}` single-key map.
    pub channels: Vec<HashMap<String, String>>,
}

/// Construction-time rejection reasons. Variants carry no caller content
/// (PII discipline) — the variant itself is the diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityResolverError {
    /// A required field (`id`, `channel_kind`, or `channel_id`) was empty.
    /// The `&'static str` is an invariant field name, not user content.
    EmptyField(&'static str),
    /// `id` failed `is_safe_id` or is not `user:`-prefixed.
    UnsafeUserId,
    /// The same `(channel_kind, channel_id)` pair appears under more than one
    /// user (identity-spoofing surface; runtime config also rejects this —
    /// re-enforced here as defense-in-depth).
    DuplicateChannelPair,
    /// A `channels` entry was not a single-key map.
    MultiKeyChannelMap,
    /// The mapping count would exceed [`MAX_IDENTITY_MAPPINGS`].
    TooManyMappings,
}

/// Channel-specific sender → unified-id resolver. Construct via
/// [`IdentityResolver::from_user_mappings`]; query via
/// [`IdentityResolver::resolve`]. Lookup is a single `HashMap` get
/// (target NFR: < 1 µs).
#[derive(Debug, Clone)]
pub struct IdentityResolver {
    /// `(channel_kind, channel_id)` → unified id (`user:alice`). A **tuple
    /// key** (not a `"{kind}:{id}"` concatenation) is used deliberately:
    /// channel kinds / channel-native ids are NOT `is_safe_id`-constrained
    /// (real Telegram/Slack ids may contain `:`), so a delimiter-joined key
    /// would alias logically-distinct pairs (`("a:b","c")` vs `("a","b:c")`
    /// both → `"a:b:c"`) — an identity-spoof primitive. The tuple key has
    /// zero delimiter ambiguity (Adversarial r1 fix).
    mappings: HashMap<(String, String), String>,
}

impl IdentityResolver {
    /// An empty resolver — every `resolve` returns `None`. Used by callers
    /// (and the slice-A-compat dispatcher constructor) that have no identity
    /// config wired yet.
    pub fn empty() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Build from a slice of [`UserChannelMapping`]. Validates each user id
    /// (`is_safe_id` + `user:` prefix), rejects empty fields, multi-key
    /// channel maps, duplicate `(kind, id)` pairs across users, and caps the
    /// total at [`MAX_IDENTITY_MAPPINGS`].
    pub fn from_user_mappings(users: &[UserChannelMapping]) -> Result<Self, IdentityResolverError> {
        let mut mappings: HashMap<(String, String), String> = HashMap::new();
        for u in users {
            if u.id.is_empty() {
                return Err(IdentityResolverError::EmptyField("id"));
            }
            if !is_safe_id(&u.id) || !u.id.starts_with(USER_PREFIX) {
                return Err(IdentityResolverError::UnsafeUserId);
            }
            // OUTER loop over the Vec; INNER loop over the single-entry map.
            for channel_map in &u.channels {
                if channel_map.len() != 1 {
                    return Err(IdentityResolverError::MultiKeyChannelMap);
                }
                for (kind, cid) in channel_map {
                    if kind.is_empty() {
                        return Err(IdentityResolverError::EmptyField("channel_kind"));
                    }
                    if cid.is_empty() {
                        return Err(IdentityResolverError::EmptyField("channel_id"));
                    }
                    let key = (kind.clone(), cid.clone());
                    if mappings.contains_key(&key) {
                        return Err(IdentityResolverError::DuplicateChannelPair);
                    }
                    if mappings.len() >= MAX_IDENTITY_MAPPINGS {
                        return Err(IdentityResolverError::TooManyMappings);
                    }
                    mappings.insert(key, u.id.clone());
                }
            }
        }
        Ok(Self { mappings })
    }

    /// Resolve a channel-specific sender to its unified id, or `None` if
    /// unmapped. O(1).
    pub fn resolve(&self, channel_kind: &str, channel_id: &str) -> Option<String> {
        // Tuple-keyed lookup — no delimiter ambiguity (Adversarial r1 fix).
        self.mappings
            .get(&(channel_kind.to_string(), channel_id.to_string()))
            .cloned()
    }

    /// Mapping count (test/diagnostic).
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(kind: &str, id: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(kind.to_string(), id.to_string());
        m
    }

    #[test]
    fn empty_resolver_resolves_nothing() {
        let r = IdentityResolver::empty();
        assert_eq!(r.resolve("telegram", "x"), None);
        assert!(r.is_empty());
    }

    #[test]
    fn from_user_mappings_basic_resolve() {
        let r = IdentityResolver::from_user_mappings(&[UserChannelMapping {
            id: "user:alice".into(),
            channels: vec![map("telegram", "user123")],
        }])
        .unwrap();
        assert_eq!(
            r.resolve("telegram", "user123").as_deref(),
            Some("user:alice")
        );
    }
}
