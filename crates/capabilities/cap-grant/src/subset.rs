//! `SubsetValidator` (CONTRACT-122, MODULE-013 §1.4.3 / PRD §5.7.4).
//!
//! Implements the 14 parameter-level subset rules from spec §1.4.3 across 11
//! capability families (`web` is whole-capability-only). Trait + impl live local to `cap-grant` (NOT promoted
//! to shared-types — ARCH §4.2's dependency-inversion list excludes
//! CONTRACT-122; ARCH §6.1's CONTRACT-122 row direction is M013 → M005 as a
//! direct compile-time edge).
//!
//! Fail-closed posture per PRD §5.7.4 mandate "Subset rules enforced
//! unconditionally; no bypass path":
//! - Unknown capability names → `SubsetViolation` (a strict superset would
//!   silently approve novel capability types and is forbidden).
//! - Capability name mismatch between parent and child → `SubsetViolation`.
//! - Empty parent params (`params == []`) = "whole-capability grant" — any
//!   child params are subset.
//! - Empty child params = "request whole capability" — fails closed against a
//!   restricted parent (cannot widen).
//! - Numeric `≤` rule on non-parsable values → `SubsetViolation`.
//! - Set-subset on missing keys (parent has key, child is missing it) → child
//!   inherits the unrestricted whole-capability semantic for that key only IF
//!   parent's key is also missing; otherwise child's missing key is treated
//!   as "request all" and fails closed.
//!
//! URL pattern subset (`http.allowlist`) uses an inline string-prefix
//! algorithm with `<prefix>/*` structural-separator enforcement — see
//! `url_pattern_subset` rustdoc for the threat model and accepted/rejected
//! shapes.

use crate::data::{CapParam, Grant, GrantDraft};
use crate::error::CapGrantError;

/// CONTRACT-122. Parameter-level subset checker invoked at narrow / preset-
/// apply / future M005 spawn enforcement points.
pub trait SubsetValidator: Send + Sync {
    fn validate(&self, parent: &Grant, child: &GrantDraft) -> Result<(), CapGrantError>;
}

/// Concrete impl with the 14 subset rules from spec §1.4.3.
pub struct SubsetValidatorImpl;

impl SubsetValidatorImpl {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SubsetValidatorImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl SubsetValidator for SubsetValidatorImpl {
    fn validate(&self, parent: &Grant, child: &GrantDraft) -> Result<(), CapGrantError> {
        // Capability name must match exactly. Cross-capability subset is
        // never legal (a `tools` grant cannot subset a `fs` grant).
        if parent.capability != child.capability {
            return Err(CapGrantError::SubsetViolation(format!(
                "capability mismatch: parent={:?} child={:?}",
                parent.capability, child.capability
            )));
        }

        // Empty parent = whole-capability grant; any child params are subset.
        if parent.params.is_empty() {
            return Ok(());
        }

        // Empty child against a restricted parent is "request whole capability"
        // and fails closed (cannot widen).
        if child.params.is_empty() {
            return Err(CapGrantError::SubsetViolation(format!(
                "child requests whole capability {:?} but parent has restricted params",
                child.capability
            )));
        }

        match parent.capability.as_str() {
            "fs" => check_fs(&parent.params, &child.params),
            "http" => check_http(&parent.params, &child.params),
            "messaging" => check_messaging(&parent.params, &child.params),
            "lifecycle" => check_lifecycle(&parent.params, &child.params),
            "llm" => check_llm(&parent.params, &child.params),
            "secrets" => check_list_subset(&parent.params, &child.params, &["names"]),
            "tools" => check_list_subset(&parent.params, &child.params, &["ids"]),
            "notify" => check_list_subset(&parent.params, &child.params, &["targets"]),
            "mcp" => check_mcp(&parent.params, &child.params),
            "skills" => check_skills(&parent.params, &child.params),
            "web" => Err(CapGrantError::SubsetViolation(
                "web is a whole-capability-only grant dimension; param-level subset rules \
                 are undefined"
                    .into(),
            )),
            other => Err(CapGrantError::SubsetViolation(format!(
                "unknown capability {other:?} — subset rules undefined; fail-closed per \
                 PRD §5.7.4"
            ))),
        }
    }
}

// ----------------------------------------------------------------------------
// Per-capability rule helpers.
// Each helper assumes parent.params is non-empty AND child.params is non-empty
// (the SubsetValidatorImpl::validate dispatcher handles the empty cases).
// ----------------------------------------------------------------------------

fn get_param<'a>(params: &'a [CapParam], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|p| p.key == key)
        .map(|p| p.value.as_str())
}

fn parse_csv(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

fn check_fs(parent: &[CapParam], child: &[CapParam]) -> Result<(), CapGrantError> {
    // Both `read-paths` and `write-paths` must be path-prefix subsets.
    //
    // Audit-fix R4 (Adversarial Critical 1): paths containing `..` segments
    // are REJECTED outright as SubsetViolation — cap-grant performs no
    // filesystem canonicalization, so a child path like `/a/../etc/passwd`
    // would otherwise pass the prefix subset check (it starts with `/a/`)
    // and downstream cap-fs would resolve `..` to escape the parent root.
    // Both parent and child are checked: a parent with `..` is also
    // rejected (operator error — narrow patterns should not contain
    // traversal sequences).
    for key in ["read-paths", "write-paths"] {
        let p = get_param(parent, key);
        let c = get_param(child, key);
        match (p, c) {
            (None, None) => continue,
            (None, Some(_)) => {
                return Err(CapGrantError::SubsetViolation(format!(
                    "fs.{key}: child requests but parent has no {key}"
                )))
            }
            (Some(_), None) => continue, // parent has it, child doesn't request it — narrower
            (Some(p_csv), Some(c_csv)) => {
                let parent_paths = parse_csv(p_csv);
                let child_paths = parse_csv(c_csv);
                for path in parent_paths.iter().chain(child_paths.iter()) {
                    if path_has_traversal(path) {
                        return Err(CapGrantError::SubsetViolation(format!(
                            "fs.{key}: path {path:?} contains `..` segment — \
                             traversal sequences are not permitted (cap-grant \
                             does not canonicalize; downstream FS would escape parent root)"
                        )));
                    }
                }
                for cp in &child_paths {
                    if !parent_paths.iter().any(|pp| path_prefix_subset(pp, cp)) {
                        return Err(CapGrantError::SubsetViolation(format!(
                            "fs.{key}: child path {cp:?} not under any parent path \
                             {parent_paths:?}"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

fn path_has_traversal(path: &str) -> bool {
    // Reject any path whose segments include exactly `..` (parent ref) or `.`
    // (current ref). An empty segment (double slash) is also rejected as it
    // is non-canonical for filesystem paths.
    for seg in path.split('/') {
        if seg == ".." || seg == "." {
            return true;
        }
    }
    false
}

/// `child` must lie under `parent` as a path prefix. Equality counts.
/// Trailing `/` in parent is normalized.
fn path_prefix_subset(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    // Treat parent without trailing `/` as a directory: child must start
    // with parent + `/` to be a strict descendant. This rejects substring
    // collisions like parent=`/a` matching child=`/abc`.
    let parent_norm = parent.trim_end_matches('/');
    if parent_norm.is_empty() {
        // Parent is `/` or empty — covers everything.
        return true;
    }
    let prefix_with_slash = format!("{parent_norm}/");
    child.starts_with(&prefix_with_slash) || child == parent_norm
}

fn check_http(parent: &[CapParam], child: &[CapParam]) -> Result<(), CapGrantError> {
    let p = get_param(parent, "allowlist");
    let c = get_param(child, "allowlist");
    match (p, c) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(CapGrantError::SubsetViolation(
            "http.allowlist: child requests but parent has no allowlist".into(),
        )),
        (Some(_), None) => Ok(()),
        (Some(p_csv), Some(c_csv)) => {
            let parent_pats = parse_csv(p_csv);
            let child_pats = parse_csv(c_csv);

            // Up-front structural validation of every parent and child pattern.
            // A malformed pattern is always rejected — even if SOME other
            // parent pattern would have covered the child.
            for pp in &parent_pats {
                validate_url_pattern_form(pp, "parent")?;
            }
            for cp in &child_pats {
                validate_url_pattern_form(cp, "child")?;
            }

            for cp in &child_pats {
                let mut covered = false;
                for pp in &parent_pats {
                    if url_pattern_subset(pp, cp).is_ok() {
                        covered = true;
                        break;
                    }
                }
                if !covered {
                    return Err(CapGrantError::SubsetViolation(format!(
                        "http.allowlist: child pattern {cp:?} not contained by any parent \
                         pattern {parent_pats:?}"
                    )));
                }
            }
            Ok(())
        }
    }
}

/// Audit-fix R4 (Adversarial W7+W8+W9): structural-form validator for URL
/// patterns. Rejects patterns that:
/// - contain `*` anywhere other than as a suffix `/*` (prevents
///   domain-prefix collision and mid-string-wildcard ambiguity)
/// - contain `//` after the scheme (e.g. `https://x//etc/passwd`) — would
///   bypass prefix matching when downstream HTTP clients collapse `//` to
///   `/`
/// - contain `%` characters (rejects percent-encoded sequences that
///   downstream URL decoders could resolve to `..`-style traversal)
/// All rejections are SubsetViolation per PRD §5.7.4 fail-closed mandate.
fn validate_url_pattern_form(s: &str, role: &str) -> Result<(), CapGrantError> {
    // Audit-fix R6 (Adversarial R3 Warning 1): reject ASCII control
    // characters (0x00-0x1F, 0x7F) and any non-ASCII byte. Downstream HTTP
    // clients commonly strip or reinterpret such bytes during URL
    // canonicalization, allowing the canonical request URL to escape the
    // intended subset (`https://api.github.com/\x00*` would prefix-pass
    // against `https://api.github.com/*` but resolve to `https://api.github.com/`
    // after the NULL is stripped). Restricting to printable ASCII forces
    // the URL pattern to be a stable byte string. IDN / Unicode hostnames
    // must be expressed as their punycode form (`xn--...`), which is
    // pure-ASCII.
    for (i, b) in s.bytes().enumerate() {
        if b < 0x20 || b == 0x7F || b > 0x7F {
            return Err(CapGrantError::SubsetViolation(format!(
                "URL {role} pattern contains non-printable / non-ASCII byte \
                 0x{b:02x} at offset {i}: {s:?}"
            )));
        }
    }
    // Mid-string `*` rejection.
    if s.contains('*') && !s.ends_with("/*") {
        return Err(CapGrantError::SubsetViolation(format!(
            "URL {role} pattern wildcard must terminate as `/*` (got: {s:?}); \
             free-form `*` would permit domain-prefix collision"
        )));
    }
    // Disallow more than one `*` (only the trailing one is allowed).
    if s.matches('*').count() > 1 {
        return Err(CapGrantError::SubsetViolation(format!(
            "URL {role} pattern may contain at most one `*` (the trailing `/*`); \
             got: {s:?}"
        )));
    }
    // Percent-encoding rejection (would let downstream URL decoders escape).
    if s.contains('%') {
        return Err(CapGrantError::SubsetViolation(format!(
            "URL {role} pattern must not contain `%` (percent-encoding could \
             decode to `..` and bypass path-prefix subset semantics); got: {s:?}"
        )));
    }
    // Double-slash detection (only one `//` is allowed: the scheme separator
    // immediately after `:`). Any additional `//` would let downstream URL
    // canonicalization collapse `//` → `/` and effectively widen the pattern.
    if let Some(idx) = s.find("://") {
        let post_scheme = &s[idx + 3..];
        if post_scheme.contains("//") {
            return Err(CapGrantError::SubsetViolation(format!(
                "URL {role} pattern must not contain `//` after the scheme \
                 (got: {s:?}); HTTP clients commonly collapse `//` to `/` and \
                 the prefix subset semantics would not match the canonical form"
            )));
        }
    } else if s.contains("//") {
        // No scheme separator but contains `//` — also reject.
        return Err(CapGrantError::SubsetViolation(format!(
            "URL {role} pattern must not contain `//` (got: {s:?})"
        )));
    }
    Ok(())
}

/// Returns `Ok(())` iff every URL string matched by `child` is also matched
/// by `parent`. Both inputs must be either exact literals (no `*`) or
/// suffix-wildcard patterns of form `<prefix>/*`. Patterns containing `*`
/// that do NOT terminate as `/*` are rejected as `SubsetViolation` —
/// closes the domain-prefix-collision attack vector
/// (`https://api.github.com*` colliding with sibling-domain
/// `https://api.github.companyevil.com/*`).
///
/// The structural-separator enforcement is the load-bearing security
/// property: the algorithm guarantees that the wildcard `*` may only
/// match content following a `/` boundary, mirroring URL path semantics
/// rather than filename-glob semantics. Mid-glob patterns (`*/repos/*`)
/// and `**` semantics are NOT supported in Slice B (fail-closed by
/// rejection).
pub fn url_pattern_subset(parent: &str, child: &str) -> Result<(), CapGrantError> {
    validate_url_pattern_form(parent, "parent")?;
    validate_url_pattern_form(child, "child")?;

    if parent == child {
        return Ok(());
    }

    if let (Some(parent_prefix), Some(child_prefix)) =
        (parent.strip_suffix("/*"), child.strip_suffix("/*"))
    {
        // Both wildcard form. Child must extend parent at a path boundary.
        if child_prefix == parent_prefix || child_prefix.starts_with(&format!("{parent_prefix}/")) {
            return Ok(());
        }
    } else if let Some(parent_prefix) = parent.strip_suffix("/*") {
        // Parent wildcard, child literal. Child must lie under parent's prefix.
        if child == parent_prefix || child.starts_with(&format!("{parent_prefix}/")) {
            return Ok(());
        }
    }
    // Else: parent literal + child wildcard (child wider, never subset)
    //       OR structural separator missing — fall through.

    Err(CapGrantError::SubsetViolation(format!(
        "http pattern not contained: child {child:?} not subset of parent {parent:?}"
    )))
}

fn check_messaging(parent: &[CapParam], child: &[CapParam]) -> Result<(), CapGrantError> {
    // 1. send/targets: list subset
    let p_targets = get_param(parent, "targets");
    let c_targets = get_param(child, "targets");
    if let (Some(p), Some(c)) = (p_targets, c_targets) {
        let pp = parse_csv(p);
        let cc = parse_csv(c);
        for ct in &cc {
            if !pp.contains(ct) {
                return Err(CapGrantError::SubsetViolation(format!(
                    "messaging.targets: child target {ct:?} not in parent set {pp:?}"
                )));
            }
        }
    } else if c_targets.is_some() && p_targets.is_none() {
        return Err(CapGrantError::SubsetViolation(
            "messaging.targets: child requests but parent has no targets".into(),
        ));
    }
    // 2. max-fanout: ≤
    check_numeric_le(parent, child, "max-fanout")?;
    // 3. max-depth: ≤
    check_numeric_le(parent, child, "max-depth")?;
    Ok(())
}

fn check_lifecycle(parent: &[CapParam], child: &[CapParam]) -> Result<(), CapGrantError> {
    for key in ["spawn-child", "spawn-sub"] {
        let p = get_param(parent, key);
        let c = get_param(child, key);
        match (p, c) {
            (Some(p), Some(c)) => {
                let pb = parse_bool(p, key)?;
                let cb = parse_bool(c, key)?;
                // Child can be only false OR equal to parent.
                // i.e. child=true and parent=false → fail.
                if cb && !pb {
                    return Err(CapGrantError::SubsetViolation(format!(
                        "lifecycle.{key}: child=true exceeds parent=false"
                    )));
                }
            }
            // Adversarial round-2 fix (m013-slice-e): child requests the
            // bool key but parent does not grant it. Without this fail-closed
            // clause, the projection's new production wiring at
            // spawn-child / spawn-sub silently allowed a child to declare
            // `spawn-child: true` against a parent that had only
            // `spawn-sub` (or nothing at all) — a real privilege elevation
            // exposed by the slice's `CapGrantSubsetAdapter` becoming the
            // first production caller of `check_lifecycle`. Pattern matches
            // the symmetric `else if c.is_some() && p.is_none()` guards in
            // check_messaging / check_list_subset / check_mcp / check_skills
            // / check_http / check_numeric_le / check_fs read-paths.
            (None, Some(c_str)) => {
                // Reject regardless of c_str's value: even `c="false"` is
                // a child request for the key, and the safe posture is
                // "child must not introduce keys the parent does not grant".
                // (Operationally, a child explicitly declaring
                // `spawn-child: false` is redundant with the parent's
                // absent key, but accepting it would establish a precedent
                // that "child can carry keys parent lacks if value is false",
                // which is fragile — narrow strengthens fail-closed.)
                return Err(CapGrantError::SubsetViolation(format!(
                    "lifecycle.{key}: child requests {c_str:?} but parent \
                     has no {key} (fail-closed; pre-existing helper bug \
                     closed in m013-slice-e adversarial round 2)"
                )));
            }
            (Some(_), None) | (None, None) => {
                // Parent has the key, child doesn't → child is narrower or
                // absent (safe). Both absent → noop.
            }
        }
    }
    Ok(())
}

fn parse_bool(s: &str, key: &str) -> Result<bool, CapGrantError> {
    match s.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(CapGrantError::SubsetViolation(format!(
            "{key}: not a boolean: {other:?}"
        ))),
    }
}

fn check_llm(parent: &[CapParam], child: &[CapParam]) -> Result<(), CapGrantError> {
    // 1. models list (set subset)
    let p_models = get_param(parent, "models");
    let c_models = get_param(child, "models");
    if let (Some(p), Some(c)) = (p_models, c_models) {
        let pp = parse_csv(p);
        let cc = parse_csv(c);
        for cm in &cc {
            if !pp.contains(cm) {
                return Err(CapGrantError::SubsetViolation(format!(
                    "llm.models: child model {cm:?} not in parent set {pp:?}"
                )));
            }
        }
    } else if c_models.is_some() && p_models.is_none() {
        return Err(CapGrantError::SubsetViolation(
            "llm.models: child requests but parent has no models".into(),
        ));
    }
    // 2. max-tokens-per-call ≤
    check_numeric_le(parent, child, "max-tokens-per-call")?;
    Ok(())
}

fn check_mcp(parent: &[CapParam], child: &[CapParam]) -> Result<(), CapGrantError> {
    for key in ["servers", "tool-patterns"] {
        let p = get_param(parent, key);
        let c = get_param(child, key);
        if let (Some(p), Some(c)) = (p, c) {
            let pp = parse_csv(p);
            let cc = parse_csv(c);
            for ct in &cc {
                if !pp.contains(ct) {
                    return Err(CapGrantError::SubsetViolation(format!(
                        "mcp.{key}: child {ct:?} not in parent set {pp:?}"
                    )));
                }
            }
        } else if c.is_some() && p.is_none() {
            return Err(CapGrantError::SubsetViolation(format!(
                "mcp.{key}: child requests but parent has no {key}"
            )));
        }
    }
    Ok(())
}

fn check_skills(parent: &[CapParam], child: &[CapParam]) -> Result<(), CapGrantError> {
    // 1. max-active-skills ≤
    check_numeric_le(parent, child, "max-active-skills")?;
    // 2. allowed-actions (set subset)
    let p = get_param(parent, "allowed-actions");
    let c = get_param(child, "allowed-actions");
    if let (Some(p), Some(c)) = (p, c) {
        let pp = parse_csv(p);
        let cc = parse_csv(c);
        for ct in &cc {
            if !pp.contains(ct) {
                return Err(CapGrantError::SubsetViolation(format!(
                    "skills.allowed-actions: child action {ct:?} not in parent set {pp:?}"
                )));
            }
        }
    } else if c.is_some() && p.is_none() {
        return Err(CapGrantError::SubsetViolation(
            "skills.allowed-actions: child requests but parent has no allowed-actions".into(),
        ));
    }
    Ok(())
}

/// Generic helper for set-subset on a single key (e.g. secrets.names,
/// tools.ids, notify.targets). The list of acceptable keys is whitelisted
/// per capability (callers pass `&["names"]` for secrets, etc.).
fn check_list_subset(
    parent: &[CapParam],
    child: &[CapParam],
    keys: &[&str],
) -> Result<(), CapGrantError> {
    for key in keys {
        let p = get_param(parent, key);
        let c = get_param(child, key);
        if let (Some(p), Some(c)) = (p, c) {
            let pp = parse_csv(p);
            let cc = parse_csv(c);
            for ct in &cc {
                if !pp.contains(ct) {
                    return Err(CapGrantError::SubsetViolation(format!(
                        "{key}: child {ct:?} not in parent set {pp:?}"
                    )));
                }
            }
        } else if c.is_some() && p.is_none() {
            return Err(CapGrantError::SubsetViolation(format!(
                "{key}: child requests but parent has no {key}"
            )));
        }
    }
    Ok(())
}

fn check_numeric_le(
    parent: &[CapParam],
    child: &[CapParam],
    key: &str,
) -> Result<(), CapGrantError> {
    let p = get_param(parent, key);
    let c = get_param(child, key);
    if let (Some(p), Some(c)) = (p, c) {
        let pn = p.trim().parse::<u64>().map_err(|e| {
            CapGrantError::SubsetViolation(format!("{key}: parent not a number: {p:?} ({e})"))
        })?;
        let cn = c.trim().parse::<u64>().map_err(|e| {
            CapGrantError::SubsetViolation(format!("{key}: child not a number: {c:?} ({e})"))
        })?;
        if cn > pn {
            return Err(CapGrantError::SubsetViolation(format!(
                "{key}: child {cn} > parent {pn}"
            )));
        }
    } else if c.is_some() && p.is_none() {
        return Err(CapGrantError::SubsetViolation(format!(
            "{key}: child requests but parent has no {key}"
        )));
    }
    Ok(())
}
