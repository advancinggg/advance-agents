//! `SubsetValidator` (CONTRACT-122, MODULE-013 §1.4.3 / PRD §5.7.4).
//!
//! Parameter-level subset rules, one helper per capability family. `web` takes no
//! params (whole-capability only), and the retired `data` family keeps its rule so
//! persisted grants still narrow and revoke. Trait + impl live local to `cap-grant`
//! (NOT promoted to shared-types — ARCH §4.2's dependency-inversion list excludes
//! CONTRACT-122; ARCH §6.1's CONTRACT-122 row direction is M013 → M005 as a
//! direct compile-time edge).
//!
//! [`SubsetValidator::validate`] answers "may `parent` issue `child`?" (narrow,
//! delegate, preset apply, spawn admission). [`SubsetValidatorImpl::covers_request`]
//! answers "does this held grant cover this call?" for the L1 gate; it is
//! `validate` for every family except `mcp`.
//!
//! Fail-closed posture per PRD §5.7.4 mandate "Subset rules enforced
//! unconditionally; no bypass path":
//! - Unknown capability names → `SubsetViolation` (a strict superset would
//!   silently approve novel capability types and is forbidden).
//! - Capability name mismatch between parent and child → `SubsetViolation`.
//! - Empty parent params (`params == []`) = "whole-capability grant" — any
//!   child params are subset (an `mcp` child must still be well-formed; see
//!   below).
//! - Empty child params = "request whole capability" — fails closed against a
//!   restricted parent (cannot widen).
//! - A key the child leaves out is not requested, so it is never a violation,
//!   whatever the parent holds (a data-tool read carries `read-paths` without
//!   `write-paths`).
//! - A key the child carries that the parent leaves out is a violation: the
//!   parent grants nothing on that key.
//! - Numeric `≤` rule on non-parsable values → `SubsetViolation`.
//!
//! `mcp` departs from those key rules, because leaving its `tool-patterns` key
//! out means every tool:
//! - `servers` is a set of literal server ids; leaving it out reaches no server.
//! - `tool-patterns` holds trailing-`*` patterns ([`advance_shared_types::mcp`]).
//!   A parent without it covers any well-formed child patterns. A child that
//!   leaves it out while the parent has it would reach every tool and is refused.
//!   Otherwise every child pattern must be covered by a parent pattern. A
//!   malformed pattern on either side is a violation.
//! - A key other than `servers` / `tool-patterns` is a violation, so a misspelled
//!   key never leaves the tool axis unrestricted.
//! - The child's keys and patterns are checked even under a whole-capability
//!   parent, so a misspelled key or a malformed pattern never passes `validate`.
//! - At call time ([`SubsetValidatorImpl::covers_request`]) request tokens are
//!   literal server ids and tool names, a request must name its server, and a
//!   request without `tool-patterns` asks for the server only, skipping the tool
//!   axis. The literal tool
//!   [`SERVER_WIDE_TOOL`](advance_shared_types::mcp::SERVER_WIDE_TOOL), which
//!   stands for a server's prompts and resources, matches no pattern, so only an
//!   unrestricted tool axis covers it.
//!
//! URL pattern subset (`http.allowlist`) uses an inline string-prefix
//! algorithm with `<prefix>/*` structural-separator enforcement — see
//! `url_pattern_subset` rustdoc for the threat model and accepted/rejected
//! shapes.

use advance_shared_types::mcp::{McpGrantScope, ToolPattern};

use crate::data::{CapParam, Grant, GrantDraft};
use crate::error::CapGrantError;

/// CONTRACT-122. Parameter-level subset checker invoked at narrow / preset-
/// apply / future M005 spawn enforcement points.
pub trait SubsetValidator: Send + Sync {
    fn validate(&self, parent: &Grant, child: &GrantDraft) -> Result<(), CapGrantError>;
}

/// Concrete impl with the per-family subset rules (see the module docs).
pub struct SubsetValidatorImpl;

impl SubsetValidatorImpl {
    pub fn new() -> Self {
        Self
    }

    /// The call-time check of the L1 gate: does the `held` grant cover `request`?
    ///
    /// For every family but `mcp` this is [`SubsetValidator::validate`]. An `mcp` request
    /// describes a call, not a grant: its tokens are literal server ids and tool names, it must
    /// name the server it addresses, and without `tool-patterns` it asks for the server only.
    /// Coverage is decided by the held grant's [`McpGrantScope`], the same scope the listing
    /// reader returns, so a listing and a call agree.
    pub fn covers_request(&self, held: &Grant, request: &GrantDraft) -> Result<(), CapGrantError> {
        if held.capability == "mcp" && request.capability == "mcp" {
            return covers_mcp_request(&held.params, &request.params);
        }
        self.validate(held, request)
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

        // An `mcp` child is checked for keys and pattern grammar whatever the parent holds:
        // issued from a whole-capability parent, a misspelled key or a malformed pattern would
        // otherwise make a grant that silently covers less than it reads.
        if child.capability == "mcp" {
            reject_unknown_mcp_keys(&child.params, "child")?;
            parse_tool_patterns(&child.params, "child")?;
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
            // Retired family: the `data` host tool is authorized by `fs` and nothing consults a
            // `data` grant. The arm stays so persisted grants still narrow and revoke cleanly.
            "data" => check_list_subset(&parent.params, &child.params, &["mode"]),
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
            // check_messaging / check_list_subset / check_mcp's `servers` axis
            // / check_skills / check_http / check_numeric_le / check_fs
            // read-paths.
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

/// The params an `mcp` grant may carry.
const MCP_KEYS: [&str; 2] = ["servers", "tool-patterns"];

/// Issuance rule for `mcp` (see the module docs): `servers` is a literal set that reaches no
/// server when absent; `tool-patterns` reaches every tool when absent, so a child may not drop a
/// parent's patterns, and child patterns must be covered by parent patterns.
fn check_mcp(parent: &[CapParam], child: &[CapParam]) -> Result<(), CapGrantError> {
    reject_unknown_mcp_keys(parent, "parent")?;
    reject_unknown_mcp_keys(child, "child")?;

    match (get_param(parent, "servers"), get_param(child, "servers")) {
        (_, None) => {}
        (None, Some(_)) => {
            return Err(CapGrantError::SubsetViolation(
                "mcp.servers: child requests servers but the parent reaches none".into(),
            ))
        }
        (Some(p), Some(c)) => {
            let pp = parse_csv(p);
            for cs in parse_csv(c) {
                if !pp.contains(&cs) {
                    return Err(CapGrantError::SubsetViolation(format!(
                        "mcp.servers: child {cs:?} not in parent set {pp:?}"
                    )));
                }
            }
        }
    }

    match (
        parse_tool_patterns(parent, "parent")?,
        parse_tool_patterns(child, "child")?,
    ) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(CapGrantError::SubsetViolation(
            "mcp.tool-patterns: child leaves out tool-patterns, which reaches every tool, but \
             the parent restricts tools"
                .into(),
        )),
        (Some(pp), Some(cc)) => {
            for c in &cc {
                if !pp.iter().any(|p| p.covers(c)) {
                    return Err(CapGrantError::SubsetViolation(format!(
                        "mcp.tool-patterns: child pattern `{c}` is not covered by a parent pattern"
                    )));
                }
            }
            Ok(())
        }
    }
}

/// One side's `tool-patterns`, `None` when the key is absent. A malformed pattern is a
/// violation.
fn parse_tool_patterns<'a>(
    params: &'a [CapParam],
    role: &str,
) -> Result<Option<Vec<ToolPattern<'a>>>, CapGrantError> {
    let Some(value) = get_param(params, "tool-patterns") else {
        return Ok(None);
    };
    parse_csv(value)
        .into_iter()
        .map(|raw| {
            ToolPattern::parse(raw).map_err(|e| {
                CapGrantError::SubsetViolation(format!(
                    "mcp.tool-patterns: {role} pattern {raw:?} is malformed: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn reject_unknown_mcp_keys(params: &[CapParam], role: &str) -> Result<(), CapGrantError> {
    match params.iter().find(|p| !MCP_KEYS.contains(&p.key.as_str())) {
        Some(p) => Err(CapGrantError::SubsetViolation(format!(
            "mcp: {role} carries {:?}, which is not an mcp param (servers, tool-patterns)",
            p.key
        ))),
        None => Ok(()),
    }
}

/// The scope one `mcp` grant reaches, or `None` when its params carry a key other than
/// `servers` / `tool-patterns` (such a grant covers nothing). A grant without params reaches
/// every server and tool; a restricted grant without `servers` reaches no server.
pub(crate) fn mcp_scope(params: &[CapParam]) -> Option<McpGrantScope> {
    if params.is_empty() {
        return Some(McpGrantScope::unrestricted());
    }
    if reject_unknown_mcp_keys(params, "grant").is_err() {
        return None;
    }
    let tokens = |key: &str| {
        get_param(params, key).map(|v| {
            parse_csv(v)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
    };
    Some(McpGrantScope {
        servers: Some(tokens("servers").unwrap_or_default()),
        tool_patterns: tokens("tool-patterns"),
    })
}

/// Call-time `mcp` coverage (see [`SubsetValidatorImpl::covers_request`]).
fn covers_mcp_request(held: &[CapParam], request: &[CapParam]) -> Result<(), CapGrantError> {
    let scope = mcp_scope(held).ok_or_else(|| {
        CapGrantError::SubsetViolation(
            "mcp: the held grant carries a param other than servers / tool-patterns and covers \
             nothing"
                .into(),
        )
    })?;
    reject_unknown_mcp_keys(request, "request")?;
    let servers = get_param(request, "servers")
        .map(parse_csv)
        .unwrap_or_default();
    if servers.is_empty() {
        return Err(CapGrantError::SubsetViolation(
            "mcp: a request must name the server it addresses".into(),
        ));
    }
    let tools = get_param(request, "tool-patterns").map(parse_csv);
    if tools.as_ref().is_some_and(Vec::is_empty) {
        return Err(CapGrantError::SubsetViolation(
            "mcp: a request carrying tool-patterns must name a tool".into(),
        ));
    }
    for server in &servers {
        let covered = match &tools {
            None => scope.covers_server(server),
            Some(tools) => tools.iter().all(|tool| scope.covers_tool(server, tool)),
        };
        if !covered {
            return Err(CapGrantError::SubsetViolation(format!(
                "mcp: the held grant does not cover the request on server {server:?}"
            )));
        }
    }
    Ok(())
}

/// What in an `mcp` grant's params makes part of it cover nothing, one line each; empty when
/// they are well-formed. Static config is stored without these checks, so the static compiler
/// reports them at boot.
pub fn mcp_param_problems(params: &[CapParam]) -> Vec<String> {
    let mut problems = Vec::new();
    if params.is_empty() {
        return problems;
    }
    for p in params
        .iter()
        .filter(|p| !MCP_KEYS.contains(&p.key.as_str()))
    {
        problems.push(format!(
            "`{}` is not an mcp param (servers, tool-patterns); the grant covers nothing",
            p.key
        ));
    }
    match get_param(params, "servers").map(parse_csv) {
        None => problems.push("`servers` is missing, so the grant reaches no server".to_string()),
        Some(servers) if servers.is_empty() => {
            problems.push("`servers` is empty, so the grant reaches no server".to_string())
        }
        Some(servers) => {
            for server in servers
                .into_iter()
                .filter(|s| s.contains(['*', '?', '[', ']', '{', '}']))
            {
                problems.push(format!(
                    "server {server:?} is a literal id and glob characters match nothing; list \
                     the servers, or grant `mcp: true` for every server"
                ));
            }
        }
    }
    if let Some(patterns) = get_param(params, "tool-patterns").map(parse_csv) {
        if patterns.is_empty() {
            problems.push("`tool-patterns` is empty, so the grant covers no tool".to_string());
        }
        for raw in patterns {
            if let Err(e) = ToolPattern::parse(raw) {
                problems.push(format!(
                    "tool pattern {raw:?} is malformed ({e}); the grant covers no tool"
                ));
            }
        }
    }
    problems
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
