//! `observability-lint` core algorithm.
//!
//! Walks `crates/capabilities/cap-*/src/**/*.rs` for every `impl
//! HostFunctionHandler for Type` block, looks inside the `fn call` body for
//! any of 4 emit-eligible call patterns, and reports unwaived gaps.
//!
//! # Emit-eligible patterns (Slice E Adversarial R1 Critical 1 narrowing)
//!
//! 1. `ExprCall` whose callee path's last segment is exactly `emit`
//!    (e.g. `EventBusEmit::emit(bus, event)`).
//! 2. `ExprMethodCall` with method name `emit`
//!    (e.g. `bus.emit(event)`, `self.event_bus.emit(...)`).
//! 3. `ExprCall` whose callee path's last segment is in `KNOWN_EMIT_HELPERS`
//!    (the curated list of canonical emit-helper free functions).
//! 4. `ExprMethodCall` with method name in `KNOWN_EMIT_HELPERS`.
//!
//! **Why the curated list (not `emit_*` open-ended)**: Slice E Adversarial R1
//! Critical 1 showed that matching ANY `emit_*` prefix lets a malicious
//! contributor pass the lint by naming a non-observability helper (e.g.
//! `self.audit.emit_local_only_metric()` or `metric.emit_counter()`) inside a
//! `HostFunctionHandler::call` body. The lint had no way to distinguish such
//! a name from a real EventBus emit. The curated list closes this elevation-
//! of-privilege vector — adding a new canonical helper requires an explicit
//! PR-reviewable edit to `KNOWN_EMIT_HELPERS`.
//!
//! The walker recurses through nested blocks, closures, async blocks, match
//! arms — anywhere expressions can appear in a `fn call` body.
//!
//! # What the lint does NOT do
//!
//! - **Transitive call-chain analysis**: a handler that calls
//!   `gateway.generate()` which itself calls `emit_llm_response()` is NOT
//!   detected as emit-eligible. Such handlers MUST be in
//!   `observability-allowlist.toml` with `delegated_to: <call-site>`.
//! - **Macro expansion**: emits inside macro invocations (`emit_macro!(...)`)
//!   are not visible to syn's AST. Future slice can extend via `cargo expand`.
//!
//! # Allowlist schema
//!
//! ```toml
//! [[handler]]
//! crate = "cap-llm"
//! struct = "AgentLlmGenerateHandler"
//! reason = "Delegates to LlmGateway::generate; emits via emit_llm_request/response helpers below the handler boundary."
//! delegated_to = "advance_cap_llm::gateway::LlmGateway::generate"
//! # OR (XOR):
//! # pending_wiring_slice = "MODULE-019 §3.6 item 1"
//! ```
//!
//! Each entry requires `reason` AND EXACTLY ONE of `delegated_to` /
//! `pending_wiring_slice`. Both missing or both present → error. Schema is
//! validated via regex; the lint refuses to load on any malformed entry.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serde::Deserialize;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, ImplItem, Item, ItemImpl};
use walkdir::WalkDir;

/// Slice E Adversarial R1 W6 fix: per-file byte cap when reading capability
/// crate sources. Defends the lint against supply-chain DoS via a malicious
/// PR that lands a 500-MB `host_fn.rs`. 10 MiB is generous (cap-fs's
/// host_fn.rs is ~80 KiB today); any legitimate handler file fits comfortably
/// below the cap.
const MAX_LINT_FILE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(ClapArgs, Debug)]
pub(crate) struct Args {
    /// Workspace root path (containing the `crates/capabilities/` directory).
    /// Defaults to current working directory.
    #[arg(long, default_value = ".")]
    workspace: PathBuf,

    /// Path to the allowlist file. Defaults to `<workspace>/observability-allowlist.toml`.
    #[arg(long)]
    allowlist: Option<PathBuf>,

    /// Emit machine-readable JSON output instead of human-readable text.
    #[arg(long, default_value_t = false)]
    json: bool,
}

/// Single violation detected by the AST walker.
#[derive(Debug, Clone)]
struct Violation {
    crate_name: String,
    struct_name: String,
    file: PathBuf,
    line: usize,
}

/// One allowlist entry. Schema enforced in `validate_allowlist`.
#[derive(Deserialize, Debug)]
struct AllowlistEntry {
    #[serde(rename = "crate")]
    crate_name: String,
    #[serde(rename = "struct")]
    struct_name: String,
    reason: String,
    #[serde(default)]
    delegated_to: Option<String>,
    #[serde(default)]
    pending_wiring_slice: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct AllowlistFile {
    #[serde(default)]
    handler: Vec<AllowlistEntry>,
}

pub(crate) fn run(args: Args) -> Result<ExitCode> {
    // Allowlist load + schema validation.
    let allowlist_path = args
        .allowlist
        .clone()
        .unwrap_or_else(|| args.workspace.join("observability-allowlist.toml"));
    let waived = load_allowlist(&allowlist_path)?;

    // Walk capability crates' src/ for HostFunctionHandler impls without emit.
    let cap_dir = args.workspace.join("crates").join("capabilities");
    let mut violations = Vec::<Violation>::new();
    for entry in WalkDir::new(&cap_dir).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        // Skip target/ directories defensively.
        if path.components().any(|c| c.as_os_str() == "target") {
            continue;
        }
        // Only process files inside cap-*/src/...
        if !is_inside_cap_src(path, &cap_dir) {
            continue;
        }
        let crate_name = match cap_crate_name(path, &cap_dir) {
            Some(c) => c,
            None => continue,
        };
        // Slice E Adversarial R1 W6 fix: bound .rs file size to defend the
        // lint against supply-chain DoS via a malicious PR adding a multi-MB
        // host_fn.rs. Files larger than MAX_LINT_FILE_BYTES are skipped with
        // a stderr warning; the lint's responsibility is to enforce the
        // emit-coverage convention on tractable source, not parse arbitrary
        // attacker-controlled blobs.
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() > MAX_LINT_FILE_BYTES {
                eprintln!(
                    "observability-lint: skipping {} ({} bytes > {} byte cap)",
                    path.display(),
                    meta.len(),
                    MAX_LINT_FILE_BYTES
                );
                continue;
            }
        }
        let src = fs::read_to_string(path)
            .with_context(|| format!("read source file {}", path.display()))?;
        let parsed = match syn::parse_file(&src) {
            Ok(f) => f,
            Err(_) => continue,
        };
        collect_violations(&parsed, &crate_name, path, &mut violations);
    }

    // Filter against allowlist.
    let unwaived: Vec<&Violation> = violations
        .iter()
        .filter(|v| !waived.contains(&(v.crate_name.clone(), v.struct_name.clone())))
        .collect();

    if args.json {
        let json = serde_json::json!({
            "violations": unwaived.iter().map(|v| serde_json::json!({
                "crate": v.crate_name,
                "struct": v.struct_name,
                "file": v.file.display().to_string(),
                "line": v.line,
            })).collect::<Vec<_>>(),
            "total_violations_pre_allowlist": violations.len(),
            "unwaived_count": unwaived.len(),
        });
        println!("{}", json);
    } else if unwaived.is_empty() {
        println!(
            "observability-lint: OK ({} handlers inspected, {} allowlist entries)",
            violations.len() + waived.len(),
            waived.len()
        );
    } else {
        eprintln!(
            "observability-lint: {} unwaived violation(s):",
            unwaived.len()
        );
        for v in &unwaived {
            eprintln!(
                "  - {}::{} ({}:{}) — no emit-eligible call found in HostFunctionHandler::call body",
                v.crate_name,
                v.struct_name,
                v.file.display(),
                v.line
            );
        }
    }

    Ok(if unwaived.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Returns true if `path` is inside `<workspace>/crates/capabilities/cap-*/src/`.
fn is_inside_cap_src(path: &Path, cap_dir: &Path) -> bool {
    let rel = match path.strip_prefix(cap_dir) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut comps = rel.components();
    let cap_crate = comps
        .next()
        .and_then(|c| c.as_os_str().to_str())
        .unwrap_or("");
    if !cap_crate.starts_with("cap-") {
        return false;
    }
    let second = comps
        .next()
        .and_then(|c| c.as_os_str().to_str())
        .unwrap_or("");
    second == "src"
}

/// Returns `Some("cap-foo")` if `path` is `<cap_dir>/cap-foo/src/...`.
fn cap_crate_name(path: &Path, cap_dir: &Path) -> Option<String> {
    let rel = path.strip_prefix(cap_dir).ok()?;
    let first = rel.components().next()?;
    Some(first.as_os_str().to_str()?.to_string())
}

/// AST walker — for each `impl HostFunctionHandler for T { fn call ... }`
/// block in `file`, check the body for emit-eligible calls. If none, record
/// a violation for struct `T`.
fn collect_violations(file: &syn::File, crate_name: &str, path: &Path, out: &mut Vec<Violation>) {
    for item in &file.items {
        if let Item::Impl(ItemImpl {
            trait_: Some((_, trait_path, _)),
            self_ty,
            items,
            ..
        }) = item
        {
            // Match the trait path's LAST segment exactly.
            let last_seg = match trait_path.segments.last() {
                Some(s) => s.ident.to_string(),
                None => continue,
            };
            if last_seg != "HostFunctionHandler" {
                continue;
            }
            // Extract the impl's Self type name.
            let struct_name = match &**self_ty {
                syn::Type::Path(p) => match p.path.segments.last() {
                    Some(s) => s.ident.to_string(),
                    None => continue,
                },
                _ => continue,
            };
            // Find `fn call(...)` inside the impl block.
            let call_method = items.iter().find_map(|it| {
                if let ImplItem::Fn(f) = it {
                    if f.sig.ident == "call" {
                        return Some(f);
                    }
                }
                None
            });
            let call_fn = match call_method {
                Some(f) => f,
                None => continue,
            };
            // Walk the function body for emit-eligible calls.
            let mut visitor = EmitVisitor::default();
            visitor.visit_block(&call_fn.block);
            if !visitor.found_emit {
                let line = call_fn.sig.ident.span().start().line;
                out.push(Violation {
                    crate_name: crate_name.to_string(),
                    struct_name,
                    file: path.to_path_buf(),
                    line,
                });
            }
        }
    }
}

/// Curated list of canonical emit-helper function/method names. Slice E
/// Adversarial R1 Critical 1 narrowing — the lint matches ONLY these names
/// (plus the bare `emit` method), NOT arbitrary `emit_*` prefixes. Adding a
/// new canonical helper requires an explicit PR-reviewable edit to this
/// list. Names below are taken from current cap-*/src/*.rs emit-helper usage
/// (verified by `grep -rn "fn emit_" crates/capabilities/`):
///
/// - `emit_fs_event` (cap-fs/src/events.rs:163,201)
/// - `emit_llm_request` / `emit_llm_response` / `emit_llm_retry` /
///   `emit_llm_error` (cap-llm/src/events.rs)
/// - `emit_authz_checked` (cap-grant/src/check.rs)
/// - `emit_runtime_degraded` (cap-fs/src/events.rs:161 — dynamic
///   `runtime.degraded.{reason}` prefix)
/// - `emit_warning` (event-bus/src/lib.rs / sweeper.rs system-emitter path)
///
/// **Maintenance**: when a new cap-* slice introduces an emit helper,
/// adding the name here is the gate. PR review verifies the helper actually
/// invokes the EventBus (closes Adversarial R1 Critical 1).
const KNOWN_EMIT_HELPERS: &[&str] = &[
    "emit_fs_event",
    "emit_llm_request",
    "emit_llm_response",
    "emit_llm_retry",
    "emit_llm_error",
    "emit_authz_checked",
    "emit_runtime_degraded",
    "emit_warning",
];

#[derive(Default)]
struct EmitVisitor {
    found_emit: bool,
}

impl EmitVisitor {
    fn check_path_last(&mut self, last_seg: &str) {
        if last_seg == "emit" || KNOWN_EMIT_HELPERS.contains(&last_seg) {
            self.found_emit = true;
        }
    }
}

impl<'ast> Visit<'ast> for EmitVisitor {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.found_emit {
            return;
        }
        // Pattern 1 + 3: callee is a Path expression with last segment `emit`
        // or `emit_*`.
        if let Expr::Path(p) = &*node.func {
            if let Some(last) = p.path.segments.last() {
                let s = last.ident.to_string();
                self.check_path_last(&s);
            }
        }
        // Recurse into args + callee.
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if self.found_emit {
            return;
        }
        // Pattern 2 + 4: method name `emit` or `emit_*`.
        let s = node.method.to_string();
        self.check_path_last(&s);
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// Load the allowlist, validate schema, return the set of waived
/// (crate, struct) tuples.
fn load_allowlist(path: &Path) -> Result<HashSet<(String, String)>> {
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let src =
        fs::read_to_string(path).with_context(|| format!("read allowlist {}", path.display()))?;
    let parsed: AllowlistFile =
        toml::from_str(&src).with_context(|| format!("parse allowlist toml {}", path.display()))?;
    let mut out = HashSet::new();
    for entry in parsed.handler {
        validate_entry(&entry, path)?;
        out.insert((entry.crate_name, entry.struct_name));
    }
    Ok(out)
}

/// Schema validation: reason non-empty, XOR of delegated_to/pending_wiring_slice,
/// format checks on the chosen field.
fn validate_entry(entry: &AllowlistEntry, allowlist_path: &Path) -> Result<()> {
    if entry.reason.trim().is_empty() {
        anyhow::bail!(
            "{}: entry for {}::{} has empty 'reason' (required, non-empty after trim)",
            allowlist_path.display(),
            entry.crate_name,
            entry.struct_name
        );
    }
    match (&entry.delegated_to, &entry.pending_wiring_slice) {
        (None, None) => anyhow::bail!(
            "{}: entry for {}::{} must specify EXACTLY ONE of 'delegated_to' or 'pending_wiring_slice'",
            allowlist_path.display(), entry.crate_name, entry.struct_name
        ),
        (Some(_), Some(_)) => anyhow::bail!(
            "{}: entry for {}::{} cannot specify BOTH 'delegated_to' AND 'pending_wiring_slice' (XOR violation)",
            allowlist_path.display(), entry.crate_name, entry.struct_name
        ),
        (Some(d), None) => validate_delegated_to(d, &entry.crate_name, &entry.struct_name, allowlist_path)?,
        (None, Some(s)) => validate_pending_wiring_slice(s, &entry.crate_name, &entry.struct_name, allowlist_path)?,
    }
    Ok(())
}

/// `delegated_to` format: `<ident>::<ident>::<ident>(::<ident>)*` — at least 3
/// segments (2+ `::` separators). Rejects 2-segment garbage like `foo::bar`.
fn validate_delegated_to(
    value: &str,
    crate_name: &str,
    struct_name: &str,
    path: &Path,
) -> Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!(
            "{}: entry for {}::{} has empty 'delegated_to'",
            path.display(),
            crate_name,
            struct_name
        );
    }
    // Validate path-like format: at least 3 segments separated by `::`.
    let segments: Vec<&str> = value.split("::").collect();
    if segments.len() < 3 {
        anyhow::bail!(
            "{}: entry for {}::{}: 'delegated_to' = {:?} must have at least 3 segments separated by '::' (e.g. crate::module::function); got {} segment(s)",
            path.display(), crate_name, struct_name, value, segments.len()
        );
    }
    for seg in &segments {
        if seg.is_empty() {
            anyhow::bail!(
                "{}: entry for {}::{}: 'delegated_to' = {:?} has empty segment",
                path.display(),
                crate_name,
                struct_name,
                value
            );
        }
        let mut chars = seg.chars();
        let first = chars.next().unwrap();
        if !(first.is_ascii_alphabetic() || first == '_') {
            anyhow::bail!(
                "{}: entry for {}::{}: 'delegated_to' = {:?} segment {:?} must start with letter or underscore",
                path.display(), crate_name, struct_name, value, seg
            );
        }
        for c in chars {
            if !(c.is_ascii_alphanumeric() || c == '_') {
                anyhow::bail!(
                    "{}: entry for {}::{}: 'delegated_to' = {:?} segment {:?} contains invalid char {:?}",
                    path.display(), crate_name, struct_name, value, seg, c
                );
            }
        }
    }
    Ok(())
}

/// `pending_wiring_slice` format: one of
/// - `^MODULE-\d{3}` (module-anchored reference)
/// - `^m\d{3}-slice-[a-z]` (canonical slice ID per repo convention)
/// - `^docs/` (doc-path reference)
///
/// All matching is done over `bytes()` to avoid multibyte-char-boundary panics
/// from `str[a..b]` byte-slicing on attacker-controlled input (Audit R1 W3 fix).
fn validate_pending_wiring_slice(
    value: &str,
    crate_name: &str,
    struct_name: &str,
    path: &Path,
) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "{}: entry for {}::{} has empty 'pending_wiring_slice' (required when delegated_to is None)",
            path.display(), crate_name, struct_name
        );
    }
    // Byte-level matching — Rust strings are byte-indexable but `&str[a..b]`
    // panics if a or b is not a UTF-8 char boundary. Working in &[u8] sidesteps
    // the boundary issue (allowlists are ASCII-only anyway).
    let bytes = trimmed.as_bytes();
    // ^MODULE-\d{3}: 10+ bytes; "MODULE-" prefix + 3 ASCII digits at positions 7..10.
    let module_anchored = bytes.len() >= 10
        && bytes.starts_with(b"MODULE-")
        && bytes[7..10].iter().all(|b| b.is_ascii_digit());
    // ^m\d{3}-slice-[a-z]: 12+ bytes; 'm' + 3 ASCII digits at 1..4 + "-slice-"
    // at 4..11 + ASCII lowercase letter at position 11.
    let slice_id = bytes.len() >= 12
        && bytes[0] == b'm'
        && bytes[1..4].iter().all(|b| b.is_ascii_digit())
        && &bytes[4..11] == b"-slice-"
        && bytes[11].is_ascii_lowercase();
    // ^docs/: 5+ bytes.
    let doc_path = bytes.starts_with(b"docs/");
    if !(module_anchored || slice_id || doc_path) {
        anyhow::bail!(
            "{}: entry for {}::{}: 'pending_wiring_slice' = {:?} must start with one of: 'MODULE-<3-digits>', 'm<3-digits>-slice-<letter>', or 'docs/'",
            path.display(), crate_name, struct_name, value
        );
    }
    Ok(())
}

// ─── Tests (T78) ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t78_emit_visitor_detects_direct_method_call() {
        // Pattern 2: `bus.emit(event)`
        let src = "fn f() { bus.emit(event); }";
        let parsed = syn::parse_file(&format!(
            "impl Foo for Bar {{ fn call() {{ {} }} }}",
            src.replace("fn f() ", "")
        ))
        .unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(v.found_emit, "pattern 2 (.emit) should match");
    }

    #[test]
    fn t78_emit_visitor_detects_helper_function_call() {
        // Pattern 3: `emit_fs_event(emitter, ...)`
        let src = "{ emit_fs_event(emitter, &event); }";
        let parsed = syn::parse_file(&format!("impl Foo for Bar {{ fn call() {} }}", src)).unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(v.found_emit, "pattern 3 (emit_<helper>) should match");
    }

    #[test]
    fn t78_emit_visitor_detects_path_emit_call() {
        // Pattern 1: `EventBusEmit::emit(bus, event)`
        let src = "{ EventBusEmit::emit(bus, event); }";
        let parsed = syn::parse_file(&format!("impl Foo for Bar {{ fn call() {} }}", src)).unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(v.found_emit, "pattern 1 (Type::emit) should match");
    }

    #[test]
    fn t78_emit_visitor_detects_helper_method_call() {
        // Pattern 4: `self.emit_authz_checked(...)`
        let src = "{ self.emit_authz_checked(); }";
        let parsed = syn::parse_file(&format!("impl Foo for Bar {{ fn call() {} }}", src)).unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(v.found_emit, "pattern 4 (.emit_<helper>) should match");
    }

    #[test]
    fn t78_emit_visitor_misses_unrelated_calls() {
        let src = "{ let _ = compute(x); foo.process(); bar(); }";
        let parsed = syn::parse_file(&format!("impl Foo for Bar {{ fn call() {} }}", src)).unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(!v.found_emit, "non-emit calls must not match");
    }

    // Adversarial R1 Critical 1 regression: lint MUST NOT match arbitrary
    // emit_*-prefixed names (e.g. metric counters, local-only audit logs).
    // Only canonical helper names in KNOWN_EMIT_HELPERS plus the bare `emit`
    // method qualify.
    #[test]
    fn t78_emit_visitor_rejects_emit_local_metric() {
        let src = "{ self.audit.emit_local_only_metric(name); }";
        let parsed = syn::parse_file(&format!("impl Foo for Bar {{ fn call() {} }}", src)).unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(
            !v.found_emit,
            "emit_local_only_metric MUST NOT be counted as observability emit (Adv R1 C1)"
        );
    }

    #[test]
    fn t78_emit_visitor_rejects_emit_counter() {
        let src = "{ metric::emit_counter(name); }";
        let parsed = syn::parse_file(&format!("impl Foo for Bar {{ fn call() {} }}", src)).unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(
            !v.found_emit,
            "free-function emit_counter NOT in KNOWN_EMIT_HELPERS MUST NOT count (Adv R1 C1)"
        );
    }

    #[test]
    fn t78_emit_visitor_accepts_known_helper_emit_fs_event() {
        let src = "{ emit_fs_event(emitter, &event); }";
        let parsed = syn::parse_file(&format!("impl Foo for Bar {{ fn call() {} }}", src)).unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(
            v.found_emit,
            "emit_fs_event IS in KNOWN_EMIT_HELPERS and MUST count"
        );
    }

    #[test]
    fn t78_emit_visitor_finds_emit_in_nested_block() {
        // Pattern 2 inside an async block + closure.
        let src = "{ tokio::spawn(async move { let _ = self.event_bus.emit(event); }); }";
        let parsed = syn::parse_file(&format!("impl Foo for Bar {{ fn call() {} }}", src)).unwrap();
        let mut v = EmitVisitor::default();
        if let Item::Impl(imp) = &parsed.items[0] {
            if let ImplItem::Fn(f) = &imp.items[0] {
                v.visit_block(&f.block);
            }
        }
        assert!(v.found_emit, "nested-block .emit should match");
    }

    fn write_allowlist(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::io::Write::write_all(&mut f, content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn t73_allowlist_rejects_empty_reason() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-x"
struct = "Foo"
reason = ""
delegated_to = "a::b::c"
"#,
        );
        let res = load_allowlist(f.path());
        assert!(res.is_err(), "empty reason should fail");
        assert!(res.unwrap_err().to_string().contains("empty 'reason'"));
    }

    #[test]
    fn t73_allowlist_rejects_missing_both_xor_fields() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-x"
struct = "Foo"
reason = "reasonable"
"#,
        );
        let res = load_allowlist(f.path());
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("must specify EXACTLY ONE"));
    }

    #[test]
    fn t73_allowlist_rejects_both_xor_fields() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-x"
struct = "Foo"
reason = "reasonable"
delegated_to = "a::b::c"
pending_wiring_slice = "MODULE-019"
"#,
        );
        let res = load_allowlist(f.path());
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("cannot specify BOTH"));
    }

    #[test]
    fn t73_allowlist_rejects_empty_pending_wiring_slice() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-x"
struct = "Foo"
reason = "reasonable"
pending_wiring_slice = ""
"#,
        );
        let res = load_allowlist(f.path());
        assert!(res.is_err());
    }

    #[test]
    fn t73_allowlist_rejects_2_segment_delegated_to() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-x"
struct = "Foo"
reason = "reasonable"
delegated_to = "foo::bar"
"#,
        );
        let res = load_allowlist(f.path());
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("at least 3 segments"), "got: {}", msg);
    }

    #[test]
    fn t73_allowlist_accepts_valid_delegated_to() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-llm"
struct = "AgentLlmGenerateHandler"
reason = "delegates"
delegated_to = "advance_cap_llm::gateway::LlmGateway::generate"
"#,
        );
        let res = load_allowlist(f.path());
        assert!(res.is_ok(), "valid 4-segment delegated_to: {:?}", res);
        assert_eq!(res.unwrap().len(), 1);
    }

    #[test]
    fn t73_allowlist_accepts_valid_pending_wiring_slice_module() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-tools"
struct = "AgentToolsInvokeHandler"
reason = "pending"
pending_wiring_slice = "MODULE-019 §3.6 item 1"
"#,
        );
        assert!(load_allowlist(f.path()).is_ok());
    }

    #[test]
    fn t73_allowlist_accepts_valid_pending_wiring_slice_slice_id() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-tools"
struct = "AgentToolsInvokeHandler"
reason = "pending"
pending_wiring_slice = "m017-slice-c"
"#,
        );
        assert!(load_allowlist(f.path()).is_ok());
    }

    #[test]
    fn t73_allowlist_accepts_valid_pending_wiring_slice_docs() {
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-tools"
struct = "AgentToolsInvokeHandler"
reason = "pending"
pending_wiring_slice = "docs/modules/MODULE-019-observability.md"
"#,
        );
        assert!(load_allowlist(f.path()).is_ok());
    }

    #[test]
    fn t73_allowlist_rejects_slice_dash_prefix() {
        // Round 4 W1 / Round 5 fix: `^slice-` is NOT a canonical referent
        // (prose placeholders like `slice-B:` exist in cap-tools/lazy_registry.rs).
        let f = write_allowlist(
            r#"
[[handler]]
crate = "cap-tools"
struct = "AgentToolsInvokeHandler"
reason = "pending"
pending_wiring_slice = "slice-B"
"#,
        );
        let res = load_allowlist(f.path());
        assert!(res.is_err(), "loose 'slice-' prefix should be rejected");
    }
}
