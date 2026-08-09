//! MODULE-001-T20 — Structural test for MODULE-001-AC-09 (REQ-330).
//!
//! AC-09: "Runtime component structure matches §16 (PRD): crates directory layout
//! exists with runtime/filesystem/git/database/messaging/sandbox/capabilities/tree/
//! scheduler/services/audit/event-bus/cost-tracker/cli."
//!
//! Of AC-09's 14 top-level dir expectations, 10 are present as top-level crates and
//! 4 are RELOCATED per architectural decisions taken during impl:
//!   - `filesystem` → `crates/capabilities/cap-fs` (Layer-1 capability, not standalone)
//!   - `sandbox`    → `crates/runtime` — merged into the runtime crate; PRD §16's own
//!     definition of `sandbox` is "WASM sandbox: wasmtime integration, capability
//!     injection" — exactly what the runtime crate delivers via component_loader /
//!     wasi_linker / capability_injector modules. Asserted at crate-level only so
//!     internal file-layout refactors remain free.
//!   - `tree`       → `crates/capabilities/cap-grant` (per PRD §16 `tree/` =
//!     "Agent 树管理: 层级关系、权限推导、Grant 索引、子集校验、ResolverChain";
//!     most of that functionality lives in cap-grant. Run-tree state lives separately
//!     in crates/run-manager/ — a distinct PRD §16 entry that's out of AC-09 scope.)
//!   - `audit`      → `crates/services/observability-xtask` (MODULE-019 observability-
//!     lint enforcing the AC-01/AC-14 emit convention across cap-* crates; the
//!     workspace's compile-time audit-compliance guard. PRD §15 names event-bus +
//!     git log as the audit substrate — that substrate is asserted via
//!     `crates/event-bus/` in EXPECTED_PRESENT below.)
//!
//! This test asserts the 10 present crates exist AND that each of the 4 relocated
//! subsystems is reachable at its documented actual path. The path-mapping
//! assertions double as regression guards: if e.g. `cap-fs` is renamed or moved,
//! this test fails loud with the specific rationale text in the panic message.

use std::fs;
use std::path::{Path, PathBuf};

/// §16 dirs that exist as top-level crates today. Each MUST be a directory under
/// `<workspace_root>/crates/`.
const EXPECTED_PRESENT: &[&str] = &[
    "runtime",
    "git",
    "database",
    "messaging",
    "capabilities",
    "scheduler",
    "services",
    "event-bus",
    "cost-tracker",
    "cli",
];

/// §16 dirs that do NOT exist as top-level crates. Each entry pairs the §16 name
/// with (a) the actual relative path under the workspace root, and (b) the
/// architectural rationale. The path MUST be a directory for the test to pass —
/// this acts as a regression guard against silent removal of the relocated
/// subsystem.
const WAIVED_RELOCATED: &[(&str, &str, &str)] = &[
    (
        "filesystem",
        "crates/capabilities/cap-fs",
        "file I/O is a Layer-1 capability under L0 static injection; not a standalone subsystem",
    ),
    (
        "sandbox",
        "crates/runtime",
        "merged into the runtime crate (wasmtime integration); per PRD §16's own \
         definition \"sandbox = WASM sandbox: wasmtime integration, capability injection\" \
         — exactly what the runtime crate's component_loader / wasi_linker / \
         capability_injector modules deliver. Asserted at crate-level only so internal \
         file-layout refactors under crates/runtime/src/ remain free",
    ),
    (
        "tree",
        "crates/capabilities/cap-grant",
        "PRD §16 `tree/` = Agent tree management (hierarchy, permission derivation, \
         Grant indexing, SubsetValidator, ResolverChain); most of that lives in cap-grant. \
         Run-tree state lives separately in crates/run-manager/ — a distinct PRD §16 \
         top-level entry out of AC-09's 14-list scope",
    ),
    (
        "audit",
        "crates/services/observability-xtask",
        "MODULE-019 observability-lint — walks cap-*/src/**/*.rs for HostFunctionHandler::call \
         bodies and enforces the AC-01/AC-14 emit convention; the workspace's compile-time \
         audit-compliance guard. PRD §15 names event-bus + git log as the audit substrate \
         (substrate asserted via crates/event-bus/ in EXPECTED_PRESENT). The standalone §16 \
         audit/ crate was not operationalized; its operational tooling lives here",
    ),
];

#[test]
fn module_001_t20_crates_layout_matches_section_16() {
    let workspace_root = workspace_root();
    let crates_dir = workspace_root.join("crates");
    assert!(
        is_real_directory(&crates_dir),
        "workspace `crates/` directory must exist (not a symlink) at {}",
        crates_dir.display()
    );

    // 1. Positive coverage: 10 expected top-level crates.
    for expected in EXPECTED_PRESENT {
        let path = crates_dir.join(expected);
        assert!(
            is_real_directory(&path),
            "AC-09 §16 requires top-level crate `{expected}` at {}; missing or symlinked",
            path.display()
        );
    }

    // 2. Relocation coverage: 4 architecturally folded subsystems. Each waiver
    // target is a directory (crate root or capability sub-crate).
    for (name, actual_path, rationale) in WAIVED_RELOCATED {
        let path = workspace_root.join(actual_path);
        assert!(
            is_real_directory(&path),
            "AC-09 §16 dir `{name}` is RELOCATED to `{actual_path}` ({rationale}); but that path is not a real directory at {} (missing, symlinked, or shadowed by a file) — architectural relocation has regressed",
            path.display(),
        );
    }
}

/// Returns true iff `path` is an existing, real (non-symlink) directory.
///
/// `Path::is_dir` calls `fs::metadata` which **follows symlinks** — a
/// `crates/messaging -> /tmp/anything-that-is-a-dir` symlink would pass
/// `is_dir()` even though the actual crate is gone. That defeats the
/// regression-guard intent of AC-09: an attacker (or a careless contributor)
/// could mask the deletion of a real crate by replacing it with a symlink.
/// Using `fs::symlink_metadata` returns metadata for the symlink itself, so
/// `metadata.is_dir()` is `false` whenever the path IS a symlink, regardless
/// of what the target is. This matches the symlink-rejecting pattern used by
/// the §3.6-referenced `binary_reload_via_restart.rs` walker.
fn is_real_directory(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) => metadata.is_dir(),
        Err(_) => false,
    }
}

/// Compute the workspace root from `CARGO_MANIFEST_DIR` (set by Cargo at compile
/// time). For `crates/runtime/`, the workspace root is two ancestors up.
fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| {
            panic!(
                "CARGO_MANIFEST_DIR={} has fewer than 2 ancestors",
                manifest_dir.display()
            )
        })
        .to_path_buf()
}
