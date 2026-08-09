//! T73 + T73-allowlist integration tests for `cargo xtask observability-lint`.
//!
//! T73(a) — fixture mode: 2-crate temp workspace, one handler emits, one doesn't,
//!         no allowlist → exit 1 + violating handler in stderr.
//! T73(b) — workspace mode: invoke against the real repo workspace with the
//!         pre-populated allowlist → exit 0.
//! T73-allowlist (multiple cases) — schema validation rejects malformed entries.

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

const EMIT_HANDLER_SRC: &str = r#"
use std::sync::Arc;
struct EventBusEmit;
pub trait HostFunctionHandler {
    fn call(&self, x: i32) -> i32;
}
pub struct EmittingHandler {
    pub bus: Arc<EventBusEmit>,
}
impl HostFunctionHandler for EmittingHandler {
    fn call(&self, x: i32) -> i32 {
        self.bus.emit(x);  // direct emit method call — pattern 2
        x + 1
    }
}
impl EventBusEmit {
    fn emit(&self, _x: i32) {}
}
"#;

const NON_EMIT_HANDLER_SRC: &str = r#"
pub trait HostFunctionHandler {
    fn call(&self, x: i32) -> i32;
}
pub struct SilentHandler;
impl HostFunctionHandler for SilentHandler {
    fn call(&self, x: i32) -> i32 {
        let _ = compute(x);
        x + 1
    }
}
fn compute(x: i32) -> i32 { x * 2 }
"#;

fn setup_fixture_workspace() -> TempDir {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    // Build a minimal `crates/capabilities/cap-emits/src/host_fn.rs` +
    // `crates/capabilities/cap-silent/src/host_fn.rs`.
    let emits = root
        .join("crates")
        .join("capabilities")
        .join("cap-emits")
        .join("src");
    let silent = root
        .join("crates")
        .join("capabilities")
        .join("cap-silent")
        .join("src");
    fs::create_dir_all(&emits).unwrap();
    fs::create_dir_all(&silent).unwrap();
    fs::write(emits.join("host_fn.rs"), EMIT_HANDLER_SRC).unwrap();
    fs::write(silent.join("host_fn.rs"), NON_EMIT_HANDLER_SRC).unwrap();
    dir
}

fn xtask_bin() -> Command {
    Command::cargo_bin("xtask").expect("xtask bin built")
}

// ─── T73(a) fixture mode ────────────────────────────────────────────────────

#[test]
fn t73_a_fixture_no_allowlist_flags_silent_handler() {
    let tmp = setup_fixture_workspace();
    let mut cmd = xtask_bin();
    cmd.arg("observability-lint")
        .arg("--workspace")
        .arg(tmp.path());
    let assert = cmd.assert().failure();
    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SilentHandler"),
        "stderr should name the silent handler; got: {}",
        stderr
    );
    assert!(
        !stderr.contains("EmittingHandler"),
        "EmittingHandler should NOT be flagged; got stderr: {}",
        stderr
    );
}

// ─── T73(b) workspace mode ──────────────────────────────────────────────────

#[test]
fn t73_b_workspace_with_allowlist_exits_zero() {
    // Resolve the repo workspace root: this test binary is built inside
    // <workspace>/target/debug/deps/. Walk up 3 levels to reach the workspace.
    let workspace = repo_workspace_root();
    let mut cmd = xtask_bin();
    cmd.arg("observability-lint")
        .arg("--workspace")
        .arg(&workspace);
    cmd.assert().success();
}

fn repo_workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR for this crate is
    // .../crates/services/observability-xtask. The workspace root is 3 dirs up.
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

// ─── T73-allowlist — schema validation cases ────────────────────────────────

fn run_with_allowlist_content(
    workspace: &Path,
    allowlist_toml: &str,
) -> assert_cmd::assert::Assert {
    let allowlist_path = workspace.join("observability-allowlist.toml");
    fs::write(&allowlist_path, allowlist_toml).unwrap();
    let mut cmd = xtask_bin();
    cmd.arg("observability-lint")
        .arg("--workspace")
        .arg(workspace)
        .arg("--allowlist")
        .arg(&allowlist_path);
    cmd.assert()
}

#[test]
fn t73_allowlist_empty_reason_fails() {
    let tmp = setup_fixture_workspace();
    let assert = run_with_allowlist_content(
        tmp.path(),
        r#"
[[handler]]
crate = "cap-silent"
struct = "SilentHandler"
reason = ""
delegated_to = "a::b::c"
"#,
    );
    let output = assert.failure().get_output().clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("empty 'reason'"), "stderr: {}", stderr);
}

#[test]
fn t73_allowlist_missing_both_xor_fields_fails() {
    let tmp = setup_fixture_workspace();
    let assert = run_with_allowlist_content(
        tmp.path(),
        r#"
[[handler]]
crate = "cap-silent"
struct = "SilentHandler"
reason = "valid reason"
"#,
    );
    let output = assert.failure().get_output().clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must specify EXACTLY ONE"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn t73_allowlist_both_xor_fields_fails() {
    let tmp = setup_fixture_workspace();
    let assert = run_with_allowlist_content(
        tmp.path(),
        r#"
[[handler]]
crate = "cap-silent"
struct = "SilentHandler"
reason = "valid"
delegated_to = "a::b::c"
pending_wiring_slice = "MODULE-019"
"#,
    );
    let output = assert.failure().get_output().clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot specify BOTH"), "stderr: {}", stderr);
}

#[test]
fn t73_allowlist_2_segment_delegated_to_fails() {
    let tmp = setup_fixture_workspace();
    let assert = run_with_allowlist_content(
        tmp.path(),
        r#"
[[handler]]
crate = "cap-silent"
struct = "SilentHandler"
reason = "valid"
delegated_to = "foo::bar"
"#,
    );
    let output = assert.failure().get_output().clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("at least 3 segments"), "stderr: {}", stderr);
}

#[test]
fn t73_allowlist_slice_dash_prefix_rejected() {
    // Round 4 / Round 5 finding: `^slice-` is NOT a canonical referent
    // (prose placeholder in cap-tools/lazy_registry.rs). Lint MUST reject.
    let tmp = setup_fixture_workspace();
    let assert = run_with_allowlist_content(
        tmp.path(),
        r#"
[[handler]]
crate = "cap-silent"
struct = "SilentHandler"
reason = "valid"
pending_wiring_slice = "slice-B"
"#,
    );
    assert.failure();
}

#[test]
fn t73_allowlist_valid_entry_silences_violation() {
    let tmp = setup_fixture_workspace();
    let assert = run_with_allowlist_content(
        tmp.path(),
        r#"
[[handler]]
crate = "cap-silent"
struct = "SilentHandler"
reason = "fixture handler delegated to inner service"
delegated_to = "advance_cap_silent::service::Service::process"
"#,
    );
    assert.success();
}

#[test]
fn t73_allowlist_valid_pending_wiring_slice_module_ref() {
    let tmp = setup_fixture_workspace();
    let assert = run_with_allowlist_content(
        tmp.path(),
        r#"
[[handler]]
crate = "cap-silent"
struct = "SilentHandler"
reason = "pending"
pending_wiring_slice = "MODULE-019 §3.6 item 1"
"#,
    );
    assert.success();
}

#[test]
fn t73_allowlist_valid_pending_wiring_slice_slice_id() {
    let tmp = setup_fixture_workspace();
    let assert = run_with_allowlist_content(
        tmp.path(),
        r#"
[[handler]]
crate = "cap-silent"
struct = "SilentHandler"
reason = "pending"
pending_wiring_slice = "m017-slice-c"
"#,
    );
    assert.success();
}
