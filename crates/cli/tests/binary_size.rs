//! MODULE-001-AC-02 build-test half — size + static-linkage gate (REQ-010 + §1.6 NFR).
//!
//! Uses `env!("CARGO_BIN_EXE_advance")` — Cargo automatically sets this env var for
//! integration tests of crates that declare a `[[bin]]` target; the path points to the
//! same profile (debug vs release) that Cargo used to build the integration test
//! itself. This avoids spawning a nested `cargo build --release` from within
//! `cargo test` (a well-known target-dir package-cache lock contention hazard —
//! rust-lang/cargo issues #7480, #5577, #4486).
//!
//! Gated by `#[cfg_attr(debug_assertions, ignore)]` so:
//!   - `cargo test --workspace` (debug) marks this test `ignored`.
//!   - `cargo test -p advance-cli --release --test binary_size -- --include-ignored`
//!     builds the release `advance` binary (as part of the integration-test pipeline)
//!     and runs the assertions against it.
//!
//! Current reality (Slice U): `target/release/advance` is ~1.1 MiB because the CLI
//! does not exercise any Wasmtime code path, so LTO dead-code-eliminates Wasmtime
//! entirely. The 50 MiB gate therefore acts as a regression ceiling for future
//! slices that introduce Wasmtime-exercising CLI paths; see MODULE-001 §3.6.
//!
//! "Statically-linked" per AC-02 is interpreted as "no third-party dynamic library
//! dependencies". Rust's default target on macOS and Linux always dynamic-links
//! libc + OS system frameworks; this is a Rust-ecosystem convention. The test
//! allowlists system paths ONLY — any `/opt/homebrew`, `/usr/local`, `/opt/...`, or
//! other third-party prefix failing the allowlist is intentional: surfacing a future
//! dep that introduces third-party native linkage is the whole point of REQ-010's
//! "single statically-linked" clause.

use std::path::PathBuf;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "AC-02: release-profile only (run with `cargo test --release -- --include-ignored`)"
)]
fn release_binary_size_and_linkage() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_advance"));
    assert!(
        binary.is_file(),
        "CARGO_BIN_EXE_advance must point to a regular file: {:?}",
        binary
    );

    // --- Size gate (REQ-010 + §1.6 NFR) ---
    let bytes = std::fs::metadata(&binary)
        .expect("stat advance binary")
        .len();
    assert!(bytes > 0, "advance binary is empty (0 bytes): {:?}", binary);
    let mib = (bytes as f64) / (1024.0 * 1024.0);
    eprintln!("[AC-02] advance release binary size: {bytes} bytes ({mib:.2} MiB)");
    let limit: u64 = 50 * 1024 * 1024;
    assert!(
        bytes < limit,
        "advance release binary exceeds 50 MiB gate: {bytes} bytes ({mib:.2} MiB) — §1.6 NFR"
    );

    // --- Static-linkage gate (REQ-010 "statically-linked" clause) ---
    check_no_third_party_dynamic_deps(&binary);
}

#[cfg(target_os = "macos")]
fn check_no_third_party_dynamic_deps(binary: &PathBuf) {
    let out = Command::new("otool")
        .args(["-L", binary.to_str().unwrap()])
        .output()
        .expect("spawn otool -L");
    assert!(
        out.status.success(),
        "otool -L failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    let _header = lines.next(); // first line is the binary path
    let mut found_any = false;
    let mut unexpected: Vec<String> = Vec::new();
    for line in lines {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let path = t.split_whitespace().next().unwrap_or("");
        // System library paths only. /opt/homebrew and /usr/local are INTENTIONALLY
        // NOT allowlisted — any non-system dylib is a REQ-010 violation to be flagged.
        let is_system = path.starts_with("/System/") || path.starts_with("/usr/lib/");
        if !is_system {
            unexpected.push(path.to_string());
        }
        found_any = true;
    }
    // Adversarial-fix R1: positive lower bound — Rust default-target Mach-O always
    // dyn-links at least libSystem; otool -L succeeding with zero dep lines is a tooling
    // anomaly that must not silently pass.
    assert!(
        found_any,
        "otool -L produced no dynamic-dep lines for {:?} — output empty or unparseable",
        binary
    );
    assert!(
        unexpected.is_empty(),
        "advance binary has unexpected (non-system) dynamic deps — REQ-010 static-linkage clause:\n{:#?}",
        unexpected
    );
}

#[cfg(target_os = "linux")]
fn check_no_third_party_dynamic_deps(binary: &PathBuf) {
    let out = Command::new("ldd")
        .arg(binary.to_str().unwrap())
        .output()
        .expect("spawn ldd");
    assert!(
        out.status.success(),
        "ldd failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // POSIX / glibc / libgcc_s allowlist — exact-equality match on the bare name.
    // Adversarial-fix R1: prefix matching previously allowed librtmp/libcrypto/libcurl/
    // libmagic to silently pass via prefix collision with libc/librt/libm; switched to
    // exact equality. Loader names are matched against `LOADER_BASENAMES` separately
    // because ldd prints the dynamic loader as an absolute path with no `=>` arrow.
    const ALLOWLIST_BARE: &[&str] = &[
        "linux-vdso",
        "libc",
        "libm",
        "libgcc_s",
        "libpthread",
        "libdl",
        "librt",
        "libresolv",
    ];
    // Loader line prefixes — ldd emits e.g. `/lib64/ld-linux-x86-64.so.2 (0x...)`
    // for the dynamic loader (no `=>`); we match against the full basename split
    // off the path. The `ld-linux*` family covers x86-64 / aarch64 / arm / i386.
    const LOADER_BASENAME_PREFIX: &str = "ld-linux";
    let mut found_any = false;
    let mut unexpected: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("statically linked") {
            return; // fully static — ideal
        }
        let name = t.split_whitespace().next().unwrap_or("");
        // ldd emits two shapes:
        //   "libfoo.so.6 => /path/to/libfoo.so.6 (0x...)"  — `name` = "libfoo.so.6"
        //   "/lib64/ld-linux-x86-64.so.2 (0x...)"           — `name` = "/lib64/ld-linux-x86-64.so.2"
        // Strip any leading directory + version suffix to get the bare ident.
        let basename = std::path::Path::new(name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(name);
        let bare = basename.split('.').next().unwrap_or("");
        let ok =
            ALLOWLIST_BARE.iter().any(|p| bare == *p) || bare.starts_with(LOADER_BASENAME_PREFIX);
        if !ok {
            unexpected.push(name.to_string());
        }
        found_any = true;
    }
    // Adversarial-fix R1: positive lower bound — empty `ldd` stdout that exits 0 must
    // not silently pass. A real Rust binary always lists at least libc + ld-linux.
    assert!(
        found_any,
        "ldd produced no dynamic-dep lines for {:?} — output empty or unparseable",
        binary
    );
    assert!(
        unexpected.is_empty(),
        "advance binary has unexpected (non-system) dynamic deps — REQ-010 static-linkage clause:\n{:#?}",
        unexpected
    );
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn check_no_third_party_dynamic_deps(_binary: &PathBuf) {
    eprintln!(
        "[AC-02] static-linkage check not implemented for this target_os; \
         size gate still enforced"
    );
}
