//! `build-agent` — the operator tool that deploys an agent guest's behavior component.
//!
//! Builds a guest crate to `wasm32-unknown-unknown --release`, wraps the resulting core
//! module into a WASM Component via [`build_agent::encode_core_to_component`], and writes
//! it to the deploy path (default `<cwd>/.agent/behavior.component.wasm`) — the form the
//! production runtime's `load_component` consumes.
//!
//! Example:
//!   `cargo run -p build-agent -- --guest crates/runtime/tests/fixtures/guest-rust-hello-llm \
//!        --out <ws>/.agent/behavior.component.wasm`

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "build-agent",
    about = "Build an agent guest crate and encode its core module into a deployable WASM Component."
)]
struct Args {
    /// Path to the guest crate directory or its Cargo.toml.
    #[arg(long)]
    guest: PathBuf,

    /// Output path for the encoded behavior component.
    #[arg(long, default_value = ".agent/behavior.component.wasm")]
    out: PathBuf,

    /// Skip `cargo build` and encode the existing core wasm artifact under the guest's target dir.
    #[arg(long)]
    no_build: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let manifest = resolve_manifest(&args.guest)?;
    let crate_dir = manifest
        .parent()
        .map(Path::to_path_buf)
        .context("guest manifest has no parent directory")?;

    if !args.no_build {
        run_cargo_build(&manifest)?;
    }

    let core_path = locate_core_wasm(&crate_dir)?;
    let core = std::fs::read(&core_path)
        .with_context(|| format!("read core wasm at {}", core_path.display()))?;

    let component = build_agent::encode_core_to_component(&core)?;

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create output directory {}", parent.display()))?;
        }
    }
    std::fs::write(&args.out, &component)
        .with_context(|| format!("write component to {}", args.out.display()))?;

    println!(
        "build-agent: encoded {} ({} bytes core) -> {} ({} bytes component)",
        core_path.display(),
        core.len(),
        args.out.display(),
        component.len()
    );
    Ok(())
}

/// Resolve `--guest` (a directory or a Cargo.toml path) to the crate's Cargo.toml.
fn resolve_manifest(guest: &Path) -> Result<PathBuf> {
    let manifest = if guest.is_dir() {
        guest.join("Cargo.toml")
    } else {
        guest.to_path_buf()
    };
    if !manifest.is_file() {
        bail!("guest manifest not found at {}", manifest.display());
    }
    Ok(manifest)
}

/// Run `cargo build --target wasm32-unknown-unknown --release` on the guest crate.
fn run_cargo_build(manifest: &Path) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .args([
            "build",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
            "--manifest-path",
        ])
        .arg(manifest)
        .status()
        .with_context(|| format!("spawn cargo build for {}", manifest.display()))?;
    if !status.success() {
        bail!(
            "cargo build for {} failed (exit {:?}) — is the wasm32-unknown-unknown target installed? \
             (`rustup target add wasm32-unknown-unknown`)",
            manifest.display(),
            status.code()
        );
    }
    Ok(())
}

/// Locate the single cdylib core wasm under `<crate_dir>/target/wasm32-unknown-unknown/release/`.
/// (The guest crate carries its own empty `[workspace]` table, so its build artifacts land
/// in the crate-local `target/`, and only the final cdylib emits a top-level `*.wasm` there —
/// dependency rlibs do not.)
fn locate_core_wasm(crate_dir: &Path) -> Result<PathBuf> {
    let release_dir = crate_dir.join("target/wasm32-unknown-unknown/release");
    if !release_dir.is_dir() {
        bail!(
            "no wasm32 release artifacts at {} — run without --no-build, or build the guest first",
            release_dir.display()
        );
    }
    let mut candidate: Option<(PathBuf, std::time::SystemTime)> = None;
    for entry in std::fs::read_dir(&release_dir)
        .with_context(|| format!("read {}", release_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        // Pick the most recently modified .wasm (the just-built cdylib).
        if candidate.as_ref().map(|(_, t)| mtime >= *t).unwrap_or(true) {
            candidate = Some((path, mtime));
        }
    }
    candidate
        .map(|(p, _)| p)
        .with_context(|| format!("no *.wasm core module found in {}", release_dir.display()))
}
