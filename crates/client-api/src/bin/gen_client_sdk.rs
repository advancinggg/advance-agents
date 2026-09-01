//! CONTRACT-192 SDK artifact checker/regenerator for `sdk-artifacts/`.
//!
//! Two modes (MODULE-020 §2.12 schema-evolution protocol):
//!
//!   - **default (check-only)**: regenerates the full artifact set in memory and compares it
//!     against the checked-in files (schema, manifest, vectors, per-target surfaces). Prints a
//!     per-file drift summary and exits nonzero on ANY divergence. Never writes — so an
//!     accidental run can never invalidate the AC-02/AC-12 witnesses.
//!   - **`--write`** (or env `ALLOW_SCHEMA_CHANGE=1`): regenerates the artifacts on disk after
//!     an INTENTIONAL DTO/vector/surface change. The manifest schema hash updates with the
//!     schema; record the change in MODULE-020 §3.7 (change history) — schema evolution without
//!     change history is a §2.12 violation.
//!
//! The CI drift witness stays in `tests/schema_contract.rs` (t02c/t12a/t12d): the checked-in
//! bytes must always byte-match a fresh generation.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use advance_client_api::schema::{
    enforce_compat_gate, generate_schema_artifact, manifest_path, platform_surface_json,
    schema_path, shared_sdk_dir, vectors_path,
};

fn check_one(path: &Path, fresh: &str, label: &str, drifted: &mut Vec<String>) {
    match fs::read_to_string(path) {
        Ok(disk) if disk == fresh => {
            println!(
                "OK      {label}: {} ({} bytes)",
                path.display(),
                fresh.len()
            );
        }
        Ok(disk) => {
            let divergence = disk
                .bytes()
                .zip(fresh.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| disk.len().min(fresh.len()));
            eprintln!(
                "DRIFT   {label}: {} (on-disk {} bytes vs generated {} bytes; first divergence at byte {})",
                path.display(),
                disk.len(),
                fresh.len(),
                divergence
            );
            drifted.push(label.to_string());
        }
        Err(e) => {
            eprintln!("MISSING {label}: {} ({e})", path.display());
            drifted.push(label.to_string());
        }
    }
}

fn main() -> ExitCode {
    let mut write_mode = std::env::var("ALLOW_SCHEMA_CHANGE").ok().as_deref() == Some("1");
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--write" => write_mode = true,
            "--check" => write_mode = false,
            other => {
                eprintln!("unknown argument {other:?}");
                eprintln!("usage: gen_client_sdk [--check|--write]   (env ALLOW_SCHEMA_CHANGE=1 == --write)");
                return ExitCode::from(2);
            }
        }
    }

    let artifact = generate_schema_artifact();
    let surfaces: Vec<(String, String)> = artifact
        .manifest
        .targets
        .iter()
        .map(|t| (t.clone(), platform_surface_json(t)))
        .collect();

    if !write_mode {
        // Check-only: report every drifted artifact, write nothing.
        let mut drifted = Vec::new();
        check_one(
            &schema_path(),
            &artifact.schema_json(),
            "schema",
            &mut drifted,
        );
        check_one(
            &manifest_path(),
            &artifact.manifest_json(),
            "manifest",
            &mut drifted,
        );
        check_one(
            &vectors_path(),
            &artifact.vectors_json(),
            "vectors",
            &mut drifted,
        );
        let fixtures = shared_sdk_dir().join("conformance/fixtures");
        for (target, fresh) in &surfaces {
            check_one(
                &fixtures.join(target).join("surface.json"),
                fresh,
                &format!("surface[{target}]"),
                &mut drifted,
            );
        }
        match enforce_compat_gate() {
            Ok(()) => println!("COMPAT  OK"),
            Err(e) => {
                eprintln!("COMPAT  FAIL: {e}");
                drifted.push("compat".to_string());
            }
        }
        if drifted.is_empty() {
            println!("no drift — checked-in CONTRACT-192 artifacts match a fresh generation");
            return ExitCode::SUCCESS;
        }
        eprintln!(
            "{} artifact(s) drifted: {}. If this is an INTENTIONAL contract change, rerun with \
             --write (or ALLOW_SCHEMA_CHANGE=1) and record the change in \
             docs/modules/MODULE-020-client-api-and-console.md §3.7.",
            drifted.len(),
            drifted.join(", ")
        );
        return ExitCode::FAILURE;
    }

    // Write mode: explicit opt-in regeneration.
    let write_all = || -> std::io::Result<()> {
        for path in [schema_path(), manifest_path(), vectors_path()] {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        advance_client_api::schema::safe_write(&schema_path(), &artifact.schema_json())?;
        advance_client_api::schema::safe_write(&manifest_path(), &artifact.manifest_json())?;
        advance_client_api::schema::safe_write(&vectors_path(), &artifact.vectors_json())?;
        println!("wrote {}", schema_path().display());
        println!("wrote {}", manifest_path().display());
        println!("wrote {}", vectors_path().display());

        let conf_dir = shared_sdk_dir().join("conformance");
        advance_client_api::schema::write_platform_surfaces(&conf_dir)?;
        println!(
            "wrote per-target surfaces under {}/fixtures/",
            conf_dir.display()
        );
        Ok(())
    };
    if let Err(e) = write_all() {
        eprintln!("regeneration failed: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "REMINDER: this regenerated the CONTRACT-192 artifact set (manifest schema_hash included). \
         Record the contract change in docs/modules/MODULE-020-client-api-and-console.md §3.7 \
         change history before committing (§2.12)."
    );
    ExitCode::SUCCESS
}
