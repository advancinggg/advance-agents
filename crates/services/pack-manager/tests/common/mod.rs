//! Shared test fixtures for Slice D AC-05 integration tests.
//!
//! Built at runtime via the `tar` + `flate2` crates (which pack-manager now
//! depends on). Each fixture function returns a `PathBuf` to a fresh artifact
//! in the caller-supplied `work_dir`; cleanup via tempdir RAII at the caller.

// Each integration test binary imports a subset of these helpers; mark the
// whole module as allow-dead-code so unused helpers don't warn per-binary.
#![allow(dead_code)]

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use flate2::Compression;

/// Modifier for the tarball-fixture builder — selects between a valid pack
/// tree and various adversarial shapes for T75-T79b.
pub enum FixtureContent {
    ValidPack,
    TraversalEntry,
    SymlinkEntry,
    HardlinkEntry,
    AbsolutePathEntry,
    OversizedPayload,
    TooManyEntries,
}

/// Build a tarball fixture in `work_dir`. Returns the path to the `.tar.gz`.
///
/// `FixtureContent::ValidPack` produces a minimal valid pack with
/// `pack.yaml` plus `behavior-binaries/dummy.wasm`. Adversarial variants
/// modify the content to trigger specific rejection paths.
pub fn build_tarball_fixture(work_dir: &Path, content: FixtureContent) -> PathBuf {
    let tarball_path = work_dir.join("fixture.tar.gz");
    let file = File::create(&tarball_path).expect("create tarball file");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);

    match content {
        FixtureContent::ValidPack => add_valid_pack_entries(&mut builder),
        FixtureContent::TraversalEntry => {
            // Valid pack PLUS a traversal entry. tar::Header::set_path rejects
            // `..` directly, so we set name field bytes manually (matches the
            // AbsolutePathEntry pattern below).
            add_valid_pack_entries(&mut builder);
            let evil = b"evil contents";
            let mut header = tar::Header::new_gnu();
            header.set_path("foo").ok();
            header.set_size(evil.len() as u64);
            header.set_mode(0o644);
            let name_bytes = header.as_old_mut().name.as_mut();
            for byte in name_bytes.iter_mut() {
                *byte = 0;
            }
            let evil_path = b"../etc/evil";
            for (i, b) in evil_path.iter().enumerate() {
                name_bytes[i] = *b;
            }
            header.set_cksum();
            builder.append(&header, &evil[..]).unwrap();
        }
        FixtureContent::SymlinkEntry => {
            add_valid_pack_entries(&mut builder);
            let mut header = tar::Header::new_gnu();
            header.set_path("evil_link").unwrap();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_link_name("../etc/passwd").unwrap();
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
        }
        FixtureContent::HardlinkEntry => {
            add_valid_pack_entries(&mut builder);
            let mut header = tar::Header::new_gnu();
            header.set_path("evil_hardlink").unwrap();
            header.set_entry_type(tar::EntryType::Link);
            header.set_size(0);
            header.set_mode(0o644);
            header.set_link_name("../etc/passwd").unwrap();
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
        }
        FixtureContent::AbsolutePathEntry => {
            add_valid_pack_entries(&mut builder);
            let evil = b"evil contents";
            let mut header = tar::Header::new_gnu();
            // GNU header allows up to 100-char path; absolute path needs the
            // `path` accessor's bypass — write the long-name header for
            // arbitrary content.
            header.set_path("foo").ok();
            header.set_size(evil.len() as u64);
            header.set_mode(0o644);
            // Use the explicit long-name override via set_path with an
            // absolute path. `tar::Header::set_path` rejects absolute paths;
            // we work around by setting the name field directly.
            // For test reliability, the tar crate's `append_data` with a
            // PathBuf prefixed with `/` exercises the absolute-path rejection
            // path in the extractor. Here we just construct the header bytes
            // by hand-setting the name.
            let name_bytes = header.as_old_mut().name.as_mut();
            let abs = b"/etc/passwd";
            for (i, b) in abs.iter().enumerate() {
                name_bytes[i] = *b;
            }
            header.set_cksum();
            builder.append(&header, &evil[..]).unwrap();
        }
        FixtureContent::OversizedPayload => {
            // Single entry whose declared size exceeds 256 MiB total cap.
            // We use a sparse trick: declare 257 MiB but write zeros via
            // chunked feed (flate2 compresses zeros aggressively so the
            // .tar.gz file stays small on disk).
            add_pack_yaml_entry(&mut builder);
            let mut header = tar::Header::new_gnu();
            header.set_path("behavior-binaries/huge.wasm").unwrap();
            let big = 257_u64 * 1024 * 1024;
            header.set_size(big);
            header.set_mode(0o644);
            header.set_cksum();
            // Feed in 1 MiB chunks of zeros (highly compressible).
            let chunk = vec![0u8; 1024 * 1024];
            let mut remaining = big;
            let mut cursor = ZeroFeeder {
                remaining: &mut remaining,
                chunk: &chunk,
            };
            builder.append(&header, &mut cursor).unwrap();
        }
        FixtureContent::TooManyEntries => {
            add_pack_yaml_entry(&mut builder);
            // 65537 tiny entries.
            for i in 0..65537 {
                let mut header = tar::Header::new_gnu();
                header
                    .set_path(format!("behavior-binaries/x{i}.txt"))
                    .unwrap();
                header.set_size(1);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, &[0u8][..]).unwrap();
            }
        }
    }

    builder.finish().unwrap();
    drop(builder);
    tarball_path
}

fn add_valid_pack_entries<W: Write>(builder: &mut tar::Builder<W>) {
    add_pack_yaml_entry(builder);
    let wasm = b"\0asm\x01\x00\x00\x00"; // minimal WASM module header
    let mut header = tar::Header::new_gnu();
    header.set_path("behavior-binaries/dummy.wasm").unwrap();
    header.set_size(wasm.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &wasm[..]).unwrap();
}

fn add_pack_yaml_entry<W: Write>(builder: &mut tar::Builder<W>) {
    let pack_yaml = r#"name: foo
version: 1.0.0
description: Slice D test fixture
runtime-version: ">=0.1.0"
provides:
  behavior-binaries:
    - dummy
checksums:
  algo: sha256
  files: {}
trust-level: untrusted
"#;
    let mut header = tar::Header::new_gnu();
    header.set_path("pack.yaml").unwrap();
    header.set_size(pack_yaml.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, pack_yaml.as_bytes()).unwrap();
}

/// Helper to stream a fixed amount of zero bytes into a tar entry without
/// allocating the full payload. Used by `OversizedPayload` to trigger the
/// 256 MiB total-size cap.
struct ZeroFeeder<'a> {
    remaining: &'a mut u64,
    chunk: &'a [u8],
}

impl<'a> std::io::Read for ZeroFeeder<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if *self.remaining == 0 {
            return Ok(0);
        }
        let take = std::cmp::min(buf.len(), self.chunk.len()) as u64;
        let take = std::cmp::min(take, *self.remaining) as usize;
        buf[..take].copy_from_slice(&self.chunk[..take]);
        *self.remaining -= take as u64;
        Ok(take)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Git fixture builder for T70a/T70b/T82a/T83.

/// Build a local bare git repo with a valid pack tree on `main`.
/// Returns `(bare_repo_path, work_dir_keeper)` — caller holds work_dir_keeper
/// to extend the tempdir's lifetime.
///
/// Optionally tags the initial commit as `v1.0` for ref-checkout tests, then
/// adds a SECOND commit on `main` with a different pack.yaml version. T70b
/// verifies that `--branch v1.0` installs the FIRST commit's content (v1.0.0)
/// while no-ref install fetches HEAD (v2.0.0).
pub fn build_git_fixture(work_dir: &Path, two_commits: bool) -> PathBuf {
    let bare = work_dir.join("bare.git");
    let sandbox = work_dir.join("sandbox");

    run_git(
        work_dir,
        &["init", "--bare", "--initial-branch=main", "bare.git"],
    );
    run_git(
        work_dir,
        &["clone", bare.to_str().unwrap(), sandbox.to_str().unwrap()],
    );
    // Defensive: ensure sandbox is on main (clone may pick a different default
    // if remote has no branches).
    let _ = std::process::Command::new("git")
        .args(["checkout", "-b", "main"])
        .current_dir(&sandbox)
        .output();

    let pack_yaml_v1 = r#"name: foo
version: 1.0.0
description: Slice D test fixture (v1.0.0 tagged)
runtime-version: ">=0.1.0"
provides:
  behavior-binaries:
    - dummy
checksums:
  algo: sha256
  files: {}
trust-level: untrusted
"#;
    std::fs::write(sandbox.join("pack.yaml"), pack_yaml_v1).unwrap();
    std::fs::create_dir_all(sandbox.join("behavior-binaries")).unwrap();
    std::fs::write(
        sandbox.join("behavior-binaries/dummy.wasm"),
        b"\0asm\x01\x00\x00\x00",
    )
    .unwrap();

    run_git(&sandbox, &["add", "."]);
    git_commit(&sandbox, "init v1.0.0");
    run_git(&sandbox, &["tag", "v1.0"]);

    if two_commits {
        let pack_yaml_v2 = r#"name: foo
version: 2.0.0
description: Slice D test fixture (v2.0.0 HEAD)
runtime-version: ">=0.1.0"
provides:
  behavior-binaries:
    - dummy
checksums:
  algo: sha256
  files: {}
trust-level: untrusted
"#;
        std::fs::write(sandbox.join("pack.yaml"), pack_yaml_v2).unwrap();
        run_git(&sandbox, &["add", "."]);
        git_commit(&sandbox, "bump to v2.0.0");
    }
    run_git(&sandbox, &["push", "origin", "main", "--tags"]);

    bare
}

fn run_git(cwd: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} spawn: {e}"));
    if !out.status.success() {
        panic!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn git_commit(cwd: &Path, msg: &str) {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.email=t@t.t",
            "-c",
            "user.name=t",
            "commit",
            "-m",
            msg,
        ])
        .current_dir(cwd)
        .output()
        .expect("git commit spawn");
    if !out.status.success() {
        panic!(
            "git commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Module-local lock for git tests in `install_flow_git.rs` (both env-
/// mutating ones AND env-observing git subprocess invocations). Uses
/// `tokio::sync::Mutex` because each test holds the guard across
/// `.await` points; std `Mutex` would trigger clippy's
/// `await_holding_lock` lint. Usage: `let _g = ENV_LOCK.lock().await;`.
pub static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
