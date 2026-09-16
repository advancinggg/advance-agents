#![cfg(feature = "gap-p3")]
//! GAP-15 (P3) — fd-relative, symlink-proof directory copy (closes the TOCTOU window
//! verify.rs:11-20 documents).
//!
//! `copy_dir_no_symlinks_observed(src, dst, on_descend)` fires the callback for a
//! directory entry AFTER it was classified as a directory and IMMEDIATELY BEFORE it is
//! opened for descent — exactly the race window. The test swaps the directory for a
//! symlink inside the callback: an fd-relative implementation (openat2 NO_SYMLINKS|BENEATH
//! on Linux, O_DIRECTORY|O_NOFOLLOW elsewhere) must fail closed and must not copy the
//! symlink target's content into `dst`.

use std::path::Path;

use advance_pack_manager::fetch::{copy_dir_no_symlinks, copy_dir_no_symlinks_observed};

fn build_src(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let src = root.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("pack.yaml"), "name: x\n").unwrap();
    std::fs::write(src.join("sub/inner.txt"), "inner").unwrap();
    let evil = root.join("evil");
    std::fs::create_dir_all(&evil).unwrap();
    std::fs::write(evil.join("leak.txt"), "should never be copied").unwrap();
    (src, evil)
}

#[cfg(unix)]
#[test]
fn g15_directory_swapped_for_symlink_during_descent_is_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (src, evil) = build_src(tmp.path());
    let dst = tmp.path().join("dst");
    let sub = src.join("sub");
    let mut swapped = false;
    let result = copy_dir_no_symlinks_observed(&src, &dst, &mut |about_to_descend: &Path| {
        if about_to_descend == sub && !swapped {
            swapped = true;
            std::fs::remove_dir_all(&sub).unwrap();
            std::os::unix::fs::symlink(&evil, &sub).unwrap();
        }
    });
    assert!(swapped, "the observer must be invoked for `sub`");
    assert!(
        result.is_err(),
        "swap during descent must fail closed, got {result:?}"
    );
    assert!(
        !dst.join("sub/leak.txt").exists(),
        "content behind the swapped-in symlink must never reach dst"
    );
}

#[test]
fn g15_plain_copy_still_works_and_is_the_observed_variant_with_noop() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (src, _evil) = build_src(tmp.path());
    let dst = tmp.path().join("dst");
    copy_dir_no_symlinks(&src, &dst).expect("no race → copy succeeds");
    assert_eq!(
        std::fs::read_to_string(dst.join("sub/inner.txt")).unwrap(),
        "inner"
    );
    let dst2 = tmp.path().join("dst2");
    copy_dir_no_symlinks_observed(&src, &dst2, &mut |_| {}).expect("noop observer");
    assert!(dst2.join("pack.yaml").is_file());
}

/// Probabilistic race harness — run manually: `cargo test ... -- --ignored g15_race`.
#[cfg(unix)]
#[test]
#[ignore = "manual race harness (probabilistic); the deterministic witness above is the gate"]
fn g15_race_harness_never_leaks_outside_content() {
    for _ in 0..200 {
        let tmp = tempfile::TempDir::new().unwrap();
        let (src, evil) = build_src(tmp.path());
        let dst = tmp.path().join("dst");
        let sub = src.join("sub");
        let flipper = {
            let (sub, evil) = (sub.clone(), evil.clone());
            std::thread::spawn(move || {
                let _ = std::fs::remove_dir_all(&sub);
                let _ = std::os::unix::fs::symlink(&evil, &sub);
            })
        };
        let _ = copy_dir_no_symlinks(&src, &dst);
        flipper.join().unwrap();
        assert!(!dst.join("sub/leak.txt").exists(), "leak observed");
    }
}
