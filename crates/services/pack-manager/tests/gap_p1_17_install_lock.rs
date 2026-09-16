#![cfg(feature = "gap-p1")]
//! GAP-17 (P1) — cross-process install lock around steps ③(AlreadyInstalled)→⑥→⑦→⑧.
//! Concurrent installs of DISTINCT packs must all
//! land in `.meta.yaml`; concurrent installs of the SAME pack must yield exactly one
//! `Ok` and one `AlreadyInstalled` (never an `Io` error from the dst-fresh check).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, PackError, INSTALL_LOCK_FILENAME,
};

fn write_pack(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(format!("{name}-src"));
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        format!("name: {name}\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  behavior-binaries:\n    - dummy\nchecksums:\n  algo: sha256\n  files: {{}}\n"),
    )
    .unwrap();
    dir
}

fn installer(packs: &Path) -> Installer {
    Installer::new(
        packs,
        Arc::new(InMemoryPackRegistry::new(packs.to_path_buf())),
        "0.1.0",
        Arc::new(AutoApprove),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g17_concurrent_installs_of_distinct_packs_all_land_in_meta_index() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let names: Vec<String> = (0..6).map(|i| format!("p{i}")).collect();
    let mut handles = Vec::new();
    for name in &names {
        let src = write_pack(work.path(), name);
        let packs_dir = packs.path().to_path_buf();
        handles.push(tokio::spawn(async move {
            installer(&packs_dir).install(src.to_str().unwrap()).await
        }));
    }
    for h in handles {
        h.await.unwrap().expect("each distinct install succeeds");
    }
    let meta = std::fs::read_to_string(packs.path().join(".meta.yaml")).unwrap();
    for name in &names {
        assert!(
            meta.contains(&format!("{name}@1.0.0")),
            "lost update for {name}: {meta}"
        );
    }
    assert!(
        packs.path().join(INSTALL_LOCK_FILENAME).exists(),
        "lock file must live in packs_dir"
    );
    let cold = InMemoryPackRegistry::new(packs.path().to_path_buf());
    cold.rescan().await.unwrap();
    assert_eq!(cold.list_installed().len(), 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g17_concurrent_installs_of_same_pack_yield_one_ok_one_already_installed() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), "same");
    let a = {
        let (src, packs_dir) = (src.clone(), packs.path().to_path_buf());
        tokio::spawn(async move { installer(&packs_dir).install(src.to_str().unwrap()).await })
    };
    let b = {
        let (src, packs_dir) = (src.clone(), packs.path().to_path_buf());
        tokio::spawn(async move { installer(&packs_dir).install(src.to_str().unwrap()).await })
    };
    let results = vec![a.await.unwrap(), b.await.unwrap()];
    let oks = results.iter().filter(|r| r.is_ok()).count();
    let already = results
        .iter()
        .filter(|r| matches!(r, Err(PackError::AlreadyInstalled { .. })))
        .count();
    assert_eq!((oks, already), (1, 1), "got {results:?}");
    let meta = std::fs::read_to_string(packs.path().join(".meta.yaml")).unwrap();
    assert_eq!(
        meta.matches("same@1.0.0").count(),
        1,
        "exactly one index entry: {meta}"
    );
}
