//! MODULE-001-AC-32 (T113 (4)) / MODULE-001-AC-30 — `state_root` holds the platform state
//! that must live outside the home: the CONTRACT-216 progress-lifecycle anchor under
//! `<root>/contract216` and the CONTRACT-218 platform directory under
//! `<root>/contract218/<sha256(home)>`, and nothing is written under the process `HOME`. A
//! state root inside the home is refused.
//!
//! The only test of its binary: it points the process `HOME` at an empty directory before
//! anything composes, and checks that it stays empty.

#[path = "support/t111.rs"]
mod t111;

use std::path::Path;
use std::sync::Arc;

use advance_runtime_compose::test_support::MemoryComposeLog;
use advance_runtime_compose::{compose, ComposeError, Unsupported};
use sha2::{Digest, Sha256};
use t111::{serial, T111Home};

/// The CONTRACT-216 anchor file's suffix.
const ANCHOR_SUFFIX: &str = ".anchor";

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac32_t113_4_state_root_layout() {
    let _serial = serial();
    let process_home = tempfile::tempdir().expect("process HOME");
    std::env::set_var("HOME", process_home.path());

    let home = T111Home::new(&["messaging", "lifecycle"], false);
    let runtime = compose(home.options(Arc::new(MemoryComposeLog::new())), Vec::new())
        .await
        .expect("compose a messaging + lifecycle home with a state root");

    let anchors = entries(&home.state_root.join("contract216"));
    assert!(
        anchors.iter().any(|name| name.ends_with(ANCHOR_SUFFIX)),
        "the progress-lifecycle anchor lies under <state_root>/contract216: {anchors:?}"
    );
    let key = hex::encode(Sha256::digest(home.home.to_string_lossy().as_bytes()));
    let platform = home.state_root.join("contract218").join(&key);
    assert!(
        platform.is_dir(),
        "the CONTRACT-218 platform directory is {}: {:?}",
        platform.display(),
        entries(&home.state_root.join("contract218"))
    );

    runtime.shutdown().await.expect("shutdown");
    assert!(
        entries(process_home.path()).is_empty(),
        "nothing is written under the process HOME: {:?}",
        entries(process_home.path())
    );

    // A state root inside the home is refused.
    let inside = home.home.join(".agent");
    let error = compose(
        home.options(Arc::new(MemoryComposeLog::new()))
            .with_state_root(&inside),
        Vec::new(),
    )
    .await
    .expect_err("a state root inside the home");
    match error {
        ComposeError::Unsupported(Unsupported::StateRoot { path, reason }) => {
            assert_eq!(path, inside);
            assert_eq!(reason, "lies inside the home");
        }
        other => panic!("expected Unsupported(StateRoot), got {other:?}"),
    }
}
