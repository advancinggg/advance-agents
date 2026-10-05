//! MODULE-001-T111 (3) / MODULE-001-AC-30 — the composition library changes no wire
//! contract: the CONTRACT-192 artifacts under `crates/client-api/sdk-artifacts` are
//! byte-identical to the lane base `84a82451` (owner ruling 2026-10-03: the schema changed on
//! the main line after v0.1.26, `api_version` did not; the base is the tree this lane started
//! from).
//!
//! `fixtures/sdk_artifacts_lane_base.sha256` holds `<sha256>  <path>` of every file, captured
//! with `git show 84a82451:crates/client-api/sdk-artifacts/<path> | shasum -a 256`. The same
//! check at lane close: `git diff --exit-code 84a82451 -- crates/client-api/sdk-artifacts`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const LANE_BASE: &str = include_str!("fixtures/sdk_artifacts_lane_base.sha256");
const SCHEMA_HASH: &str = "d7fb650a6c002a269cf3018af90701e5435246712ffe5712443f79b4a99ff492";
const API_VERSION: &str = "2026-09-17";

fn artifacts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../client-api/sdk-artifacts")
}

fn collect(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect(&path, root, out);
        } else {
            let bytes =
                std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let name = path
                .strip_prefix(root)
                .expect("under the artifacts dir")
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(name, hex::encode(Sha256::digest(&bytes)));
        }
    }
}

#[test]
fn module_001_ac30_t111_3_sdk_artifacts_byte_identical_to_lane_base() {
    let expected: BTreeMap<String, String> = LANE_BASE
        .lines()
        .map(|line| {
            let (hash, path) = line
                .split_once("  ")
                .unwrap_or_else(|| panic!("malformed fixture line {line:?}"));
            (path.to_owned(), hash.to_owned())
        })
        .collect();
    assert_eq!(expected.len(), 11, "the lane base has 11 artifact files");

    let root = artifacts_dir();
    let mut actual = BTreeMap::new();
    collect(&root, &root, &mut actual);
    assert_eq!(
        actual, expected,
        "crates/client-api/sdk-artifacts differs from the lane base 84a82451"
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("schema/manifest.json")).expect("read the manifest"),
    )
    .expect("the manifest is JSON");
    assert_eq!(manifest["schema_hash"], SCHEMA_HASH);
    assert_eq!(manifest["api_version"], API_VERSION);
    assert_eq!(advance_client_api::API_VERSION, API_VERSION);
    assert_eq!(
        expected["schema/client-api.schema.json"], SCHEMA_HASH,
        "the schema hash is the schema file's sha256"
    );
}
