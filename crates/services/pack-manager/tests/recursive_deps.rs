//! Recursive dependency install integration tests (Slice B, AC-08).
//!
//! T21 linear chain (mock resolver), T21b end-to-end Local-source chain,
//! T22 diamond dedup, T23 cycle, T24 missing dep, T25 version mismatch,
//! T26 depth cap.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use advance_pack_manager::{
    AutoApprove, DependencyResolver, InMemoryPackRegistry, Installer, PackError, PackRegistry,
    RecordingTraceSink, SourceRef,
};

/// Build a pack source dir containing pack.yaml + an empty behavior-binaries/
/// dir + the declared researcher artifact. `deps` is the YAML deps list body.
fn make_pack_fixture(
    root: &Path,
    name: &str,
    version: &str,
    runtime_range: &str,
    deps_yaml: &str,
) -> PathBuf {
    let pack_dir = root.join(format!("source-{name}-{version}"));
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::create_dir_all(pack_dir.join("behavior-binaries")).unwrap();
    std::fs::write(
        pack_dir.join("behavior-binaries").join("researcher.wasm"),
        b"",
    )
    .unwrap();
    let pack_yaml = format!(
        r#"name: {name}
version: {version}
runtime-version: "{runtime_range}"
{deps_yaml}
provides:
  behavior-binaries: [researcher]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
    );
    std::fs::write(pack_dir.join("pack.yaml"), pack_yaml).unwrap();
    pack_dir
}

/// MockDependencyResolver maps (name, req) to a SourceRef from a pre-seeded
/// table. Records resolve-call sequence for ordering assertions.
struct MockResolver {
    map: Mutex<Vec<(String, SourceRef)>>, // (name, source)
    calls: Mutex<Vec<String>>,            // names in resolve order
}

impl MockResolver {
    fn new() -> Self {
        Self {
            map: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }
    fn add(&self, name: &str, source: SourceRef) {
        self.map.lock().unwrap().push((name.into(), source));
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl DependencyResolver for MockResolver {
    async fn resolve(&self, name: &str, _req: &semver::VersionReq) -> Result<SourceRef, PackError> {
        self.calls.lock().unwrap().push(name.into());
        let map = self.map.lock().unwrap();
        for (n, src) in map.iter() {
            if n == name {
                return Ok(src.clone());
            }
        }
        Err(PackError::DependencyNotFound {
            name: name.into(),
            version_req: "<test>".into(),
        })
    }
}

fn make_installer(
    packs_dir: PathBuf,
    resolver: Option<Arc<dyn DependencyResolver>>,
) -> (Installer, Arc<InMemoryPackRegistry>) {
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: resolver,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    (installer, registry)
}

// ───── T21 linear chain A → B → C ─────────────────────────────────────

#[tokio::test]
async fn t21_linear_chain_mock_resolver_installs_in_order() {
    let dir = tempfile::TempDir::new().unwrap();
    let c_src = make_pack_fixture(dir.path(), "c", "1.0.0", ">=0.0.1", "dependencies: []");
    let b_src = make_pack_fixture(
        dir.path(),
        "b",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: c, version: \"^1.0.0\"}",
    );
    let a_src = make_pack_fixture(
        dir.path(),
        "a",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: b, version: \"^1.0.0\"}",
    );

    let resolver = Arc::new(MockResolver::new());
    resolver.add("b", SourceRef::Local(b_src));
    resolver.add("c", SourceRef::Local(c_src));

    let packs_dir = dir.path().join("packs");
    let (installer, registry) = make_installer(packs_dir, Some(resolver.clone()));
    let report = installer
        .install(a_src.to_string_lossy().as_ref())
        .await
        .expect("install A");
    assert_eq!(report.name, "a");

    let installed: Vec<_> = registry.list_installed();
    let names: Vec<_> = installed.iter().map(|m| m.name.clone()).collect();
    assert!(names.contains(&"a".to_string()));
    assert!(names.contains(&"b".to_string()));
    assert!(names.contains(&"c".to_string()));

    // Resolver was called for b then c (B's deps resolved before A finishes).
    let calls = resolver.calls();
    assert_eq!(calls, vec!["b".to_string(), "c".to_string()]);
}

// ───── T21b end-to-end Local-source chain (no separate mocks) ─────────
// Already covered by T21 — the resolver returns SourceRef::Local pointing to
// real on-disk pack sources, exercising the full fetch+parse+install loop.
// T21b kept as a regression sentinel that verifies the registry contains all
// 3 packs after a chain install.

#[tokio::test]
async fn t21b_end_to_end_chain_registers_all_packs() {
    let dir = tempfile::TempDir::new().unwrap();
    let c_src = make_pack_fixture(dir.path(), "cc", "1.0.0", ">=0.0.1", "dependencies: []");
    let b_src = make_pack_fixture(
        dir.path(),
        "bb",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: cc, version: \"^1.0.0\"}",
    );
    let a_src = make_pack_fixture(
        dir.path(),
        "aa",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: bb, version: \"^1.0.0\"}",
    );
    let resolver = Arc::new(MockResolver::new());
    resolver.add("bb", SourceRef::Local(b_src));
    resolver.add("cc", SourceRef::Local(c_src));

    let packs_dir = dir.path().join("packs");
    let (installer, registry) = make_installer(packs_dir, Some(resolver));
    installer
        .install(a_src.to_string_lossy().as_ref())
        .await
        .unwrap();
    assert!(registry.has("aa", "1.0.0"));
    assert!(registry.has("bb", "1.0.0"));
    assert!(registry.has("cc", "1.0.0"));
}

// ───── T22 diamond A → B → C, A → D → C ───────────────────────────────

#[tokio::test]
async fn t22_diamond_dedup_c_installed_once() {
    let dir = tempfile::TempDir::new().unwrap();
    let c_src = make_pack_fixture(
        dir.path(),
        "diamond-c",
        "1.0.0",
        ">=0.0.1",
        "dependencies: []",
    );
    let b_src = make_pack_fixture(
        dir.path(),
        "diamond-b",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: diamond-c, version: \"^1.0.0\"}",
    );
    let d_src = make_pack_fixture(
        dir.path(),
        "diamond-d",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: diamond-c, version: \"^1.0.0\"}",
    );
    let a_src = make_pack_fixture(
        dir.path(),
        "diamond-a",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: diamond-b, version: \"^1.0.0\"}\n  - {name: diamond-d, version: \"^1.0.0\"}",
    );

    let resolver = Arc::new(MockResolver::new());
    resolver.add("diamond-b", SourceRef::Local(b_src));
    resolver.add("diamond-c", SourceRef::Local(c_src));
    resolver.add("diamond-d", SourceRef::Local(d_src));

    let packs_dir = dir.path().join("packs");
    let (installer, registry) = make_installer(packs_dir, Some(resolver.clone()));
    installer
        .install(a_src.to_string_lossy().as_ref())
        .await
        .unwrap();

    assert!(registry.has("diamond-a", "1.0.0"));
    assert!(registry.has("diamond-b", "1.0.0"));
    assert!(registry.has("diamond-c", "1.0.0"));
    assert!(registry.has("diamond-d", "1.0.0"));

    // Resolver called for B, C, D in that order. C is NOT re-resolved on D's
    // path because find_installed_satisfying skips it.
    let calls = resolver.calls();
    assert_eq!(
        calls,
        vec![
            "diamond-b".to_string(),
            "diamond-c".to_string(),
            "diamond-d".to_string()
        ],
        "C should be resolved exactly once via B's branch"
    );
}

// ───── T23 cycle A → B → A ────────────────────────────────────────────

#[tokio::test]
async fn t23_cycle_detection_renders_dfs_path() {
    let dir = tempfile::TempDir::new().unwrap();
    let b_src = make_pack_fixture(
        dir.path(),
        "cycle-b",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: cycle-a, version: \"^1.0.0\"}",
    );
    let a_src = make_pack_fixture(
        dir.path(),
        "cycle-a",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: cycle-b, version: \"^1.0.0\"}",
    );

    let resolver = Arc::new(MockResolver::new());
    resolver.add("cycle-a", SourceRef::Local(a_src.clone()));
    resolver.add("cycle-b", SourceRef::Local(b_src));

    let packs_dir = dir.path().join("packs");
    let (installer, _) = make_installer(packs_dir, Some(resolver));
    match installer.install(a_src.to_string_lossy().as_ref()).await {
        Err(PackError::DependencyCycle { path }) => {
            // Outer install of A: not pushed. A's dep B pushed. B's install
            // recurses; B's dep A is pushed. A's install recurses; A's dep B
            // is detected on the in_flight stack → cycle.
            // Expected path: ["cycle-b", "cycle-a", "cycle-b"] (DFS order +
            // current key).
            assert_eq!(
                path,
                vec![
                    "cycle-b".to_string(),
                    "cycle-a".to_string(),
                    "cycle-b".to_string()
                ]
            );
        }
        other => panic!("expected DependencyCycle, got {other:?}"),
    }
}

// ───── T24 missing dep ────────────────────────────────────────────────

#[tokio::test]
async fn t24_missing_dep_returns_dependency_not_found() {
    let dir = tempfile::TempDir::new().unwrap();
    let a_src = make_pack_fixture(
        dir.path(),
        "miss-a",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: nonexistent, version: \"^1.0.0\"}",
    );
    let resolver = Arc::new(MockResolver::new());
    // resolver has no mapping for "nonexistent" → returns DependencyNotFound

    let packs_dir = dir.path().join("packs");
    let (installer, _) = make_installer(packs_dir, Some(resolver));
    match installer.install(a_src.to_string_lossy().as_ref()).await {
        Err(PackError::DependencyNotFound { name, .. }) => {
            assert_eq!(name, "nonexistent");
        }
        other => panic!("expected DependencyNotFound, got {other:?}"),
    }
}

// ───── T25 resolver returns wrong version ─────────────────────────────

#[tokio::test]
async fn t25_resolver_returns_wrong_version_surfaces_mismatch() {
    let dir = tempfile::TempDir::new().unwrap();
    // The resolver returns a pack named "vm-b" at version 2.0.0; A's manifest
    // requires "vm-b" at "^1.0.0". After install, find_installed_satisfying
    // returns None because 2.0.0 doesn't satisfy ^1.0.0.
    let b_src = make_pack_fixture(dir.path(), "vm-b", "2.0.0", ">=0.0.1", "dependencies: []");
    let a_src = make_pack_fixture(
        dir.path(),
        "vm-a",
        "1.0.0",
        ">=0.0.1",
        "dependencies:\n  - {name: vm-b, version: \"^1.0.0\"}",
    );
    let resolver = Arc::new(MockResolver::new());
    resolver.add("vm-b", SourceRef::Local(b_src));

    let packs_dir = dir.path().join("packs");
    let (installer, _) = make_installer(packs_dir, Some(resolver));
    match installer.install(a_src.to_string_lossy().as_ref()).await {
        Err(PackError::DependencyVersionMismatch { name, required, .. }) => {
            assert_eq!(name, "vm-b");
            assert_eq!(required, "^1.0.0");
        }
        other => panic!("expected DependencyVersionMismatch, got {other:?}"),
    }
}

// ───── T26 depth cap ─────────────────────────────────────────────────

#[tokio::test]
async fn t26_depth_cap_exceeded_at_level_33() {
    // Build 34 packs in a linear chain p0 → p1 → … → p33.
    // depth check is `depth + 1 > 32`. Outer install of p0 is depth=0; entering
    // step ⑤ for p0's dep p1, the check evaluates depth+1=1, no error.
    // Recursing into p1, depth=1; step ⑤ for p1's dep p2 → depth+1=2.
    // … after 32 recursions, p32 install at depth=32; step ⑤ for p32's dep p33
    // → depth+1=33 > 32 → DependencyDepthExceeded.
    let dir = tempfile::TempDir::new().unwrap();
    let mut srcs: Vec<PathBuf> = Vec::with_capacity(34);
    // Build in REVERSE so the "deepest" pack (p33) has no deps.
    for i in (0..=33).rev() {
        let deps_yaml = if i == 33 {
            "dependencies: []".to_string()
        } else {
            format!(
                "dependencies:\n  - {{name: dpack-{}, version: \"^1.0.0\"}}",
                i + 1
            )
        };
        let src = make_pack_fixture(
            dir.path(),
            &format!("dpack-{i}"),
            "1.0.0",
            ">=0.0.1",
            &deps_yaml,
        );
        srcs.push(src);
    }
    // srcs is in reverse order (p33 .. p0); reverse to get p0 first.
    srcs.reverse();

    let resolver = Arc::new(MockResolver::new());
    for (i, src) in srcs.iter().enumerate().skip(1).take(33) {
        resolver.add(&format!("dpack-{i}"), SourceRef::Local(src.clone()));
    }

    let packs_dir = dir.path().join("packs");
    let (installer, _) = make_installer(packs_dir, Some(resolver));
    match installer.install(srcs[0].to_string_lossy().as_ref()).await {
        Err(PackError::DependencyDepthExceeded { max_depth, name }) => {
            assert_eq!(max_depth, 32);
            assert_eq!(name, "dpack-33");
        }
        other => panic!("expected DependencyDepthExceeded, got {other:?}"),
    }
}
