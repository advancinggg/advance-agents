//! AC-15 — MockBus capture tests for `pack.registry_reloaded` (T56, T57, T58).
//!
//! AC-15 mandates a single `pack.registry_reloaded` event after step ⑧
//! rescan. M019 taxonomy registration is a Slice C+ follow-up — these
//! tests use a MockBus that does NOT enforce taxonomy validation,
//! consistent with the run-manager / others.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use advance_pack_manager::{
    AutoApprove, DependencyResolver, InMemoryPackRegistry, Installer, PackError, PackRegistry,
    RecordingTraceSink, SourceRef,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn build_pack_fixture(root: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pack_dir = root.join(format!("source-{name}-{version}"));
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::create_dir_all(pack_dir.join("behavior-binaries")).unwrap();
    std::fs::write(
        pack_dir.join("behavior-binaries").join("researcher.wasm"),
        b"",
    )
    .unwrap();
    std::fs::write(
        pack_dir.join("pack.yaml"),
        format!(
            r#"name: {name}
version: {version}
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [researcher]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
        ),
    )
    .unwrap();
    pack_dir
}

#[tokio::test]
async fn t56_pack_registry_reloaded_emitted_after_step8_rescan() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = build_pack_fixture(dir.path(), "wired", "1.0.0");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let bus = Arc::new(MockBus::default());
    let installer = Installer {
        packs_dir,
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: Some(bus.clone() as Arc<dyn EventBusEmit>),
        registry_client: None,
        fetch_timeout: None,
    };
    installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .unwrap();
    let events = bus.events.lock().unwrap();
    assert_eq!(
        events.len(),
        1,
        "exactly one event expected (pack.registry_reloaded)"
    );
    let e = &events[0];
    assert_eq!(e.event_type, "pack.registry_reloaded");
    assert_eq!(
        e.payload["installed_pack"], "wired@1.0.0",
        "payload.installed_pack must name the just-installed pack"
    );
    // UUID v4 fields are non-empty hex strings.
    assert!(!e.id.is_empty());
    assert!(!e.trace_id.is_empty());
    assert!(!e.span_id.is_empty());
    // pack_count >= 1 (the just-installed pack).
    assert!(e.payload["pack_count"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn t57_event_field_invariants() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = build_pack_fixture(dir.path(), "inv", "2.0.0");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let bus = Arc::new(MockBus::default());
    let installer = Installer {
        packs_dir,
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: Some(bus.clone() as Arc<dyn EventBusEmit>),
        registry_client: None,
        fetch_timeout: None,
    };
    installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .unwrap();
    let events = bus.events.lock().unwrap();
    let e = &events[0];
    assert_eq!(e.agent_id, "pack-manager");
    assert!(e.task_id.is_none());
    assert!(e.run_id.is_none());
    assert!(e.execution_id.is_none());
    assert!(e.parent_span_id.is_none());
    assert!(e.duration_ms.is_none());
    // Three distinct UUIDs.
    assert_ne!(e.id, e.trace_id);
    assert_ne!(e.id, e.span_id);
    assert_ne!(e.trace_id, e.span_id);
    // Timestamp within 60s of now.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let event_ts = e.timestamp.timestamp();
    assert!(
        (now - event_ts).abs() < 60,
        "event timestamp too far from now: event={event_ts}, now={now}"
    );
}

/// Multi-dep install: pack-root declares dependency on pack-leaf; both are
/// installed in one `Installer::install("pack-root")` call. Asserts the
/// emit-site discipline from §2.7: exactly ONE `pack.registry_reloaded`
/// event for the top-level install (NOT one per pack), and its
/// `installed_pack` names the root pack — guarding against regression
/// where the emit accidentally moves back into `install_with_context`
/// per audit round 8 Diff Info 3.
#[tokio::test]
async fn t56b_multi_dep_install_emits_exactly_one_event_for_root() {
    fn build_pack(root: &Path, name: &str, deps: &[&str]) -> PathBuf {
        let pack_dir = root.join(format!("source-{name}"));
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::create_dir_all(pack_dir.join("behavior-binaries")).unwrap();
        std::fs::write(
            pack_dir.join("behavior-binaries").join("researcher.wasm"),
            b"",
        )
        .unwrap();
        let deps_yaml = if deps.is_empty() {
            "dependencies: []".to_string()
        } else {
            let mut s = String::from("dependencies:\n");
            for d in deps {
                s.push_str(&format!("  - name: {d}\n    version: \">=0.0.0\"\n"));
            }
            s
        };
        std::fs::write(
            pack_dir.join("pack.yaml"),
            format!(
                r#"name: {name}
version: 1.0.0
runtime-version: ">=0.0.1"
{deps_yaml}
provides:
  behavior-binaries: [researcher]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
            ),
        )
        .unwrap();
        pack_dir
    }

    struct LocalResolver {
        map: std::sync::Mutex<Vec<(String, SourceRef)>>,
    }
    #[async_trait]
    impl DependencyResolver for LocalResolver {
        async fn resolve(
            &self,
            name: &str,
            _req: &semver::VersionReq,
        ) -> Result<SourceRef, PackError> {
            for (n, s) in self.map.lock().unwrap().iter() {
                if n == name {
                    return Ok(s.clone());
                }
            }
            Err(PackError::DependencyNotFound {
                name: name.into(),
                version_req: "test".into(),
            })
        }
    }

    let dir = tempfile::TempDir::new().unwrap();
    let leaf_src = build_pack(dir.path(), "leaf", &[]);
    let root_src = build_pack(dir.path(), "root", &["leaf"]);
    let resolver = Arc::new(LocalResolver {
        map: std::sync::Mutex::new(vec![("leaf".into(), SourceRef::Local(leaf_src))]),
    });
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let bus = Arc::new(MockBus::default());
    let installer = Installer {
        packs_dir,
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: Some(resolver as Arc<dyn DependencyResolver>),
        event_bus: Some(bus.clone() as Arc<dyn EventBusEmit>),
        registry_client: None,
        fetch_timeout: None,
    };
    installer
        .install(root_src.to_string_lossy().as_ref())
        .await
        .unwrap();

    // Both packs installed.
    assert!(registry.has("leaf", "1.0.0"));
    assert!(registry.has("root", "1.0.0"));
    // But only ONE event emitted, naming the top-level (root) pack.
    let events = bus.events.lock().unwrap();
    assert_eq!(
        events.len(),
        1,
        "multi-dep install must emit exactly ONE event from the top-level install boundary; got {}",
        events.len()
    );
    assert_eq!(events[0].event_type, "pack.registry_reloaded");
    assert_eq!(events[0].payload["installed_pack"], "root@1.0.0");
    assert!(events[0].payload["pack_count"].as_u64().unwrap() >= 2);
}

#[tokio::test]
async fn t58_event_bus_none_is_observably_silent() {
    // One MockBus + two Installers (A wired, B unwired). Install pack-b
    // through B (NO events). Install pack-a through A. Assert MockBus has
    // exactly one event corresponding to pack-a.
    let dir = tempfile::TempDir::new().unwrap();
    let pack_a_src = build_pack_fixture(dir.path(), "wired", "1.0.0");
    let pack_b_src = build_pack_fixture(dir.path(), "silent", "1.0.0");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let bus = Arc::new(MockBus::default());

    // Installer B — event_bus: None.
    let installer_b = Installer {
        packs_dir: packs_dir.clone(),
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    installer_b
        .install(pack_b_src.to_string_lossy().as_ref())
        .await
        .unwrap();
    assert!(
        bus.events.lock().unwrap().is_empty(),
        "Installer B with event_bus=None must NOT emit any event"
    );

    // Installer A — event_bus: Some(bus).
    let installer_a = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: Some(bus.clone() as Arc<dyn EventBusEmit>),
        registry_client: None,
        fetch_timeout: None,
    };
    installer_a
        .install(pack_a_src.to_string_lossy().as_ref())
        .await
        .unwrap();
    let events = bus.events.lock().unwrap();
    assert_eq!(events.len(), 1, "exactly one event from Installer A");
    assert_eq!(events[0].payload["installed_pack"], "wired@1.0.0");
}
