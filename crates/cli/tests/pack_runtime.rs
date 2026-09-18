//! `PackRuntime` over a real packs dir and the real installer: the live meta-schema, the
//! shared preset registry, the tool registry and the entity index follow install and
//! uninstall without a restart; a conflicting pack or a taken name is skipped with a warning.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use advance_cli::pack_runtime::PackRuntime;
use advance_pack_manager::{AutoApprove, InMemoryPackRegistry, Installer};
use advance_shared_types::entity::{EntityId, EntityIndex, EntityQuery};
use cap_data::test_support::MemoryEntityIndex;
use cap_fs::meta_schema::{MetaSchema, MetaSchemaLoader};
use cap_grant::preset::PresetRegistry;
use cap_tools::{LazyRegistryConfig, LazyToolRegistry};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

/// `packs/agenda` plus a `tool.wasm` for its skill. The stand-in is the cap-tools clock
/// fixture: any component exporting `tool-exports` passes the installer's check, and the
/// registered id `skill::agenda` is what the schema operations bind to.
fn agenda_with_tool(root: &Path) -> PathBuf {
    let dir = root.join("src/agenda");
    copy_tree(&repo().join("packs/agenda"), &dir);
    std::fs::copy(
        repo().join("crates/capabilities/cap-tools/tests/fixtures/clock_tool.component.wasm"),
        dir.join("skills/agenda/tool.wasm"),
    )
    .unwrap();
    dir
}

/// A second pack that claims the `agenda` aspect with a different shape.
fn rival_pack(root: &Path) -> PathBuf {
    let dir = root.join("src/rival");
    std::fs::create_dir_all(dir.join("meta-schema-extensions")).unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        "name: rival\nversion: 1.0.0\nauthor: t\ndescription: d\nlicense: MIT\n\
         runtime-version: \">=0.1.0\"\ntrust-level: untrusted\nprovides:\n  \
         meta-schema-extensions:\n    - agenda\nchecksums:\n  algo: sha256\n  files: {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("meta-schema-extensions/agenda.yaml"),
        "aspect: agenda\nkey: [status]\nfields:\n  status:\n    type: [open, closed]\n",
    )
    .unwrap();
    dir
}

struct Rig {
    tmp: tempfile::TempDir,
    packs_dir: PathBuf,
    registry: Arc<InMemoryPackRegistry>,
    loader: Arc<MetaSchemaLoader>,
    presets: Arc<PresetRegistry>,
    tools: Arc<LazyToolRegistry>,
    runtime: Arc<PackRuntime>,
}

impl Rig {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let packs_dir = tmp.path().join("packs");
        std::fs::create_dir_all(&packs_dir).unwrap();
        let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
        let schema_path = tmp.path().join(".agent/meta-schema.yaml");
        let loader = Arc::new(MetaSchemaLoader::new_with_default(schema_path.clone()));
        let presets = Arc::new(PresetRegistry::with_builtins());
        let tools = Arc::new(LazyToolRegistry::new(LazyRegistryConfig::default()));
        let runtime = Arc::new(PackRuntime::new(registry.clone(), packs_dir.clone()));
        runtime.attach_schema(loader.clone(), schema_path);
        runtime.attach_presets(presets.clone());
        runtime.attach_tools(tools.clone());
        Self {
            tmp,
            packs_dir,
            registry,
            loader,
            presets,
            tools,
            runtime,
        }
    }

    fn installer(&self) -> Installer {
        Installer::new(
            &self.packs_dir,
            self.registry.clone(),
            env!("CARGO_PKG_VERSION"),
            Arc::new(AutoApprove),
        )
    }
}

#[tokio::test]
async fn install_applies_and_uninstall_withdraws() {
    let rig = Rig::new();
    let empty = rig.runtime.apply().await;
    assert!(empty.aspects.is_empty() && empty.presets.is_empty() && empty.tools.is_empty());

    let src = agenda_with_tool(rig.tmp.path());
    rig.installer()
        .install(src.to_str().unwrap())
        .await
        .expect("install agenda");
    let report = rig.runtime.apply().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert!(report.schema_changed);
    assert_eq!(report.packs, vec!["agenda@0.1.0"]);
    assert_eq!(report.schema_packs, vec!["agenda@0.1.0"]);
    assert_eq!(report.aspects, vec!["agenda"]);
    assert_eq!(report.presets, vec!["agenda-editor"]);
    assert_eq!(report.tools, vec!["skill::agenda"]);
    // The live objects the rest of the runtime reads.
    let live = rig.loader.current();
    assert_eq!(live.aspects["agenda"].operations.len(), 2);
    assert!(
        live.required.contains_key("id"),
        "the default required fields survive"
    );
    assert!(rig.presets.contains("agenda-editor"));
    assert!(rig.tools.is_registered("skill::agenda").await);
    // Re-applying an unchanged pack set changes nothing.
    let again = rig.runtime.apply().await;
    assert!(!again.schema_changed);

    rig.installer()
        .uninstall("agenda", "0.1.0")
        .await
        .expect("uninstall");
    let gone = rig.runtime.apply().await;
    assert!(gone.schema_changed);
    assert!(gone.aspects.is_empty() && gone.presets.is_empty() && gone.tools.is_empty());
    assert_eq!(*rig.loader.current(), MetaSchema::default());
    assert!(!rig.presets.contains("agenda-editor"));
    assert!(!rig.tools.is_registered("skill::agenda").await);
}

#[tokio::test]
async fn a_conflicting_pack_is_skipped_with_a_warning() {
    let rig = Rig::new();
    let agenda = agenda_with_tool(rig.tmp.path());
    let rival = rival_pack(rig.tmp.path());
    rig.installer()
        .install(agenda.to_str().unwrap())
        .await
        .unwrap();
    rig.installer()
        .install(rival.to_str().unwrap())
        .await
        .unwrap();
    let report = rig.runtime.apply().await;
    assert_eq!(report.packs, vec!["agenda@0.1.0", "rival@1.0.0"]);
    assert_eq!(
        report.schema_packs,
        vec!["agenda@0.1.0"],
        "pack-name order: agenda first"
    );
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(report.warnings[0].starts_with("pack rival@1.0.0: meta-schema extensions skipped"));
    // agenda's shape stands; the rest of agenda still applies.
    let live = rig.loader.current();
    assert!(live.aspects["agenda"].fields.contains_key("due"));
    assert_eq!(report.presets, vec!["agenda-editor"]);
    assert_eq!(report.tools, vec!["skill::agenda"]);
}

#[tokio::test]
async fn a_workspace_skill_of_the_same_name_wins() {
    let rig = Rig::new();
    // A workspace skill registered at boot under the same id.
    rig.tools
        .register_binary("skill::agenda", b"workspace".to_vec())
        .await;
    let src = agenda_with_tool(rig.tmp.path());
    rig.installer()
        .install(src.to_str().unwrap())
        .await
        .unwrap();
    let report = rig.runtime.apply().await;
    assert!(report.tools.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("skill tool skill::agenda skipped")),
        "{:?}",
        report.warnings
    );
    rig.installer().uninstall("agenda", "0.1.0").await.unwrap();
    rig.runtime.apply().await;
    assert!(
        rig.tools.is_registered("skill::agenda").await,
        "the runtime never removes a tool it did not register"
    );
}

async fn agenda_rows(index: &MemoryEntityIndex) -> usize {
    let mut q = EntityQuery::for_agent("alice");
    q.aspect = Some("agenda".into());
    index.query(&q).await.unwrap().len()
}

#[tokio::test]
async fn existing_records_gain_and_lose_the_aspect() {
    let rig = Rig::new();
    let ws = rig.tmp.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(
        ws.join("launch.md"),
        "---\nid: e-launch\ntype: work-item\ntitle: Launch\nstatus: todo\n---\nbody\n",
    )
    .unwrap();
    let index = Arc::new(MemoryEntityIndex::default());
    rig.runtime
        .attach_entity_reindex(ws.clone(), "alice".into(), index.clone());
    let first = rig.runtime.apply().await;
    assert_eq!(first.reindexed_files, Some(1));
    assert_eq!(agenda_rows(&index).await, 0);

    let src = agenda_with_tool(rig.tmp.path());
    rig.installer()
        .install(src.to_str().unwrap())
        .await
        .unwrap();
    let installed = rig.runtime.apply().await;
    assert_eq!(installed.reindexed_files, Some(1));
    assert_eq!(agenda_rows(&index).await, 1);
    let row = index
        .get("alice", &EntityId("e-launch".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.aspects, vec!["agenda"]);

    rig.installer().uninstall("agenda", "0.1.0").await.unwrap();
    rig.runtime.apply().await;
    assert_eq!(agenda_rows(&index).await, 0);
}

#[tokio::test]
async fn the_watcher_applies_an_install_made_by_another_process() {
    let rig = Rig::new();
    rig.runtime.apply().await;
    let _watcher = rig.runtime.spawn_packs_watcher(Duration::from_millis(100));

    // "Another process": its own registry + installer over the same packs dir.
    let other_registry = Arc::new(InMemoryPackRegistry::new(rig.packs_dir.clone()));
    let other = Installer::new(
        &rig.packs_dir,
        other_registry,
        env!("CARGO_PKG_VERSION"),
        Arc::new(AutoApprove),
    );
    let src = agenda_with_tool(rig.tmp.path());
    other.install(src.to_str().unwrap()).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !rig.loader.current().aspects.contains_key("agenda") {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the watcher did not apply the install within 10 s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(rig.presets.contains("agenda-editor"));
    assert!(rig.tools.is_registered("skill::agenda").await);

    other.uninstall("agenda", "0.1.0").await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while rig.loader.current().aspects.contains_key("agenda") {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the watcher did not apply the uninstall within 10 s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!rig.tools.is_registered("skill::agenda").await);
}
