//! GAP-05 (P2, exposure leg) — installed resource-capabilities' `tools[]` reconciled against
//! host-native tools in the ToolRegistry. See docs/plans/PACK-GAP-CLOSURE.md §3.3.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_cli::tool_exposure::reconcile_pack_tool_exposure;
use advance_pack_manager::{AutoApprove, InMemoryPackRegistry, Installer, PackRegistry};
use cap_tools::{
    HostTool, LazyRegistryConfig, LazyToolRegistry, MethodInfo, ToolDescription, ToolError,
};

const CAPABILITY_YAML: &str = "id: advance.structured-data\ncanonical_surfaces:\n  - body-native\ntools:\n  - name: advance.data.query\n    read_only: true\n  - name: advance.data.upsert\n    read_only: false\n";

fn write_pack(root: &Path) -> PathBuf {
    let dir = root.join("sd-src");
    std::fs::create_dir_all(dir.join("resource-capabilities/structured-data")).unwrap();
    std::fs::write(
        dir.join("resource-capabilities/structured-data/capability.yaml"),
        CAPABILITY_YAML,
    )
    .unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        "name: sd\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  resource-capabilities:\n    - structured-data\nchecksums:\n  algo: sha256\n  files: {}\n",
    )
    .unwrap();
    dir
}

struct Echo;
#[async_trait::async_trait]
impl HostTool for Echo {
    fn describe(&self) -> ToolDescription {
        ToolDescription {
            description: "echo".into(),
            methods: vec![MethodInfo {
                name: "echo".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                idempotent: Some(true),
            }],
        }
    }
    async fn execute(&self, _m: &str, p: &[u8]) -> Result<Vec<u8>, ToolError> {
        Ok(p.to_vec())
    }
}

#[tokio::test]
async fn te_01_reports_missing_then_bound_host_tools() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs.clone()));
    Installer::new(&packs, registry.clone(), "0.1.0", Arc::new(AutoApprove))
        .install(write_pack(tmp.path()).to_str().unwrap())
        .await
        .unwrap();
    let tools = LazyToolRegistry::new(LazyRegistryConfig::default());
    let packs_dyn: Arc<dyn PackRegistry> = registry;

    let report = reconcile_pack_tool_exposure(&tools, packs_dyn.as_ref()).await;
    assert!(report.bound.is_empty());
    assert_eq!(
        report.missing,
        vec![
            "advance.data.query".to_string(),
            "advance.data.upsert".to_string()
        ]
    );

    tools
        .register_host("advance.data.query", Arc::new(Echo))
        .await
        .unwrap();
    let report = reconcile_pack_tool_exposure(&tools, packs_dyn.as_ref()).await;
    assert_eq!(report.bound, vec!["advance.data.query".to_string()]);
    assert_eq!(report.missing, vec!["advance.data.upsert".to_string()]);
}
