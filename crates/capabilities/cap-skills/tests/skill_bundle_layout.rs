//! Slice E — SkillBundle layout regression tests (SE-11..SE-14).
//!
//! Library-level coverage of SkillBundle::new + AdminPoolStorage on-disk
//! shape for the admin Path B direct-write case (where tool_wasm and
//! tool_capabilities are populated by admin-side code outside this slice).

use cap_skills::{AdminPoolStorage, Provenance, SkillBundle, TrustLevel};
use tempfile::TempDir;

fn full_bundle() -> SkillBundle {
    SkillBundle::new(
        "rich-bundle".to_string(),
        "# rich-bundle\n\nbody".to_string(),
        Some(vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]), // WASM magic
        Some(r#"{"caps":["fs.read","net.fetch"]}"#.to_string()),
        vec![
            ("intro.md".to_string(), "# intro\nstuff".to_string()),
            ("deep.md".to_string(), "# deep\nmore".to_string()),
        ],
        vec![("setup.sh".to_string(), "#!/bin/sh\necho hi\n".to_string())],
        Provenance::Imported,
        TrustLevel::Trusted,
    )
    .expect("full bundle must construct")
}

// ─── SE-11: SkillBundle::new with all 9 fields preserved
#[test]
fn se_11_constructor_full_bundle() {
    let b = full_bundle();
    assert_eq!(b.name, "rich-bundle");
    assert_eq!(b.skill_md, "# rich-bundle\n\nbody");
    assert!(b.tool_wasm.is_some());
    assert!(b.tool_capabilities.is_some());
    assert_eq!(b.templates.len(), 2);
    assert_eq!(b.source_scripts.len(), 1);
    assert_eq!(b.provenance, Provenance::Imported);
    assert_eq!(b.trust_level, TrustLevel::Trusted);
}

// ─── SE-12: AdminPool write_bundle with tool.wasm + tool.capabilities.json
#[tokio::test]
async fn se_12_admin_path_b_tool_wasm_and_caps_on_disk() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());
    let bundle = full_bundle();
    admin.write_bundle(&bundle).await.unwrap();

    // tool.wasm file
    let wasm_path = tmp.path().join("rich-bundle/tool.wasm");
    assert!(tokio::fs::try_exists(&wasm_path).await.unwrap());
    let wasm_bytes = tokio::fs::read(&wasm_path).await.unwrap();
    assert_eq!(wasm_bytes, bundle.tool_wasm.unwrap());

    // tool.capabilities.json file (separate from agent's caps)
    let caps_path = tmp.path().join("rich-bundle/tool.capabilities.json");
    assert!(tokio::fs::try_exists(&caps_path).await.unwrap());
    let caps_text = tokio::fs::read_to_string(&caps_path).await.unwrap();
    assert_eq!(caps_text, bundle.tool_capabilities.unwrap());

    // Round-trip read_bundle
    let read_back = admin.read_bundle("rich-bundle").await.unwrap().unwrap();
    assert_eq!(read_back.tool_wasm, Some(wasm_bytes));
    assert_eq!(read_back.tool_capabilities, Some(caps_text));
}

// ─── SE-13: AdminPool write_bundle with templates/ layout
#[tokio::test]
async fn se_13_templates_dir_layout() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());

    let bundle = SkillBundle::new(
        "tpl-test".to_string(),
        "# templates body".to_string(),
        None,
        None,
        vec![
            ("alpha.md".to_string(), "alpha body".to_string()),
            ("beta.md".to_string(), "beta body".to_string()),
            ("gamma.md".to_string(), "gamma body".to_string()),
        ],
        Vec::new(),
        Provenance::AgentCreated,
        TrustLevel::Untrusted,
    )
    .unwrap();
    admin.write_bundle(&bundle).await.unwrap();

    for (filename, expected) in &[
        ("alpha.md", "alpha body"),
        ("beta.md", "beta body"),
        ("gamma.md", "gamma body"),
    ] {
        let path = tmp.path().join("tpl-test/templates").join(filename);
        assert!(
            tokio::fs::try_exists(&path).await.unwrap(),
            "{filename:?} should exist"
        );
        let got = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(&got, expected);
    }

    let read_back = admin.read_bundle("tpl-test").await.unwrap().unwrap();
    assert_eq!(read_back.templates.len(), 3);
}

// ─── SE-14: AdminPool write_bundle with source-scripts/ layout
#[tokio::test]
async fn se_14_source_scripts_dir_layout() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());

    let bundle = SkillBundle::new(
        "src-test".to_string(),
        "# source-scripts body".to_string(),
        None,
        None,
        Vec::new(),
        vec![
            ("setup.sh".to_string(), "#!/bin/sh\necho up\n".to_string()),
            ("run.py".to_string(), "print('hi')\n".to_string()),
        ],
        Provenance::Imported,
        TrustLevel::Untrusted,
    )
    .unwrap();
    admin.write_bundle(&bundle).await.unwrap();

    let path = tmp.path().join("src-test/source-scripts/setup.sh");
    assert!(tokio::fs::try_exists(&path).await.unwrap());
    let got = tokio::fs::read_to_string(&path).await.unwrap();
    assert_eq!(got, "#!/bin/sh\necho up\n");

    let read_back = admin.read_bundle("src-test").await.unwrap().unwrap();
    assert_eq!(read_back.source_scripts.len(), 2);
}
