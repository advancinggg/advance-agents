//! Slice E — AdminPoolStorage integration tests.
//!
//! SE-01..SE-08 + SE-05a + SE-08a (10 tests) covering AC-19 (two-layer
//! storage structural test). Path traversal defenses (per-FILE +
//! per-DIRECTORY symlink reject, safe_remove_dir_all, size caps,
//! canonicalization, validate_skill_filename).

use std::path::PathBuf;

use cap_skills::{AdminPoolStorage, Provenance, SkillBundle, SkillImporter, TrustLevel};
use tempfile::TempDir;

fn make_bundle(name: &str, skill_md: &str) -> SkillBundle {
    SkillBundle::new(
        name.to_string(),
        skill_md.to_string(),
        None,
        None,
        Vec::new(),
        Vec::new(),
        Provenance::AgentCreated,
        TrustLevel::Untrusted,
    )
    .expect("constructor must accept valid bundle")
}

fn make_full_bundle(name: &str) -> SkillBundle {
    SkillBundle::new(
        name.to_string(),
        "# happy-path skill\n\nbody".to_string(),
        Some(vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]), // WASM magic
        Some(r#"{"caps":["fs.read"]}"#.to_string()),
        vec![
            ("intro.md".to_string(), "# intro\nstuff".to_string()),
            ("deep.md".to_string(), "# deep\nmore".to_string()),
        ],
        vec![("setup.sh".to_string(), "#!/bin/sh\necho hi\n".to_string())],
        Provenance::Imported,
        TrustLevel::Untrusted,
    )
    .expect("full bundle must construct")
}

// ─── SE-01: write_bundle + read_bundle roundtrip (SKILL.md + .meta.yaml only)
#[tokio::test]
async fn se_01_roundtrip_skill_md_only() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());
    let bundle = make_bundle("web-search", "# web-search\nbody");
    admin.write_bundle(&bundle).await.unwrap();

    let read_back = admin.read_bundle("web-search").await.unwrap().unwrap();
    assert_eq!(read_back.name, "web-search");
    assert_eq!(read_back.skill_md, "# web-search\nbody");
    assert_eq!(read_back.tool_wasm, None);
    assert_eq!(read_back.tool_capabilities, None);
    assert!(read_back.templates.is_empty());
    assert!(read_back.source_scripts.is_empty());
    assert_eq!(read_back.provenance, bundle.provenance);
    assert_eq!(read_back.trust_level, bundle.trust_level);
}

// ─── SE-02: list_bundles enumerates 3 written bundles sorted
#[tokio::test]
async fn se_02_list_bundles_sorted() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());
    for n in ["zebra", "alpha", "mango"] {
        admin.write_bundle(&make_bundle(n, "body")).await.unwrap();
    }
    let names = admin.list_bundles().await.unwrap();
    assert_eq!(names, vec!["alpha", "mango", "zebra"]);
}

// ─── SE-03: write_bundle rejects path-traversal names
#[tokio::test]
async fn se_03_write_bundle_rejects_path_traversal() {
    let tmp = TempDir::new().unwrap();
    let _admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());
    // The name "..": SkillBundle::new validates via validate_skill_name.
    let bad_names = ["..", "../etc", "a/b", "_leading", "BAD", ""];
    for n in bad_names {
        let result = SkillBundle::new(
            n.to_string(),
            "body".to_string(),
            None,
            None,
            Vec::new(),
            Vec::new(),
            Provenance::AgentCreated,
            TrustLevel::Untrusted,
        );
        assert!(
            result.is_err(),
            "expected name {n:?} to be rejected by constructor"
        );
    }
}

// ─── SE-04: After import + materialize, both admin_root + agent-local present
#[tokio::test]
async fn se_04_two_layer_storage_after_materialize() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let agent_dir = TempDir::new().unwrap();

    // Build a Path A source dir for import.
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("SKILL.md"), "# imported\nbody")
        .await
        .unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    importer
        .import_from_local_path(&source, "web-search", &admin)
        .await
        .unwrap();

    let to = cap_skills::persistence::DiskSkillStorage::with_default_writer(
        agent_dir.path().to_path_buf(),
    );
    cap_skills::materialize_skill("web-search", &admin, &to)
        .await
        .unwrap();

    // Admin pool entry exists
    let admin_skill_md: PathBuf = admin_dir.path().join("web-search").join("SKILL.md");
    assert!(
        tokio::fs::try_exists(&admin_skill_md).await.unwrap(),
        "admin SKILL.md at {admin_skill_md:?} should exist"
    );
    let admin_content = tokio::fs::read_to_string(&admin_skill_md).await.unwrap();
    assert!(admin_content.contains("# imported"));

    // Agent-local active entry exists
    let agent_skill_md: PathBuf = agent_dir
        .path()
        .join(".agent/skills")
        .join("web-search")
        .join("SKILL.md");
    assert!(
        tokio::fs::try_exists(&agent_skill_md).await.unwrap(),
        "agent SKILL.md at {agent_skill_md:?} should exist"
    );
    let agent_content = tokio::fs::read_to_string(&agent_skill_md).await.unwrap();
    assert_eq!(admin_content, agent_content);
}

// ─── SE-05: delete_bundle removes all bundle files
#[tokio::test]
async fn se_05_delete_bundle_removes_all() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());
    let bundle = make_full_bundle("rich-bundle");
    admin.write_bundle(&bundle).await.unwrap();

    let bundle_dir = tmp.path().join("rich-bundle");
    assert!(tokio::fs::try_exists(&bundle_dir).await.unwrap());

    admin.delete_bundle("rich-bundle").await.unwrap();
    assert!(!tokio::fs::try_exists(&bundle_dir).await.unwrap());
}

// ─── SE-05a: safe_remove_dir_all with symlinked leaf — symlink TARGET untouched
#[cfg(unix)]
#[tokio::test]
async fn se_05a_delete_refuses_symlink_target_untouched() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());
    let bundle = make_bundle("victim", "body");
    admin.write_bundle(&bundle).await.unwrap();

    // Create a sentinel file OUTSIDE the bundle and a symlink leaf
    // inside the bundle's templates/ pointing at the sentinel.
    let sentinel = tmp.path().join("OUTSIDE_SENTINEL");
    tokio::fs::write(&sentinel, b"DO NOT DELETE").await.unwrap();

    let templates = tmp.path().join("victim/templates");
    tokio::fs::create_dir_all(&templates).await.unwrap();
    let link = templates.join("trap.md");
    std::os::unix::fs::symlink(&sentinel, &link).unwrap();

    // delete_bundle should refuse on the symlinked leaf.
    let err = admin.delete_bundle("victim").await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("symlink"),
        "expected symlink error, got: {msg}"
    );

    // Sentinel file MUST still exist with original content.
    assert!(tokio::fs::try_exists(&sentinel).await.unwrap());
    let body = tokio::fs::read(&sentinel).await.unwrap();
    assert_eq!(body, b"DO NOT DELETE");
}

// ─── SE-06: read_bundle rejects symlinked SKILL.md
#[cfg(unix)]
#[tokio::test]
async fn se_06_read_bundle_rejects_symlinked_skill_md() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());

    // Manually create a bundle directory with a meta.yaml + symlinked
    // SKILL.md so read_bundle has to walk the symlink check.
    let bundle_dir = tmp.path().join("trap");
    tokio::fs::create_dir_all(&bundle_dir).await.unwrap();
    let sentinel = tmp.path().join("secret.txt");
    tokio::fs::write(&sentinel, b"secret").await.unwrap();
    std::os::unix::fs::symlink(&sentinel, bundle_dir.join("SKILL.md")).unwrap();

    // Write a minimally valid .meta.yaml so the parser advances.
    let meta = "name: trap\nprovenance: AgentCreated\ntrust_level: Untrusted\ntemplate_files: []\nsource_script_files: []\nhas_tool_wasm: false\nhas_tool_capabilities: false\ncreated_at: '2026-05-21T00:00:00Z'\n";
    tokio::fs::write(bundle_dir.join(".meta.yaml"), meta)
        .await
        .unwrap();

    let err = admin.read_bundle("trap").await.unwrap_err();
    assert!(
        format!("{err}").contains("symlink"),
        "expected symlink error, got: {err}"
    );
}

// ─── SE-07: with_default_writer canonicalizes root (behavioral check)
#[cfg(unix)]
#[tokio::test]
async fn se_07_with_default_writer_canonicalizes_root() {
    let tmp = TempDir::new().unwrap();
    let real_root = tmp.path().join("real_admin");
    tokio::fs::create_dir_all(&real_root).await.unwrap();
    let link_root = tmp.path().join("link");
    std::os::unix::fs::symlink(&real_root, &link_root).unwrap();

    // Construct admin pool via the symlinked path.
    let admin = AdminPoolStorage::with_default_writer(link_root.clone());
    admin
        .write_bundle(&make_bundle("foo", "body"))
        .await
        .unwrap();

    // The bundle should land at the canonical path, not the symlinked path.
    let real_target = real_root.join("foo/SKILL.md");
    assert!(
        tokio::fs::try_exists(&real_target).await.unwrap(),
        "bundle should land at canonical path {real_target:?}"
    );

    // Verify the AdminPoolStorage's exposed `root` is the canonical one.
    let real_canon = std::fs::canonicalize(&real_root).unwrap();
    assert_eq!(admin.root(), real_canon.as_path());
}

// ─── SE-08: SkillBundle::new cap rejects
#[tokio::test]
async fn se_08_constructor_cap_rejects() {
    // skill_md > 50_000
    let too_big = "x".repeat(50_001);
    let err = SkillBundle::new(
        "ok-name".to_string(),
        too_big,
        None,
        None,
        Vec::new(),
        Vec::new(),
        Provenance::AgentCreated,
        TrustLevel::Untrusted,
    )
    .unwrap_err();
    assert!(matches!(err, cap_skills::SkillError::ContentTooLarge(_)));

    // tool_wasm > 16 MiB
    let huge_blob = vec![0u8; 16 * 1024 * 1024 + 1];
    let err = SkillBundle::new(
        "ok-name".to_string(),
        "body".to_string(),
        Some(huge_blob),
        None,
        Vec::new(),
        Vec::new(),
        Provenance::AgentCreated,
        TrustLevel::Untrusted,
    )
    .unwrap_err();
    assert!(matches!(err, cap_skills::SkillError::ContentTooLarge(_)));

    // templates.len() > 32
    let templates: Vec<(String, String)> = (0..33)
        .map(|i| (format!("t{i}.md"), "body".to_string()))
        .collect();
    let err = SkillBundle::new(
        "ok-name".to_string(),
        "body".to_string(),
        None,
        None,
        templates,
        Vec::new(),
        Provenance::AgentCreated,
        TrustLevel::Untrusted,
    )
    .unwrap_err();
    assert!(matches!(err, cap_skills::SkillError::InvalidTransition(_)));

    // source_scripts.len() > 32
    let scripts: Vec<(String, String)> = (0..33)
        .map(|i| (format!("s{i}.sh"), "body".to_string()))
        .collect();
    let err = SkillBundle::new(
        "ok-name".to_string(),
        "body".to_string(),
        None,
        None,
        Vec::new(),
        scripts,
        Provenance::AgentCreated,
        TrustLevel::Untrusted,
    )
    .unwrap_err();
    assert!(matches!(err, cap_skills::SkillError::InvalidTransition(_)));
}

// ─── SE-02a: list_bundles skips symlinked bundle root (round-2 fix)
#[cfg(unix)]
#[tokio::test]
async fn se_02a_list_bundles_skips_symlinked_bundle_root() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());
    // Write a real bundle.
    admin
        .write_bundle(&make_bundle("real-one", "body"))
        .await
        .unwrap();

    // Plant a symlinked bundle root pointing at the real one — should
    // be skipped by list_bundles.
    let target = tmp.path().join("real-one");
    let link = tmp.path().join("shadow");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let names = admin.list_bundles().await.unwrap();
    assert_eq!(
        names,
        vec!["real-one"],
        "shadow symlink should not appear in list"
    );

    // read_bundle("shadow") must also refuse (round-2 list↔read symmetry).
    let read_back = admin.read_bundle("shadow").await.unwrap();
    assert!(
        read_back.is_none(),
        "read_bundle should refuse symlinked bundle root; got: {read_back:?}"
    );
}

// ─── SE-05c: write_bundle crash-safe via staging dir (round-3 fix)
//
// Verifies that if write_bundle's per-file write fails mid-staging, the
// pre-existing bundle is NOT destroyed (the staging-dir + atomic-rename
// approach preserves the original on failure).
//
// We trigger failure by constructing an admin pool where the per-file
// write step inside write_bundle would fail — for example, by making
// the staging dir's parent (root) read-only AFTER writing a valid
// original bundle. On Unix, we use chmod to flip the root to 0o555
// (read+execute only, no write). The first write succeeds; the second
// should fail at staging-dir creation; the original bundle should
// survive.
#[cfg(unix)]
#[tokio::test]
async fn se_05c_write_bundle_crash_safe_preserves_original() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());

    // First write succeeds.
    admin
        .write_bundle(&make_bundle("survivor", "# original v1"))
        .await
        .unwrap();
    let orig_path = tmp.path().join("survivor/SKILL.md");
    assert!(tokio::fs::try_exists(&orig_path).await.unwrap());

    // Make the admin root read-only so the next write_bundle fails at
    // the staging-dir creation step (cannot create `.tmp.survivor.*/`).
    let orig_perms = tokio::fs::metadata(tmp.path()).await.unwrap().permissions();
    let mut readonly = orig_perms.clone();
    readonly.set_mode(0o555);
    tokio::fs::set_permissions(tmp.path(), readonly)
        .await
        .unwrap();

    // Attempt a second write — expect failure.
    let new_bundle = make_bundle("survivor", "# new v2 should not appear");
    let result = admin.write_bundle(&new_bundle).await;
    assert!(
        result.is_err(),
        "expected write_bundle to fail under read-only root"
    );

    // Restore perms so we can read.
    tokio::fs::set_permissions(tmp.path(), orig_perms)
        .await
        .unwrap();

    // Original bundle must still be on disk with original content.
    assert!(tokio::fs::try_exists(&orig_path).await.unwrap());
    let body = tokio::fs::read_to_string(&orig_path).await.unwrap();
    assert_eq!(body, "# original v1");
}

// ─── SE-05b: write_bundle overwrite cleans stale sidecars (round-2 fix)
#[tokio::test]
async fn se_05b_write_bundle_overwrite_removes_stale_sidecars() {
    let tmp = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(tmp.path().to_path_buf());

    // First write: bundle with 2 templates + 1 source_script.
    let original = SkillBundle::new(
        "evolving".to_string(),
        "# v1\nbody".to_string(),
        None,
        None,
        vec![
            ("intro.md".to_string(), "intro".to_string()),
            ("deep.md".to_string(), "deep".to_string()),
        ],
        vec![("setup.sh".to_string(), "echo up".to_string())],
        Provenance::Imported,
        TrustLevel::Untrusted,
    )
    .unwrap();
    admin.write_bundle(&original).await.unwrap();
    assert!(
        tokio::fs::try_exists(tmp.path().join("evolving/templates/intro.md"))
            .await
            .unwrap()
    );
    assert!(
        tokio::fs::try_exists(tmp.path().join("evolving/source-scripts/setup.sh"))
            .await
            .unwrap()
    );

    // Second write: SAME name but dropped all sidecars.
    let shrunk = SkillBundle::new(
        "evolving".to_string(),
        "# v2\nbody".to_string(),
        None,
        None,
        Vec::new(),
        Vec::new(),
        Provenance::Imported,
        TrustLevel::Untrusted,
    )
    .unwrap();
    admin.write_bundle(&shrunk).await.unwrap();

    // Stale sidecars MUST be gone (clean-overwrite semantics).
    assert!(
        !tokio::fs::try_exists(tmp.path().join("evolving/templates/intro.md"))
            .await
            .unwrap(),
        "stale template intro.md should have been removed"
    );
    assert!(
        !tokio::fs::try_exists(tmp.path().join("evolving/source-scripts/setup.sh"))
            .await
            .unwrap(),
        "stale source_script setup.sh should have been removed"
    );

    // Re-read shows the new shrunk bundle.
    let read_back = admin.read_bundle("evolving").await.unwrap().unwrap();
    assert!(read_back.skill_md.contains("# v2"));
    assert!(read_back.templates.is_empty());
    assert!(read_back.source_scripts.is_empty());
}

// ─── SE-08a: validate_skill_filename suite
#[test]
fn se_08a_validate_skill_filename() {
    use cap_skills::validate_skill_filename;

    // Accepts
    for ok in [
        "foo.md",
        "tool.wasm",
        "code-style.json",
        "_underscored.txt",
        "SKILL.md",
    ] {
        assert!(
            validate_skill_filename(ok).is_ok(),
            "expected {ok:?} to be accepted"
        );
    }

    // Rejects
    let mut bad: Vec<String> = vec![
        "".to_string(),
        "../escape".to_string(),
        "foo/bar.md".to_string(),
        "foo bar".to_string(),
        "..".to_string(),
        "abc..def.md".to_string(),
        "foo\\bar.md".to_string(),
        "x".repeat(129),
    ];
    // Control byte (\x01) embedded in filename
    bad.push(format!("foo{}bar", '\u{0001}'));
    for n in &bad {
        let result = validate_skill_filename(n);
        assert!(
            result.is_err(),
            "expected {n:?} to be rejected; got {result:?}"
        );
    }
}
