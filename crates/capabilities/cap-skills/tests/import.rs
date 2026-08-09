//! Slice E — SkillImporter Path A library tests (SE-21..SE-32 + SE-22a +
//! SE-22b + SE-22c + SE-22d). 16 tests covering knowledge-only ingestion,
//! source-script binary UTF-8 reject, symlink defenses at root/dir/leaf
//! levels, target-name traversal reject, missing SKILL.md reject,
//! collision reject, URL scheme whitelist, and the git file:// happy path.

use cap_skills::{
    AdminPoolStorage, McpImportSpec, Provenance, SkillError, SkillImporter, TrustLevel,
};
use tempfile::TempDir;

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── SE-21: import_from_local_path with SKILL.md only → Imported/Untrusted
#[tokio::test]
async fn se_21_local_path_skill_md_only() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("SKILL.md"), "# imported skill\nbody")
        .await
        .unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    importer
        .import_from_local_path(&source, "imported-skill", &admin)
        .await
        .unwrap();

    let bundle = admin.read_bundle("imported-skill").await.unwrap().unwrap();
    assert_eq!(bundle.skill_md, "# imported skill\nbody");
    assert_eq!(bundle.tool_wasm, None);
    assert_eq!(bundle.tool_capabilities, None);
    assert!(bundle.templates.is_empty());
    assert!(bundle.source_scripts.is_empty());
    assert_eq!(bundle.provenance, Provenance::Imported);
    assert_eq!(bundle.trust_level, TrustLevel::Untrusted);
}

// ─── SE-22: full text-only source → templates + source_scripts populated
#[tokio::test]
async fn se_22_local_path_full_text_only() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(&source.join("templates"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(&source.join("source-scripts"))
        .await
        .unwrap();
    tokio::fs::write(source.join("SKILL.md"), "# full\nbody")
        .await
        .unwrap();
    tokio::fs::write(source.join("templates/foo.md"), "foo body")
        .await
        .unwrap();
    tokio::fs::write(source.join("templates/bar.md"), "bar body")
        .await
        .unwrap();
    tokio::fs::write(source.join("source-scripts/baz.sh"), "echo baz")
        .await
        .unwrap();
    tokio::fs::write(source.join("source-scripts/qux.py"), "print('qux')")
        .await
        .unwrap();
    // Random text file at source root — moves to source_scripts via UTF-8.
    tokio::fs::write(source.join("random.txt"), "random body")
        .await
        .unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    importer
        .import_from_local_path(&source, "full-text", &admin)
        .await
        .unwrap();

    let bundle = admin.read_bundle("full-text").await.unwrap().unwrap();
    assert_eq!(bundle.tool_wasm, None);
    assert_eq!(bundle.tool_capabilities, None);
    assert_eq!(bundle.templates.len(), 2);
    // Templates sorted: bar.md, foo.md
    assert_eq!(bundle.templates[0].0, "bar.md");
    assert_eq!(bundle.templates[1].0, "foo.md");
    // Source scripts sorted: baz.sh, qux.py, random.txt
    let names: Vec<_> = bundle
        .source_scripts
        .iter()
        .map(|(f, _)| f.as_str())
        .collect();
    assert_eq!(names, vec!["baz.sh", "qux.py", "random.txt"]);
}

// ─── SE-22a: symlinked templates/ directory → InvalidTransition
#[cfg(unix)]
#[tokio::test]
async fn se_22a_symlinked_templates_dir_rejected() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("SKILL.md"), "body")
        .await
        .unwrap();
    let target = work_dir.path().join("evil_dir");
    tokio::fs::create_dir_all(&target).await.unwrap();
    std::os::unix::fs::symlink(&target, source.join("templates")).unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    let err = importer
        .import_from_local_path(&source, "trapped", &admin)
        .await
        .unwrap_err();
    assert!(
        format!("{err}").contains("symlink"),
        "expected symlink error, got: {err}"
    );
}

// ─── SE-22b: symlinked source-scripts/ directory → InvalidTransition
#[cfg(unix)]
#[tokio::test]
async fn se_22b_symlinked_source_scripts_dir_rejected() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("SKILL.md"), "body")
        .await
        .unwrap();
    let target = work_dir.path().join("evil_dir");
    tokio::fs::create_dir_all(&target).await.unwrap();
    std::os::unix::fs::symlink(&target, source.join("source-scripts")).unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    let err = importer
        .import_from_local_path(&source, "trapped", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("symlink"));
}

// ─── SE-22c: source-scripts filename collision reject
#[tokio::test]
async fn se_22c_source_scripts_collision_reject() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(source.join("source-scripts"))
        .await
        .unwrap();
    tokio::fs::write(source.join("SKILL.md"), "body")
        .await
        .unwrap();
    // Both <source>/source-scripts/script.sh AND <source>/script.sh.
    tokio::fs::write(source.join("source-scripts/script.sh"), "from dir")
        .await
        .unwrap();
    tokio::fs::write(source.join("script.sh"), "from root")
        .await
        .unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    let err = importer
        .import_from_local_path(&source, "collide", &admin)
        .await
        .unwrap_err();
    assert!(
        format!("{err}").contains("collision"),
        "expected collision error, got: {err}"
    );
}

// ─── SE-22d: binary tool.wasm at source root → UTF-8 reject
#[tokio::test]
async fn se_22d_binary_tool_wasm_at_source_rejected() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("SKILL.md"), "body")
        .await
        .unwrap();
    // Binary content guaranteed to fail UTF-8: 0xFF 0xFE
    tokio::fs::write(source.join("tool.wasm"), [0xFFu8, 0xFE])
        .await
        .unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    let err = importer
        .import_from_local_path(&source, "binary-bait", &admin)
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("UTF-8"), "expected UTF-8 error, got: {msg}");
}

// ─── SE-23: leaf-file symlink rejection (templates/payroll.md → /etc)
#[cfg(unix)]
#[tokio::test]
async fn se_23_leaf_file_symlink_rejected() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(source.join("templates"))
        .await
        .unwrap();
    tokio::fs::write(source.join("SKILL.md"), "body")
        .await
        .unwrap();

    let sentinel = work_dir.path().join("OUTSIDE");
    tokio::fs::write(&sentinel, "secret content").await.unwrap();
    std::os::unix::fs::symlink(&sentinel, source.join("templates/payroll.md")).unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    let err = importer
        .import_from_local_path(&source, "leaf-trap", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("symlink"));
}

// ─── SE-24: source root symlink rejection
#[cfg(unix)]
#[tokio::test]
async fn se_24_source_root_symlink_rejected() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let real_dir = work_dir.path().join("real");
    tokio::fs::create_dir_all(&real_dir).await.unwrap();
    tokio::fs::write(real_dir.join("SKILL.md"), "body")
        .await
        .unwrap();

    let link_dir = work_dir.path().join("link");
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    let err = importer
        .import_from_local_path(&link_dir, "root-trap", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("symlink"));
}

// ─── SE-25: target_name "../escape" → InvalidName
#[tokio::test]
async fn se_25_target_name_traversal_reject() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("SKILL.md"), "body")
        .await
        .unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    let err = importer
        .import_from_local_path(&source, "../escape", &admin)
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::InvalidName(_)));
}

// ─── SE-26: source missing SKILL.md → InvalidTransition
#[tokio::test]
async fn se_26_missing_skill_md_reject() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let source = work_dir.path().join("src");
    tokio::fs::create_dir_all(&source).await.unwrap();
    // No SKILL.md!

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());
    let err = importer
        .import_from_local_path(&source, "no-md", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("skill.md"));
}

// ─── SE-27: import_from_mcp_source synthesizes SKILL.md
#[tokio::test]
async fn se_27_mcp_source_synthesizes_skill_md() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    let spec = McpImportSpec {
        source_name: "mcp-skill".to_string(),
        prompt_text: "This is the prompt body.".to_string(),
        description: "A short description".to_string(),
        tags: vec!["alpha".to_string(), "beta".to_string()],
    };
    importer
        .import_from_mcp_source(&spec, &admin)
        .await
        .unwrap();

    let bundle = admin.read_bundle("mcp-skill").await.unwrap().unwrap();
    assert!(bundle.skill_md.contains("name: mcp-skill"));
    assert!(bundle.skill_md.contains("description: A short description"));
    assert!(bundle.skill_md.contains("alpha"));
    assert!(bundle.skill_md.contains("beta"));
    assert!(bundle.skill_md.contains("This is the prompt body."));
    assert_eq!(bundle.tool_wasm, None);
    assert_eq!(bundle.provenance, Provenance::Imported);
}

// ─── SE-27a: import_from_mcp_source with YAML-hazardous description
// (foo: bar, [x, y], etc.) — serde_yml serialization must quote them so
// the resulting frontmatter parses to a plain string, not a nested
// mapping or sequence (round-2 audit gap closure).
#[tokio::test]
async fn se_27a_mcp_source_yaml_hazardous_description() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    for desc in [
        "foo: bar",      // YAML inline mapping-like
        "[x, y, z]",     // YAML inline sequence-like
        "{a: 1, b: 2}",  // YAML inline mapping-like
        "*anchor-ref",   // YAML alias-like
        "&anchor-def",   // YAML anchor-def-like
        "!!str literal", // YAML tag-like
        "value with \"quotes\"",
        "value with 'single quotes'",
    ] {
        let spec = McpImportSpec {
            source_name: "yaml-hazard".to_string(),
            prompt_text: "body".to_string(),
            description: desc.to_string(),
            tags: vec![],
        };
        importer
            .import_from_mcp_source(&spec, &admin)
            .await
            .unwrap();
        let bundle = admin.read_bundle("yaml-hazard").await.unwrap().unwrap();
        // Parse the frontmatter back via serde_yml and assert the
        // description is preserved as a STRING (not a nested
        // map/sequence/etc).
        let body = &bundle.skill_md;
        let (_, after) = body.split_once("---\n").expect("frontmatter open");
        let (fm, _) = after.split_once("\n---\n").expect("frontmatter close");
        #[derive(serde::Deserialize)]
        struct Fm {
            description: String,
        }
        let parsed: Fm = serde_yml::from_str(fm).unwrap_or_else(|e| {
            panic!("frontmatter parse failed for desc={desc:?}: {e}; fm:\n{fm}")
        });
        assert_eq!(parsed.description, desc, "round-trip mismatch for {desc:?}");
    }
}

// ─── SE-27b: import_from_mcp_source rejects control chars in description
#[tokio::test]
async fn se_27b_mcp_source_rejects_control_chars() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    let spec = McpImportSpec {
        source_name: "ctl-bait".to_string(),
        prompt_text: "body".to_string(),
        description: format!("desc with {} control", '\u{0001}'),
        tags: vec![],
    };
    let err = importer
        .import_from_mcp_source(&spec, &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("control"));
}

// ─── SE-28: ext:: URL scheme reject
#[tokio::test]
async fn se_28_git_url_ext_scheme_reject() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    let err = importer
        .import_from_git_url("ext::sh -c evil", "x", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("scheme"));
}

// ─── SE-29: ssh:// URL scheme reject
#[tokio::test]
async fn se_29_git_url_ssh_scheme_reject() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    let err = importer
        .import_from_git_url("ssh://user@host/repo", "x", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("scheme"));
}

// ─── SE-30: git:// URL scheme reject
#[tokio::test]
async fn se_30_git_url_git_scheme_reject() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    let err = importer
        .import_from_git_url("git://github.com/x/y", "x", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("scheme"));
}

// ─── SE-31: scp-style URL (no scheme) reject
#[tokio::test]
async fn se_31_git_url_scp_style_reject() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    let err = importer
        .import_from_git_url("user@host:path/repo", "x", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("scheme"));
}

// ─── SE-31a: http:// URL reject (adversarial round-1 Codex W1 fix —
// authenticated transport only)
#[tokio::test]
async fn se_31a_git_url_http_scheme_reject() {
    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    let err = importer
        .import_from_git_url("http://example.com/repo", "x", &admin)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("scheme"));
}

// ─── SE-32: import_from_git_url with file:// bare-git-repo
#[tokio::test]
async fn se_32_git_url_file_scheme_happy_path() {
    if !git_available() {
        eprintln!("skipping SE-32: git binary not in PATH");
        return;
    }

    let work_dir = TempDir::new().unwrap();
    let admin_dir = TempDir::new().unwrap();
    let repo_src = work_dir.path().join("repo_src");
    let bare = work_dir.path().join("repo.git");

    // Create a working repo and commit a SKILL.md.
    tokio::fs::create_dir_all(&repo_src).await.unwrap();
    tokio::fs::write(repo_src.join("SKILL.md"), "# from git\nbody")
        .await
        .unwrap();
    let run = |args: &[&str], cwd: &std::path::Path| {
        std::process::Command::new("git")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .current_dir(cwd)
            .args(args)
            .output()
            .unwrap()
    };
    let out = run(&["init", "-b", "main"], &repo_src);
    assert!(out.status.success(), "git init: {:?}", out);
    run(&["add", "SKILL.md"], &repo_src);
    let out = run(&["commit", "-m", "initial"], &repo_src);
    assert!(out.status.success(), "git commit: {:?}", out);
    // Clone --bare into the file:// target
    let out = std::process::Command::new("git")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .args(["clone", "--bare"])
        .arg(&repo_src)
        .arg(&bare)
        .output()
        .unwrap();
    assert!(out.status.success(), "git clone --bare: {:?}", out);

    let url = format!("file://{}", bare.to_string_lossy());
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let importer = SkillImporter::new(work_dir.path().to_path_buf());

    importer
        .import_from_git_url(&url, "from-git", &admin)
        .await
        .unwrap();
    let bundle = admin.read_bundle("from-git").await.unwrap().unwrap();
    assert!(bundle.skill_md.contains("# from git"));
}
