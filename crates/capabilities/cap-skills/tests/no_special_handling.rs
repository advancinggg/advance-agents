//! Slice E — AC-25 code-audit verification: `.agent/skills/` is a plain
//! directory of readable files with no privileged access path.
//!
//! These tests complement the §2.7 audit memo (which cites cap-fs::
//! resolver:123-160 hidden-name policy + cap-skills::host_fn.rs 8-lifecycle
//! enumeration + AdminPoolStorage no-host_fn-route). SE-09 + SE-10 confirm
//! the structural shape on the cap-skills side: skills written by
//! DiskSkillStorage land as plain UTF-8 files readable via standard
//! tokio::fs::* APIs.

use cap_skills::persistence::{DiskSkillStorage, SkillBlob, SkillStorage};
use cap_skills::{Provenance, TrustLevel};
use tempfile::TempDir;

// ─── SE-09: DiskSkillStorage write_active → plain tokio::fs::read works
#[tokio::test]
async fn se_09_active_skill_md_readable_via_plain_tokio_fs() {
    let agent_root = TempDir::new().unwrap();
    let storage = DiskSkillStorage::with_default_writer(agent_root.path().to_path_buf());

    let blob = SkillBlob {
        skill_id: "web-search".to_string(),
        version: 1,
        content: "# web-search\n\nbody content".to_string(),
        tags: Vec::new(),
        provenance: Provenance::Imported,
        trust_level: TrustLevel::Untrusted,
    };
    storage.write_active(&blob).await.unwrap();

    // Plain tokio::fs read — no host_fn, no special permission.
    let path = agent_root.path().join(".agent/skills/web-search/SKILL.md");
    let content = tokio::fs::read_to_string(&path).await.unwrap();
    assert_eq!(content, blob.content);
}

// ─── SE-10: tokio::fs::read_dir enumerates active skills as plain dirs
#[tokio::test]
async fn se_10_skills_dir_enumerable_as_plain_dirs() {
    let agent_root = TempDir::new().unwrap();
    let storage = DiskSkillStorage::with_default_writer(agent_root.path().to_path_buf());

    for n in ["alpha", "beta", "gamma"] {
        let blob = SkillBlob {
            skill_id: n.to_string(),
            version: 1,
            content: format!("# {n}\nbody"),
            tags: Vec::new(),
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        };
        storage.write_active(&blob).await.unwrap();
    }

    let skills_dir = agent_root.path().join(".agent/skills");
    let mut entries = tokio::fs::read_dir(&skills_dir).await.unwrap();
    let mut names: Vec<String> = Vec::new();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        let name = entry.file_name().into_string().unwrap();
        let meta = entry.metadata().await.unwrap();
        if !meta.is_dir() {
            continue; // skip workspace .meta.yaml convention if present
        }
        // Each child is a plain directory containing plain SKILL.md.
        let skill_md = entry.path().join("SKILL.md");
        let meta_md = entry.path().join(".meta.yaml");
        assert!(
            tokio::fs::try_exists(&skill_md).await.unwrap(),
            "{name}/SKILL.md should exist as plain file"
        );
        assert!(
            tokio::fs::try_exists(&meta_md).await.unwrap(),
            "{name}/.meta.yaml should exist as plain file"
        );
        names.push(name);
    }
    names.sort();
    assert_eq!(names, vec!["alpha", "beta", "gamma"]);
}
