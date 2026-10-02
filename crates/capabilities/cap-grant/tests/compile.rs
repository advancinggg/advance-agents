//! Compile tests: T04 (canonical mapping), T05 (auto-grant: false), T-A8 (charset).

mod common;

use cap_grant::data::{GrantIssuer, GrantProvenance, GrantStatus, GrantTtl};
use cap_grant::{CapGrantError, StaticConfigCompiler};
use std::io::Write;
use tempfile::NamedTempFile;

fn write_yaml(s: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(s.as_bytes()).expect("write");
    f.flush().expect("flush");
    f
}

// MODULE-013-T04 — AC-04 — canonical PRD §5.7.2 mapping form.
#[test]
fn static_compile_two_capabilities() {
    let yaml = r#"capabilities:
  fs:
    read: [/research/]
    write: [/research/]
  http:
    allowlist: ["https://api.example.com/*"]
  llm: true
"#;
    let f = write_yaml(yaml);
    let grants = StaticConfigCompiler::compile_from_path(f.path(), "root-agent").unwrap();
    assert_eq!(grants.len(), 3);
    let names: Vec<&str> = grants.iter().map(|g| g.capability.as_str()).collect();
    assert!(names.contains(&"fs"));
    assert!(names.contains(&"http"));
    assert!(names.contains(&"llm"));
    for g in &grants {
        assert!(matches!(g.provenance, GrantProvenance::StaticConfig));
        assert!(matches!(g.issuer, GrantIssuer::Config));
        assert!(matches!(g.ttl, GrantTtl::Persistent));
        assert_eq!(g.status, GrantStatus::Active);
        assert_eq!(g.grantee, "root-agent");
        assert_eq!(
            g.id.as_str(),
            &format!("static:root-agent:{}", g.capability)
        );
    }
    let llm = grants.iter().find(|g| g.capability == "llm").unwrap();
    assert!(llm.params.is_empty());
}

// MODULE-013-T05 — AC-05 — auto-grant: false skips emission.
#[test]
fn auto_grant_false_emits_no_grant() {
    let yaml = r#"capabilities:
  skills:
    auto-grant: false
  http:
    allowlist: ["https://api.example.com/*"]
"#;
    let f = write_yaml(yaml);
    let grants = StaticConfigCompiler::compile_from_path(f.path(), "root-agent").unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].capability, "http");
}

// T-A8 — AC-04 + AC-05 — charset gate (capability + grantee).
#[test]
fn reject_capability_with_colon() {
    // Capability containing ':' is rejected.
    let yaml1 = r#"capabilities:
  "fs:malicious":
    read: [/foo]
"#;
    let f1 = write_yaml(yaml1);
    let err1 = StaticConfigCompiler::compile_from_path(f1.path(), "root-agent").unwrap_err();
    let msg1 = format!("{err1}");
    assert!(matches!(err1, CapGrantError::InvalidConfig(_)));
    assert!(msg1.contains("capability") && msg1.contains(':'));

    // Grantee containing ':' is rejected.
    let yaml2 = r#"capabilities:
  fs:
    read: [/foo]
"#;
    let f2 = write_yaml(yaml2);
    let err2 = StaticConfigCompiler::compile_from_path(f2.path(), "root:agent").unwrap_err();
    assert!(matches!(err2, CapGrantError::InvalidConfig(_)));
    let msg2 = format!("{err2}");
    assert!(msg2.contains("grantee") && msg2.contains(':'));
}

// Param values are stored in the form the subset rules read: a YAML list becomes a
// comma-separated set, and `fs` accepts `read` / `write` for `read-paths` / `write-paths`.
#[test]
fn param_lists_become_csv_and_fs_aliases_resolve() {
    let yaml = r#"capabilities:
  fs:
    read: [/research, /notes]
    write-paths: /research
  tools:
    ids: [data, "skill::agenda"]
"#;
    let f = write_yaml(yaml);
    let grants = StaticConfigCompiler::compile_from_path(f.path(), "root-agent").unwrap();
    let param = |cap: &str, key: &str| {
        grants
            .iter()
            .find(|g| g.capability == cap)
            .and_then(|g| g.params.iter().find(|p| p.key == key))
            .map(|p| p.value.clone())
    };
    assert_eq!(
        param("fs", "read-paths").as_deref(),
        Some("/research,/notes")
    );
    assert_eq!(param("fs", "write-paths").as_deref(), Some("/research"));
    assert_eq!(param("fs", "read"), None);
    assert_eq!(param("tools", "ids").as_deref(), Some("data,skill::agenda"));

    let nested = write_yaml("capabilities:\n  fs:\n    read: [[/a]]\n");
    assert!(matches!(
        StaticConfigCompiler::compile_from_path(nested.path(), "root-agent"),
        Err(CapGrantError::InvalidConfig(_))
    ));
}

// `data` is a retired family: the key is ignored instead of minting a grant nothing reads.
#[test]
fn a_retired_data_key_emits_no_grant() {
    let f = write_yaml("capabilities:\n  fs: true\n  data:\n    mode: \"read,write\"\n");
    let grants = StaticConfigCompiler::compile_from_path(f.path(), "root-agent").unwrap();
    let names: Vec<&str> = grants.iter().map(|g| g.capability.as_str()).collect();
    assert_eq!(names, vec!["fs"]);
}
