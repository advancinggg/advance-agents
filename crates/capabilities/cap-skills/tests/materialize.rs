//! Slice E — materialize_skill library tests (SE-15..SE-20 + SE-33).
//!
//! Includes the `RecordingStorage` mock used by SE-19 to lock the
//! sidecars-BEFORE-write_active write-order contract, and SE-33 for the
//! direct-call SkillSidecar boundary defense (Codex round-4 Critical fix).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cap_skills::persistence::{DiskSkillStorage, DraftBlob, SkillBlob, SkillSidecar, SkillStorage};
use cap_skills::{AdminPoolStorage, Provenance, SkillBundle, SkillError, TrustLevel};
use tempfile::TempDir;

fn make_full_bundle(name: &str) -> SkillBundle {
    SkillBundle::new(
        name.to_string(),
        "# full skill\n\nbody".to_string(),
        Some(vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
        Some(r#"{"caps":["fs.read"]}"#.to_string()),
        vec![
            ("intro.md".to_string(), "intro body".to_string()),
            ("deep.md".to_string(), "deep body".to_string()),
        ],
        vec![("setup.sh".to_string(), "#!/bin/sh\necho hi\n".to_string())],
        Provenance::Imported,
        TrustLevel::Untrusted,
    )
    .unwrap()
}

// ─── SE-15: materialize_skill happy path
#[tokio::test]
async fn se_15_materialize_happy_path() {
    let admin_dir = TempDir::new().unwrap();
    let agent_dir = TempDir::new().unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let bundle = SkillBundle::new(
        "happy".to_string(),
        "# happy body".to_string(),
        None,
        None,
        Vec::new(),
        Vec::new(),
        Provenance::Imported,
        TrustLevel::Untrusted,
    )
    .unwrap();
    admin.write_bundle(&bundle).await.unwrap();

    let to = DiskSkillStorage::with_default_writer(agent_dir.path().to_path_buf());
    cap_skills::materialize_skill("happy", &admin, &to)
        .await
        .unwrap();

    let active = to.read_active("happy").await.unwrap().unwrap();
    assert_eq!(active.content, "# happy body");
    assert_eq!(active.provenance, Provenance::Imported);
    assert_eq!(active.trust_level, TrustLevel::Untrusted);
}

// ─── SE-16: materialize_skill with full bundle copies all 5+ files
#[tokio::test]
async fn se_16_materialize_full_bundle() {
    let admin_dir = TempDir::new().unwrap();
    let agent_dir = TempDir::new().unwrap();

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    admin.write_bundle(&make_full_bundle("full")).await.unwrap();

    let to = DiskSkillStorage::with_default_writer(agent_dir.path().to_path_buf());
    cap_skills::materialize_skill("full", &admin, &to)
        .await
        .unwrap();

    let skill_dir = agent_dir.path().join(".agent/skills/full");
    let expected_files = [
        "SKILL.md",
        ".meta.yaml",
        "tool.wasm",
        "tool.capabilities.json",
        "templates/intro.md",
        "templates/deep.md",
        "source-scripts/setup.sh",
    ];
    for f in expected_files {
        let path = skill_dir.join(f);
        assert!(
            tokio::fs::try_exists(&path).await.unwrap(),
            "{f:?} should exist at agent-local path {path:?}"
        );
    }
}

// ─── SE-17: materialize_skill of nonexistent admin bundle → SkillNotFound
#[tokio::test]
async fn se_17_materialize_unknown_bundle_skill_not_found() {
    let admin_dir = TempDir::new().unwrap();
    let agent_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let to = DiskSkillStorage::with_default_writer(agent_dir.path().to_path_buf());

    let err = cap_skills::materialize_skill("missing", &admin, &to)
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::SkillNotFound(_)));

    // No agent-local active skill should have been written.
    let active = to.read_active("missing").await.unwrap();
    assert!(active.is_none());
}

// ─── SE-17a: materialize_skill bundle-sync — re-materializing a shrunk
// bundle removes stale sidecars (round-6 fix to the additive-not-sync gap).
#[tokio::test]
async fn se_17a_materialize_shrink_clears_stale_sidecars() {
    let admin_dir = TempDir::new().unwrap();
    let agent_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let to = DiskSkillStorage::with_default_writer(agent_dir.path().to_path_buf());

    // Step 1: materialize a full bundle with tool.wasm + templates + scripts.
    admin
        .write_bundle(&make_full_bundle("shrink-target"))
        .await
        .unwrap();
    cap_skills::materialize_skill("shrink-target", &admin, &to)
        .await
        .unwrap();

    let skill_dir = agent_dir.path().join(".agent/skills/shrink-target");
    for f in [
        "SKILL.md",
        "tool.wasm",
        "tool.capabilities.json",
        "templates/intro.md",
        "templates/deep.md",
        "source-scripts/setup.sh",
    ] {
        assert!(
            tokio::fs::try_exists(skill_dir.join(f)).await.unwrap(),
            "{f} should exist after full materialize"
        );
    }

    // Step 2: write a SHRUNK bundle (SKILL.md only, no sidecars) and
    // re-materialize. Stale sidecars MUST be cleared.
    let shrunk = SkillBundle::new(
        "shrink-target".to_string(),
        "# shrunk\nbody".to_string(),
        None,
        None,
        Vec::new(),
        Vec::new(),
        Provenance::Imported,
        TrustLevel::Untrusted,
    )
    .unwrap();
    admin.write_bundle(&shrunk).await.unwrap();
    cap_skills::materialize_skill("shrink-target", &admin, &to)
        .await
        .unwrap();

    // SKILL.md remains (overwritten by write_active).
    assert!(tokio::fs::try_exists(skill_dir.join("SKILL.md"))
        .await
        .unwrap());
    // Stale sidecar files must be GONE.
    for f in [
        "tool.wasm",
        "tool.capabilities.json",
        "templates/intro.md",
        "templates/deep.md",
        "source-scripts/setup.sh",
    ] {
        assert!(
            !tokio::fs::try_exists(skill_dir.join(f)).await.unwrap(),
            "stale {f} should be removed after shrink re-materialize"
        );
    }
}

// ─── SE-18: materialize_skill idempotent re-run
#[tokio::test]
async fn se_18_materialize_idempotent() {
    let admin_dir = TempDir::new().unwrap();
    let agent_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    admin.write_bundle(&make_full_bundle("idem")).await.unwrap();

    let to = DiskSkillStorage::with_default_writer(agent_dir.path().to_path_buf());
    cap_skills::materialize_skill("idem", &admin, &to)
        .await
        .unwrap();
    // Run a second time — must succeed with same content.
    cap_skills::materialize_skill("idem", &admin, &to)
        .await
        .unwrap();

    let active = to.read_active("idem").await.unwrap().unwrap();
    assert_eq!(active.content, "# full skill\n\nbody");
}

// ─── SE-19: materialize_skill write-ORDER assertion via RecordingStorage
//
// Asserts that EVERY write_skill_sidecar call appears BEFORE any
// write_active call in the mock's call log; when fail_at_sidecar is set,
// write_active is NEVER called after the sidecar failure.
#[tokio::test]
async fn se_19_materialize_write_order_via_recording_mock() {
    let admin_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    admin
        .write_bundle(&make_full_bundle("ordered"))
        .await
        .unwrap();

    // Pass 1: ordered success — all sidecars come before write_active.
    let mock = Arc::new(RecordingStorage::new(false));
    cap_skills::materialize_skill("ordered", &admin, mock.as_ref())
        .await
        .unwrap();
    let calls = mock.calls();
    let first_active = calls
        .iter()
        .position(|c| matches!(c, MockCall::WriteActive(_)));
    let last_sidecar = calls
        .iter()
        .rposition(|c| matches!(c, MockCall::WriteSidecar(_, _)));
    assert!(
        first_active.is_some() && last_sidecar.is_some(),
        "expected both kinds of calls"
    );
    assert!(
        last_sidecar.unwrap() < first_active.unwrap(),
        "expected ALL sidecar calls to appear BEFORE write_active; got call log: {calls:?}"
    );

    // Pass 2: fail_at_sidecar — write_active must NEVER be called.
    let mock = Arc::new(RecordingStorage::new(true));
    let err = cap_skills::materialize_skill("ordered", &admin, mock.as_ref())
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::InvalidTransition(_)));
    let calls = mock.calls();
    assert!(
        !calls.iter().any(|c| matches!(c, MockCall::WriteActive(_))),
        "write_active must not be called after sidecar failure; got: {calls:?}"
    );
}

// ─── SE-20: materialize_skill name-regex reject
#[tokio::test]
async fn se_20_materialize_name_regex_reject() {
    let admin_dir = TempDir::new().unwrap();
    let agent_dir = TempDir::new().unwrap();
    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());
    let to = DiskSkillStorage::with_default_writer(agent_dir.path().to_path_buf());

    let err = cap_skills::materialize_skill("../escape", &admin, &to)
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::InvalidName(_)));
}

// ─── SE-33: Direct-call DiskSkillStorage::write_skill_sidecar boundary defense
//
// A caller that bypasses SkillBundle::new constructor validation by
// invoking write_skill_sidecar directly with a path-traversal filename
// must be rejected at the storage boundary by validate_skill_filename.
#[tokio::test]
async fn se_33_write_skill_sidecar_direct_call_path_traversal_reject() {
    let agent_dir = TempDir::new().unwrap();
    let to = DiskSkillStorage::with_default_writer(agent_dir.path().to_path_buf());

    let err = to
        .write_skill_sidecar(
            "ok-id",
            SkillSidecar::Template("../escape.md".to_string()),
            b"body",
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::InvalidName(_)));

    // Also test InMemorySkillStorage override
    let mem = cap_skills::persistence::InMemorySkillStorage::new();
    let err = mem
        .write_skill_sidecar(
            "ok-id",
            SkillSidecar::SourceScript("foo/bar.sh".to_string()),
            b"body",
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::InvalidName(_)));
}

// ─────────────────────────────────────────────────────────────
// RecordingStorage mock (used by SE-19)
// ─────────────────────────────────────────────────────────────

#[derive(Debug)]
enum MockCall {
    WriteSidecar(String, SkillSidecar),
    WriteActive(String),
}

struct RecordingStorage {
    inner: Mutex<RecordingState>,
}

struct RecordingState {
    calls: Vec<MockCall>,
    active: HashMap<String, SkillBlob>,
    fail_at_sidecar: bool,
}

impl RecordingStorage {
    fn new(fail_at_sidecar: bool) -> Self {
        Self {
            inner: Mutex::new(RecordingState {
                calls: Vec::new(),
                active: HashMap::new(),
                fail_at_sidecar,
            }),
        }
    }

    fn calls(&self) -> Vec<MockCall> {
        // Drain doesn't help here since we use it after the call;
        // just clone the log conceptually by enumerating descriptive
        // strings. The Vec<MockCall> matches what we need for assertions.
        let guard = self.inner.lock().unwrap();
        // We can't clone MockCall directly (SkillSidecar doesn't derive
        // Clone). Re-build descriptive records for assertions.
        guard
            .calls
            .iter()
            .map(|c| match c {
                MockCall::WriteSidecar(s, k) => MockCall::WriteSidecar(s.clone(), k.clone()),
                MockCall::WriteActive(s) => MockCall::WriteActive(s.clone()),
            })
            .collect()
    }
}

#[async_trait]
impl SkillStorage for RecordingStorage {
    async fn read_draft(&self, _name: &str) -> Result<Option<DraftBlob>, SkillError> {
        Ok(None)
    }
    async fn write_draft(&self, _blob: &DraftBlob) -> Result<(), SkillError> {
        Ok(())
    }
    async fn delete_draft(&self, _name: &str) -> Result<(), SkillError> {
        Ok(())
    }
    async fn list_drafts(&self) -> Result<Vec<DraftBlob>, SkillError> {
        Ok(Vec::new())
    }

    async fn read_active(&self, skill_id: &str) -> Result<Option<SkillBlob>, SkillError> {
        Ok(self.inner.lock().unwrap().active.get(skill_id).cloned())
    }
    async fn write_active(&self, blob: &SkillBlob) -> Result<(), SkillError> {
        let mut guard = self.inner.lock().unwrap();
        guard
            .calls
            .push(MockCall::WriteActive(blob.skill_id.clone()));
        guard.active.insert(blob.skill_id.clone(), blob.clone());
        Ok(())
    }
    async fn delete_active(&self, _skill_id: &str) -> Result<(), SkillError> {
        Ok(())
    }
    async fn list_active(&self) -> Result<Vec<SkillBlob>, SkillError> {
        Ok(Vec::new())
    }

    async fn read_version(
        &self,
        _skill_id: &str,
        _version: u32,
    ) -> Result<Option<String>, SkillError> {
        Ok(None)
    }
    async fn write_version(
        &self,
        _skill_id: &str,
        _version: u32,
        _content: &str,
    ) -> Result<(), SkillError> {
        Ok(())
    }
    async fn list_versions(&self, _skill_id: &str) -> Result<Vec<u32>, SkillError> {
        Ok(Vec::new())
    }

    async fn write_skill_sidecar(
        &self,
        skill_id: &str,
        kind: SkillSidecar,
        _bytes: &[u8],
    ) -> Result<(), SkillError> {
        let mut guard = self.inner.lock().unwrap();
        let fail = guard.fail_at_sidecar;
        guard
            .calls
            .push(MockCall::WriteSidecar(skill_id.to_string(), kind));
        if fail {
            return Err(SkillError::InvalidTransition(
                "RecordingStorage: forced sidecar failure".to_string(),
            ));
        }
        Ok(())
    }
}
