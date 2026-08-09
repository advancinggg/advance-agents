use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::SkillError;
use crate::lifecycle::{CandidateAction, CandidateResult, Draft, Skill, SkillStore};
use crate::persistence::DraftBlob;
use crate::security_scan;
use crate::turn_persistence::{PendingSkillOp, SkillTurnPersistenceDriver, TurnSkillOp};

const MAX_CONTENT_LEN: usize = 50_000;
const MAX_NAME_LEN: usize = 256;
const MAX_TAG_LEN: usize = 128;
const MAX_TAGS: usize = 32;
const MAX_REASON_LEN: usize = 1024;
const LEASE_DIR: &str = "_skill_turn_leases";
const PRECONDITION_MISMATCH: &str = "turn journal precondition mismatch";
/// Bounded reconcile replay (2026-07-03, §3.6 (ccc) closure): a lease whose
/// replay fails deterministically (non-precondition error — e.g. a persistent
/// coordinator fault) is retried at most this many times across begin_turn
/// reconciles, then PARKED (`.parked` + `.error.txt`, nothing deleted) so the
/// agent's message lane can never be wedged forever by one bad lease.
const MAX_RECONCILE_ATTEMPTS: u32 = 3;

fn truncate_string(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s
}

fn truncate_tags(tags: Vec<String>) -> Vec<String> {
    tags.into_iter()
        .take(MAX_TAGS)
        .map(|tag| truncate_string(tag, MAX_TAG_LEN))
        .collect()
}

fn stable_hash(parts: &[&str]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for part in parts {
        for byte in part.as_bytes().iter().copied().chain([0xff]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{hash:016x}")
}

fn draft_hash(draft: &Draft) -> String {
    let tags = draft.tags.join("\u{1f}");
    let parent = draft.parent.as_deref().unwrap_or("");
    let reason = draft.reason.as_deref().unwrap_or("");
    stable_hash(&["draft", &draft.name, &draft.content, &tags, parent, reason])
}

fn draft_blob_hash(draft: &DraftBlob) -> String {
    let tags = draft.tags.join("\u{1f}");
    let parent = draft.parent.as_deref().unwrap_or("");
    let reason = draft.reason.as_deref().unwrap_or("");
    stable_hash(&["draft", &draft.name, &draft.content, &tags, parent, reason])
}

fn skill_hash(skill: &Skill) -> String {
    let tags = skill.tags.join("\u{1f}");
    let version = skill.version.to_string();
    let provenance = format!("{:?}", skill.provenance);
    let trust_level = format!("{:?}", skill.trust_level);
    stable_hash(&[
        "active",
        &skill.skill_id,
        &version,
        &skill.content,
        &tags,
        &provenance,
        &trust_level,
    ])
}

#[async_trait]
pub trait SkillHealthFlush: Send + Sync {
    async fn flush(&self, agent_id: &str, lease_id: &str) -> Result<(), SkillError>;
}

pub struct NoopSkillHealthFlush;

#[async_trait]
impl SkillHealthFlush for NoopSkillHealthFlush {
    async fn flush(&self, _agent_id: &str, _lease_id: &str) -> Result<(), SkillError> {
        Ok(())
    }
}

pub struct CapMemorySkillHealthFlush {
    writer: cap_memory::SkillHealthWriter,
}

impl CapMemorySkillHealthFlush {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            writer: cap_memory::SkillHealthWriter::in_dir(root),
        }
    }
}

#[async_trait]
impl SkillHealthFlush for CapMemorySkillHealthFlush {
    async fn flush(&self, agent_id: &str, lease_id: &str) -> Result<(), SkillError> {
        let writer = self.writer.clone();
        let agent_id = agent_id.to_string();
        let lease_id = lease_id.to_string();
        tokio::task::spawn_blocking(move || {
            let entries = match std::fs::read_to_string(writer.path()) {
                Ok(yaml) => serde_yml::from_str::<cap_memory::SkillHealthFile>(&yaml)
                    .map_err(|e| {
                        cap_memory::SkillHealthWriteError::Serialize(format!(
                            "parse existing skill health yaml: {e}"
                        ))
                    })?
                    .entries
                    .into_iter()
                    .map(|entry| cap_memory::l6::SkillHealthEntry {
                        skill: entry.skill,
                        status: entry.status,
                    })
                    .collect::<Vec<_>>(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(cap_memory::SkillHealthWriteError::Io(e)),
            };
            writer.write(&agent_id, &lease_id, Utc::now().to_rfc3339(), &entries)
        })
        .await
        .map_err(|e| SkillError::InvalidTransition(format!("skill health task: {e}")))?
        .map_err(|e| SkillError::InvalidTransition(format!("skill health flush: {e}")))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum RuntimeEventKind {
    DraftCreated,
    DraftUpdated,
    CandidateResolved,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    #[default]
    Staged,
    RuntimePrivateFlushed,
    RuntimeEventsEmitted,
    GitComplete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RuntimeEventRecord {
    kind: RuntimeEventKind,
    skill_name: Option<String>,
    candidate_id: Option<String>,
    draft_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum StagedCandidateResolution {
    Accept { candidate_id: String },
    Dismiss { candidate_id: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum JournalOp {
    Activate {
        draft_id: String,
        reason: String,
    },
    Rollback {
        skill_id: String,
        version: u32,
        reason: String,
    },
    Delete {
        skill_id: String,
        reason: String,
    },
}

impl From<JournalOp> for TurnSkillOp {
    fn from(op: JournalOp) -> Self {
        match op {
            JournalOp::Activate { draft_id, reason } => TurnSkillOp::Activate { draft_id, reason },
            JournalOp::Rollback {
                skill_id,
                version,
                reason,
            } => TurnSkillOp::Rollback {
                skill_id,
                version,
                reason,
            },
            JournalOp::Delete { skill_id, reason } => TurnSkillOp::Delete { skill_id, reason },
        }
    }
}

impl From<TurnSkillOp> for JournalOp {
    fn from(op: TurnSkillOp) -> Self {
        match op {
            TurnSkillOp::Activate { draft_id, reason } => JournalOp::Activate { draft_id, reason },
            TurnSkillOp::Rollback {
                skill_id,
                version,
                reason,
            } => JournalOp::Rollback {
                skill_id,
                version,
                reason,
            },
            TurnSkillOp::Delete { skill_id, reason } => JournalOp::Delete { skill_id, reason },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct JournalActiveState {
    exists: bool,
    version: Option<u32>,
    content_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct JournalDraftState {
    exists: bool,
    content_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum JournalOpPrecondition {
    Activate {
        active: JournalActiveState,
        draft: JournalDraftState,
    },
    Rollback {
        active: JournalActiveState,
    },
    Delete {
        active: JournalActiveState,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JournalOpRecord {
    #[serde(default)]
    op_id: String,
    op: JournalOp,
    #[serde(default)]
    precondition: Option<JournalOpPrecondition>,
    #[serde(default)]
    requeue_count: u32,
}

impl JournalOpRecord {
    fn new(op: JournalOp, precondition: JournalOpPrecondition) -> Self {
        Self {
            op_id: Uuid::new_v4().to_string(),
            op,
            precondition: Some(precondition),
            requeue_count: 0,
        }
    }
}

impl From<JournalOpRecord> for PendingSkillOp {
    fn from(record: JournalOpRecord) -> Self {
        Self {
            op: TurnSkillOp::from(record.op),
            requeue_count: record.requeue_count,
        }
    }
}

impl From<PendingSkillOp> for JournalOpRecord {
    fn from(pending: PendingSkillOp) -> Self {
        Self {
            op_id: Uuid::new_v4().to_string(),
            op: JournalOp::from(pending.op),
            precondition: None,
            requeue_count: pending.requeue_count,
        }
    }
}

fn retry_record_from_pending(
    pending: PendingSkillOp,
    source_ops: &[JournalOpRecord],
) -> JournalOpRecord {
    let op = JournalOp::from(pending.op.clone());
    let mut record = source_ops
        .iter()
        .find(|record| TurnSkillOp::from(record.op.clone()) == pending.op)
        .cloned()
        .unwrap_or_else(|| JournalOpRecord::from(pending.clone()));
    record.op = op;
    record.requeue_count = pending.requeue_count;
    record
}

fn precondition_mismatch(record: &JournalOpRecord, reason: &str) -> SkillError {
    SkillError::InvalidTransition(format!(
        "{PRECONDITION_MISMATCH}: op_id={} {reason}",
        record.op_id
    ))
}

fn is_precondition_mismatch(error: &SkillError) -> bool {
    matches!(error, SkillError::InvalidTransition(msg) if msg.starts_with(PRECONDITION_MISMATCH))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TurnJournal {
    agent_id: String,
    lease_id: String,
    #[serde(default)]
    phase: JournalPhase,
    #[serde(default)]
    emitted_runtime_event_count: usize,
    /// How many begin_turn reconciles have replayed this lease (persisted
    /// BEFORE each replay so a crash mid-replay still advances the bound).
    /// Parked at `MAX_RECONCILE_ATTEMPTS`. `#[serde(default)]` keeps old
    /// on-disk leases parseable.
    #[serde(default)]
    reconcile_attempts: u32,
    drafts: Vec<DraftBlob>,
    candidate_resolutions: Vec<StagedCandidateResolution>,
    runtime_events: Vec<RuntimeEventRecord>,
    ops: Vec<JournalOpRecord>,
}

#[derive(Clone, Debug)]
struct ActiveTurn {
    journal: TurnJournal,
    path: PathBuf,
}

struct RuntimeState {
    active: Option<ActiveTurn>,
}

pub struct SkillTurnRuntime {
    agent_id: String,
    agent_root: PathBuf,
    skill_store: Arc<Mutex<SkillStore>>,
    driver: Arc<Mutex<SkillTurnPersistenceDriver>>,
    event_bus: Arc<dyn EventBusEmit>,
    health_flush: Arc<dyn SkillHealthFlush>,
    candidate_dir: PathBuf,
    state: Mutex<RuntimeState>,
}

impl SkillTurnRuntime {
    pub fn new(
        agent_id: impl Into<String>,
        agent_root: impl Into<PathBuf>,
        skill_store: Arc<Mutex<SkillStore>>,
        driver: SkillTurnPersistenceDriver,
        event_bus: Arc<dyn EventBusEmit>,
        health_flush: Arc<dyn SkillHealthFlush>,
        candidate_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            agent_root: agent_root.into(),
            skill_store,
            driver: Arc::new(Mutex::new(driver)),
            event_bus,
            health_flush,
            candidate_dir: candidate_dir.into(),
            state: Mutex::new(RuntimeState { active: None }),
        }
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub async fn is_active_for(&self, agent_id: &str) -> bool {
        agent_id == self.agent_id && self.state.lock().await.active.is_some()
    }

    pub async fn begin_turn(&self) -> Result<String, SkillError> {
        // Serialize the WHOLE begin (idempotent-return + reconcile + lease
        // creation) under the state lock (adversarial 2026-07-03 W2):
        // reconcile now mutates on-disk lease state (attempt counters, parks,
        // replays) and is not idempotent under same-runtime concurrency — two
        // interleaved begins could double-replay an op (double commit/emit).
        // Checking `active` FIRST also keeps an in-flight turn's own lease out
        // of reconcile's replay scan. Lock order: state → (inside reconcile)
        // driver; no path acquires state while holding driver, so no
        // inversion. Cross-INSTANCE concurrency over one lease dir remains
        // excluded by the per-agent single-controller runtime (§3.6 (aaa)).
        let mut state = self.state.lock().await;
        if let Some(active) = &state.active {
            return Ok(active.journal.lease_id.clone());
        }
        self.reconcile_unfinished().await?;
        let lease_id = Uuid::new_v4().to_string();
        let path = self.lease_path(&lease_id);
        let active = ActiveTurn {
            journal: TurnJournal {
                agent_id: self.agent_id.clone(),
                lease_id: lease_id.clone(),
                phase: JournalPhase::Staged,
                emitted_runtime_event_count: 0,
                reconcile_attempts: 0,
                drafts: Vec::new(),
                candidate_resolutions: Vec::new(),
                runtime_events: Vec::new(),
                ops: Vec::new(),
            },
            path,
        };
        self.persist_journal(&active).await?;
        state.active = Some(active);
        Ok(lease_id)
    }

    pub async fn abort_turn(&self, lease_id: &str) {
        let active = {
            let mut state = self.state.lock().await;
            match state.active.take() {
                Some(active) if active.journal.lease_id == lease_id => active,
                other => {
                    state.active = other;
                    return;
                }
            }
        };
        let _ = tokio::fs::remove_file(active.path).await;
    }

    pub async fn finish_turn(&self, lease_id: &str) -> Result<(), SkillError> {
        let active = {
            let mut state = self.state.lock().await;
            match state.active.take() {
                Some(active) if active.journal.lease_id == lease_id => active,
                Some(active) => {
                    state.active = Some(active);
                    return Err(SkillError::InvalidTransition(
                        "turn persistence lease mismatch".to_string(),
                    ));
                }
                None => return Ok(()),
            }
        };
        let mut journal = active.journal;
        let path = active.path;
        let result = self.finish_journal(&path, &mut journal).await;
        match result {
            Ok(()) => {
                let _ = tokio::fs::remove_file(path).await;
                Ok(())
            }
            Err(e) if is_precondition_mismatch(&e) => {
                self.park_lease(&path, &e).await?;
                Err(e)
            }
            Err(e) => {
                drop(journal);
                drop(path);
                Err(e)
            }
        }
    }

    pub async fn stage_propose_draft(
        &self,
        name: String,
        content: String,
        tags: Vec<String>,
    ) -> Result<String, SkillError> {
        security_scan::validate_skill_name(&name)?;
        if content.len() > MAX_CONTENT_LEN {
            return Err(SkillError::ContentTooLarge(content.len()));
        }
        let name = truncate_string(name, MAX_NAME_LEN);
        let blob = DraftBlob {
            name: name.clone(),
            content,
            tags: truncate_tags(tags),
            parent: None,
            reason: None,
            created_at: Utc::now(),
        };
        self.stage_draft(blob, RuntimeEventKind::DraftCreated)
            .await?;
        Ok(name)
    }

    pub async fn stage_propose_patch(
        &self,
        skill_id: &str,
        content: String,
        reason: String,
    ) -> Result<String, SkillError> {
        security_scan::validate_skill_name(skill_id)?;
        if content.len() > MAX_CONTENT_LEN {
            return Err(SkillError::ContentTooLarge(content.len()));
        }
        let active = {
            let store = self.skill_store.lock().await;
            store.get(skill_id).await?
        };
        let blob = DraftBlob {
            name: active.skill_id.clone(),
            content,
            tags: active.tags,
            parent: Some(skill_id.to_string()),
            reason: Some(truncate_string(reason, MAX_REASON_LEN)),
            created_at: Utc::now(),
        };
        let draft_id = blob.name.clone();
        self.stage_draft(blob, RuntimeEventKind::DraftCreated)
            .await?;
        Ok(draft_id)
    }

    pub async fn stage_update_draft(
        &self,
        draft_id: &str,
        content: String,
    ) -> Result<(), SkillError> {
        security_scan::validate_skill_name(draft_id)?;
        if content.len() > MAX_CONTENT_LEN {
            return Err(SkillError::ContentTooLarge(content.len()));
        }
        let mut blob = {
            let state = self.state.lock().await;
            state.active.as_ref().and_then(|active| {
                active
                    .journal
                    .drafts
                    .iter()
                    .rev()
                    .find(|draft| draft.name == draft_id)
                    .cloned()
            })
        };
        if blob.is_none() {
            let store = self.skill_store.lock().await;
            blob = store.snapshot_live(draft_id).await?.draft;
        }
        let mut blob = blob.ok_or_else(|| SkillError::DraftNotFound(draft_id.to_string()))?;
        blob.content = content;
        self.stage_draft(blob, RuntimeEventKind::DraftUpdated).await
    }

    pub async fn stage_activate(&self, draft_id: String) -> Result<String, SkillError> {
        security_scan::validate_skill_name(&draft_id)?;
        self.stage_op(JournalOp::Activate {
            draft_id: draft_id.clone(),
            reason: String::new(),
        })
        .await?;
        Ok(draft_id)
    }

    pub async fn stage_rollback(&self, skill_id: String, version: u32) -> Result<(), SkillError> {
        security_scan::validate_skill_name(&skill_id)?;
        self.stage_op(JournalOp::Rollback {
            skill_id,
            version,
            reason: String::new(),
        })
        .await
    }

    pub async fn stage_delete(&self, skill_id: String) -> Result<(), SkillError> {
        security_scan::validate_skill_name(&skill_id)?;
        self.stage_op(JournalOp::Delete {
            skill_id,
            reason: String::new(),
        })
        .await
    }

    pub async fn stage_resolve_candidate(
        &self,
        candidate_id: &str,
        action: CandidateAction,
    ) -> Result<CandidateResult, SkillError> {
        if candidate_id.len() > 128 {
            return Err(SkillError::SkillNotFound("candidate not found".to_string()));
        }
        let dir = self.candidate_dir.clone();
        let candidate_id_owned = candidate_id.to_string();
        let pending = tokio::task::spawn_blocking(move || {
            cap_memory::SkillCandidateStore::in_dir(&dir).list_pending()
        })
        .await
        .map_err(|e| SkillError::InvalidTransition(format!("skill candidate task: {e}")))?
        .map_err(|e| SkillError::InvalidTransition(format!("skill candidate read: {e}")))?;
        let candidate = pending
            .into_iter()
            .find(|candidate| candidate.candidate_id == candidate_id_owned)
            .ok_or_else(|| SkillError::SkillNotFound("candidate not found".to_string()))?;

        let draft_id = match action {
            CandidateAction::Accept => {
                security_scan::validate_skill_name(&candidate.name)?;
                let content = format!(
                    "---\nname: {name}\ndescription: L6-proposed skill candidate\n---\n\n# {name}\n\n{desc}\n\n<!-- Auto-scaffolded from an L6 skill candidate; edit, then activate. -->\n",
                    name = candidate.name,
                    desc = candidate.description
                );
                let blob = DraftBlob {
                    name: candidate.name.clone(),
                    content,
                    tags: Vec::new(),
                    parent: None,
                    reason: None,
                    created_at: Utc::now(),
                };
                let draft_id = blob.name.clone();
                self.stage_draft(blob, RuntimeEventKind::DraftCreated)
                    .await?;
                draft_id
            }
            CandidateAction::Dismiss => String::new(),
        };

        self.stage_candidate_resolution(match action {
            CandidateAction::Accept => StagedCandidateResolution::Accept {
                candidate_id: candidate_id.to_string(),
            },
            CandidateAction::Dismiss => StagedCandidateResolution::Dismiss {
                candidate_id: candidate_id.to_string(),
            },
        })
        .await?;
        self.stage_runtime_event(RuntimeEventRecord {
            kind: RuntimeEventKind::CandidateResolved,
            skill_name: None,
            candidate_id: Some(candidate_id.to_string()),
            draft_id: Some(draft_id.clone()),
        })
        .await?;
        Ok(CandidateResult {
            candidate_id: candidate_id.to_string(),
            draft_id,
        })
    }

    async fn stage_draft(
        &self,
        blob: DraftBlob,
        event_kind: RuntimeEventKind,
    ) -> Result<(), SkillError> {
        let mut state = self.state.lock().await;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| SkillError::InvalidTransition("no active skill turn".to_string()))?;
        active.journal.runtime_events.push(RuntimeEventRecord {
            kind: event_kind,
            skill_name: Some(blob.name.clone()),
            candidate_id: None,
            draft_id: Some(blob.name.clone()),
        });
        active.journal.drafts.push(blob);
        self.persist_journal(active).await
    }

    async fn stage_candidate_resolution(
        &self,
        resolution: StagedCandidateResolution,
    ) -> Result<(), SkillError> {
        let mut state = self.state.lock().await;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| SkillError::InvalidTransition("no active skill turn".to_string()))?;
        active.journal.candidate_resolutions.push(resolution);
        self.persist_journal(active).await
    }

    async fn stage_runtime_event(&self, event: RuntimeEventRecord) -> Result<(), SkillError> {
        let mut state = self.state.lock().await;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| SkillError::InvalidTransition("no active skill turn".to_string()))?;
        active.journal.runtime_events.push(event);
        self.persist_journal(active).await
    }

    async fn stage_op(&self, op: JournalOp) -> Result<(), SkillError> {
        let drafts = {
            let state = self.state.lock().await;
            state
                .active
                .as_ref()
                .ok_or_else(|| SkillError::InvalidTransition("no active skill turn".to_string()))?
                .journal
                .drafts
                .clone()
        };
        let precondition = self.build_op_precondition(&op, &drafts).await?;
        let mut state = self.state.lock().await;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| SkillError::InvalidTransition("no active skill turn".to_string()))?;
        active
            .journal
            .ops
            .push(JournalOpRecord::new(op, precondition));
        self.persist_journal(active).await
    }

    async fn build_op_precondition(
        &self,
        op: &JournalOp,
        staged_drafts: &[DraftBlob],
    ) -> Result<JournalOpPrecondition, SkillError> {
        match op {
            JournalOp::Activate { draft_id, .. } => Ok(JournalOpPrecondition::Activate {
                active: self.active_state(draft_id).await?,
                draft: self.draft_state(draft_id, staged_drafts).await?,
            }),
            JournalOp::Rollback { skill_id, .. } => Ok(JournalOpPrecondition::Rollback {
                active: self.active_state(skill_id).await?,
            }),
            JournalOp::Delete { skill_id, .. } => Ok(JournalOpPrecondition::Delete {
                active: self.active_state(skill_id).await?,
            }),
        }
    }

    async fn validate_op_preconditions(
        &self,
        records: &[JournalOpRecord],
    ) -> Result<(), SkillError> {
        for record in records {
            let expected = record
                .precondition
                .as_ref()
                .ok_or_else(|| precondition_mismatch(record, "missing op precondition"))?;
            let current = match &record.op {
                JournalOp::Activate { draft_id, .. } => JournalOpPrecondition::Activate {
                    active: self.active_state(draft_id).await?,
                    draft: self.draft_state(draft_id, &[]).await?,
                },
                JournalOp::Rollback { skill_id, .. } => JournalOpPrecondition::Rollback {
                    active: self.active_state(skill_id).await?,
                },
                JournalOp::Delete { skill_id, .. } => JournalOpPrecondition::Delete {
                    active: self.active_state(skill_id).await?,
                },
            };
            if &current != expected {
                return Err(precondition_mismatch(
                    record,
                    "live state no longer matches the staged turn",
                ));
            }
        }
        Ok(())
    }

    async fn active_state(&self, skill_id: &str) -> Result<JournalActiveState, SkillError> {
        let store = self.skill_store.lock().await;
        match store.get(skill_id).await {
            Ok(skill) => Ok(JournalActiveState {
                exists: true,
                version: Some(skill.version),
                content_hash: Some(skill_hash(&skill)),
            }),
            Err(SkillError::SkillNotFound(_)) => Ok(JournalActiveState {
                exists: false,
                version: None,
                content_hash: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn draft_state(
        &self,
        draft_id: &str,
        staged_drafts: &[DraftBlob],
    ) -> Result<JournalDraftState, SkillError> {
        if let Some(draft) = staged_drafts
            .iter()
            .rev()
            .find(|draft| draft.name == draft_id)
        {
            return Ok(JournalDraftState {
                exists: true,
                content_hash: Some(draft_blob_hash(draft)),
            });
        }
        let store = self.skill_store.lock().await;
        match store.get_draft(draft_id).await? {
            Some(draft) => Ok(JournalDraftState {
                exists: true,
                content_hash: Some(draft_hash(&draft)),
            }),
            None => Ok(JournalDraftState {
                exists: false,
                content_hash: None,
            }),
        }
    }

    async fn finish_journal(
        &self,
        path: &Path,
        journal: &mut TurnJournal,
    ) -> Result<(), SkillError> {
        if journal.phase < JournalPhase::RuntimePrivateFlushed {
            self.flush_runtime_private_with_retry(journal).await?;
            journal.phase = JournalPhase::RuntimePrivateFlushed;
            self.persist_journal_file(path, journal).await?;
        }
        if journal.phase < JournalPhase::RuntimeEventsEmitted {
            while journal.emitted_runtime_event_count < journal.runtime_events.len() {
                let index = journal.emitted_runtime_event_count;
                let event = journal.runtime_events[index].clone();
                self.emit_runtime_event(journal, index, &event);
                journal.emitted_runtime_event_count += 1;
                self.persist_journal_file(path, journal).await?;
            }
            journal.phase = JournalPhase::RuntimeEventsEmitted;
            self.persist_journal_file(path, journal).await?;
        }
        self.validate_op_preconditions(&journal.ops).await?;
        let ops: Vec<PendingSkillOp> = journal
            .ops
            .clone()
            .into_iter()
            .map(PendingSkillOp::from)
            .collect();
        let mut driver = self.driver.lock().await;
        let result = driver.run_pending_turn_persistence(ops).await;
        let pending = if !driver.pending().is_empty() {
            Some(driver.pending().to_vec())
        } else {
            None
        };
        drop(driver);
        if let Some(pending) = pending {
            if result.is_ok() {
                // Commit-failure re-enqueues from an otherwise-Ok turn become a
                // DURABLE retry journal (preconditions re-stamped from the
                // source ops). The in-memory copy is cleared even if the
                // persist itself fails — keeping a second in-memory copy would
                // later replay WITHOUT preconditions (2026-07-03, §3.6 (ccc)
                // closure: single-track durable retry). On that persist
                // failure the ORIGINAL lease file remains on disk; NOTE its
                // replay is precondition-gated ALL-or-nothing, so in a
                // multi-op turn where a sibling op already committed, the next
                // reconcile PARKS the whole lease (committed sibling = stale
                // precondition) rather than retrying the pending op —
                // quarantine-with-evidence, not silent loss (adversarial
                // 2026-07-03 W1, disclosed in §3.6 (ccc)).
                let persisted = self
                    .persist_retry_journal(&journal.agent_id, pending, &journal.ops)
                    .await;
                self.driver.lock().await.take_pending();
                persisted?;
            } else {
                // Err turn: the lease file stays on disk and the next
                // begin_turn reconcile replays it precondition-gated (parking
                // on mismatch). The in-memory pending is a precondition-LESS
                // copy of ops recorded in that journal — discard it so nothing
                // can replay outside the durable, precondition-gated track.
                // NOTE (adversarial 2026-07-03 W1): for a multi-op turn whose
                // fault struck AFTER a sibling op committed, that replay PARKS
                // the whole lease at the committed sibling's stale
                // precondition — the not-yet-run ops are quarantined with the
                // lease (evidence preserved), not auto-retried. Distinguishing
                // committed-by-us from clobbered-by-other needs per-op
                // completion markers in the journal — future work, §3.6 (ccc).
                self.driver.lock().await.take_pending();
            }
        }
        if result.is_ok() {
            journal.phase = JournalPhase::GitComplete;
            self.persist_journal_file(path, journal).await?;
        }
        result
    }

    async fn persist_retry_journal(
        &self,
        agent_id: &str,
        pending: Vec<PendingSkillOp>,
        source_ops: &[JournalOpRecord],
    ) -> Result<(), SkillError> {
        let lease_id = Uuid::new_v4().to_string();
        let active = ActiveTurn {
            path: self.lease_path(&lease_id),
            journal: TurnJournal {
                agent_id: agent_id.to_string(),
                lease_id,
                phase: JournalPhase::Staged,
                emitted_runtime_event_count: 0,
                reconcile_attempts: 0,
                drafts: Vec::new(),
                candidate_resolutions: Vec::new(),
                runtime_events: Vec::new(),
                ops: pending
                    .into_iter()
                    .map(|pending| retry_record_from_pending(pending, source_ops))
                    .collect(),
            },
        };
        self.persist_journal(&active).await
    }

    async fn flush_runtime_private_with_retry(
        &self,
        journal: &TurnJournal,
    ) -> Result<(), SkillError> {
        match self.flush_runtime_private(journal).await {
            Ok(()) => Ok(()),
            Err(first) => {
                eprintln!("cap-skills turn runtime flush failed once, retrying: {first}");
                self.flush_runtime_private(journal).await.map_err(|second| {
                    eprintln!("cap-skills turn runtime flush retry failed: {second}");
                    SkillError::InvalidTransition(
                        "runtime-private flush failed after retry".to_string(),
                    )
                })
            }
        }
    }

    async fn flush_runtime_private(&self, journal: &TurnJournal) -> Result<(), SkillError> {
        {
            let store = self.skill_store.lock().await;
            for draft in &journal.drafts {
                store.flush_draft(draft).await?;
            }
        }
        for resolution in &journal.candidate_resolutions {
            self.flush_candidate_resolution(resolution).await?;
        }
        self.health_flush
            .flush(&journal.agent_id, &journal.lease_id)
            .await
    }

    async fn flush_candidate_resolution(
        &self,
        resolution: &StagedCandidateResolution,
    ) -> Result<(), SkillError> {
        let dir = self.candidate_dir.clone();
        let (candidate_id, res) = match resolution {
            StagedCandidateResolution::Accept { candidate_id } => {
                (candidate_id.clone(), cap_memory::Resolution::Accept)
            }
            StagedCandidateResolution::Dismiss { candidate_id } => {
                (candidate_id.clone(), cap_memory::Resolution::Dismiss)
            }
        };
        let result = tokio::task::spawn_blocking(move || {
            cap_memory::SkillCandidateStore::in_dir(&dir).resolve(&candidate_id, res)
        })
        .await
        .map_err(|e| SkillError::InvalidTransition(format!("skill candidate task: {e}")))?;
        match result {
            Ok(()) | Err(cap_memory::SkillCandidateError::AlreadyResolved(_)) => Ok(()),
            Err(cap_memory::SkillCandidateError::NotFound(_)) => {
                Err(SkillError::SkillNotFound("candidate not found".to_string()))
            }
            Err(other) => Err(SkillError::InvalidTransition(format!(
                "skill candidate resolve: {other}"
            ))),
        }
    }

    async fn reconcile_unfinished(&self) -> Result<(), SkillError> {
        let dir = self.lease_dir();
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(SkillError::InvalidTransition(format!(
                    "read skill lease dir: {e}"
                )))
            }
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read skill lease entry: {e}")))?
        {
            let path = entry.path();
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("json") => {}
                // Stale atomic-write temp (crash between create and rename in
                // persist_journal_file): the rename never happened, so the
                // `.json` beside it is still the last committed version and the
                // tmp is garbage. Best-effort sweep.
                Some("tmp") => {
                    let _ = tokio::fs::remove_file(&path).await;
                    continue;
                }
                _ => continue,
            }
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("read skill lease: {e}")))?;
            // A corrupt/torn journal must QUARANTINE, not hard-error (2026-07-03,
            // §3.6 (ccc) closure): a hard Err here would fail every future
            // begin_turn — the scheduler consumes the inbound message on a
            // begin_turn error, so one bad file would brick the agent's message
            // lane with exactly the crash this feature exists to recover from.
            let journal: TurnJournal = match serde_json::from_slice(&bytes) {
                Ok(journal) => journal,
                Err(e) => {
                    self.park_lease(
                        &path,
                        &SkillError::InvalidTransition(format!("parse skill lease: {e}")),
                    )
                    .await?;
                    continue;
                }
            };
            if journal.agent_id != self.agent_id {
                continue;
            }
            let mut journal = journal;
            // Bounded replay: persist the incremented attempt count BEFORE the
            // replay so a crash mid-replay still advances the bound; past the
            // bound the lease parks (preserved on disk + error file) instead of
            // failing begin_turn forever on a deterministic replay error.
            journal.reconcile_attempts += 1;
            if journal.reconcile_attempts > MAX_RECONCILE_ATTEMPTS {
                let err = SkillError::InvalidTransition(format!(
                    "skill lease {} exceeded {MAX_RECONCILE_ATTEMPTS} reconcile attempts",
                    journal.lease_id
                ));
                self.park_lease(&path, &err).await?;
                return Err(err);
            }
            self.persist_journal_file(&path, &journal).await?;
            match self.finish_journal(&path, &mut journal).await {
                Ok(()) => {
                    let _ = tokio::fs::remove_file(path).await;
                }
                Err(e) if is_precondition_mismatch(&e) => {
                    self.park_lease(&path, &e).await?;
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn park_lease(&self, path: &Path, error: &SkillError) -> Result<(), SkillError> {
        let parked = path.with_extension("parked");
        let err_path = path.with_extension("error.txt");
        tokio::fs::write(&err_path, error.to_string())
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("write parked lease error: {e}")))?;
        tokio::fs::rename(path, parked)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("park skill lease: {e}")))
    }

    fn emit_runtime_event(&self, journal: &TurnJournal, index: usize, record: &RuntimeEventRecord) {
        let event_type = match record.kind {
            RuntimeEventKind::DraftCreated => "skill.draft_created",
            RuntimeEventKind::DraftUpdated => "skill.draft_updated",
            RuntimeEventKind::CandidateResolved => "skill.candidate_resolved",
        };
        let payload = serde_json::json!({
            "agent_id": journal.agent_id,
            "lease_id": journal.lease_id,
            "skill_name": record.skill_name,
            "candidate_id": record.candidate_id,
            "draft_id": record.draft_id,
        });
        self.event_bus.emit(Event {
            id: format!("skill-runtime:{}:{index}", journal.lease_id),
            timestamp: Utc::now(),
            agent_id: journal.agent_id.clone(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            event_type: event_type.to_string(),
            payload,
            duration_ms: None,
        });
    }

    fn lease_dir(&self) -> PathBuf {
        self.agent_root.join(".agent").join(LEASE_DIR)
    }

    fn lease_path(&self, lease_id: &str) -> PathBuf {
        self.lease_dir().join(format!("{lease_id}.json"))
    }

    async fn persist_journal(&self, active: &ActiveTurn) -> Result<(), SkillError> {
        self.persist_journal_file(&active.path, &active.journal)
            .await
    }

    async fn persist_journal_file(
        &self,
        path: &Path,
        journal: &TurnJournal,
    ) -> Result<(), SkillError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("create lease dir: {e}")))?;
        }
        let bytes = serde_json::to_vec_pretty(journal)
            .map_err(|e| SkillError::InvalidTransition(format!("serialize lease: {e}")))?;
        // Never-torn write (2026-07-03, §3.6 (ccc) closure): the journal is
        // written on EVERY staging call and at every phase transition, and
        // reconcile_unfinished parses every `.json` in the lease dir on every
        // begin_turn — a torn write must never be observable as a corrupt
        // journal. tmp + fsync + same-dir rename; a crash leaves either the
        // old journal or the new one, never a torn file (the stale `.tmp` is
        // swept by reconcile). The DIRECTORY is not fsynced, so a power loss
        // may retain the previous journal — which replays idempotently; the
        // guarantee here is never-torn, not latest-write durability.
        let tmp = path.with_extension("json.tmp");
        {
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("create lease tmp: {e}")))?;
            file.write_all(&bytes)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("write lease tmp: {e}")))?;
            file.sync_all()
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("sync lease tmp: {e}")))?;
        }
        tokio::fs::rename(&tmp, path)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("commit lease write: {e}")))
    }
}

#[allow(dead_code)]
fn _assert_path_send_sync(_: &Path) {}
