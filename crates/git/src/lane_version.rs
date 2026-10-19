//! `save_version`: marker commit + annotated `checkpoint/user/<label>` tag
//! (ADR 2026-10-15, CONTRACT-247; MODULE-003-AC-30, AC-37).
//!
//! Runs in the commit worker with the coord mutex held. Adoption is R1: tracked
//! dirty paths plus untracked content only under the request's explicit `paths`.
//! The marker reuses the parent tree; the tag is created after `main` moves.
//!
//! Panic-free: it runs while the coord mutex is held.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::path::Path;
use std::time::SystemTime;

use git2::{ObjectType, Oid};

use crate::checkpoint::{normalize_paths, validate_create_path};
use crate::commit_queue::branch_guard;
use crate::emit::EmitPlan;
use crate::error::{CheckpointError, GitError, UserOpRefusal};
use crate::label::{self, CommitLabel, MAX_LABEL_PATHS, OP_SAVE_VERSION};
use crate::lane::{land, main_state, Landed, Landing, LaneCtx, Touched, MAX_ATTEMPTS};
use crate::lane_prepare;
use crate::user_lane::{
    signature_time_now, user_authorship, SaveVersionOutcome, SaveVersionRequest, USER_NAMESPACE,
};

/// One `save_version` item's answer plus the events and logs the worker emits after L2.
pub(crate) struct VersionItemResult {
    pub answer: Result<SaveVersionOutcome, GitError>,
    pub emit: Vec<EmitPlan>,
    pub refresh_repo: bool,
    pub tag_failed_sha: Option<String>,
}

/// Run one `save_version` item (see the module docs).
pub(crate) fn exec_save_version(
    ctx: &LaneCtx<'_>,
    req: &SaveVersionRequest,
) -> Result<VersionItemResult, GitError> {
    branch_guard(ctx.repo)?;
    let mut emit = Vec::new();
    let mut adopted_sha = None;
    let mut adopt_incomplete = false;
    let mut unversioned_count = 0u32;
    if req.adopt {
        let explicit = match &req.paths {
            Some(paths) if !paths.is_empty() => paths.as_slice(),
            _ => &[],
        };
        let run = lane_prepare::adopt_for_version(ctx, explicit, req.correlation_id.as_deref())?;
        adopt_incomplete = run.adopt_incomplete;
        unversioned_count = run.unversioned_count;
        adopted_sha = run.sha_hex();
        let plan = run.emit(req.correlation_id.as_deref());
        if !plan.is_empty() {
            emit.push(plan);
        }
    }

    let (tip, base) = main_state(ctx.repo)?;
    if tip.is_none() || base.is_none() {
        return Err(refuse(UserOpRefusal::NothingToVersion, None));
    }

    let title = label::normalize_title(&req.title).map_err(|reason| refuse(reason, None))?;
    let (tag_paths, label_paths, count) = version_paths(ctx, req)?;
    let existing = existing_user_labels(ctx)?;
    let at = req.at.unwrap_or_else(SystemTime::now);
    let version = label::version_label(&title, at, existing.iter().map(String::as_str))
        .map_err(|reason| refuse(reason, None))?;
    let checkpoint = format!("{USER_NAMESPACE}/{version}");
    let json = tag_message(tag_paths.as_ref())?;

    let commit_label = CommitLabel {
        op: OP_SAVE_VERSION.to_string(),
        paths: label_paths.clone(),
        count,
        title: Some(title.clone()),
        checkpoint: Some(checkpoint.clone()),
        ..CommitLabel::default()
    };
    let subject = label::render_subject(&commit_label).ok_or_else(op_shape)?;
    let message = label::render_message(
        &commit_label,
        &req.actor.initiator(),
        req.provenance.as_ref(),
    )
    .ok_or_else(op_shape)?;
    let authorship = user_authorship(&req.actor, &signature_time_now())?;
    let touched = Touched::default();

    let mut marker: Option<Oid> = None;
    let mut moved: Option<(Option<Oid>, Option<Oid>)> = None;
    for _ in 0..MAX_ATTEMPTS {
        moved = None;
        let (tip, base) = main_state(ctx.repo)?;
        let Some(parent_now) = tip else {
            return Err(refuse(UserOpRefusal::NothingToVersion, None));
        };
        let tree = match base {
            Some(tree) => tree.id(),
            None => return Err(refuse(UserOpRefusal::NothingToVersion, None)),
        };
        let landing = Landing {
            parent: Some(parent_now),
            tree,
            message: &message,
            subject: &subject,
            authorship: &authorship,
            touched: &touched,
            stats: &[],
        };
        match land(ctx, &landing)? {
            Landed::Committed(sha) => {
                marker = Some(sha);
                break;
            }
            Landed::HeadMoved(now) => moved = Some((Some(parent_now), now)),
        }
    }
    if let Some((expected, actual)) = moved {
        return Err(GitError::HeadMoved {
            expected: expected.map(|oid| oid.to_string()),
            actual: actual.map(|oid| oid.to_string()),
        });
    }
    let sha = marker.ok_or_else(|| refuse(UserOpRefusal::NothingToVersion, None))?;
    let tag_name = format!("checkpoint/{checkpoint}");
    let object = ctx.repo.find_object(sha, Some(ObjectType::Commit))?;
    if let Err(err) = ctx
        .repo
        .tag(&tag_name, &object, &authorship.author, &json, false)
    {
        emit.clear();
        return Ok(VersionItemResult {
            answer: Err(err.into()),
            emit,
            refresh_repo: false,
            tag_failed_sha: Some(sha.to_string()),
        });
    }
    emit.push(EmitPlan::save_version(
        &authorship.event_agent_id,
        &authorship.initiator,
        &subject,
        &sha.to_string(),
        req.correlation_id.as_deref(),
        label_paths,
    ));
    Ok(VersionItemResult {
        answer: Ok(SaveVersionOutcome {
            sha: sha.to_string(),
            label: version,
            tag: tag_name,
            title,
            paths: tag_paths.map(|ps| {
                ps.into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect()
            }),
            adopted_sha,
            adopt_incomplete,
            unversioned_count,
        }),
        emit,
        refresh_repo: false,
        tag_failed_sha: None,
    })
}

fn version_paths(
    ctx: &LaneCtx<'_>,
    req: &SaveVersionRequest,
) -> Result<(Option<Vec<std::path::PathBuf>>, Vec<String>, u32), GitError> {
    let Some(paths) = req.paths.as_ref().filter(|p| !p.is_empty()) else {
        return Ok((None, Vec::new(), 0));
    };
    let inputs: Vec<std::path::PathBuf> = paths
        .iter()
        .map(|p| std::path::PathBuf::from(p.nfc()))
        .collect();
    for p in &inputs {
        validate_create_path(p).map_err(path_refuse)?;
    }
    let normalized = normalize_paths(ctx.repo, inputs);
    let count = u32::try_from(normalized.len()).unwrap_or(u32::MAX);
    let labels: Vec<String> = normalized
        .iter()
        .take(MAX_LABEL_PATHS)
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    Ok((Some(normalized), labels, count))
}

fn tag_message(paths: Option<&Vec<std::path::PathBuf>>) -> Result<String, GitError> {
    let value = match paths {
        None => serde_json::json!({}),
        Some(ps) => {
            let s: Vec<String> = ps
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            serde_json::json!({ "paths": s })
        }
    };
    serde_json::to_string(&value).map_err(|e| GitError::Io(std::io::Error::other(e.to_string())))
}

fn existing_user_labels(ctx: &LaneCtx<'_>) -> Result<Vec<String>, GitError> {
    let mut labels = Vec::new();
    let refs = ctx.repo.references_glob("refs/tags/checkpoint/*/*")?;
    for reference in refs {
        let reference = reference?;
        let Some(name) = reference.name() else {
            continue;
        };
        let Some(rest) = name.strip_prefix("refs/tags/checkpoint/") else {
            continue;
        };
        let Some((agent, label)) = rest.split_once('/') else {
            continue;
        };
        if agent.eq_ignore_ascii_case(USER_NAMESPACE) && !label.contains('/') {
            labels.push(label.to_string());
        }
    }
    Ok(labels)
}

fn path_refuse(err: CheckpointError) -> GitError {
    match err {
        CheckpointError::InvalidPath { path, .. } => {
            refuse(UserOpRefusal::InvalidPath, Some(&path))
        }
        other => GitError::Io(std::io::Error::other(other.to_string())),
    }
}

fn refuse(reason: UserOpRefusal, path: Option<&Path>) -> GitError {
    GitError::InvalidUserOp {
        reason,
        path: path.map(Path::to_path_buf),
    }
}

fn op_shape() -> GitError {
    refuse(UserOpRefusal::OpShape, None)
}
