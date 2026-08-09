//! Slice-B auto-bootstrap declarative team applier
//! (MODULE-005 §1.3.5, AC-11 + AC-12).
//!
//! Public surface:
//! - [`BootstrapEntry`] / [`BootstrapKind`] / [`BootstrapEnsure`] — serde
//!   deserializer for the `auto-bootstrap:` YAML payload inside a
//!   template manifest.
//! - [`parse_auto_bootstrap`] — pre-deserialize input cap +
//!   `serde_yml::from_str` + parse-time alias validation.
//! - [`apply_auto_bootstrap`] — full §1.3.5 5-row matrix implementer:
//!   step 0 parent existence pre-check, step 1 kind!=Child rejection,
//!   step 2 target-path lexical validation, step 3 path-normalization,
//!   steps 4–5 alias/target-path lookup, step 6 spawn.
//! - [`BootstrapReport`] / [`BootstrapEvent`] — outcome.
//! - [`BootstrapError`] — error variants.

use std::path::PathBuf;

use advance_shared_types::agent_tree::{AgentId, AgentTreeReader};
use serde::Deserialize;

use crate::identifier::validate_agent_id;
use crate::spawn::{SpawnChildConfig, Spawner};
use crate::tree::AgentTreeStore;
use crate::workspace::resolve_under_parent;

/// Pre-deserialize input-size cap for `parse_auto_bootstrap`. 64 entries
/// × ~256 bytes/entry sits well below 16 KiB; 64 KiB gives 4× headroom
/// matching `atomic::MAX_BYTES`. Reject before serde_yml runs to bound
/// memory growth from adversarial payloads.
pub const MAX_BOOTSTRAP_INPUT_BYTES: usize = 64 * 1024;

/// Soft cap on bootstrap entries per template. Defense-in-depth bound
/// matching `MAX_CAPABILITIES`.
pub const MAX_BOOTSTRAP_ENTRIES: usize = 64;

/// Hard cap on YAML anchor (`&name`) declarations and alias (`*name`)
/// references in a single `parse_auto_bootstrap` input. Closes the
/// billion-laughs / anchor-amplification DoS surface: a 64 KiB payload
/// can encode hundreds of anchor references that serde_yml expands at
/// parse time, multiplying memory usage by orders of magnitude. We
/// pre-scan the input string for `&`/`*` tokens BEFORE handing to
/// serde_yml. 64 anchors / 64 aliases is generous relative to the
/// expected human-authored use case (typically 0–4 anchors per file).
pub const MAX_YAML_ANCHORS_PER_INPUT: usize = 64;
pub const MAX_YAML_ALIASES_PER_INPUT: usize = 64;

/// Conservatively scan an input string for YAML anchor declarations
/// (`&name`) and alias references (`*name`). This is a syntactic
/// pre-scan, not a true YAML parse — false positives are possible
/// (e.g., `&` inside a flow-style scalar), but the cap is generous
/// enough that legitimate content stays well under it. The intent is
/// to reject pathological inputs that would amplify memory at parse
/// time. Returns `Err(BootstrapError::InputTooLarge(count))` when
/// either count exceeds its cap, re-using the existing variant to
/// avoid expanding the error enum.
fn precheck_yaml_anchors(input: &str) -> Result<(), BootstrapError> {
    let mut anchor_count = 0usize;
    let mut alias_count = 0usize;
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // Look for `&<word-char>` or `*<word-char>` patterns where the
        // anchor/alias char is at a token boundary. We do not attempt
        // full YAML tokenization — counting raw `&` / `*` occurrences
        // followed by an alphanumeric / underscore / hyphen byte is
        // sufficient to detect amplification attacks.
        if (b == b'&' || b == b'*') && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            let is_word = next.is_ascii_alphanumeric() || next == b'_' || next == b'-';
            if is_word {
                if b == b'&' {
                    anchor_count += 1;
                    if anchor_count > MAX_YAML_ANCHORS_PER_INPUT {
                        return Err(BootstrapError::YamlAnchorAmplification(anchor_count));
                    }
                } else {
                    alias_count += 1;
                    if alias_count > MAX_YAML_ALIASES_PER_INPUT {
                        return Err(BootstrapError::YamlAnchorAmplification(alias_count));
                    }
                }
            }
        }
        i += 1;
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapEntry {
    pub template: String,
    pub kind: BootstrapKind,
    #[serde(rename = "target-path")]
    pub target_path: PathBuf,
    pub alias: String,
    pub ensure: BootstrapEnsure,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BootstrapKind {
    Child,
    Sub,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BootstrapEnsure {
    Present,
}

#[derive(Debug, Clone)]
pub struct BootstrapReport {
    pub spawned: Vec<AgentId>,
    pub skipped: Vec<AgentId>,
    pub conflicts: Vec<BootstrapEvent>,
}

#[derive(Debug, Clone)]
pub enum BootstrapEvent {
    Conflict { alias: AgentId, reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("sub-kind rejected for alias {alias}")]
    SubKindRejected {
        alias: String,
        partial: BootstrapReport,
    },
    #[error("parent not found: {0:?}")]
    ParentNotFound(AgentId),
    #[error("parent vanished mid-batch (was: {parent:?})")]
    ParentVanished {
        parent: AgentId,
        partial: BootstrapReport,
    },
    #[error("invalid alias: {0}")]
    InvalidAlias(String),
    #[error("invalid target-path: {path:?}")]
    InvalidTargetPath {
        path: PathBuf,
        partial: BootstrapReport,
    },
    #[error("alias {alias:?} path mismatch (existing={existing:?}, expected={expected:?})")]
    AliasPathMismatch {
        alias: AgentId,
        existing: PathBuf,
        expected: PathBuf,
        partial: BootstrapReport,
    },
    #[error("target-path occupied by alias {existing_alias:?} at {target:?}")]
    TargetPathOccupied {
        existing_alias: AgentId,
        target: PathBuf,
        partial: BootstrapReport,
    },
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("input too large: {0} bytes")]
    InputTooLarge(usize),
    #[error("yaml anchor / alias count exceeds defensive cap ({0} > MAX_YAML_*)")]
    YamlAnchorAmplification(usize),
    #[error("entry limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("spawn failed: {msg}")]
    SpawnFailed {
        msg: String,
        /// Successes accumulated BEFORE the failure, so callers can observe
        /// which spawns landed without re-querying the tree.
        partial: BootstrapReport,
    },
}

/// Parse a YAML payload (a top-level sequence of `BootstrapEntry` maps)
/// into a validated `Vec<BootstrapEntry>`. Enforces pre-deserialize
/// input cap + post-deserialize entry-count cap + parse-time alias
/// charset validation.
pub fn parse_auto_bootstrap(input: &str) -> Result<Vec<BootstrapEntry>, BootstrapError> {
    if input.len() > MAX_BOOTSTRAP_INPUT_BYTES {
        return Err(BootstrapError::InputTooLarge(input.len()));
    }
    // Adversarial round-1 Critical fix: pre-scan for excessive YAML anchor /
    // alias occurrences before invoking serde_yml. Bounds the
    // billion-laughs amplification surface (serde_yml expands aliases at
    // parse time; a small input with many aliases can blow up memory).
    precheck_yaml_anchors(input)?;
    let entries: Vec<BootstrapEntry> =
        serde_yml::from_str(input).map_err(|e| BootstrapError::ParseError(e.to_string()))?;
    if entries.len() > MAX_BOOTSTRAP_ENTRIES {
        return Err(BootstrapError::LimitExceeded(format!(
            "{} > {MAX_BOOTSTRAP_ENTRIES}",
            entries.len()
        )));
    }
    for entry in &entries {
        validate_agent_id(&entry.alias)
            .map_err(|_| BootstrapError::InvalidAlias(entry.alias.clone()))?;
    }
    Ok(entries)
}

/// Apply a list of bootstrap entries against `parent_id`'s subtree.
/// Implements MODULE-005 §1.3.5 5-row matrix. Fail-fast on first
/// `BootstrapError::SpawnFailed`; caller observes partial work via
/// `tree.children_of(parent_id)` and idempotent retry is safe.
pub fn apply_auto_bootstrap(
    entries: &[BootstrapEntry],
    parent_id: &AgentId,
    spawner: &dyn Spawner,
    tree: &AgentTreeStore,
) -> Result<BootstrapReport, BootstrapError> {
    // Step 0: parent existence pre-check + cache parent node.
    let parent = tree
        .get_node(parent_id)
        .ok_or_else(|| BootstrapError::ParentNotFound(parent_id.clone()))?;
    let workspace_root = tree.workspace_root().to_path_buf();
    // Cache children_ids once — re-read inside step 5 to pick up successful
    // spawns from earlier iterations of this same call.
    let mut children_ids = tree.children_of(&parent_id.0);

    let mut report = BootstrapReport {
        spawned: Vec::new(),
        skipped: Vec::new(),
        conflicts: Vec::new(),
    };

    for entry in entries {
        // Adversarial round-1 Warning fix (parent vanished mid-batch): re-verify
        // parent existence per iteration so a concurrent removal between step 0
        // and step N doesn't silently spawn children referencing a vanished
        // parent. Use the cached parent for path computations (workspace_path is
        // canonical and immutable for a given AgentNode), but bail with a
        // distinct ParentVanished error when the parent has been removed.
        // Carries `partial` per adversarial round-2 Warning #1.
        if !tree.contains(parent_id) {
            return Err(BootstrapError::ParentVanished {
                parent: parent_id.clone(),
                partial: report,
            });
        }

        // Step 1: kind != Child rejection.
        if entry.kind != BootstrapKind::Child {
            return Err(BootstrapError::SubKindRejected {
                alias: entry.alias.clone(),
                partial: report,
            });
        }

        // Step 2: target-path lexical validation via resolve_under_parent reuse.
        if let Err(_e) =
            resolve_under_parent(&parent.workspace_path, &entry.target_path, &workspace_root)
        {
            return Err(BootstrapError::InvalidTargetPath {
                path: entry.target_path.clone(),
                partial: report,
            });
        }

        // Step 3: compute canonical-equivalent expected_path.
        // (parent.workspace_path is canonical via insert-time canonicalization;
        // target_path has been rejected for `..` / absolute / hidden / over-depth
        // in step 2, so the lexical join is canonical-equivalent.)
        let expected_path = parent.workspace_path.join(&entry.target_path);

        let alias_id = AgentId(entry.alias.clone());

        // Step 4: alias lookup.
        if let Some(existing) = tree.get_node(&alias_id) {
            if existing.workspace_path == expected_path {
                if existing.template_ref.as_deref() == Some(entry.template.as_str()) {
                    report.skipped.push(alias_id.clone());
                } else {
                    report.conflicts.push(BootstrapEvent::Conflict {
                        alias: alias_id.clone(),
                        reason: format!(
                            "template_ref mismatch: existing={:?}, new={:?}",
                            existing.template_ref, entry.template
                        ),
                    });
                }
            } else {
                return Err(BootstrapError::AliasPathMismatch {
                    alias: alias_id,
                    existing: existing.workspace_path,
                    expected: expected_path,
                    partial: report,
                });
            }
            continue;
        }

        // Step 5: target-path occupancy lookup (alias-agnostic).
        // Cache children once per call: caller-controlled M (= entries.len(),
        // bounded by MAX_BOOTSTRAP_ENTRIES = 64) used to multiply against
        // children_of (O(C) where C = tree.children_of cap = MAX_AGENTS_PER_STORE)
        // giving worst-case M*C = 64*1024 = 65,536 get_node lookups. Caching
        // collapses this to O(M+C) overall.
        let mut occupied_by: Option<AgentId> = None;
        for child_id_str in children_ids.iter() {
            let child_id = AgentId(child_id_str.clone());
            if let Some(child_node) = tree.get_node(&child_id) {
                if child_node.workspace_path == expected_path {
                    occupied_by = Some(child_id);
                    break;
                }
            }
        }
        if let Some(existing_alias) = occupied_by {
            return Err(BootstrapError::TargetPathOccupied {
                existing_alias,
                target: expected_path,
                partial: report,
            });
        }

        // Step 6: spawn.
        let cfg = SpawnChildConfig {
            parent_id: parent_id.clone(),
            child_id: alias_id.clone(),
            child_workspace_path: entry.target_path.clone(),
            capabilities: Vec::new(),
            template_ref: Some(entry.template.clone()),
            // Boot-declared children materialize their driver from the template
            // (the serve-loop boot leg is Wave-24 `perchild-daemon-2`).
            binary: None,
        };
        match spawner.spawn_child(cfg) {
            Ok(id) => {
                children_ids.push(id.0.clone());
                report.spawned.push(id);
            }
            Err(e) => {
                return Err(BootstrapError::SpawnFailed {
                    msg: format!("{}: {e}", entry.alias),
                    partial: report,
                });
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_happy_path() {
        let yaml = "- template: explorer\n  kind: child\n  target-path: agents/foo\n  alias: foo\n  ensure: present\n";
        let entries = parse_auto_bootstrap(yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "foo");
        assert_eq!(entries[0].kind, BootstrapKind::Child);
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let yaml = "- template: explorer\n  kind: child\n  target-path: foo\n  alias: foo\n  ensure: present\n  extra: bad\n";
        let err = parse_auto_bootstrap(yaml).unwrap_err();
        assert!(matches!(err, BootstrapError::ParseError(_)));
    }

    #[test]
    fn parse_rejects_oversize_input() {
        let big = "x".repeat(MAX_BOOTSTRAP_INPUT_BYTES + 1);
        let err = parse_auto_bootstrap(&big).unwrap_err();
        assert!(matches!(err, BootstrapError::InputTooLarge(_)));
    }

    #[test]
    fn parse_rejects_invalid_alias() {
        let yaml =
            "- template: explorer\n  kind: child\n  target-path: foo\n  alias: \"hello world\"\n  ensure: present\n";
        let err = parse_auto_bootstrap(yaml).unwrap_err();
        assert!(
            matches!(err, BootstrapError::InvalidAlias(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_limit_exceeded() {
        let mut buf = String::new();
        for i in 0..(MAX_BOOTSTRAP_ENTRIES + 1) {
            buf.push_str(&format!(
                "- template: explorer\n  kind: child\n  target-path: a{i}\n  alias: a{i}\n  ensure: present\n"
            ));
        }
        let err = parse_auto_bootstrap(&buf).unwrap_err();
        assert!(
            matches!(err, BootstrapError::LimitExceeded(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_accepts_kind_sub_at_parse_time() {
        // AC-12 enforcement happens at apply-time, not parse-time.
        let yaml =
            "- template: x\n  kind: sub\n  target-path: foo\n  alias: foo\n  ensure: present\n";
        let entries = parse_auto_bootstrap(yaml).unwrap();
        assert_eq!(entries[0].kind, BootstrapKind::Sub);
    }

    #[test]
    fn parse_rejects_excessive_yaml_anchors() {
        // Adversarial round-1 Critical fix: pre-scan rejects pathological
        // anchor / alias counts that would amplify serde_yml memory use.
        // Adversarial round-2 Warning fix: dedicated YamlAnchorAmplification
        // variant (was conflated with InputTooLarge).
        let mut payload = String::new();
        for i in 0..=MAX_YAML_ANCHORS_PER_INPUT {
            payload.push_str(&format!("- &anchor_{i} explorer\n"));
        }
        let err = parse_auto_bootstrap(&payload).unwrap_err();
        assert!(
            matches!(err, BootstrapError::YamlAnchorAmplification(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_excessive_yaml_aliases() {
        let mut payload = String::new();
        for i in 0..=MAX_YAML_ALIASES_PER_INPUT {
            payload.push_str(&format!("- *alias_{i}\n"));
        }
        let err = parse_auto_bootstrap(&payload).unwrap_err();
        assert!(
            matches!(err, BootstrapError::YamlAnchorAmplification(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_accepts_modest_anchor_use() {
        // A handful of anchors should pass the pre-scan and parse as usual.
        let yaml = "- &exp explorer\n";
        // serde_yml will then fail to deserialize a string into BootstrapEntry,
        // surfacing as ParseError (NOT InputTooLarge). The point is just that
        // precheck_yaml_anchors does not reject this small case.
        let err = parse_auto_bootstrap(yaml).unwrap_err();
        assert!(matches!(err, BootstrapError::ParseError(_)), "got {err:?}");
    }
}
