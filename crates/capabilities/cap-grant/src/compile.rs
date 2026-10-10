//! Static-config compilation (PRD §5.7.2, MODULE-013 §1.4.1).
//!
//! Parses `.agent/config.yaml` `capabilities:` section as a mapping
//! (capability_name → params/auto-grant value), per PRD §5.7.2 lines
//! 1438-1448. NOT a sequence form.
//!
//! `auto-grant: false` skips Grant emission while leaving host-fn
//! injection to M001 (AC-05).

use std::path::Path;

use chrono::Utc;
use serde_yml::Value;

use crate::data::{
    CapParam, ComponentId, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use crate::error::{CapGrantError, Result};
use advance_shared_types::entity::RETIRED_DATA_GRANT_CAPABILITY;

/// 1 MiB cap on YAML input — DoS posture mirroring m002/m004 Slice A.
pub const MAX_YAML_BYTES: u64 = 1 << 20;

pub struct StaticConfigCompiler;

impl StaticConfigCompiler {
    /// Read the YAML file at `path`, parse the canonical PRD §5.7.2
    /// `capabilities:` mapping, and emit one Grant per non-skipped entry.
    ///
    /// `workspace_root_agent` is the [`ComponentId`] used as `Grant.grantee`
    /// for every emitted grant. Both this id AND every capability_name MUST
    /// NOT contain `:` (used as the deterministic-id separator); violation
    /// returns [`CapGrantError::InvalidConfig`] (defense-in-depth bilateral
    /// charset gate).
    pub fn compile_from_path(path: &Path, workspace_root_agent: &str) -> Result<Vec<Grant>> {
        // Bilateral charset gate (grantee half) + empty-string defense.
        if workspace_root_agent.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "grantee must not be empty (would collide with other empty-grantee grants on the deterministic id)".to_string(),
            ));
        }
        if workspace_root_agent.contains(':') {
            return Err(CapGrantError::InvalidConfig(format!(
                "grantee contains forbidden character ':' — used as deterministic-id separator (got: {workspace_root_agent:?})"
            )));
        }

        // Size cap before reading.
        let meta = std::fs::metadata(path)
            .map_err(|e| CapGrantError::InvalidConfig(format!("stat {path:?}: {e}")))?;
        if meta.len() > MAX_YAML_BYTES {
            return Err(CapGrantError::InvalidConfig(format!(
                "yaml > {MAX_YAML_BYTES} bytes: {} bytes",
                meta.len()
            )));
        }
        let bytes = std::fs::read(path)
            .map_err(|e| CapGrantError::InvalidConfig(format!("read {path:?}: {e}")))?;
        if bytes.len() as u64 > MAX_YAML_BYTES {
            return Err(CapGrantError::InvalidConfig(format!(
                "yaml > {MAX_YAML_BYTES} bytes (post-read): {}",
                bytes.len()
            )));
        }

        let root: Value = serde_yml::from_slice(&bytes)?;
        compile_from_value(&root, workspace_root_agent)
    }

    /// Direct-from-Value form, used by tests that build a Value in-process.
    #[doc(hidden)]
    pub fn compile_from_value(root: &Value, workspace_root_agent: &str) -> Result<Vec<Grant>> {
        if workspace_root_agent.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "grantee must not be empty".to_string(),
            ));
        }
        if workspace_root_agent.contains(':') {
            return Err(CapGrantError::InvalidConfig(format!(
                "grantee contains forbidden character ':' — used as deterministic-id separator (got: {workspace_root_agent:?})"
            )));
        }
        compile_from_value(root, workspace_root_agent)
    }
}

fn compile_from_value(root: &Value, workspace_root_agent: &str) -> Result<Vec<Grant>> {
    let caps_value = root
        .as_mapping()
        .and_then(|m| m.get(Value::String("capabilities".to_string())))
        .ok_or_else(|| {
            CapGrantError::InvalidConfig("missing top-level `capabilities:` key".into())
        })?;

    let caps = caps_value.as_mapping().ok_or_else(|| {
        CapGrantError::InvalidConfig(format!(
            "`capabilities:` must be a mapping per PRD §5.7.2; got: {caps_value:?}"
        ))
    })?;

    let mut out = Vec::with_capacity(caps.len());
    let now = Utc::now();
    for (k, v) in caps {
        let capability_name = k.as_str().ok_or_else(|| {
            CapGrantError::InvalidConfig(format!("capability key must be a string; got: {k:?}"))
        })?;
        // Bilateral charset gate (capability half) + empty-string defense.
        if capability_name.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "capability key must not be empty".to_string(),
            ));
        }
        if capability_name.contains(':') {
            return Err(CapGrantError::InvalidConfig(format!(
                "capability contains forbidden character ':' — used as deterministic-id separator (got: {capability_name:?})"
            )));
        }

        // A retired family: nothing consults a `data` grant any more (the `data` tool is
        // authorized by `fs`), so the key is skipped instead of minting an inert grant.
        if capability_name == RETIRED_DATA_GRANT_CAPABILITY {
            eprintln!(
                "advance: WARN `capabilities.data` is retired and ignored; the data tool is \
                 authorized by the `fs` capability (reach it with `tools`)"
            );
            continue;
        }

        let params = match v {
            Value::Bool(true) => Vec::new(),
            Value::Mapping(m) => {
                // Skip if `auto-grant: false` is present anywhere in the mapping.
                let mut auto_grant_false = false;
                let mut params: Vec<CapParam> = Vec::with_capacity(m.len());
                for (sk, sv) in m {
                    let sk_str = sk.as_str().ok_or_else(|| {
                        CapGrantError::InvalidConfig(format!(
                            "capability `{capability_name}` sub-key must be string; got: {sk:?}"
                        ))
                    })?;
                    if sk_str == "auto-grant" {
                        if let Value::Bool(false) = sv {
                            auto_grant_false = true;
                            break;
                        }
                        // auto-grant: true is the default — do not emit as a param.
                        continue;
                    }
                    params.push(CapParam {
                        key: param_key(capability_name, sk_str).to_string(),
                        value: param_value(capability_name, sk_str, sv)?,
                    });
                }
                if auto_grant_false {
                    continue;
                }
                params
            }
            Value::Bool(false) => {
                // Bare `false` means "skip" too (e.g. `llm: false` would be odd
                // but should not emit a grant); treat as auto-grant: false.
                continue;
            }
            other => {
                return Err(CapGrantError::InvalidConfig(format!(
                    "capability `{capability_name}` value must be a mapping or `true`; got: {other:?}"
                )));
            }
        };

        // The grant is stored as written; the `mcp` rules read a malformed part of it as
        // covering nothing, so say which part at boot rather than letting calls fail silently.
        if capability_name == "mcp" {
            for problem in crate::subset::mcp_param_problems(&params) {
                eprintln!("advance: WARN `capabilities.mcp`: {problem}");
            }
        }

        let grantee: ComponentId = workspace_root_agent.to_string();
        out.push(Grant {
            id: GrantId(format!("static:{grantee}:{capability_name}")),
            grantee,
            capability: capability_name.to_string(),
            params,
            ttl: GrantTtl::Persistent,
            issuer: GrantIssuer::Config,
            provenance: GrantProvenance::StaticConfig,
            status: GrantStatus::Active,
            created_at: now,
            expires_at: None,
        });
    }
    Ok(out)
}

/// `fs` accepts `read` / `write` as aliases of the keys the subset rules read.
fn param_key<'a>(capability: &str, key: &'a str) -> &'a str {
    match (capability, key) {
        ("fs", "read") => "read-paths",
        ("fs", "write") => "write-paths",
        _ => key,
    }
}

/// The stored form of one param value. The subset rules split on `,`, so a YAML sequence of
/// scalars becomes a comma-separated list; a scalar is stored as its text.
fn param_value(capability: &str, key: &str, value: &Value) -> Result<String> {
    let scalar = |v: &Value| -> Option<String> {
        match v {
            Value::String(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    };
    if let Some(s) = scalar(value) {
        return Ok(s);
    }
    match value {
        Value::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let s = scalar(item).filter(|s| !s.contains(',')).ok_or_else(|| {
                    CapGrantError::InvalidConfig(format!(
                        "capability `{capability}` param `{key}`: list items must be scalars \
                         without `,`; got: {item:?}"
                    ))
                })?;
                out.push(s.trim().to_string());
            }
            Ok(out.join(","))
        }
        other => Err(CapGrantError::InvalidConfig(format!(
            "capability `{capability}` param `{key}` must be a scalar or a list of scalars; \
             got: {other:?}"
        ))),
    }
}
