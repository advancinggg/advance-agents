use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::l6::classifier::SkillHealthEntry;

pub const SKILL_HEALTH_FILENAME: &str = "_skill_health.yaml";
const SKILL_HEALTH_SCHEMA_VERSION: u32 = 1;
const MAX_SKILL_HEALTH_ENTRIES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillHealthFile {
    pub version: u32,
    pub agent_id: String,
    pub lease_id: String,
    pub generated_at: String,
    pub entries: Vec<SkillHealthYamlEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillHealthYamlEntry {
    pub skill: String,
    pub status: String,
}

#[derive(Debug, Error)]
pub enum SkillHealthWriteError {
    #[error("too many skill health entries: {0}")]
    TooManyEntries(usize),
    #[error("serialize skill health yaml: {0}")]
    Serialize(String),
    #[error("write skill health yaml: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct SkillHealthWriter {
    root: PathBuf,
}

impl SkillHealthWriter {
    pub fn in_dir(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn path(&self) -> PathBuf {
        self.root.join(SKILL_HEALTH_FILENAME)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn build_file(
        agent_id: &str,
        lease_id: &str,
        generated_at: String,
        entries: &[SkillHealthEntry],
    ) -> Result<SkillHealthFile, SkillHealthWriteError> {
        if entries.len() > MAX_SKILL_HEALTH_ENTRIES {
            return Err(SkillHealthWriteError::TooManyEntries(entries.len()));
        }
        Ok(SkillHealthFile {
            version: SKILL_HEALTH_SCHEMA_VERSION,
            agent_id: agent_id.to_string(),
            lease_id: lease_id.to_string(),
            generated_at,
            entries: entries
                .iter()
                .map(|entry| SkillHealthYamlEntry {
                    skill: entry.skill.clone(),
                    status: entry.status.clone(),
                })
                .collect(),
        })
    }

    pub fn write(
        &self,
        agent_id: &str,
        lease_id: &str,
        generated_at: String,
        entries: &[SkillHealthEntry],
    ) -> Result<(), SkillHealthWriteError> {
        std::fs::create_dir_all(&self.root)?;
        let file = Self::build_file(agent_id, lease_id, generated_at, entries)?;
        let yaml = serde_yml::to_string(&file)
            .map_err(|e| SkillHealthWriteError::Serialize(e.to_string()))?;
        std::fs::write(self.path(), yaml)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_runtime_private_skill_health_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let writer = SkillHealthWriter::in_dir(dir.path());
        let entries = vec![
            SkillHealthEntry {
                skill: "web-search".into(),
                status: "healthy".into(),
            },
            SkillHealthEntry {
                skill: "calendar".into(),
                status: "stale".into(),
            },
        ];

        writer
            .write(
                "agent-1",
                "lease-1",
                "2026-06-30T00:00:00Z".into(),
                &entries,
            )
            .unwrap();

        let yaml = std::fs::read_to_string(writer.path()).unwrap();
        let parsed: SkillHealthFile = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(parsed.agent_id, "agent-1");
        assert_eq!(parsed.lease_id, "lease-1");
        assert_eq!(
            parsed.entries,
            vec![
                SkillHealthYamlEntry {
                    skill: "web-search".into(),
                    status: "healthy".into(),
                },
                SkillHealthYamlEntry {
                    skill: "calendar".into(),
                    status: "stale".into(),
                },
            ]
        );
    }
}
