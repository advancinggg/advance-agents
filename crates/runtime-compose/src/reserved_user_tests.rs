//! MODULE-003-T81 (unit): reserved `user` namespace at compose boot.

use super::*;
use crate::agent_config::AgentDecl;
use crate::api::{ComposeLog, ComposeLogLine};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Default)]
struct Recording {
    keys: Mutex<Vec<&'static str>>,
}

impl ComposeLog for Recording {
    fn line(&self, line: &ComposeLogLine) {
        self.keys.lock().unwrap().push(line.key);
    }

    fn ready(&self, _line: &ComposeLogLine) -> std::io::Result<()> {
        Ok(())
    }
}

fn decl(alias: &str) -> AgentDecl {
    AgentDecl {
        alias: alias.to_string(),
        template: "default".to_string(),
        target_path: PathBuf::from("child"),
        capabilities: Vec::new(),
        children: Vec::new(),
    }
}

#[test]
fn reserved_agent_ids_cover_user_namespace() {
    assert!(RESERVED_AGENT_IDS.contains(&advance_git::USER_NAMESPACE));
}

#[test]
fn legacy_user_alias_emits_reserved_warning() {
    let rec = std::sync::Arc::new(Recording::default());
    let log = LogHandle::new(rec.clone());
    warn_reserved_agent_aliases(&log, &[decl("user"), decl("writer"), decl("USER")]);
    let keys = rec.keys.lock().unwrap().clone();
    assert_eq!(
        keys,
        vec![
            log_keys::AGENT_ALIAS_RESERVED,
            log_keys::AGENT_ALIAS_RESERVED
        ]
    );
}
