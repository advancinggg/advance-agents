//! Serde + wire-format + deny_unknown_fields tests for `advance_shared_types::agent_tree`.

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentState, AgentStatus, AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{CapParams, CapabilityId};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

#[test]
fn agent_id_round_trip_is_transparent() {
    let id = AgentId("agent:root".to_string());
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"agent:root\"");
    let back: AgentId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, id);
}

#[test]
fn agent_id_is_hashmap_key() {
    let mut m: HashMap<AgentId, u32> = HashMap::new();
    m.insert(AgentId("a".to_string()), 1);
    assert_eq!(m.get(&AgentId("a".to_string())), Some(&1));
}

#[test]
fn agent_kind_round_trip() {
    for k in [AgentKind::Root, AgentKind::Child, AgentKind::Sub] {
        let json = serde_json::to_string(&k).unwrap();
        let back: AgentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn agent_kind_wire_format_lock() {
    assert_eq!(serde_json::to_string(&AgentKind::Root).unwrap(), "\"Root\"");
    assert_eq!(
        serde_json::to_string(&AgentKind::Child).unwrap(),
        "\"Child\""
    );
    assert_eq!(serde_json::to_string(&AgentKind::Sub).unwrap(), "\"Sub\"");
}

#[test]
fn agent_kind_deny_invalid() {
    let bad = "\"Foo\"";
    let err = serde_json::from_str::<AgentKind>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn agent_status_round_trip() {
    for s in [
        AgentStatus::Active,
        AgentStatus::Paused,
        AgentStatus::Terminated,
        AgentStatus::Failed,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: AgentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn capability_round_trip() {
    let c = Capability {
        id: CapabilityId::from("fs"),
        params: CapParams::empty(),
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: Capability = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn capability_deny_unknown_fields() {
    let bad = r#"{"id":"fs","params":null,"extra":42}"#;
    let err = serde_json::from_str::<Capability>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn agent_node_round_trip() {
    let node = AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: PathBuf::from("/ws"),
        capabilities: vec![],
        template_ref: None,
        status: AgentStatus::Active,
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: AgentNode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, node);
}

#[test]
fn agent_node_deny_unknown_fields() {
    let bad = r#"{"id":"x","kind":"Root","parent":null,"workspace_path":"/ws","capabilities":[],"template_ref":null,"status":"Active","extra":true}"#;
    let err = serde_json::from_str::<AgentNode>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn agent_state_round_trip() {
    let s = AgentState {
        agent_id: "root".to_string(),
        status: AgentStatus::Active,
        current_task_id: Some("t-1".to_string()),
        current_run_id: None,
        iteration: 3,
        turn_counter: 42,
        last_handle_message_at: Some(SystemTime::UNIX_EPOCH),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: AgentState = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn agent_state_deny_unknown_fields() {
    let bad = r#"{"agent_id":"x","status":"Active","current_task_id":null,"current_run_id":null,"iteration":0,"turn_counter":0,"last_handle_message_at":null,"extra":true}"#;
    let err = serde_json::from_str::<AgentState>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn agent_tree_snapshot_data_round_trip() {
    let data = AgentTreeSnapshotData {
        nodes: vec![],
        parent_of: HashMap::new(),
        children_of: HashMap::new(),
        peer_slug_map: HashMap::new(),
        revision: 7,
    };
    let json = serde_json::to_string(&data).unwrap();
    let back: AgentTreeSnapshotData = serde_json::from_str(&json).unwrap();
    assert_eq!(back, data);
}

#[test]
fn agent_tree_snapshot_data_deny_unknown_fields() {
    let bad = r#"{"nodes":[],"parent_of":{},"children_of":{},"peer_slug_map":{},"revision":0,"extra":true}"#;
    let err = serde_json::from_str::<AgentTreeSnapshotData>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}
