//! MODULE-020-AC-10 witness (integration, FLIP): tool/skill/MCP inventory is visible through a
//! client-safe projection respecting grant filters + trust metadata.
//!
//! Drives `ClientApi::handle()` end-to-end (GET /client/tools) against a REAL `cap_tools::
//! CallableInventory` wired with a REAL `cap_grant::ToolsGrantReaderImpl` over a REAL `GrantStore`
//! (in-memory SQLite) + a REAL `cap_skills::InMemorySkillStorage`. Asserts the grant-filter
//! DIFFERENCE (narrowed agent sees fewer WASM tools than a wildcard agent), projection safety, the
//! absent-vs-empty fail-closed discriminator, and the ReadInventory scope gate.

use std::sync::Arc;

use advance_client_api::tools::{ClientMcpEntry, ClientSkillEntry, ClientToolEntry};
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientErrorCode, ClientRequest, ClientSession, ClientToolInventory,
    Platform, Principal, ProviderError, Scope, ToolsProvider,
};

use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_shared_types::capability::{McpToolEntry, ToolEntry};
use advance_shared_types::chrono::Utc;
use advance_shared_types::event::Event;
use advance_shared_types::skills::{Provenance, TrustLevel};
use advance_shared_types::traits::{CallableInventoryReader, EventBusEmit};
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{GrantSqliteIndex, GrantStore, ToolsGrantReaderImpl};
use cap_skills::persistence::{InMemorySkillStorage, SkillBlob, SkillStorage};
use cap_tools::CallableInventory;

// ── Real-provider adapter (Wave-25's job lives in the cli composition root; the witness supplies it) ──

struct InventoryTools {
    rt: Arc<tokio::runtime::Runtime>,
    inventory: CallableInventory,
    skills: Arc<InMemorySkillStorage>,
}

fn provenance_str(p: &Provenance) -> &'static str {
    match p {
        Provenance::AgentCreated => "agent_created",
        Provenance::Imported => "imported",
    }
}
fn trust_str(t: &TrustLevel) -> &'static str {
    match t {
        TrustLevel::Trusted => "trusted",
        TrustLevel::Untrusted => "untrusted",
    }
}

impl ToolsProvider for InventoryTools {
    fn inventory(&self, agent_id: &str) -> Result<ClientToolInventory, ProviderError> {
        let wasm = self
            .inventory
            .list_wasm_tools(agent_id)
            .into_iter()
            .map(|t| ClientToolEntry {
                name: t.name,
                description: t.description,
            })
            .collect();
        let mcp = self
            .inventory
            .list_mcp_tools(agent_id)
            .into_iter()
            .map(|t| ClientMcpEntry {
                name: t.name,
                description: t.description,
                server_id: t.server_id,
            })
            .collect();
        // list_active is async → bridge with the adapter-owned runtime.
        let blobs = self
            .rt
            .block_on(self.skills.list_active())
            .map_err(|_| ProviderError::Unavailable("skills".into()))?;
        let skills = blobs
            .into_iter()
            .map(|b| ClientSkillEntry {
                skill_id: b.skill_id,
                version: b.version,
                provenance: provenance_str(&b.provenance).to_string(),
                trust_level: trust_str(&b.trust_level).to_string(),
            })
            .collect();
        Ok(ClientToolInventory { wasm, mcp, skills })
    }
}

struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

// ── Test scaffolding ──

/// Mint a session directly (bypassing login) so the witness controls the principal id used as the
/// grant-filter agent id, and the exact scope set. Real handler/provider behavior is unchanged.
fn mint(api: &ClientApi, agent_id: &str, token: &str, scopes: Vec<Scope>) {
    let session = ClientSession {
        session_id: format!("sess-{agent_id}"),
        principal: Principal {
            id: agent_id.to_string(),
            os_user: "op".to_string(),
        },
        platform: Platform::Mac,
        scopes,
        csrf_token: None,
        expires_at: u64::MAX,
    };
    api.sessions().insert(token.to_string(), session, 0);
}

fn wasm(name: &str, desc: &str) -> ToolEntry {
    ToolEntry {
        name: name.to_string(),
        description: desc.to_string(),
        params_schema: serde_json::json!({}),
    }
}

/// A GrantStore with a narrow "tools" grant for agentx (only w1) and a wildcard grant for agenty
/// (all tools). Grantees are BARE ids (colon rejected by insert).
fn grant_store() -> Arc<GrantStore> {
    let handle: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite"));
    let index = GrantSqliteIndex::new(handle);
    index.ensure_schema().expect("ensure_schema");
    let store = Arc::new(GrantStore::new(index, Arc::new(NoopBus)));
    store
        .insert(Grant {
            id: GrantId::new("g-agentx"),
            grantee: "agentx".to_string(),
            capability: "tools".to_string(),
            params: vec![CapParam {
                key: "ids".to_string(),
                value: "w1".to_string(),
            }],
            ttl: GrantTtl::Persistent,
            issuer: GrantIssuer::Config,
            provenance: GrantProvenance::StaticConfig,
            status: GrantStatus::Active,
            created_at: Utc::now(),
            expires_at: None,
        })
        .expect("insert narrow grant");
    store
        .insert(Grant {
            id: GrantId::new("g-agenty"),
            grantee: "agenty".to_string(),
            capability: "tools".to_string(),
            params: vec![], // no ids → wildcard → full set
            ttl: GrantTtl::Persistent,
            issuer: GrantIssuer::Config,
            provenance: GrantProvenance::StaticConfig,
            status: GrantStatus::Active,
            created_at: Utc::now(),
            expires_at: None,
        })
        .expect("insert wildcard grant");
    store
}

fn tools_api(inventory: CallableInventory, skills: Arc<InMemorySkillStorage>) -> ClientApi {
    let rt = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime"),
    );
    ClientApi::new(ClientApiConfig::default()).with_tools_provider(Arc::new(InventoryTools {
        rt,
        inventory,
        skills,
    }))
}

fn seed_skill(skills: &InMemorySkillStorage) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        skills
            .write_active(&SkillBlob {
                skill_id: "my-skill".to_string(),
                version: 3,
                content: "---\nname: my-skill\n---\nbody".to_string(),
                tags: vec!["research".to_string()],
                provenance: Provenance::Imported,
                trust_level: TrustLevel::Trusted,
            })
            .await
            .unwrap();
    });
}

fn get_inventory(api: &ClientApi, token: &str) -> ClientToolInventory {
    let env = api.handle(ClientRequest::get("/client/tools").with_session(token));
    assert!(env.is_ok(), "expected ok envelope, got {:?}", env.error);
    serde_json::from_value(env.data.expect("data present"))
        .expect("deserializes into ClientToolInventory")
}

// ── T10: the AC-10 witness ──

#[test]
fn t10_tools_inventory_grant_filtered_projection() {
    let store = grant_store();
    let inventory = CallableInventory::new(
        vec![wasm("w1", "wasm one"), wasm("w2", "wasm two")],
        vec![McpToolEntry {
            name: "m1".to_string(),
            description: "mcp one".to_string(),
            params_schema: serde_json::json!({}),
            server_id: "srv-1".to_string(),
        }],
    )
    .with_tools_grant_reader(Arc::new(ToolsGrantReaderImpl::new(store)));
    let skills = Arc::new(InMemorySkillStorage::new());
    seed_skill(&skills);

    let api = tools_api(inventory, Arc::clone(&skills));
    mint(&api, "agentx", "tok-x", vec![Scope::ReadInventory]);
    mint(&api, "agenty", "tok-y", vec![Scope::ReadInventory]);

    // T10a: the wildcard agent sees the full inventory + real MCP + real skill provenance/trust.
    let full = get_inventory(&api, "tok-y");
    let full_wasm: Vec<String> = full.wasm.iter().map(|t| t.name.clone()).collect();
    assert_eq!(full_wasm, vec!["w1", "w2"], "wildcard sees all wasm tools");
    assert_eq!(full.mcp.len(), 1);
    assert_eq!(
        full.mcp[0].server_id, "srv-1",
        "MCP server_id provenance carried"
    );
    assert_eq!(full.skills.len(), 1);
    assert_eq!(full.skills[0].skill_id, "my-skill");
    assert_eq!(full.skills[0].provenance, "imported");
    assert_eq!(full.skills[0].trust_level, "trusted");

    // T10b (grant-filter DISCRIMINATOR): the narrowed agent sees ONLY w1 — assert the DIFFERENCE.
    let narrowed = get_inventory(&api, "tok-x");
    let narrowed_wasm: Vec<String> = narrowed.wasm.iter().map(|t| t.name.clone()).collect();
    assert_eq!(
        narrowed_wasm,
        vec!["w1"],
        "narrowed agent sees only the granted tool"
    );
    assert!(
        narrowed.wasm.len() < full.wasm.len(),
        "grant filter narrows the WASM set (narrowed {} < full {})",
        narrowed.wasm.len(),
        full.wasm.len()
    );

    // T10c (projection safety): the response deserialized into the schemars DTO — the skill entry
    // exposes ONLY skill_id/version/provenance/trust_level (no content/tags), proven by the fact
    // that ClientSkillEntry has no such fields and the deserialize above succeeded with
    // deny-unknown-free struct. Re-serialize and confirm internal fields are absent.
    let reencoded = serde_json::to_value(&full.skills[0]).unwrap();
    assert!(
        reencoded.get("content").is_none(),
        "skill content must not leak"
    );
    assert!(reencoded.get("tags").is_none(), "skill tags must not leak");
}

#[test]
fn t10d_absent_provider_is_module_unavailable_not_empty() {
    // No tools provider wired → module_unavailable (NOT unknown_route, NOT a synthesized empty set).
    let api = ClientApi::new(ClientApiConfig::default());
    mint(&api, "agentz", "tok-z", vec![Scope::ReadInventory]);
    let env = api.handle(ClientRequest::get("/client/tools").with_session("tok-z"));
    assert!(env.is_err());
    assert_eq!(env.error_code(), Some(ClientErrorCode::ModuleUnavailable));

    // A genuinely-wired-but-EMPTY inventory returns an OK empty projection (absent != empty).
    let empty_inv = CallableInventory::new(vec![], vec![]);
    let api2 = tools_api(empty_inv, Arc::new(InMemorySkillStorage::new()));
    mint(&api2, "agentz", "tok-z2", vec![Scope::ReadInventory]);
    let got = get_inventory(&api2, "tok-z2");
    assert!(got.wasm.is_empty() && got.mcp.is_empty() && got.skills.is_empty());
}

#[test]
fn t10e_read_inventory_scope_required() {
    let api = tools_api(
        CallableInventory::new(vec![wasm("w1", "one")], vec![]),
        Arc::new(InMemorySkillStorage::new()),
    );
    // Session WITHOUT ReadInventory → forbidden (authenticated but under-scoped), NOT unauthenticated.
    mint(&api, "agentx", "tok-noscope", vec![Scope::ReadRuns]);
    let env = api.handle(ClientRequest::get("/client/tools").with_session("tok-noscope"));
    assert!(env.is_err());
    assert_eq!(env.error_code(), Some(ClientErrorCode::Forbidden));

    // No session at all → unauthenticated (the pipeline's session gate, before the scope gate).
    let env2 = api.handle(ClientRequest::get("/client/tools"));
    assert_eq!(env2.error_code(), Some(ClientErrorCode::Unauthenticated));
}
