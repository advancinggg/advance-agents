//! CONTRACT-190 tools family (m020-s2, AC-10).
//!
//! `GET /client/tools` — a client-safe allowlist projection of the MODULE-017 tool/skill/MCP
//! inventory respecting grant filters + trust metadata. The provider returns an already grant-
//! filtered, already client-safe inventory (no skill content/tags; no internal-only fields).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::{ClientApi, HandlerSpec};
use crate::provider::{provider_or_unavailable, ProviderError, ToolsProviderSlot};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// A WASM callable tool (client-safe projection).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientToolEntry {
    pub name: String,
    pub description: String,
}

/// An MCP callable tool (client-safe projection; carries the MCP `server_id` provenance).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientMcpEntry {
    pub name: String,
    pub description: String,
    pub server_id: String,
}

/// An active skill (client-safe projection). Carries provenance + trust metadata but NOT the skill
/// content or tags.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientSkillEntry {
    pub skill_id: String,
    pub version: u32,
    /// `agent_created | imported`.
    pub provenance: String,
    /// `trusted | untrusted`.
    pub trust_level: String,
}

/// The `GET /client/tools` response payload: grant-filtered WASM + MCP callables + active skills.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientToolInventory {
    pub wasm: Vec<ClientToolEntry>,
    pub mcp: Vec<ClientMcpEntry>,
    pub skills: Vec<ClientSkillEntry>,
}

/// Register the tools route, capturing the shared provider slot in the closure.
pub(crate) fn register(api: &mut ClientApi, slot: ToolsProviderSlot) {
    // GET /client/tools — list tool/skill/MCP callables (grant-filtered projection). The pipeline
    // enforces ReadInventory. The projection is grant-scoped to the session principal's agent
    // identity (`principal.id`); the production operator→agent-scope binding is Wave-25 wiring.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_TOOLS,
        HandlerSpec::read(true, move |ctx| {
            let agent_id = ctx
                .principal
                .as_ref()
                .map(|p| p.id.clone())
                .unwrap_or_default();
            let provider = provider_or_unavailable(&s)?;
            let inventory = provider
                .inventory(&agent_id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(inventory).expect("ClientToolInventory serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );
}
