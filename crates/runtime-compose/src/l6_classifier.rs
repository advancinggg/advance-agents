//! Slice wave6-laneB — production `L6Classifier` adapter (the L6 keystone,
//! SYS-AC-069/216).
//!
//! Lives in `crates/cli` (NOT cap-memory) because cap-memory has ZERO cap-llm
//! dependency; cli depends on both, so this adapter bridges the cap-memory
//! crate-internal `L6Classifier` seam to MODULE-009 CONTRACT-081
//! `cap_llm::LlmGatewayInternal::chat` + `cap_llm::try_parse_and_validate` — a
//! near-mechanical clone of `LlmBatchExtractor` (`memory_extractor.rs`).
//!
//! Robustness contract (the whole reason SYS-AC-216 is reachable): EVERY
//! transport/LLM failure AND every malformed/unparseable/oversize LLM output maps
//! to `L6Error::LlmFailure`. The runnable's Step-3 abort then token-checked-releases
//! the lease (so the next trigger retries) and emits `component.error` — it NEVER
//! panics and never silently degrades to a fake "all-consistent" output (which would
//! make the 216 "LLM call fails" trigger unreachable). The prompt is a BOUNDED
//! projection of the cluster/stale/task inputs (respects the §1.6 token budget);
//! the decisions map is bounded to the INPUT cluster_ids so a hallucinated extra
//! cluster cannot inflate the runnable's `contested_clusters` count.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmGatewayInternal};
use cap_memory::l6::{
    ClusterClassification, L6ClassificationInput, L6ClassificationOutput, L6Classifier,
    SkillHealthEntry, TaskSummary,
};

use advance_shared_types::memory::L6Error;

/// Prompt-projection budgets — bound the prompt size (respects the §1.6 LLM token
/// budget; L6 is a cold path but the prompt is still capped).
const PROMPT_ENTRY_BUDGET: usize = 512;
const PROMPT_MAX_CLUSTERS: usize = 16;
const PROMPT_MAX_ENTRIES_PER_CLUSTER: usize = 12;
const PROMPT_MAX_STALE: usize = 20;
const PROMPT_MAX_TASKS: usize = 8;

/// Per-call chat token budget for the (bounded) classification output.
const L6_MAX_TOKENS: u32 = 1024;

/// JSON Schema the classifier output is validated against via
/// `cap_llm::try_parse_and_validate` (which also enforces a 256 KiB input cap).
/// `maxItems`/`maxProperties`/`maxLength` cap a compromised/prompt-injected model's
/// per-run output — an over-cap response fails schema validation → `LlmFailure` →
/// the 216 abort (no partial garbage), not a partial insert. `cluster_decisions`
/// is required (an empty `{}` is valid for a no-cluster run).
const L6_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "cluster_decisions": {
      "type": "object",
      "maxProperties": 64,
      "additionalProperties": { "type": "string", "enum": ["consistent", "contested"] }
    },
    "consolidated_preferences": {
      "type": "array",
      "maxItems": 32,
      "items": { "type": "string", "maxLength": 2048 }
    },
    "task_summaries": {
      "type": "array",
      "maxItems": 32,
      "items": {
        "type": "object",
        "properties": {
          "task_id": { "type": "string", "maxLength": 256 },
          "summary": { "type": "string", "maxLength": 4096 }
        },
        "required": ["task_id", "summary"]
      }
    },
    "skill_health": {
      "type": "array",
      "maxItems": 64,
      "items": {
        "type": "object",
        "properties": {
          "skill": { "type": "string", "maxLength": 256 },
          "status": { "type": "string", "enum": ["healthy", "stale", "unhealthy"] }
        },
        "required": ["skill", "status"]
      }
    }
  },
  "required": ["cluster_decisions"]
}"#;

#[derive(serde::Deserialize)]
struct L6OutputDto {
    #[serde(default)]
    cluster_decisions: HashMap<String, String>,
    #[serde(default)]
    consolidated_preferences: Vec<String>,
    #[serde(default)]
    task_summaries: Vec<TaskSummaryDto>,
    #[serde(default)]
    skill_health: Vec<SkillHealthDto>,
}

#[derive(serde::Deserialize)]
struct TaskSummaryDto {
    task_id: String,
    summary: String,
}

#[derive(serde::Deserialize)]
struct SkillHealthDto {
    skill: String,
    status: String,
}

/// Production `L6Classifier` (slice wave6-laneB). Holds the gateway as a TRAIT
/// OBJECT so unit tests can inject a fake `LlmGatewayInternal`; the live
/// `Arc<LlmGateway>` coerces at the cli composition root and is INJECTED into
/// `attach_l6` (the system-acceptance harness keeps `StubL6Classifier`).
pub struct LlmL6Classifier {
    gateway: Arc<dyn LlmGatewayInternal + Send + Sync>,
    model: Option<String>,
}

impl LlmL6Classifier {
    pub fn new(gateway: Arc<dyn LlmGatewayInternal + Send + Sync>, model: Option<String>) -> Self {
        Self { gateway, model }
    }

    /// Build the BOUNDED user-prompt projection: previews/caps each cluster's
    /// member contents, the stale-candidate contents, and the completed-task refs.
    fn build_user_prompt(input: &L6ClassificationInput) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "L6 cross-task consolidation for agent {} (batch {}).\n",
            input.agent_id, input.batch_id
        ));
        s.push_str(&format!(
            "Clusters to classify ({} total, showing up to {}):\n",
            input.clusters.len(),
            PROMPT_MAX_CLUSTERS
        ));
        for (assignment, entries) in input.clusters.iter().take(PROMPT_MAX_CLUSTERS) {
            s.push_str(&format!(
                "- cluster `{}` ({} entries):\n",
                assignment.cluster_id,
                entries.len()
            ));
            for e in entries.iter().take(PROMPT_MAX_ENTRIES_PER_CLUSTER) {
                s.push_str(&format!(
                    "    - {}\n",
                    bounded_str(&e.content, PROMPT_ENTRY_BUDGET)
                ));
            }
        }
        s.push_str(&format!(
            "\nStale candidates ({} total, showing up to {}):\n",
            input.stale_candidates.len(),
            PROMPT_MAX_STALE
        ));
        for e in input.stale_candidates.iter().take(PROMPT_MAX_STALE) {
            s.push_str(&format!(
                "- {}\n",
                bounded_str(&e.content, PROMPT_ENTRY_BUDGET)
            ));
        }
        s.push_str(&format!(
            "\nCompleted tasks ({} total, showing up to {}):\n",
            input.completed_tasks.len(),
            PROMPT_MAX_TASKS
        ));
        for t in input.completed_tasks.iter().take(PROMPT_MAX_TASKS) {
            s.push_str(&format!("- task `{}` ({} turns)\n", t.task_id, t.turns));
        }
        s.push_str(
            "\nFor EACH listed cluster id, decide `consistent` (members agree) or \
             `contested` (members conflict). Optionally propose durable \
             `consolidated_preferences`, per-task `task_summaries`, and `skill_health` \
             ({skill, status: healthy|stale|unhealthy}). Respond ONLY with JSON matching the schema.",
        );
        s
    }
}

/// Truncate `s` to at most `budget` bytes at a char boundary; append `…` if cut.
fn bounded_str(s: &str, budget: usize) -> String {
    if s.len() <= budget {
        return s.to_string();
    }
    let mut end = budget;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push('…');
    out
}

#[async_trait]
impl L6Classifier for LlmL6Classifier {
    async fn classify(
        &self,
        input: &L6ClassificationInput,
    ) -> Result<L6ClassificationOutput, L6Error> {
        let messages = vec![
            ChatMessage {
                role: ChatRole::System,
                content: format!(
                    "You are an L6 memory-consolidation classifier. Read the clusters and \
                     respond ONLY with JSON matching this schema:\n{L6_SCHEMA}"
                ),
            },
            ChatMessage {
                role: ChatRole::User,
                content: Self::build_user_prompt(input),
            },
        ];
        let params = ChatParams {
            model: self.model.clone(),
            temperature: Some(0.0),
            max_tokens: Some(L6_MAX_TOKENS),
            ..Default::default()
        };

        // Transport/LLM failure → L6Error::LlmFailure (the 216 abort). Coarse
        // variant name only — never echo provider error detail.
        let resp = self
            .gateway
            .chat(messages, params)
            .await
            .map_err(|e| L6Error::LlmFailure(format!("chat: {}", e.variant_name())))?;

        // Malformed / unparseable / oversize output → ALSO L6Error::LlmFailure
        // (never panic). Makes SYS-AC-216 witnessable + fuzz-safe.
        let bytes = cap_llm::try_parse_and_validate(&resp.text, L6_SCHEMA)
            .map_err(|e| L6Error::LlmFailure(format!("structured-output: {}", e.variant_name())))?;
        let dto: L6OutputDto = serde_json::from_slice(&bytes)
            .map_err(|e| L6Error::LlmFailure(format!("dto-parse: {e}")))?;

        // Bound the decisions map to the INPUT cluster_ids: a hallucinated extra
        // cluster is DROPPED so the runnable's `contested_clusters` count (derived
        // from `cluster_decisions.values()`) cannot inflate. A missing decision
        // defaults to Consistent (the conservative no-synthesis-block choice).
        let mut cluster_decisions = HashMap::with_capacity(input.clusters.len());
        for (assignment, _) in &input.clusters {
            let decision = match dto
                .cluster_decisions
                .get(&assignment.cluster_id)
                .map(String::as_str)
            {
                Some("contested") => ClusterClassification::Contested,
                _ => ClusterClassification::Consistent,
            };
            cluster_decisions.insert(assignment.cluster_id.clone(), decision);
        }

        let task_summaries = dto
            .task_summaries
            .into_iter()
            .map(|t| TaskSummary {
                task_id: t.task_id,
                summary: t.summary,
            })
            .collect();
        let skill_health = dto
            .skill_health
            .into_iter()
            .map(|h| SkillHealthEntry {
                skill: h.skill,
                status: h.status,
            })
            .collect();

        Ok(L6ClassificationOutput {
            cluster_decisions,
            consolidated_preferences: dto.consolidated_preferences,
            task_summaries,
            skill_health,
            batch_id: input.batch_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_llm::{ChatDelta, ChatResponse, LlmError};
    use cap_memory::l6::{ClusterAssignment, TaskRef};

    /// Configurable fake `LlmGatewayInternal` — `chat()` returns the configured
    /// `Ok(text)` / `Err(LlmError)`. `embed`/`stream` are inert.
    struct FakeGateway {
        chat_result: Result<String, LlmError>,
    }

    #[async_trait]
    impl LlmGatewayInternal for FakeGateway {
        async fn embed(&self, _text: &str) -> Result<Vec<f32>, LlmError> {
            Ok(vec![])
        }
        async fn chat(
            &self,
            _messages: Vec<ChatMessage>,
            _params: ChatParams,
        ) -> Result<ChatResponse, LlmError> {
            match &self.chat_result {
                Ok(text) => Ok(ChatResponse {
                    text: text.clone(),
                    model: "fake".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    finish_reason: "stop".into(),
                    parsed_output: None,
                }),
                Err(e) => Err(e.clone()),
            }
        }
        async fn stream(
            &self,
            _messages: Vec<ChatMessage>,
            _params: ChatParams,
        ) -> Result<
            Box<dyn futures_core::Stream<Item = Result<ChatDelta, LlmError>> + Send + Unpin>,
            LlmError,
        > {
            Err(LlmError::ProviderError(
                "stream unused in l6 classifier tests".into(),
            ))
        }
    }

    fn gw(chat_result: Result<String, LlmError>) -> Arc<dyn LlmGatewayInternal + Send + Sync> {
        Arc::new(FakeGateway { chat_result })
    }

    fn cluster(id: &str) -> (ClusterAssignment, Vec<cap_memory::MemoryEntry>) {
        (
            ClusterAssignment {
                cluster_id: id.into(),
                entry_ids: vec![],
            },
            vec![],
        )
    }

    fn input() -> L6ClassificationInput {
        L6ClassificationInput {
            agent_id: "agent:a".into(),
            batch_id: "b0c1d2e3".into(),
            stale_candidates: vec![],
            clusters: vec![cluster("cl-a-b0c1d2e3"), cluster("cl-b-b0c1d2e3")],
            completed_tasks: vec![TaskRef {
                task_id: "t1".into(),
                turns: 5,
            }],
        }
    }

    /// L1-valid (069 shape) + L1-bound: schema-valid JSON → correct mapped output;
    /// a HALLUCINATED extra cluster_id is DROPPED (output bounded to input clusters);
    /// `batch_id` echoes the input.
    #[tokio::test]
    async fn l1_valid_output_maps_and_bounds_to_input_clusters() {
        let json = r#"{
          "cluster_decisions": {
            "cl-a-b0c1d2e3": "contested",
            "cl-b-b0c1d2e3": "consistent",
            "cl-hallucinated": "contested"
          },
          "consolidated_preferences": ["prefer-concise"],
          "task_summaries": [{"task_id":"t1","summary":"finished t1"}],
          "skill_health": [{"skill":"summarize-pr","status":"unhealthy"}]
        }"#;
        let c = LlmL6Classifier::new(gw(Ok(json.to_string())), None);
        let inp = input();

        // The prompt is bounded.
        let prompt = LlmL6Classifier::build_user_prompt(&inp);
        assert!(prompt.contains("cl-a-b0c1d2e3"));
        assert!(prompt.len() < 64 * 1024, "prompt is bounded");

        let out = c.classify(&inp).await.expect("valid output → Ok");
        assert_eq!(out.batch_id, "b0c1d2e3");
        assert_eq!(
            out.cluster_decisions["cl-a-b0c1d2e3"],
            ClusterClassification::Contested
        );
        assert_eq!(
            out.cluster_decisions["cl-b-b0c1d2e3"],
            ClusterClassification::Consistent
        );
        // L1-bound: the hallucinated cluster is NOT in the output map.
        assert!(!out.cluster_decisions.contains_key("cl-hallucinated"));
        assert_eq!(out.cluster_decisions.len(), 2);
        assert_eq!(out.consolidated_preferences, vec!["prefer-concise"]);
        assert_eq!(out.task_summaries.len(), 1);
        assert_eq!(out.task_summaries[0].task_id, "t1");
        assert_eq!(out.skill_health.len(), 1);
        assert_eq!(out.skill_health[0].skill, "summarize-pr");
        assert_eq!(out.skill_health[0].status, "unhealthy");
    }

    /// L1-fail (216 shape): malformed outputs + transport errors ALL map to
    /// `L6Error::LlmFailure` — never panic, never a fake all-consistent output.
    #[tokio::test]
    async fn l1_malformed_and_transport_failures_all_map_to_llmfailure() {
        let inp = input();
        let cases: Vec<Result<String, LlmError>> = vec![
            Ok(String::new()),                                   // empty
            Ok("not json at all".into()),                        // non-JSON
            Ok("```json\n{ broken".into()),                      // fenced but invalid
            Ok(r#"{"consolidated_preferences":[]}"#.into()), // missing required cluster_decisions
            Ok(r#"{"cluster_decisions":12345}"#.into()),     // wrong type (schema violation)
            Ok(r#"{"cluster_decisions":{"x":"maybe"}}"#.into()), // bad enum value
            Ok("{\u{0}\u{1}\u{2}}".into()),                  // control chars
            Ok(format!(
                "{{\"cluster_decisions\":{{\"x\":\"{}\"}}}}",
                "y".repeat(400_000)
            )), // > 256 KiB cap
            Err(LlmError::RateLimited("429".into())),        // transport
            Err(LlmError::ProviderError("boom".into())),
            Err(LlmError::ContextTooLong("too long".into())),
        ];
        for case in cases {
            let c = LlmL6Classifier::new(gw(case), None);
            match c.classify(&inp).await {
                Err(L6Error::LlmFailure(_)) => {}
                other => panic!("expected LlmFailure, got {other:?}"),
            }
        }
    }

    /// An empty-but-valid `cluster_decisions` (no clusters in input) succeeds with
    /// an empty output map — a minimal valid L6 output.
    #[tokio::test]
    async fn l1_empty_cluster_decisions_is_valid() {
        let inp = L6ClassificationInput {
            agent_id: "agent:a".into(),
            batch_id: "bb".into(),
            stale_candidates: vec![],
            clusters: vec![],
            completed_tasks: vec![],
        };
        let c = LlmL6Classifier::new(gw(Ok(r#"{"cluster_decisions":{}}"#.into())), None);
        let out = c.classify(&inp).await.expect("empty decisions → Ok");
        assert!(out.cluster_decisions.is_empty());
        assert!(out.consolidated_preferences.is_empty());
        assert!(out.skill_health.is_empty());
        assert_eq!(out.batch_id, "bb");
    }
}
