//! SAT-B (slice satB-postproc) — production `BatchExtractor` adapter (AC-43).
//!
//! Lives in `crates/cli` (NOT cap-memory) because cap-memory has ZERO cap-llm
//! dependency; cli depends on both, so this adapter bridges
//! `cap_memory::BatchExtractor` (the Step-2 extraction seam) to MODULE-009
//! CONTRACT-081 `cap_llm::LlmGatewayInternal::chat` + `cap_llm::try_parse_and_validate`.
//!
//! Robustness contract (the whole reason 213-style fallback is witnessable):
//! EVERY transport/LLM failure AND every malformed/unparseable/oversize LLM
//! output maps to `BatchExtractorError::LlmFailure` — which the post-processor
//! Step 2 turns into the mechanical-digest fallback + cooldown. It NEVER panics
//! and NEVER returns the turn-fatal `Invalid` arm. The prompt is a BOUNDED
//! projection that excludes the opaque guest `new_state` (no state leak to the LLM).

use std::sync::Arc;

use async_trait::async_trait;
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmGatewayInternal};
use cap_memory::{
    BatchExtractor, BatchExtractorError, DescriptionUpdate, Extraction, ExtractionContext,
    MemoryEntry, MemoryStatus, MemoryType,
};

/// Prompt-projection budgets (bytes). Bound the prompt size (respects the §1.6
/// `<3 s` text-only SLO + the token budget) and prevent opaque-state leakage.
const PROMPT_MSG_PAYLOAD_BUDGET: usize = 4096;
const PROMPT_ACTION_BUDGET: usize = 512;
const PROMPT_MAX_ACTIONS: usize = 16;

/// Per-call chat token budget (light extraction).
const EXTRACTION_MAX_TOKENS: u32 = 512;

/// JSON Schema the extraction LLM output is validated against via
/// `cap_llm::try_parse_and_validate` (which also enforces a 256 KiB input cap).
/// Output bounds (satB-postproc adversarial r15 / Codex W2): `maxItems` on the
/// `knowledge` / `descriptions` / `tags` arrays + `maxLength` on the string
/// fields cap a compromised/prompt-injected model's per-turn entry flood — an
/// over-cap response fails schema validation, which maps to `LlmFailure` →
/// the trace-only mechanical-digest fallback (no entries persisted that turn),
/// not a partial garbage insert. Bounds the new per-turn amplification the
/// extractor adds over one-entry-per-`remember()`.
const EXTRACTION_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "digest": { "type": "string", "maxLength": 4096 },
    "descriptions": {
      "type": "array",
      "maxItems": 64,
      "items": {
        "type": "object",
        "properties": {
          "path": { "type": "string", "maxLength": 1024 },
          "description": { "type": "string", "maxLength": 2048 }
        },
        "required": ["path", "description"]
      }
    },
    "knowledge": {
      "type": "array",
      "maxItems": 64,
      "items": {
        "type": "object",
        "properties": {
          "content": { "type": "string", "maxLength": 8192 },
          "tags": { "type": "array", "maxItems": 32, "items": { "type": "string", "maxLength": 128 } },
          "kind": { "type": "string", "enum": ["fact", "user-preference"] }
        },
        "required": ["content"]
      }
    }
  },
  "required": ["digest"]
}"#;

#[derive(serde::Deserialize)]
struct ExtractionDto {
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    descriptions: Vec<DescriptionDto>,
    #[serde(default)]
    knowledge: Vec<KnowledgeDto>,
}

#[derive(serde::Deserialize)]
struct DescriptionDto {
    path: String,
    description: String,
}

#[derive(serde::Deserialize)]
struct KnowledgeDto {
    content: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    kind: Option<String>,
}

/// Production `BatchExtractor` (MODULE-011 AC-43). Holds the gateway as a TRAIT
/// OBJECT so unit tests can inject a fake `LlmGatewayInternal`; `Arc<LlmGateway>`
/// coerces at the composition root.
pub struct LlmBatchExtractor {
    gateway: Arc<dyn LlmGatewayInternal + Send + Sync>,
    model: Option<String>,
}

impl LlmBatchExtractor {
    pub fn new(gateway: Arc<dyn LlmGatewayInternal + Send + Sync>, model: Option<String>) -> Self {
        Self { gateway, model }
    }

    /// Build the BOUNDED user-prompt projection (Codex W1): EXCLUDES
    /// `result.new_state` (opaque guest bytes — never sent to the LLM), and
    /// previews/caps the message payload + a bounded per-action summary.
    fn build_user_prompt(ctx: &ExtractionContext<'_>) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "A turn occurred for agent {}. Message from {} to {} (kind {:?}).\n",
            ctx.agent_id, ctx.msg.from, ctx.msg.to, ctx.msg.kind
        ));
        s.push_str("Message payload (preview, possibly truncated):\n");
        s.push_str(&bounded_utf8(&ctx.msg.payload, PROMPT_MSG_PAYLOAD_BUDGET));
        s.push('\n');
        // NOTE: result.new_state is DELIBERATELY EXCLUDED — it is opaque
        // guest-controlled state and must not leak to the LLM provider.
        s.push_str(&format!(
            "Resulting actions: {} total (showing up to {}).\n",
            ctx.result.actions.len(),
            PROMPT_MAX_ACTIONS
        ));
        for (i, a) in ctx
            .result
            .actions
            .iter()
            .take(PROMPT_MAX_ACTIONS)
            .enumerate()
        {
            s.push_str(&format!(
                "- action[{i}] (preview): {}\n",
                bounded_utf8(&a.payload, PROMPT_ACTION_BUDGET)
            ));
        }
        s.push_str(
            "\nExtract a single-sentence `digest` of this turn, plus any durable `knowledge` \
             items (non-file insights) and file `descriptions`. Respond ONLY with JSON matching the schema.",
        );
        s
    }
}

/// Lossy-decode the first `budget` bytes of `raw`; a byte-boundary cut is
/// patched by `from_utf8_lossy`'s replacement char (never panics).
fn bounded_utf8(raw: &[u8], budget: usize) -> String {
    let end = raw.len().min(budget);
    let mut out = String::from_utf8_lossy(&raw[..end]).into_owned();
    if raw.len() > budget {
        out.push('…');
    }
    out
}

#[async_trait]
impl BatchExtractor for LlmBatchExtractor {
    async fn extract(
        &self,
        ctx: &ExtractionContext<'_>,
    ) -> Result<Extraction, BatchExtractorError> {
        let messages = vec![
            ChatMessage {
                role: ChatRole::System,
                content: format!(
                    "You are a memory-extraction assistant. Read the turn and respond ONLY with \
                     JSON matching this schema:\n{EXTRACTION_SCHEMA}"
                ),
            },
            ChatMessage {
                role: ChatRole::User,
                content: Self::build_user_prompt(ctx),
            },
        ];
        let params = ChatParams {
            model: self.model.clone(),
            temperature: Some(0.0),
            max_tokens: Some(EXTRACTION_MAX_TOKENS),
            ..Default::default()
        };

        // Transport/LLM failure → soft degrade (mechanical-digest fallback +
        // cooldown). Coarse variant name only — never echo provider error detail.
        let resp =
            self.gateway.chat(messages, params).await.map_err(|e| {
                BatchExtractorError::LlmFailure(format!("chat: {}", e.variant_name()))
            })?;

        // Malformed / unparseable / oversize output → ALSO soft degrade (NOT the
        // turn-fatal `Invalid` arm). Makes SYS-AC-213 witnessable + fuzz-safe.
        let bytes =
            cap_llm::try_parse_and_validate(&resp.text, EXTRACTION_SCHEMA).map_err(|e| {
                BatchExtractorError::LlmFailure(format!("structured-output: {}", e.variant_name()))
            })?;
        let dto: ExtractionDto = serde_json::from_slice(&bytes)
            .map_err(|e| BatchExtractorError::LlmFailure(format!("dto-parse: {e}")))?;

        let created_at = cap_memory::clock_now_rfc3339_z(&cap_memory::SystemClock);
        let task_origin = ctx.msg.context.as_ref().and_then(|c| c.task_id.clone());

        let mut knowledge = Vec::with_capacity(dto.knowledge.len());
        for k in dto.knowledge {
            let entry = MemoryEntry {
                id: uuid::Uuid::new_v4().to_string(),
                agent_id: ctx.agent_id.to_string(),
                entry_type: match k.kind.as_deref() {
                    Some("user-preference") => MemoryType::UserPreference,
                    _ => MemoryType::Fact,
                },
                content: k.content,
                tags: k.tags,
                created_at: created_at.clone(),
                task_origin: task_origin.clone(),
                is_active: true,
                superseded_by: None,
                status: MemoryStatus::Active,
                supersession_reason: None,
                cluster_id: None,
                sources: vec![],
            };
            // Defensive: a constructed entry that somehow violates the
            // status↔active invariants degrades softly rather than hard-failing
            // (Step 5's apply_action would otherwise reject it).
            entry
                .validate_invariants()
                .map_err(|e| BatchExtractorError::LlmFailure(format!("entry-invariant: {e}")))?;
            knowledge.push(entry);
        }

        let descriptions = dto
            .descriptions
            .into_iter()
            .map(|d| DescriptionUpdate {
                path: d.path,
                description: d.description,
            })
            .collect();

        Ok(Extraction {
            descriptions,
            knowledge,
            digest: dto.digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use advance_shared_types::mailbox::{ActionResult, AgentAction, Message, MessageKind};
    use cap_llm::{ChatDelta, ChatResponse, LlmError};

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
                "stream unused in extractor tests".into(),
            ))
        }
    }

    fn gw(chat_result: Result<String, LlmError>) -> Arc<dyn LlmGatewayInternal + Send + Sync> {
        Arc::new(FakeGateway { chat_result })
    }

    fn msg() -> Message {
        Message {
            id: "m1".into(),
            kind: MessageKind::User,
            from: "user:t".into(),
            to: "agent:default".into(),
            payload: b"please refactor the tokenizer".to_vec(),
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        }
    }
    fn res() -> ActionResult {
        ActionResult {
            // Opaque guest state that MUST NOT reach the prompt.
            new_state: b"SECRET-STATE-DO-NOT-LEAK".to_vec(),
            actions: vec![AgentAction {
                payload: b"reply: done".to_vec(),
            }],
        }
    }

    /// T51 (AC-43): valid schema JSON → correct `Extraction`; the built prompt
    /// EXCLUDES `new_state` and previews the message payload.
    #[tokio::test]
    async fn t51_valid_output_maps_to_extraction_and_prompt_excludes_new_state() {
        let json = r#"{"digest":"Refactored the tokenizer","knowledge":[{"content":"the tokenizer is now table-driven","tags":["parser"],"kind":"fact"}],"descriptions":[{"path":"src/tok.rs","description":"table-driven tokenizer"}]}"#;
        let extractor = LlmBatchExtractor::new(gw(Ok(json.to_string())), None);
        let m = msg();
        let r = res();
        let ctx = ExtractionContext {
            agent_id: "agent:default",
            msg: &m,
            result: &r,
        };

        let prompt = LlmBatchExtractor::build_user_prompt(&ctx);
        assert!(
            !prompt.contains("SECRET-STATE-DO-NOT-LEAK"),
            "result.new_state must NOT leak into the prompt"
        );
        assert!(
            prompt.contains("refactor the tokenizer"),
            "payload preview present"
        );
        assert!(prompt.len() < 64 * 1024, "prompt is bounded");

        let ex = extractor.extract(&ctx).await.expect("valid output → Ok");
        assert_eq!(ex.digest.as_deref(), Some("Refactored the tokenizer"));
        assert_eq!(ex.knowledge.len(), 1);
        assert_eq!(ex.knowledge[0].content, "the tokenizer is now table-driven");
        assert_eq!(ex.knowledge[0].agent_id, "agent:default");
        assert_eq!(ex.knowledge[0].entry_type, MemoryType::Fact);
        assert_eq!(ex.descriptions.len(), 1);
        assert_eq!(ex.descriptions[0].path, "src/tok.rs");
    }

    /// T52 (AC-43, fuzz): malformed outputs + transport errors ALL map to
    /// `LlmFailure` — never panic, never the turn-fatal `Invalid`.
    #[tokio::test]
    async fn t52_malformed_and_transport_failures_all_degrade_to_llmfailure() {
        let m = msg();
        let r = res();
        let ctx = ExtractionContext {
            agent_id: "a",
            msg: &m,
            result: &r,
        };

        let cases: Vec<Result<String, LlmError>> = vec![
            Ok(String::new()),                                         // empty
            Ok("not json at all".into()),                              // non-JSON
            Ok("```json\n{ broken".into()),                            // fenced but invalid
            Ok(r#"{"knowledge":[]}"#.into()),                          // missing required "digest"
            Ok(r#"{"digest":12345}"#.into()), // wrong type (schema violation)
            Ok("{\u{0}\u{1}\u{2}}".into()),   // control chars
            Ok(format!("{{\"digest\":\"{}\"}}", "x".repeat(400_000))), // > 256 KiB input cap
            Err(LlmError::RateLimited("429".into())), // transport
            Err(LlmError::ProviderError("boom".into())),
            Err(LlmError::ContextTooLong("too long".into())),
        ];
        for case in cases {
            let extractor = LlmBatchExtractor::new(gw(case), None);
            match extractor.extract(&ctx).await {
                Err(BatchExtractorError::LlmFailure(_)) => {}
                other => panic!("expected LlmFailure, got {other:?}"),
            }
        }
    }

    /// T52b (AC-43, adversarial r15 / Codex W2): a SCHEMA-VALID-shaped but
    /// OVER-CAP LLM output — a `knowledge` array beyond `maxItems` (64), or a
    /// `content` beyond `maxLength` (8192) — fails schema validation and degrades
    /// to `LlmFailure` (no partial garbage insert), bounding a prompt-injected
    /// model's per-turn entry flood. An at-cap (64-entry) response still succeeds.
    #[tokio::test]
    async fn t52b_over_cap_extraction_output_degrades_to_llmfailure() {
        let m = msg();
        let r = res();
        let ctx = ExtractionContext {
            agent_id: "a",
            msg: &m,
            result: &r,
        };

        // 65 knowledge entries (> maxItems 64) → schema-invalid.
        let many: String = (0..65)
            .map(|i| format!(r#"{{"content":"k{i}","kind":"fact"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let flood = format!(r#"{{"digest":"d","knowledge":[{many}]}}"#);
        // One entry whose content exceeds maxLength 8192 → schema-invalid.
        let huge = "x".repeat(9000);
        let oversize = format!(r#"{{"digest":"d","knowledge":[{{"content":"{huge}"}}]}}"#);

        for bad in [flood, oversize] {
            let extractor = LlmBatchExtractor::new(gw(Ok(bad)), None);
            match extractor.extract(&ctx).await {
                Err(BatchExtractorError::LlmFailure(_)) => {}
                other => panic!("over-cap output must degrade to LlmFailure, got {other:?}"),
            }
        }

        // Control: an at-cap (64-entry), well-formed response still succeeds.
        let ok_many: String = (0..64)
            .map(|i| format!(r#"{{"content":"k{i}","kind":"fact"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let ok = format!(r#"{{"digest":"d","knowledge":[{ok_many}]}}"#);
        let extractor = LlmBatchExtractor::new(gw(Ok(ok)), None);
        let ex = extractor.extract(&ctx).await.expect("at-cap output → Ok");
        assert_eq!(ex.knowledge.len(), 64, "all 64 at-cap entries kept");
    }
}
