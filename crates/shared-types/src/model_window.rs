//! The context window a model is budgeted with (MODULE-010 D5, PRD §11.3.5
//! `llm_gateway.get_context_window()`), shared by the context engine, which budgets a turn's
//! assembly with it, and the gateway, which keeps the turn's later requests inside it (S6).
//!
//! A provider entry's declared window for the model wins (`model-context-windows`, or the
//! entry's catalog profile); this table is what both fall back to: the published window of the
//! model's family. Pure, no I/O, deterministic.

/// Fail-safe-small context window for any model the [`model_context_window`]
/// table does not recognize (the common provider floor). A budget guard MUST
/// under-estimate an unknown window — over-estimating would pack a prompt
/// that overflows a real small provider limit, inverting REQ-239.
pub const SMALL_MODEL_WINDOW: usize = 8_192;

/// The context window of `model`: its family's (see [`family_context_window`]), else the
/// fail-safe-small [`SMALL_MODEL_WINDOW`].
///
/// The table holds ONLY real model families with documented real windows.
/// Any unrecognized / unknown / spoofed string falls through to the
/// fail-safe-small [`SMALL_MODEL_WINDOW`] (the safe direction for a
/// context-budget guard — never over-estimate an unknown window). There are
/// **no test-only entries** in this production table; tests drive behavior
/// via the exported pure functions + the fail-safe default.
pub fn model_context_window(model: &str) -> usize {
    family_context_window(model).unwrap_or(SMALL_MODEL_WINDOW)
}

/// The published context window of `model`'s family, or `None` for a model the table does
/// not know (the caller then falls back to [`SMALL_MODEL_WINDOW`]).
pub fn family_context_window(model: &str) -> Option<usize> {
    let model = normalize_model_id(model);
    let m = model.as_str();
    // Real model families (documented public context windows). Prefix match
    // tolerates dated/suffixed variants (e.g. `gpt-4o-2024-11-20`). Where a
    // family ships several windows the SMALLER documented one is used (a
    // budget guard must never over-estimate).
    let has = |p: &str| m.starts_with(p);
    Some(if has("claude-2") || has("claude-instant") {
        100_000
    } else if has("claude-") {
        200_000
    } else if has("gpt-5") && m.contains("-chat") {
        // GPT-5 Chat and its later releases (`gpt-5.1-chat-latest`): 128K.
        128_000
    } else if has("gpt-5") {
        // 400K in all, of which at most 272K input.
        272_000
    } else if has("gpt-4.1") {
        1_000_000
    } else if has("o1-mini") || has("o1-preview") {
        128_000
    } else if has("o1") || has("o3") || has("o4") {
        200_000
    } else if has("gpt-4o") || has("gpt-4-turbo") || has("chatgpt-4o") {
        128_000
    } else if has("gpt-4-32k") {
        32_768
    } else if has("gpt-4") {
        8_192
    } else if has("gpt-3.5-turbo-instruct") {
        4_096
    } else if has("gpt-3.5-turbo") {
        16_385
    } else if has("gemini-") && (m.contains("-native-audio") || m.contains("-live")) {
        // Gemini's Live API models: 128K input, from 32K (the first native-audio preview's
        // default).
        32_768
    } else if has("gemini-") && m.contains("-tts") {
        // Gemini's speech models (`gemini-2.5-flash-preview-tts`): 8K input.
        8_192
    } else if has("gemini-") && m.contains("-image") {
        // Gemini's image models: from 32K input (`gemini-2.0-flash-preview-image-generation`).
        32_000
    } else if has("gemini-1.5") || has("gemini-2") || has("gemini-3") {
        1_000_000
    } else if has("deepseek-v4") {
        // DeepSeek V4 (NEAR AI lists `deepseek-ai/DeepSeek-V4.1-Flash-1017` at 1 048 576).
        1_048_576
    } else if has("deepseek-coder") && !has("deepseek-coder-v2") {
        // DeepSeek-Coder: 16K, and 4K for its v1.5; DeepSeek-Coder-V2: 128K.
        4_096
    } else if has("deepseek") {
        128_000
    } else if has("qwen3-max") || has("qwen-plus") || has("qwen-turbo") {
        128_000
    } else if has("qwen-max") {
        // Qwen-Max (Qwen2.5-Max): 32K, of which at most 30,720 input.
        32_768
    } else if has("qwen") {
        // The Qwen3 open models serve 32K natively (128K only with YaRN scaling).
        32_768
    } else if has("llama-3.1") || has("llama-3.2") || has("llama-3.3") || has("llama3.1") {
        128_000
    } else if has("llama-4") || has("llama4") {
        256_000
    } else if has("llama") {
        8_192
    } else if has("mistral-large-2402") || has("mistral-medium-2312") {
        // Mistral Large 1 and the first Mistral Medium: 32K.
        32_768
    } else if has("mistral-large") || has("mistral-medium") {
        128_000
    } else if has("mistral-small") {
        // Mistral Small 3 (2501): 32K; 3.1 and later: 128K.
        32_768
    } else if has("mixtral") || has("mistral") {
        32_768
    } else if has("moonshot-v1-8k") {
        8_192
    } else if has("moonshot-v1-32k") {
        32_768
    } else if has("kimi-k2") || has("moonshot") {
        128_000
    } else if has("glm-4v-plus") || has("glm-4v-flash") || has("glm-4-airx") {
        8_192
    } else if has("glm-4v") {
        // GLM-4V: 2K.
        2_048
    } else if has("glm-4.5v") || has("glm-4.1v") {
        // GLM-4.5V and GLM-4.1V-Thinking: 64K.
        64_000
    } else if has("glm-4.5") || has("glm-4.6") || has("glm-5") {
        128_000
    } else if has("glm-4") {
        128_000
    } else if has("grok-4") {
        256_000
    } else if has("grok-3") {
        131_072
    } else if has("command-a") || has("command-r") {
        128_000
    } else if has("phi-4") {
        16_384
    } else if has("gemma-3") || has("gemma3") {
        // Gemma 3 1B and 270M: 32K; 4B and larger: 128K.
        32_768
    } else if has("gemma") {
        8_192
    } else {
        // Unknown / unrecognized / spoofed → the caller's fail-safe-small window.
        return None;
    })
}

/// Canonicalize a model id for the window table: lower-case, trimmed, with a
/// vendor / route prefix (`anthropic/claude-…`, `openai:gpt-4o`, `models/gemini-…`)
/// and a `-latest` / `:latest` suffix stripped. Pure.
pub fn normalize_model_id(model: &str) -> String {
    let mut m = model.trim().to_ascii_lowercase();
    if let Some(idx) = m.rfind('/') {
        m = m[idx + 1..].to_string();
    }
    if let Some(idx) = m.rfind(':') {
        // `openai:gpt-4o` (route prefix) or `llama3.1:70b` (tag suffix). Only treat
        // the colon as a prefix separator when the LEFT side has no digit — a tag
        // like `:70b` / `:latest` is dropped instead.
        let (left, right) = m.split_at(idx);
        if left.chars().any(|c| c.is_ascii_digit()) {
            m = left.to_string();
        } else {
            m = right[1..].to_string();
        }
    }
    if let Some(stripped) = m.strip_suffix("-latest") {
        m = stripped.to_string();
    }
    m
}

/// §1.3.7 response reservation: `min(model_limit * 0.15, 30_000)`. Integer
/// math (no float — deterministic): `model_limit * 15 / 100`, saturating mul,
/// capped at 30_000. (8_192 → 1_228; 200_000 → 30_000.)
pub fn response_reserve(model_limit: usize) -> usize {
    (model_limit.saturating_mul(15) / 100).min(30_000)
}

/// The tokens a request may take in a window of `model_limit`: the window less the
/// [`response_reserve`] (PRD §11.3.5 `budget = model_limit - response_reserve`).
pub fn request_budget(model_limit: usize) -> usize {
    model_limit.saturating_sub(response_reserve(model_limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_is_the_window_less_the_reserve() {
        assert_eq!(request_budget(8_192), 8_192 - 1_228);
        assert_eq!(request_budget(1_048_576), 1_048_576 - 30_000);
        assert_eq!(request_budget(0), 0);
    }

    #[test]
    fn a_routed_deepseek_v4_id_gets_its_family_window() {
        assert_eq!(
            family_context_window("deepseek-ai/DeepSeek-V4.1-Flash-1017"),
            Some(1_048_576)
        );
        assert_eq!(family_context_window("not-a-model"), None);
        assert_eq!(model_context_window("not-a-model"), SMALL_MODEL_WINDOW);
    }
}
