//! S6 — a turn's requests stay inside the model's window (MODULE-010; PRD §11.3.3 L0 and
//! §11.3.5 budget).
//!
//! The context engine budgets a turn's seed once, when the turn starts: the window of the model
//! the agent chats on less the response reserve (PRD §11.3.5). Each call of the turn then sends
//! that seed with the turn's own transcript, in its L0 view (`LlmGateway::transcript_messages`:
//! an older read of a file that a later read replaces, or a read that a later write made stale,
//! is shortened; PRD §11.3.3). When a request still outgrows the budget, [`fit_request`] makes
//! room in this order. The PRD gives none; the transcript is the turn's working memory and comes
//! first (PRD §11.3.5 Phase 5, before the history of Phase 6):
//!
//! 1. the seed's Tier 3 history sections go (the task's recent turns, their digests and the
//!    epoch summary, [`is_tier3_history`]); Tier 1 and Tier 2, the cache prefix, stay;
//! 2. then the turn's oldest tool results are cut to one line naming their call, all but the
//!    last [`KEEP_LAST_RESULTS`]. Each keeps its role and tool-call id, so no provider sees an
//!    orphan result.
//!
//! What still does not fit is sent as it is. A provider that refuses a request as too long gets
//! one more, fitted to [`RETRY_PERCENT`] % of what was sent ([`retry_budget`]); a second refusal
//! goes back to the guest.

use advance_shared_types::context::is_tier3_history;
use advance_shared_types::token_estimate::tokens_from_bytes;

use crate::gateway::{chat_role_name, ChatMessage, ChatRole, ToolDefinition};

/// How many of the turn's last tool results [`fit_request`] never cuts.
pub(crate) const KEEP_LAST_RESULTS: usize = 2;

/// The share of a refused request's tokens its one retry is fitted to.
pub(crate) const RETRY_PERCENT: usize = 80;

/// The start of the line a cut tool result keeps.
pub(crate) const CUT_RESULT_PREFIX: &str = "[cut to fit the model's context window: ";

/// What [`fit_request`] did to one request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Fit {
    /// The request's tokens before the fit (the shared `bytes / 4` estimate).
    pub tokens_before: usize,
    /// The request's tokens after it.
    pub tokens_after: usize,
    /// Seed history sections dropped.
    pub history_dropped: usize,
    /// Tool results cut to one line.
    pub results_cut: usize,
}

/// The request's size in tokens: every message's role, content, tool calls and tool-call id,
/// and the tools it offers, by the workspace's one `bytes / 4` estimate (the context engine's).
pub(crate) fn request_tokens(messages: &[ChatMessage], tools: &[ToolDefinition]) -> usize {
    tokens_from_bytes(request_bytes(messages).saturating_add(tools_bytes(tools)))
}

fn message_bytes(m: &ChatMessage) -> usize {
    let calls = m
        .tool_calls
        .iter()
        .map(|c| c.id.len() + c.name.len() + c.arguments.len())
        .fold(0usize, usize::saturating_add);
    chat_role_name(m.role)
        .len()
        .saturating_add(m.content.len())
        .saturating_add(calls)
        .saturating_add(m.tool_call_id.as_ref().map_or(0, String::len))
}

fn request_bytes(messages: &[ChatMessage]) -> usize {
    messages
        .iter()
        .map(message_bytes)
        .fold(0usize, usize::saturating_add)
}

fn tools_bytes(tools: &[ToolDefinition]) -> usize {
    tools
        .iter()
        .map(|t| t.name.len() + t.description.len() + t.parameters.to_string().len())
        .fold(0usize, usize::saturating_add)
}

/// The budget the one retry of a refused request is fitted to: [`RETRY_PERCENT`] % of what was
/// sent, and no more than `budget` when the window is known.
pub(crate) fn retry_budget(sent_tokens: usize, budget: Option<usize>) -> usize {
    let smaller = sent_tokens.saturating_mul(RETRY_PERCENT) / 100;
    budget.map_or(smaller, |b| b.min(smaller))
}

/// Fit `messages` into `budget` tokens (module doc). The first `*seed_len` messages are the
/// assembled seed; `*seed_len` drops by the sections taken out of it. A request already inside
/// the budget is left as it is.
pub(crate) fn fit_request(
    messages: &mut Vec<ChatMessage>,
    seed_len: &mut usize,
    tools: &[ToolDefinition],
    budget: usize,
) -> Fit {
    let tool_bytes = tools_bytes(tools);
    let tokens = |bytes: usize| tokens_from_bytes(bytes.saturating_add(tool_bytes));
    let mut bytes = request_bytes(messages);
    let mut fit = Fit {
        tokens_before: tokens(bytes),
        tokens_after: tokens(bytes),
        ..Fit::default()
    };
    if fit.tokens_before <= budget {
        return fit;
    }

    // 1. The seed's Tier 3 history.
    let seed = (*seed_len).min(messages.len());
    let mut index = 0usize;
    let mut dropped = 0usize;
    messages.retain(|m| {
        let in_seed = index < seed;
        index += 1;
        let drop = in_seed && m.role == ChatRole::System && is_tier3_history(&m.content);
        if drop {
            bytes = bytes.saturating_sub(message_bytes(m));
            dropped += 1;
        }
        !drop
    });
    fit.history_dropped = dropped;
    *seed_len = seed - dropped;
    fit.tokens_after = tokens(bytes);

    // 2. The turn's oldest tool results, all but the last KEEP_LAST_RESULTS.
    let results: Vec<usize> = (*seed_len..messages.len())
        .filter(|&i| is_tool_result(&messages[i]))
        .collect();
    let cuttable = results.len().saturating_sub(KEEP_LAST_RESULTS);
    for &i in &results[..cuttable] {
        if fit.tokens_after <= budget {
            break;
        }
        let line = cut_line(messages, i);
        if line.len() >= messages[i].content.len() {
            continue;
        }
        bytes = bytes
            .saturating_sub(messages[i].content.len())
            .saturating_add(line.len());
        messages[i].content = line;
        fit.results_cut += 1;
        fit.tokens_after = tokens(bytes);
    }
    fit
}

/// A tool result of the turn: a tool-role message, or the user message a result becomes when
/// its call is not on the last assistant message (`LlmGateway::record_tool_result`).
fn is_tool_result(m: &ChatMessage) -> bool {
    match m.role {
        ChatRole::Tool => true,
        ChatRole::User => m.content.starts_with("[tool result: "),
        _ => false,
    }
}

/// The line a cut tool result keeps: the name of its call, the file the call names when it
/// names one, and how long the result was.
fn cut_line(messages: &[ChatMessage], i: usize) -> String {
    let result = &messages[i];
    let call = result.tool_call_id.as_deref().and_then(|id| {
        messages[..i]
            .iter()
            .rev()
            .flat_map(|m| m.tool_calls.iter())
            .find(|c| c.id == id)
    });
    let what = match call {
        Some(call) => match call_path(&call.arguments) {
            Some(path) => format!("the result of {}(path={path})", call.name),
            None => format!("the result of {}", call.name),
        },
        None => "a tool result".to_string(),
    };
    format!("{CUT_RESULT_PREFIX}{what}, {} bytes]", result.content.len())
}

/// The `path` a call's arguments name, cut at 200 bytes on a character boundary.
fn call_path(arguments: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(arguments).ok()?;
    let path = v.get("path")?.as_str()?.trim();
    if path.is_empty() {
        return None;
    }
    Some(advance_shared_types::turn_log::truncate_at_char(path, 200).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::ToolCall;

    fn system(text: &str) -> ChatMessage {
        ChatMessage::new(ChatRole::System, text)
    }

    fn call(id: &str, name: &str, path: &str) -> ChatMessage {
        ChatMessage::assistant_with_calls(
            String::new(),
            vec![ToolCall {
                id: id.into(),
                name: name.into(),
                arguments: serde_json::json!({ "path": path }).to_string(),
            }],
        )
    }

    fn history(bytes: usize) -> ChatMessage {
        system(&format!(
            "{}{}",
            advance_shared_types::context::RECENT_TURNS_HEADING,
            "h".repeat(bytes)
        ))
    }

    /// identity, history, prompt, then three read calls with 4 KB results.
    fn turn() -> (Vec<ChatMessage>, usize) {
        let mut m = vec![
            system("IDENTITY"),
            history(8_000),
            ChatMessage::new(ChatRole::User, "go"),
        ];
        let seed = m.len();
        for (id, path) in [("c1", "a.md"), ("c2", "b.md"), ("c3", "c.md")] {
            m.push(call(id, "read", path));
            m.push(ChatMessage::tool(id, "r".repeat(4_000)));
        }
        (m, seed)
    }

    #[test]
    fn a_request_inside_the_budget_is_left_as_it_is() {
        let (mut m, mut seed) = turn();
        let before = m.clone();
        let fit = fit_request(&mut m, &mut seed, &[], 1_000_000);
        assert_eq!(m, before);
        assert_eq!((fit.history_dropped, fit.results_cut), (0, 0));
        assert_eq!(fit.tokens_before, fit.tokens_after);
    }

    #[test]
    fn the_seed_history_goes_first_and_the_cache_prefix_stays() {
        let (mut m, mut seed) = turn();
        let all = request_tokens(&m, &[]);
        // Room for everything but the history.
        let fit = fit_request(&mut m, &mut seed, &[], all - 1_900);
        assert_eq!((fit.history_dropped, fit.results_cut), (1, 0));
        assert_eq!(seed, 2);
        assert_eq!(m[0].content, "IDENTITY");
        assert_eq!(m[1].content, "go");
        assert!(m.iter().all(|x| !is_tier3_history(&x.content)));
        assert!(fit.tokens_after <= all - 1_900);
    }

    #[test]
    fn then_the_oldest_results_are_cut_and_the_last_two_never() {
        let (mut m, mut seed) = turn();
        let fit = fit_request(&mut m, &mut seed, &[], 10);
        assert_eq!((fit.history_dropped, fit.results_cut), (1, 1));
        let results: Vec<&ChatMessage> = m.iter().filter(|x| x.role == ChatRole::Tool).collect();
        assert_eq!(results.len(), 3, "a cut result keeps its message");
        assert_eq!(results[0].tool_call_id.as_deref(), Some("c1"));
        assert_eq!(
            results[0].content,
            format!("{CUT_RESULT_PREFIX}the result of read(path=a.md), 4000 bytes]")
        );
        assert_eq!(results[1].content.len(), 4_000);
        assert_eq!(results[2].content.len(), 4_000);
        assert!(
            fit.tokens_after > 10,
            "what still does not fit is sent as it is"
        );
    }

    #[test]
    fn a_result_shorter_than_its_line_is_kept() {
        let mut m = vec![ChatMessage::new(ChatRole::User, "go")];
        for id in ["c1", "c2", "c3"] {
            m.push(call(id, "read", "a.md"));
            m.push(ChatMessage::tool(id, "ok"));
        }
        let mut seed = 1;
        let fit = fit_request(&mut m, &mut seed, &[], 1);
        assert_eq!(fit.results_cut, 0);
        assert!(m
            .iter()
            .filter(|x| x.role == ChatRole::Tool)
            .all(|x| x.content == "ok"));
    }

    #[test]
    fn a_result_without_its_call_is_named_as_a_tool_result() {
        let mut m = vec![
            ChatMessage::new(
                ChatRole::User,
                format!("[tool result: read]\n{}", "x".repeat(900)),
            ),
            call("c2", "read", "b.md"),
            ChatMessage::tool("c2", "y".repeat(900)),
            call("c3", "read", "c.md"),
            ChatMessage::tool("c3", "z".repeat(900)),
        ];
        let mut seed = 0;
        let fit = fit_request(&mut m, &mut seed, &[], 1);
        assert_eq!(fit.results_cut, 1);
        assert_eq!(m[0].role, ChatRole::User);
        assert_eq!(
            m[0].content,
            format!("{CUT_RESULT_PREFIX}a tool result, 920 bytes]")
        );
    }

    #[test]
    fn a_seed_message_is_never_cut_as_a_result() {
        let mut m = vec![
            ChatMessage::new(
                ChatRole::User,
                format!("[tool result: read]\n{}", "x".repeat(900)),
            ),
            ChatMessage::new(ChatRole::User, "go"),
        ];
        let mut seed = 2;
        let fit = fit_request(&mut m, &mut seed, &[], 1);
        assert_eq!((fit.history_dropped, fit.results_cut), (0, 0));
    }

    #[test]
    fn the_tools_offered_count_toward_the_request() {
        let tools = vec![ToolDefinition {
            name: "read".into(),
            description: "d".repeat(4_000),
            parameters: serde_json::json!({}),
        }];
        let m = vec![ChatMessage::new(ChatRole::User, "go")];
        assert!(request_tokens(&m, &tools) > 1_000);
    }

    #[test]
    fn the_retry_is_fitted_to_80_percent_of_what_was_sent_within_the_budget() {
        assert_eq!(retry_budget(10_000, None), 8_000);
        assert_eq!(retry_budget(10_000, Some(5_000)), 5_000);
        assert_eq!(retry_budget(10_000, Some(9_000)), 8_000);
    }
}
