//! Catalog-driven default guest: a bounded generate → invoke-callable loop.
//!
//! Targets `advance-host-callables` (imports `agent-llm` + `agent-callables`).
//! On each inbound message the guest:
//!   1. calls `list-callables` once (keeps the import live);
//!   2. calls `generate` with `callables: all` and `transcript: continue`;
//!   3. if `parsed-output` is the host envelope `{"tool_calls":[...]}`,
//!      dispatches each call through `invoke-callable`;
//!   4. repeats with an empty prompt until the envelope is empty, or 8 rounds;
//!   5. if the 8th round still returned tool calls, invokes them, then performs
//!      ONE closing `generate("", callables: none, transcript: continue)` so
//!      the model must answer in text (ADR 2026-10-24 D7 / A2).
//!
//! No text parsing, no DSML. WIT `llm-response` stays 6 fields; tool calls
//! travel in `parsed-output`. Host bindgen world ≠ guest world — only the
//! exports must match; imports are satisfied by the CapabilityInjector.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-callables",
});

use advance::runtime::agent_callables;
use advance::runtime::agent_llm::{self, CallableSelection, LlmParams, LlmRequest, TranscriptMode};
use advance::runtime::types::{
    Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct CallablesGuest;

const MAX_ROUNDS: usize = 8;

struct Call {
    id: String,
    name: String,
    arguments: String,
}

impl MessageDrivenGuest for CallablesGuest {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let user = String::from_utf8(msg.payload.clone()).unwrap_or_default();
        let _ = agent_callables::list_callables();

        let params = Some(LlmParams {
            model: None,
            temperature: None,
            max_tokens: None,
            stop_sequences: None,
            tools: None,
            callables: Some(CallableSelection::All),
            transcript: Some(TranscriptMode::Continue),
        });

        let mut last_text = String::new();
        let mut last_result = String::new();
        let mut last_had_calls = false;

        for round in 0..MAX_ROUNDS {
            let prompt = if round == 0 {
                user.clone()
            } else {
                String::new()
            };
            let request = LlmRequest {
                task_id: None,
                prompt,
                params: params.clone(),
                output_schema: None,
            };
            let response =
                agent_llm::generate(&request).map_err(|e| format!("llm_generate_failed: {e:?}"))?;
            last_text = response.text.clone();

            let calls = response
                .parsed_output
                .as_deref()
                .map(parse_tool_calls)
                .unwrap_or_default();
            if calls.is_empty() {
                last_had_calls = false;
                break;
            }
            last_had_calls = true;

            for (i, call) in calls.iter().enumerate() {
                let id = if call.id.is_empty() {
                    format!("r{round}-{i}")
                } else {
                    call.id.clone()
                };
                let arguments = if call.arguments.is_empty() {
                    "{}".to_string()
                } else {
                    call.arguments.clone()
                };
                match agent_callables::invoke_callable(&id, &call.name, &arguments) {
                    Ok(result) => last_result = result.content,
                    Err(e) => last_result = format!("invoke failed: {e:?}"),
                }
            }
        }

        if last_had_calls {
            let request = LlmRequest {
                task_id: None,
                prompt: String::new(),
                params: Some(LlmParams {
                    model: None,
                    temperature: None,
                    max_tokens: None,
                    stop_sequences: None,
                    tools: None,
                    callables: None,
                    transcript: Some(TranscriptMode::Continue),
                }),
                output_schema: None,
            };
            let response =
                agent_llm::generate(&request).map_err(|e| format!("llm_generate_failed: {e:?}"))?;
            last_text = response.text.clone();
        }

        let payload = if last_text.trim().is_empty() {
            last_result
        } else {
            last_text
        };

        Ok(ActionResult {
            new_state: Vec::new(),
            actions: vec![Action {
                payload: payload.into_bytes(),
            }],
        })
    }
}

impl RunnableGuest for CallablesGuest {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

fn parse_tool_calls(bytes: &[u8]) -> Vec<Call> {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let Some(arr_at) = find_key_array(s, "tool_calls") else {
        return Vec::new();
    };
    parse_object_array(&s[arr_at..])
}

fn find_key_array(s: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(rel) = s[from..].find(&needle) {
        let k = from + rel;
        let mut i = skip_ws(s, k + needle.len());
        if s.as_bytes().get(i) == Some(&b':') {
            i = skip_ws(s, i + 1);
            if s.as_bytes().get(i) == Some(&b'[') {
                return Some(i);
            }
        }
        from = k + needle.len();
    }
    None
}

fn parse_object_array(s: &str) -> Vec<Call> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = skip_ws(s, 0);
    if i >= b.len() || b[i] != b'[' {
        return out;
    }
    i += 1;
    loop {
        i = skip_ws(s, i);
        if i >= b.len() {
            break;
        }
        match b[i] {
            b']' => break,
            b',' => {
                i += 1;
                continue;
            }
            b'{' => {
                let Some(end) = skip_balanced(s, i) else {
                    break;
                };
                if let Some(call) = parse_call_object(&s[i..end]) {
                    out.push(call);
                }
                i = end;
            }
            _ => break,
        }
    }
    out
}

fn parse_call_object(obj: &str) -> Option<Call> {
    let name = json_field(obj, "name").unwrap_or_default();
    if name.is_empty() {
        return None;
    }
    let id = json_field(obj, "id").unwrap_or_default();
    let arguments = json_field(obj, "arguments")
        .unwrap_or_else(|| json_raw_object_field(obj, "arguments").unwrap_or_else(|| "{}".into()));
    Some(Call {
        id,
        name,
        arguments,
    })
}

fn json_field(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(rel) = obj[from..].find(&needle) {
        let k = from + rel;
        let mut i = skip_ws(obj, k + needle.len());
        if obj.as_bytes().get(i) == Some(&b':') {
            i = skip_ws(obj, i + 1);
            return parse_json_atom(obj, i).map(|(v, _)| v);
        }
        from = k + needle.len();
    }
    None
}

fn json_raw_object_field(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(rel) = obj[from..].find(&needle) {
        let k = from + rel;
        let mut i = skip_ws(obj, k + needle.len());
        if obj.as_bytes().get(i) == Some(&b':') {
            i = skip_ws(obj, i + 1);
            if obj.as_bytes().get(i) == Some(&b'{') {
                let end = skip_balanced(obj, i)?;
                return Some(obj[i..end].to_string());
            }
        }
        from = k + needle.len();
    }
    None
}

fn parse_json_atom(s: &str, i: usize) -> Option<(String, usize)> {
    let i = skip_ws(s, i);
    let b = s.as_bytes();
    if i >= b.len() {
        return None;
    }
    match b[i] {
        b'"' => parse_string(s, i),
        b'{' | b'[' => {
            let end = skip_balanced(s, i)?;
            Some((s[i..end].to_string(), end))
        }
        b't' if s[i..].starts_with("true") => Some(("true".into(), i + 4)),
        b'f' if s[i..].starts_with("false") => Some(("false".into(), i + 5)),
        b'n' if s[i..].starts_with("null") => Some((String::new(), i + 4)),
        b'-' | b'0'..=b'9' => {
            let mut end = i + 1;
            while end < b.len()
                && (b[end].is_ascii_digit() || matches!(b[end], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                end += 1;
            }
            Some((s[i..end].to_string(), end))
        }
        _ => None,
    }
}

fn parse_string(s: &str, i: usize) -> Option<(String, usize)> {
    let b = s.as_bytes();
    if i >= b.len() || b[i] != b'"' {
        return None;
    }
    let mut out = String::new();
    let mut i = i + 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                i += 1;
                if i >= b.len() {
                    return None;
                }
                match b[i] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'/' => out.push('/'),
                    b'u' => {
                        if i + 4 >= b.len() {
                            return None;
                        }
                        let hex = s.get(i + 1..i + 5)?;
                        let code = u32::from_str_radix(hex, 16).ok()?;
                        if let Some(ch) = char::from_u32(code) {
                            out.push(ch);
                        }
                        i += 4;
                    }
                    c => out.push(c as char),
                }
                i += 1;
            }
            _ => {
                let ch = s[i..].chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    None
}

fn skip_balanced(s: &str, start: usize) -> Option<usize> {
    let b = s.as_bytes();
    let open = *b.get(start)?;
    let close = match open {
        b'{' => b'}',
        b'[' => b']',
        _ => return None,
    };
    let mut depth = 0usize;
    let mut i = start;
    let mut in_str = false;
    let mut esc = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_str = true,
            x if x == open => depth += 1,
            x if x == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn skip_ws(s: &str, mut i: usize) -> usize {
    let b = s.as_bytes();
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

export!(CallablesGuest with_types_in crate);
