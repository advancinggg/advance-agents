//! Reference LLM+tools guest: a bounded tool loop inside `handle-message`.
//!
//! Targets `advance-host-llm-fs` (imports `agent-llm` + `agent-fs`). On each
//! inbound message the guest:
//!   1. calls `agent-llm::generate` with `params.tools` (write / list / read / delete);
//!   2. if `parsed-output` carries the host envelope `{"tool_calls":[...]}`
//!      (or the model dumped DSML into `text`), dispatches each call through
//!      `agent-fs` and folds the results back into the next prompt;
//!   3. repeats until the model returns text with no tool calls, or the round
//!      cap is hit.
//!
//! WIT `llm-response` stays 6 fields so hello-llm keeps linking; tool calls
//! travel in `parsed-output`. Host bindgen world ≠ guest world — only the
//! exports must match; imports are satisfied by the CapabilityInjector.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-llm-fs",
});

use advance::runtime::agent_fs::{self, Entry};
use advance::runtime::agent_llm::{self, LlmParams, LlmRequest, ToolDefinition};
use advance::runtime::types::{
    Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct LlmTools;

const DEFAULT_PROMPT: &str = "hello";
const MAX_ROUNDS: usize = 8;
const MAX_RESULT_BYTES: usize = 8 * 1024;
const INSTRUCTION: &str = "You are the workspace agent. You have tools write, list, read, and delete. Call a tool to act on files. Do not describe a tool call in prose.";

const WRITE_PARAMS: &str = r#"{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}"#;
const PATH_PARAMS: &str =
    r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#;

struct Call {
    id: String,
    name: String,
    arguments: String,
}

impl MessageDrivenGuest for LlmTools {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let user = String::from_utf8(msg.payload.clone()).unwrap_or_default();
        let user = if user.trim().is_empty() {
            DEFAULT_PROMPT.to_string()
        } else {
            user
        };

        let tools = Some(vec![
            tool("write", "Write a file in the workspace.", WRITE_PARAMS),
            tool(
                "list",
                "List files in a directory. Use path \".\" for the workspace root.",
                PATH_PARAMS,
            ),
            tool("read", "Read a file in the workspace.", PATH_PARAMS),
            tool("delete", "Delete a file in the workspace.", PATH_PARAMS),
        ]);
        let params = Some(LlmParams {
            model: None,
            temperature: None,
            max_tokens: None,
            stop_sequences: None,
            tools,
        });

        let mut transcript: Vec<(String, String)> = Vec::new();
        let mut last_text = String::new();

        for round in 0..MAX_ROUNDS {
            let prompt = build_prompt(&user, &transcript);
            let request = LlmRequest {
                task_id: None,
                prompt,
                params: params.clone(),
                output_schema: None,
            };
            let response =
                agent_llm::generate(&request).map_err(|e| format!("llm_generate_failed: {e:?}"))?;
            last_text = response.text.clone();

            let mut calls = Vec::new();
            if let Some(bytes) = response.parsed_output.as_deref() {
                calls = parse_tool_calls(bytes);
            }
            if calls.is_empty() {
                calls = parse_tool_calls(last_text.as_bytes());
            }
            if calls.is_empty() {
                calls = parse_dsml(&last_text);
            }
            if calls.is_empty() && response.finish_reason != "tool_calls" {
                break;
            }
            if calls.is_empty() {
                break;
            }

            let mut round_results = String::new();
            for (i, call) in calls.iter().enumerate() {
                let result = dispatch_tool(call);
                if i > 0 {
                    round_results.push('\n');
                }
                round_results.push_str(&format!(
                    "id={} name={} result={}",
                    if call.id.is_empty() {
                        format!("r{round}-{i}")
                    } else {
                        call.id.clone()
                    },
                    call.name,
                    result
                ));
            }
            let call_desc = calls
                .iter()
                .map(|c| format!("{}({})", c.name, c.arguments))
                .collect::<Vec<_>>()
                .join("; ");
            transcript.push((call_desc, round_results));
        }

        let payload = if last_text.trim().is_empty() && !transcript.is_empty() {
            transcript
                .last()
                .map(|(_, r)| r.clone())
                .unwrap_or_default()
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

impl RunnableGuest for LlmTools {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

fn tool(name: &str, description: &str, parameters: &str) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        parameters: parameters.to_string(),
    }
}

fn build_prompt(user: &str, transcript: &[(String, String)]) -> String {
    let mut p = String::new();
    p.push_str(INSTRUCTION);
    p.push_str("\n\nUser:\n");
    p.push_str(user);
    for (i, (call, result)) in transcript.iter().enumerate() {
        p.push_str("\n\nTool call ");
        p.push_str(&(i + 1).to_string());
        p.push_str(":\n");
        p.push_str(call);
        p.push_str("\nResult:\n");
        p.push_str(result);
    }
    if !transcript.is_empty() {
        p.push_str("\n\nContinue. Call another tool if needed, otherwise answer the user.");
    }
    p
}

fn dispatch_tool(call: &Call) -> String {
    let name = call.name.trim();
    match name {
        "write" => {
            let path = json_field(&call.arguments, "path").unwrap_or_default();
            let content = json_field(&call.arguments, "content")
                .or_else(|| json_field(&call.arguments, "data"))
                .unwrap_or_default();
            if path.is_empty() {
                return "error: write requires path".into();
            }
            match agent_fs::write(&path, content.as_bytes()) {
                Ok(()) => format!("wrote {path} ({} bytes)", content.len()),
                Err(e) => format!("write failed: {e:?}"),
            }
        }
        "list" => {
            let path = json_field(&call.arguments, "path").unwrap_or_else(|| ".".into());
            let path = if path.is_empty() { ".".into() } else { path };
            match agent_fs::list(&path) {
                Ok(entries) => format_list(&entries),
                Err(e) => format!("list failed: {e:?}"),
            }
        }
        "read" => {
            let path = json_field(&call.arguments, "path").unwrap_or_default();
            if path.is_empty() {
                return "error: read requires path".into();
            }
            match agent_fs::read(&path) {
                Ok(bytes) => cap_utf8(&bytes),
                Err(e) => format!("read failed: {e:?}"),
            }
        }
        "delete" => {
            let path = json_field(&call.arguments, "path").unwrap_or_default();
            if path.is_empty() {
                return "error: delete requires path".into();
            }
            match agent_fs::delete(&path) {
                Ok(()) => format!("deleted {path}"),
                Err(e) => format!("delete failed: {e:?}"),
            }
        }
        other => format!("error: unknown tool {other}"),
    }
}

fn format_list(entries: &[Entry]) -> String {
    if entries.is_empty() {
        return "(empty)".into();
    }
    let mut s = String::new();
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            s.push('\n');
        }
        s.push_str(if e.is_dir { "dir " } else { "file " });
        s.push_str(&e.name);
    }
    s
}

fn cap_utf8(bytes: &[u8]) -> String {
    let slice = if bytes.len() > MAX_RESULT_BYTES {
        &bytes[..MAX_RESULT_BYTES]
    } else {
        bytes
    };
    let mut t = String::from_utf8_lossy(slice).into_owned();
    if bytes.len() > MAX_RESULT_BYTES {
        t.push_str("\n…truncated");
    }
    t
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
    let arguments = json_field(obj, "arguments").unwrap_or_else(|| {
        if let Some(raw) = json_raw_object_field(obj, "arguments") {
            raw
        } else {
            "{}".into()
        }
    });
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

/// DeepSeek DSML fallback: `<|DSML|invoke name="write">` plus parameter tags.
fn parse_dsml(text: &str) -> Vec<Call> {
    let mut out = Vec::new();
    let mut search_from = 0;
    while search_from < text.len() {
        let rel = match find_invoke(&text[search_from..]) {
            Some(r) => r,
            None => break,
        };
        let idx = search_from + rel;
        let after = &text[idx..];
        let Some(name) = take_quoted_after(after, "name=") else {
            search_from = idx + 1;
            continue;
        };
        if name.is_empty() {
            search_from = idx + 1;
            continue;
        }
        let name_at = after.find("name=").unwrap_or(0);
        let after_name = after.get(name_at + 5..).unwrap_or("");
        let next_rel = after_name
            .find("invoke name=")
            .or_else(|| after_name.find("invoke name ="))
            .unwrap_or(after_name.len());
        let body_end = (name_at + 5 + next_rel).min(after.len());
        let body = &after[..body_end];
        out.push(Call {
            id: String::new(),
            name,
            arguments: dsml_args(body),
        });
        search_from = idx + body_end.max(1);
    }
    out
}

fn find_invoke(s: &str) -> Option<usize> {
    s.find("invoke name=").or_else(|| s.find("invoke name ="))
}

fn take_quoted_after(s: &str, key: &str) -> Option<String> {
    let at = s.find(key)?;
    let after = s[at + key.len()..].trim_start();
    if !after.starts_with('"') {
        return None;
    }
    parse_string(after, 0).map(|(v, _)| v)
}

fn dsml_args(body: &str) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut rest = body;
    while let Some(idx) = rest.find("parameter name=\"") {
        let after = &rest[idx + "parameter name=\"".len()..];
        let Some(end) = after.find('"') else { break };
        let key = after[..end].to_string();
        let tail = &after[end + 1..];
        let value = if let Some(gt) = tail.find('>') {
            let inner = &tail[gt + 1..];
            let stop = inner
                .find("</")
                .or_else(|| inner.find("<|"))
                .or_else(|| inner.find("<｜"))
                .unwrap_or(inner.len().min(4096));
            inner[..stop].trim().to_string()
        } else {
            String::new()
        };
        if !key.is_empty() {
            pairs.push((key, value));
        }
        rest = after.get(end + 1..).unwrap_or("");
    }
    if pairs.is_empty() {
        if let Some(path) = tag_inner(body, "path") {
            pairs.push(("path".into(), path));
        }
        if let Some(content) = tag_inner(body, "content") {
            pairs.push(("content".into(), content));
        }
    }
    if pairs.is_empty() {
        return "{}".into();
    }
    let mut json = String::from("{");
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(&json_escape(k));
        json.push_str("\":\"");
        json.push_str(&json_escape(v));
        json.push('"');
    }
    json.push('}');
    json
}

fn tag_inner(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].trim().to_string())
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

export!(LlmTools with_types_in crate);
