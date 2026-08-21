//! SYS-J-75 guest: list-tools + web.search + web.extract + generate + citation reply.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-tools-fs-llm",
});

use advance::runtime::agent_fs;
use advance::runtime::agent_llm::{self, LlmRequest};
use advance::runtime::agent_tools::{self, ToolError};
use advance::runtime::types::{
    Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct J75Web;

const FORGED: &str = "ev_ffffffffffff";

fn write_file(path: &str, bytes: &[u8]) {
    let _ = agent_fs::write(path, bytes);
}

fn json_field<'a>(hay: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":\"");
    let start = hay.find(&needle)? + needle.len();
    let rest = &hay[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn err_tag(err: &ToolError) -> &'static str {
    match err {
        ToolError::NotFound(_) => "not-found",
        ToolError::MethodNotFound(_) => "method-not-found",
        ToolError::InvocationFailed(_) => "invocation-failed",
        ToolError::PermissionDenied(_) => "permission-denied",
        ToolError::InputValidationFailed(_) => "input-validation-failed",
        ToolError::OutputValidationFailed(_) => "output-validation-failed",
    }
}

fn list_tools() {
    match agent_tools::list_tools() {
        Ok(infos) => {
            let mut out = String::new();
            for info in infos {
                out.push_str(&info.id);
                out.push('\n');
            }
            write_file("tools-list.json", out.as_bytes());
        }
        Err(e) => write_file("tool-err.txt", err_tag(&e).as_bytes()),
    }
}

fn generate() {
    let request = LlmRequest {
        task_id: None,
        prompt: "j75".to_string(),
        params: None,
        output_schema: None,
    };
    let _ = agent_llm::generate(&request);
}

fn search(query: &str) -> Result<Vec<u8>, ToolError> {
    let body = format!(r#"{{"query":"{query}"}}"#);
    agent_tools::tool_invoke("web.search", "search", body.as_bytes())
}

fn extract_ref(result_ref: &str) -> Result<Vec<u8>, ToolError> {
    let body = format!(r#"{{"result_ref":"{result_ref}"}}"#);
    agent_tools::tool_invoke("web.extract", "extract", body.as_bytes())
}

fn emit_citation_reply(extract_bytes: &[u8]) -> ActionResult {
    write_file("extract.json", extract_bytes);
    let text = String::from_utf8_lossy(extract_bytes).into_owned();
    let ev = json_field(&text, "evidence_id")
        .unwrap_or("ev_missing")
        .to_string();
    let mut reply = text;
    reply.push_str(" cite ");
    reply.push_str(&ev);
    reply.push(' ');
    reply.push_str(FORGED);
    write_file("reply-raw.bin", reply.as_bytes());
    generate();
    ActionResult {
        new_state: Vec::new(),
        actions: vec![Action {
            payload: reply.into_bytes(),
        }],
    }
}

fn after_tool_err(err: &ToolError) -> ActionResult {
    write_file("tool-err.txt", err_tag(err).as_bytes());
    generate();
    ActionResult {
        new_state: Vec::new(),
        actions: vec![],
    }
}

impl MessageDrivenGuest for J75Web {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let mode = String::from_utf8_lossy(&msg.payload);
        let mode = mode.trim();
        list_tools();
        match mode {
            "hostile" => match search("hostile page") {
                Ok(bytes) => {
                    write_file("search.json", &bytes);
                    let s = String::from_utf8_lossy(&bytes);
                    match json_field(&s, "result_ref") {
                        Some(r) => match extract_ref(r) {
                            Ok(ex) => Ok(emit_citation_reply(&ex)),
                            Err(e) => Ok(after_tool_err(&e)),
                        },
                        None => Ok(after_tool_err(&ToolError::InvocationFailed(
                            "no result_ref".into(),
                        ))),
                    }
                }
                Err(e) => Ok(after_tool_err(&e)),
            },
            "url" => match search("rust async") {
                Ok(bytes) => {
                    write_file("search.json", &bytes);
                    let bad = br#"{"url":"https://evil.example"}"#;
                    match agent_tools::tool_invoke("web.extract", "extract", bad) {
                        Ok(_) => Ok(after_tool_err(&ToolError::InvocationFailed(
                            "url extract unexpectedly ok".into(),
                        ))),
                        Err(e) => Ok(after_tool_err(&e)),
                    }
                }
                Err(e) => Ok(after_tool_err(&e)),
            },
            "forged-ref" => match agent_tools::tool_invoke(
                "web.extract",
                "extract",
                br#"{"result_ref":"wr_deadbeef"}"#,
            ) {
                Ok(_) => Ok(after_tool_err(&ToolError::InvocationFailed(
                    "forged-ref unexpectedly ok".into(),
                ))),
                Err(e) => Ok(after_tool_err(&e)),
            },
            "probe" => match search("rust async") {
                Ok(bytes) => {
                    write_file("search.json", &bytes);
                    generate();
                    Ok(ActionResult {
                        new_state: Vec::new(),
                        actions: vec![],
                    })
                }
                Err(e) => Ok(after_tool_err(&e)),
            },
            _ => match search("rust async") {
                Ok(bytes) => {
                    write_file("search.json", &bytes);
                    let s = String::from_utf8_lossy(&bytes);
                    match json_field(&s, "result_ref") {
                        Some(r) => match extract_ref(r) {
                            Ok(ex) => Ok(emit_citation_reply(&ex)),
                            Err(e) => Ok(after_tool_err(&e)),
                        },
                        None => Ok(after_tool_err(&ToolError::InvocationFailed(
                            "no result_ref".into(),
                        ))),
                    }
                }
                Err(e) => Ok(after_tool_err(&e)),
            },
        }
    }
}

impl RunnableGuest for J75Web {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(J75Web with_types_in crate);
