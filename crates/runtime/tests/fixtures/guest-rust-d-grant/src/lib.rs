//! /dev Track D (2026-06-04) — grant system-acceptance guest fixture.
//!
//! Targets the `advance-host-grant` world (imports `agent-grant`, exports
//! `message-driven` + `runnable`). On `handle-message` it parses the inbound payload
//! as a UTF-8 command line and calls the matching `agent-grant` host fn (provided
//! dynamically by the host `CapabilityInjector` under the **versioned** namespace
//! `advance:runtime/agent-grant@0.1.0`). The guest returns each WIT `result` as one
//! reply action payload so system-acceptance witnesses can bind return values to the
//! real guest turn (guest → injector → host fn → outbound action seam). An L1 grant-gate
//! DENY traps the turn — but every grant op runs under capability `"grant"`, so the
//! harness pre-seeds a `"grant"` self-management grant and no trap occurs.
//!
//! Command grammar (space-delimited tokens; params are `key=value`):
//!   - `req <capability> [k=v ...]`               -> request-capability
//!   - `revoke <target> <grant-id>`               -> revoke-grant
//!   - `delegate <target> <capability> [k=v ...]` -> delegate-grant   (deferred-stub use)
//!   - `narrow <target> <grant-id> [k=v ...]`     -> narrow-grant      (deferred-stub use)
//!   - `apply-preset <target> <preset-name>`      -> apply-preset      (deferred-stub use)
//!
//! Built for `wasm32-unknown-unknown`; the core module is wrapped to a Component at
//! test time via `wit_component::ComponentEncoder` (same pattern as
//! `guest-rust-j01-skeleton`). Only the EXPORTS (`message-driven`/`runnable`) must
//! match the host bindgen; the `agent-grant` IMPORT is satisfied by the linker
//! (the injector), which provides a SUPERSET of this trimmed interface.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-grant",
});

use advance::runtime::agent_grant;
use advance::runtime::types::{
    Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct GrantGuest;

/// Witness state returned after a dispatched command (opaque; tests assert on events/store).
const STATE_DONE: [u8; 4] = [0xAC, 0x17, 0xD0, 0x01];

/// Parse `key=value` tokens into `cap-param`s (tokens without `=` or with an empty key are skipped).
fn parse_params(tokens: &[&str]) -> Vec<agent_grant::CapParam> {
    tokens
        .iter()
        .filter_map(|t| {
            let mut it = t.splitn(2, '=');
            match (it.next(), it.next()) {
                (Some(k), Some(v)) if !k.is_empty() => Some(agent_grant::CapParam {
                    key: k.to_string(),
                    value: v.to_string(),
                }),
                _ => None,
            }
        })
        .collect()
}

fn grant_error_to_payload(prefix: &str, err: agent_grant::GrantError) -> Vec<u8> {
    let rendered = match err {
        agent_grant::GrantError::NotFound(s) => format!("{prefix}:error:not-found:{s}"),
        agent_grant::GrantError::PermissionDenied(s) => {
            format!("{prefix}:error:permission-denied:{s}")
        }
        agent_grant::GrantError::SubsetViolation(s) => {
            format!("{prefix}:error:subset-violation:{s}")
        }
        agent_grant::GrantError::InvalidParams(s) => {
            format!("{prefix}:error:invalid-params:{s}")
        }
        agent_grant::GrantError::PresetNotFound(s) => {
            format!("{prefix}:error:preset-not-found:{s}")
        }
    };
    rendered.into_bytes()
}

fn request_decision_to_payload(
    result: Result<agent_grant::GrantDecision, agent_grant::GrantError>,
) -> Vec<u8> {
    match result {
        Ok(agent_grant::GrantDecision::Approved(id)) => format!("req:approved:{id}").into_bytes(),
        Ok(agent_grant::GrantDecision::Denied(reason)) => {
            format!("req:denied:{reason}").into_bytes()
        }
        Ok(agent_grant::GrantDecision::Pending) => b"req:pending".to_vec(),
        Err(err) => grant_error_to_payload("req", err),
    }
}

fn ids_to_payload(prefix: &str, result: Result<Vec<String>, agent_grant::GrantError>) -> Vec<u8> {
    match result {
        Ok(ids) => format!("{prefix}:ok:{}", ids.join(",")).into_bytes(),
        Err(err) => grant_error_to_payload(prefix, err),
    }
}

fn unit_to_payload(prefix: &str, result: Result<(), agent_grant::GrantError>) -> Vec<u8> {
    match result {
        Ok(()) => format!("{prefix}:ok").into_bytes(),
        Err(err) => grant_error_to_payload(prefix, err),
    }
}

impl MessageDrivenGuest for GrantGuest {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let line = String::from_utf8_lossy(&msg.payload);
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut reply: Option<Vec<u8>> = None;
        if let Some((cmd, rest)) = tokens.split_first() {
            match *cmd {
                // req <capability> [k=v ...]
                "req" => {
                    if let Some((cap, params)) = rest.split_first() {
                        let p = parse_params(params);
                        let request = agent_grant::GrantRequest {
                            capability: (*cap).to_string(),
                            params: if p.is_empty() { None } else { Some(p) },
                            justification: None,
                        };
                        reply = Some(request_decision_to_payload(
                            agent_grant::request_capability(&request),
                        ));
                    }
                }
                // revoke <target> <grant-id>
                "revoke" => {
                    if let [target, grant_id, ..] = rest {
                        reply = Some(unit_to_payload(
                            "revoke",
                            agent_grant::revoke_grant(target, grant_id),
                        ));
                    }
                }
                // delegate <target> <capability> [k=v ...]   (deferred-stub use)
                "delegate" => {
                    if let Some((target, tail)) = rest.split_first() {
                        if let Some((cap, params)) = tail.split_first() {
                            let draft = agent_grant::GrantDraft {
                                capability: (*cap).to_string(),
                                params: parse_params(params),
                                ttl: agent_grant::GrantTtl::Persistent,
                            };
                            reply = Some(ids_to_payload(
                                "delegate",
                                agent_grant::delegate_grant(target, &draft).map(|id| vec![id]),
                            ));
                        }
                    }
                }
                // narrow <target> <grant-id> [k=v ...]   (deferred-stub use)
                "narrow" => {
                    if let Some((target, tail)) = rest.split_first() {
                        if let Some((grant_id, params)) = tail.split_first() {
                            reply = Some(ids_to_payload(
                                "narrow",
                                agent_grant::narrow_grant(target, grant_id, &parse_params(params))
                                    .map(|id| vec![id]),
                            ));
                        }
                    }
                }
                // apply-preset <target> <preset-name>   (deferred-stub use)
                "apply-preset" => {
                    if let [target, preset, ..] = rest {
                        reply = Some(ids_to_payload(
                            "apply-preset",
                            agent_grant::apply_preset(target, preset),
                        ));
                    }
                }
                _ => {}
            }
        }
        Ok(ActionResult {
            new_state: STATE_DONE.to_vec(),
            actions: reply
                .map(|payload| vec![Action { payload }])
                .unwrap_or_default(),
        })
    }
}

impl RunnableGuest for GrantGuest {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(GrantGuest with_types_in crate);
