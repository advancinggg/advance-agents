//! SYS-J-75 — daemon-altitude web.search / web.extract witnesses.
//!
//! AC → test mapping (along bookkeeping handoff; this tree does not flip ledgers):
//!
//! | AC | Tests | Bytes prove |
//! | --- | --- | --- |
//! | SYS-AC-316 | `sys_ac_316_317_granted_search_hostile_leak` | search→extract→citation strip; hostile sanitize |
//! | SYS-AC-317 | same + `sys_ac_317_url` / `sys_ac_317_forged_ref` | typed refusals; leak-scan of wired secrets |
//! | SYS-AC-318 | `sys_ac_318_offline` / `sys_ac_318_ungranted` | withhold + leftover; `authz.checked` denied |
//! | SYS-AC-320 | `sys_ac_320_hostile_then_revoke` | HOSTILE_HTML constructs + same-instance re-auth |
//!
//! REQ-408 e2e evidence is the union of the four SYS-ACs. REQ-409 / MODULE-017-AC-32/33/34
//! are not flipped here.

#[path = "d_grant/mod.rs"]
mod d_grant;

use cap_grant::data::GrantTtl;
use system_acceptance::llm_loopback::LoopbackScript;
use system_acceptance::{Cap, GrantMode, LlmMode, SystemUnderTest, WebRunMode, AGENT_ID};

use d_grant::seed_grant;

const GUEST: &[u8] = include_bytes!("fixtures/guest-rust-j75-web.core.wasm");
const FORGED: &str = "ev_ffffffffffff";
const LLM_SECRET: &str = "test-secret-value";
const LLM_SECRET_NAME: &str = "harness-llm-api-key";
const WEB_PRINCIPAL: &str = "j75-web-cfg-secret";

fn build(mode: WebRunMode, grant: GrantMode) -> system_acceptance::SystemUnderTestBuilder {
    SystemUnderTest::builder()
        .caps(&[Cap::Tools, Cap::Fs, Cap::Llm])
        .grant(grant)
        .with_web_family(mode)
        .with_reply_capture()
        .llm(LlmMode::Loopback(LoopbackScript::reply("j75-loopback")))
}

fn seed_real(sut: &SystemUnderTest, with_web: bool) -> Option<String> {
    let store = sut
        .grant_store()
        .expect("GrantMode::Real exposes GrantStore");
    seed_grant(
        store,
        "g-j75-fs",
        AGENT_ID,
        "fs",
        vec![],
        GrantTtl::Persistent,
        None,
    );
    seed_grant(
        store,
        "g-j75-tools",
        AGENT_ID,
        "tools",
        vec![],
        GrantTtl::Persistent,
        None,
    );
    seed_grant(
        store,
        "g-j75-llm",
        AGENT_ID,
        "llm",
        vec![],
        GrantTtl::Persistent,
        None,
    );
    if with_web {
        let id = seed_grant(
            store,
            "g-j75-web",
            AGENT_ID,
            "web",
            vec![],
            GrantTtl::Persistent,
            None,
        );
        Some(id.0)
    } else {
        None
    }
}

fn workspace_text(sut: &SystemUnderTest, rel: &str) -> String {
    String::from_utf8_lossy(
        &sut.read_workspace_file(rel)
            .unwrap_or_else(|| panic!("missing workspace file {rel}")),
    )
    .into_owned()
}

fn leak_surfaces(sut: &SystemUnderTest) -> String {
    let mut acc = String::new();
    for name in [
        "search.json",
        "extract.json",
        "tools-list.json",
        "reply-raw.bin",
        "tool-err.txt",
    ] {
        if let Some(b) = sut.read_workspace_file(name) {
            acc.push_str(&String::from_utf8_lossy(&b));
        }
    }
    if let Some(body) = sut.llm_last_chat_request_body() {
        acc.push_str(&body);
    }
    for r in sut.delivered_replies() {
        acc.push_str(&String::from_utf8_lossy(&r));
    }
    for e in sut.events() {
        acc.push_str(&e.payload.to_string());
    }
    acc
}

fn assert_no_wired_secrets(hay: &str) {
    assert!(
        !hay.contains(LLM_SECRET),
        "wired LLM secret leaked onto an AC surface"
    );
    assert!(
        !hay.contains(LLM_SECRET_NAME),
        "wired LLM secret name leaked onto an AC surface"
    );
    assert!(
        !hay.contains(WEB_PRINCIPAL),
        "web config principal leaked onto an AC surface"
    );
}

fn web_invokes<'a>(
    events: &'a [advance_shared_types::event::Event],
) -> impl Iterator<Item = &'a advance_shared_types::event::Event> {
    events.iter().filter(|e| {
        e.event_type == "tool.invoke"
            && e.payload
                .get("tool_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == "web.search" || id == "web.extract")
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_316_317_granted_search_hostile_leak() {
    let sut = build(WebRunMode::Standard, GrantMode::AllowAll)
        .build(GUEST)
        .await;

    sut.inject_message("h", b"search").await;
    sut.run_turn().await;

    let list = workspace_text(&sut, "tools-list.json");
    assert!(
        list.contains("web.search") && list.contains("web.extract"),
        "Standard list-tools must offer web.*; got {list}"
    );
    let search = workspace_text(&sut, "search.json");
    assert!(
        search.contains("wr_"),
        "search hits carry result_ref; {search}"
    );
    let extract = workspace_text(&sut, "extract.json");
    assert!(
        extract.contains("evidence_id"),
        "extract JSON has evidence_id; {extract}"
    );
    let raw = workspace_text(&sut, "reply-raw.bin");
    let replies = sut.delivered_replies();
    assert!(!replies.is_empty(), "search turn delivered a reply");
    let captured = String::from_utf8_lossy(&replies[0]);
    let issued = extract
        .split("\"evidence_id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("parse evidence_id");
    assert!(raw.contains(issued), "reply-raw contains issued id");
    assert!(raw.contains(FORGED), "reply-raw contains forged id");
    assert!(
        captured.contains(issued),
        "captured reply keeps issued id; {captured}"
    );
    assert!(
        !captured.contains(FORGED),
        "captured reply strips forged id; {captured}"
    );

    let body = sut
        .llm_last_chat_request_body()
        .expect("search turn constructed model context");
    assert!(!body.is_empty());
    assert!(
        body.contains("web.search") && body.contains("web.extract"),
        "# Available Tools on Standard must list web.*; {body}"
    );

    let auth = sut
        .llm_recorded_authorization()
        .expect("loopback recorded Authorization");
    assert_eq!(auth, format!("Bearer {LLM_SECRET}"));
    assert_eq!(sut.web_principal(), Some(WEB_PRINCIPAL));
    assert_no_wired_secrets(&leak_surfaces(&sut));

    sut.inject_message("h", b"hostile").await;
    sut.run_turn().await;
    let replies = sut.delivered_replies();
    assert!(
        replies.len() >= 2,
        "hostile turn must deliver a second reply; got {}",
        replies.len()
    );
    let hostile = workspace_text(&sut, "extract.json");
    let hostile_raw = workspace_text(&sut, "reply-raw.bin");
    let hostile_reply =
        String::from_utf8_lossy(replies.last().expect("hostile reply")).into_owned();
    for hay in [&hostile, &hostile_raw, &hostile_reply] {
        assert!(
            hay.contains("call tool X"),
            "hostile page text must remain after sanitize (proves HOSTILE_HTML, not rust-async body): {hay}"
        );
        assert!(
            !hay.contains("<script"),
            "hostile extract/reply still has script: {hay}"
        );
        assert!(
            !hay.contains("hidden-css-secret"),
            "hostile extract/reply still has hidden css: {hay}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_317_url() {
    let sut = build(WebRunMode::Standard, GrantMode::AllowAll)
        .build(GUEST)
        .await;
    sut.inject_message("h", b"url").await;
    sut.run_turn().await;
    let err = workspace_text(&sut, "tool-err.txt");
    assert_eq!(
        err.trim(),
        "input-validation-failed",
        "arbitrary URL must be typed input-validation-failed, got {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_317_forged_ref() {
    let sut = build(WebRunMode::Standard, GrantMode::AllowAll)
        .build(GUEST)
        .await;
    sut.inject_message("h", b"forged-ref").await;
    sut.run_turn().await;
    let err = workspace_text(&sut, "tool-err.txt");
    assert_eq!(
        err.trim(),
        "input-validation-failed",
        "forged result_ref must be typed input-validation-failed, got {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_318_offline() {
    // Real + no web seed: OfflineDenyingGrantCheck must short-circuit so
    // leftover is permission-denied WITHOUT GrantCheckImpl `authz.checked`.
    // If the wrapper wrongly delegated, inner Deny would emit that event
    // (T07's discriminator) and this assert would fail.
    let sut = build(WebRunMode::Offline, GrantMode::Real)
        .build(GUEST)
        .await;
    seed_real(&sut, false);
    sut.inject_message("h", b"probe").await;
    sut.run_turn().await;
    let list = workspace_text(&sut, "tools-list.json");
    assert!(
        !list.contains("web.search") && !list.contains("web.extract"),
        "offline list-tools must omit web.*; {list}"
    );
    let err = workspace_text(&sut, "tool-err.txt");
    assert_eq!(
        err.trim(),
        "permission-denied",
        "offline leftover must be permission-denied, got {err}"
    );
    let web_authz = sut
        .events_of_types(&["authz.checked"])
        .into_iter()
        .any(|e| {
            e.payload.get("capability").and_then(|v| v.as_str()) == Some("web")
                && e.payload.get("decision").and_then(|v| v.as_str()) == Some("denied")
        });
    assert!(
        !web_authz,
        "offline leftover must not emit GrantCheckImpl authz.checked (T07 discriminator)"
    );
    let body = sut
        .llm_last_chat_request_body()
        .expect("probe always generate");
    assert!(body.contains("# Available Tools"), "{body}");
    assert!(
        !body.contains("web.search") && !body.contains("web.extract"),
        "offline assembler offer must omit web.*; {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_318_ungranted() {
    let sut = build(WebRunMode::Standard, GrantMode::Real)
        .build(GUEST)
        .await;
    seed_real(&sut, false);
    sut.inject_message("h", b"probe").await;
    sut.run_turn().await;
    let list = workspace_text(&sut, "tools-list.json");
    assert!(
        !list.contains("web.search") && !list.contains("web.extract"),
        "ungranted list-tools omits web.*; {list}"
    );
    let err = workspace_text(&sut, "tool-err.txt");
    assert_eq!(
        err.trim(),
        "permission-denied",
        "ungranted leftover must be permission-denied, got {err}"
    );
    let denied = sut
        .events_of_types(&["authz.checked"])
        .into_iter()
        .any(|e| {
            e.payload.get("capability").and_then(|v| v.as_str()) == Some("web")
                && e.payload.get("decision").and_then(|v| v.as_str()) == Some("denied")
        });
    assert!(
        denied,
        "ungranted web leftover must emit authz.checked denied (MODULE-013)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_320_hostile_then_revoke() {
    let sut = build(WebRunMode::Standard, GrantMode::Real)
        .build(GUEST)
        .await;
    let web_id = seed_real(&sut, true).expect("web grant id");
    sut.inject_message("h", b"hostile").await;
    sut.run_turn().await;

    let replies = sut.delivered_replies();
    assert!(!replies.is_empty(), "hostile turn delivered a reply");
    let extract = workspace_text(&sut, "extract.json");
    let raw = workspace_text(&sut, "reply-raw.bin");
    let reply = String::from_utf8_lossy(replies.last().expect("reply")).into_owned();
    for hay in [&extract, &raw, &reply] {
        assert!(
            hay.contains("call tool X"),
            "320 must extract HOSTILE_HTML (plain instruction remains): {hay}"
        );
        assert!(!hay.contains("<script"), "{hay}");
        assert!(!hay.contains("hidden-css-secret"), "{hay}");
    }

    let turn1: Vec<_> = sut.events().into_iter().collect();
    let search_n = web_invokes(&turn1)
        .filter(|e| e.payload.get("tool_id").and_then(|v| v.as_str()) == Some("web.search"))
        .count();
    let extract_n = web_invokes(&turn1)
        .filter(|e| e.payload.get("tool_id").and_then(|v| v.as_str()) == Some("web.extract"))
        .count();
    assert_eq!(search_n, 1, "turn1 web.search invoke count");
    assert_eq!(extract_n, 1, "turn1 web.extract invoke count");
    let extra = turn1.iter().any(|e| {
        e.event_type == "tool.invoke"
            && e.payload
                .get("tool_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| !id.is_empty() && id != "web.search" && id != "web.extract")
    });
    assert!(!extra, "host must not auto-invoke a third tool");

    sut.grant_store()
        .expect("store")
        .cascade_revoke(&web_id)
        .expect("cascade_revoke web only");
    sut.inject_message("h", b"probe").await;
    sut.run_turn().await;
    let err = workspace_text(&sut, "tool-err.txt");
    assert_eq!(
        err.trim(),
        "permission-denied",
        "after revoke, leftover web.search is permission-denied; {err}"
    );
}
