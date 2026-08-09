//! Track I — SYS-J-27 "agent invokes a lazily-loaded WASM tool".
//!
//! Journey (docs/SYSTEM-ACCEPTANCE.md §1): MODULE-017 → MODULE-001 → MODULE-008.
//! "An agent invokes a WASM tool that is lazily loaded (and an idle one evicted
//! past the LRU cap), with schema-validated input/output and the result returned
//! to the turn."
//!
//! The old N1 blocker ("cap-tools registers the UNVERSIONED agent-tools") is
//! STALE: `crates/capabilities/cap-tools/src/host_fn.rs:31` is now
//! `advance:runtime/agent-tools@0.1.0` (commit 560248b). These witnesses drive
//! the REAL registered `tool-invoke` / `list-tools` host-fn handlers at the agent
//! boundary via `call_host_fn_as_agent`, over the SAME concrete
//! `LazyToolRegistry` the harness wires into `register_agent_tools` (exposed via
//! `sut.tool_registry()`), with the production default config (max_tool_instances
//! = 20, max_result_bytes = 16 MiB). All assertions bind to real product output
//! (the WIT result Val, `tool.invoke`/`tool.result`/`tool.error` events, the real
//! registry cache state via `cache_len`/`list`).

use cap_tools::ToolRegistry; // brings the async `list()` trait method into scope
use system_acceptance::{Cap, SystemUnderTest};
use wasmtime::component::Val;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const ECHO_TOOL: &[u8] =
    include_bytes!("../../capabilities/cap-tools/tests/fixtures/echo_tool.component.wasm");
const SCHEMA_TOOL: &[u8] =
    include_bytes!("../../capabilities/cap-tools/tests/fixtures/schema_tool.component.wasm");
const DUAL_EXPORT: &[u8] =
    include_bytes!("../../capabilities/cap-tools/tests/fixtures/dual_export.component.wasm");
const BIG_OUTPUT: &[u8] =
    include_bytes!("../../capabilities/cap-tools/tests/fixtures/big_output.component.wasm");

const TOOLS_NS: &str = "advance:runtime/agent-tools@0.1.0";

// ── helpers ──────────────────────────────────────────────────────────

fn invoke_params(tool_id: &str, method: &str, input: &[u8]) -> Vec<Val> {
    vec![
        Val::String(tool_id.to_string()),
        Val::String(method.to_string()),
        Val::List(input.iter().map(|b| Val::U8(*b)).collect()),
    ]
}

/// Drive the REAL `tool-invoke` host-fn at the agent boundary; return its single
/// result Val (`result<list<u8>, tool-error>`).
async fn tool_invoke(sut: &SystemUnderTest, tool_id: &str, method: &str, input: &[u8]) -> Val {
    let out = sut
        .call_host_fn_as_agent(
            sut.agent_id(),
            "tools",
            TOOLS_NS,
            "tool-invoke",
            invoke_params(tool_id, method, input),
        )
        .await
        .expect("tool-invoke host-fn dispatch");
    assert_eq!(out.len(), 1, "tool-invoke returns exactly one result Val");
    out.into_iter().next().unwrap()
}

/// Decode the `Ok(list<u8>)` arm → the real execute bytes, or `None` on the Err arm.
fn ok_bytes(v: &Val) -> Option<Vec<u8>> {
    match v {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::List(items) => Some(
                items
                    .iter()
                    .map(|x| match x {
                        Val::U8(b) => *b,
                        other => panic!("non-u8 in result list: {other:?}"),
                    })
                    .collect(),
            ),
            other => panic!("Ok arm is not a list: {other:?}"),
        },
        _ => None,
    }
}

/// Decode the `Err(tool-error)` arm → the kebab-case error case (e.g.
/// "input-validation-failed"), or `None` on the Ok arm.
fn err_case(v: &Val) -> Option<String> {
    match v {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Variant(case, _) => Some(case.clone()),
            other => panic!("Err arm is not a variant: {other:?}"),
        },
        _ => None,
    }
}

/// (id, description) pairs from the REAL registry `list()` — the same function the
/// `list-tools` host-fn returns. A cached tool carries its real describe()
/// description; an uncached registered tool gets an EMPTY description (the
/// `list()` else-branch), so empty-description == "not currently cached".
async fn list_pairs(sut: &SystemUnderTest) -> Vec<(String, String)> {
    sut.tool_registry()
        .expect("tools cap")
        .list()
        .await
        .into_iter()
        .map(|i| (i.id, i.description))
        .collect()
}

// ── SYS-AC-082 ───────────────────────────────────────────────────────

/// tool-invoke on a never-loaded WASM tool lazily loads it, returns schema-valid
/// output within the turn, emitting tool.invoke then tool.result (duration_ms).
#[tokio::test]
async fn sys_ac_082_lazy_load_and_schema_valid_result_within_turn() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Tools])
        .build(CORE_BYTES)
        .await;
    // Register the binary but DO NOT load it — the first invoke must lazily load.
    sut.tool_registry()
        .expect("tools cap")
        .register_binary("echo1", ECHO_TOOL.to_vec())
        .await;
    assert_eq!(
        sut.tool_registry().unwrap().cache_len().await,
        0,
        "not loaded until first invoke (lazy)"
    );

    let res = tool_invoke(&sut, "echo1", "echo", b"hello-tool").await;
    // Real in-WASM execute output (discriminator: a stub/wrong tool would not echo).
    assert_eq!(
        ok_bytes(&res).as_deref(),
        Some(&b"hello-tool"[..]),
        "echo returns the invoked bytes verbatim (real execute)"
    );
    assert_eq!(
        sut.tool_registry().unwrap().cache_len().await,
        1,
        "the lazy load populated the cache"
    );

    // Events: tool.invoke at call-start, then tool.result with duration_ms.
    let invoke_ev = sut.assert_event("tool.invoke", |e| {
        e.payload.get("tool_id").and_then(|v| v.as_str()) == Some("echo1")
            && e.payload.get("method").and_then(|v| v.as_str()) == Some("echo")
    });
    let result_ev = sut.assert_event("tool.result", |e| {
        e.payload.get("tool_id").and_then(|v| v.as_str()) == Some("echo1")
            && e.payload.get("duration_ms").is_some()
    });
    // Ordering: tool.invoke strictly precedes tool.result.
    assert!(
        invoke_ev.timestamp <= result_ev.timestamp,
        "tool.invoke precedes tool.result"
    );
}

// ── SYS-AC-083 ───────────────────────────────────────────────────────

/// After > max_tool_instances (default 20) distinct tools are invoked, the idle
/// tool is LRU-evicted; re-invoking it triggers a fresh cold load. Witnessed via
/// the REAL LRU overflow (not the evict_id test helper): `cache_len`==20 + the
/// idle tool shows an EMPTY description in `list()`; re-invoke flips it non-empty.
#[tokio::test]
async fn sys_ac_083_lru_eviction_then_cold_reload() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Tools])
        .build(CORE_BYTES)
        .await;
    let reg = sut.tool_registry().expect("tools cap");

    // 21 DISTINCT tool ids (same echo bytes → same describe()).
    let ids: Vec<String> = (0..21).map(|n| format!("tool-{n:02}")).collect();
    for id in &ids {
        reg.register_binary(id.clone(), ECHO_TOOL.to_vec()).await;
    }
    // Invoke tool-00 FIRST (it becomes the idle LRU victim), then tool-01..tool-20.
    for id in &ids {
        let res = tool_invoke(&sut, id, "echo", id.as_bytes()).await;
        assert_eq!(
            ok_bytes(&res).as_deref(),
            Some(id.as_bytes()),
            "{id} echoes"
        );
    }

    // LRU cap enforced: 21 distinct invoked, cache holds exactly 20 (not 21).
    assert_eq!(
        reg.cache_len().await,
        20,
        "max_tool_instances=20 enforced; the 21st invoke evicted the idle tool"
    );

    // Membership/count-based discriminator: exactly ONE registered tool is
    // uncached (empty description), and it is the idle tool-00 (the LRU victim).
    let empties: Vec<String> = list_pairs(&sut)
        .await
        .into_iter()
        .filter(|(_, desc)| desc.is_empty())
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        empties,
        vec!["tool-00".to_string()],
        "tool-00 is the LRU-evicted (uncached) tool"
    );

    // Re-invoke tool-00 → a fresh COLD LOAD (it was absent). Proof: its list()
    // description flips empty → non-empty, and cache_len stays at the cap.
    let res = tool_invoke(&sut, "tool-00", "echo", b"reloaded").await;
    assert_eq!(
        ok_bytes(&res).as_deref(),
        Some(&b"reloaded"[..]),
        "cold reload returns real output"
    );
    assert_eq!(
        reg.cache_len().await,
        20,
        "still at the LRU cap after cold reload"
    );
    let tool00_desc = list_pairs(&sut)
        .await
        .into_iter()
        .find(|(id, _)| id == "tool-00")
        .map(|(_, d)| d)
        .expect("tool-00 still registered");
    assert!(
        !tool00_desc.is_empty(),
        "tool-00 is cached again after cold reload (was empty/evicted before)"
    );
}

// ── SYS-AC-084 ───────────────────────────────────────────────────────

/// Invoking a tool with input violating its declared JSON schema returns
/// tool-error::input-validation-failed and execute is NOT run.
#[tokio::test]
async fn sys_ac_084_input_schema_violation_fails_closed() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Tools])
        .build(CORE_BYTES)
        .await;
    sut.tool_registry()
        .unwrap()
        .register_binary("schema1", SCHEMA_TOOL.to_vec())
        .await;

    // Schema requires {"x": number}. `{"y":1}` violates it.
    let bad = tool_invoke(&sut, "schema1", "check", br#"{"y":1}"#).await;
    assert_eq!(
        err_case(&bad).as_deref(),
        Some("input-validation-failed"),
        "schema-violating input fails closed at the input gate"
    );
    // execute did NOT run → no tool.result emitted (only tool.invoke + tool.error).
    assert!(
        sut.events_of_types(&["tool.result"]).is_empty(),
        "execute did not run: no tool.result event for the rejected invoke"
    );
    sut.assert_event("tool.error", |e| {
        e.payload.get("error_type").and_then(|v| v.as_str()) == Some("input-validation-failed")
    });

    // Discriminator: schema-valid input runs execute and returns the bytes.
    let good = tool_invoke(&sut, "schema1", "check", br#"{"x":1}"#).await;
    assert_eq!(
        ok_bytes(&good).as_deref(),
        Some(&br#"{"x":1}"#[..]),
        "schema-valid input runs execute (echoes)"
    );
    assert_eq!(
        sut.events_of_types(&["tool.result"]).len(),
        1,
        "exactly one tool.result — only the valid invoke ran execute"
    );
}

// ── SYS-AC-085 ───────────────────────────────────────────────────────

/// A tool WASM that ALSO exports runnable (mutual-exclusion violation) is hidden
/// from list-tools and tool-invoke returns tool-error::not-found. The REAL
/// product sequence: first invoke → invocation-failed (cold-load validator
/// rejection → failed-set); then list omits it AND a second invoke → not-found.
#[tokio::test]
async fn sys_ac_085_mutual_exclusion_violation_hidden_and_not_found() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Tools])
        .build(CORE_BYTES)
        .await;
    let reg = sut.tool_registry().expect("tools cap");
    reg.register_binary("dual1", DUAL_EXPORT.to_vec()).await;
    reg.register_binary("good1", ECHO_TOOL.to_vec()).await;

    // First invoke triggers the cold load; the validator rejects runnable+tool
    // exports → invocation-failed (NOT pre-poisoned).
    let first = tool_invoke(&sut, "dual1", "echo", b"x").await;
    assert_eq!(
        err_case(&first).as_deref(),
        Some("invocation-failed"),
        "dual-export rejected at cold load with the mutual-exclusion error"
    );

    // Load the good control so list() membership is meaningful.
    let good = tool_invoke(&sut, "good1", "echo", b"y").await;
    assert_eq!(
        ok_bytes(&good).as_deref(),
        Some(&b"y"[..]),
        "control tool invokes fine"
    );

    // Post-rejection: dual1 is hidden from list-tools; good1 is present.
    let ids: Vec<String> = list_pairs(&sut)
        .await
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(
        !ids.contains(&"dual1".to_string()),
        "dual-export hidden from list-tools (failed-set)"
    );
    assert!(
        ids.contains(&"good1".to_string()),
        "the valid control tool IS listed"
    );

    // Second invoke → not-found (it is in the failed-set now).
    let second = tool_invoke(&sut, "dual1", "echo", b"x").await;
    assert_eq!(
        err_case(&second).as_deref(),
        Some("not-found"),
        "re-invoking the failed-set tool returns not-found"
    );
}

// ── SYS-AC-219 ───────────────────────────────────────────────────────

/// A tool-invoke whose WASM execute returns more than max_result_bytes is
/// fail-closed with tool-error::output-validation-failed and NO truncated result
/// is returned. Witnessed via the IDENTICAL `bytes.len() > max_result_bytes`
/// check (lazy_registry.rs ~1012) at a REDUCED cap (256 KiB) with a 2 MiB output.
/// The literal 16 MiB+ default output is NOT cleanly reachable — a 16 MiB+ result
/// list<u8> traps/times out during the component Val-boundary lift BEFORE the
/// host size check (§3.6(g) documented limitation; the same boundary deferred the
/// 64 MiB SYS-AC-235). The reduced cap is a faithful reduced-bound witness of the
/// fail-closed mechanism (value-agnostic check); the threshold differs from the
/// 16 MiB production default only because the literal default is unwitnessable
/// here.
#[tokio::test]
async fn sys_ac_219_oversized_result_fail_closed() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Tools])
        .with_tools_max_result_bytes(256 * 1024) // reduced cap; see doc comment
        .build(CORE_BYTES)
        .await;
    sut.tool_registry()
        .unwrap()
        .register_binary("big1", BIG_OUTPUT.to_vec())
        .await;

    // 2 MiB output > 256 KiB cap → fail-closed, NO bytes returned.
    let big = tool_invoke(&sut, "big1", "big", b"").await;
    assert_eq!(
        err_case(&big).as_deref(),
        Some("output-validation-failed"),
        "oversized output fails closed"
    );
    assert!(
        ok_bytes(&big).is_none(),
        "no (truncated) result value is returned to the turn"
    );
    sut.assert_event("tool.error", |e| {
        e.payload.get("error_type").and_then(|v| v.as_str()) == Some("output-validation-failed")
    });

    // Discriminator: the same fixture's under-cap method returns Ok.
    let small = tool_invoke(&sut, "big1", "small", b"").await;
    assert_eq!(
        ok_bytes(&small).as_deref(),
        Some(&b"ok"[..]),
        "under-cap output returns normally"
    );
}
