//! Lane cost-attribution (2026-09-16) — durable per-agent / per-provider cost ledger over the
//! persisted `events` table (`EventBus::cost_ledger()`, `CostLedgerQuery`).
//!
//! Witnesses the property the in-memory `CostTracker` cannot give: the figures SURVIVE a bus
//! shutdown + reopen on the same `events.db`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use advance_event_bus::{Clock, EventBus, EventBusConfig};
use advance_shared_types::cost::{CostWindow, RunCost};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{CostLedgerQuery, EventBusEmit};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};

#[derive(Clone)]
struct FrozenClock(DateTime<Utc>);
impl Clock for FrozenClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

fn cfg(root: &Path) -> EventBusConfig {
    let mut c = EventBusConfig::new(root.join("events"), root.join("events.db"));
    c.websocket_addr = "127.0.0.1:0".parse().unwrap();
    c.clock = Arc::new(FrozenClock(Utc::now()));
    c
}

fn t(h: u32, m: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 16, h, m, s).unwrap()
}

fn ev(id: &str, agent: &str, ts: DateTime<Utc>, event_type: &str, payload: Value) -> Event {
    Event {
        id: id.into(),
        timestamp: ts,
        agent_id: agent.into(),
        task_id: None,
        run_id: Some("run-1".into()),
        execution_id: None,
        trace_id: "tr".into(),
        span_id: id.into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload,
        duration_ms: Some(1),
    }
}

fn llm(
    id: &str,
    agent: &str,
    ts: DateTime<Utc>,
    provider: Option<&str>,
    tin: i64,
    tout: i64,
    cost: f64,
) -> Event {
    let mut p = json!({
        "model": "m",
        "input_tokens": tin,
        "output_tokens": tout,
        "cost_usd": cost,
        "finish_reason": "stop",
    });
    if let Some(pr) = provider {
        p["provider"] = json!(pr);
    }
    ev(id, agent, ts, "llm.response", p)
}

/// The fixture corpus. Expected totals are spelled out next to each row.
fn corpus() -> Vec<Event> {
    vec![
        // agent-a / anthropic: 100+200 in, 10+20 out, 1.0+2.0 usd, 2 calls
        llm(
            "e1",
            "agent-a",
            t(10, 0, 0),
            Some("anthropic"),
            100,
            10,
            1.0,
        ),
        llm(
            "e2",
            "agent-a",
            t(11, 0, 0),
            Some("anthropic"),
            200,
            20,
            2.0,
        ),
        // agent-a / openai: 50 in, 5 out, 0.5 usd, 1 call
        llm("e3", "agent-a", t(12, 0, 0), Some("openai"), 50, 5, 0.5),
        // agent-b / anthropic: 1000 in, 100 out, 4.0 usd, 1 call
        llm(
            "e4",
            "agent-b",
            t(12, 30, 0),
            Some("anthropic"),
            1000,
            100,
            4.0,
        ),
        // agent-b / legacy row without provider → "unknown": 7 in, 3 out, 0.25 usd
        llm("e5", "agent-b", t(13, 0, 0), None, 7, 3, 0.25),
        // agent-b / anthropic adversarial negatives → clamp to 0 tokens / 0.0 usd, still 1 call
        llm(
            "e6",
            "agent-b",
            t(13, 30, 0),
            Some("anthropic"),
            -5,
            -5,
            -9.0,
        ),
        // detached work (empty agent id) on openai: counts for the provider, not for any agent
        llm("e7", "", t(14, 0, 0), Some("openai"), 30, 3, 0.3),
        // not an llm.response: ignored everywhere
        ev(
            "e8",
            "agent-a",
            t(14, 30, 0),
            "llm.request",
            json!({"model": "m", "input_tokens": 999, "cost_usd": 99.0}),
        ),
        ev(
            "e9",
            "agent-a",
            t(14, 31, 0),
            "task.created",
            json!({"cost_usd": 99.0}),
        ),
    ]
}

const LLM_ROWS: u32 = 7;

fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

/// Poll until every `llm.response` of the corpus is durable (the async bus persists through a
/// bounded channel + writer actor), bounded at 10 s.
async fn wait_durable(ledger: &dyn CostLedgerQuery, expected_rows: u32) {
    for _ in 0..200 {
        let providers = ledger
            .provider_totals(&CostWindow::ALL)
            .expect("ledger read");
        let rows: u32 = providers.iter().map(|p| p.cost.request_count).sum();
        if rows >= expected_rows {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("llm.response rows never became durable");
}

fn assert_corpus_totals(ledger: &dyn CostLedgerQuery) {
    let all = CostWindow::ALL;

    // Per-agent totals: ordered by cost desc then id.
    let agents = ledger.agent_totals(&all).unwrap();
    assert_eq!(
        agents.len(),
        2,
        "empty agent id must not create a bucket: {agents:?}"
    );
    assert_eq!(agents[0].id, "agent-b");
    assert_eq!(agents[0].cost.tokens_in, 1007);
    assert_eq!(agents[0].cost.tokens_out, 103);
    assert!(
        approx(agents[0].cost.cost_usd, 4.25),
        "{}",
        agents[0].cost.cost_usd
    );
    assert_eq!(agents[0].cost.request_count, 3);
    assert_eq!(agents[1].id, "agent-a");
    assert_eq!(agents[1].cost.tokens_in, 350);
    assert_eq!(agents[1].cost.tokens_out, 35);
    assert!(approx(agents[1].cost.cost_usd, 3.5));
    assert_eq!(agents[1].cost.request_count, 3);

    // Single agent total == its list row; unknown agent == zero aggregate, not an error.
    assert_eq!(ledger.agent_total("agent-a", &all).unwrap(), agents[1].cost);
    assert_eq!(
        ledger.agent_total("nobody", &all).unwrap(),
        RunCost::default()
    );
    assert_eq!(ledger.agent_total("", &all).unwrap(), RunCost::default());

    // Agent split by provider.
    let a_by_p = ledger.agent_by_provider("agent-a", &all).unwrap();
    assert_eq!(a_by_p.len(), 2);
    assert_eq!(a_by_p[0].id, "anthropic");
    assert_eq!(a_by_p[0].cost.request_count, 2);
    assert!(approx(a_by_p[0].cost.cost_usd, 3.0));
    assert_eq!(a_by_p[1].id, "openai");
    assert!(approx(a_by_p[1].cost.cost_usd, 0.5));
    let b_by_p = ledger.agent_by_provider("agent-b", &all).unwrap();
    assert_eq!(
        b_by_p.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["anthropic", "unknown"]
    );
    assert_eq!(
        b_by_p[0].cost.request_count, 2,
        "the clamped row still counts as a call"
    );
    assert_eq!(b_by_p[0].cost.tokens_in, 1000, "negative tokens clamp to 0");
    assert!(
        approx(b_by_p[0].cost.cost_usd, 4.0),
        "negative cost clamps to 0.0"
    );
    assert!(approx(b_by_p[1].cost.cost_usd, 0.25));

    // Per-provider totals include the detached row.
    let providers = ledger.provider_totals(&all).unwrap();
    assert_eq!(
        providers.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["anthropic", "openai", "unknown"]
    );
    assert!(approx(providers[0].cost.cost_usd, 7.0));
    assert_eq!(providers[0].cost.request_count, 4);
    assert!(approx(providers[1].cost.cost_usd, 0.8));
    assert_eq!(providers[1].cost.tokens_in, 80);
    assert_eq!(providers[1].cost.request_count, 2);
    assert_eq!(providers[2].cost.request_count, 1);
    let total_rows: u32 = providers.iter().map(|p| p.cost.request_count).sum();
    assert_eq!(
        total_rows, LLM_ROWS,
        "non-llm.response events must be ignored"
    );

    assert_eq!(
        ledger.provider_total("openai", &all).unwrap(),
        providers[1].cost
    );
    assert_eq!(
        ledger.provider_total("gemini", &all).unwrap(),
        RunCost::default()
    );
    let openai_by_agent = ledger.provider_by_agent("openai", &all).unwrap();
    assert_eq!(
        openai_by_agent.len(),
        1,
        "detached row has no agent bucket: {openai_by_agent:?}"
    );
    assert_eq!(openai_by_agent[0].id, "agent-a");
    let anthropic_by_agent = ledger.provider_by_agent("anthropic", &all).unwrap();
    assert_eq!(
        anthropic_by_agent
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["agent-b", "agent-a"]
    );
}

fn assert_windows(ledger: &dyn CostLedgerQuery) {
    // [11:00, 13:00) → e2, e3, e4 (e5 at 13:00 is excluded by the exclusive upper bound).
    let w = CostWindow {
        since: Some(t(11, 0, 0)),
        until: Some(t(13, 0, 0)),
    };
    let providers = ledger.provider_totals(&w).unwrap();
    let rows: u32 = providers.iter().map(|p| p.cost.request_count).sum();
    assert_eq!(rows, 3, "{providers:?}");
    assert!(approx(
        ledger.agent_total("agent-a", &w).unwrap().cost_usd,
        2.5
    ));
    assert!(approx(
        ledger.agent_total("agent-b", &w).unwrap().cost_usd,
        4.0
    ));

    // Inclusive lower bound at exactly 10:00:00 includes e1.
    let w = CostWindow {
        since: Some(t(10, 0, 0)),
        until: Some(t(10, 0, 1)),
    };
    assert_eq!(ledger.agent_total("agent-a", &w).unwrap().request_count, 1);

    // A sub-second `until` is ceiled: 12:59:59.5 → 13:00:00, so e5 (13:00:00) stays excluded
    // while everything before is included; a sub-second `since` is floored.
    let w = CostWindow {
        since: Some(t(12, 59, 59) + chrono::Duration::milliseconds(500)),
        until: Some(t(13, 0, 0) + chrono::Duration::milliseconds(1)),
    };
    // floor(since)=12:59:59, ceil(until)=13:00:01 → e5 only.
    assert_eq!(ledger.agent_total("agent-b", &w).unwrap().request_count, 1);
    assert!(approx(
        ledger.agent_total("agent-b", &w).unwrap().cost_usd,
        0.25
    ));

    // Only-since / only-until.
    let since_only = CostWindow {
        since: Some(t(13, 30, 0)),
        until: None,
    };
    let rows: u32 = ledger
        .provider_totals(&since_only)
        .unwrap()
        .iter()
        .map(|p| p.cost.request_count)
        .sum();
    assert_eq!(rows, 2); // e6, e7
    let until_only = CostWindow {
        since: None,
        until: Some(t(10, 0, 1)),
    };
    let rows: u32 = ledger
        .provider_totals(&until_only)
        .unwrap()
        .iter()
        .map(|p| p.cost.request_count)
        .sum();
    assert_eq!(rows, 1); // e1

    // Empty window → zero rows, no error.
    let empty = CostWindow {
        since: Some(t(20, 0, 0)),
        until: Some(t(21, 0, 0)),
    };
    assert!(ledger.agent_totals(&empty).unwrap().is_empty());
    assert_eq!(
        ledger.provider_total("anthropic", &empty).unwrap(),
        RunCost::default()
    );
}

/// CL-01 — async production bus: totals, splits, clamping, ordering, windows; then the ledger
/// SURVIVES shutdown + reopen on the same `events.db` (the property the in-memory tracker lacks).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cl01_async_bus_ledger_is_durable_across_restart() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(temp.path())).await.expect("bus");
    let ledger = bus.cost_ledger();
    for e in corpus() {
        bus.emit(e);
    }
    wait_durable(ledger.as_ref(), LLM_ROWS).await;
    assert_corpus_totals(ledger.as_ref());
    assert_windows(ledger.as_ref());

    // The ledger handle is a pool clone: the bus can still be consumed and shut down.
    drop(ledger);
    bus.shutdown().await;

    // Reopen: no emits this time — every number must come from disk.
    let bus2 = EventBus::new(cfg(temp.path())).await.expect("bus reopen");
    let ledger2 = bus2.cost_ledger();
    assert_corpus_totals(ledger2.as_ref());
    assert_windows(ledger2.as_ref());
    drop(ledger2);
    bus2.shutdown().await;
}

/// CL-02 — the synchronous test bus exposes the same ledger (rows are durable at `emit` return).
#[test]
fn cl02_sync_bus_ledger_reads_immediately() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new_synchronous_for_tests(cfg(temp.path())).expect("sync bus");
    let ledger = bus.cost_ledger();
    for e in corpus() {
        bus.emit(e);
    }
    assert_corpus_totals(ledger.as_ref());
    assert_windows(ledger.as_ref());
}

/// CL-03 — garbage payload shapes never panic and never count: non-numeric fields fold as 0.
#[test]
fn cl03_garbage_payloads_fold_as_zero() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new_synchronous_for_tests(cfg(temp.path())).expect("sync bus");
    let ledger = bus.cost_ledger();
    bus.emit(ev(
        "g1",
        "agent-g",
        t(9, 0, 0),
        "llm.response",
        json!({"input_tokens": "lots", "output_tokens": null, "cost_usd": "NaN", "provider": 42}),
    ));
    bus.emit(ev("g2", "agent-g", t(9, 0, 1), "llm.response", json!({})));
    bus.emit(ev(
        "g3",
        "agent-g",
        t(9, 0, 2),
        "llm.response",
        json!([1, 2, 3]),
    ));
    let total = ledger.agent_total("agent-g", &CostWindow::ALL).unwrap();
    assert_eq!(total.tokens_in, 0);
    assert_eq!(total.tokens_out, 0);
    assert_eq!(total.cost_usd, 0.0);
    assert_eq!(total.request_count, 3);
    // A numeric provider id is stringified by json_extract; still a stable bucket, no panic.
    let split = ledger
        .agent_by_provider("agent-g", &CostWindow::ALL)
        .unwrap();
    assert_eq!(split.iter().map(|r| r.cost.request_count).sum::<u32>(), 3);
    assert!(split.iter().any(|r| r.id == "unknown"));
}
