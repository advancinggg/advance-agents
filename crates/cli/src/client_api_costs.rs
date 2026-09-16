//! CLI-served `CostProvider` (CONTRACT-190 costs family) over the runtime's durable cost ledger
//! (lane cost-attribution, 2026-09-16).
//!
//! The adapter binds the SAME `CostLedgerQuery` the wired `EventBus` exposes over its `events`
//! table (`EventBus::cost_ledger()`), so the figures the Client API serves are the persisted,
//! restart-surviving `llm.response` rows — never the in-memory `CostTracker` (which counts
//! emit-attempts for the live budget and is lost on restart). It only projects shapes: runtime
//! `RunCost` → client `ClientCostTotals`; a failed store read → `ProviderError::Unavailable`.

use std::sync::Arc;

use advance_client_api::costs::{
    ClientAgentCostEntry, ClientAgentCostReport, ClientCostTotals, ClientProviderCostEntry,
    ClientProviderCostReport, ValidatedCostWindow,
};
use advance_client_api::{CostProvider, ProviderError};
use advance_shared_types::cost::{AttributedCost, CostLedgerError, CostWindow, RunCost};
use advance_shared_types::traits::CostLedgerQuery;

/// The production `CostProvider`.
pub struct LedgerCostProvider {
    ledger: Arc<dyn CostLedgerQuery>,
}

impl LedgerCostProvider {
    pub fn new(ledger: Arc<dyn CostLedgerQuery>) -> Self {
        Self { ledger }
    }
}

fn window_of(w: &ValidatedCostWindow) -> CostWindow {
    CostWindow {
        since: w.since,
        until: w.until,
    }
}

fn totals_of(c: RunCost) -> ClientCostTotals {
    ClientCostTotals {
        tokens_in: c.tokens_in,
        tokens_out: c.tokens_out,
        cost_usd: c.cost_usd,
        request_count: c.request_count,
    }
}

fn agent_entry(a: AttributedCost) -> ClientAgentCostEntry {
    ClientAgentCostEntry {
        agent_id: a.id,
        totals: totals_of(a.cost),
    }
}

fn provider_entry(a: AttributedCost) -> ClientProviderCostEntry {
    ClientProviderCostEntry {
        provider_id: a.id,
        totals: totals_of(a.cost),
    }
}

fn map_err(e: CostLedgerError) -> ProviderError {
    // The ledger error text is an internal store message (pool/SQL); it is retained on the
    // variant for logging only — `into_client_error` never forwards it to the client.
    ProviderError::Unavailable(e.to_string())
}

impl CostProvider for LedgerCostProvider {
    fn agent_totals(
        &self,
        window: &ValidatedCostWindow,
    ) -> Result<Vec<ClientAgentCostEntry>, ProviderError> {
        let rows = self
            .ledger
            .agent_totals(&window_of(window))
            .map_err(map_err)?;
        Ok(rows.into_iter().map(agent_entry).collect())
    }

    fn agent_report(
        &self,
        agent_id: &str,
        window: &ValidatedCostWindow,
    ) -> Result<ClientAgentCostReport, ProviderError> {
        let w = window_of(window);
        let total = self.ledger.agent_total(agent_id, &w).map_err(map_err)?;
        let by_provider = self
            .ledger
            .agent_by_provider(agent_id, &w)
            .map_err(map_err)?;
        Ok(ClientAgentCostReport {
            agent_id: agent_id.to_string(),
            totals: totals_of(total),
            by_provider: by_provider.into_iter().map(provider_entry).collect(),
            window: window.to_client(),
        })
    }

    fn provider_totals(
        &self,
        window: &ValidatedCostWindow,
    ) -> Result<Vec<ClientProviderCostEntry>, ProviderError> {
        let rows = self
            .ledger
            .provider_totals(&window_of(window))
            .map_err(map_err)?;
        Ok(rows.into_iter().map(provider_entry).collect())
    }

    fn provider_report(
        &self,
        provider_id: &str,
        window: &ValidatedCostWindow,
    ) -> Result<ClientProviderCostReport, ProviderError> {
        let w = window_of(window);
        let total = self
            .ledger
            .provider_total(provider_id, &w)
            .map_err(map_err)?;
        let by_agent = self
            .ledger
            .provider_by_agent(provider_id, &w)
            .map_err(map_err)?;
        Ok(ClientProviderCostReport {
            provider_id: provider_id.to_string(),
            totals: totals_of(total),
            by_agent: by_agent.into_iter().map(agent_entry).collect(),
            window: window.to_client(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records the windows it receives and answers canned rows.
    struct FakeLedger {
        windows: Mutex<Vec<CostWindow>>,
        fail: bool,
    }

    impl FakeLedger {
        fn ok() -> Arc<Self> {
            Arc::new(Self {
                windows: Mutex::new(vec![]),
                fail: false,
            })
        }
        fn failing() -> Arc<Self> {
            Arc::new(Self {
                windows: Mutex::new(vec![]),
                fail: true,
            })
        }
        fn note(&self, w: &CostWindow) -> Result<(), CostLedgerError> {
            self.windows.lock().unwrap().push(w.clone());
            if self.fail {
                Err(CostLedgerError::Query("pool exhausted".into()))
            } else {
                Ok(())
            }
        }
        fn cost(n: u64) -> RunCost {
            RunCost {
                tokens_in: n,
                tokens_out: n * 2,
                cost_usd: n as f64 * 0.5,
                request_count: n as u32,
            }
        }
    }

    impl CostLedgerQuery for FakeLedger {
        fn agent_totals(&self, w: &CostWindow) -> Result<Vec<AttributedCost>, CostLedgerError> {
            self.note(w)?;
            Ok(vec![
                AttributedCost {
                    id: "a".into(),
                    cost: Self::cost(4),
                },
                AttributedCost {
                    id: "b".into(),
                    cost: Self::cost(1),
                },
            ])
        }
        fn agent_total(&self, id: &str, w: &CostWindow) -> Result<RunCost, CostLedgerError> {
            self.note(w)?;
            Ok(if id == "a" {
                Self::cost(4)
            } else {
                RunCost::default()
            })
        }
        fn agent_by_provider(
            &self,
            _id: &str,
            w: &CostWindow,
        ) -> Result<Vec<AttributedCost>, CostLedgerError> {
            self.note(w)?;
            Ok(vec![AttributedCost {
                id: "anthropic".into(),
                cost: Self::cost(4),
            }])
        }
        fn provider_totals(&self, w: &CostWindow) -> Result<Vec<AttributedCost>, CostLedgerError> {
            self.note(w)?;
            Ok(vec![AttributedCost {
                id: "anthropic".into(),
                cost: Self::cost(5),
            }])
        }
        fn provider_total(&self, _id: &str, w: &CostWindow) -> Result<RunCost, CostLedgerError> {
            self.note(w)?;
            Ok(Self::cost(5))
        }
        fn provider_by_agent(
            &self,
            _id: &str,
            w: &CostWindow,
        ) -> Result<Vec<AttributedCost>, CostLedgerError> {
            self.note(w)?;
            Ok(vec![
                AttributedCost {
                    id: "a".into(),
                    cost: Self::cost(4),
                },
                AttributedCost {
                    id: "b".into(),
                    cost: Self::cost(1),
                },
            ])
        }
    }

    fn window() -> ValidatedCostWindow {
        ValidatedCostWindow {
            since: Some(
                chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            until: None,
        }
    }

    #[test]
    fn projects_shapes_and_forwards_window_verbatim() {
        let ledger = FakeLedger::ok();
        let p = LedgerCostProvider::new(ledger.clone());
        let w = window();

        let agents = p.agent_totals(&w).unwrap();
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].agent_id, "a");
        assert_eq!(agents[0].totals.tokens_in, 4);
        assert_eq!(agents[0].totals.tokens_out, 8);
        assert!((agents[0].totals.cost_usd - 2.0).abs() < 1e-12);
        assert_eq!(agents[0].totals.request_count, 4);

        let report = p.agent_report("a", &w).unwrap();
        assert_eq!(report.agent_id, "a");
        assert_eq!(report.totals.request_count, 4);
        assert_eq!(report.by_provider[0].provider_id, "anthropic");
        assert_eq!(report.window.since.as_deref(), Some("2026-09-01T00:00:00Z"));
        assert_eq!(report.window.until, None);

        let unknown = p.agent_report("nobody", &w).unwrap();
        assert_eq!(unknown.totals, ClientCostTotals::default());

        let providers = p.provider_totals(&w).unwrap();
        assert_eq!(providers[0].provider_id, "anthropic");
        let preport = p.provider_report("anthropic", &w).unwrap();
        assert_eq!(preport.by_agent.len(), 2);
        assert_eq!(preport.by_agent[1].agent_id, "b");

        let seen = ledger.windows.lock().unwrap();
        assert!(!seen.is_empty());
        assert!(seen
            .iter()
            .all(|cw| cw.since == w.since && cw.until.is_none()));
    }

    #[test]
    fn ledger_failure_is_unavailable_never_a_client_string() {
        let p = LedgerCostProvider::new(FakeLedger::failing());
        let err = p.agent_totals(&ValidatedCostWindow::default()).unwrap_err();
        assert!(matches!(err, ProviderError::Unavailable(_)));
        let client = err.into_client_error();
        assert_eq!(
            client.code,
            advance_client_api::ClientErrorCode::ModuleUnavailable
        );
        assert!(!client.message.contains("pool exhausted"));
        assert!(matches!(
            p.provider_report("anthropic", &ValidatedCostWindow::default()),
            Err(ProviderError::Unavailable(_))
        ));
    }
}
