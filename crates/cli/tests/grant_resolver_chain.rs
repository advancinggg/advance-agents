use std::sync::Arc;

use advance_cli::wiring::{build_grant_resolver_chain, default_channel_approval_port};
use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::run::RoundResult;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::{
    AutoDenyResolver, BudgetCheckResolver, ChannelResolver, GrantRequest, GrantSqliteIndex,
    GrantStore, GrantTtl, ParentApprovalResolver, Resolver, ResolverChain, ResolverContext,
    SubsetAutoApproveResolver, SubsetValidator, SubsetValidatorImpl,
};

struct NoopBus;

impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

fn make_store(bus: Arc<dyn EventBusEmit>) -> Arc<GrantStore> {
    let handle: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("sqlite"));
    let index = GrantSqliteIndex::new(handle);
    index.ensure_schema().expect("grant schema");
    Arc::new(GrantStore::new(index, bus))
}

fn req(caller: &str, capability: &str) -> GrantRequest {
    GrantRequest {
        caller: caller.to_string(),
        capability: capability.to_string(),
        params: None,
        ttl: GrantTtl::Once,
        justification: None,
    }
}

#[tokio::test]
async fn production_builder_injects_live_budget_before_terminal_deny() {
    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    let run_manager = Arc::new(RunManager::new(bus.clone()));
    let run_id = run_manager
        .ensure_run(
            "default-agent",
            "default-agent",
            RunConfig {
                rounds_limit: Some(1),
                ..Default::default()
            },
        )
        .expect("ensure_run");
    run_manager
        .complete_round(
            &run_id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .expect("complete_round");

    let store = make_store(bus.clone());
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let chain = build_grant_resolver_chain(validator, Arc::new(run_manager.budget()), None);
    let result = chain.evaluate(
        req("default-agent", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: Some(run_id.as_ref()),
        },
        &store,
        &bus,
    );
    let cap_grant::ChainDecision::Denied(reason) = result else {
        panic!("exhausted live budget should deny, got {result:?}");
    };
    assert_eq!(reason, "budget-exceeded-rounds");

    let legacy_store = make_store(bus.clone());
    let legacy_validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let legacy_chain = ResolverChain::new(vec![
        Box::new(SubsetAutoApproveResolver::new(legacy_validator)) as Box<dyn Resolver>,
        Box::new(BudgetCheckResolver::new()),
        Box::new(ParentApprovalResolver::new_abstain()),
        Box::new(ChannelResolver::new()),
        Box::new(AutoDenyResolver::new()),
    ]);
    let legacy = legacy_chain.evaluate(
        req("default-agent", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: Some(run_id.as_ref()),
        },
        &legacy_store,
        &bus,
    );
    let cap_grant::ChainDecision::Denied(legacy_reason) = legacy else {
        panic!("legacy no-budget chain should fall through to deny, got {legacy:?}");
    };
    assert_ne!(
        legacy_reason, "budget-exceeded-rounds",
        "test must fail if production builder regresses to BudgetCheckResolver::new()"
    );
}

#[test]
fn production_builder_without_channel_port_fails_closed_after_abstains() {
    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    let run_manager = Arc::new(RunManager::new(bus.clone()));
    let run_id = run_manager
        .ensure_run(
            "default-agent",
            "default-agent",
            RunConfig {
                rounds_limit: Some(10),
                ..Default::default()
            },
        )
        .expect("ensure_run");

    let store = make_store(bus.clone());
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let chain = build_grant_resolver_chain(validator, Arc::new(run_manager.budget()), None);
    let result = chain.evaluate(
        req("default-agent", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: Some(run_id.as_ref()),
        },
        &store,
        &bus,
    );
    let cap_grant::ChainDecision::Denied(reason) = result else {
        panic!("no parent grant and no channel port should deny fail-closed, got {result:?}");
    };
    assert!(
        reason.contains("AutoDenyResolver"),
        "headroom budget abstains; no approval port should fall through to AutoDeny, got {reason:?}"
    );
}

#[test]
fn production_builder_default_channel_port_fails_closed_at_channel() {
    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    let run_manager = Arc::new(RunManager::new(bus.clone()));
    let run_id = run_manager
        .ensure_run(
            "default-agent",
            "default-agent",
            RunConfig {
                rounds_limit: Some(10),
                ..Default::default()
            },
        )
        .expect("ensure_run");

    let store = make_store(bus.clone());
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let chain = build_grant_resolver_chain(
        validator,
        Arc::new(run_manager.budget()),
        Some(default_channel_approval_port()),
    );
    let result = chain.evaluate(
        req("default-agent", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: Some(run_id.as_ref()),
        },
        &store,
        &bus,
    );
    let cap_grant::ChainDecision::Denied(reason) = result else {
        panic!("default channel port should fail closed, got {result:?}");
    };
    assert_eq!(
        reason, "channel-approval-unavailable",
        "default Channel port must deny explicitly before AutoDeny without leaking backend detail"
    );
}
