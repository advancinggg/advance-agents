//! Object-safety verification for shared-types traits.
//!
//! Constructing a `Box<dyn TraitName>` only type-checks when the trait is
//! dyn-compatible. If either trait lost object-safety (by adding a generic method,
//! `Self` in return position, an associated type without `where Self: Sized`, or an
//! `async fn`), this test body would fail to compile AND the test itself would
//! disappear from the binary — forcing the assertion into the `#[test]` body itself
//! (rather than orphan helper functions) makes the coverage load-bearing.
//!
//! The async traits in Slice AC v2 are dyn-compatible because of the `#[async_trait]`
//! macro applied in their respective modules, which rewrites async methods to return
//! `Pin<Box<dyn Future + Send + '_>>` — preserving object-safety.

use advance_shared_types::traits::*;

#[test]
fn traits_are_object_safe() {
    // These `fn()` constructors force the compiler to verify dyn-compatibility at
    // the type-checking stage. The closures are never called, but the types they
    // reference must be valid trait objects.

    // Slice A' / B' / J / K (prior-shipped).
    let _run_budget: fn(Box<dyn RunBudget>) = |_| {};
    let _callable_inventory: fn(Box<dyn CallableInventoryReader>) = |_| {};
    let _event_bus_emit: fn(Box<dyn EventBusEmit>) = |_| {};
    let _grant_check: fn(Box<dyn GrantCheck>) = |_| {};
    let _repetition_guard_check: fn(Box<dyn RepetitionGuardCheck>) = |_| {};

    // Slice m019-B (CONTRACT-181 CostTrackerQuery).
    let _cost_tracker_query: fn(Box<dyn CostTrackerQuery>) = |_| {};

    // Slice AC v2 — 12 new traits.
    let _agent_tree_reader: fn(Box<dyn AgentTreeReader>) = |_| {};
    let _agent_tree_snapshot: fn(Box<dyn AgentTreeSnapshot>) = |_| {};
    let _mailbox_reader: fn(Box<dyn MailboxReader>) = |_| {};
    let _post_processor_hook: fn(Box<dyn PostProcessorHook>) = |_| {};
    let _l6_handler: fn(Box<dyn L6Handler>) = |_| {};
    let _skill_state_reader: fn(Box<dyn SkillStateReader>) = |_| {};
    let _action_validator: fn(Box<dyn ActionValidator>) = |_| {};
    let _agent_action_dispatcher: fn(Box<dyn AgentActionDispatcher>) = |_| {};
    let _context_assembler: fn(Box<dyn ContextAssembler>) = |_| {};
    let _round_advancer: fn(Box<dyn RoundAdvancer>) = |_| {};
    let _await_session_ref: fn(Box<dyn AwaitSessionRef>) = |_| {};
    let _prompt_injection_helpers: fn(Box<dyn PromptInjectionHelpers>) = |_| {};

    // Slice m012-B.
    let _leak_detector: fn(Box<dyn LeakDetector>) = |_| {};

    // Slice m012-C.
    let _http_security_chain: fn(Box<dyn HttpSecurityChain>) = |_| {};
    let _ssrf_guard: fn(Box<dyn SsrfGuard>) = |_| {};
    let _redirect_check: fn(Box<dyn RedirectCheck>) = |_| {};

    // Wave-15 Lane E (CONTRACT-183 ToolsGrantReader).
    let _tools_grant_reader: fn(Box<dyn ToolsGrantReader>) = |_| {};

    // Wave-23 (CONTRACT-214 RememberContentPolicy — producer-boundary guard).
    let _remember_content_policy: fn(Box<dyn RememberContentPolicy>) = |_| {};

    // Load-bearing Send + Sync assertion. `Box<dyn TraitName>` is Send+Sync
    // iff the trait has the `Send + Sync` supertrait bounds. Removing
    // either supertrait strips the auto-trait and fails this generic call.
    fn assert_send_sync<T: Send + Sync>() {}

    // Prior-shipped.
    assert_send_sync::<Box<dyn GrantCheck>>();
    assert_send_sync::<Box<dyn RepetitionGuardCheck>>();

    // Slice m019-B.
    assert_send_sync::<Box<dyn CostTrackerQuery>>();

    // Slice AC v2.
    assert_send_sync::<Box<dyn AgentTreeReader>>();
    assert_send_sync::<Box<dyn AgentTreeSnapshot>>();
    assert_send_sync::<Box<dyn MailboxReader>>();
    assert_send_sync::<Box<dyn PostProcessorHook>>();
    assert_send_sync::<Box<dyn L6Handler>>();
    assert_send_sync::<Box<dyn SkillStateReader>>();
    assert_send_sync::<Box<dyn ActionValidator>>();
    assert_send_sync::<Box<dyn AgentActionDispatcher>>();
    assert_send_sync::<Box<dyn ContextAssembler>>();
    assert_send_sync::<Box<dyn RoundAdvancer>>();
    assert_send_sync::<Box<dyn AwaitSessionRef>>();
    assert_send_sync::<Box<dyn PromptInjectionHelpers>>();

    // Slice m012-B.
    assert_send_sync::<Box<dyn LeakDetector>>();

    // Slice m012-C.
    assert_send_sync::<Box<dyn HttpSecurityChain>>();
    assert_send_sync::<Box<dyn SsrfGuard>>();
    assert_send_sync::<Box<dyn RedirectCheck>>();

    // Wave-15 Lane E.
    assert_send_sync::<Box<dyn ToolsGrantReader>>();

    // Wave-23 (RememberContentPolicy).
    assert_send_sync::<Box<dyn RememberContentPolicy>>();

    // CONTRACT-240 Search Provider SPI.
    let _search_provider: fn(Box<dyn SearchProviderSpi>) = |_| {};
    assert_send_sync::<Box<dyn SearchProviderSpi>>();

    // CONTRACT-236 / CONTRACT-238 (local-endpoint-s1). Ports are Send+Sync;
    // stream traits are Send-only (HttpBodyStream precedent — do not
    // assert_send_sync on InferenceStream / LocalBodyStream).
    let _inference_port: fn(Box<dyn InferenceBackendPort>) = |_| {};
    let _inference_stream: fn(Box<dyn InferenceStream>) = |_| {};
    let _local_policy: fn(Box<dyn LocalInferenceTransportPolicy>) = |_| {};
    let _local_body: fn(Box<dyn LocalBodyStream>) = |_| {};
    assert_send_sync::<Box<dyn InferenceBackendPort>>();
    assert_send_sync::<Box<dyn LocalInferenceTransportPolicy>>();

    // L6RunnableSpec is a Send+Sync struct (trait-object field Arc<dyn L6Handler>
    // is Send+Sync; other fields are String which are Send+Sync).
    assert_send_sync::<advance_shared_types::memory::L6RunnableSpec>();
}
