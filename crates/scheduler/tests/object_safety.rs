//! Object-safety verification for the 4 MODULE-014 contract traits +
//! Slice B/C scheduler-local traits (`RunnableHook`, `RunBootstrap`,
//! `MessageHandler`, `RuntimeReadiness`, `FileWatchSource`,
//! `WebhookSource`, `TriggerSource`).
//!
//! Constructing a `Box<dyn TraitName>` only type-checks when the trait
//! is dyn-compatible. Forcing the assertion into the `#[test]` body
//! itself (not orphan helper functions) keeps the coverage
//! load-bearing.

use advance_scheduler::contracts::{
    AgentLoopDriver, ComponentSubmitApi, SchedulerExtension, TriggerBusDispatch,
};
use advance_scheduler::hook::{
    FileWatchSource, MessageHandler, RunBootstrap, RunnableHook, RunnableHookFactory,
    RuntimeReadiness, WebhookSource,
};
use advance_scheduler::trigger_source::TriggerSource;

fn assert_send_sync<T: Send + Sync + ?Sized>() {}

#[test]
fn traits_are_object_safe() {
    // Forces the compiler to verify dyn-compatibility at type-check
    // time. The closures are never invoked.
    let _f1: fn(Box<dyn ComponentSubmitApi>) = |_| {};
    let _f2: fn(Box<dyn TriggerBusDispatch>) = |_| {};
    let _f3: fn(Box<dyn AgentLoopDriver>) = |_| {};
    let _f4: fn(Box<dyn SchedulerExtension>) = |_| {};
    // Slice B scheduler-local traits.
    let _f5: fn(Box<dyn RunnableHook>) = |_| {};
    let _f6: fn(Box<dyn RunBootstrap>) = |_| {};
    // Slice C scheduler-local traits.
    let _f7: fn(Box<dyn MessageHandler>) = |_| {};
    let _f8: fn(Box<dyn RuntimeReadiness>) = |_| {};
    let _f9: fn(Box<dyn FileWatchSource>) = |_| {};
    let _f10: fn(Box<dyn WebhookSource>) = |_| {};
    let _f11: fn(Box<dyn TriggerSource>) = |_| {};
    // S3 (registry→driver materializer satellite) scheduler-local trait.
    let _f12: fn(Box<dyn RunnableHookFactory>) = |_| {};

    // Send + Sync guards on Box<dyn ...> — load-bearing for the
    // multi-threaded scheduler runtime.
    assert_send_sync::<Box<dyn ComponentSubmitApi>>();
    assert_send_sync::<Box<dyn TriggerBusDispatch>>();
    assert_send_sync::<Box<dyn AgentLoopDriver>>();
    assert_send_sync::<Box<dyn SchedulerExtension>>();
    assert_send_sync::<Box<dyn RunnableHook>>();
    assert_send_sync::<Box<dyn RunBootstrap>>();
    assert_send_sync::<Box<dyn MessageHandler>>();
    assert_send_sync::<Box<dyn RuntimeReadiness>>();
    assert_send_sync::<Box<dyn FileWatchSource>>();
    assert_send_sync::<Box<dyn WebhookSource>>();
    assert_send_sync::<Box<dyn TriggerSource>>();
    assert_send_sync::<Box<dyn RunnableHookFactory>>();
}
