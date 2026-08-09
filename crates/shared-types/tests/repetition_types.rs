//! Compile-time trait-bound assertions for the Slice K repetition types.
//!
//! Mirrors the Slice I `capability_types.rs` pattern: these assertions fail
//! at type-check time if any of `ToolCallSignature` / `OutputHash` /
//! `RepetitionDecision` accidentally loses `Send`, `Sync`, `Clone`, `Debug`,
//! or `PartialEq` (e.g. by embedding a `Cell` / `Rc` / raw pointer). The
//! `#[test]` body is load-bearing: the generic `fn` calls force the compiler
//! to verify the bounds at codegen time, so removing any assertion would
//! silently lose coverage.

use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};

fn assert_send_sync<T: Send + Sync>() {}
fn assert_clone_debug_partial_eq<T: Clone + std::fmt::Debug + PartialEq>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<ToolCallSignature>();
    assert_send_sync::<OutputHash>();
    assert_send_sync::<RepetitionDecision>();
}

#[test]
fn types_are_clone_debug_partial_eq() {
    assert_clone_debug_partial_eq::<ToolCallSignature>();
    assert_clone_debug_partial_eq::<OutputHash>();
    assert_clone_debug_partial_eq::<RepetitionDecision>();
}
