//! MODULE-001-T111 (6) / MODULE-001-AC-30, on a current-thread runtime (the flavour
//! `advance start` composes on): ordered shutdown with a WebSocket open and a turn in
//! flight, nothing left afterwards, and a second composition of the same home that commits
//! a turn to git.
//!
//! The only test of its binary: it checks process-wide state.

#[path = "support/t111.rs"]
mod t111;

#[path = "support/recompose.rs"]
mod recompose;

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_t111_6_recompose_after_ordered_shutdown_current_thread() {
    recompose::t111_6_recompose_after_ordered_shutdown().await;
}
