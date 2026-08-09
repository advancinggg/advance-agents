//! `RepetitionGuard` + `RepetitionGuardCheck` impl (CONTRACT-072).
//!
//! Slice A shipped `WarnOnly` / `Terminate` / `WarnThenTerminate` action
//! policies with the WarnThenTerminate `inject_tier3_warning` call placed
//! as a comment-only placeholder. Slice B fills in the placeholder:
//! `with_prompt_injection_helpers` + `with_context_assembler` builders
//! wire the AC-10 Tier-3 inject chain (PromptInjectionHelpers
//! `flag_injection_patterns` + `wrap_with_boundary` →
//! ContextAssembler `inject_tier3_warning`). Severity::Critical flags in
//! the synthesized warn message short-circuit the inject (fail-closed).
//! `with_event_bus` + `with_run_resolver` wire the
//! `run.repetition_detected` emit path; `decide_locked` returns
//! `(decision, Option<Event>)` and the caller emits AFTER releasing the
//! per_agent write lock.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, OnceLock, RwLock};

use advance_shared_types::event::Event;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::security_validator::{PromptInjectionHelpers, Severity, TrustLevel};
use advance_shared_types::traits::{ContextAssembler, EventBusEmit, RepetitionGuardCheck};

use crate::events;
use crate::identifier::validate_agent_id;

/// Hard cap on the number of distinct agent_ids tracked per
/// `RepetitionGuard`. Closes the unbounded-map memory-exhaustion DoS
/// surfaced by the adversarial review.
pub const MAX_AGENTS_PER_GUARD: usize = 10_000;

/// Per-field byte cap on caller-supplied `ToolCallSignature` strings.
pub const MAX_TOOL_FIELD_LEN_BYTES: usize = 256;

/// Hard cap on `RepetitionGuard::new(window_size, ...)`.
pub const MAX_WINDOW_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepetitionAction {
    WarnOnly,
    Terminate,
    WarnThenTerminate,
}

/// Slice B — M008-internal trait for resolving the triggering `agent_id`
/// of a repetition observation to its (run_id, task_id) pair. Implemented
/// by `RunManager` (walks the in-memory `RunStore` for the unique live
/// Run whose `controller_agent` matches; ambiguous-multi returns `(None,
/// None)` per the fail-honest posture documented in §3.6). Trait is
/// `pub` so tests can supply mock impls; not hoisted to shared-types
/// because M009/M017 callers receive resolved values via Event fields,
/// not via the trait directly.
pub trait AgentRunResolver: Send + Sync {
    fn resolve(&self, agent_id: &str) -> (Option<String>, Option<String>);
}

pub struct RepetitionGuard {
    window_size: usize,
    repeat_threshold: usize,
    action: RepetitionAction,
    per_agent: RwLock<HashMap<String, AgentWindow>>,
    /// AC-10 Tier-3 inject sink. Interior-mutable `OnceLock` (was `Option`) so
    /// the cli composition root can LATE-BIND the per-agent `ContextAssembler`
    /// AFTER this process-global guard is constructed (the guard is built at
    /// `wire_capabilities` Step 7, before the per-agent assembler exists).
    /// Set EITHER at construction (`with_context_assembler`) OR post-construction
    /// (`set_context_assembler`). `RepetitionGuard` is never `Clone`d (always
    /// `Arc::new`), so `OnceLock`-not-`Clone` is safe.
    context_assembler: OnceLock<Arc<dyn ContextAssembler>>,
    prompt_injection_helpers: Option<Arc<dyn PromptInjectionHelpers>>,
    event_bus: Option<Arc<dyn EventBusEmit>>,
    run_resolver: Option<Arc<dyn AgentRunResolver>>,
    /// Slice C — when `false`, both `record_tool_call` and `record_output`
    /// short-circuit to `RepetitionDecision::Pass` at entry. Honors
    /// AC-13's `RepetitionGuardConfig.enabled=Some(false)` configuration.
    /// Defaults to `true` (Slice A/B behavior preserved).
    enabled: bool,
}

#[derive(Default)]
struct AgentWindow {
    tool_calls: VecDeque<ToolCallSignature>,
    outputs: VecDeque<OutputHash>,
    warned: bool,
    /// Slice B emit-dedup: tracks the most-recently-emitted
    /// `run.repetition_detected.action_taken` value for this agent. Used
    /// to suppress duplicate emits when consecutive observations yield
    /// the same decision (closes adversarial round-1 Warning #2 emit
    /// spam DoS). Reset to None when the window resets (Pass observation
    /// on output-hash path, or via the WarnThenTerminate flip).
    last_emit_action: Option<String>,
}

impl RepetitionGuard {
    pub fn new(window_size: usize, repeat_threshold: usize, action: RepetitionAction) -> Self {
        let window_size = if window_size > MAX_WINDOW_SIZE {
            eprintln!(
                "RepetitionGuard::new window_size={window_size} clamped to MAX_WINDOW_SIZE={MAX_WINDOW_SIZE}"
            );
            MAX_WINDOW_SIZE
        } else {
            window_size
        };
        Self {
            window_size,
            repeat_threshold,
            action,
            per_agent: RwLock::new(HashMap::new()),
            context_assembler: OnceLock::new(),
            prompt_injection_helpers: None,
            event_bus: None,
            run_resolver: None,
            enabled: true,
        }
    }

    /// Slice C builder — set the AC-13 `enabled` switch. When `false`,
    /// `record_tool_call` and `record_output` short-circuit to Pass at
    /// entry. Defaults to `true`; preserves Slice A/B semantics for
    /// callers that don't invoke this builder.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Slice A builder retained for backward-compat — wires the
    /// `ContextAssembler` sink for the AC-10 Tier-3 inject path. Sets the
    /// `OnceLock` cell on a fresh guard (the only existing callers set it once);
    /// a second set is a no-op (the cell keeps its first value).
    pub fn with_context_assembler(self, ca: Arc<dyn ContextAssembler>) -> Self {
        let _ = self.context_assembler.set(ca);
        self
    }

    /// Wave-12 — LATE-BIND the `ContextAssembler` sink AFTER construction
    /// (`&self`, interior-mutable `OnceLock`). Required because the process-global
    /// tool-path guard is built at the cli `wire_capabilities` Step 7, BEFORE the
    /// per-agent `ContextAssemblerImpl` exists; the composition root sets it once
    /// the per-agent assembler is built (`try_spawn_agent_loop`). Returns `true`
    /// if this call set the cell, `false` if it was already set (idempotent —
    /// the single-agent daemon sets it exactly once).
    pub fn set_context_assembler(&self, ca: Arc<dyn ContextAssembler>) -> bool {
        self.context_assembler.set(ca).is_ok()
    }

    /// Slice B builder — wires the `PromptInjectionHelpers` sanitization
    /// stage. Without this, the inject path stays fail-closed (no
    /// `inject_tier3_warning` invocation even if `context_assembler` is
    /// Some) — refusing to inject attacker-influenceable content into
    /// Tier 3 without the injection-defense chain.
    pub fn with_prompt_injection_helpers(mut self, pih: Arc<dyn PromptInjectionHelpers>) -> Self {
        self.prompt_injection_helpers = Some(pih);
        self
    }

    /// Slice B builder — wires the `EventBusEmit` so the guard can emit
    /// `run.repetition_detected` events on non-Pass decisions.
    pub fn with_event_bus(mut self, bus: Arc<dyn EventBusEmit>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Slice B builder — wires the `AgentRunResolver` for `agent_id →
    /// (run_id, task_id)` resolution at emit time. Without this, the
    /// emitted `run.repetition_detected` events have Event.run_id /
    /// Event.task_id as None.
    pub fn with_run_resolver(mut self, r: Arc<dyn AgentRunResolver>) -> Self {
        self.run_resolver = Some(r);
        self
    }

    /// Decide under the already-held `per_agent` write lock. Returns
    /// `(decision, Option<InjectDirective>, Option<Event>)`. **Lock-drop-before-
    /// callback discipline**: this method MUST NOT invoke
    /// `ContextAssembler::inject_tier3_warning` or `EventBusEmit::emit` while
    /// holding the lock — those callbacks may re-enter back into this guard
    /// (a misbehaving ContextAssembler impl that records a tool call would
    /// otherwise deadlock the per_agent RwLock). The caller drops the lock
    /// then invokes the directive + event. **Lock-order invariant**: this
    /// method invokes `run_resolver.resolve(...)` which acquires
    /// `run_store.read()` — callers MUST NOT hold any other RunManager
    /// lock when reaching this path.
    fn decide_locked(
        &self,
        w: &mut AgentWindow,
        agent_id: &str,
        pattern: &str,
        detection_type: &'static str,
        repeat_count: u32,
    ) -> (RepetitionDecision, Option<InjectDirective>, Option<Event>) {
        let mut inject_directive: Option<InjectDirective> = None;
        let decision = match self.action {
            RepetitionAction::WarnOnly => RepetitionDecision::Warn(pattern.into()),
            RepetitionAction::Terminate => RepetitionDecision::Terminate(pattern.into()),
            RepetitionAction::WarnThenTerminate => {
                if w.warned {
                    w.warned = false;
                    RepetitionDecision::Terminate(pattern.into())
                } else {
                    w.warned = true;
                    // AC-10 inject prep — fail-CLOSED: refuse to inject
                    // without BOTH PromptInjectionHelpers (sanitization
                    // stage) AND ContextAssembler (sink). Severity::Critical
                    // flags in the synthesized warn message short-circuit
                    // the inject (defense-in-depth on attacker-influenceable
                    // pattern content). Wrap stage runs UNDER the lock
                    // (pure-function trait invariant); the inject call is
                    // DEFERRED to the caller, post-lock-drop, to avoid
                    // re-entrancy deadlock if a misbehaving ContextAssembler
                    // impl re-enters the guard.
                    match (
                        self.context_assembler.get(),
                        self.prompt_injection_helpers.as_ref(),
                    ) {
                        (Some(ca), Some(pih)) => {
                            let raw_msg = format!(
                                "Repetition detected: {pattern}. Please vary approach or confirm intent."
                            );
                            let flags = pih.flag_injection_patterns(&raw_msg);
                            let has_critical = flags
                                .iter()
                                .any(|f| matches!(f.severity, Severity::Critical));
                            if has_critical {
                                eprintln!(
                                    "AC-10 inject path: critical-severity flags in synthesized warning — skipping inject. flag_count={}",
                                    flags.len()
                                );
                            } else {
                                let wrapped = pih.wrap_with_boundary(
                                    &raw_msg,
                                    "repetition-guard",
                                    TrustLevel::Untrusted,
                                );
                                inject_directive = Some(InjectDirective {
                                    assembler: Arc::clone(ca),
                                    agent_id: agent_id.to_string(),
                                    wrapped_msg: wrapped,
                                });
                            }
                        }
                        (Some(_), None) => {
                            eprintln!(
                                "AC-10 missing PromptInjectionHelpers — skipping inject (fail-closed)."
                            );
                        }
                        (None, _) => {
                            // No context_assembler wired — Slice A
                            // backward-compat path. No eprintln (silent
                            // no-op matches Slice A semantics).
                        }
                    }
                    RepetitionDecision::Warn(pattern.into())
                }
            }
        };

        // Emit-dedup: only emit `run.repetition_detected` on the FIRST
        // observation that hits the threshold (transition into a non-Pass
        // state). Suppress subsequent emits for the same agent until either
        // (a) a Pass observation resets the window OR (b) WarnThenTerminate
        // flips warned to false (which itself constitutes a transition).
        // Closes adversarial round-1 Warning #2 (emit-spam DoS).
        // The action match above exhausts to Warn / Terminate variants only
        // (Pass is never produced by `decide_locked` — the callers only
        // invoke it when the threshold is crossed). Hard-coding to a 2-arm
        // match makes the unreachable Pass branch a compile-time error if
        // a future variant slips in.
        let new_action: &'static str = match &decision {
            RepetitionDecision::Warn(_) => "warn",
            RepetitionDecision::Terminate(_) => "terminate",
            RepetitionDecision::Pass => {
                unreachable!("decide_locked never returns Pass — action match is closed")
            }
        };
        let prev = w.last_emit_action.as_deref();
        let is_transition = prev != Some(new_action);

        let event = if self.event_bus.is_some() && is_transition {
            w.last_emit_action = Some(new_action.to_string());
            let (resolved_run_id, resolved_task_id) = self
                .run_resolver
                .as_ref()
                .map(|r| r.resolve(agent_id))
                .unwrap_or((None, None));
            Some(events::run_repetition_detected_event(
                resolved_run_id.as_deref(),
                resolved_task_id.as_deref(),
                agent_id,
                detection_type,
                pattern,
                repeat_count,
                new_action,
            ))
        } else {
            None
        };
        (decision, inject_directive, event)
    }
}

/// Slice B inject directive — returned from `decide_locked` for execution
/// AFTER the caller drops the per_agent write lock. Decouples the lock
/// scope from the ContextAssembler callback to prevent re-entrancy
/// deadlocks.
struct InjectDirective {
    assembler: Arc<dyn ContextAssembler>,
    agent_id: String,
    wrapped_msg: String,
}

/// Slice C — predicate distinguishing the `Terminate` discriminant from
/// `Pass` / `Warn`. Used by the AC-11 retry-classifier hand-off and by
/// the M008 internal flow that decides whether to continue or surface
/// the M009 `llm-error::repetition-terminated` non-retryable variant.
pub fn is_terminate_decision(d: &RepetitionDecision) -> bool {
    matches!(d, RepetitionDecision::Terminate(_))
}

/// Slice C — AC-11 retry-classifier predicate. Returns `true` for Pass /
/// Warn (retryable downstream LLM calls) and `false` for Terminate (the
/// safety-valve decision that must NOT be retried, mapping to M009's
/// `llm-error::repetition-terminated` non-retryable variant per PRD
/// §4.2.3 + §4.6).
pub fn is_retryable_repetition_decision(d: &RepetitionDecision) -> bool {
    !is_terminate_decision(d)
}

impl RepetitionGuardCheck for RepetitionGuard {
    fn record_tool_call(&self, agent_id: &str, sig: ToolCallSignature) -> RepetitionDecision {
        if !self.enabled {
            return RepetitionDecision::Pass;
        }
        if validate_agent_id(agent_id).is_err() {
            eprintln!(
                "RepetitionGuard::record_tool_call invalid agent_id={:?}",
                agent_id
            );
            return RepetitionDecision::Pass;
        }
        if sig.tool_id.len() > MAX_TOOL_FIELD_LEN_BYTES
            || sig.method.len() > MAX_TOOL_FIELD_LEN_BYTES
        {
            eprintln!(
                "RepetitionGuard::record_tool_call oversized signature: tool_id_len={} method_len={} (cap {})",
                sig.tool_id.len(),
                sig.method.len(),
                MAX_TOOL_FIELD_LEN_BYTES
            );
            return RepetitionDecision::Pass;
        }
        let pattern = sig.to_string();
        let (decision, inject_opt, event_opt) = {
            let mut map = self.per_agent.write().unwrap();
            if !map.contains_key(agent_id) && map.len() >= MAX_AGENTS_PER_GUARD {
                eprintln!(
                    "RepetitionGuard::record_tool_call rejecting new agent_id={agent_id:?} (cap {MAX_AGENTS_PER_GUARD} reached)"
                );
                return RepetitionDecision::Pass;
            }
            let w = map.entry(agent_id.to_string()).or_default();
            w.tool_calls.push_back(sig.clone());
            if w.tool_calls.len() > self.window_size {
                w.tool_calls.pop_front();
            }
            let count = w.tool_calls.iter().filter(|c| *c == &sig).count();
            if count >= self.repeat_threshold {
                self.decide_locked(w, agent_id, &pattern, "tool_call", count as u32)
            } else {
                // Reset dedup state when threshold no longer holds (window
                // eviction caused a Pass observation).
                w.last_emit_action = None;
                (RepetitionDecision::Pass, None, None)
            }
        }; // ← per_agent write lock dropped here
        if let Some(directive) = inject_opt {
            directive
                .assembler
                .inject_tier3_warning(&directive.agent_id, &directive.wrapped_msg);
        }
        if let (Some(bus), Some(evt)) = (self.event_bus.as_ref(), event_opt) {
            bus.emit(evt);
        }
        decision
    }

    fn record_output(&self, agent_id: &str, output_hash: OutputHash) -> RepetitionDecision {
        if !self.enabled {
            return RepetitionDecision::Pass;
        }
        if validate_agent_id(agent_id).is_err() {
            eprintln!(
                "RepetitionGuard::record_output invalid agent_id={:?}",
                agent_id
            );
            return RepetitionDecision::Pass;
        }
        let (decision, inject_opt, event_opt) = {
            let mut map = self.per_agent.write().unwrap();
            if !map.contains_key(agent_id) && map.len() >= MAX_AGENTS_PER_GUARD {
                eprintln!(
                    "RepetitionGuard::record_output rejecting new agent_id={agent_id:?} (cap {MAX_AGENTS_PER_GUARD} reached)"
                );
                return RepetitionDecision::Pass;
            }
            let w = map.entry(agent_id.to_string()).or_default();
            if w.outputs.back() == Some(&output_hash) {
                w.outputs.push_back(output_hash.clone());
                if w.outputs.len() > self.window_size {
                    w.outputs.pop_front();
                }
                let run_len = w
                    .outputs
                    .iter()
                    .rev()
                    .take_while(|h| *h == &output_hash)
                    .count();
                if run_len >= self.repeat_threshold {
                    self.decide_locked(
                        w,
                        agent_id,
                        "output-repeat",
                        "output_repeat",
                        run_len as u32,
                    )
                } else {
                    w.last_emit_action = None;
                    (RepetitionDecision::Pass, None, None)
                }
            } else {
                w.outputs.clear();
                w.outputs.push_back(output_hash);
                // Different hash → window reset → emit-dedup state reset.
                w.last_emit_action = None;
                (RepetitionDecision::Pass, None, None)
            }
        }; // ← per_agent write lock dropped here
        if let Some(directive) = inject_opt {
            directive
                .assembler
                .inject_tier3_warning(&directive.agent_id, &directive.wrapped_msg);
        }
        if let (Some(bus), Some(evt)) = (self.event_bus.as_ref(), event_opt) {
            bus.emit(evt);
        }
        decision
    }
}
