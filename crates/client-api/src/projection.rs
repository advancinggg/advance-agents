//! CONTRACT-191 client projection policy — exact 29-event table + CONTRACT-112 LogOutput scan.

use std::collections::BTreeMap;

use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;

use crate::events::{ClientEventPriority, ClientScalar};

/// Outcome of projecting one raw bus row.
#[derive(Debug, Clone)]
pub enum ProjectOutcome {
    /// Deliverable client event fields (event_id sealed by the handler).
    Deliver {
        event_type: String,
        timestamp: String,
        agent_id: String,
        run_id: Option<String>,
        trace_id: Option<String>,
        priority: ClientEventPriority,
        data: BTreeMap<String, ClientScalar>,
        redacted_leaves: u32,
    },
    /// Projection policy reject (counts toward `rejected_count`).
    Reject,
    /// Internal `client_api.*` — silently consume (no reject count, no audit).
    SilentConsume,
}

/// Project a raw provider row under the exact D6 table + D5 metadata grammar + CONTRACT-112.
pub fn project_raw(
    event_type: &str,
    timestamp: &DateTime<Utc>,
    agent_id: &str,
    run_id: Option<&str>,
    trace_id: &str,
    payload: &Value,
    detector: &dyn LeakDetector,
) -> ProjectOutcome {
    // Silent consume before unknown-type rejection.
    if event_type.starts_with("client_api.") {
        return ProjectOutcome::SilentConsume;
    }

    let Some(spec) = table_spec(event_type) else {
        return ProjectOutcome::Reject;
    };

    // Metadata grammar (before scanning).
    if !valid_agent_id(agent_id) {
        return ProjectOutcome::Reject;
    }
    if let Some(r) = run_id {
        if !valid_run_id(r) {
            return ProjectOutcome::Reject;
        }
    }
    let trace_out = match normalize_trace_id(trace_id) {
        Some(t) => t,
        None => return ProjectOutcome::Reject,
    };

    // CONTRACT-112 LogOutput on metadata strings only.
    if !meta_clean(detector, agent_id) {
        return ProjectOutcome::Reject;
    }
    if let Some(r) = run_id {
        if !meta_clean(detector, r) {
            return ProjectOutcome::Reject;
        }
    }
    if let Some(ref t) = trace_out {
        if !meta_clean(detector, t) {
            return ProjectOutcome::Reject;
        }
    }

    let ts = timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true);
    // Scan only emitter-controlled metadata (already done) + payload strings later.
    // Canonical timestamp is not scanned.

    let mut data = BTreeMap::new();
    let mut redacted_leaves = 0u32;
    let obj = match payload {
        Value::Object(m) => m,
        _ => {
            // Non-object payload → empty data.
            return ProjectOutcome::Deliver {
                event_type: spec.literal.to_string(),
                timestamp: ts,
                agent_id: agent_id.to_string(),
                run_id: run_id.map(|s| s.to_string()),
                trace_id: trace_out,
                priority: spec.priority,
                data,
                redacted_leaves: 0,
            };
        }
    };

    for leaf in spec.leaves {
        let Some(raw) = obj.get(leaf.name) else {
            continue;
        };
        match extract_leaf(leaf, raw, detector) {
            LeafExtract::Omit => {}
            LeafExtract::RejectEvent => return ProjectOutcome::Reject,
            LeafExtract::Keep(scalar, redacted) => {
                if redacted {
                    redacted_leaves = redacted_leaves.saturating_add(1);
                }
                data.insert(leaf.name.to_string(), scalar);
            }
        }
    }

    ProjectOutcome::Deliver {
        event_type: spec.literal.to_string(),
        timestamp: ts,
        agent_id: agent_id.to_string(),
        run_id: run_id.map(|s| s.to_string()),
        trace_id: trace_out,
        priority: spec.priority,
        data,
        redacted_leaves,
    }
}

fn meta_clean(detector: &dyn LeakDetector, text: &str) -> bool {
    matches!(
        detector.scan(text, ScanContext::LogOutput),
        ScanResult::Clean
    )
}

enum LeafExtract {
    Omit,
    RejectEvent,
    Keep(ClientScalar, bool),
}

fn extract_leaf(leaf: &LeafSpec, raw: &Value, detector: &dyn LeakDetector) -> LeafExtract {
    match leaf.kind {
        LeafKind::U32 => match raw.as_u64() {
            Some(n) if n <= u32::MAX as u64 => {
                if let Some(max) = leaf.max_u32 {
                    if n > max as u64 {
                        return LeafExtract::Omit;
                    }
                }
                if let Some(min) = leaf.min_u32 {
                    if n < min as u64 {
                        return LeafExtract::Omit;
                    }
                }
                LeafExtract::Keep(ClientScalar::Unsigned(n), false)
            }
            _ => LeafExtract::Omit,
        },
        LeafKind::U64 => match raw.as_u64() {
            Some(n) => LeafExtract::Keep(ClientScalar::Unsigned(n), false),
            _ => LeafExtract::Omit,
        },
        LeafKind::FiniteF64 { min, max } => match raw.as_f64() {
            Some(f) if f.is_finite() && f >= min && f <= max => {
                LeafExtract::Keep(ClientScalar::Float(f), false)
            }
            _ => LeafExtract::Omit,
        },
        LeafKind::Enum(opts) => match raw.as_str() {
            Some(s) if opts.iter().any(|o| *o == s) => {
                LeafExtract::Keep(ClientScalar::String(s.to_string()), false)
            }
            _ => LeafExtract::Omit,
        },
        LeafKind::SessionId => match raw.as_str() {
            Some(s) if valid_session_id(s) => scan_string_leaf(s, detector),
            _ => LeafExtract::Omit,
        },
        LeafKind::EntityRef => match raw.as_str() {
            Some(s) if valid_entity_ref(s) => scan_string_leaf(s, detector),
            _ => LeafExtract::Omit,
        },
        LeafKind::StringScanned => match raw.as_str() {
            Some(s) => scan_string_leaf(s, detector),
            _ => LeafExtract::Omit,
        },
    }
}

fn scan_string_leaf(s: &str, detector: &dyn LeakDetector) -> LeafExtract {
    match detector.scan(s, ScanContext::LogOutput) {
        ScanResult::Clean => LeafExtract::Keep(ClientScalar::String(s.to_string()), false),
        ScanResult::Redacted { redacted, .. } => {
            LeafExtract::Keep(ClientScalar::String(redacted), true)
        }
        ScanResult::Blocked { .. } | ScanResult::Warned { .. } => LeafExtract::RejectEvent,
    }
}

// ── Metadata grammar ──────────────────────────────────────────────────────────────────────

fn valid_agent_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 256 {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'.' || *c == b':' || *c == b'-')
}

fn valid_run_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

fn normalize_trace_id(s: &str) -> Option<Option<String>> {
    if s.is_empty() {
        return Some(None);
    }
    if s.len() > 256 {
        return None;
    }
    if is_uuid_hyphenated(s) || is_crockford_ulid(s) || is_runnable_trace(s) {
        // Controls / bidi / invisibles already rejected by the form checks for UUID/ULID;
        // runnable form checks ComponentId UTF-8 + no controls.
        Some(Some(s.to_string()))
    } else {
        None
    }
}

fn is_uuid_hyphenated(s: &str) -> bool {
    // lowercase hyphenated UUID: 8-4-4-4-12 hex
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    let is_hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !is_hex(c) {
                    return false;
                }
            }
        }
    }
    true
}

fn is_crockford_ulid(s: &str) -> bool {
    // 26 uppercase Crockford base32
    if s.len() != 26 {
        return false;
    }
    s.bytes().all(|c| {
        matches!(c, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z')
    })
}

fn is_runnable_trace(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("runnable:") else {
        return false;
    };
    if rest.is_empty() || rest.len() > 247 {
        return false;
    }
    // valid ComponentId UTF-8 with no control, bidi, or invisible codepoints
    if !rest.is_ascii() {
        // Non-ASCII ComponentIds are allowed (plan CE-T27); reject controls/bidi/invisibles.
        return rest.chars().all(|ch| {
            let c = ch as u32;
            // Reject C0/C1 controls, bidi, zero-width, etc.
            !ch.is_control()
                && !matches!(
                    c,
                    0x200B..=0x200F
                        | 0x202A..=0x202E
                        | 0x2060..=0x2064
                        | 0x2066..=0x206F
                        | 0xFEFF
                )
        }) && rest.len() <= 247;
    }
    !rest.bytes().any(|c| c < 0x20 || c == 0x7F)
}

fn valid_session_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

fn valid_entity_ref(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 256 {
        return false;
    }
    // agent: or component: + colon-delimited segments, or bare production entity ID.
    let body = if let Some(rest) = s.strip_prefix("agent:") {
        rest
    } else if let Some(rest) = s.strip_prefix("component:") {
        rest
    } else {
        s
    };
    if body.is_empty() {
        return false;
    }
    body.split(':').all(|seg| {
        !seg.is_empty()
            && seg
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-')
    })
}

// ── Exact 29-row table ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct LeafSpec {
    name: &'static str,
    kind: LeafKind,
    min_u32: Option<u32>,
    max_u32: Option<u32>,
}

#[derive(Clone, Copy)]
enum LeafKind {
    U32,
    U64,
    FiniteF64 {
        min: f64,
        max: f64,
    },
    Enum(&'static [&'static str]),
    SessionId,
    EntityRef,
    #[allow(dead_code)]
    StringScanned,
}

struct EventSpec {
    literal: &'static str,
    priority: ClientEventPriority,
    leaves: &'static [LeafSpec],
}

const STATUS_RUN: &[&str] = &[
    "active",
    "suspended",
    "paused",
    "completed",
    "failed",
    "cancelled",
];
const DECISION_ROUND: &[&str] = &[
    "continue-allowed",
    "blocked:rounds-exceeded",
    "blocked:cancel-pending",
];
const DETECTION_TYPE: &[&str] = &["tool_call", "output_repeat"];
const ACTION_TAKEN: &[&str] = &["warn", "terminate"];
const STRATEGY: &[&str] = &["self-execute", "decompose", "delegate-single"];
const SUBTASK_STATUS: &[&str] = &["pending", "in-progress", "completed", "failed", "skipped"];
const MSG_KIND: &[&str] = &["user", "agent", "control", "auto", "system"];
const AWAIT_MODE: &[&str] = &["all-of", "any-of"];
const AUTO_STATUS: &[&str] = &["keep", "discard", "crash"];
const AUTO_DEGRADED: &[&str] = &["no-progress-limit", "llm-error-limit"];
const AUTO_HALTED: &[&str] = &[
    "safety-valve: max_iterations",
    "safety-valve: max_cost_usd",
    "safety-valve: max_wall_time",
];

fn table_spec(event_type: &str) -> Option<&'static EventSpec> {
    TABLE.iter().find(|s| s.literal == event_type)
}

/// All accepted event type literals (for filter validation).
pub fn is_accepted_event_type(event_type: &str) -> bool {
    table_spec(event_type).is_some()
}

/// Exact 29 accepted literals (for tests).
pub fn accepted_event_literals() -> &'static [&'static str] {
    &[
        "run.created",
        "run.reused",
        "run.suspended",
        "run.resumed",
        "run.round_completed",
        "run.paused",
        "run.completed",
        "run.failed",
        "run.cancelled",
        "run.interrupted",
        "run.repetition_detected",
        "task.decomposed",
        "task.subtask_updated",
        "msg.received",
        "mailbox.delivery_slow",
        "orchestration.await_started",
        "orchestration.await_progress",
        "orchestration.await_satisfied",
        "orchestration.await_idle_timeout",
        "orchestration.await_session_closed",
        "orchestration.reply_late",
        "orchestration.deadlock_rejected",
        "auto.iteration_started",
        "auto.iteration_completed",
        "auto.iteration_kept",
        "auto.iteration_discarded",
        "auto.iteration_crashed",
        "auto.degraded",
        "auto.halted",
    ]
}

static TABLE: &[EventSpec] = &[
    EventSpec {
        literal: "run.created",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "run.reused",
        priority: ClientEventPriority::Normal,
        leaves: &[LeafSpec {
            name: "status",
            kind: LeafKind::Enum(STATUS_RUN),
            min_u32: None,
            max_u32: None,
        }],
    },
    EventSpec {
        literal: "run.suspended",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "run.resumed",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "run.round_completed",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "iteration",
                kind: LeafKind::U32,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "token_used",
                kind: LeafKind::U64,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "cost_usd",
                kind: LeafKind::FiniteF64 {
                    min: 0.0,
                    max: 1e12,
                },
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "decision",
                kind: LeafKind::Enum(DECISION_ROUND),
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "run.paused",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "run.completed",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "run.failed",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "run.cancelled",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "run.interrupted",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "run.repetition_detected",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "detection_type",
                kind: LeafKind::Enum(DETECTION_TYPE),
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "repeat_count",
                kind: LeafKind::U32,
                min_u32: Some(1),
                max_u32: None,
            },
            LeafSpec {
                name: "action_taken",
                kind: LeafKind::Enum(ACTION_TAKEN),
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "task.decomposed",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "strategy",
                kind: LeafKind::Enum(STRATEGY),
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "subtask_count",
                kind: LeafKind::U32,
                min_u32: None,
                max_u32: Some(256),
            },
        ],
    },
    EventSpec {
        literal: "task.subtask_updated",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "old_status",
                kind: LeafKind::Enum(SUBTASK_STATUS),
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "new_status",
                kind: LeafKind::Enum(SUBTASK_STATUS),
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "msg.received",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "kind",
                kind: LeafKind::Enum(MSG_KIND),
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "delivery_latency_ms",
                kind: LeafKind::U64,
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "mailbox.delivery_slow",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "latency_ms",
                kind: LeafKind::U64,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "queue_depth",
                kind: LeafKind::U64,
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "orchestration.await_started",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "session_id",
                kind: LeafKind::SessionId,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "mode",
                kind: LeafKind::Enum(AWAIT_MODE),
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "targets",
                kind: LeafKind::U32,
                min_u32: None,
                max_u32: Some(32),
            },
        ],
    },
    EventSpec {
        literal: "orchestration.await_progress",
        priority: ClientEventPriority::Low,
        leaves: &[
            LeafSpec {
                name: "session_id",
                kind: LeafKind::SessionId,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "target",
                kind: LeafKind::EntityRef,
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "orchestration.await_satisfied",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "session_id",
                kind: LeafKind::SessionId,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "mode",
                kind: LeafKind::Enum(AWAIT_MODE),
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "replies",
                kind: LeafKind::U32,
                min_u32: None,
                max_u32: Some(32),
            },
        ],
    },
    EventSpec {
        literal: "orchestration.await_idle_timeout",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "session_id",
                kind: LeafKind::SessionId,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "target",
                kind: LeafKind::EntityRef,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "idle_seconds",
                kind: LeafKind::U32,
                min_u32: Some(1),
                max_u32: Some(3600),
            },
        ],
    },
    EventSpec {
        literal: "orchestration.await_session_closed",
        priority: ClientEventPriority::Normal,
        leaves: &[LeafSpec {
            name: "session_id",
            kind: LeafKind::SessionId,
            min_u32: None,
            max_u32: None,
        }],
    },
    EventSpec {
        literal: "orchestration.reply_late",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "session_id",
                kind: LeafKind::SessionId,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "slot",
                kind: LeafKind::U32,
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "orchestration.deadlock_rejected",
        priority: ClientEventPriority::Normal,
        leaves: &[],
    },
    EventSpec {
        literal: "auto.iteration_started",
        priority: ClientEventPriority::Normal,
        leaves: &[LeafSpec {
            name: "iter",
            kind: LeafKind::U32,
            min_u32: None,
            max_u32: None,
        }],
    },
    EventSpec {
        literal: "auto.iteration_completed",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "iter",
                kind: LeafKind::U32,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "status",
                kind: LeafKind::Enum(AUTO_STATUS),
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "auto.iteration_kept",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "iter",
                kind: LeafKind::U32,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "metric",
                kind: LeafKind::FiniteF64 {
                    min: -1e12,
                    max: 1e12,
                },
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "auto.iteration_discarded",
        priority: ClientEventPriority::Normal,
        leaves: &[
            LeafSpec {
                name: "iter",
                kind: LeafKind::U32,
                min_u32: None,
                max_u32: None,
            },
            LeafSpec {
                name: "metric",
                kind: LeafKind::FiniteF64 {
                    min: -1e12,
                    max: 1e12,
                },
                min_u32: None,
                max_u32: None,
            },
        ],
    },
    EventSpec {
        literal: "auto.iteration_crashed",
        priority: ClientEventPriority::Normal,
        leaves: &[LeafSpec {
            name: "iter",
            kind: LeafKind::U32,
            min_u32: None,
            max_u32: None,
        }],
    },
    EventSpec {
        literal: "auto.degraded",
        priority: ClientEventPriority::Normal,
        leaves: &[LeafSpec {
            name: "reason",
            kind: LeafKind::Enum(AUTO_DEGRADED),
            min_u32: None,
            max_u32: None,
        }],
    },
    EventSpec {
        literal: "auto.halted",
        priority: ClientEventPriority::Normal,
        leaves: &[LeafSpec {
            name: "reason",
            kind: LeafKind::Enum(AUTO_HALTED),
            min_u32: None,
            max_u32: None,
        }],
    },
];
