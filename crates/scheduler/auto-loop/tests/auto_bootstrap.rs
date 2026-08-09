//! AC-22 (M015-side closure): auto-bootstrap coordination surface. Verifies
//! `DefaultAutoLoopDriver::consult_auto_bootstrap` delegates to the
//! `AutoBootstrapApplier`, translates the report to PRD §15.3.21 event payloads,
//! and emits them via the `AutoBootstrapEventSink` — plus the pure
//! `report_to_event_payloads` translator.
//!
//! M005 (cap-lifecycle) owns the authoritative parse/apply executor; these
//! tests use a `RecordingAutoBootstrapApplier` test double returning
//! preconfigured reports. Cross-module deferred (MODULE-015 §3.6): the
//! M005-bound applier impl + M019-bound sink impl + the Auto-mode-init
//! invocation of `consult_auto_bootstrap`.

mod common;

use std::sync::Arc;

use advance_scheduler_auto_loop::{
    report_to_event_payloads, AutoBootstrapApplierError, AutoBootstrapCoordinationError,
    AutoLoopError, BootstrapEventPayload, ConflictKind, DefaultAutoLoopDriver, M015BootstrapEntry,
    M015BootstrapOutcome, M015BootstrapReport, SkippedKind,
};

use common::{
    NoopIterationCheckpoint, NoopIterationRollback, RecordingAutoBootstrapApplier,
    RecordingAutoBootstrapEventSink,
};

fn entry(
    template: &str,
    alias: &str,
    target_path: &str,
    outcome: M015BootstrapOutcome,
) -> M015BootstrapEntry {
    M015BootstrapEntry {
        template: template.to_string(),
        alias: alias.to_string(),
        target_path: target_path.to_string(),
        outcome,
    }
}

fn spawned_entry(alias: &str) -> M015BootstrapEntry {
    entry(
        "explorer",
        alias,
        &format!("agents/{alias}"),
        M015BootstrapOutcome::Spawned,
    )
}

fn bare_driver() -> DefaultAutoLoopDriver {
    DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
}

// MODULE-015-T22-slD.a — empty raw_yaml + no applier nor sink → Ok, no calls.
#[tokio::test]
async fn empty_yaml_no_wiring_ok() {
    let driver = bare_driver();
    driver
        .consult_auto_bootstrap("root", "")
        .await
        .expect("empty config + no wiring → Ok");
}

// MODULE-015-T22-slD.b — non-empty + only applier (sink None) → NotConfigured;
// applier NOT called.
#[tokio::test]
async fn non_empty_only_applier_not_configured() {
    let applier = RecordingAutoBootstrapApplier::new(Ok(M015BootstrapReport {
        entries: vec![spawned_entry("scout")],
    }));
    let driver = bare_driver().with_auto_bootstrap_applier(Arc::new(applier.clone()));

    let err = driver
        .consult_auto_bootstrap("root", "auto-bootstrap: [...]")
        .await
        .expect_err("expected NotConfigured");
    match err {
        AutoLoopError::AutoBootstrap(inner) => assert_eq!(
            inner,
            AutoBootstrapCoordinationError::NotConfigured {
                applier_present: true,
                sink_present: false,
            }
        ),
        other => panic!("expected AutoBootstrap(NotConfigured); got {other:?}"),
    }
    assert!(
        applier.calls().is_empty(),
        "applier must NOT be called when fail-CLOSED before dispatch"
    );
}

// MODULE-015-T22-slD.b2 — non-empty + only sink (applier None) → NotConfigured;
// sink NOT called.
#[tokio::test]
async fn non_empty_only_sink_not_configured() {
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver().with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    let err = driver
        .consult_auto_bootstrap("root", "auto-bootstrap: [...]")
        .await
        .expect_err("expected NotConfigured");
    match err {
        AutoLoopError::AutoBootstrap(inner) => assert_eq!(
            inner,
            AutoBootstrapCoordinationError::NotConfigured {
                applier_present: false,
                sink_present: true,
            }
        ),
        other => panic!("expected AutoBootstrap(NotConfigured); got {other:?}"),
    }
    assert!(sink.calls().is_empty(), "sink must NOT be called");
}

// MODULE-015-T22-slD.b3 — empty/whitespace raw_yaml + only applier → Ok;
// applier NOT called (empty-config bypasses the wiring check).
#[tokio::test]
async fn empty_yaml_partial_wiring_ok() {
    let applier = RecordingAutoBootstrapApplier::new(Ok(M015BootstrapReport { entries: vec![] }));
    let driver = bare_driver().with_auto_bootstrap_applier(Arc::new(applier.clone()));

    driver
        .consult_auto_bootstrap("root", "   \n  ")
        .await
        .expect("whitespace-only config → Ok regardless of wiring");
    assert!(
        applier.calls().is_empty(),
        "applier must NOT be called for empty config"
    );
}

// MODULE-015-T22-slD.c — 1 Spawned entry → sink gets a Spawned payload with the
// PRD §15.3.21 field set (agent_id = parent root).
#[tokio::test]
async fn spawned_entry_emits_spawned_payload() {
    let report = M015BootstrapReport {
        entries: vec![spawned_entry("scout")],
    };
    let applier = RecordingAutoBootstrapApplier::new(Ok(report));
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(applier.clone()))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    driver
        .consult_auto_bootstrap("root", "auto-bootstrap: [...]")
        .await
        .expect("ok");
    // Applier was called with the right inputs.
    assert_eq!(
        applier.calls(),
        vec![("root".to_string(), "auto-bootstrap: [...]".to_string())]
    );
    // Sink received the Spawned payload with agent_id = parent root.
    assert_eq!(
        sink.calls(),
        vec![BootstrapEventPayload::Spawned {
            agent_id: "root".to_string(),
            template: "explorer".to_string(),
            alias: "scout".to_string(),
            target_path: "agents/scout".to_string(),
        }]
    );
}

// MODULE-015-T22-slD.d — Skipped entry → Skipped payload (no template field).
#[tokio::test]
async fn skipped_entry_emits_skipped_payload() {
    let report = M015BootstrapReport {
        entries: vec![entry(
            "explorer",
            "scout",
            "agents/scout",
            M015BootstrapOutcome::Skipped {
                skip_reason: SkippedKind::AliasExistsTemplateMatches,
            },
        )],
    };
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(RecordingAutoBootstrapApplier::new(Ok(report))))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    driver
        .consult_auto_bootstrap("root", "cfg")
        .await
        .expect("ok");
    assert_eq!(
        sink.calls(),
        vec![BootstrapEventPayload::Skipped {
            agent_id: "root".to_string(),
            alias: "scout".to_string(),
            target_path: "agents/scout".to_string(),
        }]
    );
}

async fn conflict_emits(kind: ConflictKind, expected_conflict_type: &'static str) {
    let report = M015BootstrapReport {
        entries: vec![entry(
            "explorer",
            "scout",
            "agents/scout",
            M015BootstrapOutcome::Conflict {
                conflict_type: kind,
            },
        )],
    };
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(RecordingAutoBootstrapApplier::new(Ok(report))))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    driver
        .consult_auto_bootstrap("root", "cfg")
        .await
        .expect("ok");
    assert_eq!(
        sink.calls(),
        vec![BootstrapEventPayload::Conflict {
            agent_id: "root".to_string(),
            alias: "scout".to_string(),
            target_path: "agents/scout".to_string(),
            conflict_type: expected_conflict_type,
        }]
    );
}

// MODULE-015-T22-slD.e — Conflict(AliasPathMismatch) → "alias_path_mismatch".
#[tokio::test]
async fn conflict_alias_path_mismatch() {
    conflict_emits(ConflictKind::AliasPathMismatch, "alias_path_mismatch").await;
}

// MODULE-015-T22-slD.f — Conflict(PathOccupied) → "path_occupied".
#[tokio::test]
async fn conflict_path_occupied() {
    conflict_emits(ConflictKind::PathOccupied, "path_occupied").await;
}

// MODULE-015-T22-slD.g — Conflict(TemplateMismatch) → "template_mismatch".
#[tokio::test]
async fn conflict_template_mismatch() {
    conflict_emits(ConflictKind::TemplateMismatch, "template_mismatch").await;
}

// MODULE-015-T22-slD.h — applier Err(Parse) (zero-progress) → ApplierFailed;
// sink got 0 payloads.
#[tokio::test]
async fn applier_parse_error_no_emit() {
    let applier = RecordingAutoBootstrapApplier::new(Err(AutoBootstrapApplierError::Parse(
        "bad yaml".into(),
    )));
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(applier))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    let err = driver
        .consult_auto_bootstrap("root", "cfg")
        .await
        .expect_err("expected ApplierFailed");
    match err {
        AutoLoopError::AutoBootstrap(AutoBootstrapCoordinationError::ApplierFailed(
            AutoBootstrapApplierError::Parse(msg),
        )) => assert_eq!(msg, "bad yaml"),
        other => panic!("expected ApplierFailed(Parse); got {other:?}"),
    }
    assert!(
        sink.calls().is_empty(),
        "no events on zero-progress parse error"
    );
}

// MODULE-015-T22-slD.h2 — applier Err(Dispatch { partial: 2 Spawned }) → sink
// gets 2 Spawned payloads (observability) THEN ApplierFailed(Dispatch).
#[tokio::test]
async fn dispatch_with_partial_emits_then_errors() {
    let partial = M015BootstrapReport {
        entries: vec![spawned_entry("scout"), spawned_entry("critic")],
    };
    let applier = RecordingAutoBootstrapApplier::new(Err(AutoBootstrapApplierError::Dispatch {
        msg: "spawn failed mid-batch".into(),
        partial,
    }));
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(applier))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    let err = driver
        .consult_auto_bootstrap("root", "cfg")
        .await
        .expect_err("expected ApplierFailed(Dispatch)");
    // The 2 partial-success events were emitted BEFORE the error surfaced.
    assert_eq!(
        sink.calls(),
        vec![
            BootstrapEventPayload::Spawned {
                agent_id: "root".to_string(),
                template: "explorer".to_string(),
                alias: "scout".to_string(),
                target_path: "agents/scout".to_string(),
            },
            BootstrapEventPayload::Spawned {
                agent_id: "root".to_string(),
                template: "explorer".to_string(),
                alias: "critic".to_string(),
                target_path: "agents/critic".to_string(),
            },
        ],
        "partial-success events emitted before surfacing the dispatch error"
    );
    assert!(matches!(
        err,
        AutoLoopError::AutoBootstrap(AutoBootstrapCoordinationError::ApplierFailed(
            AutoBootstrapApplierError::Dispatch { .. }
        ))
    ));
}

// MODULE-015-T22-slD.h3 — over-cap Dispatch partial → NO unbounded emission
// (audit R3 fix): a buggy/hostile adapter returning Dispatch { partial: 65 }
// must NOT emit all 65 events; the cap guards the Dispatch path identically to
// the Ok path. The dispatch error still surfaces.
#[tokio::test]
async fn dispatch_with_over_cap_partial_skips_emit() {
    let entries: Vec<M015BootstrapEntry> =
        (0..65).map(|i| spawned_entry(&format!("a{i}"))).collect();
    let partial = M015BootstrapReport { entries };
    let applier = RecordingAutoBootstrapApplier::new(Err(AutoBootstrapApplierError::Dispatch {
        msg: "spawn failed mid-batch".into(),
        partial,
    }));
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(applier))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    let err = driver
        .consult_auto_bootstrap("root", "cfg")
        .await
        .expect_err("expected ApplierFailed(Dispatch)");
    assert!(matches!(
        err,
        AutoLoopError::AutoBootstrap(AutoBootstrapCoordinationError::ApplierFailed(
            AutoBootstrapApplierError::Dispatch { .. }
        ))
    ));
    assert!(
        sink.calls().is_empty(),
        "over-cap Dispatch partial must NOT emit (cap guards both paths); got {} emits",
        sink.calls().len()
    );
}

// MODULE-015-T22-slD.i — multi-entry mixed-outcome report → sink payloads in
// report.entries order.
#[tokio::test]
async fn multi_entry_emitted_in_order() {
    let report = M015BootstrapReport {
        entries: vec![
            spawned_entry("a0"),
            entry(
                "explorer",
                "a1",
                "agents/a1",
                M015BootstrapOutcome::Skipped {
                    skip_reason: SkippedKind::AliasExistsTemplateMatches,
                },
            ),
            entry(
                "explorer",
                "a2",
                "agents/a2",
                M015BootstrapOutcome::Conflict {
                    conflict_type: ConflictKind::TemplateMismatch,
                },
            ),
        ],
    };
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(RecordingAutoBootstrapApplier::new(Ok(report))))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    driver
        .consult_auto_bootstrap("root", "cfg")
        .await
        .expect("ok");
    let calls = sink.calls();
    assert_eq!(calls.len(), 3);
    assert!(matches!(calls[0], BootstrapEventPayload::Spawned { .. }));
    assert!(matches!(calls[1], BootstrapEventPayload::Skipped { .. }));
    assert!(matches!(
        calls[2],
        BootstrapEventPayload::Conflict {
            conflict_type: "template_mismatch",
            ..
        }
    ));
}

// MODULE-015-T22-slD.j — pure report_to_event_payloads 2-tuple for 5 outcome
// shapes; agent_id == "parent-root" across all; no truncation.
#[test]
fn report_to_event_payloads_all_shapes() {
    let report = M015BootstrapReport {
        entries: vec![
            spawned_entry("a0"),
            entry(
                "t",
                "a1",
                "p1",
                M015BootstrapOutcome::Skipped {
                    skip_reason: SkippedKind::AliasExistsTemplateMatches,
                },
            ),
            entry(
                "t",
                "a2",
                "p2",
                M015BootstrapOutcome::Conflict {
                    conflict_type: ConflictKind::AliasPathMismatch,
                },
            ),
            entry(
                "t",
                "a3",
                "p3",
                M015BootstrapOutcome::Conflict {
                    conflict_type: ConflictKind::PathOccupied,
                },
            ),
            entry(
                "t",
                "a4",
                "p4",
                M015BootstrapOutcome::Conflict {
                    conflict_type: ConflictKind::TemplateMismatch,
                },
            ),
        ],
    };
    let (payloads, truncations) = report_to_event_payloads(&report, "parent-root");
    assert_eq!(payloads.len(), 5);
    assert!(truncations.is_empty());
    // agent_id is parent-root across every variant.
    for p in &payloads {
        let agent_id = match p {
            BootstrapEventPayload::Spawned { agent_id, .. }
            | BootstrapEventPayload::Skipped { agent_id, .. }
            | BootstrapEventPayload::Conflict { agent_id, .. } => agent_id.clone(),
            _ => panic!("unexpected BootstrapEventPayload variant"),
        };
        assert_eq!(agent_id, "parent-root");
    }
    // Conflict discriminators in order.
    assert!(matches!(
        payloads[2],
        BootstrapEventPayload::Conflict {
            conflict_type: "alias_path_mismatch",
            ..
        }
    ));
    assert!(matches!(
        payloads[3],
        BootstrapEventPayload::Conflict {
            conflict_type: "path_occupied",
            ..
        }
    ));
    assert!(matches!(
        payloads[4],
        BootstrapEventPayload::Conflict {
            conflict_type: "template_mismatch",
            ..
        }
    ));
}

// MODULE-015-T22-slD.k — sink fails for entries 0,2 of 3 → SinkFailures([(0,_),(2,_)]);
// recorder proves all 3 emitted in entry order (no short-circuit).
#[tokio::test]
async fn sink_failures_aggregated_no_short_circuit() {
    let report = M015BootstrapReport {
        entries: vec![
            spawned_entry("a0"),
            spawned_entry("a1"),
            spawned_entry("a2"),
        ],
    };
    let sink = RecordingAutoBootstrapEventSink::failing_at(vec![0, 2]);
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(RecordingAutoBootstrapApplier::new(Ok(report))))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    let err = driver
        .consult_auto_bootstrap("root", "cfg")
        .await
        .expect_err("expected SinkFailures");
    match err {
        AutoLoopError::AutoBootstrap(AutoBootstrapCoordinationError::SinkFailures(failures)) => {
            let indices: Vec<usize> = failures.iter().map(|(i, _)| *i).collect();
            assert_eq!(indices, vec![0, 2], "failed indices in order");
        }
        other => panic!("expected SinkFailures; got {other:?}"),
    }
    // All 3 emitted in entry order despite failures at 0 and 2 (no short-circuit).
    let aliases: Vec<String> = sink
        .calls()
        .iter()
        .map(|p| match p {
            BootstrapEventPayload::Spawned { alias, .. } => alias.clone(),
            _ => "?".to_string(),
        })
        .collect();
    assert_eq!(aliases, vec!["a0", "a1", "a2"], "all 3 emitted in order");
}

// MODULE-015-T22-slD.l — applier returns 65-entry report (>64 cap) →
// ReportTooLarge; sink got 0 payloads.
#[tokio::test]
async fn report_too_large_fail_closed() {
    let entries: Vec<M015BootstrapEntry> =
        (0..65).map(|i| spawned_entry(&format!("a{i}"))).collect();
    let report = M015BootstrapReport { entries };
    let sink = RecordingAutoBootstrapEventSink::new();
    let driver = bare_driver()
        .with_auto_bootstrap_applier(Arc::new(RecordingAutoBootstrapApplier::new(Ok(report))))
        .with_auto_bootstrap_event_sink(Arc::new(sink.clone()));

    let err = driver
        .consult_auto_bootstrap("root", "cfg")
        .await
        .expect_err("expected ReportTooLarge");
    match err {
        AutoLoopError::AutoBootstrap(AutoBootstrapCoordinationError::ReportTooLarge {
            received,
            limit,
        }) => {
            assert_eq!(received, 65);
            assert_eq!(limit, 64);
        }
        other => panic!("expected ReportTooLarge; got {other:?}"),
    }
    assert!(
        sink.calls().is_empty(),
        "no events emitted when the report exceeds the cap"
    );
}

// MODULE-015-T22-slD.m — report_to_event_payloads truncates an over-cap template
// at a char boundary + records a TruncationRecord.
#[test]
fn report_to_event_payloads_truncates_template() {
    // 1020 ASCII + 4-byte emoji (bytes 1020-1023) + 'b' (byte 1024) = 1025 bytes.
    let big_template = format!("{}{}{}", "a".repeat(1020), "🚀", "b");
    assert_eq!(big_template.len(), 1025);
    let report = M015BootstrapReport {
        entries: vec![entry(
            &big_template,
            "scout",
            "agents/scout",
            M015BootstrapOutcome::Spawned,
        )],
    };
    let (payloads, truncations) = report_to_event_payloads(&report, "root");
    // The template was truncated to 1023 bytes at the char boundary (byte 1020) + "…".
    match &payloads[0] {
        BootstrapEventPayload::Spawned { template, .. } => {
            assert_eq!(template.len(), 1023);
            assert!(template.ends_with('…'));
            assert!(template.starts_with(&"a".repeat(1020)));
        }
        other => panic!("expected Spawned; got {other:?}"),
    }
    assert_eq!(truncations.len(), 1);
    let rec = &truncations[0];
    assert_eq!(rec.payload_index, 0);
    assert_eq!(rec.field_name, "template");
    assert_eq!(rec.original_byte_len, 1025);
    assert_eq!(rec.truncated_byte_len, 1023);
}

// MODULE-015-T22-slD.n — adversarial: payload fields are sanitized for
// control chars / ANSI-ESC / Trojan-Source bidi-overrides before flowing into
// auto.bootstrap.* events → audit logs (same posture as round_advancer's
// sanitize_for_audit for RoundDecision text). Crafted target_path/template/alias
// from an untrusted template must NOT reach the payload verbatim.
#[test]
fn report_to_event_payloads_sanitizes_injection_fields() {
    let report = M015BootstrapReport {
        entries: vec![entry(
            // template: ANSI clear-screen + forged log line.
            "explorer\x1b[2Jforged",
            // alias: newline log-line injection.
            "scout\n2026-05-22 ERROR fake-event",
            // target_path: Trojan-Source RLO bidi override (CVE-2021-42574).
            "agents/\u{202E}cohgnp",
            M015BootstrapOutcome::Spawned,
        )],
    };
    let (payloads, _truncations) = report_to_event_payloads(&report, "root\u{202E}evil");
    match &payloads[0] {
        BootstrapEventPayload::Spawned {
            agent_id,
            template,
            alias,
            target_path,
        } => {
            // No raw control / ESC / newline / bidi chars survive in ANY field.
            for (name, val) in [
                ("agent_id", agent_id),
                ("template", template),
                ("alias", alias),
                ("target_path", target_path),
            ] {
                assert!(
                    !val.contains('\x1b'),
                    "{name} must not contain ANSI ESC: {val:?}"
                );
                assert!(
                    !val.contains('\n'),
                    "{name} must not contain newline: {val:?}"
                );
                assert!(
                    !val.contains('\u{202E}'),
                    "{name} must not contain RLO bidi override: {val:?}"
                );
                // Replacement marker `_` appears where rejected chars were.
                assert!(
                    val.contains('_'),
                    "{name} should carry sanitization marker: {val:?}"
                );
            }
            // Safe content survives.
            assert!(template.starts_with("explorer"));
            assert!(alias.starts_with("scout"));
            assert!(target_path.starts_with("agents/"));
            assert!(agent_id.starts_with("root"));
        }
        other => panic!("expected Spawned; got {other:?}"),
    }
}

// MODULE-015-T22-slD.m2 — truncation also applies to non-template fields
// (alias / target_path) on a non-Spawned variant. Confirms the per-field cap
// is symmetric, not template-only.
#[test]
fn report_to_event_payloads_truncates_alias_and_target_path() {
    let big_alias = "x".repeat(2000); // > 1024
    let big_path = "p".repeat(1500); // > 1024
    let report = M015BootstrapReport {
        entries: vec![entry(
            "explorer",
            &big_alias,
            &big_path,
            M015BootstrapOutcome::Conflict {
                conflict_type: ConflictKind::PathOccupied,
            },
        )],
    };
    let (payloads, truncations) = report_to_event_payloads(&report, "root");
    match &payloads[0] {
        BootstrapEventPayload::Conflict {
            alias, target_path, ..
        } => {
            assert!(alias.len() <= 1024 && alias.ends_with('…'));
            assert!(target_path.len() <= 1024 && target_path.ends_with('…'));
        }
        other => panic!("expected Conflict; got {other:?}"),
    }
    // Both alias and target_path produced a TruncationRecord (agent_id "root"
    // is short, so exactly 2 records).
    let fields: Vec<&str> = truncations.iter().map(|r| r.field_name).collect();
    assert!(
        fields.contains(&"alias"),
        "alias truncation recorded: {fields:?}"
    );
    assert!(
        fields.contains(&"target_path"),
        "target_path truncation recorded: {fields:?}"
    );
    assert!(
        !fields.contains(&"agent_id"),
        "short agent_id must NOT be truncated: {fields:?}"
    );
}
