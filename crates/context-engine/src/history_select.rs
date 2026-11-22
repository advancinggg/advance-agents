//! ⑯ beyond a task's recent window (PRD §11.3.5): the task's earlier turns and other tasks'
//! turns the message recalls, each kept by its retention score (§11.3.4).
//!
//! The candidates come from the recall port: [`crate::ports::UnifiedSearchPort::search_task_turns`]
//! for the task's own turns (the semantic and the keyword candidates, "先语义+关键词双路取 top-N
//! 候选"), [`crate::ports::UnifiedSearchResult::turns`] for other tasks' turns (semantic,
//! `task_id != 当前 task`). Each is then ranked by its retention score ("再用 retention_score
//! rerank") and loads by it:
//!
//! - at or above [`HIGH_SCORE_THRESHOLD`] it may load whole (L0-processed), in the modes that
//!   load turns whole (wide, medium), while the turn budget holds it and no file it read has
//!   changed since; otherwise it loads as its digest;
//! - at or above [`LOW_SCORE_THRESHOLD`] it loads as its digest;
//! - below, not at all: the epoch summary or the task summary covers it.
//!
//! A candidate its producer could not score loads as its digest. In extreme mode no history
//! turn loads (PRD §11.3.5 "不加载任何历史 turn").

use std::collections::HashSet;

use crate::ports::TurnHit;
use crate::tier3::ProgressiveMode;

/// PRD §11.3.5 `high_score_threshold`: from this retention score a turn may load whole.
pub const HIGH_SCORE_THRESHOLD: f32 = 0.5;

/// PRD §11.3.5 `low_score_threshold`: from this retention score a turn loads as its digest.
pub const LOW_SCORE_THRESHOLD: f32 = 0.2;

/// How many candidates beyond the recent window each half of a task's search keeps at least
/// (PRD §11.3.5: the earlier history's "top-N"; the PRD gives no number). Each half is asked
/// for the widest window's turns more, as the window's turns are left out of what it finds.
pub const TASK_TURN_CANDIDATES: usize = 12;

/// How a selected turn loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Granularity {
    /// Whole, L0-processed, if it is fresh and the turn budget holds it; else as its digest.
    Whole,
    /// As its digest.
    Digest,
}

/// How a turn scored `retention` loads in `mode`; `None`: it does not load.
pub(crate) fn granularity(retention: Option<f32>, mode: ProgressiveMode) -> Option<Granularity> {
    if matches!(mode, ProgressiveMode::Extreme) {
        return None;
    }
    let whole_mode = matches!(mode, ProgressiveMode::Wide | ProgressiveMode::Medium);
    match retention {
        None => Some(Granularity::Digest),
        Some(score) if !score.is_finite() => None,
        Some(score) if score >= HIGH_SCORE_THRESHOLD && whole_mode => Some(Granularity::Whole),
        Some(score) if score >= LOW_SCORE_THRESHOLD => Some(Granularity::Digest),
        Some(_) => None,
    }
}

/// One turn the selection keeps, and how it loads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Selected {
    pub hit: TurnHit,
    pub granularity: Granularity,
}

/// The candidates that load in `mode`, one per turn, best retention score first (an unscored
/// one after every scored one; ties keep the producer's order). `skip` names the turns of
/// the task that load anyway (the recent window): they are left out. A turn is one
/// `(task_id, turn)` — or, when its producer gave no number, one id — and a candidate whose
/// turn came before keeps its first place (PRD §11.3.5 "按 (task_id, turn) 去重作为兜底").
pub(crate) fn select(
    hits: &[TurnHit],
    skip: &HashSet<u64>,
    mode: ProgressiveMode,
) -> Vec<Selected> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut kept: Vec<Selected> = hits
        .iter()
        .filter(|hit| !hit.turn.is_some_and(|turn| skip.contains(&turn)))
        .filter(|hit| {
            let turn = hit
                .turn
                .map_or_else(|| hit.id.clone(), |turn| turn.to_string());
            seen.insert((hit.task_id.clone(), turn))
        })
        .filter_map(|hit| {
            granularity(hit.retention, mode).map(|granularity| Selected {
                hit: hit.clone(),
                granularity,
            })
        })
        .collect();
    kept.sort_by(|a, b| match (a.hit.retention, b.hit.retention) {
        (Some(x), Some(y)) => y.total_cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn hit(task: &str, turn: Option<u64>, retention: Option<f32>) -> TurnHit {
        TurnHit {
            id: format!("{task}#turn-{}", turn.unwrap_or(0)),
            task_id: task.into(),
            similarity: 0.6,
            timestamp: SystemTime::UNIX_EPOCH,
            snippet: Some(format!("digest of {task} {turn:?}")),
            turn,
            retention,
        }
    }

    #[test]
    fn the_scores_decide_how_a_turn_loads() {
        use ProgressiveMode::*;
        assert_eq!(granularity(Some(0.5), Wide), Some(Granularity::Whole));
        assert_eq!(granularity(Some(0.91), Medium), Some(Granularity::Whole));
        assert_eq!(granularity(Some(0.49), Wide), Some(Granularity::Digest));
        assert_eq!(granularity(Some(0.2), Wide), Some(Granularity::Digest));
        assert_eq!(granularity(Some(0.19), Wide), None);
        // Compact mode loads digests only; extreme mode no history turn at all.
        assert_eq!(granularity(Some(0.9), Compact), Some(Granularity::Digest));
        assert_eq!(granularity(Some(0.3), Compact), Some(Granularity::Digest));
        assert_eq!(granularity(Some(0.1), Compact), None);
        assert_eq!(granularity(Some(0.9), Extreme), None);
        assert_eq!(granularity(None, Extreme), None);
        // An unscored turn loads as its digest; a score that is no number, not at all.
        assert_eq!(granularity(None, Wide), Some(Granularity::Digest));
        assert_eq!(granularity(Some(f32::NAN), Wide), None);
        assert_eq!(granularity(Some(f32::INFINITY), Wide), None);
    }

    #[test]
    fn selection_ranks_by_score_skips_the_window_and_keeps_one_of_each_turn() {
        let hits = vec![
            hit("t", Some(3), Some(0.3)),
            hit("t", Some(9), Some(0.8)),
            hit("t", Some(3), Some(0.95)), // the same turn again (its other half): left out
            hit("t", Some(7), Some(0.6)),  // in the recent window: left out
            hit("t", Some(2), Some(0.1)),  // below the low threshold
            hit("t", Some(5), None),       // unscored: a digest, after the scored ones
            hit("u", Some(3), Some(0.55)), // another task's turn 3 is another turn
        ];
        let skip: HashSet<u64> = [7].into_iter().collect();
        let got: Vec<(String, Option<u64>, Granularity)> =
            select(&hits, &skip, ProgressiveMode::Wide)
                .into_iter()
                .map(|s| (s.hit.task_id, s.hit.turn, s.granularity))
                .collect();
        assert_eq!(
            got,
            vec![
                ("t".to_string(), Some(9), Granularity::Whole),
                ("u".to_string(), Some(3), Granularity::Whole),
                ("t".to_string(), Some(3), Granularity::Digest),
                ("t".to_string(), Some(5), Granularity::Digest),
            ]
        );
        assert!(select(&hits, &skip, ProgressiveMode::Extreme).is_empty());
    }

    #[test]
    fn a_turn_without_a_number_is_one_turn_per_id() {
        let mut a = hit("t", None, Some(0.4));
        a.id = "t#x".into();
        let mut b = a.clone();
        b.retention = Some(0.9);
        let mut c = a.clone();
        c.id = "t#y".into();
        let got = select(&[a, b, c], &HashSet::new(), ProgressiveMode::Wide);
        let ids: Vec<&str> = got.iter().map(|s| s.hit.id.as_str()).collect();
        assert_eq!(ids, vec!["t#x", "t#y"]);
    }
}
