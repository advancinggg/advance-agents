//! PRD §11.3.1 and §11.3.5: the turn's task is settled before any reader runs —
//! the task the message names, the task routing chose, or one minted for it — and every
//! reader reads it; routing reports what it settled (`task.created` / `task.routed`). Beyond
//! the recent window, ⑯ loads history by its retention score: the task's earlier turns under
//! `# Earlier Turns` or as their digests, other tasks' turns under `# Related Turns`. Other
//! tasks' briefs land in Tier 2 (⑭).

#[path = "common/mod.rs"]
mod common;
use common::*;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_context_engine::{
    mint_task_id, AssemblyReport, AssemblyReportSink, ContextAssemblerImpl, EmbeddingPort,
    L2DigestReader, L4TaskSummaryReader, PortError, RecentTurn, RecentTurnsReader, TaskHit,
    TaskIndexPort, TaskSummaryView, TurnDigestForEmbed, TurnHit, TurnReadFileVersions,
    UnifiedSearchPort, UnifiedSearchResult, TASK_TURN_CANDIDATES,
};
use advance_shared_types::context::{AssemblyContext, AssemblyResult, ContextAssembler};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{MessageContext, MessageKind};
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::turn_log::{L0Mark, TranscriptMessage};
use async_trait::async_trait;

const TIER2_START: &str = "<!-- ctx-cache-breakpoint:1b->2 -->";
const TIER3_START: &str = "<!-- ctx-cache-breakpoint:2->3 -->";

// ─── Fixtures ───

/// Every text embeds to the same finite vector.
struct FixedEmbedding;
#[async_trait]
impl EmbeddingPort for FixedEmbedding {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, PortError> {
        Ok(vec![1.0, 0.0])
    }
}

/// The embedder is down.
struct DownEmbedding;
#[async_trait]
impl EmbeddingPort for DownEmbedding {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, PortError> {
        Err(PortError("embedder down".into()))
    }
}

/// The task index's candidates (or its failure), the agent's current task, and how often
/// routing asked for candidates.
struct Tasks {
    hits: Result<Vec<TaskHit>, String>,
    current: Option<String>,
    calls: AtomicUsize,
}
#[async_trait]
impl TaskIndexPort for Tasks {
    async fn top_n_by_similarity(
        &self,
        _agent_id: &str,
        _q: &[f32],
        _n: usize,
    ) -> Result<Vec<TaskHit>, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.hits.clone().map_err(PortError)
    }
    async fn current_task(&self, _agent_id: &str) -> Result<Option<String>, PortError> {
        Ok(self.current.clone())
    }
}

/// What recall finds, and which task each search was for.
#[derive(Default)]
struct Search {
    result: UnifiedSearchResult,
    task_turns: Vec<TurnHit>,
    /// The task each `search_other_tasks` call leaves out.
    other_than: Mutex<Vec<Option<String>>>,
    /// The task each `search_task_turns` call searches.
    searched: Mutex<Vec<String>>,
    /// The limit each `search_task_turns` call is asked.
    limits: Mutex<Vec<usize>>,
}
#[async_trait]
impl UnifiedSearchPort for Search {
    async fn search(
        &self,
        _agent_id: &str,
        _query: &str,
        _q: &[f32],
    ) -> Result<UnifiedSearchResult, PortError> {
        Ok(self.result.clone())
    }
    async fn search_other_tasks(
        &self,
        _agent_id: &str,
        _query: &str,
        _q: &[f32],
        current_task_id: Option<&str>,
    ) -> Result<UnifiedSearchResult, PortError> {
        self.other_than
            .lock()
            .unwrap()
            .push(current_task_id.map(str::to_string));
        Ok(self.result.clone())
    }
    async fn search_task_turns(
        &self,
        _agent_id: &str,
        task_id: &str,
        _query: &str,
        _q: &[f32],
        limit: usize,
    ) -> Result<Option<Vec<TurnHit>>, PortError> {
        self.searched.lock().unwrap().push(task_id.to_string());
        self.limits.lock().unwrap().push(limit);
        Ok(Some(self.task_turns.clone()))
    }
}

/// Each task's logged turns, oldest first, and which task each read was for.
#[derive(Default)]
struct History {
    turns: HashMap<String, Vec<RecentTurn>>,
    asked: Mutex<Vec<String>>,
}
#[async_trait]
impl RecentTurnsReader for History {
    async fn read_recent_turns(
        &self,
        _agent_id: &str,
        task_id: &str,
        count: usize,
    ) -> Result<Vec<RecentTurn>, PortError> {
        self.asked.lock().unwrap().push(task_id.to_string());
        let turns = self.turns.get(task_id).cloned().unwrap_or_default();
        Ok(turns[turns.len().saturating_sub(count)..].to_vec())
    }
    async fn read_turns(
        &self,
        _agent_id: &str,
        task_id: &str,
        wanted: &[u64],
    ) -> Result<Vec<RecentTurn>, PortError> {
        self.asked.lock().unwrap().push(task_id.to_string());
        Ok(self
            .turns
            .get(task_id)
            .map(|turns| {
                turns
                    .iter()
                    .filter(|t| wanted.contains(&t.turn_id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// The L2 reader's pick of the task's digests by retention: `(turn, digest)`.
struct Digests(Vec<(u64, &'static str)>);
#[async_trait]
impl L2DigestReader for Digests {
    async fn read_digests(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Vec<TurnDigestForEmbed>, PortError> {
        Ok(self
            .0
            .iter()
            .map(|(turn, digest)| TurnDigestForEmbed {
                turn_id: *turn,
                digest: digest.to_string(),
                collapsed_view: String::new(),
            })
            .collect())
    }
}

/// Records the task each summary read was for.
#[derive(Default)]
struct Summaries(Mutex<Vec<String>>);
#[async_trait]
impl L4TaskSummaryReader for Summaries {
    async fn read_task_summary(
        &self,
        _agent_id: &str,
        task_id: &str,
    ) -> Result<Option<TaskSummaryView>, PortError> {
        self.0.lock().unwrap().push(task_id.to_string());
        Ok(None)
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<Event>>);
impl EventBusEmit for Events {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}
impl Events {
    fn of(&self, prefix: &str) -> Vec<Event> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type.starts_with(prefix))
            .cloned()
            .collect()
    }
}

#[derive(Default)]
struct Reports(Mutex<Vec<AssemblyReport>>);
impl AssemblyReportSink for Reports {
    fn record(&self, report: AssemblyReport) {
        self.0.lock().unwrap().push(report);
    }
}
impl Reports {
    fn last(&self) -> AssemblyReport {
        self.0.lock().unwrap().last().cloned().expect("a report")
    }
}

struct Rig {
    tasks: Arc<Tasks>,
    search: Arc<Search>,
    l2: Arc<dyn L2DigestReader>,
    history: Arc<History>,
    summaries: Arc<Summaries>,
    events: Arc<Events>,
    reports: Arc<Reports>,
}

impl Rig {
    fn new(tasks: Result<Vec<TaskHit>, String>, search: Search, history: History) -> Self {
        Self {
            tasks: Arc::new(Tasks {
                hits: tasks,
                current: None,
                calls: AtomicUsize::new(0),
            }),
            search: Arc::new(search),
            l2: Arc::new(NullL2Digest),
            history: Arc::new(history),
            summaries: Arc::default(),
            events: Arc::default(),
            reports: Arc::default(),
        }
    }

    /// The rig, with `current` as the agent's current task.
    fn with_current_task(mut self, current: &str) -> Self {
        Arc::get_mut(&mut self.tasks)
            .expect("not shared yet")
            .current = Some(current.into());
        self
    }

    /// The rig, with `picked` as the L2 reader's pick of the task's digests.
    fn with_l2_digests(mut self, picked: &[(u64, &'static str)]) -> Self {
        self.l2 = Arc::new(Digests(picked.to_vec()));
        self
    }

    /// The assembler over the rig, on a window of `window` tokens.
    fn assembler(&self, embedding: Arc<dyn EmbeddingPort>, window: usize) -> ContextAssemblerImpl {
        ContextAssemblerImpl::new(
            Arc::new(MockCallableInventory::default()),
            Arc::new(MockHostFnInventory::default()),
            Arc::new(NullAgentIdentity),
            Arc::new(NullKnowledgeMap),
            Arc::new(NullAgentTreeSnapshot),
            embedding,
            self.tasks.clone(),
            Arc::new(NullLightLlm),
            self.search.clone(),
            self.events.clone(),
            Arc::new(NullSkillSummary),
            Arc::new(NullVectorIndex),
            self.l2.clone(),
            Arc::new(NullL3Epoch),
            self.summaries.clone(),
            Arc::new(NullL5Synthesis),
            Arc::new(NullL6Consolidation),
            Arc::new(NullPromptInjectionHelpers),
            Arc::new(NullDecomposition),
        )
        .with_recent_turns(self.history.clone())
        .with_report_sink(self.reports.clone())
        .with_model_context_window(Some(window))
    }

    async fn assemble(&self, ctx: AssemblyContext) -> AssemblyResult {
        self.assembler(Arc::new(FixedEmbedding), WIDE)
            .assemble(ctx)
            .await
            .expect("assembles")
    }

    /// Every task a reader was asked for.
    fn read_tasks(&self) -> Vec<String> {
        let mut read = self.summaries.0.lock().unwrap().clone();
        read.extend(self.history.asked.lock().unwrap().iter().cloned());
        read.extend(self.search.searched.lock().unwrap().iter().cloned());
        read
    }
}

/// A window whose remaining budget is in the wide mode.
const WIDE: usize = 400_000;

fn ctx(prompt: &str) -> AssemblyContext {
    let mut ctx = stub_ctx();
    ctx.prompt = prompt.into();
    ctx
}

fn task(id: &str, similarity: f32, brief: Option<&str>) -> TaskHit {
    TaskHit {
        task_id: id.into(),
        similarity,
        last_turn_at: None,
        snippet: brief.map(str::to_string),
    }
}

fn hit(task: &str, turn: u64, retention: Option<f32>, digest: &str) -> TurnHit {
    TurnHit {
        id: format!("{task}#turn-{turn}"),
        task_id: task.into(),
        similarity: 0.6,
        timestamp: SystemTime::UNIX_EPOCH,
        snippet: Some(digest.into()),
        turn: Some(turn),
        retention,
    }
}

/// A logged turn: the user said `said`, the assistant answered `answer <n>`.
fn logged(turn: u64, said: &str) -> RecentTurn {
    RecentTurn {
        turn_id: turn,
        timestamp: format!("2026-11-22T10:{:02}:00Z", turn % 60),
        digest: format!("logged digest {turn}"),
        read_file_versions: TurnReadFileVersions::default(),
        messages: vec![
            TranscriptMessage::new("user", said),
            TranscriptMessage::new("assistant", &format!("answer {turn}")),
        ],
        marks: vec![L0Mark::Keep; 2],
    }
}

fn tasks_turns(task: &str, turns: impl IntoIterator<Item = RecentTurn>) -> History {
    History {
        turns: HashMap::from([(task.to_string(), turns.into_iter().collect())]),
        ..History::default()
    }
}

fn position(res: &AssemblyResult, prefix: &str) -> usize {
    res.messages
        .iter()
        .position(|m| m.content.starts_with(prefix))
        .unwrap_or_else(|| panic!("no section {prefix:?}"))
}

fn section<'a>(res: &'a AssemblyResult, prefix: &str) -> Option<&'a str> {
    res.messages
        .iter()
        .find(|m| m.content.starts_with(prefix))
        .map(|m| m.content.as_str())
}

fn all_text(res: &AssemblyResult) -> String {
    res.messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// `task-<8 digits>-<8 lowercase hex>`.
fn is_minted(id: &str) -> bool {
    let Some((day, tail)) = id
        .strip_prefix("task-")
        .and_then(|rest| rest.split_once('-'))
    else {
        return false;
    };
    day.len() == 8
        && day.bytes().all(|b| b.is_ascii_digit())
        && tail.len() == 8
        && tail
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ─── The turn's task ───

#[test]
fn minted_task_ids_are_dated_and_distinct() {
    let (a, b) = (mint_task_id(), mint_task_id());
    assert!(is_minted(&a) && is_minted(&b), "{a} {b}");
    assert_ne!(a, b);
}

#[tokio::test]
async fn a_message_no_task_matches_runs_in_a_task_minted_for_it() {
    // The one candidate is below the 0.5 threshold.
    let rig = Rig::new(
        Ok(vec![task("task-old", 0.42, Some("an older plan"))]),
        Search::default(),
        History::default(),
    );
    // The agent loop gives every turn's message its chain trace before assembly.
    let mut message = ctx("plan the launch");
    message.message.context = Some(MessageContext {
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: Some("trace-b2".into()),
        in_reply_to: None,
        correlation_id: None,
    });
    let res = rig.assemble(message).await;
    let minted = res.task_id.clone().expect("the turn runs in a task");
    assert!(is_minted(&minted), "{minted}");
    assert!(res.is_new_task);
    // Every reader read the minted task, and recall left it out of other tasks' entries.
    let read = rig.read_tasks();
    assert!(
        !read.is_empty() && read.iter().all(|t| t == &minted),
        "{read:?}"
    );
    assert_eq!(
        *rig.search.other_than.lock().unwrap(),
        vec![Some(minted.clone())]
    );

    let created = rig.events.of("task.");
    assert_eq!(created.len(), 1, "{created:?}");
    assert_eq!(created[0].event_type, "task.created");
    assert_eq!(created[0].task_id.as_deref(), Some(minted.as_str()));
    assert_eq!(created[0].payload["agent_id"], "agent-default");
    assert_eq!(created[0].payload["task_id"], minted.as_str());
    assert_eq!(created[0].payload["title"], format!("Task {minted}"));
    let assembled = rig.events.of("context.assembled");
    assert_eq!(assembled[0].task_id.as_deref(), Some(minted.as_str()));
    // The routing event shares the turn's trace and hangs below its chain root.
    assert_eq!(created[0].trace_id, "trace-b2");
    assert_eq!(assembled[0].trace_id, "trace-b2");
    assert_eq!(
        created[0].parent_span_id.as_deref(),
        Some(assembled[0].span_id.as_str())
    );
}

#[tokio::test]
async fn a_message_that_matches_a_task_runs_in_it() {
    let rig = Rig::new(
        Ok(vec![
            task("task-a", 0.9, Some("the launch plan")),
            task("task-b", 0.3, Some("ops")),
        ]),
        Search::default(),
        History::default(),
    );
    let res = rig.assemble(ctx("move the launch to Friday")).await;
    assert_eq!(res.task_id.as_deref(), Some("task-a"));
    assert!(!res.is_new_task);
    assert!(rig.read_tasks().iter().all(|t| t == "task-a"));
    let routed = rig.events.of("task.");
    assert_eq!(routed.len(), 1, "{routed:?}");
    assert_eq!(routed[0].event_type, "task.routed");
    assert_eq!(routed[0].payload["task_id"], "task-a");
    let confidence = routed[0].payload["confidence"].as_f64().unwrap();
    assert!((confidence - 0.9).abs() < 1e-6, "{confidence}");
}

#[tokio::test]
async fn a_message_that_names_its_task_is_not_routed() {
    let rig = Rig::new(
        Ok(vec![task("task-a", 0.9, Some("the launch plan"))]),
        Search::default(),
        History::default(),
    );
    let mut named = ctx("go on");
    named.task_id = Some("task-given".into());
    let res = rig.assemble(named).await;
    assert_eq!(res.task_id.as_deref(), Some("task-given"));
    assert!(!res.is_new_task);
    assert_eq!(rig.tasks.calls.load(Ordering::SeqCst), 0, "no routing ran");
    assert!(rig.read_tasks().iter().all(|t| t == "task-given"));
    assert!(rig.events.of("task.").is_empty());
}

#[tokio::test]
async fn a_message_that_names_an_empty_task_is_routed() {
    for empty in ["", "  "] {
        let rig = Rig::new(
            Ok(vec![task("task-a", 0.9, Some("the launch plan"))]),
            Search::default(),
            History::default(),
        );
        let mut named = ctx("move the launch to Friday");
        named.task_id = Some(empty.into());
        let res = rig.assemble(named).await;
        assert_eq!(res.task_id.as_deref(), Some("task-a"), "{empty:?}");
        assert_eq!(rig.tasks.calls.load(Ordering::SeqCst), 1, "{empty:?}");
        assert_eq!(rig.events.of("task.routed").len(), 1, "{empty:?}");
    }
}

#[tokio::test]
async fn control_system_and_auto_messages_stay_in_the_default_partition() {
    // None names a task, and none is a request of its own: not even a current task
    // takes them.
    for kind in [MessageKind::Control, MessageKind::System, MessageKind::Auto] {
        let rig = Rig::new(
            Ok(vec![task("task-a", 0.9, Some("the launch plan"))]),
            Search::default(),
            History::default(),
        )
        .with_current_task("task-now");
        let mut message = ctx(r#"{"event":"component.terminated","child":"agent:c"}"#);
        message.message.kind = kind.clone();
        let res = rig.assemble(message).await;
        assert_eq!(res.task_id, None, "{kind:?}");
        assert!(res.is_new_task);
        assert_eq!(rig.tasks.calls.load(Ordering::SeqCst), 0, "{kind:?}");
        assert!(rig.read_tasks().iter().all(String::is_empty), "{kind:?}");
        assert!(rig.events.of("task.").is_empty(), "{kind:?}");
    }
}

#[tokio::test]
async fn without_an_embedding_or_a_routing_answer_the_turn_runs_in_the_current_task() {
    // The embedder is down: no routing; the turn stays with the work in hand.
    let rig = Rig::new(
        Ok(vec![task("task-a", 0.9, None)]),
        Search::default(),
        History::default(),
    )
    .with_current_task("task-now");
    let res = rig
        .assembler(Arc::new(DownEmbedding), WIDE)
        .assemble(ctx("plan the launch"))
        .await
        .unwrap();
    assert_eq!(res.task_id.as_deref(), Some("task-now"));
    assert!(!res.is_new_task);
    assert_eq!(res.routing_method, "current");
    assert_eq!(rig.tasks.calls.load(Ordering::SeqCst), 0);
    let read = rig.read_tasks();
    assert!(
        !read.is_empty() && read.iter().all(|t| t == "task-now"),
        "{read:?}"
    );
    assert!(rig.events.of("task.").is_empty());

    // A blank prompt embeds nothing: the same.
    let rig = Rig::new(
        Ok(vec![task("task-a", 0.9, None)]),
        Search::default(),
        History::default(),
    )
    .with_current_task("task-now");
    let res = rig.assemble(ctx("   ")).await;
    assert_eq!(res.task_id.as_deref(), Some("task-now"));
    assert_eq!(rig.tasks.calls.load(Ordering::SeqCst), 0);

    // The task index fails: routing falls back (§2.8), it does not abort the turn.
    let rig = Rig::new(
        Err("index down".into()),
        Search::default(),
        History::default(),
    )
    .with_current_task("task-now");
    let res = rig.assemble(ctx("plan the launch")).await;
    assert_eq!(res.task_id.as_deref(), Some("task-now"));
    assert!(!res.is_new_task);
    assert!(rig.events.of("task.").is_empty());

    // With no current task, the turn stays in the default partition.
    let rig = Rig::new(
        Err("index down".into()),
        Search::default(),
        History::default(),
    );
    let res = rig.assemble(ctx("plan the launch")).await;
    assert_eq!(res.task_id, None);
    assert!(res.is_new_task);
    assert!(rig.read_tasks().iter().all(String::is_empty));
    assert!(rig.events.of("task.").is_empty());
}

/// A message of kind `Agent` with `id` and `in_reply_to`, naming no task.
fn agent_message(said: &str, id: &str, in_reply_to: &str) -> AssemblyContext {
    let mut message = ctx(said);
    message.message.id = id.into();
    message.message.kind = MessageKind::Agent;
    message.message.context = Some(MessageContext {
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: None,
        in_reply_to: Some(in_reply_to.into()),
        correlation_id: None,
    });
    message
}

#[tokio::test]
async fn a_reply_and_an_awaited_delegation_are_routed_as_any_message() {
    // A child's answer to a delegation, shaped as the dispatcher's `reply()` builds one (a
    // fresh id, the id it answers), and a delegation the parent awaits, shaped as the reply
    // tracker builds it (its own id as `in_reply_to`). Neither names a task: the message
    // they answer named none.
    let messages = [
        agent_message("Found 5 competitor prices", "reply-1", "msg-delegation"),
        agent_message(
            "Draft the Q3 hiring plan",
            "session:s1:slot:0",
            "session:s1:slot:0",
        ),
    ];
    let unmatched = || Ok(vec![task("task-old", 0.42, Some("an older plan"))]);
    for message in messages {
        // Matching no task, it starts one: the current task does not take it.
        let rig = Rig::new(unmatched(), Search::default(), History::default())
            .with_current_task("task-now");
        let res = rig.assemble(message.clone()).await;
        let minted = res.task_id.clone().expect("a task");
        assert!(is_minted(&minted), "{minted}");
        assert!(res.is_new_task);
        assert_eq!(res.routing_method, "search");
        assert_eq!(rig.events.of("task.created").len(), 1);

        // Matching a task, it runs in it.
        let rig = Rig::new(
            Ok(vec![task("task-a", 0.9, Some("competitor pricing"))]),
            Search::default(),
            History::default(),
        )
        .with_current_task("task-now");
        let res = rig.assemble(message).await;
        assert_eq!(res.task_id.as_deref(), Some("task-a"));
        assert_eq!(rig.events.of("task.routed").len(), 1);
    }

    // A reply to a message that named its task carries that task (PRD §9.2) and keeps it.
    let rig =
        Rig::new(unmatched(), Search::default(), History::default()).with_current_task("task-now");
    let mut named = agent_message("Found 5 competitor prices", "reply-2", "msg-delegation");
    named.task_id = Some("task-pricing".into());
    let res = rig.assemble(named).await;
    assert_eq!(res.task_id.as_deref(), Some("task-pricing"));
    assert!(!res.is_new_task);
    assert_eq!(rig.tasks.calls.load(Ordering::SeqCst), 0, "no routing");
}

// ─── ⑭ other tasks' briefs ───

#[tokio::test]
async fn other_tasks_briefs_land_in_tier_two() {
    let search = Search {
        result: UnifiedSearchResult {
            tasks: vec![
                task("task-b", 0.7, Some("brief of b")),
                task("task-c", 0.29, Some("brief of c")), // below the 0.3 floor
                task("task-d", 0.8, None),                // no brief to show
                task("task-e", 0.5, Some("brief of e")),
                task("task-f", 0.4, Some("brief of f")),
                task("task-g", 0.35, Some("brief of g")), // a fourth: at most three
            ],
            ..UnifiedSearchResult::default()
        },
        ..Search::default()
    };
    let rig = Rig::new(Ok(Vec::new()), search, History::default());
    let res = rig.assemble(ctx("plan the launch")).await;
    let at = position(&res, "# Related Task Briefs");
    assert!(position(&res, TIER2_START) < at && at < position(&res, TIER3_START));
    let briefs = section(&res, "# Related Task Briefs").unwrap();
    for shown in ["brief of b", "brief of e", "brief of f"] {
        assert!(briefs.contains(shown), "{shown}: {briefs}");
    }
    for left_out in ["brief of c", "task-d", "brief of g"] {
        assert!(!briefs.contains(left_out), "{left_out}: {briefs}");
    }
    assert_eq!(rig.reports.last().history.l5_related_briefs, 3);
}

// ─── ⑯ the task's earlier turns ───

#[tokio::test]
async fn the_tasks_earlier_turns_load_by_their_retention_score() {
    // Routed into task-a, whose log holds turns 1..=8: the wide window is 4..=8.
    let search = Search {
        task_turns: vec![
            hit("task-a", 2, Some(0.9), "found 2"),       // whole
            hit("task-a", 3, Some(0.3), "found 3"),       // its digest
            hit("task-a", 1, Some(0.1), "found 1"),       // below 0.2: not loaded
            hit("task-a", 6, Some(0.95), "found 6"),      // in the window: loads there only
            hit("task-a", 2, Some(0.2), "found 2 again"), // the same turn from the other half
            hit("task-a", 7, None, "found 7 unscored"),   // in the window too
        ],
        ..Search::default()
    };
    let rig = Rig::new(
        Ok(vec![task("task-a", 0.9, Some("the pricing plan"))]),
        search,
        tasks_turns("task-a", (1..=8).map(|n| logged(n, &format!("said {n}")))),
    );
    let res = rig.assemble(ctx("what did we decide about pricing")).await;

    let earlier = section(&res, "# Earlier Turns").expect("an earlier turn loaded whole");
    assert!(
        earlier.contains("## Turn 2 · 2026-11-22T10:02:00Z"),
        "{earlier}"
    );
    assert!(earlier.contains("answer 2"), "{earlier}");
    let digests = section(&res, "# Recent Turn Digests").expect("an earlier digest");
    assert!(digests.contains("found 3"), "{digests}");
    for not_loaded in ["found 1", "found 2", "found 6", "found 7"] {
        assert!(!digests.contains(not_loaded), "{not_loaded}: {digests}");
    }
    let text = all_text(&res);
    // Each turn loaded whole is there once: an earlier one, or one of the window.
    for turn in [2, 4, 5, 6, 7, 8] {
        assert_eq!(
            text.matches(&format!("answer {turn}")).count(),
            1,
            "turn {turn}: {text}"
        );
    }
    assert!(
        !text.contains("answer 1") && !text.contains("answer 3"),
        "{text}"
    );
    // ⑯ order: the digests, the earlier turns, then the recent window.
    let (d, e, r) = (
        position(&res, "# Recent Turn Digests"),
        position(&res, "# Earlier Turns"),
        position(&res, "# Recent Turns"),
    );
    assert!(
        position(&res, TIER3_START) < d && d < e && e < r,
        "{d} {e} {r}"
    );

    let history = rig.reports.last().history;
    assert_eq!(history.recent_turns, 5);
    assert_eq!(history.earlier_turns, 1);
    assert_eq!(history.earlier_turn_digests, 1);
    assert_eq!(
        *rig.search.searched.lock().unwrap(),
        vec!["task-a".to_string()]
    );
    // The window is not known when the search runs: each half is asked for the widest
    // window's turns more than it keeps beyond it.
    assert_eq!(
        *rig.search.limits.lock().unwrap(),
        vec![TASK_TURN_CANDIDATES + 5]
    );
}

#[tokio::test]
async fn the_l2_pick_stands_in_when_the_search_cannot_find_the_tasks_earlier_turns() {
    // Task-a's log holds turns 1..=8: the wide window is 4..=8. The L2 reader picks turns 1
    // and 2 by retention.
    let picked = [(1, "picked 1"), (2, "picked 2")];
    let log = || tasks_turns("task-a", (1..=8).map(|n| logged(n, &format!("said {n}"))));
    let found = || Search {
        task_turns: vec![hit("task-a", 3, Some(0.3), "found 3")],
        ..Search::default()
    };
    let routed = || Ok(vec![task("task-a", 0.9, Some("the pricing plan"))]);

    // The search finds none of the task's turns: the pick stands in.
    let rig = Rig::new(routed(), Search::default(), log()).with_l2_digests(&picked);
    let res = rig.assemble(ctx("what did we decide")).await;
    let digests = section(&res, "# Recent Turn Digests").expect("the L2 pick");
    assert!(
        digests.contains("picked 1") && digests.contains("picked 2"),
        "{digests}"
    );

    // The search finds only turns of the recent window: the pick stays.
    let window_only = Search {
        task_turns: vec![hit("task-a", 7, Some(0.9), "found 7")],
        ..Search::default()
    };
    let rig = Rig::new(routed(), window_only, log()).with_l2_digests(&picked);
    let res = rig.assemble(ctx("what did we decide")).await;
    let digests = section(&res, "# Recent Turn Digests").expect("the L2 pick");
    assert!(
        digests.contains("picked 1") && digests.contains("picked 2"),
        "{digests}"
    );

    // The search finds one beyond the window: it takes the pick's place.
    let rig = Rig::new(routed(), found(), log()).with_l2_digests(&picked);
    let res = rig.assemble(ctx("what did we decide")).await;
    let digests = section(&res, "# Recent Turn Digests").expect("a recalled digest");
    assert!(digests.contains("found 3"), "{digests}");
    assert!(!digests.contains("picked"), "{digests}");
    assert_eq!(rig.reports.last().history.l2_digests, 0);

    // Without a usable query vector the search matches keywords only: the pick stays,
    // and what the keywords found joins it.
    let rig = Rig::new(routed(), found(), log())
        .with_l2_digests(&picked)
        .with_current_task("task-a");
    let res = rig
        .assembler(Arc::new(DownEmbedding), WIDE)
        .assemble(ctx("what did we decide"))
        .await
        .unwrap();
    assert_eq!(res.task_id.as_deref(), Some("task-a"));
    let digests = section(&res, "# Recent Turn Digests").expect("the pick and the find");
    for kept in ["picked 1", "picked 2", "found 3"] {
        assert!(digests.contains(kept), "{kept}: {digests}");
    }
}

#[tokio::test]
async fn an_earlier_turn_too_large_for_the_turn_budget_loads_as_its_digest() {
    // A 100_000-token window leaves about 34_000 tokens for the turns loaded whole; turn 1
    // takes about 49_000: 24 answers, each cut to the 8 KiB a message renders.
    let mut big = logged(1, "said 1");
    big.messages
        .extend((0..24).map(|_| TranscriptMessage::new("assistant", &"x".repeat(9_000))));
    big.marks = vec![L0Mark::Keep; big.messages.len()];
    let turns = std::iter::once(big).chain((2..=6).map(|n| logged(n, &format!("said {n}"))));
    let search = Search {
        task_turns: vec![hit("task-a", 1, Some(0.9), "found 1")],
        ..Search::default()
    };
    let rig = Rig::new(
        Ok(vec![task("task-a", 0.9, None)]),
        search,
        tasks_turns("task-a", turns),
    );
    let res = rig
        .assembler(Arc::new(FixedEmbedding), 100_000)
        .assemble(ctx("the first decision"))
        .await
        .unwrap();
    assert!(section(&res, "# Earlier Turns").is_none());
    assert!(section(&res, "# Recent Turn Digests")
        .unwrap()
        .contains("found 1"));
    let history = rig.reports.last().history;
    assert_eq!(history.earlier_turns, 0);
    assert_eq!(history.earlier_turn_digests, 1);
}

#[tokio::test]
async fn the_compact_mode_loads_recalled_turns_as_digests_only() {
    // A 10_000-token window: the remaining budget is in the compact mode (5_000..10_000).
    let search = Search {
        result: UnifiedSearchResult {
            turns: vec![hit("task-b", 4, Some(0.9), "found b4")],
            ..UnifiedSearchResult::default()
        },
        task_turns: vec![hit("task-a", 2, Some(0.9), "found 2")],
        ..Search::default()
    };
    let mut history = tasks_turns("task-a", (1..=3).map(|n| logged(n, &format!("said {n}"))));
    history
        .turns
        .insert("task-b".into(), vec![logged(4, "said b4")]);
    let rig = Rig::new(Ok(vec![task("task-a", 0.9, None)]), search, history);
    let res = rig
        .assembler(Arc::new(FixedEmbedding), 10_000)
        .assemble(ctx("pricing"))
        .await
        .unwrap();
    assert_eq!(rig.reports.last().progressive_mode, "compact");
    assert!(section(&res, "# Earlier Turns").is_none());
    assert!(section(&res, "# Recent Turn Digests")
        .unwrap()
        .contains("found 2"));
    let related = section(&res, "# Related Turns").unwrap();
    assert!(
        related.contains("found b4") && !related.contains("## Turn 4 of"),
        "{related}"
    );
    let history = rig.reports.last().history;
    assert_eq!((history.earlier_turns, history.related_turns), (0, 0));
    assert_eq!(
        (history.earlier_turn_digests, history.related_turn_digests),
        (1, 1)
    );
}

// ─── ⑯ other tasks' turns ───

#[tokio::test]
async fn other_tasks_turns_load_under_related_turns() {
    let search = Search {
        result: UnifiedSearchResult {
            turns: vec![
                hit("task-b", 4, Some(0.8), "found b4"),  // whole
                hit("task-c", 1, Some(0.3), "found c1"),  // its digest
                hit("task-d", 2, Some(0.05), "found d2"), // below 0.2: not loaded
                hit("task-a", 7, Some(0.9), "found a7"),  // the routed task's own
            ],
            ..UnifiedSearchResult::default()
        },
        ..Search::default()
    };
    let rig = Rig::new(
        Ok(vec![task("task-a", 0.9, None)]),
        search,
        tasks_turns("task-b", [logged(4, "the pricing call")]),
    );
    let res = rig.assemble(ctx("pricing")).await;
    assert_eq!(res.task_id.as_deref(), Some("task-a"));
    let related = section(&res, "# Related Turns").expect("other tasks' turns");
    assert!(
        related.contains("## Turn 4 of task-b · 2026-11-22T10:04:00Z"),
        "{related}"
    );
    assert!(
        related.contains("the pricing call") && related.contains("answer 4"),
        "{related}"
    );
    assert!(
        related.contains("- task-c#turn-1 (0.600) — found c1"),
        "{related}"
    );
    for not_loaded in ["found b4", "found d2", "found a7"] {
        assert!(!related.contains(not_loaded), "{not_loaded}: {related}");
    }
    assert!(!all_text(&res).contains("found a7"));
    // ⑯ starts with them.
    let at = position(&res, "# Related Turns");
    assert!(position(&res, TIER3_START) < at);
    assert_eq!(
        *rig.search.other_than.lock().unwrap(),
        vec![Some("task-a".to_string())]
    );
    let history = rig.reports.last().history;
    assert_eq!(
        (history.related_turns, history.related_turn_digests),
        (1, 1)
    );
}
