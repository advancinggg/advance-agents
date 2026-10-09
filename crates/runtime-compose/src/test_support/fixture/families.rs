//! The fixture's (a) client-families part.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::api::{
    provider_or_unavailable, ClientError, ClientErrorCode, ClientFamilyRegistrar, ExtensionError,
    FamilyBudget, HandlerSpec, Method, PollEmit, PollStreamSpec, ProviderSlot, RouteOptions, Scope,
};

use super::FIXTURE_ID;

pub const SLOW_ROUTE_BOUND: Duration = Duration::from_secs(30);
const OPT_OUT_CURSOR: &str = "fixture: returns an opaque extension cursor";
const OPT_OUT_RAW: &str = "fixture: raw echo for the scan opt-out witness";

#[derive(Clone)]
pub struct FixtureFamilies {
    label: &'static str,
    budget: Option<FamilyBudget>,
    rule_break: Option<RouteRuleBreak>,
    feed: bool,
    nested_feed: bool,
    control: Arc<FamiliesControl>,
}

impl FixtureFamilies {
    pub fn standard() -> Self {
        Self::standard_with_label(FIXTURE_ID)
    }

    pub fn standard_with_label(label: &'static str) -> Self {
        Self {
            label,
            budget: None,
            rule_break: None,
            feed: false,
            nested_feed: false,
            control: Arc::new(FamiliesControl::default()),
        }
    }

    pub fn with_budget(mut self, budget: FamilyBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    pub fn with_break(mut self, b: RouteRuleBreak) -> Self {
        self.rule_break = Some(b);
        self
    }

    /// GET + WebSocket poll stream [`Feed::Flat`] at `/client/<label>/feed` (MODULE-001-AC-33).
    pub fn with_feed(mut self) -> Self {
        self.feed = true;
        self
    }

    /// GET + WebSocket poll stream [`Feed::Nested`] at `/client/<label>/nested-feed`, whose cursor
    /// sits at a nested JSON pointer (MODULE-001-AC-33).
    pub fn with_nested_feed(mut self) -> Self {
        self.nested_feed = true;
        self
    }

    pub fn control(&self) -> Arc<FamiliesControl> {
        Arc::clone(&self.control)
    }

    /// The standard table under `label`, then `set_budget` if configured, then the break.
    pub(crate) fn register(
        &self,
        reg: &mut ClientFamilyRegistrar<'_>,
    ) -> Result<(), ExtensionError> {
        self.register_standard(reg)?;
        if self.feed {
            self.register_feed(reg, Feed::Flat)?;
        }
        if self.nested_feed {
            self.register_feed(reg, Feed::Nested)?;
        }
        if let Some(budget) = self.budget {
            reg.set_budget(budget)?;
        }
        if let Some(rule) = self.rule_break {
            self.register_break(reg, rule)?;
        }
        Ok(())
    }

    fn register_standard(&self, reg: &mut ClientFamilyRegistrar<'_>) -> Result<(), ExtensionError> {
        let l = self.label;
        let control = Arc::clone(&self.control);
        let services = reg.services().clone();

        reg.route(
            Method::Get,
            &format!("/client/{l}/status"),
            HandlerSpec::read(true, |_| Ok(json!({"status": "ok"})))
                .with_scopes(vec![Scope::ReadInventory]),
        )?;
        {
            let control = Arc::clone(&control);
            reg.route(
                Method::Get,
                &format!("/client/{l}/items"),
                HandlerSpec::read(true, move |_| {
                    Ok(json!({
                        "items": [],
                        "created": control.created(),
                    }))
                })
                .with_scopes(vec![Scope::ReadInventory]),
            )?;
        }
        reg.route_templated(
            Method::Get,
            &format!("/client/{l}/items/{{item_id}}"),
            HandlerSpec::read(true, |ctx| {
                let item_id = ctx
                    .path_params
                    .iter()
                    .find(|(k, _)| k == "item_id")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                Ok(json!({ "item_id": item_id }))
            })
            .with_scopes(vec![Scope::ReadInventory]),
        )?;
        {
            let control = Arc::clone(&control);
            reg.route(
                Method::Post,
                &format!("/client/{l}/items:create"),
                HandlerSpec::mutation(true, move |ctx| {
                    let n = control.created.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(json!({
                        "created": n,
                        "name": ctx.body.get("name").cloned().unwrap_or(serde_json::Value::Null),
                    }))
                })
                .with_scopes(vec![Scope::WriteEntities]),
            )?;
        }
        reg.route(
            Method::Post,
            &format!("/client/{l}/items:search"),
            HandlerSpec::post_read(true, |_| Ok(json!({ "matches": [] })))
                .with_scopes(vec![Scope::ReadInventory]),
        )?;
        {
            let control = Arc::clone(&control);
            reg.route(
                Method::Get,
                &format!("/client/{l}/leak"),
                HandlerSpec::read(true, move |_| {
                    let note = control
                        .note
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    Ok(json!({ "note": note }))
                })
                .with_scopes(vec![Scope::ReadInventory]),
            )?;
        }
        {
            let control = Arc::clone(&control);
            reg.route_with(
                Method::Get,
                &format!("/client/{l}/leak-raw"),
                HandlerSpec::read(true, move |_| {
                    let note = control
                        .note
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    Ok(json!({ "note": note }))
                })
                .with_scopes(vec![Scope::ReadInventory]),
                RouteOptions::skip_response_scan(OPT_OUT_RAW),
            )?;
        }
        reg.route(
            Method::Get,
            &format!("/client/{l}/error"),
            HandlerSpec::read(true, |_| {
                Err(
                    ClientError::new(ClientErrorCode::NotFound, "fixture private detail 42")
                        .with_details(vec!["fixture_missing".into(), "Raw Reason!".into()]),
                )
            })
            .with_scopes(vec![Scope::ReadInventory]),
        )?;
        reg.route(
            Method::Get,
            &format!("/client/{l}/error-unknown"),
            HandlerSpec::read(true, |_| {
                Err(ClientError::new(
                    ClientErrorCode::Unknown,
                    "fixture private detail 43",
                ))
            })
            .with_scopes(vec![Scope::ReadInventory]),
        )?;
        reg.route(
            Method::Get,
            &format!("/client/{l}/panic"),
            HandlerSpec::read(true, |_| panic!("fixture route panic"))
                .with_scopes(vec![Scope::ReadInventory]),
        )?;
        {
            let control = Arc::clone(&control);
            reg.route(
                Method::Get,
                &format!("/client/{l}/slow"),
                HandlerSpec::read(true, move |_| {
                    control.holding.fetch_add(1, Ordering::SeqCst);
                    let (flag, cvar) = &control.slow;
                    let guard = flag.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let (guard, _) = cvar
                        .wait_timeout_while(guard, SLOW_ROUTE_BOUND, |released| !*released)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let held = *guard;
                    drop(guard);
                    control.holding.fetch_sub(1, Ordering::SeqCst);
                    Ok(json!({ "held": held }))
                })
                .with_scopes(vec![Scope::ReadInventory]),
            )?;
        }
        {
            let services = services.clone();
            reg.route_with(
                Method::Get,
                &format!("/client/{l}/cursor"),
                HandlerSpec::read(true, move |ctx| {
                    let stream_id = ctx
                        .body
                        .get("stream_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("fixture-stream");
                    let raw_id = ctx
                        .body
                        .get("raw_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("fixture-row-1");
                    let token = services.cursors().seal(stream_id, raw_id)?;
                    Ok(json!({ "cursor": token }))
                })
                .with_scopes(vec![Scope::ReadInventory]),
                RouteOptions::skip_response_scan(OPT_OUT_CURSOR),
            )?;
        }
        {
            let services = services.clone();
            reg.route_with(
                Method::Get,
                &format!("/client/{l}/cursor:open"),
                HandlerSpec::read(true, move |ctx| {
                    let stream_id = ctx
                        .body
                        .get("stream_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let token = ctx.body.get("token").and_then(|v| v.as_str()).unwrap_or("");
                    let raw_id = services.cursors().open(stream_id, token)?;
                    Ok(json!({ "raw_id": raw_id }))
                })
                .with_scopes(vec![Scope::ReadInventory]),
                RouteOptions::skip_response_scan(OPT_OUT_CURSOR),
            )?;
        }
        {
            let services = services.clone();
            reg.route(
                Method::Get,
                &format!("/client/{l}/clock"),
                HandlerSpec::read(true, move |_| {
                    Ok(json!({ "now_ms": services.clock().now_millis() }))
                })
                .with_scopes(vec![Scope::ReadInventory]),
            )?;
        }
        reg.route(
            Method::Get,
            &format!("/client/{l}/slot"),
            HandlerSpec::read(true, |_| {
                let empty: ProviderSlot<dyn Send + Sync> = Arc::new(std::sync::RwLock::new(None));
                provider_or_unavailable(&empty)?;
                Ok(json!({}))
            })
            .with_scopes(vec![Scope::ReadInventory]),
        )?;
        Ok(())
    }

    /// The feed's read records every call (request body and answered cursor), hands out the
    /// queued items and answers the cursor `c<n>`, `n` = the feed's non-empty pages so far.
    fn register_feed(
        &self,
        reg: &mut ClientFamilyRegistrar<'_>,
        feed: Feed,
    ) -> Result<(), ExtensionError> {
        let control = Arc::clone(&self.control);
        reg.poll_stream(
            &feed.path(self.label),
            PollStreamSpec::new(
                HandlerSpec::read(true, move |ctx| {
                    if control.panic_next.swap(false, Ordering::AcqRel) {
                        panic!("fixture feed panic");
                    }
                    let (items, cursor) = control.next_page(feed, &ctx.body);
                    Ok(match feed {
                        Feed::Flat => json!({ "items": items, "cursor": cursor }),
                        Feed::Nested => json!({ "items": items, "page": { "cursor": cursor } }),
                    })
                })
                .with_scopes(vec![Scope::ReadInventory]),
                feed.cursor_pointer(),
                PollEmit::NonEmptyArrayAt("/items"),
            ),
        )?;
        Ok(())
    }

    fn register_break(
        &self,
        reg: &mut ClientFamilyRegistrar<'_>,
        rule: RouteRuleBreak,
    ) -> Result<(), ExtensionError> {
        let l = self.label;
        let read =
            || HandlerSpec::read(true, |_| Ok(json!({}))).with_scopes(vec![Scope::ReadInventory]);
        match rule {
            RouteRuleBreak::EmptySegment => {
                reg.route(Method::Get, &format!("/client/{l}//x"), read())?;
            }
            RouteRuleBreak::Dot => {
                reg.route(Method::Get, &format!("/client/{l}/./x"), read())?;
            }
            RouteRuleBreak::DotDot => {
                reg.route(Method::Get, &format!("/client/{l}/../x"), read())?;
            }
            RouteRuleBreak::Percent => {
                reg.route(Method::Get, &format!("/client/{l}/%2e"), read())?;
            }
            RouteRuleBreak::Uppercase => {
                reg.route(Method::Get, &format!("/client/{l}/Items"), read())?;
            }
            RouteRuleBreak::TooLong => {
                let path = format!("/client/{l}/{}", "a".repeat(512));
                reg.route(Method::Get, &path, read())?;
            }
            RouteRuleBreak::LabelRoot => {
                reg.route(Method::Get, "/client/root/x", read())?;
            }
            RouteRuleBreak::LabelStaticFloor => {
                reg.route(Method::Get, "/client/session/x", read())?;
            }
            RouteRuleBreak::LabelLiveOss => {
                reg.route(Method::Get, "/client/runs/x", read())?;
            }
            RouteRuleBreak::StreamPath => {
                reg.route(Method::Get, "/client/events/stream", read())?;
            }
            RouteRuleBreak::LabelOwnedByEarlier => {
                reg.route(Method::Get, "/client/fixture/b", read())?;
            }
            RouteRuleBreak::ParamFirstSegment => {
                reg.route_templated(Method::Get, "/client/{x}/y", read())?;
            }
            RouteRuleBreak::DuplicateShapeOss => {
                reg.route_templated(Method::Get, "/client/runs/{other}/history", read())?;
            }
            RouteRuleBreak::DuplicateShapeOtherExtension => {
                reg.route_templated(Method::Get, "/client/fixture/items/{name}", read())?;
            }
            RouteRuleBreak::DuplicateShapeSameExtension => {
                reg.route_templated(Method::Get, &format!("/client/{l}/items/{{id}}"), read())?;
            }
            RouteRuleBreak::PostRegisteredAsRead => {
                reg.route(
                    Method::Post,
                    &format!("/client/{l}/x"),
                    HandlerSpec::read(true, |_| Ok(json!({})))
                        .with_scopes(vec![Scope::ReadInventory]),
                )?;
            }
            RouteRuleBreak::GetMutation => {
                reg.route(
                    Method::Get,
                    &format!("/client/{l}/x"),
                    HandlerSpec::mutation(true, |_| Ok(json!({})))
                        .with_scopes(vec![Scope::WriteEntities]),
                )?;
            }
            RouteRuleBreak::NoSession => {
                reg.route(
                    Method::Get,
                    &format!("/client/{l}/x"),
                    HandlerSpec::read(false, |_| Ok(json!({})))
                        .with_scopes(vec![Scope::ReadInventory]),
                )?;
            }
            RouteRuleBreak::NoScope => {
                reg.route(
                    Method::Get,
                    &format!("/client/{l}/x"),
                    HandlerSpec::read(true, |_| Ok(json!({}))),
                )?;
            }
            RouteRuleBreak::MutationReadScopeOnly => {
                reg.route(
                    Method::Post,
                    &format!("/client/{l}/x"),
                    HandlerSpec::mutation(true, |_| Ok(json!({})))
                        .with_scopes(vec![Scope::ReadInventory]),
                )?;
            }
            RouteRuleBreak::ParamInExactPath => {
                reg.route(Method::Get, &format!("/client/{l}/{{id}}"), read())?;
            }
            RouteRuleBreak::ScanOptOutWithoutReason => {
                reg.route_with(
                    Method::Get,
                    &format!("/client/{l}/x"),
                    read(),
                    RouteOptions::skip_response_scan(" "),
                )?;
            }
            RouteRuleBreak::BudgetOutOfRange => {
                reg.set_budget(FamilyBudget::new(0, 4))?;
            }
            RouteRuleBreak::BudgetTwice => {
                reg.set_budget(FamilyBudget::new(1, 1))?;
                reg.set_budget(FamilyBudget::new(1, 1))?;
            }
        }
        Ok(())
    }
}

/// A fixture poll stream (MODULE-001-AC-33).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feed {
    /// `/client/<label>/feed`, cursor pointer `/cursor`: data `{"items": [..], "cursor": "c<n>"}`.
    Flat,
    /// `/client/<label>/nested-feed`, cursor pointer `/page/cursor`:
    /// data `{"items": [..], "page": {"cursor": "c<n>"}}`.
    Nested,
}

impl Feed {
    pub fn path(self, label: &str) -> String {
        match self {
            Feed::Flat => format!("/client/{label}/feed"),
            Feed::Nested => format!("/client/{label}/nested-feed"),
        }
    }

    /// The JSON pointer the feed registers as its `PollStreamSpec` cursor.
    pub fn cursor_pointer(self) -> &'static str {
        match self {
            Feed::Flat => "/cursor",
            Feed::Nested => "/page/cursor",
        }
    }

    fn slot(self) -> usize {
        match self {
            Feed::Flat => 0,
            Feed::Nested => 1,
        }
    }
}

/// One call of a feed's read: the HTTP GET, a stream's seed or one of its polls.
#[derive(Clone, Debug)]
pub struct FeedCall {
    pub at: Instant,
    /// The request body the read was handed.
    pub body: Value,
    /// The cursor the read answered.
    pub cursor: String,
}

#[derive(Default)]
struct FeedQueue {
    items: Vec<Value>,
    pages: u64,
    calls: Vec<FeedCall>,
}

pub struct FamiliesControl {
    created: AtomicU64,
    note: Mutex<String>,
    holding: AtomicUsize,
    slow: (Mutex<bool>, Condvar),
    feeds: [Mutex<FeedQueue>; 2],
    panic_next: AtomicBool,
}

impl Default for FamiliesControl {
    fn default() -> Self {
        Self {
            created: AtomicU64::new(0),
            note: Mutex::new("key AKIAABCDEFGHIJKLMNOP".into()),
            holding: AtomicUsize::new(0),
            slow: (Mutex::new(false), Condvar::new()),
            feeds: Default::default(),
            panic_next: AtomicBool::new(false),
        }
    }
}

impl FamiliesControl {
    pub fn created(&self) -> u64 {
        self.created.load(Ordering::SeqCst)
    }

    pub fn set_note(&self, s: impl Into<String>) {
        *self
            .note
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = s.into();
    }

    pub fn holding(&self) -> usize {
        self.holding.load(Ordering::SeqCst)
    }

    pub fn release_slow_route(&self) {
        *self
            .slow
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.slow.1.notify_all();
    }

    /// Queue an item for the next read of [`Feed::Flat`].
    pub fn push_feed(&self, item: Value) {
        self.push_to(Feed::Flat, item);
    }

    /// Queue an item for the next read of `feed`.
    pub fn push_to(&self, feed: Feed, item: Value) {
        self.queue(feed).items.push(item);
    }

    /// Every read of [`Feed::Flat`], in call order: when it ran and the request body it was handed.
    pub fn polls(&self) -> Vec<(Instant, Value)> {
        self.feed_calls(Feed::Flat)
            .into_iter()
            .map(|call| (call.at, call.body))
            .collect()
    }

    /// Every read of `feed`, in call order.
    pub fn feed_calls(&self, feed: Feed) -> Vec<FeedCall> {
        self.queue(feed).calls.clone()
    }

    fn queue(&self, feed: Feed) -> std::sync::MutexGuard<'_, FeedQueue> {
        self.feeds[feed.slot()]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// One read of `feed`: take the queued items, count a non-empty page, record the call.
    fn next_page(&self, feed: Feed, body: &Value) -> (Vec<Value>, String) {
        let mut queue = self.queue(feed);
        let items = std::mem::take(&mut queue.items);
        if !items.is_empty() {
            queue.pages += 1;
        }
        let cursor = format!("c{}", queue.pages);
        queue.calls.push(FeedCall {
            at: Instant::now(),
            body: body.clone(),
            cursor: cursor.clone(),
        });
        (items, cursor)
    }

    /// One-shot: the next feed poll panics inside the wrapped handler.
    pub fn panic_next_poll(&self) {
        self.panic_next.store(true, Ordering::Release);
    }
}

/// One broken registration, made after the standard family.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteRuleBreak {
    EmptySegment,
    Dot,
    DotDot,
    Percent,
    Uppercase,
    TooLong,
    LabelRoot,
    LabelStaticFloor,
    LabelLiveOss,
    StreamPath,
    LabelOwnedByEarlier,
    ParamFirstSegment,
    DuplicateShapeOss,
    DuplicateShapeOtherExtension,
    DuplicateShapeSameExtension,
    PostRegisteredAsRead,
    GetMutation,
    NoSession,
    NoScope,
    MutationReadScopeOnly,
    ParamInExactPath,
    ScanOptOutWithoutReason,
    BudgetOutOfRange,
    BudgetTwice,
}
