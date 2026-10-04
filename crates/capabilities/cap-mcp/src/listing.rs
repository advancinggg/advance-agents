//! Reading a server's tools: `tools/list` pages, the limits each listed tool
//! must meet, and the tool cache.
//!
//! ## Pages
//!
//! A listing follows `nextCursor` from page to page and reads at most
//! [`MAX_TOOL_LIST_PAGES`] pages. It ends at a page whose cursor is missing,
//! empty, longer than [`MAX_TOOL_LIST_CURSOR_BYTES`] or the same as the one that
//! asked for the page, and once it holds [`MAX_TOOLS_PER_SERVER`] tools.
//!
//! ## Entry limits
//!
//! A listed tool is kept when its name
//! - passes the server's tool patterns and holds no control, invisible or bidi
//!   character ([`McpServerEntry::tool_allowed`]),
//! - is at most [`MAX_TOOL_NAME_BYTES`] long, so a literal tool pattern can name
//!   it, and is a name a call can carry ([`is_request_token`]),
//! - and was not listed before (a repeated name is kept once).
//!
//! Its description is cut to [`MAX_TOOL_DESCRIPTION_BYTES`] (ending in `…`). Its
//! `inputSchema` is kept when it is a JSON object of at most
//! [`MAX_TOOL_SCHEMA_BYTES`] whose references stay inside it (the
//! [`SchemaValidator`](crate::SchemaValidator) pre-scan); otherwise the tool is
//! kept without a schema.
//!
//! ## Tool cache
//!
//! The client keeps each server's latest listing as a [`CachedToolListing`].
//! The cache holds at most [`MAX_CACHED_TOOLS`] tools across all servers. When
//! the latest listings do not all fit, the room is shared max-min fairly: each
//! server gets an equal share, a server that listed fewer tools than its share
//! leaves the rest to the others, and the few tools of room an equal split
//! leaves over go one each to the first of the servers it cuts, in id order.
//! A listing larger than its server's share is cached in part (its first
//! tools) and says so ([`CachedToolListing::listed`]), while the caller of the
//! listing still receives all of it. A new listing can shrink the other
//! servers' shares: their cached listings are cut to them at once, and grow
//! back only with their servers' next listings. A cached listing is shared:
//! reading the cache clones no tool.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::sync::Arc;

use advance_shared_types::mcp::{is_request_token, MAX_TOOL_PATTERN_BYTES};
use serde_json::Value;

use crate::client::McpToolInfo;
use crate::error::McpError;
use crate::schema_validator::require_intra_schema_refs;
use crate::whitelist::McpServerEntry;

/// Most `tools/list` pages one listing reads.
pub const MAX_TOOL_LIST_PAGES: usize = 32;

/// Longest `nextCursor` sent back to a server, in bytes; a longer one ends the
/// listing.
pub const MAX_TOOL_LIST_CURSOR_BYTES: usize = 1024;

/// Most tools one listing keeps.
pub const MAX_TOOLS_PER_SERVER: usize = 512;

/// Most tools the tool cache holds, across all servers.
pub const MAX_CACHED_TOOLS: usize = 2048;

/// Longest tool name kept, in bytes: the longest literal tool pattern.
pub const MAX_TOOL_NAME_BYTES: usize = MAX_TOOL_PATTERN_BYTES;

/// Longest tool description kept, in bytes; a longer one is cut and ends in
/// `…`.
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 2048;

/// Largest `inputSchema` kept, in bytes of JSON; a tool with a larger one is
/// kept without it.
pub const MAX_TOOL_SCHEMA_BYTES: usize = 16 * 1024;

/// The tools gathered from one server's `tools/list` pages.
pub(crate) struct ToolListing {
    server_id: String,
    tools: Vec<McpToolInfo>,
    names: HashSet<String>,
}

impl ToolListing {
    pub(crate) fn new(server_id: &str) -> Self {
        Self {
            server_id: server_id.to_string(),
            tools: Vec::new(),
            names: HashSet::new(),
        }
    }

    /// Whether the listing holds [`MAX_TOOLS_PER_SERVER`] tools.
    pub(crate) fn is_full(&self) -> bool {
        self.tools.len() >= MAX_TOOLS_PER_SERVER
    }

    /// Add the tools of one `tools/list` result that `entry` and the entry
    /// limits let through, and return the page's cursor to the next page when
    /// it is one the listing may send back (non-empty, at most
    /// [`MAX_TOOL_LIST_CURSOR_BYTES`]). A result without a `tools` array, or a
    /// tool without a string `name`, fails the listing.
    pub(crate) fn read_page(
        &mut self,
        entry: &McpServerEntry,
        mut page: Value,
    ) -> Result<Option<String>, McpError> {
        let Some(Value::Array(items)) = page.get_mut("tools").map(Value::take) else {
            return Err(McpError::invalid_response(
                "tools/list missing 'tools' array",
            ));
        };
        for item in items {
            if self.is_full() {
                break;
            }
            let Value::Object(mut item) = item else {
                return Err(McpError::invalid_response("tool entry missing 'name'"));
            };
            let Some(Value::String(name)) = item.remove("name") else {
                return Err(McpError::invalid_response("tool entry missing 'name'"));
            };
            if !keeps_name(entry, &name) || !self.names.insert(name.clone()) {
                continue;
            }
            let description = match item.remove("description") {
                Some(Value::String(text)) => cut_description(text),
                _ => String::new(),
            };
            let input_schema = item.remove("inputSchema").filter(schema_within_limits);
            self.tools.push(McpToolInfo {
                name,
                description,
                server_id: self.server_id.clone(),
                input_schema,
            });
        }
        Ok(page
            .get("nextCursor")
            .and_then(Value::as_str)
            .filter(|cursor| !cursor.is_empty() && cursor.len() <= MAX_TOOL_LIST_CURSOR_BYTES)
            .map(str::to_string))
    }

    pub(crate) fn into_tools(self) -> Vec<McpToolInfo> {
        self.tools
    }
}

/// Whether a listed tool named `name` is kept (see the module docs).
fn keeps_name(entry: &McpServerEntry, name: &str) -> bool {
    name.len() <= MAX_TOOL_NAME_BYTES && is_request_token(name) && entry.tool_allowed(name)
}

/// `text` cut to at most [`MAX_TOOL_DESCRIPTION_BYTES`], on a character
/// boundary, ending in `…` when cut.
fn cut_description(mut text: String) -> String {
    if text.len() <= MAX_TOOL_DESCRIPTION_BYTES {
        return text;
    }
    let mut end = MAX_TOOL_DESCRIPTION_BYTES - '…'.len_utf8();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push('…');
    text
}

/// Whether an `inputSchema` is kept: a JSON object of at most
/// [`MAX_TOOL_SCHEMA_BYTES`] whose references stay inside it.
fn schema_within_limits(schema: &Value) -> bool {
    schema.is_object()
        && json_fits(schema, MAX_TOOL_SCHEMA_BYTES)
        && require_intra_schema_refs(schema).is_ok()
}

/// Whether `value` serializes to at most `max` bytes. The serialization stops
/// at the limit; the text is never built.
fn json_fits(value: &Value, max: usize) -> bool {
    struct Budget(usize);

    impl io::Write for Budget {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(buf.len())
                .ok_or_else(|| io::Error::other("over the limit"))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    serde_json::to_writer(Budget(max), value).is_ok()
}

/// One server's entry in the tool cache: the first tools of its latest
/// listing, as many as its share of the cache holds (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedToolListing {
    /// The server listed.
    pub server_id: String,
    /// The tools the cache keeps, in listing order.
    pub tools: Vec<McpToolInfo>,
    /// How many tools the listing held, after the entry limits. More than
    /// `tools.len()` when the cache keeps only part of it.
    pub listed: usize,
}

impl CachedToolListing {
    /// Whether the cache keeps only part of the listing.
    pub fn is_truncated(&self) -> bool {
        self.tools.len() < self.listed
    }
}

/// The latest listing of each server, within [`MAX_CACHED_TOOLS`] tools in
/// all, shared fairly (see the module docs).
#[derive(Default)]
pub(crate) struct ToolCache {
    listings: BTreeMap<String, Arc<CachedToolListing>>,
}

impl ToolCache {
    /// Make `tools` the cached listing of `server_id`: its first tools, up to
    /// the server's share. Another server's cached listing over its new share
    /// is cut to it.
    pub(crate) fn store(&mut self, server_id: &str, tools: &[McpToolInfo]) {
        let listed = tools.len();
        self.listings.insert(
            server_id.to_string(),
            Arc::new(CachedToolListing {
                server_id: server_id.to_string(),
                tools: Vec::new(),
                listed,
            }),
        );
        let demands: Vec<usize> = self.listings.values().map(|l| l.listed).collect();
        let shares = fair_shares(&demands, MAX_CACHED_TOOLS);
        for (listing, share) in self.listings.values_mut().zip(shares) {
            let kept = if listing.server_id == server_id {
                &tools[..share]
            } else if listing.tools.len() > share {
                &listing.tools[..share]
            } else {
                continue;
            };
            *listing = Arc::new(CachedToolListing {
                server_id: listing.server_id.clone(),
                tools: kept.to_vec(),
                listed: listing.listed,
            });
        }
    }

    /// Every server's cached listing, in server-id order.
    pub(crate) fn listings(&self) -> Vec<Arc<CachedToolListing>> {
        self.listings.values().cloned().collect()
    }
}

/// The max-min fair split of `capacity` among `demands`, in their order: each
/// demand in full when they all fit; otherwise an equal share, a demand below
/// it keeping only what it asks, and the remainder of the equal split given one
/// each to the first capped demands. The shares sum to the smaller of
/// `capacity` and the demands' sum, and none exceeds its demand.
fn fair_shares(demands: &[usize], capacity: usize) -> Vec<usize> {
    let mut ascending = demands.to_vec();
    ascending.sort_unstable();
    let mut remaining = capacity;
    let mut uncapped = ascending.len();
    let mut level = None;
    for demand in ascending {
        // The share left for each demand not yet met covers this one.
        if demand.saturating_mul(uncapped) <= remaining {
            remaining -= demand;
            uncapped -= 1;
        } else {
            level = Some(remaining / uncapped);
            break;
        }
    }
    let Some(level) = level else {
        return demands.to_vec();
    };
    // Every demand met in full is at most `level`; each capped one exceeds it.
    let mut extra = remaining - level * uncapped;
    demands
        .iter()
        .map(|&demand| {
            if demand <= level {
                demand
            } else if extra > 0 {
                extra -= 1;
                level + 1
            } else {
                level
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(server: &str, name: &str) -> McpToolInfo {
        McpToolInfo {
            name: name.to_string(),
            description: String::new(),
            server_id: server.to_string(),
            input_schema: None,
        }
    }

    fn tools(server: &str, count: usize) -> Vec<McpToolInfo> {
        (0..count).map(|i| tool(server, &format!("t{i}"))).collect()
    }

    #[test]
    fn a_description_is_cut_on_a_character_boundary_within_the_limit() {
        let short = "a".repeat(MAX_TOOL_DESCRIPTION_BYTES);
        assert_eq!(cut_description(short.clone()), short);
        // Two-byte characters: the cut never splits one.
        let long = "é".repeat(MAX_TOOL_DESCRIPTION_BYTES);
        let cut = cut_description(long);
        assert!(cut.len() <= MAX_TOOL_DESCRIPTION_BYTES, "{}", cut.len());
        assert!(cut.ends_with('…'));
        assert!(cut.trim_end_matches('…').chars().all(|c| c == 'é'));
    }

    #[test]
    fn json_fits_stops_at_the_limit() {
        let value = serde_json::json!({"k": "v"});
        let len = serde_json::to_vec(&value).unwrap().len();
        assert!(json_fits(&value, len));
        assert!(!json_fits(&value, len - 1));
    }

    /// `(server, kept, listed)` for each cached listing, in server-id order.
    fn summary(cache: &ToolCache) -> Vec<(String, usize, usize)> {
        cache
            .listings()
            .iter()
            .map(|l| (l.server_id.clone(), l.tools.len(), l.listed))
            .collect()
    }

    fn row(server: &str, kept: usize, listed: usize) -> (String, usize, usize) {
        (server.to_string(), kept, listed)
    }

    #[test]
    fn fair_shares_meet_small_demands_and_split_the_rest_evenly() {
        assert_eq!(fair_shares(&[], 10), Vec::<usize>::new());
        assert_eq!(fair_shares(&[3, 4], 10), [3, 4]);
        assert_eq!(fair_shares(&[2, 9, 9], 10), [2, 4, 4]);
        assert_eq!(fair_shares(&[9, 1, 9, 9], 10), [3, 1, 3, 3]);
        // The remainder of an even split goes to the first capped demands.
        assert_eq!(fair_shares(&[9, 9, 9], 10), [4, 3, 3]);
        assert_eq!(fair_shares(&[9, 1, 9, 9], 11), [4, 1, 3, 3]);
        assert_eq!(fair_shares(&[0, 20], 10), [0, 10]);
        assert_eq!(fair_shares(&[5, 5], 0), [0, 0]);
        for demands in [
            vec![MAX_TOOLS_PER_SERVER; 5],
            vec![MAX_CACHED_TOOLS - 10, 25],
            vec![1, 700, 3000, 2, 900],
        ] {
            let shares = fair_shares(&demands, MAX_CACHED_TOOLS);
            let total: usize = demands.iter().sum();
            assert_eq!(
                shares.iter().sum::<usize>(),
                total.min(MAX_CACHED_TOOLS),
                "{demands:?}"
            );
            assert!(shares.iter().zip(&demands).all(|(s, d)| s <= d));
        }
    }

    // The room is shared fairly, whichever server listed first; a listing
    // over its share is cached in part and says so; a new listing cuts the
    // others to their new shares, and they grow back with their own next
    // listing.
    #[test]
    fn the_cache_shares_the_total_cap_fairly_across_servers() {
        let mut cache = ToolCache::default();
        cache.store("a", &tools("a", MAX_CACHED_TOOLS - 10));
        assert_eq!(
            summary(&cache),
            [row("a", MAX_CACHED_TOOLS - 10, MAX_CACHED_TOOLS - 10)]
        );
        cache.store("b", &tools("b", 25));
        assert_eq!(
            summary(&cache),
            [
                row("a", MAX_CACHED_TOOLS - 25, MAX_CACHED_TOOLS - 10),
                row("b", 25, 25)
            ]
        );
        let listings = cache.listings();
        assert!(listings[0].is_truncated());
        assert!(!listings[1].is_truncated());
        assert_eq!(listings[0].tools, tools("a", MAX_CACHED_TOOLS - 25));

        // A shorter listing of `b` leaves room `a` regains only when it lists
        // again.
        cache.store("b", &tools("b", 5));
        assert_eq!(
            summary(&cache),
            [
                row("a", MAX_CACHED_TOOLS - 25, MAX_CACHED_TOOLS - 10),
                row("b", 5, 5)
            ]
        );
        cache.store("a", &tools("a", MAX_CACHED_TOOLS - 10));
        assert_eq!(
            summary(&cache),
            [
                row("a", MAX_CACHED_TOOLS - 10, MAX_CACHED_TOOLS - 10),
                row("b", 5, 5)
            ]
        );

        // A server listing no tools has an empty entry that is not truncated.
        cache.store("a", &[]);
        assert_eq!(summary(&cache), [row("a", 0, 0), row("b", 5, 5)]);
        assert!(!cache.listings()[0].is_truncated());
        assert_eq!(cache.listings()[1].tools, tools("b", 5));
    }

    // Five full listings share the cap evenly, the first ones in id order
    // taking the remainder; the cached total never exceeds the cap.
    #[test]
    fn five_full_listings_share_the_cap_evenly() {
        let mut cache = ToolCache::default();
        for server in ["e", "d", "c", "b", "a"] {
            cache.store(server, &tools(server, MAX_TOOLS_PER_SERVER));
            let total: usize = cache.listings().iter().map(|l| l.tools.len()).sum();
            assert!(total <= MAX_CACHED_TOOLS);
        }
        let share = MAX_CACHED_TOOLS / 5;
        assert_eq!(
            summary(&cache),
            [
                row("a", share + 1, MAX_TOOLS_PER_SERVER),
                row("b", share + 1, MAX_TOOLS_PER_SERVER),
                row("c", share + 1, MAX_TOOLS_PER_SERVER),
                row("d", share, MAX_TOOLS_PER_SERVER),
                row("e", share, MAX_TOOLS_PER_SERVER),
            ]
        );
        assert!(cache.listings().iter().all(|l| l.is_truncated()));
    }

    // A read shares the cached listings: it clones no tool.
    #[test]
    fn a_read_shares_the_cached_listings() {
        let mut cache = ToolCache::default();
        cache.store("a", &tools("a", 3));
        let first = cache.listings();
        let second = cache.listings();
        assert!(Arc::ptr_eq(&first[0], &second[0]));
    }
}
