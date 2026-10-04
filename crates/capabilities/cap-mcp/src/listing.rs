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
//! The client keeps each server's latest listing. The cache holds at most
//! [`MAX_CACHED_TOOLS`] tools across all servers: a listing that does not fit
//! beside the other servers' listings is cached in part (its first tools),
//! while the caller still receives all of it.

use std::collections::{BTreeMap, HashSet};
use std::io;

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

/// The latest listing of each server, within [`MAX_CACHED_TOOLS`] tools in all.
#[derive(Default)]
pub(crate) struct ToolCache {
    listings: BTreeMap<String, Vec<McpToolInfo>>,
    total: usize,
}

impl ToolCache {
    /// Make `tools` the cached listing of `server_id`, keeping its first tools
    /// up to the room the other servers' listings leave.
    pub(crate) fn store(&mut self, server_id: &str, tools: &[McpToolInfo]) {
        let replaced = self.listings.get(server_id).map_or(0, Vec::len);
        let others = self.total - replaced;
        let kept: Vec<McpToolInfo> = tools
            .iter()
            .take(MAX_CACHED_TOOLS.saturating_sub(others))
            .cloned()
            .collect();
        self.total = others + kept.len();
        self.listings.insert(server_id.to_string(), kept);
    }

    /// Every cached tool, in server-id order, then listing order.
    pub(crate) fn tools(&self) -> Vec<McpToolInfo> {
        self.listings.values().flatten().cloned().collect()
    }
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

    // A listing that does not fit beside the others is cached in part;
    // replacing a server's listing frees its room first.
    #[test]
    fn the_cache_holds_at_most_the_total_cap_across_servers() {
        let mut cache = ToolCache::default();
        cache.store("a", &tools("a", MAX_CACHED_TOOLS - 10));
        cache.store("b", &tools("b", 25));
        assert_eq!(cache.tools().len(), MAX_CACHED_TOOLS);
        let b: Vec<_> = cache
            .tools()
            .into_iter()
            .filter(|t| t.server_id == "b")
            .collect();
        assert_eq!(b, tools("b", 10));

        cache.store("a", &tools("a", 5));
        cache.store("b", &tools("b", 25));
        assert_eq!(cache.tools().len(), 30);
        assert_eq!(cache.total, 30);
        cache.store("a", &[]);
        assert_eq!(cache.tools(), tools("b", 25));
    }
}
