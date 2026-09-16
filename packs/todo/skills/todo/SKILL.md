---
name: todo
description: Manage to-do items as entities with the `completion` aspect through the data.* host functions.
---

# To-Do

An item is any entity carrying the `completion` aspect: it has a `status`
(`todo` | `doing` | `done` | `cancelled`) and optionally `due` (RFC 3339), `priority`
(integer, higher = more urgent), `assignee` (`agent:<id>` or a person) and `completed_at`.

Never edit structured fields by rewriting a file. Use the `data` capability:

- List open items: `data.query { "aspect": "completion", "status": "todo" }`
- Add an item under a project file: `data.create { "parent": "launch.md", "record": { "type": "work-item", "title": "…", "status": "todo", "due": "2026-09-20T18:00:00+08:00" } }`
- Complete: `data.patch { "target": "launch.md#e-…", "ops": [{ "set": "status", "value": "done" }, { "set": "completed_at", "value": "<now>" }] }`
- An item that needs its own notes: `data.promote { "target": "launch.md#e-…", "to": "file" }`

Items live inline in the parent's frontmatter (`items[]`) until they need a body. The host
assigns ids, validates fields against the schema, and keeps the frontmatter canonical.
