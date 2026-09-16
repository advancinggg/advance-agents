---
name: calendar
description: Schedule events as entities with the `schedule` aspect through the data.* host functions.
---

# Calendar

An event is any entity carrying the `schedule` aspect: it has `starts` (RFC 3339 with
offset) and optionally `ends`, `all_day`, `repeat` (an RFC 5545 RRULE such as
`FREQ=WEEKLY;BYDAY=MO`) and `tz` (IANA zone, e.g. `Asia/Shanghai`). An event can also carry
the `completion` aspect at the same time (a meeting you must prepare for).

Never edit structured fields by rewriting a file. Use the `data` capability:

- What is on today: `data.query { "aspect": "schedule", "occurs_between": ["<start of day>", "<end of day>"] }`
- Add a meeting under a project file: `data.create { "parent": "launch.md", "record": { "type": "event", "title": "周会", "starts": "2026-09-22T10:00:00+08:00", "ends": "2026-09-22T11:00:00+08:00", "repeat": "FREQ=WEEKLY;BYDAY=MO" } }`
- Move it: `data.patch { "target": "launch.md#e-…", "ops": [{ "set": "starts", "value": "…" }, { "set": "ends", "value": "…" }] }`

Repeating events are expanded by the host when it indexes the file; querying a window never
requires you to compute recurrences.
