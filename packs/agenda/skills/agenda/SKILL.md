---
name: agenda
description: Agenda items are entities with a status and/or a start time; manage them with the runtime's `data` tool (describe / query / get / create / patch / apply), never by rewriting files.
---

# Agenda

An entity is an agenda item when it has `status` (todo / doing / done / cancelled) or
`starts`. Call `data.describe` for the exact fields, queries (`open`, `overdue`, `day`,
`upcoming`) and operations; the runtime validates every write, enforces status transitions
and fills `completed_at` for you. The bundled tool provides `detach-occurrence` and
`shift-series` for repeating events through `data.apply`.
