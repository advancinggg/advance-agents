# Agent identity: id, handle, display name

Every agent in a workspace has three names. Each one has exactly one job.

| Name | Example | Mutable | Where it lives | Who uses it |
|---|---|---|---|---|
| **id** | `018f3c2e-…` (UUID v4) | never | `id:` key of the agent's own `.agent/config.yaml` | the tree key; `HostCallContext.agent_id`; every persistent store (grants, memory buckets, the cost ledger's `agent_id`, skills, task/turn rows) |
| **handle** | `research` | yes, via `:update` | children: the `alias:` of the parent's `agents:` declaration; root: the `handle:` key of its config document | messaging (`agent:research` is the mailbox / serve key); the `{agent_id}` path parameter of the `/client/agents` family; guest `spawn-child(id)` / `terminate-child(id)`; workspace directory default |
| **display name** | `Research Desk` | freely | `display-name:` key of the agent's own config document | people; the `display_name` field of the API |

The runtime reads only `capabilities:` and `agents:` at boot. Changing `display-name`
is therefore never a capability change and needs no restart.

## Creation

- **Root.** At boot the daemon mints the root's id when the config document has no
  `id:` and writes it back. The handle comes from the `handle:` key; when absent it is
  derived once from `display-name` (see below) and written back, else `root`. The
  product's first-open flow sets the display name before the first boot, so a home
  named "Soul Mate" boots as `soul-mate` / `agent:soul-mate`.
- **Children.** `POST /client/agents` takes an optional `agent_id` (the handle). When
  absent it is derived from `display_name`. The immutable id is minted server-side
  and persisted into the child's document; the response carries both (`agent_id` =
  handle, `id` = UUID).
- **Guest spawns.** `spawn-child(id)` treats the guest's id as the handle and mints the
  UUID. Every later child operation a guest performs by that name (`terminate-child`,
  `rollback-child`, …) resolves the handle through the tree.
- **Re-boot.** Declared children are re-materialized under the id their own document
  carries, so grants, memory and ledger rows written in an earlier daemon lifetime stay
  attached.

## Handle derivation

`derive_agent_id(display_name)` in `advance-shared-types`: lower-case, whitespace runs
become `-`, everything outside `[a-z0-9_-]` is dropped, leading/trailing `-` trimmed,
capped at 64. A collision appends `-2`, `-3`, …; a name that leaves nothing (for
example a non-Latin script) falls back to `agent`, `agent-2`, …. The derivation runs
once, at creation; renaming the display name never re-derives the handle.

## Renaming

- `display_name`: free, no restart.
- `handle` (`POST /client/agents/{agent_id}:update` with `handle`): the tree, the
  declaration alias (or the root's `handle:` key) move; the id and every store keyed by
  it are untouched. The live mailbox keeps the old key until the next daemon start, so
  the response carries `restart_required`.
- `id`: not supported. It is the persistence key; changing it would be a migration of
  every store. Delete and re-create instead.

## Invariants

- Handles are unique per workspace; the tree refuses to bind a handle another node
  owns. Two agents can only share a mailbox key by sharing a handle, which is
  therefore impossible.
- `id` is never client-writable: a config document written through the API keeps the
  node's id even if the client omitted or changed the key.
- Nothing persistent is ever keyed by a handle.
