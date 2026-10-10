# packs/

First-party and community packs for the advance-agents runtime (MODULE-018 pack system).
Each subdirectory is one installable pack: its layout IS the install layout —
`pack.yaml` plus any of the 10 canonical subdirectories (`behavior-binaries`,
`agent-templates`, `skills`, `components`, `channel-adapters`, `mcp-servers`, `presets`,
`workflows`, `memory-seeds`, `meta-schema-extensions`). Nothing else is allowed at a pack's
top level (no README / LICENSE — describe the pack in `pack.yaml` `description` and in its
skills' `SKILL.md`).

Source directories are **text only**. A pack that ships a skill `tool.wasm` keeps the Rust
source in `crates/packs/<name>-tools` (a workspace `exclude`, target `wasm32-unknown-unknown`)
and a build manifest `packs/<name>.build.yaml` next to the pack directory:

```bash
rustup target add wasm32-unknown-unknown
advance pack build packs/agenda --out target/packs     # copies the pack, builds tool.wasm, fills checksums
advance pack install target/packs/agenda --packs-dir .advance/packs
advance pack install packs/agenda --packs-dir .advance/packs   # text-only install (no series operations)
```

## Installing into a running runtime

An install takes effect without a restart, whether it goes through the Client API
(`POST /client/packs:install`) or through `advance pack install` from a shell (the daemon
notices the packs dir's index change within a few seconds). The pack's meta-schema extensions
merge into the live schema in memory: the workspace's own `.agent/meta-schema.yaml` is the
base and is never rewritten. Its presets become known to the grant preset registry, and its
skills' `tool.wasm` sidecars register as `skill::<name>` tools. Existing records are
re-indexed, so they gain the pack's aspects. Uninstalling takes all of it away again.

Each part applies only where the root agent's `.agent/config.yaml` declares the capability
that owns it: schema extensions need `fs`, presets need `grant`, skill tools need `tools`.
The `data` tool exists when both `tools` and `fs` are declared. A workspace from
`advance init` declares `fs` and `llm`, so add `tools: true` and restart before an agent can
use a pack's tools. A tool registered by a hot install is callable at once, but the tool list
shown to the model is built when the agent starts.

## Capabilities a pack relies on

A pack never adds a capability. Its content runs under the ones the runtime already has:
`tools` reaches a tool, and the capability that governs a resource authorizes what the tool
does with it. The `data` tool reads and writes workspace files, so it is authorized by the
caller's `fs` grant: reads need read access to the record's file, writes need write access,
and `query`, `promote` and `demote` need the whole territory. A pack that uses the `data`
tool declares `required-capabilities: [tools, fs]`. A preset that grants the retired `data`
family (agenda 0.1.0 shipped one) is skipped with a warning.

Conflicts never block. A pack whose schema extension conflicts with the schema, or with a
pack applied before it in pack-name order, is skipped with a warning. The Client API install
response lists, under `warnings`, everything of the pack that did not take effect; the same
lines go to the runtime log. So
is a preset or skill tool whose name is already taken, and a workspace skill wins over a pack
skill of the same name. When several versions of a pack are installed, only the highest
applies.

## What the runtime activates

Of the ten content kinds, the runtime activates `agent-templates` (when an agent is
spawned from one), `presets`, `meta-schema-extensions` and `skills` (the `tool.wasm` as a
tool, the `SKILL.md` under the agent's available skills when it can reach tools). A template
brings two more kinds with it: `behavior: { type: pack-ref, ref: <pack>@<version>/behavior-binaries/<name> }`
gives the spawned agent that behavior binary, and `memory-seed: <name>` starts it with the
pack's `memory-seeds/<name>.jsonl` as its knowledge file. `workflows` run on the operator's
request, `POST /client/packs/{name}@{version}:apply` with `{ "workflow": "<name>" }`: a
workflow spawns child agents from the pack's templates, submits the pack's `components` to
the scheduler and registers its `mcp-servers`; a failed step is compensated. `mcp-servers`
are written into the MCP servers directory (`.advance/mcp-servers/` by default; secret-ref
ids only, origin recorded) and become callable when the root agent declares `mcp`;
uninstalling the origin pack removes those files. Applying the same workflow again is a
no-op when the server is unchanged. [MCP servers](#mcp-servers) below has the details.
`channel-adapters` are refused at install: the runtime does not load channel adapters from
packs. `provides: resource-capabilities` is a retired content kind: install (and `advance pack
bundle`) refuses a manifest that declares it, and the layout check refuses a top-level
`resource-capabilities/` directory. A pack installed by an older runtime with the key still
loads; the runtime ignores the key and logs a warning for that pack. A pack's
`dependencies:` are installed from the configured registry when they are not present already.

## MCP servers

The runtime reaches MCP servers only when the root agent's `.agent/config.yaml` declares
`mcp`. The daemon then reads the server files, builds one MCP client, and gives agents the
seven `mcp-client` host functions, each call decided by the caller's `mcp` grant. A home
whose root does not declare `mcp` loads no server file, starts no server and prints nothing
about MCP when it starts.

### Grants

```yaml
capabilities:
  mcp: true                                  # every server, every tool
```

```yaml
capabilities:
  mcp:
    servers: [github, search]                # the server ids the grant reaches
    tool-patterns: ["get_*", search_code]    # the tools on them; leave it out for every tool
```

`servers` lists the ids of the servers the grant reaches, as written: a grant with
`tool-patterns` and no `servers` reaches no server (the daemon warns when it starts).
`tool-patterns` narrows the tools on those servers; without it the grant reaches every
tool. A pattern is a tool name, or a prefix followed by one `*` (`get_*` matches every tool
whose name starts with `get_`). A bare `*` or any other glob character makes the pattern
malformed, and the grant then covers no tool; a key other than these two makes it cover
nothing. A server's prompts and resources are reachable only through a grant without
`tool-patterns`. A server's `web.search` and `web.extract` tools also need the agent's `web`
grant (in the `offline` web mode no agent gets them), and those of a stdio server are never
shown or callable.

A child agent that declares `mcp` with its own `servers` / `tool-patterns` gets exactly
those when its parent's grant covers them (`get_*` covers `get_issue` and `get_is*`), and no
`mcp` grant otherwise; a child that declares `mcp: true` gets its parent's grant. Only the
root agent's prompt lists MCP tools.

### Server files

Each server is one file, `<server-id>.yaml`, in the servers directory (`mcp.servers-dir`,
default `.advance/mcp-servers`, a directory inside `.advance/` that no agent can write). A
server id is 1 to 128 characters from `[A-Za-z0-9._-]`, not starting with `.`. The daemon
reads the directory when it starts and again on every pack event. A file that cannot serve
never stops the daemon: it is skipped with a warning on stderr (an entry that is not a
regular file, a file over 64 KiB or one the schema refuses, a file not named after its
`server-id`, a stdio server while `mcp.allow-stdio` is `false`, a server whose secret is not
in the store, anything past 128 servers) and the others are kept. Hidden entries and names
that do not end in `.yaml` are ignored.

```yaml
server-id: local-tools
description: Local tools                     # optional, at most 1 KiB
transport:
  kind: stdio
  command: /usr/local/bin/local-tools-mcp    # give an absolute path
  args: ["--stdio"]
  env:                                       # literals, never secrets
    LOG_LEVEL: info
  cwd: /srv/local-tools                      # absolute; the default is /
secret-refs:                                 # stdio only: variable -> secret-store key
  API_TOKEN: local-tools-token
```

```yaml
server-id: github
transport:
  kind: http
  endpoint-url: https://mcp.example.com/mcp   # the server's Streamable HTTP endpoint
credentials:                                  # http only, and only in your own files
  - position: bearer                          # Authorization: Bearer <secret>
    secret: github-token
```

A `stdio` server is a process the daemon starts on its first use (a listing or a call) and
stops when the daemon stops. A bare `command` name is looked up on the `PATH` the server gets
(the file's own, else the daemon's, else the system's default search path), and how a
relative path such as `./server` resolves depends on the platform, so give an absolute path:
the daemon warns about a command that is not one. `args` (at most 64) are passed as written.
The process runs in `cwd`, an absolute path (`/` when the file gives none); a `cwd` that is
not an existing directory fails each start of the server with an error that names it. Its
environment is built in three layers, each over the one before:

1. the daemon's own `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`
   and `TZ`, those the daemon has set;
2. the file's `env` literals: at most 64, each name `[A-Za-z_][A-Za-z0-9_]*`, each value at
   most 4 KiB without control characters (it may be empty);
3. the file's `secret-refs` (at most 32): each variable gets the value of a secret, read
   when the file is read. A name is never both an `env` literal and a `secret-refs` variable.

Nothing else of the daemon's environment, its API keys and tokens among it, reaches a server.

An `http` server is one Streamable HTTP endpoint: `endpoint-url` is `https://` on any host,
or `http://` on loopback (`localhost`, `127.0.0.0/8`, `::1`), which only your own server
files may use. A URL with userinfo (`user@host`) or a `{` or `}` is refused, and a server on
the older HTTP+SSE transport (a GET stream beside a separate message endpoint) is refused
when it connects. Every request goes through a security chain of its own (leak scans, SSRF
guard, rate limit, redirect re-check) that reaches the endpoint's scheme, host and port only.
A loopback endpoint is exempted from the chain's loopback ban for exactly its host and port,
for the files read when the daemon starts: a loopback server that appears later is refused
with a warning until the daemon restarts.

`credentials` (at most 8) bind secrets of the daemon's secret store to every request the
server is sent:

- `{position: bearer, secret: <name>}` sends `Authorization: Bearer <secret>`;
- `{position: basic, username: <user>, secret: <name>}` sends `Authorization: Basic` of
  `<user>:<secret>` (at most one of `bearer` and `basic`; the username holds no `:`);
- `{position: header, key: <header>, secret: <name>}` sends that header, which may not be one
  the transport sets (`Authorization`, `Host`, `Content-Length`, `Transfer-Encoding`,
  `Content-Type`, `Accept`, `Mcp-Session-Id`, `MCP-Protocol-Version`, in any case);
- `{position: query, key: <key>, secret: <name>}` adds `<key>=<secret>` to the URL's query
  (`key` from `[A-Za-z0-9._-]`).

A file names secrets, never values: the chain looks each one up at every request and puts
its value into that request alone, never into a file, an event or a log line. A value changed
in the synchronized keychain is sent from the next request on; with the file store, a value
another process writes (as `advance secrets set` does) is sent once the daemon restarts.

A server file read at start that names a secret, through `secret-refs` or `credentials`,
makes the daemon open its secret store, as `secrets` or `llm` do, and that needs the home's
master key: without it the daemon does not start. A server whose secret is not in the store
is skipped with a warning, and so is every server that names a secret while no store is
open (one a pack registers on a daemon that started without opening its store, until the
daemon restarts).

### The `mcp:` block of runtime-config.yaml

| Knob | Default | Meaning |
|---|---|---|
| `servers-dir` | `.advance/mcp-servers` | the servers directory: relative to the workspace, inside `.advance/`, no `..` |
| `allow-stdio` | `true` | `false` skips every stdio server file with a warning and refuses a pack's stdio server |
| `request-timeout-sec` | `30` | `1..=300`: one request to a server |
| `startup-timeout-sec` | `10` | `1..=120`: starting a server and its `initialize` exchange |
| `max-result-bytes` | `4194304` | `1..=4194304`: a larger call result fails the call |
| `warm-tool-cache` | `false` | `true` lists, right after start, the tools of the servers the root's grants reach |

The block is read when the daemon starts: an edit takes effect at the next start, and a value
out of its range is a configuration error.

### Servers from packs

A pack ships a server as `mcp-servers/<name>.yaml`, in the schema above, and registers it
with a workflow step, which runs when the operator applies the workflow
(`POST /client/packs/{name}@{version}:apply`):

```yaml
name: setup
steps:
  - type: register-mcp-server
    config-ref: my-pack@1.0.0/mcp-servers/search
    secret-refs:                  # optional, stdio only: variable -> secret-store key
      SEARCH_TOKEN: search-token
```

The step writes `<server-id>.yaml` into the servers directory: the pack's transport as
written, the manifest's and the step's `secret-refs` as secret-store keys (never values; a
step's own keys must be in the open store when it runs) and an `origin` block naming the
pack:

```yaml
origin:
  pack: "my-pack@1.0.0"
  config-ref: "my-pack@1.0.0/mcp-servers/search"
```

A running daemon whose root declares `mcp` loads the server at once. A daemon whose root does
not declare `mcp` writes the file all the same and logs `advance: WARN mcp: server '<id>' of
pack <name@version> is registered but not loaded: …`. Applying the same workflow again
changes nothing; a registration with other content, or under an id that your own file or
another registration holds, is refused. A pack may not register:

- a stdio server, unless the pack's effective trust is `trusted` (see Trust below), and no
  stdio server at all while `mcp.allow-stdio` is `false`;
- an http server on loopback;
- a server that binds `credentials`.

The loader enforces two of these on any file with an `origin` block: it skips one whose
endpoint is on loopback, and the schema refuses `credentials` beside an `origin` block. Do
not write an `origin` block into a file of your own: the file then belongs to the pack it
names, and goes when that pack is not installed.

A pack's server files go with the pack. A running daemon removes them as soon as the pack is
uninstalled, through the Client API or by `advance pack uninstall` from a shell (which the
daemon notices within a few seconds), and disconnects the server (a stdio server's process
stops once a call still running on it ends). The files of a pack uninstalled while no daemon
ran are removed when the next daemon whose root declares `mcp` starts, before any agent
runs; a home whose root does not declare `mcp` removes them at its next pack event, without a
log line. Only the highest installed version of a pack applies, and a file belongs to the
`name@version` that wrote it: installing a newer version removes the older version's server
files, so apply the new version's workflow to register its servers again.

### What the model and the Client API see

The root agent's prompt lists, under `# Available Tools`, the MCP tools its grants reach,
each as `<server>__<tool>` (a tool whose name already starts with `<server>__` keeps it as
is; the prompt writes a character that is unsafe in its tool lines, such as a delimiter or a
look-alike of one, as `_`, and keeps ASCII `-`). While the root agent runs,
`GET /client/tools` lists the same tools under `mcp`: `name` is that same `<server>__<tool>`,
and `server_id` the server's id.

The tools come from a cache of each server's tool listing. With `warm-tool-cache: false`, the
default, nothing is listed when the daemon starts: the first read (the root agent's first
turn, or the first `GET /client/tools`) shows no MCP tools and starts listing, in the
background, the servers the root's grants reach, and a later read shows their tools.
`warm-tool-cache: true` starts those listings when the daemon starts. A server a pack
registers while the daemon runs is listed at once when the root's grants reach it, and a
listing that fails is tried again at the next read. A listing keeps at most 512 tools of a
server: a tool whose name is over 256 bytes is dropped, a description is cut at 2 KiB, and
an input schema over 16 KiB is left out. The cache holds at most 2048 tools across the
servers.

One read shows at most 32 KiB (32768 bytes) of MCP tool text, each tool counted as the line
the prompt renders for it, `- <server>__<tool>(<arguments>) — <description>`: the tools of
your own servers first, then those of trusted packs' servers, then those of the other
packs' servers, each group by server id and each server's tools by name, up to the first
tool that does not fit. When tools are left out, the prompt's tools section ends with
`… N more MCP tools not shown` (`… 1 more MCP tool not shown`), `GET /client/tools` lists the
same budgeted tools (it has no field for the count), and stderr says
`advance: WARN mcp: N of the M MCP tools agent <id> may call are left out of its prompt and
its /client/tools listing: …` each time that number changes, unless it drops to zero. When
a prompt's fixed content (all but the conversation history) does not fit the model's context
budget, its last MCP tools give way first, counted in the same closing line; only a prompt
that does not fit even without them loses its host functions, WASM tools, skills and
delegates.

The description of a pack server's tool ends in `[pack name@version]`, in the prompt and in
`GET /client/tools`, within the 2 KiB description cap: the text before it is cut, never the
marker.

## Contribution rules

1. `trust-level: untrusted` always. A `trusted` pack must ship a `pack.sig` (ed25519 over
   `pack.yaml`) issued by a maintainer trust root; a self-declared `trusted` without a valid
   signature is downgraded at install.
2. `required-capabilities` may only name runtime capabilities (`agent_config::KNOWN_CAPABILITIES`).
3. Every pack here is installed by CI on every change (`crates/cli/tests/packs_dir_ci.rs`
   drives the real installer over the source directories, and over `target/packs/*` when a
   build ran first). A pack that fails to install fails the build.
4. Versions are semver. Bumping a pack's version records the change in the `description`
   `changelog:` line (the layout allow-list has no room for a CHANGELOG file).
5. A skill's `tool.wasm` is pure computation: no clock, no randomness, no I/O. `data.apply`
   invokes it with a fixed clock and seed, so equal inputs must give equal outputs.
6. Structured data lives in frontmatter. A pack declares vocabulary (fields, invariants,
   queries, views, operation bindings, and in `display` how clients present them) in
   `meta-schema-extensions/`; it never ships code that touches storage. The runtime enforces
   the declared invariants on every write of a Markdown file, through the `data` host tool and
   through `fs.write` alike, and both keep the entity index and the change event in step.

The `agenda` pack declares the first aspect and is the reference for the entity model
(frontmatter records, inline items, the `data` host tool).

## Signing and publishing

```bash
advance pack keygen --out ~/.advance/pack-signing.key        # 64 hex chars, mode 0600; prints the public key
advance pack sign target/packs/agenda --key ~/.advance/pack-signing.key   # pack.sig over the exact pack.yaml bytes
advance pack bundle target/packs/agenda --out target/registry --base-url https://packs.example.com
```

`bundle` writes `<out>/<name>-<version>.tar.gz` and merges `<out>/index/<name>.json` — the
static layout `pack.registry-url` consumers read for `registry:<name>@<version>` sources.
Serve `<out>` from any HTTPS host that answers without redirects (loopback HTTP is accepted
for local testing). The runtime's registry client refuses 3xx responses by design, so a
host that redirects downloads (GitHub release assets always do) cannot serve a registry.
Without `--base-url` the index carries bare file names, which the runtime resolves against
`pack.registry-url`, so one tree can move between hosts. A published version is immutable:
re-bundling the same `name@version` with different bytes is refused — bump the version.

The archive format is deterministic (entries sorted, zero mtimes / uid / gid, ustar headers,
no gzip timestamp): bundling the same built pack always yields the same sha256, and two
builds in the same environment (same toolchain, same paths) yield identical tarballs. Builds
on different machines can differ, because the compiler embeds dependency source paths in
`tool.wasm`; the published digest is the one the release workflow built. The release
workflow (`.github/workflows/pack-release.yml`) runs on every `v*` tag and on demand: it
builds every `packs/*.build.yaml` pack twice and compares the tarball digests, signs with the
`PACK_SIGNING_KEY` repository secret when it is configured, publishes every new
`name@version` into the registry tree on the `gh-pages` branch (`packs/`), and attaches the
tarballs to the GitHub release as plain downloads. A version that is already published is
never rewritten; a rebuild with different bytes is skipped with a warning.

The first-party registry, for `pack.registry-url` in `runtime-config.yaml`:

```yaml
pack:
  registry-url: https://raw.githubusercontent.com/advancinggg/advance-agents/gh-pages/packs
```

Once GitHub Pages serves the `gh-pages` branch, `https://advancinggg.github.io/advance-agents/packs`
serves the same tree. Then `advance pack install registry:agenda@0.1.2` installs the built
agenda pack, `tool.wasm` included.

Trust: operators list maintainers' public keys in `runtime-config.yaml` `pack.trust-roots`;
a `pack.sig` from a listed key makes a `trust-level: trusted` claim effective at install.
The maintainer public key is published here in the same commit that configures
`PACK_SIGNING_KEY`. Until then, releases are unsigned and every pack installs as
`untrusted`. Signing applies to versions published after the key is configured; a version
that was already published unsigned stays as published.
