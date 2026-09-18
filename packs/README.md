# packs/

First-party and community packs for the advance-agents runtime (MODULE-018 pack system).
Each subdirectory is one installable pack: its layout IS the install layout —
`pack.yaml` plus any of the 11 canonical subdirectories (`behavior-binaries`,
`agent-templates`, `skills`, `components`, `channel-adapters`, `mcp-servers`, `presets`,
`workflows`, `memory-seeds`, `meta-schema-extensions`, `resource-capabilities`). Nothing
else is allowed at a pack's top level (no README / LICENSE — describe the pack in
`pack.yaml` `description` and in its skills' `SKILL.md`).

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

Conflicts never block. A pack whose schema extension conflicts with the schema, or with a
pack applied before it in pack-name order, is skipped with a warning in the runtime log. So
is a preset or skill tool whose name is already taken, and a workspace skill wins over a pack
skill of the same name. When several versions of a pack are installed, only the highest
applies.

## Contribution rules

1. `trust-level: untrusted` always. A `trusted` pack must ship a `pack.sig` (ed25519 over
   `pack.yaml`) issued by a maintainer trust root; a self-declared `trusted` without a valid
   signature is downgraded at install.
2. `required-capabilities` may only name runtime capabilities (`agent_config::KNOWN_CAPABILITIES`)
   or resource-capability ids provided by another pack in this directory.
3. Every pack here is installed by CI on every change (`crates/cli/tests/packs_dir_ci.rs`
   drives the real installer over the source directories, and over `target/packs/*` when a
   build ran first). A pack that fails to install fails the build.
4. Versions are semver. Bumping a pack's version records the change in the `description`
   `changelog:` line (the layout allow-list has no room for a CHANGELOG file).
5. A skill's `tool.wasm` is pure computation: no clock, no randomness, no I/O. `data.apply`
   invokes it with a fixed clock and seed, so equal inputs must give equal outputs.
6. Structured data lives in frontmatter and is read and written through the runtime's `data`
   host tool. A pack declares vocabulary (fields, invariants, queries, views, operation
   bindings) in `meta-schema-extensions/`; it never ships code that touches storage.

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
serves the same tree. Then `advance pack install registry:agenda@0.1.0` installs the built
agenda pack, `tool.wasm` included.

Trust: operators list maintainers' public keys in `runtime-config.yaml` `pack.trust-roots`;
a `pack.sig` from a listed key makes a `trust-level: trusted` claim effective at install.
The maintainer public key is published here in the same commit that configures
`PACK_SIGNING_KEY`. Until then, releases are unsigned and every pack installs as
`untrusted`. Signing applies to versions published after the key is configured; a version
that was already published unsigned stays as published.
