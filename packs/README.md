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
Serve `<out>` from any HTTPS host (loopback HTTP is accepted for local testing). Without
`--base-url` the index carries bare file names, which the runtime resolves against
`pack.registry-url`, so one tree can move between hosts. A published version is immutable:
re-bundling the same `name@version` with different bytes is refused — bump the version.

Tarballs are reproducible (entries sorted, zero mtimes / uid / gid, ustar headers, no gzip
timestamp), so a rebuild from the same source tree yields the same sha256. The release
workflow (`.github/workflows/pack-release.yml`) runs on every `v*` tag: build every
`packs/*.build.yaml` pack, sign with the `PACK_SIGNING_KEY` repository secret when it is
configured, bundle, build a second time and compare digests, then attach the tarballs and
index documents to the GitHub release.

Trust: operators list maintainers' public keys in `runtime-config.yaml` `pack.trust-roots`;
a `pack.sig` from a listed key makes a `trust-level: trusted` claim effective at install.
The maintainer public key is published here in the same commit that configures
`PACK_SIGNING_KEY` (until then, releases are unsigned and every pack installs as
`untrusted`).
