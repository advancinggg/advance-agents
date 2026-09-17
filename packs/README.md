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

See `the internal entity-data lane plan` for the entity model and the `agenda` pack that declares
the first aspect.
