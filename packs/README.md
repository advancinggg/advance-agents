# packs/

First-party and community packs for the advance-agents runtime (MODULE-018 pack system).
Each subdirectory is one installable pack: its layout IS the install layout —
`pack.yaml` plus any of the 11 canonical subdirectories (`behavior-binaries`,
`agent-templates`, `skills`, `components`, `channel-adapters`, `mcp-servers`, `presets`,
`workflows`, `memory-seeds`, `meta-schema-extensions`, `resource-capabilities`). Nothing
else is allowed at a pack's top level (no README / LICENSE — describe the pack in
`pack.yaml` `description` and in its skills' `SKILL.md`).

Install one locally:

```bash
advance pack install packs/todo --packs-dir .advance/packs
```

## Contribution rules

1. `trust-level: untrusted` always. A `trusted` pack must ship a `pack.sig` (ed25519 over
   `pack.yaml`) issued by a maintainer trust root; a self-declared `trusted` without a valid
   signature is downgraded at install.
2. `required-capabilities` may only name runtime capabilities (`agent_config::KNOWN_CAPABILITIES`)
   or resource-capability ids provided by another pack in this directory.
3. Every pack here is installed by CI on every change (`crates/cli/tests/packs_dir_ci.rs`
   drives the real installer). A pack that fails to install fails the build.
4. Versions are semver. Bumping a pack's version records the change in the `description`
   `changelog:` line (the layout allow-list has no room for a CHANGELOG file).
5. Skills are knowledge-only unless they ship a `tool.wasm` that exports `tool-exports`.

See the structured-data lane notes for the entity model the `todo` and `calendar` packs
declare aspects for.
