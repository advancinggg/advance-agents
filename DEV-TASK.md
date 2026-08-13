# /dev task — OSS Wave-27 Lane G0: `genui-s1` (MODULE-023 OSS half)

> **Repo:** `advance-agents`  
> **Worktree:** `/Volumes/Sandisk/Advance/advance-agents-w27-genui`  
> **Branch:** `dev-task-w27-genui-s1`  
> **Base:** `public-genesis` (public pin surface; align with team if integration branch changes)  
> **Board:** `along/docs/lanes/oss/README.md`  
> **Specs (read-only from product tree):**  
> - `along/docs/modules/MODULE-023-genui.md`  
> - `along/docs/adr/2026-07-16-genui-a2ui-adoption.md`  
> - `along/docs/OPEN-CORE-BOUNDARY.md` (SPLIT at C221)  
> - `along/docs/DELIVERY-PLAN-OSS.md` Wave-27

## Mission

Implement **OSS half of MODULE-023 GenUI** so product SwiftUI and catalog content can bind later:

1. **`crates/genui` (`advance-genui`)** — CONTRACT-220 A2UI document model + CONTRACT-221 catalog validation gate + degradation summarizer + shared conformance corpus.
2. **Web Console renderer** — conformant documents → native console components; **no** agent code eval / HTML injection path (AC-01).
3. **Runtime seams** — `agent-genui` capability injection, grant gate, `genui.enabled` flag honesty (AC-07/09), projection path notes for M020 (Console).
4. **Schema carriage** — GenUI document/event schema extension on CONTRACT-192 generation path + hash mismatch refuse semantics (AC-10).
5. **Text-channel degradation** — typed summary via C215 seam, no raw JSON dump (AC-04).
6. **Action round-trip** — catalog-validated actions + confirm-marked actions (AC-08).
7. **Seed catalog gate side** — typed schemas for §3.9 vocabulary (AC-06 mechanism); **content seeds may be product C223** — do not block OSS on product copy.

**Optional same lane / later slice:** MCP Apps iframe (AC-05) — module marks P2; ship only if it does not block P0 ACs.

## Pin / A2UI first-slice decisions (record in PR)

- A2UI protocol version pin (v0.9.1 vs v1.0-RC) — **decide and document** before freezing corpus.
- Export surface through `advance-core` façade if required for product pin consumption.
- Workspace member + `Cargo.toml` / lock updates.

## Exclusive write set

- `crates/genui/**` (new)
- Root `Cargo.toml` / `Cargo.lock` workspace members
- `crates/advance-core/**` (re-exports only as needed)
- `clients/web-console/**` (GenUI renderer + fixtures)
- `crates/client-api/**` and/or `crates/client-api/sdk-artifacts/**` (schema extension only if required for AC-10)
- `crates/capabilities/**` / composition wiring **only** for `agent-genui` inject + flag (minimal)
- `crates/system-acceptance/**` only if adding OSS-altitude witnesses for genui
- Tests colocated with above

**Forbidden:**

- Product SwiftUI / `along` clients
- C223 product catalog **content** ownership (product lane)
- CONTRACT-210 embed bridge (separate Wave-27 lane)
- device-mesh, Telegram, forge/cloud adapters
- Pre-claiming MODULE-023 §3.4 flips without witnesses (ledger updates may be coordinated in `along` docs after merge)

## Deliverables

1. Compiling `advance-genui` crate + workspace membership.
2. Catalog gate: unknown component / bad props / script-in-props → reject or explicit fallback (never raw).
3. Console renderer path for valid corpus vectors (AC-01).
4. Conformance corpus checked into OSS (shared with product later for AC-03).
5. Feature-flag + grant denial paths (AC-09/07 mechanism).
6. README in `crates/genui` + how product should depend (git tag).
7. Tests green; list which ACs are **ready to flip** vs held for product/e2e.

## Tests (minimum)

```bash
# From worktree root
cargo test -p advance-genui --locked
# + console / integration targets you add
# + workspace clippy if CI requires
cargo clippy -p advance-genui --all-targets -- -D warnings
```

Map tests to MODULE-023-T01, T02, T04, T06–T10 as implemented; T03 is **product** SwiftUI; T05 optional.

## Coordination with product peer

| Peer | Worktree | Scope |
|---|---|---|
| Product P3-G | `/Volumes/Sandisk/Advance/along-p3-genui-swiftui` | SwiftUI + C223 content; Mode A until this lane tags |

Do **not** wait on product to merge OSS. After merge, cut a tag (or note tip) for product re-pin.

## Exit criteria

- [ ] `crates/genui` present; no product deps
- [ ] Gate + corpus + console render path witnessed
- [ ] Flag/grant honesty witnessed at module altitude
- [ ] Document which MODULE-023 ACs can flip on OSS evidence
- [ ] Product handshake note: tag / façade exports for SwiftUI bind
