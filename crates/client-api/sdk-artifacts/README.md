# sdk-artifacts — CONTRACT-192 generated client SDK contract

These artifacts are the **generated** MODULE-020 CONTRACT-192 `ClientSdkContract` for web and
native clients. They are produced from the canonical Rust DTOs in `crates/client-api` (via
schemars) — **do not hand-edit**.

| File | Content |
|------|---------|
| `schema/client-api.schema.json` | JSON Schema of the canonical client envelope + in-scope DTOs (envelope, error + `ClientErrorCode` enum, warning, session, list cursor), derived from the `#[derive(JsonSchema)]` types. |
| `schema/manifest.json` | `{ api_version, schema_hash, targets }` — the schema hash is `sha256` of the canonical (sorted-key) schema; SDK generators/conformance suites check against it. |
| `conformance/vectors.json` | Conformance vectors (shared, frozen for AC-12). Each vector declares its `kind` (`data` / `error` / `invalid`); the reference conformance test asserts the envelope invariants (data-XOR-error). |
| `conformance/fixtures/<target>/surface.json` | Per-platform thin declarative surface (m020-s5). Lists error_codes (from known_codes), pagination/reconnect cursor fields (from schema components), and example_idempotency_warnings exercised by vectors. Five targets (web,mac,ios,android,windows) must declare identical surfaces. Generator + test enforce uniformity. |

## Regenerate

```
cargo run -p advance-client-api --bin gen_client_sdk
```

The `schema_contract` integration test (`crates/client-api/tests/schema_contract.rs`) fails if
these files drift from freshly generated output — the §1.6 "0 schema drift" gate.

The generator also emits the five `conformance/fixtures/*/surface.json` (additive). The AC-12 witness
test asserts that all five surfaces are byte-identical, declare the same contract surface elements
from the canonical schema + vectors, and that the generator is deterministic. Schema/manifest/vectors
bytes are never altered by stub emission.

## Scope (m020-s1 foundation)

This slice ships the **schema + manifest + conformance vectors** only. Per-platform SDK
stubs/generators and cross-platform parity are MODULE-020-AC-12 (m020-s5, Wave-25). The event
stream cursor (`ClientEventCursor`, CONTRACT-191) and provider-family DTOs (runs/messages/grants)
arrive with their contracts in Wave-24.

## LLM token-delta subscription (tee T2, CONTRACT-235)

`GET /client/llm/deltas/stream` is a WebSocket route on the public Client API server. The bearer
token rides the unselected `advance.bearer.<hex>` WebSocket subprotocol (never the URL); the
handshake seeds through one full request-pipeline pass against a `read_llm_deltas`-scoped
subscribe handler. Stream selection/resume is an in-band Text frame (`LlmDeltaStreamRequest`
`{stream_key, from_cursor}`) — never the query string. Pages are `LlmDeltaWirePage`
(`deny_unknown_fields`): ordered seq-range items plus saturating `dropped/rejected/redacted/
warned` counters, an optional `terminal` settlement marker that rides every page after the
stream's Terminal frame arrives, and an optional `cursor` — an AEAD-sealed reconnect token
minted only at item boundaries, in its own independent seal domain (event cursors and delta
cursors are mutually non-replayable; the sealed body binds both `{stream_key, seq}`,
both-or-neither). Subscriber overflow answers the existing `stream_backpressure` error (HTTP
429); a disabled surface (`client_api.llm_deltas_enabled = false`) answers the existing
`module_unavailable` code.

Absent-stream contract (identical on all five platform surfaces):

> An absent stream that this surface previously served will never be served again; a stream key
> you have never received content for reads absent with no delivery promise.
