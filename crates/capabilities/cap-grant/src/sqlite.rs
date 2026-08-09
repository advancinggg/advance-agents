//! `grant_index` SQLite dual-write (MODULE-013 §2.6).
//!
//! cap-grant manages the `grant_index` table independently of M004's
//! centralized schema (slice-A "Option B" decision per MODULE-013 §3.7).
//! `ensure_schema()` runs the table-create statement and three index-create
//! statements (all `IF NOT EXISTS`) atomically inside `BEGIN IMMEDIATE`.
//! The existence-check guards in `crates/database/src/schema.rs` filter
//! on the 11 v1 names and 6 virtual tables; `grant_index` is invisible
//! to those checks.

use std::sync::Arc;

use advance_database::SqliteIndexHandle;
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use crate::data::{CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl};
use crate::error::{CapGrantError, Result};

/// The D4 grant-mutation capability.
///
/// The ADR's letter: *"Raw SQLite index mutation is crate-private and consumes an
/// unforgeable `GrantMutationToken` owned by `GrantStore`; external callers cannot retain
/// a clone and bypass MODULE-013's own fair keyed mutation gate."*
///
/// Every property below exists to make that sentence true, and each would be defeated by
/// an obvious-looking convenience:
///
/// * **not `Clone`/`Copy`** — a clone is exactly the "retain a clone" the letter forbids;
/// * **not `Default`** — `Default::default()` is a public constructor by another name;
/// * **not `Deserialize`** — serde would mint one from untrusted bytes;
/// * **private, non-`Copy` field** — so a struct literal cannot be written outside this
///   module even though the type is `pub`;
/// * **NOT an empty marker type.** This one is easy to get wrong: the tree already
///   contains `pub trait DeviceExecutionPermit {}` in device-mesh, which anything can
///   implement. An empty `pub struct` is the same mistake — `GrantMutationToken {}` would
///   be constructible by any caller and would satisfy every word of the design while
///   defeating the property it exists for.
///
/// # Proof that the boundary holds
///
/// These are bare `compile_fail` doctests. On stable, rustdoc cannot pin the ERROR CODE
/// (`error_code` on a doctest is nightly-only), so each one proves only "this does not
/// compile" — it does NOT prove it failed for the stated reason. A `compile_fail` block
/// with a typo in it passes just as happily.
///
/// The mitigation is the POSITIVE CONTROL below: it exercises the same imports and the
/// same public surface and MUST compile. If the crate path, the type name or the import
/// were wrong, the control breaks and the whole set stops being evidence.
///
/// Positive control — the public surface compiles:
/// ```
/// use cap_grant::sqlite::{GrantMutationToken, GrantSqliteIndex};
/// fn takes(_t: &GrantMutationToken) {}
/// fn _names_the_types(_i: &GrantSqliteIndex) {}
/// ```
///
/// External construction is impossible — the field is private and non-`Copy`:
/// ```compile_fail
/// use cap_grant::sqlite::GrantMutationToken;
/// let _t = GrantMutationToken { _seal: () };
/// ```
///
/// There is no public constructor:
/// ```compile_fail
/// use cap_grant::sqlite::GrantMutationToken;
/// let _t = GrantMutationToken::new();
/// ```
///
/// It cannot be cloned into an OWNED value — "external callers cannot retain a clone".
///
/// The type annotation is load-bearing and the reason is a genuine Rust trap: `&T` is
/// itself `Copy`, so on a `&GrantMutationToken` the expression `t.clone()` resolves to
/// cloning the REFERENCE and compiles happily, yielding another `&GrantMutationToken`.
/// Written without the annotation this doctest COMPILED, i.e. it silently proved nothing.
/// Demanding an owned `GrantMutationToken` is what actually tests the property — and a
/// borrowed copy is not a bypass anyway, since it cannot outlive the borrow.
/// ```compile_fail
/// fn f(t: &cap_grant::sqlite::GrantMutationToken) {
///     let _c: cap_grant::sqlite::GrantMutationToken = t.clone();
/// }
/// ```
///
/// It has no `Default`:
/// ```compile_fail
/// use cap_grant::sqlite::GrantMutationToken;
/// let _t: GrantMutationToken = Default::default();
/// ```
///
/// It is not an empty marker that could be built with a unit-struct expression:
/// ```compile_fail
/// use cap_grant::sqlite::GrantMutationToken;
/// let _t = GrantMutationToken;
/// ```
///
/// **Claim boundary, stated rather than implied.** The guarantee is CROSS-CRATE. Inside
/// this crate a `#[cfg(test)]` module can mint one, and the coverage test is such a
/// module. This is not unforgeability in the cryptographic sense and is not claimed as
/// such; it is a compile-time ownership boundary.
pub struct GrantMutationToken {
    /// Private and non-`Copy`: blocks external struct-literal construction.
    _seal: PhantomNotCopy,
}

/// A private, non-`Copy` field type. `PhantomData` would be `Copy`, which would let
/// `GrantMutationToken { _seal: PhantomData }` be written wherever the field were visible.
struct PhantomNotCopy;

impl GrantMutationToken {
    /// Crate-private mint. `GrantStore` is the only holder.
    pub(crate) fn new() -> Self {
        Self {
            _seal: PhantomNotCopy,
        }
    }
}

impl std::fmt::Debug for GrantMutationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No state to leak, but an explicit impl keeps a future `#[derive(Debug)]` from
        // quietly printing whatever the seal becomes.
        f.write_str("GrantMutationToken")
    }
}

#[derive(Clone)]
pub struct GrantSqliteIndex {
    handle: Arc<dyn SqliteIndexHandle>,
}

impl GrantSqliteIndex {
    pub fn new(handle: Arc<dyn SqliteIndexHandle>) -> Self {
        Self { handle }
    }

    /// CREATE TABLE IF NOT EXISTS + 3 indexes, atomic under
    /// `BEGIN IMMEDIATE`. Idempotent across concurrent callers
    /// (the IMMEDIATE lock serializes them).
    pub fn ensure_schema(&self) -> Result<()> {
        let mut conn = self.handle.get_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS grant_index (
                id TEXT PRIMARY KEY,
                grantee TEXT NOT NULL,
                capability TEXT NOT NULL,
                params_json TEXT NOT NULL,
                ttl_type TEXT NOT NULL,
                ttl_value TEXT,
                issuer_type TEXT NOT NULL,
                issuer_ref TEXT,
                provenance_type TEXT NOT NULL,
                provenance_ref TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                expires_at TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_grant_grantee_cap
                 ON grant_index(grantee, capability);
             CREATE INDEX IF NOT EXISTS idx_grant_issuer
                 ON grant_index(issuer_type, issuer_ref);
             CREATE INDEX IF NOT EXISTS idx_grant_expires
                 ON grant_index(expires_at) WHERE status = 'active';",
        )?;
        tx.commit()?;
        Ok(())
    }

    /// `INSERT … ON CONFLICT(id) DO UPDATE` — idempotent on `id` collision.
    /// RAW row write — D4 crate-private and token-gated.
    ///
    /// `ensure_schema` deliberately stays `pub` and UNGATED: it has 11 out-of-crate call
    /// sites across 6 crates plus a production in-crate caller, and it is idempotent DDL
    /// that writes no grant row. It is outside the raw-row class; conflating the two
    /// would have broken real consumers for no security gain.
    pub(crate) fn upsert_grant(&self, _t: &GrantMutationToken, g: &Grant) -> Result<()> {
        let conn = self.handle.get_conn()?;
        execute_upsert_grant(&conn, g)
    }

    /// RAW row write — D4 crate-private and token-gated.
    ///
    /// AUDIT-R2-W5: this ESCAPED the token in the first pass. It performs
    /// `UPDATE grant_index SET status` and `execute_upsert_grant`, and it is
    /// production-reachable (`preset.rs` -> `store.rs::apply_preset_atomic_for_grantee`).
    /// So the D4 inventory named two raw writers when there were three, and the preset
    /// revoke+create path mutated grant rows outside the chokepoint. The token itself was
    /// always sound; the census was not.
    pub(crate) fn apply_preset_atomic(
        &self,
        _t: &GrantMutationToken,
        revoked: &[GrantId],
        created: &[Grant],
    ) -> Result<()> {
        let mut conn = self.handle.get_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for id in revoked {
            tx.execute(
                "UPDATE grant_index SET status = ?1 WHERE id = ?2",
                params![GrantStatus::Revoked.as_str(), id.as_str()],
            )?;
        }
        for grant in created {
            execute_upsert_grant(&tx, grant)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// RAW row write — D4 crate-private and token-gated (see [`Self::upsert_grant`]).
    ///
    /// AUDIT-R5 — the row count was DISCARDED. Same defect class as `release_nonce` in
    /// `device-mesh` (AUDIT-R4-W1), found there and not swept here.
    ///
    /// WHAT A ZERO-ROW UPDATE ACTUALLY MEANS, corrected by the merge-gate review because
    /// the first version of this comment got it wrong and stated a harm that cannot occur.
    /// The statement is keyed on `id` alone, and SQLite counts rows MATCHED-and-written,
    /// not value-changed. So `changes() == 0` means exactly one thing: THERE IS NO ROW
    /// WITH THAT ID. It cannot mean "the durable row kept `status='active'`" — those are
    /// mutually exclusive — and `recover_active_grants` therefore has nothing to
    /// resurrect. The resurrection story in the first draft of this comment, and in commit
    /// 09a431d7's body, was unreachable for this SQL. Recorded rather than quietly
    /// rewritten: a lane about deleting unearned claims does not get to make them.
    ///
    /// What the check IS worth: the five production callers in `store.rs` (consume,
    /// expire, and three revoke/cascade paths) each mutate the in-memory index and then
    /// call this. `Ok(())` on zero rows means memory holds a grant the durable index has
    /// never heard of, and the caller reports success anyway. That is a real
    /// memory/durable divergence and the store should refuse rather than paper over it.
    /// It is not reachable today — nothing in this crate DELETEs from `grant_index`
    /// (`grep -n DELETE` returns nothing) and every creation path writes SQLite before
    /// memory — so this is defence in depth on an invariant, not a live bug fix.
    pub(crate) fn update_status(
        &self,
        _t: &GrantMutationToken,
        id: &str,
        status: GrantStatus,
    ) -> Result<()> {
        let conn = self.handle.get_conn()?;
        let updated = conn.execute(
            "UPDATE grant_index SET status = ?1 WHERE id = ?2",
            params![status.as_str(), id],
        )?;
        if updated == 0 {
            return Err(CapGrantError::NotFound(GrantId(id.to_string())));
        }
        Ok(())
    }

    /// `SELECT * FROM grant_index WHERE status = 'active'`. Used by
    /// `register_cap_grant` cold-start recovery.
    pub fn recover_active_grants(&self) -> Result<Vec<Grant>> {
        let conn = self.handle.get_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, grantee, capability, params_json, ttl_type, ttl_value,
                    issuer_type, issuer_ref, provenance_type, provenance_ref,
                    status, created_at, expires_at
             FROM grant_index
             WHERE status = 'active'
             ORDER BY created_at, id",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let grantee: String = row.get(1)?;
            let capability: String = row.get(2)?;
            let params_json: String = row.get(3)?;
            let ttl_type: String = row.get(4)?;
            let ttl_value: Option<String> = row.get(5)?;
            let issuer_type: String = row.get(6)?;
            let issuer_ref: Option<String> = row.get(7)?;
            let provenance_type: String = row.get(8)?;
            let provenance_ref: Option<String> = row.get(9)?;
            let status: String = row.get(10)?;
            let created_at: String = row.get(11)?;
            let expires_at: Option<String> = row.get(12)?;
            Ok((
                id,
                grantee,
                capability,
                params_json,
                ttl_type,
                ttl_value,
                issuer_type,
                issuer_ref,
                provenance_type,
                provenance_ref,
                status,
                created_at,
                expires_at,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                id,
                grantee,
                capability,
                params_json,
                ttl_type,
                ttl_value,
                issuer_type,
                issuer_ref,
                provenance_type,
                provenance_ref,
                status,
                created_at,
                expires_at,
            ) = row?;
            let params: Vec<CapParam> = serde_json::from_str(&params_json).map_err(|e| {
                CapGrantError::InvalidConfig(format!("params decode for grant {id}: {e}"))
            })?;
            let ttl = decode_ttl(&ttl_type, ttl_value.as_deref())?;
            let issuer = decode_issuer(&issuer_type, issuer_ref.as_deref())?;
            let provenance = decode_provenance(&provenance_type, provenance_ref.as_deref())?;
            let status = decode_status(&status)?;
            let created_at = parse_dt(&created_at)?;
            let expires_at = expires_at.as_deref().map(parse_dt).transpose()?;
            out.push(Grant {
                id: GrantId(id),
                grantee,
                capability,
                params,
                ttl,
                issuer,
                provenance,
                status,
                created_at,
                expires_at,
            });
        }
        Ok(out)
    }

    /// Quick row-count helper used by tests.
    #[doc(hidden)]
    pub fn count_rows(&self) -> Result<u64> {
        let conn = self.handle.get_conn()?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM grant_index", [], |r| r.get(0))
            .optional()?
            .unwrap_or(0);
        Ok(n.max(0) as u64)
    }

    /// Quick status lookup helper used by tests.
    #[doc(hidden)]
    pub fn status_of(&self, id: &str) -> Result<Option<String>> {
        let conn = self.handle.get_conn()?;
        let s: Option<String> = conn
            .query_row(
                "SELECT status FROM grant_index WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(s)
    }
}

fn execute_upsert_grant(conn: &rusqlite::Connection, g: &Grant) -> Result<()> {
    let (ttl_type, ttl_value) = encode_ttl(&g.ttl);
    let (issuer_type, issuer_ref) = encode_issuer(&g.issuer);
    let (provenance_type, provenance_ref) = encode_provenance(&g.provenance);
    let params_json = serde_json::to_string(&g.params)
        .map_err(|e| CapGrantError::InvalidConfig(format!("params encode: {e}")))?;
    conn.execute(
        "INSERT INTO grant_index (
            id, grantee, capability, params_json,
            ttl_type, ttl_value,
            issuer_type, issuer_ref,
            provenance_type, provenance_ref,
            status, created_at, expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(id) DO UPDATE SET
            grantee = excluded.grantee,
            capability = excluded.capability,
            params_json = excluded.params_json,
            ttl_type = excluded.ttl_type,
            ttl_value = excluded.ttl_value,
            issuer_type = excluded.issuer_type,
            issuer_ref = excluded.issuer_ref,
            provenance_type = excluded.provenance_type,
            provenance_ref = excluded.provenance_ref,
            status = excluded.status,
            -- created_at is preserved on UPSERT (audit-trail invariant
            -- per PRD §A.18 first-issuance-time semantics): the row's
            -- original creation timestamp survives every YAML
            -- recompile / cold-start replay.
            expires_at = excluded.expires_at",
        params![
            g.id.as_str(),
            g.grantee,
            g.capability,
            params_json,
            ttl_type,
            ttl_value,
            issuer_type,
            issuer_ref,
            provenance_type,
            provenance_ref,
            g.status.as_str(),
            g.created_at.to_rfc3339(),
            g.expires_at.as_ref().map(|t| t.to_rfc3339()),
        ],
    )?;
    Ok(())
}

fn encode_ttl(t: &GrantTtl) -> (String, Option<String>) {
    match t {
        GrantTtl::Once => ("once".to_string(), None),
        GrantTtl::Lifecycle => ("lifecycle".to_string(), None),
        GrantTtl::Persistent => ("persistent".to_string(), None),
        GrantTtl::Duration(ms) => ("duration".to_string(), Some(ms.to_string())),
        GrantTtl::Until(t) => ("until".to_string(), Some(t.to_rfc3339())),
    }
}

fn encode_issuer(i: &GrantIssuer) -> (String, Option<String>) {
    match i {
        GrantIssuer::Config => ("config".to_string(), None),
        GrantIssuer::Parent(id) => ("parent".to_string(), Some(id.clone())),
        GrantIssuer::Resolver(c) => ("resolver".to_string(), Some(c.clone())),
        GrantIssuer::Admin => ("admin".to_string(), None),
    }
}

fn encode_provenance(p: &GrantProvenance) -> (String, Option<String>) {
    match p {
        GrantProvenance::StaticConfig => ("static-config".to_string(), None),
        GrantProvenance::Delegated(id) => ("delegated".to_string(), Some(id.0.clone())),
        GrantProvenance::Requested => ("requested".to_string(), None),
        GrantProvenance::Preset(n) => ("preset".to_string(), Some(n.clone())),
    }
}

fn decode_ttl(t: &str, v: Option<&str>) -> Result<GrantTtl> {
    Ok(match t {
        "once" => GrantTtl::Once,
        "lifecycle" => GrantTtl::Lifecycle,
        "persistent" => GrantTtl::Persistent,
        "duration" => {
            let v =
                v.ok_or_else(|| CapGrantError::InvalidConfig("duration ttl_value missing".into()))?;
            let ms: u64 = v
                .parse()
                .map_err(|e| CapGrantError::InvalidConfig(format!("duration parse: {e}")))?;
            GrantTtl::Duration(ms)
        }
        "until" => {
            let v =
                v.ok_or_else(|| CapGrantError::InvalidConfig("until ttl_value missing".into()))?;
            GrantTtl::Until(parse_dt(v)?)
        }
        other => {
            return Err(CapGrantError::InvalidConfig(format!(
                "unknown ttl_type: {other}"
            )));
        }
    })
}

fn decode_issuer(t: &str, v: Option<&str>) -> Result<GrantIssuer> {
    Ok(match t {
        "config" => GrantIssuer::Config,
        "parent" => {
            let v =
                v.ok_or_else(|| CapGrantError::InvalidConfig("parent issuer_ref missing".into()))?;
            // `ComponentId = String`; storing the raw string preserves the alias.
            GrantIssuer::Parent(v.to_string())
        }
        "resolver" => {
            let v = v.ok_or_else(|| {
                CapGrantError::InvalidConfig("resolver issuer_ref missing".into())
            })?;
            GrantIssuer::Resolver(v.to_string())
        }
        "admin" => GrantIssuer::Admin,
        other => {
            return Err(CapGrantError::InvalidConfig(format!(
                "unknown issuer_type: {other}"
            )));
        }
    })
}

fn decode_provenance(t: &str, v: Option<&str>) -> Result<GrantProvenance> {
    Ok(match t {
        "static-config" => GrantProvenance::StaticConfig,
        "delegated" => {
            let v = v.ok_or_else(|| {
                CapGrantError::InvalidConfig("delegated provenance_ref missing".into())
            })?;
            GrantProvenance::Delegated(GrantId(v.to_string()))
        }
        "requested" => GrantProvenance::Requested,
        "preset" => {
            let v = v.ok_or_else(|| {
                CapGrantError::InvalidConfig("preset provenance_ref missing".into())
            })?;
            GrantProvenance::Preset(v.to_string())
        }
        other => {
            return Err(CapGrantError::InvalidConfig(format!(
                "unknown provenance_type: {other}"
            )));
        }
    })
}

fn decode_status(s: &str) -> Result<GrantStatus> {
    Ok(match s {
        "active" => GrantStatus::Active,
        "consumed" => GrantStatus::Consumed,
        "expired" => GrantStatus::Expired,
        "revoked" => GrantStatus::Revoked,
        other => {
            return Err(CapGrantError::InvalidConfig(format!(
                "unknown status: {other}"
            )));
        }
    })
}

fn parse_dt(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| CapGrantError::InvalidConfig(format!("rfc3339 parse: {e}")))
}
