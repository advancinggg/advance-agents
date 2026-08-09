//! In-memory `GrantStore` (MODULE-013 §2.5).
//!
//! Per-index `RwLock<HashMap>` matching the spec verbatim.
//! Read paths take read locks; write paths take brief write locks.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use uuid::Uuid;

use crate::cascade::{walk_descendants, CascadeResult};
use crate::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use crate::error::{CapGrantError, Result};
use crate::events::{
    grant_consumed_event, grant_delegated_event, grant_expired_event, grant_issued_event,
    grant_narrowed_event, grant_revoked_event,
};
use crate::sqlite::GrantSqliteIndex;
use crate::subset::SubsetValidator;

/// Identifier acceptance gate for the dynamic mutation paths (`delegate_grant` /
/// `narrow` / `apply_preset` — agent-id arguments `caller_id` / `child_agent` /
/// `target_grantee`).
///
/// Reconciles the "two-ID-conventions" gap (2026-06-06): a real guest turn presents the
/// runtime's host-authoritative **canonical** identity `agent:<slug>`, while legacy/internal
/// callers and the static-config path use **bare** ids. Both must be accepted because dynamic
/// grants are stored with `grantee = "agent:<slug>"` (via the colon-tolerant `insert_dynamic`),
/// so `list_by_grantee` and the authz check `grant.grantee == caller_id` already operate on the
/// prefixed id.
///
/// Accept iff:
/// - `s` contains no `:` (the pre-existing bare convention — e.g. `"alice"`), OR
/// - `s` is exactly one `agent:` prefix followed by a non-empty `[A-Za-z0-9_-]` body
///   (mirrors `messaging::is_safe_id`'s body rule for the `agent:` case).
///
/// Rejects (so the R13 / log-splice hardening is preserved): `user:`-prefixed ids (a grantee
/// is always an agent), multi-colon / malformed-prefix ids (`user:agent:x`, `a:b`, `:x`, `x:`),
/// and any body byte outside `[A-Za-z0-9_-]` (which also excludes control bytes / whitespace).
/// Callers still apply their own empty / length / control-byte gates around this check.
///
/// NOT used by the static-config `insert` path: `Grant.id = "static:{grantee}:{capability}"`
/// uses `:` as the deterministic-id separator, so that path keeps its stricter no-`:` grantee
/// gate (a colon there would collide / split the id).
pub(crate) fn is_agent_or_bare_id(s: &str) -> bool {
    match s.strip_prefix("agent:") {
        Some(body) => {
            !body.is_empty()
                && body
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        }
        None => !s.contains(':'),
    }
}

pub struct GrantStore {
    grants: RwLock<HashMap<GrantId, Grant>>,
    by_grantee: RwLock<HashMap<String, HashSet<GrantId>>>,
    by_issuer: RwLock<HashMap<String, HashSet<GrantId>>>,
    /// Parent grant id → child grant id set (matches spec field name).
    provenance: RwLock<HashMap<GrantId, HashSet<GrantId>>>,
    /// Audit-fix R6 (Adversarial R3 Warning 2): set of grant ids whose
    /// `narrow` (or `revoke_dynamic_for_grantee` cascade) is currently
    /// between Phase 1 (collect descendants) and Phase 2 (flip status).
    /// `insert_dynamic` rejects any new grant whose
    /// `provenance: Delegated(parent_id)` references an id in this set —
    /// closes the Phase-1-vs-Phase-2 race where a concurrent
    /// `delegate-grant` could create a descendant that survives a narrow.
    narrow_in_progress: RwLock<HashSet<GrantId>>,
    sqlite: GrantSqliteIndex,
    event_bus: Arc<dyn EventBusEmit>,
    /// D4: the sole `GrantMutationToken` in the process. Never handed out — the raw index
    /// writers take it by reference, so no caller can retain one.
    mutation_token: crate::sqlite::GrantMutationToken,
}

impl GrantStore {
    /// `GrantStore` is the SOLE holder of the D4 mutation token. It is minted here and
    /// never handed out; the raw index writers take it by reference only.
    pub fn new(sqlite: GrantSqliteIndex, event_bus: Arc<dyn EventBusEmit>) -> Self {
        Self {
            grants: RwLock::new(HashMap::new()),
            by_grantee: RwLock::new(HashMap::new()),
            by_issuer: RwLock::new(HashMap::new()),
            provenance: RwLock::new(HashMap::new()),
            narrow_in_progress: RwLock::new(HashSet::new()),
            sqlite,
            event_bus,
            mutation_token: crate::sqlite::GrantMutationToken::new(),
        }
    }

    /// `pub(crate)` accessor used by `preset.rs::PresetRegistry::apply_preset`
    /// to emit `preset.applied` events on the same bus the store uses for
    /// `grant.issued` / `grant.revoked`. Not part of the public ABI surface.
    pub(crate) fn event_bus(&self) -> &Arc<dyn EventBusEmit> {
        &self.event_bus
    }

    /// SQLite UPSERT first; on success, in-memory write keyed on `grant.id`.
    /// On failure, no in-memory state change. Emits `grant.issued` AFTER
    /// the in-memory writes commit so subscribers always observe the
    /// fully-installed grant.
    ///
    /// Write ordering (load-bearing for concurrent-reader correctness):
    /// 1. SQLite UPSERT (source of truth + rollback boundary).
    /// 2. Primary `grants` map insert (so any subsequent
    ///    `list_by_grantee` finds the grant when it sees the id in
    ///    `by_grantee`).
    /// 3. Secondary index inserts (`by_grantee` / `by_issuer` /
    ///    `provenance`).
    /// 4. Event emit (subscribers calling `GrantCheck::check` from a
    ///    synchronous handler always see the grant in the primary map).
    ///
    /// Bilateral charset gate (defense-in-depth — also enforced at compile site):
    /// rejects `grantee` or `capability` containing `:` (deterministic-id separator).
    pub fn insert(&self, grant: Grant) -> Result<GrantId> {
        if grant.grantee.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "grantee must not be empty (would collide with other empty-grantee grants on the deterministic id)"
                    .to_string(),
            ));
        }
        if grant.capability.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "capability must not be empty (would collide with other empty-capability grants on the deterministic id)"
                    .to_string(),
            ));
        }
        if grant.grantee.contains(':') {
            return Err(CapGrantError::InvalidConfig(format!(
                "grantee contains forbidden character ':' — used as deterministic-id separator (got: {:?})",
                grant.grantee
            )));
        }
        if grant.capability.contains(':') {
            return Err(CapGrantError::InvalidConfig(format!(
                "capability contains forbidden character ':' — used as deterministic-id separator (got: {:?})",
                grant.capability
            )));
        }

        // Preserve the audit-trail invariant (PRD §A.18 first-issuance-time):
        // if a grant with this id already exists in-memory, carry its
        // `created_at` into the incoming grant so the in-memory copy
        // matches the SQLite UPSERT semantics (which preserve `created_at`
        // on conflict — see sqlite.rs::upsert_grant). Otherwise the
        // incoming grant's `created_at` (typically Utc::now() from
        // `compile_from_path`) becomes the new authoritative value.
        let mut grant = grant;
        {
            let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = g.get(&grant.id) {
                grant.created_at = existing.created_at;
            }
        }

        // 1. SQLite first.
        self.sqlite.upsert_grant(&self.mutation_token, &grant)?;

        // 2. Primary `grants` map insert (clone so we can still emit + index).
        let id = grant.id.clone();
        {
            let mut g = self.grants.write().unwrap_or_else(|e| e.into_inner());
            g.insert(id.clone(), grant.clone());
        }

        // 3. Secondary indexes — after primary so a concurrent reader who
        //    sees the id in `by_grantee` always finds the grant in `grants`.
        self.write_in_memory(&grant);

        // 4. Event emit — fully-installed state visible to all subscribers.
        self.event_bus.emit(grant_issued_event(&grant));
        Ok(id)
    }

    /// Used by `register_cap_grant` cold-start recovery. Populates
    /// in-memory indexes from grants already present in `grant_index`.
    /// Does NOT write to SQLite or emit events.
    pub(crate) fn insert_no_dual_write(&self, grant: Grant) {
        self.write_in_memory(&grant);
        let mut g = self.grants.write().unwrap_or_else(|e| e.into_inner());
        g.insert(grant.id.clone(), grant);
    }

    fn write_in_memory(&self, grant: &Grant) {
        // by_grantee
        {
            let mut idx = self.by_grantee.write().unwrap_or_else(|e| e.into_inner());
            idx.entry(grant.grantee.clone())
                .or_default()
                .insert(grant.id.clone());
        }
        // by_issuer (only Parent issuers are queryable via this index — they
        // carry an agent-id key; Config/Resolver/Admin have no ComponentId).
        if let GrantIssuer::Parent(parent_id) = &grant.issuer {
            let mut idx = self.by_issuer.write().unwrap_or_else(|e| e.into_inner());
            idx.entry(parent_id.clone())
                .or_default()
                .insert(grant.id.clone());
        }
        // provenance (parent → child link)
        if let GrantProvenance::Delegated(parent_grant_id) = &grant.provenance {
            let mut prov = self.provenance.write().unwrap_or_else(|e| e.into_inner());
            prov.entry(parent_grant_id.clone())
                .or_default()
                .insert(grant.id.clone());
        }
    }

    pub fn get(&self, id: &str) -> Option<Grant> {
        let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
        g.get(id).cloned()
    }

    /// Returns all grants for the given grantee. Filtering by status is
    /// the caller's responsibility (`GrantCheckImpl::check` filters to
    /// `Active` only).
    pub fn list_by_grantee(&self, grantee: &str) -> Vec<Grant> {
        let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
        let by = self.by_grantee.read().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<GrantId> = match by.get(grantee) {
            Some(set) => set.iter().cloned().collect(),
            None => return Vec::new(),
        };
        ids.iter().filter_map(|id| g.get(id).cloned()).collect()
    }

    pub fn list_by_issuer_parent(&self, parent_id: &str) -> Vec<Grant> {
        let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
        let by = self.by_issuer.read().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<GrantId> = match by.get(parent_id) {
            Some(set) => set.iter().cloned().collect(),
            None => return Vec::new(),
        };
        ids.iter().filter_map(|id| g.get(id).cloned()).collect()
    }

    fn validate_dynamic_grant_shape(grant: &Grant) -> Result<()> {
        if grant.grantee.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "grantee must not be empty".to_string(),
            ));
        }
        if grant.capability.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "capability must not be empty".to_string(),
            ));
        }
        if grant.id.as_str().is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "grant id must not be empty".to_string(),
            ));
        }
        if matches!(grant.provenance, GrantProvenance::StaticConfig) {
            return Err(CapGrantError::InvalidConfig(
                "dynamic grant insert rejects provenance=StaticConfig — only \
                 compile_from_path may produce static-config grants"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn apply_preset_atomic_for_grantee(
        &self,
        grantee: &str,
        created_grants: Vec<Grant>,
    ) -> Result<(Vec<GrantId>, Vec<GrantId>)> {
        for grant in &created_grants {
            Self::validate_dynamic_grant_shape(grant)?;
        }

        let revoked_by = format!("preset-apply:{grantee}");
        let mut revoked_events: Vec<(GrantId, String, String, usize)> = Vec::new();
        let mut revoked_ids: Vec<GrantId> = Vec::new();

        // Serialize against every dynamic insert path. `delegate_grant`
        // and `insert_dynamic` hold the read side from before their SQLite
        // write until after their in-memory grant/provenance indexes commit,
        // so this write guard guarantees the preset snapshot cannot miss an
        // in-flight grant that will become visible after the preset apply.
        let _dynamic_insert_barrier = self
            .narrow_in_progress
            .write()
            .unwrap_or_else(|e| e.into_inner());

        {
            // This write lock is intentionally held through the SQLite transaction
            // and the in-memory batch update. Readers either see the pre-apply
            // snapshot or the post-apply snapshot, never the revoke-before-create
            // gap that a per-grant implementation exposed.
            let mut grants = self.grants.write().unwrap_or_else(|e| e.into_inner());
            let mut active_ids: HashSet<GrantId> = grants
                .iter()
                .filter_map(|(id, grant)| {
                    if grant.status == GrantStatus::Active {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect();

            let mut roots: Vec<GrantId> = {
                let by = self.by_grantee.read().unwrap_or_else(|e| e.into_inner());
                match by.get(grantee) {
                    Some(set) => set
                        .iter()
                        .filter_map(|id| {
                            grants.get(id).and_then(|grant| {
                                if grant.status == GrantStatus::Active
                                    && !matches!(grant.provenance, GrantProvenance::StaticConfig)
                                {
                                    Some(id.clone())
                                } else {
                                    None
                                }
                            })
                        })
                        .collect(),
                    None => Vec::new(),
                }
            };
            roots.sort();

            {
                let prov = self.provenance.read().unwrap_or_else(|e| e.into_inner());
                for root in roots {
                    if !active_ids.contains(&root) {
                        continue;
                    }
                    let mut ids = vec![root.clone()];
                    ids.extend(walk_descendants(&prov, &root));
                    let mut local: Vec<(GrantId, String, String, bool)> =
                        Vec::with_capacity(ids.len());
                    for (i, id) in ids.iter().enumerate() {
                        if !active_ids.remove(id) {
                            continue;
                        }
                        if let Some(grant) = grants.get(id) {
                            if grant.status == GrantStatus::Active {
                                local.push((
                                    grant.id.clone(),
                                    grant.grantee.clone(),
                                    grant.capability.clone(),
                                    i == 0,
                                ));
                            }
                        }
                    }
                    let descendants = local.iter().filter(|(_, _, _, is_root)| !*is_root).count();
                    for (id, grantee, capability, is_root) in local {
                        let cascade_count = if is_root { descendants } else { 0 };
                        revoked_ids.push(id.clone());
                        revoked_events.push((id, grantee, capability, cascade_count));
                    }
                }
            }

            self.sqlite
                .apply_preset_atomic(&self.mutation_token, &revoked_ids, &created_grants)?;

            for id in &revoked_ids {
                if let Some(grant) = grants.get_mut(id) {
                    if grant.status == GrantStatus::Active {
                        grant.status = GrantStatus::Revoked;
                    }
                }
            }

            let mut by_grantee = self.by_grantee.write().unwrap_or_else(|e| e.into_inner());
            let mut by_issuer = self.by_issuer.write().unwrap_or_else(|e| e.into_inner());
            let mut provenance = self.provenance.write().unwrap_or_else(|e| e.into_inner());
            for grant in &created_grants {
                grants.insert(grant.id.clone(), grant.clone());
                by_grantee
                    .entry(grant.grantee.clone())
                    .or_default()
                    .insert(grant.id.clone());
                if let GrantIssuer::Parent(parent_id) = &grant.issuer {
                    by_issuer
                        .entry(parent_id.clone())
                        .or_default()
                        .insert(grant.id.clone());
                }
                if let GrantProvenance::Delegated(parent_grant_id) = &grant.provenance {
                    provenance
                        .entry(parent_grant_id.clone())
                        .or_default()
                        .insert(grant.id.clone());
                }
            }
        }

        for (id, grantee, capability, cascade_count) in &revoked_events {
            self.event_bus.emit(grant_revoked_event(
                id,
                grantee,
                capability,
                &revoked_by,
                *cascade_count,
            ));
        }
        for grant in &created_grants {
            self.event_bus.emit(grant_issued_event(grant));
        }
        let created_ids = created_grants
            .into_iter()
            .map(|grant| grant.id)
            .collect::<Vec<_>>();
        Ok((revoked_ids, created_ids))
    }

    /// `Once`-only consume. Slice C widened to take `consumed_by_function`
    /// so the emitted `grant.consumed` event carries the 4th PRD §15.3.18
    /// payload field. Validation: `consumed_by_function` must be non-empty
    /// AND ≤ 256 chars (defensive bound against log-amplification / event-bus
    /// DoS via attacker-controlled host-fn names — closes Audit-fix R1
    /// Diff-eval Warning 1). The `:` ban does NOT apply because legitimate
    /// host-fn names contain `::` (e.g. `ns-fs::scan`).
    pub fn consume(&self, id: &str, consumed_by_function: &str) -> Result<()> {
        if consumed_by_function.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "consume: consumed_by_function must not be empty".to_string(),
            ));
        }
        if consumed_by_function.len() > 256 {
            return Err(CapGrantError::InvalidConfig(format!(
                "consume: consumed_by_function exceeds 256-byte cap (got {} bytes)",
                consumed_by_function.len()
            )));
        }
        // Adversarial-fix R6 W2: reject ASCII control bytes (NUL, newline,
        // CR, ESC, etc.). consumed_by_function flows raw into the
        // grant.consumed JSON payload; control bytes could forge log lines
        // for downstream JSON-to-line consumers. Symmetric guard with
        // delegate_grant's caller_id / child_agent control-byte rejection.
        if consumed_by_function.chars().any(|c| c.is_control()) {
            return Err(CapGrantError::InvalidConfig(
                "consume: consumed_by_function contains ASCII control bytes — \
                 forbidden for event payload identifiers"
                    .to_string(),
            ));
        }
        let mut g = self.grants.write().unwrap_or_else(|e| e.into_inner());
        let grant = g
            .get_mut(id)
            .ok_or_else(|| CapGrantError::NotFound(GrantId::new(id)))?;
        if grant.status != GrantStatus::Active {
            return Err(CapGrantError::NotFound(GrantId::new(id)));
        }
        if !matches!(grant.ttl, crate::data::GrantTtl::Once) {
            return Err(CapGrantError::InvalidConfig(format!(
                "consume() called on non-Once grant {id} (ttl={:?})",
                grant.ttl
            )));
        }
        grant.status = GrantStatus::Consumed;
        let evt = grant_consumed_event(
            &grant.id,
            &grant.grantee,
            &grant.capability,
            consumed_by_function,
        );
        let snapshot_id = grant.id.clone();
        drop(g);
        self.sqlite
            .update_status(&self.mutation_token, &snapshot_id.0, GrantStatus::Consumed)?;
        self.event_bus.emit(evt);
        Ok(())
    }

    /// Bulk flip Active → Expired. Emits `grant.expired` per id.
    pub fn expire_ids(&self, ids: &[GrantId]) -> Result<usize> {
        let mut count = 0usize;
        let mut events = Vec::with_capacity(ids.len());
        {
            let mut g = self.grants.write().unwrap_or_else(|e| e.into_inner());
            for id in ids {
                if let Some(grant) = g.get_mut(id) {
                    if grant.status == GrantStatus::Active {
                        grant.status = GrantStatus::Expired;
                        count += 1;
                        events.push((
                            grant.id.clone(),
                            grant.grantee.clone(),
                            grant.capability.clone(),
                            grant.ttl.clone(),
                        ));
                    }
                }
            }
        }
        for (id, _, _, _) in &events {
            self.sqlite
                .update_status(&self.mutation_token, &id.0, GrantStatus::Expired)?;
        }
        for (id, grantee, capability, ttl) in events {
            self.event_bus
                .emit(grant_expired_event(&id, &grantee, &capability, &ttl));
        }
        Ok(count)
    }

    /// Flat (non-cascade) sweep: revoke every active grant whose
    /// `grantee == grantee_id`. Used by `Lifecycle` TTL semantic when
    /// an agent terminates.
    pub fn revoke_by_grantee(&self, grantee_id: &str) -> Result<Vec<GrantId>> {
        // Phase 1: collect ids under read lock.
        let ids: Vec<GrantId> = {
            let by = self.by_grantee.read().unwrap_or_else(|e| e.into_inner());
            match by.get(grantee_id) {
                Some(set) => set.iter().cloned().collect(),
                None => Vec::new(),
            }
        };

        // Phase 2: per-id flip + SQLite + emit.
        let mut revoked = Vec::with_capacity(ids.len());
        let revoked_by = format!("grantee-terminate:{grantee_id}");
        for id in ids {
            let event_data: Option<(GrantId, String, String)> = {
                let mut g = self.grants.write().unwrap_or_else(|e| e.into_inner());
                if let Some(grant) = g.get_mut(&id) {
                    if grant.status == GrantStatus::Active {
                        grant.status = GrantStatus::Revoked;
                        Some((
                            grant.id.clone(),
                            grant.grantee.clone(),
                            grant.capability.clone(),
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some((id, grantee, capability)) = event_data {
                self.sqlite
                    .update_status(&self.mutation_token, &id.0, GrantStatus::Revoked)?;
                self.event_bus.emit(grant_revoked_event(
                    &id,
                    &grantee,
                    &capability,
                    &revoked_by,
                    0,
                ));
                revoked.push(id);
            }
        }
        Ok(revoked)
    }

    /// Two-phase provenance-cascade revoke. Root carries
    /// `cascade_count = descendants.len()`; descendants carry 0.
    ///
    /// Race window: a concurrent `insert` of a new descendant between
    /// Phase 1 (collect) and Phase 2 (apply) will not be revoked by THIS
    /// cascade. Slice B inherits this race for the new `narrow` and
    /// `apply_preset` paths; documented in their respective rustdocs.
    /// Slice C/D follow-up will close the race via a per-grant
    /// `narrow-in-progress` lock or a generation counter.
    ///
    /// Slice B refactor — Round 4 Warning 1 fix: the existing public
    /// signature `cascade_revoke(&self, root_id: &str) -> Result<CascadeResult>`
    /// is preserved verbatim. Body forwards to
    /// [`Self::cascade_revoke_with_reason`] with `revoked_by="cascade-revoke"`,
    /// keeping Slice A's audit-trail wire string unchanged.
    pub fn cascade_revoke(&self, root_id: &str) -> Result<CascadeResult> {
        self.cascade_revoke_with_reason(root_id, "cascade-revoke")
    }

    /// Slice-B helper used by [`Self::narrow`]. `pub(crate)` — not part of
    /// the public ABI surface (Round 5 Warning 4 fix). External Slice-A
    /// consumers continue to use [`Self::cascade_revoke`] which forwards
    /// here with the canonical `cascade-revoke` reason.
    pub(crate) fn cascade_revoke_with_reason(
        &self,
        root_id: &str,
        revoked_by: &str,
    ) -> Result<CascadeResult> {
        let root_gid = GrantId::new(root_id);

        // Audit-fix R6 (Adversarial R3 Warning 2): hold `narrow_in_progress`
        // membership across Phase 1 + Phase 2 so concurrent
        // `insert_dynamic(Delegated(root_id))` is rejected during the
        // window. The set is a guard, not a mutex: multiple cascades on
        // DIFFERENT roots are still concurrent. If `root_id` is already
        // in the set, a previous cascade is in progress for the same
        // root — return NotFound so the caller can retry once the
        // earlier cascade finishes.
        {
            let mut nip = self
                .narrow_in_progress
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if !nip.insert(root_gid.clone()) {
                return Err(CapGrantError::NotFound(root_gid));
            }
        }
        // Drop guard scope: ensure narrow_in_progress is cleared even on
        // error paths.
        let _guard = NarrowInProgressGuard {
            store: self,
            id: root_gid.clone(),
        };

        let descendants: Vec<GrantId> = {
            let prov = self.provenance.read().unwrap_or_else(|e| e.into_inner());
            walk_descendants(&prov, &root_gid)
        };

        {
            let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
            match g.get(&root_gid) {
                Some(grant) if grant.status == GrantStatus::Active => {}
                Some(_) | None => return Err(CapGrantError::NotFound(root_gid)),
            }
        }

        let mut all = vec![root_gid.clone()];
        all.extend(descendants);

        let mut applied: Vec<(GrantId, String, String, bool /* is_root */)> =
            Vec::with_capacity(all.len());
        for (i, id) in all.iter().enumerate() {
            let event_data: Option<(GrantId, String, String)> = {
                let mut g = self.grants.write().unwrap_or_else(|e| e.into_inner());
                if let Some(grant) = g.get_mut(id) {
                    if grant.status == GrantStatus::Active {
                        grant.status = GrantStatus::Revoked;
                        Some((
                            grant.id.clone(),
                            grant.grantee.clone(),
                            grant.capability.clone(),
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some((id, grantee, capability)) = event_data {
                self.sqlite
                    .update_status(&self.mutation_token, &id.0, GrantStatus::Revoked)?;
                applied.push((id, grantee, capability, i == 0));
            }
        }

        let actual_descendants = applied.iter().filter(|(_, _, _, is_root)| !is_root).count();
        let mut revoked = Vec::with_capacity(applied.len());
        for (id, grantee, capability, is_root) in applied {
            let count_for_event = if is_root { actual_descendants } else { 0 };
            self.event_bus.emit(grant_revoked_event(
                &id,
                &grantee,
                &capability,
                revoked_by,
                count_for_event,
            ));
            revoked.push(id);
        }

        Ok(CascadeResult {
            root_id: root_gid,
            revoked,
            cascade_count: actual_descendants,
        })
    }

    /// Two-phase parent-terminate cascade. Selects every grant whose
    /// `issuer == Parent(parent_id)` as a root, then walks descendants
    /// from each. Emits with `revoked_by: "parent-terminate:{parent_id}"`.
    pub fn cascade_by_issuer(&self, parent_id: &str) -> Result<CascadeResult> {
        // Phase 1: find all roots issued by this parent.
        let root_ids: Vec<GrantId> = {
            let by = self.by_issuer.read().unwrap_or_else(|e| e.into_inner());
            match by.get(parent_id) {
                Some(set) => {
                    let mut v: Vec<GrantId> = set.iter().cloned().collect();
                    v.sort();
                    v
                }
                None => Vec::new(),
            }
        };

        // Walk descendants from each root, deduped.
        let mut visited: HashSet<GrantId> = HashSet::new();
        let mut all: Vec<GrantId> = Vec::new();
        for root in &root_ids {
            if visited.insert(root.clone()) {
                all.push(root.clone());
            }
            let prov = self.provenance.read().unwrap_or_else(|e| e.into_inner());
            for d in walk_descendants(&prov, root) {
                if visited.insert(d.clone()) {
                    all.push(d);
                }
            }
        }

        let revoked_by = format!("parent-terminate:{parent_id}");

        // For parent-terminate every per-event `cascade_count` is 0
        // (multi-root sweep — there's no single "the root" to attribute
        // the count to). The aggregate count appears only on the
        // returned `CascadeResult.cascade_count`, and that count
        // reflects the ACTUAL number of descendants flipped this round
        // (not the pre-collected count) — same TOCTOU-tightening
        // semantic as `cascade_revoke`. Roots themselves are not
        // counted as descendants in the aggregate.
        let root_set: std::collections::HashSet<&GrantId> = root_ids.iter().collect();
        let mut applied_descendants: usize = 0;
        let mut revoked = Vec::with_capacity(all.len());
        for id in &all {
            let event_data: Option<(GrantId, String, String)> = {
                let mut g = self.grants.write().unwrap_or_else(|e| e.into_inner());
                if let Some(grant) = g.get_mut(id) {
                    if grant.status == GrantStatus::Active {
                        grant.status = GrantStatus::Revoked;
                        Some((
                            grant.id.clone(),
                            grant.grantee.clone(),
                            grant.capability.clone(),
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some((id, grantee, capability)) = event_data {
                self.sqlite
                    .update_status(&self.mutation_token, &id.0, GrantStatus::Revoked)?;
                self.event_bus.emit(grant_revoked_event(
                    &id,
                    &grantee,
                    &capability,
                    &revoked_by,
                    0,
                ));
                if !root_set.contains(&id) {
                    applied_descendants += 1;
                }
                revoked.push(id);
            }
        }

        Ok(CascadeResult {
            // No single root in a multi-root sweep — first root in
            // sorted order serves as a stable identifier; aggregate
            // count is in `cascade_count`. Empty case: empty GrantId.
            root_id: root_ids
                .first()
                .cloned()
                .unwrap_or_else(|| GrantId::new("")),
            revoked,
            cascade_count: applied_descendants,
        })
    }

    /// Snapshot all grants whose `expires_at <= now` and `status == Active`.
    /// Used by `TtlSweeper::tick`.
    pub fn collect_expired_ids(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<GrantId> {
        let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
        g.values()
            .filter(|gr| {
                gr.status == GrantStatus::Active && gr.expires_at.is_some_and(|t| t <= now)
            })
            .map(|gr| gr.id.clone())
            .collect()
    }

    // ========================================================================
    // Slice B additions (MODULE-013 §1.4.2 / §1.4.4 / narrow op)
    // ========================================================================

    /// Insert a dynamic grant with a UUID id (Slice B). Distinct from
    /// [`Self::insert`] in that the deterministic-id bilateral charset gate
    /// (forbidding `:` in `grantee` / `capability`) is BYPASSED — UUID v4
    /// ids never contain `:`, so the gate's purpose (deterministic-id
    /// collision protection) does not apply. The empty-string defenses
    /// remain in place.
    ///
    /// Same SQLite-first ordering as [`Self::insert`]: SQLite UPSERT →
    /// primary `grants` insert → secondary indexes → emit `grant.issued`.
    /// Holds the `narrow_in_progress` read side for the whole insert so
    /// preset batch-apply can acquire the write side and see an all-old or
    /// all-new dynamic-grant snapshot.
    pub fn insert_dynamic(&self, grant: Grant) -> Result<GrantId> {
        // Slice C refactor: insert_dynamic now wraps insert_dynamic_inner
        // with the narrow_in_progress.read() guard + R7 parent-checks for
        // Delegated provenance. The bare-bones validation + SQLite + memory
        // write path lives in insert_dynamic_inner, which delegate_grant
        // calls directly while holding its OWN outer narrow_in_progress
        // read guard (avoiding `std::sync::RwLock` recursive-read UB).
        //
        // Audit-fix R7 (Adversarial R4 Warning 1) preserved: hold the
        // `narrow_in_progress` read lock through the ENTIRE insert
        // (parent existence check + SQLite UPSERT + `write_in_memory`
        // provenance edge write). cascade_revoke_with_reason acquires
        // narrow_in_progress.write() to insert the root id; read/write
        // pair naturally serializes the two operations.
        let nip_read_guard = self
            .narrow_in_progress
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let GrantProvenance::Delegated(ref parent_id) = grant.provenance {
            if nip_read_guard.contains(parent_id) {
                return Err(CapGrantError::InvalidConfig(format!(
                    "insert_dynamic rejects provenance=Delegated({}) — \
                     a narrow / cascade-revoke is in progress against the \
                     parent; retry after the cascade completes",
                    parent_id
                )));
            }
            // Parent existence check ALSO under the held lock.
            let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
            if !g.contains_key(parent_id) {
                drop(g);
                return Err(CapGrantError::InvalidConfig(format!(
                    "insert_dynamic rejects provenance=Delegated({}) — \
                     referenced parent grant does not exist in store",
                    parent_id
                )));
            }
            drop(g);
        }

        let id = self.insert_dynamic_inner(grant)?;
        // Drop the narrow_in_progress read guard AFTER inner has committed
        // the provenance edge — guarantees that any cascade starting now
        // will see the new descendant in `walk_descendants`.
        drop(nip_read_guard);
        Ok(id)
    }

    /// Hold the dynamic-insert read barrier while a caller snapshots grants
    /// and, if approved, inserts through [`Self::insert_dynamic_inner`].
    ///
    /// This is intentionally `pub(crate)`: it supports the production
    /// request-capability WIT handler's "snapshot → resolver decision →
    /// requested grant insert" critical section. Preset apply takes the write
    /// side, so it cannot commit between the snapshot that approved a request
    /// and the insert produced by that approval.
    pub(crate) fn with_dynamic_insert_read_barrier<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self
            .narrow_in_progress
            .read()
            .unwrap_or_else(|e| e.into_inner());
        f()
    }

    /// Lock-free helper extracted from `insert_dynamic` for Slice C
    /// `delegate_grant` and the request-capability resolver barrier path
    /// (closes Codex round-11 W1 RwLock recursive-read UB).
    /// Performs validation + SQLite upsert + in-memory writes + event emit.
    ///
    /// **Caller invariants** (load-bearing for `pub(crate)` safety —
    /// closes Audit-fix R2 Diff Warning 2):
    /// - For `Delegated(parent_id)` provenance: the caller MUST hold a
    ///   `narrow_in_progress.read()` guard for the duration AND have
    ///   already verified the parent grant exists (via own check). This
    ///   helper PRESERVES the StaticConfig rejection gate but skips the
    ///   parent-existence + narrow_in_progress.contains() checks that
    ///   `insert_dynamic` performs. `delegate_grant` is the only delegated
    ///   caller that bypasses `insert_dynamic`'s wrapper; future delegated
    ///   callers must follow the same discipline OR call `insert_dynamic`.
    /// - For `Requested` provenance inserted by resolver approval, the caller
    ///   MUST hold [`Self::with_dynamic_insert_read_barrier`] from before the
    ///   parent-grant snapshot through this helper.
    ///
    /// Distinct from [`Self::insert_dynamic`]:
    /// - insert_dynamic: acquires narrow_in_progress.read() + does R7 +
    ///   parent-existence check, then calls this helper.
    /// - insert_dynamic_inner: bare-bones inner work; caller holds the
    ///   outer guard + verifies parent existence if needed.
    ///
    /// Audit-fix R4 (Slice B Adversarial Warning 5) preserved: reject
    /// `provenance: StaticConfig` for dynamic inserts. Only
    /// `compile_from_path` (Slice A's static-config compiler) may produce
    /// StaticConfig provenance.
    ///
    /// Audit-fix R2 Diff Warning 2 (Slice C round 2): `Delegated(parent_id)`
    /// inserts now also verify parent existence INSIDE this helper as a
    /// defense-in-depth backstop. Even if a future caller forgets the
    /// outer narrow_in_progress check, the parent-existence gate prevents
    /// audit-graph corruption from forged `Delegated(arbitrary)` provenance.
    pub(crate) fn insert_dynamic_inner(&self, grant: Grant) -> Result<GrantId> {
        if grant.grantee.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "grantee must not be empty".to_string(),
            ));
        }
        if grant.capability.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "capability must not be empty".to_string(),
            ));
        }
        if grant.id.as_str().is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "grant id must not be empty".to_string(),
            ));
        }
        if matches!(grant.provenance, GrantProvenance::StaticConfig) {
            return Err(CapGrantError::InvalidConfig(
                "insert_dynamic_inner rejects provenance=StaticConfig — only \
                 compile_from_path may produce static-config grants"
                    .to_string(),
            ));
        }
        // Defense-in-depth: even though delegate_grant verified parent
        // existence in step 4 + insert_dynamic verifies in its R7 path,
        // re-verify EXISTENCE here so any future caller is safely-bounded
        // against forged `Delegated(arbitrary_id)` provenance pointing at
        // a non-existent parent. **This is an EXISTENCE-ONLY backstop**:
        // it does NOT verify `parent.status == Active`. Status-race windows
        // (sweeper / revoke_by_grantee / apply_preset / consume / ancestor-
        // cascade flipping parent.status between caller's check and this
        // re-check) are documented as accepted in `delegate_grant`'s
        // rustdoc — the orphan-child outcome is reaped by sweeper / next
        // cascade. Closes audit-fix R6 Diff W1 framing concern.
        if let GrantProvenance::Delegated(ref parent_id) = grant.provenance {
            let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
            if !g.contains_key(parent_id) {
                return Err(CapGrantError::InvalidConfig(format!(
                    "insert_dynamic_inner rejects provenance=Delegated({}) — \
                     referenced parent grant does not exist in store",
                    parent_id
                )));
            }
        }

        self.sqlite.upsert_grant(&self.mutation_token, &grant)?;
        let id = grant.id.clone();
        {
            let mut g = self.grants.write().unwrap_or_else(|e| e.into_inner());
            g.insert(id.clone(), grant.clone());
        }
        self.write_in_memory(&grant);
        self.event_bus.emit(grant_issued_event(&grant));
        Ok(id)
    }

    /// Slice-B `narrow` operation (AC-01).
    ///
    /// **Ordering** (Round 1 Critical 1 + Round 2 Warning 7 fix): cascade-
    /// revoke OLD grant + descendants FIRST (with `revoked_by="narrow"` —
    /// no forward reference to the not-yet-inserted new id; preserves audit
    /// trail integrity if step 5 fails); THEN insert the new dynamic grant.
    /// The brief no-grant gap between cascade_revoke commit and insert
    /// commit is fail-closed (reads see no Active grant for `(grantee,
    /// capability)`) — correct security posture per PRD §5.7.4.
    ///
    /// **Race window**: inherits Slice A's `cascade_revoke` Phase 1 vs Phase 2
    /// race (a concurrent `delegate-grant` of `grant_id` between Phase 1
    /// collect and Phase 2 apply can leave a surviving descendant). For
    /// `narrow` this race is more dangerous than for plain `cascade_revoke`
    /// because narrow's intent is to STRENGTHEN security (replace old grant
    /// with stricter params); Slice C/D follow-up MUST close the race via a
    /// per-grant `narrow-in-progress` lock or generation counter.
    ///
    /// Args:
    /// - `grant_id`: the existing Active grant to narrow.
    /// - `new_params`: strictly-narrower params; subset-checked against the
    ///   existing grant's params via `validator`.
    /// - `caller_id`: identity of the caller invoking narrow. The Slice-B
    ///   authorization model is "the grantee may narrow their own grant"
    ///   — `caller_id` MUST equal `existing.grantee` or the call is
    ///   rejected with `CapGrantError::SubsetViolation` (audit-fix R5
    ///   Adversarial Critical 1: previously narrow accepted a free-form
    ///   `narrowed_by` string with no validation, allowing any caller to
    ///   force-narrow any grant). Cross-agent narrowing (e.g., admin or
    ///   issuer narrowing someone else's grant) is Slice D's WIT-layer
    ///   policy concern. The same `caller_id` is also written into the
    ///   emitted `grant.narrowed.narrowed_by` event field.
    /// - `validator`: SubsetValidator impl used in step 3.
    ///
    /// **Audit-fix R1 (Diff Warning 2) — issuer/provenance combination**: the
    /// new narrowed grant inherits `issuer` from the parent (so the original
    /// originator is preserved across narrows — e.g., narrowing a
    /// `Config`-issued static grant produces a new grant whose
    /// `issuer == Config`) and sets `provenance: Delegated(<old grant id>)`
    /// to record the narrow audit chain. The combination
    /// `(issuer: Config, provenance: Delegated(static-id))` is NOT one of the
    /// 4 originally-documented combinations from PRD §5.7.1
    /// (`(Config, StaticConfig)`, `(Parent(_), Delegated(_))`,
    /// `(Resolver(_), Requested)`, `(Resolver(_), Preset(_))`). It is
    /// produced ONLY by narrow operations on static-config grants and is
    /// semantically valid: the originator (Config) is unchanged, the
    /// provenance trace points back to the static grant. Repeated narrows
    /// chain Delegated provenance entries arbitrarily deep; the `provenance`
    /// HashMap retains parent→children entries for revoked-but-still-stored
    /// grants. Slice C/D may introduce a `provenance: Narrowed(GrantId)`
    /// variant to disambiguate this case if the audit trail interpretation
    /// becomes load-bearing for some downstream consumer.
    pub fn narrow(
        &self,
        grant_id: &str,
        new_params: Vec<CapParam>,
        caller_id: &str,
        validator: &dyn SubsetValidator,
    ) -> Result<GrantId> {
        // Adversarial-fix R14 W2: narrow caller_id validation symmetric with
        // delegate_grant. caller_id flows into grant.narrowed.narrowed_by
        // event payload; without these gates a multi-MB / control-byte
        // caller_id could amplify event payload + log-spoof downstream
        // line-rendered consumers.
        if caller_id.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "narrow: caller_id must not be empty".to_string(),
            ));
        }
        if caller_id.len() > 256 {
            return Err(CapGrantError::InvalidConfig(format!(
                "narrow: caller_id exceeds 256-byte cap (got {} bytes)",
                caller_id.len()
            )));
        }
        // Colon-id reconciliation (2026-06-06): accept a bare colon-free id OR the runtime's
        // canonical `agent:<slug>` identity; reject `user:` / multi-colon / malformed-prefix
        // ids. Lets a real guest turn (caller_id = `agent:harness`) narrow its own grant while
        // keeping the R13 multi-colon / log-splice hardening. See `is_agent_or_bare_id`.
        if !is_agent_or_bare_id(caller_id) {
            return Err(CapGrantError::InvalidConfig(format!(
                "narrow: caller_id must be a bare id or a canonical `agent:<body>` id \
                 (got: {caller_id:?})"
            )));
        }
        if caller_id.chars().any(|c| c.is_control()) {
            return Err(CapGrantError::InvalidConfig(
                "narrow: caller_id contains ASCII control bytes — \
                 forbidden for persistent identifiers"
                    .to_string(),
            ));
        }

        // Step 1: read existing grant; status must be Active.
        let existing = {
            let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
            match g.get(grant_id) {
                Some(grant) if grant.status == GrantStatus::Active => grant.clone(),
                Some(_) | None => return Err(CapGrantError::NotFound(GrantId::new(grant_id))),
            }
        };

        // Audit-fix R5 (Adversarial Critical 1): caller authorization gate.
        // Only the grantee may narrow their own grant; cross-agent narrow
        // (admin/issuer narrowing someone else's grant) is Slice D's
        // WIT-layer policy concern.
        // Adversarial-fix R12 W1: symmetric params caps with delegate_grant
        // (R4 W1). Without this, a grantee could pass arbitrarily-large
        // `new_params: Vec<CapParam>` into narrow → SubsetValidator scan +
        // SQLite UPSERT + grant.narrowed event payload — DoS amplification.
        const NARROW_MAX_PARAMS_ENTRIES: usize = 64;
        const NARROW_MAX_PARAMS_BYTES: usize = 4096;
        if new_params.len() > NARROW_MAX_PARAMS_ENTRIES {
            return Err(CapGrantError::InvalidConfig(format!(
                "narrow: new_params exceeds {NARROW_MAX_PARAMS_ENTRIES}-entry cap (got {} entries)",
                new_params.len()
            )));
        }
        let total_bytes: usize = new_params.iter().map(|p| p.key.len() + p.value.len()).sum();
        if total_bytes > NARROW_MAX_PARAMS_BYTES {
            return Err(CapGrantError::InvalidConfig(format!(
                "narrow: new_params exceeds {NARROW_MAX_PARAMS_BYTES}-byte cap (got {total_bytes} bytes)"
            )));
        }

        if caller_id != existing.grantee {
            // Slice C: migrated from SubsetViolation → PermissionDenied to align
            // with M013 §2.8 spec'd `grant-error::permission-denied`.
            // Adversarial-fix R8 W1: error message no longer echoes
            // `existing.grantee` to prevent cross-tenant agent-id disclosure
            // to unauthorized callers (symmetric with delegate_grant R5 W2).
            return Err(CapGrantError::PermissionDenied(
                "narrow: caller is not the grantee of the parent grant; \
                 only the grantee may narrow their own grant"
                    .to_string(),
            ));
        }

        // Step 2 + 3: build child draft + subset-check.
        let child_draft = crate::data::GrantDraft {
            capability: existing.capability.clone(),
            params: new_params.clone(),
            ttl: existing.ttl.clone(),
        };
        validator.validate(&existing, &child_draft)?;

        // Step 4: cascade-revoke OLD grant FIRST.
        self.cascade_revoke_with_reason(grant_id, "narrow")?;

        // Step 5: insert new dynamic grant (UUID id; provenance carries the
        // audit chain back to the now-Revoked old grant).
        //
        // Audit-fix R2 (Diff Warning 3): cap `expires_at` at `min(new_naive,
        // existing.expires_at)` for `Duration(N)` parents — narrow MUST NOT
        // extend the absolute deadline, per PRD §5.7.4 mandate "narrow only
        // strengthens; no bypass path". The `(created_at, ttl)` pair stays
        // self-consistent (R1 fix) AND the absolute deadline cannot be
        // extended (R2 fix). For `Until(t)` parents, the absolute deadline
        // is the same `t` regardless of when narrow runs, so no cap is
        // needed. For `Once / Lifecycle / Persistent`, expires_at is None.
        //
        // Audit-fix R2 (Diff Warning 4): if `existing.expires_at` is in the
        // past (a Slice-A precedent — sweeper hasn't run yet on a still-
        // Active grant), the new grant inherits a past expires_at; the next
        // sweeper tick (~1s) will flip it to Expired. The brief "born-
        // already-expired" window is the same posture as Slice A's
        // existing-grant-with-stale-expires_at handling.
        let now = Utc::now();
        let expires_at = match &existing.ttl {
            crate::data::GrantTtl::Once
            | crate::data::GrantTtl::Lifecycle
            | crate::data::GrantTtl::Persistent => None,
            crate::data::GrantTtl::Duration(ms) => {
                // Audit-fix R4 Diff W2: saturating arithmetic (matches the
                // delegate_grant 4-quadrant clamp pattern). Without this,
                // a Duration(u64::MAX) parent panics on `now + i64::MAX ms`
                // overflow per chrono's documented behavior.
                let dur_ms = i64::try_from(*ms).unwrap_or(i64::MAX);
                let naive_new = chrono::Duration::try_milliseconds(dur_ms)
                    .and_then(|d| now.checked_add_signed(d))
                    .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC);
                // Cap at parent's deadline if parent had one.
                match existing.expires_at {
                    Some(parent_exp) => Some(naive_new.min(parent_exp)),
                    None => Some(naive_new),
                }
            }
            crate::data::GrantTtl::Until(t) => Some(*t),
        };
        let new_id = GrantId::new(Uuid::new_v4().to_string());
        let new_grant = Grant {
            id: new_id.clone(),
            grantee: existing.grantee.clone(),
            capability: existing.capability.clone(),
            params: new_params.clone(),
            ttl: existing.ttl.clone(),
            issuer: existing.issuer.clone(),
            provenance: GrantProvenance::Delegated(GrantId::new(grant_id)),
            status: GrantStatus::Active,
            created_at: now,
            expires_at,
        };
        let inserted_id = self.insert_dynamic(new_grant)?;

        // Step 6: emit `grant.narrowed` (PRD §15.3.18 4-field payload).
        // `narrowed_by` field is set to `caller_id`, which the Slice-B
        // authorization gate above guaranteed equals `existing.grantee`.
        self.event_bus.emit(grant_narrowed_event(
            &inserted_id,
            &existing.params,
            &new_params,
            caller_id,
        ));

        // Step 7: return new grant id.
        Ok(inserted_id)
    }

    /// Slice C `delegate_grant` API (CONTRACT-120 Rust half — WIT layer in Slice D).
    ///
    /// **Semantic** (closes Codex round-3 C3 + Codex round-19 W1+W2 REQ rollup):
    /// the agent that holds `parent_grant_id` (= `parent_grant.grantee` =
    /// `caller_id`) initiates delegation TO `child_agent`. PRD §15.3.18's
    /// `grant.delegated.parent_agent` field is set to `caller_id`. Cross-agent
    /// delegation (admin / issuer initiating delegation on someone else's
    /// grant) is Slice D's WIT-layer policy concern.
    ///
    /// **Algorithm** (7 steps; closes Codex round-9 C1 race + Codex round-11 W1
    /// `std::sync::RwLock` recursive-read UB by extracting `insert_dynamic_inner`
    /// helper):
    /// 1. Format validation: caller_id + child_agent non-empty + no `:`.
    /// 2. Acquire outer `narrow_in_progress.read()` guard (held until step 8 returns).
    /// 3. Reject if `outer_nip.contains(parent_grant_id)` → InvalidConfig.
    /// 4. Read parent grant; verify Active under held read guard → else NotFound.
    /// 5. Authorization: caller_id == parent.grantee → else PermissionDenied.
    /// 6. Subset-check draft against parent params via validator → else SubsetViolation.
    /// 7. Build new dynamic grant with 4-quadrant TTL clamp from `draft.ttl` × parent.expires_at.
    /// 8. `insert_dynamic_inner(new_grant)` (lock-free helper; outer guard still held).
    /// 9. Emit `grant.delegated` (6-field PRD payload).
    ///
    /// **Accepted race windows** (Audit-fix R3 Diff Warning 2 round 3 extends list):
    /// - `expire_ids` (sweeper) flipping parent Active → Expired
    /// - `revoke_by_grantee` (Lifecycle TTL on agent terminate) flipping
    ///   parent Active → Revoked
    /// - `apply_preset` step 3 (`revoke_dynamic_for_grantee`) flipping
    ///   dynamic ancestors Active → Revoked
    /// - `consume()` flipping a Once-TTL parent Active → Consumed (Audit-fix
    ///   R3 Diff W2 round 3 — same posture; child becomes Delegated descendant
    ///   of a now-Consumed parent)
    /// - **Ancestor-cascade race** (Audit-fix R2 Diff W1 round 2):
    ///   `narrow_in_progress` only stores the ROOT id of an in-flight
    ///   cascade, NOT every ancestor in the chain. A cascade against an
    ///   ANCESTOR of `parent_grant_id` (e.g., grandparent root) won't be
    ///   detected by `outer_nip.contains(&parent_id_typed)` at step 3 —
    ///   the new child is born under a parent whose ancestor is mid-cascade.
    /// All five accepted races: orphans whose Duration / Until deadline had
    /// passed get reaped within ~1 sweeper tick (default 1s); otherwise the
    /// orphan child stays Active until its own expires_at fires or the next
    /// cascade walks the now-stale provenance edge. Same posture as Slice B
    /// narrow per spec §3.7 R1+R2 history.
    ///
    /// **Lock-discipline trade-off** (Audit-fix R3 Diff W1 round 3): the
    /// outer `narrow_in_progress.read()` is held across `validator.validate`,
    /// chrono TTL math, `insert_dynamic_inner`'s SQLite I/O + in-memory
    /// writes, and event emit (steps 6-9). A reader-priority RwLock policy
    /// is fine; under writer-priority RwLock policies, sustained delegate
    /// load could starve cascade attempts. `std::sync::RwLock` documents
    /// the policy as platform-dependent. Mitigation: cascade can tolerate
    /// blocking under steady-state delegate load (cascades are
    /// administrative); the alternative — dropping the read guard before
    /// SQLite I/O — would re-introduce the cascade-vs-insert race that
    /// the held guard is specifically designed to prevent.
    pub fn delegate_grant(
        &self,
        parent_grant_id: &str,
        child_agent: &str,
        draft: GrantDraft,
        caller_id: &str,
        validator: &dyn SubsetValidator,
    ) -> Result<GrantId> {
        // Step 1: format validation (matches existing GrantStore::insert
        // identifier convention — non-empty + no `:`; deterministic-id
        // collision protection. Stricter rules deferred to a cross-cutting
        // hardening slice.)
        // Adversarial-fix R9 W1: validate parent_grant_id symmetric with
        // caller_id / child_agent gates (non-empty + ≤256 bytes + no
        // control bytes). Without these gates, an attacker-controlled
        // multi-MB / control-byte parent_grant_id flows into the lookup
        // (HashMap.get is cheap, returns None), then through
        // `CapGrantError::NotFound(GrantId)` whose Display echoes the
        // raw value to logs / WIT-error-mapped responses.
        if parent_grant_id.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "delegate_grant: parent_grant_id must not be empty".to_string(),
            ));
        }
        if parent_grant_id.len() > 256 {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: parent_grant_id exceeds 256-byte cap (got {} bytes)",
                parent_grant_id.len()
            )));
        }
        if parent_grant_id.chars().any(|c| c.is_control()) {
            return Err(CapGrantError::InvalidConfig(
                "delegate_grant: parent_grant_id contains ASCII control bytes — \
                 forbidden for persistent identifiers"
                    .to_string(),
            ));
        }
        if caller_id.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "delegate_grant: caller_id must not be empty".to_string(),
            ));
        }
        if child_agent.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "delegate_grant: child_agent must not be empty".to_string(),
            ));
        }
        // Colon-id reconciliation (2026-06-06): caller_id + child_agent each accept a bare
        // colon-free id OR the canonical `agent:<slug>` form (rejecting `user:` / multi-colon /
        // malformed). Lets a guest delegate from `agent:harness` to `agent:child`; the child
        // grant is then stored under grantee `agent:child` via insert_dynamic. See
        // `is_agent_or_bare_id`. (The static-config `insert` path keeps its stricter no-`:` gate.)
        if !is_agent_or_bare_id(caller_id) {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: caller_id must be a bare id or a canonical `agent:<body>` id \
                 (got: {caller_id:?})"
            )));
        }
        if !is_agent_or_bare_id(child_agent) {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: child_agent must be a bare id or a canonical `agent:<body>` id \
                 (got: {child_agent:?})"
            )));
        }
        // Adversarial-fix R4 W2 — reject ASCII control bytes in caller_id /
        // child_agent (NUL, newline, CR, ESC, etc.). These identifiers flow
        // into the persistent Grant state (SQLite + in-memory), the
        // grant.delegated event payload (parent_agent + child_agent fields),
        // and Event.actor (routing key). A `\n` would forge log lines
        // downstream of the bus consumer; `\0` would truncate strings in
        // C-compatible log shippers. Reject rather than sanitize because
        // these are persistent identifiers — sanitization would mutate
        // identity post-validation.
        if caller_id.chars().any(|c| c.is_control()) {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: caller_id contains ASCII control bytes (e.g. \\0, \\n, \\r) — \
                 forbidden for persistent identifiers"
            )));
        }
        if child_agent.chars().any(|c| c.is_control()) {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: child_agent contains ASCII control bytes (e.g. \\0, \\n, \\r) — \
                 forbidden for persistent identifiers"
            )));
        }
        // Adversarial-fix R2 — length caps on caller-supplied identifiers
        // (closes Adversarial round-2 W6 + matches consume's 256-byte cap).
        // Prevents resource-exhaustion via multi-MB strings flowing into
        // SQLite + event payloads.
        if caller_id.len() > 256 {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: caller_id exceeds 256-byte cap (got {} bytes)",
                caller_id.len()
            )));
        }
        if child_agent.len() > 256 {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: child_agent exceeds 256-byte cap (got {} bytes)",
                child_agent.len()
            )));
        }
        // Adversarial-fix R2 — self-delegation guard (closes Adversarial
        // round-2 Critical 1 amplification + Critical 2 laundering's
        // same-agent base case). A grantee delegating to itself produces
        // unbounded Persistent-Persistent fan-out by repeated calls; each
        // call mints a fresh grant + emits grant.delegated. The check
        // also catches the trivial A→A laundering cycle. The transitive
        // A→B→A laundering remains an accepted risk (requires collusion;
        // documented in §2.9 trust boundary): closing it would need a
        // provenance-chain walk inside delegate_grant which conflicts
        // with the lock-discipline trade-off (see narrow_in_progress
        // ordering).
        if caller_id == child_agent {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: self-delegation forbidden — caller_id ({caller_id:?}) \
                 equals child_agent. Self-delegation would mint unbounded grants for the \
                 same agent on repeated calls."
            )));
        }

        // Step 2: acquire outer narrow_in_progress.read() guard. Held until
        // function return; serializes against new cascade attempts (their
        // write blocks while we hold read).
        let outer_nip = self
            .narrow_in_progress
            .read()
            .unwrap_or_else(|e| e.into_inner());

        // Step 3: read parent grant; verify Active + authz under held outer
        // read guard. Adversarial-fix R14 W1: collapse NotFound and
        // PermissionDenied into UNIFORM PermissionDenied to eliminate the
        // valid-grant-id enumeration oracle. An unauthorized caller
        // submitting a guessed parent_grant_id previously could distinguish
        // "doesn't exist / inactive" (NotFound) from "exists+Active but not
        // yours" (PermissionDenied) via different error variants. Now both
        // return PermissionDenied with no echoed identifiers — caller
        // cannot probe grant existence via this path.
        // Trade-off: legitimate callers referencing a deleted/expired grant
        // get PermissionDenied instead of NotFound. Acceptable because
        // delegate_grant is a privileged operation; legitimate callers
        // should already know their parent grant id.
        // Adversarial-fix R15 W1: defense-in-depth `expires_at > now` filter.
        // Symmetric with check.rs Step 2 + apply_preset step 2 fixes (R6 W3 +
        // R7 W1). Without this, a caller could delegate FROM an Active-but-
        // pre-sweeper-expired parent during the orphan window (~1s sweeper
        // default). The 4-quadrant TTL clamp at step 7 already pulls
        // child.expires_at to parent.expires_at if parent is bounded, but
        // we strengthen here so the orphan-window race never produces a
        // child at all (cleaner posture than relying on next-sweeper-tick
        // child reaping).
        let now_check = chrono::Utc::now();
        let parent_id_typed = GrantId::new(parent_grant_id);
        let parent = {
            let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
            match g.get(parent_grant_id) {
                Some(p)
                    if p.status == GrantStatus::Active
                        && p.grantee == caller_id
                        && p.expires_at.map_or(true, |t| t > now_check) =>
                {
                    p.clone()
                }
                _ => {
                    return Err(CapGrantError::PermissionDenied(
                        "delegate_grant: caller is not the grantee of the parent grant, \
                         OR the parent grant does not exist / is no longer Active / \
                         is past its deadline. Only the grantee of an Active, \
                         non-expired parent grant may delegate."
                            .to_string(),
                    ));
                }
            }
        };

        // Step 4: caller authz already enforced inline in Step 3's match
        // pattern. Skip explicit step here.

        // Step 5: reject if a cascade is already in flight on parent_grant_id.
        // Only authorized callers (post-step-4) reach this point, so the
        // cascade-state observation is no longer a pre-auth oracle.
        if outer_nip.contains(&parent_id_typed) {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: a narrow / cascade-revoke is in progress against \
                 parent {parent_grant_id:?}; retry after the cascade completes"
            )));
        }

        // Adversarial-fix R4 W1 — cap GrantDraft.params total size + entry
        // count to bound resource exhaustion. SubsetValidator enforces
        // structural subset rules but no total-bytes / element-count cap;
        // without this, a caller can pass a 100MB params vec that gets
        // cloned into the grant + SQLite + grant.delegated event payload.
        // Cap: 64 entries × 4 KB total bytes (key + value combined per
        // CapParam; bytes summed across all entries).
        const MAX_PARAMS_ENTRIES: usize = 64;
        const MAX_PARAMS_BYTES: usize = 4096;
        if draft.params.len() > MAX_PARAMS_ENTRIES {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: draft.params exceeds {MAX_PARAMS_ENTRIES}-entry cap (got {} entries)",
                draft.params.len()
            )));
        }
        let total_bytes: usize = draft
            .params
            .iter()
            .map(|p| p.key.len() + p.value.len())
            .sum();
        if total_bytes > MAX_PARAMS_BYTES {
            return Err(CapGrantError::InvalidConfig(format!(
                "delegate_grant: draft.params exceeds {MAX_PARAMS_BYTES}-byte cap (got {total_bytes} bytes)",
            )));
        }

        // Step 6: subset-check draft against parent params.
        validator.validate(&parent, &draft)?;

        // Adversarial-fix R10 C1 — TTL kind subset enforcement.
        // SubsetValidator only checks capability + params (subset.rs); the
        // `ttl` field is NOT inspected. Without an additional gate here, a
        // caller holding a parent with `ttl=Once` (single-use) or
        // `ttl=Lifecycle` (tied to caller-agent lifetime, both yielding
        // `parent.expires_at = None`) could submit `draft.ttl = Persistent`,
        // pass the validator, and the step-7 4-quadrant clamp's `(None,
        // None) => None` arm would mint an unbounded child grant for
        // `child_agent` — privilege extension that survives the parent's
        // consumption / termination indefinitely.
        //
        // Containment rule (child cannot escape parent's TTL bound):
        //   Parent Once       → child Once only (single-use semantic preserved)
        //   Parent Lifecycle  → child Once or Lifecycle only (agent-bound
        //                       cannot widen to time-bound or unbounded)
        //   Parent Duration/Until → child Once / Duration / Until / Persistent
        //                       (Persistent child gets clamped to parent's
        //                       deadline by step-7's `(None, Some(p)) =>
        //                       Some(p)` arm; Lifecycle child REJECTED
        //                       because its agent-bound lifetime is
        //                       independent of parent's wall-clock deadline)
        //   Parent Persistent → child anything (parent unbounded)
        match (&parent.ttl, &draft.ttl) {
            (GrantTtl::Persistent, _) => {} // parent unbounded; any child OK
            (GrantTtl::Once, _) => {
                // Adversarial-fix R11 C1: Once parents cannot be delegated.
                // The Once TTL semantic is "single-use by the grantee";
                // permitting delegation (even to a Once child) breaks the
                // single-use invariant — parent A + N children each get
                // their own single-use redemption, totalling N+1 calls
                // for a "1 use" authorization. Reject all Once delegations
                // outright (parent must consume itself).
                return Err(CapGrantError::SubsetViolation(
                    "delegate_grant: parent ttl=Once cannot be delegated \
                     (Once semantic is single-use by the grantee; delegation \
                     would amplify N+1 redemptions of a 1-use authorization). \
                     The grantee must consume the parent directly."
                        .to_string(),
                ));
            }
            (GrantTtl::Lifecycle, GrantTtl::Once | GrantTtl::Lifecycle) => {}
            (GrantTtl::Lifecycle, _) => {
                return Err(CapGrantError::SubsetViolation(format!(
                    "delegate_grant: parent ttl=Lifecycle permits child ttl=Once \
                     or Lifecycle (got {:?})",
                    draft.ttl
                )));
            }
            (GrantTtl::Duration(_) | GrantTtl::Until(_), GrantTtl::Lifecycle) => {
                return Err(CapGrantError::SubsetViolation(
                    "delegate_grant: parent ttl is time-bounded; child Lifecycle \
                     ttl is forbidden (child_agent's lifetime is independent of \
                     parent's wall-clock deadline). Use Once / Duration / Until / \
                     Persistent (Persistent inherits parent's deadline via \
                     step-7 clamp)."
                        .to_string(),
                ));
            }
            (GrantTtl::Duration(_) | GrantTtl::Until(_), _) => {} // step-7 clamp enforces deadline for Persistent / Once / Duration / Until child
        }

        // Step 7: build new dynamic grant with 4-quadrant TTL clamp.
        // Saturating arithmetic on Duration: u64 ms > i64::MAX uses i64::MAX
        // sentinel + chrono's checked_add to avoid panic on extreme inputs
        // (closes Audit-fix R1 Diff-eval Warning 2). For pathological
        // `Duration(u64::MAX)` requests, child.expires_at saturates at
        // chrono::DateTime<Utc>::MAX (effectively-never), then the parent-
        // deadline clamp pulls it back to parent.expires_at if any.
        let now = chrono::Utc::now();
        let child_native_expires_at: Option<chrono::DateTime<chrono::Utc>> = match &draft.ttl {
            GrantTtl::Once | GrantTtl::Lifecycle | GrantTtl::Persistent => None,
            GrantTtl::Duration(ms) => {
                let dur_ms = i64::try_from(*ms).unwrap_or(i64::MAX);
                // checked_add returns None on overflow → saturate at MAX.
                let candidate = chrono::Duration::try_milliseconds(dur_ms)
                    .and_then(|d| now.checked_add_signed(d))
                    .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC);
                Some(candidate)
            }
            GrantTtl::Until(t) => Some(*t),
        };
        let expires_at = match (child_native_expires_at, parent.expires_at) {
            (Some(c), Some(p)) => Some(c.min(p)), // both bounded → min
            (Some(c), None) => Some(c),           // child bounded, parent unbounded → child
            (None, Some(p)) => Some(p),           // child unbounded, parent bounded → inherit
            (None, None) => None,                 // both unbounded
        };
        // The new grant carries `parent.capability` (NOT `draft.capability`)
        // as a defense-in-depth measure (closes Audit-fix R2 Diff Warning 3):
        // SubsetValidatorImpl already rejects capability-mismatched drafts at
        // step 6, so a draft with `capability != parent.capability` returns
        // SubsetViolation and we never reach this line. The
        // `parent.capability.clone()` here is fail-closed armor: even if a
        // future buggy SubsetValidator failed open on capability mismatch,
        // the new grant carries the parent's capability rather than the
        // caller-supplied one — auditors can read `child.capability` and
        // know it traces back to the parent's grant.
        //
        // **Audit-fix R5 Diff W1 — accepted (ttl, expires_at) tuple
        // inconsistency**: when `draft.ttl == Persistent` AND parent is
        // bounded, `child.ttl == Persistent` but `child.expires_at ==
        // Some(parent_deadline)`. Same accepted trade-off as Slice B narrow
        // R1+R2 (spec §3.7 line 774). Auditors MUST read `expires_at` as
        // the authoritative deadline; deriving expiry from `(created_at,
        // ttl)` alone gives the wrong answer in this corner. Sweeper +
        // GrantCheck both consult `expires_at`, so behavior matches intent.
        let new_id = GrantId::new(uuid::Uuid::new_v4().to_string());
        let new_grant = Grant {
            id: new_id.clone(),
            grantee: child_agent.to_string(),
            capability: parent.capability.clone(),
            params: draft.params.clone(),
            ttl: draft.ttl.clone(),
            issuer: GrantIssuer::Parent(caller_id.to_string()),
            provenance: GrantProvenance::Delegated(parent.id.clone()),
            status: GrantStatus::Active,
            created_at: now,
            expires_at,
        };

        // Step 8: lock-free insert_dynamic_inner (outer narrow_in_progress.read()
        // still held; insert_dynamic_inner does NOT re-acquire the lock —
        // closes Codex round-11 W1 RwLock recursive-read UB).
        let inserted_id = self.insert_dynamic_inner(new_grant)?;

        // Step 9: emit grant.delegated (PRD §15.3.18 6-field payload).
        self.event_bus.emit(grant_delegated_event(
            &inserted_id,
            &parent.id,
            caller_id, // parent_agent
            child_agent,
            &parent.capability,
            &draft.params,
        ));

        // Outer narrow_in_progress.read() guard drops here on function return.
        drop(outer_nip);
        Ok(inserted_id)
    }

    /// Revoke every Active dynamic grant for the given grantee, cascading
    /// through their provenance descendants. Filters `provenance !=
    /// StaticConfig` for the **roots** — static-config grants are part of
    /// the `.agent/config.yaml` declaration and should NOT be revoked by a
    /// preset apply (the user revokes static grants by editing the YAML).
    /// Cascade descendants on OTHER grantees ARE revoked because they were
    /// delegated under the now-revoked dynamic root.
    ///
    /// Legacy per-root helper retained for callers that need cascade-revoke
    /// semantics outside preset batch apply. `PresetRegistry::apply_preset`
    /// uses [`Self::apply_preset_atomic_for_grantee`] so revoke + preset
    /// creation commit as one visibility batch.
    ///
    /// Audit-fix R2 Diff Warning 1: previously this was a flat sweep that
    /// did NOT walk descendants. The fix moves descendant traversal into
    /// the same primitive used by narrow / cascade_revoke, so preset apply
    /// satisfies spec wording "(cascade)".
    ///
    /// Returns the FLAT list of all revoked grant ids (roots + descendants).
    pub fn revoke_dynamic_for_grantee(&self, grantee: &str) -> Result<Vec<GrantId>> {
        // Phase 1: collect ROOT ids under read lock — dynamic grants on
        // `grantee`. Audit-fix R3 Diff Warning 1: sort the roots
        // deterministically (alphabetically by GrantId) so the per-event
        // `cascade_count` field in emitted `grant.revoked` events is
        // reproducible across runs. Without this sort, HashSet iteration
        // order varies and a multi-root configuration where root A is
        // provenance-ancestor of root B (both dynamic on the target
        // grantee) would emit either `A.cascade_count=1, B.cascade_count=0`
        // OR `A.cascade_count=0, B.cascade_count=0` depending on iteration
        // order, breaking telemetry reconstruction. Sort gives stable order.
        let mut roots: Vec<GrantId> = {
            let g = self.grants.read().unwrap_or_else(|e| e.into_inner());
            let by = self.by_grantee.read().unwrap_or_else(|e| e.into_inner());
            match by.get(grantee) {
                Some(set) => set
                    .iter()
                    .filter_map(|id| {
                        g.get(id).and_then(|grant| {
                            if grant.status == GrantStatus::Active
                                && !matches!(grant.provenance, GrantProvenance::StaticConfig)
                            {
                                Some(id.clone())
                            } else {
                                None
                            }
                        })
                    })
                    .collect(),
                None => Vec::new(),
            }
        };
        roots.sort();

        // Phase 2: cascade-revoke each root with `revoked_by: "preset-apply:{grantee}"`.
        // Each cascade is independently two-phase per
        // `cascade_revoke_with_reason`'s contract; concurrent inserts of new
        // descendants between phases inherit the same race-window posture as
        // narrow.
        let revoked_by = format!("preset-apply:{grantee}");
        let mut all_revoked: Vec<GrantId> = Vec::new();
        for root in roots {
            // The root may have been revoked by a previous cascade in this
            // loop (descendants on `grantee` of an earlier root). Tolerate
            // NotFound and continue.
            match self.cascade_revoke_with_reason(root.as_str(), &revoked_by) {
                Ok(result) => {
                    all_revoked.extend(result.revoked);
                }
                Err(CapGrantError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(all_revoked)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    };
    use std::time::Duration;

    use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
    use advance_shared_types::event::Event;

    use super::*;
    use crate::data::{ChainDecision, GrantRequest};
    use crate::resolver::{
        AutoDenyResolver, ResolverChain, ResolverContext, SubsetAutoApproveResolver,
    };
    use crate::subset::SubsetValidatorImpl;

    #[derive(Default)]
    struct RecordingBus {
        events: Mutex<Vec<Event>>,
    }

    impl EventBusEmit for RecordingBus {
        fn emit(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    impl RecordingBus {
        fn count_of(&self, event_type: &str) -> usize {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.event_type == event_type)
                .count()
        }
    }

    fn make_store() -> (GrantStore, Arc<RecordingBus>, GrantSqliteIndex) {
        let handle: Arc<dyn SqliteIndexHandle> =
            Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite"));
        let index = GrantSqliteIndex::new(handle);
        index.ensure_schema().expect("ensure schema");
        let bus = Arc::new(RecordingBus::default());
        let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
        (GrantStore::new(index.clone(), bus_dyn), bus, index)
    }

    fn grant(id: &str, grantee: &str, capability: &str, provenance: GrantProvenance) -> Grant {
        Grant {
            id: GrantId::new(id),
            grantee: grantee.to_string(),
            capability: capability.to_string(),
            params: Vec::new(),
            ttl: GrantTtl::Persistent,
            issuer: GrantIssuer::Resolver("test".to_string()),
            provenance,
            status: GrantStatus::Active,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    fn grant_with_params(
        id: &str,
        grantee: &str,
        capability: &str,
        params: Vec<CapParam>,
        provenance: GrantProvenance,
    ) -> Grant {
        let mut grant = grant(id, grantee, capability, provenance);
        grant.params = params;
        grant
    }

    #[test]
    fn apply_preset_atomic_rejects_invalid_created_grant_without_revoking_old_grant() {
        let (store, bus, index) = make_store();
        store
            .insert_dynamic(grant("old", "agent:a", "fs", GrantProvenance::Requested))
            .expect("seed old grant");

        let err = store
            .apply_preset_atomic_for_grantee(
                "agent:a",
                vec![grant(
                    "new-invalid",
                    "agent:a",
                    "",
                    GrantProvenance::Preset("bad".to_string()),
                )],
            )
            .unwrap_err();
        assert!(
            matches!(err, CapGrantError::InvalidConfig(_)),
            "got {err:?}"
        );
        assert_eq!(
            store.get("old").expect("old grant").status,
            GrantStatus::Active,
            "old grant remains Active when preset creation preflight fails"
        );
        assert!(
            store.get("new-invalid").is_none(),
            "invalid preset grant was not installed"
        );
        assert_eq!(index.status_of("old").unwrap().as_deref(), Some("active"));
        assert_eq!(bus.count_of("grant.revoked"), 0);
        assert_eq!(bus.count_of("preset.applied"), 0);
    }

    #[test]
    fn dynamic_insert_waits_behind_preset_apply_barrier() {
        let (store, _bus, _index) = make_store();
        let store = Arc::new(store);
        let barrier = store
            .narrow_in_progress
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let (started_tx, started_rx) = mpsc::channel();
        let done = Arc::new(AtomicBool::new(false));
        let done_for_thread = done.clone();
        let store_for_thread = store.clone();

        let handle = std::thread::spawn(move || {
            started_tx.send(()).expect("signal start");
            store_for_thread
                .insert_dynamic(grant(
                    "new-requested",
                    "agent:a",
                    "fs",
                    GrantProvenance::Requested,
                ))
                .expect("insert after preset barrier");
            done_for_thread.store(true, Ordering::SeqCst);
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("insert thread started");
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !done.load(Ordering::SeqCst),
            "dynamic insert completed while preset apply barrier was held"
        );

        drop(barrier);
        handle.join().expect("insert thread joins");
        assert!(done.load(Ordering::SeqCst));
        assert_eq!(
            store.get("new-requested").expect("inserted grant").status,
            GrantStatus::Active
        );
    }

    #[test]
    fn resolver_snapshot_and_insert_are_atomic_against_preset_apply() {
        let (store, bus, _index) = make_store();
        let store = Arc::new(store);
        store
            .insert_dynamic(grant_with_params(
                "old-parent",
                "agent:a",
                "fs",
                vec![CapParam {
                    key: "write-paths".to_string(),
                    value: "/old".to_string(),
                }],
                GrantProvenance::Requested,
            ))
            .expect("seed old parent grant");

        let chain = Arc::new(ResolverChain::new(vec![
            Box::new(SubsetAutoApproveResolver::new(Arc::new(
                SubsetValidatorImpl::new(),
            ))),
            Box::new(AutoDenyResolver::new()),
        ]));
        let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
        let request = GrantRequest {
            caller: "agent:a".to_string(),
            capability: "fs".to_string(),
            params: Some(vec![CapParam {
                key: "write-paths".to_string(),
                value: "/old/sub".to_string(),
            }]),
            ttl: GrantTtl::Once,
            justification: Some("subset request racing preset apply".to_string()),
        };

        let (snapshot_tx, snapshot_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let request_store = store.clone();
        let request_chain = chain.clone();
        let request_bus = bus_dyn.clone();
        let request_handle = std::thread::spawn(move || {
            request_store.with_dynamic_insert_read_barrier(|| {
                let parent_grants = request_store.list_by_grantee("agent:a");
                snapshot_tx.send(()).expect("signal parent snapshot");
                release_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("release request evaluation");
                let context = ResolverContext {
                    parent_grants: &parent_grants,
                    run_id: None,
                };
                request_chain.evaluate_with_dynamic_insert_barrier(
                    request,
                    context,
                    &request_store,
                    &request_bus,
                )
            })
        });

        snapshot_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("request snapshotted old parent grants");
        let apply_done = Arc::new(AtomicBool::new(false));
        let apply_done_for_thread = apply_done.clone();
        let apply_store = store.clone();
        let (apply_started_tx, apply_started_rx) = mpsc::channel();
        let apply_handle = std::thread::spawn(move || {
            apply_started_tx.send(()).expect("signal apply start");
            let result = apply_store.apply_preset_atomic_for_grantee(
                "agent:a",
                vec![grant_with_params(
                    "preset-new",
                    "agent:a",
                    "fs",
                    vec![CapParam {
                        key: "write-paths".to_string(),
                        value: "/a".to_string(),
                    }],
                    GrantProvenance::Preset("sys262".to_string()),
                )],
            );
            apply_done_for_thread.store(true, Ordering::SeqCst);
            result
        });
        apply_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("apply thread started");
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !apply_done.load(Ordering::SeqCst),
            "preset apply completed between resolver snapshot and approved insert"
        );

        release_tx.send(()).expect("release request");
        let decision = request_handle.join().expect("request thread joins");
        let ChainDecision::Approved(requested_id) = decision else {
            panic!("request should approve against the old parent snapshot, got {decision:?}");
        };
        let (revoked_ids, created_ids) = apply_handle
            .join()
            .expect("apply thread joins")
            .expect("preset apply succeeds");

        assert!(
            revoked_ids.contains(&GrantId::new("old-parent")),
            "preset apply revoked the old parent"
        );
        assert!(
            revoked_ids.contains(&requested_id),
            "preset apply also revoked the grant approved from the stale snapshot"
        );
        assert_eq!(created_ids, vec![GrantId::new("preset-new")]);

        let active: Vec<_> = store
            .list_by_grantee("agent:a")
            .into_iter()
            .filter(|grant| grant.status == GrantStatus::Active)
            .map(|grant| grant.id)
            .collect();
        assert_eq!(
            active,
            vec![GrantId::new("preset-new")],
            "post-apply active grants contain only the preset grant"
        );
    }
}

/// RAII guard that removes a grant id from `narrow_in_progress` on Drop.
/// Ensures the membership flag is cleared even if `cascade_revoke_with_reason`
/// returns Err mid-Phase-2.
struct NarrowInProgressGuard<'a> {
    store: &'a GrantStore,
    id: GrantId,
}

impl Drop for NarrowInProgressGuard<'_> {
    fn drop(&mut self) {
        let mut nip = self
            .store
            .narrow_in_progress
            .write()
            .unwrap_or_else(|e| e.into_inner());
        nip.remove(&self.id);
    }
}
