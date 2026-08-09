//! Canonical CONTRACT-218 recursive-registry and write-set codecs.
//!
//! This module deliberately does not use `SELECT *` row hashing, SQLite
//! collation, or SQLite's dynamic type tags.  Every table has an explicit
//! schema-order column list and a table-specific canonical primary key.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, Row};
use sha2::{Digest, Sha256};

const STATE_ROOT_DOMAIN: &[u8] = b"advance.contract218.registry-state-root.v1\0";
const WRITE_SET_DOMAIN: &[u8] = b"advance.contract218.registry-write-set.v1\0";
const MAX_CANONICAL_TEXT_PRIMARY_KEY_BYTES: usize = 256;
const TERMINATION_FINALIZE_TOTAL_BYTES: u64 = 2_048;
const AUDIT_CHECKPOINT_BYTES: u64 = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegistrySnapshot {
    tables: Vec<CanonicalTable>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalTable {
    tag: u8,
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone, Copy)]
enum Kind {
    Int,
    Text,
    Blob,
    OperationKind,
    OptInt,
    OptText,
    OptBlob,
}

#[derive(Clone, Copy)]
enum Key {
    Text(usize),
    TwoText(usize, usize),
    Blob32(usize),
    Singleton(usize),
    Blob16(usize),
    MigrationRow {
        migration: usize,
        store_kind: usize,
        event_digest: usize,
    },
}

pub(crate) fn capture(conn: &Connection) -> Result<RegistrySnapshot, String> {
    let tables = vec![
        table(
            conn,
            1,
            "SELECT id,sensitive_params,identity_incarnation,declaration_digest,\
                    lifecycle_state,catalog_visible,operation_id,tombstoned_at_ms,retain_until_ms \
             FROM components",
            Key::Text(0),
            &[
                Kind::Text,
                Kind::Blob,
                Kind::Int,
                Kind::Blob,
                Kind::Text,
                Kind::Int,
                Kind::OptText,
                Kind::OptInt,
                Kind::OptInt,
            ],
        )?,
        table(
            conn,
            2,
            "SELECT operation_id,kind,phase,is_active,retain_until_ms,\
                    termination_emission_receipt_set_digest \
             FROM observation_identity_operations",
            Key::Text(0),
            &[
                Kind::Text,
                Kind::OperationKind,
                Kind::Text,
                Kind::Int,
                Kind::OptInt,
                Kind::OptBlob,
            ],
        )?,
        table(
            conn,
            3,
            "SELECT id,class,incarnation,declaration_digest,lifecycle_state,\
                    catalog_visible,operation_id,tombstoned_at_ms,retain_until_ms \
             FROM observation_identities",
            Key::Text(0),
            &[
                Kind::Text,
                Kind::Text,
                Kind::Int,
                Kind::Blob,
                Kind::Text,
                Kind::Int,
                Kind::OptText,
                Kind::OptInt,
                Kind::OptInt,
            ],
        )?,
        table(
            conn,
            4,
            "SELECT id,class,last_incarnation,last_declaration_digest \
             FROM observation_identity_authority",
            Key::Text(0),
            &[Kind::Text, Kind::Text, Kind::Int, Kind::Blob],
        )?,
        table(
            conn,
            5,
            "SELECT operation_id,identity_id,identity_class,identity_incarnation,\
                    declaration_digest,termination_subject_receipt_digest,\
                    termination_emission_receipt_digest,gc_subject_receipt_digest,\
                    gc_reference_scan_digest,gc_challenge_nonce,gc_tombstone_state_root,\
                    gc_operation_boot,gc_phase,gc_generation,gc_registry_sequence,\
                    gc_challenge_consumed,is_active \
             FROM observation_identity_operation_members",
            Key::TwoText(0, 1),
            &[
                Kind::Text,
                Kind::Text,
                Kind::Text,
                Kind::Int,
                Kind::Blob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::Text,
                Kind::Int,
                Kind::OptInt,
                Kind::Int,
                Kind::Int,
            ],
        )?,
        table(
            conn,
            6,
            "SELECT activation_nonce,boot_id,registry_instance_id,role,operation_id,\
                    operation_kind,identity_id,identity_class,identity_incarnation,\
                    declaration_digest,registry_sequence,phase,subject_receipt_digest,\
                    table_receipt_digest,lifecycle_receipt_digest,subject_absence_digest,\
                    table_absence_digest,lifecycle_absence_digest,ready_proof_nonce,\
                    abort_proof_nonce,rejection_nonce,recovery_nonce,updated_sequence,\
                    terminal_at_ms,audit_checkpoint_sequence,encoded_bytes,future_reserved_bytes \
             FROM observation_previsible_activations",
            Key::Blob32(0),
            &[
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Int,
                Kind::Text,
                Kind::OperationKind,
                Kind::Text,
                Kind::Text,
                Kind::Int,
                Kind::Blob,
                Kind::Int,
                Kind::Text,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::Int,
                Kind::OptInt,
                Kind::OptInt,
                Kind::Int,
                Kind::Int,
            ],
        )?,
        table(
            conn,
            7,
            "SELECT singleton,row_count,actual_encoded_bytes,future_reserved_bytes \
             FROM observation_previsible_capacity",
            Key::Singleton(0),
            &[Kind::Int, Kind::Int, Kind::Int, Kind::Int],
        )?,
        table(
            conn,
            8,
            "SELECT operation_id,operation_kind,registry_instance_id,operation_boot_id,\
                    prepare_ack_digest,prepare_ack_nonce,prepare_sequence,member_set_digest,phase,\
                    cleanup_receipt_digest,cleanup_high_water_digest,cleanup_receipt_set_digest,\
                    cleanup_nonce,finalize_recovery_nonce,finalize_sequence,finalize_ack_digest,\
                    terminal_at_ms,audit_checkpoint_sequence,encoded_bytes,future_reserved_bytes \
             FROM observation_termination_finalizations",
            Key::Text(0),
            &[
                Kind::Text,
                Kind::OperationKind,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Int,
                Kind::Blob,
                Kind::Text,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptBlob,
                Kind::OptInt,
                Kind::OptBlob,
                Kind::OptInt,
                Kind::OptInt,
                Kind::Int,
                Kind::Int,
            ],
        )?,
        table(
            conn,
            9,
            "SELECT singleton,row_count,actual_encoded_bytes,future_reserved_bytes \
             FROM observation_termination_finalize_capacity",
            Key::Singleton(0),
            &[Kind::Int, Kind::Int, Kind::Int, Kind::Int],
        )?,
        table(
            conn,
            10,
            "SELECT migration_id,registry_instance_id,m019_ledger_instance_id,\
                    cross_owner_key_epoch,source_m019_sequence,source_m019_head,\
                    source_m019_state_root,target_m019_sequence,target_m019_head,\
                    target_m019_state_root,sqlite_store_instance_digest,\
                    sqlite_retained_high_water,sqlite_source_root,sqlite_target_root,\
                    jsonl_store_instance_digest,jsonl_retained_high_water,\
                    jsonl_source_inventory_root,jsonl_target_inventory_root,\
                    frozen_row_set_digest,owner_plan_digest,freeze_receipt_digest,\
                    planned_row_count,issued_row_count,finalized_row_count,\
                    actual_encoded_bytes,future_reserved_bytes,phase,updated_registry_sequence \
             FROM observation_carrier_migrations",
            Key::Blob16(0),
            &[
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Int,
                Kind::Int,
                Kind::Blob,
                Kind::Blob,
                Kind::Int,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Int,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Int,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Int,
                Kind::Int,
                Kind::Int,
                Kind::Int,
                Kind::Int,
                Kind::Text,
                Kind::Int,
            ],
        )?,
        table(
            conn,
            11,
            "SELECT migration_id,store_kind,event_key_digest,event_cursor_digest,\
                    receipt_nonce,legacy_receipt,owner_intent_digest,owner_preimage_digest,\
                    owner_postimage_digest,phase,owner_commit_receipt_digest,\
                    finalized_registry_sequence,encoded_bytes \
             FROM observation_carrier_migration_rows",
            Key::MigrationRow {
                migration: 0,
                store_kind: 1,
                event_digest: 2,
            },
            &[
                Kind::Blob,
                Kind::Int,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Blob,
                Kind::Text,
                Kind::OptBlob,
                Kind::OptInt,
                Kind::Int,
            ],
        )?,
    ];
    Ok(RegistrySnapshot { tables })
}

pub(crate) fn state_root(snapshot: &RegistrySnapshot) -> Result<[u8; 32], String> {
    if snapshot.tables.len() != 11
        || snapshot
            .tables
            .iter()
            .enumerate()
            .any(|(index, table)| table.tag != (index + 1) as u8)
    {
        return Err("canonical state snapshot does not contain tags 1..=11".to_owned());
    }
    let mut hasher = Sha256::new();
    hasher.update(STATE_ROOT_DOMAIN);
    hasher.update([11]);
    for table in &snapshot.tables {
        hasher.update([table.tag]);
        hasher.update((table.rows.len() as u64).to_be_bytes());
        for (key, row) in &table.rows {
            put_len(&mut hasher, key.len())?;
            hasher.update(key);
            put_len(&mut hasher, row.len())?;
            hasher.update(row);
        }
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn write_set_digest(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<[u8; 32], String> {
    if before.tables.len() != 11 || after.tables.len() != 11 {
        return Err("canonical write set requires eleven tables".to_owned());
    }
    let mut records = Vec::new();
    for (old_table, new_table) in before.tables.iter().zip(&after.tables) {
        if old_table.tag != new_table.tag {
            return Err("canonical write-set table tags differ".to_owned());
        }
        let mut keys = BTreeMap::<Vec<u8>, ()>::new();
        keys.extend(old_table.rows.keys().cloned().map(|key| (key, ())));
        keys.extend(new_table.rows.keys().cloned().map(|key| (key, ())));
        for key in keys.keys() {
            let before_row = old_table.rows.get(key);
            let after_row = new_table.rows.get(key);
            if before_row != after_row {
                records.push(CanonicalWriteRecord {
                    tag: old_table.tag,
                    key: key.clone(),
                    before: before_row.cloned(),
                    after: after_row.cloned(),
                });
            }
        }
    }
    canonical_write_set_digest_records(&records)
}

/// One already-locked canonical write-set record.  Synthetic artifact tags
/// use the same record grammar as rooted SQLite tables; their rows are the
/// complete authenticated files rather than structured SQLite rows.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalWriteRecord {
    tag: u8,
    key: Vec<u8>,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
}

fn canonical_write_set_digest_records(
    records: &[CanonicalWriteRecord],
) -> Result<[u8; 32], String> {
    let preimage = canonical_write_set_preimage(records)?;
    Ok(Sha256::digest(preimage).into())
}

fn canonical_write_set_preimage(records: &[CanonicalWriteRecord]) -> Result<Vec<u8>, String> {
    let count = u32::try_from(records.len()).map_err(|_| "write-set record count overflow")?;
    let mut out = Vec::new();
    out.extend_from_slice(WRITE_SET_DOMAIN);
    out.extend_from_slice(&count.to_be_bytes());

    let mut previous: Option<(u8, &[u8])> = None;
    for record in records {
        validate_canonical_write_record(record)?;
        if previous.is_some_and(|prior| prior >= (record.tag, record.key.as_slice())) {
            return Err(
                "canonical write-set records are duplicate or not strictly sorted".to_owned(),
            );
        }
        previous = Some((record.tag, record.key.as_slice()));

        out.push(record.tag);
        put_vec_len(&mut out, record.key.len())?;
        out.extend_from_slice(&record.key);
        put_optional_vec(&mut out, record.before.as_deref())?;
        put_optional_vec(&mut out, record.after.as_deref())?;
    }
    Ok(out)
}

/// Verify one operation's closed table cohort and its already-authenticated
/// write-set digest.  Keeping this private avoids creating a second anchor
/// authority while still making the rooted and synthetic record grammar one
/// executable codec boundary.
#[allow(dead_code)]
fn verify_canonical_write_set(
    records: &[CanonicalWriteRecord],
    expected_cohort: &[u8],
    expected_digest: [u8; 32],
) -> Result<Vec<u8>, String> {
    if expected_cohort.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("expected canonical write-set cohort is not strictly sorted".to_owned());
    }
    let actual_cohort = records
        .iter()
        .map(|record| record.tag)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if actual_cohort != expected_cohort {
        return Err(format!(
            "canonical write-set cohort {actual_cohort:?} differs from expected {expected_cohort:?}"
        ));
    }
    let preimage = canonical_write_set_preimage(records)?;
    let observed: [u8; 32] = Sha256::digest(&preimage).into();
    if observed != expected_digest {
        return Err("canonical write-set digest does not match authenticated witness".to_owned());
    }
    Ok(preimage)
}

fn validate_canonical_write_record(record: &CanonicalWriteRecord) -> Result<(), String> {
    if record.before.is_none() && record.after.is_none() {
        return Err("canonical write-set record has no preimage or postimage".to_owned());
    }
    if record.before == record.after {
        return Err("canonical write-set record does not change its row".to_owned());
    }

    match record.tag {
        1..=11 => {
            for row in [record.before.as_deref(), record.after.as_deref()]
                .into_iter()
                .flatten()
            {
                let row_key = canonical_key_from_encoded_row(record.tag, row)?;
                if row_key != record.key {
                    return Err(format!(
                        "canonical row primary key disagrees with table-{} write-set key",
                        record.tag
                    ));
                }
            }
        }
        12..=14 => {
            if record.key != 1_u64.to_be_bytes() {
                return Err(format!(
                    "synthetic table-{} key is not canonical singleton 1",
                    record.tag
                ));
            }
        }
        _ => {
            return Err(format!(
                "unknown canonical write-set table tag {}",
                record.tag
            ))
        }
    }
    Ok(())
}

fn canonical_key_from_encoded_row(tag: u8, row: &[u8]) -> Result<Vec<u8>, String> {
    let cells = decode_canonical_row(tag, row)?;
    match tag {
        1..=4 | 8 => canonical_text_cell_key(&cells[0], "single-text primary key"),
        5 => {
            let mut key = canonical_text_cell_key(&cells[0], "operation primary key")?;
            key.extend_from_slice(&canonical_text_cell_key(&cells[1], "identity primary key")?);
            Ok(key)
        }
        6 => canonical_blob_cell_key(&cells[0], 32, "activation primary key"),
        7 | 9 => {
            if cells[0] != CanonicalCell::Integer(1) {
                return Err(format!("table-{tag} singleton primary key is not one"));
            }
            Ok(1_u64.to_be_bytes().to_vec())
        }
        10 => canonical_blob_cell_key(&cells[0], 16, "migration primary key"),
        11 => {
            let mut key = canonical_blob_cell_key(&cells[0], 16, "migration row primary key")?;
            let store = cells[1].integer("migration row store kind")?;
            if !(1..=2).contains(&store) {
                return Err("migration row store kind is outside 1..=2".to_owned());
            }
            key.push(store as u8);
            key.extend_from_slice(&canonical_blob_cell_key(
                &cells[2],
                32,
                "migration event primary key",
            )?);
            Ok(key)
        }
        _ => Err(format!("no canonical key grammar for table tag {tag}")),
    }
}

fn canonical_text_cell_key(cell: &CanonicalCell, label: &str) -> Result<Vec<u8>, String> {
    let value = cell.text(label)?;
    validate_text_primary_key(value, label)?;
    let mut key = Vec::new();
    put_vec_len(&mut key, value.len())?;
    key.extend_from_slice(value);
    Ok(key)
}

fn canonical_blob_cell_key(
    cell: &CanonicalCell,
    width: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let CanonicalCell::Blob(value) = cell else {
        return Err(format!("{label} is not a canonical blob"));
    };
    if value.len() != width {
        return Err(format!("{label} is not {width} bytes"));
    }
    Ok(value.clone())
}

fn put_optional_vec(out: &mut Vec<u8>, row: Option<&[u8]>) -> Result<(), String> {
    match row {
        None => out.extend_from_slice(&0_u32.to_be_bytes()),
        Some(row) => {
            put_vec_len(out, row.len())?;
            out.extend_from_slice(row);
        }
    }
    Ok(())
}

pub(crate) fn validate_operation_effects(
    operation_tag: u8,
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let changed = changed_table_tags(before, after)?;
    if changed.is_empty() && operation_tag != 6 {
        return Err(format!(
            "operation tag {operation_tag} produced an empty recursive write set"
        ));
    }
    if operation_tag != 8 {
        validate_non_gc_tag_preserves_gc_fields(operation_tag, before, after)?;
    }
    match operation_tag {
        1 => validate_registration_effects(before, after, true),
        2 => validate_registration_effects(before, after, false),
        3 => validate_previsible_effects(before, after),
        4 => validate_termination_prepare_effects(before, after),
        5 => validate_termination_finalize_effects(before, after),
        6 => validate_sealed_host_or_carrier_effects(before, after),
        7 => validate_tag_seven_effects(before, after),
        8 => validate_tag_eight_gc_effects(before, after),
        _ => Err("unknown registry operation tag".to_owned()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CanonicalCell {
    Integer(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
    OperationKind(u8),
    Null,
}

impl CanonicalCell {
    fn integer(&self, label: &str) -> Result<u64, String> {
        match self {
            Self::Integer(value) => Ok(*value),
            _ => Err(format!("{label} is not a canonical integer")),
        }
    }

    fn text(&self, label: &str) -> Result<&[u8], String> {
        match self {
            Self::Text(value) => Ok(value),
            _ => Err(format!("{label} is not canonical text")),
        }
    }

    fn operation_kind(&self) -> Result<u8, String> {
        match self {
            Self::OperationKind(value) => Ok(*value),
            _ => Err("operation kind is not canonical".to_owned()),
        }
    }
}

#[derive(Clone, Debug)]
struct CanonicalRowMutation {
    key: Vec<u8>,
    before: Option<Vec<CanonicalCell>>,
    after: Option<Vec<CanonicalCell>>,
}

fn row_mutations(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    tag: u8,
) -> Result<Vec<CanonicalRowMutation>, String> {
    let old = table_by_tag(before, tag)?;
    let new = table_by_tag(after, tag)?;
    let mut keys = BTreeSet::new();
    keys.extend(old.rows.keys().cloned());
    keys.extend(new.rows.keys().cloned());
    keys.into_iter()
        .filter_map(|key| {
            let old_row = old.rows.get(&key);
            let new_row = new.rows.get(&key);
            (old_row != new_row).then_some((key, old_row, new_row))
        })
        .map(|(key, old_row, new_row)| {
            Ok(CanonicalRowMutation {
                key,
                before: old_row
                    .map(|row| decode_canonical_row(tag, row))
                    .transpose()?,
                after: new_row
                    .map(|row| decode_canonical_row(tag, row))
                    .transpose()?,
            })
        })
        .collect()
}

fn require_changed_tags(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    expected: &[u8],
    label: &str,
) -> Result<(), String> {
    let changed = changed_table_tags(before, after)?;
    if changed != expected {
        return Err(format!(
            "{label} changed recursive table tags {changed:?}, expected {expected:?}"
        ));
    }
    Ok(())
}

fn require_exact_columns(
    before: &[CanonicalCell],
    after: &[CanonicalCell],
    expected: &[usize],
    label: &str,
) -> Result<(), String> {
    if before.len() != after.len() {
        return Err(format!("{label} changed canonical row width"));
    }
    let changed = before
        .iter()
        .zip(after)
        .enumerate()
        .filter_map(|(index, (old, new))| (old != new).then_some(index))
        .collect::<Vec<_>>();
    if changed != expected {
        return Err(format!(
            "{label} changed columns {changed:?}, expected {expected:?}"
        ));
    }
    Ok(())
}

fn require_permitted_columns(
    before: &[CanonicalCell],
    after: &[CanonicalCell],
    required: &[usize],
    permitted: &[usize],
    label: &str,
) -> Result<(), String> {
    let changed = before
        .iter()
        .zip(after)
        .enumerate()
        .filter_map(|(index, (old, new))| (old != new).then_some(index))
        .collect::<Vec<_>>();
    if required.iter().any(|index| !changed.contains(index))
        || changed.iter().any(|index| !permitted.contains(index))
    {
        return Err(format!(
            "{label} changed columns {changed:?}; required {required:?}, permitted {permitted:?}"
        ));
    }
    Ok(())
}

fn require_one_insert(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    tag: u8,
    label: &str,
) -> Result<CanonicalRowMutation, String> {
    let mutations = row_mutations(before, after, tag)?;
    if mutations.len() != 1 || mutations[0].before.is_some() || mutations[0].after.is_none() {
        return Err(format!("{label} must insert exactly one table-{tag} row"));
    }
    Ok(mutations.into_iter().next().expect("one mutation"))
}

fn require_one_update(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    tag: u8,
    label: &str,
) -> Result<CanonicalRowMutation, String> {
    let mutations = row_mutations(before, after, tag)?;
    if mutations.len() != 1 || mutations[0].before.is_none() || mutations[0].after.is_none() {
        return Err(format!("{label} must update exactly one table-{tag} row"));
    }
    Ok(mutations.into_iter().next().expect("one mutation"))
}

fn is_null(cell: &CanonicalCell) -> bool {
    *cell == CanonicalCell::Null
}

fn is_nonzero_integer(cell: &CanonicalCell) -> bool {
    matches!(cell, CanonicalCell::Integer(value) if *value > 0)
}

fn validate_capacity_row_update(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    tag: u8,
    expected_columns: &[usize],
    label: &str,
) -> Result<(), String> {
    let mutation = require_one_update(before, after, tag, label)?;
    if mutation.key != 1_u64.to_be_bytes()
        || mutation
            .before
            .as_ref()
            .is_none_or(|cells| cells.first() != Some(&CanonicalCell::Integer(1)))
        || mutation
            .after
            .as_ref()
            .is_none_or(|cells| cells.first() != Some(&CanonicalCell::Integer(1)))
    {
        return Err(format!("{label} changed a noncanonical capacity singleton"));
    }
    require_exact_columns(
        mutation.before.as_ref().expect("checked"),
        mutation.after.as_ref().expect("checked"),
        expected_columns,
        label,
    )
}

fn validate_authority_allocation(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    expected_identity: &[CanonicalCell],
    label: &str,
) -> Result<(), String> {
    let mutations = row_mutations(before, after, 4)?;
    if mutations.len() != 1 {
        return Err(format!("{label} must allocate exactly one authority row"));
    }
    let mutation = &mutations[0];
    let authority = mutation
        .after
        .as_ref()
        .ok_or_else(|| format!("{label} deleted the identity authority row"))?;
    if authority[0] != expected_identity[0]
        || authority[1] != expected_identity[1]
        || authority[2] != expected_identity[2]
        || authority[3] != expected_identity[3]
    {
        return Err(format!(
            "{label} authority row does not match the allocated identity"
        ));
    }
    if let Some(old) = &mutation.before {
        require_exact_columns(old, authority, &[2, 3], label)?;
        if old[0] != authority[0]
            || old[1] != authority[1]
            || old[2]
                .integer("previous authority incarnation")?
                .checked_add(1)
                != Some(authority[2].integer("allocated authority incarnation")?)
        {
            return Err(format!(
                "{label} did not advance one exact authority incarnation"
            ));
        }
    }
    Ok(())
}

fn validate_registration_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    component: bool,
) -> Result<(), String> {
    let label = if component {
        "tag-1 component registration"
    } else {
        "tag-2 agent registration"
    };
    require_changed_tags(
        before,
        after,
        if component {
            &[1, 2, 3, 4, 5, 7]
        } else {
            &[2, 3, 4, 5, 7]
        },
        label,
    )?;
    let operation = require_one_insert(before, after, 2, label)?;
    let identity = require_one_insert(before, after, 3, label)?;
    let member = require_one_insert(before, after, 5, label)?;
    let operation = operation.after.expect("insert");
    let identity = identity.after.expect("insert");
    let member = member.after.expect("insert");
    let expected_kind = if component { 2 } else { 1 };
    let expected_class = if component {
        b"component".as_slice()
    } else {
        b"agent".as_slice()
    };
    if operation[1].operation_kind()? != expected_kind
        || operation[2].text("registration phase")? != b"prepared"
        || operation[3] != CanonicalCell::Integer(1)
        || !is_null(&operation[4])
        || !is_null(&operation[5])
        || identity[1].text("registration identity class")? != expected_class
        || identity[4].text("registration identity lifecycle")? != b"pending"
        || identity[5] != CanonicalCell::Integer(0)
        || identity[6] != operation[0]
        || !is_null(&identity[7])
        || !is_null(&identity[8])
        || member[0] != operation[0]
        || member[1] != identity[0]
        || member[2] != identity[1]
        || member[3] != identity[2]
        || member[4] != identity[3]
        || !is_null(&member[5])
        || !is_null(&member[6])
        || !gc_cells_are_idle(&member)?
        || member[16] != CanonicalCell::Integer(1)
    {
        return Err(format!("{label} inserted a noncanonical operation cohort"));
    }
    validate_authority_allocation(before, after, &identity, label)?;
    if component {
        let projection = require_one_insert(before, after, 1, label)?;
        let projection = projection.after.expect("insert");
        if projection[0] != identity[0]
            || projection[2] != identity[2]
            || projection[3] != identity[3]
            || projection[4].text("component lifecycle")? != b"live"
            || projection[5] != CanonicalCell::Integer(0)
            || projection[6] != operation[0]
            || !is_null(&projection[7])
            || !is_null(&projection[8])
        {
            return Err(format!(
                "{label} inserted a mismatched component projection"
            ));
        }
    }
    let capacity = require_one_update(before, after, 7, label)?;
    let old_capacity = capacity.before.expect("update");
    let new_capacity = capacity.after.expect("update");
    require_exact_columns(&old_capacity, &new_capacity, &[1, 3], label)?;
    if old_capacity[1]
        .integer("registration reserved row count")?
        .checked_add(1)
        != Some(new_capacity[1].integer("registration postimage reserved rows")?)
        || old_capacity[2] != new_capacity[2]
        || old_capacity[3]
            .integer("registration reserved future bytes")?
            .checked_add(4096)
            != Some(new_capacity[3].integer("registration postimage future bytes")?)
    {
        return Err(format!("{label} capacity reservation is not exact"));
    }
    Ok(())
}

fn validate_previsible_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let journal_mutations = row_mutations(before, after, 6)?;
    if journal_mutations.len() != 1 {
        return Err("tag-3 must mutate exactly one previsible journal row".to_owned());
    }
    let journal = &journal_mutations[0];
    match (&journal.before, &journal.after) {
        (None, Some(inserted)) => {
            require_changed_tags(before, after, &[6, 7], "tag-3 journal allocation")?;
            if inserted[11].text("new previsible phase")? != b"prepared"
                || inserted[3].integer("new previsible role")? == 0
                || !matches!(inserted[5], CanonicalCell::OperationKind(1 | 2))
                || inserted[10].integer("new previsible registry sequence")?
                    != inserted[22].integer("new previsible updated sequence")?
                || inserted[12..=21].iter().any(|cell| !is_null(cell))
                || !is_null(&inserted[23])
                || !is_null(&inserted[24])
                || inserted[26].integer("new previsible future reservation")? == 0
            {
                return Err("tag-3 inserted a noncanonical prepared journal".to_owned());
            }
            let capacity =
                require_one_update(before, after, 7, "tag-3 journal allocation capacity")?;
            let old_capacity = capacity.before.expect("update");
            let new_capacity = capacity.after.expect("update");
            require_exact_columns(
                &old_capacity,
                &new_capacity,
                &[2, 3],
                "tag-3 journal allocation capacity",
            )?;
            let encoded = inserted[25].integer("new previsible encoded bytes")?;
            if old_capacity[1] != new_capacity[1]
                || old_capacity[2]
                    .integer("previsible capacity actual preimage")?
                    .checked_add(encoded)
                    != Some(new_capacity[2].integer("previsible capacity actual postimage")?)
                || old_capacity[3]
                    .integer("previsible capacity future preimage")?
                    .checked_sub(encoded)
                    != Some(new_capacity[3].integer("previsible capacity future postimage")?)
            {
                return Err("tag-3 did not consume the exact registration reservation".to_owned());
            }
            Ok(())
        }
        (Some(old), Some(new)) => {
            if old[..11] != new[..11] || old[24] != new[24] {
                return Err(
                    "tag-3 rewrote immutable previsible journal identity/audit fields".to_owned(),
                );
            }
            match (
                old[11].text("previsible preimage phase")?,
                new[11].text("previsible postimage phase")?,
            ) {
                (b"prepared", b"ready") => {
                    require_changed_tags(before, after, &[6, 7], "tag-3 Ready")?;
                    require_exact_columns(
                        old,
                        new,
                        &[11, 12, 13, 14, 18, 21, 22, 25, 26],
                        "tag-3 Ready journal",
                    )?;
                    if new[12..=14].iter().any(|cell| !nonempty_blob(cell))
                        || !nonempty_blob(&new[18])
                        || !nonempty_blob(&new[21])
                        || new[15..=17].iter().any(|cell| !is_null(cell))
                        || !is_null(&new[19])
                        || !is_null(&new[20])
                    {
                        return Err("tag-3 Ready metadata is incomplete".to_owned());
                    }
                    validate_capacity_row_update(before, after, 7, &[2, 3], "tag-3 Ready capacity")
                }
                (b"ready", b"publishing") => {
                    require_changed_tags(before, after, &[6], "tag-3 Publishing")?;
                    require_exact_columns(old, new, &[11, 22], "tag-3 Publishing journal")
                }
                (b"publishing", b"published") => {
                    require_exact_columns(
                        old,
                        new,
                        &[11, 22, 23, 25, 26],
                        "tag-3 Published journal",
                    )?;
                    validate_previsible_terminal_cohort(before, after, new, false)
                }
                (b"prepared" | b"ready" | b"rejected", b"aborting") => {
                    require_changed_tags(before, after, &[6, 7], "tag-3 Abort prepare")?;
                    require_exact_columns(
                        old,
                        new,
                        &[11, 15, 16, 17, 19, 21, 22, 25, 26],
                        "tag-3 Abort prepare journal",
                    )?;
                    if new[15..=17].iter().any(|cell| !nonempty_blob(cell))
                        || !nonempty_blob(&new[19])
                        || !nonempty_blob(&new[21])
                    {
                        return Err("tag-3 Abort metadata is incomplete".to_owned());
                    }
                    validate_capacity_row_update(
                        before,
                        after,
                        7,
                        &[2, 3],
                        "tag-3 Abort prepare capacity",
                    )
                }
                (b"aborting", b"aborted") => {
                    require_exact_columns(
                        old,
                        new,
                        &[11, 22, 23, 25, 26],
                        "tag-3 Aborted journal",
                    )?;
                    validate_previsible_terminal_cohort(before, after, new, true)
                }
                (old_phase, new_phase) => Err(format!(
                    "tag-3 previsible phase transition is closed: {} -> {}",
                    String::from_utf8_lossy(old_phase),
                    String::from_utf8_lossy(new_phase)
                )),
            }
        }
        _ => Err("tag-3 cannot delete a previsible journal".to_owned()),
    }
}

fn validate_previsible_terminal_cohort(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    journal: &[CanonicalCell],
    aborted: bool,
) -> Result<(), String> {
    let component = journal[5].operation_kind()? == 2;
    let expected_tags: &[u8] = if component {
        &[1, 2, 3, 5, 6, 7]
    } else {
        &[2, 3, 5, 6, 7]
    };
    let label = if aborted {
        "tag-3 Aborted"
    } else {
        "tag-3 Published"
    };
    require_changed_tags(before, after, expected_tags, label)?;
    if !is_nonzero_integer(&journal[23]) || journal[26] != CanonicalCell::Integer(8) {
        return Err(format!("{label} terminal journal is incomplete"));
    }
    let operation = require_one_update(before, after, 2, label)?;
    let old_operation = operation.before.expect("update");
    let new_operation = operation.after.expect("update");
    require_exact_columns(&old_operation, &new_operation, &[2, 3], label)?;
    if new_operation[0] != journal[4]
        || old_operation[2].text("registration operation phase")? != b"prepared"
        || old_operation[3] != CanonicalCell::Integer(1)
        || new_operation[2].text("registration operation phase")? != b"committed"
        || new_operation[3] != CanonicalCell::Integer(0)
    {
        return Err(format!("{label} operation transition is not exact"));
    }
    let member = require_one_update(before, after, 5, label)?;
    let old_member = member.before.expect("update");
    let new_member = member.after.expect("update");
    require_exact_columns(&old_member, &new_member, &[16], label)?;
    if new_member[0] != journal[4]
        || new_member[1] != journal[6]
        || new_member[2] != journal[7]
        || new_member[3] != journal[8]
        || new_member[4] != journal[9]
        || old_member[16] != CanonicalCell::Integer(1)
        || new_member[16] != CanonicalCell::Integer(0)
    {
        return Err(format!("{label} member transition is not exact"));
    }
    let identity = row_mutations(before, after, 3)?;
    if identity.len() != 1 {
        return Err(format!("{label} must mutate exactly one identity row"));
    }
    let identity = &identity[0];
    if aborted {
        let old_identity = identity
            .before
            .as_ref()
            .filter(|_| identity.after.is_none())
            .ok_or_else(|| format!("{label} must delete the exact hidden identity"))?;
        if old_identity[0] != journal[6]
            || old_identity[1] != journal[7]
            || old_identity[2] != journal[8]
            || old_identity[3] != journal[9]
            || old_identity[4].text("aborted identity lifecycle")? != b"pending"
            || old_identity[5] != CanonicalCell::Integer(0)
            || old_identity[6] != journal[4]
        {
            return Err(format!("{label} deleted a mismatched identity"));
        }
    } else {
        let old_identity = identity
            .before
            .as_ref()
            .ok_or_else(|| format!("{label} did not update the hidden identity"))?;
        let new_identity = identity
            .after
            .as_ref()
            .ok_or_else(|| format!("{label} deleted the hidden identity"))?;
        require_exact_columns(old_identity, new_identity, &[4, 5, 6], label)?;
        if old_identity[0] != journal[6]
            || old_identity[4].text("hidden identity lifecycle")? != b"pending"
            || new_identity[4].text("published identity lifecycle")? != b"live"
            || new_identity[5] != CanonicalCell::Integer(1)
            || !is_null(&new_identity[6])
        {
            return Err(format!("{label} identity publication is not exact"));
        }
    }
    if component {
        let projection = row_mutations(before, after, 1)?;
        if projection.len() != 1 {
            return Err(format!("{label} must mutate one component projection"));
        }
        let projection = &projection[0];
        let old_projection = projection
            .before
            .as_ref()
            .ok_or_else(|| format!("{label} component projection preimage is missing"))?;
        if old_projection[0] != journal[6]
            || old_projection[2] != journal[8]
            || old_projection[3] != journal[9]
            || old_projection[4].text("hidden component lifecycle")? != b"live"
            || old_projection[5] != CanonicalCell::Integer(0)
            || old_projection[6] != journal[4]
        {
            return Err(format!("{label} component projection is mismatched"));
        }
        if aborted {
            if projection.after.is_some() {
                return Err(format!("{label} did not delete the hidden component"));
            }
        } else {
            let new_projection = projection
                .after
                .as_ref()
                .ok_or_else(|| format!("{label} deleted the component projection"))?;
            require_exact_columns(old_projection, new_projection, &[5, 6], label)?;
            if new_projection[5] != CanonicalCell::Integer(1) || !is_null(&new_projection[6]) {
                return Err(format!("{label} component publication is not exact"));
            }
        }
    }
    validate_capacity_row_update(before, after, 7, &[2, 3], label)
}

fn validate_termination_prepare_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let label = "tag-4 termination prepare";
    let operation = require_one_insert(before, after, 2, label)?;
    let operation = operation.after.expect("insert");
    let kind = operation[1].operation_kind()?;
    let component = kind == 4;
    if !matches!(kind, 3 | 4)
        || operation[2].text("termination prepare phase")? != b"prepared"
        || operation[3] != CanonicalCell::Integer(1)
        || !is_nonzero_integer(&operation[4])
        || !nonempty_blob(&operation[5])
    {
        return Err("tag-4 inserted a noncanonical termination operation".to_owned());
    }
    require_changed_tags(
        before,
        after,
        if component {
            &[1, 2, 3, 5, 8, 9]
        } else {
            &[2, 3, 5, 8, 9]
        },
        label,
    )?;
    let members = row_mutations(before, after, 5)?;
    if members.is_empty()
        || members
            .iter()
            .any(|mutation| mutation.before.is_some() || mutation.after.is_none())
    {
        return Err("tag-4 must insert a nonempty exact member cohort".to_owned());
    }
    let expected_class = if component {
        b"component".as_slice()
    } else {
        b"agent".as_slice()
    };
    let mut member_by_identity = BTreeMap::<Vec<u8>, Vec<CanonicalCell>>::new();
    for mutation in members {
        let member = mutation.after.expect("insert");
        if member[0] != operation[0]
            || member[2].text("termination member class")? != expected_class
            || !nonempty_blob(&member[5])
            || !nonempty_blob(&member[6])
            || !gc_cells_are_idle(&member)?
            || member[16] != CanonicalCell::Integer(1)
        {
            return Err("tag-4 inserted a malformed termination member".to_owned());
        }
        if member_by_identity
            .insert(member[1].text("termination member id")?.to_vec(), member)
            .is_some()
        {
            return Err("tag-4 inserted duplicate termination identities".to_owned());
        }
    }
    let identities = row_mutations(before, after, 3)?;
    if identities.len() != member_by_identity.len() {
        return Err("tag-4 did not transition the complete termination identity cohort".to_owned());
    }
    for mutation in identities {
        let old = mutation
            .before
            .as_ref()
            .ok_or_else(|| "tag-4 inserted an identity instead of terminating it".to_owned())?;
        let new = mutation
            .after
            .as_ref()
            .ok_or_else(|| "tag-4 deleted an identity during prepare".to_owned())?;
        require_exact_columns(old, new, &[4, 6, 8], label)?;
        let member = member_by_identity
            .get(old[0].text("termination identity id")?)
            .ok_or("tag-4 changed an identity outside its member cohort")?;
        if old[1] != member[2]
            || old[2] != member[3]
            || old[3] != member[4]
            || old[4].text("termination identity preimage")? != b"live"
            || old[5] != CanonicalCell::Integer(1)
            || is_null(&old[6]) == false
            || !is_null(&old[8])
            || new[4].text("termination identity postimage")? != b"terminating"
            || new[6] != operation[0]
            || new[8] != operation[4]
        {
            return Err("tag-4 termination identity transition is not exact".to_owned());
        }
    }
    if component {
        let projections = row_mutations(before, after, 1)?;
        if projections.len() != member_by_identity.len() {
            return Err("tag-4 did not transition the complete component cohort".to_owned());
        }
        for mutation in projections {
            let old = mutation
                .before
                .as_ref()
                .ok_or("tag-4 inserted a component projection")?;
            let new = mutation
                .after
                .as_ref()
                .ok_or("tag-4 deleted a component projection")?;
            require_exact_columns(old, new, &[4, 5, 6, 8], label)?;
            let member = member_by_identity
                .get(old[0].text("termination component id")?)
                .ok_or("tag-4 changed a component outside its member cohort")?;
            if old[2] != member[3]
                || old[3] != member[4]
                || old[4].text("component preimage lifecycle")? != b"live"
                || old[5] != CanonicalCell::Integer(1)
                || !is_null(&old[6])
                || !is_null(&old[8])
                || new[4].text("component postimage lifecycle")? != b"terminating"
                || new[5] != CanonicalCell::Integer(0)
                || new[6] != operation[0]
                || new[8] != operation[4]
            {
                return Err("tag-4 component transition is not exact".to_owned());
            }
        }
    }
    let finalization = require_one_insert(before, after, 8, label)?;
    let finalization = finalization.after.expect("insert");
    if finalization[0] != operation[0]
        || finalization[1].operation_kind()? != kind
        || finalization[8].text("termination journal phase")? != b"prepared"
        || finalization[2..=7]
            .iter()
            .any(|cell| !nonempty_blob(cell) && !is_nonzero_integer(cell))
        || finalization[9..=17].iter().any(|cell| !is_null(cell))
        || finalization[19].integer("termination future reservation")? == 0
    {
        return Err("tag-4 inserted a malformed finalization journal".to_owned());
    }
    let capacity = require_one_update(before, after, 9, label)?;
    let old_capacity = capacity.before.expect("update");
    let new_capacity = capacity.after.expect("update");
    require_exact_columns(&old_capacity, &new_capacity, &[1, 2, 3], label)?;
    let encoded = finalization[18].integer("termination prepared encoded bytes")?;
    let future = finalization[19].integer("termination prepared future bytes")?;
    if encoded.checked_add(future) != Some(TERMINATION_FINALIZE_TOTAL_BYTES)
        || old_capacity[1]
            .integer("termination capacity rows preimage")?
            .checked_add(1)
            != Some(new_capacity[1].integer("termination capacity rows postimage")?)
        || old_capacity[2]
            .integer("termination capacity actual preimage")?
            .checked_add(encoded)
            != Some(new_capacity[2].integer("termination capacity actual postimage")?)
        || old_capacity[3]
            .integer("termination capacity future preimage")?
            .checked_add(future)
            != Some(new_capacity[3].integer("termination capacity future postimage")?)
    {
        return Err("tag-4 termination capacity reservation is not exact".to_owned());
    }
    Ok(())
}

fn validate_termination_finalize_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let label = "tag-5 termination finalize";
    let operation = require_one_update(before, after, 2, label)?;
    let old_operation = operation.before.expect("update");
    let new_operation = operation.after.expect("update");
    require_exact_columns(&old_operation, &new_operation, &[2, 3], label)?;
    let kind = old_operation[1].operation_kind()?;
    let component = kind == 4;
    if !matches!(kind, 3 | 4)
        || old_operation[2].text("termination operation preimage")? != b"prepared"
        || old_operation[3] != CanonicalCell::Integer(1)
        || new_operation[2].text("termination operation postimage")? != b"committed"
        || new_operation[3] != CanonicalCell::Integer(0)
    {
        return Err("tag-5 termination operation transition is not exact".to_owned());
    }
    require_changed_tags(
        before,
        after,
        if component {
            &[1, 2, 3, 5, 8, 9]
        } else {
            &[2, 3, 5, 8, 9]
        },
        label,
    )?;
    let members = row_mutations(before, after, 5)?;
    if members.is_empty() {
        return Err("tag-5 finalized an empty member cohort".to_owned());
    }
    let mut member_by_identity = BTreeMap::<Vec<u8>, Vec<CanonicalCell>>::new();
    for mutation in members {
        let old = mutation.before.as_ref().ok_or("tag-5 inserted a member")?;
        let new = mutation.after.as_ref().ok_or("tag-5 deleted a member")?;
        require_exact_columns(old, new, &[16], label)?;
        if old[0] != old_operation[0]
            || old[16] != CanonicalCell::Integer(1)
            || new[16] != CanonicalCell::Integer(0)
        {
            return Err("tag-5 member finalization is not exact".to_owned());
        }
        member_by_identity.insert(old[1].text("finalized member id")?.to_vec(), new.clone());
    }
    let identities = row_mutations(before, after, 3)?;
    if identities.len() != member_by_identity.len() {
        return Err("tag-5 did not finalize the complete identity cohort".to_owned());
    }
    let mut terminal_at = None::<CanonicalCell>;
    for mutation in identities {
        let old = mutation
            .before
            .as_ref()
            .ok_or("tag-5 inserted an identity")?;
        let new = mutation.after.as_ref().ok_or("tag-5 deleted an identity")?;
        require_exact_columns(old, new, &[4, 7], label)?;
        let member = member_by_identity
            .get(old[0].text("finalized identity id")?)
            .ok_or("tag-5 finalized an identity outside its member cohort")?;
        if old[1] != member[2]
            || old[2] != member[3]
            || old[3] != member[4]
            || old[4].text("identity finalize preimage")? != b"terminating"
            || new[4].text("identity finalize postimage")? != b"tombstoned"
            || !is_nonzero_integer(&new[7])
        {
            return Err("tag-5 identity finalization is not exact".to_owned());
        }
        if terminal_at.get_or_insert_with(|| new[7].clone()) != &new[7] {
            return Err("tag-5 identity cohort used mixed tombstone timestamps".to_owned());
        }
    }
    if component {
        let projections = row_mutations(before, after, 1)?;
        if projections.len() != member_by_identity.len() {
            return Err("tag-5 did not finalize the complete component cohort".to_owned());
        }
        for mutation in projections {
            let old = mutation
                .before
                .as_ref()
                .ok_or("tag-5 inserted a component")?;
            let new = mutation.after.as_ref().ok_or("tag-5 deleted a component")?;
            require_exact_columns(old, new, &[4, 7], label)?;
            if !member_by_identity.contains_key(old[0].text("finalized component id")?)
                || old[4].text("component finalize preimage")? != b"terminating"
                || new[4].text("component finalize postimage")? != b"tombstoned"
                || Some(&new[7]) != terminal_at.as_ref()
            {
                return Err("tag-5 component finalization is not exact".to_owned());
            }
        }
    }
    let finalization = require_one_update(before, after, 8, label)?;
    let old_finalization = finalization.before.expect("update");
    let new_finalization = finalization.after.expect("update");
    require_exact_columns(
        &old_finalization,
        &new_finalization,
        &[8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19],
        label,
    )?;
    if old_finalization[0] != old_operation[0]
        || old_finalization[1].operation_kind()? != kind
        || old_finalization[8].text("finalization preimage phase")? != b"prepared"
        || new_finalization[8].text("finalization postimage phase")? != b"finalized"
        || old_finalization[..8] != new_finalization[..8]
        || new_finalization[9..=16]
            .iter()
            .any(|cell| !nonempty_blob(cell) && !is_nonzero_integer(cell))
        || new_finalization[16] != terminal_at.unwrap_or(CanonicalCell::Null)
        || new_finalization[19] != CanonicalCell::Integer(AUDIT_CHECKPOINT_BYTES)
    {
        return Err(
            "tag-5 rewrote frozen prepare receipts/ack or emitted an incomplete finalization"
                .to_owned(),
        );
    }
    let old_encoded = old_finalization[18].integer("finalization encoded preimage")?;
    let new_encoded = new_finalization[18].integer("finalization encoded postimage")?;
    let old_future = old_finalization[19].integer("finalization future preimage")?;
    let new_future = new_finalization[19].integer("finalization future postimage")?;
    let actual_delta = new_encoded
        .checked_sub(old_encoded)
        .ok_or("tag-5 finalization encoded bytes regressed")?;
    let future_delta = old_future
        .checked_sub(new_future)
        .ok_or("tag-5 finalization future bytes increased")?;
    let old_combined = old_encoded
        .checked_add(old_future)
        .ok_or("tag-5 prepared finalization byte total overflowed")?;
    let new_combined = new_encoded
        .checked_add(new_future)
        .ok_or("tag-5 terminal finalization byte total overflowed")?;
    if old_combined != TERMINATION_FINALIZE_TOTAL_BYTES || new_combined > old_combined {
        return Err("tag-5 finalization byte transfer is not exact".to_owned());
    }
    let capacity = require_one_update(before, after, 9, label)?;
    let old_capacity = capacity.before.expect("update");
    let new_capacity = capacity.after.expect("update");
    require_exact_columns(&old_capacity, &new_capacity, &[2, 3], label)?;
    if old_capacity[1] != new_capacity[1]
        || old_capacity[2]
            .integer("finalization capacity actual preimage")?
            .checked_add(actual_delta)
            != Some(new_capacity[2].integer("finalization capacity actual postimage")?)
        || old_capacity[3]
            .integer("finalization capacity future preimage")?
            .checked_sub(future_delta)
            != Some(new_capacity[3].integer("finalization capacity future postimage")?)
    {
        return Err("tag-5 finalization capacity transfer is not exact".to_owned());
    }
    Ok(())
}

fn validate_sealed_host_or_carrier_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let changed = changed_table_tags(before, after)?;
    if changed.is_empty() {
        // A tag-6 external artifact replacement can legitimately advance the
        // rooted ledger without changing one of the recursive SQLite tables.
        return Ok(());
    }
    if changed == [3, 4] {
        return validate_host_registration_effects(before, after);
    }
    validate_carrier_migration_effects(before, after)
}

fn validate_host_registration_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let label = "tag-6 sealed host registration";
    let identity = require_one_insert(before, after, 3, label)?;
    let identity = identity.after.expect("insert");
    if identity[1].text("host identity class")? != b"host"
        || identity[4].text("host lifecycle")? != b"permanent"
        || identity[5] != CanonicalCell::Integer(1)
        || !is_null(&identity[6])
        || !is_null(&identity[7])
        || !is_null(&identity[8])
    {
        return Err("tag-6 inserted a noncanonical permanent host".to_owned());
    }
    validate_authority_allocation(before, after, &identity, label)
}

fn validate_carrier_migration_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let label = "tag-6 carrier migration";
    let headers = row_mutations(before, after, 10)?;
    let rows = row_mutations(before, after, 11)?;
    if headers.len() != 1 {
        return Err("tag-6 carrier mutation must change exactly one header".to_owned());
    }
    let header = &headers[0];
    match (&header.before, &header.after) {
        (None, Some(new)) => {
            require_changed_tags(before, after, &[10], label)?;
            let phase = new[26].text("new carrier phase")?;
            if !matches!(phase, b"issuing" | b"verified")
                || new[22] != CanonicalCell::Integer(0)
                || new[23] != CanonicalCell::Integer(0)
                || new[24] != CanonicalCell::Integer(0)
                || !is_nonzero_integer(&new[27])
                || (phase == b"verified" && new[21] != CanonicalCell::Integer(0))
                || (phase == b"issuing" && !is_nonzero_integer(&new[21]))
            {
                return Err("tag-6 inserted a malformed carrier reservation".to_owned());
            }
            Ok(())
        }
        (Some(old), Some(new)) => {
            if old[..22] != new[..22] {
                return Err("tag-6 rewrote a frozen carrier plan/header identity".to_owned());
            }
            match (
                old[26].text("carrier preimage phase")?,
                new[26].text("carrier postimage phase")?,
                rows.as_slice(),
            ) {
                (b"issuing", b"issuing" | b"owner-ready", [row])
                    if row.before.is_none() && row.after.is_some() =>
                {
                    require_changed_tags(before, after, &[10, 11], label)?;
                    require_permitted_columns(
                        old,
                        new,
                        &[22, 24, 25, 27],
                        &[22, 24, 25, 26, 27],
                        label,
                    )?;
                    let inserted = row.after.as_ref().expect("guarded");
                    if inserted[0] != new[0]
                        || inserted[9].text("carrier row phase")? != b"prepared"
                        || !is_null(&inserted[10])
                        || !is_null(&inserted[11])
                        || old[22].integer("carrier issued preimage")?.checked_add(1)
                            != Some(new[22].integer("carrier issued postimage")?)
                        || new[24].integer("carrier actual postimage")?
                            <= old[24].integer("carrier actual preimage")?
                        || new[25].integer("carrier future postimage")?
                            >= old[25].integer("carrier future preimage")?
                    {
                        return Err("tag-6 carrier prepare row transition is not exact".to_owned());
                    }
                    Ok(())
                }
                (b"owner-ready", b"owner-ready" | b"verifying", [row])
                    if row.before.is_some() && row.after.is_some() =>
                {
                    require_changed_tags(before, after, &[10, 11], label)?;
                    require_permitted_columns(old, new, &[23, 24, 27], &[23, 24, 26, 27], label)?;
                    let row_old = row.before.as_ref().expect("guarded");
                    let row_new = row.after.as_ref().expect("guarded");
                    require_exact_columns(row_old, row_new, &[9, 10, 11, 12], label)?;
                    if row_old[0] != new[0]
                        || row_old[9].text("carrier row preimage phase")? != b"prepared"
                        || row_new[9].text("carrier row postimage phase")? != b"finalized"
                        || !nonempty_blob(&row_new[10])
                        || !is_nonzero_integer(&row_new[11])
                        || new[23].integer("carrier finalized postimage")?
                            != old[23]
                                .integer("carrier finalized preimage")?
                                .checked_add(1)
                                .ok_or("carrier finalized count overflow")?
                        || new[24].integer("carrier finalized actual bytes")?
                            <= old[24].integer("carrier prepared actual bytes")?
                    {
                        return Err("tag-6 carrier finalize row transition is not exact".to_owned());
                    }
                    Ok(())
                }
                (b"verifying", b"verified", []) => {
                    require_changed_tags(before, after, &[10], label)?;
                    require_exact_columns(old, new, &[26, 27], label)?;
                    if new[21] != new[22]
                        || new[21] != new[23]
                        || new[25] != CanonicalCell::Integer(0)
                    {
                        return Err("tag-6 carrier verification is incomplete".to_owned());
                    }
                    Ok(())
                }
                (old_phase, new_phase, _) => Err(format!(
                    "tag-6 carrier phase/row grammar is closed: {} -> {}",
                    String::from_utf8_lossy(old_phase),
                    String::from_utf8_lossy(new_phase)
                )),
            }
        }
        _ => Err("tag-6 cannot delete a carrier-migration header".to_owned()),
    }
}

fn validate_non_gc_tag_preserves_gc_fields(
    operation_tag: u8,
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let old = table_by_tag(before, 5)?;
    let new = table_by_tag(after, 5)?;
    let mut keys = BTreeSet::new();
    keys.extend(old.rows.keys().cloned());
    keys.extend(new.rows.keys().cloned());
    for key in keys {
        match (old.rows.get(&key), new.rows.get(&key)) {
            (Some(before_row), Some(after_row)) if before_row != after_row => {
                let before_cells = decode_canonical_row(5, before_row)?;
                let after_cells = decode_canonical_row(5, after_row)?;
                let gc_changed = before_cells[7..=15] != after_cells[7..=15];
                if gc_changed {
                    return Err(format!(
                        "operation tag {operation_tag} changed a closed gc_* member field"
                    ));
                }
            }
            (None, Some(after_row)) => {
                let cells = decode_canonical_row(5, after_row)?;
                if !gc_cells_are_idle(&cells)? {
                    return Err(format!(
                        "operation tag {operation_tag} inserted non-idle gc_* fields"
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_tag_eight_gc_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let mutations = row_mutations(before, after, 5)?;
    if mutations.is_empty()
        || mutations
            .iter()
            .any(|mutation| mutation.before.is_none() || mutation.after.is_none())
    {
        return Err("tag-8 must update a nonempty existing member cohort".to_owned());
    }
    let first_old = mutations[0].before.as_ref().expect("checked");
    let first_new = mutations[0].after.as_ref().expect("checked");
    let operation_id = first_old[0].text("tag-8 operation id")?.to_vec();
    let transition = (
        first_old[12].text("tag-8 preimage phase")?.to_vec(),
        first_new[12].text("tag-8 postimage phase")?.to_vec(),
    );
    let complete_preimage_count = table_by_tag(before, 5)?
        .rows
        .values()
        .map(|row| decode_canonical_row(5, row))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .filter(|cells| cells[0].text("member operation id") == Ok(operation_id.as_slice()))
        .count();
    if complete_preimage_count != mutations.len() {
        return Err("tag-8 changed only a partial operation-member cohort".to_owned());
    }
    let expected_metadata = first_new[9..=14].to_vec();
    let expected_prepared_metadata = first_old[9..=14].to_vec();
    let mut members = BTreeMap::<Vec<u8>, Vec<CanonicalCell>>::new();
    for mutation in &mutations {
        let old = mutation.before.as_ref().expect("checked");
        let new = mutation.after.as_ref().expect("checked");
        if old[0].text("tag-8 operation id")? != operation_id
            || old[..7] != new[..7]
            || old[16] != new[16]
            || old[16] != CanonicalCell::Integer(0)
            || (
                old[12].text("tag-8 preimage phase")?.to_vec(),
                new[12].text("tag-8 postimage phase")?.to_vec(),
            ) != transition
        {
            return Err("tag-8 mixed operations, phases, or non-GC member columns".to_owned());
        }
        validate_exact_gc_transition(old, new)?;
        if new[9..=14] != expected_metadata {
            return Err("tag-8 member cohort used mixed challenge metadata".to_owned());
        }
        if transition.0 == b"prepared" && old[9..=14] != expected_prepared_metadata {
            return Err("tag-8 collected a cohort with mixed prepared metadata".to_owned());
        }
        if transition.1 == b"collected" && (new[7] != first_new[7] || new[8] != first_new[8]) {
            return Err("tag-8 collected a cohort with mixed verified receipt metadata".to_owned());
        }
        if members
            .insert(old[1].text("tag-8 member identity")?.to_vec(), old.clone())
            .is_some()
        {
            return Err("tag-8 member cohort contains a duplicate identity".to_owned());
        }
    }
    match (transition.0.as_slice(), transition.1.as_slice()) {
        (b"idle" | b"prepared", b"prepared") => {
            require_changed_tags(before, after, &[5], "tag-8 PrepareGc")?;
            if !row_mutations(before, after, 1)?.is_empty()
                || !row_mutations(before, after, 3)?.is_empty()
            {
                return Err(
                    "tag-8 PrepareGc deleted or rewrote retained identities/components".to_owned(),
                );
            }
            Ok(())
        }
        (b"prepared", b"collected") => {
            let component_count = members
                .values()
                .filter(|member| member[2].text("GC member class") == Ok(b"component"))
                .count();
            require_changed_tags(
                before,
                after,
                if component_count == 0 {
                    &[3, 5]
                } else {
                    &[1, 3, 5]
                },
                "tag-8 CommitGc",
            )?;
            validate_gc_retained_deletions(before, after, &operation_id, &members, component_count)
        }
        _ => Err("tag-8 GC transition is not PrepareGc or CommitGc".to_owned()),
    }
}

fn validate_gc_retained_deletions(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    operation_id: &[u8],
    members: &BTreeMap<Vec<u8>, Vec<CanonicalCell>>,
    component_count: usize,
) -> Result<(), String> {
    let identities = row_mutations(before, after, 3)?;
    if identities.len() != members.len() {
        return Err(
            "tag-8 CommitGc did not delete the complete retained identity cohort".to_owned(),
        );
    }
    for mutation in identities {
        let old = mutation
            .before
            .as_ref()
            .filter(|_| mutation.after.is_none())
            .ok_or("tag-8 CommitGc inserted or updated an identity")?;
        let id = old[0].text("GC identity id")?;
        let member = members
            .get(id)
            .ok_or("tag-8 CommitGc deleted an identity outside the member cohort")?;
        if old[1] != member[2]
            || old[2] != member[3]
            || old[3] != member[4]
            || old[4].text("GC identity lifecycle")? != b"tombstoned"
            || old[5] != CanonicalCell::Integer(1)
            || old[6].text("GC identity operation")? != operation_id
            || !is_nonzero_integer(&old[7])
            || !is_nonzero_integer(&old[8])
        {
            return Err("tag-8 CommitGc identity deletion is not exact".to_owned());
        }
    }
    let components = row_mutations(before, after, 1)?;
    if components.len() != component_count {
        return Err("tag-8 CommitGc did not delete the exact retained component subset".to_owned());
    }
    for mutation in components {
        let old = mutation
            .before
            .as_ref()
            .filter(|_| mutation.after.is_none())
            .ok_or("tag-8 CommitGc inserted or updated a component")?;
        let id = old[0].text("GC component id")?;
        let member = members
            .get(id)
            .filter(|member| member[2].text("GC member class") == Ok(b"component"))
            .ok_or("tag-8 CommitGc deleted a component outside the member cohort")?;
        if old[2] != member[3]
            || old[3] != member[4]
            || old[4].text("GC component lifecycle")? != b"tombstoned"
            || old[6].text("GC component operation")? != operation_id
            || !is_nonzero_integer(&old[7])
        {
            return Err("tag-8 CommitGc component deletion is not exact".to_owned());
        }
    }
    Ok(())
}

fn validate_exact_gc_transition(
    before: &[CanonicalCell],
    after: &[CanonicalCell],
) -> Result<(), String> {
    let before_phase = before[12].text("preimage GC phase")?;
    let after_phase = after[12].text("postimage GC phase")?;
    let before_generation = before[13].integer("preimage GC generation")?;
    let after_generation = after[13].integer("postimage GC generation")?;
    match (before_phase, after_phase) {
        (b"idle", b"prepared") => {
            if !gc_cells_are_idle(before)?
                || after_generation != 1
                || !gc_cells_are_prepared(after)?
            {
                return Err("tag-8 idle-to-prepared GC transition is not exact".to_owned());
            }
        }
        (b"prepared", b"prepared") => {
            if !gc_cells_are_prepared(before)?
                || !gc_cells_are_prepared(after)?
                || before_generation.checked_add(1) != Some(after_generation)
                || before[7..=15] == after[7..=15]
            {
                return Err("tag-8 stale prepared challenge replacement is not exact".to_owned());
            }
        }
        (b"prepared", b"collected") => {
            if !gc_cells_are_prepared(before)?
                || !gc_cells_are_collected(after)?
                || before[9] != after[9]
                || before[10] != after[10]
                || before[11] != after[11]
                || before[13] != after[13]
                || before[14] != after[14]
            {
                return Err("tag-8 prepared-to-collected GC transition is not exact".to_owned());
            }
        }
        _ => {
            return Err(format!(
                "tag-8 GC phase transition is closed: {} -> {}",
                String::from_utf8_lossy(before_phase),
                String::from_utf8_lossy(after_phase)
            ));
        }
    }
    Ok(())
}

fn gc_cells_are_idle(cells: &[CanonicalCell]) -> Result<bool, String> {
    Ok(cells[7] == CanonicalCell::Null
        && cells[8] == CanonicalCell::Null
        && cells[9] == CanonicalCell::Null
        && cells[10] == CanonicalCell::Null
        && cells[11] == CanonicalCell::Null
        && cells[12].text("GC phase")? == b"idle"
        && cells[13].integer("GC generation")? == 0
        && cells[14] == CanonicalCell::Null
        && cells[15].integer("GC consumed bit")? == 0)
}

fn gc_cells_are_prepared(cells: &[CanonicalCell]) -> Result<bool, String> {
    Ok(cells[7] == CanonicalCell::Null
        && cells[8] == CanonicalCell::Null
        && nonempty_blob(&cells[9])
        && nonempty_blob(&cells[10])
        && nonempty_blob(&cells[11])
        && cells[12].text("GC phase")? == b"prepared"
        && cells[13].integer("GC generation")? > 0
        && matches!(cells[14], CanonicalCell::Integer(value) if value > 0)
        && cells[15].integer("GC consumed bit")? == 0)
}

fn gc_cells_are_collected(cells: &[CanonicalCell]) -> Result<bool, String> {
    Ok(nonempty_blob(&cells[7])
        && nonempty_blob(&cells[8])
        && nonempty_blob(&cells[9])
        && nonempty_blob(&cells[10])
        && nonempty_blob(&cells[11])
        && cells[12].text("GC phase")? == b"collected"
        && cells[13].integer("GC generation")? > 0
        && matches!(cells[14], CanonicalCell::Integer(value) if value > 0)
        && cells[15].integer("GC consumed bit")? == 1)
}

fn nonempty_blob(cell: &CanonicalCell) -> bool {
    matches!(cell, CanonicalCell::Blob(bytes) if !bytes.is_empty())
}

fn validate_tag_seven_effects(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<(), String> {
    let changed = changed_table_tags(before, after)?;
    if changed
        .iter()
        .any(|tag| !matches!(tag, 2 | 5 | 6 | 7 | 8 | 9))
    {
        return Err(format!(
            "tag-7 changed a table outside its closed compaction grammar: {changed:?}"
        ));
    }
    let mut deleted_operations = BTreeMap::<Vec<u8>, u8>::new();
    let mut deleted_members = BTreeMap::<Vec<u8>, u64>::new();
    let mut deleted_previsible = BTreeMap::<Vec<u8>, (u64, u64, u64)>::new();
    let mut deleted_finalizations = BTreeMap::<Vec<u8>, (u64, u64, u64)>::new();
    let mut checkpoint_values = BTreeSet::<u64>::new();
    let mut previsible_checkpoint_bytes = 0_u64;
    let mut finalization_checkpoint_bytes = 0_u64;

    validate_deleted_operations(before, after, &mut deleted_operations)?;
    validate_deleted_members(before, after, &deleted_operations, &mut deleted_members)?;
    validate_tag_seven_journal(
        6,
        before,
        after,
        &deleted_operations,
        &mut deleted_previsible,
        &mut checkpoint_values,
        &mut previsible_checkpoint_bytes,
    )?;
    validate_tag_seven_journal(
        8,
        before,
        after,
        &deleted_operations,
        &mut deleted_finalizations,
        &mut checkpoint_values,
        &mut finalization_checkpoint_bytes,
    )?;
    if checkpoint_values.len() > 1 {
        return Err("tag-7 installed more than one audit-checkpoint sequence".to_owned());
    }

    for (operation_id, kind) in &deleted_operations {
        let member_count = deleted_members.get(operation_id).copied().unwrap_or(0);
        if member_count == 0 {
            return Err("tag-7 deleted an operation without all inactive members".to_owned());
        }
        match kind {
            1 | 2 => {
                if deleted_previsible.get(operation_id).map(|entry| entry.0) != Some(1)
                    || deleted_finalizations.contains_key(operation_id)
                {
                    return Err(
                        "tag-7 registration deletion lacks its one terminal previsible journal"
                            .to_owned(),
                    );
                }
            }
            3 | 4 => {
                if deleted_finalizations.get(operation_id).map(|entry| entry.0) != Some(1)
                    || deleted_previsible.contains_key(operation_id)
                {
                    return Err(
                        "tag-7 termination deletion lacks its one finalized journal".to_owned()
                    );
                }
            }
            _ => return Err("tag-7 deleted an unknown operation kind".to_owned()),
        }
    }
    for operation_id in deleted_previsible
        .keys()
        .chain(deleted_finalizations.keys())
    {
        if !deleted_operations.contains_key(operation_id) {
            return Err("tag-7 deleted a journal without its whole operation".to_owned());
        }
    }

    let previsible_totals = sum_deleted_journals(&deleted_previsible)?;
    let finalize_totals = sum_deleted_journals(&deleted_finalizations)?;
    validate_capacity_transition(
        7,
        before,
        after,
        previsible_totals,
        previsible_checkpoint_bytes,
    )?;
    validate_capacity_transition(
        9,
        before,
        after,
        finalize_totals,
        finalization_checkpoint_bytes,
    )?;
    Ok(())
}

fn validate_deleted_operations(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    deleted: &mut BTreeMap<Vec<u8>, u8>,
) -> Result<(), String> {
    let old = table_by_tag(before, 2)?;
    let new = table_by_tag(after, 2)?;
    let mut keys = BTreeSet::new();
    keys.extend(old.rows.keys().cloned());
    keys.extend(new.rows.keys().cloned());
    for key in keys {
        match (old.rows.get(&key), new.rows.get(&key)) {
            (Some(row), None) => {
                let cells = decode_canonical_row(2, row)?;
                if cells[2].text("deleted operation phase")? != b"committed"
                    || cells[3].integer("deleted operation active bit")? != 0
                {
                    return Err("tag-7 deleted a nonterminal operation".to_owned());
                }
                deleted.insert(
                    cells[0].text("deleted operation id")?.to_vec(),
                    cells[1].operation_kind()?,
                );
            }
            (None, Some(_)) => return Err("tag-7 inserted an operation".to_owned()),
            (Some(before_row), Some(after_row)) if before_row != after_row => {
                return Err("tag-7 updated an operation row".to_owned());
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_deleted_members(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    operations: &BTreeMap<Vec<u8>, u8>,
    deleted: &mut BTreeMap<Vec<u8>, u64>,
) -> Result<(), String> {
    let old = table_by_tag(before, 5)?;
    let new = table_by_tag(after, 5)?;
    let mut keys = BTreeSet::new();
    keys.extend(old.rows.keys().cloned());
    keys.extend(new.rows.keys().cloned());
    for key in keys {
        match (old.rows.get(&key), new.rows.get(&key)) {
            (Some(row), None) => {
                let cells = decode_canonical_row(5, row)?;
                let operation_id = cells[0].text("deleted member operation id")?.to_vec();
                let kind = operations
                    .get(&operation_id)
                    .ok_or("tag-7 deleted a member without its operation")?;
                if cells[16].integer("deleted member active bit")? != 0
                    || (matches!(kind, 1 | 2) && !gc_cells_are_idle(&cells)?)
                    || (matches!(kind, 3 | 4) && !gc_cells_are_collected(&cells)?)
                {
                    return Err(
                        "tag-7 member deletion is not inactive registration/collected termination"
                            .to_owned(),
                    );
                }
                let count = deleted.entry(operation_id).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or("deleted member count overflow")?;
            }
            (None, Some(_)) => return Err("tag-7 inserted an operation member".to_owned()),
            (Some(before_row), Some(after_row)) if before_row != after_row => {
                return Err("tag-7 updated an operation member".to_owned());
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_tag_seven_journal(
    tag: u8,
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    operations: &BTreeMap<Vec<u8>, u8>,
    deleted: &mut BTreeMap<Vec<u8>, (u64, u64, u64)>,
    checkpoint_values: &mut BTreeSet<u64>,
    checkpoint_actual_bytes: &mut u64,
) -> Result<(), String> {
    let old = table_by_tag(before, tag)?;
    let new = table_by_tag(after, tag)?;
    let (operation_index, phase_index, audit_index, encoded_index, future_index) = match tag {
        6 => (4, 11, 24, 25, 26),
        8 => (0, 8, 17, 18, 19),
        _ => return Err("tag-7 journal validator received an unknown table".to_owned()),
    };
    let mut keys = BTreeSet::new();
    keys.extend(old.rows.keys().cloned());
    keys.extend(new.rows.keys().cloned());
    for key in keys {
        match (old.rows.get(&key), new.rows.get(&key)) {
            (Some(row), None) => {
                let cells = decode_canonical_row(tag, row)?;
                let operation_id = cells[operation_index]
                    .text("deleted journal operation id")?
                    .to_vec();
                let terminal = match tag {
                    6 => matches!(
                        cells[phase_index].text("activation phase")?,
                        b"published" | b"aborted"
                    ),
                    8 => cells[phase_index].text("finalization phase")? == b"finalized",
                    _ => false,
                };
                if !terminal
                    || !matches!(cells[audit_index], CanonicalCell::Integer(value) if value > 0)
                    || cells[future_index].integer("deleted journal future bytes")? != 0
                    || !operations.contains_key(&operation_id)
                {
                    return Err("tag-7 deleted an uncheckpointed/nonterminal journal".to_owned());
                }
                if deleted
                    .insert(
                        operation_id,
                        (
                            1,
                            cells[encoded_index].integer("deleted journal encoded bytes")?,
                            cells[future_index].integer("deleted journal future bytes")?,
                        ),
                    )
                    .is_some()
                {
                    return Err("tag-7 deleted duplicate journals for one operation".to_owned());
                }
            }
            (None, Some(_)) => return Err("tag-7 inserted a replay journal".to_owned()),
            (Some(before_row), Some(after_row)) if before_row != after_row => {
                let before_cells = decode_canonical_row(tag, before_row)?;
                let after_cells = decode_canonical_row(tag, after_row)?;
                for index in 0..before_cells.len() {
                    if index != audit_index
                        && index != encoded_index
                        && index != future_index
                        && before_cells[index] != after_cells[index]
                    {
                        return Err(
                            "tag-7 changed a journal column outside checkpoint accounting"
                                .to_owned(),
                        );
                    }
                }
                if before_cells[audit_index] != CanonicalCell::Null {
                    return Err("tag-7 overwrote an installed audit checkpoint".to_owned());
                }
                let checkpoint = after_cells[audit_index].integer("audit checkpoint sequence")?;
                if checkpoint == 0 {
                    return Err("tag-7 installed audit checkpoint zero".to_owned());
                }
                let before_encoded =
                    before_cells[encoded_index].integer("pre-checkpoint journal encoded bytes")?;
                let after_encoded =
                    after_cells[encoded_index].integer("post-checkpoint journal encoded bytes")?;
                if before_encoded.checked_add(8) != Some(after_encoded)
                    || before_cells[future_index].integer("pre-checkpoint journal future bytes")?
                        != 8
                    || after_cells[future_index].integer("post-checkpoint journal future bytes")?
                        != 0
                {
                    return Err(
                        "tag-7 checkpoint did not move the exact eight future bytes into actual"
                            .to_owned(),
                    );
                }
                let terminal = match tag {
                    6 => matches!(
                        after_cells[phase_index].text("activation phase")?,
                        b"published" | b"aborted"
                    ),
                    8 => after_cells[phase_index].text("finalization phase")? == b"finalized",
                    _ => false,
                };
                if !terminal {
                    return Err("tag-7 checkpointed a nonterminal journal".to_owned());
                }
                checkpoint_values.insert(checkpoint);
                *checkpoint_actual_bytes = checkpoint_actual_bytes
                    .checked_add(8)
                    .ok_or("checkpoint accounting byte overflow")?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn sum_deleted_journals(
    rows: &BTreeMap<Vec<u8>, (u64, u64, u64)>,
) -> Result<(u64, u64, u64), String> {
    rows.values().try_fold((0_u64, 0_u64, 0_u64), |sum, row| {
        Ok((
            sum.0
                .checked_add(row.0)
                .ok_or("deleted row count overflow")?,
            sum.1
                .checked_add(row.1)
                .ok_or("deleted byte count overflow")?,
            sum.2
                .checked_add(row.2)
                .ok_or("deleted future count overflow")?,
        ))
    })
}

fn validate_capacity_transition(
    tag: u8,
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
    deleted: (u64, u64, u64),
    installed_actual: u64,
) -> Result<(), String> {
    let old = table_by_tag(before, tag)?;
    let new = table_by_tag(after, tag)?;
    let key = 1_u64.to_be_bytes().to_vec();
    let before_row = old
        .rows
        .get(&key)
        .ok_or("missing preimage capacity singleton")?;
    let after_row = new
        .rows
        .get(&key)
        .ok_or("missing postimage capacity singleton")?;
    let before_cells = decode_canonical_row(tag, before_row)?;
    let after_cells = decode_canonical_row(tag, after_row)?;
    if before_cells[0] != after_cells[0]
        || before_cells[1]
            .integer("preimage capacity rows")?
            .checked_sub(deleted.0)
            != Some(after_cells[1].integer("postimage capacity rows")?)
        || before_cells[2]
            .integer("preimage capacity actual")?
            .checked_add(installed_actual)
            .ok_or("checkpoint capacity actual overflow")?
            .checked_sub(deleted.1)
            != Some(after_cells[2].integer("postimage capacity actual")?)
        || before_cells[3]
            .integer("preimage capacity future")?
            .checked_sub(installed_actual)
            .ok_or("checkpoint capacity future underflow")?
            .checked_sub(deleted.2)
            != Some(after_cells[3].integer("postimage capacity future")?)
    {
        return Err(format!(
            "tag-7 table {tag} capacity transition does not equal checkpoints/deleted journals"
        ));
    }
    Ok(())
}

fn table_by_tag(snapshot: &RegistrySnapshot, tag: u8) -> Result<&CanonicalTable, String> {
    snapshot
        .tables
        .iter()
        .find(|table| table.tag == tag)
        .ok_or_else(|| format!("canonical snapshot is missing table tag {tag}"))
}

fn canonical_row_kinds(tag: u8) -> Result<&'static [Kind], String> {
    let kinds: &'static [Kind] = match tag {
        1 => &[
            Kind::Text,
            Kind::Blob,
            Kind::Int,
            Kind::Blob,
            Kind::Text,
            Kind::Int,
            Kind::OptText,
            Kind::OptInt,
            Kind::OptInt,
        ],
        2 => &[
            Kind::Text,
            Kind::OperationKind,
            Kind::Text,
            Kind::Int,
            Kind::OptInt,
            Kind::OptBlob,
        ],
        3 => &[
            Kind::Text,
            Kind::Text,
            Kind::Int,
            Kind::Blob,
            Kind::Text,
            Kind::Int,
            Kind::OptText,
            Kind::OptInt,
            Kind::OptInt,
        ],
        4 => &[Kind::Text, Kind::Text, Kind::Int, Kind::Blob],
        5 => &[
            Kind::Text,
            Kind::Text,
            Kind::Text,
            Kind::Int,
            Kind::Blob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::Text,
            Kind::Int,
            Kind::OptInt,
            Kind::Int,
            Kind::Int,
        ],
        6 => &[
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Int,
            Kind::Text,
            Kind::OperationKind,
            Kind::Text,
            Kind::Text,
            Kind::Int,
            Kind::Blob,
            Kind::Int,
            Kind::Text,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::Int,
            Kind::OptInt,
            Kind::OptInt,
            Kind::Int,
            Kind::Int,
        ],
        7 | 9 => &[Kind::Int, Kind::Int, Kind::Int, Kind::Int],
        8 => &[
            Kind::Text,
            Kind::OperationKind,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Int,
            Kind::Blob,
            Kind::Text,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptBlob,
            Kind::OptInt,
            Kind::OptBlob,
            Kind::OptInt,
            Kind::OptInt,
            Kind::Int,
            Kind::Int,
        ],
        10 => &[
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Int,
            Kind::Int,
            Kind::Blob,
            Kind::Blob,
            Kind::Int,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Int,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Int,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Int,
            Kind::Int,
            Kind::Int,
            Kind::Int,
            Kind::Int,
            Kind::Text,
            Kind::Int,
        ],
        11 => &[
            Kind::Blob,
            Kind::Int,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Blob,
            Kind::Text,
            Kind::OptBlob,
            Kind::OptInt,
            Kind::Int,
        ],
        _ => return Err(format!("no structured decoder for table tag {tag}")),
    };
    Ok(kinds)
}

fn decode_canonical_row(tag: u8, row: &[u8]) -> Result<Vec<CanonicalCell>, String> {
    let kinds = canonical_row_kinds(tag)?;
    let mut offset = 0_usize;
    let mut cells = Vec::with_capacity(kinds.len());
    for kind in kinds {
        cells.push(decode_cell(row, &mut offset, *kind)?);
    }
    if offset != row.len() {
        return Err(format!(
            "canonical row for table tag {tag} has trailing bytes"
        ));
    }
    Ok(cells)
}

fn decode_cell(row: &[u8], offset: &mut usize, kind: Kind) -> Result<CanonicalCell, String> {
    match kind {
        Kind::OptInt | Kind::OptText | Kind::OptBlob => {
            let present = take(row, offset, 1)?[0];
            match present {
                0 => Ok(CanonicalCell::Null),
                1 => decode_cell(
                    row,
                    offset,
                    match kind {
                        Kind::OptInt => Kind::Int,
                        Kind::OptText => Kind::Text,
                        Kind::OptBlob => Kind::Blob,
                        _ => unreachable!(),
                    },
                ),
                _ => Err("canonical optional field has an invalid presence byte".to_owned()),
            }
        }
        Kind::Int => {
            let bytes: [u8; 8] = take(row, offset, 8)?
                .try_into()
                .map_err(|_| "canonical integer width")?;
            Ok(CanonicalCell::Integer(u64::from_be_bytes(bytes)))
        }
        Kind::Text | Kind::Blob => {
            let len: [u8; 4] = take(row, offset, 4)?
                .try_into()
                .map_err(|_| "canonical length width")?;
            let value = take(row, offset, u32::from_be_bytes(len) as usize)?.to_vec();
            if matches!(kind, Kind::Text) {
                validate_utf8_text(&value, "canonical text")?;
            }
            Ok(match kind {
                Kind::Text => CanonicalCell::Text(value),
                Kind::Blob => CanonicalCell::Blob(value),
                _ => unreachable!(),
            })
        }
        Kind::OperationKind => {
            let value = take(row, offset, 1)?[0];
            if !(1..=4).contains(&value) {
                return Err("canonical operation kind byte is unknown".to_owned());
            }
            Ok(CanonicalCell::OperationKind(value))
        }
    }
}

fn take<'a>(row: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(len)
        .ok_or("canonical row offset overflow")?;
    let value = row.get(*offset..end).ok_or("canonical row is truncated")?;
    *offset = end;
    Ok(value)
}

fn changed_table_tags(
    before: &RegistrySnapshot,
    after: &RegistrySnapshot,
) -> Result<Vec<u8>, String> {
    if before.tables.len() != 11 || after.tables.len() != 11 {
        return Err("operation-effect validation requires eleven tables".to_owned());
    }
    let mut changed = Vec::new();
    for (old, new) in before.tables.iter().zip(&after.tables) {
        if old.tag != new.tag {
            return Err("operation-effect table tags differ".to_owned());
        }
        if old.rows != new.rows {
            changed.push(old.tag);
        }
    }
    Ok(changed)
}

fn table(
    conn: &Connection,
    tag: u8,
    query: &str,
    key_shape: Key,
    kinds: &[Kind],
) -> Result<CanonicalTable, String> {
    let mut stmt = conn.prepare(query).map_err(sql)?;
    if stmt.column_count() != kinds.len() {
        return Err(format!(
            "table tag {tag} selected {} columns, expected {}",
            stmt.column_count(),
            kinds.len()
        ));
    }
    let mut cursor = stmt.query([]).map_err(sql)?;
    let mut rows = BTreeMap::new();
    while let Some(row) = cursor.next().map_err(sql)? {
        let key = canonical_key(row, key_shape)?;
        let mut encoded = Vec::new();
        for (index, kind) in kinds.iter().copied().enumerate() {
            encode_value(&mut encoded, row.get_ref(index).map_err(sql)?, kind)?;
        }
        if rows.insert(key, encoded).is_some() {
            return Err(format!("duplicate canonical key in table tag {tag}"));
        }
    }
    Ok(CanonicalTable { tag, rows })
}

fn canonical_key(row: &Row<'_>, shape: Key) -> Result<Vec<u8>, String> {
    match shape {
        Key::Text(index) => framed_text_key(row.get_ref(index).map_err(sql)?),
        Key::TwoText(first, second) => {
            let mut key = framed_text_key(row.get_ref(first).map_err(sql)?)?;
            key.extend_from_slice(&framed_text_key(row.get_ref(second).map_err(sql)?)?);
            Ok(key)
        }
        Key::Blob32(index) => exact_blob_key(row.get_ref(index).map_err(sql)?, 32),
        Key::Singleton(index) => match row.get_ref(index).map_err(sql)? {
            ValueRef::Integer(1) => Ok(1_u64.to_be_bytes().to_vec()),
            _ => Err("canonical singleton primary key is not integer 1".to_owned()),
        },
        Key::Blob16(index) => exact_blob_key(row.get_ref(index).map_err(sql)?, 16),
        Key::MigrationRow {
            migration,
            store_kind,
            event_digest,
        } => {
            let mut key = exact_blob_key(row.get_ref(migration).map_err(sql)?, 16)?;
            let store = match row.get_ref(store_kind).map_err(sql)? {
                ValueRef::Integer(value @ 1..=2) => value as u8,
                _ => return Err("canonical migration store kind is outside 1..=2".to_owned()),
            };
            key.push(store);
            key.extend_from_slice(&exact_blob_key(
                row.get_ref(event_digest).map_err(sql)?,
                32,
            )?);
            Ok(key)
        }
    }
}

fn framed_text_key(value: ValueRef<'_>) -> Result<Vec<u8>, String> {
    let ValueRef::Text(bytes) = value else {
        return Err("canonical text primary key has the wrong SQLite type".to_owned());
    };
    validate_text_primary_key(bytes, "canonical text primary key")?;
    let mut key = Vec::new();
    put_vec_len(&mut key, bytes.len())?;
    key.extend_from_slice(bytes);
    Ok(key)
}

fn exact_blob_key(value: ValueRef<'_>, width: usize) -> Result<Vec<u8>, String> {
    let ValueRef::Blob(bytes) = value else {
        return Err("canonical blob primary key has the wrong SQLite type".to_owned());
    };
    if bytes.len() != width {
        return Err(format!("canonical blob primary key is not {width} bytes"));
    }
    Ok(bytes.to_vec())
}

fn encode_value(out: &mut Vec<u8>, value: ValueRef<'_>, kind: Kind) -> Result<(), String> {
    match kind {
        Kind::OptInt | Kind::OptText | Kind::OptBlob if matches!(value, ValueRef::Null) => {
            out.push(0);
            Ok(())
        }
        Kind::OptInt => {
            out.push(1);
            encode_value(out, value, Kind::Int)
        }
        Kind::OptText => {
            out.push(1);
            encode_value(out, value, Kind::Text)
        }
        Kind::OptBlob => {
            out.push(1);
            encode_value(out, value, Kind::Blob)
        }
        Kind::Int => match value {
            ValueRef::Integer(value) if value >= 0 => {
                out.extend_from_slice(&(value as u64).to_be_bytes());
                Ok(())
            }
            _ => {
                Err("canonical integer is negative, null, or has the wrong SQLite type".to_owned())
            }
        },
        Kind::Text => match value {
            ValueRef::Text(bytes) => {
                validate_utf8_text(bytes, "canonical text")?;
                put_vec_len(out, bytes.len())?;
                out.extend_from_slice(bytes);
                Ok(())
            }
            _ => Err("canonical text has the wrong SQLite type".to_owned()),
        },
        Kind::Blob => match value {
            ValueRef::Blob(bytes) => {
                put_vec_len(out, bytes.len())?;
                out.extend_from_slice(bytes);
                Ok(())
            }
            _ => Err("canonical blob has the wrong SQLite type".to_owned()),
        },
        Kind::OperationKind => match value {
            ValueRef::Text(b"register-agent") => {
                out.push(1);
                Ok(())
            }
            ValueRef::Text(b"register-component") => {
                out.push(2);
                Ok(())
            }
            ValueRef::Text(b"terminate-agents") => {
                out.push(3);
                Ok(())
            }
            ValueRef::Text(b"terminate-component") => {
                out.push(4);
                Ok(())
            }
            _ => Err("canonical operation kind is unknown or has the wrong SQLite type".to_owned()),
        },
    }
}

fn validate_utf8_text(bytes: &[u8], label: &str) -> Result<(), String> {
    std::str::from_utf8(bytes)
        .map(|_| ())
        .map_err(|_| format!("{label} is not valid UTF-8"))
}

fn validate_text_primary_key(bytes: &[u8], label: &str) -> Result<(), String> {
    validate_utf8_text(bytes, label)?;
    if !(1..=MAX_CANONICAL_TEXT_PRIMARY_KEY_BYTES).contains(&bytes.len()) {
        return Err(format!(
            "{label} length is outside 1..={MAX_CANONICAL_TEXT_PRIMARY_KEY_BYTES} bytes"
        ));
    }
    Ok(())
}

fn put_len(hasher: &mut Sha256, len: usize) -> Result<(), String> {
    let len = u32::try_from(len).map_err(|_| "canonical field exceeds u32")?;
    hasher.update(len.to_be_bytes());
    Ok(())
}

fn put_vec_len(out: &mut Vec<u8>, len: usize) -> Result<(), String> {
    let len = u32::try_from(len).map_err(|_| "canonical field exceeds u32")?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn sql(error: rusqlite::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SyntheticFixtureAnchor;

    impl crate::observation_anchor::RegistryAnchorTransaction for SyntheticFixtureAnchor {
        fn observe(
            &self,
        ) -> Result<
            crate::observation_anchor::RegistryAnchorWorld,
            crate::observation_anchor::RegistryAnchorError,
        > {
            Err(crate::observation_anchor::RegistryAnchorError::Uninitialized)
        }

        fn anchor_lease_tag(
            &self,
            _challenge: [u8; 32],
        ) -> Result<[u8; 32], crate::observation_anchor::RegistryAnchorError> {
            Ok([0x5a; 32])
        }

        fn authenticate_role_allocation_artifacts(
            &self,
            _current: &crate::observation_anchor::RegistryAnchorTuple,
            _head_context: &crate::observation_anchor::RegistryHeadContext,
            _previous_manifest_bytes: &[u8],
            _next_manifest_bytes: &[u8],
        ) -> Result<(), crate::observation_anchor::RegistryAnchorError> {
            Ok(())
        }

        fn authenticate_persisted_keyring_artifacts(
            &self,
            _current: &crate::observation_anchor::RegistryAnchorTuple,
            _head_context: &crate::observation_anchor::RegistryHeadContext,
            _previous_file_bytes: &[u8],
            _next_file_bytes: &[u8],
        ) -> Result<(), crate::observation_anchor::RegistryAnchorError> {
            Ok(())
        }

        fn authenticate_legacy_migration_artifacts(
            &self,
            _migration_block: &[u8],
            _prepared_marker: &[u8],
            _installed_marker: &[u8],
            _complete_marker: &[u8],
            _initial_keyring_file: &[u8],
            _initial_role_allocation_file: &[u8],
        ) -> Result<(), crate::observation_anchor::RegistryAnchorError> {
            Ok(())
        }

        fn authenticate_legacy_marker_transition_artifacts(
            &self,
            _previous: &crate::observation_anchor::RegistryAnchorTuple,
            _next: &crate::observation_anchor::RegistryAnchorTuple,
            _head_context: &crate::observation_anchor::RegistryHeadContext,
            _previous_marker: &[u8],
            _next_marker: &[u8],
        ) -> Result<(), crate::observation_anchor::RegistryAnchorError> {
            Ok(())
        }

        fn initialize_compact(
            &self,
            _genesis: crate::observation_anchor::VerifiedEmptyRegistryGenesis,
        ) -> Result<(), crate::observation_anchor::RegistryAnchorError> {
            Err(crate::observation_anchor::RegistryAnchorError::InvalidTransition)
        }

        fn prepare_current(
            &self,
            _mutation: crate::observation_anchor::RegistryAnchorMutation,
        ) -> Result<
            Box<dyn crate::observation_anchor::PreparedCurrent>,
            crate::observation_anchor::RegistryAnchorError,
        > {
            Err(crate::observation_anchor::RegistryAnchorError::InvalidTransition)
        }

        fn recover(
            &self,
            _capability: crate::observation_anchor::RegistryRecoveryCapability,
        ) -> Result<(), crate::observation_anchor::RegistryAnchorError> {
            Err(crate::observation_anchor::RegistryAnchorError::InvalidTransition)
        }
    }

    fn empty_snapshot() -> RegistrySnapshot {
        RegistrySnapshot {
            tables: (1..=11)
                .map(|tag| CanonicalTable {
                    tag,
                    rows: BTreeMap::new(),
                })
                .collect(),
        }
    }

    fn encode_test_row(tag: u8, cells: &[CanonicalCell]) -> Vec<u8> {
        fn encode_cell(out: &mut Vec<u8>, kind: Kind, cell: &CanonicalCell) {
            match (kind, cell) {
                (Kind::OptInt | Kind::OptText | Kind::OptBlob, CanonicalCell::Null) => out.push(0),
                (Kind::OptInt, cell) => {
                    out.push(1);
                    encode_cell(out, Kind::Int, cell);
                }
                (Kind::OptText, cell) => {
                    out.push(1);
                    encode_cell(out, Kind::Text, cell);
                }
                (Kind::OptBlob, cell) => {
                    out.push(1);
                    encode_cell(out, Kind::Blob, cell);
                }
                (Kind::Int, CanonicalCell::Integer(value)) => {
                    out.extend_from_slice(&value.to_be_bytes())
                }
                (Kind::Text, CanonicalCell::Text(value))
                | (Kind::Blob, CanonicalCell::Blob(value)) => literal_len(out, value),
                (Kind::OperationKind, CanonicalCell::OperationKind(value)) => out.push(*value),
                _ => panic!("test cell does not match canonical kind"),
            }
        }

        let kinds = canonical_row_kinds(tag).unwrap();
        assert_eq!(kinds.len(), cells.len());
        let mut row = Vec::new();
        for (kind, cell) in kinds.iter().copied().zip(cells) {
            encode_cell(&mut row, kind, cell);
        }
        row
    }

    fn replace_snapshot_cell(
        snapshot: &mut RegistrySnapshot,
        tag: u8,
        key: &[u8],
        index: usize,
        replacement: CanonicalCell,
    ) {
        let table = snapshot.tables.get_mut(usize::from(tag - 1)).unwrap();
        let row = table.rows.get_mut(key).expect("fixture row");
        let mut cells = decode_canonical_row(tag, row).unwrap();
        cells[index] = replacement;
        *row = encode_test_row(tag, &cells);
        assert_eq!(canonical_key_from_encoded_row(tag, row).unwrap(), key);
    }

    fn text_key(value: &[u8]) -> Vec<u8> {
        let mut key = Vec::new();
        literal_len(&mut key, value);
        key
    }

    fn two_text_key(first: &[u8], second: &[u8]) -> Vec<u8> {
        let mut key = text_key(first);
        literal_len(&mut key, second);
        key
    }

    fn literal_len(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    fn literal_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn literal_carrier_header(seed: u8) -> Vec<u8> {
        let mut row = Vec::new();
        literal_len(&mut row, &[seed; 16]);
        literal_len(&mut row, &[seed.wrapping_add(1); 16]);
        literal_len(&mut row, &[seed.wrapping_add(2); 16]);
        literal_u64(&mut row, u64::from(seed) + 1);
        literal_u64(&mut row, u64::from(seed) + 10);
        for value in seed.wrapping_add(3)..=seed.wrapping_add(4) {
            literal_len(&mut row, &[value; 32]);
        }
        literal_u64(&mut row, u64::from(seed) + 20);
        for value in seed.wrapping_add(5)..=seed.wrapping_add(7) {
            literal_len(&mut row, &[value; 32]);
        }
        literal_u64(&mut row, u64::from(seed) + 30);
        for value in seed.wrapping_add(8)..=seed.wrapping_add(10) {
            literal_len(&mut row, &[value; 32]);
        }
        literal_u64(&mut row, u64::from(seed) + 40);
        for value in seed.wrapping_add(11)..=seed.wrapping_add(15) {
            literal_len(&mut row, &[value; 32]);
        }
        literal_u64(&mut row, 1);
        literal_u64(&mut row, 1);
        literal_u64(&mut row, 1);
        literal_u64(&mut row, 500);
        literal_u64(&mut row, 0);
        literal_len(&mut row, b"verified");
        literal_u64(&mut row, u64::from(seed) + 50);
        row
    }

    fn literal_carrier_row_with_event_and_nonce(
        seed: u8,
        store_kind: u8,
        event_digest_byte: u8,
        receipt_nonce_byte: u8,
    ) -> Vec<u8> {
        let mut row = Vec::new();
        literal_len(&mut row, &[seed; 16]);
        literal_u64(&mut row, u64::from(store_kind));
        literal_len(&mut row, &[event_digest_byte; 32]);
        literal_len(&mut row, &[seed.wrapping_add(17); 32]);
        literal_len(&mut row, &[receipt_nonce_byte; 32]);
        literal_len(&mut row, &vec![seed.wrapping_add(19); 300]);
        for value in seed.wrapping_add(20)..=seed.wrapping_add(22) {
            literal_len(&mut row, &[value; 32]);
        }
        literal_len(&mut row, b"finalized");
        row.push(1);
        literal_len(&mut row, &[seed.wrapping_add(23); 32]);
        row.push(1);
        literal_u64(&mut row, u64::from(seed) + 60);
        literal_u64(&mut row, 500);
        row
    }

    fn literal_carrier_row_with_event(seed: u8, store_kind: u8, event_digest_byte: u8) -> Vec<u8> {
        literal_carrier_row_with_event_and_nonce(
            seed,
            store_kind,
            event_digest_byte,
            seed.wrapping_add(18),
        )
    }

    fn literal_carrier_row(seed: u8, store_kind: u8) -> Vec<u8> {
        literal_carrier_row_with_event(seed, store_kind, seed.wrapping_add(16))
    }

    fn literal_carrier_row_key_with_event(
        seed: u8,
        store_kind: u8,
        event_digest_byte: u8,
    ) -> Vec<u8> {
        let mut key = vec![seed; 16];
        key.push(store_kind);
        key.extend_from_slice(&[event_digest_byte; 32]);
        key
    }

    fn literal_carrier_row_key(seed: u8, store_kind: u8) -> Vec<u8> {
        literal_carrier_row_key_with_event(seed, store_kind, seed.wrapping_add(16))
    }

    fn snapshot_with_capacity_singletons() -> RegistrySnapshot {
        let mut snapshot = empty_snapshot();
        let mut row = Vec::new();
        for value in [1_u64, 0, 0, 0] {
            literal_u64(&mut row, value);
        }
        for tag in [7_u8, 9] {
            snapshot.tables[usize::from(tag - 1)]
                .rows
                .insert(1_u64.to_be_bytes().to_vec(), row.clone());
        }
        snapshot
    }

    fn install_sql_carrier_header(conn: &Connection, seed: u8) {
        let migration = vec![seed; 16];
        conn.execute(
            "INSERT INTO observation_carrier_migrations VALUES
             (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,
              ?15,?16,?17,?18,?19,?20,?21,1,1,1,500,0,'verified',?22)",
            rusqlite::params![
                migration,
                vec![seed.wrapping_add(1); 16],
                vec![seed.wrapping_add(2); 16],
                i64::from(seed) + 1,
                i64::from(seed) + 10,
                vec![seed.wrapping_add(3); 32],
                vec![seed.wrapping_add(4); 32],
                i64::from(seed) + 20,
                vec![seed.wrapping_add(5); 32],
                vec![seed.wrapping_add(6); 32],
                vec![seed.wrapping_add(7); 32],
                i64::from(seed) + 30,
                vec![seed.wrapping_add(8); 32],
                vec![seed.wrapping_add(9); 32],
                vec![seed.wrapping_add(10); 32],
                i64::from(seed) + 40,
                vec![seed.wrapping_add(11); 32],
                vec![seed.wrapping_add(12); 32],
                vec![seed.wrapping_add(13); 32],
                vec![seed.wrapping_add(14); 32],
                vec![seed.wrapping_add(15); 32],
                i64::from(seed) + 50,
            ],
        )
        .unwrap();
    }

    fn install_sql_carrier_row(
        conn: &Connection,
        seed: u8,
        store_kind: u8,
        event_digest_byte: u8,
        receipt_nonce_byte: u8,
    ) {
        conn.execute(
            "INSERT INTO observation_carrier_migration_rows VALUES
             (?1,?2,?3,?4,?5,?6,?7,?8,?9,'finalized',?10,?11,500)",
            rusqlite::params![
                vec![seed; 16],
                i64::from(store_kind),
                vec![event_digest_byte; 32],
                vec![seed.wrapping_add(17); 32],
                vec![receipt_nonce_byte; 32],
                vec![seed.wrapping_add(19); 300],
                vec![seed.wrapping_add(20); 32],
                vec![seed.wrapping_add(21); 32],
                vec![seed.wrapping_add(22); 32],
                vec![seed.wrapping_add(23); 32],
                i64::from(seed) + 60,
            ],
        )
        .unwrap();
    }

    fn observation_schema_connection() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE components (
               id TEXT PRIMARY KEY,sensitive_params BLOB NOT NULL,
               identity_incarnation INTEGER NOT NULL,declaration_digest BLOB NOT NULL,
               lifecycle_state TEXT NOT NULL,catalog_visible INTEGER NOT NULL,
               operation_id TEXT,tombstoned_at_ms INTEGER,retain_until_ms INTEGER
             ) STRICT;",
        )
        .unwrap();
        conn.execute_batch(include_str!("observation_schema.sql"))
            .unwrap();
        conn
    }

    fn retained_gc_connection(prepared: bool) -> Connection {
        let conn = observation_schema_connection();
        conn.execute(
            "INSERT INTO observation_identity_operations VALUES
             ('gc-op','terminate-agents','committed',0,1,?1)",
            [[0x41_u8; 32].as_slice()],
        )
        .unwrap();
        for (id, digest) in [("agent-a", [0x51_u8; 32]), ("agent-b", [0x52_u8; 32])] {
            conn.execute(
                "INSERT INTO observation_identity_authority VALUES (?1,'agent',1,?2)",
                rusqlite::params![id, digest.as_slice()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO observation_identities VALUES
                 (?1,'agent',1,?2,'tombstoned',1,'gc-op',1,1)",
                rusqlite::params![id, digest.as_slice()],
            )
            .unwrap();
            if prepared {
                conn.execute(
                    "INSERT INTO observation_identity_operation_members
                     (operation_id,identity_id,identity_class,identity_incarnation,
                      declaration_digest,termination_subject_receipt_digest,
                      termination_emission_receipt_digest,gc_challenge_nonce,
                      gc_tombstone_state_root,gc_operation_boot,gc_phase,gc_generation,
                      gc_registry_sequence,gc_challenge_consumed,is_active)
                     VALUES ('gc-op',?1,'agent',1,?2,?3,?4,?5,?6,?7,
                             'prepared',1,5,0,0)",
                    rusqlite::params![
                        id,
                        digest.as_slice(),
                        [0x61_u8; 32].as_slice(),
                        [0x62_u8; 32].as_slice(),
                        [0x71_u8; 32].as_slice(),
                        [0x72_u8; 32].as_slice(),
                        [0x73_u8; 16].as_slice(),
                    ],
                )
                .unwrap();
            } else {
                conn.execute(
                    "INSERT INTO observation_identity_operation_members
                     (operation_id,identity_id,identity_class,identity_incarnation,
                      declaration_digest,termination_subject_receipt_digest,
                      termination_emission_receipt_digest,gc_phase,gc_generation,
                      gc_challenge_consumed,is_active)
                     VALUES ('gc-op',?1,'agent',1,?2,?3,?4,'idle',0,0,0)",
                    rusqlite::params![
                        id,
                        digest.as_slice(),
                        [0x61_u8; 32].as_slice(),
                        [0x62_u8; 32].as_slice(),
                    ],
                )
                .unwrap();
            }
        }
        conn
    }

    fn prepare_all_gc_members(conn: &Connection) {
        conn.execute(
            "UPDATE observation_identity_operation_members
             SET gc_challenge_nonce=?1,gc_tombstone_state_root=?2,gc_operation_boot=?3,
                 gc_phase='prepared',gc_generation=1,gc_registry_sequence=5
             WHERE operation_id='gc-op'",
            rusqlite::params![
                [0x71_u8; 32].as_slice(),
                [0x72_u8; 32].as_slice(),
                [0x73_u8; 16].as_slice(),
            ],
        )
        .unwrap();
    }

    fn collect_all_gc_members(conn: &Connection) {
        conn.execute(
            "UPDATE observation_identity_operation_members
             SET gc_subject_receipt_digest=?1,gc_reference_scan_digest=?2,
                 gc_phase='collected',gc_challenge_consumed=1
             WHERE operation_id='gc-op'",
            rusqlite::params![[0x81_u8; 32].as_slice(), [0x82_u8; 32].as_slice()],
        )
        .unwrap();
    }

    fn termination_finalize_connection() -> Connection {
        let conn = observation_schema_connection();
        conn.execute(
            "INSERT INTO observation_identity_operations VALUES
             ('term-op','terminate-agents','prepared',1,100,?1)",
            [[0x11_u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_authority VALUES ('agent-z','agent',1,?1)",
            [[0x12_u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identities VALUES
             ('agent-z','agent',1,?1,'terminating',1,'term-op',NULL,100)",
            [[0x12_u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_operation_members
             (operation_id,identity_id,identity_class,identity_incarnation,
              declaration_digest,termination_subject_receipt_digest,
              termination_emission_receipt_digest,gc_phase,gc_generation,
              gc_challenge_consumed,is_active)
             VALUES ('term-op','agent-z','agent',1,?1,?2,?3,'idle',0,0,1)",
            rusqlite::params![
                [0x12_u8; 32].as_slice(),
                [0x13_u8; 32].as_slice(),
                [0x14_u8; 32].as_slice(),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_termination_finalizations
             (operation_id,operation_kind,registry_instance_id,operation_boot_id,
              prepare_ack_digest,prepare_ack_nonce,prepare_sequence,member_set_digest,
              phase,encoded_bytes,future_reserved_bytes)
             VALUES ('term-op','terminate-agents',?1,?2,?3,?4,1,?5,'prepared',159,1889)",
            rusqlite::params![
                [0x15_u8; 16].as_slice(),
                [0x16_u8; 16].as_slice(),
                [0x17_u8; 32].as_slice(),
                [0x18_u8; 32].as_slice(),
                [0x19_u8; 32].as_slice(),
            ],
        )
        .unwrap();
        conn.execute(
            "UPDATE observation_termination_finalize_capacity
             SET row_count=1,actual_encoded_bytes=159,future_reserved_bytes=1889
             WHERE singleton=1",
            [],
        )
        .unwrap();
        conn
    }

    fn registration_baseline(component: bool) -> (Connection, RegistrySnapshot, RegistrySnapshot) {
        let conn = observation_schema_connection();
        let before = capture(&conn).unwrap();
        let (operation_id, identity_id, kind, class) = if component {
            (
                "reg-component",
                "component-a",
                "register-component",
                "component",
            )
        } else {
            ("reg-agent", "agent-a", "register-agent", "agent")
        };
        let digest = [0x31_u8; 32];
        conn.execute(
            "INSERT INTO observation_identity_operations
             (operation_id,kind,phase,is_active)
             VALUES (?1,?2,'prepared',1)",
            rusqlite::params![operation_id, kind],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identities
             (id,class,incarnation,declaration_digest,lifecycle_state,catalog_visible,operation_id)
             VALUES (?1,?2,1,?3,'pending',0,?4)",
            rusqlite::params![identity_id, class, digest.as_slice(), operation_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_authority VALUES (?1,?2,1,?3)",
            rusqlite::params![identity_id, class, digest.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_operation_members
             (operation_id,identity_id,identity_class,identity_incarnation,
              declaration_digest,is_active)
             VALUES (?1,?2,?3,1,?4,1)",
            rusqlite::params![operation_id, identity_id, class, digest.as_slice()],
        )
        .unwrap();
        if component {
            conn.execute(
                "INSERT INTO components
                 (id,sensitive_params,identity_incarnation,declaration_digest,
                  lifecycle_state,catalog_visible,operation_id)
                 VALUES (?1,?2,1,?3,'live',0,?4)",
                rusqlite::params![
                    identity_id,
                    [0x32_u8; 32].as_slice(),
                    digest.as_slice(),
                    operation_id,
                ],
            )
            .unwrap();
        }
        conn.execute(
            "UPDATE observation_previsible_capacity
             SET row_count=1,future_reserved_bytes=4096 WHERE singleton=1",
            [],
        )
        .unwrap();
        let after = capture(&conn).unwrap();
        (conn, before, after)
    }

    fn previsible_allocation_baseline() -> (RegistrySnapshot, RegistrySnapshot) {
        let (conn, _, registered) = registration_baseline(false);
        let digest = [0x31_u8; 32];
        conn.execute(
            "INSERT INTO observation_previsible_activations
             (activation_nonce,boot_id,registry_instance_id,role,operation_id,
              operation_kind,identity_id,identity_class,identity_incarnation,
              declaration_digest,registry_sequence,phase,updated_sequence,
              encoded_bytes,future_reserved_bytes)
             VALUES (?1,?2,?3,1,'reg-agent','register-agent','agent-a','agent',1,
                     ?4,1,'prepared',1,200,3896)",
            rusqlite::params![
                [0x41_u8; 32].as_slice(),
                [0x42_u8; 16].as_slice(),
                [0x43_u8; 16].as_slice(),
                digest.as_slice(),
            ],
        )
        .unwrap();
        conn.execute(
            "UPDATE observation_previsible_capacity
             SET actual_encoded_bytes=200,future_reserved_bytes=3896 WHERE singleton=1",
            [],
        )
        .unwrap();
        (registered, capture(&conn).unwrap())
    }

    fn termination_prepare_baseline() -> (Connection, RegistrySnapshot, RegistrySnapshot) {
        let conn = observation_schema_connection();
        let identity_digest = [0x51_u8; 32];
        conn.execute(
            "INSERT INTO observation_identities VALUES
             ('agent-t','agent',1,?1,'live',1,NULL,NULL,NULL)",
            [identity_digest.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_authority VALUES ('agent-t','agent',1,?1)",
            [identity_digest.as_slice()],
        )
        .unwrap();
        let before = capture(&conn).unwrap();
        conn.execute(
            "INSERT INTO observation_identity_operations VALUES
             ('term-prepare','terminate-agents','prepared',1,100,?1)",
            [[0x52_u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "UPDATE observation_identities
             SET lifecycle_state='terminating',operation_id='term-prepare',retain_until_ms=100
             WHERE id='agent-t'",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_operation_members
             (operation_id,identity_id,identity_class,identity_incarnation,
              declaration_digest,termination_subject_receipt_digest,
              termination_emission_receipt_digest,is_active)
             VALUES ('term-prepare','agent-t','agent',1,?1,?2,?3,1)",
            rusqlite::params![
                identity_digest.as_slice(),
                [0x53_u8; 32].as_slice(),
                [0x54_u8; 32].as_slice(),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_termination_finalizations
             (operation_id,operation_kind,registry_instance_id,operation_boot_id,
              prepare_ack_digest,prepare_ack_nonce,prepare_sequence,member_set_digest,
              phase,encoded_bytes,future_reserved_bytes)
             VALUES ('term-prepare','terminate-agents',?1,?2,?3,?4,1,?5,'prepared',164,1884)",
            rusqlite::params![
                [0x55_u8; 16].as_slice(),
                [0x56_u8; 16].as_slice(),
                [0x57_u8; 32].as_slice(),
                [0x58_u8; 32].as_slice(),
                [0x59_u8; 32].as_slice(),
            ],
        )
        .unwrap();
        conn.execute(
            "UPDATE observation_termination_finalize_capacity
             SET row_count=1,actual_encoded_bytes=164,future_reserved_bytes=1884
             WHERE singleton=1",
            [],
        )
        .unwrap();
        let after = capture(&conn).unwrap();
        (conn, before, after)
    }

    fn termination_finalize_baseline() -> (RegistrySnapshot, RegistrySnapshot) {
        let conn = termination_finalize_connection();
        let before = capture(&conn).unwrap();
        conn.execute_batch(
            "UPDATE observation_identity_operations
             SET phase='committed',is_active=0 WHERE operation_id='term-op';
             UPDATE observation_identity_operation_members
             SET is_active=0 WHERE operation_id='term-op';
             UPDATE observation_identities
             SET lifecycle_state='tombstoned',tombstoned_at_ms=1 WHERE id='agent-z';
             UPDATE observation_termination_finalizations
             SET phase='finalized',cleanup_receipt_digest=zeroblob(32),
                 cleanup_high_water_digest=zeroblob(32),
                 cleanup_receipt_set_digest=zeroblob(32),cleanup_nonce=zeroblob(32),
                 finalize_recovery_nonce=zeroblob(32),finalize_sequence=2,
                 finalize_ack_digest=zeroblob(32),terminal_at_ms=1,
                 encoded_bytes=367,future_reserved_bytes=8
             WHERE operation_id='term-op';
             UPDATE observation_termination_finalize_capacity
             SET actual_encoded_bytes=367,future_reserved_bytes=8 WHERE singleton=1;",
        )
        .unwrap();
        (before, capture(&conn).unwrap())
    }

    fn host_registration_baseline() -> (RegistrySnapshot, RegistrySnapshot) {
        let conn = observation_schema_connection();
        let before = capture(&conn).unwrap();
        conn.execute(
            "INSERT INTO observation_identities VALUES
             ('host-a','host',1,?1,'permanent',1,NULL,NULL,NULL)",
            [[0x61_u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_authority VALUES ('host-a','host',1,?1)",
            [[0x61_u8; 32].as_slice()],
        )
        .unwrap();
        (before, capture(&conn).unwrap())
    }

    fn carrier_prepare_baseline() -> (RegistrySnapshot, RegistrySnapshot) {
        let mut before = snapshot_with_capacity_singletons();
        let mut issuing = decode_canonical_row(10, &literal_carrier_header(0x21)).unwrap();
        issuing[21] = CanonicalCell::Integer(1);
        issuing[22] = CanonicalCell::Integer(0);
        issuing[23] = CanonicalCell::Integer(0);
        issuing[24] = CanonicalCell::Integer(0);
        issuing[25] = CanonicalCell::Integer(1000);
        issuing[26] = CanonicalCell::Text(b"issuing".to_vec());
        issuing[27] = CanonicalCell::Integer(1);
        let migration_key = vec![0x21; 16];
        before.tables[9]
            .rows
            .insert(migration_key.clone(), encode_test_row(10, &issuing));

        let mut after = before.clone();
        let mut owner_ready = issuing;
        owner_ready[22] = CanonicalCell::Integer(1);
        owner_ready[24] = CanonicalCell::Integer(500);
        owner_ready[25] = CanonicalCell::Integer(500);
        owner_ready[26] = CanonicalCell::Text(b"owner-ready".to_vec());
        owner_ready[27] = CanonicalCell::Integer(2);
        after.tables[9]
            .rows
            .insert(migration_key, encode_test_row(10, &owner_ready));

        let mut prepared_row = decode_canonical_row(11, &literal_carrier_row(0x21, 1)).unwrap();
        prepared_row[9] = CanonicalCell::Text(b"prepared".to_vec());
        prepared_row[10] = CanonicalCell::Null;
        prepared_row[11] = CanonicalCell::Null;
        after.tables[10].rows.insert(
            literal_carrier_row_key(0x21, 1),
            encode_test_row(11, &prepared_row),
        );
        (before, after)
    }

    fn checkpoint_baseline() -> (RegistrySnapshot, RegistrySnapshot) {
        let conn = observation_schema_connection();
        conn.execute(
            "INSERT INTO observation_identity_operations
             (operation_id,kind,phase,is_active)
             VALUES ('checkpoint-op','register-agent','committed',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_authority
             VALUES ('checkpoint-agent','agent',1,?1)",
            [[0x74_u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_identity_operation_members
             (operation_id,identity_id,identity_class,identity_incarnation,
              declaration_digest,is_active)
             VALUES ('checkpoint-op','checkpoint-agent','agent',1,?1,0)",
            [[0x74_u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO observation_previsible_activations
             (activation_nonce,boot_id,registry_instance_id,role,operation_id,
              operation_kind,identity_id,identity_class,identity_incarnation,
              declaration_digest,registry_sequence,phase,subject_receipt_digest,
              table_receipt_digest,lifecycle_receipt_digest,ready_proof_nonce,
              recovery_nonce,updated_sequence,terminal_at_ms,encoded_bytes,
              future_reserved_bytes)
             VALUES (?1,?2,?3,1,'checkpoint-op','register-agent','checkpoint-agent',
                     'agent',1,?4,1,'published',?5,?6,?7,?8,?9,4,5,300,8)",
            rusqlite::params![
                [0x71_u8; 32].as_slice(),
                [0x72_u8; 16].as_slice(),
                [0x73_u8; 16].as_slice(),
                [0x74_u8; 32].as_slice(),
                [0x75_u8; 32].as_slice(),
                [0x76_u8; 32].as_slice(),
                [0x77_u8; 32].as_slice(),
                [0x78_u8; 32].as_slice(),
                [0x79_u8; 32].as_slice(),
            ],
        )
        .unwrap();
        conn.execute(
            "UPDATE observation_previsible_capacity
             SET row_count=1,actual_encoded_bytes=300,future_reserved_bytes=8
             WHERE singleton=1",
            [],
        )
        .unwrap();
        let before = capture(&conn).unwrap();
        conn.execute(
            "UPDATE observation_previsible_activations
             SET audit_checkpoint_sequence=10,encoded_bytes=308,future_reserved_bytes=0",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE observation_previsible_capacity
             SET actual_encoded_bytes=308,future_reserved_bytes=0 WHERE singleton=1",
            [],
        )
        .unwrap();
        (before, capture(&conn).unwrap())
    }

    #[test]
    fn tag1_through_tag14_closed_grammar_table_driven_kat() {
        struct Case {
            tag: u8,
            key_hex: &'static str,
            before_hex: &'static str,
            after_hex: &'static str,
            preimage_hex: &'static str,
            digest_hex: &'static str,
        }

        // These are independently generated, test-owned literals.  In
        // particular, none of the expected rows, frames, or digests is made
        // with the production encoder above.
        let cases = [
            Case { tag: 1, key_hex: "000000026b31", before_hex: "000000026b31000000017300000000000000010000000164000000046c69766500000000000000010000010000000000000007", after_hex: "000000026b31000000017300000000000000010000000164000000046c69766500000000000000010000010000000000000008", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010100000006000000026b3100000033000000026b31000000017300000000000000010000000164000000046c6976650000000000000001000001000000000000000700000033000000026b31000000017300000000000000010000000164000000046c69766500000000000000010000010000000000000008", digest_hex: "a25aa7fb1bc57de6c2937e8278433f4dc9dad24df3a213db837f0e944cdca4cd" },
            Case { tag: 2, key_hex: "000000026b32", before_hex: "000000026b320100000008707265706172656400000000000000070000", after_hex: "000000026b320100000008707265706172656400000000000000080000", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010200000006000000026b320000001d000000026b3201000000087072657061726564000000000000000700000000001d000000026b320100000008707265706172656400000000000000080000", digest_hex: "cbb5c2d91bd6fe8c10754093ef4d7559a299f9fe2d9eaa9c3983babb86d3da14" },
            Case { tag: 3, key_hex: "000000026b33", before_hex: "000000026b33000000056167656e7400000000000000010000000164000000046c6976650000000000000007000000", after_hex: "000000026b33000000056167656e7400000000000000010000000164000000046c6976650000000000000008000000", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010300000006000000026b330000002f000000026b33000000056167656e7400000000000000010000000164000000046c69766500000000000000070000000000002f000000026b33000000056167656e7400000000000000010000000164000000046c6976650000000000000008000000", digest_hex: "81fdc8349b592c848552dee8f86449b75874888c901f1c3c8544ad2e42b81be4" },
            Case { tag: 4, key_hex: "000000026b34", before_hex: "000000026b34000000056167656e7400000000000000070000000164", after_hex: "000000026b34000000056167656e7400000000000000080000000164", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010400000006000000026b340000001c000000026b34000000056167656e74000000000000000700000001640000001c000000026b34000000056167656e7400000000000000080000000164", digest_hex: "bb12be9b2bf53431fe50b680179a90ff5fd5ba4714a66a728906c3fec0df7264" },
            Case { tag: 5, key_hex: "000000026b35000000066d656d626572", before_hex: "000000026b35000000066d656d626572000000056167656e7400000000000000010000000164000000000000000000000469646c6500000000000000000000000000000000000000000000000007", after_hex: "000000026b35000000066d656d626572000000056167656e7400000000000000010000000164000000000000000000000469646c6500000000000000000000000000000000000000000000000008", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010500000010000000026b35000000066d656d6265720000004e000000026b35000000066d656d626572000000056167656e7400000000000000010000000164000000000000000000000469646c65000000000000000000000000000000000000000000000000070000004e000000026b35000000066d656d626572000000056167656e7400000000000000010000000164000000000000000000000469646c6500000000000000000000000000000000000000000000000008", digest_hex: "cbf8c70d770ce54346cc051e8c185716e14f1e434d7bce0c27c657f820cbb0aa" },
            Case { tag: 6, key_hex: "0606060606060606060606060606060606060606060606060606060606060606", before_hex: "000000200606060606060606060606060606060606060606060606060606060606060606000000016200000001720000000000000001000000036f70360100000003696436000000056167656e74000000000000000100000001640000000000000001000000087072657061726564000000000000000000000000000000000001000000000000000000400000000000000007", after_hex: "000000200606060606060606060606060606060606060606060606060606060606060606000000016200000001720000000000000001000000036f70360100000003696436000000056167656e74000000000000000100000001640000000000000001000000087072657061726564000000000000000000000000000000000001000000000000000000400000000000000008", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010600000020060606060606060606060606060606060606060606060606060606060606060600000093000000200606060606060606060606060606060606060606060606060606060606060606000000016200000001720000000000000001000000036f70360100000003696436000000056167656e7400000000000000010000000164000000000000000100000008707265706172656400000000000000000000000000000000000100000000000000000040000000000000000700000093000000200606060606060606060606060606060606060606060606060606060606060606000000016200000001720000000000000001000000036f70360100000003696436000000056167656e74000000000000000100000001640000000000000001000000087072657061726564000000000000000000000000000000000001000000000000000000400000000000000008", digest_hex: "dbaedf795741bd708e5faf3078dac050868c96554c33196805163fc8a4a12f0f" },
            Case { tag: 7, key_hex: "0000000000000001", before_hex: "0000000000000001000000000000000200000000000000030000000000000007", after_hex: "0000000000000001000000000000000200000000000000030000000000000008", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e7631000000000107000000080000000000000001000000200000000000000001000000000000000200000000000000030000000000000007000000200000000000000001000000000000000200000000000000030000000000000008", digest_hex: "b86ccbbbb81fd835a7982ae9c225213285e80630fdd1df0889208e07d8404352" },
            Case { tag: 8, key_hex: "000000026b38", before_hex: "000000026b3803000000017200000001620000000161000000016e0000000000000001000000016d00000008707265706172656400000000000000000000000000000000400000000000000007", after_hex: "000000026b3803000000017200000001620000000161000000016e0000000000000001000000016d00000008707265706172656400000000000000000000000000000000400000000000000008", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010800000006000000026b380000004d000000026b3803000000017200000001620000000161000000016e0000000000000001000000016d000000087072657061726564000000000000000000000000000000004000000000000000070000004d000000026b3803000000017200000001620000000161000000016e0000000000000001000000016d00000008707265706172656400000000000000000000000000000000400000000000000008", digest_hex: "7367c61dc102f4a32e551bc47b307bebc8577aecbcfad12c9b3a5899264ae3d5" },
            Case { tag: 9, key_hex: "0000000000000001", before_hex: "0000000000000001000000000000000200000000000000030000000000000007", after_hex: "0000000000000001000000000000000200000000000000030000000000000008", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e7631000000000109000000080000000000000001000000200000000000000001000000000000000200000000000000030000000000000007000000200000000000000001000000000000000200000000000000030000000000000008", digest_hex: "8c62a46a5cb714fa4968852e541341bf9e68c8da9e06927c0c98fb0211901ac1" },
            Case { tag: 10, key_hex: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", before_hex: "000000100a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000000172000000016c00000000000000010000000000000002000000016100000001620000000000000003000000016300000001640000000165000000000000000400000001660000000167000000016800000000000000050000000169000000016a000000016b000000016c000000016d000000000000000100000000000000010000000000000001000000000000006400000000000000070000000876657269666965640000000000000009", after_hex: "000000100a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000000172000000016c00000000000000010000000000000002000000016100000001620000000000000003000000016300000001640000000165000000000000000400000001660000000167000000016800000000000000050000000169000000016a000000016b000000016c000000016d000000000000000100000000000000010000000000000001000000000000006400000000000000080000000876657269666965640000000000000009", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010a000000100a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000000c3000000100a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000000172000000016c00000000000000010000000000000002000000016100000001620000000000000003000000016300000001640000000165000000000000000400000001660000000167000000016800000000000000050000000169000000016a000000016b000000016c000000016d000000000000000100000000000000010000000000000001000000000000006400000000000000070000000876657269666965640000000000000009000000c3000000100a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000000172000000016c00000000000000010000000000000002000000016100000001620000000000000003000000016300000001640000000165000000000000000400000001660000000167000000016800000000000000050000000169000000016a000000016b000000016c000000016d000000000000000100000000000000010000000000000001000000000000006400000000000000080000000876657269666965640000000000000009", digest_hex: "5bd1d17626000c976b6f12bb4f6eb276af1f713f920768b16b54f507b30fa859" },
            Case { tag: 11, key_hex: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b010c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", before_hex: "000000100b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000001000000200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000163000000016e000000016c0000000169000000017000000001710000000966696e616c697a656400000000000000000007", after_hex: "000000100b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000001000000200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000163000000016e000000016c0000000169000000017000000001710000000966696e616c697a656400000000000000000008", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010b000000310b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b010c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000075000000100b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000001000000200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000163000000016e000000016c0000000169000000017000000001710000000966696e616c697a65640000000000000000000700000075000000100b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000001000000200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000163000000016e000000016c0000000169000000017000000001710000000966696e616c697a656400000000000000000008", digest_hex: "a9c352720b5230ac5d0711201b20b8f763cfb5a493a6a3296359ab8d8aa69053" },
            Case { tag: 12, key_hex: "0000000000000001", before_hex: "0100000001070707070707070707070707070707070000000000000000000000000000000000000000000000000000000000000000000000000000000066666666666666666666666666666666666666666666666666666666666666660000000000000002000000010000000100000001010000000100000000000000000007070707070707070707070707070707070707070707070707070707070707078888888888888888888888888888888888888888888888888888888888888888", after_hex: "0100000001070707070707070707070707070707070000000000000001893cdd56432a373f94adb5554ce52d9f96d113555de50231ab6badc5385befe766666666666666666666666666666666666666666666666666666666666666660000000000000002000000010000000100000001010000000100000000000000090008080808080808080808080808080808080808080808080808080808080808088888888888888888888888888888888888888888888888888888888888888888", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010c000000080000000000000001000000bf0100000001070707070707070707070707070707070000000000000000000000000000000000000000000000000000000000000000000000000000000066666666666666666666666666666666666666666666666666666666666666660000000000000002000000010000000100000001010000000100000000000000000007070707070707070707070707070707070707070707070707070707070707078888888888888888888888888888888888888888888888888888888888888888000000bf0100000001070707070707070707070707070707070000000000000001893cdd56432a373f94adb5554ce52d9f96d113555de50231ab6badc5385befe766666666666666666666666666666666666666666666666666666666666666660000000000000002000000010000000100000001010000000100000000000000090008080808080808080808080808080808080808080808080808080808080808088888888888888888888888888888888888888888888888888888888888888888", digest_hex: "b4b95f1d3d8f55c39295a452296dbfdde901ea54186020d47532c48497243569" },
            Case { tag: 13, key_hex: "0000000000000001", before_hex: "0100000001010101010101010101010101010101010707070707070707070707070707070702020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000000010404040404040404040404040404040404040404040404040404040404040404893cdd56432a373f94adb5554ce52d9f96d113555de50231ab6badc5385befe7ca3d380f4159a62be339f67721a6036335ac51756a44b76b0e3d3e51166e5adc05050505050505050505050505050505050505050505050505050505050505050101010101010101010101010101010101010101010101010101010101010101018181818181818181818181818181818181818181818181818181818181818181", after_hex: "0100000001010101010101010101010101010101010707070707070707070707070707070702020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000000010404040404040404040404040404040404040404040404040404040404040404893cdd56432a373f94adb5554ce52d9f96d113555de50231ab6badc5385befe7ca3d380f4159a62be339f67721a6036335ac51756a44b76b0e3d3e51166e5adc05050505050505050505050505050505050505050505050505050505050505050202020202020202020202020202020202020202020202020202020202020202028282828282828282828282828282828282828282828282828282828282828282", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010d0000000800000000000000010000012a0100000001010101010101010101010101010101010707070707070707070707070707070702020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000000010404040404040404040404040404040404040404040404040404040404040404893cdd56432a373f94adb5554ce52d9f96d113555de50231ab6badc5385befe7ca3d380f4159a62be339f67721a6036335ac51756a44b76b0e3d3e51166e5adc050505050505050505050505050505050505050505050505050505050505050501010101010101010101010101010101010101010101010101010101010101010181818181818181818181818181818181818181818181818181818181818181810000012a0100000001010101010101010101010101010101010707070707070707070707070707070702020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000000010404040404040404040404040404040404040404040404040404040404040404893cdd56432a373f94adb5554ce52d9f96d113555de50231ab6badc5385befe7ca3d380f4159a62be339f67721a6036335ac51756a44b76b0e3d3e51166e5adc05050505050505050505050505050505050505050505050505050505050505050202020202020202020202020202020202020202020202020202020202020202028282828282828282828282828282828282828282828282828282828282828282", digest_hex: "bcc61c735910957718c56585c983074093ed06c8f5e3dbb3c341b04fe61bc1d0" },
            Case { tag: 14, key_hex: "0000000000000001", before_hex: "010000000107070707070707070707070707070707000000000000000000000000000000010000000001010101010101010101010101010101010101010101010101010101010101010000000000000000000000000000000000000000000000000000000000000000", after_hex: "010000000107070707070707070707070707070707000000000000000100000000000000020000000102020202020202020202020202020202000000010000000000000001010000000101030303030303030303030303030303030303030303030303010404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040105050505050505050505050505050505050505050505050501060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606000000000000000500000000000000000007070707070707070707070707070707070707070707070707070707070707070808080808080808080808080808080808080808080808080808080808080808", preimage_hex: "616476616e63652e636f6e74726163743231382e72656769737472792d77726974652d7365742e763100000000010e000000080000000000000001000000690100000001070707070707070707070707070707070000000000000000000000000000000100000000010101010101010101010101010101010101010101010101010101010101010100000000000000000000000000000000000000000000000000000000000000000000012f010000000107070707070707070707070707070707000000000000000100000000000000020000000102020202020202020202020202020202000000010000000000000001010000000101030303030303030303030303030303030303030303030303010404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040105050505050505050505050505050505050505050505050501060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606000000000000000500000000000000000007070707070707070707070707070707070707070707070707070707070707070808080808080808080808080808080808080808080808080808080808080808", digest_hex: "bd7d755fa09e0034e7880ea706e7ee03f88f6ab728dd2f27bcfa618b2a63ccad" },
        ];

        let record_for = |case: &Case| CanonicalWriteRecord {
            tag: case.tag,
            key: hex::decode(case.key_hex).unwrap(),
            before: Some(hex::decode(case.before_hex).unwrap()),
            after: Some(hex::decode(case.after_hex).unwrap()),
        };
        let snapshots_for = |record: &CanonicalWriteRecord| {
            let mut before = empty_snapshot();
            let mut after = empty_snapshot();
            before.tables[usize::from(record.tag - 1)].rows.insert(
                record.key.clone(),
                record.before.clone().expect("literal preimage"),
            );
            after.tables[usize::from(record.tag - 1)].rows.insert(
                record.key.clone(),
                record.after.clone().expect("literal postimage"),
            );
            (before, after)
        };
        let digest_for =
            |case: &Case| -> [u8; 32] { hex::decode(case.digest_hex).unwrap().try_into().unwrap() };

        // Immutable companion artifacts for synthetic tag 13.  Malformed
        // candidates below are supplied only as the Prepared/Installed slots;
        // the migration block and Complete marker never come from slicing the
        // candidate under test.  That guarantees every negative reaches the
        // production legacy-marker parser instead of failing in fixture code.
        const LEGACY_MIGRATION_BLOCK_HEX: &str = "010101010101010101010101010101010707070707070707070707070707070702020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000000010404040404040404040404040404040404040404040404040404040404040404893cdd56432a373f94adb5554ce52d9f96d113555de50231ab6badc5385befe7ca3d380f4159a62be339f67721a6036335ac51756a44b76b0e3d3e51166e5adc0505050505050505050505050505050505050505050505050505050505050505";
        const LEGACY_COMPLETE_MARKER_HEX: &str = "0100000001010101010101010101010101010101010707070707070707070707070707070702020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000000010404040404040404040404040404040404040404040404040404040404040404893cdd56432a373f94adb5554ce52d9f96d113555de50231ab6badc5385befe7ca3d380f4159a62be339f67721a6036335ac51756a44b76b0e3d3e51166e5adc05050505050505050505050505050505050505050505050505050505050505050303030303030303030303030303030303030303030303030303030303030303038383838383838383838383838383838383838383838383838383838383838383";
        let legacy_migration_block: [u8; 228] = hex::decode(LEGACY_MIGRATION_BLOCK_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let legacy_complete_marker = hex::decode(LEGACY_COMPLETE_MARKER_HEX).unwrap();
        let synthetic_anchor_digest =
            |tag: u8, record: &CanonicalWriteRecord| -> Result<[u8; 32], String> {
                use crate::observation_anchor as anchor;

                let before = record
                    .before
                    .as_deref()
                    .ok_or_else(|| "synthetic preimage is absent".to_owned())?;
                let after = record
                    .after
                    .as_deref()
                    .ok_or_else(|| "synthetic postimage is absent".to_owned())?;
                let fixture = SyntheticFixtureAnchor;
                let context = anchor::RegistryHeadContext::unchanged([6; 32], 1)
                    .map_err(|error| error.to_string())?;
                match tag {
                    12 => {
                        let current = anchor::RegistryAnchorTuple {
                            registry_instance: [7; 16],
                            sequence: 4,
                            head: [9; 32],
                            state_root: [4; 32],
                            keyring_root: anchor::persisted_keyring_file_root(before),
                            role_allocation_root: [3; 32],
                            migration_digest: [5; 32],
                        };
                        let prepared = anchor::prepare_persisted_keyring_mutation(
                            &fixture, current, context, before, after,
                        )
                        .map_err(|error| error.to_string())?;
                        let (mutation, _, _) = prepared
                            .into_parts_authenticated(&fixture)
                            .map_err(|error| error.to_string())?;
                        Ok(mutation.write_set_digest())
                    }
                    13 => {
                        let initial_keyring = hex::decode(cases[11].before_hex).unwrap();
                        let initial_roles = hex::decode(cases[13].before_hex).unwrap();
                        let migration = anchor::prepare_legacy_registry_migration(
                            &fixture,
                            &legacy_migration_block,
                            before,
                            after,
                            &legacy_complete_marker,
                            &initial_keyring,
                            &initial_roles,
                        )
                        .map_err(|error| error.to_string())?;
                        let current = anchor::RegistryAnchorTuple {
                            registry_instance: [7; 16],
                            sequence: 0,
                            head: [9; 32],
                            state_root: [4; 32],
                            keyring_root: anchor::persisted_keyring_file_root(&initial_keyring),
                            role_allocation_root: anchor::role_allocation_file_root(&initial_roles),
                            migration_digest: anchor::legacy_registry_migration_digest(
                                &legacy_migration_block,
                            ),
                        };
                        let context = anchor::RegistryHeadContext {
                            previous_marker_root: anchor::registry_marker_root(before)
                                .map_err(|error| error.to_string())?,
                            next_marker_root: anchor::registry_marker_root(after)
                                .map_err(|error| error.to_string())?,
                            manifest_key_epoch: 1,
                            next_manifest_key_epoch: 1,
                        };
                        let prepared = anchor::prepare_legacy_installed_marker_mutation(
                            &fixture, &migration, current, context,
                        )
                        .map_err(|error| error.to_string())?;
                        Ok(prepared
                            .authenticated_mutation(&fixture)
                            .map_err(|error| error.to_string())?
                            .write_set_digest())
                    }
                    14 => {
                        let current = anchor::RegistryAnchorTuple {
                            registry_instance: [7; 16],
                            sequence: 4,
                            head: [9; 32],
                            state_root: [4; 32],
                            keyring_root: [3; 32],
                            role_allocation_root: anchor::role_allocation_file_root(before),
                            migration_digest: [5; 32],
                        };
                        let prepared = anchor::prepare_role_allocation_mutation(
                            &fixture, current, context, before, after,
                        )
                        .map_err(|error| error.to_string())?;
                        Ok(prepared
                            .into_mutation_authenticated(&fixture)
                            .map_err(|error| error.to_string())?
                            .write_set_digest())
                    }
                    _ => Err("not a synthetic artifact tag".to_owned()),
                }
            };
        let assert_production_synthetic_parser_rejects =
            |tag: u8, record: &CanonicalWriteRecord, label: &str| {
                let error = match synthetic_anchor_digest(tag, record) {
                    Ok(_) => panic!("{label} unexpectedly passed production parser"),
                    Err(error) => error,
                };
                assert_eq!(
                    error,
                    crate::observation_anchor::RegistryAnchorError::InvalidTransition.to_string(),
                    "{label} must fail in the production artifact grammar"
                );
            };

        assert_eq!(
            cases.iter().map(|case| case.tag).collect::<Vec<_>>(),
            (1..=14).collect::<Vec<_>>()
        );
        for (index, case) in cases.iter().enumerate() {
            let record = record_for(case);
            let expected_digest = digest_for(case);
            let preimage = verify_canonical_write_set(
                std::slice::from_ref(&record),
                &[case.tag],
                expected_digest,
            )
            .unwrap_or_else(|error| panic!("tag {} positive literal rejected: {error}", case.tag));
            assert_eq!(
                hex::encode(preimage),
                case.preimage_hex,
                "tag {} full framed preimage",
                case.tag
            );
            assert_eq!(
                canonical_write_set_digest_records(std::slice::from_ref(&record)).unwrap(),
                expected_digest,
                "tag {} literal digest",
                case.tag
            );
            if case.tag >= 12 {
                assert_eq!(
                    synthetic_anchor_digest(case.tag, &record),
                    Ok(expected_digest),
                    "tag {} real anchor-helper digest",
                    case.tag
                );
            } else {
                let (before, after) = snapshots_for(&record);
                assert_eq!(
                    write_set_digest(&before, &after),
                    Ok(expected_digest),
                    "tag {} candidate authenticates with its own literal digest",
                    case.tag
                );
                for operation_tag in 1..=8 {
                    assert!(
                        validate_operation_effects(operation_tag, &before, &after).is_err(),
                        "table tag {} non-key mutation escaped operation-tag {} cohort grammar",
                        case.tag,
                        operation_tag
                    );
                }
            }

            let rejects = |candidate: &CanonicalWriteRecord| {
                verify_canonical_write_set(
                    std::slice::from_ref(candidate),
                    &[case.tag],
                    expected_digest,
                )
                .is_err()
            };

            let mut crossed = record.clone();
            crossed.tag = if case.tag == 14 { 1 } else { case.tag + 1 };
            assert!(rejects(&crossed), "tag {} crossed tag", case.tag);
            if matches!(case.tag, 12 | 13) {
                assert_production_synthetic_parser_rejects(
                    crossed.tag,
                    &crossed,
                    &format!("tag {} crossed synthetic artifact grammar", case.tag),
                );
            } else {
                assert!(
                    canonical_write_set_preimage(std::slice::from_ref(&crossed)).is_err(),
                    "tag {} crossed tag passed record grammar with its own digest",
                    case.tag
                );
            }

            let mut unknown = record.clone();
            unknown.tag = 15;
            assert!(rejects(&unknown), "tag {} unknown tag", case.tag);
            assert!(
                canonical_write_set_preimage(std::slice::from_ref(&unknown)).is_err(),
                "tag {} unknown tag passed record grammar",
                case.tag
            );

            let mut missing = record.clone();
            missing.after.as_mut().unwrap().pop();
            assert!(
                rejects(&missing),
                "tag {} missing field/artifact byte",
                case.tag
            );
            if case.tag >= 12 {
                assert_production_synthetic_parser_rejects(
                    case.tag,
                    &missing,
                    &format!("tag {} truncated artifact", case.tag),
                );
            } else {
                assert!(
                    canonical_write_set_preimage(std::slice::from_ref(&missing)).is_err(),
                    "tag {} truncated row passed grammar with a recomputed digest",
                    case.tag
                );
            }

            let mut extra_field = record.clone();
            extra_field
                .after
                .as_mut()
                .unwrap()
                .extend_from_slice(&0_u64.to_be_bytes());
            assert!(
                rejects(&extra_field),
                "tag {} extra field/artifact bytes",
                case.tag
            );
            if case.tag >= 12 {
                assert_production_synthetic_parser_rejects(
                    case.tag,
                    &extra_field,
                    &format!("tag {} extra artifact bytes", case.tag),
                );
            } else {
                assert!(
                    canonical_write_set_preimage(std::slice::from_ref(&extra_field)).is_err(),
                    "tag {} extra row field passed grammar with a recomputed digest",
                    case.tag
                );
            }

            let mut alternate_key = record.clone();
            alternate_key.key.push(0);
            assert!(
                rejects(&alternate_key),
                "tag {} alternate primary-key framing",
                case.tag
            );
            assert!(
                canonical_write_set_preimage(std::slice::from_ref(&alternate_key)).is_err(),
                "tag {} alternate key passed record grammar with a recomputed digest",
                case.tag
            );

            let duplicate = vec![record.clone(), record.clone()];
            assert!(
                verify_canonical_write_set(&duplicate, &[case.tag], expected_digest).is_err(),
                "tag {} duplicate canonical key",
                case.tag
            );
            assert!(
                canonical_write_set_digest_records(&duplicate).is_err(),
                "tag {} duplicate key acquired its own digest",
                case.tag
            );

            let mut trailing = record.clone();
            trailing.after.as_mut().unwrap().push(0xff);
            assert!(rejects(&trailing), "tag {} trailing byte", case.tag);
            if case.tag >= 12 {
                assert_production_synthetic_parser_rejects(
                    case.tag,
                    &trailing,
                    &format!("tag {} trailing artifact byte", case.tag),
                );
            } else {
                assert!(
                    canonical_write_set_preimage(std::slice::from_ref(&trailing)).is_err(),
                    "tag {} trailing byte passed grammar with a recomputed digest",
                    case.tag
                );
            }

            if case.tag <= 11 {
                let mut forbidden_key_column = record.clone();
                let offset = if matches!(case.tag, 7 | 9) { 7 } else { 4 };
                forbidden_key_column.after.as_mut().unwrap()[offset] ^= 1;
                assert!(
                    rejects(&forbidden_key_column),
                    "tag {} forbidden primary-key-column mutation",
                    case.tag
                );
                assert!(
                    canonical_write_set_preimage(std::slice::from_ref(&forbidden_key_column))
                        .is_err(),
                    "tag {} forbidden primary-key column acquired its own digest",
                    case.tag
                );
            }

            if case.tag >= 12 {
                let mut closed_field = record.clone();
                let bytes = closed_field.after.as_mut().unwrap();
                match case.tag {
                    12 => bytes[113] = 4, // unknown persisted-key status
                    13 => bytes[233] = 3, // Installed transition cannot skip to Complete
                    14 => bytes[60] = 2,  // closed role family is exactly one
                    _ => unreachable!(),
                }
                assert_production_synthetic_parser_rejects(
                    case.tag,
                    &closed_field,
                    &format!("tag {} closed artifact field", case.tag),
                );
            }

            let mut crossed_cohort = vec![record, record_for(&cases[(index + 1) % cases.len()])];
            crossed_cohort
                .sort_by(|left, right| (left.tag, &left.key).cmp(&(right.tag, &right.key)));
            let crossed_cohort_digest =
                canonical_write_set_digest_records(&crossed_cohort).unwrap();
            assert!(
                verify_canonical_write_set(&crossed_cohort, &[case.tag], crossed_cohort_digest,)
                    .is_err(),
                "tag {} extra/crossed cohort",
                case.tag
            );
        }
    }

    #[test]
    fn empty_eleven_table_kat_matches_ratified_literal() {
        let snapshot = RegistrySnapshot {
            tables: (1..=11)
                .map(|tag| CanonicalTable {
                    tag,
                    rows: BTreeMap::new(),
                })
                .collect(),
        };
        assert_eq!(
            hex::encode(state_root(&snapshot).unwrap()),
            "552ff8a24ca85562511ca4fa58f035aaf013087a0ab3e956aa8d60cfcb703477"
        );
    }

    #[test]
    fn canonical_primary_key_literals_are_exact() {
        let text = |value: &[u8]| {
            let mut literal = (value.len() as u32).to_be_bytes().to_vec();
            literal.extend_from_slice(value);
            literal
        };

        let tag2 = text(b"a");
        assert_eq!(hex::encode(&tag2), "0000000161");

        let mut tag5_first = text(b"a");
        tag5_first.extend_from_slice(&text(b"bc"));
        let mut tag5_second = text(b"aa");
        tag5_second.extend_from_slice(&text(b"b"));
        assert_eq!(hex::encode(&tag5_first), "0000000161000000026263");
        assert_eq!(hex::encode(&tag5_second), "0000000261610000000162");
        assert!(tag5_first < tag5_second);

        let tag6 = [0x11_u8; 32];
        assert_eq!(
            hex::encode(tag6),
            "1111111111111111111111111111111111111111111111111111111111111111"
        );

        let tag7 = 1_u64.to_be_bytes();
        assert_eq!(hex::encode(tag7), "0000000000000001");

        let tag10 = [0x22_u8; 16];
        assert_eq!(hex::encode(tag10), "22222222222222222222222222222222");

        let mut tag11 = tag10.to_vec();
        tag11.push(1);
        tag11.extend_from_slice(&[0x33; 32]);
        assert_eq!(tag11.len(), 49);
        assert_eq!(
            hex::encode(&tag11),
            "22222222222222222222222222222222013333333333333333333333333333333333333333333333333333333333333333"
        );
    }

    #[test]
    fn text_grammar_rejects_self_digested_invalid_utf8_and_oversized_primary_keys() {
        fn component_row(id: &[u8], lifecycle: &[u8], tombstoned_at: u64) -> Vec<u8> {
            let mut row = Vec::new();
            literal_len(&mut row, id);
            literal_len(&mut row, b"sealed");
            literal_u64(&mut row, 1);
            literal_len(&mut row, &[0x42; 32]);
            literal_len(&mut row, lifecycle);
            literal_u64(&mut row, 1);
            row.push(0); // operation_id
            row.push(1);
            literal_u64(&mut row, tombstoned_at);
            row.push(0); // retain_until_ms
            row
        }

        fn unchecked_digest(record: &CanonicalWriteRecord) -> [u8; 32] {
            let mut preimage = Vec::new();
            preimage.extend_from_slice(WRITE_SET_DOMAIN);
            preimage.extend_from_slice(&1_u32.to_be_bytes());
            preimage.push(record.tag);
            literal_len(&mut preimage, &record.key);
            for row in [record.before.as_deref(), record.after.as_deref()] {
                match row {
                    Some(row) => literal_len(&mut preimage, row),
                    None => preimage.extend_from_slice(&0_u32.to_be_bytes()),
                }
            }
            Sha256::digest(preimage).into()
        }

        let mut valid_key = Vec::new();
        literal_len(&mut valid_key, b"component-a");
        let invalid_utf8 = CanonicalWriteRecord {
            tag: 1,
            key: valid_key,
            before: Some(component_row(b"component-a", &[0xff], 7)),
            after: Some(component_row(b"component-a", &[0xff], 8)),
        };
        let invalid_utf8_digest = unchecked_digest(&invalid_utf8);
        let error = verify_canonical_write_set(
            std::slice::from_ref(&invalid_utf8),
            &[1],
            invalid_utf8_digest,
        )
        .unwrap_err();
        assert!(
            error.contains("canonical text is not valid UTF-8"),
            "{error}"
        );

        let oversized_id = vec![b'x'; 257];
        let mut oversized_key = Vec::new();
        literal_len(&mut oversized_key, &oversized_id);
        let oversized = CanonicalWriteRecord {
            tag: 1,
            key: oversized_key,
            before: Some(component_row(&oversized_id, b"live", 7)),
            after: Some(component_row(&oversized_id, b"live", 8)),
        };
        let oversized_digest = unchecked_digest(&oversized);
        let error =
            verify_canonical_write_set(std::slice::from_ref(&oversized), &[1], oversized_digest)
                .unwrap_err();
        assert!(error.contains("length is outside 1..=256 bytes"), "{error}");

        // The SQLite capture entrance enforces the same grammar before any
        // canonical row or primary-key frame can be emitted.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE capture_text (id TEXT NOT NULL,value TEXT NOT NULL);
             INSERT INTO capture_text VALUES ('valid',CAST(x'ff' AS TEXT));",
        )
        .unwrap();
        let error = table(
            &conn,
            1,
            "SELECT id,value FROM capture_text",
            Key::Text(0),
            &[Kind::Text, Kind::Text],
        )
        .unwrap_err();
        assert!(
            error.contains("canonical text is not valid UTF-8"),
            "{error}"
        );

        conn.execute("DELETE FROM capture_text", []).unwrap();
        conn.execute(
            "INSERT INTO capture_text VALUES (?1,'valid')",
            ["x".repeat(257)],
        )
        .unwrap();
        let error = table(
            &conn,
            1,
            "SELECT id,value FROM capture_text",
            Key::Text(0),
            &[Kind::Text, Kind::Text],
        )
        .unwrap_err();
        assert!(error.contains("length is outside 1..=256 bytes"), "{error}");
    }

    #[test]
    fn every_operation_tag_rejects_forbidden_non_key_columns_after_a_real_valid_cohort() {
        fn assert_forbidden_column(
            operation_tag: u8,
            before: &RegistrySnapshot,
            valid_after: &RegistrySnapshot,
            table_tag: u8,
            key: &[u8],
            column: usize,
            replacement: CanonicalCell,
            expected_error: &str,
        ) {
            let mut candidate = valid_after.clone();
            replace_snapshot_cell(&mut candidate, table_tag, key, column, replacement);
            let self_digest = write_set_digest(before, &candidate)
                .unwrap_or_else(|error| panic!("table-{table_tag} candidate grammar: {error}"));
            assert_ne!(self_digest, [0; 32], "candidate must own a real digest");
            let error = match validate_operation_effects(operation_tag, before, &candidate) {
                Ok(()) => panic!(
                    "operation tag {operation_tag} accepted table-{table_tag} forbidden column {column}"
                ),
                Err(error) => error,
            };
            assert!(
                error.contains(expected_error),
                "operation tag {operation_tag}, table-{table_tag}: {error}"
            );
        }

        let mut covered_tables = BTreeSet::new();

        let (_, component_before, component_after) = registration_baseline(true);
        validate_operation_effects(1, &component_before, &component_after).unwrap();
        let component_key = text_key(b"component-a");
        let operation_key = text_key(b"reg-component");
        let member_key = two_text_key(b"reg-component", b"component-a");
        let singleton_key = 1_u64.to_be_bytes();
        for (table_tag, key, column, replacement, expected) in [
            (
                1,
                component_key.as_slice(),
                4,
                CanonicalCell::Text(b"idle".to_vec()),
                "mismatched component projection",
            ),
            (
                2,
                operation_key.as_slice(),
                2,
                CanonicalCell::Text(b"forbidden".to_vec()),
                "noncanonical operation cohort",
            ),
            (
                3,
                component_key.as_slice(),
                1,
                CanonicalCell::Text(b"forbidden".to_vec()),
                "noncanonical operation cohort",
            ),
            (
                4,
                component_key.as_slice(),
                3,
                CanonicalCell::Blob(vec![0x91; 32]),
                "authority row does not match",
            ),
            (
                5,
                member_key.as_slice(),
                5,
                CanonicalCell::Blob(vec![0x92; 32]),
                "noncanonical operation cohort",
            ),
            (
                7,
                singleton_key.as_slice(),
                2,
                CanonicalCell::Integer(1),
                "changed columns",
            ),
        ] {
            assert_forbidden_column(
                1,
                &component_before,
                &component_after,
                table_tag,
                key,
                column,
                replacement,
                expected,
            );
            covered_tables.insert(table_tag);
        }

        let (_, agent_before, agent_after) = registration_baseline(false);
        validate_operation_effects(2, &agent_before, &agent_after).unwrap();
        assert_forbidden_column(
            2,
            &agent_before,
            &agent_after,
            3,
            &text_key(b"agent-a"),
            4,
            CanonicalCell::Text(b"forbidden".to_vec()),
            "noncanonical operation cohort",
        );

        let (previsible_before, previsible_after) = previsible_allocation_baseline();
        validate_operation_effects(3, &previsible_before, &previsible_after).unwrap();
        assert_forbidden_column(
            3,
            &previsible_before,
            &previsible_after,
            6,
            &[0x41; 32],
            11,
            CanonicalCell::Text(b"rejected".to_vec()),
            "inserted a noncanonical prepared journal",
        );
        covered_tables.insert(6);

        let (_, termination_before, termination_after) = termination_prepare_baseline();
        validate_operation_effects(4, &termination_before, &termination_after).unwrap();
        assert_forbidden_column(
            4,
            &termination_before,
            &termination_after,
            8,
            &text_key(b"term-prepare"),
            8,
            CanonicalCell::Text(b"forbidden".to_vec()),
            "malformed finalization journal",
        );
        covered_tables.insert(8);
        assert_forbidden_column(
            4,
            &termination_before,
            &termination_after,
            9,
            singleton_key.as_slice(),
            2,
            CanonicalCell::Integer(101),
            "capacity reservation is not exact",
        );
        covered_tables.insert(9);

        let (finalize_before, finalize_after) = termination_finalize_baseline();
        validate_operation_effects(5, &finalize_before, &finalize_after).unwrap();
        assert_forbidden_column(
            5,
            &finalize_before,
            &finalize_after,
            8,
            &text_key(b"term-op"),
            4,
            CanonicalCell::Blob(vec![0x93; 32]),
            "changed columns",
        );

        let (host_before, host_after) = host_registration_baseline();
        validate_operation_effects(6, &host_before, &host_after).unwrap();
        assert_forbidden_column(
            6,
            &host_before,
            &host_after,
            3,
            &text_key(b"host-a"),
            3,
            CanonicalCell::Blob(vec![0x94; 32]),
            "authority row does not match",
        );

        let (carrier_before, carrier_after) = carrier_prepare_baseline();
        validate_operation_effects(6, &carrier_before, &carrier_after).unwrap();
        assert_forbidden_column(
            6,
            &carrier_before,
            &carrier_after,
            10,
            &[0x21; 16],
            4,
            CanonicalCell::Integer(999),
            "rewrote a frozen carrier plan",
        );
        covered_tables.insert(10);
        assert_forbidden_column(
            6,
            &carrier_before,
            &carrier_after,
            11,
            &literal_carrier_row_key(0x21, 1),
            9,
            CanonicalCell::Text(b"forbidden".to_vec()),
            "carrier prepare row transition is not exact",
        );
        covered_tables.insert(11);

        let (checkpoint_before, checkpoint_after) = checkpoint_baseline();
        validate_operation_effects(7, &checkpoint_before, &checkpoint_after).unwrap();
        assert_forbidden_column(
            7,
            &checkpoint_before,
            &checkpoint_after,
            6,
            &[0x71; 32],
            3,
            CanonicalCell::Integer(2),
            "outside checkpoint accounting",
        );

        let conn = retained_gc_connection(false);
        let gc_before = capture(&conn).unwrap();
        prepare_all_gc_members(&conn);
        let gc_after = capture(&conn).unwrap();
        validate_operation_effects(8, &gc_before, &gc_after).unwrap();
        assert_forbidden_column(
            8,
            &gc_before,
            &gc_after,
            5,
            &two_text_key(b"gc-op", b"agent-a"),
            5,
            CanonicalCell::Blob(vec![0x95; 32]),
            "non-GC member columns",
        );

        assert_eq!(
            covered_tables,
            (1_u8..=11).collect(),
            "every rooted table must be covered by a valid operation cohort"
        );
    }

    #[test]
    fn two_row_tag10_tag11_state_and_write_set_kat_is_independent_and_ordered() {
        fn append_len(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }

        fn independent_state_preimage(snapshot: &RegistrySnapshot) -> Vec<u8> {
            assert_eq!(snapshot.tables.len(), 11);
            let mut preimage = b"advance.contract218.registry-state-root.v1\0".to_vec();
            preimage.push(11);
            for (index, table) in snapshot.tables.iter().enumerate() {
                assert_eq!(table.tag, (index + 1) as u8);
                preimage.push(table.tag);
                preimage.extend_from_slice(&(table.rows.len() as u64).to_be_bytes());
                for (key, row) in &table.rows {
                    append_len(&mut preimage, key);
                    append_len(&mut preimage, row);
                }
            }
            preimage
        }

        fn append_insert_record(out: &mut Vec<u8>, tag: u8, key: &[u8], row: &[u8]) {
            out.push(tag);
            append_len(out, key);
            out.extend_from_slice(&0_u32.to_be_bytes());
            append_len(out, row);
        }

        fn independent_write_set_preimage(
            header_key: &[u8],
            header_row: &[u8],
            first_key: &[u8],
            first_row: &[u8],
            second_key: &[u8],
            second_row: &[u8],
        ) -> Vec<u8> {
            let mut preimage = b"advance.contract218.registry-write-set.v1\0".to_vec();
            preimage.extend_from_slice(&3_u32.to_be_bytes());
            append_insert_record(&mut preimage, 10, header_key, header_row);
            append_insert_record(&mut preimage, 11, first_key, first_row);
            append_insert_record(&mut preimage, 11, second_key, second_row);
            preimage
        }

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE components (
               id TEXT PRIMARY KEY,sensitive_params BLOB NOT NULL,
               identity_incarnation INTEGER NOT NULL,declaration_digest BLOB NOT NULL,
               lifecycle_state TEXT NOT NULL,catalog_visible INTEGER NOT NULL,
               operation_id TEXT,tombstoned_at_ms INTEGER,retain_until_ms INTEGER
             ) STRICT;",
        )
        .unwrap();
        conn.execute_batch(include_str!("observation_schema.sql"))
            .unwrap();

        // The single header owns both rows. Insert the larger canonical key
        // first so capture must discard SQL insertion order.
        install_sql_carrier_header(&conn, 0x22);
        install_sql_carrier_row(&conn, 0x22, 2, 0x44, 0x66);
        install_sql_carrier_row(&conn, 0x22, 1, 0x33, 0x55);

        let captured = capture(&conn).unwrap();
        let mut independent = snapshot_with_capacity_singletons();
        let header_key = vec![0x22; 16];
        let header_row = literal_carrier_header(0x22);
        independent.tables[9]
            .rows
            .insert(header_key.clone(), header_row.clone());

        let first_key = literal_carrier_row_key_with_event(0x22, 1, 0x33);
        let first_row = literal_carrier_row_with_event_and_nonce(0x22, 1, 0x33, 0x55);
        let second_key = literal_carrier_row_key_with_event(0x22, 2, 0x44);
        let second_row = literal_carrier_row_with_event_and_nonce(0x22, 2, 0x44, 0x66);
        assert_eq!(first_key.len(), 49);
        assert_eq!(second_key.len(), 49);
        assert_eq!(
            hex::encode(&first_key),
            "22222222222222222222222222222222013333333333333333333333333333333333333333333333333333333333333333"
        );
        assert_eq!(
            hex::encode(&second_key),
            "22222222222222222222222222222222024444444444444444444444444444444444444444444444444444444444444444"
        );
        assert!(first_key < second_key);
        independent.tables[10]
            .rows
            .insert(first_key.clone(), first_row.clone());
        independent.tables[10]
            .rows
            .insert(second_key.clone(), second_row.clone());
        assert_eq!(captured, independent);
        assert_eq!(
            captured.tables[10].rows.keys().cloned().collect::<Vec<_>>(),
            vec![first_key.clone(), second_key.clone()]
        );

        let baseline = snapshot_with_capacity_singletons();
        let state_preimage = independent_state_preimage(&independent);
        let write_set_preimage = independent_write_set_preimage(
            &header_key,
            &header_row,
            &first_key,
            &first_row,
            &second_key,
            &second_row,
        );
        let independent_state_digest: [u8; 32] = Sha256::digest(&state_preimage).into();
        let independent_write_set_digest: [u8; 32] = Sha256::digest(&write_set_preimage).into();
        assert_eq!(
            hex::encode(independent_state_digest),
            "c1337c58fed242fedf7bc694521b4ee4b20a4b1290b769f752201d0af282c3a1"
        );
        assert_eq!(
            hex::encode(independent_write_set_digest),
            "482155f3fe762dc1dd6781f77489ccdfe36a6a8d43bf8c0cf7f2b0dee1a194c8"
        );
        assert_eq!(state_root(&captured).unwrap(), independent_state_digest);
        assert_eq!(
            write_set_digest(&baseline, &captured).unwrap(),
            independent_write_set_digest
        );
    }

    #[test]
    fn carrier_literal_missing_inner_length_and_duplicate_keys_reject() {
        let row = literal_carrier_header(0x21);
        assert!(decode_canonical_row(10, &row[4..]).is_err());

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE duplicate_headers (migration_id BLOB NOT NULL);
             INSERT INTO duplicate_headers VALUES (x'01010101010101010101010101010101');
             INSERT INTO duplicate_headers VALUES (x'01010101010101010101010101010101');
             CREATE TABLE duplicate_rows (
               migration_id BLOB NOT NULL,store_kind INTEGER NOT NULL,event_digest BLOB NOT NULL
             );
             INSERT INTO duplicate_rows VALUES
               (x'02020202020202020202020202020202',1,zeroblob(32));
             INSERT INTO duplicate_rows VALUES
               (x'02020202020202020202020202020202',1,zeroblob(32));",
        )
        .unwrap();
        assert!(table(
            &conn,
            10,
            "SELECT migration_id FROM duplicate_headers",
            Key::Blob16(0),
            &[Kind::Blob],
        )
        .unwrap_err()
        .contains("duplicate canonical key"));
        assert!(table(
            &conn,
            11,
            "SELECT migration_id,store_kind,event_digest FROM duplicate_rows",
            Key::MigrationRow {
                migration: 0,
                store_kind: 1,
                event_digest: 2,
            },
            &[Kind::Blob, Kind::Int, Kind::Blob],
        )
        .unwrap_err()
        .contains("duplicate canonical key"));
    }

    #[test]
    fn tag8_prepare_rejects_partial_mixed_and_retained_deletion() {
        let conn = retained_gc_connection(false);
        let before = capture(&conn).unwrap();
        conn.execute(
            "UPDATE observation_identity_operation_members
             SET gc_challenge_nonce=?1,gc_tombstone_state_root=?2,gc_operation_boot=?3,
                 gc_phase='prepared',gc_generation=1,gc_registry_sequence=5
             WHERE identity_id='agent-a'",
            rusqlite::params![
                [0x71_u8; 32].as_slice(),
                [0x72_u8; 32].as_slice(),
                [0x73_u8; 16].as_slice(),
            ],
        )
        .unwrap();
        let partial = capture(&conn).unwrap();
        assert!(validate_operation_effects(8, &before, &partial)
            .unwrap_err()
            .contains("partial"));

        let conn = retained_gc_connection(false);
        let before = capture(&conn).unwrap();
        prepare_all_gc_members(&conn);
        conn.execute(
            "UPDATE observation_identity_operation_members
             SET gc_challenge_nonce=?1 WHERE identity_id='agent-b'",
            [[0x74_u8; 32].as_slice()],
        )
        .unwrap();
        let mixed = capture(&conn).unwrap();
        assert!(validate_operation_effects(8, &before, &mixed)
            .unwrap_err()
            .contains("mixed challenge metadata"));

        let conn = retained_gc_connection(false);
        let before = capture(&conn).unwrap();
        prepare_all_gc_members(&conn);
        conn.execute("DELETE FROM observation_identities WHERE id='agent-a'", [])
            .unwrap();
        let deleted = capture(&conn).unwrap();
        assert!(validate_operation_effects(8, &before, &deleted)
            .unwrap_err()
            .contains("changed recursive table tags"));
    }

    #[test]
    fn tag8_commit_requires_full_corresponding_retained_deletion() {
        let conn = retained_gc_connection(true);
        let before = capture(&conn).unwrap();
        collect_all_gc_members(&conn);
        conn.execute("DELETE FROM observation_identities WHERE id='agent-a'", [])
            .unwrap();
        let partial = capture(&conn).unwrap();
        assert!(validate_operation_effects(8, &before, &partial)
            .unwrap_err()
            .contains("complete retained identity cohort"));

        let conn = retained_gc_connection(true);
        let before = capture(&conn).unwrap();
        collect_all_gc_members(&conn);
        conn.execute("DELETE FROM observation_identities", [])
            .unwrap();
        let complete = capture(&conn).unwrap();
        validate_operation_effects(8, &before, &complete).unwrap();
    }

    #[test]
    fn tag5_releases_unused_envelope_keeps_eight_future_and_rejects_growth_or_counter_mismatch() {
        let (legal_before, legal_after) = termination_finalize_baseline();
        validate_operation_effects(5, &legal_before, &legal_after).unwrap();

        let finalization_key = text_key(b"term-op");
        let capacity_key = 1_u64.to_be_bytes();
        let old_finalization = decode_canonical_row(
            8,
            legal_before.tables[7]
                .rows
                .get(&finalization_key)
                .expect("prepared finalization row"),
        )
        .unwrap();
        let new_finalization = decode_canonical_row(
            8,
            legal_after.tables[7]
                .rows
                .get(&finalization_key)
                .expect("terminal finalization row"),
        )
        .unwrap();
        let old_capacity = decode_canonical_row(
            9,
            legal_before.tables[8]
                .rows
                .get(capacity_key.as_slice())
                .expect("prepared capacity row"),
        )
        .unwrap();
        let new_capacity = decode_canonical_row(
            9,
            legal_after.tables[8]
                .rows
                .get(capacity_key.as_slice())
                .expect("terminal capacity row"),
        )
        .unwrap();

        let old_encoded = old_finalization[18].integer("old encoded bytes").unwrap();
        let old_future = old_finalization[19]
            .integer("old future reserved bytes")
            .unwrap();
        let new_encoded = new_finalization[18].integer("new encoded bytes").unwrap();
        let new_future = new_finalization[19]
            .integer("new future reserved bytes")
            .unwrap();
        let terminal_actual_delta = new_encoded - old_encoded;
        let future_reserved_delta = old_future - new_future;
        let unused_envelope_released = future_reserved_delta - terminal_actual_delta;

        assert_eq!(old_encoded + old_future, TERMINATION_FINALIZE_TOTAL_BYTES);
        assert_eq!((old_encoded, old_future), (159, 1_889));
        assert_eq!((new_encoded, new_future), (367, AUDIT_CHECKPOINT_BYTES));
        assert_eq!(terminal_actual_delta, 208);
        assert_eq!(unused_envelope_released, 1_673);
        assert_eq!(new_future, 8);
        assert!(new_encoded + new_future <= old_encoded + old_future);

        let old_capacity_rows = old_capacity[1].integer("old capacity row count").unwrap();
        let old_capacity_actual = old_capacity[2]
            .integer("old capacity actual bytes")
            .unwrap();
        let old_capacity_future = old_capacity[3]
            .integer("old capacity future bytes")
            .unwrap();
        let new_capacity_rows = new_capacity[1].integer("new capacity row count").unwrap();
        let new_capacity_actual = new_capacity[2]
            .integer("new capacity actual bytes")
            .unwrap();
        let new_capacity_future = new_capacity[3]
            .integer("new capacity future bytes")
            .unwrap();
        assert_eq!(new_capacity_rows, old_capacity_rows);
        assert_eq!(
            new_capacity_actual,
            old_capacity_actual + terminal_actual_delta
        );
        assert_eq!(
            new_capacity_future,
            old_capacity_future - future_reserved_delta
        );
        assert_eq!(
            old_capacity_actual + old_capacity_future - (new_capacity_actual + new_capacity_future),
            unused_envelope_released
        );

        // Growing the terminal row past the prepared envelope is rejected even
        // when the capacity counter is changed by the same apparent delta.
        let mut combined_growth = legal_after.clone();
        replace_snapshot_cell(
            &mut combined_growth,
            8,
            &finalization_key,
            18,
            CanonicalCell::Integer(2_041),
        );
        replace_snapshot_cell(
            &mut combined_growth,
            9,
            &capacity_key,
            2,
            CanonicalCell::Integer(2_041),
        );
        assert!(
            validate_operation_effects(5, &legal_before, &combined_growth)
                .unwrap_err()
                .contains("finalization byte transfer is not exact")
        );

        let mut counter_mismatch = legal_after.clone();
        replace_snapshot_cell(
            &mut counter_mismatch,
            9,
            &capacity_key,
            2,
            CanonicalCell::Integer(368),
        );
        assert!(
            validate_operation_effects(5, &legal_before, &counter_mismatch)
                .unwrap_err()
                .contains("finalization capacity transfer is not exact")
        );
    }

    #[test]
    fn tag5_frozen_prepare_receipts_and_ack_cannot_be_rewritten() {
        let capacity_key = 1_u64.to_be_bytes();
        let (_, prepare_before, mut under_reserved_prepare) = termination_prepare_baseline();
        replace_snapshot_cell(
            &mut under_reserved_prepare,
            8,
            &text_key(b"term-prepare"),
            19,
            CanonicalCell::Integer(1_883),
        );
        replace_snapshot_cell(
            &mut under_reserved_prepare,
            9,
            &capacity_key,
            3,
            CanonicalCell::Integer(1_883),
        );
        assert!(
            validate_operation_effects(4, &prepare_before, &under_reserved_prepare)
                .unwrap_err()
                .contains("termination capacity reservation is not exact")
        );

        let conn = termination_finalize_connection();
        let before = capture(&conn).unwrap();
        conn.execute_batch(
            "UPDATE observation_identity_operations
             SET phase='committed',is_active=0 WHERE operation_id='term-op';
             UPDATE observation_identity_operation_members
             SET is_active=0 WHERE operation_id='term-op';
             UPDATE observation_identities
             SET lifecycle_state='tombstoned',tombstoned_at_ms=1 WHERE id='agent-z';
             UPDATE observation_termination_finalizations
             SET prepare_ack_digest=zeroblob(32),phase='finalized',
                 cleanup_receipt_digest=zeroblob(32),cleanup_high_water_digest=zeroblob(32),
                 cleanup_receipt_set_digest=zeroblob(32),cleanup_nonce=zeroblob(32),
                 finalize_recovery_nonce=zeroblob(32),finalize_sequence=2,
                 finalize_ack_digest=zeroblob(32),terminal_at_ms=1,
                 encoded_bytes=367,future_reserved_bytes=8
             WHERE operation_id='term-op';
             UPDATE observation_termination_finalize_capacity
             SET actual_encoded_bytes=367,future_reserved_bytes=8 WHERE singleton=1;",
        )
        .unwrap();
        let after = capture(&conn).unwrap();
        assert!(validate_operation_effects(5, &before, &after)
            .unwrap_err()
            .contains("changed columns"));
    }
}
