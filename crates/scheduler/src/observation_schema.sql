CREATE TABLE IF NOT EXISTS observation_identity_operations (
    operation_id TEXT PRIMARY KEY CHECK (
        length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 256
    ),
    kind TEXT NOT NULL CHECK (
        kind IN ('register-agent','register-component','terminate-agents','terminate-component')
    ),
    phase TEXT NOT NULL CHECK (phase IN ('prepared','committed')),
    is_active INTEGER NOT NULL CHECK (is_active IN (0,1)),
    retain_until_ms INTEGER,
    termination_emission_receipt_set_digest BLOB CHECK (
        termination_emission_receipt_set_digest IS NULL OR
        (typeof(termination_emission_receipt_set_digest)='blob' AND
         length(termination_emission_receipt_set_digest)=32)
    ),
    CHECK ((phase='prepared' AND is_active=1) OR
           (phase='committed' AND is_active=0)),
    CHECK ((kind IN ('register-agent','register-component') AND retain_until_ms IS NULL) OR
           (kind IN ('terminate-agents','terminate-component') AND
            retain_until_ms IS NOT NULL AND retain_until_ms >= 0)),
    CHECK ((termination_emission_receipt_set_digest IS NOT NULL) =
           (kind IN ('terminate-agents','terminate-component'))),
    UNIQUE(operation_id,kind)
) STRICT;

CREATE TABLE IF NOT EXISTS observation_identities (
    id TEXT PRIMARY KEY CHECK (length(CAST(id AS BLOB)) BETWEEN 1 AND 256),
    class TEXT NOT NULL CHECK (class IN ('component','agent','host')),
    incarnation INTEGER NOT NULL CHECK (incarnation > 0),
    declaration_digest BLOB NOT NULL CHECK (
        typeof(declaration_digest)='blob' AND length(declaration_digest)=32
    ),
    lifecycle_state TEXT NOT NULL CHECK (
        lifecycle_state IN ('pending','live','terminating','tombstoned','permanent')
    ),
    catalog_visible INTEGER NOT NULL CHECK (catalog_visible IN (0,1)),
    operation_id TEXT,
    tombstoned_at_ms INTEGER,
    retain_until_ms INTEGER,
    CHECK (
      (lifecycle_state IN ('pending','live','permanent') AND
       tombstoned_at_ms IS NULL AND retain_until_ms IS NULL) OR
      (lifecycle_state='terminating' AND tombstoned_at_ms IS NULL AND
       retain_until_ms IS NOT NULL AND retain_until_ms >= 0) OR
      (lifecycle_state='tombstoned' AND tombstoned_at_ms IS NOT NULL AND
       tombstoned_at_ms >= 0 AND retain_until_ms IS NOT NULL AND
       retain_until_ms >= tombstoned_at_ms)
    ),
    CHECK ((class='host') = (lifecycle_state='permanent')),
    CHECK ((lifecycle_state='pending' AND catalog_visible=0) OR
           lifecycle_state='live' OR
           (lifecycle_state IN ('terminating','tombstoned','permanent') AND catalog_visible=1)),
    CHECK (catalog_visible=1 OR operation_id IS NOT NULL),
    CHECK (lifecycle_state NOT IN ('pending','terminating','tombstoned') OR
           operation_id IS NOT NULL),
    CHECK (class!='host' OR operation_id IS NULL),
    UNIQUE(id,class,incarnation,declaration_digest),
    FOREIGN KEY(operation_id) REFERENCES observation_identity_operations(operation_id)
      ON DELETE RESTRICT
) STRICT;

CREATE TABLE IF NOT EXISTS observation_identity_authority (
    id TEXT PRIMARY KEY CHECK (length(CAST(id AS BLOB)) BETWEEN 1 AND 256),
    class TEXT NOT NULL CHECK (class IN ('component','agent','host')),
    last_incarnation INTEGER NOT NULL CHECK (last_incarnation > 0),
    last_declaration_digest BLOB NOT NULL CHECK (
        typeof(last_declaration_digest)='blob' AND length(last_declaration_digest)=32
    )
) STRICT;

CREATE TABLE IF NOT EXISTS observation_identity_operation_members (
    operation_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    identity_class TEXT NOT NULL CHECK (identity_class IN ('component','agent','host')),
    identity_incarnation INTEGER NOT NULL CHECK (identity_incarnation > 0),
    declaration_digest BLOB NOT NULL CHECK (
        typeof(declaration_digest)='blob' AND length(declaration_digest)=32
    ),
    termination_subject_receipt_digest BLOB CHECK (
        termination_subject_receipt_digest IS NULL OR
        (typeof(termination_subject_receipt_digest)='blob' AND
         length(termination_subject_receipt_digest)=32)
    ),
    termination_emission_receipt_digest BLOB CHECK (
        termination_emission_receipt_digest IS NULL OR
        (typeof(termination_emission_receipt_digest)='blob' AND
         length(termination_emission_receipt_digest)=32)
    ),
    gc_subject_receipt_digest BLOB CHECK (
        gc_subject_receipt_digest IS NULL OR
        (typeof(gc_subject_receipt_digest)='blob' AND length(gc_subject_receipt_digest)=32)
    ),
    gc_reference_scan_digest BLOB CHECK (
        gc_reference_scan_digest IS NULL OR
        (typeof(gc_reference_scan_digest)='blob' AND length(gc_reference_scan_digest)=32)
    ),
    gc_challenge_nonce BLOB CHECK (
        gc_challenge_nonce IS NULL OR
        (typeof(gc_challenge_nonce)='blob' AND length(gc_challenge_nonce)=32)
    ),
    gc_tombstone_state_root BLOB CHECK (
        gc_tombstone_state_root IS NULL OR
        (typeof(gc_tombstone_state_root)='blob' AND length(gc_tombstone_state_root)=32)
    ),
    gc_operation_boot BLOB CHECK (
        gc_operation_boot IS NULL OR
        (typeof(gc_operation_boot)='blob' AND length(gc_operation_boot)=16)
    ),
    gc_phase TEXT NOT NULL DEFAULT 'idle' CHECK (
        gc_phase IN ('idle','prepared','collected')
    ),
    gc_generation INTEGER NOT NULL DEFAULT 0 CHECK (gc_generation >= 0),
    gc_registry_sequence INTEGER CHECK (
        gc_registry_sequence IS NULL OR gc_registry_sequence > 0
    ),
    gc_challenge_consumed INTEGER NOT NULL DEFAULT 0 CHECK (
        gc_challenge_consumed IN (0,1)
    ),
    is_active INTEGER NOT NULL CHECK (is_active IN (0,1)),
    CHECK ((gc_subject_receipt_digest IS NULL) = (gc_reference_scan_digest IS NULL)),
    CHECK (
      (gc_phase='idle' AND gc_generation=0 AND gc_registry_sequence IS NULL AND
       gc_challenge_nonce IS NULL AND gc_tombstone_state_root IS NULL AND
       gc_operation_boot IS NULL AND
       gc_challenge_consumed=0 AND
       gc_subject_receipt_digest IS NULL AND gc_reference_scan_digest IS NULL) OR
      (gc_phase='prepared' AND gc_generation>0 AND gc_registry_sequence IS NOT NULL AND
       gc_challenge_nonce IS NOT NULL AND gc_tombstone_state_root IS NOT NULL AND
       gc_operation_boot IS NOT NULL AND
       gc_challenge_consumed=0 AND
       gc_subject_receipt_digest IS NULL AND gc_reference_scan_digest IS NULL) OR
      (gc_phase='collected' AND gc_generation>0 AND gc_registry_sequence IS NOT NULL AND
       gc_challenge_nonce IS NOT NULL AND gc_tombstone_state_root IS NOT NULL AND
       gc_operation_boot IS NOT NULL AND
       gc_challenge_consumed=1 AND
       gc_subject_receipt_digest IS NOT NULL AND gc_reference_scan_digest IS NOT NULL)
    ),
    PRIMARY KEY(operation_id,identity_id),
    UNIQUE(operation_id,identity_id,identity_class,identity_incarnation,declaration_digest),
    FOREIGN KEY(operation_id) REFERENCES observation_identity_operations(operation_id)
      ON DELETE RESTRICT,
    FOREIGN KEY(identity_id) REFERENCES observation_identity_authority(id)
      ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_observation_identity_one_active_operation
    ON observation_identity_operation_members(identity_id) WHERE is_active=1;

CREATE TABLE IF NOT EXISTS observation_previsible_activations (
    activation_nonce BLOB PRIMARY KEY CHECK (
        typeof(activation_nonce)='blob' AND length(activation_nonce)=32
    ),
    boot_id BLOB NOT NULL CHECK (typeof(boot_id)='blob' AND length(boot_id)=16),
    registry_instance_id BLOB NOT NULL CHECK (
        typeof(registry_instance_id)='blob' AND length(registry_instance_id)=16
    ),
    role INTEGER NOT NULL CHECK (role IN (1,2)),
    operation_id TEXT NOT NULL CHECK (
        length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 256
    ),
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN ('register-agent','register-component')
    ),
    identity_id TEXT NOT NULL CHECK (
        length(CAST(identity_id AS BLOB)) BETWEEN 1 AND 256
    ),
    identity_class TEXT NOT NULL CHECK (identity_class IN ('component','agent')),
    identity_incarnation INTEGER NOT NULL CHECK (identity_incarnation > 0),
    declaration_digest BLOB NOT NULL CHECK (
        typeof(declaration_digest)='blob' AND length(declaration_digest)=32
    ),
    registry_sequence INTEGER NOT NULL CHECK (registry_sequence >= 0),
    phase TEXT NOT NULL CHECK (
        phase IN ('prepared','ready','publishing','rejected','published','aborting','aborted')
    ),
    subject_receipt_digest BLOB,
    table_receipt_digest BLOB,
    lifecycle_receipt_digest BLOB,
    subject_absence_digest BLOB,
    table_absence_digest BLOB,
    lifecycle_absence_digest BLOB,
    ready_proof_nonce BLOB,
    abort_proof_nonce BLOB,
    rejection_nonce BLOB,
    recovery_nonce BLOB,
    updated_sequence INTEGER NOT NULL CHECK (updated_sequence >= registry_sequence),
    terminal_at_ms INTEGER,
    audit_checkpoint_sequence INTEGER,
    encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes BETWEEN 147 AND 4096),
    future_reserved_bytes INTEGER NOT NULL CHECK (future_reserved_bytes BETWEEN 0 AND 4096),
    CHECK (
      (subject_receipt_digest IS NULL OR
       (typeof(subject_receipt_digest)='blob' AND length(subject_receipt_digest)=32)) AND
      (table_receipt_digest IS NULL OR
       (typeof(table_receipt_digest)='blob' AND length(table_receipt_digest)=32)) AND
      (lifecycle_receipt_digest IS NULL OR
       (typeof(lifecycle_receipt_digest)='blob' AND length(lifecycle_receipt_digest)=32)) AND
      (subject_absence_digest IS NULL OR
       (typeof(subject_absence_digest)='blob' AND length(subject_absence_digest)=32)) AND
      (table_absence_digest IS NULL OR
       (typeof(table_absence_digest)='blob' AND length(table_absence_digest)=32)) AND
      (lifecycle_absence_digest IS NULL OR
       (typeof(lifecycle_absence_digest)='blob' AND length(lifecycle_absence_digest)=32)) AND
      (ready_proof_nonce IS NULL OR
       (typeof(ready_proof_nonce)='blob' AND length(ready_proof_nonce)=32)) AND
      (abort_proof_nonce IS NULL OR
       (typeof(abort_proof_nonce)='blob' AND length(abort_proof_nonce)=32)) AND
      (rejection_nonce IS NULL OR
       (typeof(rejection_nonce)='blob' AND length(rejection_nonce)=32)) AND
      (recovery_nonce IS NULL OR
       (typeof(recovery_nonce)='blob' AND length(recovery_nonce)=32))
    ),
    CHECK (
      (phase='prepared' AND
       subject_receipt_digest IS NULL AND table_receipt_digest IS NULL AND
       lifecycle_receipt_digest IS NULL AND subject_absence_digest IS NULL AND
       table_absence_digest IS NULL AND lifecycle_absence_digest IS NULL AND
       ready_proof_nonce IS NULL AND abort_proof_nonce IS NULL AND
       rejection_nonce IS NULL AND recovery_nonce IS NULL) OR
      (phase='ready' AND
       subject_receipt_digest IS NOT NULL AND table_receipt_digest IS NOT NULL AND
       lifecycle_receipt_digest IS NOT NULL AND subject_absence_digest IS NULL AND
       table_absence_digest IS NULL AND lifecycle_absence_digest IS NULL AND
       ready_proof_nonce IS NOT NULL AND abort_proof_nonce IS NULL AND
       rejection_nonce IS NULL AND recovery_nonce IS NOT NULL) OR
      (phase='publishing' AND
       subject_receipt_digest IS NOT NULL AND table_receipt_digest IS NOT NULL AND
       lifecycle_receipt_digest IS NOT NULL AND subject_absence_digest IS NULL AND
       table_absence_digest IS NULL AND lifecycle_absence_digest IS NULL AND
       ready_proof_nonce IS NOT NULL AND abort_proof_nonce IS NULL AND
       rejection_nonce IS NULL AND recovery_nonce IS NOT NULL) OR
      (phase='rejected' AND
       subject_receipt_digest IS NOT NULL AND table_receipt_digest IS NOT NULL AND
       lifecycle_receipt_digest IS NOT NULL AND subject_absence_digest IS NULL AND
       table_absence_digest IS NULL AND lifecycle_absence_digest IS NULL AND
       ready_proof_nonce IS NOT NULL AND abort_proof_nonce IS NULL AND
       rejection_nonce IS NOT NULL AND recovery_nonce IS NOT NULL) OR
      (phase='published' AND
       subject_receipt_digest IS NOT NULL AND table_receipt_digest IS NOT NULL AND
       lifecycle_receipt_digest IS NOT NULL AND subject_absence_digest IS NULL AND
       table_absence_digest IS NULL AND lifecycle_absence_digest IS NULL AND
       ready_proof_nonce IS NOT NULL AND abort_proof_nonce IS NULL AND
       rejection_nonce IS NULL AND recovery_nonce IS NOT NULL) OR
      (phase IN ('aborting','aborted') AND
       subject_absence_digest IS NOT NULL AND table_absence_digest IS NOT NULL AND
       lifecycle_absence_digest IS NOT NULL AND abort_proof_nonce IS NOT NULL AND
       recovery_nonce IS NOT NULL AND
       ((subject_receipt_digest IS NULL AND table_receipt_digest IS NULL AND
         lifecycle_receipt_digest IS NULL AND ready_proof_nonce IS NULL AND
         rejection_nonce IS NULL) OR
        (subject_receipt_digest IS NOT NULL AND table_receipt_digest IS NOT NULL AND
         lifecycle_receipt_digest IS NOT NULL AND ready_proof_nonce IS NOT NULL)))
    ),
    CHECK ((phase IN ('published','aborted')) = (terminal_at_ms IS NOT NULL)),
    CHECK (audit_checkpoint_sequence IS NULL OR phase IN ('published','aborted')),
    CHECK ((phase IN ('published','aborted') AND
            ((audit_checkpoint_sequence IS NULL AND future_reserved_bytes=8) OR
             (audit_checkpoint_sequence IS NOT NULL AND future_reserved_bytes=0))) OR
           (phase NOT IN ('published','aborted') AND
            encoded_bytes + future_reserved_bytes=4096)),
    FOREIGN KEY(operation_id,operation_kind)
      REFERENCES observation_identity_operations(operation_id,kind) ON DELETE RESTRICT,
    FOREIGN KEY(operation_id,identity_id,identity_class,identity_incarnation,declaration_digest)
      REFERENCES observation_identity_operation_members(
        operation_id,identity_id,identity_class,identity_incarnation,declaration_digest
      ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE IF NOT EXISTS observation_previsible_capacity (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    row_count INTEGER NOT NULL CHECK (row_count BETWEEN 0 AND 65536),
    actual_encoded_bytes INTEGER NOT NULL CHECK (
        actual_encoded_bytes BETWEEN 0 AND 16777216
    ),
    future_reserved_bytes INTEGER NOT NULL CHECK (
        future_reserved_bytes BETWEEN 0 AND 16777216
    ),
    CHECK (actual_encoded_bytes + future_reserved_bytes <= 16777216)
) STRICT;
INSERT OR IGNORE INTO observation_previsible_capacity
    (singleton,row_count,actual_encoded_bytes,future_reserved_bytes) VALUES (1,0,0,0);

CREATE TABLE IF NOT EXISTS observation_termination_finalizations (
    operation_id TEXT PRIMARY KEY CHECK (
        length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 256
    ),
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN ('terminate-agents','terminate-component')
    ),
    registry_instance_id BLOB NOT NULL CHECK (
        typeof(registry_instance_id)='blob' AND length(registry_instance_id)=16
    ),
    operation_boot_id BLOB NOT NULL CHECK (
        typeof(operation_boot_id)='blob' AND length(operation_boot_id)=16
    ),
    prepare_ack_digest BLOB NOT NULL CHECK (
        typeof(prepare_ack_digest)='blob' AND length(prepare_ack_digest)=32
    ),
    prepare_ack_nonce BLOB NOT NULL CHECK (
        typeof(prepare_ack_nonce)='blob' AND length(prepare_ack_nonce)=32
    ),
    prepare_sequence INTEGER NOT NULL CHECK (prepare_sequence > 0),
    member_set_digest BLOB NOT NULL CHECK (
        typeof(member_set_digest)='blob' AND length(member_set_digest)=32
    ),
    phase TEXT NOT NULL CHECK (phase IN ('prepared','finalized')),
    cleanup_receipt_digest BLOB,
    cleanup_high_water_digest BLOB,
    cleanup_receipt_set_digest BLOB,
    cleanup_nonce BLOB,
    finalize_recovery_nonce BLOB,
    finalize_sequence INTEGER,
    finalize_ack_digest BLOB,
    terminal_at_ms INTEGER,
    audit_checkpoint_sequence INTEGER,
    encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes BETWEEN 1 AND 2048),
    future_reserved_bytes INTEGER NOT NULL CHECK (future_reserved_bytes BETWEEN 0 AND 2048),
    CHECK (
      (cleanup_receipt_digest IS NULL OR
       (typeof(cleanup_receipt_digest)='blob' AND length(cleanup_receipt_digest)=32)) AND
      (cleanup_high_water_digest IS NULL OR
       (typeof(cleanup_high_water_digest)='blob' AND length(cleanup_high_water_digest)=32)) AND
      (cleanup_receipt_set_digest IS NULL OR
       (typeof(cleanup_receipt_set_digest)='blob' AND length(cleanup_receipt_set_digest)=32)) AND
      (cleanup_nonce IS NULL OR
       (typeof(cleanup_nonce)='blob' AND length(cleanup_nonce)=32)) AND
      (finalize_recovery_nonce IS NULL OR
       (typeof(finalize_recovery_nonce)='blob' AND length(finalize_recovery_nonce)=32)) AND
      (finalize_sequence IS NULL OR finalize_sequence > 0) AND
      (finalize_ack_digest IS NULL OR
       (typeof(finalize_ack_digest)='blob' AND length(finalize_ack_digest)=32)) AND
      (terminal_at_ms IS NULL OR terminal_at_ms >= 0) AND
      (audit_checkpoint_sequence IS NULL OR audit_checkpoint_sequence >= 0)
    ),
    CHECK (
      (phase='prepared' AND cleanup_receipt_digest IS NULL AND
       cleanup_high_water_digest IS NULL AND cleanup_receipt_set_digest IS NULL AND
       cleanup_nonce IS NULL AND finalize_recovery_nonce IS NULL AND
       finalize_sequence IS NULL AND finalize_ack_digest IS NULL AND
       terminal_at_ms IS NULL AND audit_checkpoint_sequence IS NULL AND
       encoded_bytes + future_reserved_bytes=2048) OR
      (phase='finalized' AND cleanup_receipt_digest IS NOT NULL AND
       cleanup_high_water_digest IS NOT NULL AND cleanup_receipt_set_digest IS NOT NULL AND
       cleanup_nonce IS NOT NULL AND finalize_recovery_nonce IS NOT NULL AND
       finalize_sequence IS NOT NULL AND finalize_sequence > prepare_sequence AND
       finalize_ack_digest IS NOT NULL AND terminal_at_ms IS NOT NULL AND
       ((audit_checkpoint_sequence IS NULL AND future_reserved_bytes=8) OR
        (audit_checkpoint_sequence IS NOT NULL AND future_reserved_bytes=0)))
    ),
    CHECK (audit_checkpoint_sequence IS NULL OR phase='finalized'),
    FOREIGN KEY(operation_id,operation_kind)
      REFERENCES observation_identity_operations(operation_id,kind) ON DELETE RESTRICT
) STRICT;

CREATE TABLE IF NOT EXISTS observation_termination_finalize_capacity (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    row_count INTEGER NOT NULL CHECK (row_count BETWEEN 0 AND 65536),
    actual_encoded_bytes INTEGER NOT NULL CHECK (
        actual_encoded_bytes BETWEEN 0 AND 67108864
    ),
    future_reserved_bytes INTEGER NOT NULL CHECK (
        future_reserved_bytes BETWEEN 0 AND 67108864
    ),
    CHECK (actual_encoded_bytes + future_reserved_bytes <= 67108864)
) STRICT;
INSERT OR IGNORE INTO observation_termination_finalize_capacity
    (singleton,row_count,actual_encoded_bytes,future_reserved_bytes) VALUES (1,0,0,0);

CREATE TABLE IF NOT EXISTS observation_carrier_migrations (
    migration_id BLOB PRIMARY KEY CHECK (
        typeof(migration_id)='blob' AND length(migration_id)=16
    ),
    registry_instance_id BLOB NOT NULL CHECK (
        typeof(registry_instance_id)='blob' AND length(registry_instance_id)=16
    ),
    m019_ledger_instance_id BLOB NOT NULL CHECK (
        typeof(m019_ledger_instance_id)='blob' AND length(m019_ledger_instance_id)=16
    ),
    cross_owner_key_epoch INTEGER NOT NULL CHECK (
        cross_owner_key_epoch BETWEEN 1 AND 4294967295
    ),
    source_m019_sequence INTEGER NOT NULL CHECK (source_m019_sequence >= 0),
    source_m019_head BLOB NOT NULL CHECK (
        typeof(source_m019_head)='blob' AND length(source_m019_head)=32
    ),
    source_m019_state_root BLOB NOT NULL CHECK (
        typeof(source_m019_state_root)='blob' AND length(source_m019_state_root)=32
    ),
    target_m019_sequence INTEGER NOT NULL CHECK (
        target_m019_sequence >= source_m019_sequence
    ),
    target_m019_head BLOB NOT NULL CHECK (
        typeof(target_m019_head)='blob' AND length(target_m019_head)=32
    ),
    target_m019_state_root BLOB NOT NULL CHECK (
        typeof(target_m019_state_root)='blob' AND length(target_m019_state_root)=32
    ),
    sqlite_store_instance_digest BLOB NOT NULL CHECK (
        typeof(sqlite_store_instance_digest)='blob' AND length(sqlite_store_instance_digest)=32
    ),
    sqlite_retained_high_water INTEGER NOT NULL CHECK (sqlite_retained_high_water >= 0),
    sqlite_source_root BLOB NOT NULL CHECK (
        typeof(sqlite_source_root)='blob' AND length(sqlite_source_root)=32
    ),
    sqlite_target_root BLOB NOT NULL CHECK (
        typeof(sqlite_target_root)='blob' AND length(sqlite_target_root)=32
    ),
    jsonl_store_instance_digest BLOB NOT NULL CHECK (
        typeof(jsonl_store_instance_digest)='blob' AND length(jsonl_store_instance_digest)=32
    ),
    jsonl_retained_high_water INTEGER NOT NULL CHECK (jsonl_retained_high_water >= 0),
    jsonl_source_inventory_root BLOB NOT NULL CHECK (
        typeof(jsonl_source_inventory_root)='blob' AND length(jsonl_source_inventory_root)=32
    ),
    jsonl_target_inventory_root BLOB NOT NULL CHECK (
        typeof(jsonl_target_inventory_root)='blob' AND length(jsonl_target_inventory_root)=32
    ),
    frozen_row_set_digest BLOB NOT NULL CHECK (
        typeof(frozen_row_set_digest)='blob' AND length(frozen_row_set_digest)=32
    ),
    owner_plan_digest BLOB NOT NULL CHECK (
        typeof(owner_plan_digest)='blob' AND length(owner_plan_digest)=32
    ),
    freeze_receipt_digest BLOB NOT NULL CHECK (
        typeof(freeze_receipt_digest)='blob' AND length(freeze_receipt_digest)=32
    ),
    planned_row_count INTEGER NOT NULL CHECK (planned_row_count BETWEEN 0 AND 4194304),
    issued_row_count INTEGER NOT NULL CHECK (
        issued_row_count BETWEEN 0 AND planned_row_count
    ),
    finalized_row_count INTEGER NOT NULL CHECK (
        finalized_row_count BETWEEN 0 AND issued_row_count
    ),
    actual_encoded_bytes INTEGER NOT NULL CHECK (
        actual_encoded_bytes BETWEEN 0 AND 8589934592
    ),
    future_reserved_bytes INTEGER NOT NULL CHECK (
        future_reserved_bytes BETWEEN 0 AND 8589934592
    ),
    phase TEXT NOT NULL CHECK (phase IN ('issuing','owner-ready','verifying','verified')),
    updated_registry_sequence INTEGER NOT NULL CHECK (updated_registry_sequence >= 0),
    CHECK (actual_encoded_bytes + future_reserved_bytes <= 8589934592),
    CHECK ((phase='issuing' AND issued_row_count < planned_row_count) OR
           (phase IN ('owner-ready','verifying','verified') AND
            issued_row_count=planned_row_count AND future_reserved_bytes=0)),
    CHECK ((phase IN ('issuing','owner-ready') AND
            finalized_row_count < planned_row_count) OR
           (phase='verifying' AND planned_row_count > 0 AND
            finalized_row_count=planned_row_count) OR
           (phase='verified' AND finalized_row_count=planned_row_count))
) STRICT;

CREATE TABLE IF NOT EXISTS observation_carrier_migration_rows (
    migration_id BLOB NOT NULL CHECK (
        typeof(migration_id)='blob' AND length(migration_id)=16
    ),
    store_kind INTEGER NOT NULL CHECK (store_kind IN (1,2)),
    event_key_digest BLOB NOT NULL CHECK (
        typeof(event_key_digest)='blob' AND length(event_key_digest)=32
    ),
    event_cursor_digest BLOB NOT NULL CHECK (
        typeof(event_cursor_digest)='blob' AND length(event_cursor_digest)=32
    ),
    receipt_nonce BLOB NOT NULL UNIQUE CHECK (
        typeof(receipt_nonce)='blob' AND length(receipt_nonce)=32
    ),
    legacy_receipt BLOB NOT NULL CHECK (
        typeof(legacy_receipt)='blob' AND length(legacy_receipt) BETWEEN 300 AND 555
    ),
    owner_intent_digest BLOB NOT NULL CHECK (
        typeof(owner_intent_digest)='blob' AND length(owner_intent_digest)=32
    ),
    owner_preimage_digest BLOB NOT NULL CHECK (
        typeof(owner_preimage_digest)='blob' AND length(owner_preimage_digest)=32
    ),
    owner_postimage_digest BLOB NOT NULL CHECK (
        typeof(owner_postimage_digest)='blob' AND length(owner_postimage_digest)=32
    ),
    phase TEXT NOT NULL CHECK (phase IN ('prepared','finalized')),
    owner_commit_receipt_digest BLOB CHECK (
        owner_commit_receipt_digest IS NULL OR
        (typeof(owner_commit_receipt_digest)='blob' AND
         length(owner_commit_receipt_digest)=32)
    ),
    finalized_registry_sequence INTEGER CHECK (
        finalized_registry_sequence IS NULL OR finalized_registry_sequence >= 0
    ),
    encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes BETWEEN 1 AND 2048),
    PRIMARY KEY(migration_id,store_kind,event_key_digest),
    CHECK ((phase='prepared' AND owner_commit_receipt_digest IS NULL AND
            finalized_registry_sequence IS NULL) OR
           (phase='finalized' AND owner_commit_receipt_digest IS NOT NULL AND
            finalized_registry_sequence IS NOT NULL)),
    FOREIGN KEY(migration_id) REFERENCES observation_carrier_migrations(migration_id)
      ON DELETE RESTRICT
) STRICT;

CREATE TABLE IF NOT EXISTS observation_persisted_keyring_entries (
    key_id INTEGER PRIMARY KEY CHECK (key_id BETWEEN 1 AND 4294967295),
    status TEXT NOT NULL CHECK (status IN ('signing','verify-only','retired')),
    master_key_epoch INTEGER NOT NULL CHECK (master_key_epoch BETWEEN 1 AND 4294967295),
    last_issued_at_ms INTEGER NOT NULL CHECK (last_issued_at_ms >= 0),
    sqlite_scan_sequence INTEGER,
    jsonl_inventory_digest BLOB,
    jsonl_segment_count INTEGER,
    jsonl_byte_count INTEGER,
    retention_high_water_ms INTEGER,
    CHECK ((status='retired') = (sqlite_scan_sequence IS NOT NULL)),
    CHECK ((sqlite_scan_sequence IS NULL) = (jsonl_inventory_digest IS NULL)),
    CHECK ((sqlite_scan_sequence IS NULL) = (jsonl_segment_count IS NULL)),
    CHECK ((sqlite_scan_sequence IS NULL) = (jsonl_byte_count IS NULL)),
    CHECK ((sqlite_scan_sequence IS NULL) = (retention_high_water_ms IS NULL)),
    CHECK (sqlite_scan_sequence IS NULL OR sqlite_scan_sequence >= 0),
    CHECK (jsonl_inventory_digest IS NULL OR
           (typeof(jsonl_inventory_digest)='blob' AND length(jsonl_inventory_digest)=32)),
    CHECK (jsonl_segment_count IS NULL OR jsonl_segment_count >= 0),
    CHECK (jsonl_byte_count IS NULL OR jsonl_byte_count >= 0),
    CHECK (retention_high_water_ms IS NULL OR retention_high_water_ms >= 0)
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_observation_one_signing_key
    ON observation_persisted_keyring_entries(status) WHERE status='signing';

CREATE TABLE IF NOT EXISTS observation_retained_carrier_metadata (
    carrier_digest BLOB PRIMARY KEY CHECK (
        typeof(carrier_digest)='blob' AND length(carrier_digest)=32
    ),
    event_id TEXT NOT NULL CHECK (length(CAST(event_id AS BLOB)) BETWEEN 1 AND 256),
    cursor TEXT NOT NULL CHECK (cursor=event_id),
    identity_id TEXT NOT NULL,
    identity_class TEXT NOT NULL CHECK (identity_class IN ('component','agent','host')),
    identity_incarnation INTEGER NOT NULL CHECK (identity_incarnation > 0),
    declaration_digest BLOB NOT NULL CHECK (
        typeof(declaration_digest)='blob' AND length(declaration_digest)=32
    ),
    safe_event_digest BLOB NOT NULL CHECK (
        typeof(safe_event_digest)='blob' AND length(safe_event_digest)=32
    ),
    key_id INTEGER NOT NULL,
    retained_until_ms INTEGER NOT NULL CHECK (retained_until_ms >= 0),
    FOREIGN KEY(key_id) REFERENCES observation_persisted_keyring_entries(key_id)
      ON DELETE RESTRICT,
    FOREIGN KEY(identity_id) REFERENCES observation_identity_authority(id)
      ON DELETE RESTRICT
) STRICT;

CREATE TABLE IF NOT EXISTS observation_identity_ledger (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    registry_instance_id BLOB NOT NULL CHECK (
        typeof(registry_instance_id)='blob' AND length(registry_instance_id)=16
    ),
    committed_sequence INTEGER NOT NULL CHECK (committed_sequence >= 0),
    committed_head_digest BLOB NOT NULL CHECK (
        typeof(committed_head_digest)='blob' AND length(committed_head_digest)=32
    ),
    committed_state_root BLOB NOT NULL CHECK (
        typeof(committed_state_root)='blob' AND length(committed_state_root)=32
    ),
    committed_keyring_root BLOB NOT NULL CHECK (
        typeof(committed_keyring_root)='blob' AND length(committed_keyring_root)=32
    ),
    committed_role_allocation_root BLOB NOT NULL CHECK (
        typeof(committed_role_allocation_root)='blob' AND
        length(committed_role_allocation_root)=32
    ),
    migration_digest BLOB NOT NULL CHECK (
        typeof(migration_digest)='blob' AND length(migration_digest)=32
    )
) STRICT;

-- The marker root and manifest epoch participate in the authenticated head,
-- but not in the eleven-table recursive state root or seven-field ledger
-- tuple.  This singleton is scheduler-private recovery metadata used to reject
-- caller-reported tag-6 context that disagrees with the last durable commit.
CREATE TABLE IF NOT EXISTS observation_registry_head_context (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    current_marker_root BLOB NOT NULL CHECK (
        typeof(current_marker_root)='blob' AND length(current_marker_root)=32
    ),
    current_manifest_key_epoch INTEGER NOT NULL CHECK (
        current_manifest_key_epoch BETWEEN 1 AND 4294967295
    )
) STRICT;
