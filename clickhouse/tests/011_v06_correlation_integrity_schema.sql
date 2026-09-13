-- Focused Fusion v0.6 durable correlation-integrity regression.
-- Run only against a fresh isolated database after migrations 010 and 011.
-- The validation harness may replace the `fusion.` qualifier consistently.

SELECT throwIf(
    (SELECT countIf(engine NOT LIKE '%View')
     FROM system.tables
     WHERE database = currentDatabase()
       AND (name LIKE 'incident%' OR name LIKE 'correlation%')) != 12
    OR
    (SELECT countIf(engine = 'View')
     FROM system.tables
     WHERE database = currentDatabase()
       AND (name LIKE 'incident%' OR name LIKE 'correlation%')) != 12
    OR
    (SELECT countIf(engine = 'MaterializedView')
     FROM system.tables
     WHERE database = currentDatabase()
       AND (name LIKE 'incident%' OR name LIKE 'correlation%')) != 2,
    'expected twelve tables, twelve views, and two materialized views after migration 011'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name IN
       (
           'correlation_detection_input_witness',
           'correlation_integrity_events'
       )
       AND engine NOT LIKE '%View') != 2
    OR
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_integrity_scope_state_current'
       AND engine = 'View') != 1
    OR
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_detection_input_witness_mv'
       AND engine = 'MaterializedView') != 1,
    'expected migration 011 tables and views are incomplete'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_detection_input_witness'
       AND engine = 'ReplacingMergeTree'
       AND sorting_key = 'detection_id, detected_at, semantic_fingerprint'
       AND partition_key = 'toYYYYMM(detected_at)') != 1,
    'payload-free observation-witness storage contract differs'
);

SELECT throwIf(
    (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(
        x -> x.2,
        arraySort(groupArray((position, concat(name, ':', type))))
    ), '|'))))
     FROM system.columns
     WHERE database = currentDatabase()
       AND table = 'correlation_detection_input_witness') !=
        'bbf05f3795b3d4c785f759e5b3e9215889247682480ebdce59e62bf7b4c0ae49',
    'observation-witness exact three-column contract differs'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_detection_input_witness_mv'
       AND engine = 'MaterializedView'
       AND target_database = currentDatabase()
       AND target_table = 'correlation_detection_input_witness'
       AND lower(hex(SHA256(replaceAll(
           replaceAll(as_select, concat(currentDatabase(), '.'), ''),
           '`', ''
       )))) = '1b4222e930e5aa08b466ad6023f11ea6c462d81f38fc634393e8008047dc9a5d') != 1,
    'observation-witness materialized-view contract differs'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_detection_input_witness'
       AND positionCaseInsensitive(create_table_query, ' TTL ') > 0) != 0,
    'observation witness must not have a TTL'
);

SELECT throwIf(
    (SELECT count() FROM system.columns
     WHERE database = currentDatabase()
       AND table = 'correlation_detection_input_witness'
       AND name NOT IN ('detection_id', 'detected_at', 'semantic_fingerprint')) != 0,
    'observation witness must remain an exact payload-free projection'
);

-- Any primary history that existed before migration 011 must have been copied
-- to the witness. This is intentionally a logical identity comparison because
-- idempotent migration reapplication may add exact physical copies pre-merge.
SELECT throwIf(
    (SELECT count() FROM
     (
         SELECT DISTINCT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_history
         EXCEPT DISTINCT
         SELECT DISTINCT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_witness
     )) != 0
    OR
    (SELECT count() FROM
     (
         SELECT DISTINCT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_witness
         EXCEPT DISTINCT
         SELECT DISTINCT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_history
     )) != 0,
    'migration-011 backfill did not establish witness/history parity'
);

SELECT throwIf(
    (SELECT count()
     FROM fusion.correlation_detection_input_history
     WHERE detection_id = ''
       AND detected_at = toDateTime64('2026-09-12 08:00:00.000', 3, 'UTC')) != 1
    OR
    (SELECT count()
     FROM fusion.correlation_detection_input_witness
     WHERE detection_id = ''
       AND detected_at = toDateTime64('2026-09-12 08:00:00.000', 3, 'UTC')) < 1,
    'migration-011 rejected or failed to witness a v0.5.2-compatible empty detection ID'
);

-- Healthy new inserts must project the same observation identities into both
-- durable stores, including an immutable semantic conflict and an exact replay.
INSERT INTO fusion.detections
(
    detection_id, detected_at, updated_at, source_event_time, rule_id,
    rule_version, rule_name, severity, platform, vendor, product, source_type,
    host_name, user_name, source_ip, destination_ip, protocol, signature,
    signature_id, mitre_technique_ids, validation_id
)
VALUES
(
    'integrity-witness-live',
    toDateTime64('2026-09-13 11:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-13 11:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-13 10:59:59.000', 3, 'UTC'), 'rule-live', '1',
    'Witness live rule', 'medium', 'windows', 'Fusion', 'Test',
    'fusion_detection', 'host-a.example', 'alice', '192.0.2.1',
    '198.51.100.1', 'tcp', '', '', [], 'integrity-witness-test'
),
(
    'integrity-witness-live',
    toDateTime64('2026-09-13 11:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-13 11:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-13 10:59:59.000', 3, 'UTC'), 'rule-live', '1',
    'Witness live rule', 'medium', 'windows', 'Fusion', 'Test',
    'fusion_detection', 'host-a.example', 'alice', '192.0.2.1',
    '198.51.100.1', 'tcp', '', '', [], 'integrity-witness-test'
),
(
    'integrity-witness-live',
    toDateTime64('2026-09-13 11:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-13 11:00:00.001', 3, 'UTC'),
    toDateTime64('2026-09-13 10:59:59.000', 3, 'UTC'), 'rule-live', '1',
    'Witness live rule', 'medium', 'windows', 'Fusion', 'Test',
    'fusion_detection', 'host-b.example', 'alice', '192.0.2.1',
    '198.51.100.1', 'tcp', '', '', [], 'integrity-witness-test'
);

SELECT throwIf(
    (SELECT uniqExact(semantic_fingerprint)
     FROM fusion.correlation_detection_input_history
     WHERE detection_id = 'integrity-witness-live') != 2
    OR (SELECT uniqExact(semantic_fingerprint)
        FROM fusion.correlation_detection_input_witness
        WHERE detection_id = 'integrity-witness-live') != 2
    OR
    (SELECT count() FROM
     (
         SELECT DISTINCT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_history
         WHERE detection_id = 'integrity-witness-live'
         EXCEPT DISTINCT
         SELECT DISTINCT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_witness
         WHERE detection_id = 'integrity-witness-live'
     )) != 0
    OR
    (SELECT count() FROM
     (
         SELECT DISTINCT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_witness
         WHERE detection_id = 'integrity-witness-live'
         EXCEPT DISTINCT
         SELECT DISTINCT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_history
         WHERE detection_id = 'integrity-witness-live'
     )) != 0,
    'healthy projection did not preserve exact witness/history parity'
);

OPTIMIZE TABLE fusion.detections FINAL;
OPTIMIZE TABLE fusion.correlation_detection_input_history FINAL;
OPTIMIZE TABLE fusion.correlation_detection_input_witness FINAL;

SELECT throwIf(
    (SELECT count() FROM fusion.detections
     WHERE detection_id = 'integrity-witness-live') != 1
    OR (SELECT count() FROM fusion.correlation_detection_input_history
        WHERE detection_id = 'integrity-witness-live') != 2
    OR (SELECT count() FROM fusion.correlation_detection_input_witness
        WHERE detection_id = 'integrity-witness-live') != 2
    OR
    (SELECT count() FROM
     (
         SELECT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_history
         WHERE detection_id = 'integrity-witness-live'
         EXCEPT DISTINCT
         SELECT detection_id, detected_at, semantic_fingerprint
         FROM fusion.correlation_detection_input_witness
         WHERE detection_id = 'integrity-witness-live'
     )) != 0,
    'OPTIMIZE FINAL changed witness durability, conflict evidence, or parity'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_integrity_events'
       AND engine = 'MergeTree'
       AND sorting_key = concat(
           'engine_id, ruleset_fingerprint, correlation_rule_id, ',
           'correlation_rule_version, correlation_scope_fingerprint, ',
           'first_detected_at, integrity_event_id, detected_at'
       )
       AND partition_key = 'toYYYYMM(first_detected_at)') != 1,
    'integrity-event append-only storage contract differs'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_integrity_scope_state_current'
       AND engine = 'View'
       AND lower(hex(SHA256(replaceAll(
           as_select,
           concat(currentDatabase(), '.'),
           ''
       )))) = '1f18afc97e85597f86a8b8eb312fb534d1f7f39615b7ce38012126b90c5b862d') != 1,
    'current blocked-integrity scope view contract differs'
);

SELECT throwIf(
    (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(
        x -> x.2,
        arraySort(groupArray((position, concat(name, ':', type))))
    ), '|'))))
     FROM system.columns
     WHERE database = currentDatabase()
       AND table = 'correlation_integrity_scope_state_current') !=
        'dbe2546ec110d44f07dd24b276463dd0c3afb034f643e2f704951266cc82cbbd',
    'current blocked-integrity view column/type contract differs'
);

SELECT throwIf(
    (SELECT count() FROM system.columns
     WHERE database = currentDatabase()
       AND table = 'correlation_integrity_events') != 17,
    'integrity-event exact column count differs'
);

SELECT throwIf(
    (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(
        x -> x.2,
        arraySort(groupArray((position, concat(name, ':', type))))
    ), '|'))))
     FROM system.columns
     WHERE database = currentDatabase()
       AND table = 'correlation_integrity_events') !=
        '9e8dad9539efe424640f91a5f7bed018d5fba5c1152ae2aaa68b169b5871130b',
    'integrity-event exact column/type contract differs'
);

SELECT throwIf(
    (SELECT countIf(
        (name = 'input_kind' AND default_kind = 'DEFAULT' AND default_expression = '\'\'')
        OR (name = 'input_id' AND default_kind = 'DEFAULT' AND default_expression = '\'\'')
        OR (name = 'projection_name' AND default_kind = 'DEFAULT' AND default_expression = '\'\'')
        OR (name = 'expected_projection_fingerprint' AND default_kind = 'DEFAULT' AND default_expression = '\'\'')
        OR (name = 'actual_projection_fingerprint' AND default_kind = 'DEFAULT' AND default_expression = '\'\'')
        OR (name = 'diagnostic_json' AND default_kind = 'DEFAULT' AND default_expression = '\'{}\'')
    ) FROM system.columns
       WHERE database = currentDatabase()
         AND table = 'correlation_integrity_events') != 6,
    'integrity-event safe defaults differ'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_integrity_events'
       AND positionCaseInsensitive(create_table_query, ' TTL ') > 0) != 0,
    'integrity evidence must not have a TTL'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_integrity_events'
       AND position(create_table_query, 'correlation_integrity_identity_nonempty') > 0
       AND position(create_table_query, 'correlation_integrity_rule_version_positive') > 0
       AND position(create_table_query, 'correlation_integrity_detection_ordered') > 0
       AND position(create_table_query, 'correlation_integrity_violation_allowed') > 0
       AND position(create_table_query, 'correlation_integrity_input_kind_allowed') > 0
       AND position(create_table_query, 'correlation_integrity_details_consistent') > 0
       AND position(create_table_query, 'correlation_integrity_diagnostic_safe') > 0
       AND position(create_table_query, 'correlation_integrity_projection_fingerprints_valid') > 0) != 1,
    'integrity-event validation constraints are incomplete'
);

-- The authority contract is exact, not a list of names or permissive
-- substrings: a constraint weakened with an appended OR branch must fail.
SELECT throwIf(
    (SELECT lower(hex(SHA256(replaceAll(
        create_table_query,
        concat(currentDatabase(), '.'),
        ''
    ))))
     FROM system.tables
     WHERE database = currentDatabase()
       AND name = 'correlation_integrity_events') !=
        '021402ff07da4311c0801faf30066352714ff5a4a4ef82e17af0f1141b9090b6',
    'integrity-event exact table and constraint contract differs'
);

SELECT throwIf(
    (SELECT count() FROM system.columns
     WHERE database = currentDatabase()
       AND table = 'correlation_integrity_events'
       AND lower(name) IN
       (
           'raw_json', 'raw_xml', 'event_json', 'evidence_json',
           'command_line', 'message', 'payload'
       )) != 0,
    'integrity evidence must not contain source payload fields'
);

SELECT throwIf(
    (SELECT count() FROM fusion.correlation_integrity_events) != 0
    OR (SELECT count() FROM fusion.correlation_integrity_scope_state_current) != 0,
    'fresh integrity state must be empty and healthy'
);

INSERT INTO fusion.correlation_integrity_events
(
    integrity_event_id, detected_at, first_detected_at, engine_id,
    ruleset_fingerprint, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, violation_type, input_kind, input_id,
    ledger_observed_at, canonical_observed_at, projection_name,
    expected_projection_fingerprint, actual_projection_fingerprint,
    diagnostic_json
)
VALUES
(
    repeat('a', 64), toDateTime64('2026-09-13 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-13 10:00:00.000', 3, 'UTC'), 'engine-test',
    repeat('b', 64), 'correlation-rule-test', 1, repeat('c', 64),
    'canonical_observation_mismatch', 'detection', 'detection-1',
    toDateTime64('2026-09-13 09:30:00.000', 3, 'UTC'),
    toDateTime64('2026-09-13 09:00:00.000', 3, 'UTC'), '', '', '',
    '{"source":"canonical-history-ledger-comparison"}'
),
(
    repeat('a', 64), toDateTime64('2026-09-13 10:00:02.000', 3, 'UTC'),
    toDateTime64('2026-09-13 10:00:00.000', 3, 'UTC'), 'engine-test',
    repeat('b', 64), 'correlation-rule-test', 1, repeat('c', 64),
    'canonical_observation_mismatch', 'detection', 'detection-1',
    toDateTime64('2026-09-13 09:30:00.000', 3, 'UTC'),
    toDateTime64('2026-09-13 09:00:00.000', 3, 'UTC'), '', '', '',
    '{"source":"canonical-history-ledger-comparison"}'
),
(
    repeat('d', 64), toDateTime64('2026-09-13 10:00:03.000', 3, 'UTC'),
    toDateTime64('2026-09-13 10:00:03.000', 3, 'UTC'), 'engine-test',
    repeat('b', 64), 'correlation-rule-test', 1, repeat('c', 64),
    'projection_contract_mismatch', '', '', NULL, NULL,
    'fusion.correlation_detection_input_history_mv', repeat('e', 64),
    repeat('f', 64), '{"contract":"normalized-create-query-v1"}'
),
(
    repeat('1', 64), toDateTime64('2026-09-13 10:00:04.000', 3, 'UTC'),
    toDateTime64('2026-09-13 10:00:04.000', 3, 'UTC'), 'engine-test',
    repeat('b', 64), 'correlation-rule-test', 1, repeat('c', 64),
    'projection_coverage_uncertain', '', '', NULL, NULL,
    'fusion.correlation_detection_input_history_mv', repeat('e', 64),
    repeat('e', 64), '{"reason":"bounded-coverage-query-failed"}'
),
(
    repeat('4', 64), toDateTime64('2026-09-13 10:00:04.500', 3, 'UTC'),
    toDateTime64('2026-09-13 10:00:04.500', 3, 'UTC'), 'engine-test',
    repeat('b', 64), 'correlation-rule-test', 1, repeat('c', 64),
    'canonical_observation_uncertain', '', '', NULL, NULL,
    'fusion.correlation_detection_input_history_mv', repeat('e', 64),
    repeat('e', 64), '{"reason":"bounded-canonical-query-failed"}'
),
(
    repeat('2', 64), toDateTime64('2026-09-13 10:00:05.000', 3, 'UTC'),
    toDateTime64('2026-09-13 10:00:05.000', 3, 'UTC'), 'engine-test',
    repeat('3', 64), 'correlation-rule-test', 1, repeat('c', 64),
    'projection_unavailable', '', '', NULL, NULL,
    'fusion.correlation_detection_input_history_mv', repeat('e', 64), '',
    '{"reason":"ruleset-change-must-not-unblock-stable-scope"}'
);

SELECT throwIf(
    (SELECT count() FROM fusion.correlation_integrity_events) != 6,
    'append-only integrity history did not retain physical diagnostics'
);

SELECT throwIf(
    (SELECT count() FROM fusion.correlation_integrity_scope_state_current) != 1
    OR (SELECT correlation_status
        FROM fusion.correlation_integrity_scope_state_current) != 'blocked_integrity'
    OR (SELECT integrity_violation_count
        FROM fusion.correlation_integrity_scope_state_current) != 5
    OR (SELECT ruleset_fingerprints
        FROM fusion.correlation_integrity_scope_state_current) !=
        [repeat('3', 64), repeat('b', 64)]
    OR (SELECT violation_types
        FROM fusion.correlation_integrity_scope_state_current) !=
        [
            'canonical_observation_mismatch',
            'canonical_observation_uncertain',
            'projection_contract_mismatch',
            'projection_coverage_uncertain',
            'projection_unavailable'
        ]
    OR (SELECT first_detected_at
        FROM fusion.correlation_integrity_scope_state_current) !=
        toDateTime64('2026-09-13 10:00:00.000', 3, 'UTC')
    OR (SELECT last_detected_at
        FROM fusion.correlation_integrity_scope_state_current) !=
        toDateTime64('2026-09-13 10:00:05.000', 3, 'UTC'),
    'current integrity state did not remain logically blocked without replay amplification'
);

OPTIMIZE TABLE fusion.correlation_integrity_events FINAL;

SELECT throwIf(
    (SELECT count() FROM fusion.correlation_integrity_events) != 6
    OR (SELECT integrity_violation_count
        FROM fusion.correlation_integrity_scope_state_current) != 5,
    'OPTIMIZE FINAL changed durable integrity history or logical state'
);

SELECT 'v0.6 correlation integrity schema regression passed';
