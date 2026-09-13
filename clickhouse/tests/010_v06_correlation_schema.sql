-- Focused Fusion v0.6 correlation-schema regression.
-- Run only against a fresh isolated database after applying migration 010.
-- The validation harness may replace the `fusion.` qualifier consistently.

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND engine NOT LIKE '%View'
       AND (name LIKE 'incident%' OR name LIKE 'correlation%')) != 10,
    'expected ten v0.6 correlation/incident tables'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND engine = 'View'
       AND (name LIKE 'incident%' OR name LIKE 'correlation%')) != 11,
    'expected eleven v0.6 confirmation-aware views'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND engine = 'MaterializedView'
       AND name = 'correlation_detection_input_history_mv') != 1,
    'expected the durable detection-observation materialized view'
);

SELECT throwIf(
    (SELECT countIf(
        (name = 'correlation_detection_input_history' AND engine = 'ReplacingMergeTree' AND sorting_key = 'detection_id, detected_at, semantic_fingerprint' AND partition_key = 'toYYYYMM(detected_at)')
        OR
        (name = 'incidents' AND engine = 'ReplacingMergeTree' AND sorting_key = 'incident_id, revision' AND partition_key = 'toYYYYMM(created_at)')
        OR (name = 'incident_detection_links' AND engine = 'MergeTree' AND sorting_key = 'incident_id, detection_id' AND partition_key = 'toYYYYMM(occurred_at)')
        OR (name = 'incident_event_links' AND engine = 'MergeTree' AND sorting_key = 'incident_id, event_uid' AND partition_key = 'toYYYYMM(occurred_at)')
        OR (name = 'correlation_evaluated_inputs' AND engine = 'ReplacingMergeTree' AND sorting_key = 'engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, input_kind, input_id' AND partition_key = 'toYYYYMM(observed_at)')
        OR (name = 'correlation_rule_state' AND engine = 'ReplacingMergeTree' AND sorting_key = 'engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, revision' AND partition_key = '')
        OR (name = 'correlation_episode_state' AND engine = 'ReplacingMergeTree' AND sorting_key = 'engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, group_key_hash, episode_state_id, revision' AND partition_key = '')
        OR (name = 'correlation_scope_bootstrap_confirmations' AND engine = 'MergeTree' AND sorting_key = 'engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, scope_bootstrap_token' AND partition_key = '')
        OR (name = 'correlation_schedule_state' AND engine = 'ReplacingMergeTree' AND sorting_key = 'engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint' AND partition_key = '')
        OR (name = 'incident_status_transitions' AND engine = 'MergeTree' AND sorting_key = 'incident_id, applied_at, transition_id' AND partition_key = 'toYYYYMM(applied_at)')
    ) FROM system.tables
       WHERE database = currentDatabase()
         AND engine NOT LIKE '%View'
          AND (name LIKE 'incident%' OR name LIKE 'correlation%')) != 10,
    'v0.6 table engine, sorting-key, or partition contract differs'
);

-- These hashes cover every raw-table column name, type, and ordinal position.
-- They keep this executable assertion compact while the migration remains the
-- human-readable source of truth for the exact schema.
SELECT throwIf(
    (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
     FROM system.columns WHERE database = currentDatabase() AND table = 'correlation_detection_input_history') !=
        '7798162599c6738549383f8948db5825079421632f8b1f25790fa6a71a2a666e'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
     FROM system.columns WHERE database = currentDatabase() AND table = 'incidents') !=
        'a22bc6fc4bee282a50149ae8397a84206c50244859666c6f52d7760eaf60e112'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
        FROM system.columns WHERE database = currentDatabase() AND table = 'incident_detection_links') !=
        '9b1a33dc61e64e5f3182b12c593e2769e1088ece8afbedbc56c3ee01e4dcf79f'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
        FROM system.columns WHERE database = currentDatabase() AND table = 'incident_event_links') !=
        'f4f0e2189f4c700f77d8b5a7c183ea801838552852720a1a7668805449e0c6e3'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
        FROM system.columns WHERE database = currentDatabase() AND table = 'correlation_evaluated_inputs') !=
        '24f1ae382e1ca5bd5eec3889561682799254c2986c7562361db4be7a2158d8c5'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
        FROM system.columns WHERE database = currentDatabase() AND table = 'correlation_rule_state') !=
        '4fa973ea5788483300d5bd9529cdeae7598811634868678264adced2cefc8c36'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
        FROM system.columns WHERE database = currentDatabase() AND table = 'correlation_episode_state') !=
        'f9542751005748e29a0084034f3105121e3363f7489f37e10c4a364571f018ee'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
        FROM system.columns WHERE database = currentDatabase() AND table = 'correlation_scope_bootstrap_confirmations') !=
        'c241870d7d364d8620605e41413ca10cd60105706cbccc23cfb122790cba892d'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
        FROM system.columns WHERE database = currentDatabase() AND table = 'correlation_schedule_state') !=
        'd879dbff734350d9b758653822953a723525197013da42ff6ba195153a3f014d'
    OR (SELECT lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(groupArray((position, concat(name, ':', type))))), '|'))))
        FROM system.columns WHERE database = currentDatabase() AND table = 'incident_status_transitions') !=
        'e4c5f0638aa5dabe5e9baae155feac55735b85e8e9fe194757d676ae40ed3d5d',
    'v0.6 exact raw-table column/type contract differs'
);

SELECT throwIf(
    (SELECT countIf(
        (table = 'incidents' AND name = 'status' AND default_kind = 'DEFAULT' AND default_expression = '\'new\'')
        OR (table = 'incidents' AND name = 'updated_at' AND default_kind = 'DEFAULT' AND default_expression = 'now64(3)')
        OR (table = 'correlation_evaluated_inputs' AND name = 'evaluated_at' AND default_kind = 'DEFAULT' AND default_expression = 'now64(3)')
        OR (table = 'correlation_schedule_state' AND name = 'updated_at' AND default_kind = 'DEFAULT' AND default_expression = 'now64(3)')
        OR (table = 'incident_status_transitions' AND name = 'actor_type' AND default_kind = 'DEFAULT' AND default_expression = '\'local_admin\'')
    ) FROM system.columns WHERE database = currentDatabase()) != 5,
    'v0.6 immutable/default column contract differs'
);

SELECT throwIf(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase()
       AND engine NOT LIKE '%View'
       AND (name LIKE 'incident%' OR name LIKE 'correlation%')
       AND positionCaseInsensitive(create_table_query, ' TTL ') > 0) != 0,
    'v0.6 correctness state must not have a TTL'
);

SELECT throwIf(
    (SELECT sorting_key FROM system.tables
     WHERE database = currentDatabase() AND name = 'incidents') != 'incident_id, revision',
    'incident sorting key must preserve revisions'
);

SELECT throwIf(
    (SELECT sorting_key FROM system.tables
     WHERE database = currentDatabase() AND name = 'correlation_rule_state') !=
        'engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, revision',
    'rule-state sorting key must preserve revisions'
);

SELECT throwIf(
    (SELECT sorting_key FROM system.tables
     WHERE database = currentDatabase() AND name = 'correlation_episode_state') !=
        'engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, group_key_hash, episode_state_id, revision',
    'episode-state sorting key must preserve revisions'
);

SELECT throwIf(
    (SELECT sorting_key FROM system.tables
     WHERE database = currentDatabase() AND name = 'correlation_evaluated_inputs') !=
        'engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, input_kind, input_id',
    'evaluation ledger sorting key must be the exact completeness identity'
);

SELECT throwIf(
    (SELECT count() FROM fusion.incidents) != 0
    OR (SELECT count() FROM fusion.correlation_evaluated_inputs) != 0,
    'fresh v0.6 state must be empty'
);

-- Bootstrap state is invisible until the exact durable confirmation exists.
INSERT INTO fusion.correlation_rule_state
(
    engine_id, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, evaluation_floor_observed_at,
    compiler_version, normalization_contract_version, revision_token,
    state_hash, activated_at, updated_at, revision
)
VALUES
(
    'fusion-correlation-v06', 'test-rule', 1, 'scope-v1',
    toDateTime64('2026-09-12 10:00:00.000', 3, 'UTC'),
    'fusion-correlation/v1', 'fusion-normalized/v1', 'bootstrap-token',
    'rule-state-bootstrap', toDateTime64('2026-09-12 10:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:00.001', 3, 'UTC'), 1
);

SELECT throwIf(
    (SELECT count() FROM fusion.correlation_rule_state_current) != 0,
    'unconfirmed bootstrap state must be hidden'
);

INSERT INTO fusion.correlation_scope_bootstrap_confirmations
(
    engine_id, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, scope_bootstrap_token,
    expected_rule_state_hash, expected_rule_state_revision, confirmed_at
)
VALUES
(
    'fusion-correlation-v06', 'test-rule', 1, 'scope-v1',
    'bootstrap-token', 'rule-state-bootstrap', 1,
    toDateTime64('2026-09-12 10:00:00.002', 3, 'UTC')
);

SELECT throwIf(
    (SELECT count() FROM fusion.correlation_rule_state_current) != 1
    OR (SELECT revision FROM fusion.correlation_rule_state_current) != 1,
    'confirmed bootstrap state must become current exactly once'
);

-- Revision one is fully confirmed by its exact evaluation token.
INSERT INTO fusion.incidents
(
    incident_id, incident_title, incident_type, status, severity, severity_rank,
    confidence, created_at, updated_at, first_seen, last_seen,
    acknowledged_at, closed_at, last_transition_id, last_transition_from,
    last_transition_at, primary_host, primary_user, primary_source_ip,
    primary_destination_ip, input_count, detection_count, event_count,
    distinct_detection_rule_count, source_family_count, mitre_tactic_ids,
    mitre_technique_ids, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, group_key_json, group_key_hash,
    episode_anchor_kind, episode_anchor_id, episode_anchor_time,
    episode_window_start, episode_window_end, last_evidence_observed_at,
    late_accept_until, late_update_count, revision, state_hash,
    revision_source, revision_token, evidence_json, validation_id
)
VALUES
(
    'incident-1', 'Test incident', 'host_compromise', 'new', 'high', 3, 80,
    toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.100', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    NULL, NULL, '', '', NULL, 'host.example.test', 'LAB\\analyst',
    '192.0.2.10', '198.51.100.20', 1, 1, 0, 1, 1,
    ['TA0006'], ['T1110'], 'test-rule', 1, 'scope-v1',
    '{"host":"host.example.test"}', 'group-1', 'detection', 'detection-1',
    toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:10:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.050', 3, 'UTC'),
    toDateTime64('2026-09-12 10:12:01.000', 3, 'UTC'),
    0, 1, 'incident-state-1', 'correlation_input', 'evaluation-token-1',
    '{"schema_version":1}', 'v06-schema-test'
);

INSERT INTO fusion.incident_detection_links
(
    incident_id, detection_id, link_id, introduction_revision_token,
    relationship, occurred_at, observed_at, linked_at, correlation_rule_id,
    correlation_rule_version, correlation_scope_fingerprint, source_type,
    detection_rule_id, detection_rule_name, severity, host_name, user_name,
    source_ip, destination_ip, mitre_technique_ids, summary, validation_id
)
VALUES
(
    'incident-1', 'detection-1', 'link-detection-1', 'evaluation-token-1',
    'trigger', toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.050', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.100', 3, 'UTC'),
    'test-rule', 1, 'scope-v1', 'linux_auth', 'sigma-rule-1',
    'Test detection one', 'high', 'host.example.test', 'LAB\\analyst',
    '192.0.2.10', '198.51.100.20', ['T1110'], 'bounded detection summary',
    'v06-schema-test'
);

INSERT INTO fusion.correlation_episode_state
(
    engine_id, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, group_key_json, group_key_hash,
    episode_state_id, revision_token, canonical_qualifying_inputs,
    episode_anchor_kind, episode_anchor_id, episode_anchor_time,
    episode_window_start, episode_window_end, active_incident_id,
    owned_detection_ids, owned_event_uids, last_input_observed_at,
    late_accept_until, collision_count, state_hash, updated_at, revision
)
VALUES
(
    'fusion-correlation-v06', 'test-rule', 1, 'scope-v1',
    '{"host":"host.example.test"}', 'group-1', 'episode-1',
    'evaluation-token-1', ['detection:detection-1'], 'detection', 'detection-1',
    toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:10:01.000', 3, 'UTC'), 'incident-1',
    ['detection-1'], [], toDateTime64('2026-09-12 10:00:01.050', 3, 'UTC'),
    toDateTime64('2026-09-12 10:12:01.000', 3, 'UTC'), 0,
    'episode-state-1', toDateTime64('2026-09-12 10:00:01.100', 3, 'UTC'), 1
);

INSERT INTO fusion.correlation_evaluated_inputs
(
    engine_id, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, input_kind, input_id, occurred_at,
    observed_at, evaluated_at, evaluation_action, lateness_status,
    incident_id, evaluation_token, reason_code, source_type, host_name,
    validation_id
)
VALUES
(
    'fusion-correlation-v06', 'test-rule', 1, 'scope-v1', 'detection',
    'detection-1', toDateTime64('2026-09-12 10:00:01.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.050', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:01.200', 3, 'UTC'), 'created', 'on_time',
    'incident-1', 'evaluation-token-1', 'matched', 'linux_auth',
    'host.example.test', 'v06-schema-test'
);

SELECT throwIf(
    (SELECT count() FROM fusion.incidents_current) != 1
    OR (SELECT revision FROM fusion.incidents_current WHERE incident_id = 'incident-1') != 1
    OR (SELECT count() FROM fusion.incident_detection_links_current) != 1
    OR (SELECT count() FROM fusion.correlation_episode_state_current) != 1,
    'fully confirmed revision one must be visible'
);

-- A crash after writing revision two, links, and state but before ledgering must
-- leave the last confirmed incident/state/timeline unchanged.
INSERT INTO fusion.incidents SELECT
    incident_id, incident_title, incident_type, status, severity, severity_rank,
    confidence, created_at, toDateTime64('2026-09-12 10:00:02.100', 3, 'UTC'),
    first_seen, toDateTime64('2026-09-12 10:00:02.000', 3, 'UTC'),
    acknowledged_at, closed_at, last_transition_id, last_transition_from,
    last_transition_at, primary_host, primary_user, primary_source_ip,
    primary_destination_ip, 3, 2, 1, 2, 2, mitre_tactic_ids,
    arraySort(arrayDistinct(arrayConcat(mitre_technique_ids, ['T1059.001']))),
    correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, group_key_json, group_key_hash,
    episode_anchor_kind, episode_anchor_id, episode_anchor_time,
    episode_window_start, episode_window_end,
    toDateTime64('2026-09-12 10:00:02.050', 3, 'UTC'), late_accept_until,
    0, 2, 'incident-state-2', 'correlation_input', 'evaluation-token-2',
    '{"schema_version":1,"input_count":3}', validation_id
FROM fusion.incidents
WHERE incident_id = 'incident-1' AND revision = 1;

INSERT INTO fusion.incident_detection_links
(
    incident_id, detection_id, link_id, introduction_revision_token,
    relationship, occurred_at, observed_at, linked_at, correlation_rule_id,
    correlation_rule_version, correlation_scope_fingerprint, source_type,
    detection_rule_id, detection_rule_name, severity, host_name, user_name,
    source_ip, destination_ip, mitre_technique_ids, summary, validation_id
)
VALUES
(
    'incident-1', 'detection-2', 'link-detection-2', 'evaluation-token-2',
    'supporting', toDateTime64('2026-09-12 10:00:02.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:02.050', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:02.100', 3, 'UTC'),
    'test-rule', 1, 'scope-v1', 'windows_sysmon', 'sigma-rule-2',
    'Test detection two', 'medium', 'host.example.test', 'LAB\\analyst',
    '192.0.2.10', '198.51.100.20', ['T1059.001'],
    'bounded detection summary two', 'v06-schema-test'
);

INSERT INTO fusion.incident_event_links
(
    incident_id, event_uid, link_id, introduction_revision_token, relationship,
    occurred_at, observed_at, linked_at, correlation_rule_id,
    correlation_rule_version, correlation_scope_fingerprint, source_type,
    event_category, event_action, outcome, service_name, host_name, user_name,
    source_ip, destination_ip, summary, validation_id
)
VALUES
(
    'incident-1', 'event-1', 'link-event-1', 'evaluation-token-2', 'context',
    toDateTime64('2026-09-12 10:00:01.500', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:02.040', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:02.100', 3, 'UTC'),
    'test-rule', 1, 'scope-v1', 'windows_sysmon', 'network',
    'network_connect', 'success', '', 'host.example.test', 'LAB\\analyst',
    '192.0.2.10', '198.51.100.20', 'bounded event summary', 'v06-schema-test'
);

INSERT INTO fusion.correlation_rule_state SELECT
    engine_id, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, evaluation_floor_observed_at,
    compiler_version, normalization_contract_version, 'evaluation-token-2',
    'rule-state-2', activated_at,
    toDateTime64('2026-09-12 10:00:02.100', 3, 'UTC'), 2
FROM fusion.correlation_rule_state
WHERE revision = 1;

INSERT INTO fusion.correlation_episode_state SELECT
    engine_id, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, group_key_json, group_key_hash,
    episode_state_id, 'evaluation-token-2',
    ['detection:detection-1', 'event:event-1', 'detection:detection-2'],
    episode_anchor_kind, episode_anchor_id, episode_anchor_time,
    episode_window_start, episode_window_end, active_incident_id,
    ['detection-1', 'detection-2'], ['event-1'],
    toDateTime64('2026-09-12 10:00:02.050', 3, 'UTC'), late_accept_until,
    collision_count, 'episode-state-2',
    toDateTime64('2026-09-12 10:00:02.100', 3, 'UTC'), 2
FROM fusion.correlation_episode_state
WHERE revision = 1;

SELECT throwIf(
    (SELECT revision FROM fusion.incidents_current WHERE incident_id = 'incident-1') != 1
    OR (SELECT count() FROM fusion.incident_detection_links_current) != 1
    OR (SELECT count() FROM fusion.incident_event_links_current) != 0
    OR (SELECT revision FROM fusion.correlation_rule_state_current) != 1
    OR (SELECT revision FROM fusion.correlation_episode_state_current) != 1
    OR (SELECT count() FROM fusion.incident_timeline) != 1,
    'provisional effects must be hidden before ledger confirmation'
);

OPTIMIZE TABLE fusion.incidents FINAL;
OPTIMIZE TABLE fusion.correlation_rule_state FINAL;
OPTIMIZE TABLE fusion.correlation_episode_state FINAL;

SELECT throwIf(
    (SELECT revision FROM fusion.incidents_current WHERE incident_id = 'incident-1') != 1
    OR (SELECT revision FROM fusion.correlation_rule_state_current) != 1
    OR (SELECT revision FROM fusion.correlation_episode_state_current) != 1,
    'merge must retain the last confirmed predecessor'
);

INSERT INTO fusion.correlation_evaluated_inputs
(
    engine_id, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, input_kind, input_id, occurred_at,
    observed_at, evaluated_at, evaluation_action, lateness_status,
    incident_id, evaluation_token, reason_code, source_type, host_name,
    validation_id
)
VALUES
(
    'fusion-correlation-v06', 'test-rule', 1, 'scope-v1', 'detection',
    'detection-2', toDateTime64('2026-09-12 10:00:02.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:02.050', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:02.200', 3, 'UTC'), 'updated', 'on_time',
    'incident-1', 'evaluation-token-2', 'matched', 'windows_sysmon',
    'host.example.test', 'v06-schema-test'
);

SELECT throwIf(
    (SELECT revision FROM fusion.incidents_current WHERE incident_id = 'incident-1') != 2
    OR (SELECT count() FROM fusion.incident_detection_links_current) != 2
    OR (SELECT count() FROM fusion.incident_event_links_current) != 1
    OR (SELECT revision FROM fusion.correlation_rule_state_current) != 2
    OR (SELECT revision FROM fusion.correlation_episode_state_current) != 2
    OR (SELECT count() FROM fusion.incident_timeline) != 3
    OR (SELECT related_detection_ids FROM fusion.incidents_current WHERE incident_id = 'incident-1') != ['detection-1', 'detection-2'],
    'ledger confirmation must expose revision two and exact logical membership'
);

-- A lifecycle revision is hidden until the immutable transition audit exists.
INSERT INTO fusion.incidents SELECT
    incident_id, incident_title, incident_type, 'acknowledged', severity,
    severity_rank, confidence, created_at,
    toDateTime64('2026-09-12 10:00:03.100', 3, 'UTC'), first_seen, last_seen,
    toDateTime64('2026-09-12 10:00:03.000', 3, 'UTC'), closed_at,
    'transition-token-1', 'new',
    toDateTime64('2026-09-12 10:00:03.000', 3, 'UTC'), primary_host,
    primary_user, primary_source_ip, primary_destination_ip, input_count,
    detection_count, event_count, distinct_detection_rule_count,
    source_family_count, mitre_tactic_ids, mitre_technique_ids,
    correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, group_key_json, group_key_hash,
    episode_anchor_kind, episode_anchor_id, episode_anchor_time,
    episode_window_start, episode_window_end, last_evidence_observed_at,
    late_accept_until, late_update_count, 3, 'incident-state-3',
    'lifecycle_transition', 'transition-token-1', evidence_json, validation_id
FROM fusion.incidents
WHERE incident_id = 'incident-1' AND revision = 2;

SELECT throwIf(
    (SELECT revision FROM fusion.incidents_current WHERE incident_id = 'incident-1') != 2,
    'lifecycle revision must be hidden before its audit row'
);

INSERT INTO fusion.incident_status_transitions
(
    transition_id, incident_id, from_status, to_status, requested_at,
    applied_at, actor_type, resulting_incident_revision, validation_id
)
VALUES
(
    'transition-token-1', 'incident-1', 'new', 'acknowledged',
    toDateTime64('2026-09-12 10:00:02.900', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:03.000', 3, 'UTC'), 'local_admin', 3,
    'v06-schema-test'
),
(
    'transition-token-1', 'incident-1', 'new', 'acknowledged',
    toDateTime64('2026-09-12 10:00:02.900', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:03.000', 3, 'UTC'), 'local_admin', 3,
    'v06-schema-test'
);

SELECT throwIf(
    (SELECT revision FROM fusion.incidents_current WHERE incident_id = 'incident-1') != 3
    OR (SELECT status FROM fusion.incidents_current WHERE incident_id = 'incident-1') != 'acknowledged'
    OR (SELECT count() FROM fusion.incident_status_transitions_current) != 1,
    'audited lifecycle revision must become current without logical audit duplicates'
);

INSERT INTO fusion.correlation_schedule_state
(
    engine_id, correlation_rule_id, correlation_rule_version,
    correlation_scope_fingerprint, candidate_cursor_occurred_at,
    candidate_cursor_observed_at, candidate_cursor_input_kind,
    candidate_cursor_input_id, newest_eligible_occurred_at,
    newest_eligible_observed_at, newest_eligible_input_kind,
    newest_eligible_input_id, unevaluated_input_count,
    oldest_unevaluated_observed_at, oldest_unevaluated_age_seconds,
    cycle_evaluated_count, cycle_matched_count, cycle_failed_count,
    cycle_incident_create_count, cycle_incident_update_count,
    cycle_detection_link_write_count,
    cycle_event_link_write_count, processing_duration_seconds,
    evaluated_inputs_per_second, consecutive_drain_cycles, updated_at, revision
)
VALUES
(
    'fusion-correlation-v06', 'test-rule', 1, 'scope-v1', NULL, NULL, '', '',
    NULL, NULL, '', '', 1, toDateTime64('2026-09-12 10:00:02.050', 3, 'UTC'),
    1.0, 1, 1, 0, 1, 0, 1, 0, 0.1, 10.0, 0,
    toDateTime64('2026-09-12 10:00:03.100', 3, 'UTC'), 1
),
(
    'fusion-correlation-v06', 'test-rule', 1, 'scope-v1',
    toDateTime64('2026-09-12 10:00:02.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:02.050', 3, 'UTC'), 'detection',
    'detection-2', toDateTime64('2026-09-12 10:00:02.000', 3, 'UTC'),
    toDateTime64('2026-09-12 10:00:02.050', 3, 'UTC'), 'detection',
    'detection-2', 0, NULL, 0.0, 1, 1, 0, 0, 1, 1, 1, 0.1, 10.0, 1,
    toDateTime64('2026-09-12 10:00:03.200', 3, 'UTC'), 2
);

SELECT throwIf(
    (SELECT revision FROM fusion.correlation_schedule_state_current) != 2
    OR (SELECT unevaluated_input_count FROM fusion.correlation_schedule_state_current) != 0
    OR (SELECT oldest_unevaluated_observed_at IS NULL FROM fusion.correlation_schedule_state_current) != 1
    OR (SELECT oldest_unevaluated_age_seconds FROM fusion.correlation_schedule_state_current) != 0.0,
    'current schedule state must expose the drained highest revision'
);

-- Replayed physical rows remain one logical ledger/link/incident/audit identity.
INSERT INTO fusion.correlation_evaluated_inputs SELECT *
FROM fusion.correlation_evaluated_inputs
WHERE evaluation_token = 'evaluation-token-2';

INSERT INTO fusion.incident_detection_links SELECT *
FROM fusion.incident_detection_links
WHERE detection_id = 'detection-2';

SELECT throwIf(
    (SELECT count() FROM fusion.correlation_evaluated_inputs_current) != 2
    OR (SELECT count() FROM fusion.incident_detection_links_current) != 2
    OR (SELECT count() FROM fusion.incidents_current) != 1
    OR (SELECT count() FROM fusion.incident_timeline) != 3,
    'physical replay must not amplify logical identities'
);

-- The durable detection projection preserves the earliest observation and
-- immutable conflict evidence even after the ReplacingMergeTree source merges.
INSERT INTO fusion.detections
(
    detection_id, detected_at, updated_at, source_event_time, rule_id,
    rule_version, rule_name, severity, platform, vendor, product, source_type,
    host_name, user_name, source_ip, destination_ip, protocol, signature,
    signature_id, mitre_technique_ids, validation_id
)
VALUES
(
    'history-stale', toDateTime64('2026-09-12 11:59:59.000', 3, 'UTC'),
    toDateTime64('2026-09-12 11:59:59.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:05:00.000', 3, 'UTC'), 'rule-a', '1',
    'Rule A', 'medium', 'windows', 'Fusion', 'Test', 'fusion_detection',
    'host.example', 'alice', '192.0.2.1', '198.51.100.1', 'tcp', '', '', [],
    'history-test'
),
(
    'history-stale', toDateTime64('2026-09-12 13:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 13:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:05:00.000', 3, 'UTC'), 'rule-a', '1',
    'Rule A', 'medium', 'windows', 'Fusion', 'Test', 'fusion_detection',
    'host.example', 'alice', '192.0.2.1', '198.51.100.1', 'tcp', '', '', [],
    'history-test'
),
(
    'history-conflict', toDateTime64('2026-09-12 12:31:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:31:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:06:00.000', 3, 'UTC'), 'rule-a', '1',
    'Rule A', 'medium', 'windows', 'Fusion', 'Test', 'fusion_detection',
    'host-a.example', 'alice', '192.0.2.1', '198.51.100.1', 'tcp', '', '', [],
    'history-test'
),
(
    'history-conflict', toDateTime64('2026-09-12 12:32:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:32:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:06:00.000', 3, 'UTC'), 'rule-a', '1',
    'Rule A', 'medium', 'windows', 'Fusion', 'Test', 'fusion_detection',
    'host-b.example', 'alice', '192.0.2.1', '198.51.100.1', 'tcp', '', '', [],
    'history-test'
),
(
    'history-duplicate', toDateTime64('2026-09-12 12:33:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:33:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:07:00.000', 3, 'UTC'), 'rule-b', '1',
    'Rule B', 'medium', 'windows', 'Fusion', 'Test', 'fusion_detection',
    'host.example', 'alice', '192.0.2.1', '198.51.100.1', 'tcp', '', '', [],
    'history-test'
),
(
    'history-duplicate', toDateTime64('2026-09-12 12:33:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:33:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 12:07:00.000', 3, 'UTC'), 'rule-b', '1',
    'Rule B', 'medium', 'windows', 'Fusion', 'Test', 'fusion_detection',
    'host.example', 'alice', '192.0.2.1', '198.51.100.1', 'tcp', '', '', [],
    'history-test'
);

SELECT throwIf(
    (SELECT min(detected_at) FROM fusion.correlation_detection_input_history
     WHERE detection_id = 'history-stale') !=
        toDateTime64('2026-09-12 11:59:59.000', 3, 'UTC')
    OR (SELECT uniqExact(semantic_fingerprint)
        FROM fusion.correlation_detection_input_history
        WHERE detection_id = 'history-conflict') != 2,
    'detection projection did not capture canonical time and conflict variants'
);

OPTIMIZE TABLE fusion.detections FINAL;
OPTIMIZE TABLE fusion.correlation_detection_input_history FINAL;

SELECT throwIf(
    (SELECT count() FROM fusion.detections WHERE detection_id = 'history-stale') != 1
    OR (SELECT min(detected_at) FROM fusion.correlation_detection_input_history
        WHERE detection_id = 'history-stale') !=
        toDateTime64('2026-09-12 11:59:59.000', 3, 'UTC')
    OR (SELECT uniqExact(semantic_fingerprint)
        FROM fusion.correlation_detection_input_history
        WHERE detection_id = 'history-conflict') != 2
    OR (SELECT count() FROM fusion.correlation_detection_input_history
        WHERE detection_id = 'history-duplicate') != 1,
    'source merge changed canonical observation, conflict, or duplicate identity'
);

SELECT 'v0.6 correlation schema regression passed';
