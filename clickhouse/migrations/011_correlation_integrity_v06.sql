-- Idempotent Fusion v0.6 correlation-integrity storage.
--
-- Integrity violations are append-only correctness evidence. They have no TTL,
-- contain no source payload/evidence fields, and cannot be cleared implicitly by
-- a restart or by restoring a failed projection. A scope with any logical event
-- in this table remains blocked until an explicit operator recovery mechanism is
-- designed and approved.

-- This independent, payload-free witness records only the immutable identity of
-- each projected detection observation. It is diagnostic state, never a source
-- of candidates, canonical values, or automatic repairs. Comparing it with the
-- primary history makes a transient single-projection failure remain detectable
-- after the ReplacingMergeTree source has merged away an older physical row.
CREATE TABLE IF NOT EXISTS fusion.correlation_detection_input_witness
(
    detection_id String,
    detected_at DateTime64(3, 'UTC'),
    semantic_fingerprint String,
    CONSTRAINT correlation_detection_witness_identity_valid CHECK
        match(semantic_fingerprint, '^[0-9a-f]{64}$')
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(detected_at)
ORDER BY (detection_id, detected_at, semantic_fingerprint)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS fusion.correlation_detection_input_witness_mv
TO fusion.correlation_detection_input_witness
AS
SELECT
    detection_id,
    detected_at,
    lower(hex(SHA256(toString(tuple(
        source_event_time, rule_id, rule_version, rule_name, severity, platform,
        vendor, product, source_type, host_name, user_name, source_ip,
        destination_ip, protocol, signature, signature_id,
        mitre_technique_ids, validation_id
    ))))) AS semantic_fingerprint
FROM fusion.detections;

-- The view is installed before this backfill so concurrent new inserts are
-- witnessed. Reapplication may add exact physical copies; the deterministic
-- sorting key collapses those without erasing distinct times or semantics.
INSERT INTO fusion.correlation_detection_input_witness
(
    detection_id,
    detected_at,
    semantic_fingerprint
)
SELECT
    detection_id,
    detected_at,
    semantic_fingerprint
FROM fusion.correlation_detection_input_history;

CREATE TABLE IF NOT EXISTS fusion.correlation_integrity_events
(
    integrity_event_id String,
    detected_at DateTime64(3, 'UTC'),
    first_detected_at DateTime64(3, 'UTC'),
    engine_id LowCardinality(String),
    ruleset_fingerprint String,
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    violation_type LowCardinality(String),
    input_kind LowCardinality(String) DEFAULT '',
    input_id String DEFAULT '',
    ledger_observed_at Nullable(DateTime64(3, 'UTC')),
    canonical_observed_at Nullable(DateTime64(3, 'UTC')),
    projection_name String DEFAULT '',
    expected_projection_fingerprint String DEFAULT '',
    actual_projection_fingerprint String DEFAULT '',
    diagnostic_json String DEFAULT '{}',
    CONSTRAINT correlation_integrity_identity_nonempty CHECK
        match(integrity_event_id, '^[0-9a-f]{64}$')
        AND notEmpty(engine_id)
        AND match(ruleset_fingerprint, '^[0-9a-f]{64}$')
        AND notEmpty(correlation_rule_id)
        AND match(correlation_scope_fingerprint, '^[0-9a-f]{64}$'),
    CONSTRAINT correlation_integrity_rule_version_positive CHECK
        correlation_rule_version > 0,
    CONSTRAINT correlation_integrity_detection_ordered CHECK
        detected_at >= first_detected_at,
    CONSTRAINT correlation_integrity_violation_allowed CHECK
        violation_type IN
        (
            'canonical_observation_mismatch',
            'canonical_observation_uncertain',
            'projection_unavailable',
            'projection_contract_mismatch',
            'projection_coverage_gap',
            'projection_coverage_uncertain'
        ),
    CONSTRAINT correlation_integrity_input_kind_allowed CHECK
        input_kind IN ('', 'detection', 'event'),
    CONSTRAINT correlation_integrity_details_consistent CHECK
        (
            violation_type = 'canonical_observation_mismatch'
            AND input_kind IN ('detection', 'event')
            AND notEmpty(input_id)
            AND ledger_observed_at IS NOT NULL
            AND canonical_observed_at IS NOT NULL
            AND ledger_observed_at != canonical_observed_at
        )
        OR
        (
            violation_type = 'projection_coverage_gap'
            AND input_kind = 'detection'
            AND canonical_observed_at IS NOT NULL
            AND notEmpty(projection_name)
            AND
            (
                (
                    notEmpty(input_id)
                    AND JSONExtractString(diagnostic_json, 'input_id_state') = ''
                )
                OR
                (
                    empty(input_id)
                    AND JSONExtractString(diagnostic_json, 'input_id_state') = 'empty'
                )
            )
        )
        OR
        (
            violation_type IN
            (
                'projection_unavailable',
                'projection_contract_mismatch',
                'projection_coverage_uncertain',
                'canonical_observation_uncertain'
            )
            AND notEmpty(projection_name)
        ),
    CONSTRAINT correlation_integrity_diagnostic_safe CHECK
        length(diagnostic_json) <= 8192 AND isValidJSON(diagnostic_json),
    CONSTRAINT correlation_integrity_projection_fingerprints_valid CHECK
        (
            empty(expected_projection_fingerprint)
            OR match(expected_projection_fingerprint, '^[0-9a-f]{64}$')
        )
        AND
        (
            empty(actual_projection_fingerprint)
            OR match(actual_projection_fingerprint, '^[0-9a-f]{64}$')
        )
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(first_detected_at)
ORDER BY
(
    engine_id,
    ruleset_fingerprint,
    correlation_rule_id,
    correlation_rule_version,
    correlation_scope_fingerprint,
    first_detected_at,
    integrity_event_id,
    detected_at
)
SETTINGS index_granularity = 128;

-- This is deliberately derived from immutable events instead of mutable status
-- rows. Replayed inserts with the same deterministic integrity_event_id do not
-- amplify the logical violation count, while every physical diagnostic remains
-- available for investigation. The aggregate ruleset fingerprint is provenance,
-- not unblock identity: an unrelated ruleset change cannot clear a fault for an
-- unchanged stable rule scope.
CREATE VIEW IF NOT EXISTS fusion.correlation_integrity_scope_state_current AS
SELECT
    engine_id,
    correlation_rule_id,
    correlation_rule_version,
    correlation_scope_fingerprint,
    'blocked_integrity' AS correlation_status,
    arraySort(groupUniqArray(ruleset_fingerprint)) AS ruleset_fingerprints,
    uniqExact(integrity_event_id) AS integrity_violation_count,
    arraySort(groupUniqArray(violation_type)) AS violation_types,
    min(first_detected_at) AS first_detected_at,
    max(detected_at) AS last_detected_at
FROM fusion.correlation_integrity_events
GROUP BY
    engine_id,
    correlation_rule_id,
    correlation_rule_version,
    correlation_scope_fingerprint;
