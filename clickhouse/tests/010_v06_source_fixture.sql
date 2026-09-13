-- Minimal pre-v0.6 detection source used only by the isolated migration test.
-- Production deployments already have this table from migration 005.
CREATE TABLE IF NOT EXISTS fusion.detections
(
    detection_id String,
    detected_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC'),
    rule_id String,
    rule_version String,
    rule_name String,
    severity LowCardinality(String),
    platform LowCardinality(String),
    vendor LowCardinality(String),
    product LowCardinality(String),
    source_type LowCardinality(String),
    host_name String,
    user_name String,
    source_ip String,
    destination_ip String,
    protocol LowCardinality(String),
    signature String,
    signature_id String,
    mitre_technique_ids Array(String),
    source_event_time DateTime64(3, 'UTC'),
    validation_id String
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(detected_at)
ORDER BY detection_id;

-- v0.5.2 did not prohibit an empty detection_id. Keep one realistic legacy
-- row populated before migration 010 so migration 011 must preserve and
-- witness every source shape accepted by the released schema.
INSERT INTO fusion.detections
(
    detection_id, detected_at, updated_at, rule_id, rule_version, rule_name,
    severity, platform, vendor, product, source_type, host_name, user_name,
    source_ip, destination_ip, protocol, signature, signature_id,
    mitre_technique_ids, source_event_time, validation_id
)
VALUES
(
    '',
    toDateTime64('2026-09-12 08:00:00.000', 3, 'UTC'),
    toDateTime64('2026-09-12 08:00:01.000', 3, 'UTC'),
    'legacy-empty-id-rule', '1', 'Legacy empty ID compatibility fixture',
    'low', 'linux', 'Fusion', 'Legacy', 'fusion_detection',
    'legacy-empty-id.invalid', '', '', '', '', '', '', [],
    toDateTime64('2026-09-12 07:59:59.000', 3, 'UTC'),
    'v052-empty-id-upgrade'
);
