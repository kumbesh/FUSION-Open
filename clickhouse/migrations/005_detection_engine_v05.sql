-- Idempotent v0.5 detection-engine schema.
-- Keep the historical sysmon_events table name for v0.1-v0.4 compatibility.
ALTER TABLE fusion.sysmon_events
    ADD COLUMN IF NOT EXISTS event_uid String MATERIALIZED lower(hex(SHA256(concat(
        platform, '|', source_type, '|', host_name, '|', source_event_id, '|',
        toString(event_time), '|', event_code, '|', process_guid, '|', raw_json
    )))) AFTER raw_json;

ALTER TABLE fusion.sysmon_events
    ADD INDEX IF NOT EXISTS event_uid_idx event_uid TYPE bloom_filter(0.001) GRANULARITY 4;

CREATE TABLE IF NOT EXISTS fusion.detections
(
    detection_id String,
    detected_at DateTime64(3, 'UTC') DEFAULT now64(3),
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    rule_id String,
    rule_name String,
    rule_description String,
    rule_source LowCardinality(String),
    rule_version String,
    severity LowCardinality(String),
    status LowCardinality(String) DEFAULT 'new',
    platform LowCardinality(String),
    vendor LowCardinality(String),
    product LowCardinality(String),
    source_type LowCardinality(String),
    host_name String,
    user_name String,
    process_name String,
    process_path String,
    command_line String,
    source_ip String,
    source_port UInt16,
    destination_ip String,
    destination_port UInt16,
    protocol LowCardinality(String),
    signature String,
    signature_id String,
    mitre_tactics Array(String),
    mitre_techniques Array(String),
    mitre_technique_ids Array(String),
    source_event_uid String,
    source_event_id String,
    source_event_time DateTime64(3, 'UTC'),
    validation_id String,
    evidence_json String,
    rule_metadata_json String,
    INDEX detection_rule_idx rule_id TYPE bloom_filter(0.001) GRANULARITY 4,
    INDEX detection_source_event_idx source_event_uid TYPE bloom_filter(0.001) GRANULARITY 4,
    INDEX detection_status_severity_idx (status, severity) TYPE set(50) GRANULARITY 4,
    INDEX detection_host_idx host_name TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(detected_at)
ORDER BY detection_id
TTL detected_at + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS fusion.detection_checkpoints
(
    engine_id LowCardinality(String),
    checkpoint_time DateTime64(3, 'UTC'),
    checkpoint_uid String,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY engine_id
SETTINGS index_granularity = 128;

-- Keep repeated development/upgrade runs idempotent if an earlier v0.5 draft exists.
ALTER TABLE fusion.detections
    ADD COLUMN IF NOT EXISTS validation_id String AFTER source_event_time;
