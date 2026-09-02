CREATE DATABASE IF NOT EXISTS fusion;

CREATE TABLE IF NOT EXISTS fusion.sysmon_events
(
    event_time DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    event_id UInt16,
    event_type LowCardinality(String),
    channel LowCardinality(String),
    computer LowCardinality(String),
    user String,
    process_guid String,
    process_id UInt32,
    image String,
    command_line String,
    parent_image String,
    parent_command_line String,
    powershell_script String,
    source_ip String,
    source_port UInt16,
    destination_ip String,
    destination_port UInt16,
    destination_hostname String,
    protocol LowCardinality(String),
    initiated UInt8,
    hashes String,
    rule_name String,
    validation_id String,
    raw_json String,
    INDEX image_token_idx lower(image) TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4,
    INDEX command_token_idx lower(command_line) TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX destination_ip_idx destination_ip TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_type, event_time, computer, event_id)
TTL event_time + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

