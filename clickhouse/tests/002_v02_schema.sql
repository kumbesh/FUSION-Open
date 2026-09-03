-- Minimal isolated copy of the v0.2 table used to prove that migration 003
-- upgrades an existing schema without deleting its Windows rows.
CREATE DATABASE IF NOT EXISTS fusion_v03_migration_test;
DROP TABLE IF EXISTS fusion_v03_migration_test.sysmon_events;

CREATE TABLE fusion_v03_migration_test.sysmon_events
(
    event_time DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    event_id UInt16,
    event_type LowCardinality(String),
    channel LowCardinality(String),
    provider_name LowCardinality(String),
    record_id UInt64,
    computer LowCardinality(String),
    user String,
    process_guid String,
    process_id UInt32,
    image String,
    image_loaded String,
    command_line String,
    parent_image String,
    parent_command_line String,
    powershell_script String,
    source_ip String,
    source_port UInt16,
    destination_ip String,
    destination_port UInt16,
    destination_hostname String,
    query_name String,
    query_status String,
    query_results String,
    target_filename String,
    target_object String,
    registry_details String,
    protocol LowCardinality(String),
    initiated UInt8,
    hashes String,
    rule_name String,
    message String,
    validation_id String,
    raw_json String
)
ENGINE = MergeTree
ORDER BY (event_type, event_time, computer, event_id);

INSERT INTO fusion_v03_migration_test.sysmon_events
    (event_time, event_id, event_type, channel, provider_name, record_id, computer, user, process_id, image, command_line, initiated, raw_json)
VALUES
    ('2026-09-02 10:00:00.000', 1, 'process_create', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Sysmon', 42, 'V02-HOST', 'LAB\\analyst', 1234, 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c whoami', 0, '{"v":"0.2"}');
