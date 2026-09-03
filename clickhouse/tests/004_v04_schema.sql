DROP DATABASE IF EXISTS fusion_v05_migration_test;
CREATE DATABASE fusion_v05_migration_test;

-- Minimal v0.4-compatible source table containing every column used to derive event_uid.
CREATE TABLE fusion_v05_migration_test.sysmon_events
(
    event_time DateTime64(3, 'UTC'),
    event_id UInt16,
    event_code String,
    platform LowCardinality(String),
    source_type LowCardinality(String),
    host_name LowCardinality(String),
    source_event_id String,
    process_guid String,
    raw_json String
)
ENGINE = MergeTree
ORDER BY (event_time, source_type);

INSERT INTO fusion_v05_migration_test.sysmon_events
    (event_time, event_id, event_code, platform, source_type, host_name, source_event_id, process_guid, raw_json)
VALUES
    ('2026-09-04 10:00:00.000', 1, '1', 'windows', 'windows_sysmon', 'WIN-V04', '1001', '{A}', '{"version":"0.4","platform":"windows"}'),
    ('2026-09-04 10:00:01.000', 0, 'EXECVE', 'linux', 'linux_auditd', 'LINUX-V04', '2001', '', '{"version":"0.4","platform":"linux"}'),
    ('2026-09-04 10:00:02.000', 0, 'alert', 'network', 'suricata_eve', 'NIDS-V04', '3001', '', '{"version":"0.4","product":"Suricata"}'),
    ('2026-09-04 10:00:03.000', 0, 'ID47', 'network', 'generic_syslog', 'FW-V04', '4001', '', '{"version":"0.4","format":"rfc5424"}');
