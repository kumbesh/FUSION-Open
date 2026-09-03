-- Idempotent v0.3 upgrade from the v0.2 Windows-oriented schema to a common
-- security-event model. Existing Sysmon columns and rows remain unchanged.
ALTER TABLE fusion.sysmon_events
    ADD COLUMN IF NOT EXISTS host_name LowCardinality(String) DEFAULT computer AFTER raw_json,
    ADD COLUMN IF NOT EXISTS platform LowCardinality(String) DEFAULT if(event_id > 0, 'windows', 'unknown') AFTER host_name,
    ADD COLUMN IF NOT EXISTS source_type LowCardinality(String) DEFAULT if(event_id > 0, 'windows_sysmon', 'unknown') AFTER platform,
    ADD COLUMN IF NOT EXISTS event_category LowCardinality(String) DEFAULT event_type AFTER source_type,
    ADD COLUMN IF NOT EXISTS event_action LowCardinality(String) DEFAULT event_type AFTER event_category,
    ADD COLUMN IF NOT EXISTS event_code String DEFAULT if(event_id > 0, toString(event_id), '') AFTER event_action,
    ADD COLUMN IF NOT EXISTS source_event_id String DEFAULT toString(record_id) AFTER event_code,
    ADD COLUMN IF NOT EXISTS user_name String DEFAULT user AFTER source_event_id,
    ADD COLUMN IF NOT EXISTS user_id String AFTER user_name,
    ADD COLUMN IF NOT EXISTS process_name String DEFAULT image AFTER user_id,
    ADD COLUMN IF NOT EXISTS process_path String DEFAULT image AFTER process_name,
    ADD COLUMN IF NOT EXISTS parent_process_name String DEFAULT parent_image AFTER process_path,
    ADD COLUMN IF NOT EXISTS parent_process_id UInt32 AFTER parent_process_name,
    ADD COLUMN IF NOT EXISTS service_name String AFTER parent_process_id,
    ADD COLUMN IF NOT EXISTS outcome LowCardinality(String) AFTER service_name,
    ADD COLUMN IF NOT EXISTS severity LowCardinality(String) AFTER outcome;

ALTER TABLE fusion.sysmon_events
    ADD INDEX IF NOT EXISTS process_path_token_idx lower(process_path) TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS source_type_set_idx source_type TYPE set(100) GRANULARITY 4;
