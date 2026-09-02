-- Idempotent upgrade for Fusion v0.1 volumes. New installations already contain
-- these columns through clickhouse/init/001_schema.sql.
ALTER TABLE fusion.sysmon_events
    ADD COLUMN IF NOT EXISTS provider_name LowCardinality(String) AFTER channel,
    ADD COLUMN IF NOT EXISTS record_id UInt64 AFTER provider_name,
    ADD COLUMN IF NOT EXISTS image_loaded String AFTER image,
    ADD COLUMN IF NOT EXISTS query_name String AFTER destination_hostname,
    ADD COLUMN IF NOT EXISTS query_status String AFTER query_name,
    ADD COLUMN IF NOT EXISTS query_results String AFTER query_status,
    ADD COLUMN IF NOT EXISTS target_filename String AFTER query_results,
    ADD COLUMN IF NOT EXISTS target_object String AFTER target_filename,
    ADD COLUMN IF NOT EXISTS registry_details String AFTER target_object,
    ADD COLUMN IF NOT EXISTS message String AFTER rule_name;

ALTER TABLE fusion.sysmon_events
    ADD INDEX IF NOT EXISTS query_name_idx lower(query_name) TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS target_filename_idx lower(target_filename) TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4;
