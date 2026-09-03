-- Idempotent v0.4 extension of the shared v0.3 security-event model.
-- The table name and every v0.1-v0.3 column remain unchanged.
ALTER TABLE fusion.sysmon_events
    ADD COLUMN IF NOT EXISTS device_name String DEFAULT host_name AFTER severity,
    ADD COLUMN IF NOT EXISTS vendor LowCardinality(String) DEFAULT if(platform = 'windows', 'Microsoft', if(platform = 'linux', 'Fusion', 'generic')) AFTER device_name,
    ADD COLUMN IF NOT EXISTS product LowCardinality(String) DEFAULT if(platform = 'windows', 'Sysmon', if(platform = 'linux', 'Linux', '')) AFTER vendor,
    ADD COLUMN IF NOT EXISTS event_kind LowCardinality(String) DEFAULT 'event' AFTER product,
    ADD COLUMN IF NOT EXISTS ingestion_protocol LowCardinality(String) DEFAULT if(source_type != '', 'http', '') AFTER event_kind,
    ADD COLUMN IF NOT EXISTS ingestion_path String DEFAULT if(platform = 'windows', '/sysmon', if(platform = 'linux', '/linux', '')) AFTER ingestion_protocol,
    ADD COLUMN IF NOT EXISTS source_address String AFTER ingestion_path,
    ADD COLUMN IF NOT EXISTS original_format LowCardinality(String) DEFAULT if(platform IN ('windows', 'linux'), 'json', '') AFTER source_address,
    ADD COLUMN IF NOT EXISTS network_direction LowCardinality(String) AFTER original_format,
    ADD COLUMN IF NOT EXISTS rule_id String AFTER network_direction,
    ADD COLUMN IF NOT EXISTS signature String AFTER rule_id,
    ADD COLUMN IF NOT EXISTS signature_id String AFTER signature,
    ADD COLUMN IF NOT EXISTS url String AFTER signature_id,
    ADD COLUMN IF NOT EXISTS domain String AFTER url,
    ADD COLUMN IF NOT EXISTS syslog_facility LowCardinality(String) AFTER domain,
    ADD COLUMN IF NOT EXISTS syslog_application String AFTER syslog_facility;

ALTER TABLE fusion.sysmon_events
    ADD INDEX IF NOT EXISTS vendor_product_set_idx (vendor, product) TYPE set(250) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS source_address_idx source_address TYPE bloom_filter(0.01) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS domain_token_idx lower(domain) TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS signature_token_idx lower(signature) TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;
