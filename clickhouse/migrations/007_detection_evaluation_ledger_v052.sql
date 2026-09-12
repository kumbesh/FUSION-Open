-- Idempotent v0.5.2 evaluation-completeness ledger.
-- A row is written only after rule evaluation and any required detection writes
-- complete successfully. There is intentionally no TTL: expiring ledger rows
-- while their source events still exist could cause duplicate evaluation.
CREATE TABLE IF NOT EXISTS fusion.detection_evaluated_events
(
    engine_id LowCardinality(String),
    ruleset_fingerprint String,
    event_uid String,
    event_time DateTime64(3, 'UTC'),
    evaluated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    source_type LowCardinality(String),
    host_name String,
    validation_id String
)
ENGINE = ReplacingMergeTree(evaluated_at)
PARTITION BY toYYYYMM(event_time)
ORDER BY (engine_id, ruleset_fingerprint, event_uid)
SETTINGS index_granularity = 8192;

-- The fixed floor preserves the v0.5 lookback boundary across restarts. Rows
-- ingested after the floor remain eligible even when their event_time is older.
ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS evaluation_floor_time Nullable(DateTime64(3, 'UTC')) AFTER checkpoint_uid;

-- A changed ruleset receives a fresh bounded evaluation floor, preserving the
-- v0.5 behavior of evaluating the active lookback against new/changed rules.
ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS ruleset_fingerprint String AFTER engine_id;

-- Positional checkpoint lag remains diagnostic only. These columns describe
-- actual evaluation completeness using the persisted ledger.
ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS unevaluated_event_count UInt64 AFTER checkpoint_lag_seconds;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS oldest_unevaluated_event_time Nullable(DateTime64(3, 'UTC')) AFTER unevaluated_event_count;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS oldest_unevaluated_age_seconds Float64 AFTER oldest_unevaluated_event_time;
