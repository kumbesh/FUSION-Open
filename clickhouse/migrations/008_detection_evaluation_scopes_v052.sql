-- Idempotent v0.5.2 evaluation-scope state.
-- Floors are keyed by both engine and ruleset so switching A -> B -> A cannot
-- silently move A's enrollment boundary past an unfinished eligible event.
CREATE TABLE IF NOT EXISTS fusion.detection_evaluation_scopes
(
    engine_id LowCardinality(String),
    ruleset_fingerprint String,
    evaluation_floor_time DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (engine_id, ruleset_fingerprint)
SETTINGS index_granularity = 128;
