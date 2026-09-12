-- Idempotent v0.5.2 checkpoint/backlog telemetry.
-- Existing v0.5 checkpoint rows are preserved and receive safe defaults.
ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS newest_eligible_event_time Nullable(DateTime64(3, 'UTC')) AFTER checkpoint_uid;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS newest_eligible_event_uid String AFTER newest_eligible_event_time;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS checkpoint_lag_events UInt64 AFTER newest_eligible_event_uid;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS checkpoint_lag_seconds Float64 AFTER checkpoint_lag_events;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS events_evaluated UInt32 AFTER checkpoint_lag_seconds;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS new_events_processed UInt32 AFTER events_evaluated;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS late_events_processed UInt32 AFTER new_events_processed;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS processing_duration_seconds Float64 AFTER late_events_processed;

ALTER TABLE fusion.detection_checkpoints
    ADD COLUMN IF NOT EXISTS evaluated_events_per_second Float64 AFTER processing_duration_seconds;
