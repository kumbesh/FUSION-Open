-- Idempotent v0.5.2 candidate scheduling cursor.
-- This cursor rotates bounded candidate pages so a repeatably failing event
-- cannot starve valid events behind it. It is scheduling state only: the
-- evaluation ledger remains the sole completeness authority.
ALTER TABLE fusion.detection_evaluation_scopes
    ADD COLUMN IF NOT EXISTS candidate_cursor_time Nullable(DateTime64(3, 'UTC')) AFTER evaluation_floor_time;

ALTER TABLE fusion.detection_evaluation_scopes
    ADD COLUMN IF NOT EXISTS candidate_cursor_uid String AFTER candidate_cursor_time;
