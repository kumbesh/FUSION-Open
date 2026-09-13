-- Idempotent Fusion v0.6 correlation and incident storage.
--
-- Correctness state intentionally has no TTL. Incident and semantic-state
-- revisions retain revision in their sorting keys so an unconfirmed higher
-- revision cannot replace the last confirmed predecessor during a merge.

-- fusion.detections is a ReplacingMergeTree whose older physical rows may be
-- removed during normal merges. Correlation needs the first observation and
-- every immutable semantic variant of a logical detection to remain stable
-- across replay, restart, and source-table merges. This narrow projection is
-- populated synchronously by the materialized view before correlation starts.
-- Exact physical duplicates may collapse; distinct observations or semantics
-- have distinct sorting keys and are retained. Correctness history has no TTL.
CREATE TABLE IF NOT EXISTS fusion.correlation_detection_input_history
(
    detection_id String,
    detected_at DateTime64(3, 'UTC'),
    source_event_time DateTime64(3, 'UTC'),
    rule_id String,
    rule_version String,
    rule_name String,
    severity LowCardinality(String),
    platform LowCardinality(String),
    vendor LowCardinality(String),
    product LowCardinality(String),
    source_type LowCardinality(String),
    host_name String,
    user_name String,
    source_ip String,
    destination_ip String,
    protocol LowCardinality(String),
    signature String,
    signature_id String,
    mitre_technique_ids Array(String),
    validation_id String,
    semantic_fingerprint String MATERIALIZED lower(hex(SHA256(toString(tuple(
        source_event_time, rule_id, rule_version, rule_name, severity, platform,
        vendor, product, source_type, host_name, user_name, source_ip,
        destination_ip, protocol, signature, signature_id,
        mitre_technique_ids, validation_id
    )))))
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(detected_at)
ORDER BY (detection_id, detected_at, semantic_fingerprint)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS fusion.correlation_detection_input_history_mv
TO fusion.correlation_detection_input_history
AS
SELECT
    detection_id,
    detected_at,
    source_event_time,
    rule_id,
    rule_version,
    rule_name,
    severity,
    platform,
    vendor,
    product,
    source_type,
    host_name,
    user_name,
    source_ip,
    destination_ip,
    protocol,
    signature,
    signature_id,
    mitre_technique_ids,
    validation_id
FROM fusion.detections;

-- Backfill detections that existed before the materialized view. Reapplying
-- this migration may add exact physical copies, but their sorting key and
-- semantics are identical and the logical correlation query collapses by ID
-- before any LIMIT. This avoids a race-prone anti-join during first install.
INSERT INTO fusion.correlation_detection_input_history
(
    detection_id, detected_at, source_event_time, rule_id, rule_version,
    rule_name, severity, platform, vendor, product, source_type, host_name,
    user_name, source_ip, destination_ip, protocol, signature, signature_id,
    mitre_technique_ids, validation_id
)
SELECT
    detection_id, detected_at, source_event_time, rule_id, rule_version,
    rule_name, severity, platform, vendor, product, source_type, host_name,
    user_name, source_ip, destination_ip, protocol, signature, signature_id,
    mitre_technique_ids, validation_id
FROM fusion.detections;

CREATE TABLE IF NOT EXISTS fusion.incidents
(
    incident_id String,
    incident_title String,
    incident_type LowCardinality(String),
    status LowCardinality(String) DEFAULT 'new',
    severity LowCardinality(String),
    severity_rank UInt8,
    confidence UInt8,
    created_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    first_seen DateTime64(3, 'UTC'),
    last_seen DateTime64(3, 'UTC'),
    acknowledged_at Nullable(DateTime64(3, 'UTC')),
    closed_at Nullable(DateTime64(3, 'UTC')),
    last_transition_id String,
    last_transition_from LowCardinality(String),
    last_transition_at Nullable(DateTime64(3, 'UTC')),
    primary_host String,
    primary_user String,
    primary_source_ip String,
    primary_destination_ip String,
    input_count UInt32,
    detection_count UInt32,
    event_count UInt32,
    distinct_detection_rule_count UInt16,
    source_family_count UInt8,
    mitre_tactic_ids Array(String),
    mitre_technique_ids Array(String),
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    group_key_json String,
    group_key_hash String,
    episode_anchor_kind LowCardinality(String),
    episode_anchor_id String,
    episode_anchor_time DateTime64(3, 'UTC'),
    episode_window_start DateTime64(3, 'UTC'),
    episode_window_end DateTime64(3, 'UTC'),
    last_evidence_observed_at DateTime64(3, 'UTC'),
    late_accept_until DateTime64(3, 'UTC'),
    late_update_count UInt32,
    revision UInt64,
    state_hash String,
    revision_source LowCardinality(String),
    revision_token String,
    evidence_json String,
    validation_id String,
    CONSTRAINT incidents_identity_nonempty CHECK notEmpty(incident_id) AND notEmpty(correlation_rule_id) AND notEmpty(correlation_scope_fingerprint) AND notEmpty(group_key_hash),
    CONSTRAINT incidents_anchor_nonempty CHECK notEmpty(episode_anchor_id),
    CONSTRAINT incidents_revision_identity_nonempty CHECK notEmpty(state_hash) AND notEmpty(revision_token),
    CONSTRAINT incidents_rule_version_positive CHECK correlation_rule_version > 0,
    CONSTRAINT incidents_status_allowed CHECK status IN ('new', 'acknowledged', 'closed'),
    CONSTRAINT incidents_severity_allowed CHECK severity IN ('low', 'medium', 'high', 'critical'),
    CONSTRAINT incidents_severity_rank_allowed CHECK severity_rank BETWEEN 1 AND 4,
    CONSTRAINT incidents_confidence_allowed CHECK confidence <= 100,
    CONSTRAINT incidents_has_detection CHECK detection_count > 0,
    CONSTRAINT incidents_input_count_consistent CHECK input_count = detection_count + event_count,
    CONSTRAINT incidents_revision_positive CHECK revision > 0,
    CONSTRAINT incidents_revision_source_allowed CHECK revision_source IN ('correlation_input', 'lifecycle_transition'),
    CONSTRAINT incidents_anchor_kind_allowed CHECK episode_anchor_kind IN ('detection', 'event'),
    CONSTRAINT incidents_window_ordered CHECK episode_window_end >= episode_window_start
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (incident_id, revision)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS fusion.incident_detection_links
(
    incident_id String,
    detection_id String,
    link_id String,
    introduction_revision_token String,
    relationship LowCardinality(String),
    occurred_at DateTime64(3, 'UTC'),
    observed_at DateTime64(3, 'UTC'),
    linked_at DateTime64(3, 'UTC') DEFAULT now64(3),
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    source_type LowCardinality(String),
    detection_rule_id String,
    detection_rule_name String,
    severity LowCardinality(String),
    host_name String,
    user_name String,
    source_ip String,
    destination_ip String,
    mitre_technique_ids Array(String),
    summary String,
    validation_id String,
    CONSTRAINT incident_detection_links_identity_nonempty CHECK notEmpty(incident_id) AND notEmpty(detection_id) AND notEmpty(link_id) AND notEmpty(introduction_revision_token),
    CONSTRAINT incident_detection_links_rule_version_positive CHECK correlation_rule_version > 0,
    CONSTRAINT incident_detection_links_relationship_allowed CHECK relationship IN ('trigger', 'supporting', 'context')
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (incident_id, detection_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS fusion.incident_event_links
(
    incident_id String,
    event_uid String,
    link_id String,
    introduction_revision_token String,
    relationship LowCardinality(String),
    occurred_at DateTime64(3, 'UTC'),
    observed_at DateTime64(3, 'UTC'),
    linked_at DateTime64(3, 'UTC') DEFAULT now64(3),
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    source_type LowCardinality(String),
    event_category LowCardinality(String),
    event_action LowCardinality(String),
    outcome LowCardinality(String),
    service_name String,
    host_name String,
    user_name String,
    source_ip String,
    destination_ip String,
    summary String,
    validation_id String,
    CONSTRAINT incident_event_links_identity_nonempty CHECK notEmpty(incident_id) AND notEmpty(event_uid) AND notEmpty(link_id) AND notEmpty(introduction_revision_token),
    CONSTRAINT incident_event_links_rule_version_positive CHECK correlation_rule_version > 0,
    CONSTRAINT incident_event_links_relationship_allowed CHECK relationship IN ('trigger', 'supporting', 'context')
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (incident_id, event_uid)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS fusion.correlation_evaluated_inputs
(
    engine_id LowCardinality(String),
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    input_kind LowCardinality(String),
    input_id String,
    occurred_at DateTime64(3, 'UTC'),
    observed_at DateTime64(3, 'UTC'),
    evaluated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    evaluation_action LowCardinality(String),
    lateness_status LowCardinality(String),
    incident_id String,
    evaluation_token String,
    reason_code LowCardinality(String),
    source_type LowCardinality(String),
    host_name String,
    validation_id String,
    CONSTRAINT correlation_evaluated_inputs_identity_nonempty CHECK notEmpty(engine_id) AND notEmpty(correlation_rule_id) AND notEmpty(correlation_scope_fingerprint) AND notEmpty(input_id) AND notEmpty(evaluation_token),
    CONSTRAINT correlation_evaluated_inputs_rule_version_positive CHECK correlation_rule_version > 0,
    CONSTRAINT correlation_evaluated_inputs_kind_allowed CHECK input_kind IN ('detection', 'event'),
    CONSTRAINT correlation_evaluated_inputs_action_allowed CHECK evaluation_action IN ('no_match', 'created', 'updated', 'enriched_closed', 'invalid_input'),
    CONSTRAINT correlation_evaluated_inputs_lateness_allowed CHECK lateness_status IN ('on_time', 'late_within_boundary', 'late_outside_boundary', 'not_applicable')
)
ENGINE = ReplacingMergeTree(evaluated_at)
PARTITION BY toYYYYMM(observed_at)
ORDER BY
(
    engine_id,
    correlation_rule_id,
    correlation_rule_version,
    correlation_scope_fingerprint,
    input_kind,
    input_id
)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS fusion.correlation_rule_state
(
    engine_id LowCardinality(String),
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    evaluation_floor_observed_at DateTime64(3, 'UTC'),
    compiler_version String,
    normalization_contract_version String,
    revision_token String,
    state_hash String,
    activated_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    revision UInt64,
    CONSTRAINT correlation_rule_state_identity_nonempty CHECK notEmpty(engine_id) AND notEmpty(correlation_rule_id) AND notEmpty(correlation_scope_fingerprint) AND notEmpty(revision_token) AND notEmpty(state_hash),
    CONSTRAINT correlation_rule_state_rule_version_positive CHECK correlation_rule_version > 0,
    CONSTRAINT correlation_rule_state_revision_positive CHECK revision > 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY
(
    engine_id,
    correlation_rule_id,
    correlation_rule_version,
    correlation_scope_fingerprint,
    revision
)
SETTINGS index_granularity = 128;

CREATE TABLE IF NOT EXISTS fusion.correlation_episode_state
(
    engine_id LowCardinality(String),
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    group_key_json String,
    group_key_hash String,
    episode_state_id String,
    revision_token String,
    canonical_qualifying_inputs Array(String),
    episode_anchor_kind LowCardinality(String),
    episode_anchor_id String,
    episode_anchor_time Nullable(DateTime64(3, 'UTC')),
    episode_window_start DateTime64(3, 'UTC'),
    episode_window_end DateTime64(3, 'UTC'),
    active_incident_id String,
    owned_detection_ids Array(String),
    owned_event_uids Array(String),
    last_input_observed_at DateTime64(3, 'UTC'),
    late_accept_until DateTime64(3, 'UTC'),
    collision_count UInt32,
    state_hash String,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    revision UInt64,
    CONSTRAINT correlation_episode_state_identity_nonempty CHECK notEmpty(engine_id) AND notEmpty(correlation_rule_id) AND notEmpty(correlation_scope_fingerprint) AND notEmpty(group_key_hash) AND notEmpty(episode_state_id) AND notEmpty(revision_token) AND notEmpty(state_hash),
    CONSTRAINT correlation_episode_state_rule_version_positive CHECK correlation_rule_version > 0,
    CONSTRAINT correlation_episode_state_revision_positive CHECK revision > 0,
    CONSTRAINT correlation_episode_state_anchor_kind_allowed CHECK episode_anchor_kind IN ('', 'detection', 'event'),
    CONSTRAINT correlation_episode_state_window_ordered CHECK episode_window_end >= episode_window_start
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY
(
    engine_id,
    correlation_rule_id,
    correlation_rule_version,
    correlation_scope_fingerprint,
    group_key_hash,
    episode_state_id,
    revision
)
SETTINGS index_granularity = 128;

CREATE TABLE IF NOT EXISTS fusion.correlation_scope_bootstrap_confirmations
(
    engine_id LowCardinality(String),
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    scope_bootstrap_token String,
    expected_rule_state_hash String,
    expected_rule_state_revision UInt64,
    confirmed_at DateTime64(3, 'UTC') DEFAULT now64(3),
    CONSTRAINT correlation_scope_bootstrap_identity_nonempty CHECK notEmpty(engine_id) AND notEmpty(correlation_rule_id) AND notEmpty(correlation_scope_fingerprint) AND notEmpty(scope_bootstrap_token) AND notEmpty(expected_rule_state_hash),
    CONSTRAINT correlation_scope_bootstrap_rule_version_positive CHECK correlation_rule_version > 0,
    CONSTRAINT correlation_scope_bootstrap_revision_positive CHECK expected_rule_state_revision > 0
)
ENGINE = MergeTree
ORDER BY
(
    engine_id,
    correlation_rule_id,
    correlation_rule_version,
    correlation_scope_fingerprint,
    scope_bootstrap_token
)
SETTINGS index_granularity = 128;

CREATE TABLE IF NOT EXISTS fusion.correlation_schedule_state
(
    engine_id LowCardinality(String),
    correlation_rule_id String,
    correlation_rule_version UInt32,
    correlation_scope_fingerprint String,
    candidate_cursor_occurred_at Nullable(DateTime64(3, 'UTC')),
    candidate_cursor_observed_at Nullable(DateTime64(3, 'UTC')),
    candidate_cursor_input_kind LowCardinality(String),
    candidate_cursor_input_id String,
    newest_eligible_occurred_at Nullable(DateTime64(3, 'UTC')),
    newest_eligible_observed_at Nullable(DateTime64(3, 'UTC')),
    newest_eligible_input_kind LowCardinality(String),
    newest_eligible_input_id String,
    unevaluated_input_count UInt64,
    oldest_unevaluated_observed_at Nullable(DateTime64(3, 'UTC')),
    oldest_unevaluated_age_seconds Float64,
    cycle_evaluated_count UInt32,
    cycle_matched_count UInt32,
    cycle_failed_count UInt32,
    cycle_incident_create_count UInt32,
    cycle_incident_update_count UInt32,
    cycle_detection_link_write_count UInt32,
    cycle_event_link_write_count UInt32,
    processing_duration_seconds Float64,
    evaluated_inputs_per_second Float64,
    consecutive_drain_cycles UInt32,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    revision UInt64,
    CONSTRAINT correlation_schedule_state_identity_nonempty CHECK notEmpty(engine_id) AND notEmpty(correlation_rule_id) AND notEmpty(correlation_scope_fingerprint),
    CONSTRAINT correlation_schedule_state_rule_version_positive CHECK correlation_rule_version > 0,
    CONSTRAINT correlation_schedule_state_revision_positive CHECK revision > 0,
    CONSTRAINT correlation_schedule_state_cursor_kind_allowed CHECK candidate_cursor_input_kind IN ('', 'detection', 'event'),
    CONSTRAINT correlation_schedule_state_newest_kind_allowed CHECK newest_eligible_input_kind IN ('', 'detection', 'event'),
    CONSTRAINT correlation_schedule_state_oldest_age_nonnegative CHECK oldest_unevaluated_age_seconds >= 0
)
ENGINE = ReplacingMergeTree(revision)
ORDER BY
(
    engine_id,
    correlation_rule_id,
    correlation_rule_version,
    correlation_scope_fingerprint
)
SETTINGS index_granularity = 128;

CREATE TABLE IF NOT EXISTS fusion.incident_status_transitions
(
    transition_id String,
    incident_id String,
    from_status LowCardinality(String),
    to_status LowCardinality(String),
    requested_at DateTime64(3, 'UTC'),
    applied_at DateTime64(3, 'UTC'),
    actor_type LowCardinality(String) DEFAULT 'local_admin',
    resulting_incident_revision UInt64,
    validation_id String,
    CONSTRAINT incident_status_transitions_identity_nonempty CHECK notEmpty(transition_id) AND notEmpty(incident_id),
    CONSTRAINT incident_status_transitions_from_allowed CHECK from_status IN ('new', 'acknowledged'),
    CONSTRAINT incident_status_transitions_to_allowed CHECK to_status IN ('acknowledged', 'closed'),
    CONSTRAINT incident_status_transitions_transition_allowed CHECK (from_status = 'new' AND to_status IN ('acknowledged', 'closed')) OR (from_status = 'acknowledged' AND to_status = 'closed'),
    CONSTRAINT incident_status_transitions_revision_positive CHECK resulting_incident_revision > 0,
    CONSTRAINT incident_status_transitions_actor_fixed CHECK actor_type = 'local_admin'
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(applied_at)
ORDER BY (incident_id, applied_at, transition_id)
SETTINGS index_granularity = 8192;

-- Logical completeness and lifecycle-audit views collapse physical replays.
CREATE VIEW IF NOT EXISTS fusion.correlation_evaluated_inputs_current AS
SELECT * EXCEPT (_logical_rank)
FROM
(
    SELECT
        *,
        row_number() OVER
        (
            PARTITION BY
                engine_id,
                correlation_rule_id,
                correlation_rule_version,
                correlation_scope_fingerprint,
                input_kind,
                input_id
            ORDER BY evaluated_at DESC, evaluation_token DESC
        ) AS _logical_rank
    FROM fusion.correlation_evaluated_inputs
)
WHERE _logical_rank = 1;

CREATE VIEW IF NOT EXISTS fusion.incident_status_transitions_current AS
SELECT * EXCEPT (_logical_rank)
FROM
(
    SELECT
        *,
        row_number() OVER
        (
            PARTITION BY incident_id, transition_id
            ORDER BY applied_at DESC, resulting_incident_revision DESC
        ) AS _logical_rank
    FROM fusion.incident_status_transitions
)
WHERE _logical_rank = 1;

CREATE VIEW IF NOT EXISTS fusion.correlation_scope_bootstrap_confirmations_current AS
SELECT * EXCEPT (_logical_rank)
FROM
(
    SELECT
        *,
        row_number() OVER
        (
            PARTITION BY
                engine_id,
                correlation_rule_id,
                correlation_rule_version,
                correlation_scope_fingerprint,
                scope_bootstrap_token
            ORDER BY confirmed_at DESC, expected_rule_state_revision DESC
        ) AS _logical_rank
    FROM fusion.correlation_scope_bootstrap_confirmations
)
WHERE _logical_rank = 1;

-- Candidate-mutated state is committed by its exact evaluation token. Initial
-- immutable rule-scope state instead requires its deterministic bootstrap
-- confirmation, including the expected state hash and revision.
CREATE VIEW IF NOT EXISTS fusion.correlation_rule_state_current AS
SELECT * EXCEPT (_logical_rank)
FROM
(
    SELECT
        *,
        row_number() OVER
        (
            PARTITION BY
                engine_id,
                correlation_rule_id,
                correlation_rule_version,
                correlation_scope_fingerprint
            ORDER BY revision DESC, updated_at DESC, state_hash DESC
        ) AS _logical_rank
    FROM
    (
        SELECT state.*
        FROM fusion.correlation_rule_state AS state
        INNER JOIN
        (
            SELECT DISTINCT evaluation_token
            FROM fusion.correlation_evaluated_inputs_current
        ) AS evaluated
            ON state.revision_token = evaluated.evaluation_token

        UNION ALL

        SELECT state.*
        FROM fusion.correlation_rule_state AS state
        INNER JOIN fusion.correlation_scope_bootstrap_confirmations_current AS bootstrap
            ON state.engine_id = bootstrap.engine_id
            AND state.correlation_rule_id = bootstrap.correlation_rule_id
            AND state.correlation_rule_version = bootstrap.correlation_rule_version
            AND state.correlation_scope_fingerprint = bootstrap.correlation_scope_fingerprint
            AND state.revision_token = bootstrap.scope_bootstrap_token
            AND state.state_hash = bootstrap.expected_rule_state_hash
            AND state.revision = bootstrap.expected_rule_state_revision
    )
)
WHERE _logical_rank = 1;

CREATE VIEW IF NOT EXISTS fusion.correlation_episode_state_current AS
SELECT * EXCEPT (_logical_rank)
FROM
(
    SELECT
        *,
        row_number() OVER
        (
            PARTITION BY
                engine_id,
                correlation_rule_id,
                correlation_rule_version,
                correlation_scope_fingerprint,
                group_key_hash,
                episode_state_id
            ORDER BY revision DESC, updated_at DESC, state_hash DESC
        ) AS _logical_rank
    FROM
    (
        SELECT state.*
        FROM fusion.correlation_episode_state AS state
        INNER JOIN
        (
            SELECT DISTINCT evaluation_token
            FROM fusion.correlation_evaluated_inputs_current
        ) AS evaluated
            ON state.revision_token = evaluated.evaluation_token
    )
)
WHERE _logical_rank = 1;

CREATE VIEW IF NOT EXISTS fusion.correlation_schedule_state_current AS
SELECT * EXCEPT (_logical_rank)
FROM
(
    SELECT
        *,
        row_number() OVER
        (
            PARTITION BY
                engine_id,
                correlation_rule_id,
                correlation_rule_version,
                correlation_scope_fingerprint
            ORDER BY revision DESC, updated_at DESC
        ) AS _logical_rank
    FROM fusion.correlation_schedule_state
)
WHERE _logical_rank = 1;

-- Links become visible only after the evaluation token that introduced them is
-- present in the exact correlation ledger. The earliest immutable introduction
-- wins if an invalid writer ever proposes more than one confirmed token.
CREATE VIEW IF NOT EXISTS fusion.incident_detection_links_current AS
SELECT * EXCEPT (_logical_rank)
FROM
(
    SELECT
        link.*,
        row_number() OVER
        (
            PARTITION BY link.incident_id, link.detection_id
            ORDER BY link.linked_at ASC, link.introduction_revision_token ASC
        ) AS _logical_rank
    FROM fusion.incident_detection_links AS link
    INNER JOIN
    (
        SELECT DISTINCT evaluation_token
        FROM fusion.correlation_evaluated_inputs_current
    ) AS evaluated
        ON link.introduction_revision_token = evaluated.evaluation_token
)
WHERE _logical_rank = 1;

CREATE VIEW IF NOT EXISTS fusion.incident_event_links_current AS
SELECT * EXCEPT (_logical_rank)
FROM
(
    SELECT
        link.*,
        row_number() OVER
        (
            PARTITION BY link.incident_id, link.event_uid
            ORDER BY link.linked_at ASC, link.introduction_revision_token ASC
        ) AS _logical_rank
    FROM fusion.incident_event_links AS link
    INNER JOIN
    (
        SELECT DISTINCT evaluation_token
        FROM fusion.correlation_evaluated_inputs_current
    ) AS evaluated
        ON link.introduction_revision_token = evaluated.evaluation_token
)
WHERE _logical_rank = 1;

-- Correlation-created revisions require their ledger token. Lifecycle revisions
-- require the exact immutable audit record, including the resulting revision.
CREATE VIEW IF NOT EXISTS fusion.incident_revisions_committed AS
SELECT incident.*
FROM fusion.incidents AS incident
INNER JOIN
(
    SELECT DISTINCT evaluation_token
    FROM fusion.correlation_evaluated_inputs_current
) AS evaluated
    ON incident.revision_token = evaluated.evaluation_token
WHERE incident.revision_source = 'correlation_input'

UNION ALL

SELECT incident.*
FROM fusion.incidents AS incident
INNER JOIN fusion.incident_status_transitions_current AS transition
    ON incident.incident_id = transition.incident_id
    AND incident.revision_token = transition.transition_id
    AND incident.revision = transition.resulting_incident_revision
WHERE incident.revision_source = 'lifecycle_transition';

-- Current incident state is the highest confirmation-backed revision. Related
-- detection IDs are derived from authoritative confirmed links, never stored as
-- a second writable membership authority in fusion.incidents.
CREATE VIEW IF NOT EXISTS fusion.incidents_current AS
SELECT
    current.incident_id,
    current.incident_title,
    current.incident_type,
    current.status,
    current.severity,
    current.severity_rank,
    current.confidence,
    current.created_at,
    current.updated_at,
    current.first_seen,
    current.last_seen,
    current.acknowledged_at,
    current.closed_at,
    current.last_transition_id,
    current.last_transition_from,
    current.last_transition_at,
    current.primary_host,
    current.primary_user,
    current.primary_source_ip,
    current.primary_destination_ip,
    current.input_count,
    current.detection_count,
    current.event_count,
    current.distinct_detection_rule_count,
    current.source_family_count,
    ifNull(links.related_detection_ids, CAST([], 'Array(String)')) AS related_detection_ids,
    current.mitre_tactic_ids,
    current.mitre_technique_ids,
    current.correlation_rule_id,
    current.correlation_rule_version,
    current.correlation_scope_fingerprint,
    current.group_key_json,
    current.group_key_hash,
    current.episode_anchor_kind,
    current.episode_anchor_id,
    current.episode_anchor_time,
    current.episode_window_start,
    current.episode_window_end,
    current.last_evidence_observed_at,
    current.late_accept_until,
    current.late_update_count,
    current.revision,
    current.state_hash,
    current.revision_source,
    current.revision_token,
    current.evidence_json,
    current.validation_id
FROM
(
    SELECT * EXCEPT (_logical_rank)
    FROM
    (
        SELECT
            *,
            row_number() OVER
            (
                PARTITION BY incident_id
                ORDER BY revision DESC, updated_at DESC, state_hash DESC
            ) AS _logical_rank
        FROM fusion.incident_revisions_committed
    )
    WHERE _logical_rank = 1
) AS current
LEFT JOIN
(
    SELECT
        incident_id,
        arraySort(groupUniqArray(detection_id)) AS related_detection_ids
    FROM fusion.incident_detection_links_current
    GROUP BY incident_id
) AS links
    ON current.incident_id = links.incident_id;

-- Stable, bounded snapshots provide a deterministic timeline even after source
-- telemetry reaches its independent retention limit. Raw payloads are excluded.
CREATE VIEW IF NOT EXISTS fusion.incident_timeline AS
SELECT
    incident_id,
    'detection' AS input_kind,
    detection_id AS input_id,
    link_id,
    relationship,
    occurred_at,
    observed_at,
    linked_at,
    source_type,
    detection_rule_id AS rule_id,
    detection_rule_name AS rule_name,
    '' AS event_category,
    '' AS event_action,
    '' AS outcome,
    '' AS service_name,
    severity,
    host_name,
    user_name,
    source_ip,
    destination_ip,
    mitre_technique_ids,
    summary,
    validation_id
FROM fusion.incident_detection_links_current

UNION ALL

SELECT
    incident_id,
    'event' AS input_kind,
    event_uid AS input_id,
    link_id,
    relationship,
    occurred_at,
    observed_at,
    linked_at,
    source_type,
    '' AS rule_id,
    '' AS rule_name,
    event_category,
    event_action,
    outcome,
    service_name,
    '' AS severity,
    host_name,
    user_name,
    source_ip,
    destination_ip,
    CAST([], 'Array(String)') AS mitre_technique_ids,
    summary,
    validation_id
FROM fusion.incident_event_links_current
ORDER BY incident_id, occurred_at, input_kind, input_id;
