from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from fusion_correlation.clickhouse import ClickHouseCorrelationStore
from fusion_correlation.engine import CorrelationEngine
from fusion_correlation.evaluator import CorrelationEvaluator


DETECTION_COLUMNS = [
    "detection_id",
    "detected_at",
    "updated_at",
    "rule_id",
    "rule_name",
    "rule_version",
    "severity",
    "platform",
    "vendor",
    "product",
    "source_type",
    "host_name",
    "source_event_uid",
    "source_event_id",
    "source_event_time",
    "validation_id",
    "evidence_json",
    "rule_metadata_json",
]


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        clickhouse_host=os.getenv("FUSION_TEST_CLICKHOUSE_HOST", "127.0.0.1"),
        clickhouse_port=int(os.getenv("FUSION_TEST_CLICKHOUSE_PORT", "8123")),
        clickhouse_database="fusion",
        clickhouse_user=os.getenv("FUSION_TEST_CLICKHOUSE_USER", "fusion"),
        clickhouse_password=os.getenv(
            "FUSION_TEST_CLICKHOUSE_PASSWORD", "adapter-test-only"
        ),
        context_limit=10_000,
    )


def _row(
    detection_id: str,
    observed_at: datetime,
    occurred_at: datetime,
    *,
    rule_id: str,
    host_name: str,
    validation_id: str,
) -> list[object]:
    return [
        detection_id,
        observed_at,
        observed_at,
        rule_id,
        rule_id,
        "1",
        "medium",
        "windows",
        "Fusion",
        "EnrollmentTest",
        "fusion_detection",
        host_name,
        f"source-event-{detection_id}",
        f"source-record-{detection_id}",
        occurred_at,
        validation_id,
        "{}",
        "{}",
    ]


def _engine(store, compiled, engine_id: str, floor: datetime) -> CorrelationEngine:
    return CorrelationEngine(
        store=store,
        evaluator=CorrelationEvaluator(),
        compiled_rules=[compiled],
        engine_id=engine_id,
        lookback_seconds=60,
        batch_size=100,
        context_limit=10_000,
        clock=lambda: floor + timedelta(seconds=60),
    )


@pytest.mark.skipif(
    os.getenv("FUSION_TEST_CLICKHOUSE") != "1",
    reason="requires an isolated migrated ClickHouse test container",
)
def test_live_replay_cannot_resurrect_pre_enrollment_detection(compiler, rules_dir):
    suffix = uuid4().hex
    validation_id = f"enrollment-floor-{suffix}"
    engine_id = f"enrollment-floor-engine-{suffix}"
    floor = (datetime.now(UTC) + timedelta(days=2)).replace(microsecond=0)
    occurred_at = floor - timedelta(seconds=10)
    host = f"enrollment-{suffix}.example"
    stale_id = f"z-stale-{suffix}"
    fresh_id = f"m-fresh-{suffix}"
    lower_id = f"a-lower-{suffix}"
    conflict_id = f"n-conflict-{suffix}"
    compiled = compiler.load_rule(rules_dir / "host-suspicious-activity.yml")
    store = ClickHouseCorrelationStore(_settings())
    store.healthcheck()

    stale_original = _row(
        stale_id,
        floor - timedelta(milliseconds=1),
        occurred_at,
        rule_id="rule-a",
        host_name=host,
        validation_id=validation_id,
    )
    fresh = _row(
        fresh_id,
        floor + timedelta(milliseconds=1),
        occurred_at,
        rule_id="rule-b",
        host_name=host,
        validation_id=validation_id,
    )
    conflict_a = _row(
        conflict_id,
        floor + timedelta(milliseconds=2),
        occurred_at,
        rule_id="rule-conflict",
        host_name=host,
        validation_id=validation_id,
    )
    conflict_b = _row(
        conflict_id,
        floor + timedelta(milliseconds=3),
        occurred_at,
        rule_id="rule-conflict",
        host_name=f"other-{host}",
        validation_id=validation_id,
    )
    store.client.insert(
        "fusion.detections",
        [stale_original, fresh, list(fresh), conflict_b, conflict_a],
        column_names=DETECTION_COLUMNS,
    )

    first = _engine(store, compiled, engine_id, floor).run_cycle()[0]
    assert first.evaluated_inputs == 2
    assert first.failed_inputs == 0
    assert first.incidents_created == 0
    assert first.detection_links_written == 0

    # Restart before multiple replays arrive. Their insertion order is not
    # chronological, and one replay is an immutable semantic conflict.
    restarted_store = ClickHouseCorrelationStore(_settings())
    stale_replays = []
    for minute in (30, 10, 20):
        replay = list(stale_original)
        replay[DETECTION_COLUMNS.index("detected_at")] = floor + timedelta(
            minutes=minute
        )
        replay[DETECTION_COLUMNS.index("updated_at")] = floor + timedelta(
            minutes=minute
        )
        stale_replays.append(replay)
    stale_conflict = list(stale_replays[0])
    stale_conflict[DETECTION_COLUMNS.index("host_name")] = f"attacker-{host}"
    restarted_store.client.insert(
        "fusion.detections",
        [*stale_replays, stale_conflict],
        column_names=DETECTION_COLUMNS,
    )
    replay_cycle = _engine(restarted_store, compiled, engine_id, floor).run_cycle()[0]
    assert replay_cycle.evaluated_inputs == 0
    assert replay_cycle.backlog.unevaluated_input_count == 0

    # The lower lexical ID appears after the persisted cursor. It is genuine
    # post-floor work and must be found once, while the stale ID stays excluded.
    lower = _row(
        lower_id,
        floor + timedelta(milliseconds=4),
        occurred_at,
        rule_id="rule-a",
        host_name=host,
        validation_id=validation_id,
    )
    restarted_store.client.insert(
        "fusion.detections", [lower, list(lower)], column_names=DETECTION_COLUMNS
    )
    lower_cycle = _engine(
        ClickHouseCorrelationStore(_settings()), compiled, engine_id, floor
    ).run_cycle()[0]
    assert lower_cycle.evaluated_inputs == 1
    assert lower_cycle.incidents_created == 1
    assert lower_cycle.detection_links_written == 2

    before_merge = restarted_store.client.query(
        "SELECT incident_id, state_hash FROM fusion.incidents_current "
        "WHERE validation_id={validation_id:String}",
        parameters={"validation_id": validation_id},
    ).result_rows
    assert len(before_merge) == 1
    incident_id, incident_hash = map(str, before_merge[0])

    restarted_store.client.command("OPTIMIZE TABLE fusion.detections FINAL")
    restarted_store.client.command(
        "OPTIMIZE TABLE fusion.correlation_detection_input_history FINAL"
    )
    bypass = _engine(
        ClickHouseCorrelationStore(_settings()), compiled, engine_id, floor
    ).run_cycle()[0]
    assert bypass.evaluated_inputs == 0
    assert bypass.incidents_created == 0
    assert bypass.incidents_updated == 0
    assert bypass.backlog.unevaluated_input_count == 0

    exact = restarted_store.client.query(
        "SELECT "
        "(SELECT count() FROM fusion.incidents_current "
        " WHERE validation_id={validation_id:String}), "
        "(SELECT count() FROM fusion.incident_detection_links_current "
        " WHERE validation_id={validation_id:String}), "
        "(SELECT count() FROM fusion.correlation_evaluated_inputs_current "
        " WHERE engine_id={engine_id:String}), "
        "(SELECT count() FROM fusion.correlation_evaluated_inputs_current "
        " WHERE engine_id={engine_id:String} AND input_id={stale_id:String}), "
        "(SELECT count() FROM fusion.incident_detection_links_current "
        " WHERE detection_id={stale_id:String}), "
        "(SELECT evaluation_action FROM fusion.correlation_evaluated_inputs_current "
        " WHERE engine_id={engine_id:String} AND input_id={conflict_id:String}), "
        "(SELECT evaluation_floor_observed_at "
        " FROM fusion.correlation_rule_state_current "
        " WHERE engine_id={engine_id:String} LIMIT 1)",
        parameters={
            "validation_id": validation_id,
            "engine_id": engine_id,
            "stale_id": stale_id,
            "conflict_id": conflict_id,
        },
    ).result_rows[0]
    assert tuple(exact[:5]) == (1, 2, 3, 0, 0)
    assert str(exact[5]) == "invalid_input"
    assert exact[6].replace(tzinfo=UTC) == floor

    after_merge = restarted_store.client.query(
        "SELECT incident_id, state_hash FROM fusion.incidents_current "
        "WHERE validation_id={validation_id:String}",
        parameters={"validation_id": validation_id},
    ).result_rows
    assert [(str(row[0]), str(row[1])) for row in after_merge] == [
        (incident_id, incident_hash)
    ]
