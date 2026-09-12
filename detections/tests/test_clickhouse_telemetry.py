from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from fusion_detection.clickhouse import ClickHouseStore
from fusion_detection.config import Settings
import fusion_detection.main as detection_main
from fusion_detection.main import _status
from fusion_detection.models import (
    BacklogStatus,
    Checkpoint,
    CycleStats,
    EvaluationScope,
)


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def settings(tmp_path: Path) -> Settings:
    return Settings(
        "clickhouse",
        8123,
        "fusion",
        "fusion",
        "secret",
        tmp_path,
        tmp_path / "fields.yml",
        tmp_path / "mitre.yml",
        10,
        120,
        1000,
        "test-engine",
        "INFO",
    )


class QueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class RecordingClient:
    def __init__(self, query_rows=()):
        self.query_rows = deque_rows = list(query_rows)
        self.commands = []
        self.queries = []
        self.inserts = []
        self._query_rows = deque_rows

    def command(self, command):
        self.commands.append(command)
        return 1

    def query(self, query, parameters=None):
        self.queries.append((query, parameters))
        return QueryResult(self._query_rows.pop(0))

    def insert(self, table, rows, column_names):
        self.inserts.append((table, rows, column_names))


def test_healthcheck_requires_detection_telemetry_schema(tmp_path):
    client = RecordingClient([[], [], []])
    store = ClickHouseStore(settings(tmp_path), client=client)

    store.healthcheck()

    assert client.commands == [
        "SELECT 1",
        "SELECT getSetting('wait_for_async_insert')",
    ]
    query, parameters = client.queries[0]
    assert parameters is None
    assert "FROM fusion.detection_checkpoints LIMIT 0" in query
    for column in (
        "engine_id",
        "evaluation_floor_time",
        "checkpoint_lag_events",
        "checkpoint_lag_seconds",
        "unevaluated_event_count",
        "oldest_unevaluated_event_time",
        "oldest_unevaluated_age_seconds",
        "events_evaluated",
        "new_events_processed",
        "processing_duration_seconds",
        "evaluated_events_per_second",
        "updated_at",
    ):
        assert column in query
    ledger_query, ledger_parameters = client.queries[1]
    assert ledger_parameters is None
    assert "FROM fusion.detection_evaluated_events LIMIT 0" in ledger_query
    for column in (
        "engine_id",
        "ruleset_fingerprint",
        "event_uid",
        "event_time",
        "evaluated_at",
    ):
        assert column in ledger_query
    scope_query, scope_parameters = client.queries[2]
    assert scope_parameters is None
    assert "FROM fusion.detection_evaluation_scopes LIMIT 0" in scope_query
    for column in (
        "engine_id",
        "ruleset_fingerprint",
        "evaluation_floor_time",
        "candidate_cursor_time",
        "candidate_cursor_uid",
        "updated_at",
    ):
        assert column in scope_query


def test_runtime_client_requires_acknowledged_async_inserts(monkeypatch, tmp_path):
    captured = {}
    client = RecordingClient()

    def get_client(**kwargs):
        captured.update(kwargs)
        return client

    monkeypatch.setattr(
        "fusion_detection.clickhouse.clickhouse_connect.get_client", get_client
    )

    store = ClickHouseStore(settings(tmp_path))

    assert store.client is client
    assert captured["settings"] == {"wait_for_async_insert": 1}


def test_healthcheck_fails_when_detection_telemetry_schema_is_missing(tmp_path):
    class MissingSchemaClient(RecordingClient):
        def query(self, query, parameters=None):
            raise RuntimeError("unknown identifier checkpoint_lag_events")

    store = ClickHouseStore(settings(tmp_path), client=MissingSchemaClient())

    with pytest.raises(RuntimeError, match="checkpoint_lag_events"):
        store.healthcheck()


def test_healthcheck_rejects_unacknowledged_async_inserts(tmp_path):
    class UnsafeInsertClient(RecordingClient):
        def command(self, command):
            self.commands.append(command)
            return 0 if "wait_for_async_insert" in command else 1

    store = ClickHouseStore(settings(tmp_path), client=UnsafeInsertClient())

    with pytest.raises(RuntimeError, match="wait_for_async_insert"):
        store.healthcheck()


def test_backlog_query_uses_parameterized_checkpoint_and_reports_exact_lag(tmp_path):
    checkpoint = Checkpoint(NOW, "checkpoint-secret-looking-value")
    evaluation_floor = NOW - timedelta(seconds=120)
    newest = NOW + timedelta(seconds=12.5)
    oldest = NOW - timedelta(seconds=5)
    client = RecordingClient([
        [(newest, "uid-z", 3)],
        [(4, oldest)],
    ])
    store = ClickHouseStore(settings(tmp_path), client=client)

    result = store.fetch_backlog_status(checkpoint, evaluation_floor)

    assert result.newest_event_time == newest
    assert result.newest_event_uid == "uid-z"
    assert result.lag_events == 3
    assert result.lag_seconds == 12.5
    assert result.unevaluated_events == 4
    assert result.oldest_unevaluated_event_time == oldest
    assert result.oldest_unevaluated_age_seconds >= 0
    query, parameters = client.queries[0]
    assert "{checkpoint_time:DateTime64(3)}" in query
    assert "{checkpoint_uid:String}" in query
    assert checkpoint.event_uid not in query
    assert parameters == {
        "engine_id": "test-engine",
        "ruleset_fingerprint": "unscoped",
        "evaluation_floor_time": evaluation_floor,
        "checkpoint_time": checkpoint.event_time,
        "checkpoint_uid": checkpoint.event_uid,
    }
    ledger_query, ledger_parameters = client.queries[1]
    assert "LEFT ANTI JOIN" in ledger_query
    assert "fusion.detection_evaluated_events FINAL" in ledger_query
    assert ledger_parameters == parameters


def test_empty_backlog_reports_no_eligible_source_head(tmp_path):
    checkpoint = Checkpoint(NOW, "uid-current")
    evaluation_floor = NOW - timedelta(seconds=120)
    client = RecordingClient([[(None, None, 0)], [(0, None)]])
    store = ClickHouseStore(settings(tmp_path), client=client)

    assert store.fetch_backlog_status(checkpoint, evaluation_floor) == BacklogStatus(
        None, "", 0, 0.0, 0, None, 0.0
    )


def test_evaluation_scope_is_loaded_for_the_exact_engine_and_ruleset(tmp_path):
    floor = NOW - timedelta(seconds=120)
    cursor = Checkpoint(NOW, "cursor-uid")
    client = RecordingClient([[(floor, cursor.event_time, cursor.event_uid)]])
    store = ClickHouseStore(
        settings(tmp_path), client=client, ruleset_fingerprint="f" * 64
    )

    assert store.load_evaluation_scope() == EvaluationScope(floor, cursor)
    query, parameters = client.queries[0]
    assert "fusion.detection_evaluation_scopes FINAL" in query
    assert "ruleset_fingerprint = {ruleset_fingerprint:String}" in query
    assert parameters == {
        "engine_id": "test-engine",
        "ruleset_fingerprint": "f" * 64,
    }


def test_legacy_evaluation_floor_is_loaded_for_scope_promotion(tmp_path):
    floor = NOW - timedelta(seconds=120)
    client = RecordingClient([[(floor,)]])
    store = ClickHouseStore(
        settings(tmp_path), client=client, ruleset_fingerprint="f" * 64
    )

    assert store.load_legacy_evaluation_floor() == floor
    query, parameters = client.queries[0]
    assert "fusion.detection_checkpoints FINAL" in query
    assert "ruleset_fingerprint = {ruleset_fingerprint:String}" in query
    assert "evaluation_floor_time IS NOT NULL" in query
    assert parameters == {
        "engine_id": "test-engine",
        "ruleset_fingerprint": "f" * 64,
    }


def test_initializing_evaluation_floor_persists_scope_before_checkpoint(tmp_path):
    floor = NOW - timedelta(seconds=120)
    checkpoint = Checkpoint(NOW, "uid-current")
    client = RecordingClient()
    store = ClickHouseStore(
        settings(tmp_path), client=client, ruleset_fingerprint="f" * 64
    )

    store.initialize_evaluation_floor(checkpoint, floor)

    assert [insert[0] for insert in client.inserts] == [
        "fusion.detection_evaluation_scopes",
        "fusion.detection_checkpoints",
    ]
    scope_values = dict(
        zip(client.inserts[0][2], client.inserts[0][1][0], strict=True)
    )
    assert scope_values["engine_id"] == "test-engine"
    assert scope_values["ruleset_fingerprint"] == "f" * 64
    assert scope_values["evaluation_floor_time"] == floor
    assert scope_values["candidate_cursor_time"] is None
    assert scope_values["candidate_cursor_uid"] == ""


def test_candidate_cursor_update_preserves_the_scope_floor(tmp_path):
    floor = NOW - timedelta(seconds=120)
    cursor = Checkpoint(NOW, "cursor-uid")
    client = RecordingClient()
    store = ClickHouseStore(
        settings(tmp_path), client=client, ruleset_fingerprint="f" * 64
    )

    store.save_candidate_cursor(floor, cursor)

    table, rows, columns = client.inserts[0]
    assert table == "fusion.detection_evaluation_scopes"
    values = dict(zip(columns, rows[0], strict=True))
    assert values["evaluation_floor_time"] == floor
    assert values["candidate_cursor_time"] == cursor.event_time
    assert values["candidate_cursor_uid"] == cursor.event_uid


def test_checkpoint_insert_persists_all_pipeline_telemetry(tmp_path):
    checkpoint = Checkpoint(NOW, "uid-current")
    backlog = BacklogStatus(NOW + timedelta(seconds=9), "uid-newest", 42, 9.0)
    stats = CycleStats(
        events_evaluated=1200,
        new_events_processed=1000,
        late_events_processed=200,
        matches_found=5,
        detections_inserted=4,
        duplicates_skipped=1,
        evaluation_failures=0,
        processing_duration_seconds=2.5,
        evaluated_events_per_second=480.0,
        checkpoint=checkpoint,
        backlog=backlog,
        evaluation_floor_time=NOW - timedelta(seconds=120),
    )
    client = RecordingClient()
    store = ClickHouseStore(settings(tmp_path), client=client)

    store.save_checkpoint(stats)

    assert len(client.inserts) == 1
    table, rows, columns = client.inserts[0]
    assert table == "fusion.detection_checkpoints"
    values = dict(zip(columns, rows[0], strict=True))
    assert values["engine_id"] == "test-engine"
    assert values["ruleset_fingerprint"] == "unscoped"
    assert values["checkpoint_time"] == NOW
    assert values["checkpoint_uid"] == "uid-current"
    assert values["evaluation_floor_time"] == NOW - timedelta(seconds=120)
    assert values["newest_eligible_event_time"] == backlog.newest_event_time
    assert values["newest_eligible_event_uid"] == "uid-newest"
    assert values["checkpoint_lag_events"] == 42
    assert values["checkpoint_lag_seconds"] == 9.0
    assert values["unevaluated_event_count"] == 0
    assert values["oldest_unevaluated_event_time"] is None
    assert values["oldest_unevaluated_age_seconds"] == 0.0
    assert values["events_evaluated"] == 1200
    assert values["new_events_processed"] == 1000
    assert values["late_events_processed"] == 200
    assert values["processing_duration_seconds"] == 2.5
    assert values["evaluated_events_per_second"] == 480.0
    assert values["updated_at"].tzinfo is not None


@pytest.mark.parametrize("persisted", [True, False])
def test_status_outputs_machine_readable_checkpoint_and_backlog_fields(
    monkeypatch, capsys, tmp_path, persisted
):
    checkpoint = Checkpoint(NOW, "uid-current") if persisted else None
    backlog = BacklogStatus(NOW + timedelta(seconds=5), "uid-newest", 9, 5.0)

    class StatusStore:
        def __init__(self, _settings, ruleset_fingerprint):
            assert ruleset_fingerprint == "f" * 64

        def load_checkpoint(self):
            return checkpoint

        def load_evaluation_scope(self):
            if not persisted:
                return None
            return EvaluationScope(
                NOW - timedelta(seconds=120), Checkpoint(NOW, "cursor-uid")
            )

        def load_legacy_evaluation_floor(self):
            return None

        def fetch_backlog_status(self, effective_checkpoint, evaluation_floor):
            if persisted:
                assert effective_checkpoint == checkpoint
                assert evaluation_floor == NOW - timedelta(seconds=120)
            return backlog

    monkeypatch.setattr("fusion_detection.main.ClickHouseStore", StatusStore)
    monkeypatch.setattr("fusion_detection.main.load_rules_strict", lambda *_args: ())
    monkeypatch.setattr(
        "fusion_detection.main._ruleset_fingerprint",
        lambda _rules, _settings: "f" * 64,
    )

    assert _status(settings(tmp_path)) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["engine_id"] == "test-engine"
    assert output["ruleset_fingerprint"] == "f" * 64
    assert output["checkpoint_persisted"] is persisted
    assert output["checkpoint_uid"] == ("uid-current" if persisted else "")
    assert output["evaluation_floor_persisted"] is persisted
    assert output["candidate_cursor_time"] == (NOW.isoformat() if persisted else None)
    assert output["candidate_cursor_uid"] == ("cursor-uid" if persisted else "")
    assert output["newest_eligible_event_time"] == backlog.newest_event_time.isoformat()
    assert output["newest_eligible_event_uid"] == "uid-newest"
    assert output["checkpoint_lag_events"] == 9
    assert output["checkpoint_lag_seconds"] == 5.0


def test_ruleset_fingerprint_is_order_independent_and_tracks_all_semantic_inputs(
    monkeypatch, tmp_path
):
    fields = tmp_path / "fields.yml"
    mitre = tmp_path / "mitre.yml"
    first_rule = tmp_path / "first.yml"
    second_rule = tmp_path / "second.yml"
    fields.write_text("Image: process_path\n", encoding="utf-8")
    mitre.write_text("T1059.001: PowerShell\n", encoding="utf-8")
    first_rule.write_text("title: First\n", encoding="utf-8")
    second_rule.write_text("title: Second\n", encoding="utf-8")
    configured = settings(tmp_path)
    first = SimpleNamespace(rule=SimpleNamespace(rule_id="rule-a", path=first_rule))
    second = SimpleNamespace(rule=SimpleNamespace(rule_id="rule-b", path=second_rule))

    baseline = detection_main._ruleset_fingerprint((second, first), configured)

    assert baseline == detection_main._ruleset_fingerprint((first, second), configured)
    first_rule.write_text("title: First changed\n", encoding="utf-8")
    assert baseline != detection_main._ruleset_fingerprint((first, second), configured)
    first_rule.write_text("title: First\n", encoding="utf-8")
    fields.write_text("Image: executable\n", encoding="utf-8")
    assert baseline != detection_main._ruleset_fingerprint((first, second), configured)
    fields.write_text("Image: process_path\n", encoding="utf-8")
    mitre.write_text("T1059.001: PowerShell changed\n", encoding="utf-8")
    assert baseline != detection_main._ruleset_fingerprint((first, second), configured)
    mitre.write_text("T1059.001: PowerShell\n", encoding="utf-8")
    moved_rule = tmp_path / "moved" / "first.yml"
    moved_rule.parent.mkdir()
    first_rule.rename(moved_rule)
    moved_first = SimpleNamespace(
        rule=SimpleNamespace(rule_id="rule-a", path=moved_rule)
    )
    assert baseline != detection_main._ruleset_fingerprint(
        (moved_first, second), configured
    )
    moved_rule.rename(first_rule)
    monkeypatch.setattr(detection_main, "__version__", "0.5.3-test")
    assert baseline != detection_main._ruleset_fingerprint((first, second), configured)
