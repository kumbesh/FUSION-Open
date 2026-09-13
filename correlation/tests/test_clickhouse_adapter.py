from __future__ import annotations

import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from threading import Thread
from time import monotonic, sleep
from types import SimpleNamespace
from uuid import uuid4

import fusion_correlation.clickhouse as adapter
import pytest
from fusion_correlation.models import CompiledRule, Predicate, Selector
from fusion_correlation.runtime_models import (
    CorrelationIntegrityStatus,
    CorrelationPersistenceConflict,
    EvaluationDecision,
    EvidenceLink,
    InputEnvelope,
    RuleScope,
)
from runtime_memory_store import MemoryCorrelationStore

NOW = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)


class Result:
    def __init__(self, rows=(), columns=()):
        self.result_rows = list(rows)
        self.column_names = list(columns)


class QueueClient:
    def __init__(self, *results):
        self.results = list(results)
        self.queries: list[tuple[str, dict]] = []
        self.inserts: list[tuple[str, list, list]] = []

    def query(self, sql, parameters=None):
        self.queries.append((sql, dict(parameters or {})))
        if not self.results:
            raise AssertionError(f"unexpected query: {sql}")
        return self.results.pop(0)

    def insert(self, table, rows, column_names):
        self.inserts.append((table, list(rows), list(column_names)))


def _store(client):
    return adapter.ClickHouseCorrelationStore(
        SimpleNamespace(context_limit=10_000), client=client
    )


def _compiled(compiler, rules_dir, name="ssh-bruteforce-success.yml"):
    return compiler.load_rule(rules_dir / name)


def _candidate(kind="detection", input_id="input-1"):
    return InputEnvelope(
        kind,
        input_id,
        NOW,
        NOW,
        {
            "source_type": "test_source",
            "host_name": "host.example",
            "validation_id": "v",
        },
    )


def _decision(token="token-1"):
    return EvaluationDecision(
        "no_match", "not_applicable", "selector_not_satisfied", token
    )


def _link(relationship="trigger"):
    return EvidenceLink(
        "incident-1",
        "detection",
        "detection-1",
        "link-1",
        "token-1",
        relationship,
        NOW,
        NOW,
        "correlation-rule",
        1,
        "fingerprint",
        {
            "source_type": "linux_auth",
            "rule_id": "sigma-rule",
            "rule_name": "Sigma rule",
            "severity": "high",
            "host_name": "host.example",
            "user_name": "analyst",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "mitre_technique_ids": ["T1110"],
            "summary": "bounded summary",
            "validation_id": "v",
        },
    )


def test_default_client_scopes_synchronous_acknowledged_insert_settings(monkeypatch):
    captured = {}
    sentinel = object()

    def fake_get_client(**kwargs):
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(adapter.clickhouse_connect, "get_client", fake_get_client)
    settings = SimpleNamespace(
        clickhouse_host="clickhouse",
        clickhouse_port=8123,
        clickhouse_database="fusion",
        clickhouse_user="fusion",
        clickhouse_password="not-logged",
        context_limit=10_000,
    )

    store = adapter.ClickHouseCorrelationStore(settings)

    assert store.client is sentinel
    assert captured["settings"] == {
        "async_insert": 0,
        "wait_for_async_insert": 1,
        "use_query_cache": 0,
    }


class HealthcheckClient:
    def __init__(
        self,
        *,
        async_insert=0,
        wait_for_async_insert=1,
        projection_engine="MaterializedView",
        projection_select=None,
        projection_target_table=None,
        projection_exists=True,
        history_target_exists=True,
        history_target_engine="ReplacingMergeTree",
        history_target_columns=None,
        history_target_create=None,
        witness_projection_engine="MaterializedView",
        witness_projection_select=None,
        witness_projection_target_table=None,
        witness_projection_exists=True,
        witness_target_exists=True,
        witness_target_engine="ReplacingMergeTree",
        witness_target_columns=None,
        witness_target_create=None,
        integrity_target_exists=True,
        integrity_target_engine="MergeTree",
        integrity_target_columns=None,
        integrity_target_create=None,
        integrity_view_exists=True,
        integrity_view_engine="View",
        integrity_view_select=None,
        blocked_events=0,
    ):
        self.async_insert = async_insert
        self.wait_for_async_insert = wait_for_async_insert
        self.projection_engine = projection_engine
        self.projection_select = (
            projection_select
            if projection_select is not None
            else adapter.EXPECTED_HISTORY_PROJECTION_SELECT
        )
        self.projection_target_table = (
            projection_target_table
            if projection_target_table is not None
            else adapter.HISTORY_TABLE_NAME
        )
        self.projection_exists = projection_exists
        self.history_target_exists = history_target_exists
        self.history_target_engine = history_target_engine
        self.history_target_columns = (
            tuple(history_target_columns)
            if history_target_columns is not None
            else adapter.HISTORY_TARGET_COLUMN_CONTRACT
        )
        self.history_target_create = (
            history_target_create
            if history_target_create is not None
            else "CREATE TABLE fusion."
            + adapter.HISTORY_TABLE_NAME
            + " ENGINE=ReplacingMergeTree PARTITION BY toYYYYMM(detected_at) "
            "ORDER BY (detection_id, detected_at, semantic_fingerprint)"
        )
        self.witness_projection_engine = witness_projection_engine
        self.witness_projection_select = (
            witness_projection_select
            if witness_projection_select is not None
            else adapter.EXPECTED_WITNESS_PROJECTION_SELECT
        )
        self.witness_projection_target_table = (
            witness_projection_target_table
            if witness_projection_target_table is not None
            else adapter.WITNESS_TABLE_NAME
        )
        self.witness_projection_exists = witness_projection_exists
        self.witness_target_exists = witness_target_exists
        self.witness_target_engine = witness_target_engine
        self.witness_target_columns = (
            tuple(witness_target_columns)
            if witness_target_columns is not None
            else adapter.WITNESS_TARGET_COLUMN_CONTRACT
        )
        self.witness_target_create = (
            witness_target_create
            if witness_target_create is not None
            else "CREATE TABLE fusion."
            + adapter.WITNESS_TABLE_NAME
            + " ("
            + ", ".join(adapter.WITNESS_REQUIRED_CONSTRAINTS)
            + ") ENGINE=ReplacingMergeTree PARTITION BY toYYYYMM(detected_at) "
            "ORDER BY (detection_id, detected_at, semantic_fingerprint)"
        )
        self.integrity_target_exists = integrity_target_exists
        self.integrity_target_engine = integrity_target_engine
        self.integrity_target_columns = (
            tuple(integrity_target_columns)
            if integrity_target_columns is not None
            else adapter.INTEGRITY_TARGET_COLUMN_CONTRACT
        )
        self.integrity_target_create = (
            integrity_target_create
            if integrity_target_create is not None
            else "CREATE TABLE fusion."
            + adapter.INTEGRITY_TABLE_NAME
            + " ("
            + ", ".join(adapter.INTEGRITY_REQUIRED_CONSTRAINT_FRAGMENTS)
            + ") ENGINE=MergeTree PARTITION BY toYYYYMM(first_detected_at) "
            + "ORDER BY ("
            + adapter.INTEGRITY_SORT_KEY
            + ")"
        )
        self.integrity_view_exists = integrity_view_exists
        self.integrity_view_engine = integrity_view_engine
        self.integrity_view_select = (
            integrity_view_select
            if integrity_view_select is not None
            else adapter.EXPECTED_INTEGRITY_CURRENT_VIEW_SELECT
        )
        self.blocked_events = blocked_events
        self.commands = []
        self.queries = []

    def command(self, sql):
        self.commands.append(sql)
        if "getSetting('async_insert')" in sql:
            return self.async_insert
        if "getSetting('wait_for_async_insert')" in sql:
            return self.wait_for_async_insert
        return 1

    def query(self, sql, parameters=None):
        self.queries.append((sql, dict(parameters or {})))
        if "FROM system.tables" in sql:
            if f"name='{adapter.INTEGRITY_CURRENT_VIEW_NAME}'" in sql:
                return (
                    Result(
                        [
                            (
                                self.integrity_view_engine,
                                self.integrity_view_select,
                            )
                        ]
                    )
                    if self.integrity_view_exists
                    else Result()
                )
            if f"name='{adapter.INTEGRITY_TABLE_NAME}'" in sql:
                return (
                    Result(
                        [
                            (
                                self.integrity_target_engine,
                                self.integrity_target_engine,
                                "toYYYYMM(first_detected_at)",
                                adapter.INTEGRITY_SORT_KEY,
                                adapter.INTEGRITY_SORT_KEY,
                                self.integrity_target_create,
                            )
                        ]
                    )
                    if self.integrity_target_exists
                    else Result()
                )
            if f"name='{adapter.HISTORY_TABLE_NAME}'" in sql:
                return (
                    Result(
                        [
                            (
                                self.history_target_engine,
                                self.history_target_engine,
                                "toYYYYMM(detected_at)",
                                "detection_id, detected_at, semantic_fingerprint",
                                "detection_id, detected_at, semantic_fingerprint",
                                self.history_target_create,
                            )
                        ]
                    )
                    if self.history_target_exists
                    else Result()
                )
            if f"name='{adapter.WITNESS_TABLE_NAME}'" in sql:
                return (
                    Result(
                        [
                            (
                                self.witness_target_engine,
                                self.witness_target_engine,
                                "toYYYYMM(detected_at)",
                                "detection_id, detected_at, semantic_fingerprint",
                                "detection_id, detected_at, semantic_fingerprint",
                                self.witness_target_create,
                            )
                        ]
                    )
                    if self.witness_target_exists
                    else Result()
                )
            if f"name='{adapter.HISTORY_PROJECTION_NAME}'" in sql:
                if not self.projection_exists:
                    return Result()
                return Result(
                    [
                        (
                            self.projection_engine,
                            "fusion",
                            self.projection_target_table,
                            self.projection_select,
                        )
                    ]
                )
            if f"name='{adapter.WITNESS_PROJECTION_NAME}'" in sql:
                if not self.witness_projection_exists:
                    return Result()
                return Result(
                    [
                        (
                            self.witness_projection_engine,
                            "fusion",
                            self.witness_projection_target_table,
                            self.witness_projection_select,
                        )
                    ]
                )
            raise AssertionError(f"unexpected system.tables query: {sql}")
        if "FROM system.columns" in sql:
            if f"table='{adapter.INTEGRITY_TABLE_NAME}'" in sql:
                return Result(self.integrity_target_columns)
            if f"table='{adapter.WITNESS_TABLE_NAME}'" in sql:
                return Result(self.witness_target_columns)
            return Result(self.history_target_columns)
        if "uniqExact(integrity_event_id)" in sql:
            return Result([(self.blocked_events,)])
        return Result()


def test_healthcheck_requires_synchronous_acknowledged_insert_session():
    healthy = HealthcheckClient()
    _store(healthy).healthcheck()
    assert "SELECT getSetting('async_insert')" in healthy.commands
    assert "SELECT getSetting('wait_for_async_insert')" in healthy.commands
    health_sql = "\n".join(sql for sql, _ in healthy.queries)
    assert f"name='{adapter.HISTORY_TABLE_NAME}'" in health_sql
    assert "FROM system.tables" in health_sql

    with pytest.raises(RuntimeError, match="async_insert must be disabled"):
        _store(HealthcheckClient(async_insert=1)).healthcheck()

    with pytest.raises(RuntimeError, match="wait_for_async_insert must be enabled"):
        _store(HealthcheckClient(wait_for_async_insert=0)).healthcheck()


def test_healthcheck_rejects_missing_or_same_name_filtered_projection():
    with pytest.raises(RuntimeError, match="projection_unavailable"):
        _store(HealthcheckClient(projection_exists=False)).healthcheck()

    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(
            HealthcheckClient(
                projection_select=adapter.EXPECTED_HISTORY_PROJECTION_SELECT
                + " WHERE 0"
            )
        ).healthcheck()

    # Worker startup uses structural health so rule-scope preflight can persist
    # the exact projection fault instead of exiting before durable diagnostics.
    _store(HealthcheckClient(projection_exists=False)).healthcheck(
        check_projection_integrity=False
    )
    _store(HealthcheckClient(history_target_exists=False)).healthcheck(
        check_projection_integrity=False
    )
    _store(HealthcheckClient(witness_projection_exists=False)).healthcheck(
        check_projection_integrity=False
    )
    _store(HealthcheckClient(witness_target_exists=False)).healthcheck(
        check_projection_integrity=False
    )
    with pytest.raises(RuntimeError, match="projection_unavailable"):
        _store(HealthcheckClient(history_target_exists=False)).healthcheck()
    with pytest.raises(RuntimeError, match="projection_unavailable"):
        _store(HealthcheckClient(witness_projection_exists=False)).healthcheck()
    with pytest.raises(RuntimeError, match="projection_unavailable"):
        _store(HealthcheckClient(witness_target_exists=False)).healthcheck()


def test_strict_healthcheck_rejects_persistently_blocked_engine_but_structural_passes():
    client = HealthcheckClient(blocked_events=1)
    with pytest.raises(RuntimeError, match="blocked_integrity"):
        _store(client).healthcheck()
    _store(client).healthcheck(check_projection_integrity=False)


def test_structural_health_rejects_untrusted_integrity_event_authority():
    with pytest.raises(RuntimeError, match="authority is unavailable"):
        _store(HealthcheckClient(integrity_target_exists=False)).healthcheck(
            check_projection_integrity=False
        )

    ttl_contract = (
        "CREATE TABLE fusion."
        + adapter.INTEGRITY_TABLE_NAME
        + " ("
        + ", ".join(adapter.INTEGRITY_REQUIRED_CONSTRAINT_FRAGMENTS)
        + ") ENGINE=MergeTree PARTITION BY toYYYYMM(first_detected_at) "
        + "ORDER BY ("
        + adapter.INTEGRITY_SORT_KEY
        + ") TTL first_detected_at + INTERVAL 1 DAY"
    )
    with pytest.raises(RuntimeError, match="authority contract differs"):
        _store(
            HealthcheckClient(integrity_target_create=ttl_contract)
        ).healthcheck(check_projection_integrity=False)

    with pytest.raises(RuntimeError, match="authority contract differs"):
        _store(
            HealthcheckClient(
                integrity_target_columns=adapter.INTEGRITY_TARGET_COLUMN_CONTRACT[:-1]
            )
        ).healthcheck(check_projection_integrity=False)

    healthy_create = HealthcheckClient().integrity_target_create
    weakened_create = healthy_create.replace(
        adapter.INTEGRITY_REQUIRED_CONSTRAINT_FRAGMENTS[-1],
        adapter.INTEGRITY_REQUIRED_CONSTRAINT_FRAGMENTS[-1] + " OR 1",
    )
    with pytest.raises(RuntimeError, match="authority contract differs"):
        _store(
            HealthcheckClient(integrity_target_create=weakened_create)
        ).healthcheck(check_projection_integrity=False)

    with pytest.raises(RuntimeError, match="integrity-current view is unavailable"):
        _store(HealthcheckClient(integrity_view_exists=False)).healthcheck(
            check_projection_integrity=False
        )

    with pytest.raises(RuntimeError, match="integrity-current view contract differs"):
        _store(
            HealthcheckClient(
                integrity_view_select=(
                    adapter.EXPECTED_INTEGRITY_CURRENT_VIEW_SELECT + " WHERE 0"
                )
            )
        ).healthcheck(check_projection_integrity=False)


def test_projection_contract_accepts_formatting_but_rejects_wrong_source_or_target():
    formatted = adapter.EXPECTED_HISTORY_PROJECTION_SELECT.replace(
        "SELECT ", "SELECT\n    "
    ).replace(", ", ",\n    ")
    _store(HealthcheckClient(projection_select=formatted)).healthcheck()

    wrong_source = adapter.EXPECTED_HISTORY_PROJECTION_SELECT.replace(
        "FROM fusion.detections", "FROM fusion.other"
    )
    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(HealthcheckClient(projection_select=wrong_source)).healthcheck()

    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(HealthcheckClient(projection_target_table="other_history")).healthcheck()

    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(HealthcheckClient(history_target_engine="MergeTree")).healthcheck()

    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(
            HealthcheckClient(
                history_target_columns=adapter.HISTORY_TARGET_COLUMN_CONTRACT[:-1]
            )
        ).healthcheck()

    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(
            HealthcheckClient(
                witness_projection_select=(
                    adapter.EXPECTED_WITNESS_PROJECTION_SELECT + " WHERE 0"
                )
            )
        ).healthcheck()

    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(
            HealthcheckClient(
                witness_target_columns=adapter.WITNESS_TARGET_COLUMN_CONTRACT[:-1]
            )
        ).healthcheck()

    witness_create = HealthcheckClient().witness_target_create
    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(
            HealthcheckClient(
                witness_target_create=witness_create.replace(
                    adapter.WITNESS_REQUIRED_CONSTRAINTS[0],
                    adapter.WITNESS_REQUIRED_CONSTRAINTS[0] + " OR 1",
                )
            )
        ).healthcheck()

    with pytest.raises(RuntimeError, match="projection_contract_mismatch"):
        _store(
            HealthcheckClient(
                history_target_create="CREATE TABLE fusion."
                + adapter.HISTORY_TABLE_NAME
                + " ENGINE=ReplacingMergeTree ORDER BY detection_id "
                "TTL detected_at + INTERVAL 1 DAY"
            )
        ).healthcheck()


class IntegrityClient(HealthcheckClient):
    def __init__(
        self,
        *,
        mismatches=(),
        coverage_gaps=(),
        coverage_snapshots=None,
        persisted=(),
        coverage_error=None,
        mismatch_error=None,
        insert_activity=(),
        storage_generations=(),
    ):
        super().__init__()
        self.mismatches = list(mismatches)
        self.coverage_gaps = list(coverage_gaps)
        self.coverage_snapshots = (
            None
            if coverage_snapshots is None
            else list(coverage_snapshots)
        )
        self.persisted = list(persisted)
        self.coverage_error = coverage_error
        self.mismatch_error = mismatch_error
        self.insert_activity = list(insert_activity)
        self.storage_generations = list(storage_generations)
        self.inserts = []

    def query(self, sql, parameters=None):
        if "FROM system.tables" in sql or "FROM system.columns" in sql:
            return super().query(sql, parameters)
        self.queries.append((sql, dict(parameters or {})))
        if (
            "FROM fusion.correlation_integrity_events" in sql
            and "uniqExact(integrity_event_id)" in sql
        ):
            rows = self.persisted
            if not rows and self.inserts:
                rows = [
                    (
                        len({row[0] for row in self.inserts}),
                        sorted({row[8] for row in self.inserts}),
                        max(row[1] for row in self.inserts),
                    )
                ]
            if not rows:
                rows = [(0, [], None)]
            return Result(
                rows,
                (
                    "integrity_violation_count",
                    "violation_types",
                    "last_detected_at",
                ),
            )
        if "canonical_observation_mismatch_query" in sql:
            if self.mismatch_error is not None:
                raise self.mismatch_error
            return Result(self.mismatches)
        if "detection_source_insert_activity_query" in sql:
            if self.insert_activity:
                value = self.insert_activity.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return Result([(int(value),)])
            return Result([(0,)])
        if "detection_projection_storage_generation_query" in sql:
            if self.storage_generations:
                value = self.storage_generations.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return Result([value])
            return Result([(3, "d" * 64)])
        if "projection_coverage_query" in sql:
            if self.coverage_error is not None:
                raise self.coverage_error
            if self.coverage_snapshots is not None:
                if not self.coverage_snapshots:
                    return Result()
                snapshot = self.coverage_snapshots.pop(0)
                if isinstance(snapshot, BaseException):
                    raise snapshot
                return Result(snapshot)
            return Result(self.coverage_gaps)
        if "FROM fusion.correlation_integrity_events" in sql:
            event_id = dict(parameters or {}).get("event_id")
            count = sum(row[0] == event_id for row in self.inserts)
            return Result([(count,)])
        return Result()

    def insert(self, table, rows, column_names):
        assert table == "fusion.correlation_integrity_events"
        self.inserts.extend(rows)


def test_scope_integrity_persists_canonical_mismatch_and_is_idempotent(
    compiler, rules_dir
):
    canonical = NOW - timedelta(minutes=5)
    client = IntegrityClient(
        mismatches=[("detection", "d-1", NOW, canonical)]
    )
    store = _store(client)
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    blocked = store.check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert blocked == CorrelationIntegrityStatus(
        "blocked_integrity", 1, ("canonical_observation_mismatch",), NOW
    )
    assert len(client.inserts) == 1
    row = dict(zip(adapter.INTEGRITY_EVENT_COLUMNS, client.inserts[0], strict=True))
    assert row["input_kind"] == "detection"
    assert row["input_id"] == "d-1"
    assert row["ledger_observed_at"] == NOW
    assert row["canonical_observed_at"] == canonical
    assert "host_name" not in row["diagnostic_json"]
    mismatch_sql = next(
        sql
        for sql, _parameters in client.queries
        if "canonical_observation_mismatch_query" in sql
    )
    assert "use_query_cache=0" in mismatch_sql
    assert (
        "FROM fusion.sysmon_events PREWHERE event_uid IN ("
        "SELECT input_id FROM fusion.correlation_evaluated_inputs_current"
    ) in mismatch_sql
    assert "GROUP BY event_uid) AS canonical_event" in mismatch_sql
    assert "INNER JOIN fusion.sysmon_events AS events" not in mismatch_sql


def test_scope_integrity_has_no_false_positive_for_healthy_projection(
    compiler, rules_dir
):
    client = IntegrityClient()
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    healthy = _store(client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert healthy == CorrelationIntegrityStatus.healthy(NOW)
    assert client.inserts == []


def test_scope_integrity_confirms_transient_cross_table_gap_before_persisting(
    compiler, rules_dir
):
    gap = (
        "in-flight-detection",
        NOW,
        adapter.WITNESS_PROJECTION_QUALIFIED_NAME,
        1,
        "f" * 64,
    )
    client = IntegrityClient(coverage_snapshots=[[gap], []])
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    healthy = _store(client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert healthy == CorrelationIntegrityStatus.healthy(NOW)
    assert client.inserts == []
    assert sum(
        "projection_coverage_query" in sql for sql, _parameters in client.queries
    ) == 2


def test_scope_integrity_holds_inflight_publication_fail_closed_without_sticky_write(
    compiler, rules_dir
):
    gap = (
        "slow-in-flight-detection",
        NOW,
        adapter.WITNESS_PROJECTION_QUALIFIED_NAME,
        1,
        "e" * 64,
    )
    client = IntegrityClient(coverage_snapshots=[[gap]], insert_activity=[1])
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    blocked = _store(client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert blocked.blocked
    assert blocked.violation_count == 0
    assert blocked.violation_types == (
        adapter._PROJECTION_PUBLICATION_UNCONFIRMED,
    )
    assert client.inserts == []
    assert sum(
        "projection_coverage_query" in sql for sql, _parameters in client.queries
    ) == 1


def test_scope_integrity_requires_stable_scoped_generation_and_complete_activity_guard(
    compiler, rules_dir
):
    gap = (
        "generation-race-detection",
        NOW,
        adapter.WITNESS_PROJECTION_QUALIFIED_NAME,
        1,
        "e" * 64,
    )
    client = IntegrityClient(
        coverage_snapshots=[[gap], [gap]],
        insert_activity=[0, 0],
        storage_generations=[(3, "a" * 64), (4, "b" * 64)],
    )
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    blocked = _store(client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert blocked.blocked
    assert blocked.violation_count == 0
    assert blocked.violation_types == (
        adapter._PROJECTION_PUBLICATION_UNCONFIRMED,
    )
    assert client.inserts == []
    activity_sql = next(
        sql
        for sql, _parameters in client.queries
        if "detection_source_insert_activity_query" in sql
    )
    assert "'AsyncInsertFlush'" in activity_sql
    assert "system.asynchronous_inserts" in activity_sql
    assert "use_query_cache=0" in activity_sql
    generation_sql = next(
        sql
        for sql, _parameters in client.queries
        if "detection_projection_storage_generation_query" in sql
    )
    assert "FROM system.parts" in generation_sql
    assert "hash_of_all_files" in generation_sql
    assert "use_query_cache=0" in generation_sql


@pytest.mark.parametrize("second_activity", (False, True))
def test_scope_integrity_never_persists_changed_or_second_probe_active_gap(
    compiler, rules_dir, second_activity
):
    first_gap = (
        "changing-gap-detection",
        NOW,
        adapter.WITNESS_PROJECTION_QUALIFIED_NAME,
        1,
        "a" * 64,
    )
    second_gap = (
        "changing-gap-detection",
        NOW,
        adapter.WITNESS_PROJECTION_QUALIFIED_NAME,
        2,
        "b" * 64,
    )
    client = IntegrityClient(
        coverage_snapshots=[
            [first_gap],
            [first_gap if second_activity else second_gap],
        ],
        insert_activity=[0, int(second_activity)],
    )
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    blocked = _store(client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert blocked.blocked
    assert blocked.violation_count == 0
    assert blocked.violation_types == (
        adapter._PROJECTION_PUBLICATION_UNCONFIRMED,
    )
    assert client.inserts == []


def test_scope_integrity_revalidates_projection_contract_after_gap_proof(
    compiler, rules_dir, monkeypatch
):
    gap = (
        "contract-race-detection",
        NOW,
        adapter.HISTORY_PROJECTION_QUALIFIED_NAME,
        1,
        "c" * 64,
    )
    client = IntegrityClient(coverage_snapshots=[[gap], [gap]])
    store = _store(client)
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")
    original = store._validate_history_projection_contract
    calls = 0

    def changing_contract():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise adapter._ProjectionContractViolation(
                "projection_contract_mismatch",
                "test-only bounded DDL race",
                projection_name=adapter.HISTORY_PROJECTION_QUALIFIED_NAME,
                expected_fingerprint="a" * 64,
                actual_fingerprint="b" * 64,
            )
        return original()

    monkeypatch.setattr(
        store, "_validate_history_projection_contract", changing_contract
    )

    blocked = store.check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert blocked.blocked
    assert blocked.violation_types == ("projection_contract_mismatch",)
    assert len(client.inserts) == 1


def test_scope_integrity_second_snapshot_failure_is_persisted_as_uncertainty(
    compiler, rules_dir
):
    gap = (
        "in-flight-detection",
        NOW,
        adapter.HISTORY_PROJECTION_QUALIFIED_NAME,
        1,
        "f" * 64,
    )
    client = IntegrityClient(
        coverage_snapshots=[[gap], TimeoutError("sensitive-second-snapshot")]
    )
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    blocked = _store(client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert blocked.blocked
    assert blocked.violation_types == ("projection_coverage_uncertain",)
    assert len(client.inserts) == 2
    assert all(
        "sensitive-second-snapshot" not in row[-1] for row in client.inserts
    )


def test_scope_integrity_persists_bounded_query_uncertainty(compiler, rules_dir):
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")
    coverage_client = IntegrityClient(coverage_error=TimeoutError("sensitive"))

    coverage = _store(coverage_client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert coverage.blocked
    assert coverage.violation_count == 2
    assert coverage.violation_types == ("projection_coverage_uncertain",)
    coverage_rows = [
        dict(zip(adapter.INTEGRITY_EVENT_COLUMNS, row, strict=True))
        for row in coverage_client.inserts
    ]
    assert {row["projection_name"] for row in coverage_rows} == {
        adapter.HISTORY_PROJECTION_QUALIFIED_NAME,
        adapter.WITNESS_PROJECTION_QUALIFIED_NAME,
    }
    assert all("sensitive" not in row["diagnostic_json"] for row in coverage_rows)

    mismatch_client = IntegrityClient(mismatch_error=TimeoutError("sensitive"))
    mismatch = _store(mismatch_client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="b" * 64,
        checked_at=NOW,
    )

    assert mismatch.blocked
    assert mismatch.violation_types == ("canonical_observation_uncertain",)
    mismatch_row = dict(
        zip(
            adapter.INTEGRITY_EVENT_COLUMNS,
            mismatch_client.inserts[0],
            strict=True,
        )
    )
    assert mismatch_row["projection_name"] == adapter.HISTORY_PROJECTION_QUALIFIED_NAME
    assert "sensitive" not in mismatch_row["diagnostic_json"]


def test_scope_integrity_persists_bounded_projection_coverage_gap(
    compiler, rules_dir
):
    client = IntegrityClient(
        coverage_gaps=[
            (
                "missing-detection",
                NOW,
                adapter.HISTORY_PROJECTION_QUALIFIED_NAME,
                1,
                "f" * 64,
            )
        ]
    )
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    blocked = _store(client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert blocked.blocked
    assert blocked.violation_types == ("projection_coverage_gap",)
    assert len(client.inserts) == 1
    row = dict(zip(adapter.INTEGRITY_EVENT_COLUMNS, client.inserts[0], strict=True))
    assert row["input_kind"] == "detection"
    assert row["input_id"] == "missing-detection"
    assert row["projection_name"] == adapter.HISTORY_PROJECTION_QUALIFIED_NAME
    coverage_sql, coverage_parameters = next(
        (sql, parameters)
        for sql, parameters in client.queries
        if "projection_coverage_query" in sql
    )
    assert "detected_at >= {evaluation_floor:DateTime64(3)}" in coverage_sql
    assert "correlation_evaluated_inputs_current" in coverage_sql
    assert "has_post_floor_observation" in coverage_sql
    assert "ledger_row_present=1" in coverage_sql
    assert "notEmpty(ledger_ids.ledger_input_id)" not in coverage_sql
    assert "arrayJoin(arrayConcat" in coverage_sql
    assert coverage_sql.count("WHERE detection_id IN candidate_ids") == 3
    assert adapter.WITNESS_TABLE_QUALIFIED_NAME in coverage_sql
    assert "use_query_cache=0" in coverage_sql
    assert coverage_parameters["evaluation_floor"] == NOW - timedelta(hours=1)
    assert coverage_parameters["rule_id"] == compiled.rule_id
    assert sum(
        "projection_coverage_query" in sql for sql, _parameters in client.queries
    ) == 2


def test_scope_integrity_persists_empty_detection_id_coverage_gap(
    compiler, rules_dir
):
    client = IntegrityClient(
        coverage_gaps=[
            (
                "",
                NOW,
                adapter.WITNESS_PROJECTION_QUALIFIED_NAME,
                1,
                "f" * 64,
            )
        ]
    )
    compiled = _compiled(compiler, rules_dir)
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")

    blocked = _store(client).check_scope_integrity(
        scope,
        compiled,
        NOW - timedelta(hours=1),
        ruleset_fingerprint="a" * 64,
        checked_at=NOW,
    )

    assert blocked.blocked
    assert blocked.violation_types == ("projection_coverage_gap",)
    row = dict(zip(adapter.INTEGRITY_EVENT_COLUMNS, client.inserts[0], strict=True))
    assert row["input_id"] == ""
    assert row["projection_name"] == adapter.WITNESS_PROJECTION_QUALIFIED_NAME
    assert '"input_id_state":"empty"' in row["diagnostic_json"]


class StatusClient(HealthcheckClient):
    def __init__(
        self,
        *,
        global_gaps=(),
        global_snapshots=None,
        global_error=None,
        insert_activity=(),
        storage_generations=(),
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.global_gaps = list(global_gaps)
        self.global_snapshots = (
            None if global_snapshots is None else list(global_snapshots)
        )
        self.global_error = global_error
        self.insert_activity = list(insert_activity)
        self.storage_generations = list(storage_generations)

    def query(self, sql, parameters=None):
        if "detection_source_insert_activity_query" in sql:
            self.queries.append((sql, dict(parameters or {})))
            if self.insert_activity:
                value = self.insert_activity.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return Result([(int(value),)])
            return Result([(0,)])
        if "detection_projection_storage_generation_query" in sql:
            self.queries.append((sql, dict(parameters or {})))
            if self.storage_generations:
                value = self.storage_generations.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return Result([value])
            return Result([(3, "d" * 64)])
        if "FROM fusion.correlation_schedule_state_current" in sql:
            self.queries.append((sql, dict(parameters or {})))
            return Result()
        if (
            "FROM fusion.correlation_integrity_events" in sql
            and "GROUP BY correlation_rule_id" in sql
        ):
            self.queries.append((sql, dict(parameters or {})))
            return Result()
        if (
            "FROM fusion.correlation_integrity_events" in sql
            and "blocked_scope_count" in sql
        ):
            self.queries.append((sql, dict(parameters or {})))
            return Result([(0, 0, [])])
        if "global_projection_coverage_query" in sql:
            self.queries.append((sql, dict(parameters or {})))
            if self.global_error is not None:
                raise self.global_error
            if self.global_snapshots is not None:
                if not self.global_snapshots:
                    return Result()
                snapshot = self.global_snapshots.pop(0)
                if isinstance(snapshot, BaseException):
                    raise snapshot
                return Result(snapshot)
            return Result(self.global_gaps)
        return super().query(sql, parameters)


@pytest.mark.parametrize(
    ("client", "expected_type", "expected_live_status"),
    (
        (
            StatusClient(projection_exists=False),
            "projection_unavailable",
            "blocked_integrity",
        ),
        (
            StatusClient(
                projection_select=adapter.EXPECTED_HISTORY_PROJECTION_SELECT
                + " WHERE 0"
            ),
            "projection_contract_mismatch",
            "blocked_integrity",
        ),
        (
            StatusClient(witness_projection_exists=False),
            "projection_unavailable",
            "blocked_integrity",
        ),
        (
            StatusClient(
                witness_projection_select=(
                    adapter.EXPECTED_WITNESS_PROJECTION_SELECT + " WHERE 0"
                )
            ),
            "projection_contract_mismatch",
            "blocked_integrity",
        ),
        (
            StatusClient(
                global_gaps=[
                    (adapter.HISTORY_PROJECTION_QUALIFIED_NAME, 1, "f" * 64)
                ]
            ),
            "projection_coverage_gap",
            "blocked_integrity",
        ),
        (
            StatusClient(global_error=TimeoutError("sensitive-server-text")),
            "projection_coverage_uncertain",
            "unconfirmed",
        ),
    ),
)
def test_status_live_projection_probe_never_claims_healthy_before_persistence(
    client, expected_type, expected_live_status
):
    store = adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="engine", context_limit=10_000), client=client
    )

    status = store.status()

    assert status["correlation_status"] == "blocked_integrity"
    assert status["integrity_violation_count"] == 0
    assert status["live_projection_status"] == expected_live_status
    assert status["live_projection_violation_types"] == [expected_type]
    assert status["live_projection_blocks_all_scopes"] is True
    assert status["unevaluated_input_count"] is None
    assert "sensitive-server-text" not in str(status)


def test_status_live_projection_probe_reports_healthy_exact_parity():
    status = adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="engine", context_limit=10_000),
        client=StatusClient(),
    ).status()

    assert status["correlation_status"] == "healthy"
    assert status["live_projection_status"] == "healthy"
    assert status["live_projection_gap_count"] == 0
    assert status["live_projection_blocks_all_scopes"] is False


def test_status_confirms_transient_cross_table_gap_before_reporting_blocked():
    client = StatusClient(
        global_snapshots=[
            [(adapter.WITNESS_PROJECTION_QUALIFIED_NAME, 1, "f" * 64)],
            [],
        ]
    )

    status = adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="engine", context_limit=10_000), client=client
    ).status()

    assert status["correlation_status"] == "healthy"
    assert status["live_projection_status"] == "healthy"
    assert status["integrity_violation_count"] == 0


def test_status_keeps_inflight_projection_publication_unconfirmed():
    client = StatusClient(
        global_snapshots=[
            [(adapter.WITNESS_PROJECTION_QUALIFIED_NAME, 1, "f" * 64)]
        ],
        insert_activity=[1],
    )

    status = adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="engine", context_limit=10_000), client=client
    ).status()

    assert status["correlation_status"] == "blocked_integrity"
    assert status["live_projection_status"] == "unconfirmed"
    assert status["live_projection_violation_types"] == [
        adapter._PROJECTION_PUBLICATION_UNCONFIRMED
    ]
    assert status["integrity_violation_count"] == 0
    assert status["unevaluated_input_count"] is None


def test_strict_healthcheck_consumes_live_coverage_proof():
    gap = (adapter.WITNESS_PROJECTION_QUALIFIED_NAME, 1, "f" * 64)
    stable_gap = StatusClient(global_snapshots=[[gap], [gap]])
    with pytest.raises(RuntimeError, match="live observation projection integrity"):
        adapter.ClickHouseCorrelationStore(
            SimpleNamespace(engine_id="engine", context_limit=10_000),
            client=stable_gap,
        ).healthcheck()

    transient = StatusClient(global_snapshots=[[gap], []])
    adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="engine", context_limit=10_000),
        client=transient,
    ).healthcheck()

    active = StatusClient(global_snapshots=[[gap]], insert_activity=[1])
    with pytest.raises(RuntimeError, match="projection_publication_unconfirmed"):
        adapter.ClickHouseCorrelationStore(
            SimpleNamespace(engine_id="engine", context_limit=10_000),
            client=active,
        ).healthcheck()


def test_status_exposes_persisted_integrity_and_never_reports_stale_zero_backlog():
    schedule_columns = (
        "correlation_rule_id",
        "correlation_rule_version",
        "correlation_scope_fingerprint",
        "candidate_cursor_occurred_at",
        "candidate_cursor_observed_at",
        "candidate_cursor_input_kind",
        "candidate_cursor_input_id",
        "newest_eligible_occurred_at",
        "newest_eligible_observed_at",
        "newest_eligible_input_kind",
        "newest_eligible_input_id",
        "unevaluated_input_count",
        "oldest_unevaluated_observed_at",
        "oldest_unevaluated_age_seconds",
        "cycle_evaluated_count",
        "cycle_matched_count",
        "cycle_failed_count",
        "cycle_incident_create_count",
        "cycle_incident_update_count",
        "processing_duration_seconds",
        "evaluated_inputs_per_second",
        "updated_at",
    )
    schedule_row = (
        "rule-1",
        1,
        "f" * 64,
        None,
        None,
        "",
        "",
        NOW,
        NOW,
        "detection",
        "d-1",
        0,
        None,
        0.0,
        1,
        1,
        0,
        1,
        0,
        0.1,
        10.0,
        NOW,
    )
    integrity_columns = (
        "correlation_rule_id",
        "correlation_rule_version",
        "correlation_scope_fingerprint",
        "ruleset_fingerprints",
        "integrity_violation_count",
        "violation_types",
        "first_detected_at",
        "last_detected_at",
    )
    integrity_row = (
        "rule-1",
        1,
        "f" * 64,
        ["a" * 64],
        1,
        ["canonical_observation_mismatch"],
        NOW,
        NOW,
    )
    client = QueueClient(
        Result([schedule_row], schedule_columns),
        Result([integrity_row], integrity_columns),
        Result(
            [(1, 1, ["canonical_observation_mismatch"])],
            (
                "integrity_violation_count",
                "blocked_scope_count",
                "violation_types",
            ),
        ),
    )
    store = adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="engine", context_limit=10_000), client=client
    )

    status = store.status()

    assert status["correlation_status"] == "blocked_integrity"
    assert status["integrity_violation_count"] == 1
    assert status["integrity_violation_types"] == [
        "canonical_observation_mismatch"
    ]
    assert status["unevaluated_input_count"] is None
    assert status["oldest_unevaluated_age_seconds"] is None
    assert status["integrity_scope_details_truncated"] is False
    assert status["scopes"][0]["correlation_status"] == "blocked_integrity"
    assert status["scopes"][0]["unevaluated_input_count"] is None


def test_status_global_integrity_summary_cannot_be_hidden_by_detail_limit():
    client = QueueClient(
        Result([], ()),
        Result([], ()),
        Result(
            [(257, 257, ["projection_contract_mismatch"])],
            (
                "integrity_violation_count",
                "blocked_scope_count",
                "violation_types",
            ),
        ),
    )
    store = adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="engine", context_limit=10_000), client=client
    )

    status = store.status()

    assert status["correlation_status"] == "blocked_integrity"
    assert status["blocked_scope_count"] == 257
    assert status["integrity_violation_count"] == 257
    assert status["integrity_scope_details_truncated"] is True
    assert status["unevaluated_input_count"] is None


def test_source_collapse_uses_one_whole_row_and_all_semantic_fields(
    compiler, rules_dir
):
    sql, _ = adapter._source_union_sql(_compiled(compiler, rules_dir))
    assert "argMin(tuple(source_event_time" in sql
    assert "argMin(tuple(event_time" in sql
    assert "semantic_variant_count" in sql
    for field in adapter.DETECTION_VALUE_FIELDS:
        assert field in sql
    for field in adapter.EVENT_VALUE_FIELDS:
        assert field in sql
    assert "toUInt32(0) AS rule_version" not in sql
    assert "'' AS rule_version" in sql
    # Enrollment is applied after grouping the complete logical source ID and
    # must use its canonical earliest observation.  A newer physical replay
    # cannot move an old logical ID across a rule's enrollment floor.
    assert "GROUP BY detection_id) AS logical_detection WHERE observed_at" in sql
    assert "GROUP BY event_uid) AS logical_event WHERE observed_at" in sql
    assert "latest_observed_at" not in sql
    assert "FROM fusion.correlation_detection_input_history" in sql


def test_event_source_prefilters_ids_before_full_canonical_collapse(
    compiler, rules_dir
):
    sql, parameters = adapter._source_union_sql(_compiled(compiler, rules_dir))

    # The selective source_type/event-shape predicate may identify candidate
    # logical IDs, but canonical MIN(observed_at), whole-row selection, and
    # conflict detection must still read every physical variant for each ID.
    expected = (
        "FROM fusion.sysmon_events WHERE event_uid IN ("
        "SELECT event_uid FROM fusion.sysmon_events PREWHERE "
    )
    assert expected in sql
    event_sql = sql[sql.index(expected) :]
    assert "ingested_at >= {evaluation_floor:DateTime64(3)}" in event_sql
    assert "toString(event_action) = {selector_0_0:String}" in event_sql
    assert "toString(event_category) = {selector_0_1:String}" in event_sql
    assert "toString(outcome) = {selector_0_2:String}" in event_sql
    assert "toString(service_name) = {selector_0_3:String}" in event_sql
    assert "toString(source_type) = {selector_0_4:String}" in event_sql
    assert (
        "GROUP BY event_uid) GROUP BY event_uid) AS logical_event "
        "WHERE observed_at >= {evaluation_floor:DateTime64(3)}"
    ) in event_sql
    assert sql.count("min(ingested_at) AS observed_at") == 1
    assert sql.count("uniqExact(tuple(event_time") == 1
    assert parameters == {
        "selector_0_0": "ssh_login",
        "selector_0_1": "authentication",
        "selector_0_2": "success",
        "selector_0_3": "ssh",
        "selector_0_4": "linux_journald",
    }


def test_event_id_prefilter_does_not_push_canonical_identity_equality(
    compiler, rules_dir
):
    base = _compiled(compiler, rules_dir)
    event_selector = Selector(
        "context",
        "event",
        (
            Predicate("source_type", "eq", "windows_sysmon"),
            Predicate("event_code", "eq", "3"),
            Predicate("host_name", "eq", "host.example"),
        ),
    )
    compiled = CompiledRule(
        replace(base.rule, selectors=(event_selector,)),
        base.scope_fingerprint,
        base.canonical_semantic_plan,
    )

    sql, parameters = adapter._source_union_sql(compiled)

    assert "SELECT event_uid FROM fusion.sysmon_events PREWHERE" in sql
    assert "toString(source_type) = {selector_0_0:String}" in sql
    assert "toString(event_code) = {selector_0_1:String}" in sql
    assert "selector_0_2" not in sql
    assert "host_name =" not in sql
    assert parameters == {
        "selector_0_0": "windows_sysmon",
        "selector_0_1": "3",
    }


def test_event_sql_prefilter_is_broad_but_python_match_is_canonical(
    compiler, rules_dir
):
    base = _compiled(compiler, rules_dir)
    event_selector = Selector(
        "context",
        "event",
        (
            Predicate("source_type", "eq", "windows_sysmon"),
            Predicate("event_code", "eq", "3"),
            Predicate("host_name", "eq", "host.example"),
        ),
    )
    compiled = CompiledRule(
        replace(base.rule, selectors=(*base.rule.selectors, event_selector)),
        base.scope_fingerprint,
        base.canonical_semantic_plan,
    )
    sql, _ = adapter._source_union_sql(compiled)
    assert "event_source.host_name" not in sql
    columns = (
        "input_kind",
        "input_id",
        "occurred_at",
        "observed_at",
        *adapter.INPUT_VALUE_FIELDS,
        "invalid_reason",
    )
    values = {field: "" for field in adapter.INPUT_VALUE_FIELDS}
    values.update(
        source_type="windows_sysmon",
        event_code="3",
        host_name="HOST.EXAMPLE.",
        platform="windows",
        initiated=1,
        mitre_technique_ids=[],
    )
    row = (
        "event",
        "event-1",
        NOW,
        NOW,
        *(values[f] for f in adapter.INPUT_VALUE_FIELDS),
        "",
    )
    inputs = adapter._input_rows(Result([row], columns), compiled)
    assert [item.input_id for item in inputs] == ["event-1"]

    values["host_name"] = "different.example"
    row = (
        "event",
        "event-2",
        NOW,
        NOW,
        *(values[f] for f in adapter.INPUT_VALUE_FIELDS),
        "",
    )
    assert adapter._input_rows(Result([row], columns), compiled) == []


def test_context_query_enforces_the_same_canonical_enrollment_floor(
    compiler, rules_dir
):
    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    client = QueueClient(Result())
    floor = NOW - timedelta(minutes=5)

    assert _store(client).fetch_context(compiled, _candidate(), floor, 100) == []

    sql, parameters = client.queries[0]
    assert "FROM fusion.correlation_detection_input_history" in sql
    assert "WHERE observed_at >= {evaluation_floor:DateTime64(3)}" in sql
    assert parameters["evaluation_floor"] == floor
    assert "latest_observed_at" not in sql


def test_event_context_pushes_occurrence_window_into_candidate_id_seed(
    compiler, rules_dir
):
    compiled = _compiled(compiler, rules_dir, "ssh-bruteforce-success.yml")
    client = QueueClient(Result())
    candidate = _candidate()
    floor = NOW - timedelta(minutes=5)

    assert _store(client).fetch_context(compiled, candidate, floor, 100) == []

    sql, parameters = client.queries[0]
    seed_start = sql.index("SELECT event_uid FROM fusion.sysmon_events PREWHERE")
    seed_end = sql.index("GROUP BY event_uid)", seed_start)
    seed_sql = sql[seed_start:seed_end]
    assert "event_time >= {start:DateTime64(3)}" in seed_sql
    assert "event_time <= {end:DateTime64(3)}" in seed_sql
    assert "ingested_at >= {evaluation_floor:DateTime64(3)}" in seed_sql
    assert parameters["evaluation_floor"] == floor
    assert parameters["start"] == candidate.occurred_at - timedelta(minutes=5)
    assert parameters["end"] == candidate.occurred_at + timedelta(minutes=5)


def test_conflicted_event_is_enrolled_when_nonwinning_physical_variant_matches(
    compiler, rules_dir
):
    base = _compiled(compiler, rules_dir)
    event_selector = Selector(
        "context",
        "event",
        (
            Predicate("source_type", "eq", "windows_sysmon"),
            Predicate("event_code", "eq", "3"),
            Predicate("host_name", "eq", "host.example"),
        ),
    )
    compiled = CompiledRule(
        replace(base.rule, selectors=(*base.rule.selectors, event_selector)),
        base.scope_fingerprint,
        base.canonical_semantic_plan,
    )
    columns = (
        "input_kind",
        "input_id",
        "occurred_at",
        "observed_at",
        *adapter.INPUT_VALUE_FIELDS,
        "invalid_reason",
    )

    def event_row(host: str, invalid_reason: str = ""):
        values = {field: "" for field in adapter.INPUT_VALUE_FIELDS}
        values.update(
            source_type="windows_sysmon",
            event_code="3",
            host_name=host,
            platform="windows",
            initiated=1,
            mitre_technique_ids=[],
        )
        return (
            "event",
            "conflicted-event",
            NOW,
            NOW,
            *(values[field] for field in adapter.INPUT_VALUE_FIELDS),
            invalid_reason,
        )

    collapsed = Result(
        [event_row("wrong.example", "conflicting_immutable_values")], columns
    )
    physical = Result([event_row("wrong.example"), event_row("HOST.EXAMPLE.")], columns)
    store = _store(QueueClient(physical))

    inputs = store._decode_input_rows(collapsed, compiled, include_invalid_events=True)

    assert len(inputs) == 1
    assert inputs[0].invalid_reason == "conflicting_immutable_values"
    assert inputs[0].values["host_name"] == "wrong.example"
    assert "fusion.sysmon_events" in store.client.queries[0][0]

    assert (
        _store(QueueClient())._decode_input_rows(
            collapsed, compiled, include_invalid_events=False
        )
        == []
    )


def test_schedule_cursor_reconciles_from_later_exact_ledger_position():
    schedule = Result(
        [
            (
                NOW,
                NOW,
                "detection",
                "a",
            )
        ]
    )
    later = NOW.replace(second=1)
    ledger = Result([(later, later, "event", "b")])
    client = QueueClient(schedule, ledger)
    cursor = _store(client).load_schedule_cursor(
        RuleScope("engine", "rule", 1, "fingerprint")
    )
    assert cursor is not None
    assert cursor.occurred_at == later
    assert cursor.input_kind == "event"
    assert "correlation_evaluated_inputs_current" in client.queries[1][0]


def test_drained_clickhouse_backlog_retains_source_high_water(compiler, rules_dir):
    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    columns = (
        "input_kind",
        "input_id",
        "occurred_at",
        "observed_at",
        *adapter.INPUT_VALUE_FIELDS,
        "invalid_reason",
    )
    values = {field: "" for field in adapter.INPUT_VALUE_FIELDS}
    values.update(
        severity="high",
        host_name="host.example",
        source_type="fusion_detection",
        initiated=0,
        mitre_technique_ids=[],
    )
    high_water = (
        "detection",
        "detection-high-water",
        NOW,
        NOW,
        *(values[field] for field in adapter.INPUT_VALUE_FIELDS),
        "",
    )
    client = QueueClient(
        Result([high_water], columns),
        Result([(0, None, None, None, None, None)]),
    )

    backlog = _store(client).fetch_backlog(
        RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint"),
        compiled,
        NOW - timedelta(hours=1),
    )

    assert backlog.unevaluated_input_count == 0
    assert backlog.oldest_unevaluated_observed_at is None
    assert backlog.oldest_unevaluated_age_seconds == 0.0
    assert backlog.newest_input_kind == "detection"
    assert backlog.newest_input_id == "detection-high-water"
    assert backlog.newest_occurred_at == NOW
    backlog_sql = client.queries[1][0]
    assert "LEFT JOIN fusion.correlation_evaluated_inputs_current" in backlog_sql
    assert "source.invalid_reason='conflicting_immutable_values'" in backlog_sql


def test_candidate_join_surfaces_conflict_discovered_after_normal_ledger(
    compiler, rules_dir
):
    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    columns = (
        "input_kind",
        "input_id",
        "occurred_at",
        "observed_at",
        *adapter.INPUT_VALUE_FIELDS,
        "invalid_reason",
    )
    client = QueueClient(Result([], columns))

    assert (
        _store(client).fetch_candidates(
            RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint"),
            compiled,
            NOW - timedelta(hours=1),
            None,
            10,
        )
        == []
    )

    sql = client.queries[0][0]
    assert "LEFT JOIN fusion.correlation_evaluated_inputs_current" in sql
    assert "source.invalid_reason='conflicting_immutable_values'" in sql
    assert "evaluated.evaluation_action='invalid_input'" in sql


def test_candidate_page_bulk_primes_unique_group_state_and_replay_misses(
    compiler, rules_dir
):
    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")
    columns = (
        "input_kind",
        "input_id",
        "occurred_at",
        "observed_at",
        *adapter.INPUT_VALUE_FIELDS,
        "invalid_reason",
    )
    rows = []
    for index in range(1001):
        values = {field: "" for field in adapter.INPUT_VALUE_FIELDS}
        values.update(
            rule_id=f"rule-{index}",
            severity="high",
            host_name=f"host-{index}.example",
            source_type="fusion_detection",
            initiated=0,
            mitre_technique_ids=[],
        )
        rows.append(
            (
                "detection",
                f"detection-{index}",
                NOW,
                NOW,
                *(values[field] for field in adapter.INPUT_VALUE_FIELDS),
                "",
            )
        )
    client = QueueClient(
        Result(rows, columns),
        Result([], ("revision_token",)),
        Result([], adapter.EPISODE_COLUMNS),
    )
    store = _store(client)

    page = store.fetch_candidates(
        scope, compiled, NOW - timedelta(seconds=1), None, 1001
    )
    for candidate in page:
        assert (
            store.load_episode_states(
                scope,
                candidate,
                compiled,
                10_000,
                adapter.evaluation_token(scope, candidate),
            )
            == []
        )

    assert len(page) == 1001
    assert len(client.queries) == 3
    assert "GROUP BY revision_token" in client.queries[1][0]
    assert "correlation_episode_state_current" in client.queries[2][0]


def test_incident_reads_normalize_all_datetime64_fields_to_aware_utc():
    naive = NOW.replace(tzinfo=None)
    values = {column: "" for column in adapter.INCIDENT_COLUMNS}
    values.update(
        incident_id="incident-1",
        status="new",
        revision=1,
        state_hash="state-hash",
    )
    for field in adapter.INCIDENT_DATETIME_FIELDS:
        values[field] = naive
    row = tuple(values[column] for column in adapter.INCIDENT_COLUMNS)
    client = QueueClient(Result([row], adapter.INCIDENT_COLUMNS))

    record = _store(client).load_incidents(["incident-1"])["incident-1"]

    for field in adapter.INCIDENT_DATETIME_FIELDS:
        assert record.values[field].tzinfo is timezone.utc
        assert record.values[field] == NOW


def test_incident_members_use_bounded_confirmed_link_snapshots_and_utc():
    columns = (
        "input_kind",
        "input_id",
        "occurred_at",
        "observed_at",
        "source_type",
        "rule_id",
        "rule_name",
        "severity",
        "event_category",
        "event_action",
        "outcome",
        "service_name",
        "host_name",
        "user_name",
        "source_ip",
        "destination_ip",
        "mitre_technique_ids",
        "summary",
        "validation_id",
    )
    naive = NOW.replace(tzinfo=None)
    rows = [
        (
            "detection",
            "detection-1",
            naive,
            naive,
            "fusion_detection",
            "sigma-rule",
            "Sigma rule",
            "high",
            "",
            "",
            "",
            "",
            "HOST.EXAMPLE",
            "LAB\\analyst",
            "192.0.2.10",
            "198.51.100.20",
            ["T1110"],
            "Detection snapshot",
            "validation-1",
        ),
        (
            "event",
            "event-1",
            naive,
            naive,
            "linux_auditd",
            "",
            "",
            "",
            "authentication",
            "ssh_login",
            "failure",
            "sshd",
            "host.example",
            "analyst",
            "192.0.2.10",
            "198.51.100.20",
            [],
            "Event snapshot",
            "validation-1",
        ),
    ]
    client = QueueClient(Result(rows, columns))

    members = _store(client).load_incident_members("incident-1", 2)

    assert [(member.input_kind, member.input_id) for member in members] == [
        ("detection", "detection-1"),
        ("event", "event-1"),
    ]
    assert all(member.occurred_at.tzinfo is timezone.utc for member in members)
    assert all(member.observed_at.tzinfo is timezone.utc for member in members)
    assert members[0].values["rule_id"] == "sigma-rule"
    assert members[0].values["mitre_technique_ids"] == ["T1110"]
    assert members[1].values["event_action"] == "ssh_login"
    sql, parameters = client.queries[0]
    assert "incident_detection_links_current" in sql
    assert "incident_event_links_current" in sql
    assert "ORDER BY occurred_at, input_kind, input_id" in sql
    assert parameters == {"incident_id": "incident-1", "limit": 3}


def test_incident_members_fail_closed_when_membership_exceeds_bound():
    columns = (
        "input_kind",
        "input_id",
        "occurred_at",
        "observed_at",
        "source_type",
        "rule_id",
        "rule_name",
        "severity",
        "event_category",
        "event_action",
        "outcome",
        "service_name",
        "host_name",
        "user_name",
        "source_ip",
        "destination_ip",
        "mitre_technique_ids",
        "summary",
        "validation_id",
    )
    row = (
        "event",
        "event-1",
        NOW,
        NOW,
        "linux_auditd",
        "",
        "",
        "",
        "authentication",
        "ssh_login",
        "failure",
        "sshd",
        "host.example",
        "analyst",
        "192.0.2.10",
        "198.51.100.20",
        [],
        "Event snapshot",
        "validation-1",
    )
    client = QueueClient(Result([row, row, row], columns))

    with pytest.raises(OverflowError, match="incident membership exceeds 2"):
        _store(client).load_incident_members("incident-1", 2)

    assert client.queries[0][1]["limit"] == 3


def test_lifecycle_replay_uses_the_same_aware_incident_decoder():
    naive = NOW.replace(tzinfo=None)
    values = {column: "" for column in adapter.INCIDENT_COLUMNS}
    values.update(
        incident_id="incident-1",
        status="acknowledged",
        revision=2,
        state_hash="state-hash",
        revision_token="transition-1",
        last_transition_at=naive,
    )
    for field in adapter.INCIDENT_DATETIME_FIELDS:
        values[field] = naive
    row = tuple(values[column] for column in adapter.INCIDENT_COLUMNS)
    client = QueueClient(
        Result([row], adapter.INCIDENT_COLUMNS),
        Result([(1,)], ("count()",)),
        Result([(1,)], ("count()",)),
    )

    replay = _store(client).transition_incident(
        "incident-1", "acknowledged", "transition-1", NOW
    )

    assert replay.values["late_accept_until"].tzinfo is timezone.utc
    assert replay.values["last_transition_at"] == NOW
    assert client.inserts == []


def test_lifecycle_mutation_is_blocked_for_persisted_integrity_scope():
    values = {column: "" for column in adapter.INCIDENT_COLUMNS}
    values.update(
        incident_id="incident-1",
        correlation_rule_id="rule-1",
        correlation_rule_version=1,
        correlation_scope_fingerprint="f" * 64,
        revision=1,
        state_hash="state",
    )
    client = HealthcheckClient(blocked_events=1)

    with pytest.raises(CorrelationPersistenceConflict, match="lifecycle mutation"):
        _store(client)._assert_incident_scope_mutable(
            adapter.IncidentRecord(values)
        )

    sql, parameters = client.queries[-1]
    assert "correlation_integrity_events" in sql
    assert "uniqExact(integrity_event_id)" in sql
    assert "engine_id=" not in sql
    assert "engine_id" not in parameters
    assert parameters["fingerprint"] == "f" * 64


def test_lifecycle_mutation_fails_closed_when_integrity_authority_is_invalid():
    values = {column: "" for column in adapter.INCIDENT_COLUMNS}
    values.update(
        incident_id="incident-1",
        correlation_rule_id="rule-1",
        correlation_rule_version=1,
        correlation_scope_fingerprint="f" * 64,
        revision=1,
        state_hash="state",
    )
    bad_create = (
        "CREATE TABLE fusion."
        + adapter.INTEGRITY_TABLE_NAME
        + " ("
        + ", ".join(adapter.INTEGRITY_REQUIRED_CONSTRAINT_FRAGMENTS)
        + ") ENGINE=MergeTree PARTITION BY toYYYYMM(first_detected_at) "
        + "ORDER BY ("
        + adapter.INTEGRITY_SORT_KEY
        + ") TTL first_detected_at + INTERVAL 1 DAY"
    )
    client = HealthcheckClient(integrity_target_create=bad_create)

    with pytest.raises(RuntimeError, match="authority contract differs"):
        _store(client)._assert_incident_scope_mutable(adapter.IncidentRecord(values))

    assert not any(
        "WHERE correlation_rule_id" in sql
        for sql, _parameters in client.queries
    )


class LifecycleProbeClient(StatusClient):
    def __init__(self, *, canonical_mismatch_count=0, **kwargs):
        super().__init__(**kwargs)
        self.canonical_mismatch_count = canonical_mismatch_count
        values = {
            column: (None if column in adapter.INCIDENT_DATETIME_FIELDS else "")
            for column in adapter.INCIDENT_COLUMNS
        }
        values.update(
            incident_id="incident-1",
            status="new",
            correlation_rule_id="rule-1",
            correlation_rule_version=1,
            correlation_scope_fingerprint="f" * 64,
            revision=1,
            state_hash="state",
        )
        self.incident_row = tuple(values[column] for column in adapter.INCIDENT_COLUMNS)
        self.inserts = []

    def query(self, sql, parameters=None):
        if "revision_source='lifecycle_transition'" in sql:
            self.queries.append((sql, dict(parameters or {})))
            return Result([], adapter.INCIDENT_COLUMNS)
        if "FROM fusion.incidents_current" in sql:
            self.queries.append((sql, dict(parameters or {})))
            return Result([self.incident_row], adapter.INCIDENT_COLUMNS)
        if "lifecycle_canonical_observation_mismatch_query" in sql:
            self.queries.append((sql, dict(parameters or {})))
            return Result([(self.canonical_mismatch_count,)], ("count()",))
        return super().query(sql, parameters)

    def insert(self, table, rows, column_names):
        self.inserts.append((table, list(rows), list(column_names)))


@pytest.mark.parametrize(
    "client",
    (
        LifecycleProbeClient(projection_exists=False),
        LifecycleProbeClient(
            projection_select=adapter.EXPECTED_HISTORY_PROJECTION_SELECT + " WHERE 0"
        ),
        LifecycleProbeClient(
            global_gaps=[
                (adapter.WITNESS_PROJECTION_QUALIFIED_NAME, 1, "f" * 64)
            ]
        ),
    ),
)
def test_lifecycle_transition_before_worker_fails_closed_on_live_projection_fault(
    client,
):
    store = adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="different-engine", context_limit=10_000),
        client=client,
    )

    with pytest.raises(CorrelationPersistenceConflict, match="lifecycle mutation"):
        store.transition_incident("incident-1", "acknowledged", "transition-1", NOW)

    assert client.inserts == []
    assert not any(
        "incident_status_transitions" in sql
        for sql, _parameters in client.queries
    )


def test_lifecycle_transition_before_worker_fails_closed_on_canonical_regression():
    client = LifecycleProbeClient(canonical_mismatch_count=1)
    store = adapter.ClickHouseCorrelationStore(
        SimpleNamespace(engine_id="different-engine", context_limit=10_000),
        client=client,
    )

    with pytest.raises(CorrelationPersistenceConflict, match="canonical observation"):
        store.transition_incident("incident-1", "acknowledged", "transition-1", NOW)

    assert client.inserts == []
    mismatch_sql = next(
        sql
        for sql, _parameters in client.queries
        if "lifecycle_canonical_observation_mismatch_query" in sql
    )
    assert (
        "FROM fusion.sysmon_events PREWHERE event_uid IN ("
        "SELECT input_id FROM fusion.correlation_evaluated_inputs_current"
    ) in mismatch_sql
    assert "GROUP BY event_uid) AS canonical_event" in mismatch_sql
    assert "INNER JOIN fusion.sysmon_events AS events" not in mismatch_sql


def test_raw_episode_state_lookup_is_bounded(compiler, rules_dir):
    current = Result([], adapter.EPISODE_COLUMNS)
    raw = Result([(), (), ()], adapter.EPISODE_COLUMNS)
    client = QueueClient(current, raw)
    with pytest.raises(OverflowError, match="bounded raw episode-state"):
        _store(client).load_episode_states(
            RuleScope("engine", "rule", 1, "fingerprint"),
            _candidate(),
            _compiled(compiler, rules_dir, "host-suspicious-activity.yml"),
            2,
            "token-1",
        )
    raw_sql, parameters = client.queries[1]
    assert "episode_window_start" in raw_sql
    assert "LIMIT {limit:UInt32}" in raw_sql
    assert parameters["limit"] == 3


def test_scope_bootstrap_conflicting_physical_rows_fail_closed(compiler, rules_dir):
    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    current = Result([])
    raw = Result(
        [
            (NOW, "0.6.0", "fusion-identity-v1", "token", "hash-a", NOW, 1),
            (NOW, "0.6.0", "fusion-identity-v1", "token", "hash-b", NOW, 1),
        ]
    )
    with pytest.raises(CorrelationPersistenceConflict, match="conflicting immutable"):
        _store(QueueClient(current, raw)).ensure_scope(
            RuleScope(
                "engine", compiled.rule_id, compiled.version, compiled.scope_fingerprint
            ),
            compiled,
            NOW,
        )


def test_link_replay_checks_full_immutable_content():
    link = _link()
    columns = tuple(
        column
        for column in adapter.DETECTION_LINK_COLUMNS
        if column not in adapter._LINK_VOLATILE_COLUMNS
    )
    row = adapter._row_content(
        adapter.DETECTION_LINK_COLUMNS,
        adapter._link_row(link, NOW, adapter.DETECTION_LINK_COLUMNS),
        columns,
    )
    client = QueueClient(Result([row], columns))
    assert _store(client).write_links([link]) == (0, 0)
    assert client.inserts == []

    conflict = list(row)
    conflict[columns.index("relationship")] = "supporting"
    client = QueueClient(Result([conflict], columns))
    with pytest.raises(CorrelationPersistenceConflict, match="immutable content"):
        _store(client).write_links([link])


def test_ledger_exact_replay_is_idempotent_and_conflict_fails_closed():
    scope = RuleScope("engine", "rule", 1, "fingerprint")
    candidate = _candidate()
    decision = _decision()
    columns = tuple(
        column for column in adapter.LEDGER_COLUMNS if column != "evaluated_at"
    )
    row_by_name = {
        "engine_id": scope.engine_id,
        "correlation_rule_id": scope.rule_id,
        "correlation_rule_version": scope.rule_version,
        "correlation_scope_fingerprint": scope.fingerprint,
        "input_kind": candidate.input_kind,
        "input_id": candidate.input_id,
        "occurred_at": candidate.occurred_at,
        "observed_at": candidate.observed_at,
        "evaluation_action": decision.evaluation_action,
        "lateness_status": decision.lateness_status,
        "incident_id": decision.resulting_incident_id,
        "evaluation_token": decision.revision_token,
        "reason_code": decision.reason_code,
        "source_type": candidate.values["source_type"],
        "host_name": candidate.values["host_name"],
        "validation_id": candidate.values["validation_id"],
    }
    row = tuple(row_by_name[column] for column in columns)
    aggregate_columns = ("input_kind", "input_id", "immutable_variants")
    client = QueueClient(
        Result([("detection", "input-1", [row])], aggregate_columns),
        Result([row], columns),
    )
    assert _store(client).mark_evaluated(scope, [(candidate, decision)]) == 1
    assert client.inserts == []

    conflict = list(row)
    conflict[columns.index("reason_code")] = "different_reason"
    client = QueueClient(
        Result([("detection", "input-1", [tuple(conflict)])], aggregate_columns)
    )
    with pytest.raises(CorrelationPersistenceConflict, match="ledger identity"):
        _store(client).mark_evaluated(scope, [(candidate, decision)])
    assert client.inserts == []


def test_ledger_batch_uses_one_preflight_and_one_confirmation_query():
    scope = RuleScope("engine", "rule", 1, "fingerprint")
    immutable_columns = tuple(
        column for column in adapter.LEDGER_COLUMNS if column != "evaluated_at"
    )

    class BatchLedgerClient(QueueClient):
        def query(self, sql, parameters=None):
            self.queries.append((sql, dict(parameters or {})))
            if len(self.queries) == 1:
                return Result([], ("input_kind", "input_id", "immutable_variants"))
            assert len(self.queries) == 2
            assert len(self.inserts) == 1
            _, inserted, inserted_columns = self.inserts[0]
            confirmed = [
                adapter._row_content(inserted_columns, row, immutable_columns)
                for row in inserted
            ]
            return Result(confirmed, immutable_columns)

    client = BatchLedgerClient()
    store = _store(client)
    entries = [
        (
            _candidate(input_id=f"input-{index}"),
            _decision(f"token-{index}"),
        )
        for index in range(1000)
    ]

    assert store.mark_evaluated(scope, entries) == 1000
    assert len(client.queries) == 2
    assert len(client.inserts) == 1
    assert len(client.inserts[0][1]) == 1000
    assert "groupUniqArray(2)" in client.queries[0][0]
    assert "correlation_evaluated_inputs_current" in client.queries[1][0]


def test_late_physical_conflict_stays_visible_without_overwriting_ledger(
    compiler, rules_dir
):
    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    scope = RuleScope("engine", compiled.rule_id, compiled.version, "fingerprint")
    first = InputEnvelope(
        "detection",
        "logical-id",
        NOW,
        NOW,
        {
            "rule_id": "rule-a",
            "severity": "high",
            "host_name": "host-a.example",
            "source_type": "fusion_detection",
        },
    )
    store = MemoryCorrelationStore([first])
    original_decision = _decision("original-token")
    store.mark_evaluated(scope, [(first, original_decision)])

    store.inputs.append(
        replace(first, values={**first.values, "host_name": "host-b.example"})
    )
    candidates = store.fetch_candidates(
        scope, compiled, NOW - timedelta(seconds=1), None, 10
    )

    assert len(candidates) == 1
    assert candidates[0].invalid_reason == "conflicting_immutable_values"
    conflict_decision = EvaluationDecision(
        "invalid_input",
        "not_applicable",
        "conflicting_immutable_values",
        "conflict-token",
    )
    with pytest.raises(CorrelationPersistenceConflict, match="ledger identity"):
        store.mark_evaluated(scope, [(candidates[0], conflict_decision)])
    assert store.ledger[store._ledger_key(scope, first)] == original_decision
    assert (
        store.fetch_backlog(
            scope, compiled, NOW - timedelta(seconds=1)
        ).unevaluated_input_count
        == 1
    )


@pytest.mark.skipif(
    os.getenv("FUSION_TEST_CLICKHOUSE") != "1",
    reason="requires an isolated migrated ClickHouse test container",
)
def test_live_logical_source_projection_and_canonical_enrollment(
    compiler, rules_dir, request
):
    suffix = uuid4().hex
    now = datetime.now(timezone.utc).replace(microsecond=0)
    settings = SimpleNamespace(
        clickhouse_host=os.getenv("FUSION_TEST_CLICKHOUSE_HOST", "127.0.0.1"),
        clickhouse_port=int(os.getenv("FUSION_TEST_CLICKHOUSE_PORT", "8123")),
        clickhouse_database="fusion",
        clickhouse_user=os.getenv("FUSION_TEST_CLICKHOUSE_USER", "fusion"),
        clickhouse_password=os.getenv(
            "FUSION_TEST_CLICKHOUSE_PASSWORD", "adapter-test-only"
        ),
        context_limit=10_000,
    )
    store = adapter.ClickHouseCorrelationStore(settings)
    store.healthcheck()
    assert str(store.client.command("SELECT getSetting('async_insert')")).lower() in {
        "0",
        "false",
    }
    assert str(
        store.client.command("SELECT getSetting('wait_for_async_insert')")
    ).lower() in {"1", "true"}
    # Preserve physical source variants long enough to exercise the adapter's
    # conflict collapse. The disposable live-test server is restarted/removed
    # after the test; production code never changes merge settings.
    store.client.command("SYSTEM STOP MERGES fusion.detections")
    request.addfinalizer(
        lambda: store.client.command("SYSTEM START MERGES fusion.detections")
    )
    detection_columns = [
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
        "user_name",
        "source_ip",
        "destination_ip",
        "protocol",
        "signature",
        "signature_id",
        "mitre_technique_ids",
        "source_event_time",
        "validation_id",
    ]
    duplicate_id = f"adapter-conflict-{suffix}"
    common = [
        duplicate_id,
        now,
        now,
        "sigma-test",
        "row-a",
        "1.2.0",
        "high",
        "windows",
        "Microsoft",
        "Sysmon",
        "windows_sysmon",
        "HOST-A",
        "LAB\\analyst",
        "192.0.2.1",
        "198.51.100.1",
        "tcp",
        "",
        "",
        ["T1110"],
        now,
        suffix,
    ]
    conflicting = list(common)
    conflicting[detection_columns.index("updated_at")] = now.replace(microsecond=1_000)
    conflicting[detection_columns.index("rule_name")] = "row-b"
    conflicting[detection_columns.index("host_name")] = "HOST-B"
    epoch = list(common)
    epoch[0] = f"adapter-epoch-{suffix}"
    epoch[detection_columns.index("source_event_time")] = datetime(
        1970, 1, 1, tzinfo=timezone.utc
    )
    after_floor_id = f"adapter-after-floor-{suffix}"
    after_floor = list(common)
    after_floor[0] = after_floor_id
    after_floor[detection_columns.index("detected_at")] = now + timedelta(
        milliseconds=1
    )
    after_floor[detection_columns.index("updated_at")] = now + timedelta(
        milliseconds=1
    )
    after_floor[detection_columns.index("rule_name")] = "stable-after-floor"
    after_floor[detection_columns.index("host_name")] = "STABLE-A"
    store.client.insert(
        "fusion.detections",
        [common, after_floor, list(after_floor)],
        column_names=detection_columns,
    )
    store.client.insert(
        "fusion.detections",
        [conflicting, epoch],
        column_names=detection_columns,
    )
    replay_early = list(common)
    replay_early[0] = f"adapter-replay-{suffix}"
    replay_early[1] = now - timedelta(minutes=1)
    replay_early[2] = replay_early[1]
    replay_later = list(replay_early)
    replay_later[1] = now
    replay_later[2] = now
    replay_latest = list(replay_early)
    replay_latest[1] = now + timedelta(minutes=30)
    replay_latest[2] = now + timedelta(minutes=30)
    store.client.insert(
        "fusion.detections", [replay_early], column_names=detection_columns
    )
    store.client.insert(
        "fusion.detections",
        [replay_latest, replay_later],  # newest replay deliberately arrives first
        column_names=detection_columns,
    )

    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    scope = RuleScope("adapter-live", compiled.rule_id, compiled.version, suffix)
    assert store.ensure_scope(scope, compiled, now) == now
    assert store.ensure_scope(scope, compiled, now.replace(second=1)) == now
    inputs = store.fetch_candidates(scope, compiled, now, None, 100)
    by_id = {item.input_id: item for item in inputs}
    duplicate = by_id[duplicate_id]
    assert duplicate.invalid_reason == "conflicting_immutable_values"
    assert duplicate.values["rule_version"] == "1.2.0"
    assert (duplicate.values["rule_name"], duplicate.values["host_name"]) in {
        ("row-a", "HOST-A"),
        ("row-b", "HOST-B"),
    }
    assert by_id[epoch[0]].invalid_reason == "missing_occurrence_time"
    assert replay_early[0] not in by_id
    assert by_id[after_floor_id].observed_at == after_floor[
        detection_columns.index("detected_at")
    ]
    assert sum(item.input_id == after_floor_id for item in inputs) == 1

    post_ledger_id = f"adapter-post-ledger-conflict-{suffix}"
    post_original = list(common)
    post_original[0] = post_ledger_id
    post_original[detection_columns.index("rule_name")] = "post-original"
    post_original[detection_columns.index("host_name")] = "POST-A"
    store.client.insert(
        "fusion.detections", [post_original], column_names=detection_columns
    )
    post_scope = RuleScope(
        "adapter-post-ledger", compiled.rule_id, compiled.version, suffix
    )
    post_candidate = next(
        item
        for item in store.fetch_candidates(post_scope, compiled, now, None, 100)
        if item.input_id == post_ledger_id
    )
    original_post_decision = EvaluationDecision(
        "no_match", "not_applicable", "pre_conflict_evaluation", f"post-{suffix}"
    )
    assert (
        store.mark_evaluated(post_scope, [(post_candidate, original_post_decision)])
        == 1
    )
    post_conflict = list(post_original)
    post_conflict[detection_columns.index("updated_at")] = now + timedelta(
        milliseconds=2
    )
    post_conflict[detection_columns.index("host_name")] = "POST-B"
    store.client.insert(
        "fusion.detections", [post_conflict], column_names=detection_columns
    )
    resurfaced = next(
        item
        for item in store.fetch_candidates(post_scope, compiled, now, None, 100)
        if item.input_id == post_ledger_id
    )
    assert resurfaced.invalid_reason == "conflicting_immutable_values"
    with pytest.raises(CorrelationPersistenceConflict, match="ledger identity"):
        store.mark_evaluated(
            post_scope,
            [
                (
                    resurfaced,
                    EvaluationDecision(
                        "invalid_input",
                        "not_applicable",
                        "conflicting_immutable_values",
                        f"post-conflict-{suffix}",
                    ),
                )
            ],
        )
    assert store.fetch_backlog(post_scope, compiled, now).unevaluated_input_count >= 1

    base = _compiled(compiler, rules_dir)
    canonical_event = Selector(
        "canonical_event",
        "event",
        (
            Predicate("source_type", "eq", "windows_sysmon"),
            Predicate("event_code", "eq", "3"),
            Predicate("host_name", "eq", "host.example"),
        ),
    )
    custom = CompiledRule(
        replace(base.rule, selectors=(*base.rule.selectors, canonical_event)),
        base.scope_fingerprint,
        base.canonical_semantic_plan,
    )
    event_columns = [
        "event_time",
        "ingested_at",
        "event_id",
        "event_type",
        "channel",
        "host_name",
        "platform",
        "source_type",
        "event_category",
        "event_action",
        "event_code",
        "source_event_id",
        "initiated",
        "raw_json",
    ]
    after_floor_event = [
        now,
        now,
        3,
        "network_connection",
        "Microsoft-Windows-Sysmon/Operational",
        "HOST.EXAMPLE.",
        "windows",
        "windows_sysmon",
        "network",
        "connect",
        "3",
        f"source-{suffix}",
        1,
        suffix,
    ]
    stale_event = list(after_floor_event)
    stale_event[event_columns.index("ingested_at")] = now - timedelta(milliseconds=1)
    stale_event[event_columns.index("source_event_id")] = f"stale-source-{suffix}"
    stale_event[event_columns.index("raw_json")] = f"stale-{suffix}"
    stale_event_replay = list(stale_event)
    stale_event_replay[event_columns.index("ingested_at")] = now + timedelta(
        minutes=5
    )
    store.client.insert(
        "fusion.sysmon_events",
        [
            after_floor_event,
            list(after_floor_event),
            stale_event_replay,  # deliberately reordered replay first
            stale_event,
        ],
        column_names=event_columns,
    )
    stale_event_uid = str(
        store.client.query(
            "SELECT any(event_uid) FROM fusion.sysmon_events "
            "WHERE raw_json={raw_json:String}",
            parameters={"raw_json": f"stale-{suffix}"},
        ).result_rows[0][0]
    )
    event_inputs = store.fetch_candidates(
        RuleScope("adapter-live", custom.rule_id, custom.version, suffix + "-event"),
        custom,
        now,
        None,
        100,
    )
    assert any(
        item.input_kind == "event" and item.values["host_name"] == "HOST.EXAMPLE."
        for item in event_inputs
    )
    assert all(item.input_id != stale_event_uid for item in event_inputs)
    event_item = next(item for item in event_inputs if item.input_kind == "event")

    # Force two physical variants under one materialized identity.  The
    # deterministic display winner is deliberately nonmatching; the other
    # complete physical row proves selector enrollment and the logical input
    # must remain visible only as invalid_input material.
    conflict_event_id = f"adapter-conflict-event-{suffix}"
    conflict_columns = [
        "event_uid",
        "event_time",
        "ingested_at",
        "event_id",
        "event_type",
        "channel",
        "host_name",
        "platform",
        "source_type",
        "event_category",
        "event_action",
        "event_code",
        "source_event_id",
        "initiated",
        "raw_json",
    ]
    store.client.insert(
        "fusion.sysmon_events",
        [
            [
                conflict_event_id,
                now,
                now,
                3,
                "network_connection",
                "Microsoft-Windows-Sysmon/Operational",
                "wrong.example",
                "windows",
                "windows_sysmon",
                "network",
                "connect",
                "3",
                f"conflict-{suffix}",
                1,
                f"{suffix}-wrong",
            ],
            [
                conflict_event_id,
                now,
                now + timedelta(milliseconds=1),
                3,
                "network_connection",
                "Microsoft-Windows-Sysmon/Operational",
                "HOST.EXAMPLE.",
                "windows",
                "windows_sysmon",
                "network",
                "connect",
                "3",
                f"conflict-{suffix}",
                1,
                f"{suffix}-matching",
            ],
        ],
        column_names=conflict_columns,
        column_type_names=[
            "String",
            "DateTime64(3, 'UTC')",
            "DateTime64(3, 'UTC')",
            "UInt16",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "UInt8",
            "String",
        ],
        settings={"insert_allow_materialized_columns": 1},
    )

    # A post-floor matching replay must not resurrect an ID whose canonical
    # observation is a pre-floor, nonmatching physical variant.  Conversely,
    # when every observation is post-floor, a nonmatching argMin row plus a
    # matching later variant must remain visible as a conflict, not disappear
    # behind the selective ID seed or become valid context.
    stale_shape_event_id = f"adapter-stale-shape-event-{suffix}"
    shape_conflict_event_id = f"adapter-shape-conflict-event-{suffix}"
    stale_shape_original = [
        stale_shape_event_id,
        now,
        now - timedelta(milliseconds=1),
        3,
        "network_connection",
        "Microsoft-Windows-Sysmon/Operational",
        "HOST.EXAMPLE.",
        "windows",
        "generic_json",
        "network",
        "connect",
        "3",
        f"stale-shape-{suffix}",
        1,
        f"{suffix}-stale-shape-original",
    ]
    stale_shape_replay = list(stale_shape_original)
    stale_shape_replay[conflict_columns.index("ingested_at")] = now + timedelta(
        milliseconds=2
    )
    stale_shape_replay[conflict_columns.index("source_type")] = "windows_sysmon"
    stale_shape_replay[conflict_columns.index("raw_json")] = (
        f"{suffix}-stale-shape-replay"
    )
    shape_conflict_nonmatching = list(stale_shape_original)
    shape_conflict_nonmatching[conflict_columns.index("event_uid")] = (
        shape_conflict_event_id
    )
    shape_conflict_nonmatching[conflict_columns.index("ingested_at")] = now
    shape_conflict_nonmatching[conflict_columns.index("source_event_id")] = (
        f"shape-conflict-{suffix}"
    )
    shape_conflict_nonmatching[conflict_columns.index("raw_json")] = (
        f"{suffix}-shape-conflict-nonmatching"
    )
    shape_conflict_matching = list(shape_conflict_nonmatching)
    shape_conflict_matching[conflict_columns.index("ingested_at")] = now + timedelta(
        milliseconds=1
    )
    shape_conflict_matching[conflict_columns.index("source_type")] = "windows_sysmon"
    shape_conflict_matching[conflict_columns.index("raw_json")] = (
        f"{suffix}-shape-conflict-matching"
    )
    store.client.insert(
        "fusion.sysmon_events",
        [
            stale_shape_replay,
            stale_shape_original,
            shape_conflict_nonmatching,
            shape_conflict_matching,
        ],
        column_names=conflict_columns,
        column_type_names=[
            "String",
            "DateTime64(3, 'UTC')",
            "DateTime64(3, 'UTC')",
            "UInt16",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "UInt8",
            "String",
        ],
        settings={"insert_allow_materialized_columns": 1},
    )
    conflict_scope = RuleScope(
        "adapter-conflict-event", custom.rule_id, custom.version, suffix
    )
    conflict_inputs = store.fetch_candidates(conflict_scope, custom, now, None, 100)
    conflicted = next(
        item for item in conflict_inputs if item.input_id == conflict_event_id
    )
    assert conflicted.invalid_reason == "conflicting_immutable_values"
    assert conflicted.values["host_name"] == "wrong.example"
    shape_conflict = next(
        item for item in conflict_inputs if item.input_id == shape_conflict_event_id
    )
    assert shape_conflict.invalid_reason == "conflicting_immutable_values"
    assert shape_conflict.values["source_type"] == "generic_json"
    assert all(item.input_id != stale_shape_event_id for item in conflict_inputs)

    context = store.fetch_context(custom, event_item, now, 100)
    assert any(item.input_kind == "event" for item in context)
    assert all(item.input_id != stale_event_uid for item in context)
    assert all(item.input_id != conflict_event_id for item in context)
    assert all(item.input_id != stale_shape_event_id for item in context)
    assert all(item.input_id != shape_conflict_event_id for item in context)
    backlog = store.fetch_backlog(
        RuleScope("adapter-live", custom.rule_id, custom.version, suffix + "-event"),
        custom,
        now,
    )
    assert backlog.unevaluated_input_count == len(event_inputs) + 2

    future = now.replace(second=min(57, now.second))
    future = future + timedelta(minutes=2)
    event_rows = []
    for offset, host in ((0, "wrong.example"), (1, "HOST.EXAMPLE.")):
        event_rows.append(
            [
                future + timedelta(milliseconds=offset),
                future + timedelta(milliseconds=offset),
                3,
                "network_connection",
                "Microsoft-Windows-Sysmon/Operational",
                host,
                "windows",
                "windows_sysmon",
                "network",
                "connect",
                "3",
                f"source-page-{offset}-{suffix}",
                1,
                f"{suffix}-{offset}",
            ]
        )
    store.client.insert(
        "fusion.sysmon_events",
        event_rows,
        column_names=[
            "event_time",
            "ingested_at",
            "event_id",
            "event_type",
            "channel",
            "host_name",
            "platform",
            "source_type",
            "event_category",
            "event_action",
            "event_code",
            "source_event_id",
            "initiated",
            "raw_json",
        ],
    )
    page_scope = RuleScope(
        "adapter-page", custom.rule_id, custom.version, suffix + "-page"
    )
    page = store.fetch_candidates(page_scope, custom, future, None, 1)
    assert len(page) == 1
    assert page[0].input_kind == "event"
    assert page[0].values["host_name"] == "HOST.EXAMPLE."
    assert store.fetch_backlog(page_scope, custom, future).unevaluated_input_count >= 1

    high_water_scope = RuleScope(
        "adapter-high-water", custom.rule_id, custom.version, suffix
    )
    high_water_inputs = store.fetch_candidates(high_water_scope, custom, now, None, 100)
    assert high_water_inputs
    store.mark_evaluated(
        high_water_scope,
        [
            (
                item,
                EvaluationDecision(
                    "invalid_input" if item.invalid_reason else "no_match",
                    "not_applicable",
                    item.invalid_reason or "live_high_water_drain",
                    f"high-water-{item.input_kind}-{item.input_id}",
                ),
            )
            for item in high_water_inputs
        ],
    )
    drained = store.fetch_backlog(high_water_scope, custom, now)
    expected_high_water = max(high_water_inputs, key=lambda item: item.order_key)
    assert drained.unevaluated_input_count == 0
    assert drained.oldest_unevaluated_observed_at is None
    assert drained.newest_input_kind == expected_high_water.input_kind
    assert drained.newest_input_id == expected_high_water.input_id
    assert drained.newest_occurred_at == expected_high_water.occurred_at

    invalid_decision = EvaluationDecision(
        "invalid_input",
        "not_applicable",
        "conflicting_immutable_values",
        f"ledger-{suffix}",
    )
    assert store.mark_evaluated(scope, [(duplicate, invalid_decision)]) == 1
    assert store.mark_evaluated(scope, [(duplicate, invalid_decision)]) == 1

    link = replace(
        _link(),
        incident_id=f"incident-{suffix}",
        input_id=duplicate_id,
        link_id=f"link-{suffix}",
        introduction_revision_token=invalid_decision.revision_token,
        correlation_rule_id=compiled.rule_id,
        correlation_scope_fingerprint=scope.fingerprint,
    )
    assert store.write_links([link]) == (1, 0)
    assert store.write_links([link]) == (0, 0)
    store.confirm_decision(
        scope,
        duplicate,
        EvaluationDecision(
            "no_match",
            "not_applicable",
            "test_confirmation",
            link.introduction_revision_token,
            links=(link,),
        ),
    )
    confirmed_members = store.load_incident_members(link.incident_id, 10)
    assert len(confirmed_members) == 1
    assert confirmed_members[0].input_kind == "detection"
    assert confirmed_members[0].input_id == duplicate_id
    assert confirmed_members[0].occurred_at.tzinfo is timezone.utc
    assert confirmed_members[0].values["rule_id"] == link.snapshot["rule_id"]
    store.client.command("SYSTEM START MERGES fusion.detections")
    store.client.command("OPTIMIZE TABLE fusion.detections FINAL")
    store.client.command(
        "OPTIMIZE TABLE fusion.correlation_detection_input_history FINAL"
    )
    store.client.command("OPTIMIZE TABLE fusion.sysmon_events FINAL")

    # Recreate the adapter after source/history merges. The durable projection
    # must keep the old replay outside enrollment and retain conflict evidence.
    restarted = adapter.ClickHouseCorrelationStore(settings)
    merge_scope = RuleScope(
        "adapter-after-merge", compiled.rule_id, compiled.version, suffix
    )
    merged_inputs = restarted.fetch_candidates(
        merge_scope, compiled, now, None, 100
    )
    merged_by_id = {item.input_id: item for item in merged_inputs}
    assert replay_early[0] not in merged_by_id
    assert merged_by_id[after_floor_id].observed_at == after_floor[
        detection_columns.index("detected_at")
    ]
    assert sum(item.input_id == after_floor_id for item in merged_inputs) == 1
    assert merged_by_id[duplicate_id].invalid_reason == "conflicting_immutable_values"
    assert (
        merged_by_id[post_ledger_id].invalid_reason
        == "conflicting_immutable_values"
    )
    merged_event_inputs = restarted.fetch_candidates(
        RuleScope("adapter-event-after-merge", custom.rule_id, custom.version, suffix),
        custom,
        now,
        None,
        100,
    )
    assert all(item.input_id != stale_event_uid for item in merged_event_inputs)
    assert all(item.input_id != stale_shape_event_id for item in merged_event_inputs)
    merged_shape_conflict = next(
        item
        for item in merged_event_inputs
        if item.input_id == shape_conflict_event_id
    )
    assert merged_shape_conflict.invalid_reason == "conflicting_immutable_values"


@pytest.mark.skipif(
    os.getenv("FUSION_TEST_CLICKHOUSE") != "1",
    reason="requires an isolated migrated ClickHouse test container",
)
@pytest.mark.parametrize(
    ("async_insert", "wait_for_async_insert"),
    ((0, 1), (1, 1), (1, 0)),
    ids=("sync", "async-wait", "async-detached-client"),
)
def test_live_inflight_projection_publication_is_fail_closed_without_false_sticky(
    compiler, rules_dir, request, async_insert, wait_for_async_insert
):
    suffix = uuid4().hex
    prefix = (
        f"inflight-publication-{async_insert}-{wait_for_async_insert}-{suffix}-"
    )
    delayed_view = f"correlation_detection_input_mid_delay_{suffix}"
    delayed_target = f"correlation_detection_input_mid_delay_target_{suffix}"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    floor = now - timedelta(minutes=1)
    settings = SimpleNamespace(
        clickhouse_host=os.getenv("FUSION_TEST_CLICKHOUSE_HOST", "127.0.0.1"),
        clickhouse_port=int(os.getenv("FUSION_TEST_CLICKHOUSE_PORT", "8123")),
        clickhouse_database="fusion",
        clickhouse_user=os.getenv("FUSION_TEST_CLICKHOUSE_USER", "fusion"),
        clickhouse_password=os.getenv(
            "FUSION_TEST_CLICKHOUSE_PASSWORD", "adapter-test-only"
        ),
        context_limit=10_000,
        engine_id=f"inflight-publication-engine-{suffix}",
    )
    store = adapter.ClickHouseCorrelationStore(settings)
    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    scope = RuleScope(
        settings.engine_id, compiled.rule_id, compiled.version, "d" * 64
    )
    writer = adapter.clickhouse_connect.get_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        username=settings.clickhouse_user,
        password=settings.clickhouse_password,
        database=settings.clickhouse_database,
        settings={
            "async_insert": async_insert,
            "wait_for_async_insert": wait_for_async_insert,
            "async_insert_busy_timeout_ms": 50,
            "parallel_view_processing": 0,
        },
    )
    store.client.command(
        f"CREATE TABLE fusion.{delayed_target} (detection_id String) "
        "ENGINE=MergeTree ORDER BY detection_id"
    )
    store.client.command(
        f"CREATE MATERIALIZED VIEW fusion.{delayed_view} "
        f"TO fusion.{delayed_target} AS SELECT detection_id "
        "FROM fusion.detections WHERE sleepEachRow(0.003)=0"
    )
    writer_errors = []
    worker = None

    def cleanup():
        if worker is not None:
            worker.join(timeout=10)
        store.client.command(f"DROP TABLE IF EXISTS fusion.{delayed_view}")
        store.client.command(f"DROP TABLE IF EXISTS fusion.{delayed_target}")
        for table in (
            adapter.WITNESS_TABLE_QUALIFIED_NAME,
            adapter.HISTORY_TABLE_QUALIFIED_NAME,
            "fusion.detections",
        ):
            store.client.command(
                f"ALTER TABLE {table} DELETE WHERE "
                "startsWith(detection_id, {prefix:String}) SETTINGS mutations_sync=2",
                parameters={"prefix": prefix},
            )
        writer.close()

    request.addfinalizer(cleanup)

    columns = [
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
        "source_event_time",
    ]
    rows = [
        [
            f"{prefix}{index:04d}",
            now,
            now,
            "sigma-test",
            "In-flight publication test",
            "1",
            "high",
            "windows",
            "Microsoft",
            "Sysmon",
            "windows_sysmon",
            now,
        ]
        for index in range(400)
    ]

    def write_rows():
        try:
            writer.insert("fusion.detections", rows, column_names=columns)
        except Exception as exc:  # pragma: no cover - asserted by parent thread
            writer_errors.append(exc)

    worker = Thread(target=write_rows, daemon=True)
    worker.start()
    deadline = monotonic() + 8
    observed_partial_publication = False
    observed_states = []
    while monotonic() < deadline:
        if writer_errors:
            break
        source_count, history_count, witness_count = store.client.query(
            "SELECT "
            "(SELECT count() FROM fusion.detections WHERE "
            "startsWith(detection_id, {prefix:String})), "
            f"(SELECT count() FROM {adapter.HISTORY_TABLE_QUALIFIED_NAME} WHERE "
            "startsWith(detection_id, {prefix:String})), "
            f"(SELECT count() FROM {adapter.WITNESS_TABLE_QUALIFIED_NAME} WHERE "
            "startsWith(detection_id, {prefix:String}))",
            parameters={"prefix": prefix},
        ).result_rows[0]
        state = (int(source_count), int(history_count), int(witness_count))
        if not observed_states or observed_states[-1] != state:
            observed_states.append(state)
        if state[0] == 400 and (state[1] != 400 or state[2] != 400):
            observed_partial_publication = True
            break
        sleep(0.01)
    assert writer_errors == []
    assert observed_partial_publication, observed_states
    assert store._detections_insert_in_progress()

    in_flight = store.check_scope_integrity(
        scope,
        compiled,
        floor,
        ruleset_fingerprint="e" * 64,
        checked_at=now,
    )
    assert in_flight.blocked
    assert in_flight.violation_count == 0
    assert in_flight.violation_types == (
        adapter._PROJECTION_PUBLICATION_UNCONFIRMED,
    )
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert writer_errors == []

    deadline = monotonic() + 12
    while monotonic() < deadline:
        source_count, history_count, witness_count = store.client.query(
            "SELECT "
            "(SELECT count() FROM fusion.detections WHERE "
            "startsWith(detection_id, {prefix:String})), "
            f"(SELECT count() FROM {adapter.HISTORY_TABLE_QUALIFIED_NAME} WHERE "
            "startsWith(detection_id, {prefix:String})), "
            f"(SELECT count() FROM {adapter.WITNESS_TABLE_QUALIFIED_NAME} WHERE "
            "startsWith(detection_id, {prefix:String}))",
            parameters={"prefix": prefix},
        ).result_rows[0]
        if (int(source_count), int(history_count), int(witness_count)) == (
            400,
            400,
            400,
        ):
            break
        sleep(0.02)
    assert (int(source_count), int(history_count), int(witness_count)) == (
        400,
        400,
        400,
    )

    recovered = store.check_scope_integrity(
        scope,
        compiled,
        floor,
        ruleset_fingerprint="e" * 64,
        checked_at=now + timedelta(seconds=2),
    )
    assert not recovered.blocked
    persisted = store.client.query(
        "SELECT uniqExact(integrity_event_id) "
        "FROM fusion.correlation_integrity_events "
        "WHERE engine_id={engine_id:String} "
        "AND correlation_rule_id={rule_id:String} "
        "AND correlation_rule_version={rule_version:UInt32} "
        "AND correlation_scope_fingerprint={fingerprint:String}",
        parameters={
            "engine_id": scope.engine_id,
            "rule_id": scope.rule_id,
            "rule_version": scope.rule_version,
            "fingerprint": scope.fingerprint,
        },
    )
    assert int(persisted.result_rows[0][0]) == 0


@pytest.mark.skipif(
    os.getenv("FUSION_TEST_CLICKHOUSE") != "1",
    reason="requires an isolated migrated ClickHouse test container",
)
def test_live_projection_faults_block_persist_and_do_not_auto_clear(
    compiler, rules_dir, request, monkeypatch
):
    settings = SimpleNamespace(
        clickhouse_host=os.getenv("FUSION_TEST_CLICKHOUSE_HOST", "127.0.0.1"),
        clickhouse_port=int(os.getenv("FUSION_TEST_CLICKHOUSE_PORT", "8123")),
        clickhouse_database="fusion",
        clickhouse_user=os.getenv("FUSION_TEST_CLICKHOUSE_USER", "fusion"),
        clickhouse_password=os.getenv(
            "FUSION_TEST_CLICKHOUSE_PASSWORD", "adapter-test-only"
        ),
        context_limit=10_000,
        engine_id=f"adapter-integrity-live-{uuid4().hex}",
    )
    store = adapter.ClickHouseCorrelationStore(settings)
    store.healthcheck()
    status_settings = SimpleNamespace(
        **{
            **vars(settings),
            "engine_id": f"adapter-status-live-{uuid4().hex}",
        }
    )
    status_store = adapter.ClickHouseCorrelationStore(status_settings)
    compiled = _compiled(compiler, rules_dir, "host-suspicious-activity.yml")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    floor = now - timedelta(hours=1)
    original_create = str(
        store.client.query(
            "SELECT create_table_query FROM system.tables WHERE database='fusion' "
            f"AND name='{adapter.HISTORY_PROJECTION_NAME}'"
        ).result_rows[0][0]
    )
    original_witness_create = str(
        store.client.query(
            "SELECT create_table_query FROM system.tables WHERE database='fusion' "
            f"AND name='{adapter.WITNESS_PROJECTION_NAME}'"
        ).result_rows[0][0]
    )

    def scope(label: str) -> RuleScope:
        return RuleScope(
            settings.engine_id,
            compiled.rule_id,
            compiled.version,
            sha256(label.encode("utf-8")).hexdigest(),
        )

    def restore_projection() -> None:
        attached = int(
            store.client.query(
                "SELECT count() FROM system.tables WHERE database='fusion' "
                f"AND name='{adapter.HISTORY_PROJECTION_NAME}'"
            ).result_rows[0][0]
        )
        if not attached:
            try:
                store.client.command(
                    f"ATTACH TABLE fusion.{adapter.HISTORY_PROJECTION_NAME}"
                )
            except Exception:  # noqa: BLE001 - test cleanup must restore any state
                store.client.command(original_create)
        current = str(
            store.client.query(
                "SELECT as_select FROM system.tables WHERE database='fusion' "
                f"AND name='{adapter.HISTORY_PROJECTION_NAME}'"
            ).result_rows[0][0]
        )
        if adapter._normalize_projection_sql(current) != adapter._normalize_projection_sql(
            adapter.EXPECTED_HISTORY_PROJECTION_SELECT
        ):
            store.client.command(
                f"DROP TABLE fusion.{adapter.HISTORY_PROJECTION_NAME}"
            )
            store.client.command(original_create)

    def restore_witness_projection() -> None:
        attached = int(
            store.client.query(
                "SELECT count() FROM system.tables WHERE database='fusion' "
                f"AND name='{adapter.WITNESS_PROJECTION_NAME}'"
            ).result_rows[0][0]
        )
        if not attached:
            try:
                store.client.command(
                    f"ATTACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
                )
            except Exception:  # noqa: BLE001 - test cleanup must restore any state
                store.client.command(original_witness_create)
        current = str(
            store.client.query(
                "SELECT as_select FROM system.tables WHERE database='fusion' "
                f"AND name='{adapter.WITNESS_PROJECTION_NAME}'"
            ).result_rows[0][0]
        )
        if adapter._normalize_projection_sql(current) != adapter._normalize_projection_sql(
            adapter.EXPECTED_WITNESS_PROJECTION_SELECT
        ):
            store.client.command(
                f"DROP TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
            )
            store.client.command(original_witness_create)

    request.addfinalizer(restore_projection)
    request.addfinalizer(restore_witness_projection)

    retro_scope = scope("retroactive-canonical-time")
    retro_id = f"retroactive-observation-{uuid4().hex}"
    detection_columns = [
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
        "source_event_time",
    ]
    retro_row = [
        retro_id,
        now,
        now,
        "sigma-test",
        "Retroactive observation test",
        "1",
        "high",
        "windows",
        "Microsoft",
        "Sysmon",
        "windows_sysmon",
        now,
    ]
    store.client.insert(
        "fusion.detections", [retro_row], column_names=detection_columns
    )
    retro_candidate = next(
        item
        for item in store.fetch_candidates(
            retro_scope, compiled, floor, None, 10_000
        )
        if item.input_id == retro_id
    )
    assert store.mark_evaluated(
        retro_scope,
        [
            (
                retro_candidate,
                EvaluationDecision(
                    "no_match",
                    "not_applicable",
                    "integrity_test",
                    f"retro-{retro_id}",
                ),
            )
        ],
    ) == 1
    assert not store.check_scope_integrity(
        retro_scope,
        compiled,
        floor,
        ruleset_fingerprint="9" * 64,
        checked_at=now,
    ).blocked
    retro_replay = list(retro_row)
    retro_replay[detection_columns.index("detected_at")] = now - timedelta(
        minutes=5
    )
    retro_replay[detection_columns.index("updated_at")] = now + timedelta(
        seconds=1
    )
    store.client.insert(
        "fusion.detections", [retro_replay], column_names=detection_columns
    )
    retro_block = store.check_scope_integrity(
        retro_scope,
        compiled,
        floor,
        ruleset_fingerprint="9" * 64,
        checked_at=now + timedelta(seconds=2),
    )
    assert retro_block.blocked
    assert retro_block.violation_types == ("canonical_observation_mismatch",)
    assert adapter.ClickHouseCorrelationStore(settings).check_scope_integrity(
        retro_scope,
        compiled,
        floor,
        ruleset_fingerprint="8" * 64,
        checked_at=now + timedelta(seconds=3),
    ).blocked

    # The optimized event-integrity query must remain correctness-equivalent:
    # it may narrow the source scan to exact ledger IDs, but it must still
    # discover a later-visible physical observation that moves an evaluated
    # event's canonical MIN(ingested_at) backwards.  The persisted block must
    # also survive adapter recreation.
    base = _compiled(compiler, rules_dir)
    event_selector = Selector(
        "retroactive_event",
        "event",
        (
            Predicate("source_type", "eq", "windows_sysmon"),
            Predicate("event_code", "eq", "3"),
        ),
    )
    event_compiled = CompiledRule(
        replace(base.rule, selectors=(*base.rule.selectors, event_selector)),
        base.scope_fingerprint,
        base.canonical_semantic_plan,
    )
    event_scope = RuleScope(
        settings.engine_id,
        event_compiled.rule_id,
        event_compiled.version,
        sha256(f"retroactive-event-{uuid4().hex}".encode("utf-8")).hexdigest(),
    )
    retro_event_id = f"retroactive-event-observation-{uuid4().hex}"
    event_columns = [
        "event_uid",
        "event_time",
        "ingested_at",
        "event_id",
        "event_type",
        "channel",
        "host_name",
        "platform",
        "source_type",
        "event_category",
        "event_action",
        "event_code",
        "source_event_id",
        "initiated",
        "raw_json",
    ]
    event_row = [
        retro_event_id,
        now,
        now,
        3,
        "network_connection",
        "Microsoft-Windows-Sysmon/Operational",
        "retro-event.example",
        "windows",
        "windows_sysmon",
        "network",
        "connect",
        "3",
        f"retro-event-source-{uuid4().hex}",
        1,
        "event-integrity-test",
    ]
    store.client.insert(
        "fusion.sysmon_events",
        [event_row],
        column_names=event_columns,
        column_type_names=[
            "String",
            "DateTime64(3, 'UTC')",
            "DateTime64(3, 'UTC')",
            "UInt16",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "UInt8",
            "String",
        ],
        settings={"insert_allow_materialized_columns": 1},
    )
    retro_event_candidate = next(
        item
        for item in store.fetch_candidates(
            event_scope, event_compiled, floor, None, 10_000
        )
        if item.input_kind == "event" and item.input_id == retro_event_id
    )
    assert store.mark_evaluated(
        event_scope,
        [
            (
                retro_event_candidate,
                EvaluationDecision(
                    "no_match",
                    "not_applicable",
                    "event_integrity_test",
                    f"retro-event-{retro_event_id}",
                ),
            )
        ],
    ) == 1
    assert not store.check_scope_integrity(
        event_scope,
        event_compiled,
        floor,
        ruleset_fingerprint="7" * 64,
        checked_at=now,
    ).blocked
    earlier_event_row = list(event_row)
    earlier_event_row[event_columns.index("ingested_at")] = now - timedelta(
        minutes=5
    )
    store.client.insert(
        "fusion.sysmon_events",
        [earlier_event_row],
        column_names=event_columns,
        column_type_names=[
            "String",
            "DateTime64(3, 'UTC')",
            "DateTime64(3, 'UTC')",
            "UInt16",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "String",
            "UInt8",
            "String",
        ],
        settings={"insert_allow_materialized_columns": 1},
    )
    event_retro_block = store.check_scope_integrity(
        event_scope,
        event_compiled,
        floor,
        ruleset_fingerprint="7" * 64,
        checked_at=now + timedelta(seconds=1),
    )
    assert event_retro_block.blocked
    assert event_retro_block.violation_types == (
        "canonical_observation_mismatch",
    )
    assert adapter.ClickHouseCorrelationStore(settings).check_scope_integrity(
        event_scope,
        event_compiled,
        floor,
        ruleset_fingerprint="6" * 64,
        checked_at=now + timedelta(seconds=2),
    ).blocked

    detached_scope = scope("detached")
    store.client.command(f"DETACH TABLE fusion.{adapter.HISTORY_PROJECTION_NAME}")
    detached_status = status_store.status()
    assert detached_status["correlation_status"] == "blocked_integrity"
    assert detached_status["integrity_violation_count"] == 0
    assert detached_status["live_projection_violation_types"] == [
        "projection_unavailable"
    ]
    detached = store.check_scope_integrity(
        detached_scope,
        compiled,
        floor,
        ruleset_fingerprint="a" * 64,
        checked_at=now,
    )
    assert detached.blocked
    assert detached.violation_types == ("projection_unavailable",)
    store.client.command(f"ATTACH TABLE fusion.{adapter.HISTORY_PROJECTION_NAME}")
    assert store.check_scope_integrity(
        detached_scope,
        compiled,
        floor,
        ruleset_fingerprint="b" * 64,
        checked_at=now + timedelta(seconds=1),
    ).blocked

    store.client.command(f"DROP TABLE fusion.{adapter.HISTORY_PROJECTION_NAME}")
    store.client.command(
        "CREATE MATERIALIZED VIEW fusion."
        + adapter.HISTORY_PROJECTION_NAME
        + " TO "
        + adapter.HISTORY_TABLE_QUALIFIED_NAME
        + " AS "
        + adapter.EXPECTED_HISTORY_PROJECTION_SELECT
        + " WHERE 0"
    )
    filtered_status = status_store.status()
    assert filtered_status["correlation_status"] == "blocked_integrity"
    assert filtered_status["integrity_violation_count"] == 0
    assert filtered_status["live_projection_violation_types"] == [
        "projection_contract_mismatch"
    ]
    filtered_scope = scope("where-zero")
    filtered = store.check_scope_integrity(
        filtered_scope,
        compiled,
        floor,
        ruleset_fingerprint="c" * 64,
        checked_at=now + timedelta(seconds=2),
    )
    assert filtered.blocked
    assert filtered.violation_types == ("projection_contract_mismatch",)
    restore_projection()
    assert store.check_scope_integrity(
        filtered_scope,
        compiled,
        floor,
        ruleset_fingerprint="d" * 64,
        checked_at=now + timedelta(seconds=3),
    ).blocked

    witness_detached_scope = scope("witness-detached")
    store.client.command(
        f"DETACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    witness_detached = store.check_scope_integrity(
        witness_detached_scope,
        compiled,
        floor,
        ruleset_fingerprint="2" * 64,
        checked_at=now + timedelta(seconds=3),
    )
    assert witness_detached.blocked
    assert witness_detached.violation_types == ("projection_unavailable",)
    store.client.command(
        f"ATTACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    assert store.check_scope_integrity(
        witness_detached_scope,
        compiled,
        floor,
        ruleset_fingerprint="3" * 64,
        checked_at=now + timedelta(seconds=4),
    ).blocked

    store.client.command(
        f"DROP TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    store.client.command(
        "CREATE MATERIALIZED VIEW fusion."
        + adapter.WITNESS_PROJECTION_NAME
        + " TO "
        + adapter.WITNESS_TABLE_QUALIFIED_NAME
        + " AS "
        + adapter.EXPECTED_WITNESS_PROJECTION_SELECT
        + " WHERE 0"
    )
    witness_filtered_scope = scope("witness-where-zero")
    witness_filtered = store.check_scope_integrity(
        witness_filtered_scope,
        compiled,
        floor,
        ruleset_fingerprint="4" * 64,
        checked_at=now + timedelta(seconds=4),
    )
    assert witness_filtered.blocked
    assert witness_filtered.violation_types == (
        "projection_contract_mismatch",
    )
    restore_witness_projection()
    assert store.check_scope_integrity(
        witness_filtered_scope,
        compiled,
        floor,
        ruleset_fingerprint="5" * 64,
        checked_at=now + timedelta(seconds=5),
    ).blocked

    # A short detach/restore can miss a physical insert even though the restored
    # definition is exact. Coverage proof blocks that scope until investigation;
    # explicit test repair permits unrelated new scopes but never clears the old.
    store.client.command(f"DETACH TABLE fusion.{adapter.HISTORY_PROJECTION_NAME}")
    detection_id = f"projection-gap-{uuid4().hex}"
    detection_row = [
        detection_id,
        floor - timedelta(minutes=1),
        floor - timedelta(minutes=1),
        "sigma-test",
        "Projection coverage test",
        "1",
        "high",
        "windows",
        "Microsoft",
        "Sysmon",
        "windows_sysmon",
        now,
    ]
    store.client.insert(
        "fusion.detections", [detection_row], column_names=detection_columns
    )
    # The source is replaceable. The independent witness must retain this old
    # observation even after normal source merges erase it later.
    store.client.command("OPTIMIZE TABLE fusion.detections FINAL")
    store.client.command(f"ATTACH TABLE fusion.{adapter.HISTORY_PROJECTION_NAME}")
    post_floor_replay = list(detection_row)
    post_floor_replay[detection_columns.index("detected_at")] = now
    post_floor_replay[detection_columns.index("updated_at")] = now
    store.client.insert(
        "fusion.detections", [post_floor_replay], column_names=detection_columns
    )
    store.client.command("OPTIMIZE TABLE fusion.detections FINAL")
    store.client.command(
        f"OPTIMIZE TABLE {adapter.WITNESS_TABLE_QUALIFIED_NAME} FINAL"
    )
    gap_status = status_store.status()
    assert gap_status["correlation_status"] == "blocked_integrity"
    assert gap_status["integrity_violation_count"] == 0
    assert gap_status["live_projection_violation_types"] == [
        "projection_coverage_gap"
    ]
    gap_scope = scope("coverage-gap")
    gap = store.check_scope_integrity(
        gap_scope,
        compiled,
        floor,
        ruleset_fingerprint="e" * 64,
        checked_at=now + timedelta(seconds=6),
    )
    assert gap.blocked
    assert gap.violation_types == ("projection_coverage_gap",)

    history_columns = [
        "detection_id",
        "detected_at",
        "source_event_time",
        "rule_id",
        "rule_version",
        "rule_name",
        "severity",
        "platform",
        "vendor",
        "product",
        "source_type",
    ]
    history_row = [
        detection_row[detection_columns.index(column)] for column in history_columns
    ]
    store.client.insert(
        adapter.HISTORY_TABLE_QUALIFIED_NAME,
        [history_row],
        column_names=history_columns,
    )
    healthy_scope = scope("healthy-after-repair")
    assert not store.check_scope_integrity(
        healthy_scope,
        compiled,
        floor,
        ruleset_fingerprint="f" * 64,
        checked_at=now + timedelta(seconds=7),
    ).blocked
    restarted = adapter.ClickHouseCorrelationStore(settings)
    assert restarted.check_scope_integrity(
        gap_scope,
        compiled,
        floor,
        ruleset_fingerprint="1" * 64,
        checked_at=now + timedelta(seconds=8),
    ).blocked

    # Reverse direction: a temporary witness outage must remain provable from
    # primary history after the replaceable source drops the missed variant.
    store.client.command(
        f"DETACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    reverse_id = f"witness-gap-{uuid4().hex}"
    reverse_early = list(retro_row)
    reverse_early[detection_columns.index("detection_id")] = reverse_id
    reverse_early[detection_columns.index("detected_at")] = floor - timedelta(
        minutes=2
    )
    reverse_early[detection_columns.index("updated_at")] = floor - timedelta(
        minutes=2
    )
    store.client.insert(
        "fusion.detections", [reverse_early], column_names=detection_columns
    )
    store.client.command(
        f"ATTACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    reverse_replay = list(reverse_early)
    reverse_replay[detection_columns.index("detected_at")] = now + timedelta(
        seconds=10
    )
    reverse_replay[detection_columns.index("updated_at")] = now + timedelta(
        seconds=10
    )
    store.client.insert(
        "fusion.detections", [reverse_replay], column_names=detection_columns
    )
    store.client.command("OPTIMIZE TABLE fusion.detections FINAL")
    reverse_scope = scope("reverse-witness-coverage-gap")
    reverse_gap = store.check_scope_integrity(
        reverse_scope,
        compiled,
        floor,
        ruleset_fingerprint="2" * 64,
        checked_at=now + timedelta(seconds=10),
    )
    assert reverse_gap.blocked
    assert reverse_gap.violation_types == ("projection_coverage_gap",)
    assert adapter.ClickHouseCorrelationStore(settings).check_scope_integrity(
        reverse_scope,
        compiled,
        floor,
        ruleset_fingerprint="3" * 64,
        checked_at=now + timedelta(seconds=11),
    ).blocked
    store.client.command(
        f"INSERT INTO {adapter.WITNESS_TABLE_QUALIFIED_NAME} "
        "SELECT detection_id, detected_at, semantic_fingerprint "
        f"FROM {adapter.HISTORY_TABLE_QUALIFIED_NAME} "
        "WHERE detection_id={input_id:String}",
        parameters={"input_id": reverse_id},
    )

    # Legacy v0.5.2 rows may have an empty detection ID. They remain invalid
    # correlation inputs, but observation loss must still be diagnosable and
    # durable instead of failing the migration or the integrity-event insert.
    store.client.command(
        f"DETACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    blank_row = list(retro_row)
    blank_row[detection_columns.index("detection_id")] = ""
    blank_row[detection_columns.index("detected_at")] = now + timedelta(seconds=12)
    blank_row[detection_columns.index("updated_at")] = now + timedelta(seconds=12)
    store.client.insert(
        "fusion.detections", [blank_row], column_names=detection_columns
    )
    store.client.command(
        f"ATTACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    blank_scope = scope("blank-detection-id-coverage-gap")
    blank_gap = store.check_scope_integrity(
        blank_scope,
        compiled,
        floor,
        ruleset_fingerprint="4" * 64,
        checked_at=now + timedelta(seconds=12),
    )
    assert blank_gap.blocked
    assert blank_gap.violation_types == ("projection_coverage_gap",)
    blank_diagnostic = store.client.query(
        "SELECT input_id, JSONExtractString(diagnostic_json, 'input_id_state') "
        "FROM fusion.correlation_integrity_events "
        "WHERE engine_id={engine_id:String} "
        "AND correlation_rule_id={rule_id:String} "
        "AND correlation_rule_version={rule_version:UInt32} "
        "AND correlation_scope_fingerprint={fingerprint:String} "
        "AND violation_type='projection_coverage_gap' LIMIT 1",
        parameters={
            "engine_id": blank_scope.engine_id,
            "rule_id": blank_scope.rule_id,
            "rule_version": blank_scope.rule_version,
            "fingerprint": blank_scope.fingerprint,
        },
    ).result_rows[0]
    assert tuple(str(value) for value in blank_diagnostic) == ("", "empty")
    store.client.command(
        f"OPTIMIZE TABLE {adapter.INTEGRITY_TABLE_QUALIFIED_NAME} FINAL"
    )
    store.client.command(
        f"OPTIMIZE TABLE {adapter.HISTORY_TABLE_QUALIFIED_NAME} FINAL"
    )
    store.client.command(
        f"OPTIMIZE TABLE {adapter.WITNESS_TABLE_QUALIFIED_NAME} FINAL"
    )
    assert adapter.ClickHouseCorrelationStore(settings).check_scope_integrity(
        blank_scope,
        compiled,
        floor,
        ruleset_fingerprint="5" * 64,
        checked_at=now + timedelta(seconds=13),
    ).blocked
    blank_incident_values = {
        column: (None if column in adapter.INCIDENT_DATETIME_FIELDS else "")
        for column in adapter.INCIDENT_COLUMNS
    }
    blank_incident_values.update(
        incident_id=f"blank-guard-{uuid4().hex}",
        correlation_rule_id=blank_scope.rule_id,
        correlation_rule_version=blank_scope.rule_version,
        correlation_scope_fingerprint=blank_scope.fingerprint,
        revision=1,
        state_hash="test-only",
    )
    with pytest.raises(CorrelationPersistenceConflict, match="lifecycle mutation"):
        store._assert_incident_scope_mutable(
            adapter.IncidentRecord(blank_incident_values)
        )
    store.client.command(
        f"INSERT INTO {adapter.WITNESS_TABLE_QUALIFIED_NAME} "
        "SELECT detection_id, detected_at, semantic_fingerprint "
        f"FROM {adapter.HISTORY_TABLE_QUALIFIED_NAME} "
        "WHERE detection_id={input_id:String}",
        parameters={"input_id": ""},
    )

    # Reproduce an in-flight source/MV publication without using semantic-time
    # grace. The first snapshot observes the missed witness row; the activity
    # probe completes the publish but reports that it was in flight. This cycle
    # remains fail-closed without a sticky write, and the next cycle proves
    # parity and returns healthy.
    transient_id = f"transient-publication-{uuid4().hex}"
    transient_row = list(retro_row)
    transient_row[detection_columns.index("detection_id")] = transient_id
    transient_row[detection_columns.index("detected_at")] = now + timedelta(
        seconds=14
    )
    transient_row[detection_columns.index("updated_at")] = now + timedelta(
        seconds=14
    )
    store.client.command(
        f"DETACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    store.client.insert(
        "fusion.detections", [transient_row], column_names=detection_columns
    )
    store.client.command(
        f"ATTACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    transient_scope = scope("transient-cross-table-publication")
    activity_checks = []

    def complete_transient_publication():
        activity_checks.append(True)
        store.client.command(
            f"INSERT INTO {adapter.WITNESS_TABLE_QUALIFIED_NAME} "
            "SELECT detection_id, detected_at, semantic_fingerprint "
            f"FROM {adapter.HISTORY_TABLE_QUALIFIED_NAME} "
            "WHERE detection_id={input_id:String}",
            parameters={"input_id": transient_id},
        )
        return True

    with monkeypatch.context() as patch_context:
        patch_context.setattr(
            store,
            "_detections_insert_in_progress",
            complete_transient_publication,
        )
        transient_status = store.check_scope_integrity(
            transient_scope,
            compiled,
            floor,
            ruleset_fingerprint="6" * 64,
            checked_at=now + timedelta(seconds=14),
        )
    assert transient_status.blocked
    assert transient_status.violation_count == 0
    assert transient_status.violation_types == (
        adapter._PROJECTION_PUBLICATION_UNCONFIRMED,
    )
    assert activity_checks == [True]
    transient_integrity_count = store.client.query(
        "SELECT uniqExact(integrity_event_id) "
        "FROM fusion.correlation_integrity_events "
        "WHERE engine_id={engine_id:String} "
        "AND correlation_rule_id={rule_id:String} "
        "AND correlation_rule_version={rule_version:UInt32} "
        "AND correlation_scope_fingerprint={fingerprint:String}",
        parameters={
            "engine_id": transient_scope.engine_id,
            "rule_id": transient_scope.rule_id,
            "rule_version": transient_scope.rule_version,
            "fingerprint": transient_scope.fingerprint,
        },
    ).result_rows[0][0]
    assert int(transient_integrity_count) == 0
    assert not store.check_scope_integrity(
        transient_scope,
        compiled,
        floor,
        ruleset_fingerprint="6" * 64,
        checked_at=now + timedelta(seconds=15),
    ).blocked

    # A normal acknowledged insert synchronously reaches both exact MVs and
    # must not false-block even when checked immediately.
    healthy_now_id = f"projection-healthy-now-{uuid4().hex}"
    healthy_now_row = list(retro_row)
    healthy_now_row[detection_columns.index("detection_id")] = healthy_now_id
    healthy_now_row[detection_columns.index("detected_at")] = now + timedelta(
        seconds=20
    )
    healthy_now_row[detection_columns.index("updated_at")] = now + timedelta(
        seconds=20
    )
    store.client.insert(
        "fusion.detections", [healthy_now_row], column_names=detection_columns
    )
    healthy_now_scope = scope("healthy-immediate-insert")
    assert not store.check_scope_integrity(
        healthy_now_scope,
        compiled,
        floor,
        ruleset_fingerprint="6" * 64,
        checked_at=now + timedelta(seconds=20),
    ).blocked

    # No semantic-time grace is allowed: a fresh or future-skewed row missing
    # from either observation projection blocks before correlation can mutate.
    store.client.command(
        f"DETACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    skewed_id = f"projection-future-gap-{uuid4().hex}"
    skewed_row = list(retro_row)
    skewed_row[detection_columns.index("detection_id")] = skewed_id
    skewed_row[detection_columns.index("detected_at")] = now + timedelta(hours=1)
    skewed_row[detection_columns.index("updated_at")] = now + timedelta(hours=1)
    store.client.insert(
        "fusion.detections", [skewed_row], column_names=detection_columns
    )
    store.client.command(
        f"ATTACH TABLE fusion.{adapter.WITNESS_PROJECTION_NAME}"
    )
    skewed_scope = scope("future-skewed-gap")
    skewed = store.check_scope_integrity(
        skewed_scope,
        compiled,
        floor,
        ruleset_fingerprint="7" * 64,
        checked_at=now + timedelta(seconds=20),
    )
    assert skewed.blocked
    assert skewed.violation_types == ("projection_coverage_gap",)
    store.client.command(
        f"INSERT INTO {adapter.WITNESS_TABLE_QUALIFIED_NAME} "
        "SELECT detection_id, detected_at, semantic_fingerprint "
        f"FROM {adapter.HISTORY_TABLE_QUALIFIED_NAME} "
        "WHERE detection_id={input_id:String}",
        parameters={"input_id": skewed_id},
    )

    with pytest.raises(RuntimeError, match="blocked_integrity"):
        store.healthcheck()
    store.healthcheck(check_projection_integrity=False)


@pytest.mark.skipif(
    os.getenv("FUSION_TEST_CLICKHOUSE") != "1",
    reason="requires an isolated migrated ClickHouse test container",
)
def test_live_structural_health_rejects_ttl_integrity_authority(request):
    settings = SimpleNamespace(
        clickhouse_host=os.getenv("FUSION_TEST_CLICKHOUSE_HOST", "127.0.0.1"),
        clickhouse_port=int(os.getenv("FUSION_TEST_CLICKHOUSE_PORT", "8123")),
        clickhouse_database="fusion",
        clickhouse_user=os.getenv("FUSION_TEST_CLICKHOUSE_USER", "fusion"),
        clickhouse_password=os.getenv(
            "FUSION_TEST_CLICKHOUSE_PASSWORD", "adapter-test-only"
        ),
        context_limit=10_000,
        engine_id=f"adapter-integrity-contract-{uuid4().hex}",
    )
    store = adapter.ClickHouseCorrelationStore(settings)
    store.healthcheck(check_projection_integrity=False)
    saved_name = "correlation_integrity_events_adapter_test_saved"
    original_integrity_create = str(
        store.client.query(
            "SELECT create_table_query FROM system.tables WHERE database='fusion' "
            f"AND name='{adapter.INTEGRITY_TABLE_NAME}'"
        ).result_rows[0][0]
    )
    original_integrity_view_create = str(
        store.client.query(
            "SELECT create_table_query FROM system.tables WHERE database='fusion' "
            f"AND name='{adapter.INTEGRITY_CURRENT_VIEW_NAME}'"
        ).result_rows[0][0]
    )

    def restore_integrity_authority() -> None:
        saved = int(
            store.client.query(
                "SELECT count() FROM system.tables WHERE database='fusion' "
                "AND name={name:String}",
                parameters={"name": saved_name},
            ).result_rows[0][0]
        )
        if saved:
            store.client.command(
                f"DROP TABLE IF EXISTS {adapter.INTEGRITY_TABLE_QUALIFIED_NAME}"
            )
            store.client.command(
                "RENAME TABLE fusion."
                + saved_name
                + " TO "
                + adapter.INTEGRITY_TABLE_QUALIFIED_NAME
            )

    request.addfinalizer(restore_integrity_authority)

    def restore_integrity_view() -> None:
        current = store.client.query(
            "SELECT as_select FROM system.tables WHERE database='fusion' "
            f"AND name='{adapter.INTEGRITY_CURRENT_VIEW_NAME}'"
        )
        if (
            len(current.result_rows) != 1
            or adapter._normalize_projection_sql(str(current.result_rows[0][0]))
            != adapter._normalize_projection_sql(
                adapter.EXPECTED_INTEGRITY_CURRENT_VIEW_SELECT
            )
        ):
            store.client.command(
                f"DROP VIEW IF EXISTS {adapter.INTEGRITY_CURRENT_VIEW_QUALIFIED_NAME}"
            )
            store.client.command(original_integrity_view_create)

    request.addfinalizer(restore_integrity_view)
    store.client.command(
        "RENAME TABLE "
        + adapter.INTEGRITY_TABLE_QUALIFIED_NAME
        + " TO fusion."
        + saved_name
    )
    store.client.command(
        "CREATE TABLE "
        + adapter.INTEGRITY_TABLE_QUALIFIED_NAME
        + " AS fusion."
        + saved_name
        + " ENGINE=MergeTree PARTITION BY toYYYYMM(first_detected_at) "
        + "ORDER BY ("
        + adapter.INTEGRITY_SORT_KEY
        + ") TTL first_detected_at + INTERVAL 1 DAY "
        + "SETTINGS index_granularity=128"
    )

    with pytest.raises(RuntimeError, match="authority contract differs"):
        store.healthcheck(check_projection_integrity=False)

    restore_integrity_authority()
    store.healthcheck(check_projection_integrity=False)

    # Exact constraint bodies are part of the authority contract. A same-name
    # table whose required CHECK merely contains the expected expression and
    # appends ``OR 1`` must fail structural health.
    store.client.command(
        "RENAME TABLE "
        + adapter.INTEGRITY_TABLE_QUALIFIED_NAME
        + " TO fusion."
        + saved_name
    )
    weakened_integrity_create = original_integrity_create.replace(
        "CHECK correlation_rule_version > 0",
        "CHECK (correlation_rule_version > 0) OR 1",
    )
    assert weakened_integrity_create != original_integrity_create
    store.client.command(weakened_integrity_create)
    with pytest.raises(RuntimeError, match="authority contract differs"):
        store.healthcheck(check_projection_integrity=False)
    restore_integrity_authority()
    store.healthcheck(check_projection_integrity=False)

    # The derived operator view is non-authoritative, but structural health
    # must reject a same-column filtered replacement that hides diagnostics.
    store.client.command(
        f"DROP VIEW {adapter.INTEGRITY_CURRENT_VIEW_QUALIFIED_NAME}"
    )
    store.client.command(
        f"CREATE VIEW {adapter.INTEGRITY_CURRENT_VIEW_QUALIFIED_NAME} AS "
        + "SELECT * FROM ("
        + adapter.EXPECTED_INTEGRITY_CURRENT_VIEW_SELECT
        + ") WHERE 0"
    )
    with pytest.raises(RuntimeError, match="integrity-current view contract differs"):
        store.healthcheck(check_projection_integrity=False)
    restore_integrity_view()
    store.healthcheck(check_projection_integrity=False)
