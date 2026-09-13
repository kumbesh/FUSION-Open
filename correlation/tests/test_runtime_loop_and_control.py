from __future__ import annotations

import os
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fusion_correlation.config import Settings
from fusion_correlation.control import (
    LifecycleControlServer,
    _validate_request,
    request_transition,
)
from fusion_correlation.main import _run_loop
from fusion_correlation.runtime_models import (
    CandidateCursor,
    CorrelationBacklog,
    CorrelationCycleStats,
    CorrelationIntegrityStatus,
    IncidentRecord,
    RuleScope,
)


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)
SCOPE = RuleScope("engine", "rule", 1, "f" * 64)


def _settings(
    *, poll_seconds: int = 10, max_drain_cycles: int = 3, yield_ms: int = 100
) -> Settings:
    return Settings(
        clickhouse_host="clickhouse",
        clickhouse_port=8123,
        clickhouse_database="fusion",
        clickhouse_user="fusion",
        clickhouse_password="not-used",
        rules_dir=Path("/rules"),
        mitre_mapping_path=Path("/mappings/mitre.yml"),
        poll_seconds=poll_seconds,
        lookback_seconds=3600,
        batch_size=1000,
        context_limit=10_000,
        max_consecutive_drain_cycles=max_drain_cycles,
        drain_yield_milliseconds=yield_ms,
        engine_id="engine",
        control_socket=Path("/tmp/not-used.sock"),
        log_level="INFO",
    )


def _stats(evaluated: int, backlog: int, *, failed: int = 0) -> CorrelationCycleStats:
    remaining = CorrelationBacklog(
        NOW if backlog else None,
        NOW if backlog else None,
        "detection" if backlog else "",
        "remaining" if backlog else "",
        backlog,
        NOW if backlog else None,
        1.0 if backlog else 0.0,
    )
    cursor = CandidateCursor(NOW, NOW, "detection", "cursor") if evaluated else None
    return CorrelationCycleStats(
        SCOPE,
        evaluated,
        0,
        failed,
        0,
        0,
        0,
        0,
        0.01,
        evaluated / 0.01,
        remaining,
        cursor,
    )


class ScriptedEngine:
    def __init__(self, script, events=None) -> None:
        self.script = list(script)
        self.calls = 0
        self.events = events if events is not None else []

    def run_cycle(self):
        self.calls += 1
        self.events.append(f"run:{self.calls}")
        value = self.script.pop(0)
        if isinstance(value, BaseException):
            raise value
        return (value,)


@pytest.mark.parametrize("evaluated", [0, 417])
def test_empty_or_partial_cycle_uses_normal_poll_sleep(evaluated: int) -> None:
    stopped_flag = False
    sleeps: list[float] = []

    def sleeper(seconds, _stopped):
        nonlocal stopped_flag
        sleeps.append(seconds)
        stopped_flag = True

    engine = ScriptedEngine([_stats(evaluated, 0)])
    result = _run_loop(
        _settings(), engine, False, lambda: stopped_flag, sleeper=sleeper
    )
    assert result == 0
    assert engine.calls == 1
    assert sleeps == [10]


def test_full_page_drains_next_page_without_poll_delay() -> None:
    stopped_flag = False
    sleeps: list[float] = []
    events: list[str] = []

    def sleeper(seconds, _stopped):
        nonlocal stopped_flag
        sleeps.append(seconds)
        events.append(f"sleep:{seconds}")
        stopped_flag = True

    engine = ScriptedEngine([_stats(1000, 1), _stats(1, 0)], events)
    result = _run_loop(
        _settings(), engine, False, lambda: stopped_flag, sleeper=sleeper
    )
    assert result == 0
    assert events == ["run:1", "run:2", "sleep:10"]
    assert sleeps == [10]


def test_backlog_drain_has_bounded_cooperative_yield() -> None:
    stopped_flag = False
    sleeps: list[float] = []

    def sleeper(seconds, _stopped):
        nonlocal stopped_flag
        sleeps.append(seconds)
        stopped_flag = True

    engine = ScriptedEngine([_stats(1000, 5000), _stats(1000, 4000)])
    result = _run_loop(
        _settings(max_drain_cycles=2, yield_ms=125),
        engine,
        False,
        lambda: stopped_flag,
        sleeper=sleeper,
    )
    assert result == 0
    assert engine.calls == 2
    assert sleeps == [0.125]


def test_shutdown_is_observed_between_full_backlog_pages() -> None:
    stopped_flag = False
    sleeps: list[float] = []

    class StopAfterCycle:
        calls = 0

        def run_cycle(self):
            nonlocal stopped_flag
            self.calls += 1
            stopped_flag = True
            return (_stats(1000, 5000),)

    engine = StopAfterCycle()
    result = _run_loop(
        _settings(),
        engine,
        False,
        lambda: stopped_flag,
        sleeper=lambda seconds, _stopped: sleeps.append(seconds),
    )
    assert result == 0
    assert engine.calls == 1
    assert sleeps == []


def test_store_failure_retries_with_bounded_exponential_backoff_then_recovers() -> None:
    stopped_flag = False
    sleeps: list[float] = []

    def sleeper(seconds, _stopped):
        nonlocal stopped_flag
        sleeps.append(seconds)
        if seconds == 10:
            stopped_flag = True

    engine = ScriptedEngine(
        [RuntimeError("clickhouse unavailable"), TimeoutError("retry"), _stats(1, 0)]
    )
    result = _run_loop(
        _settings(), engine, False, lambda: stopped_flag, sleeper=sleeper
    )
    assert result == 0
    assert engine.calls == 3
    assert sleeps == [1, 2, 10]


def test_once_mode_returns_nonzero_on_store_failure_without_sleeping() -> None:
    sleeps: list[float] = []
    engine = ScriptedEngine([RuntimeError("clickhouse unavailable")])
    result = _run_loop(
        _settings(),
        engine,
        True,
        lambda: False,
        sleeper=lambda seconds, _stopped: sleeps.append(seconds),
    )
    assert result == 1
    assert sleeps == []


def test_once_mode_returns_nonzero_for_persistently_blocked_integrity_scope() -> None:
    blocked = _stats(0, 0)
    blocked = CorrelationCycleStats(
        scope=blocked.scope,
        evaluated_inputs=0,
        matched_inputs=0,
        failed_inputs=0,
        incidents_created=0,
        incidents_updated=0,
        detection_links_written=0,
        event_links_written=0,
        processing_duration_seconds=0.01,
        evaluated_inputs_per_second=0.0,
        backlog=None,
        cursor=None,
        integrity=CorrelationIntegrityStatus(
            "blocked_integrity",
            1,
            ("projection_contract_mismatch",),
            NOW,
        ),
    )
    sleeps: list[float] = []
    result = _run_loop(
        _settings(),
        ScriptedEngine([blocked]),
        True,
        lambda: False,
        sleeper=lambda seconds, _stopped: sleeps.append(seconds),
    )
    assert result == 1
    assert sleeps == []


class LifecycleMemoryStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def transition_incident(
        self, incident_id: str, target_status: str, transition_id: str
    ) -> IncidentRecord:
        self.calls.append((incident_id, target_status, transition_id))
        return IncidentRecord(
            {
                "incident_id": incident_id,
                "status": target_status,
                "revision": 2,
                "state_hash": "a" * 64,
            }
        )


def test_lifecycle_control_socket_is_private_bounded_and_serialized(tmp_path: Path) -> None:
    socket_path = tmp_path / "control.sock"
    store = LifecycleMemoryStore()
    server = LifecycleControlServer(socket_path, store, threading.RLock())
    incident_id = "1" * 64
    try:
        server.start()
        assert stat.S_IMODE(os.stat(socket_path).st_mode) == 0o600
        response = request_transition(
            socket_path, incident_id, "acknowledged", "acceptance-transition-1"
        )
    finally:
        server.stop()
    assert response == {
        "ok": True,
        "incident_id": incident_id,
        "revision": 2,
        "status": "acknowledged",
        "transition_id": "acceptance-transition-1",
    }
    assert store.calls == [
        (incident_id, "acknowledged", "acceptance-transition-1")
    ]
    assert not socket_path.exists()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "incident_id": "1" * 64,
            "target_status": "new",
            "transition_id": "x",
        },
        {
            "incident_id": "not-a-hash",
            "target_status": "closed",
            "transition_id": "x",
        },
        {
            "incident_id": "1" * 64,
            "target_status": "closed",
            "transition_id": "contains whitespace",
        },
        {
            "incident_id": "1" * 64,
            "target_status": "closed",
            "transition_id": "x",
            "unexpected": True,
        },
    ],
)
def test_lifecycle_control_request_validation_fails_closed(payload) -> None:
    with pytest.raises(ValueError):
        _validate_request(payload)
