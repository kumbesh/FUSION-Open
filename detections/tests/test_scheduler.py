from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from fusion_detection.main import (
    DRAIN_YIELD_SECONDS,
    MAX_CONSECUTIVE_DRAIN_CYCLES,
    _run_loop,
)
from fusion_detection.models import BacklogStatus, Checkpoint, CycleStats


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def cycle_stats(
    new_events: int, lag_events: int, *, evaluation_failures: int = 0
) -> CycleStats:
    checkpoint = Checkpoint(NOW, "checkpoint")
    newest = NOW + timedelta(seconds=lag_events > 0)
    return CycleStats(
        events_evaluated=new_events,
        new_events_processed=new_events,
        late_events_processed=0,
        matches_found=0,
        detections_inserted=0,
        duplicates_skipped=0,
        evaluation_failures=evaluation_failures,
        processing_duration_seconds=0.25,
        evaluated_events_per_second=float(new_events * 4),
        checkpoint=checkpoint,
        backlog=BacklogStatus(
            newest,
            "newest",
            lag_events,
            float(lag_events > 0),
            lag_events,
            newest if lag_events > 0 else None,
            float(lag_events > 0),
        ),
    )


class SequenceEngine:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def run_cycle(self):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def scheduler_settings(batch_size: int = 1000, poll_seconds: int = 10):
    return SimpleNamespace(batch_size=batch_size, poll_seconds=poll_seconds)


@pytest.mark.parametrize(
    ("new_events", "lag_events"),
    [(0, 0), (999, 0), (1000, 0)],
    ids=["empty", "partial", "full-but-drained"],
)
def test_drained_cycles_sleep_at_the_normal_poll_interval(new_events, lag_events):
    engine = SequenceEngine([cycle_stats(new_events, lag_events)])
    state = {"stopped": False}
    sleeps = []

    def sleeper(seconds, _stopped):
        sleeps.append(seconds)
        state["stopped"] = True

    assert _run_loop(
        scheduler_settings(), engine, False, lambda: state["stopped"], sleeper=sleeper
    ) == 0
    assert engine.calls == 1
    assert sleeps == [10]


def test_multiple_full_batches_drain_without_poll_sleeps_between_them():
    engine = SequenceEngine([
        cycle_stats(1000, 2000),
        cycle_stats(1000, 1000),
        cycle_stats(250, 0),
    ])
    state = {"stopped": False}
    sleeps = []

    def sleeper(seconds, _stopped):
        sleeps.append(seconds)
        state["stopped"] = True

    assert _run_loop(
        scheduler_settings(), engine, False, lambda: state["stopped"], sleeper=sleeper
    ) == 0
    assert engine.calls == 3
    assert sleeps == [10]


def test_full_page_with_one_failure_drains_valid_backlog_without_poll_sleep():
    engine = SequenceEngine([
        cycle_stats(999, 1001, evaluation_failures=1),
        cycle_stats(2, 0, evaluation_failures=1),
    ])
    state = {"stopped": False}
    sleeps = []

    def sleeper(seconds, _stopped):
        sleeps.append(seconds)
        state["stopped"] = True

    assert _run_loop(
        scheduler_settings(), engine, False, lambda: state["stopped"], sleeper=sleeper
    ) == 0
    assert engine.calls == 2
    assert sleeps == [10]


def test_full_page_of_failures_sleeps_instead_of_busy_looping():
    engine = SequenceEngine([
        cycle_stats(0, 1000, evaluation_failures=1000),
    ])
    state = {"stopped": False}
    sleeps = []

    def sleeper(seconds, _stopped):
        sleeps.append(seconds)
        state["stopped"] = True

    assert _run_loop(
        scheduler_settings(), engine, False, lambda: state["stopped"], sleeper=sleeper
    ) == 0
    assert engine.calls == 1
    assert sleeps == [10]


def test_backlog_drain_is_cooperatively_yielded_after_the_fixed_bound(caplog):
    engine = SequenceEngine(
        [cycle_stats(1000, 1) for _ in range(MAX_CONSECUTIVE_DRAIN_CYCLES)]
    )
    state = {"stopped": False}
    sleeps = []

    def sleeper(seconds, _stopped):
        sleeps.append(seconds)
        state["stopped"] = True

    with caplog.at_level(logging.INFO, logger="test.scheduler"):
        assert _run_loop(
            scheduler_settings(),
            engine,
            False,
            lambda: state["stopped"],
            sleeper=sleeper,
            logger=logging.getLogger("test.scheduler"),
        ) == 0

    assert engine.calls == MAX_CONSECUTIVE_DRAIN_CYCLES
    assert sleeps == [DRAIN_YIELD_SECONDS]
    assert "backlog_drain_yield" in caplog.text
    assert f"completed_cycles={MAX_CONSECUTIVE_DRAIN_CYCLES}" in caplog.text


def test_shutdown_is_checked_between_full_backlog_cycles():
    state = {"stopped": False}
    sleeps = []

    class StoppingEngine:
        calls = 0

        def run_cycle(self):
            self.calls += 1
            state["stopped"] = True
            return cycle_stats(1000, 1000)

    engine = StoppingEngine()
    assert _run_loop(
        scheduler_settings(),
        engine,
        False,
        lambda: state["stopped"],
        sleeper=lambda seconds, stopped: sleeps.append(seconds),
    ) == 0
    assert engine.calls == 1
    assert sleeps == []


def test_retry_backoff_resets_after_a_successful_full_cycle():
    engine = SequenceEngine([
        RuntimeError("first transient failure"),
        cycle_stats(1000, 1000),
        RuntimeError("second transient failure"),
        cycle_stats(1, 0),
    ])
    state = {"stopped": False}
    sleeps = []

    def sleeper(seconds, _stopped):
        sleeps.append(seconds)
        if seconds == 10:
            state["stopped"] = True

    assert _run_loop(
        scheduler_settings(),
        engine,
        False,
        lambda: state["stopped"],
        sleeper=sleeper,
        logger=logging.getLogger("test.scheduler.retry"),
    ) == 0
    assert engine.calls == 4
    assert sleeps == [1, 1, 10]


def test_consecutive_failures_use_exponential_backoff_with_a_fixed_cap():
    engine = SequenceEngine(
        [RuntimeError(f"transient failure {index}") for index in range(7)]
        + [cycle_stats(1, 0)]
    )
    state = {"stopped": False}
    sleeps = []

    def sleeper(seconds, _stopped):
        sleeps.append(seconds)
        if seconds == 10:
            state["stopped"] = True

    assert _run_loop(
        scheduler_settings(),
        engine,
        False,
        lambda: state["stopped"],
        sleeper=sleeper,
        logger=logging.getLogger("test.scheduler.backoff-cap"),
    ) == 0
    assert engine.calls == 8
    assert sleeps == [1, 2, 4, 8, 16, 32, 60, 10]


def test_once_runs_exactly_one_full_cycle_without_sleeping():
    engine = SequenceEngine([cycle_stats(1000, 1000), cycle_stats(1000, 0)])
    sleeps = []

    assert _run_loop(
        scheduler_settings(),
        engine,
        True,
        lambda: False,
        sleeper=lambda seconds, stopped: sleeps.append(seconds),
    ) == 0
    assert engine.calls == 1
    assert sleeps == []


def test_once_returns_failure_without_retrying_or_sleeping():
    engine = SequenceEngine([RuntimeError("unavailable")])
    sleeps = []

    assert _run_loop(
        scheduler_settings(),
        engine,
        True,
        lambda: False,
        sleeper=lambda seconds, stopped: sleeps.append(seconds),
        logger=logging.getLogger("test.scheduler.once"),
    ) == 1
    assert engine.calls == 1
    assert sleeps == []
