from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fusion_detection.checkpoint import DetectionEngine
from fusion_detection.models import BacklogStatus, Checkpoint, CycleStats, EvaluationScope


NOW = datetime.now(timezone.utc)


class NoMatchEvaluator:
    def evaluate(self, event):
        return []


class CycleStore:
    def __init__(
        self,
        checkpoint,
        event_batches,
        backlogs,
        evaluation_floor=None,
        legacy_evaluation_floor=None,
    ):
        self.settings = SimpleNamespace(lookback_seconds=120)
        self.checkpoint = checkpoint
        self.event_batches = deque(event_batches)
        self.backlogs = deque(backlogs)
        self.evaluation_floor = evaluation_floor
        self.legacy_evaluation_floor = legacy_evaluation_floor
        self.candidate_cursor = None
        self.saved_stats = []
        self.fetches = 0
        self.initialized_floors = []
        self.marked_uids = []

    def load_checkpoint(self):
        return self.checkpoint

    def load_evaluation_scope(self):
        if self.evaluation_floor is None:
            return None
        return EvaluationScope(self.evaluation_floor, self.candidate_cursor)

    def load_legacy_evaluation_floor(self):
        return self.legacy_evaluation_floor

    def initialize_evaluation_floor(self, checkpoint, evaluation_floor):
        self.initialized_floors.append((checkpoint, evaluation_floor))
        self.evaluation_floor = evaluation_floor

    def fetch_unevaluated_events(self, evaluation_floor, candidate_cursor):
        assert evaluation_floor == self.evaluation_floor
        assert candidate_cursor == self.candidate_cursor
        self.fetches += 1
        return self.event_batches.popleft()

    def save_candidate_cursor(self, evaluation_floor, candidate_cursor):
        assert evaluation_floor == self.evaluation_floor
        self.candidate_cursor = candidate_cursor

    def existing_detection_ids(self, identifiers):
        return set()

    def insert_detections(self, candidates):
        return len(list(candidates))

    def mark_events_evaluated(self, events):
        batch = list(events)
        self.marked_uids.extend(item["event_uid"] for item in batch)
        return len(batch)

    def fetch_backlog_status(self, checkpoint, evaluation_floor):
        assert evaluation_floor == self.evaluation_floor
        return self.backlogs.popleft()

    def save_checkpoint(self, stats):
        self.saved_stats.append(stats)
        self.checkpoint = stats.checkpoint


def event(seconds: int, uid: str):
    return {"event_time": NOW + timedelta(seconds=seconds), "event_uid": uid}


def test_cycle_advances_checkpoint_and_persists_cycle_telemetry(caplog):
    first = event(1, "uid-a")
    last = event(1, "uid-b")
    backlog = BacklogStatus(NOW + timedelta(seconds=4), "uid-z", 7, 3.0)
    store = CycleStore(None, [[first, last]], [backlog])
    engine = DetectionEngine(store, NoMatchEvaluator(), logging.getLogger("test.checkpoint"))

    with caplog.at_level(logging.INFO, logger="test.checkpoint"):
        stats = engine.run_cycle()

    assert isinstance(stats, CycleStats)
    assert stats.checkpoint.event_time == last["event_time"]
    assert stats.checkpoint.event_uid == "uid-b"
    assert stats.events_evaluated == 2
    assert stats.new_events_processed == 2
    assert stats.late_events_processed == 0
    assert stats.backlog == backlog
    assert stats.evaluation_floor_time == store.evaluation_floor
    assert stats.processing_duration_seconds >= 0
    assert stats.evaluated_events_per_second >= 0
    assert store.saved_stats == [stats]
    assert store.marked_uids == ["uid-a", "uid-b"]
    assert len(store.initialized_floors) == 1
    assert "new_events_processed=2" in caplog.text
    assert "checkpoint_uid=uid-b" in caplog.text
    assert "newest_eligible_event_uid=uid-z" in caplog.text
    assert "checkpoint_lag_events=7" in caplog.text
    assert "checkpoint_lag_seconds=3.000" in caplog.text


def test_fixed_lookback_floor_is_reused_on_every_immediate_cycle():
    backlog_after_first = BacklogStatus(
        NOW + timedelta(seconds=2), "uid-b", 1, 1.0, 1
    )
    drained = BacklogStatus(NOW + timedelta(seconds=2), "uid-b", 0, 0.0)
    store = CycleStore(
        None,
        [[event(1, "uid-a")], [event(2, "uid-b")]],
        [backlog_after_first, drained],
    )
    engine = DetectionEngine(store, NoMatchEvaluator(), logging.getLogger("test.lookback"))

    first = engine.run_cycle()
    second = engine.run_cycle()

    assert first.checkpoint.event_uid == "uid-a"
    assert second.checkpoint.event_uid == "uid-b"
    assert store.fetches == 2
    assert len(store.initialized_floors) == 1
    initial_checkpoint, initialized_floor = store.initialized_floors[0]
    assert initialized_floor == initial_checkpoint.event_time - timedelta(seconds=120)
    assert first.evaluation_floor_time == initialized_floor
    assert second.evaluation_floor_time == initialized_floor
    assert [saved.checkpoint.event_uid for saved in store.saved_stats] == ["uid-a", "uid-b"]


def test_empty_cycle_persists_a_reconciled_checkpoint_snapshot():
    checkpoint = event(3, "uid-ledger-head")
    drained = BacklogStatus(checkpoint["event_time"], checkpoint["event_uid"], 0, 0.0)
    store = CycleStore(
        Checkpoint(checkpoint["event_time"], checkpoint["event_uid"]),
        [[]],
        [drained],
        evaluation_floor=NOW - timedelta(seconds=120),
    )

    stats = DetectionEngine(
        store,
        NoMatchEvaluator(),
        logging.getLogger("test.checkpoint-reconciliation"),
    ).run_cycle()

    assert stats.events_evaluated == 0
    assert store.saved_stats == [stats]
    assert stats.checkpoint.event_uid == "uid-ledger-head"


def test_exercised_migration_007_floor_is_promoted_into_scope_state():
    checkpoint = Checkpoint(NOW, "uid-current")
    legacy_floor = NOW - timedelta(seconds=300)
    store = CycleStore(
        checkpoint,
        [[]],
        [BacklogStatus(None, "", 0, 0.0)],
        legacy_evaluation_floor=legacy_floor,
    )

    stats = DetectionEngine(
        store,
        NoMatchEvaluator(),
        logging.getLogger("test.legacy-floor-promotion"),
    ).run_cycle()

    assert stats.evaluation_floor_time == legacy_floor
    assert store.evaluation_floor == legacy_floor
    assert store.initialized_floors == [(checkpoint, legacy_floor)]
