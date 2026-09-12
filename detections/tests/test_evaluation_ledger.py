from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from fusion_detection.checkpoint import DetectionEngine
from fusion_detection.clickhouse import EVENT_COLUMNS, ClickHouseStore
from fusion_detection.config import Settings
from fusion_detection.models import (
    BacklogStatus,
    Checkpoint,
    DetectionCandidate,
    EvaluationScope,
)


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)
ENGINE_ID = "ledger-test-engine"
RULESET = "ruleset-a"


def event(
    uid: str,
    *,
    when: datetime = NOW,
    ingested_at: datetime | None = None,
    physical_copy: int = 0,
) -> dict:
    return {
        "event_uid": uid,
        "event_time": when,
        "ingested_at": ingested_at or when,
        "source_event_id": uid,
        "physical_copy": physical_copy,
    }


class RecordingEvaluator:
    def __init__(self, matching_uids=()):
        self.matching_uids = set(matching_uids)
        self.evaluated_uids: list[str] = []

    def evaluate(self, source_event):
        uid = source_event["event_uid"]
        self.evaluated_uids.append(uid)
        if uid not in self.matching_uids:
            return []
        detection_id = f"detection-{uid}"
        return [
            DetectionCandidate(
                detection_id=detection_id,
                detected_at=NOW,
                values={"detection_id": detection_id},
            )
        ]


@dataclass
class LedgerState:
    events: list[dict]
    checkpoints: dict[str, Checkpoint] = field(default_factory=dict)
    evaluation_floors: dict[tuple[str, str], datetime] = field(default_factory=dict)
    candidate_cursors: dict[tuple[str, str], Checkpoint] = field(default_factory=dict)
    evaluated: set[tuple[str, str, str]] = field(default_factory=set)
    physical_detection_ids: list[str] = field(default_factory=list)


class LedgerStore:
    """Deterministic fake for the intended persistent evaluation-ledger API."""

    def __init__(
        self,
        state: LedgerState,
        *,
        engine_id: str = ENGINE_ID,
        ruleset_fingerprint: str = RULESET,
        batch_size: int = 1000,
        mark_failures: int = 0,
        cursor_failures: int = 0,
    ):
        self.state = state
        self.ruleset_fingerprint = ruleset_fingerprint
        self.settings = SimpleNamespace(
            engine_id=engine_id,
            batch_size=batch_size,
            lookback_seconds=120,
        )
        self.mark_failures = mark_failures
        self.cursor_failures = cursor_failures
        self.fetch_batch_sizes: list[int] = []
        self.marked_batches: list[list[str]] = []
        self.saved_stats = []
        self.calls: list[str] = []

    @property
    def engine_id(self) -> str:
        return self.settings.engine_id

    def _pending(self, evaluation_floor_time: datetime | None = None) -> list[dict]:
        logical_events: dict[str, dict] = {}
        for source_event in self.state.events:
            if evaluation_floor_time is not None and not (
                source_event["event_time"] >= evaluation_floor_time
                or source_event["ingested_at"] >= evaluation_floor_time
            ):
                continue
            uid = source_event["event_uid"]
            if (self.engine_id, self.ruleset_fingerprint, uid) in self.state.evaluated:
                continue
            logical_events.setdefault(uid, source_event)
        return sorted(
            logical_events.values(),
            key=lambda source_event: (
                source_event["event_time"],
                source_event["event_uid"],
            ),
        )

    def load_checkpoint(self):
        checkpoint = self.state.checkpoints.get(self.engine_id)
        evaluated_positions = [
            Checkpoint(source_event["event_time"], source_event["event_uid"])
            for source_event in self.state.events
            if (
                self.engine_id,
                self.ruleset_fingerprint,
                source_event["event_uid"],
            ) in self.state.evaluated
        ]
        positions = ([checkpoint] if checkpoint is not None else []) + evaluated_positions
        return max(
            positions,
            key=lambda item: (item.event_time, item.event_uid),
            default=None,
        )

    def load_evaluation_scope(self):
        key = (self.engine_id, self.ruleset_fingerprint)
        evaluation_floor = self.state.evaluation_floors.get(key)
        if evaluation_floor is None:
            return None
        return EvaluationScope(
            evaluation_floor,
            self.state.candidate_cursors.get(key),
        )

    def load_legacy_evaluation_floor(self):
        return None

    def initialize_evaluation_floor(self, checkpoint, evaluation_floor_time):
        self.calls.append("initialize_evaluation_floor")
        self.state.checkpoints[self.engine_id] = checkpoint
        self.state.evaluation_floors[
            (self.engine_id, self.ruleset_fingerprint)
        ] = evaluation_floor_time
        self.state.candidate_cursors.pop(
            (self.engine_id, self.ruleset_fingerprint), None
        )

    def fetch_unevaluated_events(self, evaluation_floor_time, candidate_cursor):
        pending = self._pending(evaluation_floor_time)
        if candidate_cursor is not None:
            cursor_position = (
                candidate_cursor.event_time,
                candidate_cursor.event_uid,
            )
            pending = [
                source_event
                for source_event in pending
                if (source_event["event_time"], source_event["event_uid"])
                > cursor_position
            ] + [
                source_event
                for source_event in pending
                if (source_event["event_time"], source_event["event_uid"])
                <= cursor_position
            ]
        batch = pending[: self.settings.batch_size]
        self.fetch_batch_sizes.append(len(batch))
        self.calls.append("fetch_unevaluated_events")
        return batch

    def save_candidate_cursor(self, evaluation_floor_time, candidate_cursor):
        self.calls.append("save_candidate_cursor")
        if self.cursor_failures:
            self.cursor_failures -= 1
            raise RuntimeError("candidate cursor write failed")
        assert evaluation_floor_time == self.state.evaluation_floors[
            (self.engine_id, self.ruleset_fingerprint)
        ]
        self.state.candidate_cursors[
            (self.engine_id, self.ruleset_fingerprint)
        ] = candidate_cursor

    def existing_detection_ids(self, identifiers):
        return set(identifiers) & set(self.state.physical_detection_ids)

    def insert_detections(self, candidates):
        candidates = list(candidates)
        self.calls.append("insert_detections")
        self.state.physical_detection_ids.extend(
            candidate.detection_id for candidate in candidates
        )
        return len(candidates)

    def mark_events_evaluated(self, events):
        events = list(events)
        self.calls.append("mark_events_evaluated")
        if self.mark_failures:
            self.mark_failures -= 1
            raise RuntimeError("ledger write failed")
        unique_uids = list(dict.fromkeys(source_event["event_uid"] for source_event in events))
        if not unique_uids:
            return 0
        self.marked_batches.append(unique_uids)
        self.state.evaluated.update(
            (self.engine_id, self.ruleset_fingerprint, uid) for uid in unique_uids
        )
        return len(unique_uids)

    def fetch_backlog_status(self, checkpoint, evaluation_floor_time):
        pending = self._pending(evaluation_floor_time)
        eligible = [
            source_event
            for source_event in self.state.events
            if source_event["event_time"] >= evaluation_floor_time
            or source_event["ingested_at"] >= evaluation_floor_time
        ]
        if not eligible:
            return BacklogStatus(None, "", 0, 0.0)
        newest = max(
            eligible,
            key=lambda source_event: (
                source_event["event_time"],
                source_event["event_uid"],
            ),
        )
        positional_lag = len(
            {
                source_event["event_uid"]
                for source_event in eligible
                if (source_event["event_time"], source_event["event_uid"])
                > (checkpoint.event_time, checkpoint.event_uid)
            }
        )
        oldest = min(
            (source_event["event_time"] for source_event in pending),
            default=None,
        )
        return BacklogStatus(
            newest["event_time"],
            newest["event_uid"],
            positional_lag,
            max(0.0, (newest["event_time"] - checkpoint.event_time).total_seconds()),
            len(pending),
            oldest,
            max(0.0, (NOW - oldest).total_seconds()) if oldest is not None else 0.0,
        )

    def save_checkpoint(self, stats):
        self.calls.append("save_checkpoint")
        self.saved_stats.append(stats)
        self.state.checkpoints[self.engine_id] = stats.checkpoint


def engine(store, evaluator):
    return DetectionEngine(store, evaluator, logging.getLogger("test.evaluation-ledger"))


def test_1001_same_timestamp_lower_uids_remain_discoverable():
    checkpoint = Checkpoint(NOW, "f" * 64)
    source_events = [event(f"{index:064x}") for index in range(1001)]
    state = LedgerState(
        source_events,
        checkpoints={ENGINE_ID: checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state)
    evaluator = RecordingEvaluator()
    detection_engine = engine(store, evaluator)

    first = detection_engine.run_cycle()
    second = detection_engine.run_cycle()

    assert first.events_evaluated == 1000
    assert first.new_events_processed == 0
    assert first.late_events_processed == 1000
    assert first.backlog.lag_events == 0
    assert first.backlog.unevaluated_events == 1
    assert second.events_evaluated == 1
    assert second.new_events_processed == 0
    assert second.late_events_processed == 1
    assert second.backlog.unevaluated_events == 0
    assert store.fetch_batch_sizes == [1000, 1]
    assert len(evaluator.evaluated_uids) == 1001
    assert len(set(evaluator.evaluated_uids)) == 1001
    assert len(state.evaluated) == 1001
    assert state.checkpoints[ENGINE_ID] == checkpoint


def test_out_of_order_older_event_is_evaluated_without_regressing_checkpoint():
    checkpoint = Checkpoint(NOW, "checkpoint-uid")
    older = event("older-event", when=NOW - timedelta(seconds=30))
    state = LedgerState(
        [older],
        checkpoints={ENGINE_ID: checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state)
    evaluator = RecordingEvaluator()

    stats = engine(store, evaluator).run_cycle()

    assert evaluator.evaluated_uids == ["older-event"]
    assert stats.new_events_processed == 0
    assert stats.late_events_processed == 1
    assert (ENGINE_ID, RULESET, "older-event") in state.evaluated
    assert state.checkpoints[ENGINE_ID] == checkpoint


def test_saturated_lookback_advances_through_every_bounded_ledger_page():
    checkpoint = Checkpoint(NOW, "f" * 64)
    source_events = [
        event(f"{index:064x}", when=NOW - timedelta(seconds=1))
        for index in range(2501)
    ]
    state = LedgerState(
        source_events,
        checkpoints={ENGINE_ID: checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state, batch_size=1000)
    evaluator = RecordingEvaluator()
    detection_engine = engine(store, evaluator)

    cycles = [detection_engine.run_cycle() for _ in range(4)]

    assert [cycle.events_evaluated for cycle in cycles] == [1000, 1000, 501, 0]
    assert [cycle.backlog.unevaluated_events for cycle in cycles] == [1501, 501, 0, 0]
    assert store.fetch_batch_sizes == [1000, 1000, 501, 0]
    assert len(state.evaluated) == 2501
    assert len(evaluator.evaluated_uids) == 2501
    assert len(set(evaluator.evaluated_uids)) == 2501
    assert cycles[-1].backlog.lag_events == 0


def test_duplicate_physical_rows_are_evaluated_and_marked_logically_once():
    uid = "duplicate-event"
    state = LedgerState(
        [event(uid, physical_copy=1), event(uid, physical_copy=2)],
        checkpoints={ENGINE_ID: Checkpoint(NOW - timedelta(seconds=1), "")},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state)
    evaluator = RecordingEvaluator()
    detection_engine = engine(store, evaluator)

    first = detection_engine.run_cycle()
    second = detection_engine.run_cycle()

    assert first.events_evaluated == 1
    assert second.events_evaluated == 0
    assert evaluator.evaluated_uids == [uid]
    assert store.marked_batches == [[uid]]
    assert state.evaluated == {(ENGINE_ID, RULESET, uid)}


def test_ledger_identity_is_scoped_by_engine_id():
    uid = "shared-event"
    original_checkpoint = Checkpoint(NOW - timedelta(seconds=1), "")
    state = LedgerState(
        [event(uid)],
        checkpoints={
            "engine-a": original_checkpoint,
            "engine-b": original_checkpoint,
        },
        evaluation_floors={
            ("engine-a", RULESET): NOW - timedelta(seconds=120),
            ("engine-b", RULESET): NOW - timedelta(seconds=120),
        },
    )
    evaluator_a = RecordingEvaluator()
    evaluator_b = RecordingEvaluator()

    engine(LedgerStore(state, engine_id="engine-a"), evaluator_a).run_cycle()
    engine(LedgerStore(state, engine_id="engine-b"), evaluator_b).run_cycle()

    assert evaluator_a.evaluated_uids == [uid]
    assert evaluator_b.evaluated_uids == [uid]
    assert state.evaluated == {
        ("engine-a", RULESET, uid),
        ("engine-b", RULESET, uid),
    }


def test_changed_ruleset_fingerprint_re_evaluates_the_bounded_source_event():
    uid = "ruleset-change-event"
    state = LedgerState(
        [event(uid)],
        checkpoints={ENGINE_ID: Checkpoint(NOW - timedelta(seconds=1), "")},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    evaluator = RecordingEvaluator()

    engine(
        LedgerStore(state, ruleset_fingerprint="ruleset-a"), evaluator
    ).run_cycle()
    engine(
        LedgerStore(state, ruleset_fingerprint="ruleset-b"), evaluator
    ).run_cycle()

    assert evaluator.evaluated_uids == [uid, uid]
    assert state.evaluated == {
        (ENGINE_ID, "ruleset-a", uid),
        (ENGINE_ID, "ruleset-b", uid),
    }


def test_ruleset_floor_survives_a_b_a_transition_with_undrained_event():
    old_uid = "a-old-event"
    new_uid = "z-new-event"
    original_floor = NOW - timedelta(seconds=120)
    state = LedgerState(
        [
            event(old_uid, when=NOW),
            event(new_uid, when=NOW + timedelta(hours=1)),
        ],
        checkpoints={ENGINE_ID: Checkpoint(NOW - timedelta(seconds=1), "")},
        evaluation_floors={(ENGINE_ID, "ruleset-a"): original_floor},
    )

    engine(
        LedgerStore(state, ruleset_fingerprint="ruleset-b", batch_size=2),
        RecordingEvaluator(),
    ).run_cycle()
    evaluator_a = RecordingEvaluator()
    stats_a = engine(
        LedgerStore(state, ruleset_fingerprint="ruleset-a", batch_size=1),
        evaluator_a,
    ).run_cycle()

    assert state.evaluation_floors[(ENGINE_ID, "ruleset-a")] == original_floor
    assert evaluator_a.evaluated_uids == [old_uid]
    assert stats_a.events_evaluated == 1
    assert stats_a.late_events_processed == 1


def test_post_start_arrival_is_eligible_even_when_event_time_predates_floor():
    uid = "old-timestamp-new-arrival"
    state = LedgerState(
        [
            event(
                uid,
                when=NOW - timedelta(hours=1),
                ingested_at=NOW + timedelta(seconds=1),
            )
        ],
        checkpoints={ENGINE_ID: Checkpoint(NOW, "checkpoint")},
        evaluation_floors={(ENGINE_ID, RULESET): NOW},
    )
    evaluator = RecordingEvaluator()

    stats = engine(LedgerStore(state), evaluator).run_cycle()

    assert stats.events_evaluated == 1
    assert stats.late_events_processed == 1
    assert state.evaluated == {(ENGINE_ID, RULESET, uid)}


def test_crash_before_ledger_mark_replays_and_deduplicates_detection():
    uid = "crash-window-event"
    original_checkpoint = Checkpoint(NOW - timedelta(seconds=1), "")
    state = LedgerState(
        [event(uid)],
        checkpoints={ENGINE_ID: original_checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state, mark_failures=1)
    evaluator = RecordingEvaluator(matching_uids={uid})

    with pytest.raises(RuntimeError, match="ledger write failed"):
        engine(store, evaluator).run_cycle()

    assert state.physical_detection_ids == [f"detection-{uid}"]
    assert state.evaluated == set()
    assert state.checkpoints[ENGINE_ID] == original_checkpoint
    assert "save_checkpoint" not in store.calls

    replay = engine(store, evaluator).run_cycle()

    assert replay.detections_inserted == 0
    assert replay.duplicates_skipped == 1
    assert state.physical_detection_ids == [f"detection-{uid}"]
    assert state.evaluated == {(ENGINE_ID, RULESET, uid)}
    assert state.checkpoints[ENGINE_ID].event_uid == uid


def test_restart_heals_checkpoint_after_ledger_commit_before_checkpoint_write():
    uid = "ledger-committed-before-checkpoint"
    original_checkpoint = Checkpoint(NOW - timedelta(seconds=1), "")
    state = LedgerState(
        [event(uid)],
        checkpoints={ENGINE_ID: original_checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
        evaluated={(ENGINE_ID, RULESET, uid)},
    )
    store = LedgerStore(state)
    evaluator = RecordingEvaluator()

    stats = engine(store, evaluator).run_cycle()

    assert stats.events_evaluated == 0
    assert evaluator.evaluated_uids == []
    assert stats.checkpoint == Checkpoint(NOW, uid)
    assert state.checkpoints[ENGINE_ID] == Checkpoint(NOW, uid)
    assert store.calls[-1] == "save_checkpoint"


def test_ledger_write_failure_propagates_and_does_not_advance_checkpoint():
    uid = "ledger-failure-zero-match"
    original_checkpoint = Checkpoint(NOW - timedelta(seconds=1), "")
    state = LedgerState(
        [event(uid)],
        checkpoints={ENGINE_ID: original_checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state, mark_failures=1)
    evaluator = RecordingEvaluator()

    with pytest.raises(RuntimeError, match="ledger write failed"):
        engine(store, evaluator).run_cycle()

    assert evaluator.evaluated_uids == [uid]
    assert state.evaluated == set()
    assert state.checkpoints[ENGINE_ID] == original_checkpoint
    assert [source_event["event_uid"] for source_event in store._pending()] == [uid]
    assert "save_checkpoint" not in store.calls


def test_failed_event_remains_eligible_while_successful_peers_are_ledgered():
    failed_uid = "aaa-failed-event"
    successful_uid = "bbb-successful-event"
    original_checkpoint = Checkpoint(NOW - timedelta(seconds=1), "")
    state = LedgerState(
        [event(failed_uid), event(successful_uid)],
        checkpoints={ENGINE_ID: original_checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state)

    class SelectiveFailureEvaluator(RecordingEvaluator):
        def evaluate(self, source_event):
            uid = source_event["event_uid"]
            self.evaluated_uids.append(uid)
            if uid == failed_uid:
                raise ValueError("controlled evaluation failure")
            return []

    evaluator = SelectiveFailureEvaluator()
    stats = engine(store, evaluator).run_cycle()

    assert stats.evaluation_failures == 1
    assert stats.events_evaluated == 1
    assert state.evaluated == {(ENGINE_ID, RULESET, successful_uid)}
    assert [item["event_uid"] for item in store._pending()] == [failed_uid]
    assert state.checkpoints[ENGINE_ID].event_uid == successful_uid


def test_one_repeatable_failure_does_not_block_valid_events_beyond_one_batch():
    failed_uid = "000-failed-event"
    valid_uids = [f"{index:064x}" for index in range(1, 1002)]
    state = LedgerState(
        [event(failed_uid), *(event(uid) for uid in valid_uids)],
        checkpoints={ENGINE_ID: Checkpoint(NOW - timedelta(seconds=1), "")},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state, batch_size=1000)

    class RepeatableFailureEvaluator(RecordingEvaluator):
        def evaluate(self, source_event):
            uid = source_event["event_uid"]
            self.evaluated_uids.append(uid)
            if uid == failed_uid:
                raise ValueError("controlled repeatable failure")
            return []

    evaluator = RepeatableFailureEvaluator()
    detection_engine = engine(store, evaluator)

    first = detection_engine.run_cycle()
    second = detection_engine.run_cycle()

    assert first.events_evaluated == 999
    assert second.events_evaluated == 2
    assert first.evaluation_failures == second.evaluation_failures == 1
    assert {
        uid
        for engine_id, ruleset, uid in state.evaluated
        if engine_id == ENGINE_ID and ruleset == RULESET
    } == set(valid_uids)
    assert [item["event_uid"] for item in store._pending()] == [failed_uid]


def test_all_failure_page_rotates_after_restart_and_does_not_starve_valid_event():
    failed_uids = ["000-failed-event", "001-failed-event"]
    valid_uid = "999-valid-event"
    original_checkpoint = Checkpoint(NOW - timedelta(seconds=1), "")
    state = LedgerState(
        [*(event(uid) for uid in failed_uids), event(valid_uid)],
        checkpoints={ENGINE_ID: original_checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )

    class FailurePageEvaluator(RecordingEvaluator):
        def evaluate(self, source_event):
            uid = source_event["event_uid"]
            self.evaluated_uids.append(uid)
            if uid in failed_uids:
                raise ValueError("controlled repeatable evaluation failure")
            return []

    evaluator = FailurePageEvaluator()
    first = engine(LedgerStore(state, batch_size=2), evaluator).run_cycle()

    assert first.events_evaluated == 0
    assert first.evaluation_failures == 2
    assert first.checkpoint == original_checkpoint
    assert state.evaluated == set()
    assert state.candidate_cursors[(ENGINE_ID, RULESET)].event_uid == failed_uids[-1]

    # A new store represents a restart and must resume from the persisted
    # scheduling cursor rather than selecting the same poisoned page forever.
    second = engine(LedgerStore(state, batch_size=2), evaluator).run_cycle()

    assert second.events_evaluated == 1
    assert second.evaluation_failures == 1
    assert (ENGINE_ID, RULESET, valid_uid) in state.evaluated
    assert all(
        (ENGINE_ID, RULESET, uid) not in state.evaluated for uid in failed_uids
    )
    assert second.checkpoint.event_uid == valid_uid
    assert [item["event_uid"] for item in LedgerStore(state)._pending()] == failed_uids


def test_failure_page_cursor_write_failure_does_not_claim_progress():
    failed_uid = "failed-event"
    original_checkpoint = Checkpoint(NOW - timedelta(seconds=1), "")
    state = LedgerState(
        [event(failed_uid)],
        checkpoints={ENGINE_ID: original_checkpoint},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )

    class AlwaysFails(RecordingEvaluator):
        def evaluate(self, source_event):
            self.evaluated_uids.append(source_event["event_uid"])
            raise ValueError("controlled repeatable evaluation failure")

    store = LedgerStore(state, batch_size=1, cursor_failures=1)
    with pytest.raises(RuntimeError, match="candidate cursor write failed"):
        engine(store, AlwaysFails()).run_cycle()

    assert state.evaluated == set()
    assert state.checkpoints[ENGINE_ID] == original_checkpoint
    assert (ENGINE_ID, RULESET) not in state.candidate_cursors
    assert "save_checkpoint" not in store.calls


def test_zero_match_event_is_ledgered_and_not_reprocessed():
    uid = "zero-match-event"
    state = LedgerState(
        [event(uid)],
        checkpoints={ENGINE_ID: Checkpoint(NOW - timedelta(seconds=1), "")},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    store = LedgerStore(state)
    evaluator = RecordingEvaluator()
    detection_engine = engine(store, evaluator)

    first = detection_engine.run_cycle()
    second = detection_engine.run_cycle()

    assert first.matches_found == 0
    assert first.detections_inserted == 0
    assert second.events_evaluated == 0
    assert evaluator.evaluated_uids == [uid]
    assert state.evaluated == {(ENGINE_ID, RULESET, uid)}


def test_restart_resumes_persisted_ledger_backlog_without_amplification():
    source_events = [
        event(f"{index:064x}", when=NOW + timedelta(milliseconds=index))
        for index in range(1500)
    ]
    state = LedgerState(
        source_events,
        checkpoints={ENGINE_ID: Checkpoint(NOW - timedelta(seconds=1), "")},
        evaluation_floors={(ENGINE_ID, RULESET): NOW - timedelta(seconds=120)},
    )
    evaluator = RecordingEvaluator()

    first_store = LedgerStore(state, batch_size=1000)
    first = engine(first_store, evaluator).run_cycle()
    restarted_store = LedgerStore(state, batch_size=1000)
    second = engine(restarted_store, evaluator).run_cycle()

    assert first.events_evaluated == 1000
    assert first.backlog.lag_events == 500
    assert first.backlog.unevaluated_events == 500
    assert second.events_evaluated == 500
    assert second.backlog.lag_events == 0
    assert second.backlog.unevaluated_events == 0
    assert len(state.evaluated) == 1500
    assert len(evaluator.evaluated_uids) == 1500
    assert len(set(evaluator.evaluated_uids)) == 1500
    assert state.physical_detection_ids == []
    assert state.checkpoints[ENGINE_ID].event_uid == f"{1499:064x}"


def settings(tmp_path: Path, *, engine_id: str = ENGINE_ID, batch_size: int = 1000):
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
        batch_size,
        engine_id,
        "INFO",
    )


class QueryResult:
    def __init__(self, rows, columns=EVENT_COLUMNS):
        self.result_rows = rows
        self.column_names = columns


class RecordingClient:
    def __init__(self, query_results=()):
        self.query_results = list(query_results)
        self.queries = []
        self.inserts = []

    def query(self, query, parameters=None):
        self.queries.append((query, parameters))
        return self.query_results.pop(0)

    def insert(self, table, rows, column_names):
        self.inserts.append((table, rows, column_names))


def event_row(source_event: dict) -> tuple:
    numeric_columns = {
        "event_id",
        "source_port",
        "destination_port",
        "parent_process_id",
    }
    values = []
    for column in EVENT_COLUMNS:
        if column == "event_uid":
            values.append(source_event["event_uid"])
        elif column == "event_time":
            values.append(source_event["event_time"])
        elif column == "source_event_id":
            values.append(source_event["event_uid"])
        elif column in numeric_columns:
            values.append(0)
        else:
            values.append("")
    return tuple(values)


def test_clickhouse_unevaluated_query_uses_engine_scoped_ledger_and_deduplicates(
    tmp_path,
):
    source_event = event("duplicate-query-row")
    row = event_row(source_event)
    client = RecordingClient([QueryResult([row, row])])
    store = ClickHouseStore(settings(tmp_path), client=client)

    evaluation_floor = NOW - timedelta(seconds=120)
    pending = store.fetch_unevaluated_events(evaluation_floor)

    assert [item["event_uid"] for item in pending] == ["duplicate-query-row"]
    query, parameters = client.queries[0]
    assert "fusion.detection_evaluated_events" in query
    assert "FINAL" in query
    assert "{engine_id:String}" in query
    assert "{batch_size:UInt32}" in query
    assert parameters["engine_id"] == ENGINE_ID
    assert parameters["evaluation_floor_time"] == evaluation_floor
    assert parameters["candidate_cursor_present"] == 0
    assert parameters["candidate_cursor_time"] == evaluation_floor
    assert parameters["candidate_cursor_uid"] == ""
    assert parameters["batch_size"] == 1000
    upper_query = query.upper()
    assert (
        any(anti_join in upper_query for anti_join in ("ANTI JOIN", "NOT EXISTS", "NOT IN"))
        or ("LEFT JOIN" in upper_query and "IS NULL" in upper_query)
    )


def test_clickhouse_candidate_query_rotates_after_persisted_cursor(tmp_path):
    source_event = event("later-valid-event", when=NOW + timedelta(seconds=1))
    client = RecordingClient([QueryResult([event_row(source_event)])])
    store = ClickHouseStore(settings(tmp_path), client=client)
    evaluation_floor = NOW - timedelta(seconds=120)
    cursor = Checkpoint(NOW, "failed-page-tail")

    pending = store.fetch_unevaluated_events(evaluation_floor, cursor)

    assert [item["event_uid"] for item in pending] == ["later-valid-event"]
    query, parameters = client.queries[0]
    assert "{candidate_cursor_present:UInt8}" in query
    assert "{candidate_cursor_time:DateTime64(3)}" in query
    assert "source.event_uid <= {candidate_cursor_uid:String}" in query
    assert parameters["candidate_cursor_present"] == 1
    assert parameters["candidate_cursor_time"] == cursor.event_time
    assert parameters["candidate_cursor_uid"] == cursor.event_uid


def test_clickhouse_ledger_mark_is_unique_and_engine_scoped(tmp_path):
    source_event = event("mark-once")
    client = RecordingClient()
    store = ClickHouseStore(
        settings(tmp_path, engine_id="engine-a"),
        client=client,
        ruleset_fingerprint="f" * 64,
    )

    inserted = store.mark_events_evaluated([source_event, dict(source_event)])

    assert inserted == 1
    assert len(client.inserts) == 1
    table, rows, columns = client.inserts[0]
    assert table == "fusion.detection_evaluated_events"
    assert len(rows) == 1
    values = dict(zip(columns, rows[0], strict=True))
    assert values["engine_id"] == "engine-a"
    assert values["ruleset_fingerprint"] == "f" * 64
    assert values["event_uid"] == "mark-once"
    assert values["event_time"] == NOW
