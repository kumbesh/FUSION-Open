"""Persistent, ledger-backed evaluation with a diagnostic watermark."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from .clickhouse import ClickHouseStore
from .evaluator import DetectionEvaluator
from .models import Checkpoint, CycleStats


class DetectionEngine:
    def __init__(self, store: ClickHouseStore, evaluator: DetectionEvaluator, logger: logging.Logger):
        self.store = store
        self.evaluator = evaluator
        self.logger = logger

    def run_cycle(self) -> CycleStats:
        started_at = time.perf_counter()
        checkpoint = self.store.load_checkpoint()
        if checkpoint is None:
            checkpoint = Checkpoint(
                datetime.now(timezone.utc) - timedelta(seconds=self.store.settings.lookback_seconds),
                "",
            )
        scope = self.store.load_evaluation_scope()
        scope_floor_time = (
            scope.evaluation_floor_time if scope is not None else None
        )
        candidate_cursor = scope.candidate_cursor if scope is not None else None
        evaluation_floor_time = scope_floor_time
        if evaluation_floor_time is None:
            evaluation_floor_time = self.store.load_legacy_evaluation_floor()
        if evaluation_floor_time is None:
            # Preserve the effective v0.5 lookback window, then keep the floor
            # fixed so a late-visible event never ages out of eligibility.
            evaluation_floor_time = checkpoint.event_time - timedelta(
                seconds=self.store.settings.lookback_seconds
            )
        if scope_floor_time is None:
            self.store.initialize_evaluation_floor(checkpoint, evaluation_floor_time)

        events = self.store.fetch_unevaluated_events(
            evaluation_floor_time, candidate_cursor
        )
        events_by_uid = {str(event["event_uid"]): event for event in events}

        candidates = []
        rule_failures = 0
        successfully_evaluated = []
        for event in events_by_uid.values():
            try:
                candidates.extend(self.evaluator.evaluate(event))
                successfully_evaluated.append(event)
            except Exception:
                rule_failures += 1
                self.logger.exception("event_evaluation_failed source_event_uid=%s", event.get("event_uid", ""))

        existing = self.store.existing_detection_ids(candidate.detection_id for candidate in candidates)
        unique_candidates = []
        seen = set(existing)
        for candidate in candidates:
            if candidate.detection_id in seen:
                continue
            seen.add(candidate.detection_id)
            unique_candidates.append(candidate)
        inserted = self.store.insert_detections(unique_candidates)

        # Crash consistency is deliberate: required detection writes complete
        # before evaluation success is persisted. A crash in this window may
        # replay an event, while deterministic detection IDs prevent a logical
        # duplicate. Nothing is marked complete before its detections are safe.
        marked = self.store.mark_events_evaluated(successfully_evaluated)
        if marked != len(successfully_evaluated):
            raise RuntimeError(
                "evaluation ledger did not acknowledge every successfully evaluated event"
            )

        # This is a scheduling cursor, never a completeness marker. Advancing
        # it after the page has been attempted allows a repeatably failing
        # event to wrap around while later valid events remain reachable. A
        # failed event stays absent from the ledger and is retried on a future
        # rotation. Persist only after required detection and ledger writes so
        # storage failures replay the same bounded page safely.
        if events:
            last_candidate = events[-1]
            candidate_cursor = Checkpoint(
                last_candidate["event_time"], str(last_candidate["event_uid"])
            )
            self.store.save_candidate_cursor(
                evaluation_floor_time, candidate_cursor
            )

        original_checkpoint = checkpoint
        if successfully_evaluated:
            furthest = max(
                successfully_evaluated,
                key=lambda event: (event["event_time"], str(event["event_uid"])),
            )
            furthest_checkpoint = Checkpoint(
                furthest["event_time"], str(furthest["event_uid"])
            )
            if (
                furthest_checkpoint.event_time,
                furthest_checkpoint.event_uid,
            ) > (checkpoint.event_time, checkpoint.event_uid):
                checkpoint = furthest_checkpoint

        new_events_processed = sum(
            1
            for event in successfully_evaluated
            if (event["event_time"], str(event["event_uid"]))
            > (original_checkpoint.event_time, original_checkpoint.event_uid)
        )
        late_events_processed = len(successfully_evaluated) - new_events_processed

        backlog = self.store.fetch_backlog_status(checkpoint, evaluation_floor_time)
        processing_duration = max(time.perf_counter() - started_at, 0.0)
        evaluated_rate = (
            len(successfully_evaluated) / processing_duration
            if processing_duration > 0
            else 0.0
        )
        stats = CycleStats(
            events_evaluated=len(successfully_evaluated),
            new_events_processed=new_events_processed,
            late_events_processed=late_events_processed,
            matches_found=len(candidates),
            detections_inserted=inserted,
            duplicates_skipped=len(candidates) - len(unique_candidates),
            evaluation_failures=rule_failures,
            processing_duration_seconds=processing_duration,
            evaluated_events_per_second=evaluated_rate,
            checkpoint=checkpoint,
            backlog=backlog,
            evaluation_floor_time=evaluation_floor_time,
            candidate_cursor=candidate_cursor,
        )
        # Persist even an empty-cycle snapshot. Besides keeping the stored
        # telemetry current, this heals the deliberate crash window where the
        # ledger insert committed but the previous checkpoint insert did not:
        # load_checkpoint derives the effective watermark from both tables.
        self.store.save_checkpoint(stats)

        self.logger.info(
            "poll_complete events_evaluated=%d new_events_processed=%d late_events_processed=%d "
            "matches=%d detections_inserted=%d duplicates_skipped=%d evaluation_failures=%d "
            "processing_duration_seconds=%.6f evaluated_events_per_second=%.3f "
            "checkpoint_time=%s checkpoint_uid=%s newest_eligible_event_time=%s "
            "newest_eligible_event_uid=%s checkpoint_lag_events=%d checkpoint_lag_seconds=%.3f "
            "unevaluated_event_count=%d oldest_unevaluated_event_time=%s "
            "oldest_unevaluated_age_seconds=%.3f evaluation_floor_time=%s "
            "candidate_cursor_time=%s candidate_cursor_uid=%s",
            stats.events_evaluated,
            stats.new_events_processed,
            stats.late_events_processed,
            stats.matches_found,
            stats.detections_inserted,
            stats.duplicates_skipped,
            stats.evaluation_failures,
            stats.processing_duration_seconds,
            stats.evaluated_events_per_second,
            stats.checkpoint.event_time.isoformat(),
            stats.checkpoint.event_uid,
            (
                stats.backlog.newest_event_time.isoformat()
                if stats.backlog.newest_event_time is not None
                else ""
            ),
            stats.backlog.newest_event_uid,
            stats.backlog.lag_events,
            stats.backlog.lag_seconds,
            stats.backlog.unevaluated_events,
            (
                stats.backlog.oldest_unevaluated_event_time.isoformat()
                if stats.backlog.oldest_unevaluated_event_time is not None
                else ""
            ),
            stats.backlog.oldest_unevaluated_age_seconds,
            evaluation_floor_time.isoformat(),
            (
                candidate_cursor.event_time.isoformat()
                if candidate_cursor is not None
                else ""
            ),
            candidate_cursor.event_uid if candidate_cursor is not None else "",
        )
        return stats
