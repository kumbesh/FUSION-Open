"""Incremental processing with a persistent watermark and bounded lookback."""

from __future__ import annotations

import logging
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
        checkpoint = self.store.load_checkpoint()
        if checkpoint is None:
            checkpoint = Checkpoint(
                datetime.now(timezone.utc) - timedelta(seconds=self.store.settings.lookback_seconds),
                "",
            )
        new_events = self.store.fetch_new_events(checkpoint)
        late_events = self.store.fetch_late_events(checkpoint)
        events_by_uid = {event["event_uid"]: event for event in late_events}
        events_by_uid.update({event["event_uid"]: event for event in new_events})

        candidates = []
        rule_failures = 0
        for event in events_by_uid.values():
            try:
                candidates.extend(self.evaluator.evaluate(event))
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

        if new_events:
            last = new_events[-1]
            checkpoint = Checkpoint(last["event_time"], str(last["event_uid"]))
            self.store.save_checkpoint(checkpoint)

        duplicate_count = len(candidates) - len(unique_candidates)
        self.logger.info(
            "poll_complete events_evaluated=%d matches=%d detections_inserted=%d "
            "duplicates_skipped=%d evaluation_failures=%d checkpoint_time=%s checkpoint_uid=%s",
            len(events_by_uid),
            len(candidates),
            inserted,
            duplicate_count,
            rule_failures,
            checkpoint.event_time.isoformat(),
            checkpoint.event_uid,
        )
        return CycleStats(len(events_by_uid), len(candidates), inserted, duplicate_count, checkpoint)
