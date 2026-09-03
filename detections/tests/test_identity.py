from __future__ import annotations

import logging
from conftest import MITRE_PATH, complete_event, load_detection_fixtures
from fusion_detection.checkpoint import DetectionEngine
from fusion_detection.config import Settings
from fusion_detection.evaluator import DetectionEvaluator, detection_identity
from fusion_detection.models import Checkpoint


def test_detection_identity_is_deterministic_and_rule_specific():
    first = detection_identity("rule-a", "event-1")
    assert first == detection_identity("rule-a", "event-1")
    assert first != detection_identity("rule-b", "event-1")
    assert first != detection_identity("rule-a", "event-2")


def test_two_rules_on_one_event_create_distinct_detections(compiled_rules, evaluator):
    event = complete_event(
        {
            "platform": "network",
            "source_type": "suricata_eve",
            "event_kind": "alert",
            "event_action": "network_alert",
            "severity": "high",
            "signature": "FUSION TEST controlled overlap",
            "signature_id": "9000001",
        },
        "two-rule-event",
    )
    detections = evaluator.evaluate(event)
    ids = {candidate.detection_id for candidate in detections}
    rules = {candidate.values["rule_id"] for candidate in detections}
    assert len(ids) == 2
    assert rules == {
        "fusion-network-high-severity-suricata-alert",
        "fusion-network-controlled-suricata-signature",
    }


class FakeStore:
    def __init__(self, settings, event):
        self.settings = settings
        self.event = event
        self.checkpoint = Checkpoint(event["event_time"], event["event_uid"])
        self.ids = set()

    def load_checkpoint(self):
        return self.checkpoint

    def fetch_new_events(self, checkpoint):
        return []

    def fetch_late_events(self, checkpoint):
        return [self.event]

    def existing_detection_ids(self, identifiers):
        return set(identifiers) & self.ids

    def insert_detections(self, candidates):
        candidates = list(candidates)
        self.ids.update(candidate.detection_id for candidate in candidates)
        return len(candidates)

    def save_checkpoint(self, checkpoint):
        self.checkpoint = checkpoint


def test_replay_and_restart_do_not_duplicate(compiled_rules, evaluator, tmp_path):
    fixture = next(value for path, value in load_detection_fixtures() if path.stem == "encoded-powershell")
    event = complete_event(fixture["positive"], "restart-event")
    settings = Settings(
        "clickhouse", 8123, "fusion", "fusion", "secret", tmp_path, tmp_path / "fields.yml",
        tmp_path / "mitre.yml", 10, 120, 1000, "test-engine", "INFO",
    )
    target_rule = next(rule for rule in compiled_rules if rule.rule.rule_id == fixture["rule_id"])
    target_evaluator = DetectionEvaluator((target_rule,), MITRE_PATH)
    store = FakeStore(settings, event)
    engine = DetectionEngine(store, target_evaluator, logging.getLogger("test"))
    first = engine.run_cycle()
    restarted = DetectionEngine(store, target_evaluator, logging.getLogger("test"))
    second = restarted.run_cycle()
    assert first.detections_inserted >= 1
    assert second.detections_inserted == 0
    assert second.duplicates_skipped >= 1
