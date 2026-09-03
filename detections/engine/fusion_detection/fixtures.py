"""Synthetic fixture validation and explicit lab seeding helpers."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .compiler import CompiledRule
from .models import RuleValidationError


def load_fixture_files(fixtures_dir: Path) -> list[tuple[Path, Mapping[str, Any]]]:
    fixtures: list[tuple[Path, Mapping[str, Any]]] = []
    for path in sorted(fixtures_dir.rglob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise RuleValidationError(f"invalid detection fixture {path}: {exc}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("rule_id"), str):
            raise RuleValidationError(f"fixture must contain rule_id: {path}")
        if not isinstance(raw.get("positive"), dict) or not isinstance(raw.get("negative"), dict):
            raise RuleValidationError(f"fixture must contain positive and negative event mappings: {path}")
        fixtures.append((path, raw))
    if not fixtures:
        raise RuleValidationError(f"no detection fixtures found under {fixtures_dir}")
    return fixtures


def validate_fixtures(fixtures_dir: Path, rules: Iterable[CompiledRule]) -> tuple[int, int]:
    rules_by_id = {rule.rule.rule_id: rule for rule in rules}
    fixtures = load_fixture_files(fixtures_dir)
    fixture_ids = {str(fixture["rule_id"]) for _, fixture in fixtures}
    missing = sorted(set(rules_by_id) - fixture_ids)
    unknown = sorted(fixture_ids - set(rules_by_id))
    if missing or unknown:
        raise RuleValidationError(f"fixture/rule mismatch missing={missing} unknown={unknown}")
    positives = 0
    negatives = 0
    for path, fixture in fixtures:
        rule = rules_by_id[str(fixture["rule_id"])]
        if not rule.evaluate(fixture["positive"]).matched:
            raise RuleValidationError(f"positive fixture does not match {rule.rule.rule_id}: {path}")
        positives += 1
        if rule.evaluate(fixture["negative"]).matched:
            raise RuleValidationError(f"negative fixture unexpectedly matches {rule.rule.rule_id}: {path}")
        negatives += 1
    return positives, negatives


def prepare_fixture_events(fixtures_dir: Path, run_id: str) -> list[dict[str, Any]]:
    if not run_id or len(run_id) > 128 or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in run_id):
        raise RuleValidationError("fixture run id must contain only letters, numbers, hyphens, or underscores")
    base_time = datetime.now(timezone.utc) + timedelta(seconds=1)
    events: list[dict[str, Any]] = []
    for index, (path, fixture) in enumerate(load_fixture_files(fixtures_dir)):
        for polarity in ("positive", "negative"):
            event = dict(fixture[polarity])
            source_id = f"{run_id}-{fixture['rule_id']}-{polarity}"
            event.update(
                {
                    "event_time": base_time + timedelta(milliseconds=index * 2 + (polarity == "negative")),
                    "event_type": event.get("event_action", "detection_fixture"),
                    "computer": event.get("host_name", "fusion-detection-fixture"),
                    "source_event_id": source_id,
                    "event_code": str(event.get("event_code", event.get("event_id", "fixture"))),
                    "validation_id": run_id,
                    "ingestion_protocol": "test_fixture",
                    "ingestion_path": "/detections/test",
                    "raw_json": json.dumps(
                        {
                            "fixture_file": path.name,
                            "fixture_rule_id": fixture["rule_id"],
                            "fixture_polarity": polarity,
                            "validation_id": run_id,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                }
            )
            events.append(event)
    return events
