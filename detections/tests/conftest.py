from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from fusion_detection.compiler import SigmaCompiler, validate_rule_directory
from fusion_detection.evaluator import DetectionEvaluator


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPOSITORY_ROOT / "detections" / "rules"
MAPPING_PATH = REPOSITORY_ROOT / "detections" / "mappings" / "sigma_fields.yml"
MITRE_PATH = REPOSITORY_ROOT / "detections" / "mappings" / "mitre.yml"
FIXTURES_DIR = REPOSITORY_ROOT / "samples" / "detections"


@pytest.fixture(scope="session")
def compiler() -> SigmaCompiler:
    return SigmaCompiler(MAPPING_PATH)


@pytest.fixture(scope="session")
def compiled_rules(compiler: SigmaCompiler):
    result = validate_rule_directory(RULES_DIR, compiler)
    assert not result.errors, result.errors
    return result.rules


@pytest.fixture(scope="session")
def evaluator(compiled_rules):
    return DetectionEvaluator(compiled_rules, MITRE_PATH)


def load_detection_fixtures() -> list[tuple[Path, dict[str, Any]]]:
    fixtures = []
    for path in sorted(FIXTURES_DIR.rglob("*.json")):
        fixtures.append((path, json.loads(path.read_text(encoding="utf-8"))))
    return fixtures


def complete_event(event: dict[str, Any], uid: str) -> dict[str, Any]:
    return {
        "event_uid": uid,
        "event_time": datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
        "source_event_id": uid,
        **event,
    }
