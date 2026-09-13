"""Strict offline loader for bounded correlation rule fixture bundles."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .compiler import DETECTION_FIELDS, EVENT_FIELDS
from .models import CompiledRule, RuleValidationError

FIXTURE_SCHEMA = "fusion-correlation-fixture/v1"
MAX_FIXTURE_BYTES = 65_536
_INPUT_KEYS = {"input_kind", "input_id", "occurred_at", "observed_at", "values"}
_SCENARIO_KEYS = {"name", "inputs", "expected"}
_EXPECTED_KEYS = {
    "incident_count",
    "severity",
    "confidence",
    "mitre_technique_ids",
}
_DETECTION_EXTRA_FIELDS = {"mitre_tactic_ids", "mitre_technique_ids"}


def load_fixture_bundle(path: Path) -> Mapping[str, Any]:
    data = path.read_bytes()
    if not data or len(data) > MAX_FIXTURE_BYTES:
        raise RuleValidationError(
            f"fixture must contain 1-{MAX_FIXTURE_BYTES} bytes: {path}"
        )
    try:
        raw = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuleValidationError(f"invalid fixture JSON {path}: {exc}") from exc
    root = _mapping(raw, "fixture root")
    _exact_keys(root, {"schema", "rule_id", "positive", "negative"}, "fixture root")
    if root["schema"] != FIXTURE_SCHEMA:
        raise RuleValidationError(f"fixture schema must be exactly {FIXTURE_SCHEMA}")
    if not isinstance(root["rule_id"], str) or not root["rule_id"]:
        raise RuleValidationError("fixture rule_id must be a nonblank string")
    _validate_scenario(root["positive"], "positive", expected_count=1)
    negative = root["negative"]
    if not isinstance(negative, list) or not negative:
        raise RuleValidationError("fixture negative must be a non-empty scenario list")
    for index, scenario in enumerate(negative):
        _validate_scenario(scenario, f"negative[{index}]", expected_count=0)
    return root


def validate_fixture_coverage(
    fixtures_dir: Path, rules: Iterable[CompiledRule]
) -> tuple[str, ...]:
    expected = {rule.rule_id for rule in rules}
    observed: dict[str, Path] = {}
    errors: list[str] = []
    if not fixtures_dir.is_dir():
        return (f"{fixtures_dir}: fixture directory does not exist",)
    paths = sorted(fixtures_dir.glob("*.json"))
    for path in paths:
        try:
            fixture = load_fixture_bundle(path)
            rule_id = str(fixture["rule_id"])
            if rule_id in observed:
                raise RuleValidationError(
                    f"duplicate fixture rule_id also used by {observed[rule_id]}"
                )
            observed[rule_id] = path
        except (RuleValidationError, OSError) as exc:
            errors.append(f"{path}: {exc}")
    missing = sorted(expected - set(observed))
    unexpected = sorted(set(observed) - expected)
    if missing:
        errors.append("missing fixtures for rules: " + ", ".join(missing))
    if unexpected:
        errors.append("fixtures reference unshipped rules: " + ", ".join(unexpected))
    return tuple(errors)


def _validate_scenario(raw: Any, location: str, *, expected_count: int) -> None:
    scenario = _mapping(raw, location)
    _exact_keys(scenario, _SCENARIO_KEYS, location)
    if not isinstance(scenario["name"], str) or not scenario["name"].strip():
        raise RuleValidationError(f"{location}.name must be nonblank")
    inputs = scenario["inputs"]
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 1_000:
        raise RuleValidationError(f"{location}.inputs must contain 1-1000 inputs")
    tagged: set[tuple[str, str]] = set()
    for index, raw_input in enumerate(inputs):
        item = _mapping(raw_input, f"{location}.inputs[{index}]")
        _exact_keys(item, _INPUT_KEYS, f"{location}.inputs[{index}]")
        kind = item["input_kind"]
        input_id = item["input_id"]
        if kind not in {"detection", "event"}:
            raise RuleValidationError(f"{location}.inputs[{index}].input_kind is invalid")
        if not isinstance(input_id, str) or not input_id.strip():
            raise RuleValidationError(f"{location}.inputs[{index}].input_id is blank")
        identity = (kind, input_id)
        if identity in tagged:
            raise RuleValidationError(f"{location} has duplicate tagged input {identity}")
        tagged.add(identity)
        _utc_timestamp(item["occurred_at"], f"{location}.inputs[{index}].occurred_at")
        _utc_timestamp(item["observed_at"], f"{location}.inputs[{index}].observed_at")
        values = _mapping(item["values"], f"{location}.inputs[{index}].values")
        allowed = (
            DETECTION_FIELDS | _DETECTION_EXTRA_FIELDS
            if kind == "detection"
            else EVENT_FIELDS
        )
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise RuleValidationError(
                f"{location}.inputs[{index}].values has unknown fields: {', '.join(unknown)}"
            )
    if expected_count and not any(item["input_kind"] == "detection" for item in inputs):
        raise RuleValidationError(f"{location} positive fixture must include a detection")
    expected = _mapping(scenario["expected"], f"{location}.expected")
    unknown_expected = sorted(set(expected) - _EXPECTED_KEYS)
    if unknown_expected:
        raise RuleValidationError(
            f"{location}.expected has unknown fields: {', '.join(unknown_expected)}"
        )
    if expected.get("incident_count") != expected_count:
        raise RuleValidationError(
            f"{location}.expected.incident_count must be {expected_count}"
        )


def _utc_timestamp(value: Any, location: str) -> datetime:
    if not isinstance(value, str):
        raise RuleValidationError(f"{location} must be an ISO UTC string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RuleValidationError(f"{location} is not an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise RuleValidationError(f"{location} must be UTC")
    if parsed.microsecond % 1_000:
        raise RuleValidationError(f"{location} must use millisecond precision")
    return parsed


def _mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RuleValidationError(f"{location} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], location: str) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        raise RuleValidationError(f"{location} has unknown fields: {', '.join(unknown)}")
    if missing:
        raise RuleValidationError(f"{location} is missing fields: {', '.join(missing)}")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuleValidationError(f"duplicate fixture JSON key: {key}")
        result[key] = value
    return result
