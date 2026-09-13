from __future__ import annotations

import json
from datetime import datetime

import pytest

from fusion_correlation.compiler import validate_rule_directory
from fusion_correlation.evaluator import CorrelationEvaluator
from fusion_correlation.fixtures import load_fixture_bundle, validate_fixture_coverage
from fusion_correlation.models import RuleValidationError
from fusion_correlation.runtime_models import InputEnvelope, RuleScope


def test_every_shipped_rule_has_one_strict_positive_and_negative_fixture(
    rules_dir, correlation_fixtures_dir, compiler
):
    rules = validate_rule_directory(rules_dir, compiler).rules
    assert len(tuple(correlation_fixtures_dir.glob("*.json"))) == 4
    assert validate_fixture_coverage(correlation_fixtures_dir, rules) == ()
    for path in correlation_fixtures_dir.glob("*.json"):
        fixture = load_fixture_bundle(path)
        assert fixture["positive"]["expected"]["incident_count"] == 1
        assert fixture["negative"]
        assert all(
            scenario["expected"]["incident_count"] == 0
            for scenario in fixture["negative"]
        )


def test_fixture_duplicate_json_keys_fail_closed(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema":"fusion-correlation-fixture/v1","schema":"duplicate",'
        '"rule_id":"x","positive":{},"negative":[]}',
        encoding="utf-8",
    )
    with pytest.raises(RuleValidationError, match="duplicate fixture JSON key"):
        load_fixture_bundle(path)


def test_fixture_unknown_event_field_is_rejected(
    tmp_path, correlation_fixtures_dir
):
    fixture = json.loads(
        (correlation_fixtures_dir / "fusion-correlation-ssh-bruteforce-success.json").read_text(
            encoding="utf-8"
        )
    )
    fixture["positive"]["inputs"][-1]["values"]["raw_json"] = "secret"
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    with pytest.raises(RuleValidationError, match="raw_json"):
        load_fixture_bundle(path)


def test_fixture_coverage_reports_missing_and_unshipped_rule(
    tmp_path, rules_dir, correlation_fixtures_dir, compiler
):
    rules = validate_rule_directory(rules_dir, compiler).rules
    source = correlation_fixtures_dir / "fusion-correlation-host-suspicious-activity.json"
    fixture = json.loads(source.read_text(encoding="utf-8"))
    fixture["rule_id"] = "fusion-correlation-unshipped"
    (tmp_path / "unshipped.json").write_text(json.dumps(fixture), encoding="utf-8")
    errors = validate_fixture_coverage(tmp_path, rules)
    assert any("missing fixtures for rules" in error for error in errors)
    assert any("unshipped" in error for error in errors)


def test_positive_and_negative_fixtures_execute_against_typed_plans(
    rules_dir, correlation_fixtures_dir, compiler
):
    compiled_by_id = {
        rule.rule_id: rule for rule in validate_rule_directory(rules_dir, compiler).rules
    }
    evaluator = CorrelationEvaluator(technique_to_tactics=compiler.technique_to_tactics)
    for path in sorted(correlation_fixtures_dir.glob("*.json")):
        fixture = load_fixture_bundle(path)
        compiled = compiled_by_id[str(fixture["rule_id"])]
        scope = RuleScope(
            "fixture-engine",
            compiled.rule_id,
            compiled.version,
            compiled.scope_fingerprint,
        )
        positive = _envelopes(fixture["positive"]["inputs"])
        decision = evaluator.evaluate(
            scope, compiled, positive[-1], positive[:-1], now=positive[-1].observed_at
        )
        assert decision.matched, path
        assert decision.incident is not None, path
        expected = fixture["positive"]["expected"]
        assert decision.incident.values["severity"] == expected["severity"], path
        assert decision.incident.values["confidence"] == expected["confidence"], path
        assert tuple(decision.incident.values["mitre_technique_ids"]) == tuple(
            sorted(expected["mitre_technique_ids"])
        ), path
        for negative in fixture["negative"]:
            inputs = _envelopes(negative["inputs"])
            decision = evaluator.evaluate(
                scope, compiled, inputs[-1], inputs[:-1], now=inputs[-1].observed_at
            )
            assert not decision.matched, (path, negative["name"])


def _envelopes(items):
    return tuple(
        InputEnvelope(
            item["input_kind"],
            item["input_id"],
            datetime.fromisoformat(item["occurred_at"]),
            datetime.fromisoformat(item["observed_at"]),
            item["values"],
        )
        for item in items
    )
