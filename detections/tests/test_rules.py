from __future__ import annotations

from conftest import complete_event, load_detection_fixtures
from fusion_detection.compiler import validate_rule_directory


def test_repository_rules_are_valid_and_unique(compiler):
    result = validate_rule_directory(compiler.mapping_path.parent.parent / "rules", compiler)
    assert result.total == 9
    assert result.valid == 9
    assert result.invalid == 0
    assert result.unsupported == 0


def test_every_rule_has_positive_and_negative_fixture(compiled_rules, evaluator):
    rules_by_id = {rule.rule.rule_id: rule for rule in compiled_rules}
    fixtures = load_detection_fixtures()
    assert len(fixtures) == len(rules_by_id)
    fixture_ids = {fixture["rule_id"] for _, fixture in fixtures}
    assert fixture_ids == set(rules_by_id)

    for path, fixture in fixtures:
        rule_id = fixture["rule_id"]
        positive = complete_event(fixture["positive"], f"{path.stem}-positive")
        negative = complete_event(fixture["negative"], f"{path.stem}-negative")
        assert rules_by_id[rule_id].evaluate(positive).matched, path
        assert not rules_by_id[rule_id].evaluate(negative).matched, path
        assert {match.values["rule_id"] for match in evaluator.evaluate(positive)} == {rule_id}, path
        assert evaluator.evaluate(negative) == [], path


def test_cross_source_platform_coverage(compiled_rules, evaluator):
    platforms = set()
    for path, fixture in load_detection_fixtures():
        matches = evaluator.evaluate(complete_event(fixture["positive"], f"coverage-{path.stem}"))
        assert any(match.values["rule_id"] == fixture["rule_id"] for match in matches)
        platforms.add(fixture["positive"]["platform"])
    assert platforms == {"windows", "linux", "network"}


def test_mitre_metadata_is_derived_from_sigma_tags(evaluator):
    fixture = next(value for path, value in load_detection_fixtures() if path.stem == "encoded-powershell")
    detection = next(
        candidate for candidate in evaluator.evaluate(complete_event(fixture["positive"], "mitre-event"))
        if candidate.values["rule_id"] == fixture["rule_id"]
    )
    assert "Execution" in detection.values["mitre_tactics"]
    assert "PowerShell" in detection.values["mitre_techniques"]
    assert "T1059.001" in detection.values["mitre_technique_ids"]
    assert detection.values["severity"] == "high"
