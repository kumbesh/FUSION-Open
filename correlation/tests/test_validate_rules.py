from __future__ import annotations

import json

from fusion_correlation.validate_rules import main


def test_validator_cli_reports_four_passes(
    capsys, rules_dir, mitre_mapping_path, correlation_fixtures_dir
):
    result = main(
        [
            str(rules_dir),
            "--mitre-mapping",
            str(mitre_mapping_path),
            "--expected-count",
            "4",
            "--fixtures-dir",
            str(correlation_fixtures_dir),
        ]
    )
    output = capsys.readouterr().out
    assert result == 0
    assert output.count("PASS fusion-correlation-") == 4
    assert "total=4 valid=4 invalid=0" in output


def test_validator_cli_json_is_bounded_and_machine_readable(
    capsys, rules_dir, mitre_mapping_path
):
    result = main(
        [
            str(rules_dir),
            "--mitre-mapping",
            str(mitre_mapping_path),
            "--expected-count",
            "4",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["schema"] == "fusion-correlation-validation/v1"
    assert payload["total"] == payload["valid"] == 4
    assert payload["invalid"] == 0
    assert all(len(rule["scope_fingerprint"]) == 64 for rule in payload["rules"])


def test_validator_cli_fails_expected_count_without_external_effects(
    capsys, rules_dir, mitre_mapping_path
):
    result = main(
        [
            str(rules_dir),
            "--mitre-mapping",
            str(mitre_mapping_path),
            "--expected-count",
            "5",
        ]
    )
    assert result == 1
    assert "expected exactly 5 rules but found 4" in capsys.readouterr().out


def test_validator_cli_reports_malformed_mapping_without_a_traceback(
    capsys, tmp_path, rules_dir
):
    mapping = tmp_path / "malformed-mapping.yml"
    mapping.write_text("version: [\n", encoding="utf-8")

    result = main(
        [
            str(rules_dir),
            "--mitre-mapping",
            str(mapping),
            "--expected-count",
            "4",
        ]
    )

    output = capsys.readouterr().out
    assert result == 1
    assert "FAIL" in output
    assert "expected exactly 4 rules but found 0" in output
