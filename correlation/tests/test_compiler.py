from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

import fusion_correlation.compiler as compiler_module
from fusion_correlation.compiler import (
    MAX_DOCUMENT_BYTES,
    CorrelationCompiler,
    load_rules_strict,
    validate_rule_directory,
)
from fusion_correlation.models import RuleValidationError, UnsupportedCorrelationError

BASE_RULE = """\
schema: fusion-correlation/v1
id: fusion-correlation-test-rule
version: 1
status: experimental
title: Test correlation
description: A bounded test rule.
window: 10m
allowed_lateness: 15m
group_by: [host_name]
selectors:
  signal:
    source: detection
    where:
      - {field: platform, op: eq, value: windows}
      - {field: severity, op: in, value: [medium, high]}
correlate:
  type: threshold
  selector: signal
  min_count: 2
  distinct_by: rule_id
  min_distinct: 2
incident:
  type: test_activity
  title: "Test activity on {host_name}"
  severity: medium
  confidence: 70
  primary: {host: host_name}
mitre: {tactic_ids: [], technique_ids: []}
false_positives:
  - Controlled test activity.
"""


def _compile(tmp_path: Path, compiler: CorrelationCompiler, text: str = BASE_RULE):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "rule.yml"
    path.write_text(text, encoding="utf-8")
    return compiler.load_rule(path)


def _dump(tmp_path: Path, compiler: CorrelationCompiler, raw: dict):
    return _compile(tmp_path, compiler, yaml.safe_dump(raw, sort_keys=False))


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("sql: SELECT * FROM fusion.incidents\n", "unknown fields: sql"),
        ("query: arbitrary\n", "unknown fields: query"),
        ("condition: count() > 2\n", "unknown fields: condition"),
        ("code: __import__('os')\n", "unknown fields: code"),
    ],
)
def test_executable_or_free_form_root_constructs_fail_closed(
    tmp_path, compiler, extra, message
):
    with pytest.raises(UnsupportedCorrelationError, match=message):
        _compile(tmp_path, compiler, BASE_RULE + extra)


def test_duplicate_yaml_key_is_rejected(tmp_path, compiler):
    text = BASE_RULE.replace(
        "schema: fusion-correlation/v1",
        "schema: fusion-correlation/v1\nschema: fusion-correlation/v1",
    )
    with pytest.raises(RuleValidationError, match="duplicate YAML mapping key"):
        _compile(tmp_path, compiler, text)


@pytest.mark.parametrize(
    "text",
    [
        BASE_RULE.replace("group_by: [host_name]", "group_by: &group [host_name]"),
        BASE_RULE.replace("group_by: [host_name]", "group_by: *group"),
        BASE_RULE.replace("title: Test correlation", "title: !unsafe Test correlation"),
        "%YAML 1.2\n---\n" + BASE_RULE,
    ],
)
def test_yaml_anchors_aliases_tags_and_directives_are_rejected(tmp_path, compiler, text):
    with pytest.raises(RuleValidationError, match="aliases, anchors, tags, and directives"):
        _compile(tmp_path, compiler, text)


def test_multiple_yaml_documents_are_rejected(tmp_path, compiler):
    with pytest.raises(yaml.YAMLError):
        _compile(tmp_path, compiler, BASE_RULE + "\n---\n{}\n")


def test_oversized_document_is_rejected_before_parsing(tmp_path, compiler):
    path = tmp_path / "huge.yml"
    path.write_bytes(b"#" * (MAX_DOCUMENT_BYTES + 1))
    with pytest.raises(RuleValidationError, match="bytes"):
        compiler.load_rule(path)


def test_unknown_nested_key_is_rejected(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["incident"]["risk_formula"] = "severity * 10"
    with pytest.raises(UnsupportedCorrelationError, match="risk_formula"):
        _dump(tmp_path, compiler, raw)


@pytest.mark.parametrize("field", ["raw_json", "evidence_json", "command_line", "arbitrary.path"])
def test_unsafe_or_arbitrary_selector_fields_are_rejected(tmp_path, compiler, field):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"][0]["field"] = field
    with pytest.raises(UnsupportedCorrelationError, match="unsupported detection field"):
        _dump(tmp_path, compiler, raw)


@pytest.mark.parametrize("operator", ["regex", "glob", "contains", "not", "gt"])
def test_unknown_or_unbounded_predicate_operators_are_rejected(
    tmp_path, compiler, operator
):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"][0]["op"] = operator
    with pytest.raises(UnsupportedCorrelationError, match="operator"):
        _dump(tmp_path, compiler, raw)


@pytest.mark.parametrize("value", ["win*", "win?ows"])
def test_glob_values_are_rejected_instead_of_approximated(tmp_path, compiler, value):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"][0]["value"] = value
    with pytest.raises(UnsupportedCorrelationError, match="wildcard"):
        _dump(tmp_path, compiler, raw)


@pytest.mark.parametrize("value", ["${HOST}", "$env:HOST", "$HOST", "%HOST%"])
def test_environment_expansion_is_rejected_anywhere(tmp_path, compiler, value):
    raw = yaml.safe_load(BASE_RULE)
    raw["description"] = value
    with pytest.raises(UnsupportedCorrelationError, match="environment expansion"):
        _dump(tmp_path, compiler, raw)


def test_exists_cannot_be_used_as_an_unsupported_missing_or_not_operator(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"] = [
        {"field": "host_name", "op": "exists", "value": False}
    ]
    with pytest.raises(UnsupportedCorrelationError, match="boolean true"):
        _dump(tmp_path, compiler, raw)


def test_eq_rejects_a_list_and_in_rejects_an_empty_list(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"][0]["value"] = ["windows"]
    with pytest.raises(RuleValidationError, match="eq requires one"):
        _dump(tmp_path, compiler, raw)
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"][1]["value"] = []
    with pytest.raises(RuleValidationError, match="in requires"):
        _dump(tmp_path, compiler, raw)


def test_event_selector_requires_source_and_specific_event_constraint(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"] = {
        "source": "event",
        "where": [{"field": "event_kind", "op": "eq", "value": "event"}],
    }
    with pytest.raises(RuleValidationError, match="source_type"):
        _dump(tmp_path, compiler, raw)
    raw["selectors"]["signal"]["where"].append(
        {"field": "source_type", "op": "eq", "value": "linux_journald"}
    )
    with pytest.raises(RuleValidationError, match="event_category, event_action, or event_code"):
        _dump(tmp_path, compiler, raw)


def test_event_threshold_is_rejected_even_when_selector_is_narrow(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"] = {
        "source": "event",
        "where": [
            {"field": "source_type", "op": "eq", "value": "linux_journald"},
            {"field": "event_category", "op": "eq", "value": "authentication"},
        ],
    }
    with pytest.raises(UnsupportedCorrelationError, match="event-backed thresholds"):
        _dump(tmp_path, compiler, raw)


def test_sequence_without_a_detection_stage_is_rejected(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    event_body = {
        "source": "event",
        "where": [
            {"field": "source_type", "op": "eq", "value": "linux_journald"},
            {"field": "event_category", "op": "eq", "value": "authentication"},
        ],
    }
    raw["selectors"] = {"first": event_body, "second": copy.deepcopy(event_body)}
    raw["correlate"] = {
        "type": "sequence",
        "stages": [
            {"selector": "first", "min_count": 1},
            {"selector": "second", "min_count": 1},
        ],
    }
    with pytest.raises(UnsupportedCorrelationError, match="detection stage"):
        _dump(tmp_path, compiler, raw)


def test_join_without_a_detection_input_is_rejected(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"] = {
        "left": {
            "source": "event",
            "where": [
                {"field": "source_type", "op": "eq", "value": "linux_journald"},
                {"field": "event_category", "op": "eq", "value": "authentication"},
            ],
        },
        "right": {
            "source": "event",
            "where": [
                {"field": "source_type", "op": "eq", "value": "windows_sysmon"},
                {"field": "event_code", "op": "eq", "value": "3"},
            ],
        },
    }
    raw["correlate"] = {
        "type": "join",
        "require": ["left", "right"],
        "relations": [
            {"left": "left.host_name", "op": "equals", "right": "right.host_name"}
        ],
    }
    with pytest.raises(UnsupportedCorrelationError, match="detection input"):
        _dump(tmp_path, compiler, raw)


def test_ownership_join_cannot_be_weakened_to_string_equality(
    tmp_path, compiler, rules_dir
):
    raw = yaml.safe_load((rules_dir / "suricata-endpoint.yml").read_text(encoding="utf-8"))
    raw["correlate"]["relations"] = [raw["correlate"]["relations"][0]]
    with pytest.raises(UnsupportedCorrelationError, match="intersect"):
        _dump(tmp_path, compiler, raw)


def test_ownership_join_requires_direction_safe_initiated_sysmon_event(
    tmp_path, compiler, rules_dir
):
    raw = yaml.safe_load((rules_dir / "suricata-endpoint.yml").read_text(encoding="utf-8"))
    initiated = raw["selectors"]["endpoint_identity"]["where"][-1]
    initiated["value"] = 0
    with pytest.raises(UnsupportedCorrelationError, match="initiated Windows Sysmon"):
        _dump(tmp_path, compiler, raw)


def test_symmetric_join_relation_order_compiles_to_one_fingerprint(
    tmp_path, compiler, rules_dir
):
    raw = yaml.safe_load((rules_dir / "suricata-endpoint.yml").read_text(encoding="utf-8"))
    baseline = _dump(tmp_path / "baseline", compiler, raw)
    for relation in raw["correlate"]["relations"]:
        relation["left"], relation["right"] = relation["right"], relation["left"]
    reversed_sides = _dump(tmp_path / "reversed", compiler, raw)
    assert baseline.scope_fingerprint == reversed_sides.scope_fingerprint


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("window", "0s", "window must be between"),
        ("window", "3601s", "window must be between"),
        ("window", "1.5m", "integer followed"),
        ("allowed_lateness", "25h", "allowed_lateness must be between"),
        ("allowed_lateness", "-1s", "integer followed"),
    ],
)
def test_duration_bounds_are_fail_closed(tmp_path, compiler, field, value, message):
    raw = yaml.safe_load(BASE_RULE)
    raw[field] = value
    with pytest.raises(RuleValidationError, match=message):
        _dump(tmp_path, compiler, raw)


def test_exact_time_bounds_are_accepted(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["window"] = "1h"
    raw["allowed_lateness"] = "24h"
    compiled = _dump(tmp_path, compiler, raw)
    assert compiled.rule.window.milliseconds == 3_600_000
    assert compiled.rule.allowed_lateness.milliseconds == 86_400_000


def test_minimum_window_and_zero_lateness_are_accepted(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["window"] = "1s"
    raw["allowed_lateness"] = "0s"
    compiled = _dump(tmp_path, compiler, raw)
    assert compiled.rule.window.milliseconds == 1_000
    assert compiled.rule.allowed_lateness.milliseconds == 0


@pytest.mark.parametrize("count", [1, 1001])
def test_threshold_count_bounds_are_enforced(tmp_path, compiler, count):
    raw = yaml.safe_load(BASE_RULE)
    raw["correlate"]["min_count"] = count
    raw["correlate"]["min_distinct"] = 2 if count != 1 else 1
    with pytest.raises(RuleValidationError, match="min_count"):
        _dump(tmp_path, compiler, raw)


@pytest.mark.parametrize("version", [0, -1, True, "1"])
def test_rule_version_must_be_a_positive_integer(tmp_path, compiler, version):
    raw = yaml.safe_load(BASE_RULE)
    raw["version"] = version
    with pytest.raises(RuleValidationError, match="version must be an integer"):
        _dump(tmp_path, compiler, raw)


def test_detection_rule_version_predicate_preserves_source_string(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"] = [
        {"field": "rule_version", "op": "eq", "value": "1.2.0"},
    ]
    compiled = _dump(tmp_path, compiler, raw)
    assert compiled.rule.selectors[0].predicates[0].value == "1.2.0"


@pytest.mark.parametrize("value", [1, True, "", "*"])
def test_detection_rule_version_predicate_rejects_non_string_or_unsafe_values(
    tmp_path, compiler, value
):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"] = [
        {"field": "rule_version", "op": "eq", "value": value},
    ]
    with pytest.raises((RuleValidationError, UnsupportedCorrelationError)):
        _dump(tmp_path, compiler, raw)


@pytest.mark.parametrize("rule_id", ["Fusion-Correlation-Test", "fusion_correlation_test", "fusi\N{LATIN SMALL LETTER O WITH DIAERESIS}n-rule"])
def test_rule_id_must_be_a_stable_ascii_lowercase_slug(
    tmp_path, compiler, rule_id
):
    raw = yaml.safe_load(BASE_RULE)
    raw["id"] = rule_id
    with pytest.raises(RuleValidationError, match="ASCII lowercase slug"):
        _dump(tmp_path, compiler, raw)


def test_selector_predicate_group_stage_and_relation_bounds(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"] = {
        f"signal_{index}": copy.deepcopy(raw["selectors"]["signal"])
        for index in range(9)
    }
    with pytest.raises(RuleValidationError, match="selectors must contain"):
        _dump(tmp_path / "selectors", compiler, raw)

    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"] = [
        {"field": "host_name", "op": "eq", "value": f"host-{index}"}
        for index in range(17)
    ]
    with pytest.raises(RuleValidationError, match="where must contain"):
        _dump(tmp_path / "predicates", compiler, raw)

    raw = yaml.safe_load(BASE_RULE)
    raw["group_by"] = [
        "host_name",
        "user_name",
        "platform",
        "source_ip",
        "destination_ip",
    ]
    with pytest.raises(RuleValidationError, match="group_by must contain"):
        _dump(tmp_path / "groups", compiler, raw)

    raw = yaml.safe_load(BASE_RULE)
    raw["correlate"] = {
        "type": "sequence",
        "stages": [
            {"selector": "signal", "min_count": 1} for _ in range(5)
        ],
    }
    with pytest.raises(RuleValidationError, match="sequence.stages must contain"):
        _dump(tmp_path / "stages", compiler, raw)

    raw = yaml.safe_load(BASE_RULE)
    raw["correlate"] = {
        "type": "sequence",
        "stages": [
            {"selector": "signal", "min_count": 101},
            {"selector": "signal", "min_count": 1},
        ],
    }
    with pytest.raises(RuleValidationError, match="min_count"):
        _dump(tmp_path / "stage-count", compiler, raw)

    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["other"] = {
        "source": "detection",
        "where": [{"field": "platform", "op": "eq", "value": "windows"}],
    }
    raw["correlate"] = {
        "type": "join",
        "require": ["signal", "other"],
        "relations": [
            {"left": "signal.host_name", "op": "equals", "right": "other.host_name"}
            for _ in range(5)
        ],
    }
    with pytest.raises(RuleValidationError, match="join.relations must contain"):
        _dump(tmp_path / "relations", compiler, raw)


def test_duplicate_in_values_and_predicates_are_rejected(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"][1]["value"] = ["medium", "medium"]
    with pytest.raises(RuleValidationError, match="duplicate values"):
        _dump(tmp_path / "values", compiler, raw)
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["signal"]["where"].append(
        dict(raw["selectors"]["signal"]["where"][0])
    )
    with pytest.raises(RuleValidationError, match="duplicate values"):
        _dump(tmp_path / "predicates", compiler, raw)


def test_unused_selector_and_shared_ip_outside_ownership_join_are_rejected(
    tmp_path, compiler
):
    raw = yaml.safe_load(BASE_RULE)
    raw["selectors"]["unused"] = {
        "source": "detection",
        "where": [{"field": "severity", "op": "eq", "value": "high"}],
    }
    with pytest.raises(RuleValidationError, match="unreferenced selectors"):
        _dump(tmp_path / "unused", compiler, raw)
    raw = yaml.safe_load(BASE_RULE)
    raw["group_by"] = ["shared_ip"]
    raw["incident"]["title"] = "Test activity"
    with pytest.raises(UnsupportedCorrelationError, match="ownership join"):
        _dump(tmp_path / "shared-ip", compiler, raw)


def test_title_placeholders_are_simple_and_entity_scoped(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    raw["incident"]["title"] = "Test on {user_name}"
    with pytest.raises(UnsupportedCorrelationError, match="unavailable placeholders"):
        _dump(tmp_path, compiler, raw)
    raw["incident"]["title"] = "Test on {host_name!r}"
    with pytest.raises(UnsupportedCorrelationError, match="formatting"):
        _dump(tmp_path, compiler, raw)


def test_duplicate_rule_ids_fail_directory_validation(tmp_path, compiler):
    (tmp_path / "one.yml").write_text(BASE_RULE, encoding="utf-8")
    (tmp_path / "two.yml").write_text(BASE_RULE.replace("version: 1", "version: 2"), encoding="utf-8")
    result = validate_rule_directory(tmp_path, compiler)
    assert result.total == 2
    assert result.valid == 1
    assert result.invalid == 1
    assert "duplicate rule id/version scope" in result.errors[0]
    with pytest.raises(RuleValidationError, match="validation failed"):
        load_rules_strict(tmp_path, compiler)


def test_fingerprint_excludes_version_prose_status_path_and_yaml_order(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    baseline = _dump(tmp_path / "base", compiler, raw)
    variant = yaml.safe_load(BASE_RULE)
    variant["version"] = 9
    variant["status"] = "stable"
    variant["title"] = "Renamed metadata"
    variant["description"] = "Different review prose."
    variant["false_positives"] = ["Different explanatory prose."]
    variant["selectors"]["signal"]["where"].reverse()
    variant = {key: variant[key] for key in reversed(tuple(variant))}
    changed = _dump(tmp_path / "variant", compiler, variant)
    assert baseline.scope_fingerprint == changed.scope_fingerprint


def test_semantic_change_changes_fingerprint(tmp_path, compiler):
    raw = yaml.safe_load(BASE_RULE)
    baseline = _dump(tmp_path / "base", compiler, raw)
    raw["incident"]["confidence"] = 71
    changed = _dump(tmp_path / "changed", compiler, raw)
    assert baseline.scope_fingerprint != changed.scope_fingerprint


def test_exact_mapping_bytes_participate_in_fingerprint(
    tmp_path, mitre_mapping_path
):
    mapping_a = tmp_path / "a.yml"
    mapping_b = tmp_path / "b.yml"
    data = mitre_mapping_path.read_bytes()
    mapping_a.write_bytes(data)
    mapping_b.write_bytes(data + b"# audit-only byte change\n")
    rule_a = _compile(tmp_path / "rule-a", CorrelationCompiler(mapping_a))
    rule_b = _compile(tmp_path / "rule-b", CorrelationCompiler(mapping_b))
    assert rule_a.scope_fingerprint != rule_b.scope_fingerprint
    assert rule_a.plan()["mitre_technique_tactic_mapping"]["bytes_sha256"] != rule_b.plan()[
        "mitre_technique_tactic_mapping"
    ]["bytes_sha256"]


def test_identity_normalization_semantics_participate_in_fingerprint(
    tmp_path, compiler, monkeypatch
):
    baseline = _compile(tmp_path / "baseline", compiler, BASE_RULE)
    changed_contract = dict(compiler_module.IDENTITY_NORMALIZATION_CONTRACT)
    changed_contract["hostname"] = "reviewed-future-host-contract"
    monkeypatch.setattr(
        compiler_module,
        "IDENTITY_NORMALIZATION_CONTRACT",
        changed_contract,
    )

    changed = _compile(tmp_path / "changed", compiler, BASE_RULE)

    assert changed.scope_fingerprint != baseline.scope_fingerprint


def test_rule_technique_must_exist_in_versioned_mapping(
    tmp_path, mitre_mapping_path, rules_dir
):
    mapping = yaml.safe_load(mitre_mapping_path.read_text(encoding="utf-8"))
    del mapping["techniques"]["T1110"]
    mapping_path = tmp_path / "mapping.yml"
    mapping_path.write_text(yaml.safe_dump(mapping, sort_keys=False), encoding="utf-8")
    compiler = CorrelationCompiler(mapping_path)
    with pytest.raises(RuleValidationError, match="T1110"):
        compiler.load_rule(rules_dir / "ssh-bruteforce-success.yml")


def test_invalid_mitre_mapping_fails_before_rules_load(tmp_path):
    mapping_path = tmp_path / "mapping.yml"
    mapping_path.write_text(
        "version: fusion-mitre-technique-tactics-v1\ntechniques:\n  bad: []\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleValidationError, match="invalid MITRE mapping technique"):
        CorrelationCompiler(mapping_path)
