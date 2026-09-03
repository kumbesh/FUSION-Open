from __future__ import annotations

from pathlib import Path

import pytest

from fusion_detection.compiler import ConditionParser, SigmaCompiler, validate_rule_directory
from fusion_detection.models import RuleValidationError, UnsupportedSigmaError


def _write_rule(path: Path, rule_id: str, detection: str, *, field: str = "CommandLine") -> None:
    path.write_text(
        f"""title: Test rule
id: {rule_id}
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    {field}: {detection}
  condition: selection
level: medium
""",
        encoding="utf-8",
    )


def test_invalid_yaml_is_reported(tmp_path, compiler):
    (tmp_path / "invalid.yml").write_text("title: [unterminated", encoding="utf-8")
    result = validate_rule_directory(tmp_path, compiler)
    assert result.total == 1
    assert result.invalid == 1


def test_duplicate_rule_ids_are_reported(tmp_path, compiler):
    _write_rule(tmp_path / "one.yml", "duplicate-id", "one")
    _write_rule(tmp_path / "two.yml", "duplicate-id", "two")
    result = validate_rule_directory(tmp_path, compiler)
    assert result.total == 2
    assert result.valid == 1
    assert result.invalid == 1
    assert "duplicate rule id" in result.errors[0]


def test_unsupported_correlation_construct_fails(tmp_path, compiler):
    path = tmp_path / "unsupported.yml"
    path.write_text(
        """title: Unsupported
id: unsupported-correlation
logsource:
  product: windows
detection:
  selection:
    Image: cmd.exe
  timeframe: 5m
  condition: selection | count() > 3
level: medium
""",
        encoding="utf-8",
    )
    with pytest.raises(UnsupportedSigmaError):
        compiler.load_rule(path)


def test_arbitrary_sql_field_is_rejected(tmp_path, compiler):
    path = tmp_path / "unsafe-field.yml"
    _write_rule(path, "unsafe-field", "anything", field="Image); DROP TABLE fusion.sysmon_events; --")
    with pytest.raises(RuleValidationError, match="unsupported Sigma field"):
        compiler.load_rule(path)


def test_unsafe_looking_value_is_literal_not_sql(tmp_path, compiler):
    path = tmp_path / "literal.yml"
    _write_rule(path, "literal-value", "\"' OR 1=1 --\"")
    rule = compiler.load_rule(path)
    base = {"platform": "windows", "source_type": "windows_sysmon"}
    assert rule.evaluate({**base, "command_line": "' OR 1=1 --"}).matched
    assert not rule.evaluate({**base, "command_line": "normal command"}).matched


@pytest.mark.parametrize(
    ("condition", "truth", "expected"),
    [
        ("a and b", {"a": True, "b": True, "filter": False}, True),
        ("a or b", {"a": False, "b": True, "filter": False}, True),
        ("a and not filter", {"a": True, "b": False, "filter": False}, True),
        ("1 of sel_*", {"sel_a": False, "sel_b": True}, True),
        ("all of sel_*", {"sel_a": True, "sel_b": False}, False),
    ],
)
def test_condition_operators(condition, truth, expected):
    names = tuple(truth)
    assert ConditionParser(condition, names).parse().evaluate(truth) is expected


def test_only_one_of_quantifier_is_supported():
    with pytest.raises(UnsupportedSigmaError, match="only '1 of'"):
        ConditionParser("2 of sel_*", ("sel_a", "sel_b")).parse()


def test_unsupported_modifier_chain_fails(tmp_path, compiler):
    path = tmp_path / "modifier.yml"
    _write_rule(path, "bad-modifier", "test", field="Image|contains|all")
    with pytest.raises(UnsupportedSigmaError, match="modifier chain"):
        compiler.load_rule(path)


def test_sigma_wildcards_are_rejected_instead_of_approximated(tmp_path, compiler):
    path = tmp_path / "wildcard.yml"
    _write_rule(path, "unsupported-wildcard", "'*.example.test'", field="QueryName")
    with pytest.raises(UnsupportedSigmaError, match="wildcards"):
        compiler.load_rule(path)
