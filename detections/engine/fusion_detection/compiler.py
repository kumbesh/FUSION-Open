"""Fail-closed compiler for Fusion's documented Sigma subset."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from .models import (
    EvaluationResult,
    RuleValidationError,
    SelectionResult,
    SigmaRule,
    UnsupportedSigmaError,
)


ALLOWED_NORMALIZED_FIELDS = frozenset(
    {
        "event_id",
        "event_code",
        "event_category",
        "event_action",
        "event_kind",
        "platform",
        "vendor",
        "product",
        "source_type",
        "host_name",
        "user_name",
        "user_id",
        "process_name",
        "process_path",
        "command_line",
        "parent_process_name",
        "parent_process_id",
        "service_name",
        "outcome",
        "severity",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "destination_hostname",
        "protocol",
        "query_name",
        "domain",
        "signature",
        "signature_id",
        "url",
        "network_direction",
        "ingestion_protocol",
        "ingestion_path",
        "syslog_application",
        "syslog_facility",
    }
)
SUPPORTED_OPERATORS = frozenset({"exact", "contains", "startswith", "endswith", "exists"})
SUPPORTED_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})
RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SELECTION_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")


@dataclass(frozen=True)
class FieldPredicate:
    source_field: str
    normalized_field: str
    operator: str
    values: tuple[Any, ...]

    def evaluate(self, event: Mapping[str, Any]) -> tuple[bool, Any]:
        present = self.normalized_field in event
        actual = event.get(self.normalized_field)
        if self.operator == "exists":
            exists = present and actual not in (None, "")
            return exists is bool(self.values[0]), actual
        if not present or actual is None:
            return False, actual
        if self.operator == "exact":
            return any(_equal(actual, expected) for expected in self.values), actual
        actual_text = str(actual).casefold()
        expected_text = tuple(str(value).casefold() for value in self.values)
        if self.operator == "contains":
            return any(value in actual_text for value in expected_text), actual
        if self.operator == "startswith":
            return any(actual_text.startswith(value) for value in expected_text), actual
        if self.operator == "endswith":
            return any(actual_text.endswith(value) for value in expected_text), actual
        raise AssertionError(f"Unexpected compiled operator: {self.operator}")


@dataclass(frozen=True)
class CompiledSelection:
    name: str
    predicates: tuple[FieldPredicate, ...]

    def evaluate(self, event: Mapping[str, Any]) -> SelectionResult:
        evidence: dict[str, Any] = {}
        for predicate in self.predicates:
            matched, actual = predicate.evaluate(event)
            if not matched:
                return SelectionResult(False)
            evidence[predicate.normalized_field] = actual
        return SelectionResult(True, evidence)


@dataclass(frozen=True)
class ConditionNode:
    kind: str
    value: str = ""
    children: tuple["ConditionNode", ...] = ()

    def evaluate(self, selections: Mapping[str, bool]) -> bool:
        if self.kind == "selection":
            return selections[self.value]
        if self.kind == "and":
            return all(child.evaluate(selections) for child in self.children)
        if self.kind == "or":
            return any(child.evaluate(selections) for child in self.children)
        if self.kind == "not":
            return not self.children[0].evaluate(selections)
        raise AssertionError(f"Unexpected condition node: {self.kind}")

    def describe(self) -> str:
        if self.kind == "selection":
            return self.value
        if self.kind == "not":
            return f"NOT ({self.children[0].describe()})"
        joiner = f" {self.kind.upper()} "
        return "(" + joiner.join(child.describe() for child in self.children) + ")"


@dataclass(frozen=True)
class CompiledRule:
    rule: SigmaRule
    selections: Mapping[str, CompiledSelection]
    condition: ConditionNode
    logsource_predicates: tuple[FieldPredicate, ...]

    def evaluate(self, event: Mapping[str, Any]) -> EvaluationResult:
        for predicate in self.logsource_predicates:
            matched, _ = predicate.evaluate(event)
            if not matched:
                return EvaluationResult(False)
        results = {name: selection.evaluate(event) for name, selection in self.selections.items()}
        truth = {name: result.matched for name, result in results.items()}
        if not self.condition.evaluate(truth):
            return EvaluationResult(False)
        matched_names = tuple(sorted(name for name, result in results.items() if result.matched))
        fields: dict[str, Any] = {}
        for name in matched_names:
            fields.update(results[name].fields)
        return EvaluationResult(True, matched_names, fields)

    def plan(self) -> Mapping[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "logsource_filters": [
                {
                    "field": predicate.normalized_field,
                    "operator": predicate.operator,
                    "values": list(predicate.values),
                }
                for predicate in self.logsource_predicates
            ],
            "condition": self.condition.describe(),
            "selections": {
                name: [
                    {
                        "sigma_field": predicate.source_field,
                        "fusion_field": predicate.normalized_field,
                        "operator": predicate.operator,
                        "values": list(predicate.values),
                    }
                    for predicate in selection.predicates
                ]
                for name, selection in self.selections.items()
            },
        }


@dataclass(frozen=True)
class RuleDirectoryResult:
    total: int
    rules: tuple[CompiledRule, ...]
    errors: tuple[str, ...]
    unsupported: int

    @property
    def valid(self) -> int:
        return len(self.rules)

    @property
    def invalid(self) -> int:
        return len(self.errors)


class SigmaCompiler:
    def __init__(self, mapping_path: Path):
        self.mapping_path = mapping_path
        mapping = _load_yaml(mapping_path)
        if not isinstance(mapping, dict):
            raise RuleValidationError(f"Field mapping must be a YAML mapping: {mapping_path}")
        raw_fields = mapping.get("fields")
        if not isinstance(raw_fields, dict) or not raw_fields:
            raise RuleValidationError(f"Field mapping has no fields: {mapping_path}")
        self.fields: dict[str, str] = {}
        self.fields_casefold: dict[str, str] = {}
        for alias, normalized in raw_fields.items():
            if not isinstance(alias, str) or not isinstance(normalized, str):
                raise RuleValidationError("Sigma field mappings must use string names")
            if normalized not in ALLOWED_NORMALIZED_FIELDS:
                raise RuleValidationError(f"Mapping targets unsupported Fusion field: {normalized}")
            self.fields[alias] = normalized
            self.fields_casefold[alias.casefold()] = normalized
        self.logsource = mapping.get("logsource", {})
        if not isinstance(self.logsource, dict):
            raise RuleValidationError("logsource mapping must be a mapping")

    def load_rule(self, path: Path) -> CompiledRule:
        raw = _load_yaml(path)
        if not isinstance(raw, dict):
            raise RuleValidationError("rule root must be a YAML mapping")
        rule = self._parse_metadata(raw, path)
        selections = self._compile_selections(rule.detection)
        condition_text = rule.detection.get("condition")
        if not isinstance(condition_text, str) or not condition_text.strip():
            raise RuleValidationError("detection.condition must be a non-empty string")
        condition = ConditionParser(condition_text, tuple(selections)).parse()
        logsource_predicates = self._compile_logsource(rule.logsource)
        return CompiledRule(rule, selections, condition, logsource_predicates)

    def _parse_metadata(self, raw: Mapping[str, Any], path: Path) -> SigmaRule:
        rule_id = raw.get("id")
        title = raw.get("title")
        detection = raw.get("detection")
        logsource = raw.get("logsource")
        if not isinstance(rule_id, str) or not RULE_ID_PATTERN.fullmatch(rule_id):
            raise RuleValidationError("id must be 1-128 safe identifier characters")
        if not isinstance(title, str) or not title.strip():
            raise RuleValidationError("title must be a non-empty string")
        if not isinstance(detection, dict):
            raise RuleValidationError("detection must be a mapping")
        if not isinstance(logsource, dict) or not logsource:
            raise RuleValidationError("logsource must be a non-empty mapping")
        level = str(raw.get("level", "medium")).casefold()
        if level not in SUPPORTED_LEVELS:
            raise RuleValidationError(f"unsupported level: {level}")
        tags = _string_tuple(raw.get("tags", []), "tags")
        references = _string_tuple(raw.get("references", []), "references")
        supported_root = {
            "title", "id", "status", "description", "references", "author", "date",
            "modified", "tags", "logsource", "detection", "falsepositives", "level",
        }
        unsupported_keys = sorted(set(raw) - supported_root)
        if unsupported_keys:
            raise UnsupportedSigmaError(f"unsupported root keys: {', '.join(unsupported_keys)}")
        return SigmaRule(
            rule_id=rule_id,
            title=title.strip(),
            description=str(raw.get("description", "")),
            level=level,
            tags=tags,
            author=str(raw.get("author", "")),
            date=str(raw.get("date", "")),
            modified=str(raw.get("modified", "")),
            references=references,
            logsource={str(key): str(value) for key, value in logsource.items()},
            detection=detection,
            path=path,
        )

    def _compile_selections(self, detection: Mapping[str, Any]) -> Mapping[str, CompiledSelection]:
        unsupported = set(detection) & {"timeframe"}
        if unsupported:
            raise UnsupportedSigmaError("timeframe/correlation constructs are not supported in v0.5")
        selections: dict[str, CompiledSelection] = {}
        for name, body in detection.items():
            if name == "condition":
                continue
            if not isinstance(name, str) or not SELECTION_NAME_PATTERN.fullmatch(name):
                raise RuleValidationError(f"invalid selection name: {name!r}")
            if not isinstance(body, dict) or not body:
                raise UnsupportedSigmaError(f"selection {name!r} must be a non-empty field mapping")
            predicates = tuple(self._compile_field(key, value) for key, value in body.items())
            selections[name] = CompiledSelection(name, predicates)
        if not selections:
            raise RuleValidationError("detection must define at least one selection")
        return selections

    def _compile_field(self, raw_key: Any, raw_value: Any) -> FieldPredicate:
        if not isinstance(raw_key, str):
            raise RuleValidationError("selection field names must be strings")
        parts = raw_key.split("|")
        if len(parts) > 2:
            raise UnsupportedSigmaError(f"unsupported modifier chain: {raw_key}")
        alias = parts[0]
        operator = parts[1].casefold() if len(parts) == 2 else "exact"
        if operator not in SUPPORTED_OPERATORS:
            raise UnsupportedSigmaError(f"unsupported field operator: {operator}")
        normalized = self.fields_casefold.get(alias.casefold())
        if normalized is None:
            raise RuleValidationError(f"unsupported Sigma field: {alias}")
        values = tuple(raw_value) if isinstance(raw_value, list) else (raw_value,)
        if not values:
            raise RuleValidationError(f"{raw_key} cannot use an empty value list")
        if operator == "exists":
            if len(values) != 1 or not isinstance(values[0], bool):
                raise RuleValidationError(f"{raw_key} requires exactly one boolean value")
        elif operator in {"contains", "startswith", "endswith"}:
            if any(not isinstance(value, str) or not value for value in values):
                raise RuleValidationError(f"{raw_key} requires non-empty string values")
        elif any(value is None or isinstance(value, (dict, list)) for value in values):
            raise RuleValidationError(f"{raw_key} contains an unsupported exact-match value")
        if operator != "exists" and any(
            isinstance(value, str) and ("*" in value or "?" in value)
            for value in values
        ):
            raise UnsupportedSigmaError(
                f"{raw_key} uses Sigma wildcards; use an explicit contains, startswith, or endswith modifier"
            )
        return FieldPredicate(alias, normalized, operator, values)

    def _compile_logsource(self, logsource: Mapping[str, str]) -> tuple[FieldPredicate, ...]:
        predicates: list[FieldPredicate] = []
        for dimension, value in logsource.items():
            dimension_map = self.logsource.get(dimension)
            if not isinstance(dimension_map, dict):
                raise UnsupportedSigmaError(f"unsupported logsource dimension: {dimension}")
            filter_map = dimension_map.get(value)
            if not isinstance(filter_map, dict):
                raise UnsupportedSigmaError(f"unsupported logsource {dimension}: {value}")
            for normalized, expected in filter_map.items():
                if normalized not in ALLOWED_NORMALIZED_FIELDS:
                    raise RuleValidationError(f"unsafe logsource target field: {normalized}")
                values = tuple(expected) if isinstance(expected, list) else (expected,)
                predicates.append(FieldPredicate(f"logsource.{dimension}", normalized, "exact", values))
        return tuple(predicates)


class ConditionParser:
    _token = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_-]*\*?|[0-9]+)")

    def __init__(self, expression: str, selection_names: tuple[str, ...]):
        if len(expression) > 512:
            raise RuleValidationError("condition exceeds 512 characters")
        self.expression = expression
        self.selection_names = selection_names
        self.tokens = self._tokenize(expression)
        self.index = 0

    def parse(self) -> ConditionNode:
        if not self.tokens:
            raise RuleValidationError("condition is empty")
        node = self._parse_or()
        if self.index != len(self.tokens):
            raise UnsupportedSigmaError(f"unexpected condition token: {self.tokens[self.index]}")
        return node

    def _tokenize(self, expression: str) -> tuple[str, ...]:
        tokens: list[str] = []
        position = 0
        for match in self._token.finditer(expression):
            if expression[position:match.start()].strip():
                raise UnsupportedSigmaError(f"unsupported condition syntax near {expression[position:match.start()]!r}")
            tokens.append(match.group(1))
            position = match.end()
        if expression[position:].strip():
            raise UnsupportedSigmaError(f"unsupported condition syntax near {expression[position:]!r}")
        return tuple(tokens)

    def _parse_or(self) -> ConditionNode:
        children = [self._parse_and()]
        while self._peek("or"):
            self.index += 1
            children.append(self._parse_and())
        return children[0] if len(children) == 1 else ConditionNode("or", children=tuple(children))

    def _parse_and(self) -> ConditionNode:
        children = [self._parse_factor()]
        while self._peek("and"):
            self.index += 1
            children.append(self._parse_factor())
        return children[0] if len(children) == 1 else ConditionNode("and", children=tuple(children))

    def _parse_factor(self) -> ConditionNode:
        if self._peek("not"):
            self.index += 1
            return ConditionNode("not", children=(self._parse_factor(),))
        if self._peek("("):
            self.index += 1
            node = self._parse_or()
            self._expect(")")
            return node
        token = self._take()
        if token.casefold() in {"all", "1"} and self._peek("of"):
            self.index += 1
            pattern = self._take()
            return self._expand_quantifier(token.casefold(), pattern)
        if token.isdigit():
            raise UnsupportedSigmaError("only '1 of' and 'all of' quantifiers are supported")
        if token not in self.selection_names:
            raise RuleValidationError(f"condition references unknown selection: {token}")
        return ConditionNode("selection", value=token)

    def _expand_quantifier(self, quantifier: str, pattern: str) -> ConditionNode:
        if pattern.casefold() == "them":
            names = sorted(self.selection_names)
        elif pattern.endswith("*"):
            prefix = pattern[:-1]
            names = sorted(name for name in self.selection_names if name.startswith(prefix))
        else:
            raise UnsupportedSigmaError("quantifiers require 'them' or a trailing-wildcard selection pattern")
        if not names:
            raise RuleValidationError(f"condition pattern matches no selections: {pattern}")
        kind = "or" if quantifier == "1" else "and"
        nodes = tuple(ConditionNode("selection", value=name) for name in names)
        return nodes[0] if len(nodes) == 1 else ConditionNode(kind, children=nodes)

    def _peek(self, expected: str) -> bool:
        return self.index < len(self.tokens) and self.tokens[self.index].casefold() == expected.casefold()

    def _take(self) -> str:
        if self.index >= len(self.tokens):
            raise RuleValidationError("condition ended unexpectedly")
        token = self.tokens[self.index]
        self.index += 1
        return token

    def _expect(self, expected: str) -> None:
        if not self._peek(expected):
            raise RuleValidationError(f"condition expected {expected!r}")
        self.index += 1


def validate_rule_directory(rules_dir: Path, compiler: SigmaCompiler) -> RuleDirectoryResult:
    paths = sorted((*rules_dir.rglob("*.yml"), *rules_dir.rglob("*.yaml")))
    rules: list[CompiledRule] = []
    errors: list[str] = []
    unsupported = 0
    seen: dict[str, Path] = {}
    for path in paths:
        try:
            compiled = compiler.load_rule(path)
            previous = seen.get(compiled.rule.rule_id)
            if previous is not None:
                raise RuleValidationError(f"duplicate rule id also used by {previous}")
            seen[compiled.rule.rule_id] = path
            rules.append(compiled)
        except UnsupportedSigmaError as exc:
            unsupported += 1
            errors.append(f"{path}: unsupported: {exc}")
        except (RuleValidationError, yaml.YAMLError, OSError) as exc:
            errors.append(f"{path}: invalid: {exc}")
    return RuleDirectoryResult(len(paths), tuple(rules), tuple(errors), unsupported)


def load_rules_strict(rules_dir: Path, mapping_path: Path) -> tuple[CompiledRule, ...]:
    compiler = SigmaCompiler(mapping_path)
    result = validate_rule_directory(rules_dir, compiler)
    if result.errors:
        raise RuleValidationError("rule validation failed:\n" + "\n".join(result.errors))
    if not result.rules:
        raise RuleValidationError(f"no Sigma YAML rules found under {rules_dir}")
    return result.rules


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuleValidationError(f"{name} must be a list of strings")
    return tuple(value)


def _equal(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str) or isinstance(expected, str):
        return str(actual).casefold() == str(expected).casefold()
    return actual == expected
