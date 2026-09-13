"""Fail-closed compiler for the frozen ``fusion-correlation/v1`` subset.

Rules compile to typed, bounded plans.  This module deliberately emits no SQL:
runtime query shapes, identifiers, ordering, and limits remain trusted code.
"""

from __future__ import annotations

import hashlib
import json
import re
import string
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, ScalarNode
from yaml.tokens import AliasToken, AnchorToken, DirectiveToken, TagToken

from .identity import IDENTITY_NORMALIZATION_CONTRACT
from .models import (
    CompiledRule,
    CorrelationCondition,
    CorrelationRule,
    Duration,
    IncidentSpec,
    JoinCondition,
    JoinRelation,
    MitreSpec,
    Predicate,
    RuleDirectoryResult,
    RuleValidationError,
    Selector,
    SequenceCondition,
    SequenceStage,
    ThresholdCondition,
    UnsupportedCorrelationError,
)

SCHEMA = "fusion-correlation/v1"
COMPILER_CONTRACT_VERSION = "fusion-correlation-compiler-v1"
NORMALIZED_FIELD_CONTRACT_VERSION = "fusion-normalized-fields-v06-1"

MAX_DOCUMENT_BYTES = 65_536
MAX_NESTING_DEPTH = 12
MAX_TOTAL_NODES = 512
MAX_COLLECTION_ITEMS = 64
MAX_STRING_LENGTH = 4_096
MAX_SELECTORS = 8
MAX_PREDICATES_PER_SELECTOR = 16
MAX_IN_VALUES = 32
MAX_GROUP_KEYS = 4
MAX_WINDOW_MILLISECONDS = 60 * 60 * 1_000
MAX_LATENESS_MILLISECONDS = 24 * 60 * 60 * 1_000
MAX_THRESHOLD_INPUTS = 1_000
MAX_SEQUENCE_STAGES = 4
MAX_STAGE_COUNT = 100
MAX_JOIN_RELATIONS = 4

DETECTION_FIELDS = frozenset(
    {
        "rule_id",
        "rule_version",
        "severity",
        "platform",
        "vendor",
        "product",
        "source_type",
        "host_name",
        "user_name",
        "source_ip",
        "destination_ip",
        "protocol",
        "signature_id",
    }
)
EVENT_FIELDS = frozenset(
    {
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
        "service_name",
        "outcome",
        "source_ip",
        "destination_ip",
        "protocol",
        "initiated",
    }
)
GROUP_FIELDS = frozenset(
    {
        "host_name",
        "user_name",
        "platform",
        "source_ip",
        "destination_ip",
        "source_type",
        "rule_id",
        "signature_id",
        "shared_ip",
    }
)
SCALAR_RELATION_FIELDS = frozenset(
    {
        "host_name",
        "user_name",
        "platform",
        "vendor",
        "product",
        "source_type",
        "source_ip",
        "destination_ip",
        "protocol",
    }
)
IP_RELATION_FIELDS = frozenset({"source_ip", "destination_ip"})
SUPPORTED_OPERATORS = frozenset({"eq", "in", "exists"})
SUPPORTED_STATUSES = frozenset({"experimental", "stable", "deprecated"})
SEVERITIES = frozenset({"low", "medium", "high", "critical"})
SEVERITY_RANKS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
PLATFORMS = frozenset({"windows", "linux", "network"})

_RULE_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_SELECTOR_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_INCIDENT_TYPE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SOURCE_TYPE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MITRE_TACTIC = re.compile(r"^TA[0-9]{4}$")
_MITRE_TECHNIQUE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_DURATION = re.compile(r"^(0|[1-9][0-9]*)([smh])$")
_RELATION_ENDPOINT = re.compile(r"^([a-z][a-z0-9_]{0,63})\.([a-z][a-z0-9_]{0,63})$")
_PLACEHOLDER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ENV_EXPANSION = re.compile(
    r"\$\{[^}]+\}|\$env:[A-Za-z_][A-Za-z0-9_]*|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%",
    re.IGNORECASE,
)

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "id",
        "version",
        "status",
        "title",
        "description",
        "window",
        "allowed_lateness",
        "group_by",
        "selectors",
        "correlate",
        "incident",
        "mitre",
        "false_positives",
    }
)


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate/non-string keys and merge keys."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[str, Any]:
        if not isinstance(node, MappingNode):
            raise RuleValidationError("expected a YAML mapping")
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if isinstance(key_node, ScalarNode) and key_node.value == "<<":
                raise RuleValidationError("YAML merge keys are not allowed")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise RuleValidationError("YAML mapping keys must be strings")
            if key in result:
                raise RuleValidationError(f"duplicate YAML mapping key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


class CorrelationCompiler:
    """Parse and compile one strict, bounded Fusion correlation rule."""

    def __init__(self, mitre_mapping_path: Path | None = None) -> None:
        self.mitre_mapping_path = mitre_mapping_path or (
            Path(__file__).resolve().parents[2]
            / "mappings"
            / "mitre-technique-tactics.yml"
        )
        (
            self.mitre_mapping_version,
            self.technique_to_tactics,
            self.mitre_mapping_sha256,
        ) = _load_mitre_mapping(self.mitre_mapping_path)

    def load_rule(self, path: Path) -> CompiledRule:
        raw = _load_yaml_strict(path)
        rule = self._parse_rule(raw, path)
        undeclared = sorted(
            set(rule.mitre.technique_ids) - set(self.technique_to_tactics)
        )
        if undeclared:
            raise RuleValidationError(
                "MITRE technique IDs missing from the versioned tactic mapping: "
                + ", ".join(undeclared)
            )
        semantic_plan = _semantic_plan(
            rule,
            mapping_version=self.mitre_mapping_version,
            mapping_sha256=self.mitre_mapping_sha256,
            technique_to_tactics=self.technique_to_tactics,
        )
        fingerprint = _fingerprint(semantic_plan)
        return CompiledRule(rule, fingerprint, semantic_plan)

    def _parse_rule(self, raw: Any, path: Path) -> CorrelationRule:
        root = _require_mapping(raw, "rule root")
        _require_exact_keys(root, _TOP_LEVEL_KEYS, _TOP_LEVEL_KEYS, "rule root")

        schema = _require_string(root["schema"], "schema", maximum=64)
        if schema != SCHEMA:
            raise UnsupportedCorrelationError(f"schema must be exactly {SCHEMA!r}")

        rule_id = _require_string(root["id"], "id", maximum=128)
        if not rule_id.isascii() or not _RULE_ID.fullmatch(rule_id):
            raise RuleValidationError("id must be an ASCII lowercase slug")

        version = _bounded_integer(root["version"], "version", 1, 2**32 - 1)
        status = _require_string(root["status"], "status", maximum=32)
        if status not in SUPPORTED_STATUSES:
            raise UnsupportedCorrelationError(f"unsupported status: {status}")
        title = _require_string(root["title"], "title", maximum=256)
        description = _require_string(root["description"], "description", maximum=2_048)
        window = _parse_duration(root["window"], "window", 1_000, MAX_WINDOW_MILLISECONDS)
        allowed_lateness = _parse_duration(
            root["allowed_lateness"],
            "allowed_lateness",
            0,
            MAX_LATENESS_MILLISECONDS,
        )
        group_by = self._parse_group_by(root["group_by"])
        selectors = self._parse_selectors(root["selectors"])
        selector_map = {selector.name: selector for selector in selectors}
        condition = self._parse_condition(root["correlate"], selector_map, group_by)
        self._validate_selector_usage(selectors, condition)
        incident = self._parse_incident(root["incident"], group_by)
        mitre = self._parse_mitre(root["mitre"])
        false_positives = _string_list(
            root["false_positives"],
            "false_positives",
            minimum=1,
            maximum=16,
            item_maximum=512,
        )
        return CorrelationRule(
            schema=schema,
            rule_id=rule_id,
            version=version,
            status=status,
            title=title,
            description=description,
            window=window,
            allowed_lateness=allowed_lateness,
            group_by=group_by,
            selectors=selectors,
            condition=condition,
            incident=incident,
            mitre=mitre,
            false_positives=false_positives,
            path=path,
        )

    def _parse_group_by(self, raw: Any) -> tuple[str, ...]:
        values = _string_list(raw, "group_by", minimum=1, maximum=MAX_GROUP_KEYS, item_maximum=64)
        _reject_duplicates(values, "group_by")
        unsupported = sorted(set(values) - GROUP_FIELDS)
        if unsupported:
            raise UnsupportedCorrelationError(
                f"unsupported group_by fields: {', '.join(unsupported)}"
            )
        return values

    def _parse_selectors(self, raw: Any) -> tuple[Selector, ...]:
        mapping = _require_mapping(raw, "selectors")
        if not 1 <= len(mapping) <= MAX_SELECTORS:
            raise RuleValidationError(f"selectors must contain 1-{MAX_SELECTORS} entries")
        selectors: list[Selector] = []
        for name, body_raw in mapping.items():
            if not _SELECTOR_NAME.fullmatch(name):
                raise RuleValidationError(f"invalid selector name: {name!r}")
            body = _require_mapping(body_raw, f"selector {name}")
            _require_exact_keys(body, {"source", "where"}, {"source", "where"}, f"selector {name}")
            source = _require_string(body["source"], f"selector {name}.source", maximum=16)
            if source not in {"detection", "event"}:
                raise UnsupportedCorrelationError(f"unsupported selector source: {source}")
            where = body["where"]
            if not isinstance(where, list) or not 1 <= len(where) <= MAX_PREDICATES_PER_SELECTOR:
                raise RuleValidationError(
                    f"selector {name}.where must contain 1-{MAX_PREDICATES_PER_SELECTOR} predicates"
                )
            predicates = tuple(
                self._parse_predicate(item, source, f"selector {name}.where[{index}]")
                for index, item in enumerate(where)
            )
            predicate_keys = [_canonical_json(predicate.semantic_plan()) for predicate in predicates]
            _reject_duplicates(predicate_keys, f"selector {name} predicates")
            ordered = tuple(
                predicate
                for _, predicate in sorted(zip(predicate_keys, predicates), key=lambda item: item[0])
            )
            selector = Selector(name, source, ordered)
            if source == "event":
                self._validate_event_selector(selector)
            selectors.append(selector)
        return tuple(sorted(selectors, key=lambda selector: selector.name))

    def _parse_predicate(self, raw: Any, source: str, location: str) -> Predicate:
        body = _require_mapping(raw, location)
        _require_exact_keys(body, {"field", "op", "value"}, {"field", "op", "value"}, location)
        field = _require_string(body["field"], f"{location}.field", maximum=64)
        allowed_fields = DETECTION_FIELDS if source == "detection" else EVENT_FIELDS
        if field not in allowed_fields:
            raise UnsupportedCorrelationError(f"unsupported {source} field: {field}")
        operator = _require_string(body["op"], f"{location}.op", maximum=16)
        if operator not in SUPPORTED_OPERATORS:
            raise UnsupportedCorrelationError(f"unsupported predicate operator: {operator}")

        raw_value = body["value"]
        if operator == "exists":
            if raw_value is not True:
                raise UnsupportedCorrelationError(
                    "exists requires boolean true; missing-value/NOT predicates are not supported"
                )
            return Predicate(field, "exists", True)
        if operator == "eq":
            if isinstance(raw_value, list):
                raise RuleValidationError("eq requires one typed scalar; use in for a list")
            return Predicate(field, "eq", _typed_predicate_value(field, raw_value))
        if not isinstance(raw_value, list) or not 1 <= len(raw_value) <= MAX_IN_VALUES:
            raise RuleValidationError(f"in requires a list containing 1-{MAX_IN_VALUES} typed scalars")
        values = tuple(_typed_predicate_value(field, value) for value in raw_value)
        _reject_duplicates(values, f"{location}.value")
        return Predicate(field, "in", tuple(sorted(values, key=_canonical_json)))

    def _validate_event_selector(self, selector: Selector) -> None:
        constrained = {
            predicate.field
            for predicate in selector.predicates
            if predicate.operator in {"eq", "in"}
        }
        if "source_type" not in constrained:
            raise RuleValidationError(
                f"event selector {selector.name} must constrain source_type with eq or in"
            )
        if not constrained.intersection({"event_category", "event_action", "event_code"}):
            raise RuleValidationError(
                f"event selector {selector.name} must constrain event_category, event_action, or event_code"
            )

    def _parse_condition(
        self,
        raw: Any,
        selectors: Mapping[str, Selector],
        group_by: tuple[str, ...],
    ) -> CorrelationCondition:
        body = _require_mapping(raw, "correlate")
        condition_type = _require_string(body.get("type"), "correlate.type", maximum=16)
        if condition_type == "threshold":
            return self._parse_threshold(body, selectors, group_by)
        if condition_type == "sequence":
            return self._parse_sequence(body, selectors, group_by)
        if condition_type == "join":
            return self._parse_join(body, selectors, group_by)
        raise UnsupportedCorrelationError(f"unsupported correlate.type: {condition_type}")

    def _parse_threshold(
        self,
        body: Mapping[str, Any],
        selectors: Mapping[str, Selector],
        group_by: tuple[str, ...],
    ) -> ThresholdCondition:
        allowed = {"type", "selector", "min_count", "distinct_by", "min_distinct"}
        required = {"type", "selector", "min_count"}
        _require_exact_keys(body, allowed, required, "threshold")
        selector_name = _require_selector_name(body["selector"], selectors, "threshold.selector")
        selector = selectors[selector_name]
        if selector.source != "detection":
            raise UnsupportedCorrelationError("event-backed thresholds are not supported")
        min_count = _bounded_integer(
            body["min_count"], "threshold.min_count", 2, MAX_THRESHOLD_INPUTS
        )
        distinct_by = body.get("distinct_by")
        min_distinct = body.get("min_distinct")
        if (distinct_by is None) != (min_distinct is None):
            raise RuleValidationError("distinct_by and min_distinct must be supplied together")
        if distinct_by is not None:
            distinct_by = _require_string(distinct_by, "threshold.distinct_by", maximum=64)
            if distinct_by not in DETECTION_FIELDS:
                raise UnsupportedCorrelationError(
                    f"unsupported threshold distinct_by field: {distinct_by}"
                )
            min_distinct = _bounded_integer(
                min_distinct, "threshold.min_distinct", 2, min_count
            )
        if "shared_ip" in group_by:
            raise UnsupportedCorrelationError("shared_ip is available only to an ownership join")
        return ThresholdCondition(selector_name, min_count, distinct_by, min_distinct)

    def _parse_sequence(
        self,
        body: Mapping[str, Any],
        selectors: Mapping[str, Selector],
        group_by: tuple[str, ...],
    ) -> SequenceCondition:
        _require_exact_keys(body, {"type", "stages"}, {"type", "stages"}, "sequence")
        raw_stages = body["stages"]
        if not isinstance(raw_stages, list) or not 2 <= len(raw_stages) <= MAX_SEQUENCE_STAGES:
            raise RuleValidationError(f"sequence.stages must contain 2-{MAX_SEQUENCE_STAGES} stages")
        stages: list[SequenceStage] = []
        for index, raw_stage in enumerate(raw_stages):
            stage = _require_mapping(raw_stage, f"sequence.stages[{index}]")
            _require_exact_keys(
                stage,
                {"selector", "min_count"},
                {"selector", "min_count"},
                f"sequence.stages[{index}]",
            )
            selector_name = _require_selector_name(
                stage["selector"], selectors, f"sequence.stages[{index}].selector"
            )
            min_count = _bounded_integer(
                stage["min_count"],
                f"sequence.stages[{index}].min_count",
                1,
                MAX_STAGE_COUNT,
            )
            stages.append(SequenceStage(selector_name, min_count))
        _reject_duplicates(tuple(stage.selector for stage in stages), "sequence stage selectors")
        if sum(stage.min_count for stage in stages) > MAX_THRESHOLD_INPUTS:
            raise RuleValidationError(
                f"sequence minimum input count exceeds {MAX_THRESHOLD_INPUTS}"
            )
        if not any(selectors[stage.selector].source == "detection" for stage in stages):
            raise UnsupportedCorrelationError("a sequence must contain a detection stage")
        if "shared_ip" in group_by:
            raise UnsupportedCorrelationError("shared_ip is available only to an ownership join")
        return SequenceCondition(tuple(stages))

    def _parse_join(
        self,
        body: Mapping[str, Any],
        selectors: Mapping[str, Selector],
        group_by: tuple[str, ...],
    ) -> JoinCondition:
        _require_exact_keys(
            body,
            {"type", "require", "relations"},
            {"type", "require", "relations"},
            "join",
        )
        require = _string_list(
            body["require"], "join.require", minimum=2, maximum=3, item_maximum=64
        )
        _reject_duplicates(require, "join.require")
        for selector_name in require:
            _require_selector_name(selector_name, selectors, "join.require")
        if not any(selectors[name].source == "detection" for name in require):
            raise UnsupportedCorrelationError("a join must contain a detection input")
        event_names = tuple(name for name in require if selectors[name].source == "event")
        if len(event_names) > 1:
            raise UnsupportedCorrelationError("a join supports at most one event context selector")

        raw_relations = body["relations"]
        if not isinstance(raw_relations, list) or not 1 <= len(raw_relations) <= MAX_JOIN_RELATIONS:
            raise RuleValidationError(f"join.relations must contain 1-{MAX_JOIN_RELATIONS} relations")
        relations = tuple(
            self._parse_relation(item, selectors, set(require), index)
            for index, item in enumerate(raw_relations)
        )
        relation_keys = [_canonical_json(relation.semantic_plan()) for relation in relations]
        _reject_duplicates(relation_keys, "join relations")
        ordered_relations = tuple(
            relation
            for _, relation in sorted(zip(relation_keys, relations), key=lambda item: item[0])
        )
        ordered_require = tuple(sorted(require))
        if event_names:
            self._validate_ownership_join(
                selectors, ordered_require, ordered_relations, event_names[0], group_by
            )
        elif "shared_ip" in group_by:
            raise UnsupportedCorrelationError(
                "shared_ip requires a direction-safe endpoint ownership context selector"
            )
        return JoinCondition(ordered_require, ordered_relations)

    def _parse_relation(
        self,
        raw: Any,
        selectors: Mapping[str, Selector],
        required: set[str],
        index: int,
    ) -> JoinRelation:
        location = f"join.relations[{index}]"
        body = _require_mapping(raw, location)
        _require_exact_keys(body, {"left", "op", "right"}, {"left", "op", "right"}, location)
        left_selector, left_field = _parse_relation_endpoint(body["left"], location + ".left")
        right_selector, right_field = _parse_relation_endpoint(body["right"], location + ".right")
        if left_selector not in required or right_selector not in required:
            raise RuleValidationError("join relations may reference only required selectors")
        if left_selector == right_selector:
            raise RuleValidationError("join relation sides must use different selectors")
        operator = _require_string(body["op"], location + ".op", maximum=16)
        if operator not in {"equals", "intersects"}:
            raise UnsupportedCorrelationError(f"unsupported join relation operator: {operator}")
        left_source = selectors[left_selector].source
        right_source = selectors[right_selector].source
        if operator == "equals":
            self._validate_scalar_relation(left_field, left_source, right_field, right_source)
        else:
            sides = {(left_source, left_field), (right_source, right_field)}
            if sides != {("detection", "ip_set"), ("event", "local_ip_set")}:
                raise UnsupportedCorrelationError(
                    "intersects is limited to detection.ip_set and event.local_ip_set"
                )
        if operator == "intersects" and left_source == "event":
            left_selector, right_selector = right_selector, left_selector
            left_field, right_field = right_field, left_field
        elif operator == "equals" and (left_selector, left_field) > (right_selector, right_field):
            left_selector, right_selector = right_selector, left_selector
            left_field, right_field = right_field, left_field
        return JoinRelation(
            left_selector,
            left_field,
            operator,  # type: ignore[arg-type]
            right_selector,
            right_field,
        )

    def _validate_scalar_relation(
        self, left_field: str, left_source: str, right_field: str, right_source: str
    ) -> None:
        for field, source in ((left_field, left_source), (right_field, right_source)):
            allowed = DETECTION_FIELDS if source == "detection" else EVENT_FIELDS
            if field not in allowed or field not in SCALAR_RELATION_FIELDS:
                raise UnsupportedCorrelationError(
                    f"unsupported {source} scalar relation field: {field}"
                )
        if left_field in IP_RELATION_FIELDS and right_field not in IP_RELATION_FIELDS:
            raise RuleValidationError("an IP relation endpoint must be compared with another IP field")
        if right_field in IP_RELATION_FIELDS and left_field not in IP_RELATION_FIELDS:
            raise RuleValidationError("an IP relation endpoint must be compared with another IP field")
        if left_field not in IP_RELATION_FIELDS and left_field != right_field:
            raise RuleValidationError("non-IP scalar relations must compare the same normalized field")

    def _validate_ownership_join(
        self,
        selectors: Mapping[str, Selector],
        require: tuple[str, ...],
        relations: tuple[JoinRelation, ...],
        event_name: str,
        group_by: tuple[str, ...],
    ) -> None:
        if len(require) != 3:
            raise UnsupportedCorrelationError(
                "the v0.6 ownership join requires two detections and one endpoint event"
            )
        event_selector = selectors[event_name]
        if not (
            _selector_has_exact(event_selector, "source_type", "windows_sysmon")
            and _selector_has_exact(event_selector, "event_code", "3")
            and _selector_has_exact(event_selector, "initiated", 1)
        ):
            raise UnsupportedCorrelationError(
                "endpoint ownership context must be an initiated Windows Sysmon event 3"
            )
        detection_names = tuple(name for name in require if selectors[name].source == "detection")
        network_names = tuple(
            name
            for name in detection_names
            if _selector_has_exact(selectors[name], "source_type", "suricata_eve")
        )
        endpoint_names = tuple(
            name
            for name in detection_names
            if _selector_has_exact(selectors[name], "platform", "windows")
        )
        if len(network_names) != 1 or len(endpoint_names) != 1 or network_names[0] == endpoint_names[0]:
            raise UnsupportedCorrelationError(
                "ownership join requires distinct Suricata and Windows detection selectors"
            )
        host_pair = frozenset({(endpoint_names[0], "host_name"), (event_name, "host_name")})
        ip_pair = frozenset({(network_names[0], "ip_set"), (event_name, "local_ip_set")})
        if not any(
            relation.operator == "equals"
            and frozenset(
                {
                    (relation.left_selector, relation.left_field),
                    (relation.right_selector, relation.right_field),
                }
            )
            == host_pair
            for relation in relations
        ):
            raise UnsupportedCorrelationError(
                "ownership join must bind the endpoint detection host to the ownership event host"
            )
        if not any(
            relation.operator == "intersects"
            and frozenset(
                {
                    (relation.left_selector, relation.left_field),
                    (relation.right_selector, relation.right_field),
                }
            )
            == ip_pair
            for relation in relations
        ):
            raise UnsupportedCorrelationError(
                "ownership join must intersect Suricata IPs with direction-safe local IPs"
            )
        if set(group_by) != {"shared_ip", "host_name"}:
            raise UnsupportedCorrelationError(
                "ownership join group_by must contain exactly shared_ip and host_name"
            )

    def _validate_selector_usage(
        self, selectors: tuple[Selector, ...], condition: CorrelationCondition
    ) -> None:
        available = {selector.name for selector in selectors}
        if isinstance(condition, ThresholdCondition):
            referenced = {condition.selector}
        elif isinstance(condition, SequenceCondition):
            referenced = {stage.selector for stage in condition.stages}
        else:
            referenced = set(condition.require)
        unused = sorted(available - referenced)
        if unused:
            raise RuleValidationError(f"unreferenced selectors are not allowed: {', '.join(unused)}")
        if not any(selector.source == "detection" for selector in selectors if selector.name in referenced):
            raise UnsupportedCorrelationError("every qualifying rule must include a detection")

    def _parse_incident(self, raw: Any, group_by: tuple[str, ...]) -> IncidentSpec:
        body = _require_mapping(raw, "incident")
        required = {"type", "title", "severity", "confidence", "primary"}
        _require_exact_keys(body, required, required, "incident")
        incident_type = _require_string(body["type"], "incident.type", maximum=64)
        if not _INCIDENT_TYPE.fullmatch(incident_type):
            raise RuleValidationError("incident.type must be a lowercase underscore identifier")
        title_template = _require_string(body["title"], "incident.title", maximum=256)
        severity = _require_string(body["severity"], "incident.severity", maximum=16)
        if severity not in SEVERITIES:
            raise UnsupportedCorrelationError(f"unsupported incident severity: {severity}")
        confidence = _bounded_integer(body["confidence"], "incident.confidence", 0, 100)
        primary_body = _require_mapping(body["primary"], "incident.primary")
        if not 1 <= len(primary_body) <= 4:
            raise RuleValidationError("incident.primary must contain 1-4 mappings")
        allowed_primary = {"host", "user", "source_ip", "destination_ip"}
        _require_exact_keys(primary_body, allowed_primary, set(), "incident.primary")
        primary: list[tuple[str, str]] = []
        target_fields = {
            "host": {"host_name"},
            "user": {"user_name"},
            "source_ip": {"source_ip", "shared_ip"},
            "destination_ip": {"destination_ip", "shared_ip"},
        }
        for output, source in primary_body.items():
            field = _require_string(source, f"incident.primary.{output}", maximum=64)
            if field not in target_fields[output]:
                raise UnsupportedCorrelationError(
                    f"incident.primary.{output} cannot map from {field}"
                )
            primary.append((output, field))
        primary_tuple = tuple(sorted(primary))
        placeholders = _validate_title_template(title_template)
        allowed_placeholders = set(group_by) | {field for _, field in primary_tuple}
        unsupported = sorted(placeholders - allowed_placeholders)
        if unsupported:
            raise UnsupportedCorrelationError(
                f"incident.title uses unavailable placeholders: {', '.join(unsupported)}"
            )
        return IncidentSpec(
            incident_type, title_template, severity, confidence, primary_tuple
        )

    def _parse_mitre(self, raw: Any) -> MitreSpec:
        body = _require_mapping(raw, "mitre")
        required = {"tactic_ids", "technique_ids"}
        _require_exact_keys(body, required, required, "mitre")
        tactics = _string_list(
            body["tactic_ids"], "mitre.tactic_ids", minimum=0, maximum=32, item_maximum=16
        )
        techniques = _string_list(
            body["technique_ids"],
            "mitre.technique_ids",
            minimum=0,
            maximum=32,
            item_maximum=16,
        )
        _reject_duplicates(tactics, "mitre.tactic_ids")
        _reject_duplicates(techniques, "mitre.technique_ids")
        for value in tactics:
            if not _MITRE_TACTIC.fullmatch(value):
                raise RuleValidationError(f"invalid MITRE tactic ID: {value}")
        for value in techniques:
            if not _MITRE_TECHNIQUE.fullmatch(value):
                raise RuleValidationError(f"invalid MITRE technique ID: {value}")
        return MitreSpec(tuple(sorted(tactics)), tuple(sorted(techniques)))


def validate_rule_directory(rules_dir: Path, compiler: CorrelationCompiler | None = None) -> RuleDirectoryResult:
    """Validate every YAML rule below ``rules_dir`` without external effects."""

    compiler = compiler or CorrelationCompiler()
    if not rules_dir.is_dir():
        return RuleDirectoryResult(0, (), (f"{rules_dir}: rule directory does not exist",))
    paths = sorted({*rules_dir.rglob("*.yml"), *rules_dir.rglob("*.yaml")})
    rules: list[CompiledRule] = []
    errors: list[str] = []
    seen: dict[str, Path] = {}
    for path in paths:
        try:
            if path.is_symlink():
                raise RuleValidationError("symbolic-link rule files are not allowed")
            compiled = compiler.load_rule(path)
            previous = seen.get(compiled.rule_id)
            if previous is not None:
                raise RuleValidationError(
                    f"duplicate rule id/version scope also loaded from {previous}"
                )
            seen[compiled.rule_id] = path
            rules.append(compiled)
        except (RuleValidationError, yaml.YAMLError, UnicodeError, OSError) as exc:
            errors.append(f"{path}: {exc}")
    return RuleDirectoryResult(len(paths), tuple(rules), tuple(errors))


def load_rules_strict(
    rules_dir: Path, compiler: CorrelationCompiler | None = None
) -> tuple[CompiledRule, ...]:
    result = validate_rule_directory(rules_dir, compiler)
    if result.errors:
        raise RuleValidationError("correlation rule validation failed:\n" + "\n".join(result.errors))
    if not result.rules:
        raise RuleValidationError(f"no correlation YAML rules found under {rules_dir}")
    return result.rules


def _load_yaml_strict(path: Path) -> Any:
    data = path.read_bytes()
    return _load_yaml_bytes_strict(data)


def _load_yaml_bytes_strict(data: bytes) -> Any:
    if not data or len(data) > MAX_DOCUMENT_BYTES:
        raise RuleValidationError(
            f"rule document must be 1-{MAX_DOCUMENT_BYTES} bytes"
        )
    text = data.decode("utf-8-sig", errors="strict")
    for token in yaml.scan(text, Loader=yaml.SafeLoader):
        if isinstance(token, (AliasToken, AnchorToken, TagToken, DirectiveToken)):
            raise RuleValidationError(
                "YAML aliases, anchors, tags, and directives are not allowed"
            )
    loader = _StrictSafeLoader(text)
    try:
        raw = loader.get_single_data()
    finally:
        loader.dispose()
    _validate_resource_bounds(raw)
    return raw


def _validate_resource_bounds(value: Any) -> None:
    count = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_TOTAL_NODES:
            raise RuleValidationError(f"rule exceeds {MAX_TOTAL_NODES} parsed nodes")
        if depth > MAX_NESTING_DEPTH:
            raise RuleValidationError(f"rule nesting exceeds {MAX_NESTING_DEPTH}")
        if isinstance(item, str):
            if len(item) > MAX_STRING_LENGTH:
                raise RuleValidationError(f"rule string exceeds {MAX_STRING_LENGTH} characters")
            if _ENV_EXPANSION.search(item):
                raise UnsupportedCorrelationError("environment expansion is not allowed in rules")
            return
        if isinstance(item, Mapping):
            if len(item) > MAX_COLLECTION_ITEMS:
                raise RuleValidationError("rule mapping exceeds collection bound")
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
            return
        if isinstance(item, list):
            if len(item) > MAX_COLLECTION_ITEMS:
                raise RuleValidationError("rule list exceeds collection bound")
            for child in item:
                visit(child, depth + 1)
            return
        if item is None or type(item) in {bool, int}:
            return
        raise RuleValidationError(f"unsupported YAML scalar type: {type(item).__name__}")

    visit(value, 0)


def _semantic_plan(
    rule: CorrelationRule,
    *,
    mapping_version: str,
    mapping_sha256: str,
    technique_to_tactics: Mapping[str, tuple[str, ...]],
) -> Mapping[str, Any]:
    return {
        "schema": rule.schema,
        "compiler_contract": COMPILER_CONTRACT_VERSION,
        "normalized_field_contract": {
            "version": NORMALIZED_FIELD_CONTRACT_VERSION,
            "detection_selector_fields": sorted(DETECTION_FIELDS),
            "event_selector_fields": sorted(EVENT_FIELDS),
            "group_fields": sorted(GROUP_FIELDS),
            "predicate_operators": sorted(SUPPORTED_OPERATORS),
            "scalar_relation_fields": sorted(SCALAR_RELATION_FIELDS),
            "set_relation_projections": {
                "detection": "ip_set(source_ip,destination_ip)",
                "event": "local_ip_set(direction-safe-source_ip)",
            },
            "ownership_event": {
                "source_type": "windows_sysmon",
                "event_code": "3",
                "initiated": 1,
            },
        },
        "identity_normalization_contract": dict(IDENTITY_NORMALIZATION_CONTRACT),
        "incident_scoring_contract": {
            "severity": "max(rule_base,linked_detection_max)",
            "severity_ranks": SEVERITY_RANKS,
            "confidence": "static_rule_declared_0_100",
            "events_raise_severity": False,
        },
        "mitre_technique_tactic_mapping": {
            "version": mapping_version,
            "bytes_sha256": mapping_sha256,
            "techniques": {
                technique: list(tactics)
                for technique, tactics in sorted(technique_to_tactics.items())
            },
        },
        "time_semantics": {
            "correlation_clock": "occurred_at",
            "visibility_clock": "observed_at",
            "window_boundary": "inclusive",
            "sequence_cross_stage_order": "strict",
            "precision": "utc-milliseconds",
        },
        "window_milliseconds": rule.window.milliseconds,
        "allowed_lateness_milliseconds": rule.allowed_lateness.milliseconds,
        "group_by": list(rule.group_by),
        "selectors": {
            selector.name: selector.semantic_plan() for selector in rule.selectors
        },
        "correlate": rule.condition.semantic_plan(),
        "incident": rule.incident.semantic_plan(),
        "mitre": rule.mitre.semantic_plan(),
    }


def _fingerprint(semantic_plan: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(semantic_plan).encode("utf-8")).hexdigest()


def _load_mitre_mapping(
    path: Path,
) -> tuple[str, Mapping[str, tuple[str, ...]], str]:
    data = path.read_bytes()
    raw = _require_mapping(_load_yaml_bytes_strict(data), "MITRE mapping root")
    _require_exact_keys(
        raw,
        {"version", "techniques"},
        {"version", "techniques"},
        "MITRE mapping root",
    )
    version = _require_string(raw["version"], "MITRE mapping version", maximum=64)
    if not re.fullmatch(r"fusion-mitre-technique-tactics-v[1-9][0-9]*", version):
        raise RuleValidationError("MITRE mapping version is not a stable version identifier")
    techniques_raw = _require_mapping(raw["techniques"], "MITRE mapping techniques")
    if not techniques_raw:
        raise RuleValidationError("MITRE mapping techniques must not be empty")
    techniques: dict[str, tuple[str, ...]] = {}
    for technique, raw_tactics in techniques_raw.items():
        if not _MITRE_TECHNIQUE.fullmatch(technique):
            raise RuleValidationError(f"invalid MITRE mapping technique ID: {technique}")
        tactics = _string_list(
            raw_tactics,
            f"MITRE mapping {technique}",
            minimum=1,
            maximum=16,
            item_maximum=16,
        )
        _reject_duplicates(tactics, f"MITRE mapping {technique}")
        for tactic in tactics:
            if not _MITRE_TACTIC.fullmatch(tactic):
                raise RuleValidationError(f"invalid MITRE mapping tactic ID: {tactic}")
        techniques[technique] = tuple(sorted(tactics))
    digest = hashlib.sha256(data).hexdigest()
    return version, techniques, digest


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _require_mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RuleValidationError(f"{location} must be a YAML mapping")
    return value


def _require_exact_keys(
    mapping: Mapping[str, Any],
    allowed: Iterable[str],
    required: Iterable[str],
    location: str,
) -> None:
    allowed_set = set(allowed)
    required_set = set(required)
    unknown = sorted(set(mapping) - allowed_set)
    missing = sorted(required_set - set(mapping))
    if unknown:
        raise UnsupportedCorrelationError(
            f"{location} has unknown fields: {', '.join(unknown)}"
        )
    if missing:
        raise RuleValidationError(f"{location} is missing fields: {', '.join(missing)}")


def _require_string(value: Any, location: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleValidationError(f"{location} must be a nonblank string")
    if value != value.strip():
        raise RuleValidationError(f"{location} must not have outer whitespace")
    if len(value) > maximum:
        raise RuleValidationError(f"{location} exceeds {maximum} characters")
    if any(ord(character) < 32 and character not in {"\n", "\r", "\t"} for character in value):
        raise RuleValidationError(f"{location} contains control characters")
    return value


def _string_list(
    value: Any,
    location: str,
    *,
    minimum: int,
    maximum: int,
    item_maximum: int,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise RuleValidationError(f"{location} must contain {minimum}-{maximum} strings")
    return tuple(
        _require_string(item, f"{location}[{index}]", maximum=item_maximum)
        for index, item in enumerate(value)
    )


def _bounded_integer(value: Any, location: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RuleValidationError(f"{location} must be an integer from {minimum} through {maximum}")
    return value


def _parse_duration(value: Any, location: str, minimum: int, maximum: int) -> Duration:
    text = _require_string(value, location, maximum=16)
    match = _DURATION.fullmatch(text)
    if match is None:
        raise RuleValidationError(f"{location} must be an integer followed by s, m, or h")
    number = int(match.group(1))
    multiplier = {"s": 1_000, "m": 60_000, "h": 3_600_000}[match.group(2)]
    milliseconds = number * multiplier
    if not minimum <= milliseconds <= maximum:
        raise RuleValidationError(
            f"{location} must be between {minimum} and {maximum} milliseconds"
        )
    return Duration(text, milliseconds)


def _typed_predicate_value(field: str, value: Any) -> str | int:
    if field == "rule_version":
        # This is the source detection rule's version, whose v0.5 schema is a
        # String (unlike the positive-integer correlation rule version).
        text = _require_string(value, f"predicate {field}", maximum=512)
        if "*" in text or "?" in text:
            raise UnsupportedCorrelationError(
                "glob/wildcard predicate values are not supported"
            )
        return text
    if field == "initiated":
        return _bounded_integer(value, f"predicate {field}", 0, 1)
    if not isinstance(value, str):
        raise RuleValidationError(f"predicate {field} requires a string value")
    text = _require_string(value, f"predicate {field}", maximum=512)
    if "*" in text or "?" in text:
        raise UnsupportedCorrelationError("glob/wildcard predicate values are not supported")
    if field == "severity" and text not in SEVERITIES:
        raise RuleValidationError(f"invalid detection severity: {text}")
    if field == "platform" and text not in PLATFORMS:
        raise RuleValidationError(f"invalid normalized platform: {text}")
    if field in {"rule_id"} and not _RULE_ID.fullmatch(text):
        raise RuleValidationError(f"predicate {field} must be a lowercase rule slug")
    if field == "source_type" and not _SOURCE_TYPE.fullmatch(text):
        raise RuleValidationError("predicate source_type must be a lowercase underscore identifier")
    return text


def _require_selector_name(
    value: Any, selectors: Mapping[str, Selector], location: str
) -> str:
    name = _require_string(value, location, maximum=64)
    if name not in selectors:
        raise RuleValidationError(f"{location} references unknown selector: {name}")
    return name


def _parse_relation_endpoint(value: Any, location: str) -> tuple[str, str]:
    text = _require_string(value, location, maximum=129)
    match = _RELATION_ENDPOINT.fullmatch(text)
    if match is None:
        raise RuleValidationError(f"{location} must be selector.field")
    return match.group(1), match.group(2)


def _selector_has_exact(selector: Selector, field: str, value: Any) -> bool:
    return any(
        predicate.field == field
        and predicate.operator == "eq"
        and predicate.value == value
        for predicate in selector.predicates
    )


def _validate_title_template(template: str) -> set[str]:
    placeholders: set[str] = set()
    try:
        parsed = tuple(string.Formatter().parse(template))
    except ValueError as exc:
        raise RuleValidationError(f"invalid incident.title template: {exc}") from exc
    for _, field_name, format_spec, conversion in parsed:
        if field_name is None:
            continue
        if not _PLACEHOLDER.fullmatch(field_name):
            raise UnsupportedCorrelationError(
                "incident.title placeholders must be simple lowercase field names"
            )
        if format_spec or conversion:
            raise UnsupportedCorrelationError(
                "incident.title formatting and conversions are not supported"
            )
        placeholders.add(field_name)
    return placeholders


def _reject_duplicates(values: Sequence[Any], location: str) -> None:
    serialized = [_canonical_json(value) for value in values]
    if len(set(serialized)) != len(serialized):
        raise RuleValidationError(f"{location} contains duplicate values")
