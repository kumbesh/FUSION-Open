"""Typed models for the strict ``fusion-correlation/v1`` rule language.

The models intentionally contain no storage or polling behavior.  They are the
small, immutable interface between fail-closed YAML validation and the future
correlation runtime.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypeAlias

InputKind: TypeAlias = Literal["detection", "event"]
PredicateOperator: TypeAlias = Literal["eq", "in", "exists"]
ConditionKind: TypeAlias = Literal["threshold", "sequence", "join"]


class RuleValidationError(ValueError):
    """A rule cannot be represented safely by ``fusion-correlation/v1``."""


class UnsupportedCorrelationError(RuleValidationError):
    """A rule requests a construct outside the frozen v0.6 subset."""


@dataclass(frozen=True)
class Duration:
    """A validated duration retaining both author text and canonical millis."""

    text: str
    milliseconds: int

    @property
    def seconds(self) -> int:
        return self.milliseconds // 1_000


@dataclass(frozen=True)
class Predicate:
    field: str
    operator: PredicateOperator
    value: Any

    def semantic_plan(self) -> Mapping[str, Any]:
        value = list(self.value) if isinstance(self.value, tuple) else self.value
        return {"field": self.field, "op": self.operator, "value": value}


@dataclass(frozen=True)
class Selector:
    name: str
    source: InputKind
    predicates: tuple[Predicate, ...]

    def semantic_plan(self) -> Mapping[str, Any]:
        return {
            "source": self.source,
            "where": [predicate.semantic_plan() for predicate in self.predicates],
        }


@dataclass(frozen=True)
class ThresholdCondition:
    selector: str
    min_count: int
    distinct_by: str | None = None
    min_distinct: int | None = None
    kind: Literal["threshold"] = "threshold"

    def semantic_plan(self) -> Mapping[str, Any]:
        result: dict[str, Any] = {
            "type": self.kind,
            "selector": self.selector,
            "min_count": self.min_count,
        }
        if self.distinct_by is not None:
            result["distinct_by"] = self.distinct_by
            result["min_distinct"] = self.min_distinct
        return result


@dataclass(frozen=True)
class SequenceStage:
    selector: str
    min_count: int

    def semantic_plan(self) -> Mapping[str, Any]:
        return {"selector": self.selector, "min_count": self.min_count}


@dataclass(frozen=True)
class SequenceCondition:
    stages: tuple[SequenceStage, ...]
    kind: Literal["sequence"] = "sequence"

    def semantic_plan(self) -> Mapping[str, Any]:
        return {
            "type": self.kind,
            "stages": [stage.semantic_plan() for stage in self.stages],
        }


@dataclass(frozen=True)
class JoinRelation:
    left_selector: str
    left_field: str
    operator: Literal["equals", "intersects"]
    right_selector: str
    right_field: str

    @property
    def left(self) -> str:
        return f"{self.left_selector}.{self.left_field}"

    @property
    def right(self) -> str:
        return f"{self.right_selector}.{self.right_field}"

    def semantic_plan(self) -> Mapping[str, Any]:
        return {"left": self.left, "op": self.operator, "right": self.right}


@dataclass(frozen=True)
class JoinCondition:
    require: tuple[str, ...]
    relations: tuple[JoinRelation, ...]
    kind: Literal["join"] = "join"

    def semantic_plan(self) -> Mapping[str, Any]:
        return {
            "type": self.kind,
            "require": list(self.require),
            "relations": [relation.semantic_plan() for relation in self.relations],
        }


CorrelationCondition: TypeAlias = ThresholdCondition | SequenceCondition | JoinCondition


@dataclass(frozen=True)
class IncidentSpec:
    incident_type: str
    title_template: str
    severity: str
    confidence: int
    primary: tuple[tuple[str, str], ...]

    def semantic_plan(self) -> Mapping[str, Any]:
        return {
            "type": self.incident_type,
            "title": self.title_template,
            "severity": self.severity,
            "confidence": self.confidence,
            "primary": dict(self.primary),
        }


@dataclass(frozen=True)
class MitreSpec:
    tactic_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]

    def semantic_plan(self) -> Mapping[str, Any]:
        return {
            "tactic_ids": list(self.tactic_ids),
            "technique_ids": list(self.technique_ids),
        }


@dataclass(frozen=True)
class CorrelationRule:
    schema: str
    rule_id: str
    version: int
    status: str
    title: str
    description: str
    window: Duration
    allowed_lateness: Duration
    group_by: tuple[str, ...]
    selectors: tuple[Selector, ...]
    condition: CorrelationCondition
    incident: IncidentSpec
    mitre: MitreSpec
    false_positives: tuple[str, ...]
    path: Path

    @property
    def selector_map(self) -> Mapping[str, Selector]:
        return {selector.name: selector for selector in self.selectors}


@dataclass(frozen=True)
class CompiledRule:
    """A validated rule and its deterministic semantic scope fingerprint."""

    rule: CorrelationRule
    scope_fingerprint: str
    canonical_semantic_plan: Mapping[str, Any]

    @property
    def rule_id(self) -> str:
        return self.rule.rule_id

    @property
    def version(self) -> int:
        return self.rule.version

    @property
    def condition_kind(self) -> ConditionKind:
        return self.rule.condition.kind

    def plan(self) -> Mapping[str, Any]:
        """Return a JSON-safe audit plan without executable query material."""

        return {
            "rule_id": self.rule.rule_id,
            "rule_version": self.rule.version,
            "correlation_scope_fingerprint": self.scope_fingerprint,
            **self.canonical_semantic_plan,
        }


@dataclass(frozen=True)
class RuleDirectoryResult:
    total: int
    rules: tuple[CompiledRule, ...]
    errors: tuple[str, ...]

    @property
    def valid(self) -> int:
        return len(self.rules)

    @property
    def invalid(self) -> int:
        return len(self.errors)
