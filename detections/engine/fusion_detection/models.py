"""Typed models shared by the compiler, evaluator, and storage adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping


class RuleValidationError(ValueError):
    """A Sigma rule cannot be represented safely by the supported subset."""


class UnsupportedSigmaError(RuleValidationError):
    """A valid-looking Sigma construct is outside Fusion's documented subset."""


@dataclass(frozen=True)
class SigmaRule:
    rule_id: str
    title: str
    description: str
    level: str
    tags: tuple[str, ...]
    author: str
    date: str
    modified: str
    references: tuple[str, ...]
    logsource: Mapping[str, str]
    detection: Mapping[str, Any]
    path: Path

    @property
    def version(self) -> str:
        return self.modified or self.date or "1"


@dataclass(frozen=True)
class SelectionResult:
    matched: bool
    fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    matched: bool
    selections: tuple[str, ...] = ()
    fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionCandidate:
    detection_id: str
    detected_at: datetime
    values: Mapping[str, Any]


@dataclass(frozen=True)
class Checkpoint:
    event_time: datetime
    event_uid: str


@dataclass(frozen=True)
class CycleStats:
    events_evaluated: int
    matches_found: int
    detections_inserted: int
    duplicates_skipped: int
    checkpoint: Checkpoint
