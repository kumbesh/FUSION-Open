"""Runtime records shared by correlation evaluation and persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping


class CorrelationPersistenceConflict(RuntimeError):
    """A deterministic persisted identity has incompatible immutable content."""


@dataclass(frozen=True)
class InputEnvelope:
    """One canonical logical correlation input."""

    input_kind: str
    input_id: str
    occurred_at: datetime
    observed_at: datetime
    values: Mapping[str, Any]
    invalid_reason: str = ""

    @property
    def tagged_id(self) -> str:
        return f"{self.input_kind}\0{self.input_id}"

    @property
    def order_key(self) -> tuple[datetime, str, str]:
        return (self.occurred_at, self.input_kind, self.input_id)


@dataclass(frozen=True)
class CandidateCursor:
    occurred_at: datetime
    observed_at: datetime
    input_kind: str
    input_id: str


@dataclass(frozen=True)
class RuleScope:
    engine_id: str
    rule_id: str
    rule_version: int
    fingerprint: str

    @property
    def key(self) -> tuple[str, str, int, str]:
        return (
            self.engine_id,
            self.rule_id,
            self.rule_version,
            self.fingerprint,
        )


@dataclass(frozen=True)
class EvidenceLink:
    incident_id: str
    input_kind: str
    input_id: str
    link_id: str
    introduction_revision_token: str
    relationship: str
    occurred_at: datetime
    observed_at: datetime
    correlation_rule_id: str
    correlation_rule_version: int
    correlation_scope_fingerprint: str
    snapshot: Mapping[str, Any]


@dataclass(frozen=True)
class EpisodeState:
    scope: RuleScope
    group_key_json: str
    group_key_hash: str
    episode_state_id: str
    revision_token: str
    canonical_qualifying_set_json: str
    anchor_kind: str
    anchor_id: str
    anchor_time: datetime | None
    window_start: datetime
    window_end: datetime
    incident_id: str
    owned_detection_ids: tuple[str, ...]
    owned_event_ids: tuple[str, ...]
    last_input_observed_at: datetime
    late_accept_until: datetime
    collision_count: int
    state_hash: str
    updated_at: datetime
    revision: int

    @property
    def owned_tagged_ids(self) -> frozenset[str]:
        return frozenset(
            [f"detection\0{value}" for value in self.owned_detection_ids]
            + [f"event\0{value}" for value in self.owned_event_ids]
        )


@dataclass(frozen=True)
class IncidentRecord:
    values: Mapping[str, Any]

    @property
    def incident_id(self) -> str:
        return str(self.values["incident_id"])

    @property
    def revision(self) -> int:
        return int(self.values["revision"])

    @property
    def state_hash(self) -> str:
        return str(self.values["state_hash"])


@dataclass(frozen=True)
class EvaluationDecision:
    evaluation_action: str
    lateness_status: str
    reason_code: str
    revision_token: str
    resulting_incident_id: str = ""
    incident: IncidentRecord | None = None
    expected_incident: IncidentRecord | None = None
    links: tuple[EvidenceLink, ...] = ()
    episode_states: tuple[EpisodeState, ...] = ()
    matched: bool = False


@dataclass(frozen=True)
class CorrelationBacklog:
    newest_occurred_at: datetime | None
    newest_observed_at: datetime | None
    newest_input_kind: str
    newest_input_id: str
    unevaluated_input_count: int
    oldest_unevaluated_observed_at: datetime | None
    oldest_unevaluated_age_seconds: float


@dataclass(frozen=True)
class CorrelationIntegrityStatus:
    """Durable integrity preflight result for one correlation rule scope."""

    status: str
    violation_count: int
    violation_types: tuple[str, ...] = field(default_factory=tuple)
    checked_at: datetime | None = None

    @property
    def blocked(self) -> bool:
        return self.status == "blocked_integrity"

    @classmethod
    def healthy(cls, checked_at: datetime | None = None) -> "CorrelationIntegrityStatus":
        return cls("healthy", 0, (), checked_at)


@dataclass(frozen=True)
class CorrelationCycleStats:
    scope: RuleScope
    evaluated_inputs: int
    matched_inputs: int
    failed_inputs: int
    incidents_created: int
    incidents_updated: int
    detection_links_written: int
    event_links_written: int
    processing_duration_seconds: float
    evaluated_inputs_per_second: float
    backlog: CorrelationBacklog | None
    cursor: CandidateCursor | None
    consecutive_drain_cycles: int = 0
    errors: tuple[str, ...] = field(default_factory=tuple)
    integrity: CorrelationIntegrityStatus = field(
        default_factory=CorrelationIntegrityStatus.healthy
    )
