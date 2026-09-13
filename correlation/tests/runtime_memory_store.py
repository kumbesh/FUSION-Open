"""In-memory persistence model for v0.6 runtime acceptance tests.

This test double deliberately models the correlation contract rather than
ClickHouse internals: raw effects become serving/current state only after the
decision confirmation, while the exact ledger remains the sole completeness
authority.  Schedule cursors influence scan order, never eligibility.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from fusion_correlation.evaluator import selector_matches
from fusion_correlation.identity import (
    IdentityNormalizationError,
    canonical_group_json,
)
from fusion_correlation.incident import canonical_json, group_identity
from fusion_correlation.models import CompiledRule
from fusion_correlation.runtime_models import (
    CandidateCursor,
    CorrelationBacklog,
    CorrelationCycleStats,
    CorrelationIntegrityStatus,
    CorrelationPersistenceConflict,
    EpisodeState,
    EvaluationDecision,
    EvidenceLink,
    IncidentRecord,
    InputEnvelope,
    RuleScope,
)


class MemoryCorrelationStore:
    """Confirmation-aware, deterministic implementation of CorrelationStore."""

    def __init__(self, inputs: Sequence[InputEnvelope] = ()) -> None:
        self.inputs = list(inputs)
        self._logical_cache_length = -1
        self._logical_cache: list[InputEnvelope] = []
        self.floors: dict[tuple[str, str, int, str], datetime] = {}
        self.cursors: dict[tuple[str, str, int, str], CandidateCursor | None] = {}
        self.ledger: dict[tuple[str, str, int, str, str, str], EvaluationDecision] = {}
        self.ledger_inputs: dict[tuple[str, str, int, str, str, str], InputEnvelope] = (
            {}
        )
        self.raw_incidents: dict[str, list[IncidentRecord]] = {}
        self.raw_states: dict[str, list[EpisodeState]] = {}
        self.state_ids_by_group: dict[
            tuple[tuple[str, str, int, str], str], set[str]
        ] = {}
        self.state_ids_by_token: dict[str, set[str]] = {}
        self.raw_links: dict[tuple[str, str], EvidenceLink] = {}
        self.readback_tokens: set[str] = set()
        self.confirmed_tokens: set[str] = set()
        self.schedules: list[CorrelationCycleStats] = []
        self.operations: list[tuple[str, str]] = []
        self.fetch_started_at: list[float] = []
        self.integrity_states: dict[
            tuple[str, str, int, str], CorrelationIntegrityStatus
        ] = {}
        self.integrity_events: list[dict[str, Any]] = []
        self.projection_contract_valid = True
        self.projection_coverage_complete = True

    def ensure_scope(
        self, scope: RuleScope, compiled: CompiledRule, evaluation_floor: datetime
    ) -> datetime:
        del compiled
        self.operations.append(("ensure_scope", ""))
        return self.floors.setdefault(scope.key, evaluation_floor)

    def check_scope_integrity(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
        *,
        ruleset_fingerprint: str,
        checked_at: datetime,
    ) -> CorrelationIntegrityStatus:
        del compiled, evaluation_floor
        self.operations.append(("check_scope_integrity", scope.rule_id))
        persisted = self.integrity_states.get(scope.key)
        if persisted is not None and persisted.blocked:
            return persisted

        violation_type = ""
        input_kind = ""
        input_id = ""
        ledger_observed_at = None
        canonical_observed_at = None
        if not self.projection_contract_valid:
            violation_type = "projection_contract_mismatch"
        elif not self.projection_coverage_complete:
            violation_type = "projection_coverage_gap"
        else:
            logical = {item.tagged_id: item for item in self._logical_inputs()}
            for key, ledgered in sorted(self.ledger_inputs.items()):
                if key[:4] != scope.key:
                    continue
                canonical = logical.get(ledgered.tagged_id)
                if canonical is not None and canonical.observed_at != ledgered.observed_at:
                    violation_type = "canonical_observation_mismatch"
                    input_kind = ledgered.input_kind
                    input_id = ledgered.input_id
                    ledger_observed_at = ledgered.observed_at
                    canonical_observed_at = canonical.observed_at
                    break

        if violation_type:
            status = CorrelationIntegrityStatus(
                "blocked_integrity", 1, (violation_type,), checked_at
            )
            self.integrity_states[scope.key] = status
            self.integrity_events.append(
                {
                    "detected_at": checked_at,
                    "engine_id": scope.engine_id,
                    "ruleset_fingerprint": ruleset_fingerprint,
                    "correlation_rule_id": scope.rule_id,
                    "violation_type": violation_type,
                    "input_kind": input_kind,
                    "input_id": input_id,
                    "ledger_observed_at": ledger_observed_at,
                    "canonical_observed_at": canonical_observed_at,
                }
            )
            return status

        status = CorrelationIntegrityStatus.healthy(checked_at)
        self.integrity_states[scope.key] = status
        return status

    def load_schedule_cursor(self, scope: RuleScope) -> CandidateCursor | None:
        self.operations.append(("load_schedule_cursor", ""))
        persisted = self.cursors.get(scope.key)
        ledgered = [
            item for key, item in self.ledger_inputs.items() if key[:4] == scope.key
        ]
        if not ledgered:
            return persisted
        latest = max(ledgered, key=lambda item: item.order_key)
        recovered = CandidateCursor(
            latest.occurred_at,
            latest.observed_at,
            latest.input_kind,
            latest.input_id,
        )
        if (
            persisted is None
            or (
                persisted.occurred_at,
                persisted.input_kind,
                persisted.input_id,
            )
            < latest.order_key
        ):
            return recovered
        return persisted

    def fetch_candidates(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
        cursor: CandidateCursor | None,
        limit: int,
    ) -> list[InputEnvelope]:
        self.operations.append(("fetch_candidates", ""))
        self.fetch_started_at.append(time.perf_counter())
        values = [
            item
            for item in self._logical_inputs()
            if self._eligible(compiled, item)
            and item.observed_at >= evaluation_floor
            and self._requires_evaluation(scope, item)
        ]

        # Match the production rotating order: unledgered rows beyond the
        # diagnostic cursor first, then wrap. No row is filtered by the cursor.
        def order(item: InputEnvelope) -> tuple[Any, ...]:
            after = True
            if cursor is not None:
                after = item.order_key > (
                    cursor.occurred_at,
                    cursor.input_kind,
                    cursor.input_id,
                )
            return (0 if after else 1, *item.order_key)

        return sorted(values, key=order)[:limit]

    def fetch_context(
        self,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        evaluation_floor: datetime,
        limit: int,
    ) -> list[InputEnvelope]:
        self.operations.append(("fetch_context", candidate.input_id))
        span_ms = compiled.rule.window.milliseconds
        values = [
            item
            for item in self._logical_inputs()
            if self._eligible(compiled, item)
            and item.observed_at >= evaluation_floor
            and not item.invalid_reason
            and abs((item.occurred_at - candidate.occurred_at).total_seconds() * 1000)
            <= span_ms
        ]
        return sorted(values, key=lambda item: item.order_key)[:limit]

    def load_episode_states(
        self,
        scope: RuleScope,
        candidate: InputEnvelope,
        compiled: CompiledRule,
        limit: int,
        revision_token: str = "",
    ) -> list[EpisodeState]:
        self.operations.append(("load_episode_states", revision_token))
        candidate_group_hash: str | None = None
        if "shared_ip" not in compiled.rule.group_by:
            try:
                group_json = canonical_group_json(
                    compiled.rule.group_by, candidate.values
                )
                candidate_group_hash = group_identity(json.loads(group_json))[1]
            except (IdentityNormalizationError, TypeError, ValueError):
                return []
        span = compiled.rule.window.milliseconds / 1000.0
        current: dict[str, EpisodeState] = {}
        if candidate_group_hash is None:
            episode_ids = set(self.raw_states)
        else:
            episode_ids = set(
                self.state_ids_by_group.get((scope.key, candidate_group_hash), ())
            )
        if revision_token:
            episode_ids.update(self.state_ids_by_token.get(revision_token, ()))
        for episode_id in episode_ids:
            records = self.raw_states[episode_id]
            eligible = [
                state
                for state in records
                if state.scope == scope
                and (
                    (
                        state.revision_token in self.confirmed_tokens
                        and (
                            candidate_group_hash is None
                            or state.group_key_hash == candidate_group_hash
                        )
                        and state.window_start
                        <= candidate.occurred_at + timedelta(seconds=span)
                        and state.window_end
                        >= candidate.occurred_at - timedelta(seconds=span)
                    )
                    or (revision_token and state.revision_token == revision_token)
                )
            ]
            if eligible:
                current[episode_id] = max(
                    eligible, key=lambda state: (state.revision, state.updated_at)
                )
        if len(current) > limit:
            raise OverflowError(f"bounded episode-state query exceeds {limit} rows")
        return list(current.values())

    def load_incidents(
        self, incident_ids: Sequence[str], *, include_unconfirmed: bool = False
    ) -> Mapping[str, IncidentRecord]:
        self.operations.append(
            ("load_incidents_raw" if include_unconfirmed else "load_incidents", "")
        )
        result: dict[str, IncidentRecord] = {}
        for incident_id in incident_ids:
            values = self.raw_incidents.get(incident_id, [])
            if not include_unconfirmed:
                values = [
                    record
                    for record in values
                    if str(record.values["revision_token"]) in self.confirmed_tokens
                ]
            if values:
                result[incident_id] = max(
                    values,
                    key=lambda record: (
                        record.revision,
                        record.values["updated_at"],
                    ),
                )
        return result

    def load_incident_members(
        self, incident_id: str, limit: int
    ) -> list[InputEnvelope]:
        self.operations.append(("load_incident_members", incident_id))
        if limit < 1:
            raise ValueError("incident-member limit must be positive")
        links = sorted(
            (
                link
                for link in self.current_links().values()
                if link.incident_id == incident_id
            ),
            key=lambda link: (link.occurred_at, link.input_kind, link.input_id),
        )
        if len(links) > limit:
            raise OverflowError(
                f"bounded confirmed incident membership exceeds {limit} rows"
            )
        return [
            InputEnvelope(
                link.input_kind,
                link.input_id,
                link.occurred_at,
                link.observed_at,
                dict(link.snapshot),
            )
            for link in links
        ]

    def write_incident(self, incident: IncidentRecord) -> bool:
        token = str(incident.values["revision_token"])
        self.operations.append(("write_incident", token))
        rows = self.raw_incidents.setdefault(incident.incident_id, [])
        identity = (incident.revision, incident.state_hash, token)
        if any(
            (row.revision, row.state_hash, str(row.values["revision_token"]))
            == identity
            for row in rows
        ):
            return False
        rows.append(incident)
        return True

    def load_link_ids(self, incident_id: str) -> set[str]:
        self.operations.append(("load_link_ids", incident_id))
        return {
            link_id
            for (link_id, token), link in self.raw_links.items()
            if link.incident_id == incident_id and token in self.confirmed_tokens
        }

    def write_links(self, links: Sequence[EvidenceLink]) -> tuple[int, int]:
        if links:
            self.operations.append(
                ("write_links", links[0].introduction_revision_token)
            )
        detection_count = 0
        event_count = 0
        for link in links:
            key = (link.link_id, link.introduction_revision_token)
            if key not in self.raw_links:
                self.raw_links[key] = link
            detection_count += int(link.input_kind == "detection")
            event_count += int(link.input_kind == "event")
        return detection_count, event_count

    def write_episode_states(self, states: Sequence[EpisodeState]) -> int:
        if states:
            self.operations.append(("write_episode_states", states[0].revision_token))
        inserted = 0
        for state in states:
            rows = self.raw_states.setdefault(state.episode_state_id, [])
            identity = (state.revision, state.state_hash, state.revision_token)
            if not any(
                (row.revision, row.state_hash, row.revision_token) == identity
                for row in rows
            ):
                rows.append(state)
                self.state_ids_by_group.setdefault(
                    (state.scope.key, state.group_key_hash), set()
                ).add(state.episode_state_id)
                self.state_ids_by_token.setdefault(state.revision_token, set()).add(
                    state.episode_state_id
                )
                inserted += 1
        return inserted

    def confirm_decision(
        self, scope: RuleScope, candidate: InputEnvelope, decision: EvaluationDecision
    ) -> None:
        del scope, candidate
        token = decision.revision_token
        self.operations.append(("confirm_decision", token))
        expected = decision.expected_incident or decision.incident
        if expected is not None:
            expected_token = str(expected.values["revision_token"])
            rows = self.raw_incidents.get(expected.incident_id, ())
            if not any(
                row.revision == expected.revision
                and row.state_hash == expected.state_hash
                and str(row.values["revision_token"]) == expected_token
                for row in rows
            ):
                raise RuntimeError("incident confirmation failed")
        for link in decision.links:
            if (link.link_id, token) not in self.raw_links:
                raise RuntimeError("link confirmation failed")
        for expected_state in decision.episode_states:
            rows = self.raw_states.get(expected_state.episode_state_id, ())
            if not any(
                state.revision == expected_state.revision
                and state.state_hash == expected_state.state_hash
                and state.revision_token == token
                for state in rows
            ):
                raise RuntimeError("episode-state confirmation failed")
        self.readback_tokens.add(token)

    def mark_evaluated(
        self,
        scope: RuleScope,
        entries: Sequence[tuple[InputEnvelope, EvaluationDecision]],
    ) -> int:
        token = entries[0][1].revision_token if entries else ""
        self.operations.append(("mark_evaluated", token))
        for candidate, decision in entries:
            has_effects = bool(
                decision.incident is not None
                or decision.links
                or decision.episode_states
            )
            if has_effects and decision.revision_token not in self.readback_tokens:
                raise RuntimeError("cannot ledger an unconfirmed decision")
            key = self._ledger_key(scope, candidate)
            prior = self.ledger.get(key)
            if prior is not None:
                prior_input = self.ledger_inputs[key]
                expected = (
                    candidate.occurred_at,
                    candidate.observed_at,
                    decision.evaluation_action,
                    decision.lateness_status,
                    decision.resulting_incident_id,
                    decision.revision_token,
                    decision.reason_code,
                    str(candidate.values.get("source_type", "")),
                    str(candidate.values.get("host_name", "")),
                    str(candidate.values.get("validation_id", "")),
                )
                actual = (
                    prior_input.occurred_at,
                    prior_input.observed_at,
                    prior.evaluation_action,
                    prior.lateness_status,
                    prior.resulting_incident_id,
                    prior.revision_token,
                    prior.reason_code,
                    str(prior_input.values.get("source_type", "")),
                    str(prior_input.values.get("host_name", "")),
                    str(prior_input.values.get("validation_id", "")),
                )
                if actual != expected:
                    raise CorrelationPersistenceConflict(
                        "evaluation-ledger identity has conflicting immutable content"
                    )
                continue
            self.ledger[key] = decision
            self.ledger_inputs[key] = candidate
            self.confirmed_tokens.add(decision.revision_token)
        return len(entries)

    def fetch_backlog(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
    ) -> CorrelationBacklog:
        self.operations.append(("fetch_backlog", ""))
        eligible = [
            item
            for item in self._logical_inputs()
            if self._eligible(compiled, item) and item.observed_at >= evaluation_floor
        ]
        values = [item for item in eligible if self._requires_evaluation(scope, item)]
        newest = max(eligible, key=lambda item: item.order_key, default=None)
        if not values:
            return CorrelationBacklog(
                newest.occurred_at if newest else None,
                newest.observed_at if newest else None,
                newest.input_kind if newest else "",
                newest.input_id if newest else "",
                0,
                None,
                0.0,
            )
        oldest = min(item.observed_at for item in values)
        age = max(0.0, (datetime.now(timezone.utc) - oldest).total_seconds())
        return CorrelationBacklog(
            newest.occurred_at,
            newest.observed_at,
            newest.input_kind,
            newest.input_id,
            len(values),
            oldest,
            age,
        )

    def save_schedule(self, stats: CorrelationCycleStats) -> None:
        self.operations.append(("save_schedule", ""))
        self.schedules.append(stats)
        self.cursors[stats.scope.key] = stats.cursor

    def current_incidents(self) -> dict[str, IncidentRecord]:
        return {
            incident_id: record
            for incident_id in self.raw_incidents
            if (record := self.load_incidents([incident_id]).get(incident_id))
            is not None
        }

    def current_links(self) -> dict[str, EvidenceLink]:
        result: dict[str, EvidenceLink] = {}
        for (link_id, token), link in self.raw_links.items():
            if token in self.confirmed_tokens:
                result.setdefault(link_id, link)
        return result

    def _logical_inputs(self) -> list[InputEnvelope]:
        """Model the source queries' GROUP BY logical ID collapse."""

        if len(self.inputs) == self._logical_cache_length:
            return self._logical_cache
        result: dict[str, InputEnvelope] = {}
        for item in self.inputs:
            prior = result.get(item.tagged_id)
            if prior is None:
                result[item.tagged_id] = item
                continue
            prior_semantic = (prior.occurred_at, canonical_json(dict(prior.values)))
            item_semantic = (item.occurred_at, canonical_json(dict(item.values)))
            if prior_semantic != item_semantic:
                winner = min(
                    (prior, item),
                    key=lambda value: (
                        value.observed_at,
                        value.occurred_at,
                        canonical_json(dict(value.values)),
                    ),
                )
                result[item.tagged_id] = InputEnvelope(
                    winner.input_kind,
                    winner.input_id,
                    winner.occurred_at,
                    min(prior.observed_at, item.observed_at),
                    winner.values,
                    "conflicting_immutable_values",
                )
            elif item.observed_at < prior.observed_at:
                result[item.tagged_id] = item
        self._logical_cache_length = len(self.inputs)
        self._logical_cache = list(result.values())
        return self._logical_cache

    @staticmethod
    def _ledger_key(
        scope: RuleScope, item: InputEnvelope
    ) -> tuple[str, str, int, str, str, str]:
        return (*scope.key, item.input_kind, item.input_id)

    def _eligible(self, compiled: CompiledRule, item: InputEnvelope) -> bool:
        if item.input_kind == "detection":
            return True
        if item.input_kind != "event":
            return False
        if item.invalid_reason == "conflicting_immutable_values":
            return any(
                raw.tagged_id == item.tagged_id
                and any(
                    selector.source == "event" and selector_matches(selector, raw)
                    for selector in compiled.rule.selectors
                )
                for raw in self.inputs
            )
        return any(
            selector.source == "event" and selector_matches(selector, item)
            for selector in compiled.rule.selectors
        )

    def _requires_evaluation(self, scope: RuleScope, item: InputEnvelope) -> bool:
        prior = self.ledger.get(self._ledger_key(scope, item))
        if prior is None:
            return True
        return item.invalid_reason == "conflicting_immutable_values" and not (
            prior.evaluation_action == "invalid_input"
            and prior.reason_code == "conflicting_immutable_values"
        )
