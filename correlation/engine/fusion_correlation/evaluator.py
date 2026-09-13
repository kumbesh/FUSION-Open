"""Bounded threshold, sequence, and join evaluation for compiled rules."""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from .identity import (
    IdentityNormalizationError,
    OwnershipFact,
    canonical_group_json,
    canonical_host,
    canonical_ip,
    canonical_ip_set,
    canonical_principal,
    ownership_fact_matches,
    shared_owned_ips,
)
from .incident import (
    build_incident,
    canonical_json,
    episode_state_identity,
    evaluation_token,
    group_identity,
    incident_identity,
    state_hash,
)
from .models import (
    CompiledRule,
    JoinCondition,
    Predicate,
    Selector,
    SequenceCondition,
    ThresholdCondition,
)
from .runtime_models import (
    EpisodeState,
    EvaluationDecision,
    IncidentRecord,
    InputEnvelope,
    RuleScope,
)


MAX_COMBINATION_ATTEMPTS = 100_000


class CorrelationEvaluationError(RuntimeError):
    """A bounded rule evaluation cannot be completed safely."""


@dataclass(frozen=True)
class PreparedContext:
    """One collapsed source window with a canonical per-group index.

    The engine may reuse this immutable value only for candidates whose
    occurrence timestamp produces the same bounded source window.  Join rules
    retain the complete context because their group is derived from proven
    relations; threshold and sequence rules can safely select their exact
    canonical group without rescanning every unrelated identity.
    """

    logical_inputs: tuple[InputEnvelope, ...]
    inputs_by_group: Mapping[str, tuple[InputEnvelope, ...]]


class CorrelationEvaluator:
    """Evaluate one compiled rule without constructing executable SQL."""

    def __init__(
        self,
        *,
        technique_to_tactics: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self.technique_to_tactics = technique_to_tactics or {}

    def evaluate(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        context: Sequence[InputEnvelope],
        episode_states: Sequence[EpisodeState] = (),
        incidents: Mapping[str, IncidentRecord] | None = None,
        now: datetime | None = None,
        confirmed_members: Mapping[str, Sequence[InputEnvelope]] | None = None,
    ) -> EvaluationDecision:
        token = evaluation_token(scope, candidate)
        if candidate.invalid_reason:
            return EvaluationDecision(
                "invalid_input",
                "not_applicable",
                candidate.invalid_reason,
                token,
            )
        if not candidate.input_id or candidate.input_kind not in {"detection", "event"}:
            return EvaluationDecision(
                "invalid_input", "not_applicable", "invalid_input_identity", token
            )

        logical_context = _collapse_inputs([*context, candidate])
        condition = compiled.rule.condition
        if isinstance(condition, ThresholdCondition):
            matches = self._threshold_matches(compiled, candidate, logical_context)
        elif isinstance(condition, SequenceCondition):
            matches = self._sequence_matches(compiled, candidate, logical_context)
        elif isinstance(condition, JoinCondition):
            matches = self._join_matches(compiled, candidate, logical_context)
        else:  # pragma: no cover - compiler owns the closed condition union
            raise CorrelationEvaluationError("unsupported compiled condition")

        current_incidents = incidents or {}
        confirmed_members_by_incident = confirmed_members or {}
        selected = self._select_match(
            compiled, matches, candidate, episode_states, current_incidents
        )
        if selected is None:
            late_incident_id = self._late_outside_boundary(
                compiled,
                candidate,
                episode_states,
                current_incidents,
                matches,
            )
            if late_incident_id is not None:
                return EvaluationDecision(
                    "no_match",
                    "late_outside_boundary",
                    "late_outside_boundary",
                    token,
                    resulting_incident_id=late_incident_id,
                )
            reconciliation_deadline = candidate.occurred_at + timedelta(
                milliseconds=(
                    compiled.rule.window.milliseconds
                    + compiled.rule.allowed_lateness.milliseconds
                )
            )
            if candidate.observed_at > reconciliation_deadline:
                return EvaluationDecision(
                    "no_match",
                    "late_outside_boundary",
                    "outside_reconciliation_horizon",
                    token,
                )
            partial = self._build_partial_state(
                scope, compiled, candidate, logical_context, episode_states, token, now
            )
            return EvaluationDecision(
                "no_match",
                "not_applicable",
                "condition_not_satisfied",
                token,
                episode_states=(partial,) if partial is not None else (),
            )

        group, qualifying, related_context, selected_owner = selected
        group_json, group_hash = group_identity(group)
        existing_state = selected_owner or _select_existing_episode(
            tuple(state for state in episode_states if not state.incident_id),
            group_hash,
            candidate,
            qualifying,
        )
        existing_incident = (
            current_incidents.get(existing_state.incident_id)
            if existing_state is not None and existing_state.incident_id
            else None
        )
        overlapping_incident_states = [
            state
            for state in episode_states
            if state.group_key_hash == group_hash
            and state.incident_id
            and state.window_start <= candidate.occurred_at <= state.window_end
        ]
        replaying_episode_write = (
            existing_state is not None
            and existing_state.revision_token == token
        )
        collision_increment = (
            0
            if replaying_episode_write
            else max(0, len(overlapping_incident_states) - 1)
        )

        if existing_state is not None and existing_state.incident_id:
            anchor_members = {
                item.tagged_id: item
                for item in confirmed_members_by_incident.get(
                    existing_state.incident_id, ()
                )
            }
            for item in logical_context:
                anchor_members.setdefault(item.tagged_id, item)
            anchor = next(
                (
                    item
                    for item in anchor_members.values()
                    if item.input_kind == existing_state.anchor_kind
                    and item.input_id == existing_state.anchor_id
                ),
                None,
            )
            if anchor is None:
                raise CorrelationEvaluationError(
                    "persisted episode anchor is unavailable from bounded context"
                )
        else:
            anchor = self._anchor(compiled, qualifying)

        if existing_incident is None:
            provisional_incident_id = incident_identity(
                scope, group_json, anchor
            )
            existing_incident = current_incidents.get(provisional_incident_id)
            if existing_incident is not None:
                values = existing_incident.values
                if (
                    str(values.get("episode_anchor_kind", "")) != anchor.input_kind
                    or str(values.get("episode_anchor_id", "")) != anchor.input_id
                ):
                    raise CorrelationEvaluationError(
                        "provisional incident anchor does not match replay"
                    )

        if (
            existing_state is not None and existing_state.incident_id
        ) or existing_incident is not None:
            existing_values = existing_incident.values if existing_incident else {}
            deadline = existing_values.get(
                "late_accept_until",
                existing_state.late_accept_until if existing_state else None,
            )
            if deadline is None:
                raise CorrelationEvaluationError("existing incident lateness deadline is missing")
            status = str(existing_values.get("status", "new"))
            closed_at = existing_values.get("closed_at")
            prior_window_start = (
                existing_state.window_start
                if existing_state is not None and existing_state.incident_id
                else existing_values["episode_window_start"]
            )
            prior_window_end = (
                existing_state.window_end
                if existing_state is not None and existing_state.incident_id
                else existing_values["episode_window_end"]
            )
            occurrence_allowed = prior_window_start <= candidate.occurred_at <= prior_window_end
            if status == "closed" and closed_at is not None:
                occurrence_allowed = occurrence_allowed and candidate.occurred_at <= closed_at
            if not occurrence_allowed or candidate.observed_at > deadline:
                return EvaluationDecision(
                    "no_match",
                    "late_outside_boundary",
                    "late_outside_boundary",
                    token,
                    resulting_incident_id=(
                        existing_state.incident_id
                        if existing_state is not None
                        else existing_incident.incident_id
                    ),
                )

        qualifying_ids = {item.tagged_id for item in qualifying}
        related_ids = {item.tagged_id for item in related_context}
        prior_owned = existing_state.owned_tagged_ids if existing_state else frozenset()
        confirmed_incident_id = (
            existing_state.incident_id
            if existing_state is not None and existing_state.incident_id
            else existing_incident.incident_id
            if existing_incident is not None
            else ""
        )
        confirmed_by_tag = {
            item.tagged_id: item
            for item in confirmed_members_by_incident.get(confirmed_incident_id, ())
        }
        membership_context = [
            *confirmed_by_tag.values(),
            *(
                item
                for item in logical_context
                if item.tagged_id not in confirmed_by_tag
            ),
        ]
        episode_start = (
            existing_state.window_start
            if existing_state is not None and existing_state.incident_id
            else existing_incident.values["episode_window_start"]
            if existing_incident is not None
            else min(item.occurred_at for item in qualifying)
        )
        episode_end = (
            existing_state.window_end
            if existing_state is not None and existing_state.incident_id
            else existing_incident.values["episode_window_end"]
            if existing_incident is not None
            else episode_start + timedelta(seconds=compiled.rule.window.seconds)
        )
        if any(
            not episode_start <= item.occurred_at <= episode_end
            for item in confirmed_by_tag.values()
        ):
            raise CorrelationEvaluationError(
                "confirmed incident member is outside its immutable episode interval"
            )
        incident_values = existing_incident.values if existing_incident else {}
        member_deadline = incident_values.get(
            "late_accept_until",
            episode_end + timedelta(seconds=compiled.rule.allowed_lateness.seconds),
        )
        member_closed_at = (
            incident_values.get("closed_at")
            if str(incident_values.get("status", "new")) == "closed"
            else None
        )
        if any(
            item.invalid_reason and item.tagged_id in prior_owned
            for item in logical_context
        ):
            raise CorrelationEvaluationError(
                "previously owned input now has conflicting immutable values"
            )

        def eligible_member(item: InputEnvelope) -> bool:
            if not episode_start <= item.occurred_at <= episode_end:
                return False
            if item.tagged_id in confirmed_by_tag:
                return True
            if item.tagged_id in prior_owned:
                return True
            if item.invalid_reason or item.observed_at > member_deadline:
                return False
            if member_closed_at is not None and item.occurred_at > member_closed_at:
                return False
            return (
                item.tagged_id in qualifying_ids
                or item.tagged_id in related_ids
                or self._approved_member(compiled, item, group)
            )

        members = tuple(
            item
            for item in membership_context
            if eligible_member(item)
        )
        rule_info = {
            "type": compiled.rule.incident.incident_type,
            "title": compiled.rule.incident.title_template,
            "severity": compiled.rule.incident.severity,
            "confidence": compiled.rule.incident.confidence,
            "primary": dict(compiled.rule.incident.primary),
            "condition_type": compiled.condition_kind,
            "condition": compiled.rule.condition.semantic_plan(),
            "tactic_ids": compiled.rule.mitre.tactic_ids,
            "technique_ids": compiled.rule.mitre.technique_ids,
            "false_positives": compiled.rule.false_positives,
        }
        incident, proposed_links = build_incident(
            scope=scope,
            rule_info=rule_info,
            group=group,
            qualifying=qualifying,
            members=members,
            anchor=anchor,
            window_seconds=compiled.rule.window.seconds,
            allowed_lateness_seconds=compiled.rule.allowed_lateness.seconds,
            revision_token=token,
            now=now,
            existing=existing_incident,
            technique_to_tactics=self.technique_to_tactics,
        )
        # The store filters only confirmation-backed link identities.  Do not
        # trust an incident snapshot for this decision: after a partial write,
        # evidence_json may describe a link that was never durably written.
        links = proposed_links

        ordered_qualifying = sorted(qualifying, key=lambda item: item.order_key)
        owned_detection_ids = tuple(
            sorted(
                {
                    item.input_id
                    for item in members
                    if item.input_kind == "detection"
                }
            )
        )
        owned_event_ids = tuple(
            sorted(
                {item.input_id for item in members if item.input_kind == "event"}
            )
        )
        episode_id = (
            existing_state.episode_state_id
            if existing_state is not None
            else episode_state_identity(scope, group_json, ordered_qualifying[0])
        )
        if existing_state is not None and existing_state.incident_id:
            canonical_qualifying_inputs = list(
                json.loads(existing_state.canonical_qualifying_set_json)
            )
        elif existing_incident is not None:
            try:
                canonical_qualifying_inputs = list(
                    json.loads(
                        str(existing_incident.values.get("evidence_json", "{}"))
                    ).get("qualifying_input_ids", ())
                )
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise CorrelationEvaluationError(
                    "provisional incident qualifying set is invalid"
                ) from exc
        else:
            canonical_qualifying_inputs = [
                item.tagged_id for item in ordered_qualifying
            ]
        state_values = {
            "scope": scope.key,
            "group_key_json": group_json,
            "group_key_hash": group_hash,
            "episode_state_id": episode_id,
            "canonical_qualifying_inputs": canonical_qualifying_inputs,
            "anchor_kind": anchor.input_kind,
            "anchor_id": anchor.input_id,
            "anchor_time": anchor.occurred_at,
            "window_start": episode_start,
            "window_end": episode_end,
            "incident_id": incident.incident_id,
            "owned_detection_ids": owned_detection_ids,
            "owned_event_ids": owned_event_ids,
            "last_input_observed_at": max(
                [item.observed_at for item in members]
                + (
                    [existing_state.last_input_observed_at]
                    if existing_state is not None
                    else []
                )
            ),
            "late_accept_until": incident.values["late_accept_until"],
            "collision_count": (
                existing_state.collision_count if existing_state else 0
            )
            + collision_increment,
        }
        episode = EpisodeState(
            scope=scope,
            group_key_json=group_json,
            group_key_hash=group_hash,
            episode_state_id=episode_id,
            revision_token=token,
            canonical_qualifying_set_json=canonical_json(
                state_values["canonical_qualifying_inputs"]
            ),
            anchor_kind=anchor.input_kind,
            anchor_id=anchor.input_id,
            anchor_time=anchor.occurred_at,
            window_start=episode_start,
            window_end=episode_end,
            incident_id=incident.incident_id,
            owned_detection_ids=owned_detection_ids,
            owned_event_ids=owned_event_ids,
            last_input_observed_at=state_values["last_input_observed_at"],
            late_accept_until=incident.values["late_accept_until"],
            collision_count=int(state_values["collision_count"]),
            state_hash=state_hash(state_values),
            updated_at=(
                existing_state.updated_at
                if replaying_episode_write
                else _utc(now or datetime.now(timezone.utc))
            ),
            revision=(
                existing_state.revision
                if replaying_episode_write
                else existing_state.revision + 1
                if existing_state
                else 1
            ),
        )
        if replaying_episode_write:
            if episode.state_hash != existing_state.state_hash:
                raise CorrelationEvaluationError(
                    "provisional episode state conflicts with deterministic replay"
                )
            episode = existing_state

        if existing_incident is not None and incident.state_hash == existing_incident.state_hash:
            incident_to_write = None
            expected_incident = existing_incident
        else:
            incident_to_write = incident
            expected_incident = incident
        action = "created" if existing_incident is None else "updated"
        if existing_incident is not None and str(existing_incident.values.get("status")) == "closed":
            action = "enriched_closed"
        lateness = (
            "late_within_boundary"
            if candidate.observed_at > episode_end
            else "on_time"
        )
        return EvaluationDecision(
            action,
            lateness,
            "matched",
            token,
            resulting_incident_id=incident.incident_id,
            incident=incident_to_write,
            expected_incident=expected_incident,
            links=links,
            episode_states=(episode,),
            matched=True,
        )

    def candidate_matches_any_selector(
        self, compiled: CompiledRule, candidate: InputEnvelope
    ) -> bool:
        return any(
            selector_matches(selector, candidate)
            for selector in compiled.rule.selectors
        )

    def prepare_context(
        self, compiled: CompiledRule, context: Sequence[InputEnvelope]
    ) -> PreparedContext:
        """Collapse and index one bounded source window exactly once."""

        logical = _collapse_inputs(context)
        if isinstance(compiled.rule.condition, JoinCondition):
            return PreparedContext(logical, {})
        grouped: dict[str, list[InputEnvelope]] = {}
        for item in logical:
            key = _group_key(compiled, item)
            if key is not None:
                grouped.setdefault(key, []).append(item)
        return PreparedContext(
            logical,
            {key: tuple(items) for key, items in grouped.items()},
        )

    def context_for_candidate(
        self,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        prepared: PreparedContext,
    ) -> tuple[InputEnvelope, ...]:
        """Return the complete join window or one exact canonical group."""

        if isinstance(compiled.rule.condition, JoinCondition):
            return prepared.logical_inputs
        key = _group_key(compiled, candidate)
        if key is None:
            return (candidate,)
        return prepared.inputs_by_group.get(key, (candidate,))

    def _threshold_matches(
        self,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        context: Sequence[InputEnvelope],
    ) -> list[
        tuple[
            Mapping[str, Any],
            tuple[InputEnvelope, ...],
            tuple[InputEnvelope, ...],
        ]
    ]:
        condition = compiled.rule.condition
        assert isinstance(condition, ThresholdCondition)
        selector = compiled.rule.selector_map[condition.selector]
        if not selector_matches(selector, candidate):
            return []
        grouped = _group_inputs(compiled, context, selector)
        candidate_group = _safe_group(compiled, candidate)
        if candidate_group is None:
            return []
        items = grouped.get(canonical_json(candidate_group), ())
        matches: list[
            tuple[
                Mapping[str, Any],
                tuple[InputEnvelope, ...],
                tuple[InputEnvelope, ...],
            ]
        ] = []
        for combination in _bounded_combinations(items, condition.min_count):
            if candidate.tagged_id not in {item.tagged_id for item in combination}:
                continue
            if max(item.occurred_at for item in combination) - min(
                item.occurred_at for item in combination
            ) > timedelta(milliseconds=compiled.rule.window.milliseconds):
                continue
            if condition.distinct_by is not None:
                distinct: set[str] = set()
                for item in combination:
                    try:
                        component = _canonical_group_component(
                            condition.distinct_by, item.values
                        )
                    except (IdentityNormalizationError, TypeError, ValueError):
                        continue
                    distinct.add(canonical_json(component))
                if len(distinct) < int(condition.min_distinct or 0):
                    continue
            matches.append((candidate_group, tuple(combination), ()))
        return matches

    def _sequence_matches(
        self,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        context: Sequence[InputEnvelope],
    ) -> list[
        tuple[
            Mapping[str, Any],
            tuple[InputEnvelope, ...],
            tuple[InputEnvelope, ...],
        ]
    ]:
        condition = compiled.rule.condition
        assert isinstance(condition, SequenceCondition)
        candidate_group = _safe_group(compiled, candidate)
        if candidate_group is None:
            return []
        key = canonical_json(candidate_group)
        stage_options: list[list[tuple[InputEnvelope, ...]]] = []
        for stage in condition.stages:
            selector = compiled.rule.selector_map[stage.selector]
            items = [
                item
                for item in context
                if selector_matches(selector, item)
                and _group_key(compiled, item) == key
            ]
            stage_options.append(list(_bounded_combinations(items, stage.min_count)))
        if any(not options for options in stage_options):
            return []
        matches: list[
            tuple[
                Mapping[str, Any],
                tuple[InputEnvelope, ...],
                tuple[InputEnvelope, ...],
            ]
        ] = []
        attempts = 0
        for chosen_stages in itertools.product(*stage_options):
            attempts += 1
            if attempts > MAX_COMBINATION_ATTEMPTS:
                raise CorrelationEvaluationError("sequence combination bound exceeded")
            flattened = tuple(item for stage in chosen_stages for item in stage)
            if len({item.tagged_id for item in flattened}) != len(flattened):
                continue
            if candidate.tagged_id not in {item.tagged_id for item in flattened}:
                continue
            if any(
                max(item.occurred_at for item in chosen_stages[index])
                >= min(item.occurred_at for item in chosen_stages[index + 1])
                for index in range(len(chosen_stages) - 1)
            ):
                continue
            if max(item.occurred_at for item in flattened) - min(
                item.occurred_at for item in flattened
            ) > timedelta(milliseconds=compiled.rule.window.milliseconds):
                continue
            matches.append((candidate_group, flattened, ()))
        return matches

    def _sequence_partial_prefix(
        self,
        compiled: CompiledRule,
        context: Sequence[InputEnvelope],
        *,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        late_accept_until: datetime | None = None,
    ) -> tuple[InputEnvelope, ...]:
        """Return the canonical longest complete strict sequence prefix."""

        condition = compiled.rule.condition
        assert isinstance(condition, SequenceCondition)
        longest: tuple[InputEnvelope, ...] = ()
        attempts = 0
        # The complete sequence is handled by ``_sequence_matches``. Partial
        # state exists only for one or more fully satisfied leading stages.
        for prefix_length in range(1, len(condition.stages)):
            stage_options: list[list[tuple[InputEnvelope, ...]]] = []
            for stage in condition.stages[:prefix_length]:
                selector = compiled.rule.selector_map[stage.selector]
                items = [
                    item
                    for item in context
                    if selector_matches(selector, item)
                    and (window_start is None or item.occurred_at >= window_start)
                    and (window_end is None or item.occurred_at <= window_end)
                    and (
                        late_accept_until is None
                        or item.observed_at <= late_accept_until
                    )
                ]
                stage_options.append(
                    list(_bounded_combinations(items, stage.min_count))
                )
            if any(not options for options in stage_options):
                break
            valid: list[tuple[InputEnvelope, ...]] = []
            for chosen_stages in itertools.product(*stage_options):
                attempts += 1
                if attempts > MAX_COMBINATION_ATTEMPTS:
                    raise CorrelationEvaluationError(
                        "sequence partial-prefix combination bound exceeded"
                    )
                flattened = tuple(
                    item for stage_items in chosen_stages for item in stage_items
                )
                if len({item.tagged_id for item in flattened}) != len(flattened):
                    continue
                if any(
                    max(item.occurred_at for item in chosen_stages[index])
                    >= min(item.occurred_at for item in chosen_stages[index + 1])
                    for index in range(len(chosen_stages) - 1)
                ):
                    continue
                earliest = min(item.occurred_at for item in flattened)
                latest = max(item.occurred_at for item in flattened)
                if latest - earliest > timedelta(
                    milliseconds=compiled.rule.window.milliseconds
                ):
                    continue
                natural_deadline = earliest + timedelta(
                    milliseconds=(
                        compiled.rule.window.milliseconds
                        + compiled.rule.allowed_lateness.milliseconds
                    )
                )
                if any(item.observed_at > natural_deadline for item in flattened):
                    continue
                valid.append(flattened)
            if not valid:
                break
            longest = min(
                valid,
                key=lambda values: canonical_json(
                    [
                        item.tagged_id
                        for item in sorted(values, key=lambda item: item.order_key)
                    ]
                ),
            )
        return tuple(sorted(longest, key=lambda item: item.order_key))

    def _join_matches(
        self,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        context: Sequence[InputEnvelope],
    ) -> list[
        tuple[
            Mapping[str, Any],
            tuple[InputEnvelope, ...],
            tuple[InputEnvelope, ...],
        ]
    ]:
        condition = compiled.rule.condition
        assert isinstance(condition, JoinCondition)
        options: list[list[InputEnvelope]] = []
        for selector_name in condition.require:
            selector = compiled.rule.selector_map[selector_name]
            options.append(
                [item for item in context if selector_matches(selector, item)]
            )
        if any(not values for values in options):
            return []
        matches: list[
            tuple[
                Mapping[str, Any],
                tuple[InputEnvelope, ...],
                tuple[InputEnvelope, ...],
            ]
        ] = []
        ownership_roles = _ownership_join_roles(compiled)
        ownership_options = (
            options[condition.require.index(ownership_roles[2])]
            if ownership_roles is not None
            else []
        )
        seen: set[str] = set()
        attempts = 0
        for selected_values in itertools.product(*options):
            attempts += 1
            if attempts > MAX_COMBINATION_ATTEMPTS:
                raise CorrelationEvaluationError("join combination bound exceeded")
            if len({item.tagged_id for item in selected_values}) != len(selected_values):
                continue
            if max(item.occurred_at for item in selected_values) - min(
                item.occurred_at for item in selected_values
            ) > timedelta(milliseconds=compiled.rule.window.milliseconds):
                continue
            by_selector = dict(zip(condition.require, selected_values, strict=True))
            relation_values: dict[str, Any] = {}
            if not all(
                _relation_matches(relation, by_selector, relation_values, compiled)
                for relation in condition.relations
            ):
                continue
            related: tuple[InputEnvelope, ...] = ()
            if ownership_roles is not None:
                _, _, ownership_name = ownership_roles
                base_start = min(item.occurred_at for item in selected_values)
                base_end = base_start + timedelta(
                    milliseconds=compiled.rule.window.milliseconds
                )
                proven: list[InputEnvelope] = []
                proven_ips: set[str] = set()
                for ownership in ownership_options:
                    if not base_start <= ownership.occurred_at <= base_end:
                        continue
                    trial = dict(by_selector)
                    trial[ownership_name] = ownership
                    derived: dict[str, Any] = {}
                    if not all(
                        _relation_matches(relation, trial, derived, compiled)
                        for relation in condition.relations
                    ):
                        continue
                    proven.append(ownership)
                    proven_ips.update(derived.get("shared_ip_intersection", ()))
                if not proven or not proven_ips:
                    continue
                relation_values["shared_ip"] = sorted(proven_ips)[0]
                relation_values["shared_ip_intersection"] = tuple(sorted(proven_ips))
                selected_ids = {item.tagged_id for item in selected_values}
                related = tuple(
                    sorted(
                        (
                            item
                            for item in proven
                            if item.tagged_id not in selected_ids
                        ),
                        key=lambda item: item.order_key,
                    )
                )
            if candidate.tagged_id not in {
                item.tagged_id for item in (*selected_values, *related)
            }:
                continue
            group: dict[str, Any] = {}
            for field in compiled.rule.group_by:
                try:
                    if field == "shared_ip":
                        value = _canonical_group_component(
                            field, {field: relation_values.get("shared_ip")}
                        )
                    elif field == "host_name" and ownership_roles is not None:
                        # The endpoint side owns the host identity in the
                        # direction-safe cross-source mapping; a Suricata sensor
                        # hostname is not an endpoint alias.
                        endpoint = by_selector[ownership_roles[1]]
                        value = _canonical_group_component(field, endpoint.values)
                    else:
                        canonical_values: dict[str, Any] = {}
                        for item in selected_values:
                            component = _canonical_group_component(field, item.values)
                            canonical_values[canonical_json(component)] = component
                        value = (
                            next(iter(canonical_values.values()))
                            if len(canonical_values) == 1
                            else None
                        )
                except (IdentityNormalizationError, TypeError, ValueError):
                    value = None
                if value in (None, ""):
                    group = {}
                    break
                group[field] = value
            if group:
                identity = canonical_json(
                    {
                        "group": group,
                        "qualifying": sorted(item.tagged_id for item in selected_values),
                        "related": sorted(item.tagged_id for item in related),
                    }
                )
                if identity not in seen:
                    seen.add(identity)
                    matches.append((group, tuple(selected_values), related))
        return matches

    def _select_match(
        self,
        compiled: CompiledRule,
        matches: Sequence[
            tuple[
                Mapping[str, Any],
                tuple[InputEnvelope, ...],
                tuple[InputEnvelope, ...],
            ]
        ],
        candidate: InputEnvelope,
        states: Sequence[EpisodeState],
        incidents: Mapping[str, IncidentRecord],
    ) -> tuple[
        Mapping[str, Any],
        tuple[InputEnvelope, ...],
        tuple[InputEnvelope, ...],
        EpisodeState | None,
    ] | None:
        if not matches:
            return None

        eligible_matches: list[
            tuple[
                Mapping[str, Any],
                tuple[InputEnvelope, ...],
                tuple[InputEnvelope, ...],
                EpisodeState | None,
            ]
        ] = []
        for group, members, related in matches:
            _, group_hash = group_identity(group)
            group_states = [
                state
                for state in states
                if state.group_key_hash == group_hash and state.incident_id
            ]
            candidate_owners = [
                state
                for state in group_states
                if candidate.tagged_id in state.owned_tagged_ids
                or state.window_start <= candidate.occurred_at <= state.window_end
            ]
            attachable_owners: list[EpisodeState] = []
            for possible_owner in candidate_owners:
                owner_incident = incidents.get(possible_owner.incident_id)
                owner_values = owner_incident.values if owner_incident else {}
                deadline = owner_values.get(
                    "late_accept_until", possible_owner.late_accept_until
                )
                status = str(owner_values.get("status", "new"))
                closed_at = owner_values.get("closed_at")
                new_members = [
                    item
                    for item in (*members, *related)
                    if item.tagged_id not in possible_owner.owned_tagged_ids
                ]
                if any(item.observed_at > deadline for item in new_members):
                    continue
                if status == "closed" and closed_at is not None and any(
                    item.occurred_at > closed_at for item in new_members
                ):
                    continue
                attachable_owners.append(possible_owner)
            owner = (
                min(
                    attachable_owners,
                    key=lambda state: (
                        abs(
                            (
                                candidate.occurred_at
                                - (state.anchor_time or state.window_start)
                            ).total_seconds()
                        ),
                        state.incident_id,
                        state.episode_state_id,
                    ),
                )
                if attachable_owners
                else None
            )
            if candidate_owners and owner is None:
                # The occurrence overlaps a qualified episode, but every such
                # episode is outside its immutable observation/closure cap.
                # Do not clone the occurrence into a replacement incident.
                continue
            member_ids = {item.tagged_id for item in (*members, *related)}
            if any(
                bool(member_ids & state.owned_tagged_ids)
                for state in group_states
                if owner is None or state.episode_state_id != owner.episode_state_id
            ):
                # Evidence owned by another episode can never seed this one.
                continue
            if owner is None:
                start = min(item.occurred_at for item in (*members, *related))
                deadline = start + timedelta(
                    milliseconds=(
                        compiled.rule.window.milliseconds
                        + compiled.rule.allowed_lateness.milliseconds
                    )
                )
                if any(
                    item.observed_at > deadline
                    for item in (*members, *related)
                ):
                    continue
            eligible_matches.append((group, members, related, owner))

        if not eligible_matches:
            return None

        def key(
            value: tuple[
                Mapping[str, Any],
                tuple[InputEnvelope, ...],
                tuple[InputEnvelope, ...],
                EpisodeState | None,
            ]
        ) -> tuple[Any, ...]:
            group, members, related, owner = value
            if owner is not None:
                owner_key = (0, owner.incident_id, owner.episode_state_id)
            else:
                owner_key = (1, "", "")
            serialized = canonical_json(
                [item.tagged_id for item in sorted(members, key=lambda item: item.order_key)]
            )
            related_serialized = canonical_json(
                [
                    item.tagged_id
                    for item in sorted(related, key=lambda item: item.order_key)
                ]
            )
            return (*owner_key, serialized, related_serialized, canonical_json(group))

        return min(eligible_matches, key=key)

    def _late_outside_boundary(
        self,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        states: Sequence[EpisodeState],
        incidents: Mapping[str, IncidentRecord],
        matches: Sequence[
            tuple[
                Mapping[str, Any],
                tuple[InputEnvelope, ...],
                tuple[InputEnvelope, ...],
            ]
        ] = (),
    ) -> str | None:
        if not self.candidate_matches_any_selector(compiled, candidate):
            return None
        derived_owners: list[EpisodeState] = []
        for match_group, members, related in matches:
            _, match_hash = group_identity(match_group)
            member_ids = {item.tagged_id for item in (*members, *related)}
            derived_owners.extend(
                state
                for state in states
                if state.incident_id
                and state.group_key_hash == match_hash
                and (
                    candidate.tagged_id in state.owned_tagged_ids
                    or state.window_start
                    <= candidate.occurred_at
                    <= state.window_end
                )
                and bool(member_ids - state.owned_tagged_ids)
            )
        if derived_owners:
            owner = min(
                derived_owners,
                key=lambda state: (
                    abs(
                        (
                            candidate.occurred_at
                            - (state.anchor_time or state.window_start)
                        ).total_seconds()
                    ),
                    state.incident_id,
                    state.episode_state_id,
                ),
            )
            return owner.incident_id
        group = _safe_group(compiled, candidate)
        if group is None:
            return None
        _, group_hash = group_identity(group)
        owners = [
            state
            for state in states
            if state.group_key_hash == group_hash
            and state.incident_id
            and state.window_start <= candidate.occurred_at <= state.window_end
        ]
        if not owners:
            return None
        owner = min(
            owners,
            key=lambda state: (
                abs(
                    (
                        candidate.occurred_at
                        - (state.anchor_time or state.window_start)
                    ).total_seconds()
                ),
                state.incident_id,
                state.episode_state_id,
            ),
        )
        incident = incidents.get(owner.incident_id)
        values = incident.values if incident else {}
        deadline = values.get("late_accept_until", owner.late_accept_until)
        closed_at = values.get("closed_at")
        status = str(values.get("status", "new"))
        if candidate.observed_at > deadline or (
            status == "closed"
            and closed_at is not None
            and candidate.occurred_at > closed_at
        ):
            return owner.incident_id
        return None

    def _anchor(
        self, compiled: CompiledRule, qualifying: Sequence[InputEnvelope]
    ) -> InputEnvelope:
        condition = compiled.rule.condition
        ordered = sorted(qualifying, key=lambda item: item.order_key)
        if isinstance(condition, SequenceCondition):
            terminal_selector = compiled.rule.selector_map[condition.stages[-1].selector]
            terminal = [
                item for item in ordered if selector_matches(terminal_selector, item)
            ]
            return terminal[-1]
        return ordered[-1]

    def _approved_member(
        self,
        compiled: CompiledRule,
        item: InputEnvelope,
        group: Mapping[str, Any],
    ) -> bool:
        if not any(
            selector_matches(selector, item)
            for selector in compiled.rule.selectors
        ):
            return False
        if "shared_ip" in group:
            # Join evidence must be part of a proven relation, not just share a
            # loose string field. Only the canonical qualifying set is added.
            return False
        item_group = _safe_group(compiled, item)
        return item_group == group

    def _build_partial_state(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        context: Sequence[InputEnvelope],
        states: Sequence[EpisodeState],
        token: str,
        now: datetime | None,
    ) -> EpisodeState | None:
        if not self.candidate_matches_any_selector(compiled, candidate):
            return None
        group = _safe_group(compiled, candidate)
        if group is None or "shared_ip" in compiled.rule.group_by:
            return None
        group_json, group_hash = group_identity(group)
        replay = next(
            (
                state
                for state in states
                if state.revision_token == token
                and state.group_key_hash == group_hash
                and not state.incident_id
            ),
            None,
        )
        if replay is not None:
            if candidate.tagged_id not in replay.owned_tagged_ids:
                raise CorrelationEvaluationError(
                    "provisional partial state does not own its replay input"
                )
            return replay
        qualified_overlaps = [
            state
            for state in states
            if state.group_key_hash == group_hash
            and state.incident_id
            and state.window_start <= candidate.occurred_at <= state.window_end
        ]
        if qualified_overlaps:
            # An in-range input that cannot enrich an existing incident must
            # not seed a clone of that immutable occurrence episode.
            return None
        existing = next(
            (
                state
                for state in states
                if state.group_key_hash == group_hash
                and not state.incident_id
                and state.window_start <= candidate.occurred_at <= state.window_end
                and candidate.observed_at <= state.late_accept_until
            ),
            None,
        )
        unavailable_owned = set().union(
            *(
                set(state.owned_tagged_ids)
                for state in states
                if state.group_key_hash == group_hash
                and (existing is None or state.episode_state_id != existing.episode_state_id)
            )
        )
        members = sorted(
            [
                item
                for item in context
                if _group_key(compiled, item) == canonical_json(group)
                and item.tagged_id not in unavailable_owned
                and any(
                    selector_matches(selector, item)
                    for selector in compiled.rule.selectors
                )
            ],
            key=lambda item: item.order_key,
        )
        condition = compiled.rule.condition
        if isinstance(condition, SequenceCondition):
            prefix = self._sequence_partial_prefix(
                compiled,
                members,
                window_start=(existing.window_start if existing is not None else None),
                window_end=(existing.window_end if existing is not None else None),
                late_accept_until=(
                    existing.late_accept_until if existing is not None else None
                ),
            )
            if (
                not prefix
                or candidate.tagged_id
                not in {item.tagged_id for item in prefix}
            ):
                # Incomplete stage cardinality and terminal-/middle-only input
                # remain durable source context after a stateless ledger row.
                # Only a complete strict prefix owns partial episode state.
                return None
            prefix_ids = frozenset(item.tagged_id for item in prefix)
            if (
                existing is not None
                and prefix_ids == existing.owned_tagged_ids
            ):
                # A prior candidate in this source page may already have
                # persisted the complete canonical prefix. The remaining
                # prefix members still need ledger identities, but identical
                # semantic state must not create one revision per member.
                return None
            members = list(prefix)
        if not members:
            return None
        start = existing.window_start if existing is not None else members[0].occurred_at
        end = (
            existing.window_end
            if existing is not None
            else start + timedelta(seconds=compiled.rule.window.seconds)
        )
        late_until = (
            existing.late_accept_until
            if existing is not None
            else end + timedelta(seconds=compiled.rule.allowed_lateness.seconds)
        )
        prior_owned = existing.owned_tagged_ids if existing is not None else frozenset()
        members = [
            item
            for item in members
            if start <= item.occurred_at <= end
            and (
                item.tagged_id in prior_owned
                or item.observed_at <= late_until
            )
        ]
        if (
            candidate.tagged_id not in {item.tagged_id for item in members}
            or candidate.observed_at > late_until
        ):
            return None
        episode_id = (
            existing.episode_state_id
            if existing is not None
            else episode_state_identity(scope, group_json, members[0])
        )
        detection_ids = tuple(
            sorted({item.input_id for item in members if item.input_kind == "detection"})
        )
        event_ids = tuple(
            sorted({item.input_id for item in members if item.input_kind == "event"})
        )
        last_input_observed_at = max(
            [item.observed_at for item in members]
            + (
                [existing.last_input_observed_at]
                if existing is not None
                else []
            )
        )
        content = {
            "scope": scope.key,
            "group_key_json": group_json,
            "episode_state_id": episode_id,
            "window_start": start,
            "window_end": end,
            "owned_detection_ids": detection_ids,
            "owned_event_ids": event_ids,
            "last_input_observed_at": last_input_observed_at,
            "late_accept_until": late_until,
        }
        return EpisodeState(
            scope,
            group_json,
            group_hash,
            episode_id,
            token,
            "[]",
            "",
            "",
            None,
            start,
            end,
            "",
            detection_ids,
            event_ids,
            last_input_observed_at,
            late_until,
            existing.collision_count if existing else 0,
            state_hash(content),
            _utc(now or datetime.now(timezone.utc)),
            (existing.revision + 1 if existing else 1),
        )


def selector_matches(selector: Selector, item: InputEnvelope) -> bool:
    if item.invalid_reason:
        return False
    if selector.source != item.input_kind:
        return False
    return all(_predicate_matches(predicate, item.values) for predicate in selector.predicates)


def _predicate_matches(predicate: Predicate, values: Mapping[str, Any]) -> bool:
    actual = values.get(predicate.field)
    if predicate.operator == "exists":
        present = actual is not None and (
            not isinstance(actual, str) or actual.strip() != ""
        )
        return present is bool(predicate.value)
    if predicate.operator == "eq":
        return _field_equal(predicate.field, actual, predicate.value, values)
    if predicate.operator == "in":
        return any(
            _field_equal(predicate.field, actual, expected, values)
            for expected in predicate.value
        )
    return False


def _scalar_equal(actual: Any, expected: Any) -> bool:
    if isinstance(expected, bool):
        return bool(actual) is expected
    if isinstance(expected, int) and not isinstance(expected, bool):
        try:
            return int(actual) == expected
        except (TypeError, ValueError):
            return False
    return str(actual) == str(expected)


def _field_equal(
    field: str,
    actual: Any,
    expected: Any,
    values: Mapping[str, Any],
) -> bool:
    if field == "host_name":
        left = canonical_host(actual)
        right = canonical_host(expected)
        return left is not None and left == right
    if field == "user_name":
        left = canonical_principal(actual, values.get("platform"))
        right = canonical_principal(expected, values.get("platform"))
        return left is not None and left == right
    if field in {"source_ip", "destination_ip"}:
        left = canonical_ip(actual)
        right = canonical_ip(expected)
        return left is not None and left == right
    if field == "platform":
        return str(actual).strip().casefold() == str(expected).strip().casefold()
    return _scalar_equal(actual, expected)


def _safe_group(
    compiled: CompiledRule, item: InputEnvelope
) -> Mapping[str, Any] | None:
    try:
        return json.loads(
            canonical_group_json(compiled.rule.group_by, item.values)
        )
    except (IdentityNormalizationError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _group_key(compiled: CompiledRule, item: InputEnvelope) -> str | None:
    group = _safe_group(compiled, item)
    return canonical_json(group) if group is not None else None


def _group_inputs(
    compiled: CompiledRule,
    context: Sequence[InputEnvelope],
    selector: Selector,
) -> Mapping[str, tuple[InputEnvelope, ...]]:
    grouped: dict[str, list[InputEnvelope]] = {}
    for item in context:
        if not selector_matches(selector, item):
            continue
        key = _group_key(compiled, item)
        if key is None:
            continue
        grouped.setdefault(key, []).append(item)
    return {
        key: tuple(sorted(items, key=lambda item: item.order_key))
        for key, items in grouped.items()
    }


def _bounded_combinations(
    items: Sequence[InputEnvelope], count: int
) -> Iterable[tuple[InputEnvelope, ...]]:
    attempts = 0
    for combination in itertools.combinations(
        sorted(_collapse_inputs(items), key=lambda item: item.order_key), count
    ):
        attempts += 1
        if attempts > MAX_COMBINATION_ATTEMPTS:
            raise CorrelationEvaluationError("canonical combination bound exceeded")
        yield combination


def _relation_matches(
    relation: Any,
    selected: Mapping[str, InputEnvelope],
    derived: dict[str, Any],
    compiled: CompiledRule,
) -> bool:
    left_item = selected[relation.left_selector]
    right_item = selected[relation.right_selector]
    if relation.operator == "equals":
        if relation.left_field == "host_name" and relation.right_field == "host_name":
            left = canonical_host(left_item.values.get("host_name"))
            right = canonical_host(right_item.values.get("host_name"))
            return left is not None and left == right
        if relation.left_field == "user_name" and relation.right_field == "user_name":
            left = canonical_principal(
                left_item.values.get("user_name"), left_item.values.get("platform")
            )
            right = canonical_principal(
                right_item.values.get("user_name"), right_item.values.get("platform")
            )
            return left is not None and left == right
        if relation.left_field in {"source_ip", "destination_ip"} and relation.right_field in {
            "source_ip",
            "destination_ip",
        }:
            left = canonical_ip(left_item.values.get(relation.left_field))
            right = canonical_ip(right_item.values.get(relation.right_field))
            return left is not None and left == right
        if relation.left_field == "platform" and relation.right_field == "platform":
            return str(left_item.values.get("platform", "")).strip().casefold() == str(
                right_item.values.get("platform", "")
            ).strip().casefold()
        return _scalar_equal(
            left_item.values.get(relation.left_field),
            right_item.values.get(relation.right_field),
        )
    if relation.operator != "intersects":
        return False
    if relation.left_field != "ip_set" or relation.right_field != "local_ip_set":
        return False
    network_ips = canonical_ip_set(
        (
            left_item.values.get("source_ip"),
            left_item.values.get("destination_ip"),
        ),
        ownership=True,
    )
    if not _is_direction_safe_ownership_event(right_item):
        return False
    try:
        fact = OwnershipFact.create(
            right_item.values.get("host_name"),
            right_item.values.get("source_ip"),
            right_item.input_id,
            right_item.occurred_at,
        )
    except IdentityNormalizationError:
        return False
    roles = _ownership_join_roles(compiled)
    endpoint = selected.get(roles[1]) if roles is not None else None
    if endpoint is None or not ownership_fact_matches(
        fact,
        endpoint_host=endpoint.values.get("host_name"),
        network_ips=network_ips,
        occurrence_times=(left_item.occurred_at, endpoint.occurred_at),
        window_milliseconds=compiled.rule.window.milliseconds,
    ):
        return False
    shared, intersection = shared_owned_ips(network_ips, (fact.canonical_local_ip,))
    if shared is None:
        return False
    derived["shared_ip"] = shared
    derived["shared_ip_intersection"] = intersection
    return True


def _ownership_join_roles(
    compiled: CompiledRule,
) -> tuple[str, str, str] | None:
    """Derive network, endpoint, and ownership selectors from relations.

    Selector names are user-chosen syntax.  The compiler validates the frozen
    ownership topology, so runtime behavior must depend on typed relation roles
    rather than the names used by the repository rule.
    """

    condition = compiled.rule.condition
    if not isinstance(condition, JoinCondition):
        return None
    intersects = [
        relation
        for relation in condition.relations
        if relation.operator == "intersects"
        and relation.left_field == "ip_set"
        and relation.right_field == "local_ip_set"
    ]
    if len(intersects) != 1:
        return None
    network_name = intersects[0].left_selector
    ownership_name = intersects[0].right_selector
    endpoint_names: set[str] = set()
    for relation in condition.relations:
        if relation.operator != "equals":
            continue
        sides = {
            (relation.left_selector, relation.left_field),
            (relation.right_selector, relation.right_field),
        }
        if (ownership_name, "host_name") not in sides:
            continue
        endpoint_names.update(
            selector_name
            for selector_name, field in sides
            if selector_name != ownership_name and field == "host_name"
        )
    if len(endpoint_names) != 1:
        return None
    return network_name, next(iter(endpoint_names)), ownership_name


def _is_direction_safe_ownership_event(item: InputEnvelope) -> bool:
    try:
        initiated = int(item.values.get("initiated", 0) or 0)
    except (TypeError, ValueError):
        return False
    return (
        item.input_kind == "event"
        and str(item.values.get("source_type", "")) == "windows_sysmon"
        and str(item.values.get("event_code", "")) == "3"
        and initiated == 1
    )


def _select_existing_episode(
    states: Sequence[EpisodeState],
    group_hash: str,
    candidate: InputEnvelope,
    qualifying: Sequence[InputEnvelope],
) -> EpisodeState | None:
    eligible = [
        state
        for state in states
        if state.group_key_hash == group_hash
        and (
            candidate.tagged_id in state.owned_tagged_ids
            or state.window_start <= candidate.occurred_at <= state.window_end
        )
    ]
    if not eligible:
        return None
    return min(
        eligible,
        key=lambda state: (
            abs(
                (
                    candidate.occurred_at
                    - (state.anchor_time or state.window_start)
                ).total_seconds()
            ),
            state.incident_id,
            state.episode_state_id,
        ),
    )


def _collapse_inputs(items: Iterable[InputEnvelope]) -> tuple[InputEnvelope, ...]:
    logical: dict[str, InputEnvelope] = {}
    for item in items:
        prior = logical.get(item.tagged_id)
        if prior is None:
            logical[item.tagged_id] = item
            continue
        immutable_prior = (prior.occurred_at, _immutable_identity_values(prior))
        immutable_current = (item.occurred_at, _immutable_identity_values(item))
        if immutable_prior != immutable_current:
            logical[item.tagged_id] = InputEnvelope(
                item.input_kind,
                item.input_id,
                min(prior.occurred_at, item.occurred_at),
                min(prior.observed_at, item.observed_at),
                prior.values,
                "conflicting_immutable_values",
            )
        elif item.observed_at < prior.observed_at:
            logical[item.tagged_id] = item
    return tuple(sorted(logical.values(), key=lambda item: item.order_key))


def _canonical_group_component(field: str, values: Mapping[str, Any]) -> Any:
    """Canonicalize one join-group component with the frozen group contract."""

    return json.loads(canonical_group_json((field,), values))[field]


def _immutable_identity_values(item: InputEnvelope) -> tuple[str, ...]:
    keys = (
        "platform",
        "source_type",
        "host_name",
        "user_name",
        "source_ip",
        "destination_ip",
        "rule_id",
        "event_code",
    )
    return tuple(str(item.values.get(key, "")) for key in keys)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.replace(microsecond=(value.microsecond // 1_000) * 1_000)
