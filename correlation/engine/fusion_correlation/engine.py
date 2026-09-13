"""Restart-safe correlation polling and ordered effect persistence."""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Protocol

from .evaluator import (
    CorrelationEvaluationError,
    CorrelationEvaluator,
    PreparedContext,
)
from .incident import canonical_json, state_hash
from .models import CompiledRule
from .runtime_models import (
    CandidateCursor,
    CorrelationBacklog,
    CorrelationCycleStats,
    CorrelationIntegrityStatus,
    CorrelationPersistenceConflict,
    EpisodeState,
    EvaluationDecision,
    IncidentRecord,
    InputEnvelope,
    RuleScope,
)


CrashHook = Callable[[str, InputEnvelope, EvaluationDecision], None]


class CorrelationStore(Protocol):
    """Persistence operations required by the ordered correlation protocol."""

    def ensure_scope(
        self, scope: RuleScope, compiled: CompiledRule, evaluation_floor: datetime
    ) -> datetime: ...

    def load_schedule_cursor(self, scope: RuleScope) -> CandidateCursor | None: ...

    def check_scope_integrity(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
        *,
        ruleset_fingerprint: str,
        checked_at: datetime,
    ) -> CorrelationIntegrityStatus: ...

    def fetch_candidates(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
        cursor: CandidateCursor | None,
        limit: int,
    ) -> list[InputEnvelope]: ...

    def fetch_context(
        self,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        evaluation_floor: datetime,
        limit: int,
    ) -> list[InputEnvelope]: ...

    def load_episode_states(
        self,
        scope: RuleScope,
        candidate: InputEnvelope,
        compiled: CompiledRule,
        limit: int,
        revision_token: str = "",
    ) -> list[EpisodeState]: ...

    def load_incidents(
        self, incident_ids: Sequence[str], *, include_unconfirmed: bool = False
    ) -> Mapping[str, IncidentRecord]: ...

    def load_incident_members(
        self, incident_id: str, limit: int
    ) -> list[InputEnvelope]: ...

    def load_link_ids(self, incident_id: str) -> set[str]: ...

    def write_incident(self, incident: IncidentRecord) -> bool: ...

    def write_links(self, links: Sequence) -> tuple[int, int]: ...

    def write_episode_states(self, states: Sequence[EpisodeState]) -> int: ...

    def confirm_decision(
        self, scope: RuleScope, candidate: InputEnvelope, decision: EvaluationDecision
    ) -> None: ...

    def mark_evaluated(
        self,
        scope: RuleScope,
        entries: Sequence[tuple[InputEnvelope, EvaluationDecision]],
    ) -> int: ...

    def fetch_backlog(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
    ) -> CorrelationBacklog: ...

    def save_schedule(self, stats: CorrelationCycleStats) -> None: ...


class CorrelationEngine:
    """Process bounded candidate pages with ledger-last completeness."""

    def __init__(
        self,
        *,
        store: CorrelationStore,
        evaluator: CorrelationEvaluator,
        compiled_rules: Sequence[CompiledRule],
        engine_id: str,
        lookback_seconds: int,
        batch_size: int,
        context_limit: int,
        logger: logging.Logger | None = None,
        clock: Callable[[], datetime] | None = None,
        crash_hook: CrashHook | None = None,
    ) -> None:
        self.store = store
        self.evaluator = evaluator
        self.compiled_rules = tuple(compiled_rules)
        ruleset_material = canonical_json(
            {
                "schema": "fusion-correlation-ruleset/v1",
                "rules": sorted(
                    (
                        compiled.rule_id,
                        compiled.version,
                        compiled.scope_fingerprint,
                    )
                    for compiled in self.compiled_rules
                ),
            }
        )
        self.ruleset_fingerprint = hashlib.sha256(
            ruleset_material.encode("utf-8")
        ).hexdigest()
        self.engine_id = engine_id
        self.lookback_seconds = lookback_seconds
        self.batch_size = batch_size
        self.context_limit = context_limit
        self.logger = logger or logging.getLogger("fusion_correlation")
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.crash_hook = crash_hook
        self._floors: dict[tuple[str, str, int, str], datetime] = {}
        self._drain_cycles: dict[tuple[str, str, int, str], int] = {}

    def run_cycle(self) -> tuple[CorrelationCycleStats, ...]:
        return tuple(self.run_rule_cycle(rule) for rule in self.compiled_rules)

    def run_rule_cycle(self, compiled: CompiledRule) -> CorrelationCycleStats:
        started = time.perf_counter()
        now = _utc(self.clock())
        scope = RuleScope(
            self.engine_id,
            compiled.rule_id,
            compiled.version,
            compiled.scope_fingerprint,
        )
        evaluation_floor = self._floors.get(scope.key)
        if evaluation_floor is None:
            requested_floor = now - timedelta(seconds=self.lookback_seconds)
            # A new process does not yet know whether this is a persisted scope
            # or a genuinely new enrollment.  Prove integrity against the
            # requested bounded floor before ensure_scope can create bootstrap
            # rule state.  This keeps a projection fault present at first
            # startup from causing any correlation-state mutation.
            integrity = self.store.check_scope_integrity(
                scope,
                compiled,
                requested_floor,
                ruleset_fingerprint=self.ruleset_fingerprint,
                checked_at=now,
            )
            if integrity.blocked:
                return self._blocked_cycle_stats(scope, integrity, started)
            self._require_healthy_integrity(integrity)
            evaluation_floor = self.store.ensure_scope(
                scope, compiled, requested_floor
            )
            self._floors[scope.key] = evaluation_floor
            # A restored scope can have an older immutable enrollment floor
            # than this process's requested floor.  Recheck using the confirmed
            # value before reading a cursor or candidates.
        integrity = self.store.check_scope_integrity(
            scope,
            compiled,
            evaluation_floor,
            ruleset_fingerprint=self.ruleset_fingerprint,
            checked_at=now,
        )
        if integrity.blocked:
            return self._blocked_cycle_stats(scope, integrity, started)
        self._require_healthy_integrity(integrity)
        cursor = self.store.load_schedule_cursor(scope)
        candidates = self.store.fetch_candidates(
            scope,
            compiled,
            evaluation_floor,
            cursor,
            self.batch_size,
        )

        completed: list[tuple[InputEnvelope, EvaluationDecision]] = []
        pending_stateless: list[tuple[InputEnvelope, EvaluationDecision]] = []
        failed = 0
        # Candidates with the same occurrence timestamp share the exact same
        # inclusive source window.  Reuse a bounded number of collapsed/grouped
        # windows so same-timestamp pages do not repeatedly query and normalize
        # all unrelated identities.
        context_cache: dict[datetime, PreparedContext] = {}

        for candidate in candidates:
            try:
                decision = self._evaluate_candidate(
                    scope,
                    compiled,
                    candidate,
                    evaluation_floor,
                    now,
                    context_cache,
                )
                has_effects = bool(
                    decision.incident is not None
                    or decision.links
                    or decision.episode_states
                )
                if has_effects:
                    self._persist_effects(scope, candidate, decision)
                    ledgered = self.store.mark_evaluated(
                        scope, [(candidate, decision)]
                    )
                    if ledgered != 1:
                        raise RuntimeError(
                            "correlation ledger did not acknowledge confirmed input"
                        )
                    self._crash("after_ledger_before_schedule", candidate, decision)
                else:
                    # Truly stateless no-match/invalid decisions cannot affect a
                    # later candidate. Batch only their acknowledged ledger insert;
                    # every semantic-state decision is ledgered above before the
                    # next candidate is evaluated.
                    pending_stateless.append((candidate, decision))
            except (
                CorrelationEvaluationError,
                CorrelationPersistenceConflict,
                OverflowError,
            ) as exc:
                # Deterministic candidate-local failures stay unledgered and
                # visible for retry, but the rotating diagnostic cursor may
                # move past them so they cannot poison a page. Connectivity,
                # timeouts, and other store failures deliberately escape to the
                # outer bounded retry/backoff loop.
                failed += 1
                self.logger.exception(
                    "correlation_input_failed rule_id=%s rule_version=%d "
                    "input_kind=%s input_id=%s failure_kind=%s",
                    scope.rule_id,
                    scope.rule_version,
                    candidate.input_kind,
                    candidate.input_id,
                    type(exc).__name__,
                )
                continue
            if has_effects:
                completed.append((candidate, decision))

        if pending_stateless:
            try:
                ledgered = self.store.mark_evaluated(scope, pending_stateless)
                if ledgered != len(pending_stateless):
                    raise RuntimeError(
                        "correlation ledger did not acknowledge every confirmed "
                        "stateless input"
                    )
                completed.extend(pending_stateless)
                for candidate, decision in pending_stateless:
                    self._crash("after_ledger_before_schedule", candidate, decision)
            except CorrelationPersistenceConflict:
                # The adapter validates a batch before inserting it. Isolate a
                # deterministic identity/content conflict to its exact input so
                # every other stateless decision can still complete. Unexpected
                # store errors are intentionally not caught here.
                for candidate, decision in pending_stateless:
                    try:
                        ledgered = self.store.mark_evaluated(
                            scope, [(candidate, decision)]
                        )
                        if ledgered != 1:
                            raise RuntimeError(
                                "correlation ledger did not acknowledge confirmed "
                                "stateless input"
                            )
                    except CorrelationPersistenceConflict as exc:
                        failed += 1
                        self.logger.exception(
                            "correlation_input_failed rule_id=%s rule_version=%d "
                            "input_kind=%s input_id=%s failure_kind=%s",
                            scope.rule_id,
                            scope.rule_version,
                            candidate.input_kind,
                            candidate.input_id,
                            type(exc).__name__,
                        )
                        continue
                    completed.append((candidate, decision))
                    self._crash("after_ledger_before_schedule", candidate, decision)

        decisions = [decision for _, decision in completed]
        matched = sum(decision.matched for decision in decisions)
        created = sum(
            decision.evaluation_action == "created" for decision in decisions
        )
        updated = sum(
            decision.evaluation_action in {"updated", "enriched_closed"}
            for decision in decisions
        )
        detection_links = sum(
            link.input_kind == "detection"
            for decision in decisions
            for link in decision.links
        )
        event_links = sum(
            link.input_kind == "event"
            for decision in decisions
            for link in decision.links
        )
        invalid_inputs = sum(
            decision.evaluation_action == "invalid_input" for decision in decisions
        )
        late_outside_boundary = sum(
            decision.lateness_status == "late_outside_boundary"
            for decision in decisions
        )
        outside_reconciliation_horizon = sum(
            decision.reason_code == "outside_reconciliation_horizon"
            for decision in decisions
        )

        next_cursor = (
            CandidateCursor(
                candidates[-1].occurred_at,
                candidates[-1].observed_at,
                candidates[-1].input_kind,
                candidates[-1].input_id,
            )
            if candidates
            else cursor
        )
        backlog = self.store.fetch_backlog(
            scope, compiled, evaluation_floor
        )
        duration = max(time.perf_counter() - started, 0.0)
        has_immediate_work = (
            failed == 0
            and len(completed) == self.batch_size
            and backlog.unevaluated_input_count > 0
        )
        consecutive_drain_cycles = (
            self._drain_cycles.get(scope.key, 0) + 1
            if has_immediate_work
            else 0
        )
        self._drain_cycles[scope.key] = consecutive_drain_cycles
        stats = CorrelationCycleStats(
            scope=scope,
            evaluated_inputs=len(completed),
            matched_inputs=matched,
            failed_inputs=failed,
            incidents_created=created,
            incidents_updated=updated,
            detection_links_written=detection_links,
            event_links_written=event_links,
            processing_duration_seconds=duration,
            evaluated_inputs_per_second=(len(completed) / duration if duration else 0.0),
            backlog=backlog,
            cursor=next_cursor,
            consecutive_drain_cycles=consecutive_drain_cycles,
            integrity=integrity,
        )
        self.store.save_schedule(stats)
        self.logger.info(
            "correlation_cycle_complete engine_id=%s rule_id=%s rule_version=%d "
            "rule_fingerprint=%s evaluated_inputs=%d matched_inputs=%d failed_inputs=%d "
            "incidents_created=%d incidents_updated=%d detection_links_written=%d "
            "event_links_written=%d processing_duration_seconds=%.6f "
            "evaluated_inputs_per_second=%.3f unevaluated_input_count=%d "
            "oldest_unevaluated_age_seconds=%.3f invalid_input_count=%d "
            "late_outside_boundary_count=%d outside_reconciliation_horizon_count=%d "
            "newest_input_kind=%s newest_input_id=%s",
            scope.engine_id,
            scope.rule_id,
            scope.rule_version,
            scope.fingerprint,
            stats.evaluated_inputs,
            stats.matched_inputs,
            stats.failed_inputs,
            stats.incidents_created,
            stats.incidents_updated,
            stats.detection_links_written,
            stats.event_links_written,
            stats.processing_duration_seconds,
            stats.evaluated_inputs_per_second,
            backlog.unevaluated_input_count,
            backlog.oldest_unevaluated_age_seconds,
            invalid_inputs,
            late_outside_boundary,
            outside_reconciliation_horizon,
            backlog.newest_input_kind,
            backlog.newest_input_id,
        )
        return stats

    def _blocked_cycle_stats(
        self,
        scope: RuleScope,
        integrity: CorrelationIntegrityStatus,
        started: float,
    ) -> CorrelationCycleStats:
        self._drain_cycles[scope.key] = 0
        duration = max(time.perf_counter() - started, 0.0)
        stats = CorrelationCycleStats(
            scope=scope,
            evaluated_inputs=0,
            matched_inputs=0,
            failed_inputs=0,
            incidents_created=0,
            incidents_updated=0,
            detection_links_written=0,
            event_links_written=0,
            processing_duration_seconds=duration,
            evaluated_inputs_per_second=0.0,
            backlog=None,
            cursor=None,
            consecutive_drain_cycles=0,
            errors=integrity.violation_types,
            integrity=integrity,
        )
        self.logger.error(
            "correlation_scope_blocked_integrity engine_id=%s rule_id=%s "
            "rule_version=%d rule_fingerprint=%s ruleset_fingerprint=%s "
            "integrity_violation_count=%d violation_types=%s backlog=unavailable",
            scope.engine_id,
            scope.rule_id,
            scope.rule_version,
            scope.fingerprint,
            self.ruleset_fingerprint,
            integrity.violation_count,
            ",".join(integrity.violation_types),
        )
        return stats

    @staticmethod
    def _require_healthy_integrity(integrity: CorrelationIntegrityStatus) -> None:
        if integrity.status != "healthy" or integrity.violation_count != 0:
            raise RuntimeError(
                "integrity preflight returned an invalid non-blocked status"
            )

    def _evaluate_candidate(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        evaluation_floor: datetime,
        now: datetime,
        context_cache: dict[datetime, PreparedContext] | None = None,
    ) -> EvaluationDecision:
        if self.evaluator.candidate_matches_any_selector(compiled, candidate):
            prepared = (
                context_cache.get(candidate.occurred_at)
                if context_cache is not None
                else None
            )
            if prepared is None:
                context = self.store.fetch_context(
                    compiled,
                    candidate,
                    evaluation_floor,
                    self.context_limit + 1,
                )
                # Enrollment is a correctness boundary, not an adapter hint.
                # Keep a second fail-safe at the engine boundary so an old
                # logical input can never contribute context or membership.
                context = [
                    item for item in context if item.observed_at >= evaluation_floor
                ]
                if len(context) > self.context_limit:
                    raise OverflowError(
                        f"bounded context exceeds {self.context_limit} rows"
                    )
                prepared = self.evaluator.prepare_context(compiled, context)
                if context_cache is not None:
                    if len(context_cache) >= 8:
                        context_cache.clear()
                    context_cache[candidate.occurred_at] = prepared
            context = self.evaluator.context_for_candidate(
                compiled, candidate, prepared
            )
        else:
            context = [candidate]
        from .incident import evaluation_token  # avoid an import cycle in protocols

        token = evaluation_token(scope, candidate)
        states = self.store.load_episode_states(
            scope, candidate, compiled, self.context_limit, token
        )
        incident_ids = sorted({state.incident_id for state in states if state.incident_id})
        incidents = self.store.load_incidents(incident_ids)
        incident_members: dict[str, tuple[InputEnvelope, ...]] = {}
        remaining_member_capacity = self.context_limit
        for incident_id in incident_ids:
            if remaining_member_capacity < 1:
                raise OverflowError(
                    f"bounded confirmed incident membership exceeds {self.context_limit} rows"
                )
            members = self.store.load_incident_members(
                incident_id, remaining_member_capacity
            )
            incident_members[incident_id] = tuple(members)
            remaining_member_capacity -= len(members)
        decision = self.evaluator.evaluate(
            scope,
            compiled,
            candidate,
            context,
            states,
            incidents,
            now,
            incident_members,
        )
        if decision.incident is not None and decision.resulting_incident_id not in incidents:
            raw = self.store.load_incidents(
                [decision.resulting_incident_id], include_unconfirmed=True
            )
            if raw:
                provisional = raw[decision.resulting_incident_id]
                derived = dict(decision.incident.values)
                derived["created_at"] = provisional.values["created_at"]
                derived["updated_at"] = provisional.values["updated_at"]
                derived["state_hash"] = state_hash(derived)
                if (
                    provisional.revision != decision.incident.revision
                    or str(provisional.values["revision_token"])
                    != decision.revision_token
                    or provisional.state_hash != derived["state_hash"]
                ):
                    raise CorrelationEvaluationError(
                        "provisional incident conflicts with deterministic replay"
                    )
                decision = replace(
                    decision,
                    incident=None,
                    expected_incident=provisional,
                )
        if decision.links:
            confirmed_link_ids = self.store.load_link_ids(
                decision.resulting_incident_id
            )
            decision = replace(
                decision,
                links=tuple(
                    link
                    for link in decision.links
                    if link.link_id not in confirmed_link_ids
                ),
            )
        return decision

    def _persist_effects(
        self,
        scope: RuleScope,
        candidate: InputEnvelope,
        decision: EvaluationDecision,
    ) -> None:
        if decision.incident is not None:
            self.store.write_incident(decision.incident)
            self._crash("after_incident_before_links", candidate, decision)
        if decision.links:
            self.store.write_links(decision.links)
        if decision.episode_states:
            self.store.write_episode_states(decision.episode_states)
        self._crash("after_links_state_before_confirmation", candidate, decision)
        self.store.confirm_decision(scope, candidate, decision)
        self._crash("after_confirmation_before_ledger", candidate, decision)

    def _crash(
        self, stage: str, candidate: InputEnvelope, decision: EvaluationDecision
    ) -> None:
        if self.crash_hook is not None:
            self.crash_hook(stage, candidate, decision)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.replace(microsecond=(value.microsecond // 1_000) * 1_000)
