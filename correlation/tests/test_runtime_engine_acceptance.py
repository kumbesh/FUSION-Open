from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fusion_correlation.compiler import CorrelationCompiler, load_rules_strict
from fusion_correlation.engine import CorrelationEngine
from fusion_correlation.evaluator import CorrelationEvaluator
from fusion_correlation.incident import evaluation_token
from fusion_correlation.models import (
    CompiledRule,
    JoinCondition,
    JoinRelation,
    Predicate,
    Selector,
    ThresholdCondition,
)
from fusion_correlation.runtime_models import (
    CorrelationIntegrityStatus,
    CorrelationPersistenceConflict,
    EvaluationDecision,
    IncidentRecord,
    InputEnvelope,
    RuleScope,
)

from runtime_memory_store import MemoryCorrelationStore


BASE_TIME = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
ENGINE_ID = "fusion-correlation-runtime-acceptance"


class SimulatedCrash(BaseException):
    """Bypass the per-input Exception handler to model process termination."""


def _rules(
    rules_dir: Path, mitre_mapping_path: Path
) -> dict[str, object]:
    compiler = CorrelationCompiler(mitre_mapping_path)
    return {
        rule.rule_id: rule for rule in load_rules_strict(rules_dir, compiler)
    }


def _engine(
    store: MemoryCorrelationStore,
    rule: object,
    *,
    batch_size: int = 1000,
    crash_hook=None,
    now: datetime = BASE_TIME + timedelta(minutes=1),
) -> CorrelationEngine:
    return CorrelationEngine(
        store=store,
        evaluator=CorrelationEvaluator(),
        compiled_rules=[rule],
        engine_id=ENGINE_ID,
        lookback_seconds=3600,
        batch_size=batch_size,
        context_limit=20_000,
        clock=lambda: now,
        crash_hook=crash_hook,
    )


def _detection(
    input_id: str,
    *,
    occurred_at: datetime = BASE_TIME,
    observed_at: datetime | None = None,
    host: str = "Host01.lab.example",
    rule_id: str = "det-rule-a",
    severity: str = "medium",
    user: str = "alice",
    source_ip: str = "192.0.2.10",
    platform: str = "windows",
) -> InputEnvelope:
    return InputEnvelope(
        "detection",
        input_id,
        occurred_at,
        observed_at or occurred_at + timedelta(seconds=1),
        {
            "source_type": "fusion_detection",
            "platform": platform,
            "host_name": host,
            "user_name": user,
            "source_ip": source_ip,
            "destination_ip": "198.51.100.20",
            "rule_id": rule_id,
            "rule_name": rule_id,
            "severity": severity,
            "mitre_technique_ids": ["T1059.001"],
        },
    )


def _ssh_success_event(
    input_id: str,
    *,
    source_ip: str,
    occurred_at: datetime = BASE_TIME,
) -> InputEnvelope:
    return InputEnvelope(
        "event",
        input_id,
        occurred_at,
        occurred_at + timedelta(seconds=1),
        {
            "source_type": "linux_journald",
            "platform": "linux",
            "host_name": "fusion-ubuntu",
            "user_name": f"user-{input_id}",
            "source_ip": source_ip,
            "destination_ip": "192.0.2.20",
            "event_category": "authentication",
            "event_action": "ssh_login",
            "service_name": "ssh",
            "outcome": "success",
        },
    )


def _run_until_drained(
    engine: CorrelationEngine, store: MemoryCorrelationStore, maximum: int = 100
) -> list:
    results = []
    for _ in range(maximum):
        stats = engine.run_cycle()[0]
        results.append(stats)
        if stats.backlog.unevaluated_input_count == 0:
            return results
    pytest.fail(f"backlog did not drain in {maximum} cycles")


def _baseline_two_detection_run(rule: object) -> MemoryCorrelationStore:
    inputs = [
        _detection("d-001", rule_id="det-rule-a"),
        _detection(
            "d-002",
            occurred_at=BASE_TIME + timedelta(seconds=1),
            rule_id="det-rule-b",
            severity="high",
        ),
    ]
    store = MemoryCorrelationStore(inputs)
    _run_until_drained(_engine(store, rule, batch_size=2), store)
    return store


def test_normative_effect_order_is_confirmed_before_ledger_and_schedule(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    store = _baseline_two_detection_run(rule)
    incidents = store.current_incidents()
    assert len(incidents) == 1
    incident = next(iter(incidents.values()))
    token = str(incident.values["revision_token"])

    names = [name for name, _ in store.operations]
    incident_index = store.operations.index(("write_incident", token))
    link_index = store.operations.index(("write_links", token))
    state_index = store.operations.index(("write_episode_states", token))
    confirm_index = store.operations.index(("confirm_decision", token))
    ledger_index = names.index("mark_evaluated")
    backlog_index = names.index("fetch_backlog")
    schedule_index = names.index("save_schedule")
    assert (
        incident_index
        < link_index
        < state_index
        < confirm_index
        < ledger_index
        < backlog_index
        < schedule_index
    )
    assert len(store.ledger) == 2
    assert len(store.current_links()) == 2


@pytest.mark.parametrize(
    "crash_stage",
    [
        "after_incident_before_links",
        "after_links_state_before_confirmation",
        "after_confirmation_before_ledger",
        "after_ledger_before_schedule",
    ],
)
def test_required_crash_cuts_replay_to_one_logical_incident(
    crash_stage: str, rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    baseline = _baseline_two_detection_run(rule)
    expected_incident = next(iter(baseline.current_incidents().values()))
    expected_links = set(baseline.current_links())
    inputs = [
        _detection("d-001", rule_id="det-rule-a"),
        _detection(
            "d-002",
            occurred_at=BASE_TIME + timedelta(seconds=1),
            rule_id="det-rule-b",
            severity="high",
        ),
    ]
    store = MemoryCorrelationStore(inputs)
    crashed = False
    crash_target = "d-002" if crash_stage == "after_ledger_before_schedule" else "d-001"

    def crash(stage, candidate, _decision):
        nonlocal crashed
        if not crashed and stage == crash_stage and candidate.input_id == crash_target:
            crashed = True
            raise SimulatedCrash(stage)

    with pytest.raises(SimulatedCrash, match=crash_stage):
        _engine(store, rule, batch_size=2, crash_hook=crash).run_cycle()
    assert crashed

    results = _run_until_drained(_engine(store, rule, batch_size=2), store)
    incidents = store.current_incidents()
    assert set(incidents) == {expected_incident.incident_id}
    actual = incidents[expected_incident.incident_id]
    assert actual.state_hash == expected_incident.state_hash
    assert json.loads(actual.values["evidence_json"])["member_ids"] == json.loads(
        expected_incident.values["evidence_json"]
    )["member_ids"]
    assert set(store.current_links()) == expected_links
    assert len(store.ledger) == 2
    assert results[-1].backlog.unevaluated_input_count == 0
    assert results[-1].backlog.oldest_unevaluated_observed_at is None
    assert results[-1].backlog.oldest_unevaluated_age_seconds == 0.0
    assert store.schedules[-1].cursor is not None


@pytest.mark.parametrize(
    "crash_stage",
    [
        "after_incident_before_links",
        "after_links_state_before_confirmation",
        "after_confirmation_before_ledger",
    ],
)
def test_late_initial_creation_replays_as_created_at_every_preledger_cut(
    crash_stage: str, rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    observed_late = BASE_TIME + timedelta(minutes=11)
    inputs = [
        _detection(
            "late-create-a",
            observed_at=observed_late,
            rule_id="det-rule-a",
        ),
        _detection(
            "late-create-b",
            occurred_at=BASE_TIME + timedelta(seconds=1),
            observed_at=observed_late,
            rule_id="det-rule-b",
            severity="high",
        ),
    ]
    baseline = MemoryCorrelationStore(inputs)
    _run_until_drained(
        _engine(
            baseline,
            rule,
            batch_size=2,
            now=BASE_TIME + timedelta(minutes=12),
        ),
        baseline,
    )
    expected = next(iter(baseline.current_incidents().values()))
    expected_members = json.loads(expected.values["evidence_json"])["member_ids"]

    store = MemoryCorrelationStore(inputs)
    crashed = False

    def crash(stage, candidate, _decision):
        nonlocal crashed
        if (
            not crashed
            and stage == crash_stage
            and candidate.input_id == "late-create-a"
        ):
            crashed = True
            raise SimulatedCrash(stage)

    with pytest.raises(SimulatedCrash, match=crash_stage):
        _engine(
            store,
            rule,
            batch_size=2,
            crash_hook=crash,
            now=BASE_TIME + timedelta(minutes=12),
        ).run_cycle()
    assert crashed
    assert len(store.ledger) == 0

    _run_until_drained(
        _engine(
            store,
            rule,
            batch_size=2,
            now=BASE_TIME + timedelta(minutes=12),
        ),
        store,
    )
    actual = next(iter(store.current_incidents().values()))
    replay_decision = next(
        decision
        for key, decision in store.ledger.items()
        if key[-1] == "late-create-a"
    )
    assert replay_decision.evaluation_action == "created"
    assert replay_decision.lateness_status == "late_within_boundary"
    assert actual.incident_id == expected.incident_id
    assert actual.state_hash == expected.state_hash
    assert actual.revision == expected.revision
    assert json.loads(actual.values["evidence_json"])["member_ids"] == expected_members
    assert set(store.current_links()) == set(baseline.current_links())
    assert len(store.current_links()) == 2


def test_ledger_not_stale_cursor_is_completeness_authority(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    store = MemoryCorrelationStore([_detection("z", severity="low")])
    engine = _engine(store, rule, batch_size=1)
    first = engine.run_cycle()[0]
    assert first.cursor is not None and first.cursor.input_id == "z"
    store.inputs.append(_detection("a", severity="low"))

    second = engine.run_cycle()[0]
    assert second.evaluated_inputs == 1
    assert second.cursor is not None and second.cursor.input_id == "a"
    assert {key[-2:] for key in store.ledger} == {
        ("detection", "z"),
        ("detection", "a"),
    }
    assert second.backlog.unevaluated_input_count == 0


def test_drained_backlog_retains_newest_eligible_source_position(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    store = MemoryCorrelationStore([_detection("eligible-high-water", severity="low")])

    stats = _engine(store, rule, batch_size=1).run_cycle()[0]

    assert stats.backlog.unevaluated_input_count == 0
    assert stats.backlog.oldest_unevaluated_observed_at is None
    assert stats.backlog.oldest_unevaluated_age_seconds == 0.0
    assert stats.backlog.newest_input_kind == "detection"
    assert stats.backlog.newest_input_id == "eligible-high-water"
    assert stats.backlog.newest_occurred_at == BASE_TIME
    assert stats.backlog.newest_observed_at == BASE_TIME + timedelta(seconds=1)


def test_observation_time_controls_enrollment_but_not_occurrence_order(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    late_visible = _detection(
        "late-visible",
        occurred_at=BASE_TIME - timedelta(hours=2),
        observed_at=BASE_TIME,
        severity="low",
    )
    fully_old = _detection(
        "fully-old",
        occurred_at=BASE_TIME - timedelta(hours=2),
        observed_at=BASE_TIME - timedelta(hours=2),
        severity="low",
    )
    store = MemoryCorrelationStore([late_visible, fully_old])
    stats = _engine(store, rule).run_cycle()[0]
    assert stats.evaluated_inputs == 1
    assert {key[-1] for key in store.ledger} == {"late-visible"}
    assert stats.backlog.unevaluated_input_count == 0


def test_canonical_observation_floor_blocks_replay_resurrection_across_restart(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    """Physical replays and cursors cannot enroll a pre-floor logical ID."""

    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    floor = BASE_TIME
    now = floor + timedelta(hours=1)
    occurrence = floor + timedelta(minutes=1)
    stale_original = _detection(
        "z-stale",
        occurred_at=occurrence,
        observed_at=floor - timedelta(milliseconds=1),
        rule_id="det-rule-a",
    )
    after_floor = _detection(
        "m-after-floor",
        occurred_at=occurrence,
        observed_at=floor + timedelta(milliseconds=1),
        rule_id="det-rule-b",
    )
    store = MemoryCorrelationStore(
        [
            stale_original,
            after_floor,
            replace(after_floor),  # identical physical duplicate
        ]
    )

    first = _engine(store, rule, batch_size=1, now=now).run_cycle()[0]
    assert first.evaluated_inputs == 1
    assert {key[-1] for key in store.ledger} == {"m-after-floor"}
    assert store.current_incidents() == {}
    assert store.current_links() == {}
    persisted_floor = next(iter(store.floors.values()))
    assert persisted_floor == floor

    # Restart between the original observation and several later physical
    # replays.  Include reordered timestamps and a conflicting semantic row.
    store.inputs.extend(
        [
            replace(stale_original, observed_at=floor + timedelta(minutes=30)),
            replace(stale_original, observed_at=floor + timedelta(minutes=10)),
            replace(stale_original, observed_at=floor + timedelta(minutes=20)),
            replace(
                stale_original,
                observed_at=floor + timedelta(minutes=40),
                values={**stale_original.values, "host_name": "other.example"},
            ),
        ]
    )
    restarted = _engine(store, rule, batch_size=1, now=now + timedelta(minutes=1))
    replay_cycle = restarted.run_cycle()[0]
    assert replay_cycle.evaluated_inputs == 0
    assert replay_cycle.backlog.unevaluated_input_count == 0
    assert {key[-1] for key in store.ledger} == {"m-after-floor"}
    assert store.current_incidents() == {}
    assert store.current_links() == {}
    assert next(iter(store.floors.values())) == persisted_floor

    # A genuinely post-floor logical input with a lower lexical ID must still
    # be evaluated even though the recovered diagnostic cursor points at "m".
    lower_lexical = _detection(
        "a-after-floor",
        occurred_at=occurrence,
        observed_at=floor + timedelta(minutes=2),
        rule_id="det-rule-a",
    )
    store.inputs.extend([lower_lexical, replace(lower_lexical)])
    final = _engine(store, rule, batch_size=1, now=now + timedelta(minutes=2)).run_cycle()[0]
    assert final.evaluated_inputs == 1
    assert {key[-1] for key in store.ledger} == {
        "a-after-floor",
        "m-after-floor",
    }
    assert len(store.current_incidents()) == 1
    incident = next(iter(store.current_incidents().values()))
    assert set(json.loads(incident.values["evidence_json"])["member_ids"]) == {
        lower_lexical.tagged_id,
        after_floor.tagged_id,
    }
    assert len(store.current_links()) == 2

    # More replays after the incident is stable cannot amplify or change it.
    incident_id = incident.incident_id
    incident_hash = incident.state_hash
    store.inputs.append(
        replace(stale_original, observed_at=floor + timedelta(minutes=50))
    )
    no_amplification = _engine(
        store, rule, batch_size=1, now=now + timedelta(minutes=3)
    ).run_cycle()[0]
    assert no_amplification.evaluated_inputs == 0
    assert set(store.current_incidents()) == {incident_id}
    assert store.current_incidents()[incident_id].state_hash == incident_hash
    assert len(store.current_links()) == 2


def test_physical_source_duplicates_do_not_amplify_membership(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    d1 = _detection("d-001", rule_id="det-rule-a")
    d2 = _detection(
        "d-002",
        occurred_at=BASE_TIME + timedelta(seconds=1),
        rule_id="det-rule-b",
    )
    duplicates = [
        d1,
        replace(d1, observed_at=d1.observed_at + timedelta(seconds=30)),
        d2,
        replace(d2, observed_at=d2.observed_at + timedelta(seconds=30)),
    ]
    store = MemoryCorrelationStore(duplicates)
    _run_until_drained(_engine(store, rule), store)
    incident = next(iter(store.current_incidents().values()))
    assert len(store.ledger) == 2
    assert incident.values["input_count"] == 2
    assert incident.values["detection_count"] == 2
    assert len(store.current_links()) == 2


def test_conflicting_physical_replay_after_ledger_stays_visible_without_starvation(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    """A post-ledger source conflict must not disappear behind the anti-join."""

    class ConflictAwareMemoryStore(MemoryCorrelationStore):
        def _logical_inputs(self):
            collapsed = list(super()._logical_inputs())
            physical_by_id: dict[str, list[InputEnvelope]] = {}
            for item in self.inputs:
                physical_by_id.setdefault(item.tagged_id, []).append(item)
            return [
                replace(item, invalid_reason="conflicting_immutable_values")
                if any(
                    (other.occurred_at, other.values)
                    != (item.occurred_at, item.values)
                    for other in physical_by_id[item.tagged_id]
                )
                else item
                for item in collapsed
            ]

    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    store = ConflictAwareMemoryStore(
        [
            _detection(
                "replayed",
                occurred_at=BASE_TIME + timedelta(seconds=1),
                rule_id="det-rule-a",
            ),
            _detection(
                "qualifier",
                occurred_at=BASE_TIME,
                rule_id="det-rule-b",
            ),
        ]
    )
    _run_until_drained(_engine(store, rule, batch_size=2), store)
    prior_incidents = {
        key: (value.state_hash, value.revision)
        for key, value in store.current_incidents().items()
    }
    prior_links = set(store.current_links())

    store.inputs.append(
        replace(
                _detection(
                    "replayed",
                    occurred_at=BASE_TIME + timedelta(seconds=1),
                    observed_at=BASE_TIME + timedelta(minutes=2),
                    rule_id="det-rule-a",
                ),
                values={
                    **_detection(
                        "replayed",
                        occurred_at=BASE_TIME + timedelta(seconds=1),
                        rule_id="det-rule-a",
                    ).values,
                "host_name": "conflicting-host.example",
            },
        )
    )

    conflict_stats = _engine(
        store,
        rule,
        batch_size=2,
        now=BASE_TIME + timedelta(minutes=3),
    ).run_cycle()[0]
    assert {
        key: (value.state_hash, value.revision)
        for key, value in store.current_incidents().items()
    } == prior_incidents
    assert set(store.current_links()) == prior_links
    assert conflict_stats.failed_inputs == 1

    store.inputs.append(
        _detection(
            "later-valid",
            occurred_at=BASE_TIME + timedelta(minutes=2),
            rule_id="det-rule-c",
        )
    )
    valid_stats = _engine(
        store,
        rule,
        batch_size=2,
        now=BASE_TIME + timedelta(minutes=3),
    ).run_cycle()[0]

    assert valid_stats.failed_inputs == 1
    assert any(key[-1] == "later-valid" for key in store.ledger)
    current = store.current_incidents()
    assert set(current) == set(prior_incidents)
    incident_id = next(iter(current))
    assert current[incident_id].revision == prior_incidents[incident_id][1] + 1
    assert current[incident_id].state_hash != prior_incidents[incident_id][0]
    assert prior_links < set(store.current_links())
    assert any(
        link.input_id == "later-valid" for link in store.current_links().values()
    )
    incident_links = {
        link_id: link
        for link_id, link in store.current_links().items()
        if link.incident_id == incident_id
    }
    assert current[incident_id].values["input_count"] == len(incident_links)
    assert current[incident_id].values["detection_count"] == len(incident_links)
    assert set(json.loads(current[incident_id].values["evidence_json"])["member_ids"]) == {
        f"{link.input_kind}\0{link.input_id}" for link in incident_links.values()
    }


def test_ambiguous_confirmation_is_retried_without_missing_or_duplicate_effects(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]

    class AmbiguousConfirmationStore(MemoryCorrelationStore):
        failed_once = False

        def confirm_decision(self, scope, candidate, decision):
            super().confirm_decision(scope, candidate, decision)
            if not self.failed_once and decision.resulting_incident_id:
                self.failed_once = True
                raise TimeoutError("acknowledgement outcome was ambiguous")

    inputs = [
        _detection("ambiguous-a", rule_id="det-rule-a"),
        _detection(
            "ambiguous-b",
            occurred_at=BASE_TIME + timedelta(seconds=1),
            rule_id="det-rule-b",
        ),
    ]
    store = AmbiguousConfirmationStore(inputs)
    engine = _engine(store, rule, batch_size=2)
    with pytest.raises(TimeoutError, match="ambiguous"):
        engine.run_cycle()
    assert len(store.ledger) == 0
    assert store.schedules == []

    final = _run_until_drained(engine, store)[-1]
    assert final.backlog.unevaluated_input_count == 0
    assert len(store.ledger) == 2
    assert len(store.current_incidents()) == 1
    assert len(store.current_links()) == 2


def _same_timestamp_inputs(kind: str, count: int) -> list[InputEnvelope]:
    values: list[InputEnvelope] = []
    if kind in {"detection", "mixed"}:
        detection_count = count if kind == "detection" else count // 2
        for index in range(detection_count):
            input_id = f"same-{index:04d}"
            address = f"10.{10 + index // 60_000}.{(index // 250) % 240 + 1}.{index % 250 + 1}"
            values.append(
                _detection(
                    input_id,
                    host=(f"host-{index:04d}" if kind == "detection" else "fusion-ubuntu"),
                    rule_id="fusion-linux-authentication-failure",
                    severity="medium",
                    user=f"user-{input_id}",
                    source_ip=address,
                    platform="linux",
                )
            )
    if kind in {"event", "mixed"}:
        event_count = count if kind == "event" else count - count // 2
        values.extend(
            _ssh_success_event(
                f"same-{index:04d}",
                source_ip=f"10.{10 + index // 60_000}.{(index // 250) % 240 + 1}.{index % 250 + 1}",
            )
            for index in range(event_count)
        )
    return values


@pytest.mark.parametrize("input_shape", ["detection", "event", "mixed"])
def test_1001_same_timestamp_inputs_cross_page_exactly_once(
    input_shape: str, rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rules = _rules(rules_dir, mitre_mapping_path)
    rule = rules[
        "fusion-correlation-host-suspicious-activity"
        if input_shape == "detection"
        else "fusion-correlation-ssh-bruteforce-success"
    ]
    store = MemoryCorrelationStore(_same_timestamp_inputs(input_shape, 1001))
    engine = _engine(store, rule, batch_size=1000)
    started = time.perf_counter()
    first = engine.run_cycle()[0]
    first_page_completed = time.perf_counter()
    second = engine.run_cycle()[0]
    elapsed = time.perf_counter() - started
    results = [first, second]

    assert [result.evaluated_inputs for result in results] == [1000, 1]
    assert len(store.fetch_started_at) == 2
    assert sum(name == "fetch_context" for name, _ in store.operations) == 2
    assert store.fetch_started_at[1] - first_page_completed < 1.0
    assert elapsed < 15.0
    assert len(store.ledger) == 1001
    assert len({key for key in store.ledger}) == 1001
    if input_shape == "mixed":
        assert ("detection", "same-0000") in {key[-2:] for key in store.ledger}
        assert ("event", "same-0000") in {key[-2:] for key in store.ledger}
    assert store.current_incidents() == {}
    assert store.current_links() == {}
    assert results[-1].backlog.unevaluated_input_count == 0
    assert results[-1].backlog.oldest_unevaluated_observed_at is None
    assert results[-1].backlog.oldest_unevaluated_age_seconds == 0.0


def test_prepared_context_group_index_preserves_threshold_semantics(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    candidate = _detection(
        "target-b",
        occurred_at=BASE_TIME + timedelta(seconds=1),
        host="target.example",
        rule_id="det-rule-b",
    )
    full_context = [
        _detection("target-a", host="TARGET.EXAMPLE.", rule_id="det-rule-a"),
        candidate,
        _detection("other-a", host="other.example", rule_id="det-rule-a"),
        _detection(
            "other-b",
            occurred_at=BASE_TIME + timedelta(seconds=1),
            host="other.example",
            rule_id="det-rule-b",
        ),
    ]
    direct = evaluator.evaluate(
        scope, rule, candidate, full_context, now=BASE_TIME + timedelta(minutes=1)
    )
    prepared = evaluator.prepare_context(rule, full_context)
    bounded_context = evaluator.context_for_candidate(rule, candidate, prepared)
    indexed = evaluator.evaluate(
        scope,
        rule,
        candidate,
        bounded_context,
        now=BASE_TIME + timedelta(minutes=1),
    )

    assert len(bounded_context) == 2
    assert direct.matched and indexed.matched
    assert direct.resulting_incident_id == indexed.resulting_incident_id
    assert direct.incident is not None and indexed.incident is not None
    assert direct.incident.state_hash == indexed.incident.state_hash
    assert {link.link_id for link in direct.links} == {
        link.link_id for link in indexed.links
    }


def test_renamed_join_selectors_and_two_owned_ips_preserve_provenance(
    tmp_path: Path,
    rules_dir: Path,
    mitre_mapping_path: Path,
) -> None:
    source = (rules_dir / "suricata-endpoint.yml").read_text(encoding="utf-8")
    renamed = (
        source.replace("network_alert", "net_signal")
        .replace("endpoint_detection", "host_signal")
        .replace("endpoint_identity", "ownership_fact")
    )
    path = tmp_path / "renamed-ownership-join.yml"
    path.write_text(renamed, encoding="utf-8")
    rule = CorrelationCompiler(mitre_mapping_path).load_rule(path)
    assert set(rule.rule.selector_map) == {
        "net_signal",
        "host_signal",
        "ownership_fact",
    }

    network = InputEnvelope(
        "detection",
        "suricata-alert",
        BASE_TIME,
        BASE_TIME + timedelta(seconds=1),
        {
            "source_type": "suricata_eve",
            "platform": "network",
            "host_name": "sensor-01",
            "source_ip": "10.20.30.20",
            "destination_ip": "10.20.30.10",
            "rule_id": "fusion-network-alert",
            "rule_name": "Network alert",
            "severity": "medium",
        },
    )
    endpoint = _detection(
        "endpoint-detection",
        occurred_at=BASE_TIME + timedelta(seconds=1),
        host="WORKSTATION-01.lab.example",
        rule_id="fusion-windows-encoded-powershell",
        severity="high",
    )

    def ownership(input_id: str, address: str, seconds: int) -> InputEnvelope:
        occurred = BASE_TIME + timedelta(seconds=seconds)
        return InputEnvelope(
            "event",
            input_id,
            occurred,
            occurred + timedelta(seconds=1),
            {
                "source_type": "windows_sysmon",
                "platform": "windows",
                "host_name": "workstation-01.LAB.EXAMPLE.",
                "source_ip": address,
                "destination_ip": "203.0.113.5",
                "event_code": "3",
                "initiated": 1,
                "event_category": "network",
                "event_action": "connection",
            },
        )

    ip_high = ownership("ownership-ip-high", "10.20.30.20", 2)
    ip_low = ownership("ownership-ip-low", "10.20.30.10", 3)
    context = [network, endpoint, ip_high, ip_low]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    decision = evaluator.evaluate(
        scope,
        rule,
        ip_low,
        context,
        now=BASE_TIME + timedelta(minutes=1),
    )

    assert decision.matched
    assert decision.incident is not None
    assert json.loads(decision.incident.values["group_key_json"]) == {
        "shared_ip": "10.20.30.10",
        "host_name": "workstation-01.lab.example",
    }
    evidence = json.loads(decision.incident.values["evidence_json"])
    assert len(evidence["qualifying_input_ids"]) == 3
    assert set(evidence["member_ids"]) == {
        item.tagged_id for item in context
    }
    assert evidence["shared_ip_intersection"] == ["10.20.30.10", "10.20.30.20"]
    assert {
        item["evidence_event_uid"] for item in evidence["ownership_provenance"]
    } == {ip_low.input_id, ip_high.input_id}
    assert {
        link.input_id for link in decision.links if link.input_kind == "event"
    } == {ip_low.input_id, ip_high.input_id}


def test_cross_source_enrichment_hydrates_members_and_retains_ownership(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    """A later source conflict cannot erase confirmed ownership provenance."""

    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-suricata-endpoint"
    ]
    network = InputEnvelope(
        "detection",
        "hydrated-network",
        BASE_TIME,
        BASE_TIME + timedelta(seconds=1),
        {
            "source_type": "suricata_eve",
            "platform": "network",
            "host_name": "sensor-01",
            "source_ip": "10.20.30.20",
            "destination_ip": "10.20.30.10",
            "rule_id": "fusion-network-controlled-suricata-signature",
            "rule_name": "Controlled network alert",
            "severity": "medium",
            "mitre_technique_ids": [],
        },
    )
    endpoint = _detection(
        "hydrated-endpoint-1",
        occurred_at=BASE_TIME + timedelta(seconds=1),
        host="workstation-01.lab.example",
        rule_id="fusion-windows-encoded-powershell",
        severity="high",
    )

    def ownership(input_id: str, address: str, seconds: int) -> InputEnvelope:
        occurred = BASE_TIME + timedelta(seconds=seconds)
        return InputEnvelope(
            "event",
            input_id,
            occurred,
            occurred + timedelta(seconds=1),
            {
                "source_type": "windows_sysmon",
                "platform": "windows",
                "host_name": "workstation-01.lab.example",
                "source_ip": address,
                "destination_ip": "203.0.113.5",
                "event_code": "3",
                "initiated": 1,
                "event_category": "network",
                "event_action": "connection",
            },
        )

    low = ownership("hydrated-ownership-low", "10.20.30.10", 2)
    high = ownership("hydrated-ownership-high", "10.20.30.20", 3)
    store = MemoryCorrelationStore([network, endpoint, low, high])
    _run_until_drained(_engine(store, rule, batch_size=4), store)
    incident_id = next(iter(store.current_incidents()))
    initial_evidence = json.loads(
        store.current_incidents()[incident_id].values["evidence_json"]
    )
    assert {
        value["evidence_event_uid"]
        for value in initial_evidence["ownership_provenance"]
    } == {low.input_id, high.input_id}
    assert initial_evidence["shared_ip_intersection"] == [
        "10.20.30.10",
        "10.20.30.20",
    ]

    store.inputs.append(
        replace(
            high,
            observed_at=BASE_TIME + timedelta(minutes=2),
            values={**high.values, "host_name": "conflicting-host.example"},
        )
    )
    store.inputs.append(
        _detection(
            "hydrated-endpoint-2",
            occurred_at=BASE_TIME + timedelta(seconds=4),
            host="workstation-01.lab.example",
            rule_id="fusion-windows-process-access",
            severity="high",
        )
    )

    stats = _engine(
        store,
        rule,
        batch_size=2,
        now=BASE_TIME + timedelta(minutes=3),
    ).run_cycle()[0]
    assert stats.failed_inputs == 1
    incident = store.current_incidents()[incident_id]
    links = [
        link
        for link in store.current_links().values()
        if link.incident_id == incident_id
    ]
    evidence = json.loads(incident.values["evidence_json"])
    assert incident.values["input_count"] == len(links) == 5
    assert incident.values["detection_count"] == sum(
        link.input_kind == "detection" for link in links
    ) == 3
    assert incident.values["event_count"] == sum(
        link.input_kind == "event" for link in links
    ) == 2
    assert set(evidence["member_ids"]) == {
        f"{link.input_kind}\0{link.input_id}" for link in links
    }
    assert {
        value["evidence_event_uid"] for value in evidence["ownership_provenance"]
    } == {low.input_id, high.input_id}
    assert evidence["shared_ip_intersection"] == [
        "10.20.30.10",
        "10.20.30.20",
    ]


@pytest.mark.parametrize(
    ("relation_field", "group_by", "left_value", "right_value", "expected"),
    [
        (
            "user_name",
            ("platform", "user_name"),
            "DOMAIN\\Alice",
            "domain\\ALICE",
            {
                "platform": "windows",
                "user_name": {
                    "platform": "windows",
                    "namespace": "downlevel",
                    "realm": "domain",
                    "account": "alice",
                },
            },
        ),
        ("platform", ("platform",), "WINDOWS", "windows", {"platform": "windows"}),
        (
            "source_ip",
            ("source_ip",),
            "::ffff:192.0.2.44",
            "192.0.2.44",
            {"source_ip": "192.0.2.44"},
        ),
    ],
)
def test_detection_join_group_uses_canonical_identity_contract(
    relation_field: str,
    group_by: tuple[str, ...],
    left_value: str,
    right_value: str,
    expected: dict,
    rules_dir: Path,
    mitre_mapping_path: Path,
) -> None:
    base = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    selectors = (
        Selector("left", "detection", (Predicate("rule_id", "eq", "join-left"),)),
        Selector("right", "detection", (Predicate("rule_id", "eq", "join-right"),)),
    )
    condition = JoinCondition(
        ("left", "right"),
        (JoinRelation("left", relation_field, "equals", "right", relation_field),),
    )
    compiled = CompiledRule(
        replace(
            base.rule,
            group_by=group_by,
            selectors=selectors,
            condition=condition,
            incident=replace(base.rule.incident, title_template="Canonical detection join"),
        ),
        base.scope_fingerprint,
        base.canonical_semantic_plan,
    )
    left = _detection("join-left", rule_id="join-left")
    right = _detection(
        "join-right",
        occurred_at=BASE_TIME + timedelta(milliseconds=1),
        rule_id="join-right",
    )
    left = replace(left, values={**left.values, relation_field: left_value})
    right = replace(right, values={**right.values, relation_field: right_value})
    decision = CorrelationEvaluator().evaluate(
        RuleScope(ENGINE_ID, compiled.rule_id, compiled.version, compiled.scope_fingerprint),
        compiled,
        right,
        [left, right],
        now=BASE_TIME + timedelta(minutes=1),
    )

    assert decision.matched
    assert decision.evaluation_action == "created"
    assert decision.incident is not None
    assert json.loads(decision.incident.values["group_key_json"]) == expected


@pytest.mark.parametrize(
    ("distinct_by", "left", "equivalent", "different"),
    [
        ("host_name", "Host.Example.", "host.example", "other.example"),
        ("user_name", "DOMAIN\\Alice", "domain\\ALICE", "domain\\bob"),
        ("platform", "Windows", "WINDOWS", "linux"),
        ("source_ip", "::ffff:192.0.2.44", "192.0.2.44", "192.0.2.45"),
    ],
)
def test_threshold_distinct_by_uses_canonical_identity_values(
    distinct_by: str,
    left: str,
    equivalent: str,
    different: str,
    rules_dir: Path,
    mitre_mapping_path: Path,
) -> None:
    base = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    compiled = CompiledRule(
        replace(
            base.rule,
            group_by=("rule_id",),
            condition=ThresholdCondition(
                selector="suspicious",
                min_count=2,
                distinct_by=distinct_by,
                min_distinct=2,
            ),
        ),
        base.scope_fingerprint,
        base.canonical_semantic_plan,
    )

    def item(input_id: str, value: str, offset_ms: int) -> InputEnvelope:
        detection = _detection(
            input_id,
            occurred_at=BASE_TIME + timedelta(milliseconds=offset_ms),
            rule_id="same-group",
        )
        return replace(
            detection,
            values={**detection.values, distinct_by: value},
        )

    first = item("distinct-first", left, 0)
    same = item("distinct-same", equivalent, 1)
    truly_different = item("distinct-different", different, 2)
    evaluator = CorrelationEvaluator()

    assert evaluator._threshold_matches(compiled, same, [first, same]) == []
    assert evaluator._threshold_matches(
        compiled, truly_different, [first, truly_different]
    )


def test_group_identity_and_persisted_state_keep_declared_nonlexical_order(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    base = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-user-suspicious-activity"
    ]
    compiled = CompiledRule(
        replace(base.rule, group_by=("user_name", "platform")),
        base.scope_fingerprint,
        base.canonical_semantic_plan,
    )
    first = _detection(
        "ordered-group-a",
        rule_id="det-rule-a",
        user="DOMAIN\\Alice",
        platform="windows",
    )
    second = _detection(
        "ordered-group-b",
        occurred_at=BASE_TIME + timedelta(milliseconds=1),
        rule_id="det-rule-b",
        user="domain\\ALICE",
        platform="WINDOWS",
    )
    decision = CorrelationEvaluator().evaluate(
        RuleScope(ENGINE_ID, compiled.rule_id, compiled.version, compiled.scope_fingerprint),
        compiled,
        second,
        [first, second],
        now=BASE_TIME + timedelta(minutes=1),
    )

    assert decision.matched
    assert decision.incident is not None
    assert decision.episode_states
    expected_order = ["user_name", "platform"]
    assert list(json.loads(decision.incident.values["group_key_json"])) == expected_order
    assert list(json.loads(decision.episode_states[0].group_key_json)) == expected_order


def test_10k_nonmatching_backlog_drains_with_exact_ledger_under_slo(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    store = MemoryCorrelationStore(
        [_detection(f"bulk-{index:05d}", severity="low") for index in range(10_000)]
    )
    started = time.perf_counter()
    results = _run_until_drained(_engine(store, rule, batch_size=1000), store)
    elapsed = time.perf_counter() - started

    assert len(results) == 10
    assert all(result.evaluated_inputs == 1000 for result in results)
    assert elapsed < 60.0
    assert len(store.ledger) == 10_000
    assert store.current_incidents() == {}
    assert store.current_links() == {}
    assert results[-1].backlog.unevaluated_input_count == 0
    assert results[-1].backlog.oldest_unevaluated_age_seconds == 0.0


def test_inclusive_episode_boundary_and_new_post_boundary_episode(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    first = _detection("old-a", rule_id="det-rule-a")
    boundary = _detection(
        "old-b",
        occurred_at=BASE_TIME + timedelta(minutes=10),
        rule_id="det-rule-b",
    )
    decision = evaluator.evaluate(
        scope, rule, boundary, [first, boundary], now=BASE_TIME + timedelta(minutes=10)
    )
    assert decision.matched
    assert decision.incident is not None
    old_id = decision.incident.incident_id
    assert decision.incident.values["episode_window_end"] == boundary.occurred_at

    fresh_a = _detection(
        "new-a",
        occurred_at=boundary.occurred_at + timedelta(milliseconds=1),
        rule_id="det-rule-c",
    )
    fresh_b = _detection(
        "new-b",
        occurred_at=boundary.occurred_at + timedelta(seconds=1),
        rule_id="det-rule-d",
    )
    second = evaluator.evaluate(
        scope,
        rule,
        fresh_b,
        [first, boundary, fresh_a, fresh_b],
        decision.episode_states,
        {old_id: decision.incident},
        now=BASE_TIME + timedelta(minutes=11),
    )
    assert second.matched
    assert second.incident is not None
    assert second.incident.incident_id != old_id
    member_ids = set(json.loads(second.incident.values["evidence_json"])["member_ids"])
    assert member_ids == {fresh_a.tagged_id, fresh_b.tagged_id}


def test_late_earlier_input_cannot_move_anchor_or_reuse_owned_evidence(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    d1 = _detection("anchor-a", rule_id="det-rule-a")
    d2 = _detection(
        "anchor-b",
        occurred_at=BASE_TIME + timedelta(seconds=1),
        rule_id="det-rule-b",
    )
    initial = evaluator.evaluate(scope, rule, d2, [d1, d2], now=BASE_TIME)
    assert initial.incident is not None
    initial_state = initial.episode_states[0]
    initial_anchor = (
        initial_state.anchor_kind,
        initial_state.anchor_id,
        initial_state.anchor_time,
    )

    late_earlier = _detection(
        "late-earlier",
        occurred_at=BASE_TIME - timedelta(minutes=1),
        observed_at=BASE_TIME + timedelta(minutes=2),
        rule_id="det-rule-c",
    )
    decision = evaluator.evaluate(
        scope,
        rule,
        late_earlier,
        [late_earlier, d1, d2],
        (initial_state,),
        {initial.incident.incident_id: initial.incident},
        now=BASE_TIME + timedelta(minutes=2),
    )
    assert not decision.matched
    assert decision.resulting_incident_id != initial.incident.incident_id
    for partial in decision.episode_states:
        assert partial.owned_tagged_ids.isdisjoint(initial_state.owned_tagged_ids)
    assert (
        initial_state.anchor_kind,
        initial_state.anchor_id,
        initial_state.anchor_time,
    ) == initial_anchor


def test_late_earlier_input_can_complete_an_unqualified_partial_episode(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    first_visible = _detection("partial-a", rule_id="det-rule-a")
    store = MemoryCorrelationStore([first_visible])
    first_engine = _engine(store, rule)
    first = first_engine.run_cycle()[0]
    assert first.evaluated_inputs == 1
    assert store.current_incidents() == {}
    assert len(store.ledger) == 1

    late_earlier = _detection(
        "partial-b",
        occurred_at=BASE_TIME - timedelta(seconds=1),
        observed_at=BASE_TIME + timedelta(seconds=2),
        rule_id="det-rule-b",
    )
    store.inputs.append(late_earlier)
    second = first_engine.run_cycle()[0]
    assert second.evaluated_inputs == 1
    assert second.matched_inputs == 1
    assert len(store.ledger) == 2
    incident = next(iter(store.current_incidents().values()))
    assert incident.values["episode_window_start"] == late_earlier.occurred_at
    assert incident.values["episode_anchor_id"] == first_visible.input_id
    assert set(json.loads(incident.values["evidence_json"])["member_ids"]) == {
        first_visible.tagged_id,
        late_earlier.tagged_id,
    }
    assert len(store.current_links()) == 2


def test_overlapping_partial_states_promote_the_canonical_qualifying_episode(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    """The selected partial must own the qualifying set, not merely be nearest."""

    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    near = _detection(
        "z-near-partial",
        occurred_at=BASE_TIME + timedelta(minutes=10),
        observed_at=BASE_TIME + timedelta(minutes=10, seconds=1),
        rule_id="det-rule-a",
    )
    early = _detection(
        "a-early-partial",
        occurred_at=BASE_TIME + timedelta(minutes=1),
        observed_at=BASE_TIME + timedelta(minutes=11),
        rule_id="det-rule-a",
    )
    completing = _detection(
        "partial-completing",
        occurred_at=BASE_TIME + timedelta(minutes=10, seconds=30),
        observed_at=BASE_TIME + timedelta(minutes=12),
        rule_id="det-rule-b",
    )
    store = MemoryCorrelationStore([near])
    engine = _engine(store, rule, now=BASE_TIME + timedelta(minutes=30))
    assert engine.run_cycle()[0].matched_inputs == 0
    store.inputs.append(early)
    assert engine.run_cycle()[0].matched_inputs == 0
    store.inputs.append(completing)

    final = engine.run_cycle()[0]

    assert final.matched_inputs == 1
    incident = next(iter(store.current_incidents().values()))
    evidence = json.loads(incident.values["evidence_json"])
    assert incident.values["episode_window_start"] == early.occurred_at
    assert set(evidence["qualifying_input_ids"]) <= set(evidence["member_ids"])
    assert {early.tagged_id, completing.tagged_id} <= set(evidence["member_ids"])
    assert {early.input_id, completing.input_id} <= {
        link.input_id for link in store.current_links().values()
    }


def test_late_fifth_ssh_failure_before_prior_success_completes_sequence(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-ssh-bruteforce-success"
    ]

    def failure(index: int, *, observed_at: datetime | None = None) -> InputEnvelope:
        occurred = BASE_TIME + timedelta(seconds=index * 10)
        return _detection(
            f"ssh-failure-{index}",
            occurred_at=occurred,
            observed_at=observed_at,
            host="fusion-ubuntu",
            rule_id="fusion-linux-authentication-failure",
            severity="low",
            user="definitely-not-a-user",
            source_ip="192.0.2.44",
            platform="linux",
        )

    initial_failures = [
        failure(
            index,
            observed_at=BASE_TIME + timedelta(seconds=60 + index),
        )
        for index in range(4)
    ]
    success = _ssh_success_event(
        "ssh-success",
        source_ip="192.0.2.44",
        occurred_at=BASE_TIME + timedelta(seconds=50),
    )
    # Match the failure group's user exactly; the helper uses an ID-derived
    # principal by default so replace only the immutable fixture values here.
    success = replace(
        success,
        values={**success.values, "user_name": "definitely-not-a-user"},
    )
    store = MemoryCorrelationStore([success])
    terminal_only = _engine(store, rule, batch_size=1000).run_cycle()[0]
    assert terminal_only.evaluated_inputs == 1
    assert terminal_only.matched_inputs == 0
    assert len(store.ledger) == 1
    assert store.raw_states == {}

    store.inputs.extend(initial_failures)
    _run_until_drained(_engine(store, rule, batch_size=1000), store)
    assert len(store.ledger) == 5
    assert store.current_incidents() == {}
    assert store.raw_states == {}

    fifth = failure(4, observed_at=BASE_TIME + timedelta(minutes=6))
    store.inputs.append(fifth)
    final = _engine(
        store,
        rule,
        now=BASE_TIME + timedelta(minutes=6),
    ).run_cycle()[0]
    assert final.evaluated_inputs == 1
    assert final.matched_inputs == 1
    assert len(store.ledger) == 6
    incident = next(iter(store.current_incidents().values()))
    assert incident.values["episode_anchor_kind"] == "event"
    assert incident.values["episode_anchor_id"] == success.input_id
    assert incident.values["detection_count"] == 5
    assert incident.values["event_count"] == 1
    assert len(store.current_links()) == 6
    decision = next(
        value for key, value in store.ledger.items() if key[-1] == fifth.input_id
    )
    assert decision.lateness_status == "late_within_boundary"


def test_sequence_partial_state_requires_a_complete_strict_prefix(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-ssh-bruteforce-success"
    ]

    def failure(index: int) -> InputEnvelope:
        occurred = BASE_TIME + timedelta(seconds=index * 10)
        return _detection(
            f"prefix-failure-{index}",
            occurred_at=occurred,
            host="fusion-ubuntu",
            rule_id="fusion-linux-authentication-failure",
            severity="low",
            user="prefix-user",
            source_ip="192.0.2.44",
            platform="linux",
        )

    store = MemoryCorrelationStore([failure(index) for index in range(4)])
    _run_until_drained(_engine(store, rule), store)
    assert len(store.ledger) == 4
    assert store.raw_states == {}

    fifth = failure(4)
    store.inputs.append(fifth)
    fifth_stats = _engine(store, rule).run_cycle()[0]
    assert fifth_stats.evaluated_inputs == 1
    assert fifth_stats.matched_inputs == 0
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    partials = store.load_episode_states(scope, fifth, rule, 100)
    assert len(partials) == 1
    partial = partials[0]
    assert not partial.incident_id
    assert partial.owned_tagged_ids == frozenset(
        failure(index).tagged_id for index in range(5)
    )
    raw_revision_count = len(store.raw_states[partial.episode_state_id])

    sixth = failure(5)
    store.inputs.append(sixth)
    sixth_stats = _engine(store, rule).run_cycle()[0]
    assert sixth_stats.evaluated_inputs == 1
    assert sixth_stats.matched_inputs == 0
    assert len(store.raw_states[partial.episode_state_id]) == raw_revision_count

    success = _ssh_success_event(
        "prefix-success",
        source_ip="192.0.2.44",
        occurred_at=BASE_TIME + timedelta(seconds=55),
    )
    success = replace(
        success,
        values={**success.values, "user_name": "prefix-user"},
    )
    store.inputs.append(success)
    final = _engine(store, rule).run_cycle()[0]
    assert final.evaluated_inputs == 1
    assert final.matched_inputs == 1
    incident = next(iter(store.current_incidents().values()))
    assert incident.values["episode_anchor_id"] == success.input_id
    assert incident.values["detection_count"] == 6
    assert incident.values["event_count"] == 1


def test_preloaded_complete_sequence_prefix_writes_one_state_revision(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-ssh-bruteforce-success"
    ]

    failures = [
        _detection(
            f"preloaded-prefix-failure-{index}",
            occurred_at=BASE_TIME + timedelta(seconds=index * 10),
            host="fusion-ubuntu",
            rule_id="fusion-linux-authentication-failure",
            severity="low",
            user="preloaded-prefix-user",
            source_ip="192.0.2.44",
            platform="linux",
        )
        for index in range(5)
    ]
    store = MemoryCorrelationStore(failures)

    stats = _engine(store, rule, batch_size=1_000).run_cycle()[0]

    assert stats.evaluated_inputs == 5
    assert stats.matched_inputs == 0
    assert len(store.ledger) == 5
    assert store.current_incidents() == {}
    assert len(store.raw_states) == 1
    assert sum(len(revisions) for revisions in store.raw_states.values()) == 1
    partial = next(iter(store.raw_states.values()))[-1]
    assert partial.owned_tagged_ids == frozenset(
        failure.tagged_id for failure in failures
    )


def test_1001_terminal_only_sequence_inputs_are_stateless_and_page_completely(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-ssh-bruteforce-success"
    ]
    successes = []
    for index in range(1_001):
        item = _ssh_success_event(
            f"terminal-only-{index:04d}",
            source_ip="192.0.2.44",
        )
        successes.append(
            replace(
                item,
                values={**item.values, "user_name": f"terminal-user-{index:04d}"},
            )
        )
    store = MemoryCorrelationStore(successes)

    cycles = _run_until_drained(
        _engine(store, rule, batch_size=1_000), store, maximum=3
    )

    assert [cycle.evaluated_inputs for cycle in cycles] == [1_000, 1]
    assert len(store.ledger) == 1_001
    assert store.raw_states == {}
    assert store.current_incidents() == {}


def test_observation_deadline_is_inclusive_then_rejects_one_millisecond_late(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    d1 = _detection("d-a", rule_id="det-rule-a")
    d2 = _detection(
        "d-b", occurred_at=BASE_TIME + timedelta(seconds=1), rule_id="det-rule-b"
    )
    initial = evaluator.evaluate(scope, rule, d2, [d1, d2], now=BASE_TIME)
    assert initial.incident is not None
    state = initial.episode_states[0]
    deadline = state.late_accept_until
    exactly = _detection(
        "d-c",
        occurred_at=BASE_TIME + timedelta(seconds=2),
        observed_at=deadline,
        rule_id="det-rule-c",
    )
    accepted = evaluator.evaluate(
        scope,
        rule,
        exactly,
        [d1, d2, exactly],
        (state,),
        {initial.incident.incident_id: initial.incident},
        now=deadline,
    )
    assert accepted.matched
    assert accepted.lateness_status == "late_within_boundary"

    too_late = _detection(
        "d-d",
        occurred_at=BASE_TIME + timedelta(seconds=3),
        observed_at=deadline + timedelta(milliseconds=1),
        rule_id="det-rule-d",
    )
    rejected = evaluator.evaluate(
        scope,
        rule,
        too_late,
        [d1, d2, too_late],
        (state,),
        {initial.incident.incident_id: initial.incident},
        now=deadline + timedelta(milliseconds=1),
    )
    assert not rejected.matched
    assert rejected.evaluation_action == "no_match"
    assert rejected.lateness_status == "late_outside_boundary"


def test_closed_incident_uses_closed_at_lateness_cap_and_never_reopens(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    d1 = _detection("closed-a", rule_id="det-rule-a")
    d2 = _detection(
        "closed-b",
        occurred_at=BASE_TIME + timedelta(seconds=1),
        rule_id="det-rule-b",
    )
    initial = evaluator.evaluate(scope, rule, d2, [d1, d2], now=BASE_TIME)
    assert initial.incident is not None
    closed_at = BASE_TIME + timedelta(minutes=2)
    closed_deadline = closed_at + timedelta(
        seconds=rule.rule.allowed_lateness.seconds
    )
    closed_values = {
        **initial.incident.values,
        "status": "closed",
        "closed_at": closed_at,
        "late_accept_until": closed_deadline,
    }
    closed = IncidentRecord(closed_values)

    exact_cap = _detection(
        "closed-exact-cap",
        occurred_at=BASE_TIME + timedelta(minutes=1),
        observed_at=closed_deadline,
        rule_id="det-rule-c",
    )
    accepted = evaluator.evaluate(
        scope,
        rule,
        exact_cap,
        [d1, d2, exact_cap],
        initial.episode_states,
        {closed.incident_id: closed},
        now=closed_deadline,
    )
    assert accepted.matched
    assert accepted.evaluation_action == "enriched_closed"
    assert accepted.expected_incident is not None
    assert accepted.expected_incident.values["status"] == "closed"

    after_cap = _detection(
        "closed-c",
        occurred_at=BASE_TIME + timedelta(minutes=1),
        observed_at=closed_deadline + timedelta(milliseconds=1),
        rule_id="det-rule-c",
    )
    rejected = evaluator.evaluate(
        scope,
        rule,
        after_cap,
        [d1, d2, after_cap],
        initial.episode_states,
        {closed.incident_id: closed},
        now=closed_deadline + timedelta(milliseconds=1),
    )
    assert not rejected.matched
    assert rejected.lateness_status == "late_outside_boundary"

    after_close_occurrence = _detection(
        "closed-d",
        occurred_at=closed_at + timedelta(milliseconds=1),
        observed_at=closed_at + timedelta(seconds=1),
        rule_id="det-rule-d",
    )
    rejected_occurrence = evaluator.evaluate(
        scope,
        rule,
        after_close_occurrence,
        [d1, d2, after_close_occurrence],
        initial.episode_states,
        {closed.incident_id: closed},
        now=closed_at + timedelta(seconds=1),
    )
    assert not rejected_occurrence.matched
    assert rejected_occurrence.resulting_incident_id == closed.incident_id


def _overlapping_episode_case(rule, evaluator, scope):
    """Build two independently qualified, overlapping states for collision tests."""

    first_a = _detection("overlap-first-a", rule_id="det-rule-a")
    first_b = _detection(
        "overlap-first-b",
        occurred_at=BASE_TIME + timedelta(seconds=5),
        rule_id="det-rule-b",
    )
    second_a = _detection(
        "overlap-second-a",
        occurred_at=BASE_TIME + timedelta(seconds=4),
        rule_id="det-rule-c",
    )
    second_b = _detection(
        "overlap-second-b",
        occurred_at=BASE_TIME + timedelta(seconds=8),
        rule_id="det-rule-d",
    )
    first = evaluator.evaluate(scope, rule, first_b, [first_a, first_b], now=BASE_TIME)
    second = evaluator.evaluate(
        scope, rule, second_b, [second_a, second_b], now=BASE_TIME
    )
    assert first.incident is not None and second.incident is not None

    # Both occurrence intervals contain this candidate. The first anchor is
    # nearer, but observation is 2s after its deadline and 2s before the
    # second episode's deadline.
    candidate = _detection(
        "overlap-candidate",
        occurred_at=BASE_TIME + timedelta(seconds=6),
        observed_at=BASE_TIME + timedelta(minutes=25, seconds=2),
        rule_id="det-rule-e",
    )
    context = [first_a, first_b, second_a, second_b, candidate]
    states = (first.episode_states[0], second.episode_states[0])
    incidents = {
        first.incident.incident_id: first.incident,
        second.incident.incident_id: second.incident,
    }
    return candidate, context, states, incidents, first, second


def test_overlap_selects_attachable_owner_before_nearest_expired_owner(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    candidate, context, states, incidents, _first, second = _overlapping_episode_case(
        rule, evaluator, scope
    )

    decision = evaluator.evaluate(
        scope,
        rule,
        candidate,
        context,
        states,
        incidents,
        now=candidate.observed_at,
    )

    assert decision.matched
    assert decision.resulting_incident_id == second.incident.incident_id
    assert decision.episode_states[0].collision_count == 1


def test_collision_count_is_not_amplified_by_preledger_crash_replay(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    candidate, context, _states, _incidents, first, second = _overlapping_episode_case(
        rule, evaluator, scope
    )
    store = MemoryCorrelationStore(context)

    def persist_seed(completing_input, decision):
        store.write_incident(decision.incident)
        store.write_links(decision.links)
        store.write_episode_states(decision.episode_states)
        store.confirm_decision(scope, completing_input, decision)
        store.mark_evaluated(scope, [(completing_input, decision)])

    persist_seed(context[1], first)
    persist_seed(context[3], second)
    for item in (context[0], context[2]):
        decision = EvaluationDecision(
            "no_match",
            "not_applicable",
            "seeded_context",
            evaluation_token(scope, item),
        )
        store.mark_evaluated(scope, [(item, decision)])

    crashed = False

    def crash(stage, crash_candidate, _decision):
        nonlocal crashed
        if (
            not crashed
            and stage == "after_links_state_before_confirmation"
            and crash_candidate.input_id == candidate.input_id
        ):
            crashed = True
            raise SimulatedCrash(stage)

    with pytest.raises(SimulatedCrash, match="after_links_state_before_confirmation"):
        _engine(
            store,
            rule,
            crash_hook=crash,
            now=BASE_TIME + timedelta(minutes=26),
        ).run_cycle()
    assert crashed
    token = evaluation_token(scope, candidate)
    provisional = [
        state
        for rows in store.raw_states.values()
        for state in rows
        if state.revision_token == token
    ]
    assert len(provisional) == 1
    assert provisional[0].collision_count == 1

    final = _engine(
        store, rule, now=BASE_TIME + timedelta(minutes=26)
    ).run_cycle()[0]
    assert final.backlog.unevaluated_input_count == 0
    assert len(store.ledger) == 5
    replayed = [
        state
        for rows in store.raw_states.values()
        for state in rows
        if state.revision_token == token
    ]
    assert {state.collision_count for state in replayed} == {1}
    assert len({state.state_hash for state in replayed}) == 1


def test_shared_ip_join_after_deadline_is_explicitly_late_outside_boundary(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-suricata-endpoint"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    network = replace(
        _detection(
            "shared-late-network",
            source_ip="192.168.186.129",
            rule_id="fusion-network-controlled-suricata-signature",
            platform="network",
        ),
        values={
            **_detection("unused").values,
            "source_type": "suricata_eve",
            "platform": "network",
            "host_name": "",
            "source_ip": "192.168.186.129",
            "destination_ip": "192.168.186.2",
            "rule_id": "fusion-network-controlled-suricata-signature",
            "severity": "medium",
        },
    )
    endpoint = replace(
        _detection(
            "shared-late-endpoint",
            occurred_at=BASE_TIME + timedelta(seconds=1),
            host="Endpoint.Example.",
            rule_id="fusion-windows-encoded-powershell",
        ),
        values={
            **_detection("unused").values,
            "source_type": "windows_sysmon",
            "platform": "windows",
            "host_name": "Endpoint.Example.",
            "rule_id": "fusion-windows-encoded-powershell",
            "severity": "high",
        },
    )
    ownership = InputEnvelope(
        "event",
        "shared-late-ownership",
        BASE_TIME + timedelta(seconds=2),
        BASE_TIME + timedelta(seconds=3),
        {
            "source_type": "windows_sysmon",
            "platform": "windows",
            "host_name": "endpoint.example",
            "source_ip": "192.168.186.129",
            "destination_ip": "192.168.186.2",
            "event_code": "3",
            "initiated": 1,
        },
    )
    initial = evaluator.evaluate(
        scope,
        rule,
        ownership,
        [network, endpoint, ownership],
        now=BASE_TIME + timedelta(minutes=1),
    )
    assert initial.incident is not None
    late_endpoint = replace(
        endpoint,
        input_id="shared-late-new-endpoint",
        occurred_at=BASE_TIME + timedelta(seconds=3),
        observed_at=initial.episode_states[0].late_accept_until
        + timedelta(milliseconds=1),
        values={**endpoint.values, "rule_id": "fusion-windows-suspicious-lolbin"},
    )

    rejected = evaluator.evaluate(
        scope,
        rule,
        late_endpoint,
        [network, endpoint, ownership, late_endpoint],
        initial.episode_states,
        {initial.incident.incident_id: initial.incident},
        now=late_endpoint.observed_at,
    )

    assert not rejected.matched
    assert rejected.evaluation_action == "no_match"
    assert rejected.lateness_status == "late_outside_boundary"
    assert rejected.reason_code == "late_outside_boundary"
    assert rejected.resulting_incident_id == initial.incident.incident_id


def test_natural_reconciliation_horizon_is_explicitly_accounted(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    evaluator = CorrelationEvaluator()
    scope = RuleScope(ENGINE_ID, rule.rule_id, rule.version, rule.scope_fingerprint)
    outside = _detection(
        "outside-reconciliation-horizon",
        observed_at=BASE_TIME
        + timedelta(
            milliseconds=(
                rule.rule.window.milliseconds
                + rule.rule.allowed_lateness.milliseconds
                + 1
            )
        ),
        rule_id="det-rule-a",
    )

    decision = evaluator.evaluate(scope, rule, outside, [outside], now=outside.observed_at)

    assert not decision.matched
    assert decision.evaluation_action == "no_match"
    assert decision.lateness_status == "late_outside_boundary"
    assert decision.reason_code == "outside_reconciliation_horizon"
    assert decision.episode_states == ()


def test_repeatable_input_persistence_conflict_rotates_without_starving_later_pages(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]

    class PoisonInputStore(MemoryCorrelationStore):
        def mark_evaluated(self, scope, entries):
            if any(candidate.input_id == "poison" for candidate, _ in entries):
                raise CorrelationPersistenceConflict("repeatable per-input conflict")
            return super().mark_evaluated(scope, entries)

    inputs = [
        _detection("poison", rule_id="det-rule-a"),
        _detection(
            "later-b",
            occurred_at=BASE_TIME + timedelta(seconds=1),
            rule_id="det-rule-b",
        ),
        _detection(
            "later-c",
            occurred_at=BASE_TIME + timedelta(seconds=2),
            rule_id="det-rule-c",
        ),
    ]
    store = PoisonInputStore(inputs)
    engine = _engine(store, rule, batch_size=1)

    first = engine.run_cycle()[0]
    assert first.evaluated_inputs == 0
    assert first.failed_inputs == 1
    assert first.cursor is not None and first.cursor.input_id == "poison"
    assert {key[-1] for key in store.ledger} == set()

    second = engine.run_cycle()[0]
    assert second.evaluated_inputs == 1
    assert second.failed_inputs == 0
    assert second.cursor is not None and second.cursor.input_id == "later-b"
    assert {key[-1] for key in store.ledger} == {"later-b"}

    third = engine.run_cycle()[0]
    assert third.evaluated_inputs == 1
    assert third.failed_inputs == 0
    assert third.cursor is not None and third.cursor.input_id == "later-c"
    assert {key[-1] for key in store.ledger} == {"later-b", "later-c"}

    retried = engine.run_cycle()[0]
    assert retried.evaluated_inputs == 0
    assert retried.failed_inputs == 1
    assert retried.cursor is not None and retried.cursor.input_id == "poison"
    assert {key[-1] for key in store.ledger} == {"later-b", "later-c"}


def test_retroactive_canonical_time_regression_blocks_scope_before_mutation(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    first = _detection("retroactive-a", rule_id="det-rule-a")
    second = _detection(
        "retroactive-b",
        occurred_at=BASE_TIME + timedelta(seconds=1),
        observed_at=BASE_TIME + timedelta(seconds=2),
        rule_id="det-rule-b",
    )
    store = MemoryCorrelationStore([first, second])
    initial = _engine(store, rule, batch_size=2).run_cycle()[0]
    assert initial.integrity.status == "healthy"
    assert len(store.current_incidents()) == 1
    assert len(store.current_links()) == 2

    baseline = (
        len(store.ledger),
        len(store.raw_incidents),
        len(store.raw_links),
        len(store.raw_states),
        len(store.schedules),
    )
    operation_count = len(store.operations)
    store.inputs.extend(
        [
            replace(first, observed_at=first.observed_at - timedelta(seconds=30)),
            _detection(
                "would-have-been-new",
                occurred_at=BASE_TIME + timedelta(seconds=2),
                observed_at=BASE_TIME + timedelta(seconds=3),
                rule_id="det-rule-c",
            ),
        ]
    )

    blocked = _engine(
        store, rule, batch_size=2, now=BASE_TIME + timedelta(minutes=2)
    ).run_cycle()[0]
    assert blocked.integrity.status == "blocked_integrity"
    assert blocked.integrity.violation_count == 1
    assert blocked.integrity.violation_types == (
        "canonical_observation_mismatch",
    )
    assert blocked.backlog is None
    assert blocked.evaluated_inputs == 0
    assert [name for name, _ in store.operations[operation_count:]] == [
        "check_scope_integrity",
    ]
    assert baseline == (
        len(store.ledger),
        len(store.raw_incidents),
        len(store.raw_links),
        len(store.raw_states),
        len(store.schedules),
    )
    assert store.integrity_events[0]["input_id"] == first.input_id
    assert store.integrity_events[0]["ledger_observed_at"] == first.observed_at
    assert store.integrity_events[0]["canonical_observed_at"] == (
        first.observed_at - timedelta(seconds=30)
    )

    # The durable block survives another process restart and does not duplicate
    # its first-detected diagnostic.
    restarted = _engine(
        store, rule, batch_size=2, now=BASE_TIME + timedelta(minutes=3)
    ).run_cycle()[0]
    assert restarted.integrity.blocked
    assert restarted.backlog is None
    assert len(store.integrity_events) == 1
    assert [name for name, _ in store.operations[-1:]] == [
        "check_scope_integrity",
    ]
    assert baseline == (
        len(store.ledger),
        len(store.raw_incidents),
        len(store.raw_links),
        len(store.raw_states),
        len(store.schedules),
    )


def test_unchanged_canonical_time_does_not_false_block_scope(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    original = _detection("unchanged-canonical", rule_id="det-rule-a")
    store = MemoryCorrelationStore([original])
    first = _engine(store, rule).run_cycle()[0]
    assert first.integrity.status == "healthy"

    # Identical and later physical observations leave canonical MIN unchanged.
    store.inputs.extend(
        [
            replace(original),
            replace(original, observed_at=original.observed_at + timedelta(minutes=1)),
        ]
    )
    replay = _engine(
        store, rule, now=BASE_TIME + timedelta(minutes=2)
    ).run_cycle()[0]
    assert replay.integrity.status == "healthy"
    assert replay.integrity.violation_count == 0
    assert replay.backlog is not None
    assert replay.backlog.unevaluated_input_count == 0
    assert store.integrity_events == []


def test_projection_fault_on_first_cycle_precedes_scope_enrollment_mutation(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rule = _rules(rules_dir, mitre_mapping_path)[
        "fusion-correlation-host-suspicious-activity"
    ]
    store = MemoryCorrelationStore(
        [_detection("must-not-enroll", rule_id="det-rule-a")]
    )
    store.projection_contract_valid = False

    blocked = _engine(store, rule).run_cycle()[0]

    assert blocked.integrity.status == "blocked_integrity"
    assert blocked.integrity.violation_types == ("projection_contract_mismatch",)
    assert blocked.backlog is None
    assert blocked.evaluated_inputs == 0
    assert store.operations == [("check_scope_integrity", rule.rule_id)]
    assert store.floors == {}
    assert store.cursors == {}
    assert store.ledger == {}
    assert store.raw_incidents == {}
    assert store.raw_links == {}
    assert store.raw_states == {}
    assert store.readback_tokens == set()
    assert store.confirmed_tokens == set()
    assert store.schedules == []
    assert len(store.integrity_events) == 1

    # A process restart consults the durable integrity block before attempting
    # enrollment and cannot turn the diagnostic into scope bootstrap state.
    restarted = _engine(
        store, rule, now=BASE_TIME + timedelta(minutes=1)
    ).run_cycle()[0]
    assert restarted.integrity.blocked
    assert restarted.backlog is None
    assert [name for name, _ in store.operations] == [
        "check_scope_integrity",
        "check_scope_integrity",
    ]
    assert store.floors == {}
    assert len(store.integrity_events) == 1


def test_integrity_block_is_scoped_and_other_rule_remains_operational(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rules = _rules(rules_dir, mitre_mapping_path)
    blocked_rule = rules["fusion-correlation-host-suspicious-activity"]
    healthy_rule = rules["fusion-correlation-user-suspicious-activity"]
    candidate = _detection("scope-isolation", rule_id="det-rule-a")
    store = MemoryCorrelationStore([candidate])
    blocked_scope = RuleScope(
        ENGINE_ID,
        blocked_rule.rule_id,
        blocked_rule.version,
        blocked_rule.scope_fingerprint,
    )
    store.integrity_states[blocked_scope.key] = CorrelationIntegrityStatus(
        "blocked_integrity", 1, ("projection_coverage_gap",), BASE_TIME
    )
    engine = CorrelationEngine(
        store=store,
        evaluator=CorrelationEvaluator(),
        compiled_rules=[blocked_rule, healthy_rule],
        engine_id=ENGINE_ID,
        lookback_seconds=3600,
        batch_size=1000,
        context_limit=20_000,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )

    by_rule = {stats.scope.rule_id: stats for stats in engine.run_cycle()}
    assert by_rule[blocked_rule.rule_id].integrity.blocked
    assert by_rule[blocked_rule.rule_id].backlog is None
    assert by_rule[healthy_rule.rule_id].integrity.status == "healthy"
    assert by_rule[healthy_rule.rule_id].evaluated_inputs == 1
    assert any(key[1] == healthy_rule.rule_id for key in store.ledger)
    assert not any(key[1] == blocked_rule.rule_id for key in store.ledger)


def test_ruleset_fingerprint_is_order_independent_and_semantic(
    rules_dir: Path, mitre_mapping_path: Path
) -> None:
    rules = list(_rules(rules_dir, mitre_mapping_path).values())
    store = MemoryCorrelationStore()

    def engine_for(values) -> CorrelationEngine:
        return CorrelationEngine(
            store=store,
            evaluator=CorrelationEvaluator(),
            compiled_rules=values,
            engine_id=ENGINE_ID,
            lookback_seconds=3600,
            batch_size=1000,
            context_limit=20_000,
        )

    forward = engine_for(rules)
    reverse = engine_for(list(reversed(rules)))
    changed = engine_for([replace(rules[0], scope_fingerprint="0" * 64), *rules[1:]])
    assert forward.ruleset_fingerprint == reverse.ruleset_fingerprint
    assert len(forward.ruleset_fingerprint) == 64
    assert forward.ruleset_fingerprint != changed.ruleset_fingerprint
