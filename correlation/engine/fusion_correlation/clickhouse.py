"""Acknowledged, bounded ClickHouse persistence for correlation state."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

import clickhouse_connect

from . import __version__
from .config import Settings
from .evaluator import selector_matches
from .identity import (
    IDENTITY_NORMALIZATION_VERSION,
    IdentityNormalizationError,
    canonical_group_json,
)
from .incident import (
    canonical_json,
    evaluation_token,
    group_identity,
    scope_bootstrap_token,
    state_hash,
)
from .models import CompiledRule, Selector
from .runtime_models import (
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

INCIDENT_COLUMNS = (
    "incident_id",
    "incident_title",
    "incident_type",
    "status",
    "severity",
    "severity_rank",
    "confidence",
    "created_at",
    "updated_at",
    "first_seen",
    "last_seen",
    "acknowledged_at",
    "closed_at",
    "last_transition_id",
    "last_transition_from",
    "last_transition_at",
    "primary_host",
    "primary_user",
    "primary_source_ip",
    "primary_destination_ip",
    "input_count",
    "detection_count",
    "event_count",
    "distinct_detection_rule_count",
    "source_family_count",
    "mitre_tactic_ids",
    "mitre_technique_ids",
    "correlation_rule_id",
    "correlation_rule_version",
    "correlation_scope_fingerprint",
    "group_key_json",
    "group_key_hash",
    "episode_anchor_kind",
    "episode_anchor_id",
    "episode_anchor_time",
    "episode_window_start",
    "episode_window_end",
    "last_evidence_observed_at",
    "late_accept_until",
    "late_update_count",
    "revision",
    "state_hash",
    "revision_source",
    "revision_token",
    "evidence_json",
    "validation_id",
)

INCIDENT_DATETIME_FIELDS = frozenset(
    {
        "created_at",
        "updated_at",
        "first_seen",
        "last_seen",
        "acknowledged_at",
        "closed_at",
        "last_transition_at",
        "episode_anchor_time",
        "episode_window_start",
        "episode_window_end",
        "last_evidence_observed_at",
        "late_accept_until",
    }
)

EPISODE_COLUMNS = (
    "engine_id",
    "correlation_rule_id",
    "correlation_rule_version",
    "correlation_scope_fingerprint",
    "group_key_json",
    "group_key_hash",
    "episode_state_id",
    "revision_token",
    "canonical_qualifying_inputs",
    "episode_anchor_kind",
    "episode_anchor_id",
    "episode_anchor_time",
    "episode_window_start",
    "episode_window_end",
    "active_incident_id",
    "owned_detection_ids",
    "owned_event_uids",
    "last_input_observed_at",
    "late_accept_until",
    "collision_count",
    "state_hash",
    "updated_at",
    "revision",
)

LEDGER_COLUMNS = (
    "engine_id",
    "correlation_rule_id",
    "correlation_rule_version",
    "correlation_scope_fingerprint",
    "input_kind",
    "input_id",
    "occurred_at",
    "observed_at",
    "evaluated_at",
    "evaluation_action",
    "lateness_status",
    "incident_id",
    "evaluation_token",
    "reason_code",
    "source_type",
    "host_name",
    "validation_id",
)

DETECTION_LINK_COLUMNS = (
    "incident_id",
    "detection_id",
    "link_id",
    "introduction_revision_token",
    "relationship",
    "occurred_at",
    "observed_at",
    "linked_at",
    "correlation_rule_id",
    "correlation_rule_version",
    "correlation_scope_fingerprint",
    "source_type",
    "detection_rule_id",
    "detection_rule_name",
    "severity",
    "host_name",
    "user_name",
    "source_ip",
    "destination_ip",
    "mitre_technique_ids",
    "summary",
    "validation_id",
)

EVENT_LINK_COLUMNS = (
    "incident_id",
    "event_uid",
    "link_id",
    "introduction_revision_token",
    "relationship",
    "occurred_at",
    "observed_at",
    "linked_at",
    "correlation_rule_id",
    "correlation_rule_version",
    "correlation_scope_fingerprint",
    "source_type",
    "event_category",
    "event_action",
    "outcome",
    "service_name",
    "host_name",
    "user_name",
    "source_ip",
    "destination_ip",
    "summary",
    "validation_id",
)

_LINK_VOLATILE_COLUMNS = frozenset({"linked_at"})
_CANONICAL_SQL_FIELDS = frozenset(
    {"host_name", "user_name", "source_ip", "destination_ip", "platform"}
)

SCHEDULE_COLUMNS = (
    "engine_id",
    "correlation_rule_id",
    "correlation_rule_version",
    "correlation_scope_fingerprint",
    "candidate_cursor_occurred_at",
    "candidate_cursor_observed_at",
    "candidate_cursor_input_kind",
    "candidate_cursor_input_id",
    "newest_eligible_occurred_at",
    "newest_eligible_observed_at",
    "newest_eligible_input_kind",
    "newest_eligible_input_id",
    "unevaluated_input_count",
    "oldest_unevaluated_observed_at",
    "oldest_unevaluated_age_seconds",
    "cycle_evaluated_count",
    "cycle_matched_count",
    "cycle_failed_count",
    "cycle_incident_create_count",
    "cycle_incident_update_count",
    "cycle_detection_link_write_count",
    "cycle_event_link_write_count",
    "processing_duration_seconds",
    "evaluated_inputs_per_second",
    "consecutive_drain_cycles",
    "updated_at",
    "revision",
)

DETECTION_VALUE_FIELDS = (
    "rule_id",
    "rule_version",
    "rule_name",
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
    "signature",
    "signature_id",
    "mitre_technique_ids",
    "validation_id",
)

EVENT_VALUE_FIELDS = (
    "platform",
    "vendor",
    "product",
    "source_type",
    "host_name",
    "user_name",
    "user_id",
    "source_ip",
    "destination_ip",
    "protocol",
    "event_code",
    "event_category",
    "event_action",
    "event_kind",
    "service_name",
    "outcome",
    "initiated",
    "validation_id",
)

INPUT_VALUE_FIELDS = (
    "rule_id",
    "rule_version",
    "rule_name",
    "severity",
    "platform",
    "vendor",
    "product",
    "source_type",
    "host_name",
    "user_name",
    "user_id",
    "source_ip",
    "destination_ip",
    "protocol",
    "signature",
    "signature_id",
    "mitre_technique_ids",
    "event_code",
    "event_category",
    "event_action",
    "event_kind",
    "service_name",
    "outcome",
    "initiated",
    "validation_id",
)

SELECTOR_SQL_FIELDS = frozenset(
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
        "user_id",
        "source_ip",
        "destination_ip",
        "protocol",
        "signature_id",
        "event_code",
        "event_category",
        "event_action",
        "event_kind",
        "service_name",
        "outcome",
        "initiated",
    }
)

HISTORY_TABLE_NAME = "correlation_detection_input_history"
HISTORY_PROJECTION_NAME = "correlation_detection_input_history_mv"
HISTORY_PROJECTION_QUALIFIED_NAME = f"fusion.{HISTORY_PROJECTION_NAME}"
HISTORY_TABLE_QUALIFIED_NAME = f"fusion.{HISTORY_TABLE_NAME}"
HISTORY_SOURCE_QUALIFIED_NAME = "fusion.detections"
WITNESS_TABLE_NAME = "correlation_detection_input_witness"
WITNESS_PROJECTION_NAME = "correlation_detection_input_witness_mv"
WITNESS_PROJECTION_QUALIFIED_NAME = f"fusion.{WITNESS_PROJECTION_NAME}"
WITNESS_TABLE_QUALIFIED_NAME = f"fusion.{WITNESS_TABLE_NAME}"
HISTORY_PROJECTION_COLUMNS = (
    "detection_id",
    "detected_at",
    "source_event_time",
    *DETECTION_VALUE_FIELDS,
)
HISTORY_SEMANTIC_FINGERPRINT_EXPRESSION = (
    "lower(hex(SHA256(toString(tuple("
    + ", ".join(("source_event_time", *DETECTION_VALUE_FIELDS))
    + ")))))"
)
HISTORY_TARGET_COLUMN_CONTRACT = (
    ("detection_id", "String", "", ""),
    ("detected_at", "DateTime64(3, 'UTC')", "", ""),
    ("source_event_time", "DateTime64(3, 'UTC')", "", ""),
    ("rule_id", "String", "", ""),
    ("rule_version", "String", "", ""),
    ("rule_name", "String", "", ""),
    ("severity", "LowCardinality(String)", "", ""),
    ("platform", "LowCardinality(String)", "", ""),
    ("vendor", "LowCardinality(String)", "", ""),
    ("product", "LowCardinality(String)", "", ""),
    ("source_type", "LowCardinality(String)", "", ""),
    ("host_name", "String", "", ""),
    ("user_name", "String", "", ""),
    ("source_ip", "String", "", ""),
    ("destination_ip", "String", "", ""),
    ("protocol", "LowCardinality(String)", "", ""),
    ("signature", "String", "", ""),
    ("signature_id", "String", "", ""),
    ("mitre_technique_ids", "Array(String)", "", ""),
    ("validation_id", "String", "", ""),
    (
        "semantic_fingerprint",
        "String",
        "MATERIALIZED",
        HISTORY_SEMANTIC_FINGERPRINT_EXPRESSION,
    ),
)
EXPECTED_HISTORY_PROJECTION_SELECT = (
    "SELECT "
    + ", ".join(HISTORY_PROJECTION_COLUMNS)
    + " FROM "
    + HISTORY_SOURCE_QUALIFIED_NAME
)
WITNESS_TARGET_COLUMN_CONTRACT = (
    ("detection_id", "String", "", ""),
    ("detected_at", "DateTime64(3, 'UTC')", "", ""),
    ("semantic_fingerprint", "String", "", ""),
)
WITNESS_REQUIRED_CONSTRAINTS = (
    (
        "CONSTRAINT correlation_detection_witness_identity_valid CHECK "
        "match(semantic_fingerprint, '^[0-9a-f]{64}$')"
    ),
)
EXPECTED_WITNESS_PROJECTION_SELECT = (
    "SELECT detection_id, detected_at, "
    + HISTORY_SEMANTIC_FINGERPRINT_EXPRESSION
    + " AS semantic_fingerprint FROM "
    + HISTORY_SOURCE_QUALIFIED_NAME
)
INTEGRITY_EVENT_COLUMNS = (
    "integrity_event_id",
    "detected_at",
    "first_detected_at",
    "engine_id",
    "ruleset_fingerprint",
    "correlation_rule_id",
    "correlation_rule_version",
    "correlation_scope_fingerprint",
    "violation_type",
    "input_kind",
    "input_id",
    "ledger_observed_at",
    "canonical_observed_at",
    "projection_name",
    "expected_projection_fingerprint",
    "actual_projection_fingerprint",
    "diagnostic_json",
)
INTEGRITY_TABLE_NAME = "correlation_integrity_events"
INTEGRITY_TABLE_QUALIFIED_NAME = f"fusion.{INTEGRITY_TABLE_NAME}"
INTEGRITY_CURRENT_VIEW_NAME = "correlation_integrity_scope_state_current"
INTEGRITY_CURRENT_VIEW_QUALIFIED_NAME = f"fusion.{INTEGRITY_CURRENT_VIEW_NAME}"
INTEGRITY_TARGET_COLUMN_CONTRACT = (
    ("integrity_event_id", "String", "", ""),
    ("detected_at", "DateTime64(3, 'UTC')", "", ""),
    ("first_detected_at", "DateTime64(3, 'UTC')", "", ""),
    ("engine_id", "LowCardinality(String)", "", ""),
    ("ruleset_fingerprint", "String", "", ""),
    ("correlation_rule_id", "String", "", ""),
    ("correlation_rule_version", "UInt32", "", ""),
    ("correlation_scope_fingerprint", "String", "", ""),
    ("violation_type", "LowCardinality(String)", "", ""),
    ("input_kind", "LowCardinality(String)", "DEFAULT", "''"),
    ("input_id", "String", "DEFAULT", "''"),
    ("ledger_observed_at", "Nullable(DateTime64(3, 'UTC'))", "", ""),
    ("canonical_observed_at", "Nullable(DateTime64(3, 'UTC'))", "", ""),
    ("projection_name", "String", "DEFAULT", "''"),
    ("expected_projection_fingerprint", "String", "DEFAULT", "''"),
    ("actual_projection_fingerprint", "String", "DEFAULT", "''"),
    ("diagnostic_json", "String", "DEFAULT", "'{}'"),
)
INTEGRITY_SORT_KEY = (
    "engine_id, ruleset_fingerprint, correlation_rule_id, "
    "correlation_rule_version, correlation_scope_fingerprint, "
    "first_detected_at, integrity_event_id, detected_at"
)
INTEGRITY_REQUIRED_CONSTRAINTS = (
    (
        "CONSTRAINT correlation_integrity_identity_nonempty CHECK "
        "match(integrity_event_id, '^[0-9a-f]{64}$') AND notEmpty(engine_id) "
        "AND match(ruleset_fingerprint, '^[0-9a-f]{64}$') "
        "AND notEmpty(correlation_rule_id) "
        "AND match(correlation_scope_fingerprint, '^[0-9a-f]{64}$')"
    ),
    (
        "CONSTRAINT correlation_integrity_rule_version_positive CHECK "
        "correlation_rule_version > 0"
    ),
    (
        "CONSTRAINT correlation_integrity_detection_ordered CHECK "
        "detected_at >= first_detected_at"
    ),
    (
        "CONSTRAINT correlation_integrity_violation_allowed CHECK violation_type IN "
        "('canonical_observation_mismatch', 'canonical_observation_uncertain', "
        "'projection_unavailable', 'projection_contract_mismatch', "
        "'projection_coverage_gap', 'projection_coverage_uncertain')"
    ),
    (
        "CONSTRAINT correlation_integrity_input_kind_allowed CHECK input_kind IN "
        "('', 'detection', 'event')"
    ),
    (
        "CONSTRAINT correlation_integrity_details_consistent CHECK "
        "((violation_type = 'canonical_observation_mismatch') AND "
        "(input_kind IN ('detection', 'event')) AND notEmpty(input_id) AND "
        "(ledger_observed_at IS NOT NULL) AND "
        "(canonical_observed_at IS NOT NULL) AND "
        "(ledger_observed_at != canonical_observed_at)) OR "
        "((violation_type = 'projection_coverage_gap') AND "
        "(input_kind = 'detection') AND "
        "(canonical_observed_at IS NOT NULL) AND notEmpty(projection_name) AND "
        "((notEmpty(input_id) AND "
        "(JSONExtractString(diagnostic_json, 'input_id_state') = '')) OR "
        "(empty(input_id) AND "
        "(JSONExtractString(diagnostic_json, 'input_id_state') = 'empty')))) OR "
        "((violation_type IN ('projection_unavailable', "
        "'projection_contract_mismatch', 'projection_coverage_uncertain', "
        "'canonical_observation_uncertain')) AND notEmpty(projection_name))"
    ),
    (
        "CONSTRAINT correlation_integrity_diagnostic_safe CHECK "
        "(length(diagnostic_json) <= 8192) AND isValidJSON(diagnostic_json)"
    ),
    (
        "CONSTRAINT correlation_integrity_projection_fingerprints_valid CHECK "
        "(empty(expected_projection_fingerprint) OR "
        "match(expected_projection_fingerprint, '^[0-9a-f]{64}$')) AND "
        "(empty(actual_projection_fingerprint) OR "
        "match(actual_projection_fingerprint, '^[0-9a-f]{64}$'))"
    ),
)
# Backward-compatible name for focused tests and downstream diagnostics.  The
# values are complete constraints, not substrings; runtime comparison parses
# top-level constraint declarations and requires exact normalized equality.
INTEGRITY_REQUIRED_CONSTRAINT_FRAGMENTS = INTEGRITY_REQUIRED_CONSTRAINTS
EXPECTED_INTEGRITY_CURRENT_VIEW_SELECT = (
    "SELECT engine_id, correlation_rule_id, correlation_rule_version, "
    "correlation_scope_fingerprint, 'blocked_integrity' AS correlation_status, "
    "arraySort(groupUniqArray(ruleset_fingerprint)) AS ruleset_fingerprints, "
    "uniqExact(integrity_event_id) AS integrity_violation_count, "
    "arraySort(groupUniqArray(violation_type)) AS violation_types, "
    "min(first_detected_at) AS first_detected_at, "
    "max(detected_at) AS last_detected_at "
    "FROM fusion.correlation_integrity_events "
    "GROUP BY engine_id, correlation_rule_id, correlation_rule_version, "
    "correlation_scope_fingerprint"
)

_INTEGRITY_RESULT_LIMIT = 32
_INTEGRITY_QUERY_MAX_SECONDS = 5
_INTEGRITY_QUERY_MAX_MEMORY = 256 * 1024 * 1024
# ClickHouse can expose one insert's source and materialized-view target parts
# serially. Never use elapsed/event time to guess that publication completed:
# bracket the deciding snapshot with monotonic insert counters and explicit
# synchronous/asynchronous source activity checks.
_PROJECTION_PUBLICATION_UNCONFIRMED = "projection_publication_unconfirmed"


class _ProjectionContractViolation(RuntimeError):
    def __init__(
        self,
        violation_type: str,
        message: str,
        *,
        projection_name: str,
        expected_fingerprint: str,
        actual_fingerprint: str = "",
    ) -> None:
        super().__init__(message)
        self.violation_type = violation_type
        self.projection_name = projection_name
        self.expected_fingerprint = expected_fingerprint
        self.actual_fingerprint = actual_fingerprint


class ClickHouseCorrelationStore:
    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        self.settings = settings
        self.client = client or clickhouse_connect.get_client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            username=settings.clickhouse_user,
            password=settings.clickhouse_password,
            database=settings.clickhouse_database,
            connect_timeout=10,
            send_receive_timeout=60,
            # Correlation persists a small ordered protocol (incident, links,
            # state, then ledger) and confirms every effect before advancing.
            # Do not inherit a server/user async_insert default: its busy
            # timeout adds latency to each ordered write and acknowledgement.
            # This is scoped to this client session and does not affect Vector,
            # detection ingestion, validation, or the ClickHouse server.
            settings={
                "async_insert": 0,
                "wait_for_async_insert": 1,
                "use_query_cache": 0,
            },
        )
        # These are per-candidate-page read caches. fetch_candidates resets and
        # primes them, while every semantic-state write invalidates them.
        self._episode_current_cache: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        self._known_absent_episode_tokens: set[str] = set()
        self._episode_page_scope: tuple[str, str, int, str] | None = None
        self._episode_page_range: tuple[datetime, datetime] | None = None
        self._episode_page_group_hashes: frozenset[str] | None = frozenset()
        self._episode_page_rows: list[dict[str, Any]] | None = None

    def healthcheck(self, *, check_projection_integrity: bool = True) -> None:
        self.client.command("SELECT 1")
        async_insert = self.client.command("SELECT getSetting('async_insert')")
        if str(async_insert).strip().lower() not in {"0", "false"}:
            raise RuntimeError(
                "ClickHouse async_insert must be disabled for ordered correlation writes"
            )
        wait = self.client.command("SELECT getSetting('wait_for_async_insert')")
        if str(wait).strip().lower() not in {"1", "true"}:
            raise RuntimeError(
                "ClickHouse wait_for_async_insert must be enabled for correlation write ordering"
            )
        # This append-only table is the authority that makes integrity blocks
        # survive restarts. Validate it even for structural worker/status health;
        # a same-name replaceable or TTL table could otherwise auto-unblock.
        self._validate_integrity_event_contract()
        self._validate_integrity_current_view_contract()
        for relation in (
            "incidents",
            "incident_detection_links",
            "incident_event_links",
            "correlation_evaluated_inputs",
            "correlation_rule_state",
            "correlation_episode_state",
            "correlation_scope_bootstrap_confirmations",
            "correlation_schedule_state",
            "incident_status_transitions",
            "incidents_current",
            "incident_timeline",
        ):
            self.client.query(f"SELECT * FROM fusion.{relation} LIMIT 0")
        if check_projection_integrity:
            try:
                self._validate_history_projection_contract()
                self._validate_witness_projection_contract()
                for target in (
                    HISTORY_TABLE_QUALIFIED_NAME,
                    WITNESS_TABLE_QUALIFIED_NAME,
                ):
                    self.client.query(f"SELECT * FROM {target} LIMIT 0")
            except _ProjectionContractViolation as exc:
                raise RuntimeError(
                    f"{exc.violation_type}: {exc}; "
                    f"projection_name={exc.projection_name} "
                    f"expected_fingerprint={exc.expected_fingerprint} "
                    f"actual_fingerprint={exc.actual_fingerprint or 'unavailable'}"
                ) from exc
            live_projection = self._probe_live_projection_integrity()
            if live_projection["status"] != "healthy":
                violation_types = ",".join(live_projection["violation_types"])
                raise RuntimeError(
                    "blocked_integrity: live observation projection integrity "
                    f"is {live_projection['status']}; "
                    f"violation_types={violation_types or 'unknown'}"
                )
            blocked = self.client.query(
                "SELECT uniqExact(integrity_event_id) "
                "FROM fusion.correlation_integrity_events "
                "WHERE engine_id={engine_id:String}",
                parameters={
                    "engine_id": str(
                        getattr(self.settings, "engine_id", "fusion-correlation-v1")
                    )
                },
            )
            if blocked.result_rows and int(blocked.result_rows[0][0]) > 0:
                raise RuntimeError(
                    "blocked_integrity: current correlation engine has persistent "
                    "integrity violations"
                )

    def check_scope_integrity(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
        *,
        ruleset_fingerprint: str,
        checked_at: datetime,
    ) -> CorrelationIntegrityStatus:
        """Fail closed when durable input history disagrees with evaluated state.

        Integrity events are immutable operator diagnostics.  Once any event is
        persisted for the stable rule scope, a process restart or unrelated
        ruleset change cannot make that scope healthy implicitly.
        """

        del compiled  # every post-floor detection is ledger-eligible per rule scope
        checked_at = _utc(checked_at)
        if not re.fullmatch(r"[0-9a-f]{64}", ruleset_fingerprint):
            raise ValueError("ruleset_fingerprint must be 64 lowercase hex characters")

        # The append-only block authority is itself part of every preflight.
        # If it is replaced or gains a TTL while the worker is running, stop
        # before trusting an empty aggregate or performing any mutation.
        self._validate_integrity_event_contract()
        persisted = self._load_scope_integrity(scope, checked_at)
        if persisted.blocked:
            return persisted

        projection_contracts: dict[str, tuple[str, str]] = {}
        contract_violations: list[_ProjectionContractViolation] = []
        for projection_name, validator in (
            (
                HISTORY_PROJECTION_QUALIFIED_NAME,
                self._validate_history_projection_contract,
            ),
            (
                WITNESS_PROJECTION_QUALIFIED_NAME,
                self._validate_witness_projection_contract,
            ),
        ):
            try:
                projection_contracts[projection_name] = validator()
            except _ProjectionContractViolation as exc:
                contract_violations.append(exc)
        for exc in contract_violations:
            self._persist_integrity_event(
                scope,
                ruleset_fingerprint,
                checked_at,
                violation_type=exc.violation_type,
                projection_name=exc.projection_name,
                expected_projection_fingerprint=exc.expected_fingerprint,
                actual_projection_fingerprint=exc.actual_fingerprint,
                diagnostic={"check": "projection_contract"},
            )
        if contract_violations:
            return self._load_scope_integrity(scope, checked_at)

        publication_unconfirmed = False
        try:
            coverage_gaps = self._find_projection_coverage_gaps(
                scope, _utc(evaluation_floor)
            )
            if coverage_gaps:
                coverage_gaps, publication_unconfirmed = (
                    self._confirm_projection_coverage_gaps(
                        coverage_gaps,
                        lambda: self._find_projection_coverage_gaps(
                            scope, _utc(evaluation_floor)
                        ),
                    )
                )
        except _ProjectionContractViolation as exc:
            self._persist_integrity_event(
                scope,
                ruleset_fingerprint,
                checked_at,
                violation_type=exc.violation_type,
                projection_name=exc.projection_name,
                expected_projection_fingerprint=exc.expected_fingerprint,
                actual_projection_fingerprint=exc.actual_fingerprint,
                diagnostic={"check": "projection_contract"},
            )
            return self._load_scope_integrity(scope, checked_at)
        except Exception as exc:  # noqa: BLE001 - inability to prove coverage blocks
            # A bounded coverage proof that cannot complete is uncertainty, not
            # evidence of completeness. Persist only the exception class, never
            # its potentially sensitive server text.
            for projection_name, fingerprints in projection_contracts.items():
                self._persist_integrity_event(
                    scope,
                    ruleset_fingerprint,
                    checked_at,
                    violation_type="projection_coverage_uncertain",
                    projection_name=projection_name,
                    expected_projection_fingerprint=fingerprints[0],
                    actual_projection_fingerprint=fingerprints[1],
                    diagnostic={
                        "check": "observation_projection_coverage",
                        "failure_kind": type(exc).__name__,
                    },
                )
            return self._load_scope_integrity(scope, checked_at)

        if coverage_gaps and publication_unconfirmed:
            # This is a fail-closed, non-persistent state. The source INSERT is
            # still visible in system.processes, or the two quiescent snapshots
            # did not agree. A later cycle must prove parity or a stable gap;
            # persisting now could turn healthy serial MV publication into a
            # false sticky operator fault.
            return CorrelationIntegrityStatus(
                "blocked_integrity",
                0,
                (_PROJECTION_PUBLICATION_UNCONFIRMED,),
                checked_at,
            )

        for (
            input_id,
            canonical_observed_at,
            missing_projection_name,
            missing_variant_count,
            _missing_variant_fingerprint,
        ) in coverage_gaps:
            expected_projection_fingerprint, actual_projection_fingerprint = (
                projection_contracts[str(missing_projection_name)]
            )
            input_id_text = str(input_id)
            coverage_diagnostic: dict[str, Any] = {
                "check": "observation_projection_coverage",
                "missing_semantic_variant_count": int(missing_variant_count),
            }
            if not input_id_text:
                coverage_diagnostic["input_id_state"] = "empty"
            self._persist_integrity_event(
                scope,
                ruleset_fingerprint,
                checked_at,
                violation_type="projection_coverage_gap",
                input_kind="detection",
                input_id=input_id_text,
                canonical_observed_at=_utc(canonical_observed_at),
                projection_name=str(missing_projection_name),
                expected_projection_fingerprint=expected_projection_fingerprint,
                actual_projection_fingerprint=actual_projection_fingerprint,
                diagnostic=coverage_diagnostic,
            )
        if coverage_gaps:
            return self._load_scope_integrity(scope, checked_at)

        try:
            mismatches = self._find_canonical_observation_mismatches(scope)
        except Exception as exc:  # noqa: BLE001 - inability to prove canonical time blocks
            expected_projection_fingerprint, actual_projection_fingerprint = (
                projection_contracts[HISTORY_PROJECTION_QUALIFIED_NAME]
            )
            self._persist_integrity_event(
                scope,
                ruleset_fingerprint,
                checked_at,
                violation_type="canonical_observation_uncertain",
                projection_name=HISTORY_PROJECTION_QUALIFIED_NAME,
                expected_projection_fingerprint=expected_projection_fingerprint,
                actual_projection_fingerprint=actual_projection_fingerprint,
                diagnostic={
                    "check": "ledger_canonical_observation",
                    "failure_kind": type(exc).__name__,
                },
            )
            return self._load_scope_integrity(scope, checked_at)
        for input_kind, input_id, ledger_observed_at, canonical_observed_at in mismatches:
            expected_projection_fingerprint, actual_projection_fingerprint = (
                projection_contracts[HISTORY_PROJECTION_QUALIFIED_NAME]
            )
            self._persist_integrity_event(
                scope,
                ruleset_fingerprint,
                checked_at,
                violation_type="canonical_observation_mismatch",
                input_kind=str(input_kind),
                input_id=str(input_id),
                ledger_observed_at=_utc(ledger_observed_at),
                canonical_observed_at=_utc(canonical_observed_at),
                projection_name=HISTORY_PROJECTION_QUALIFIED_NAME,
                expected_projection_fingerprint=expected_projection_fingerprint,
                actual_projection_fingerprint=actual_projection_fingerprint,
                diagnostic={"check": "ledger_canonical_observation"},
            )
        if mismatches:
            return self._load_scope_integrity(scope, checked_at)
        return CorrelationIntegrityStatus.healthy(checked_at)

    def _validate_integrity_event_contract(self) -> None:
        result = self.client.query(
            "SELECT engine, engine_full, partition_key, sorting_key, primary_key, "
            "create_table_query FROM system.tables WHERE database='fusion' "
            f"AND name='{INTEGRITY_TABLE_NAME}' LIMIT 2"
        )
        if len(result.result_rows) != 1:
            raise RuntimeError(
                "correlation integrity-event authority is unavailable"
            )
        columns_result = self.client.query(
            "SELECT name, type, default_kind, default_expression "
            "FROM system.columns WHERE database='fusion' "
            f"AND table='{INTEGRITY_TABLE_NAME}' ORDER BY position"
        )
        engine, engine_full, partition_key, sorting_key, primary_key, create_query = (
            result.result_rows[0]
        )
        actual_columns = tuple(
            tuple(str(value) for value in row) for row in columns_result.result_rows
        )
        contract_valid = (
            str(engine) == "MergeTree"
            and _normalize_engine_clause(str(engine_full)) == "mergetree"
            and _normalize_projection_sql(str(partition_key))
            == "toyyyymm(first_detected_at)"
            and _normalize_sort_key(str(sorting_key))
            == _normalize_sort_key(INTEGRITY_SORT_KEY)
            and _normalize_sort_key(str(primary_key))
            == _normalize_sort_key(INTEGRITY_SORT_KEY)
            and _normalized_column_contract(actual_columns)
            == _normalized_column_contract(INTEGRITY_TARGET_COLUMN_CONTRACT)
            and not bool(re.search(r"\bTTL\b", str(create_query), re.IGNORECASE))
            and _integrity_constraint_contract(str(create_query))
            == tuple(sorted(
                _normalize_projection_sql(fragment)
                for fragment in INTEGRITY_REQUIRED_CONSTRAINTS
            ))
        )
        if not contract_valid:
            raise RuntimeError(
                "correlation integrity-event authority contract differs"
            )
        self.client.query(f"SELECT * FROM {INTEGRITY_TABLE_QUALIFIED_NAME} LIMIT 0")

    def _validate_integrity_current_view_contract(self) -> None:
        """Require the convenience view to remain an exact derived projection.

        Runtime correctness and status aggregate the immutable event table
        directly.  Still validate this operator-facing view so a same-column
        ``WHERE 0`` replacement cannot silently hide durable diagnostics from
        an administrator using the documented relation.
        """

        result = self.client.query(
            "SELECT engine, as_select FROM system.tables WHERE database='fusion' "
            f"AND name='{INTEGRITY_CURRENT_VIEW_NAME}' LIMIT 2"
        )
        if len(result.result_rows) != 1:
            raise RuntimeError("correlation integrity-current view is unavailable")
        engine, as_select = result.result_rows[0]
        if (
            str(engine) != "View"
            or _normalize_projection_sql(str(as_select))
            != _normalize_projection_sql(EXPECTED_INTEGRITY_CURRENT_VIEW_SELECT)
        ):
            raise RuntimeError("correlation integrity-current view contract differs")
        self.client.query(
            f"SELECT * FROM {INTEGRITY_CURRENT_VIEW_QUALIFIED_NAME} LIMIT 0"
        )

    def _validate_history_projection_contract(self) -> tuple[str, str]:
        try:
            return self._validate_detection_observation_projection(
                projection_name=HISTORY_PROJECTION_NAME,
                target_name=HISTORY_TABLE_NAME,
                target_columns=HISTORY_TARGET_COLUMN_CONTRACT,
                expected_select=EXPECTED_HISTORY_PROJECTION_SELECT,
                label="correlation detection-history",
            )
        except _ProjectionContractViolation:
            raise
        except Exception as exc:
            raise _ProjectionContractViolation(
                "projection_unavailable",
                "correlation detection-history contract could not be verified",
                projection_name=HISTORY_PROJECTION_QUALIFIED_NAME,
                expected_fingerprint=_history_projection_fingerprint(
                    "MaterializedView",
                    HISTORY_TABLE_QUALIFIED_NAME,
                    EXPECTED_HISTORY_PROJECTION_SELECT,
                ),
            ) from exc

    def _validate_witness_projection_contract(self) -> tuple[str, str]:
        try:
            return self._validate_detection_observation_projection(
                projection_name=WITNESS_PROJECTION_NAME,
                target_name=WITNESS_TABLE_NAME,
                target_columns=WITNESS_TARGET_COLUMN_CONTRACT,
                target_constraints=WITNESS_REQUIRED_CONSTRAINTS,
                expected_select=EXPECTED_WITNESS_PROJECTION_SELECT,
                label="correlation detection-observation witness",
            )
        except _ProjectionContractViolation:
            raise
        except Exception as exc:
            raise _ProjectionContractViolation(
                "projection_unavailable",
                "correlation detection-observation witness contract could not be verified",
                projection_name=WITNESS_PROJECTION_QUALIFIED_NAME,
                expected_fingerprint=_history_projection_fingerprint(
                    "MaterializedView",
                    WITNESS_TABLE_QUALIFIED_NAME,
                    EXPECTED_WITNESS_PROJECTION_SELECT,
                ),
            ) from exc

    def _validate_detection_observation_projection(
        self,
        *,
        projection_name: str,
        target_name: str,
        target_columns: Sequence[Sequence[str]],
        target_constraints: Sequence[str] = (),
        expected_select: str,
        label: str,
    ) -> tuple[str, str]:
        projection_qualified_name = f"fusion.{projection_name}"
        target_qualified_name = f"fusion.{target_name}"
        expected = _history_projection_fingerprint(
            "MaterializedView", target_qualified_name, expected_select
        )
        target_result = self.client.query(
            "SELECT engine, engine_full, partition_key, sorting_key, primary_key, "
            "create_table_query FROM system.tables WHERE database='fusion' "
            f"AND name='{target_name}' LIMIT 2"
        )
        if len(target_result.result_rows) != 1:
            raise _ProjectionContractViolation(
                "projection_unavailable",
                f"{label} target table is unavailable",
                projection_name=projection_qualified_name,
                expected_fingerprint=expected,
            )
        target_columns_result = self.client.query(
            "SELECT name, type, default_kind, default_expression "
            "FROM system.columns WHERE database='fusion' "
            f"AND table='{target_name}' ORDER BY position"
        )
        target_metadata = target_result.result_rows[0]
        actual_columns = tuple(
            tuple(str(value) for value in row)
            for row in target_columns_result.result_rows
        )
        expected_target = _history_target_fingerprint(
            "ReplacingMergeTree",
            "ReplacingMergeTree",
            "toYYYYMM(detected_at)",
            "detection_id, detected_at, semantic_fingerprint",
            "detection_id, detected_at, semantic_fingerprint",
            target_columns,
            constraints=target_constraints,
            has_ttl=False,
        )
        actual_constraints = _integrity_constraint_contract(str(target_metadata[5]))
        actual_target = _history_target_fingerprint(
            *(str(value) for value in target_metadata[:5]),
            actual_columns,
            constraints=actual_constraints,
            has_ttl=bool(
                re.search(r"\bTTL\b", str(target_metadata[5]), re.IGNORECASE)
            ),
        )
        if (
            str(target_metadata[0]) != "ReplacingMergeTree"
            or _normalize_engine_clause(str(target_metadata[1]))
            != "replacingmergetree"
            or _normalize_projection_sql(str(target_metadata[2]))
            != "toyyyymm(detected_at)"
            or _normalize_sort_key(str(target_metadata[3]))
            != "detection_id,detected_at,semantic_fingerprint"
            or _normalize_sort_key(str(target_metadata[4]))
            != "detection_id,detected_at,semantic_fingerprint"
            or _normalized_column_contract(actual_columns)
            != _normalized_column_contract(target_columns)
            or actual_constraints
            != tuple(
                sorted(
                    _normalize_projection_sql(value)
                    for value in target_constraints
                )
            )
            or bool(re.search(r"\bTTL\b", str(target_metadata[5]), re.IGNORECASE))
        ):
            raise _ProjectionContractViolation(
                "projection_contract_mismatch",
                f"{label} target contract differs",
                projection_name=projection_qualified_name,
                expected_fingerprint=expected_target,
                actual_fingerprint=actual_target,
            )
        result = self.client.query(
            "SELECT engine, target_database, target_table, as_select "
            "FROM system.tables "
            "WHERE database='fusion' "
            f"AND name='{projection_name}' LIMIT 2"
        )
        if len(result.result_rows) != 1:
            raise _ProjectionContractViolation(
                "projection_unavailable",
                f"{label} materialized view is not attached",
                projection_name=projection_qualified_name,
                expected_fingerprint=expected,
            )
        engine, target_database, target_table, as_select = result.result_rows[0]
        target = f"{target_database}.{target_table}"
        actual = _history_projection_fingerprint(str(engine), target, str(as_select))
        if (
            str(engine) != "MaterializedView"
            or target != target_qualified_name
            or _normalize_projection_sql(str(as_select))
            != _normalize_projection_sql(expected_select)
        ):
            raise _ProjectionContractViolation(
                "projection_contract_mismatch",
                f"{label} materialized view contract differs",
                projection_name=projection_qualified_name,
                expected_fingerprint=expected,
                actual_fingerprint=actual,
            )
        return expected, actual

    def _confirm_projection_coverage_gaps(
        self,
        first_snapshot: Sequence[Sequence[Any]],
        read_snapshot: Any,
    ) -> tuple[list[tuple[Any, ...]], bool]:
        """Return a completed stable gap, or a fail-closed transient result.

        Incremental materialized-view targets are acknowledged synchronously,
        but their parts are visible serially while the INSERT remains active.
        A gap is durable evidence only when two exact snapshots agree, the
        active source/target part generation is unchanged, and no synchronous,
        asynchronous, or queued source INSERT is present. This avoids both a
        fixed timing assumption and a cross-table visibility race.
        """

        first = [tuple(row) for row in first_snapshot]
        generation_before = self._projection_storage_generation()
        if self._detections_insert_in_progress():
            return first, True
        second = [tuple(row) for row in read_snapshot()]
        if self._detections_insert_in_progress():
            return second or first, True
        generation_after = self._projection_storage_generation()
        if generation_before != generation_after:
            return second or first, True
        # Close the bounded same-name DDL/replacement window before deciding
        # that parity or a durable gap is authoritative. A later privileged
        # DDL race remains outside the supported trusted-writer boundary.
        self._validate_history_projection_contract()
        self._validate_witness_projection_contract()
        if not second:
            return [], False
        if first != second:
            return second, True
        return second, False

    def _projection_storage_generation(self) -> tuple[int, str]:
        """Fingerprint active source/history/witness parts for a stable proof."""

        result = self.client.query(
            "/* detection_projection_storage_generation_query */ "
            "SELECT count(), lower(hex(SHA256(arrayStringConcat(arraySort("
            "groupArray(toString(tuple(table, uuid, name, rows, data_version, "
            "hash_of_all_files)))), '\\0')))) FROM system.parts "
            "WHERE active AND database='fusion' AND table IN "
            "('detections', {history_table:String}, {witness_table:String}) "
            "SETTINGS use_query_cache=0, "
            "max_execution_time={max_seconds:UInt32}, "
            "max_memory_usage={max_memory:UInt64}",
            parameters={
                "history_table": HISTORY_TABLE_NAME,
                "witness_table": WITNESS_TABLE_NAME,
                "max_seconds": _INTEGRITY_QUERY_MAX_SECONDS,
                "max_memory": _INTEGRITY_QUERY_MAX_MEMORY,
            },
        )
        if len(result.result_rows) != 1 or len(result.result_rows[0]) != 2:
            raise CorrelationPersistenceConflict(
                "detection projection storage generation is unavailable"
            )
        count, fingerprint = result.result_rows[0]
        if not re.fullmatch(r"[0-9a-f]{64}", str(fingerprint)):
            raise CorrelationPersistenceConflict(
                "detection projection storage generation is invalid"
            )
        return int(count), str(fingerprint)

    def _detections_insert_in_progress(self) -> bool:
        result = self.client.query(
            "/* detection_source_insert_activity_query */ "
            "SELECT count() FROM ("
            "SELECT query, current_database AS database, '' AS table "
            "FROM system.processes WHERE "
            "query_kind IN ('Insert', 'AsyncInsertFlush') "
            "AND query_id != currentQueryID() UNION ALL "
            "SELECT query, database, table FROM system.asynchronous_inserts"
            ") WHERE (database='fusion' AND table='detections') OR "
            "match(query, '(?is)insert\\s+into\\s+(?:`fusion`|\"fusion\"|fusion)"
            "\\s*\\.\\s*(?:`detections`|\"detections\"|detections)(?:\\s|\\()') "
            "OR (database='fusion' AND "
            "match(query, '(?is)insert\\s+into\\s+"
            "(?:`detections`|\"detections\"|detections)(?:\\s|\\()')) "
            "SETTINGS use_query_cache=0, "
            "max_execution_time={max_seconds:UInt32}, "
            "max_memory_usage={max_memory:UInt64}",
            parameters={
                "max_seconds": _INTEGRITY_QUERY_MAX_SECONDS,
                "max_memory": _INTEGRITY_QUERY_MAX_MEMORY,
            },
        )
        if len(result.result_rows) != 1:
            raise CorrelationPersistenceConflict(
                "detection source insert activity is unavailable"
            )
        return int(result.result_rows[0][0]) > 0

    def _find_projection_coverage_gaps(
        self,
        scope: RuleScope,
        evaluation_floor: datetime,
    ) -> list[tuple[Any, Any, Any, Any, Any]]:
        semantic_fields = ", ".join(
            ("source_event_time", *DETECTION_VALUE_FIELDS)
        )
        result = self.client.query(
            "/* projection_coverage_query */ "
            "WITH candidate_ids AS ("
            "SELECT DISTINCT detection_id FROM fusion.detections "
            "WHERE detected_at >= {evaluation_floor:DateTime64(3)} "
            "UNION DISTINCT SELECT detection_id "
            f"FROM {HISTORY_TABLE_QUALIFIED_NAME} "
            "WHERE detected_at >= {evaluation_floor:DateTime64(3)} "
            "UNION DISTINCT SELECT detection_id "
            f"FROM {WITNESS_TABLE_QUALIFIED_NAME} "
            "WHERE detected_at >= {evaluation_floor:DateTime64(3)} "
            "UNION DISTINCT SELECT input_id AS detection_id "
            "FROM fusion.correlation_evaluated_inputs_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND input_kind='detection'), physical_rows AS ("
            "SELECT detection_id, detected_at, "
            f"lower(hex(SHA256(toString(tuple({semantic_fields}))))) "
            "AS semantic_fingerprint, 1 AS in_source, 0 AS in_history, "
            "0 AS in_witness FROM fusion.detections "
            "WHERE detection_id IN candidate_ids UNION ALL "
            "SELECT detection_id, detected_at, semantic_fingerprint, "
            f"0, 1, 0 FROM {HISTORY_TABLE_QUALIFIED_NAME} "
            "WHERE detection_id IN candidate_ids UNION ALL "
            "SELECT detection_id, detected_at, semantic_fingerprint, "
            f"0, 0, 1 FROM {WITNESS_TABLE_QUALIFIED_NAME} "
            "WHERE detection_id IN candidate_ids), "
            "variant_presence AS ("
            "SELECT detection_id, detected_at, semantic_fingerprint, "
            "max(in_source) AS in_source, max(in_history) AS in_history, "
            "max(in_witness) AS in_witness FROM physical_rows "
            "GROUP BY detection_id, detected_at, semantic_fingerprint), "
            "classified AS ("
            "SELECT *, min(detected_at) OVER (PARTITION BY detection_id) "
            "AS canonical_observed_at, "
            "max(detected_at >= {evaluation_floor:DateTime64(3)}) "
            "OVER (PARTITION BY detection_id) AS has_post_floor_observation "
            "FROM variant_presence), ledger_ids AS ("
            "SELECT DISTINCT input_id AS ledger_input_id "
            "FROM fusion.correlation_evaluated_inputs_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND input_kind='detection'), missing_rows AS ("
            "SELECT detection_id, detected_at, semantic_fingerprint, "
            "canonical_observed_at, arrayJoin(arrayConcat("
            f"if(in_history=0, ['{HISTORY_PROJECTION_QUALIFIED_NAME}'], "
            "emptyArrayString()), "
            f"if(in_witness=0, ['{WITNESS_PROJECTION_QUALIFIED_NAME}'], "
            "emptyArrayString()))) AS missing_projection_name "
            "FROM classified LEFT JOIN ("
            "SELECT ledger_input_id, 1 AS ledger_row_present FROM ledger_ids"
            ") AS ledger_presence "
            "ON ledger_presence.ledger_input_id=classified.detection_id "
            "WHERE (has_post_floor_observation=1 OR "
            "ledger_presence.ledger_row_present=1)) "
            "SELECT detection_id, canonical_observed_at, "
            "missing_projection_name, "
            "uniqExact(tuple(detected_at, semantic_fingerprint)) "
            "AS missing_semantic_variant_count, "
            "lower(hex(SHA256(arrayStringConcat(arraySort(groupArray("
            "toString(tuple(detected_at, semantic_fingerprint)))), '\\0')))) "
            "AS missing_semantic_variant_fingerprint FROM missing_rows "
            "GROUP BY detection_id, canonical_observed_at, "
            "missing_projection_name "
            "ORDER BY canonical_observed_at, detection_id, "
            "missing_projection_name "
            "LIMIT {limit:UInt32} SETTINGS "
            "use_query_cache=0, max_execution_time={max_seconds:UInt32}, "
            "max_memory_usage={max_memory:UInt64}, "
            "max_result_rows={limit:UInt32}, result_overflow_mode='throw'",
            parameters={
                **_scope_parameters(scope),
                "evaluation_floor": evaluation_floor,
                "limit": _INTEGRITY_RESULT_LIMIT,
                "max_seconds": _INTEGRITY_QUERY_MAX_SECONDS,
                "max_memory": _INTEGRITY_QUERY_MAX_MEMORY,
            },
        )
        return list(result.result_rows)

    def _probe_live_projection_integrity(self) -> Mapping[str, Any]:
        """Return a non-mutating global projection-integrity status.

        The CLI status path must remain readable before a worker has persisted
        a per-scope violation. It therefore performs its own exact contract and
        bounded parity proof, but never writes integrity state or exposes raw
        ClickHouse exception text.
        """

        faults: list[_ProjectionContractViolation] = []
        for validator in (
            self._validate_history_projection_contract,
            self._validate_witness_projection_contract,
        ):
            try:
                validator()
            except _ProjectionContractViolation as exc:
                faults.append(exc)
        if faults:
            return {
                "status": "blocked_integrity",
                "violation_types": sorted(
                    {str(fault.violation_type) for fault in faults}
                ),
                "projection_names": sorted(
                    {str(fault.projection_name) for fault in faults}
                ),
                "gap_count": None,
                "failure_kind": "",
            }
        try:
            gaps = self._find_global_projection_coverage_gaps()
            if gaps:
                gaps, publication_unconfirmed = (
                    self._confirm_projection_coverage_gaps(
                        gaps, self._find_global_projection_coverage_gaps
                    )
                )
                if publication_unconfirmed:
                    return {
                        "status": "unconfirmed",
                        "violation_types": [
                            _PROJECTION_PUBLICATION_UNCONFIRMED
                        ],
                        "projection_names": sorted(str(row[0]) for row in gaps),
                        "gap_count": sum(int(row[1]) for row in gaps),
                        "failure_kind": "",
                    }
        except _ProjectionContractViolation as exc:
            return {
                "status": "blocked_integrity",
                "violation_types": [str(exc.violation_type)],
                "projection_names": [str(exc.projection_name)],
                "gap_count": None,
                "failure_kind": "",
            }
        except Exception as exc:  # noqa: BLE001 - uncertainty must remain visible
            return {
                "status": "unconfirmed",
                "violation_types": ["projection_coverage_uncertain"],
                "projection_names": sorted(
                    (
                        HISTORY_PROJECTION_QUALIFIED_NAME,
                        WITNESS_PROJECTION_QUALIFIED_NAME,
                    )
                ),
                "gap_count": None,
                "failure_kind": type(exc).__name__,
            }
        if gaps:
            return {
                "status": "blocked_integrity",
                "violation_types": ["projection_coverage_gap"],
                "projection_names": sorted(str(row[0]) for row in gaps),
                "gap_count": sum(int(row[1]) for row in gaps),
                "failure_kind": "",
            }
        return {
            "status": "healthy",
            "violation_types": [],
            "projection_names": [],
            "gap_count": 0,
            "failure_kind": "",
        }

    def _find_global_projection_coverage_gaps(
        self,
    ) -> list[tuple[Any, Any, Any]]:
        semantic_fields = ", ".join(("source_event_time", *DETECTION_VALUE_FIELDS))
        result = self.client.query(
            "/* global_projection_coverage_query */ "
            "WITH physical_rows AS ("
            "SELECT detection_id, detected_at, "
            f"lower(hex(SHA256(toString(tuple({semantic_fields}))))) "
            "AS semantic_fingerprint, 0 AS in_history, 0 AS in_witness "
            "FROM fusion.detections UNION ALL "
            "SELECT detection_id, detected_at, semantic_fingerprint, 1, 0 "
            f"FROM {HISTORY_TABLE_QUALIFIED_NAME} UNION ALL "
            "SELECT detection_id, detected_at, semantic_fingerprint, 0, 1 "
            f"FROM {WITNESS_TABLE_QUALIFIED_NAME}), variant_presence AS ("
            "SELECT detection_id, detected_at, semantic_fingerprint, "
            "max(in_history) AS in_history, max(in_witness) AS in_witness "
            "FROM physical_rows GROUP BY detection_id, detected_at, "
            "semantic_fingerprint), missing_rows AS ("
            "SELECT detection_id, detected_at, semantic_fingerprint, "
            "arrayJoin(arrayConcat("
            f"if(in_history=0, ['{HISTORY_PROJECTION_QUALIFIED_NAME}'], "
            "emptyArrayString()), "
            f"if(in_witness=0, ['{WITNESS_PROJECTION_QUALIFIED_NAME}'], "
            "emptyArrayString()))) AS missing_projection_name "
            "FROM variant_presence) SELECT missing_projection_name, "
            "uniqExact(tuple(detection_id, detected_at, semantic_fingerprint)) "
            "AS missing_semantic_variant_count, "
            "lower(hex(SHA256(arrayStringConcat(arraySort(groupArray("
            "toString(tuple(detection_id, detected_at, semantic_fingerprint)))), "
            "'\\0')))) AS missing_semantic_variant_fingerprint FROM missing_rows "
            "GROUP BY missing_projection_name ORDER BY missing_projection_name "
            "LIMIT 2 SETTINGS use_query_cache=0, "
            "max_execution_time={max_seconds:UInt32}, "
            "max_memory_usage={max_memory:UInt64}, max_result_rows=2, "
            "result_overflow_mode='throw'",
            parameters={
                "max_seconds": _INTEGRITY_QUERY_MAX_SECONDS,
                "max_memory": _INTEGRITY_QUERY_MAX_MEMORY,
            },
        )
        return list(result.result_rows)

    def _find_canonical_observation_mismatches(
        self, scope: RuleScope
    ) -> list[tuple[Any, Any, Any, Any]]:
        result = self.client.query(
            "/* canonical_observation_mismatch_query */ "
            "SELECT input_kind, input_id, ledger_observed_at, "
            "canonical_observed_at FROM ("
            "SELECT 'detection' AS input_kind, evaluated.input_id AS input_id, "
            "evaluated.observed_at AS ledger_observed_at, "
            "min(history.detected_at) AS canonical_observed_at "
            "FROM fusion.correlation_evaluated_inputs_current AS evaluated "
            f"INNER JOIN {HISTORY_TABLE_QUALIFIED_NAME} AS history "
            "ON history.detection_id=evaluated.input_id "
            "WHERE evaluated.engine_id={engine_id:String} "
            "AND evaluated.correlation_rule_id={rule_id:String} "
            "AND evaluated.correlation_rule_version={rule_version:UInt32} "
            "AND evaluated.correlation_scope_fingerprint={fingerprint:String} "
            "AND evaluated.input_kind='detection' "
            "GROUP BY evaluated.input_id, evaluated.observed_at "
            "HAVING ledger_observed_at != canonical_observed_at "
            "UNION ALL "
            "SELECT 'event' AS input_kind, evaluated.input_id AS input_id, "
            "evaluated.observed_at AS ledger_observed_at, "
            "canonical_event.canonical_observed_at AS canonical_observed_at "
            "FROM fusion.correlation_evaluated_inputs_current AS evaluated "
            "INNER JOIN (SELECT event_uid, "
            "min(ingested_at) AS canonical_observed_at "
            "FROM fusion.sysmon_events PREWHERE event_uid IN ("
            "SELECT input_id FROM fusion.correlation_evaluated_inputs_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND input_kind='event') GROUP BY event_uid) AS canonical_event "
            "ON canonical_event.event_uid=evaluated.input_id "
            "WHERE evaluated.engine_id={engine_id:String} "
            "AND evaluated.correlation_rule_id={rule_id:String} "
            "AND evaluated.correlation_rule_version={rule_version:UInt32} "
            "AND evaluated.correlation_scope_fingerprint={fingerprint:String} "
            "AND evaluated.input_kind='event' "
            "AND evaluated.observed_at != canonical_event.canonical_observed_at) "
            "ORDER BY input_kind, input_id LIMIT {limit:UInt32} SETTINGS "
            "use_query_cache=0, max_execution_time={max_seconds:UInt32}, "
            "max_memory_usage={max_memory:UInt64}, "
            "max_result_rows={limit:UInt32}, result_overflow_mode='throw'",
            parameters={
                **_scope_parameters(scope),
                "limit": _INTEGRITY_RESULT_LIMIT,
                "max_seconds": _INTEGRITY_QUERY_MAX_SECONDS,
                "max_memory": _INTEGRITY_QUERY_MAX_MEMORY,
            },
        )
        return list(result.result_rows)

    def _load_scope_integrity(
        self, scope: RuleScope, checked_at: datetime
    ) -> CorrelationIntegrityStatus:
        result = self.client.query(
            "SELECT uniqExact(integrity_event_id) AS integrity_violation_count, "
            "arraySort(groupUniqArray(violation_type)) AS violation_types, "
            "maxOrNull(detected_at) AS last_detected_at "
            "FROM fusion.correlation_integrity_events "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String}",
            parameters=_scope_parameters(scope),
        )
        if len(result.result_rows) != 1:
            raise CorrelationPersistenceConflict(
                "stable correlation scope integrity aggregate is unavailable"
            )
        count, violation_types, last_detected_at = result.result_rows[0]
        if int(count) == 0:
            return CorrelationIntegrityStatus.healthy(checked_at)
        if last_detected_at is None:
            raise CorrelationPersistenceConflict("integrity event timestamp is missing")
        return CorrelationIntegrityStatus(
            "blocked_integrity",
            int(count),
            tuple(sorted(str(value) for value in violation_types)),
            _utc(last_detected_at),
        )

    def _persist_integrity_event(
        self,
        scope: RuleScope,
        ruleset_fingerprint: str,
        detected_at: datetime,
        *,
        violation_type: str,
        input_kind: str = "",
        input_id: str = "",
        ledger_observed_at: datetime | None = None,
        canonical_observed_at: datetime | None = None,
        projection_name: str = "",
        expected_projection_fingerprint: str = "",
        actual_projection_fingerprint: str = "",
        diagnostic: Mapping[str, Any] | None = None,
    ) -> None:
        identity = canonical_json(
            {
                "schema": "fusion-correlation-integrity-identity/v1",
                "engine_id": scope.engine_id,
                "correlation_rule_id": scope.rule_id,
                "correlation_rule_version": scope.rule_version,
                "correlation_scope_fingerprint": scope.fingerprint,
                "violation_type": violation_type,
                "input_kind": input_kind,
                "input_id": input_id,
                "ledger_observed_at": (
                    _utc(ledger_observed_at).isoformat()
                    if ledger_observed_at is not None
                    else None
                ),
                "canonical_observed_at": (
                    _utc(canonical_observed_at).isoformat()
                    if canonical_observed_at is not None
                    else None
                ),
                "projection_name": projection_name,
                "expected_projection_fingerprint": expected_projection_fingerprint,
                "actual_projection_fingerprint": actual_projection_fingerprint,
            }
        )
        event_id = sha256(identity.encode("utf-8")).hexdigest()
        existing = self.client.query(
            "SELECT count() FROM fusion.correlation_integrity_events "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND integrity_event_id={event_id:String}",
            parameters={**_scope_parameters(scope), "event_id": event_id},
        )
        if int(existing.result_rows[0][0]) == 0:
            diagnostic_json = json.dumps(
                dict(diagnostic or {}), sort_keys=True, separators=(",", ":")
            )
            if len(diagnostic_json.encode("utf-8")) > 8192:
                raise ValueError("integrity diagnostic exceeds 8192 bytes")
            row = [
                event_id,
                detected_at,
                detected_at,
                scope.engine_id,
                ruleset_fingerprint,
                scope.rule_id,
                scope.rule_version,
                scope.fingerprint,
                violation_type,
                input_kind,
                input_id,
                ledger_observed_at,
                canonical_observed_at,
                projection_name,
                expected_projection_fingerprint,
                actual_projection_fingerprint,
                diagnostic_json,
            ]
            self.client.insert(
                "fusion.correlation_integrity_events",
                [row],
                column_names=list(INTEGRITY_EVENT_COLUMNS),
            )
        confirmed = self.client.query(
            "SELECT count() FROM fusion.correlation_integrity_events "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND integrity_event_id={event_id:String}",
            parameters={**_scope_parameters(scope), "event_id": event_id},
        )
        if int(confirmed.result_rows[0][0]) < 1:
            raise RuntimeError("integrity diagnostic read-back confirmation failed")

    def ensure_scope(
        self, scope: RuleScope, compiled: CompiledRule, evaluation_floor: datetime
    ) -> datetime:
        parameters = _scope_parameters(scope)
        result = self.client.query(
            "SELECT evaluation_floor_observed_at "
            "FROM fusion.correlation_rule_state_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} LIMIT 1",
            parameters=parameters,
        )
        token = scope_bootstrap_token(scope)
        raw = self.client.query(
            "SELECT evaluation_floor_observed_at, compiler_version, "
            "normalization_contract_version, revision_token, state_hash, "
            "activated_at, revision "
            "FROM fusion.correlation_rule_state "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND revision_token={token:String} "
            "ORDER BY revision DESC, updated_at DESC LIMIT 101",
            parameters={**parameters, "token": token},
        )
        now = _utc(datetime.now(timezone.utc))
        if raw.result_rows:
            if len(raw.result_rows) > 100:
                raise CorrelationPersistenceConflict(
                    "scope bootstrap token has an excessive number of physical rows"
                )
            canonical = tuple(
                _normalized_content_value(value) for value in raw.result_rows[0]
            )
            if any(
                tuple(_normalized_content_value(value) for value in row) != canonical
                for row in raw.result_rows[1:]
            ):
                raise CorrelationPersistenceConflict(
                    "scope bootstrap token has conflicting immutable content"
                )
            (
                floor,
                compiler_version,
                normalization_version,
                persisted_token,
                expected_hash,
                activated_at,
                revision,
            ) = canonical
            floor = _utc(floor)
            if (
                str(compiler_version) != __version__
                or str(normalization_version) != IDENTITY_NORMALIZATION_VERSION
                or str(persisted_token) != token
                or int(revision) != 1
            ):
                raise CorrelationPersistenceConflict(
                    "scope bootstrap immutable contract does not match this engine"
                )
            expected_content = {
                "scope": scope.key,
                "evaluation_floor_observed_at": floor,
                "compiler_version": str(compiler_version),
                "normalization_contract_version": str(normalization_version),
                "activated_at": _utc(activated_at),
            }
            if str(expected_hash) != state_hash(expected_content):
                raise CorrelationPersistenceConflict(
                    "scope bootstrap state hash does not match immutable content"
                )
        else:
            floor = _utc(evaluation_floor)
            revision = 1
            content = {
                "scope": scope.key,
                "evaluation_floor_observed_at": floor,
                "compiler_version": __version__,
                "normalization_contract_version": IDENTITY_NORMALIZATION_VERSION,
                "activated_at": now,
            }
            expected_hash = state_hash(content)
            self.client.insert(
                "fusion.correlation_rule_state",
                [
                    [
                        scope.engine_id,
                        scope.rule_id,
                        scope.rule_version,
                        scope.fingerprint,
                        floor,
                        __version__,
                        IDENTITY_NORMALIZATION_VERSION,
                        token,
                        expected_hash,
                        now,
                        now,
                        revision,
                    ]
                ],
                column_names=[
                    "engine_id",
                    "correlation_rule_id",
                    "correlation_rule_version",
                    "correlation_scope_fingerprint",
                    "evaluation_floor_observed_at",
                    "compiler_version",
                    "normalization_contract_version",
                    "revision_token",
                    "state_hash",
                    "activated_at",
                    "updated_at",
                    "revision",
                ],
            )
        if result.result_rows:
            current_floor = _utc(result.result_rows[0][0])
            if current_floor != floor:
                raise CorrelationPersistenceConflict(
                    "confirmed scope bootstrap floor conflicts with raw state"
                )
            return current_floor
        verify = self.client.query(
            "SELECT count() FROM fusion.correlation_rule_state "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND revision_token={token:String} AND state_hash={state_hash:String} "
            "AND revision={revision:UInt64}",
            parameters={
                **parameters,
                "token": token,
                "state_hash": str(expected_hash),
                "revision": int(revision),
            },
        )
        if int(verify.result_rows[0][0]) < 1:
            raise RuntimeError("scope bootstrap state read-back confirmation failed")
        confirmation_exists = self.client.query(
            "SELECT count() FROM fusion.correlation_scope_bootstrap_confirmations_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND scope_bootstrap_token={token:String} "
            "AND expected_rule_state_hash={state_hash:String} "
            "AND expected_rule_state_revision={revision:UInt64}",
            parameters={
                **parameters,
                "token": token,
                "state_hash": str(expected_hash),
                "revision": int(revision),
            },
        )
        if int(confirmation_exists.result_rows[0][0]) == 0:
            self.client.insert(
                "fusion.correlation_scope_bootstrap_confirmations",
                [
                    [
                        scope.engine_id,
                        scope.rule_id,
                        scope.rule_version,
                        scope.fingerprint,
                        token,
                        expected_hash,
                        revision,
                        now,
                    ]
                ],
                column_names=[
                    "engine_id",
                    "correlation_rule_id",
                    "correlation_rule_version",
                    "correlation_scope_fingerprint",
                    "scope_bootstrap_token",
                    "expected_rule_state_hash",
                    "expected_rule_state_revision",
                    "confirmed_at",
                ],
            )
            confirmation_exists = self.client.query(
                "SELECT count() FROM fusion.correlation_scope_bootstrap_confirmations_current "
                "WHERE engine_id={engine_id:String} "
                "AND correlation_rule_id={rule_id:String} "
                "AND correlation_rule_version={rule_version:UInt32} "
                "AND correlation_scope_fingerprint={fingerprint:String} "
                "AND scope_bootstrap_token={token:String}",
                parameters={**parameters, "token": token},
            )
        if int(confirmation_exists.result_rows[0][0]) != 1:
            raise RuntimeError("scope bootstrap confirmation was not durable")
        return floor

    def load_schedule_cursor(self, scope: RuleScope) -> CandidateCursor | None:
        schedule_result = self.client.query(
            "SELECT candidate_cursor_occurred_at, candidate_cursor_observed_at, "
            "candidate_cursor_input_kind, candidate_cursor_input_id "
            "FROM fusion.correlation_schedule_state_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} LIMIT 1",
            parameters=_scope_parameters(scope),
        )
        schedule_cursor: CandidateCursor | None = None
        if (
            schedule_result.result_rows
            and schedule_result.result_rows[0][0] is not None
        ):
            occurred, observed, kind, input_id = schedule_result.result_rows[0]
            schedule_cursor = CandidateCursor(
                _utc(occurred), _utc(observed), str(kind), str(input_id)
            )

        # Scheduling state is deliberately written after the exact ledger.  A
        # crash at that boundary may therefore leave the diagnostic cursor
        # absent or behind.  Reconcile it from the latest completed ledger key;
        # candidate eligibility remains the exact ledger join's responsibility.
        ledger_result = self.client.query(
            "SELECT occurred_at, observed_at, input_kind, input_id "
            "FROM fusion.correlation_evaluated_inputs_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "ORDER BY occurred_at DESC, input_kind DESC, input_id DESC LIMIT 1",
            parameters=_scope_parameters(scope),
        )
        ledger_cursor: CandidateCursor | None = None
        if ledger_result.result_rows:
            occurred, observed, kind, input_id = ledger_result.result_rows[0]
            ledger_cursor = CandidateCursor(
                _utc(occurred), _utc(observed), str(kind), str(input_id)
            )
        if schedule_cursor is None:
            return ledger_cursor
        if ledger_cursor is None:
            return schedule_cursor
        return max(
            (schedule_cursor, ledger_cursor),
            key=lambda value: (value.occurred_at, value.input_kind, value.input_id),
        )

    def fetch_candidates(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
        cursor: CandidateCursor | None,
        limit: int,
    ) -> list[InputEnvelope]:
        source_sql, selector_parameters = _source_union_sql(compiled)
        parameters = {
            **_scope_parameters(scope),
            **selector_parameters,
            "evaluation_floor": evaluation_floor,
            "cursor_present": int(cursor is not None),
            "cursor_occurred": cursor.occurred_at if cursor else evaluation_floor,
            "cursor_kind": cursor.input_kind if cursor else "",
            "cursor_id": cursor.input_id if cursor else "",
            "limit": limit,
        }
        query_suffix = (
            "LEFT JOIN fusion.correlation_evaluated_inputs_current AS evaluated "
            "ON evaluated.engine_id={engine_id:String} "
            "AND evaluated.correlation_rule_id={rule_id:String} "
            "AND evaluated.correlation_rule_version={rule_version:UInt32} "
            "AND evaluated.correlation_scope_fingerprint={fingerprint:String} "
            "AND evaluated.input_kind=source.input_kind "
            "AND evaluated.input_id=source.input_id "
            + _unevaluated_or_new_conflict_sql()
            + "ORDER BY if({cursor_present:UInt8}=1 AND "
            "tuple(source.occurred_at, source.input_kind, source.input_id) <= "
            "tuple({cursor_occurred:DateTime64(3)}, {cursor_kind:String}, {cursor_id:String}), 1, 0), "
            "source.occurred_at, source.input_kind, source.input_id "
            "LIMIT {limit:UInt32}"
        )
        if not _requires_python_event_filter(compiled):
            result = self.client.query(
                "SELECT source.* FROM (" + source_sql + ") AS source " + query_suffix,
                parameters=parameters,
            )
            return self._prepare_candidate_page(
                scope,
                compiled,
                self._decode_input_rows(result, compiled, include_invalid_events=True),
            )

        # Canonical host/principal/IP/platform equality deliberately remains a
        # Python contract. Query detection and broad event candidates
        # separately so broad event false positives cannot consume the shared
        # SQL LIMIT and hide later eligible inputs.
        detection_sql, event_sql, event_parameters = _source_sql_parts(compiled)
        assert event_sql is not None
        detection_result = self.client.query(
            "SELECT source.* FROM (" + detection_sql + ") AS source " + query_suffix,
            parameters=parameters,
        )
        scan_cap = int(self.settings.context_limit)
        event_result = self.client.query(
            "SELECT source.* FROM (" + event_sql + ") AS source " + query_suffix,
            parameters={
                **parameters,
                **event_parameters,
                "limit": scan_cap + 1,
            },
        )
        if len(event_result.result_rows) > scan_cap:
            raise OverflowError(
                "canonical event enrollment prefilter exceeds bounded scan limit "
                f"{scan_cap}"
            )
        candidates = [
            *self._decode_input_rows(
                detection_result, compiled, include_invalid_events=True
            ),
            *self._decode_input_rows(
                event_result, compiled, include_invalid_events=True
            ),
        ]
        cursor_key = (
            (cursor.occurred_at, cursor.input_kind, cursor.input_id)
            if cursor is not None
            else None
        )

        def candidate_order(item: InputEnvelope) -> tuple[Any, ...]:
            key = (item.occurred_at, item.input_kind, item.input_id)
            return (int(cursor_key is not None and key <= cursor_key), *key)

        return self._prepare_candidate_page(
            scope,
            compiled,
            sorted(candidates, key=candidate_order)[:limit],
        )

    def _prepare_candidate_page(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        candidates: Sequence[InputEnvelope],
    ) -> list[InputEnvelope]:
        """Prime bounded replay metadata once for one evaluated source page."""

        page = list(candidates)
        self._episode_current_cache.clear()
        self._known_absent_episode_tokens.clear()
        self._episode_page_scope = None
        self._episode_page_range = None
        self._episode_page_group_hashes = frozenset()
        self._episode_page_rows = None
        if not page:
            return page
        tokens = sorted({evaluation_token(scope, candidate) for candidate in page})
        result = self.client.query(
            "SELECT revision_token FROM fusion.correlation_episode_state "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND revision_token IN {tokens:Array(String)} "
            "GROUP BY revision_token LIMIT {limit:UInt32}",
            parameters={
                **_scope_parameters(scope),
                "tokens": tokens,
                "limit": len(tokens) + 1,
            },
        )
        if len(result.result_rows) > len(tokens):
            raise OverflowError("episode replay-token prefetch exceeded page bound")
        present = {str(row[0]) for row in result.result_rows}
        if not present.issubset(tokens):
            raise CorrelationPersistenceConflict(
                "episode replay-token prefetch returned an unexpected identity"
            )
        self._known_absent_episode_tokens.update(set(tokens) - present)
        self._prime_episode_page(scope, compiled, page)
        return page

    def _prime_episode_page(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        candidates: Sequence[InputEnvelope],
    ) -> None:
        """Load one bounded current-state snapshot for a candidate page.

        If the union of relevant groups is too large for the configured bound,
        the snapshot is discarded and load_episode_states transparently uses
        its original exact per-candidate query. No partial snapshot is used.
        """

        span = _milliseconds(compiled.rule.window.milliseconds)
        range_start = min(item.occurred_at for item in candidates) - span
        range_end = max(item.occurred_at for item in candidates) + span
        group_hashes: frozenset[str] | None
        if "shared_ip" in compiled.rule.group_by:
            group_hashes = None
        else:
            hashes: set[str] = set()
            for candidate in candidates:
                try:
                    group = json.loads(
                        canonical_group_json(compiled.rule.group_by, candidate.values)
                    )
                    hashes.add(group_identity(group)[1])
                except (
                    IdentityNormalizationError,
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                ):
                    continue
            group_hashes = frozenset(hashes)
            if not group_hashes:
                self._episode_page_scope = scope.key
                self._episode_page_range = (range_start, range_end)
                self._episode_page_group_hashes = group_hashes
                self._episode_page_rows = []
                return

        parameters: dict[str, Any] = {
            **_scope_parameters(scope),
            "range_start": range_start,
            "range_end": range_end,
            "limit": int(self.settings.context_limit) + 1,
        }
        group_filter = ""
        if group_hashes is not None:
            group_filter = " AND group_key_hash IN {group_hashes:Array(String)}"
            parameters["group_hashes"] = sorted(group_hashes)
        result = self.client.query(
            f"SELECT {', '.join(EPISODE_COLUMNS)} "
            "FROM fusion.correlation_episode_state_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND episode_window_start <= {range_end:DateTime64(3)} "
            "AND episode_window_end >= {range_start:DateTime64(3)}"
            + group_filter
            + " ORDER BY episode_window_start, episode_state_id "
            "LIMIT {limit:UInt32}",
            parameters=parameters,
        )
        rows = list(_named_rows(result))
        if len(rows) > int(self.settings.context_limit):
            # Preserve correctness under a large state union: individual
            # bounded queries remain authoritative for this page.
            return
        self._episode_page_scope = scope.key
        self._episode_page_range = (range_start, range_end)
        self._episode_page_group_hashes = group_hashes
        self._episode_page_rows = rows

    def fetch_context(
        self,
        compiled: CompiledRule,
        candidate: InputEnvelope,
        evaluation_floor: datetime,
        limit: int,
    ) -> list[InputEnvelope]:
        source_sql, selector_parameters = _source_union_sql(
            compiled, event_occurrence_bounds=True
        )
        span = compiled.rule.window.milliseconds
        query_suffix = (
            "WHERE source.occurred_at >= "
            "{start:DateTime64(3)} AND source.occurred_at <= {end:DateTime64(3)} "
            "ORDER BY source.occurred_at, source.input_kind, source.input_id "
            "LIMIT {limit:UInt32}"
        )
        parameters = {
            **selector_parameters,
            "evaluation_floor": evaluation_floor,
            "start": candidate.occurred_at - _milliseconds(span),
            "end": candidate.occurred_at + _milliseconds(span),
            "limit": limit,
        }
        if not _requires_python_event_filter(compiled):
            result = self.client.query(
                "SELECT * FROM (" + source_sql + ") AS source " + query_suffix,
                parameters=parameters,
            )
            return self._decode_input_rows(
                result, compiled, include_invalid_events=False
            )

        detection_sql, event_sql, event_parameters = _source_sql_parts(
            compiled, event_occurrence_bounds=True
        )
        assert event_sql is not None
        detection_result = self.client.query(
            "SELECT * FROM (" + detection_sql + ") AS source " + query_suffix,
            parameters=parameters,
        )
        scan_cap = int(self.settings.context_limit)
        event_result = self.client.query(
            "SELECT * FROM (" + event_sql + ") AS source " + query_suffix,
            parameters={
                **parameters,
                **event_parameters,
                "limit": scan_cap + 1,
            },
        )
        if len(event_result.result_rows) > scan_cap:
            raise OverflowError(
                "canonical event context prefilter exceeds bounded scan limit "
                f"{scan_cap}"
            )
        context = [
            *self._decode_input_rows(
                detection_result, compiled, include_invalid_events=False
            ),
            *self._decode_input_rows(
                event_result, compiled, include_invalid_events=False
            ),
        ]
        return sorted(context, key=lambda item: item.order_key)[:limit]

    def _decode_input_rows(
        self,
        result: Any,
        compiled: CompiledRule,
        *,
        include_invalid_events: bool,
    ) -> list[InputEnvelope]:
        """Apply exact event-selector semantics after broad SQL enrollment.

        A conflicted logical event cannot be judged from its deterministic
        display row: a different physical variant may be the one that matched
        the approved selector.  Inspect those exceptional IDs separately and
        surface one invalid candidate only when at least one complete physical
        variant really matches.  Invalid events are never admitted as context.
        """

        inputs = _input_rows(result)
        conflict_ids = sorted(
            {
                item.input_id
                for item in inputs
                if item.input_kind == "event"
                and item.invalid_reason == "conflicting_immutable_values"
            }
        )
        matching_conflicts = (
            self._matching_conflicted_event_ids(conflict_ids, compiled)
            if include_invalid_events and conflict_ids
            else set()
        )
        selected: list[InputEnvelope] = []
        event_selectors = tuple(
            selector
            for selector in compiled.rule.selectors
            if selector.source == "event"
        )
        for item in inputs:
            if item.input_kind != "event":
                # Conflicted detections remain visible to candidate/backlog
                # scans so the engine can report and rotate past them, but
                # they must never become correlation context for a different
                # valid input.  Doing so would let an untrusted physical
                # variant poison an otherwise deterministic replay.
                if not item.invalid_reason or include_invalid_events:
                    selected.append(item)
                continue
            if item.invalid_reason == "conflicting_immutable_values":
                if item.input_id in matching_conflicts:
                    selected.append(item)
                continue
            if item.invalid_reason and not include_invalid_events:
                continue
            enrollment_item = InputEnvelope(
                item.input_kind,
                item.input_id,
                item.occurred_at,
                item.observed_at,
                item.values,
                "",
            )
            if any(
                selector_matches(selector, enrollment_item)
                for selector in event_selectors
            ):
                selected.append(item)
        return selected

    def _matching_conflicted_event_ids(
        self, input_ids: Sequence[str], compiled: CompiledRule
    ) -> set[str]:
        if not input_ids:
            return set()
        limit = int(self.settings.context_limit)
        result = self.client.query(
            _raw_event_variants_sql() + " LIMIT {limit:UInt32}",
            parameters={"ids": list(input_ids), "limit": limit + 1},
        )
        if len(result.result_rows) > limit:
            raise OverflowError(
                "conflicting event physical-variant lookup exceeds bounded scan "
                f"limit {limit}"
            )
        return {item.input_id for item in _input_rows(result, compiled)}

    def load_episode_states(
        self,
        scope: RuleScope,
        candidate: InputEnvelope,
        compiled: CompiledRule,
        limit: int,
        revision_token: str = "",
    ) -> list[EpisodeState]:
        if limit < 1:
            raise ValueError("episode-state limit must be positive")
        base_columns = ", ".join(EPISODE_COLUMNS)
        parameters = {
            **_scope_parameters(scope),
            "range_start": candidate.occurred_at
            - _milliseconds(compiled.rule.window.milliseconds),
            "range_end": candidate.occurred_at
            + _milliseconds(compiled.rule.window.milliseconds),
            "limit": limit + 1,
        }
        group_filter = ""
        candidate_group_hash: str | None = None
        if "shared_ip" not in compiled.rule.group_by:
            try:
                group = json.loads(
                    canonical_group_json(compiled.rule.group_by, candidate.values)
                )
                _, candidate_group_hash = group_identity(group)
                group_filter = " AND group_key_hash={group_hash:String}"
                parameters["group_hash"] = candidate_group_hash
            except (
                IdentityNormalizationError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
            ):
                return []
        sql = (
            f"SELECT {base_columns} FROM fusion.correlation_episode_state_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND episode_window_start <= {range_end:DateTime64(3)} "
            "AND episode_window_end >= {range_start:DateTime64(3)}"
            + group_filter
            + " ORDER BY episode_window_start, episode_state_id LIMIT {limit:UInt32}"
        )
        cache_key = (
            scope.key,
            parameters["range_start"],
            parameters["range_end"],
            str(parameters.get("group_hash", "")),
            limit,
        )
        page_start, page_end = self._episode_page_range or (
            parameters["range_start"],
            parameters["range_end"],
        )
        page_groups = self._episode_page_group_hashes
        page_usable = (
            self._episode_page_rows is not None
            and self._episode_page_scope == scope.key
            and page_start <= parameters["range_start"]
            and page_end >= parameters["range_end"]
            and (
                page_groups is None
                or candidate_group_hash is not None
                and candidate_group_hash in page_groups
            )
        )
        if page_usable:
            rows = [
                row
                for row in self._episode_page_rows or ()
                if _utc(row["episode_window_start"]) <= parameters["range_end"]
                and _utc(row["episode_window_end"]) >= parameters["range_start"]
                and (
                    page_groups is None
                    or str(row["group_key_hash"]) == candidate_group_hash
                )
            ]
        else:
            cached_rows = self._episode_current_cache.get(cache_key)
            if cached_rows is None:
                rows = list(_named_rows(self.client.query(sql, parameters=parameters)))
                self._episode_current_cache[cache_key] = rows
            else:
                rows = list(cached_rows)
        if len(rows) > limit:
            raise OverflowError(f"bounded episode-state query exceeds {limit} rows")
        if revision_token and revision_token not in self._known_absent_episode_tokens:
            raw = self.client.query(
                f"SELECT {base_columns} FROM fusion.correlation_episode_state "
                "WHERE engine_id={engine_id:String} "
                "AND correlation_rule_id={rule_id:String} "
                "AND correlation_rule_version={rule_version:UInt32} "
                "AND correlation_scope_fingerprint={fingerprint:String} "
                "AND revision_token={token:String} "
                "AND episode_window_start <= {range_end:DateTime64(3)} "
                "AND episode_window_end >= {range_start:DateTime64(3)}"
                + group_filter
                + " ORDER BY episode_window_start, episode_state_id "
                "LIMIT {limit:UInt32}",
                parameters={**parameters, "token": revision_token},
            )
            if len(raw.result_rows) > limit:
                raise OverflowError(
                    f"bounded raw episode-state query exceeds {limit} rows"
                )
            raw_rows = list(_named_rows(raw))
            rows.extend(raw_rows)
        states: dict[str, EpisodeState] = {}
        for row in rows:
            state = _episode_from_row(row)
            prior = states.get(state.episode_state_id)
            if prior is None or state.revision > prior.revision:
                states[state.episode_state_id] = state
        if len(states) > limit:
            raise OverflowError(
                f"combined episode-state query exceeds {limit} logical rows"
            )
        return list(states.values())

    def load_incidents(
        self, incident_ids: Sequence[str], *, include_unconfirmed: bool = False
    ) -> Mapping[str, IncidentRecord]:
        ids = sorted({value for value in incident_ids if value})
        if not ids:
            return {}
        table = (
            "fusion.incidents" if include_unconfirmed else "fusion.incidents_current"
        )
        order = (
            " ORDER BY incident_id, revision DESC, updated_at DESC"
            if include_unconfirmed
            else ""
        )
        result = self.client.query(
            f"SELECT {', '.join(INCIDENT_COLUMNS)} FROM {table} "
            "WHERE incident_id IN {ids:Array(String)}" + order,
            parameters={"ids": ids},
        )
        records: dict[str, IncidentRecord] = {}
        for row in _named_rows(result):
            record = _incident_from_row(row)
            records.setdefault(record.incident_id, record)
        return records

    def load_link_ids(self, incident_id: str) -> set[str]:
        result = self.client.query(
            "SELECT link_id FROM fusion.incident_detection_links_current "
            "WHERE incident_id={incident_id:String} UNION ALL "
            "SELECT link_id FROM fusion.incident_event_links_current "
            "WHERE incident_id={incident_id:String}",
            parameters={"incident_id": incident_id},
        )
        return {str(row[0]) for row in result.result_rows}

    def load_incident_members(
        self, incident_id: str, limit: int
    ) -> list[InputEnvelope]:
        """Load bounded, confirmation-backed incident evidence snapshots.

        These rows come only from the immutable link serving views. They are
        authoritative prior membership, not a second read of mutable source
        tables whose logical ID may since have become conflicted.
        """

        if not incident_id:
            raise ValueError("incident ID must be nonempty")
        if limit < 1:
            raise ValueError("incident-member limit must be positive")
        columns = (
            "input_kind",
            "input_id",
            "occurred_at",
            "observed_at",
            "source_type",
            "rule_id",
            "rule_name",
            "severity",
            "event_category",
            "event_action",
            "outcome",
            "service_name",
            "host_name",
            "user_name",
            "source_ip",
            "destination_ip",
            "mitre_technique_ids",
            "summary",
            "validation_id",
        )
        result = self.client.query(
            "SELECT * FROM ("
            "SELECT 'detection' AS input_kind, detection_id AS input_id, "
            "occurred_at, observed_at, toString(source_type) AS source_type, "
            "detection_rule_id AS rule_id, detection_rule_name AS rule_name, "
            "toString(severity) AS severity, '' AS event_category, "
            "'' AS event_action, '' AS outcome, '' AS service_name, host_name, "
            "user_name, source_ip, destination_ip, mitre_technique_ids, summary, "
            "validation_id FROM fusion.incident_detection_links_current "
            "WHERE incident_id={incident_id:String} UNION ALL "
            "SELECT 'event' AS input_kind, event_uid AS input_id, occurred_at, "
            "observed_at, toString(source_type) AS source_type, '' AS rule_id, "
            "'' AS rule_name, '' AS severity, toString(event_category) AS event_category, "
            "event_action, outcome, service_name, host_name, user_name, source_ip, "
            "destination_ip, CAST([], 'Array(String)') AS mitre_technique_ids, "
            "summary, validation_id FROM fusion.incident_event_links_current "
            "WHERE incident_id={incident_id:String}) AS member "
            "ORDER BY occurred_at, input_kind, input_id LIMIT {limit:UInt32}",
            parameters={"incident_id": incident_id, "limit": limit + 1},
        )
        if len(result.result_rows) > limit:
            raise OverflowError(f"incident membership exceeds {limit} rows")
        members: list[InputEnvelope] = []
        for row in _named_rows(result):
            values = {
                field: row[field]
                for field in columns
                if field not in {"input_kind", "input_id", "occurred_at", "observed_at"}
            }
            values["mitre_technique_ids"] = list(
                values.get("mitre_technique_ids") or ()
            )
            members.append(
                InputEnvelope(
                    str(row["input_kind"]),
                    str(row["input_id"]),
                    _utc(row["occurred_at"]),
                    _utc(row["observed_at"]),
                    values,
                )
            )
        return members

    def write_incident(self, incident: IncidentRecord) -> bool:
        values = incident.values
        existing = self.client.query(
            "SELECT revision, revision_token, state_hash FROM fusion.incidents "
            "WHERE incident_id={incident_id:String} "
            "AND (revision={revision:UInt64} OR revision_token={token:String})",
            parameters={
                "incident_id": incident.incident_id,
                "revision": incident.revision,
                "state_hash": incident.state_hash,
                "token": str(values["revision_token"]),
            },
        )
        if existing.result_rows:
            expected = (
                incident.revision,
                str(values["revision_token"]),
                incident.state_hash,
            )
            if all(
                (int(row[0]), str(row[1]), str(row[2])) == expected
                for row in existing.result_rows
            ):
                return False
            raise CorrelationPersistenceConflict(
                "conflicting incident revision/token already exists"
            )
        self.client.insert(
            "fusion.incidents",
            [[values.get(column) for column in INCIDENT_COLUMNS]],
            column_names=list(INCIDENT_COLUMNS),
        )
        return True

    def write_links(self, links: Sequence[EvidenceLink]) -> tuple[int, int]:
        detection_rows: list[list[Any]] = []
        event_rows: list[list[Any]] = []
        linked_at = _utc(datetime.now(timezone.utc))
        for link in links:
            table, columns = _link_table_and_columns(link.input_kind)
            id_column = columns[1]
            row = _link_row(link, linked_at, columns)
            immutable_columns = tuple(
                column for column in columns if column not in _LINK_VOLATILE_COLUMNS
            )
            expected = _row_content(columns, row, immutable_columns)
            existing = self.client.query(
                f"SELECT {', '.join(immutable_columns)} FROM {table} "
                "WHERE link_id={link_id:String} "
                f"OR (incident_id={{incident_id:String}} AND {id_column}={{input_id:String}})",
                parameters={
                    "link_id": link.link_id,
                    "incident_id": link.incident_id,
                    "input_id": link.input_id,
                },
            )
            if existing.result_rows:
                if all(
                    _content_equal(immutable_columns, persisted, expected)
                    for persisted in existing.result_rows
                ):
                    continue
                raise CorrelationPersistenceConflict(
                    "conflicting evidence-link immutable content already exists"
                )
            if link.input_kind == "detection":
                detection_rows.append(row)
            else:
                event_rows.append(row)
        if detection_rows:
            self.client.insert(
                "fusion.incident_detection_links",
                detection_rows,
                column_names=list(DETECTION_LINK_COLUMNS),
            )
        if event_rows:
            self.client.insert(
                "fusion.incident_event_links",
                event_rows,
                column_names=list(EVENT_LINK_COLUMNS),
            )
        return len(detection_rows), len(event_rows)

    def write_episode_states(self, states: Sequence[EpisodeState]) -> int:
        if not states:
            return 0
        # From this point onward the page snapshot is stale. Even an exact
        # replay may complete a previously unconfirmed state revision.
        self._episode_current_cache.clear()
        self._episode_page_rows = None
        self._episode_page_scope = None
        self._episode_page_range = None
        self._episode_page_group_hashes = frozenset()
        for state in states:
            self._known_absent_episode_tokens.discard(state.revision_token)
        rows = []
        for state in states:
            existing = self.client.query(
                "SELECT revision, revision_token, state_hash "
                "FROM fusion.correlation_episode_state "
                "WHERE engine_id={engine_id:String} "
                "AND correlation_rule_id={rule_id:String} "
                "AND correlation_rule_version={rule_version:UInt32} "
                "AND correlation_scope_fingerprint={fingerprint:String} "
                "AND episode_state_id={episode_id:String} "
                "AND (revision={revision:UInt64} OR revision_token={token:String})",
                parameters={
                    **_scope_parameters(state.scope),
                    "episode_id": state.episode_state_id,
                    "revision": state.revision,
                    "token": state.revision_token,
                },
            )
            if existing.result_rows:
                expected = (
                    state.revision,
                    state.revision_token,
                    state.state_hash,
                )
                if all(
                    (int(row[0]), str(row[1]), str(row[2])) == expected
                    for row in existing.result_rows
                ):
                    continue
                raise CorrelationPersistenceConflict(
                    "conflicting episode-state revision/token already exists"
                )
            rows.append(
                [
                    state.scope.engine_id,
                    state.scope.rule_id,
                    state.scope.rule_version,
                    state.scope.fingerprint,
                    state.group_key_json,
                    state.group_key_hash,
                    state.episode_state_id,
                    state.revision_token,
                    list(json.loads(state.canonical_qualifying_set_json)),
                    state.anchor_kind,
                    state.anchor_id,
                    state.anchor_time,
                    state.window_start,
                    state.window_end,
                    state.incident_id,
                    list(state.owned_detection_ids),
                    list(state.owned_event_ids),
                    state.last_input_observed_at,
                    state.late_accept_until,
                    state.collision_count,
                    state.state_hash,
                    state.updated_at,
                    state.revision,
                ]
            )
        if rows:
            self.client.insert(
                "fusion.correlation_episode_state",
                rows,
                column_names=list(EPISODE_COLUMNS),
            )
        return len(rows)

    def confirm_decision(
        self, scope: RuleScope, candidate: InputEnvelope, decision: EvaluationDecision
    ) -> None:
        expected_incident = decision.expected_incident or decision.incident
        if expected_incident is not None:
            result = self.client.query(
                "SELECT count() FROM fusion.incidents "
                "WHERE incident_id={incident_id:String} AND revision={revision:UInt64} "
                "AND state_hash={state_hash:String} AND revision_token={token:String}",
                parameters={
                    "incident_id": expected_incident.incident_id,
                    "revision": expected_incident.revision,
                    "state_hash": expected_incident.state_hash,
                    "token": str(expected_incident.values["revision_token"]),
                },
            )
            if int(result.result_rows[0][0]) < 1:
                raise RuntimeError("incident read-back confirmation failed")
        for link in decision.links:
            table, columns = _link_table_and_columns(link.input_kind)
            id_column = columns[1]
            immutable_columns = tuple(
                column for column in columns if column not in _LINK_VOLATILE_COLUMNS
            )
            expected = _row_content(
                columns,
                _link_row(link, link.observed_at, columns),
                immutable_columns,
            )
            result = self.client.query(
                f"SELECT {', '.join(immutable_columns)} FROM {table} "
                "WHERE incident_id={incident_id:String} "
                f"AND {id_column}={{input_id:String}} AND link_id={{link_id:String}} "
                "AND introduction_revision_token={token:String}",
                parameters={
                    "incident_id": link.incident_id,
                    "input_id": link.input_id,
                    "link_id": link.link_id,
                    "token": link.introduction_revision_token,
                },
            )
            if not result.result_rows:
                raise RuntimeError("evidence-link read-back confirmation failed")
            if not all(
                _content_equal(immutable_columns, persisted, expected)
                for persisted in result.result_rows
            ):
                raise CorrelationPersistenceConflict(
                    "evidence-link read-back immutable content mismatch"
                )
        for state in decision.episode_states:
            result = self.client.query(
                "SELECT count() FROM fusion.correlation_episode_state "
                "WHERE engine_id={engine_id:String} "
                "AND correlation_rule_id={rule_id:String} "
                "AND correlation_rule_version={rule_version:UInt32} "
                "AND correlation_scope_fingerprint={fingerprint:String} "
                "AND episode_state_id={episode_id:String} AND revision={revision:UInt64} "
                "AND revision_token={token:String} AND state_hash={state_hash:String}",
                parameters={
                    **_scope_parameters(scope),
                    "episode_id": state.episode_state_id,
                    "revision": state.revision,
                    "token": decision.revision_token,
                    "state_hash": state.state_hash,
                },
            )
            if int(result.result_rows[0][0]) < 1:
                raise RuntimeError("episode-state read-back confirmation failed")

    def mark_evaluated(
        self,
        scope: RuleScope,
        entries: Sequence[tuple[InputEnvelope, EvaluationDecision]],
    ) -> int:
        if not entries:
            return 0
        if len(entries) > 10_000:
            raise ValueError("evaluation-ledger batch exceeds hard limit 10000")
        evaluated_at = _utc(datetime.now(timezone.utc))
        rows_by_identity: dict[tuple[str, str], list[Any]] = {}
        expected_by_identity: dict[tuple[str, str], tuple[Any, ...]] = {}
        immutable_columns = tuple(
            column for column in LEDGER_COLUMNS if column != "evaluated_at"
        )
        for candidate, decision in entries:
            row = [
                scope.engine_id,
                scope.rule_id,
                scope.rule_version,
                scope.fingerprint,
                candidate.input_kind,
                candidate.input_id,
                candidate.occurred_at,
                candidate.observed_at,
                evaluated_at,
                decision.evaluation_action,
                decision.lateness_status,
                decision.resulting_incident_id,
                decision.revision_token,
                decision.reason_code,
                str(candidate.values.get("source_type", "")),
                str(candidate.values.get("host_name", "")),
                str(candidate.values.get("validation_id", "")),
            ]
            identity = (candidate.input_kind, candidate.input_id)
            expected = _row_content(LEDGER_COLUMNS, row, immutable_columns)
            prior_expected = expected_by_identity.get(identity)
            if prior_expected is not None:
                if not _content_equal(immutable_columns, prior_expected, expected):
                    raise CorrelationPersistenceConflict(
                        "one evaluation batch contains conflicting ledger identities"
                    )
                continue
            expected_by_identity[identity] = expected
            rows_by_identity[identity] = row

        identities = sorted(expected_by_identity)
        identity_parameters = {
            **_scope_parameters(scope),
            "identities": identities,
            "identity_limit": len(identities) + 1,
        }
        immutable_tuple_sql = "tuple(" + ", ".join(immutable_columns) + ")"
        existing = self.client.query(
            "SELECT input_kind, input_id, "
            f"groupUniqArray(2)({immutable_tuple_sql}) AS immutable_variants "
            "FROM fusion.correlation_evaluated_inputs "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND tuple(input_kind, input_id) IN "
            "{identities:Array(Tuple(String,String))} "
            "GROUP BY input_kind, input_id ORDER BY input_kind, input_id "
            "LIMIT {identity_limit:UInt32}",
            parameters=identity_parameters,
        )
        if len(existing.result_rows) > len(identities):
            raise RuntimeError("evaluation-ledger preflight exceeded identity bound")
        existing_identities: set[tuple[str, str]] = set()
        for raw_kind, raw_id, variants in existing.result_rows:
            identity = (str(raw_kind), str(raw_id))
            expected = expected_by_identity.get(identity)
            if expected is None or identity in existing_identities:
                raise CorrelationPersistenceConflict(
                    "evaluation-ledger preflight returned an unexpected identity"
                )
            existing_identities.add(identity)
            if (
                not isinstance(variants, (list, tuple))
                or len(variants) != 1
                or not _content_equal(immutable_columns, variants[0], expected)
            ):
                raise CorrelationPersistenceConflict(
                    "conflicting evaluation-ledger identity already exists"
                )

        rows = [
            row
            for identity, row in rows_by_identity.items()
            if identity not in existing_identities
        ]
        if rows:
            self.client.insert(
                "fusion.correlation_evaluated_inputs",
                rows,
                column_names=list(LEDGER_COLUMNS),
            )

        confirmed = self.client.query(
            f"SELECT {', '.join(immutable_columns)} "
            "FROM fusion.correlation_evaluated_inputs_current "
            "WHERE engine_id={engine_id:String} "
            "AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND tuple(input_kind, input_id) IN "
            "{identities:Array(Tuple(String,String))} "
            "ORDER BY input_kind, input_id LIMIT {identity_limit:UInt32}",
            parameters=identity_parameters,
        )
        if len(confirmed.result_rows) != len(identities):
            raise RuntimeError(
                "evaluation ledger batch read-back did not produce every identity"
            )
        confirmed_identities: set[tuple[str, str]] = set()
        kind_position = immutable_columns.index("input_kind")
        id_position = immutable_columns.index("input_id")
        for persisted in confirmed.result_rows:
            identity = (
                str(persisted[kind_position]),
                str(persisted[id_position]),
            )
            expected = expected_by_identity.get(identity)
            if expected is None or identity in confirmed_identities:
                raise CorrelationPersistenceConflict(
                    "evaluation-ledger batch read-back returned an unexpected identity"
                )
            confirmed_identities.add(identity)
            if not _content_equal(immutable_columns, persisted, expected):
                raise CorrelationPersistenceConflict(
                    "evaluation-ledger read-back immutable content mismatch"
                )
        return len(expected_by_identity)

    def fetch_backlog(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
    ) -> CorrelationBacklog:
        source_sql, selector_parameters = _source_union_sql(compiled)
        if _requires_python_event_filter(compiled):
            return self._fetch_backlog_with_python_event_filter(
                scope, compiled, evaluation_floor
            )
        newest_eligible = self._newest_eligible_input(compiled, evaluation_floor)
        result = self.client.query(
            "SELECT count(), minOrNull(source.observed_at), "
            "argMaxOrNull(source.occurred_at, tuple(source.occurred_at,source.input_kind,source.input_id)), "
            "argMaxOrNull(source.observed_at, tuple(source.occurred_at,source.input_kind,source.input_id)), "
            "argMaxOrNull(source.input_kind, tuple(source.occurred_at,source.input_kind,source.input_id)), "
            "argMaxOrNull(source.input_id, tuple(source.occurred_at,source.input_kind,source.input_id)) "
            "FROM (" + source_sql + ") AS source "
            "LEFT JOIN fusion.correlation_evaluated_inputs_current AS evaluated "
            "ON evaluated.engine_id={engine_id:String} "
            "AND evaluated.correlation_rule_id={rule_id:String} "
            "AND evaluated.correlation_rule_version={rule_version:UInt32} "
            "AND evaluated.correlation_scope_fingerprint={fingerprint:String} "
            "AND evaluated.input_kind=source.input_kind "
            "AND evaluated.input_id=source.input_id "
            + _unevaluated_or_new_conflict_sql(),
            parameters={
                **_scope_parameters(scope),
                **selector_parameters,
                "evaluation_floor": evaluation_floor,
            },
        )
        count, oldest, *_unevaluated_high_water = result.result_rows[0]
        oldest_utc = _utc(oldest) if oldest is not None else None
        return CorrelationBacklog(
            newest_eligible.occurred_at if newest_eligible else None,
            newest_eligible.observed_at if newest_eligible else None,
            newest_eligible.input_kind if newest_eligible else "",
            newest_eligible.input_id if newest_eligible else "",
            int(count),
            oldest_utc,
            (
                max(
                    0.0, (_utc(datetime.now(timezone.utc)) - oldest_utc).total_seconds()
                )
                if oldest_utc is not None
                else 0.0
            ),
        )

    def _fetch_backlog_with_python_event_filter(
        self,
        scope: RuleScope,
        compiled: CompiledRule,
        evaluation_floor: datetime,
    ) -> CorrelationBacklog:
        detection_sql, event_sql, selector_parameters = _source_sql_parts(compiled)
        assert event_sql is not None
        join_sql = (
            "LEFT JOIN fusion.correlation_evaluated_inputs_current AS evaluated "
            "ON evaluated.engine_id={engine_id:String} "
            "AND evaluated.correlation_rule_id={rule_id:String} "
            "AND evaluated.correlation_rule_version={rule_version:UInt32} "
            "AND evaluated.correlation_scope_fingerprint={fingerprint:String} "
            "AND evaluated.input_kind=source.input_kind "
            "AND evaluated.input_id=source.input_id "
            + _unevaluated_or_new_conflict_sql()
        )
        parameters = {
            **_scope_parameters(scope),
            **selector_parameters,
            "evaluation_floor": evaluation_floor,
        }
        detection_result = self.client.query(
            "SELECT count(), minOrNull(source.observed_at), "
            "argMaxOrNull(source.occurred_at, tuple(source.occurred_at,source.input_kind,source.input_id)), "
            "argMaxOrNull(source.observed_at, tuple(source.occurred_at,source.input_kind,source.input_id)), "
            "argMaxOrNull(source.input_kind, tuple(source.occurred_at,source.input_kind,source.input_id)), "
            "argMaxOrNull(source.input_id, tuple(source.occurred_at,source.input_kind,source.input_id)) "
            "FROM (" + detection_sql + ") AS source " + join_sql,
            parameters=parameters,
        )
        scan_cap = int(self.settings.context_limit)
        event_result = self.client.query(
            "SELECT source.* FROM ("
            + event_sql
            + ") AS source "
            + join_sql
            + "ORDER BY source.occurred_at, source.input_kind, source.input_id "
            "LIMIT {limit:UInt32}",
            parameters={**parameters, "limit": scan_cap + 1},
        )
        if len(event_result.result_rows) > scan_cap:
            raise OverflowError(
                "canonical event backlog prefilter exceeds bounded scan limit "
                f"{scan_cap}"
            )
        events = self._decode_input_rows(
            event_result, compiled, include_invalid_events=True
        )
        (
            detection_count,
            detection_oldest,
            *_unevaluated_detection_high_water,
        ) = detection_result.result_rows[0]
        newest = self._newest_eligible_input(compiled, evaluation_floor)
        oldest_values = [item.observed_at for item in events]
        if detection_oldest is not None:
            oldest_values.append(_utc(detection_oldest))
        oldest = min(oldest_values, default=None)
        return CorrelationBacklog(
            newest.occurred_at if newest else None,
            newest.observed_at if newest else None,
            newest.input_kind if newest else "",
            newest.input_id if newest else "",
            int(detection_count) + len(events),
            oldest,
            (
                max(0.0, (_utc(datetime.now(timezone.utc)) - oldest).total_seconds())
                if oldest is not None
                else 0.0
            ),
        )

    def _newest_eligible_input(
        self, compiled: CompiledRule, evaluation_floor: datetime
    ) -> InputEnvelope | None:
        """Return source high-water independently of evaluation-ledger state."""

        source_sql, selector_parameters = _source_union_sql(compiled)
        parameters = {
            **selector_parameters,
            "evaluation_floor": evaluation_floor,
            "limit": 1,
        }
        suffix = (
            "ORDER BY source.occurred_at DESC, source.input_kind DESC, "
            "source.input_id DESC LIMIT {limit:UInt32}"
        )
        if not _requires_python_event_filter(compiled):
            result = self.client.query(
                "SELECT source.* FROM (" + source_sql + ") AS source " + suffix,
                parameters=parameters,
            )
            inputs = self._decode_input_rows(
                result, compiled, include_invalid_events=True
            )
            return inputs[0] if inputs else None

        detection_sql, event_sql, event_parameters = _source_sql_parts(compiled)
        assert event_sql is not None
        detection_result = self.client.query(
            "SELECT source.* FROM (" + detection_sql + ") AS source " + suffix,
            parameters=parameters,
        )
        scan_cap = int(self.settings.context_limit)
        event_result = self.client.query(
            "SELECT source.* FROM (" + event_sql + ") AS source " + suffix,
            parameters={
                **parameters,
                **event_parameters,
                "limit": scan_cap + 1,
            },
        )
        detection_inputs = self._decode_input_rows(
            detection_result, compiled, include_invalid_events=True
        )
        event_inputs = self._decode_input_rows(
            event_result, compiled, include_invalid_events=True
        )
        # Descending scan proves a found event is the exact event high-water.
        # If none matched within the bounded superset, fail visibly instead of
        # reporting a false empty/older position.
        if not event_inputs and len(event_result.result_rows) > scan_cap:
            raise OverflowError(
                "canonical event high-water prefilter exceeds bounded scan limit "
                f"{scan_cap}"
            )
        return max(
            (*detection_inputs, *event_inputs),
            default=None,
            key=lambda item: item.order_key,
        )

    def save_schedule(self, stats: CorrelationCycleStats) -> None:
        scope = stats.scope
        revision_result = self.client.query(
            "SELECT maxOrNull(revision) FROM fusion.correlation_schedule_state "
            "WHERE engine_id={engine_id:String} AND correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String}",
            parameters=_scope_parameters(scope),
        )
        prior_revision = revision_result.result_rows[0][0]
        revision = int(prior_revision or 0) + 1
        cursor = stats.cursor
        backlog = stats.backlog
        now = _utc(datetime.now(timezone.utc))
        row = [
            scope.engine_id,
            scope.rule_id,
            scope.rule_version,
            scope.fingerprint,
            cursor.occurred_at if cursor else None,
            cursor.observed_at if cursor else None,
            cursor.input_kind if cursor else "",
            cursor.input_id if cursor else "",
            backlog.newest_occurred_at,
            backlog.newest_observed_at,
            backlog.newest_input_kind,
            backlog.newest_input_id,
            backlog.unevaluated_input_count,
            backlog.oldest_unevaluated_observed_at,
            backlog.oldest_unevaluated_age_seconds,
            stats.evaluated_inputs,
            stats.matched_inputs,
            stats.failed_inputs,
            stats.incidents_created,
            stats.incidents_updated,
            stats.detection_links_written,
            stats.event_links_written,
            stats.processing_duration_seconds,
            stats.evaluated_inputs_per_second,
            stats.consecutive_drain_cycles,
            now,
            revision,
        ]
        self.client.insert(
            "fusion.correlation_schedule_state",
            [row],
            column_names=list(SCHEDULE_COLUMNS),
        )

    def status(self) -> Mapping[str, Any]:
        """Return bounded persisted per-rule scheduling diagnostics."""

        result = self.client.query(
            "SELECT correlation_rule_id, correlation_rule_version, "
            "correlation_scope_fingerprint, candidate_cursor_occurred_at, "
            "candidate_cursor_observed_at, candidate_cursor_input_kind, "
            "candidate_cursor_input_id, newest_eligible_occurred_at, "
            "newest_eligible_observed_at, newest_eligible_input_kind, "
            "newest_eligible_input_id, unevaluated_input_count, "
            "oldest_unevaluated_observed_at, oldest_unevaluated_age_seconds, "
            "cycle_evaluated_count, cycle_matched_count, cycle_failed_count, "
            "cycle_incident_create_count, cycle_incident_update_count, "
            "processing_duration_seconds, evaluated_inputs_per_second, "
            "updated_at FROM fusion.correlation_schedule_state_current "
            "WHERE engine_id={engine_id:String} "
            "ORDER BY correlation_rule_id, correlation_rule_version, "
            "correlation_scope_fingerprint LIMIT 256",
            parameters={"engine_id": self.settings.engine_id},
        )
        schedule_scopes = list(_named_rows(result))
        integrity_result = self.client.query(
            "SELECT correlation_rule_id, correlation_rule_version, "
            "correlation_scope_fingerprint, "
            "arraySort(groupUniqArray(ruleset_fingerprint)) AS ruleset_fingerprints, "
            "uniqExact(integrity_event_id) AS integrity_violation_count, "
            "arraySort(groupUniqArray(violation_type)) AS violation_types, "
            "min(first_detected_at) AS first_detected_at, "
            "max(detected_at) AS last_detected_at "
            "FROM fusion.correlation_integrity_events "
            "WHERE engine_id={engine_id:String} "
            "GROUP BY correlation_rule_id, correlation_rule_version, "
            "correlation_scope_fingerprint "
            "ORDER BY correlation_rule_id, correlation_rule_version, "
            "correlation_scope_fingerprint LIMIT 256",
            parameters={"engine_id": self.settings.engine_id},
        )
        integrity_summary_result = self.client.query(
            "SELECT uniqExact(integrity_event_id) AS integrity_violation_count, "
            "uniqExact(tuple(correlation_rule_id, correlation_rule_version, "
            "correlation_scope_fingerprint)) AS blocked_scope_count, "
            "arraySort(groupUniqArray(violation_type)) AS violation_types "
            "FROM fusion.correlation_integrity_events "
            "WHERE engine_id={engine_id:String}",
            parameters={"engine_id": self.settings.engine_id},
        )
        if len(integrity_summary_result.result_rows) != 1:
            raise CorrelationPersistenceConflict(
                "correlation integrity summary is unavailable"
            )
        (
            global_integrity_violation_count,
            global_blocked_scope_count,
            global_violation_types,
        ) = integrity_summary_result.result_rows[0]
        global_integrity_violation_count = int(global_integrity_violation_count)
        global_blocked_scope_count = int(global_blocked_scope_count)
        live_projection = self._probe_live_projection_integrity()
        live_projection_blocked = live_projection["status"] != "healthy"
        integrity_by_scope = {
            (
                str(row["correlation_rule_id"]),
                int(row["correlation_rule_version"]),
                str(row["correlation_scope_fingerprint"]),
            ): row
            for row in _named_rows(integrity_result)
        }
        schedule_by_scope = {
            (
                str(row["correlation_rule_id"]),
                int(row["correlation_rule_version"]),
                str(row["correlation_scope_fingerprint"]),
            ): row
            for row in schedule_scopes
        }
        scopes: list[dict[str, Any]] = []
        for key in sorted(set(schedule_by_scope) | set(integrity_by_scope)):
            row = dict(schedule_by_scope.get(key, {}))
            integrity = integrity_by_scope.get(key)
            row.setdefault("correlation_rule_id", key[0])
            row.setdefault("correlation_rule_version", key[1])
            row.setdefault("correlation_scope_fingerprint", key[2])
            if integrity is None:
                row.update(
                    correlation_status=(
                        "blocked_integrity_unpersisted"
                        if live_projection_blocked
                        else "healthy"
                    ),
                    integrity_violation_count=0,
                    integrity_violation_types=[],
                    integrity_first_detected_at=None,
                    integrity_last_detected_at=None,
                    integrity_ruleset_fingerprints=[],
                )
                if live_projection_blocked:
                    row.update(
                        unevaluated_input_count=None,
                        oldest_unevaluated_observed_at=None,
                        oldest_unevaluated_age_seconds=None,
                    )
            else:
                # Never present a stale saved zero as proof of a healthy drain.
                # The schedule remains durable diagnostic history, but backlog
                # correctness is unavailable while the scope is blocked.
                row.update(
                    correlation_status="blocked_integrity",
                    integrity_violation_count=int(
                        integrity["integrity_violation_count"]
                    ),
                    integrity_violation_types=list(integrity["violation_types"]),
                    integrity_first_detected_at=integrity["first_detected_at"],
                    integrity_last_detected_at=integrity["last_detected_at"],
                    integrity_ruleset_fingerprints=list(
                        integrity["ruleset_fingerprints"]
                    ),
                    unevaluated_input_count=None,
                    oldest_unevaluated_observed_at=None,
                    oldest_unevaluated_age_seconds=None,
                )
            scopes.append(row)
        healthy_scopes = [
            row for row in scopes if row["correlation_status"] == "healthy"
        ]
        any_integrity_block = bool(
            global_integrity_violation_count or live_projection_blocked
        )
        return {
            "schema": "fusion-correlation-status/v1",
            "engine_id": self.settings.engine_id,
            "correlation_status": (
                "blocked_integrity"
                if any_integrity_block
                else "healthy"
            ),
            "scope_count": len(scopes),
            "blocked_scope_count": global_blocked_scope_count,
            "integrity_violation_count": global_integrity_violation_count,
            "integrity_violation_types": sorted(
                str(value) for value in global_violation_types
            ),
            "integrity_scope_details_truncated": (
                global_blocked_scope_count > len(integrity_by_scope)
            ),
            "live_projection_status": live_projection["status"],
            "live_projection_violation_types": live_projection[
                "violation_types"
            ],
            "live_projection_names": live_projection["projection_names"],
            "live_projection_gap_count": live_projection["gap_count"],
            "live_projection_failure_kind": live_projection["failure_kind"],
            "live_projection_blocks_all_scopes": live_projection_blocked,
            "unevaluated_input_count": (
                None
                if any_integrity_block
                else sum(int(row["unevaluated_input_count"]) for row in healthy_scopes)
            ),
            "oldest_unevaluated_age_seconds": (
                None
                if any_integrity_block
                else max(
                    (
                        float(row["oldest_unevaluated_age_seconds"])
                        for row in healthy_scopes
                    ),
                    default=0.0,
                )
            ),
            "scopes": scopes,
        }

    def transition_incident(
        self,
        incident_id: str,
        target_status: str,
        transition_id: str,
        requested_at: datetime | None = None,
    ) -> IncidentRecord:
        if target_status not in {"acknowledged", "closed"}:
            raise ValueError("target status must be acknowledged or closed")
        if not transition_id or len(transition_id) > 128:
            raise ValueError("transition id must contain 1-128 characters")
        request_time = _utc(requested_at or datetime.now(timezone.utc))
        raw = self.client.query(
            f"SELECT {', '.join(INCIDENT_COLUMNS)} FROM fusion.incidents "
            "WHERE incident_id={incident_id:String} AND revision_source='lifecycle_transition' "
            "AND revision_token={token:String} ORDER BY revision DESC LIMIT 1",
            parameters={"incident_id": incident_id, "token": transition_id},
        )
        if raw.result_rows:
            replay = _incident_from_row(next(_named_rows(raw)))
            if str(replay.values["status"]) != target_status:
                raise ValueError(
                    "transition id was already used for a different target status"
                )
            original_requested_at = replay.values.get("last_transition_at")
            if original_requested_at is None:
                raise RuntimeError("persisted lifecycle transition time is missing")
            self._ensure_transition_audit(replay, _utc(original_requested_at))
            return replay
        current = self.load_incidents([incident_id]).get(incident_id)
        if current is None:
            raise LookupError(f"incident not found: {incident_id}")
        self._assert_incident_scope_mutable(current)
        values = dict(current.values)
        current_status = str(values["status"])
        if current_status == target_status:
            return current
        allowed = {
            ("new", "acknowledged"),
            ("new", "closed"),
            ("acknowledged", "closed"),
        }
        if (current_status, target_status) not in allowed:
            raise ValueError(
                f"forbidden incident transition {current_status}->{target_status}"
            )
        # The private serialized command has no caller-controlled timestamp.
        # Use one persisted millisecond instant for both request and apply so a
        # retry can reconstruct a missing immutable audit row exactly.
        applied_at = request_time
        values.update(
            {
                "status": target_status,
                "updated_at": applied_at,
                "last_transition_id": transition_id,
                "last_transition_from": current_status,
                "last_transition_at": applied_at,
                "revision": current.revision + 1,
                "revision_source": "lifecycle_transition",
                "revision_token": transition_id,
            }
        )
        if target_status == "acknowledged":
            values["acknowledged_at"] = values.get("acknowledged_at") or applied_at
        else:
            values["closed_at"] = applied_at
            allowed_lateness = (
                values["late_accept_until"] - values["episode_window_end"]
            )
            values["late_accept_until"] = applied_at + max(
                allowed_lateness, _milliseconds(0)
            )
        values["state_hash"] = state_hash(values)
        record = IncidentRecord(values)
        self.write_incident(record)
        check = self.client.query(
            "SELECT count() FROM fusion.incidents WHERE incident_id={incident_id:String} "
            "AND revision={revision:UInt64} AND revision_token={token:String} "
            "AND state_hash={state_hash:String}",
            parameters={
                "incident_id": incident_id,
                "revision": record.revision,
                "token": transition_id,
                "state_hash": record.state_hash,
            },
        )
        if int(check.result_rows[0][0]) < 1:
            raise RuntimeError("lifecycle incident revision confirmation failed")
        self._ensure_transition_audit(record, applied_at)
        return record

    def _assert_incident_scope_mutable(self, incident: IncidentRecord) -> None:
        # The control socket can mutate lifecycle state outside the polling
        # engine. Revalidate the append-only block authority here so replacing
        # or adding a TTL to it cannot bypass a persisted scope block.
        self._validate_integrity_event_contract()
        values = incident.values
        result = self.client.query(
            "SELECT uniqExact(integrity_event_id) "
            "FROM fusion.correlation_integrity_events "
            "WHERE correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String}",
            parameters={
                "rule_id": str(values["correlation_rule_id"]),
                "rule_version": int(values["correlation_rule_version"]),
                "fingerprint": str(values["correlation_scope_fingerprint"]),
            },
        )
        if int(result.result_rows[0][0]) > 0:
            raise CorrelationPersistenceConflict(
                "incident lifecycle mutation is blocked by correlation integrity state"
            )
        # A control request can arrive before the polling worker has observed
        # and persisted a projection outage.  Prove the live global projection
        # contract/coverage without mutating integrity state; anything other
        # than exact parity is an explicit fail-closed lifecycle result.
        live_projection = self._probe_live_projection_integrity()
        if live_projection["status"] != "healthy":
            raise CorrelationPersistenceConflict(
                "incident lifecycle mutation is blocked because correlation "
                "observation projection integrity is unconfirmed"
            )
        try:
            mismatch_count = self._count_stable_scope_canonical_mismatches(incident)
        except Exception as exc:
            raise CorrelationPersistenceConflict(
                "incident lifecycle mutation is blocked because canonical "
                "observation integrity is unconfirmed"
            ) from exc
        if mismatch_count:
            raise CorrelationPersistenceConflict(
                "incident lifecycle mutation is blocked by a canonical "
                "observation mismatch"
            )

    def _count_stable_scope_canonical_mismatches(
        self, incident: IncidentRecord
    ) -> int:
        """Count canonical regressions for an incident scope across engines.

        Incident rows intentionally do not carry an engine ID.  Querying every
        ledger engine for the stable rule/version/scope key prevents changing
        the configured engine ID from bypassing the lifecycle guard.
        """

        values = incident.values
        result = self.client.query(
            "/* lifecycle_canonical_observation_mismatch_query */ "
            "SELECT count() FROM ("
            "SELECT evaluated.engine_id, evaluated.input_id, "
            "evaluated.observed_at AS ledger_observed_at, "
            "min(history.detected_at) AS canonical_observed_at "
            "FROM fusion.correlation_evaluated_inputs_current AS evaluated "
            f"INNER JOIN {HISTORY_TABLE_QUALIFIED_NAME} AS history "
            "ON history.detection_id=evaluated.input_id "
            "WHERE evaluated.correlation_rule_id={rule_id:String} "
            "AND evaluated.correlation_rule_version={rule_version:UInt32} "
            "AND evaluated.correlation_scope_fingerprint={fingerprint:String} "
            "AND evaluated.input_kind='detection' "
            "GROUP BY evaluated.engine_id, evaluated.input_id, "
            "evaluated.observed_at "
            "HAVING ledger_observed_at != canonical_observed_at "
            "UNION ALL SELECT evaluated.engine_id, evaluated.input_id, "
            "evaluated.observed_at AS ledger_observed_at, "
            "canonical_event.canonical_observed_at AS canonical_observed_at "
            "FROM fusion.correlation_evaluated_inputs_current AS evaluated "
            "INNER JOIN (SELECT event_uid, "
            "min(ingested_at) AS canonical_observed_at "
            "FROM fusion.sysmon_events PREWHERE event_uid IN ("
            "SELECT input_id FROM fusion.correlation_evaluated_inputs_current "
            "WHERE correlation_rule_id={rule_id:String} "
            "AND correlation_rule_version={rule_version:UInt32} "
            "AND correlation_scope_fingerprint={fingerprint:String} "
            "AND input_kind='event') GROUP BY event_uid) AS canonical_event "
            "ON canonical_event.event_uid=evaluated.input_id "
            "WHERE evaluated.correlation_rule_id={rule_id:String} "
            "AND evaluated.correlation_rule_version={rule_version:UInt32} "
            "AND evaluated.correlation_scope_fingerprint={fingerprint:String} "
            "AND evaluated.input_kind='event' "
            "AND evaluated.observed_at != canonical_event.canonical_observed_at) "
            "SETTINGS max_execution_time={max_seconds:UInt32}, "
            "max_memory_usage={max_memory:UInt64}",
            parameters={
                "rule_id": str(values["correlation_rule_id"]),
                "rule_version": int(values["correlation_rule_version"]),
                "fingerprint": str(values["correlation_scope_fingerprint"]),
                "max_seconds": _INTEGRITY_QUERY_MAX_SECONDS,
                "max_memory": _INTEGRITY_QUERY_MAX_MEMORY,
            },
        )
        if len(result.result_rows) != 1:
            raise CorrelationPersistenceConflict(
                "canonical observation mismatch count is unavailable"
            )
        return int(result.result_rows[0][0])

    def _ensure_transition_audit(
        self, record: IncidentRecord, requested_at: datetime
    ) -> None:
        values = record.values
        token = str(values["revision_token"])
        existing = self.client.query(
            "SELECT count() FROM fusion.incident_status_transitions_current "
            "WHERE incident_id={incident_id:String} AND transition_id={token:String}",
            parameters={"incident_id": record.incident_id, "token": token},
        )
        if int(existing.result_rows[0][0]) == 0:
            self.client.insert(
                "fusion.incident_status_transitions",
                [
                    [
                        token,
                        record.incident_id,
                        str(values["last_transition_from"]),
                        str(values["status"]),
                        requested_at,
                        values["last_transition_at"],
                        "local_admin",
                        record.revision,
                        str(values.get("validation_id", "")),
                    ]
                ],
                column_names=[
                    "transition_id",
                    "incident_id",
                    "from_status",
                    "to_status",
                    "requested_at",
                    "applied_at",
                    "actor_type",
                    "resulting_incident_revision",
                    "validation_id",
                ],
            )
        confirmed = self.client.query(
            "SELECT count() FROM fusion.incident_status_transitions_current "
            "WHERE incident_id={incident_id:String} AND transition_id={token:String} "
            "AND resulting_incident_revision={revision:UInt64}",
            parameters={
                "incident_id": record.incident_id,
                "token": token,
                "revision": record.revision,
            },
        )
        if int(confirmed.result_rows[0][0]) != 1:
            raise RuntimeError("lifecycle transition audit confirmation failed")


def _scope_parameters(scope: RuleScope) -> Mapping[str, Any]:
    return {
        "engine_id": scope.engine_id,
        "rule_id": scope.rule_id,
        "rule_version": scope.rule_version,
        "fingerprint": scope.fingerprint,
    }


def _normalize_projection_sql(value: str) -> str:
    """Normalize formatting/identifier quoting without erasing SQL semantics."""

    # The expected projection contains no string literals. Removing only
    # comments, identifier quotes, statement terminators, and whitespace keeps
    # predicates/operators/literals (notably ``WHERE 0``) fingerprint-visible.
    without_comments = re.sub(r"/\*.*?\*/", "", value, flags=re.DOTALL)
    without_comments = re.sub(r"--[^\r\n]*", "", without_comments)
    return re.sub(r"\s+", "", without_comments.replace("`", "")).rstrip(";").lower()


def _projection_target(create_query: str) -> str:
    normalized = _normalize_projection_sql(create_query)
    match = re.search(r"to(fusion\.[a-z0-9_]+?)(?=asselect|\()", normalized)
    return match.group(1) if match else ""


def _history_projection_fingerprint(
    engine: str,
    target: str,
    as_select: str,
) -> str:
    contract = canonical_json(
        {
            "schema": "fusion-correlation-detection-history-projection/v1",
            "engine": str(engine),
            "target": _normalize_projection_sql(str(target)),
            "select": _normalize_projection_sql(str(as_select)),
        }
    )
    return sha256(contract.encode("utf-8")).hexdigest()


def _normalize_sort_key(value: str) -> str:
    normalized = _normalize_projection_sql(value)
    if normalized.startswith("tuple(") and normalized.endswith(")"):
        normalized = normalized[6:-1]
    return normalized


def _integrity_constraint_contract(create_query: str) -> tuple[str, ...]:
    """Extract exact top-level CHECK declarations from SHOW CREATE output.

    A substring/name check is unsafe because ``expected_expression OR 1``
    contains the expected text while removing every guarantee.  Split the
    table declaration only at top-level commas (respecting nested functions
    and quoted literals), then compare complete normalized declarations.
    """

    normalized = _normalize_projection_sql(create_query)
    body_start = normalized.find("(")
    if body_start < 0:
        return ()
    depth = 0
    quoted = False
    escaped = False
    body_end = -1
    for index in range(body_start, len(normalized)):
        character = normalized[index]
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "'":
                # SQL also escapes a quote by doubling it.
                if index + 1 < len(normalized) and normalized[index + 1] == "'":
                    escaped = True
                else:
                    quoted = False
            continue
        if character == "'":
            quoted = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                body_end = index
                break
    if body_end < 0:
        return ()

    body = normalized[body_start + 1 : body_end]
    items: list[str] = []
    item_start = 0
    depth = 0
    quoted = False
    escaped = False
    for index, character in enumerate(body):
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "'":
                if index + 1 < len(body) and body[index + 1] == "'":
                    escaped = True
                else:
                    quoted = False
            continue
        if character == "'":
            quoted = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            items.append(body[item_start:index])
            item_start = index + 1
    items.append(body[item_start:])
    return tuple(sorted(item for item in items if item.startswith("constraint")))


def _normalize_engine_clause(value: str) -> str:
    normalized = _normalize_projection_sql(value)
    match = re.match(r"(.+?)(?=partitionby|orderby|primarykey|sampleby|ttl|settings|$)", normalized)
    return match.group(1).rstrip("()") if match else normalized.rstrip("()")


def _normalized_column_contract(
    columns: Sequence[Sequence[str]],
) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        (
            str(name),
            _normalize_projection_sql(str(column_type)),
            str(default_kind).upper(),
            _normalize_projection_sql(str(default_expression)),
        )
        for name, column_type, default_kind, default_expression in columns
    )


def _history_target_fingerprint(
    engine: str,
    engine_full: str,
    partition_key: str,
    sorting_key: str,
    primary_key: str,
    columns: Sequence[Sequence[str]],
    *,
    constraints: Sequence[str] = (),
    has_ttl: bool,
) -> str:
    contract = canonical_json(
        {
            "schema": "fusion-correlation-detection-history-target/v1",
            "engine": str(engine),
            "engine_full": _normalize_engine_clause(str(engine_full)),
            "partition_key": _normalize_projection_sql(str(partition_key)),
            "sorting_key": _normalize_sort_key(str(sorting_key)),
            "primary_key": _normalize_sort_key(str(primary_key)),
            "columns": _normalized_column_contract(columns),
            "constraints": tuple(
                sorted(_normalize_projection_sql(str(value)) for value in constraints)
            ),
            "has_ttl": bool(has_ttl),
        }
    )
    return sha256(contract.encode("utf-8")).hexdigest()


def _unevaluated_or_new_conflict_sql() -> str:
    """Keep new identities and newly discovered immutable source conflicts.

    The ledger is insert-once.  If a physical replay makes an already-ledgered
    logical source ID conflicting, the old successful evaluation must not hide
    that poison input or be overwritten.  Once that identity was originally
    ledgered as the same invalid conflict, exact replay is complete.
    """

    return (
        "WHERE empty(evaluated.input_id) OR ("
        "source.invalid_reason='conflicting_immutable_values' AND NOT ("
        "evaluated.evaluation_action='invalid_input' AND "
        "evaluated.reason_code='conflicting_immutable_values')) "
    )


def _link_table_and_columns(input_kind: str) -> tuple[str, tuple[str, ...]]:
    if input_kind == "detection":
        return "fusion.incident_detection_links", DETECTION_LINK_COLUMNS
    if input_kind == "event":
        return "fusion.incident_event_links", EVENT_LINK_COLUMNS
    raise ValueError(f"unsupported evidence-link input kind: {input_kind!r}")


def _link_row(
    link: EvidenceLink, linked_at: datetime, columns: Sequence[str]
) -> list[Any]:
    snapshot = link.snapshot
    values: dict[str, Any] = {
        "incident_id": link.incident_id,
        "detection_id": link.input_id,
        "event_uid": link.input_id,
        "link_id": link.link_id,
        "introduction_revision_token": link.introduction_revision_token,
        "relationship": link.relationship,
        "occurred_at": _utc(link.occurred_at),
        "observed_at": _utc(link.observed_at),
        "linked_at": _utc(linked_at),
        "correlation_rule_id": link.correlation_rule_id,
        "correlation_rule_version": link.correlation_rule_version,
        "correlation_scope_fingerprint": link.correlation_scope_fingerprint,
        "source_type": str(snapshot.get("source_type", "")),
        "detection_rule_id": str(snapshot.get("rule_id", "")),
        "detection_rule_name": str(snapshot.get("rule_name", "")),
        "severity": str(snapshot.get("severity", "")),
        "event_category": str(snapshot.get("event_category", "")),
        "event_action": str(snapshot.get("event_action", "")),
        "outcome": str(snapshot.get("outcome", "")),
        "service_name": str(snapshot.get("service_name", "")),
        "host_name": str(snapshot.get("host_name", "")),
        "user_name": str(snapshot.get("user_name", "")),
        "source_ip": str(snapshot.get("source_ip", "")),
        "destination_ip": str(snapshot.get("destination_ip", "")),
        "mitre_technique_ids": list(snapshot.get("mitre_technique_ids", ()) or ()),
        "summary": str(snapshot.get("summary", ""))[:512],
        "validation_id": str(snapshot.get("validation_id", "")),
    }
    return [values[column] for column in columns]


def _row_content(
    columns: Sequence[str], row: Sequence[Any], selected: Sequence[str]
) -> tuple[Any, ...]:
    values = dict(zip(columns, row, strict=True))
    return tuple(values[column] for column in selected)


def _content_equal(
    columns: Sequence[str], actual: Sequence[Any], expected: Sequence[Any]
) -> bool:
    if len(actual) != len(columns) or len(expected) != len(columns):
        return False
    return all(
        _normalized_content_value(left) == _normalized_content_value(right)
        for left, right in zip(actual, expected, strict=True)
    )


def _normalized_content_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, (list, tuple)):
        return tuple(_normalized_content_value(item) for item in value)
    return value


def _source_union_sql(
    compiled: CompiledRule,
    *,
    bounded_by_observation: bool = True,
    event_occurrence_bounds: bool = False,
) -> tuple[str, Mapping[str, Any]]:
    detection, event, parameters = _source_sql_parts(
        compiled,
        bounded_by_observation=bounded_by_observation,
        event_occurrence_bounds=event_occurrence_bounds,
    )
    if event is None:
        return detection, parameters
    return detection + " UNION ALL " + event, parameters


def _source_sql_parts(
    compiled: CompiledRule,
    *,
    bounded_by_observation: bool = True,
    event_occurrence_bounds: bool = False,
) -> tuple[str, str | None, Mapping[str, Any]]:
    detection = _logical_source_sql(
        input_kind="detection",
        table="fusion.correlation_detection_input_history",
        id_column="detection_id",
        occurred_column="source_event_time",
        observed_column="detected_at",
        tie_columns=("detected_at",),
        value_fields=DETECTION_VALUE_FIELDS,
        bounded_by_observation=bounded_by_observation,
    )
    event_selectors = [
        selector for selector in compiled.rule.selectors if selector.source == "event"
    ]
    if not event_selectors:
        return detection, None, {}
    # Compute the safe SQL prefilter over each complete physical row, then
    # aggregate it with the logical ID.  This retains a conflicted ID when any
    # one physical variant passes the non-canonical selector constraints;
    # canonical identity semantics and conflicted-variant proof remain Python.
    predicate_sql, parameters = _selector_predicates(event_selectors, field_prefix="")
    event = _logical_source_sql(
        input_kind="event",
        table="fusion.sysmon_events",
        id_column="event_uid",
        occurred_column="event_time",
        observed_column="ingested_at",
        tie_columns=("ingested_at",),
        value_fields=EVENT_VALUE_FIELDS,
        bounded_by_observation=bounded_by_observation,
        enrollment_predicate_sql=predicate_sql,
        candidate_predicate_sql=(
            "event_time >= {start:DateTime64(3)} AND "
            "event_time <= {end:DateTime64(3)}"
            if event_occurrence_bounds
            else ""
        ),
    )
    return detection, event, parameters


def _requires_python_event_filter(compiled: CompiledRule) -> bool:
    return any(
        predicate.field in _CANONICAL_SQL_FIELDS
        for selector in compiled.rule.selectors
        if selector.source == "event"
        for predicate in selector.predicates
    )


def _logical_source_sql(
    *,
    input_kind: str,
    table: str,
    id_column: str,
    occurred_column: str,
    observed_column: str,
    tie_columns: Sequence[str],
    value_fields: Sequence[str],
    bounded_by_observation: bool,
    enrollment_predicate_sql: str = "",
    candidate_predicate_sql: str = "",
) -> str:
    """Collapse a physical source ID into one deterministic, whole source row.

    Conflict detection covers the occurrence clock and every projected semantic
    field.  The selected tuple is taken as a unit, so an invalid duplicate ID
    can never be reconstructed from values belonging to different rows.
    Grouping happens before enrollment filtering. Detection inputs are read
    from the immutable correlation projection, so source-table replacement
    cannot erase their earliest observation or prior semantic variants.
    """

    semantic_columns = (occurred_column, *value_fields)
    semantic_tuple = "tuple(" + ", ".join(semantic_columns) + ")"
    tie_tuple = (
        "tuple(" + ", ".join((*tie_columns, f"toString({semantic_tuple})")) + ")"
    )
    selected_fields: list[str] = []
    position_by_field = {
        field: index for index, field in enumerate(semantic_columns, start=1)
    }
    for field in INPUT_VALUE_FIELDS:
        if field in position_by_field:
            selected_fields.append(
                f"tupleElement(canonical_row, {position_by_field[field]}) AS {field}"
            )
        else:
            selected_fields.append(_source_placeholder(field))
    enrollment_conditions: list[str] = []
    selector_aggregate = ""
    physical_source_filter = ""
    if bounded_by_observation:
        enrollment_conditions.append("observed_at >= {evaluation_floor:DateTime64(3)}")
    if enrollment_predicate_sql:
        selector_aggregate = (
            f", countIf({enrollment_predicate_sql}) AS selector_prefilter_count"
        )
        enrollment_conditions.append("selector_prefilter_count > 0")
        # Use the approved event shape only to discover candidate logical IDs.
        # The outer aggregate deliberately reads every physical variant for
        # those IDs so canonical MIN(observed_at), whole-row argMin selection,
        # and semantic-conflict detection retain their frozen meaning.  In
        # particular, a newer matching replay cannot hide an older pre-floor
        # observation, and a nonmatching conflicting variant remains visible.
        candidate_conditions: list[str] = []
        if bounded_by_observation:
            candidate_conditions.append(
                f"{observed_column} >= {{evaluation_floor:DateTime64(3)}}"
            )
        if candidate_predicate_sql:
            candidate_conditions.append(candidate_predicate_sql)
        candidate_conditions.append(enrollment_predicate_sql)
        physical_source_filter = (
            f" WHERE {id_column} IN (SELECT {id_column} FROM {table} PREWHERE "
            + " AND ".join(candidate_conditions)
            + f" GROUP BY {id_column})"
        )
    enrollment = (
        " WHERE " + " AND ".join(enrollment_conditions) if enrollment_conditions else ""
    )
    return (
        f"SELECT '{input_kind}' AS input_kind, input_id, "
        "tupleElement(canonical_row, 1) AS occurred_at, observed_at, "
        + ", ".join(selected_fields)
        + ", multiIf(empty(input_id), 'blank_input_id', "
        "tupleElement(canonical_row, 1) = toDateTime64(0, 3, 'UTC'), "
        "'missing_occurrence_time', semantic_variant_count != 1, "
        "'conflicting_immutable_values', '') AS invalid_reason FROM ("
        f"SELECT {id_column} AS input_id, min({observed_column}) AS observed_at, "
        f"argMin({semantic_tuple}, {tie_tuple}) AS canonical_row, "
        f"uniqExact({semantic_tuple}) AS semantic_variant_count"
        + selector_aggregate
        + f" FROM {table}"
        + physical_source_filter
        + " "
        f"GROUP BY {id_column}) AS logical_{input_kind}" + enrollment
    )


def _source_placeholder(field: str) -> str:
    if field == "mitre_technique_ids":
        return "CAST([], 'Array(String)') AS mitre_technique_ids"
    if field == "initiated":
        return "toUInt8(0) AS initiated"
    # fusion.detections.rule_version is String.  Keep it lossless; semantic
    # versions such as "1.2.0" must never be coerced to a correlation-rule UInt32.
    return f"'' AS {field}"


def _selector_predicates(
    selectors: Sequence[Selector], *, field_prefix: str = "event_source."
) -> tuple[str, Mapping[str, Any]]:
    parameters: dict[str, Any] = {}
    selector_sql: list[str] = []
    for selector_index, selector in enumerate(selectors):
        parts: list[str] = []
        for predicate_index, predicate in enumerate(selector.predicates):
            if predicate.field not in SELECTOR_SQL_FIELDS:
                raise ValueError(
                    f"selector field is not SQL-allowlisted: {predicate.field}"
                )
            field = f"{field_prefix}{predicate.field}"
            name = f"selector_{selector_index}_{predicate_index}"
            if predicate.field in _CANONICAL_SQL_FIELDS:
                # SQL is only an I/O prefilter.  Host/principal/IP/platform
                # equivalence is normative Python behavior and can be broader
                # than raw ClickHouse string equality (case, FQDN terminal dot,
                # principal syntax, and IPv4-mapped IPv6).  Other mandatory
                # event-selector fields still bound the source scan.
                parts.append("1")
                continue
            if predicate.operator == "exists":
                expected = 1 if bool(predicate.value) else 0
                parameters[name] = expected
                parts.append(f"(notEmpty(toString({field})) = {{{name}:UInt8}})")
            elif predicate.operator == "eq":
                parameters[name] = str(predicate.value)
                parts.append(f"toString({field}) = {{{name}:String}}")
            elif predicate.operator == "in":
                parameters[name] = [str(value) for value in predicate.value]
                parts.append(f"toString({field}) IN {{{name}:Array(String)}}")
            else:  # compiler validation should make this unreachable
                raise ValueError(f"unsupported selector operator: {predicate.operator}")
        selector_sql.append("(" + " AND ".join(parts) + ")")
    return "(" + " OR ".join(selector_sql) + ")", parameters


def _raw_event_variants_sql() -> str:
    selected_fields = [
        (field if field in EVENT_VALUE_FIELDS else _source_placeholder(field))
        for field in INPUT_VALUE_FIELDS
    ]
    return (
        "SELECT 'event' AS input_kind, event_uid AS input_id, "
        "event_time AS occurred_at, ingested_at AS observed_at, "
        + ", ".join(selected_fields)
        + ", '' AS invalid_reason FROM fusion.sysmon_events "
        "WHERE event_uid IN {ids:Array(String)} "
        "ORDER BY event_uid, ingested_at, toString(tuple("
        + ", ".join(("event_time", *EVENT_VALUE_FIELDS))
        + "))"
    )


def _input_rows(
    result: Any, compiled: CompiledRule | None = None
) -> list[InputEnvelope]:
    inputs: list[InputEnvelope] = []
    for row in _named_rows(result):
        values = {
            key: value
            for key, value in row.items()
            if key
            not in {
                "input_kind",
                "input_id",
                "occurred_at",
                "observed_at",
                "invalid_reason",
            }
        }
        item = InputEnvelope(
            str(row["input_kind"]),
            str(row["input_id"]),
            _utc(row["occurred_at"]),
            _utc(row["observed_at"]),
            values,
            str(row.get("invalid_reason", "")),
        )
        if compiled is not None and item.input_kind == "event":
            # The logical-row decoder cannot decide a conflicted event from
            # its deterministic display tuple.  Preserve it for the store's
            # bounded physical-variant proof instead of letting argMin choose
            # selector enrollment.  Context decoding subsequently excludes
            # invalid rows.
            if item.invalid_reason == "conflicting_immutable_values":
                inputs.append(item)
                continue
            event_selectors = (
                selector
                for selector in compiled.rule.selectors
                if selector.source == "event"
            )
            enrollment_item = InputEnvelope(
                item.input_kind,
                item.input_id,
                item.occurred_at,
                item.observed_at,
                item.values,
                "",
            )
            if not any(
                selector_matches(selector, enrollment_item)
                for selector in event_selectors
            ):
                continue
        inputs.append(item)
    return inputs


def _episode_from_row(row: Mapping[str, Any]) -> EpisodeState:
    scope = RuleScope(
        str(row["engine_id"]),
        str(row["correlation_rule_id"]),
        int(row["correlation_rule_version"]),
        str(row["correlation_scope_fingerprint"]),
    )
    return EpisodeState(
        scope,
        str(row["group_key_json"]),
        str(row["group_key_hash"]),
        str(row["episode_state_id"]),
        str(row["revision_token"]),
        canonical_json(list(row["canonical_qualifying_inputs"] or [])),
        str(row["episode_anchor_kind"]),
        str(row["episode_anchor_id"]),
        _utc(row["episode_anchor_time"]) if row["episode_anchor_time"] else None,
        _utc(row["episode_window_start"]),
        _utc(row["episode_window_end"]),
        str(row["active_incident_id"]),
        tuple(str(value) for value in row["owned_detection_ids"] or ()),
        tuple(str(value) for value in row["owned_event_uids"] or ()),
        _utc(row["last_input_observed_at"]),
        _utc(row["late_accept_until"]),
        int(row["collision_count"]),
        str(row["state_hash"]),
        _utc(row["updated_at"]),
        int(row["revision"]),
    )


def _incident_from_row(row: Mapping[str, Any]) -> IncidentRecord:
    """Decode persisted incident timestamps into aware UTC datetimes.

    clickhouse-connect may return DateTime64 values without ``tzinfo`` even
    when their server-side type declares UTC.  Normalize every incident clock
    at the adapter boundary so live reload/replay cannot mix naive persisted
    deadlines with aware source-event timestamps.
    """

    values = dict(row)
    for field in INCIDENT_DATETIME_FIELDS:
        value = values.get(field)
        if value is not None:
            values[field] = _utc(value)
    return IncidentRecord(values)


def _named_rows(result: Any) -> Iterable[dict[str, Any]]:
    names = list(result.column_names)
    for row in result.result_rows:
        yield dict(zip(names, row, strict=True))


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"expected datetime, got {type(value).__name__}")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.replace(microsecond=(value.microsecond // 1_000) * 1_000)


def _milliseconds(value: int):
    from datetime import timedelta

    return timedelta(milliseconds=value)
