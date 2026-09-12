"""Bounded ClickHouse access for events, detections, and checkpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

import clickhouse_connect

from .config import Settings
from .models import (
    BacklogStatus,
    Checkpoint,
    CycleStats,
    DetectionCandidate,
    EvaluationScope,
)


EVENT_COLUMNS = (
    "event_uid",
    "event_time",
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
    "source_event_id",
    "validation_id",
)

DETECTION_COLUMNS = (
    "detection_id",
    "detected_at",
    "updated_at",
    "rule_id",
    "rule_name",
    "rule_description",
    "rule_source",
    "rule_version",
    "severity",
    "status",
    "platform",
    "vendor",
    "product",
    "source_type",
    "host_name",
    "user_name",
    "process_name",
    "process_path",
    "command_line",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "signature",
    "signature_id",
    "mitre_tactics",
    "mitre_techniques",
    "mitre_technique_ids",
    "source_event_uid",
    "source_event_id",
    "source_event_time",
    "validation_id",
    "evidence_json",
    "rule_metadata_json",
)

CHECKPOINT_TELEMETRY_COLUMNS = (
    "engine_id",
    "ruleset_fingerprint",
    "checkpoint_time",
    "checkpoint_uid",
    "evaluation_floor_time",
    "newest_eligible_event_time",
    "newest_eligible_event_uid",
    "checkpoint_lag_events",
    "checkpoint_lag_seconds",
    "unevaluated_event_count",
    "oldest_unevaluated_event_time",
    "oldest_unevaluated_age_seconds",
    "events_evaluated",
    "new_events_processed",
    "late_events_processed",
    "processing_duration_seconds",
    "evaluated_events_per_second",
    "updated_at",
)

EVALUATION_LEDGER_COLUMNS = (
    "engine_id",
    "ruleset_fingerprint",
    "event_uid",
    "event_time",
    "evaluated_at",
    "source_type",
    "host_name",
    "validation_id",
)

EVALUATION_SCOPE_COLUMNS = (
    "engine_id",
    "ruleset_fingerprint",
    "evaluation_floor_time",
    "candidate_cursor_time",
    "candidate_cursor_uid",
    "updated_at",
)


class ClickHouseStore:
    def __init__(
        self,
        settings: Settings,
        client: Any | None = None,
        ruleset_fingerprint: str = "unscoped",
    ):
        self.settings = settings
        self.ruleset_fingerprint = ruleset_fingerprint
        self.client = client or clickhouse_connect.get_client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            username=settings.clickhouse_user,
            password=settings.clickhouse_password,
            database=settings.clickhouse_database,
            connect_timeout=10,
            send_receive_timeout=30,
            settings={"wait_for_async_insert": 1},
        )

    def healthcheck(self) -> None:
        self.client.command("SELECT 1")
        wait_for_async_insert = self.client.command(
            "SELECT getSetting('wait_for_async_insert')"
        )
        if str(wait_for_async_insert).strip().lower() not in {"1", "true"}:
            raise RuntimeError(
                "ClickHouse wait_for_async_insert must be enabled for detection write ordering"
            )
        columns = ", ".join(CHECKPOINT_TELEMETRY_COLUMNS)
        self.client.query(f"SELECT {columns} FROM fusion.detection_checkpoints LIMIT 0")
        ledger_columns = ", ".join(EVALUATION_LEDGER_COLUMNS)
        self.client.query(
            f"SELECT {ledger_columns} FROM fusion.detection_evaluated_events LIMIT 0"
        )
        scope_columns = ", ".join(EVALUATION_SCOPE_COLUMNS)
        self.client.query(
            f"SELECT {scope_columns} FROM fusion.detection_evaluation_scopes LIMIT 0"
        )

    def load_checkpoint(self) -> Checkpoint | None:
        result = self.client.query(
            "SELECT maxOrNull(event_time), "
            "argMaxOrNull(event_uid, tuple(event_time, event_uid)) FROM ("
            "SELECT checkpoint_time AS event_time, checkpoint_uid AS event_uid "
            "FROM fusion.detection_checkpoints FINAL "
            "WHERE engine_id = {engine_id:String} "
            "UNION ALL "
            "SELECT event_time, event_uid "
            "FROM fusion.detection_evaluated_events "
            "WHERE engine_id = {engine_id:String} "
            "AND ruleset_fingerprint = {ruleset_fingerprint:String})",
            parameters={
                "engine_id": self.settings.engine_id,
                "ruleset_fingerprint": self.ruleset_fingerprint,
            },
        )
        if not result.result_rows or result.result_rows[0][0] is None:
            return None
        event_time, event_uid = result.result_rows[0]
        return Checkpoint(_utc(event_time), str(event_uid))

    def load_evaluation_scope(self) -> EvaluationScope | None:
        result = self.client.query(
            "SELECT evaluation_floor_time, candidate_cursor_time, candidate_cursor_uid "
            "FROM fusion.detection_evaluation_scopes FINAL "
            "WHERE engine_id = {engine_id:String} "
            "AND ruleset_fingerprint = {ruleset_fingerprint:String} LIMIT 1",
            parameters={
                "engine_id": self.settings.engine_id,
                "ruleset_fingerprint": self.ruleset_fingerprint,
            },
        )
        if not result.result_rows:
            return None
        evaluation_floor_time, candidate_cursor_time, candidate_cursor_uid = (
            result.result_rows[0]
        )
        candidate_cursor = (
            Checkpoint(_utc(candidate_cursor_time), str(candidate_cursor_uid))
            if candidate_cursor_time is not None
            else None
        )
        return EvaluationScope(_utc(evaluation_floor_time), candidate_cursor)

    def load_legacy_evaluation_floor(self) -> datetime | None:
        """Read the v0.5.2 draft floor once when upgrading an exercised 007."""
        result = self.client.query(
            "SELECT evaluation_floor_time "
            "FROM fusion.detection_checkpoints FINAL "
            "WHERE engine_id = {engine_id:String} "
            "AND ruleset_fingerprint = {ruleset_fingerprint:String} "
            "AND evaluation_floor_time IS NOT NULL LIMIT 1",
            parameters={
                "engine_id": self.settings.engine_id,
                "ruleset_fingerprint": self.ruleset_fingerprint,
            },
        )
        if not result.result_rows:
            return None
        return _utc(result.result_rows[0][0])

    def initialize_evaluation_floor(
        self, checkpoint: Checkpoint, evaluation_floor_time: datetime
    ) -> None:
        updated_at = datetime.now(timezone.utc)
        self.client.insert(
            "fusion.detection_evaluation_scopes",
            [[
                self.settings.engine_id,
                self.ruleset_fingerprint,
                evaluation_floor_time,
                None,
                "",
                updated_at,
            ]],
            column_names=list(EVALUATION_SCOPE_COLUMNS),
        )
        self.client.insert(
            "fusion.detection_checkpoints",
            [[
                self.settings.engine_id,
                self.ruleset_fingerprint,
                checkpoint.event_time,
                checkpoint.event_uid,
                evaluation_floor_time,
                updated_at,
            ]],
            column_names=[
                "engine_id",
                "ruleset_fingerprint",
                "checkpoint_time",
                "checkpoint_uid",
                "evaluation_floor_time",
                "updated_at",
            ],
        )

    def save_candidate_cursor(
        self, evaluation_floor_time: datetime, candidate_cursor: Checkpoint
    ) -> None:
        self.client.insert(
            "fusion.detection_evaluation_scopes",
            [[
                self.settings.engine_id,
                self.ruleset_fingerprint,
                evaluation_floor_time,
                candidate_cursor.event_time,
                candidate_cursor.event_uid,
                datetime.now(timezone.utc),
            ]],
            column_names=list(EVALUATION_SCOPE_COLUMNS),
        )

    def save_checkpoint(self, stats: CycleStats) -> None:
        checkpoint = stats.checkpoint
        backlog = stats.backlog
        if stats.evaluation_floor_time is None:
            raise ValueError("evaluation_floor_time is required for checkpoint persistence")
        self.client.insert(
            "fusion.detection_checkpoints",
            [[
                self.settings.engine_id,
                self.ruleset_fingerprint,
                checkpoint.event_time,
                checkpoint.event_uid,
                stats.evaluation_floor_time,
                backlog.newest_event_time,
                backlog.newest_event_uid,
                backlog.lag_events,
                backlog.lag_seconds,
                backlog.unevaluated_events,
                backlog.oldest_unevaluated_event_time,
                backlog.oldest_unevaluated_age_seconds,
                stats.events_evaluated,
                stats.new_events_processed,
                stats.late_events_processed,
                stats.processing_duration_seconds,
                stats.evaluated_events_per_second,
                datetime.now(timezone.utc),
            ]],
            column_names=[
                "engine_id",
                "ruleset_fingerprint",
                "checkpoint_time",
                "checkpoint_uid",
                "evaluation_floor_time",
                "newest_eligible_event_time",
                "newest_eligible_event_uid",
                "checkpoint_lag_events",
                "checkpoint_lag_seconds",
                "unevaluated_event_count",
                "oldest_unevaluated_event_time",
                "oldest_unevaluated_age_seconds",
                "events_evaluated",
                "new_events_processed",
                "late_events_processed",
                "processing_duration_seconds",
                "evaluated_events_per_second",
                "updated_at",
            ],
        )

    def fetch_unevaluated_events(
        self,
        evaluation_floor_time: datetime,
        candidate_cursor: Checkpoint | None = None,
    ) -> list[dict[str, Any]]:
        columns = ", ".join(f"source.{column} AS {column}" for column in EVENT_COLUMNS)
        result = self.client.query(
            f"SELECT {columns} FROM fusion.sysmon_events AS source "
            "LEFT ANTI JOIN ("
            "SELECT event_uid FROM fusion.detection_evaluated_events FINAL "
            "WHERE engine_id = {engine_id:String} "
            "AND ruleset_fingerprint = {ruleset_fingerprint:String} GROUP BY event_uid"
            ") AS evaluated ON source.event_uid = evaluated.event_uid "
            "WHERE source.event_time >= {evaluation_floor_time:DateTime64(3)} "
            "OR source.ingested_at >= {evaluation_floor_time:DateTime64(3)} "
            "ORDER BY if({candidate_cursor_present:UInt8} = 1 AND "
            "(source.event_time < {candidate_cursor_time:DateTime64(3)} OR "
            "(source.event_time = {candidate_cursor_time:DateTime64(3)} AND "
            "source.event_uid <= {candidate_cursor_uid:String})), 1, 0) ASC, "
            "source.event_time ASC, source.event_uid ASC, source.ingested_at ASC "
            "LIMIT 1 BY source.event_uid LIMIT {batch_size:UInt32}",
            parameters={
                "engine_id": self.settings.engine_id,
                "ruleset_fingerprint": self.ruleset_fingerprint,
                "evaluation_floor_time": evaluation_floor_time,
                "candidate_cursor_present": int(candidate_cursor is not None),
                "candidate_cursor_time": (
                    candidate_cursor.event_time
                    if candidate_cursor is not None
                    else evaluation_floor_time
                ),
                "candidate_cursor_uid": (
                    candidate_cursor.event_uid if candidate_cursor is not None else ""
                ),
                "batch_size": self.settings.batch_size,
            },
        )
        # LIMIT BY already provides logical uniqueness. Keep this defensive
        # collapse for test doubles and future query changes.
        unique_rows = []
        seen_uids = set()
        for row in _named_rows(result):
            event_uid = str(row["event_uid"])
            if event_uid in seen_uids:
                continue
            seen_uids.add(event_uid)
            unique_rows.append(row)
        return unique_rows

    def mark_events_evaluated(self, events: Iterable[Mapping[str, Any]]) -> int:
        unique_events: dict[str, Mapping[str, Any]] = {}
        for event in events:
            event_uid = str(event.get("event_uid", ""))
            if not event_uid:
                raise ValueError("event_uid is required for evaluation ledger identity")
            unique_events.setdefault(event_uid, event)
        if not unique_events:
            return 0
        evaluated_at = datetime.now(timezone.utc)
        rows = [
            [
                self.settings.engine_id,
                self.ruleset_fingerprint,
                event_uid,
                event["event_time"],
                evaluated_at,
                str(event.get("source_type", "") or ""),
                str(event.get("host_name", "") or ""),
                str(event.get("validation_id", "") or ""),
            ]
            for event_uid, event in unique_events.items()
        ]
        self.client.insert(
            "fusion.detection_evaluated_events",
            rows,
            column_names=list(EVALUATION_LEDGER_COLUMNS),
        )
        return len(rows)

    def fetch_backlog_status(
        self, checkpoint: Checkpoint, evaluation_floor_time: datetime
    ) -> BacklogStatus:
        parameters = {
            "engine_id": self.settings.engine_id,
            "ruleset_fingerprint": self.ruleset_fingerprint,
            "evaluation_floor_time": evaluation_floor_time,
            "checkpoint_time": checkpoint.event_time,
            "checkpoint_uid": checkpoint.event_uid,
        }
        source_result = self.client.query(
            "SELECT maxOrNull(event_time), "
            "argMaxOrNull(event_uid, tuple(event_time, event_uid)), "
            "uniqExactIf(event_uid, event_time > {checkpoint_time:DateTime64(3)} "
            "OR (event_time = {checkpoint_time:DateTime64(3)} "
            "AND event_uid > {checkpoint_uid:String})) "
            "FROM fusion.sysmon_events "
            "WHERE event_time >= {evaluation_floor_time:DateTime64(3)} "
            "OR ingested_at >= {evaluation_floor_time:DateTime64(3)}",
            parameters=parameters,
        )
        newest_time, newest_uid, positional_lag = source_result.result_rows[0]
        newest = _utc(newest_time) if newest_time is not None else None

        ledger_result = self.client.query(
            "SELECT uniqExact(source.event_uid), minOrNull(source.event_time) "
            "FROM fusion.sysmon_events AS source "
            "LEFT ANTI JOIN ("
            "SELECT event_uid FROM fusion.detection_evaluated_events FINAL "
            "WHERE engine_id = {engine_id:String} "
            "AND ruleset_fingerprint = {ruleset_fingerprint:String} GROUP BY event_uid"
            ") AS evaluated ON source.event_uid = evaluated.event_uid "
            "WHERE source.event_time >= {evaluation_floor_time:DateTime64(3)} "
            "OR source.ingested_at >= {evaluation_floor_time:DateTime64(3)}",
            parameters=parameters,
        )
        unevaluated_events, oldest_time = ledger_result.result_rows[0]
        oldest = _utc(oldest_time) if oldest_time is not None else None
        oldest_age = (
            max(0.0, (datetime.now(timezone.utc) - oldest).total_seconds())
            if oldest is not None
            else 0.0
        )
        return BacklogStatus(
            newest,
            str(newest_uid or ""),
            int(positional_lag or 0),
            (
                max(0.0, (newest - checkpoint.event_time).total_seconds())
                if newest is not None
                else 0.0
            ),
            int(unevaluated_events or 0),
            oldest,
            oldest_age,
        )

    def fetch_recent_events(self, since: datetime, limit: int) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(limit, self.settings.batch_size, 10000))
        columns = ", ".join(EVENT_COLUMNS)
        result = self.client.query(
            f"SELECT {columns} FROM fusion.sysmon_events "
            "WHERE event_time >= {since:DateTime64(3)} "
            "ORDER BY event_time DESC, event_uid DESC LIMIT {limit:UInt32}",
            parameters={"since": since, "limit": bounded_limit},
        )
        return _named_rows(result)

    def existing_detection_ids(self, detection_ids: Iterable[str]) -> set[str]:
        identifiers = sorted(set(detection_ids))
        existing: set[str] = set()
        for offset in range(0, len(identifiers), 1000):
            chunk = identifiers[offset : offset + 1000]
            result = self.client.query(
                "SELECT detection_id FROM fusion.detections FINAL "
                "WHERE detection_id IN {detection_ids:Array(String)}",
                parameters={"detection_ids": chunk},
            )
            existing.update(str(row[0]) for row in result.result_rows)
        return existing

    def insert_detections(self, candidates: Iterable[DetectionCandidate]) -> int:
        rows = [[candidate.values[column] for column in DETECTION_COLUMNS] for candidate in candidates]
        if not rows:
            return 0
        self.client.insert("fusion.detections", rows, column_names=list(DETECTION_COLUMNS))
        return len(rows)

    def insert_fixture_events(self, events: Iterable[Mapping[str, Any]]) -> int:
        columns = (
            "event_time", "event_id", "event_type", "computer", "record_id", "process_guid",
            "platform", "source_type", "host_name", "source_event_id", "event_code",
            "event_category", "event_action", "event_kind", "vendor", "product", "user_name",
            "user_id", "process_name", "process_path", "command_line", "parent_process_name",
            "parent_process_id", "service_name", "outcome", "severity", "source_ip", "source_port",
            "destination_ip", "destination_port", "destination_hostname", "protocol", "query_name",
            "domain", "signature", "signature_id", "url", "network_direction",
            "ingestion_protocol", "ingestion_path", "syslog_application", "syslog_facility",
            "validation_id", "raw_json",
        )
        numeric = {"event_id", "record_id", "parent_process_id", "source_port", "destination_port"}
        rows = []
        for event in events:
            row = []
            for column in columns:
                if column == "event_time":
                    value = event[column]
                elif column in numeric:
                    value = int(event.get(column, 0) or 0)
                else:
                    value = str(event.get(column, "") or "")
                row.append(value)
            rows.append(row)
        if rows:
            self.client.insert("fusion.sysmon_events", rows, column_names=list(columns))
        return len(rows)


def _named_rows(result: Any) -> list[dict[str, Any]]:
    names = tuple(str(name) for name in result.column_names)
    rows: list[dict[str, Any]] = []
    for raw in result.result_rows:
        row = dict(zip(names, raw, strict=True))
        row["event_time"] = _utc(row["event_time"])
        rows.append(row)
    return rows


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
