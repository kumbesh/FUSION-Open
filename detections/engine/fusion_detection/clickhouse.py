"""Bounded ClickHouse access for events, detections, and checkpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

import clickhouse_connect

from .config import Settings
from .models import Checkpoint, DetectionCandidate


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


class ClickHouseStore:
    def __init__(self, settings: Settings, client: Any | None = None):
        self.settings = settings
        self.client = client or clickhouse_connect.get_client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            username=settings.clickhouse_user,
            password=settings.clickhouse_password,
            database=settings.clickhouse_database,
            connect_timeout=10,
            send_receive_timeout=30,
        )

    def healthcheck(self) -> None:
        self.client.command("SELECT 1")

    def load_checkpoint(self) -> Checkpoint | None:
        result = self.client.query(
            "SELECT checkpoint_time, checkpoint_uid "
            "FROM fusion.detection_checkpoints FINAL "
            "WHERE engine_id = {engine_id:String} LIMIT 1",
            parameters={"engine_id": self.settings.engine_id},
        )
        if not result.result_rows:
            return None
        event_time, event_uid = result.result_rows[0]
        return Checkpoint(_utc(event_time), str(event_uid))

    def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        self.client.insert(
            "fusion.detection_checkpoints",
            [[self.settings.engine_id, checkpoint.event_time, checkpoint.event_uid, datetime.now(timezone.utc)]],
            column_names=["engine_id", "checkpoint_time", "checkpoint_uid", "updated_at"],
        )

    def fetch_new_events(self, checkpoint: Checkpoint) -> list[dict[str, Any]]:
        columns = ", ".join(EVENT_COLUMNS)
        result = self.client.query(
            f"SELECT {columns} FROM fusion.sysmon_events "
            "WHERE event_time > {checkpoint_time:DateTime64(3)} "
            "OR (event_time = {checkpoint_time:DateTime64(3)} AND event_uid > {checkpoint_uid:String}) "
            "ORDER BY event_time ASC, event_uid ASC LIMIT {batch_size:UInt32}",
            parameters={
                "checkpoint_time": checkpoint.event_time,
                "checkpoint_uid": checkpoint.event_uid,
                "batch_size": self.settings.batch_size,
            },
        )
        return _named_rows(result)

    def fetch_late_events(self, checkpoint: Checkpoint) -> list[dict[str, Any]]:
        if self.settings.lookback_seconds == 0:
            return []
        start = checkpoint.event_time - timedelta(seconds=self.settings.lookback_seconds)
        columns = ", ".join(EVENT_COLUMNS)
        result = self.client.query(
            f"SELECT {columns} FROM fusion.sysmon_events "
            "WHERE event_time >= {start_time:DateTime64(3)} "
            "AND (event_time < {checkpoint_time:DateTime64(3)} "
            "OR (event_time = {checkpoint_time:DateTime64(3)} AND event_uid <= {checkpoint_uid:String})) "
            "ORDER BY event_time DESC, event_uid DESC LIMIT {batch_size:UInt32}",
            parameters={
                "start_time": start,
                "checkpoint_time": checkpoint.event_time,
                "checkpoint_uid": checkpoint.event_uid,
                "batch_size": self.settings.batch_size,
            },
        )
        return _named_rows(result)

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
