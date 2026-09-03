"""Rule evaluation and deterministic detection construction."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from .compiler import CompiledRule
from .models import DetectionCandidate, RuleValidationError


EVIDENCE_CONTEXT_FIELDS = (
    "event_time",
    "event_id",
    "event_code",
    "event_category",
    "event_action",
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
    "domain",
    "signature",
    "signature_id",
)


def detection_identity(rule_id: str, source_event_uid: str) -> str:
    material = f"{rule_id}\0{source_event_uid}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class DetectionEvaluator:
    def __init__(self, rules: Iterable[CompiledRule], mitre_mapping_path: Path):
        self.rules = tuple(rules)
        self.mitre = _load_mitre_mapping(mitre_mapping_path)

    def evaluate(self, event: Mapping[str, Any], detected_at: datetime | None = None) -> list[DetectionCandidate]:
        source_uid = str(event.get("event_uid", ""))
        if not source_uid:
            raise ValueError("event_uid is required for deterministic detection identity")
        now = detected_at or datetime.now(timezone.utc)
        candidates: list[DetectionCandidate] = []
        for compiled in self.rules:
            result = compiled.evaluate(event)
            if not result.matched:
                continue
            tactics, techniques, technique_ids = self._attack_metadata(compiled.rule.tags)
            evidence = {
                "source_event_uid": source_uid,
                "matched_selections": list(result.selections),
                "matched_fields": result.fields,
                "event_context": {
                    field: event.get(field)
                    for field in EVIDENCE_CONTEXT_FIELDS
                    if event.get(field) not in (None, "")
                },
            }
            metadata = {
                "author": compiled.rule.author,
                "date": compiled.rule.date,
                "modified": compiled.rule.modified,
                "references": list(compiled.rule.references),
                "tags": list(compiled.rule.tags),
                "logsource": dict(compiled.rule.logsource),
                "path": str(compiled.rule.path),
            }
            values = {
                "detection_id": detection_identity(compiled.rule.rule_id, source_uid),
                "detected_at": now,
                "updated_at": now,
                "rule_id": compiled.rule.rule_id,
                "rule_name": compiled.rule.title,
                "rule_description": compiled.rule.description,
                "rule_source": "fusion-sigma",
                "rule_version": compiled.rule.version,
                "severity": compiled.rule.level,
                "status": "new",
                "platform": _text(event, "platform"),
                "vendor": _text(event, "vendor"),
                "product": _text(event, "product"),
                "source_type": _text(event, "source_type"),
                "host_name": _text(event, "host_name"),
                "user_name": _text(event, "user_name"),
                "process_name": _text(event, "process_name"),
                "process_path": _text(event, "process_path"),
                "command_line": _text(event, "command_line"),
                "source_ip": _text(event, "source_ip"),
                "source_port": _port(event, "source_port"),
                "destination_ip": _text(event, "destination_ip"),
                "destination_port": _port(event, "destination_port"),
                "protocol": _text(event, "protocol"),
                "signature": _text(event, "signature"),
                "signature_id": _text(event, "signature_id"),
                "mitre_tactics": tactics,
                "mitre_techniques": techniques,
                "mitre_technique_ids": technique_ids,
                "source_event_uid": source_uid,
                "source_event_id": _text(event, "source_event_id"),
                "source_event_time": event["event_time"],
                "validation_id": _text(event, "validation_id"),
                "evidence_json": json.dumps(evidence, default=str, sort_keys=True, separators=(",", ":")),
                "rule_metadata_json": json.dumps(metadata, default=str, sort_keys=True, separators=(",", ":")),
            }
            candidates.append(DetectionCandidate(values["detection_id"], now, values))
        return candidates

    def _attack_metadata(self, tags: tuple[str, ...]) -> tuple[list[str], list[str], list[str]]:
        tactics: list[str] = []
        technique_ids: list[str] = []
        techniques: list[str] = []
        tactic_mapping = self.mitre["tactics"]
        technique_mapping = self.mitre["techniques"]
        for tag in tags:
            lowered = tag.casefold()
            if not lowered.startswith("attack."):
                continue
            value = lowered.removeprefix("attack.")
            if re_is_technique(value):
                identifier = value.upper()
                if identifier not in technique_ids:
                    technique_ids.append(identifier)
                    techniques.append(technique_mapping.get(value, identifier))
            elif value in tactic_mapping:
                tactic = tactic_mapping[value]
                if tactic not in tactics:
                    tactics.append(tactic)
        return tactics, techniques, technique_ids


def re_is_technique(value: str) -> bool:
    if not value.startswith("t"):
        return False
    base, separator, sub = value[1:].partition(".")
    return len(base) == 4 and base.isdigit() and (not separator or (len(sub) == 3 and sub.isdigit()))


def _load_mitre_mapping(path: Path) -> Mapping[str, Mapping[str, str]]:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise RuleValidationError(f"MITRE mapping must be a YAML mapping: {path}")
    result: dict[str, dict[str, str]] = {}
    for section in ("tactics", "techniques"):
        values = raw.get(section, {})
        if not isinstance(values, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()):
            raise RuleValidationError(f"MITRE {section} mapping must contain string pairs")
        result[section] = {key.casefold(): value for key, value in values.items()}
    return result


def _text(event: Mapping[str, Any], field: str) -> str:
    value = event.get(field, "")
    return "" if value is None else str(value)


def _port(event: Mapping[str, Any], field: str) -> int:
    try:
        value = int(event.get(field, 0) or 0)
    except (TypeError, ValueError):
        return 0
    return value if 0 <= value <= 65535 else 0
