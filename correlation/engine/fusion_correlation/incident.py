"""Deterministic incident, episode, link, and revision construction."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from .identity import canonical_host, canonical_ip
from .runtime_models import EvidenceLink, IncidentRecord, InputEnvelope, RuleScope


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_EVIDENCE_MEMBERS = 256
MAX_EVIDENCE_JSON_BYTES = 32768


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_parts(namespace: str, *parts: object) -> str:
    material = "\0".join([namespace, *(str(part) for part in parts)])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def group_identity(group: Mapping[str, Any]) -> tuple[str, str]:
    # Group mappings are built in the rule's declared ``group_by`` order, and
    # nested typed principal mappings are likewise schema-ordered.  Preserve
    # that order in the incident identity preimage; generic state/evidence JSON
    # continues to use key sorting through ``canonical_json``.
    group_json = json.dumps(
        group,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return group_json, hashlib.sha256(group_json.encode("utf-8")).hexdigest()


def evaluation_token(scope: RuleScope, item: InputEnvelope) -> str:
    return sha256_parts(
        "fusion-correlation-evaluation-v1",
        scope.engine_id,
        scope.rule_id,
        scope.rule_version,
        scope.fingerprint,
        item.input_kind,
        item.input_id,
    )


def scope_bootstrap_token(scope: RuleScope) -> str:
    return sha256_parts(
        "fusion-correlation-scope-bootstrap-v1",
        scope.engine_id,
        scope.rule_id,
        scope.rule_version,
        scope.fingerprint,
    )


def episode_state_identity(
    scope: RuleScope,
    group_key_json: str,
    earliest: InputEnvelope,
) -> str:
    return sha256_parts(
        "fusion-correlation-episode-state-v1",
        scope.engine_id,
        scope.rule_id,
        scope.rule_version,
        scope.fingerprint,
        group_key_json,
        earliest.input_kind,
        earliest.input_id,
    )


def incident_identity(
    scope: RuleScope,
    group_key_json: str,
    anchor: InputEnvelope,
) -> str:
    return sha256_parts(
        "fusion-incident-v1",
        scope.rule_id,
        scope.rule_version,
        scope.fingerprint,
        group_key_json,
        f"{anchor.input_kind}:{anchor.input_id}",
    )


def link_identity(
    incident_id: str,
    input_kind: str,
    input_id: str,
) -> str:
    return sha256_parts(
        "fusion-incident-link-v1", incident_id, input_kind, input_id
    )


def state_hash(values: Mapping[str, Any], excluded: Iterable[str] = ()) -> str:
    ignored = {
        "updated_at",
        "revision",
        "state_hash",
        "revision_token",
        *excluded,
    }
    stable = {key: value for key, value in values.items() if key not in ignored}
    return hashlib.sha256(
        canonical_json(_jsonable(stable)).encode("utf-8")
    ).hexdigest()


def build_links(
    scope: RuleScope,
    incident_id: str,
    members: Sequence[InputEnvelope],
    qualifying_tagged_ids: frozenset[str],
    anchor: InputEnvelope,
    revision_token: str,
) -> tuple[EvidenceLink, ...]:
    links: list[EvidenceLink] = []
    for item in sorted(_unique_inputs(members), key=lambda value: value.order_key):
        if item.tagged_id == anchor.tagged_id:
            relationship = "trigger"
        elif item.tagged_id in qualifying_tagged_ids:
            relationship = "supporting"
        else:
            relationship = "context"
        snapshot = _snapshot(item)
        links.append(
            EvidenceLink(
                incident_id=incident_id,
                input_kind=item.input_kind,
                input_id=item.input_id,
                link_id=link_identity(incident_id, item.input_kind, item.input_id),
                introduction_revision_token=revision_token,
                relationship=relationship,
                occurred_at=item.occurred_at,
                observed_at=item.observed_at,
                correlation_rule_id=scope.rule_id,
                correlation_rule_version=scope.rule_version,
                correlation_scope_fingerprint=scope.fingerprint,
                snapshot=snapshot,
            )
        )
    return tuple(links)


def build_incident(
    *,
    scope: RuleScope,
    rule_info: Mapping[str, Any],
    group: Mapping[str, Any],
    qualifying: Sequence[InputEnvelope],
    members: Sequence[InputEnvelope],
    anchor: InputEnvelope,
    window_seconds: int,
    allowed_lateness_seconds: int,
    revision_token: str,
    now: datetime | None = None,
    existing: IncidentRecord | None = None,
    technique_to_tactics: Mapping[str, Sequence[str]] | None = None,
) -> tuple[IncidentRecord, tuple[EvidenceLink, ...]]:
    """Build one complete deterministic incident snapshot from authoritative links."""

    current_time = _utc(now or datetime.now(timezone.utc))
    logical_members = sorted(_unique_inputs(members), key=lambda value: value.order_key)
    logical_qualifying = sorted(
        _unique_inputs(qualifying), key=lambda value: value.order_key
    )
    if not logical_members or not logical_qualifying:
        raise ValueError("incident membership and qualifying set must be nonempty")
    if len(logical_members) > MAX_EVIDENCE_MEMBERS:
        raise OverflowError(
            f"incident evidence exceeds {MAX_EVIDENCE_MEMBERS} members"
        )
    detections = [item for item in logical_members if item.input_kind == "detection"]
    events = [item for item in logical_members if item.input_kind == "event"]
    if not detections:
        raise ValueError("every incident must contain at least one detection")

    group_json, group_hash = group_identity(group)
    identity = incident_identity(scope, group_json, anchor)
    prior_evidence: Mapping[str, Any] = {}
    if existing is not None:
        try:
            decoded = json.loads(str(existing.values.get("evidence_json", "{}")))
            if isinstance(decoded, Mapping):
                prior_evidence = decoded
        except (TypeError, ValueError, json.JSONDecodeError):
            prior_evidence = {}
    canonical_qualifying_ids = (
        tuple(str(value) for value in prior_evidence.get("qualifying_input_ids", ()))
        if existing is not None
        else tuple(item.tagged_id for item in logical_qualifying)
    )
    qualifying_ids = frozenset(canonical_qualifying_ids)
    links = build_links(
        scope,
        identity,
        logical_members,
        qualifying_ids,
        anchor,
        revision_token,
    )

    detection_severities = {
        str(item.values.get("severity", "")).casefold()
        for item in detections
        if str(item.values.get("severity", "")).casefold() in SEVERITY_RANK
    }
    base_severity = str(rule_info["severity"]).casefold()
    if base_severity not in SEVERITY_RANK:
        raise ValueError(f"unsupported rule severity: {base_severity!r}")
    severity = max(
        {base_severity, *detection_severities},
        key=lambda value: SEVERITY_RANK[value],
    )

    technique_ids = sorted(
        {
            *[str(value) for value in rule_info.get("technique_ids", ())],
            *[
                str(value)
                for item in detections
                for value in item.values.get("mitre_technique_ids", ()) or ()
            ],
        }
    )
    tactic_ids = set(str(value) for value in rule_info.get("tactic_ids", ()))
    mapping = technique_to_tactics or {}
    for technique_id in technique_ids:
        tactic_ids.update(str(value) for value in mapping.get(technique_id, ()))

    previous = dict(existing.values) if existing is not None else {}
    if existing is not None:
        window_start = _utc(previous["episode_window_start"])
        window_end = _utc(previous["episode_window_end"])
    else:
        window_start = min(item.occurred_at for item in logical_qualifying)
        window_end = window_start + timedelta(seconds=window_seconds)
    first_seen = min(item.occurred_at for item in logical_members)
    last_seen = max(item.occurred_at for item in logical_members)
    latest_observed = max(item.observed_at for item in logical_members)
    status = str(previous.get("status", "new"))
    closed_at = previous.get("closed_at")
    late_accept_until = (
        _utc(previous["late_accept_until"])
        if existing is not None
        else window_end + timedelta(seconds=allowed_lateness_seconds)
    )
    prior_ids = set(prior_evidence.get("member_ids", ()))
    newly_late = sum(
        1
        for item in logical_members
        if item.tagged_id not in prior_ids and item.observed_at > window_end
    )
    late_member_count = int(previous.get("late_update_count", 0)) + newly_late
    ownership_provenance = [
        dict(value)
        for value in prior_evidence.get("ownership_provenance", ())
        if isinstance(value, Mapping)
    ]
    shared_ip_values = {
        str(value)
        for value in prior_evidence.get("shared_ip_intersection", ())
        if str(value)
    }
    if "shared_ip" in group:
        for item in events:
            if (
                str(item.values.get("source_type", "")) == "windows_sysmon"
                and str(item.values.get("event_code", "")) == "3"
                and str(item.values.get("initiated", "")) in {"1", "True", "true"}
            ):
                ownership_provenance.append(
                    {
                        "evidence_event_uid": item.input_id,
                        "host_name": canonical_host(
                            item.values.get("host_name")
                        ),
                        "local_ip": canonical_ip(
                            item.values.get("source_ip")
                        ),
                        "normalized_field": "source_ip",
                        "source_type": "windows_sysmon",
                        "occurred_at": item.occurred_at.isoformat(),
                    }
                )
        shared_ip_values.update(
            normalized
            for item in events
            if (normalized := canonical_ip(item.values.get("source_ip"))) is not None
        )
    ownership_provenance = [
        json.loads(value)
        for value in sorted(
            {canonical_json(value) for value in ownership_provenance}
        )
    ]
    shared_ip_intersection = sorted(shared_ip_values)
    validation_values = {
        str(item.values.get("validation_id", ""))
        for item in logical_members
        if str(item.values.get("validation_id", ""))
    }
    validation_id = (
        next(iter(validation_values)) if len(validation_values) == 1 else ""
    )
    primary = rule_info.get("primary", {})
    evidence = {
        "schema": "fusion-incident-evidence/v1",
        "rule_id": scope.rule_id,
        "rule_version": scope.rule_version,
        "rule_fingerprint": scope.fingerprint,
        "condition_type": str(rule_info["condition_type"]),
        "condition": rule_info.get("condition", {}),
        "group": group,
        "window_seconds": window_seconds,
        "qualifying_input_ids": list(canonical_qualifying_ids),
        "member_ids": [item.tagged_id for item in logical_members],
        "anchor": {
            "kind": anchor.input_kind,
            "id": anchor.input_id,
            "occurred_at": anchor.occurred_at.isoformat(),
        },
        "counts": {
            "inputs": len(logical_members),
            "detections": len(detections),
            "events": len(events),
            "distinct_detection_rules": len(
                {
                    str(item.values.get("rule_id", ""))
                    for item in detections
                    if str(item.values.get("rule_id", ""))
                }
            ),
        },
        "severity": {
            "rule": base_severity,
            "highest_detection": max(
                detection_severities or {"low"},
                key=lambda value: SEVERITY_RANK[value],
            ),
            "incident": severity,
        },
        "confidence": int(rule_info["confidence"]),
        "late_update": late_member_count > 0,
        "lateness": {
            "latest_observed_at": latest_observed.isoformat(),
            "accept_until": late_accept_until.isoformat(),
            "late_member_count": late_member_count,
            "max_observed_after_window_seconds": max(
                0.0,
                max(
                    (item.observed_at - window_end).total_seconds()
                    for item in logical_members
                ),
            ),
        },
        "ownership_provenance": ownership_provenance[:16],
        "shared_ip_intersection": shared_ip_intersection[:16],
        "false_positives": list(rule_info.get("false_positives", ()))[:16],
    }
    evidence_json = canonical_json(evidence)
    if len(evidence_json.encode("utf-8")) > MAX_EVIDENCE_JSON_BYTES:
        raise OverflowError("bounded incident evidence_json exceeds 32768 bytes")

    created_at = _utc(previous.get("created_at", current_time))
    values: dict[str, Any] = {
        "incident_id": identity,
        "incident_title": _render_title(str(rule_info["title"]), group),
        "incident_type": str(rule_info["type"]),
        "status": status,
        "severity": severity,
        "severity_rank": SEVERITY_RANK[severity],
        "confidence": int(rule_info["confidence"]),
        "created_at": created_at,
        "updated_at": current_time,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "acknowledged_at": previous.get("acknowledged_at"),
        "closed_at": closed_at,
        "last_transition_id": str(previous.get("last_transition_id", "")),
        "last_transition_from": str(previous.get("last_transition_from", "")),
        "last_transition_at": previous.get("last_transition_at"),
        "primary_host": _primary_value(primary, "host", group, logical_members),
        "primary_user": _primary_value(primary, "user", group, logical_members),
        "primary_source_ip": _primary_value(
            primary, "source_ip", group, logical_members
        ),
        "primary_destination_ip": _primary_value(
            primary, "destination_ip", group, logical_members
        ),
        "input_count": len(logical_members),
        "detection_count": len(detections),
        "event_count": len(events),
        "distinct_detection_rule_count": len(
            {
                str(item.values.get("rule_id", ""))
                for item in detections
                if str(item.values.get("rule_id", ""))
            }
        ),
        "source_family_count": len(
            {_source_family(str(item.values.get("source_type", ""))) for item in logical_members}
        ),
        "mitre_tactic_ids": sorted(tactic_ids),
        "mitre_technique_ids": technique_ids,
        "correlation_rule_id": scope.rule_id,
        "correlation_rule_version": scope.rule_version,
        "correlation_scope_fingerprint": scope.fingerprint,
        "group_key_json": group_json,
        "group_key_hash": group_hash,
        "episode_anchor_kind": anchor.input_kind,
        "episode_anchor_id": anchor.input_id,
        "episode_anchor_time": anchor.occurred_at,
        "episode_window_start": window_start,
        "episode_window_end": window_end,
        "last_evidence_observed_at": latest_observed,
        "late_accept_until": late_accept_until,
        "late_update_count": late_member_count,
        "revision": int(previous.get("revision", 0)) + 1,
        "revision_source": "correlation_input",
        "revision_token": revision_token,
        "evidence_json": evidence_json,
        "validation_id": validation_id,
    }
    values["state_hash"] = state_hash(values)
    return IncidentRecord(values), links


def _unique_inputs(values: Sequence[InputEnvelope]) -> list[InputEnvelope]:
    unique: dict[str, InputEnvelope] = {}
    for item in values:
        prior = unique.get(item.tagged_id)
        if prior is None or item.observed_at < prior.observed_at:
            unique[item.tagged_id] = item
    return list(unique.values())


def _snapshot(item: InputEnvelope) -> Mapping[str, Any]:
    if item.input_kind == "detection":
        keys = (
            "source_type",
            "rule_id",
            "rule_name",
            "severity",
            "host_name",
            "user_name",
            "source_ip",
            "destination_ip",
            "mitre_technique_ids",
            "validation_id",
        )
    else:
        keys = (
            "source_type",
            "event_category",
            "event_action",
            "outcome",
            "service_name",
            "host_name",
            "user_name",
            "source_ip",
            "destination_ip",
            "validation_id",
        )
    result = {key: item.values.get(key, "") for key in keys}
    if item.input_kind == "detection":
        result["summary"] = str(item.values.get("rule_name", ""))[:512]
    else:
        category = str(item.values.get("event_category", ""))
        action = str(item.values.get("event_action", ""))
        result["summary"] = f"{category}: {action}".strip(": ")[:512]
    return result


def _primary_value(
    primary: Mapping[str, Any],
    name: str,
    group: Mapping[str, Any],
    members: Sequence[InputEnvelope],
) -> str:
    source_field = str(primary.get(name, name))
    group_value = group.get(source_field)
    if group_value not in (None, ""):
        return _display_group_value(group_value)
    values = sorted(
        {
            str(item.values.get(source_field, ""))
            for item in members
            if str(item.values.get(source_field, ""))
        }
    )
    return values[0] if values else ""


def _render_title(template: str, group: Mapping[str, Any]) -> str:
    rendered = template
    for key, value in group.items():
        rendered = rendered.replace("{" + key + "}", _display_group_value(value))
    if "{" in rendered or "}" in rendered:
        raise ValueError("incident title contains an unresolved placeholder")
    return rendered[:512]


def _display_group_value(value: Any) -> str:
    if isinstance(value, Mapping):
        namespace = str(value.get("namespace", ""))
        account = str(value.get("account", ""))
        realm = str(value.get("realm", ""))
        if namespace == "downlevel" and realm and account:
            return f"{realm}\\{account}"
        if namespace == "upn" and realm and account:
            return f"{account}@{realm}"
        if namespace == "bare" and account:
            return account
        return canonical_json(value)
    return str(value)


def _source_family(source_type: str) -> str:
    value = source_type.casefold()
    if value.startswith("windows"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    if value.startswith("suricata"):
        return "suricata"
    return value or "unknown"


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc(value).isoformat()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"expected datetime, got {type(value).__name__}")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.replace(microsecond=(value.microsecond // 1_000) * 1_000)
