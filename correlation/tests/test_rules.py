from __future__ import annotations

import re

from fusion_correlation.compiler import validate_rule_directory

EXPECTED = {
    "fusion-correlation-ssh-bruteforce-success": {
        "kind": "sequence",
        "severity": "high",
        "confidence": 90,
        "tactics": ("TA0006",),
        "techniques": ("T1110",),
    },
    "fusion-correlation-host-suspicious-activity": {
        "kind": "threshold",
        "severity": "medium",
        "confidence": 70,
        "tactics": (),
        "techniques": (),
    },
    "fusion-correlation-suricata-endpoint": {
        "kind": "join",
        "severity": "high",
        "confidence": 85,
        "tactics": (),
        "techniques": (),
    },
    "fusion-correlation-user-suspicious-activity": {
        "kind": "threshold",
        "severity": "medium",
        "confidence": 70,
        "tactics": (),
        "techniques": (),
    },
}


def test_repository_contains_exactly_four_frozen_valid_rules(rules_dir, compiler):
    result = validate_rule_directory(rules_dir, compiler)
    assert result.total == 4
    assert result.valid == 4
    assert result.invalid == 0
    assert {rule.rule_id for rule in result.rules} == set(EXPECTED)


def test_frozen_rule_scoring_mitre_and_condition_types(rules_dir, compiler):
    result = validate_rule_directory(rules_dir, compiler)
    for compiled in result.rules:
        expected = EXPECTED[compiled.rule_id]
        assert compiled.version == 1
        assert compiled.rule.status == "experimental"
        assert compiled.condition_kind == expected["kind"]
        assert compiled.rule.incident.severity == expected["severity"]
        assert compiled.rule.incident.confidence == expected["confidence"]
        assert compiled.rule.mitre.tactic_ids == expected["tactics"]
        assert compiled.rule.mitre.technique_ids == expected["techniques"]
        assert re.fullmatch(r"[0-9a-f]{64}", compiled.scope_fingerprint)


def test_semantic_plans_are_bounded_data_and_never_executable_sql(rules_dir, compiler):
    result = validate_rule_directory(rules_dir, compiler)
    for compiled in result.rules:
        plan = compiled.plan()
        serialized = repr(plan).casefold()
        assert "raw_json" not in serialized
        assert "evidence_json" not in serialized
        assert "select " not in serialized
        assert "insert " not in serialized
        assert "query" not in plan
        assert "sql" not in plan
        assert plan["time_semantics"]["correlation_clock"] == "occurred_at"
        assert plan["time_semantics"]["visibility_clock"] == "observed_at"
        assert plan["time_semantics"]["window_boundary"] == "inclusive"
        assert plan["normalized_field_contract"]["event_selector_fields"]
        identity = plan["identity_normalization_contract"]
        assert identity["ownership"]["timeless_cache"] is False
        assert identity["ownership"]["window"] == (
            "same-inclusive-rule-window-for-fact-and-both-detections"
        )
        assert identity["ip"]["ownership_ineligible"] == [
            "invalid",
            "unspecified",
            "loopback",
            "multicast",
            "link-local",
        ]
        assert plan["incident_scoring_contract"]["events_raise_severity"] is False
        assert re.fullmatch(
            r"[0-9a-f]{64}",
            plan["mitre_technique_tactic_mapping"]["bytes_sha256"],
        )


def test_cross_source_rule_requires_direction_safe_ownership_fact(rules_dir, compiler):
    compiled = next(
        rule
        for rule in validate_rule_directory(rules_dir, compiler).rules
        if rule.rule_id == "fusion-correlation-suricata-endpoint"
    )
    plan = compiled.plan()
    assert plan["group_by"] == ["shared_ip", "host_name"]
    assert plan["selectors"]["endpoint_identity"] == {
        "source": "event",
        "where": [
            {"field": "event_code", "op": "eq", "value": "3"},
            {"field": "initiated", "op": "eq", "value": 1},
            {"field": "source_type", "op": "eq", "value": "windows_sysmon"},
        ],
    }
    assert {
        (item["left"], item["op"], item["right"])
        for item in plan["correlate"]["relations"]
    } == {
        (
            "endpoint_detection.host_name",
            "equals",
            "endpoint_identity.host_name",
        ),
        (
            "network_alert.ip_set",
            "intersects",
            "endpoint_identity.local_ip_set",
        ),
    }


def test_event_inputs_only_supply_approved_facts(rules_dir, compiler):
    rules = validate_rule_directory(rules_dir, compiler).rules
    event_selectors = [
        selector
        for compiled in rules
        for selector in compiled.rule.selectors
        if selector.source == "event"
    ]
    assert {selector.name for selector in event_selectors} == {"success", "endpoint_identity"}
    for selector in event_selectors:
        assert all(
            predicate.field not in {"severity", "rule_id", "mitre_tactic_ids", "mitre_technique_ids"}
            for predicate in selector.predicates
        )
    for compiled in rules:
        assert any(selector.source == "detection" for selector in compiled.rule.selectors)
