from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from fusion_correlation.identity import (
    IdentityNormalizationError,
    OwnershipFact,
    canonical_group_json,
    canonical_host,
    canonical_ip,
    canonical_ip_set,
    canonical_ownership_ip,
    canonical_principal,
    canonical_stable_id,
    canonical_user,
    ownership_fact_matches,
    shared_owned_ips,
)


def test_windows_downlevel_principal_is_nfc_trimmed_and_casefolded():
    left = canonical_principal("  D\N{LATIN CAPITAL LETTER O WITH DIAERESIS}MAIN\\Alice  ", "WINDOWS")
    right = canonical_principal("d\N{LATIN SMALL LETTER O WITH DIAERESIS}main\\ALICE", "windows")
    assert left == right
    assert left is not None
    assert left.namespace == "downlevel"
    assert left.realm == "d\N{LATIN SMALL LETTER O WITH DIAERESIS}main"
    assert left.account == "alice"


def test_windows_upn_splits_at_final_at_and_preserves_namespace():
    principal = canonical_principal(" Part@Alice@EXAMPLE.COM ", "windows")
    assert principal is not None
    assert principal.namespace == "upn"
    assert principal.account == "part@alice"
    assert principal.realm == "example.com"


def test_downlevel_upn_and_bare_windows_principals_never_alias():
    keys = {
        canonical_user("DOMAIN\\Alice", "windows"),
        canonical_user("Alice@domain", "windows"),
        canonical_user("Alice", "windows"),
    }
    assert None not in keys
    assert len(keys) == 3


def test_windows_casefolds_but_linux_and_unknown_preserve_account_case():
    assert canonical_user("Alice", "windows") == canonical_user("alice", "windows")
    assert canonical_user("Alice", "linux") != canonical_user("alice", "linux")
    assert canonical_user("Alice", "other") != canonical_user("alice", "other")
    assert canonical_user("Alice", "windows") != canonical_user("Alice", "linux")


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "DOMAIN\\",
        "\\alice",
        "a\\b\\c",
        "DOMAIN \\alice",
        "alice @domain",
    ],
)
def test_empty_or_malformed_principals_are_ineligible(value):
    assert canonical_principal(value, "windows") is None


def test_hostname_case_and_one_terminal_dot_normalize_without_alias_inference():
    assert canonical_host(" Host.Example.COM. ") == "host.example.com"
    assert canonical_host("HOST.EXAMPLE.COM") == "host.example.com"
    assert canonical_host("host") != canonical_host("host.example.com")
    assert canonical_host("host.example.com..") is None
    assert canonical_host("h\N{LATIN SMALL LETTER O WITH DIAERESIS}st.example") is None


def test_stable_ids_remain_exact_and_case_sensitive():
    assert canonical_stable_id(" Detection-A ") == " Detection-A "
    assert canonical_stable_id("Detection-A") != canonical_stable_id("detection-a")
    assert canonical_stable_id("   ") is None
    assert json.loads(
        canonical_group_json(("rule_id",), {"rule_id": " Rule-A "})
    )["rule_id"] == " Rule-A "


def test_ipv4_mapped_ipv6_collapses_and_ipv6_is_canonical():
    assert canonical_ip("::ffff:192.0.2.4") == "192.0.2.4"
    assert canonical_ip("2001:0DB8:0:0::1") == "2001:db8::1"
    assert canonical_ip("fe80::1%eth0") is None
    assert canonical_ip("not-an-ip") is None


@pytest.mark.parametrize(
    "value",
    ["0.0.0.0", "127.0.0.1", "224.0.0.1", "::", "::1", "ff02::1", "fe80::1"],
)
def test_unsafe_addresses_cannot_prove_cross_host_ownership(value):
    assert canonical_ownership_ip(value) is None


def test_private_lab_ips_and_multiple_simultaneous_ips_remain_distinct():
    assert canonical_ownership_ip("192.168.186.129") == "192.168.186.129"
    assert canonical_ip_set(
        ["192.168.186.130", "192.168.186.129", "::ffff:192.168.186.129"],
        ownership=True,
    ) == ("192.168.186.129", "192.168.186.130")
    selected, all_shared = shared_owned_ips(
        ["192.168.186.130", "192.168.186.129"],
        ["192.168.186.129", "192.168.186.130"],
    )
    assert selected == "192.168.186.129"
    assert all_shared == ("192.168.186.129", "192.168.186.130")


def test_ownership_requires_host_ip_and_same_inclusive_occurrence_window():
    start = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)
    fact = OwnershipFact.create("ENDPOINT.example.", "192.168.186.129", "event-3", start)
    common = {
        "endpoint_host": "endpoint.example",
        "network_ips": ["198.51.100.2", "::ffff:192.168.186.129"],
        "window_milliseconds": 10 * 60 * 1_000,
    }
    assert ownership_fact_matches(
        fact,
        occurrence_times=(start + timedelta(minutes=2), start + timedelta(minutes=10)),
        **common,
    )
    assert not ownership_fact_matches(
        fact,
        occurrence_times=(
            start + timedelta(minutes=2),
            start + timedelta(minutes=10, milliseconds=1),
        ),
        **common,
    )
    assert not ownership_fact_matches(
        fact,
        endpoint_host="other.example",
        network_ips=common["network_ips"],
        occurrence_times=(start, start),
        window_milliseconds=common["window_milliseconds"],
    )
    assert not ownership_fact_matches(
        fact,
        endpoint_host=common["endpoint_host"],
        network_ips=["192.168.186.200"],
        occurrence_times=(start, start),
        window_milliseconds=common["window_milliseconds"],
    )


def test_group_json_is_schema_ordered_typed_and_rejects_empty_components():
    encoded = canonical_group_json(
        ("platform", "user_name", "host_name", "source_ip"),
        {
            "platform": "WINDOWS",
            "user_name": "DOMAIN\\Alice",
            "host_name": "Host.EXAMPLE.",
            "source_ip": "::ffff:192.0.2.4",
        },
    )
    assert list(json.loads(encoded)) == ["platform", "user_name", "host_name", "source_ip"]
    assert json.loads(encoded)["user_name"] == {
        "platform": "windows",
        "namespace": "downlevel",
        "realm": "domain",
        "account": "alice",
    }
    assert json.loads(encoded)["source_ip"] == "192.0.2.4"
    with pytest.raises(IdentityNormalizationError, match="host_name"):
        canonical_group_json(("host_name",), {"host_name": " "})
