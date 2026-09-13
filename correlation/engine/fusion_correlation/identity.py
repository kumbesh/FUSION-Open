"""Frozen Fusion v0.6 identity and ownership canonicalization.

Display values remain available in source evidence.  These helpers produce the
typed canonical values used only for grouping, equality, and deterministic
identity hashes.  They deliberately do not invent host aliases, principal
aliases, NAT relationships, DHCP history, or a timeless host-to-IP cache.
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

IDENTITY_NORMALIZATION_VERSION = "fusion-identity-v1"

# Fingerprint input.  Changing any behavior below requires changing this
# contract and therefore every affected correlation semantic fingerprint.
IDENTITY_NORMALIZATION_CONTRACT: Mapping[str, Any] = {
    "version": IDENTITY_NORMALIZATION_VERSION,
    "stable_ids": {
        "normalization": "none",
        "case_sensitive": True,
        "invalid": ["empty", "whitespace-only"],
    },
    "principals": {
        "unicode": "NFC",
        "outer_whitespace": "trim",
        "windows": {
            "case": "casefold-realm-and-account",
            "downlevel": "split-one-backslash-realm-account",
            "upn": "split-final-at-account-realm",
            "bare": "typed-bare-account",
            "namespace_aliasing": "none",
        },
        "linux": "typed-bare-case-sensitive",
        "unknown_platform": "typed-platform-and-bare-case-sensitive",
    },
    "hostname": {
        "unicode": "NFC",
        "whitespace": "trim",
        "alphabet": "ASCII-DNS-display-subset",
        "case": "lower",
        "terminal_dot": "remove-exactly-one",
        "short_fqdn_aliasing": "none",
    },
    "ip": {
        "parser": "typed-ip-address",
        "ipv4": "dotted-decimal",
        "ipv6": "compressed-lowercase",
        "ipv4_mapped_ipv6": "collapse-to-ipv4",
        "zone_scoped": "invalid",
        "ownership_ineligible": [
            "invalid",
            "unspecified",
            "loopback",
            "multicast",
            "link-local",
        ],
        "private_lab_addresses": "eligible",
    },
    "multi_ip": {
        "facts": "separate-immutable-observations",
        "intersection": "sorted-unique-canonical-addresses",
        "shared_ip": "lexical-lowest-intersection-member",
    },
    "ownership": {
        "fact": [
            "canonical_host",
            "canonical_local_ip",
            "evidence_event_uid",
            "occurred_at",
        ],
        "source": "direction-safe-approved-endpoint-event",
        "clock": "occurred_at-utc-milliseconds",
        "window": "same-inclusive-rule-window-for-fact-and-both-detections",
        "timeless_cache": False,
    },
    "group_key": {
        "encoding": "canonical-json",
        "field_order": "schema-declared",
        "typed_values": True,
        "missing_required_component": "ineligible-no-global-group",
    },
}

_HOST_CHARS = re.compile(r"^[A-Za-z0-9_.-]+$")


class IdentityNormalizationError(ValueError):
    """A required identity cannot be represented by the frozen contract."""


@dataclass(frozen=True)
class CanonicalPrincipal:
    platform: str
    namespace: str
    account: str
    realm: str = ""

    @property
    def key(self) -> str:
        """Return an unambiguous, typed canonical principal serialization."""

        return json.dumps(
            [self.platform, self.namespace, self.realm, self.account],
            ensure_ascii=False,
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class OwnershipFact:
    """One immutable point-in-time endpoint host/local-IP observation."""

    canonical_host: str
    canonical_local_ip: str
    evidence_event_uid: str
    occurred_at: datetime

    @classmethod
    def create(
        cls,
        host_name: object,
        local_ip: object,
        evidence_event_uid: object,
        occurred_at: datetime,
    ) -> OwnershipFact:
        host = canonical_host(host_name)
        address = canonical_ownership_ip(local_ip)
        event_uid = canonical_stable_id(evidence_event_uid)
        if host is None:
            raise IdentityNormalizationError("ownership host is blank or invalid")
        if address is None:
            raise IdentityNormalizationError("ownership local IP cannot prove a cross-host join")
        if event_uid is None:
            raise IdentityNormalizationError("ownership evidence event UID is blank")
        return cls(host, address, event_uid, _utc_millis(occurred_at))


def canonical_stable_id(value: object) -> str | None:
    """Preserve case and bytes apart from rejecting a blank identity."""

    if not isinstance(value, str) or not value or value.strip() == "":
        return None
    return value


def canonical_host(value: object) -> str | None:
    """Normalize hostname case/trailing-dot variants without alias inference."""

    text = _normalized_nonblank(value)
    if text is None or not text.isascii():
        return None
    text = text.removesuffix(".")
    if not text or len(text) > 253 or not _HOST_CHARS.fullmatch(text):
        return None
    if text.endswith(".") or ".." in text:
        return None
    return text.lower()


def canonical_principal(value: object, platform: object) -> CanonicalPrincipal | None:
    """Return a platform-aware typed principal, preserving namespace syntax."""

    text = _normalized_nonblank(value)
    platform_text = _normalized_nonblank(platform)
    if text is None or platform_text is None:
        return None
    platform_key = platform_text.casefold()

    if platform_key == "windows":
        if "\\" in text:
            if text.count("\\") != 1:
                return None
            realm, account = text.split("\\", 1)
            realm = _principal_component(realm)
            account = _principal_component(account)
            if realm is None or account is None:
                return None
            return CanonicalPrincipal(
                "windows", "downlevel", account.casefold(), realm.casefold()
            )
        if "@" in text:
            account, realm = text.rsplit("@", 1)
            account = _principal_component(account)
            realm = _principal_component(realm)
            if account is None or realm is None:
                return None
            return CanonicalPrincipal("windows", "upn", account.casefold(), realm.casefold())
        return CanonicalPrincipal("windows", "bare", text.casefold())

    if platform_key == "linux":
        return CanonicalPrincipal("linux", "bare", text)
    return CanonicalPrincipal(platform_key, "bare", text)


def canonical_user(value: object, platform: object) -> str | None:
    """Return the stable serialized principal key used by group hashing."""

    principal = canonical_principal(value, platform)
    return principal.key if principal is not None else None


def canonical_ip(value: object) -> str | None:
    """Parse an address and collapse IPv4-mapped IPv6 to dotted IPv4."""

    text = _normalized_nonblank(value)
    if text is None or "%" in text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return address.compressed.lower()


def canonical_ownership_ip(value: object) -> str | None:
    """Return an IP only when it may prove an endpoint ownership join."""

    canonical = canonical_ip(value)
    if canonical is None:
        return None
    address = ipaddress.ip_address(canonical)
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
        return None
    return canonical


def canonical_ip_set(values: Iterable[object], *, ownership: bool = False) -> tuple[str, ...]:
    """Return a sorted unique typed address set, excluding invalid entries."""

    normalizer = canonical_ownership_ip if ownership else canonical_ip
    return tuple(sorted({value for item in values if (value := normalizer(item)) is not None}))


def shared_owned_ips(
    network_values: Iterable[object], local_values: Iterable[object]
) -> tuple[str | None, tuple[str, ...]]:
    """Return the canonical selected shared IP and complete bounded intersection."""

    network = set(canonical_ip_set(network_values, ownership=True))
    local = set(canonical_ip_set(local_values, ownership=True))
    intersection = tuple(sorted(network & local))
    return (intersection[0] if intersection else None), intersection


def ownership_fact_matches(
    fact: OwnershipFact,
    *,
    endpoint_host: object,
    network_ips: Iterable[object],
    occurrence_times: Sequence[datetime],
    window_milliseconds: int,
) -> bool:
    """Prove host/IP ownership inside one inclusive occurrence-time window.

    The caller must pass the endpoint detection and network detection occurrence
    times.  The immutable ownership fact supplies the third time.  No ingestion
    timestamp participates in this decision.
    """

    host = canonical_host(endpoint_host)
    if host is None or host != fact.canonical_host or window_milliseconds < 0:
        return False
    network = canonical_ip_set(network_ips, ownership=True)
    if fact.canonical_local_ip not in network:
        return False
    try:
        times = [_utc_millis(value) for value in occurrence_times]
    except (IdentityNormalizationError, TypeError, ValueError):
        return False
    times.append(fact.occurred_at)
    if len(times) < 3:
        return False
    return max(times) - min(times) <= timedelta(milliseconds=window_milliseconds)


def canonical_group_json(group_by: Sequence[str], values: Mapping[str, Any]) -> str:
    """Build schema-ordered typed group JSON or reject a missing component."""

    result: dict[str, Any] = {}
    for field in group_by:
        raw = values.get(field)
        if field == "host_name":
            canonical: Any = canonical_host(raw)
        elif field == "user_name":
            principal = canonical_principal(raw, values.get("platform"))
            canonical = (
                {
                    "platform": principal.platform,
                    "namespace": principal.namespace,
                    "realm": principal.realm,
                    "account": principal.account,
                }
                if principal is not None
                else None
            )
        elif field in {"source_ip", "destination_ip", "shared_ip"}:
            canonical = canonical_ip(raw)
        elif field == "platform":
            text = _normalized_nonblank(raw)
            canonical = text.casefold() if text is not None else None
        elif field == "rule_id":
            canonical = canonical_stable_id(raw)
        else:
            canonical = _normalized_nonblank(raw)
        if canonical is None:
            raise IdentityNormalizationError(f"required group component {field!r} is blank or invalid")
        result[field] = canonical
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"))


def _normalized_nonblank(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized or any(unicodedata.category(char) == "Cc" for char in normalized):
        return None
    return normalized


def _principal_component(value: str) -> str | None:
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized
        or normalized != normalized.strip()
        or any(unicodedata.category(char) == "Cc" for char in normalized)
    ):
        return None
    return normalized


def _utc_millis(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise IdentityNormalizationError("occurrence time must be timezone-aware")
    utc = value.astimezone(UTC)
    return utc.replace(microsecond=(utc.microsecond // 1_000) * 1_000)
