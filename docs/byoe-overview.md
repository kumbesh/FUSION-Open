# BYOE — Bring Your Own EDR

> Keep your EDR. Bring the telemetry. Correlate everything.

BYOE means **Bring Your Own EDR**. It is FUSION-Open's model for using telemetry from an existing endpoint detection and response product alongside other security data. FUSION is a vendor-neutral security analytics, detection, correlation, and incident layer; it complements endpoint protection rather than replacing it.

BYOE is an integration approach, not a claim that every named vendor has a native or validated FUSION integration. A source is usable only after its events are transported, mapped into the approved FUSION schema, and verified. See the [compatibility matrix](byoe-compatibility-matrix.md) for evidence-scoped statuses.

## Why FUSION uses BYOE

Organizations should not need to remove a working endpoint control to evaluate cross-source analytics. BYOE keeps the existing EDR in its operational role while giving selected telemetry a common place to be normalized, analyzed, and related to network and system activity.

The existing EDR or security product remains responsible for:

- prevention;
- malware blocking;
- endpoint isolation;
- sensor deployment and management; and
- vendor-native remediation and response.

FUSION provides:

- telemetry normalization into a common schema;
- detection enrichment through reviewed, repository-managed rules;
- bounded cross-source correlation;
- durable incident creation and evidence links;
- Grafana dashboards; and
- a future path for asset, inventory, health, and posture enrichment.

Transport acceptance does not by itself enable analytics. The fields needed by a detection or correlation rule must be present in the normalized event, and suspiciousness must be established by a reviewed detection before an event can create or contribute suspicious weight to an incident.

## Architecture

```text
Existing EDRs / Security Tools
        ↓
Webhook / JSON / Syslog / API
        ↓
FUSION ingestion
        ↓
Vector normalization
        ↓
ClickHouse
        ↓
Detection
        ↓
Correlation
        ↓
Incidents
        ↓
Grafana
```

The diagram shows the target BYOE flow, not equal implementation status for every transport. Generic HTTP JSON at `POST /security` and RFC 3164/5424 syslog over TCP or UDP are current ingestion paths. Vendor REST API connectors are a future design; FUSION-Open does not currently ship one. The current HTTP and syslog inputs are unauthenticated and are suitable only for an isolated, firewall-restricted lab or controlled pilot. See the [integration guide](byoe-integration-guide.md) and [security policy](../SECURITY.md).

## Vendor examples

Potential BYOE telemetry sources include Microsoft Defender, CrowdStrike Falcon, SentinelOne, Wazuh, and other EDR or security products. These names illustrate the vendor-neutral model only. They do not mean that FUSION currently ships, validates, or supports a vendor API connector, response action, or complete vendor-specific field mapping.

Until a vendor path has explicit repository evidence, treat it as planned. A vendor may still be evaluated by exporting an event through a supported generic format and mapping it to the [generic BYOE JSON contract](byoe-generic-json-schema.md), but that validates the mapped format—not the vendor product as a whole.

## Correlation value: current and future

The current v0.6 rule set includes this narrowly defined, experimental cross-source scenario:

```text
Suricata detection
        +
Windows endpoint detection
        +
time-valid initiated Sysmon network event proving host/IP ownership
        ↓
existing v0.6 Suricata/endpoint correlation rule
        ↓
one FUSION incident
```

All three inputs must satisfy the rule's normalized-field, identity, and time-window requirements. A generic vendor alert is not automatically interchangeable with the Windows inputs.

A broader BYOE outcome could look like this:

```text
Normalized EDR endpoint alert
        +
Suricata network alert
        +
Linux authentication activity
        ↓
future reviewed detection and correlation mappings
        ↓
one FUSION incident
```

That three-source example is a future concept, not a current v0.6 capability. Before a vendor-specific EDR shape can participate, its useful fields must normalize into the approved FUSION schema and any suspicious event must match a reviewed detection rule. Raw or merely stored telemetry never creates an event-only incident.

## Beta guidance

> **Beta warning:** FUSION-Open should complement, not replace, existing endpoint protection.

The current BYOE workflow has:

- no automated endpoint isolation;
- no vendor response actions or native remediation;
- no production service-level agreement;
- no high availability, load balancing, or broker;
- no full enterprise role-based access control or multi-tenancy; and
- unauthenticated HTTP ingestion and plaintext, unauthenticated syslog.

Use the current deployment for labs, evaluation, and controlled pilots on an isolated network. Do not send real credentials or sensitive production telemetry to the sample environment. Apply the firewall and binding controls in the [security policy](../SECURITY.md).

A conservative beta rollout is:

| Stage | Suggested scope | Gate to expand |
| --- | ---: | --- |
| Initial beta | 5–25 endpoints | Confirm field mapping, event volume, retention, detection quality, and operational ownership. |
| Expanded beta | 25–100 endpoints | Measure ingestion, backlog, storage, dashboard, and recovery behavior under representative load. |
| Larger evaluation | More than 100 endpoints | Proceed only after environment-specific capacity, reliability, security, and recovery validation. |

These ranges are rollout guidance, not supported-capacity or throughput claims.

## Future connector model

The following structure is a roadmap proposal. The directories and vendor connectors shown here are not current implementation:

```text
integrations/
  generic-edr/
  wazuh/
  microsoft-defender/
  crowdstrike/
  sentinelone/
```

Two connector classes are proposed:

1. **Event connectors** collect alerts and detections through a webhook, syslog feed, event stream, or checkpointed API, then emit the shared `/security` envelope. They preserve the original vendor evidence and normalize only the fields needed for analytics.
2. **Context connectors** collect assets, sensor health, device posture, vulnerabilities, and inventory. This context can support future entity and asset enrichment, but it must not be treated as suspicious evidence or silently establish identity relationships.

This roadmap is intended to align with future v0.7 asset/entity work. It does not mean those capabilities or schedules are implemented. Any future API connector must also satisfy the state, retry, rate-limit, deduplication, secret-handling, TLS, and review controls in the [future API connector framework](api-connectors.md).

## Continue with BYOE

- [Choose and verify an integration path](byoe-integration-guide.md)
- [Map a payload to the generic JSON contract](byoe-generic-json-schema.md)
- [Check current compatibility and evidence](byoe-compatibility-matrix.md)
