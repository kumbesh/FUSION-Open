# BYOE generic JSON contract

This document defines the current, vendor-neutral JSON contract for sending endpoint-security telemetry to FUSION-Open. It describes the v0.6 implementation as it exists today; it is not a claim that any named EDR vendor has been validated.

Use the existing endpoint:

```text
POST /security
Content-Type: application/json
```

The default local URL is `http://127.0.0.1:8686/security`. The receiver is plaintext and unauthenticated, so keep it on localhost or a source-restricted isolated lab network. Do not expose it directly to the Internet.

## Contract layers

A BYOE request has three distinct layers:

1. **Envelope identity** describes the sending vendor, product, source type, platform, and endpoint or sensor.
2. **Normalized candidates** are fields the current `/security` normalizer can promote into columns in `fusion.sysmon_events`.
3. **Vendor-native evidence** remains inside `event` and is retained as part of the generated `raw_json`, even when it has no first-class FUSION column yet.

The request must be a JSON object with a top-level `event` object. A flat payload without `event`, or a request whose `event` value is not an object, is rejected from the normalization pipeline.

FUSION generates `raw_json`; senders should not construct or overwrite that field. For HTTP JSON, it is a re-encoded representation of the decoded request object and may also contain receiver-added transport metadata. It preserves the payload's JSON content for investigation and reprocessing, but it is not a byte-for-byte copy of the original HTTP body.

## Current envelope

This is the recommended shape for a useful endpoint alert:

```json
{
  "vendor": "ExampleEDR",
  "product": "Endpoint Security",
  "source_type": "example_edr",
  "platform": "windows",
  "host_name": "WIN-LAPTOP-01",
  "device_name": "WIN-LAPTOP-01",
  "event": {
    "id": "example-edr-01HZZY7G4BA9",
    "timestamp": "2026-09-14T10:15:30.123Z",
    "event_kind": "alert",
    "event_category": "endpoint_detection",
    "event_action": "endpoint_alert",
    "severity": "high",
    "outcome": "unknown",
    "rule_id": "EDR-123",
    "signature_id": "EDR-123",
    "signature": "Suspicious endpoint activity"
  }
}
```

In the tables below, **Required** means required by this interoperability contract, not necessarily enforced by the receiver. The current runtime enforces only the JSON object shape and the presence of an `event` object. Defaults allow less complete events to be stored, but those defaults can hide source identity, replace a missing or invalid occurrence time with collector time, and prevent useful filtering or correlation.

## Field matrix

### Envelope and event identity

| BYOE field | Contract level | Send at | Current normalized output | Current behavior |
|---|---|---|---|---|
| `vendor` | Required | Top level | `vendor` | String; defaults to `generic` when absent. |
| `product` | Required | Top level | `product` | String; defaults to `generic` when absent. |
| `source_type` | Required | Top level | `source_type` | Use a stable, lower-case integration identifier such as `example_edr`; defaults to `generic_json`. A new value does not automatically gain detection rules. |
| `platform` | Recommended | Top level | `platform` | Use the source platform, such as `windows`, `linux`, `macos`, or `cloud`; defaults to `network`. Values are not currently allowlisted at ingestion. |
| `host_name` | Required for endpoint events | Top level | `host_name` | Preferred endpoint identity. If absent, the normalizer tries top-level `device_name`, top-level `sensor_name`, then `event.host`, and finally `unknown`. |
| `device_name` | Recommended | Top level | `device_name` | Defaults to the resolved `host_name`. Use it for the vendor's device or sensor display name. |
| `event` | Required and enforced | Top level | `raw_json` plus selected columns | Must be an object. Keep the complete vendor event, or a lossless copy under a nested key such as `vendor_native`, here. |
| `event.id` | Recommended | Inside `event` | `source_event_id` | Stable vendor event identifier. `event.flow_id` is also accepted and takes precedence. Numeric values are converted to strings. An absent value becomes empty. |
| `event.timestamp` | Required | Inside `event` | `event_time` | Supply an RFC 3339 timestamp with an offset or `Z`. `event.@timestamp`, top-level `timestamp`, and top-level `@timestamp` are also read. Missing or unparseable time falls back to collector time. The literal input key `event_time` is not read by this path. |
| `event.event_kind` | Recommended | Inside `event` | `event_kind` | Defaults to `event`. Use `alert` for alert-like records; the current Grafana **Recent security alerts** panel filters for exactly `alert`. Top-level `event_kind` is also read. |
| `event.event_category` | Recommended | Inside `event` | `event_category` | Broad category such as `endpoint_detection`, `malware`, `process`, or `network`; defaults to `other`. Top-level `event_category` is also read. |
| `event.event_action` | Required | Inside `event` | `event_action` and legacy `event_type` | Specific action such as `endpoint_alert`, `malware_detected`, or `network_connection`; defaults to `event.event_type`, then `event`. Top-level `event_action` is also read. |
| `event.event_code` | Optional | Inside `event` | `event_code` | Vendor event code. `event.event_type` takes precedence when both are present. |
| `event.severity` | Recommended | Inside `event` | `severity` | Lower-cased on ingestion. Prefer `info`, `low`, `medium`, `high`, or `critical`. Other strings are currently stored but may not behave as expected in rules or dashboards. Top-level `severity` is also read. |
| `event.outcome` | Optional | Inside `event` | `outcome` | Lower-cased on ingestion; defaults to `unknown`. Top-level `outcome` is also read. |
| `event.rule_id` | Recommended for alerts | Inside `event` | `rule_id` | Defaults to the normalized `signature_id`. A top-level `rule_id` is not read by the current generic normalizer. |
| `event.signature` | Recommended for alerts | Inside `event` | `signature` and legacy `rule_name` | `event.alert.signature` is also read and takes precedence. |
| `event.signature_id` | Optional | Inside `event` | `signature_id` | `event.alert.signature_id` is also read and takes precedence. Numeric values are converted to strings. |
| `event.message` | Optional | Inside `event` | `message` | Defaults to the normalized signature. |

### Network fields

| BYOE field | Contract level | Send at | Current normalized output | Accepted aliases and notes |
|---|---|---|---|---|
| `event.source_ip` | Optional | Inside `event` | `source_ip` | Also accepts `event.src_ip` or `event.source.ip`. Stored as a string; ingestion does not prove that it is a valid or endpoint-local address. |
| `event.source_port` | Optional | Inside `event` | `source_port` | Also accepts `event.src_port` or `event.source.port`. Send an integer from 0 through 65535. |
| `event.destination_ip` | Optional | Inside `event` | `destination_ip` | Also accepts `event.dest_ip` or `event.destination.ip`. Stored as a string. |
| `event.destination_port` | Optional | Inside `event` | `destination_port` | Also accepts `event.dest_port` or `event.destination.port`. Send an integer from 0 through 65535. |
| `event.protocol` | Optional | Inside `event` | `protocol` | Also accepts `event.proto` or `event.network.transport`; lower-cased on ingestion. |
| `event.direction` | Optional | Inside `event` | `network_direction` | Top-level `network_direction` is also read. The nested key `event.network_direction` is not currently read. |
| `event.domain` | Optional | Inside `event` | `domain` and legacy `destination_hostname` | Direct generic mapping is supported. Suricata DNS, HTTP hostname, and TLS SNI locations have additional special-case mappings. |
| `event.url` | Optional | Inside `event` | `url` | Direct generic mapping is supported. Suricata HTTP host and path have an additional special-case mapping. |

### Preserved now, but not first-class for generic BYOE

The following proposed fields may be included inside `event`; they remain available in generated `raw_json`. The current generic `/security` normalizer does not populate their corresponding analytics columns, or the common event table has no such column. Treat each as a **future schema consideration**, not an implemented normalized field.

| Proposed BYOE field | Current result | Limitation |
|---|---|---|
| `event.user_name` | Preserved in `raw_json` only | `fusion.sysmon_events.user_name` exists, but generic `/security` records currently write it as empty. |
| `event.process_name` | Preserved in `raw_json` only | The existing first-class column is left empty by the generic normalizer. |
| `event.process_path` | Preserved in `raw_json` only | The existing first-class column is left empty by the generic normalizer. |
| `event.command_line` | Preserved in `raw_json` only | The existing first-class column is left empty by the generic normalizer. Command lines can contain secrets; minimize and protect them. |
| `event.mitre_tactic_ids` | Preserved in `raw_json` only | The common event table has no first-class MITRE tactic array. Detection and incident MITRE metadata currently comes from reviewed FUSION rules. |
| `event.mitre_technique_ids` | Preserved in `raw_json` only | The common event table has no first-class MITRE technique array. Payload values do not automatically become detection metadata. |
| `raw_json` or `original` as a sender field | No special input mapping | Do not pre-encode the whole event into `raw_json`. Keep native evidence as JSON inside `event`; FUSION generates the stored `raw_json`. |

Promoting these fields requires a reviewed runtime normalizer and schema decision. Documentation alone cannot make them searchable, detectable, or correlatable as first-class values.

## Examples

All four examples use the currently accepted envelope. Arbitrary vendor-native keys are intentionally retained under `event.vendor_native`; only fields marked as currently normalized in the matrix are promoted into analytics columns.

### A. Generic endpoint detection

```json
{
  "vendor": "ExampleEDR",
  "product": "Endpoint Security",
  "source_type": "example_edr",
  "platform": "windows",
  "host_name": "WIN-LAPTOP-01",
  "device_name": "example-device-7f31",
  "event": {
    "id": "alert-7f31-0001",
    "timestamp": "2026-09-14T10:15:30.123Z",
    "event_kind": "alert",
    "event_category": "endpoint_detection",
    "event_action": "endpoint_alert",
    "severity": "medium",
    "outcome": "unknown",
    "rule_id": "EDR-123",
    "signature_id": "EDR-123",
    "signature": "Suspicious endpoint behavior",
    "vendor_native": {
      "console_url": "https://edr.invalid/alerts/alert-7f31-0001",
      "confidence": 72
    }
  }
}
```

### B. Malware alert

```json
{
  "vendor": "ExampleEDR",
  "product": "Endpoint Security",
  "source_type": "example_edr",
  "platform": "windows",
  "host_name": "FINANCE-LAPTOP-02",
  "event": {
    "id": "malware-20260914-0042",
    "timestamp": "2026-09-14T10:18:09.482Z",
    "event_kind": "alert",
    "event_category": "malware",
    "event_action": "malware_blocked",
    "severity": "high",
    "outcome": "blocked",
    "rule_id": "MAL-2048",
    "signature_id": "MAL-2048",
    "signature": "Example test malware",
    "vendor_native": {
      "file_path": "C:\\Users\\analyst\\Downloads\\harmless-test.bin",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "quarantine_state": "quarantined"
    }
  }
}
```

### C. Suspicious PowerShell alert

```json
{
  "vendor": "ExampleEDR",
  "product": "Endpoint Security",
  "source_type": "example_edr",
  "platform": "windows",
  "host_name": "ADMIN-LAPTOP-03",
  "event": {
    "id": "behavior-ps-0099",
    "timestamp": "2026-09-14T10:21:44.006Z",
    "event_kind": "alert",
    "event_category": "process",
    "event_action": "suspicious_powershell",
    "severity": "high",
    "outcome": "observed",
    "rule_id": "BEHAVIOR-PS-7",
    "signature": "Suspicious PowerShell execution",
    "user_name": "EXAMPLE\\alice",
    "process_name": "powershell.exe",
    "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoProfile -Command Get-Process",
    "mitre_tactic_ids": ["TA0002"],
    "mitre_technique_ids": ["T1059.001"]
  }
}
```

In this example, the alert identity, time, classification, severity, rule, signature, and host are normalized. `user_name`, the process fields, `command_line`, and the MITRE arrays are retained only in `raw_json` by the current generic path. This record does not match the existing Sysmon-specific PowerShell rule merely because the raw payload names PowerShell.

### D. Network-related endpoint detection

```json
{
  "vendor": "ExampleEDR",
  "product": "Endpoint Security",
  "source_type": "example_edr",
  "platform": "windows",
  "host_name": "ENGINEERING-WS-04",
  "event": {
    "id": "network-alert-8812",
    "timestamp": "2026-09-14T10:24:11.870Z",
    "event_kind": "alert",
    "event_category": "network",
    "event_action": "suspicious_network_connection",
    "severity": "medium",
    "outcome": "blocked",
    "rule_id": "NET-8812",
    "signature": "Endpoint connection to a suspicious destination",
    "source_ip": "192.0.2.25",
    "source_port": 51432,
    "destination_ip": "198.51.100.44",
    "destination_port": 443,
    "protocol": "tcp",
    "direction": "outbound",
    "domain": "telemetry-test.example",
    "url": "https://telemetry-test.example/check-in"
  }
}
```

## Submit and verify an event

Save an example as `byoe-smoke.json`, give `event.id` a unique value, and send exactly one JSON object per request.

PowerShell:

```powershell
$response = Invoke-WebRequest -UseBasicParsing `
  -Uri 'http://127.0.0.1:8686/security' `
  -Method Post `
  -ContentType 'application/json' `
  -InFile '.\byoe-smoke.json'
$response.StatusCode
```

curl:

```sh
curl -i \
  -H 'Content-Type: application/json' \
  --data-binary @byoe-smoke.json \
  http://127.0.0.1:8686/security
```

The configured success response is HTTP `202 Accepted`. **A 202 response proves only that the HTTP receiver accepted the request for asynchronous handling. It does not prove that the path matched, the event normalized, ClickHouse stored it, or Grafana can display it.** Always verify persistence.

On a PowerShell-based FUSION host, load the local ClickHouse credentials and query through the container. Replace the example ID with the unique `event.id` that you sent:

```powershell
$settings = @{}
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^#][^=]*)=(.*)$') { $settings[$matches[1]] = $matches[2] }
}

docker compose exec -T clickhouse clickhouse-client `
  --user $settings.CLICKHOUSE_USER `
  --password $settings.CLICKHOUSE_PASSWORD `
  --query "SELECT event_time, vendor, product, source_type, platform, host_name, device_name, event_kind, event_category, event_action, severity, outcome, rule_id, signature, signature_id, source_ip, source_port, destination_ip, destination_port, protocol, domain, url, length(raw_json) AS raw_bytes FROM fusion.sysmon_events WHERE source_event_id = 'alert-7f31-0001' ORDER BY ingested_at DESC LIMIT 5 FORMAT Vertical"
```

Verify that a vendor-native marker survived without printing the complete evidence body:

```powershell
docker compose exec -T clickhouse clickhouse-client `
  --user $settings.CLICKHOUSE_USER `
  --password $settings.CLICKHOUSE_PASSWORD `
  --query "SELECT source_event_id, position(raw_json, 'console_url') > 0 AS native_evidence_retained FROM fusion.sysmon_events WHERE source_event_id = 'alert-7f31-0001' ORDER BY ingested_at DESC LIMIT 5"
```

Then open **Dashboards → Fusion → Fusion Security Sources** and filter by the submitted vendor, product, or source type. An event with `event_kind: "alert"` can also appear in **Recent security alerts**. Grafana visibility still depends on its selected time range and filters.

If no row appears after allowing for the one-second sink batch interval, inspect `docker compose logs vector` for normalization, schema, buffer, or ClickHouse delivery errors. Do not treat repeated HTTP submission as safe unless the upstream vendor event ID and the desired duplicate behavior have been reviewed; the raw event table does not deduplicate generic submissions.

## Limits and current detection boundary

- The decoded JSON envelope is limited to 1 MiB by the normalizer, and the deployment also caps decompressed HTTP input at 1 MiB. Oversized input is not stored.
- `/security` is HTTP `POST` only. Use the exact path; an unmatched path is routed to the collector's rejected-event log.
- The ClickHouse event table uses a 90-day TTL by default.
- Event IP values are stored as strings at ingestion. Supplying an IP does not establish endpoint ownership for correlation.
- Port columns are unsigned 16-bit integers. Use values from 0 through 65535.
- Current generic JSON storage is not a vendor connector. It supplies no vendor API polling, authentication, cursor, rate-limit, response-action, or endpoint-isolation behavior.
- Storage is not detection. The current reviewed Sigma rules and log-source mappings target Sysmon, Linux auditd/journald, and Suricata shapes. An `example_edr` event remains searchable and visible in security-source dashboards, but it does not automatically create a FUSION detection.
- Correlation consumes FUSION detections plus narrowly allowlisted normalized context events. A vendor-specific EDR alert must first map to approved first-class fields and match a reviewed detection rule before it can contribute as a detection to current correlation scenarios.
- Payload MITRE arrays are evidence only today. Current detection and incident ATT&CK metadata is assigned by reviewed FUSION detection and correlation rules.

Future schema work should prioritize first-class user and process fields, explicit input aliases for `event_time` and stable source-event IDs, reviewed ATT&CK provenance, and vendor-specific mappings without discarding the complete native event.

## Implementation references

- [`vector/vector.yaml`](../vector/vector.yaml) defines the HTTP source, `/security` route, generic normalization, raw preservation, limits, and `202` response.
- [`clickhouse/init/001_schema.sql`](../clickhouse/init/001_schema.sql) defines the current shared event table and retention TTL.
- [`detections/mappings/sigma_fields.yml`](../detections/mappings/sigma_fields.yml) lists first-class fields available to detection rules and the currently mapped log sources.
- [`grafana/dashboards/fusion-security-sources.json`](../grafana/dashboards/fusion-security-sources.json) defines the current security-source and recent-alert panels.
- [`api-connectors.md`](api-connectors.md) describes the future API-polling connector contract; no API polling connector is implemented today.
- [`SECURITY.md`](../SECURITY.md) describes the current lab-only transport boundary and required exposure precautions.
