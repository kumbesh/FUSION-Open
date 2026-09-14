# BYOE integration guide

This guide turns **BYOE—Bring Your Own EDR** into a practical onboarding path for a FUSION-Open lab or controlled beta. FUSION complements an existing EDR or security product; it does not replace that product's prevention, isolation, sensor management, or remediation capabilities.

Start with the [BYOE overview](byoe-overview.md), use the [generic JSON contract](byoe-generic-json-schema.md) while mapping fields, and consult the [compatibility matrix](byoe-compatibility-matrix.md) before interpreting a format-level capability as a validated vendor integration.

## Choose an integration path

| Path | Use it when | Current status |
| --- | --- | --- |
| Generic JSON / webhook push | The source can send JSON, or a small external adapter can create the FUSION envelope | Validated format at `POST /security`; named EDR mappings are not validated |
| RFC 3164 or RFC 5424 syslog | The source or relay can emit standards-compliant syslog | Receiver validated for TCP/UDP; end-to-end fixtures prove RFC 3164/TCP and RFC 5424/UDP |
| CEF or LEEF | A product emits CEF/LEEF inside a valid syslog frame | Supported format for opaque RFC-syslog carriage only; no CEF/LEEF field parser exists |
| REST API connector | Events must be polled from a vendor API | Planned; no API polling connector ships today |

Do not invent or send to `/edr`. The only current vendor-neutral HTTP security-tool path is `POST /security`.

## Prerequisites and security boundary

Before onboarding a source:

1. Deploy FUSION and confirm its services are healthy with `docker compose ps`.
2. Keep the default loopback bindings when the sender runs on the FUSION host.
3. For an isolated lab VM or appliance, bind only the specific reachable host interface and restrict the firewall to that sender or lab subnet.
4. Keep test payloads free of passwords, tokens, private keys, and unnecessary personal data.
5. Choose a stable source identity: `vendor`, `product`, `source_type`, and `host_name` for endpoint events; add `device_name` when the vendor has a separate device or sensor display identity.
6. Record which fields the source adapter actually maps and test both representative and malformed events.

HTTP ingestion on TCP 8686 has no TLS or authentication. Syslog on TCP/UDP 5514 is plaintext and unauthenticated. Neither service may be exposed directly to the public Internet or an untrusted network. See the repository [security boundaries](../README.md#security-boundaries) before changing a bind address.

## A. Generic JSON or webhook push

### When to use it

Use generic JSON when the product supports an outbound webhook, a relay can transform its alerts, or a small external adapter can wrap vendor JSON without losing the original vendor object. This is the most expressive currently implemented BYOE transport.

### Transport and payload

- Method and path: `POST /security`
- Default URL: `http://127.0.0.1:8686/security`
- Content type: `application/json`
- Body: one JSON object with a top-level `event` object
- Maximum encoded event size: 1 MiB
- Successful receiver response: HTTP `202`

The top-level `event` object is mandatory. A flat event without it is rejected by normalization. A `202` response proves only that the HTTP receiver accepted the request; it does **not** prove that Vector normalized the event or that ClickHouse stored it.

For useful analytics, supply at least:

- `vendor`
- `product`
- `source_type`
- `platform`
- `host_name` for endpoint events
- `device_name` when it is distinct and useful
- `event.timestamp`
- `event.event_action`
- `event.event_category`
- `event.severity`
- a stable `event.id` when the vendor provides one

Use the exact field behavior in the [generic JSON contract](byoe-generic-json-schema.md). The current generic normalizer promotes alert and network metadata, but it does not yet promote generic `user_name`, process, command-line, or MITRE fields into first-class event columns.

### Controlled sample

The following sample uses only the currently implemented envelope and mappings:

```json
{
  "vendor": "ExampleEDR",
  "product": "Endpoint Security",
  "source_type": "example_edr",
  "platform": "windows",
  "host_name": "WIN-LAPTOP-01",
  "device_name": "WIN-LAPTOP-01",
  "event": {
    "timestamp": "2026-09-14T12:00:00.000Z",
    "id": "byoe-event-001",
    "event_kind": "alert",
    "event_category": "intrusion_detection",
    "event_action": "endpoint_alert",
    "severity": "high",
    "rule_id": "EDR-123",
    "signature": "Controlled BYOE onboarding event",
    "signature_id": "EDR-123",
    "message": "Controlled BYOE onboarding event"
  }
}
```

PowerShell uses the current UTC time so the event appears in the default Grafana time range:

```powershell
$payload = @{
  vendor = 'ExampleEDR'
  product = 'Endpoint Security'
  source_type = 'example_edr'
  platform = 'windows'
  host_name = 'WIN-LAPTOP-01'
  device_name = 'WIN-LAPTOP-01'
  event = @{
    timestamp = [DateTime]::UtcNow.ToString('o')
    id = 'byoe-event-001'
    event_kind = 'alert'
    event_category = 'intrusion_detection'
    event_action = 'endpoint_alert'
    severity = 'high'
    rule_id = 'EDR-123'
    signature = 'Controlled BYOE onboarding event'
    signature_id = 'EDR-123'
    message = 'Controlled BYOE onboarding event'
  }
} | ConvertTo-Json -Depth 6

$response = Invoke-WebRequest `
  -Uri 'http://127.0.0.1:8686/security' `
  -Method Post `
  -UseBasicParsing `
  -ContentType 'application/json' `
  -Headers @{ 'X-Fusion-Validation-Id' = 'byoe-json-001' } `
  -Body $payload

$response.StatusCode
```

curl uses the sender's current UTC time:

```sh
event_time=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
curl -i \
  -H 'Content-Type: application/json' \
  -H 'X-Fusion-Validation-Id: byoe-json-001' \
  --data-binary @- \
  http://127.0.0.1:8686/security <<JSON
{
    "vendor":"ExampleEDR",
    "product":"Endpoint Security",
    "source_type":"example_edr",
    "platform":"windows",
    "host_name":"WIN-LAPTOP-01",
    "device_name":"WIN-LAPTOP-01",
    "event":{
      "timestamp":"$event_time",
      "id":"byoe-event-001",
      "event_kind":"alert",
      "event_category":"intrusion_detection",
      "event_action":"endpoint_alert",
      "severity":"high",
      "rule_id":"EDR-123",
      "signature":"Controlled BYOE onboarding event",
      "signature_id":"EDR-123",
      "message":"Controlled BYOE onboarding event"
    }
}
JSON
```

### Verification

1. Confirm the HTTP response is `202`.
2. Wait briefly for the bounded Vector batch to flush.
3. Query ClickHouse using the credentials from the ignored local `.env` file:

```powershell
$settings = @{}
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^#][^=]*)=(.*)$') { $settings[$matches[1]] = $matches[2] }
}

docker compose exec -T clickhouse clickhouse-client `
  --user $settings.CLICKHOUSE_USER `
  --password $settings.CLICKHOUSE_PASSWORD `
  --query "
    SELECT
      event_time, vendor, product, source_type, platform,
      host_name, event_kind, event_category, event_action,
      severity, rule_id, signature_id, source_event_id
    FROM fusion.sysmon_events
    WHERE validation_id = 'byoe-json-001'
    ORDER BY ingested_at DESC
    LIMIT 5
    FORMAT Vertical"
```

4. Confirm the normalized values match the mapping plan and that `raw_json` is populated. Inspect only the fields needed for testing; raw vendor payloads may contain sensitive evidence.
5. Open **Dashboards → Fusion → Fusion Security Sources**, select the relevant vendor/product/source filters, and widen the time range if necessary.
6. Treat detection and correlation as separate gates. Storage in `fusion.sysmon_events` does not automatically make an event suspicious or eligible for an incident. A reviewed normalization mapping and an approved detection/correlation rule must support the resulting fields.

### Limitations

- There is no authentication, TLS, per-source authorization, tenant boundary, or webhook signature verification.
- A producer receives `202` before downstream normalization and storage are proven.
- Events over 1 MiB or events without an object-valued `event` field are rejected from storage and logged by Vector.
- Generic process, user, command-line, hash, and MITRE values remain only inside `raw_json` today unless a source-specific approved mapping promotes them.
- Named EDR products have not been validated merely because they can emit JSON.

## B. RFC 3164 and RFC 5424 syslog

### When to use it

Use syslog when a security appliance, EDR relay, or log forwarder can produce RFC 3164 or RFC 5424 but cannot call the JSON endpoint. Prefer TCP when the sender supports it, while recognizing that the current receiver does not provide TLS or application-level acknowledgement.

### Transport

- TCP: `${FUSION_SYSLOG_BIND_ADDRESS:-127.0.0.1}:${FUSION_SYSLOG_TCP_PORT:-5514}`
- UDP: `${FUSION_SYSLOG_BIND_ADDRESS:-127.0.0.1}:${FUSION_SYSLOG_UDP_PORT:-5514}`
- Maximum message length: 64 KiB
- TCP connection limit: 100

Set `FUSION_SYSLOG_BIND_ADDRESS` to a specific lab-facing host address only when an external sender requires it. Restrict TCP and/or UDP 5514 to the individual source or isolated lab subnet.

### Minimum useful fields

A standards-compliant frame should provide a timestamp, hostname, application name, severity/facility, and message. RFC 5424 can additionally provide a message ID. The current normalizer produces:

- `source_type = generic_syslog`
- `platform = network`
- `product` and `process_name` from the syslog application name
- `host_name` and `device_name` from the syslog hostname
- `event_action = syslog_message`
- normalized `severity`, `syslog_facility`, `syslog_application`, and `message`
- transport peer address in `source_address`
- parsed syslog evidence in `raw_json`

Transport peer metadata is deliberately not copied into the event-level `source_ip` field.

### Controlled RFC 5424 sample

From a Linux or macOS sender with netcat:

```sh
event_time=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
printf '<134>1 %s edge-edr-01 exampleedr 4321 EDR123 - Controlled BYOE syslog event\n' "$event_time" \
  | nc -w 2 127.0.0.1 5514
```

From PowerShell over TCP:

```powershell
$eventTime = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$message = "<134>1 $eventTime edge-edr-01 exampleedr 4321 EDR123 - Controlled BYOE syslog event"
$client = New-Object System.Net.Sockets.TcpClient
try {
  $client.Connect('127.0.0.1', 5514)
  $bytes = [Text.Encoding]::UTF8.GetBytes("$message`n")
  $stream = $client.GetStream()
  $stream.Write($bytes, 0, $bytes.Length)
  $stream.Flush()
} finally {
  $client.Dispose()
}
```

Verify receipt in ClickHouse:

```powershell
$settings = @{}
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^#][^=]*)=(.*)$') { $settings[$matches[1]] = $matches[2] }
}

docker compose exec -T clickhouse clickhouse-client `
  --user $settings.CLICKHOUSE_USER `
  --password $settings.CLICKHOUSE_PASSWORD `
  --query "
    SELECT
      event_time, host_name, product, severity, event_code,
      ingestion_protocol, source_address, message
    FROM fusion.sysmon_events
    WHERE source_type = 'generic_syslog'
      AND message = 'Controlled BYOE syslog event'
    ORDER BY ingested_at DESC
    LIMIT 5
    FORMAT Vertical"
```

Then confirm the row appears on **Fusion Security Sources**. Syslog has no HTTP response, so ClickHouse and collector logs are the authoritative receipt checks.

### Limitations

- TCP and UDP are plaintext and unauthenticated; syslog over TLS is not implemented.
- UDP delivery is not acknowledged and may be lost in transit.
- The normalizer handles the outer RFC frame, not arbitrary vendor key/value grammars inside `message`.
- Syslog does not currently populate event-level endpoint network, user, process path, command-line, signature, or MITRE fields.

## C. CEF and LEEF

### When to consider it

CEF or LEEF may be practical when a source already exports one of those formats through a syslog relay and an operator can define a small, tested adapter. FUSION does not currently contain a CEF or LEEF parser.

### Current behavior

If CEF or LEEF text is carried inside a syntactically valid RFC 3164/5424 message, the existing syslog source can retain that text in `message` and the parsed outer record in `raw_json`. CEF/LEEF extension keys are **not** promoted into FUSION fields. Sending bare CEF/LEEF without a valid outer syslog frame is not a supported contract.

Before calling a CEF/LEEF integration operational:

1. Capture representative vendor fixtures without secrets or personal data.
2. Define an explicit mapping into the [generic JSON contract](byoe-generic-json-schema.md).
3. Preserve the complete vendor record inside the nested `event` object.
4. Test missing, repeated, escaped, oversized, and malformed extension values.
5. Verify normalized rows and negative cases in ClickHouse.
6. Add source-specific detection/correlation validation if those outcomes are required.

Until that work exists, this is only a **Supported format** transport-and-preservation path. Native CEF/LEEF semantic mapping is **Not supported**, and raw receipt must not be described as full field compatibility.

## D. Future REST API connector model

No vendor REST API polling connector ships with FUSION today. The proposed connector boundary is documented in [Future API connector framework](api-connectors.md).

### When and how it may be used

This planned path is for products that expose events only through a vendor REST API. A future external connector would call that API over certificate-verified HTTPS, translate each accepted record into the existing generic envelope, and submit it to `POST /security`. It must not introduce a vendor-specific FUSION table or a parallel ingestion pipeline.

At minimum, its output would need the same contract fields as a webhook submission: stable `vendor`, `product`, and `source_type`; `platform`; `host_name` for endpoint events; and an object-valued `event` containing a vendor event ID, occurrence timestamp, action, category, kind, and severity where the source supplies them. The complete vendor record should remain as structured evidence inside `event` so FUSION can generate `raw_json` without discarding context.

### Required implementation and verification gates

A future connector should:

- use HTTPS with certificate verification;
- obtain least-privilege credentials from a local secret file or external secret provider;
- preserve opaque cursor/pagination state only after downstream acknowledgement;
- apply bounded overlap and stable vendor-event deduplication;
- honor rate limits and use bounded retry/backoff;
- bound response size, decompression, page size, and parsing depth;
- quarantine malformed records observably;
- emit the same nested `/security` envelope instead of adding a vendor table or parallel pipeline; and
- expose health, cursor age, throttling, error, buffer, and normalization metrics without leaking payloads.

Before any connector can move beyond **Planned**, verification must cover a controlled API response, pagination and restart recovery, retry and rate-limit behavior, stable deduplication, malformed records, secret redaction, downstream ClickHouse fields and `raw_json`, Grafana visibility, and any separately reviewed detection or correlation mapping. Vendor authentication, scopes, quotas, identifiers, and failure behavior must be reviewed and tested per connector.

There is no current sample request or operational verification command for this path because there is no connector to run. This is roadmap material, not evidence that Microsoft Defender, CrowdStrike Falcon, SentinelOne, Wazuh, or another vendor API works today.

## End-to-end onboarding checklist

For every BYOE source:

1. **Send one controlled event.** Avoid attack payloads and sensitive evidence.
2. **Check transport.** Record HTTP status or sender/syslog delivery diagnostics.
3. **Prove storage.** Query ClickHouse using a unique validation marker, source ID, or message.
4. **Inspect normalization.** Compare every required field with the mapping document and inspect `raw_json` preservation safely.
5. **Inspect Grafana.** Confirm the event appears on **Fusion Security Sources** with expected filters.
6. **Test detection separately.** Confirm an approved Sigma rule supports the normalized fields; generic receipt alone is insufficient.
7. **Test correlation separately.** Confirm an approved correlation rule accepts the resulting detection/context shape. Raw events can provide only bounded context required by a frozen rule; correlation is not a second detection engine.
8. **Record negative cases.** Missing required structure, malformed types, oversized inputs, retries, and duplicates must behave as documented.

## Troubleshooting

### `HTTP method not allowed`

The `/security` source accepts `POST`, not a browser `GET`. Use `Invoke-WebRequest` or `curl` with a JSON body.

### HTTP `202`, but no ClickHouse row

- Confirm the body contains an object-valued top-level `event` field.
- Confirm the encoded event is no larger than 1 MiB.
- Check `docker compose logs vector` for `fusion_error=normalization_or_path_rejected` or sink errors.
- Query with the exact validation marker and expand the time range.
- Remember that the HTTP response precedes downstream storage confirmation.

### Syslog sender reports success, but no row appears

- Confirm TCP/UDP, destination address, and port match `.env`.
- Confirm the message is valid RFC 3164 or RFC 5424, including its priority prefix.
- Check source-scoped firewall rules and `docker compose logs vector`.
- For UDP, capture or relay diagnostics may be needed because delivery is unacknowledged.

### Event is stored but no detection or incident appears

This is expected unless current detection and correlation rules support the normalized event. Review the first-class fields, add a tested source mapping where necessary, and use the normal rule-review process. Do not weaken a rule or classify arbitrary raw text inside the correlation layer to make a demo pass.

## Controlled-beta limits

FUSION-Open should complement, not replace, endpoint protection. The current BYOE workflow provides no endpoint isolation, vendor response action, production SLA, HA, or complete enterprise RBAC/multi-tenancy.

Use conservative onboarding stages and measure each one:

- 5–25 endpoints for an initial controlled beta;
- 25–100 endpoints only after the initial scope is stable; and
- larger scopes only after workload-specific performance, retention, failure-recovery, and operational validation.

These ranges are beta planning guidance, not demonstrated capacity or a production scale guarantee.
