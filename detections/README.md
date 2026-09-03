# Fusion Detection Engine

Fusion v0.5 adds a standalone, post-ingestion detection service. Vector continues to collect, parse, normalize, and route events; it contains no detection logic. The Python engine reads bounded batches from the existing normalized `fusion.sysmon_events` table, evaluates repository-managed Sigma YAML, and writes source-agnostic results to `fusion.detections`. A detection failure cannot stop Vector or ClickHouse ingestion.

## Runtime design

The service polls on a configurable interval and stores a `(event_time, event_uid)` checkpoint in ClickHouse. New events are read in ascending order with a fixed batch limit. A bounded lookback query revisits slightly late events. The deterministic detection ID is:

```text
SHA-256(rule_id + NUL + source_event_uid)
```

`event_uid` is a materialized SHA-256 identity derived from stable normalized/source fields and preserved raw JSON. The engine checks existing IDs before insertion, and `detections` uses `ReplacingMergeTree(updated_at)` as a second idempotency layer. The same rule and event therefore produce the same ID after replay or restart, while two rules matching one event produce two IDs.

The checkpoint is persistent, but it is not a distributed lease. v0.5 supports one normal engine instance. Multiple concurrent instances are not a supported high-availability configuration.

## Supported Sigma subset

Sigma YAML remains the source format. The Fusion compiler supports:

- Exact scalar matches and OR lists of scalar values
- `contains`, `startswith`, `endswith`, and boolean `exists` field modifiers
- AND between fields inside one selection
- `and`, `or`, `not`, and parentheses in conditions
- `1 of selection_*`, `all of selection_*`, `1 of them`, and `all of them`
- `product` and `service` logsource mappings declared in `mappings/sigma_fields.yml`
- Metadata fields `id`, `title`, `description`, `level`, `tags`, `author`, `date`, `modified`, and `references`

String comparisons are case-insensitive. A list attached to one field is OR; fields inside one selection are AND.

The compiler rejects unknown fields, arbitrary condition syntax, chained/unknown modifiers, unknown logsources, empty selections, duplicate rule IDs, non-boolean `exists`, correlation, aggregation, `timeframe`, threshold expressions, regular-expression field modifiers, wildcards inside values, and other constructs outside this subset. It never treats rule text as SQL: ClickHouse queries are fixed and parameterized, and rule evaluation occurs in Python.

## Field mapping

The versioned mapping is `mappings/sigma_fields.yml`. Common examples are:

| Sigma field | Fusion field |
| --- | --- |
| `Image` | `process_path` |
| `CommandLine` | `command_line` |
| `ParentImage` | `parent_process_name` |
| `User` | `user_name` |
| `DestinationIp` | `destination_ip` |
| `DestinationPort` | `destination_port` |
| `SourceIp` | `source_ip` |
| `QueryName` | `domain` |
| `EventID` | `event_id` |

Rules should use normalized fields. Source-specific raw JSON is retained in `sysmon_events` for investigation but is intentionally not exposed as a general rule field in v0.5.

## Curated rules

Nine intentionally small rules ship under `rules/`:

- Windows encoded PowerShell
- Windows LOLBin with remote/script input
- Windows suspicious command-shell chain
- Linux shell executed through sudo
- Linux potential download-and-execute command
- Linux authentication failure
- High-severity Suricata alert
- Controlled Fusion Suricata signature
- Selected dynamic-DNS query

Each rule has one positive and one negative normalized fixture under `samples/detections/`. These are synthetic tests, not proof of malicious behavior or real-sensor acceptance.

## Validate and dry-run rules

Validate all rules without querying events or writing detections:

```sh
docker compose run --rm --no-deps fusion-detection-engine validate-rules
```

The command prints total, valid, invalid, unsupported, and duplicate-ID failures. Any invalid rule exits nonzero.

Dry-run one rule against a bounded recent window:

```sh
docker compose run --rm --no-deps fusion-detection-engine \
  test-rule /rules/windows/encoded-powershell.yml --hours 24 --limit 1000
```

The JSON output contains the loaded rule, Sigma-to-Fusion mapping, evaluation plan, query bounds, match count, and sample source event UIDs. It always reports `detections_written: 0`.

## Writing a Fusion Detection Rule

A Windows example:

```yaml
title: Encoded PowerShell Command
id: fusion-windows-encoded-powershell
description: Detects PowerShell with an encoded-command switch.
author: Fusion Project
date: 2026-09-04
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  service: sysmon
detection:
  selection_process:
    EventID: 1
    Image|endswith: '\powershell.exe'
  selection_flag:
    CommandLine|contains: ' -enc '
  condition: selection_process and selection_flag
level: high
```

A network example:

```yaml
title: Selected Dynamic DNS Query
id: example-network-dynamic-dns
logsource:
  product: network
  service: suricata
detection:
  selection:
    Action: dns_query
    QueryName|endswith: '.duckdns.org'
  condition: selection
level: low
```

Use a globally stable rule ID, choose severity conservatively, document likely false positives, use only mapped fields, and add positive plus negative fixtures. Run rule validation, unit tests, and the full lab validator before review. Do not paste arbitrary third-party rules into a running lab without reviewing and adapting them to the supported subset.

## MITRE ATT&CK metadata

Tags such as `attack.execution` and `attack.t1059.001` populate `mitre_tactics`, `mitre_techniques`, and `mitre_technique_ids`. Human-readable names come from the small repository mapping in `mappings/mitre.yml`; the engine makes no runtime Internet requests.

## Lifecycle and operations

The schema supports `new`, `acknowledged`, and `closed`. Generated detections default to `new`. v0.5 intentionally has no mutation UI, API, or fake case-management workflow, so normal generated records remain `new`; status-management commands are reserved for a later milestone.

Useful commands:

```sh
docker compose ps fusion-detection-engine
docker compose logs -f fusion-detection-engine
docker compose stop fusion-detection-engine
docker compose start fusion-detection-engine
./scripts/validate-detections.sh
```

PowerShell uses `./scripts/validate-detections.ps1`. Normal deploy, stop, and reset scripts include the detection container automatically.

Environment safeguards:

| Variable | Default | Bounds |
| --- | ---: | ---: |
| `FUSION_DETECTION_POLL_SECONDS` | `10` | 1–3600 |
| `FUSION_DETECTION_LOOKBACK_SECONDS` | `120` | 0–86400 |
| `FUSION_DETECTION_BATCH_SIZE` | `1000` | 1–10000 |
| `FUSION_DETECTION_LOG_LEVEL` | `INFO` | Python log level |

The container exposes no host port, runs as UID/GID 10001, drops all Linux capabilities, uses a read-only root filesystem and bounded `/tmp`, and has CPU, memory, and PID limits. It retries ClickHouse failures with exponential backoff capped at 60 seconds and never busy-loops.

Logs report startup, loaded rule count, poll counts, matches, inserted/skipped detections, failures, and checkpoint position. Raw event bodies are not logged.

## Limitations

- Single-node polling engine; no HA lease or distributed queue
- Single-event rules only; no threshold, sequence, aggregation, or cross-event correlation
- No automatic community-rule download or live MITRE lookup
- No lifecycle mutation UI, notification, containment, or case management
- `FINAL` queries are acceptable for this small lab but are not an enterprise-scale serving design
- Lookback is bounded; events arriving later than the configured window require an explicit controlled replay
- The current lab uses the main ClickHouse credential; a production deployment needs separate least-privilege read/write users and managed secrets
- Detection results are analytical signals and are not proof of malicious activity

## Real acceptance gate

Fixtures establish code behavior only. Before v0.5 real-lab acceptance, generate and verify:

1. A harmless encoded PowerShell command producing a real Sysmon Event ID 1 and `T1059.001` detection.
2. A controlled Ubuntu action matching one Linux rule with the expected user, process, and evidence.
3. A controlled Suricata alert with the expected signature, signature ID, source, destination, and evidence.
4. A detection-engine restart proving old detections do not duplicate and a new real matching event still creates a detection.

Record host, timestamps, source event UIDs, detection IDs, queries, and Grafana evidence without publishing sensitive raw telemetry. Do not call fixtures real acceptance.

## Troubleshooting

- `validate-rules` errors: read the reported path and unsupported construct; do not weaken validation.
- Unhealthy container: inspect `docker compose logs fusion-detection-engine`, then verify ClickHouse and migration 005.
- No matches: use `test-rule`, confirm the event is inside the bounded window, and compare normalized fields—not raw source names—with the plan.
- Backlog: inspect `poll_complete` checkpoint progress; increase batch size only within the documented bound and available lab resources.
- Duplicate-looking dashboard rows: compare `detection_id`; queries use `FINAL` to resolve lifecycle replacements.
