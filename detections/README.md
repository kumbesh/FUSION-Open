# Fusion Detection Engine

Fusion v0.5 adds a standalone, post-ingestion detection service. Vector continues to collect, parse, normalize, and route events; it contains no detection logic. The Python engine reads bounded batches from the existing normalized `fusion.sysmon_events` table, evaluates repository-managed Sigma YAML, and writes source-agnostic results to `fusion.detections`. A detection failure cannot stop Vector or ClickHouse ingestion.

## Runtime design

Starting in v0.5.2, evaluation completeness is recorded in a persistent ClickHouse ledger. Each cycle follows this order:

```text
normalized source event
  -> Sigma evaluation
  -> synchronous detection write, when matched
  -> evaluation-ledger write
  -> diagnostic checkpoint/telemetry write
```

An event is marked evaluated only after rule evaluation and every required detection write complete successfully. Detection-engine ClickHouse clients explicitly request `wait_for_async_insert=1`, so an enabled asynchronous insert is acknowledged by the server before the dependent ledger write is attempted. The ledger key is `(engine_id, ruleset_fingerprint, event_uid)`. The ruleset fingerprint covers the detection-engine version, each rule's repository-relative path and bytes, and the Sigma field and MITRE mapping files. A rule, mapping, path, or engine-version change therefore creates a distinct evaluation scope instead of trusting results produced under different semantics. `fusion.detection_evaluation_scopes`, keyed by `(engine_id, ruleset_fingerprint)`, preserves each scope's enrollment floor and candidate scheduling cursor across restarts and A→B→A ruleset transitions.

The candidate query anti-joins normalized source events against that ledger, rotates deterministic ordering after the persisted scheduling cursor, applies `LIMIT 1 BY event_uid` to collapse physical source replays, and only then applies the configured bounded batch limit. The cursor advances after a candidate page is attempted, but is neither a checkpoint nor a completeness marker: failed events remain unledgered and reappear when the bounded scan wraps. This prevents a full page of repeatable failures from permanently starving later valid events while retaining visible retries and bounded memory. The `(event_time, event_uid)` checkpoint is retained as a diagnostic maximum evaluated watermark; it is not the source of evaluation completeness. Actual pending work is the exact logical source-event set left by the ledger anti-join.

`FUSION_DETECTION_LOOKBACK_SECONDS` defines the enrollment floor for existing history when an engine/ruleset scope starts. That floor remains fixed for the scope. Rows ingested after the floor remain eligible even when their source `event_time` is older than the configured lookback, so late visibility cannot make an enrolled event disappear behind an advancing positional checkpoint.

When a cycle returns a full candidate batch, makes evaluation progress, and the ledger-backed backlog still contains work, the next bounded cycle begins immediately instead of waiting for the normal poll delay. A failed event therefore does not force a 10-second pause between otherwise productive full pages. A page on which every event fails advances only the scheduling cursor and then uses the normal poll interval; it does not advance the evaluated checkpoint or ledger. On the next cycle the scan resumes after that cursor, so later valid events remain reachable without creating a busy loop. After ten consecutive drain cycles the engine takes a 100 ms, shutdown-aware cooperative yield. Empty, partial, and fully drained cycles also use the configured poll interval. Successful empty cycles still persist the effective checkpoint and current telemetry, which heals the crash window where the ledger insert committed but the process stopped before the checkpoint insert.

The deterministic detection ID is:

```text
SHA-256(rule_id + NUL + source_event_uid)
```

`event_uid` is a materialized SHA-256 identity derived from stable normalized/source fields and preserved raw JSON. The engine checks existing IDs before insertion, and `detections` uses `ReplacingMergeTree(updated_at)` as a second idempotency layer. If the process stops after a detection write but before its ledger write, replay produces the same detection ID and does not amplify the logical detection. The same rule and event therefore produce the same ID after replay or restart, while two rules matching one event produce two IDs.

The checkpoint and ledger are persistent, but neither is a distributed lease. v0.5 supports one normal engine instance. Multiple concurrent instances are not a supported high-availability configuration.

Each successful cycle stores a current pipeline snapshot: the newest eligible source position (nullable when the eligible source set is empty), diagnostic checkpoint lag in events and seconds, exact unevaluated count and oldest unevaluated age, evaluated and newly processed event counts, late-event count, processing duration, and effective evaluated events per second. Every cycle emits the same payload-free fields in the `poll_complete` log, including empty cycles. The status output also exposes the current per-scope scheduling cursor. Inspect the current position and lag as JSON without changing state:

```sh
docker compose exec -T fusion-detection-engine fusion-detection status
```

The current dashboard-ready snapshot is available through `fusion.detection_checkpoints FINAL`. Snapshot timing covers candidate fetch, evaluation, detection and ledger writes, and the exact post-cycle backlog query; it excludes checkpoint persistence and log formatting. Positional checkpoint lag can be zero while an older event remains pending, so use `unevaluated_event_count` as the evaluation-completeness measure. Exact ledger anti-join counting is appropriate for the single-node lab, but it can become a scan cost on substantially larger datasets.

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

The container exposes no host port, runs as UID/GID 10001, drops all Linux capabilities, uses a read-only root filesystem and bounded `/tmp`, and has CPU, memory, and PID limits. It retries ClickHouse failures with exponential backoff capped at 60 seconds. An event that raises a repeatable evaluation error remains unledgered for visible retry and is never silently discarded. The rotating scheduling cursor prevents it from permanently blocking later valid events, but repeated failures still consume evaluation capacity and require operator investigation.

Logs report startup, loaded rule count, per-cycle new/late/evaluated counts, matches, inserted/skipped detections, failures, duration, effective rate, checkpoint/source-head position, and event/time lag. Raw event bodies are not logged.

## Limitations

- Single-node polling engine; no HA lease or distributed queue
- Single-event rules only; no threshold, sequence, aggregation, or cross-event correlation
- No automatic community-rule download or live MITRE lookup
- No lifecycle mutation UI, notification, containment, or case management
- `FINAL` queries are acceptable for this small lab but are not an enterprise-scale serving design
- Lookback controls existing-history enrollment for a new engine/ruleset scope; it is not a continuing maximum age for events ingested afterward
- The evaluation ledger intentionally has no TTL because expiring it while a corresponding source row exists could cause duplicate evaluation. The source table's TTL bounds source-side scans, but ledger rows and old ruleset fingerprints accumulate and need capacity monitoring
- Repeatable per-event evaluation failures remain unledgered and observable, rotate back into future bounded pages, and can reduce drain throughput until the event shape or evaluator problem is corrected
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
- Unhealthy container: inspect `docker compose logs fusion-detection-engine`, then verify ClickHouse migrations 005 through 009.
- No matches: use `test-rule`, confirm the event is enrolled by the current evaluation floor, and compare normalized fields—not raw source names—with the plan.
- Backlog: run `fusion-detection status` in the container and inspect `unevaluated_event_count`, the oldest unevaluated age, and `poll_complete` fields. Full batches drain immediately; investigate ClickHouse or evaluation errors and sustained input above processing capacity before changing the bounded batch size.
- Duplicate-looking dashboard rows: compare `detection_id`; queries use `FINAL` to resolve lifecycle replacements.
