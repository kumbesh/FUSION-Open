# Fusion v0.5.2 Detection-Pipeline Performance Validation

## Scope and provenance

This report covers the narrowly scoped Fusion v0.5.2 detection-pipeline work:

- persistent checkpoint and backlog telemetry;
- bounded immediate draining after full detection batches;
- evaluation completeness through an engine- and ruleset-scoped ledger;
- persisted candidate-page rotation so failed events cannot starve later work;
- Windows PowerShell 5.1-compatible secret generation;
- command-scoped `async_insert=0` for validation/admin inserts only.

Final-code measurements were collected on 2026-09-12 UTC in the isolated Compose project `fusion-v052-perf`. Its volumes and benchmark rows were preserved. The test host used Docker Desktop 29.7.2 with 32 logical CPUs and 30.0 GiB assigned memory on Windows 11 Pro/WSL2. The stack used ClickHouse 26.8.1.2041, Vector 0.58.0, Grafana 13.2.1, and Python 3.12.12.

The v0.5.1 values in this report are the supplied baseline for released commit `6af01aa`. They were not re-derived from the current v0.5.2 artifacts, and comparisons are therefore descriptive rather than a controlled claim of ingestion improvement or regression.

## Architecture and correctness model

The v0.5.2 evaluation path is:

```text
Vector -> ClickHouse source events
              |
              v
        fixed per-scope enrollment floor + candidate scheduling cursor
              |
              v
        bounded rotating anti-join against fusion.detection_evaluated_events
              |
              v
        rule evaluation -> deterministic detection writes -> ledger mark
              |
              v
        checkpoint/backlog telemetry
```

Candidate eligibility no longer depends on advancing past a positional `(event_time, event_uid)` watermark. The detector selects bounded, logically unique source UIDs that do not have an evaluation-ledger row for the current `engine_id` and `ruleset_fingerprint`. Candidate ordering rotates after a persisted per-scope scheduling cursor; the cursor is not a completion marker, and failed events remain unledgered for retry after the scan wraps. The detector writes any detections before marking source events evaluated, and its ClickHouse client explicitly requires `wait_for_async_insert=1` so dependent writes are server-acknowledged in order. A crash in that interval can replay an event, but deterministic detection IDs prevent a logical duplicate. The positional checkpoint remains progress telemetry; the ledger and anti-join are the completeness authority.

### Fixed evaluation-enrollment floor

For an engine and active ruleset fingerprint, the first cycle derives an evaluation-enrollment floor from the effective checkpoint minus the configured lookback and persists it in `fusion.detection_evaluation_scopes`. That table is keyed by engine and ruleset fingerprint, so an A→B→A transition restores A's original floor and scheduling cursor. On an engine with no prior checkpoint, the checkpoint already defaults to `now - lookback`, retaining the effective v0.5 new-plus-late enrollment window rather than claiming an all-history backfill.

The persisted floor does not move forward on later cycles. A source row remains eligible when either its `event_time` or its `ingested_at` is at or after that floor. Consequently, a row that becomes visible later, has an older event timestamp, or has a UID below the positional checkpoint remains discoverable once enrolled. A changed ruleset fingerprint receives a fresh bounded floor; it does not silently reevaluate unlimited historical data.

## Method and acceptance gates

Every load stage used a unique `validation_id` and unique source identity. The load generator made no HTTP retries, and the harness performed no row deletion, direct/manual checkpoint writes, volume cleanup, Vector sink tuning, or VMware/firewall changes. The detector continued to write its normal checkpoint telemetry and exercise its normal retry behavior. A passing stage required:

- every submitted request to return HTTP 202;
- exact physical source-row count, exact unique source ID count, and exact unique `event_uid` count;
- no blank source or event identity;
- exact physical and logical evaluation-ledger counts for the current engine and ruleset;
- a checkpoint-independent, anti-join-derived actual backlog count of zero;
- final actual unevaluated backlog and positional checkpoint lag of zero;
- no physical duplicate amplification;
- zero unexpected detections for the nonmatching performance events;
- healthy services with stable automatic restart counts;
- no rejection, drop, or sink-error signal from the stage log gates.

Vector's `/metrics` HTTP request returned an empty response body in this environment. Vector error-counter deltas were therefore unavailable and are not represented as zero. Row integrity, the scoped ledger, checkpoint-independent anti-join backlog, logs, health, and restart checks supplied the acceptance evidence instead.

## Final ledger-backed burst results

ClickHouse completion is measured from send start. Evaluation completion is reported both from send start and after the sender finished. Detection processing time is the sum of measured evaluation-cycle work, not end-to-end wall time.

| Stage | Accepted / exact source / exact ledger | Send rate | ClickHouse complete | Evaluation complete: start / post-send | Evaluation processing / effective rate | Peak unevaluated | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1K | 1,000 / 1,000 / 1,000 | 6,086.58 EPS | 0.592 s | 11.198 s / 11.034 s | 0.501435 s / 1,994.28 EPS | 1,000 | PASS |
| 10K | 10,000 / 10,000 / 10,000 | 7,352.03 EPS | 1.795 s | 12.754 s / 11.394 s | 2.650045 s / 3,773.52 EPS | 10,000 | PASS |
| 100K | 100,000 / 100,000 / 100,000 | 8,166.71 EPS | 12.739 s | 44.119 s / 31.874 s | 32.152905 s / 3,110.14 EPS | 85,000 | PASS |

Artifact run IDs:

- `perf-v052-perf-v052-cursor-final-burst-1k-20260912T132046Z-4dad2a74`
- `perf-v052-perf-v052-cursor-final-burst-10k-20260912T132127Z-11b9f9f9`
- `perf-v052-perf-v052-cursor-final-burst-100k-20260912T132209Z-d3e642cf`

All three runs finished with exact physical and unique source counts, exact physical and unique current-ruleset ledger counts, zero actual unevaluated events, zero positional checkpoint lag, zero unexpected detections, and no duplicate amplification.

## v0.5.1 supplied comparison

The v0.5.1 completion column is its supplied positional checkpoint result; v0.5.1 did not have the v0.5.2 evaluation ledger. The v0.5.2 column is the stricter exact ledger-backed completion result.

| Stage | v0.5.1 send rate | v0.5.1 ClickHouse complete | v0.5.1 checkpoint complete | v0.5.2 send rate | v0.5.2 ClickHouse complete | v0.5.2 exact evaluation complete |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1K | 6,064.1 EPS | 0.578 s | 6.256 s | 6,086.58 EPS | 0.592 s | 11.198 s |
| 10K | 8,492.4 EPS | 1.595 s | 92.487 s | 7,352.03 EPS | 1.795 s | 12.754 s |
| 100K | 9,778.7 EPS | 10.642 s | 1,007.042 s | 8,166.71 EPS | 12.739 s | 44.119 s |

The v0.5.2 harness and correctness gate add instrumentation and ledger work. Because the supplied v0.5.1 runs were not repeated with identical final-code instrumentation, the send-rate and ClickHouse differences are not classified here as regressions or improvements.

## Final sustained-rate results

Each sustained stage ran for 300 seconds. Completion values are shown as time from send start and drain time after the sender finished.

| Target | Exact source / ledger | Actual rate | ClickHouse complete: start / post-send | Evaluation complete: start / post-send | Evaluation processing / effective rate | Peak unevaluated | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 100 EPS | 30,000 / 30,000 | 100.00 EPS | 300.438 s / 0.428 s | 302.378 s / 2.368 s | 14.481030 s / 2,071.68 EPS | 1,008 | PASS |
| 250 EPS | 75,000 / 75,000 | 249.99 EPS | 300.468 s / 0.457 s | 307.079 s / 7.067 s | 22.625312 s / 3,314.87 EPS | 2,560 | PASS |
| 500 EPS | 150,000 / 150,000 | 499.98 EPS | 302.940 s / 2.926 s | 309.812 s / 9.798 s | 48.931766 s / 3,065.49 EPS | 4,592 | PASS |

Artifact run IDs:

- `perf-v052-perf-v052-cursor-final-sustained-100eps-20260912T132325Z-83d346e6`
- `perf-v052-perf-v052-cursor-final-sustained-250eps-20260912T132857Z-c2108e1c`
- `perf-v052-perf-v052-cursor-final-sustained-500eps-20260912T133433Z-06fb98db`

All three achieved the requested-rate guard, exact source and scoped-ledger counts, zero final backlog, zero unexpected detections, and no duplicate amplification. No rate above the requested 500 EPS ceiling was attempted.

## Ledger growth and query cost

A read-only observation at 2026-09-12 13:40 UTC, after the final six-stage benchmark series, found 1,502,072 physical ledger rows and 1,502,072 unique engine/ruleset/event identities. Eight active parts occupied 118,656,003 compressed bytes (113.16 MiB) and 387,969,410 uncompressed bytes (370.00 MiB). The final series added exactly 366,000 logical ledger rows. The retained source table held 1,877,148 physical and unique events, and the active engine/ruleset scope had zero pending anti-join rows. A byte-accurate pre-series ledger snapshot was not captured, so this report does not claim a storage-byte delta for the series.

Recent idle-cycle query-log measurements on that retained dataset were:

| Read path | Samples | Average / p50 / p95 / maximum | Average / maximum bytes read |
| --- | ---: | ---: | ---: |
| Candidate ledger anti-join | 439 | 140.37 / 128 / 210 / 262 ms | 473,975,988 / 581,216,964 |
| Actual-backlog ledger anti-join | 546 | 92.07 / 89 / 122 / 161 ms | 263,670,170 / 331,876,938 |
| Checkpoint plus ledger head | 546 | 15.23 / 14 / 22 / 50 ms | 133,862,258 / 160,911,058 |
| Positional source head/lag | 546 | 10.90 / 10 / 16 / 38 ms | 78,586,155 / 93,369,854 |
| Evaluation-scope/cursor lookup | 546 | 2.60 / 3 / 3 / 9 ms | 362 / 642 |

Summing the five per-query averages yields about 906.08 MiB when all five paths execute in a cycle; actual cycle cost varies because the query sample counts differ. This is acceptable for the tested single-node lab, but the increase on the larger retained dataset directly demonstrates why ledger retention and query optimization remain required future scalability work.

## Resource observations

Docker CPU percentages are aggregate across assigned logical CPUs and can exceed 100%. Values are average / peak. Short burst sampling is coarse: the 10K Vector samples missed its active load interval, so the near-zero Vector CPU observation for that stage is not evidence that Vector performed no work.

| Stage | Component | CPU average / peak | RAM average / peak |
| --- | --- | ---: | ---: |
| 1K burst | ClickHouse | 23.12% / 56.86% | 874.93 / 977.40 MiB |
| 1K burst | Detection engine | 12.50% / 37.49% | 29.72 / 30.17 MiB |
| 1K burst | Vector | 0.04% / 0.04% | 102.40 / 103.80 MiB |
| 10K burst | ClickHouse | 13.36% / 17.92% | 928.67 / 981.30 MiB |
| 10K burst | Detection engine | 4.22% / 12.63% | 35.32 / 45.11 MiB |
| 10K burst | Vector | 9.19% / 27.50% | 113.30 / 117.30 MiB |
| 100K burst | ClickHouse | 604.08% / 1,100.27% | 1,731.29 / 2,094.08 MiB |
| 100K burst | Detection engine | 20.19% / 57.48% | 32.59 / 48.76 MiB |
| 100K burst | Vector | 62.35% / 283.21% | 122.56 / 125.00 MiB |
| 100 EPS | ClickHouse | 43.69% / 523.18% | 1,157.18 / 1,898.50 MiB |
| 100 EPS | Detection engine | 4.77% / 40.11% | 31.97 / 53.52 MiB |
| 100 EPS | Vector | 3.93% / 6.75% | 104.53 / 119.70 MiB |
| 250 EPS | ClickHouse | 86.37% / 767.86% | 1,347.97 / 2,078.72 MiB |
| 250 EPS | Detection engine | 5.43% / 40.40% | 32.44 / 54.26 MiB |
| 250 EPS | Vector | 9.72% / 13.90% | 103.24 / 107.50 MiB |
| 500 EPS | ClickHouse | 188.42% / 1,364.69% | 1,492.06 / 2,657.28 MiB |
| 500 EPS | Detection engine | 5.99% / 81.54% | 33.20 / 56.00 MiB |
| 500 EPS | Vector | 21.07% / 30.63% | 104.24 / 107.00 MiB |

## Detection latency

Run `latency-v052-20260912T134438Z-bcbb16f6` submitted ten harmless synthetic Sysmon Event ID 1 records one second apart. The payloads represented, but did not execute, encoded PowerShell commands. The run produced the ten expected `fusion-windows-encoded-powershell` detections, an exact 10/10 current-engine/current-ruleset ledger, and zero final actual backlog.

| Sample | Minimum | Average | Median | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: |
| v0.5.2 ledger-backed, n=10 | 1.776 s | 6.490 s | 7.013 s | 11.052 s | 11.052 s |
| v0.5.1 supplied baseline, n=10 | 1.589 s | 7.041 s | 7.545 s | 10.955 s | 10.955 s |

Both samples reflect the configured 10-second idle poll. Ten observations are insufficient for a statistical latency-improvement claim.

## Backlog and recovery validation

### Preloaded same-timestamp backlog

Run `preloaded-v052-20260912T134501Z-34584964` stopped the detector while 10,000 nonmatching events sharing one millisecond timestamp were ingested. After the same detector container restarted, ten full 1,000-event batches were evaluated in 7.388 seconds from engine start. Source and current-ruleset ledger counts were exactly 10,000, the actual backlog returned to zero, no duplicate amplification occurred, and container identity plus automatic restart count were preserved.

This test specifically verifies bounded immediate draining without an unconditional 10-second sleep between full batches.

### ClickHouse outage and Vector replay

Run `outage-v052-20260912T134522Z-9cad6695` stopped ClickHouse while Vector accepted 1,000 events into its existing recovery path. After ClickHouse restarted, all 1,000 events were stored and ledgered with exact physical and unique counts. The one expected encoded-PowerShell detection existed exactly once physically, detector retry/backoff was observed, actual backlog returned to zero, and container identities plus automatic restart counts were preserved.

No Docker volume or Vector buffer was deleted or recreated.

## Correctness finding: why the ledger is required

An earlier pre-ledger v0.5.2 100K run reached its positional checkpoint in 19.434 seconds and stored all 100,000 events, but cycle logs observed only 76,213 events as new. That result is **INCONCLUSIVE**, not a successful evaluation-completeness result. A deterministic 1,001-event same-timestamp case then proved the defect: positional traversal evaluated 1,000 rows and permanently left one lower-UID row undiscovered while reporting zero checkpoint lag.

The final ledger-backed 100K run evaluated and ledgered all 100,000 unique source events and independently proved zero remaining anti-join rows. Its 44.119-second exact completion includes the correctness cost of ledger writes, persisted page rotation, and anti-join/count work. The earlier 19.434-second positional result is not an equivalent correct-completion baseline and must not be presented as one.

## Remaining limits

- `fusion.detection_evaluated_events` intentionally has no TTL. It grows by one logical row per evaluated event for each engine/ruleset identity. Expiring a ledger row while its source event is still eligible could cause reevaluation, so any future retention design must coordinate source retention, ruleset lifecycle, and ledger retention.
- The fixed enrollment floor and current exact backlog query require source scanning plus an anti-join against the growing ledger. The tested maximum was 150,000 events over a five-minute sustained stage; these results do not establish long-duration query cost or unbounded ledger scalability.
- Exact counts and `FINAL` queries are appropriate acceptance gates, but their cost can rise with retained data. A production-scale telemetry/metrics design remains future work.
- Checkpoint-table metrics are the latest cycle snapshot, while every cycle is also logged. A source event arriving just after a cycle can wait for the next configured poll.
- Repeatable evaluation failures remain unledgered and rotate into later candidate pages. They cannot permanently block later valid events, but they continue to consume retry capacity and require operator investigation.
- The Vector `/metrics` body was unavailable, so this report makes no counter-based claim about Vector error/drop deltas.
- These are single-node Docker Desktop lab measurements, not HA, enterprise-capacity, or public-network deployment claims.

## Conclusion

The final ledger-backed implementation resolved the deterministic same-timestamp/lower-UID completeness failure. It passed exact source, exact current-engine/current-ruleset ledger, independent zero-backlog, no-amplification, latency, preloaded-backlog, ClickHouse recovery, and sustained-rate gates through 500 EPS. The measured performance cost is explicit, and the no-TTL ledger plus growing anti-join/query surface remain documented limitations rather than hidden scalability claims.
