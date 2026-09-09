# Vector sink recovery

## Confirmed v0.5 recovery incident

At `2026-09-09 19:53:21 UTC`, ClickHouse rejected one Vector request with
`Code: 117 INCORRECT_DATA`. The strict `JSONEachRow` parser found the unexpected
top-level field `X-Fusion-Validation-Id` at row 197. ClickHouse recorded a
4,686,949-byte request, zero inserted rows, and a parsing error. Vector classified
the HTTP 400 response as non-retryable and reported 1,000 unintentionally dropped
events. Requests immediately before and after it succeeded, including other
1,000-row requests, so neither the configured event count nor payload size caused
the rejection.

The surrounding inserts contained replayed telemetry, making a stale buffered
event the likely source. The rejected request body was not retained, however, and
every tracked Fusion normalizer revision rebuilds the event into a fixed schema.
The exact provenance of the offending row therefore cannot be proven. Raw
security payloads and credentials should not be added to diagnostic logs merely
to establish that provenance.

## Hardening behavior

Fusion keeps strict ClickHouse schema enforcement with
`skip_unknown_fields: false`. At the ClickHouse serialization boundary, Vector
now excludes only these transport-level field names:

- `X-Fusion-Validation-Id`
- `x-fusion-validation-id`

The normalizers continue to map their value into `validation_id`, and the
original input—including the captured header—is preserved inside `raw_json`.
The exclusion is part of the sink encoder, which runs after disk-buffer replay,
so it also repairs this known stale event shape without deleting or rewriting the
buffer. Batch size, retry count, retry backoff, and acknowledgement behavior are
unchanged.

Transient connection errors, timeouts, HTTP 408/429 responses, and most 5xx
responses follow Vector's bounded retry policy. A permanent HTTP 400/schema
error, or a request that exhausts its configured retry attempts, is terminal:
Vector logs the rejected request and dropped-event count, then acknowledges it
out of the disk buffer. Vector 0.58's ClickHouse sink has no rejected-event or
dead-letter output. The normalizer's `rejected_console` path covers transform and
route failures only; it cannot receive sink HTTP failures.

## Regression test

Run the isolated test from a POSIX shell with Docker available:

```sh
./scripts/test-vector-recovery.sh
```

The harness publishes no host ports and uses only a uniquely prefixed Compose
project with labelled, project-scoped test volumes. It refuses to reuse existing
project resources. The test verifies normal ingestion, stops ClickHouse, buffers
exactly 1,000 legacy-shaped events with the stale field only on row 197, restarts
Vector with the preserved buffer and hardened sink, restores ClickHouse, and
checks that:

- all 1,000 events are stored;
- all 1,000 source event IDs are unique;
- row 197 is stored exactly once;
- no `Code: 117`, bad-request, or dropped-event error occurs after restart; and
- new ingestion still works after recovery.

Set `FUSION_RECOVERY_KEEP_STATE=1` to retain the generated fixtures and rendered
legacy configuration for inspection. The harness never invokes the default
Fusion Compose project and never removes Docker volumes; it prints the unique
test project name so its labelled ClickHouse and Vector volumes remain available
for inspection.

## Remaining limitations

This fix is deliberately narrow. An unrelated future schema or type-invalid
field can still cause ClickHouse to reject its complete request; Vector 0.58 does
not provide per-row quarantine or automatic batch bisection for this sink. Fusion
logs such terminal failures but does not yet have a dead-letter store. Delivery is
at least once, so an ambiguous response failure can also produce duplicates even
though the controlled recovery regression checks that this path does not amplify
events. Operators should monitor Vector dropped-event errors and ClickHouse
`INCORRECT_DATA` responses and preserve the buffer while investigating.
