# Future API connector framework

Fusion v0.4 does not ship an API polling connector. This note defines the minimum contract for a later version so an API source can join the same normalization and storage path without introducing a second schema or pipeline.

## Connector boundary

An API connector should emit the same `/security` envelope used by file-based integrations:

```json
{
  "vendor": "Vendor",
  "product": "Product",
  "source_type": "vendor_api",
  "platform": "cloud",
  "device_name": "tenant-or-sensor",
  "event": {}
}
```

Vendor-specific interpretation belongs in a small, reviewable normalizer branch. The complete vendor response object must remain inside `event` so `raw_json` supports investigation and future reprocessing. API transport metadata must use the `ingestion_*` and `source_address` fields and must not overwrite event network endpoints.

## Required state and reliability controls

- **Cursor state:** persist opaque continuation tokens and high-water timestamps only after downstream acknowledgement. Store state in a dedicated connector data directory, not in source code or the event table.
- **Overlap:** request a small configurable look-back window to tolerate delayed records, then deduplicate.
- **Deduplication:** derive a stable key from the vendor event ID plus tenant/source identity. Define the retention and collision behavior before implementation.
- **Rate limits:** honor standard and vendor-specific reset/retry headers, add jitter, and cap concurrent requests.
- **Retry:** distinguish retryable transport/429/5xx failures from permanent 4xx/schema errors. Use bounded exponential backoff and a bounded disk buffer.
- **Pagination:** checkpoint only fully acknowledged pages. Detect repeated cursors to avoid loops.
- **Request bounds:** limit response bytes, page size, decompressed size, and parsing depth. Quarantine malformed records without halting other sources.
- **Secrets:** accept tokens through a local secret file or an external secret provider, with restrictive permissions. Never commit credentials, place them in URLs, copy them into events, or print them in logs.
- **TLS:** require HTTPS with certificate verification. Custom CAs must be explicit and narrowly scoped; an insecure-skip option should not be provided.
- **Observability:** expose last-success time, cursor age, API errors, throttling, dropped/quarantined records, buffer usage, and normalized event counts without leaking payloads or secrets.

## Review gate

Before adding a concrete connector, document the vendor API's authentication, permissions, cursor semantics, quotas, data-retention impact, stable event identifier, failure modes, and test fixtures. Unit tests must cover pagination, cursor restart, rate limiting, retry, deduplication, secret redaction, malformed/oversized responses, and compatibility with the common ClickHouse table. No new broker, vendor-specific table, or parallel ingestion stack is implied by this design.
