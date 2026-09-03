# Security policy

## Supported versions

Fusion is a learning lab. Security fixes are applied to the current `main` branch; older revisions are not maintained.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature for this repository, or contact the repository owner privately. Include the affected version, reproduction steps, impact, and any suggested mitigation.

## Deployment warning

The included topology is bound to localhost by default and is not hardened for exposure to an untrusted network. HTTP ingestion can bind to a specific lab interface through `FUSION_BIND_ADDRESS`; TCP/UDP syslog has its own `FUSION_SYSLOG_BIND_ADDRESS`. When used, restrict TCP 8686 and only the required TCP/UDP 5514 transports with host firewall rules scoped to individual test devices or the isolated lab subnet.

The `/sysmon`, `/linux`, and `/security` HTTP paths have no TLS and no authentication. Generic syslog is plaintext and unauthenticated. Never bind either address to `0.0.0.0`, expose 8686 or 5514 directly to the public Internet, or place them on an untrusted network. Source data may contain sensitive payloads and anyone with network access can inject records. Before any shared or production deployment, add TLS, ingestion authentication, least-privilege ClickHouse accounts, centralized secret management, network policy, backups, monitoring, and an explicit retention policy.

Future ingestion hardening should include HTTPS with scoped API tokens or mTLS and syslog over TLS. These controls are not implemented in v0.4 and must not be inferred from source-address logging or firewall guidance.

The Linux Vector service runs as root so it can read the normally restricted audit log. Keep the included systemd sandbox and dedicated state directories intact. Audit and command telemetry can contain usernames, command arguments, remote addresses, and other sensitive data; use synthetic accounts and disposable endpoints in the lab.

The Suricata EVE shipper also runs as a sandboxed root service so it can read `/var/log/suricata`. It does not install or manage Suricata. Preserve the read-only source path, bounded buffers, restrictive state-directory permissions, and source-scoped firewall rules.

## Detection rules and analytical results

Detection rules are trusted, repository-controlled configuration. The detection engine reads normalized security events from ClickHouse and writes only to the detection/checkpoint tables using the lab's current ClickHouse credential. A production deployment must replace this shared credential with separately managed least-privilege accounts that grant event-table read access and detection/checkpoint write access only.

Do not accept or automatically activate arbitrary Sigma YAML from untrusted users. The Fusion compiler enforces a strict field and operator allowlist, evaluates values in Python rather than interpolating them into SQL, and rejects unsupported constructs. This boundary reduces injection risk but does not replace review: a syntactically valid rule can still be expensive, noisy, misleading, or designed to expose sensitive event fields through evidence.

Fusion does not download community rules, MITRE data, or other executable configuration at runtime. Keep those controls intact. Review rule sources, metadata, expected matches, expected non-matches, and performance impact before merging.

Detection evidence intentionally contains focused normalized context rather than the complete raw event, but it can still include usernames, command lines, hostnames, and network addresses. Apply the same access and retention controls used for source telemetry. Detection results are analytical signals, not guarantees that an event is malicious; validate context before taking action.

The detection container has no host port and is isolated from ingestion. Stopping or crashing it must not interrupt Vector or ClickHouse. Preserve the non-root user, read-only filesystem, dropped capabilities, bounded resources, polling limits, and retry backoff in `docker-compose.yml`.
