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
