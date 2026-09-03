# Security policy

## Supported versions

Fusion is a learning lab. Security fixes are applied to the current `main` branch; older revisions are not maintained.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature for this repository, or contact the repository owner privately. Include the affected version, reproduction steps, impact, and any suggested mitigation.

## Deployment warning

The included topology is bound to localhost by default and is not hardened for exposure to an untrusted network. Fusion v0.3 allows the ingestion listener alone to bind to a specific lab interface through `FUSION_BIND_ADDRESS`; when used, restrict TCP 8686 with a host firewall rule to the Windows or Linux test VM address or isolated lab subnet.

The v0.3 `/sysmon` and `/linux` HTTP ingestion paths have no TLS and no authentication. Never bind TCP 8686 to `0.0.0.0`, expose it directly to the public Internet, or place it on an untrusted network. Before any shared or production deployment, add TLS, ingestion authentication, least-privilege ClickHouse accounts, centralized secret management, network policy, backups, monitoring, and an explicit retention policy.

The Linux Vector service runs as root so it can read the normally restricted audit log. Keep the included systemd sandbox and dedicated state directories intact. Audit and command telemetry can contain usernames, command arguments, remote addresses, and other sensitive data; use synthetic accounts and disposable endpoints in the lab.
