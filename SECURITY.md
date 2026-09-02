# Security policy

## Supported versions

Fusion is a learning lab. Security fixes are applied to the current `main` branch; older revisions are not maintained.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature for this repository, or contact the repository owner privately. Include the affected version, reproduction steps, impact, and any suggested mitigation.

## Deployment warning

The included topology is bound to localhost by default and is not hardened for exposure to an untrusted network. Fusion v0.2 allows the ingestion listener alone to bind to a specific lab interface through `FUSION_BIND_ADDRESS`; when used, restrict TCP 8686 with a host firewall rule to the test VM address or isolated lab subnet.

The v0.2 HTTP ingestion endpoint has no TLS and no authentication. Never bind it to `0.0.0.0`, expose it directly to the public Internet, or place it on an untrusted network. Before any shared or production deployment, add TLS, ingestion authentication, least-privilege ClickHouse accounts, centralized secret management, network policy, backups, monitoring, and an explicit retention policy.
