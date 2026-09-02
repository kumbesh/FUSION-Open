# Security policy

## Supported versions

Fusion is a learning lab. Security fixes are applied to the current `main` branch; older revisions are not maintained.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature for this repository, or contact the repository owner privately. Include the affected version, reproduction steps, impact, and any suggested mitigation.

## Deployment warning

The included topology is deliberately bound to localhost and is not hardened for exposure to an untrusted network. Before any shared or production deployment, add TLS, ingestion authentication, least-privilege ClickHouse accounts, centralized secret management, network policy, backups, monitoring, and an explicit retention policy.

