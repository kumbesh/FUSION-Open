# Contributing to Fusion

Thank you for improving Fusion.

1. Fork the repository and create a focused branch.
2. Keep configuration portable across Docker Desktop and Docker Engine.
3. Add or update Vector unit tests and synthetic fixtures for normalization changes.
4. Validate changed endpoint templates with `agents/windows/test-config.ps1`, `agents/linux/test-config.sh`, or `integrations/suricata/test-config.sh` as applicable.
5. Run `scripts/validate.ps1` or `scripts/validate.sh` before submitting a pull request.
6. Never commit `.env`, credentials, real hostnames, or production telemetry.
7. Add new security tools through the `/security` envelope and shared table; do not add vendor-specific tables or parallel pipelines without an approved architecture change.
8. Do not treat fixtures as real-integration acceptance. Record manual sensor evidence for release gates that require live telemetry.
9. Detection rules must use the documented Sigma subset, normalized allowlisted fields, stable unique IDs, conservative severity, and positive plus negative fixtures. Run `fusion-detection validate-rules` and the detection unit tests before review.

Bug reports should include the operating system, Docker and Compose versions, relevant container logs, and steps to reproduce. Sample events must be synthetic and free of sensitive data.
