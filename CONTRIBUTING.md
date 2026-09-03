# Contributing to Fusion

Thank you for improving Fusion.

1. Fork the repository and create a focused branch.
2. Keep configuration portable across Docker Desktop and Docker Engine.
3. Add or update Vector unit tests and synthetic fixtures for normalization changes.
4. Validate changed endpoint templates with `agents/windows/test-config.ps1` or `agents/linux/test-config.sh` as applicable.
5. Run `scripts/validate.ps1` or `scripts/validate.sh` before submitting a pull request.
6. Never commit `.env`, credentials, real hostnames, or production telemetry.

Bug reports should include the operating system, Docker and Compose versions, relevant container logs, and steps to reproduce. Sample events must be synthetic and free of sensitive data.
