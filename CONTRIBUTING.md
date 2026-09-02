# Contributing to Fusion

Thank you for improving Fusion.

1. Fork the repository and create a focused branch.
2. Keep configuration portable across Docker Desktop and Docker Engine.
3. Add or update Vector unit tests for normalization changes.
4. Run `scripts/validate.ps1` or `scripts/validate.sh` before submitting a pull request.
5. Never commit `.env`, credentials, real hostnames, or production telemetry.

Bug reports should include the operating system, Docker and Compose versions, relevant container logs, and steps to reproduce. Sample events must be synthetic and free of sensitive data.

