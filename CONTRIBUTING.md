# Contributing to Sentinel

Sentinel is a security lab and reference environment. Changes should distinguish repository implementation from deployment-specific evidence and should never imply that an untested response path is production-safe.

## Expectations

- Keep Sigma source rules, deployed representations, validation records, and ATT&CK mappings synchronized.
- Add validation for new detection and infrastructure behavior.
- Document false-positive assumptions and required telemetry.
- Treat destructive response changes as high risk and describe authorization, rollback, and failure behavior.
- Never commit secrets, Terraform state, alert evidence, customer data, or model-provider credentials.

Run the detection validator and relevant infrastructure checks before submitting a pull request. The pull request should identify the tested deployment profile, evidence collected, and limitations that remain.

Report vulnerabilities through `SECURITY.md`.
