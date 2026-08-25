# Release Procedure

Sentinel releases should distinguish source readiness from deployment readiness.

## Source release

Validate Sigma rules, deployed rule representations, ATT&CK mappings, infrastructure syntax, dependency inputs, and documentation. Tag only a reviewed commit and record tool versions used during validation.

## Deployment promotion

Promotion additionally requires environment-specific telemetry tests, access review, secret rotation readiness, backup restoration evidence, and an end-to-end benign detection exercise. Automated response must remain disabled until its authorization and rollback controls are separately approved.

Release notes should enumerate supported deployment profiles, known limitations, migrations or manual steps, artifact versions, and rollback instructions. Do not attach operational secrets, alert evidence, or Terraform state.
