# Changelog

Notable Sentinel changes will be recorded here. Sentinel is currently a lab/reference project; entries describe repository capabilities, not proof of a production deployment.

## Unreleased

### Added

- Contribution and private security-reporting policies.
- Operational readiness and recovery evidence guidance.
- Explicit documentation of lab status and automated-response limitations.
- ILM rollover + retention for the Elastic telemetry and audit indices
  (`auditbeat-linux`, `winlogbeat-ecs`, `sentinel-triage`,
  `sentinel-response-actions`), plus a one-time, human-run
  `bootstrap-rollover-migration.sh` that reindexes the existing plain
  indices onto write aliases behind typed confirmation prompts.
- Container healthchecks for the MCP server and the n8n triage service.

### Changed

- MCP server reuses a pooled HTTP client across tool calls, and resolves
  triage documents by `_id` search so lookups keep working once
  `sentinel-triage` has rolled over to a multi-index alias.
- The LLM triage workflow skips alerts a previous poll already triaged,
  removing the duplicate work caused by the deliberate lookback overlap.

Earlier implementation history is described in `docs/build-log.md` and the Git history.
