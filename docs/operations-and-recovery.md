# Operations and Recovery Guide

This guide records the minimum evidence required before describing a Sentinel deployment as operationally ready.

## Deployment record

Record the commit, deployment profile, container image versions or digests, infrastructure plan, secret sources, exposed endpoints, and responsible operator. Store real credentials outside this repository.

## Health verification

Verify telemetry ingestion, detection execution, triage writes, notification delivery, audit indexing, storage capacity, clock synchronization, and backup completion. A component being reachable is not proof that the end-to-end detection path works.

## Recovery evidence

At least one controlled exercise should demonstrate:

1. restoration of Elasticsearch and other persistent stores;
2. recreation of infrastructure from reviewed configuration;
3. re-establishment of agent and integration credentials;
4. replay of a benign test signal through detection and triage;
5. confirmation that destructive response remains disabled until separately authorized.

Capture timestamps, commands, resulting versions, validation output, recovery duration, and unresolved deviations. Store evidence in an access-controlled operational system, not in the public repository.

## Incident response

If automation behaves unexpectedly, disable response integrations first, preserve relevant logs, rotate affected shared credentials, and validate the alert-to-action chain before re-enabling execution. Document ownership and escalation contacts for each deployed environment.
