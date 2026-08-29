#!/usr/bin/env bash
# Deploys every ILM policy in this directory. PUT _ilm/policy/<name> is a
# true upsert, so this is safe to re-run -- it does NOT retroactively touch
# already-rolled-over indices' phase timing, just the policy definition.
#
# Run this BEFORE infra/elasticsearch/index-templates/deploy.sh, since the
# templates reference these policies by name via index.lifecycle.name.
#
# This only creates/updates the policies. It does not migrate the existing
# auditbeat-linux / sentinel-triage / sentinel-response-actions indices onto
# a rollover alias -- see bootstrap-rollover-migration.sh for that one-time,
# human-run step (not part of scripts/redeploy.sh).
#
# Usage: ELASTIC_URL=http://100.103.246.10:9200 ELASTIC_PASSWORD=... ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${ELASTIC_URL:?set ELASTIC_URL, e.g. http://100.103.246.10:9200}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"

for policy in *.json; do
  name="${policy%.json}"
  echo "Deploying ILM policy: $name"
  curl -sf -u "elastic:${ELASTIC_PASSWORD}" -X PUT \
    -H 'Content-Type: application/json' \
    "${ELASTIC_URL}/_ilm/policy/${name}" \
    -d @"$policy" > /dev/null
done
