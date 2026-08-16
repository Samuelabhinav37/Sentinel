#!/usr/bin/env bash
# Deploys every Elasticsearch index template in this directory.
# PUT _index_template/<name> is a true upsert, so this is safe to re-run.
# Usage: ELASTIC_URL=http://100.103.246.10:9200 ELASTIC_PASSWORD=... ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${ELASTIC_URL:?set ELASTIC_URL, e.g. http://100.103.246.10:9200}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"

for template in *.json; do
  name="${template%.json}"
  echo "Deploying index template: $name"
  curl -sf -u "elastic:${ELASTIC_PASSWORD}" -X PUT \
    -H 'Content-Type: application/json' \
    "${ELASTIC_URL}/_index_template/${name}" \
    -d @"$template" > /dev/null
done
