#!/usr/bin/env bash
# Deploys every rule in this directory to Kibana's Detection Engine.
# Usage: KIBANA_URL=http://100.103.246.10:5601 ELASTIC_PASSWORD=... ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${KIBANA_URL:?set KIBANA_URL, e.g. http://100.103.246.10:5601}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"

curl -s -u "elastic:${ELASTIC_PASSWORD}" -X POST -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' "${KIBANA_URL}/api/detection_engine/index" > /dev/null

for rule in *.json; do
  echo "Deploying $rule"
  # POST creates (404s if rule_id already exists is wrong -> actually 409);
  # PUT updates (404s if rule_id doesn't exist yet). Neither is a true
  # upsert, so try create first and fall back to update.
  resp=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" -X POST -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' "${KIBANA_URL}/api/detection_engine/rules" \
    -d @"$rule")
  if echo "$resp" | grep -q '"status_code":409'; then
    resp=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" -X PUT -H 'kbn-xsrf: true' \
      -H 'Content-Type: application/json' "${KIBANA_URL}/api/detection_engine/rules" \
      -d @"$rule")
  fi
  echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name', d))"
done
