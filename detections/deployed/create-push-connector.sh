#!/usr/bin/env bash
# One-time bootstrap: creates the Kibana .webhook connector that pushes alerts
# to n8n's webhook trigger (infra/compose/soar/n8n/workflows/llm-triage-push.json).
# Requires a Gold+ license -- this project runs on a self-hosted trial license
# started via POST _license/start_trial (see docs/build-log.md Phase 23).
# Prints the connector id; pass it as CONNECTOR_ID to attach-push-actions.sh.
# Usage: KIBANA_URL=http://100.103.246.10:5601 ELASTIC_PASSWORD=... N8N_WEBHOOK_URL=http://100.90.159.33:5678/webhook/sentinel-alert-push ./create-push-connector.sh
set -euo pipefail

: "${KIBANA_URL:?set KIBANA_URL, e.g. http://100.103.246.10:5601}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"
: "${N8N_WEBHOOK_URL:?set N8N_WEBHOOK_URL, e.g. http://100.90.159.33:5678/webhook/sentinel-alert-push}"

curl -sf -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -X POST \
  "${KIBANA_URL}/api/actions/connector" \
  -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"n8n Alert Push\",
    \"connector_type_id\": \".webhook\",
    \"config\": {
      \"url\": \"${N8N_WEBHOOK_URL}\",
      \"method\": \"post\",
      \"headers\": { \"Content-Type\": \"application/json\" }
    },
    \"secrets\": {}
  }" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['id'])"
