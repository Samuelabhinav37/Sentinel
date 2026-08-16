#!/usr/bin/env bash
# Attaches the n8n webhook connector as a per-alert action to every deployed
# Sigma rule, so Kibana pushes each new alert to n8n the instant it fires
# (see infra/compose/soar/n8n/workflows/llm-triage-push.json) instead of
# waiting for n8n's 5-min poll. Safe to re-run: PATCH replaces the rule's
# actions array each time rather than appending duplicates.
#
# {{{context}}} (triple mustache) is required, not {{context}} -- the double
# form double-escapes embedded quotes and produces invalid JSON on the wire
# (see docs/build-log.md Phase 23).
#
# Usage: KIBANA_URL=http://100.103.246.10:5601 ELASTIC_PASSWORD=... CONNECTOR_ID=<id from create-push-connector.sh> ./attach-push-actions.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${KIBANA_URL:?set KIBANA_URL, e.g. http://100.103.246.10:5601}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"
: "${CONNECTOR_ID:?set CONNECTOR_ID to the id printed by create-push-connector.sh}"

for rule in *.json; do
  rid=$(python3 -c "import json; print(json.load(open('$rule'))['rule_id'])")
  resp=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -X PATCH \
    "${KIBANA_URL}/api/detection_engine/rules" \
    -H 'Content-Type: application/json' \
    -d "{
      \"rule_id\": \"${rid}\",
      \"actions\": [
        {
          \"group\": \"default\",
          \"action_type_id\": \".webhook\",
          \"id\": \"${CONNECTOR_ID}\",
          \"params\": { \"body\": \"{{{context}}}\" },
          \"frequency\": { \"summary\": false, \"throttle\": null, \"notifyWhen\": \"onActiveAlert\" }
        }
      ]
    }")
  name=$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name', d.get('message')))")
  echo "$rid -> $name"
done
