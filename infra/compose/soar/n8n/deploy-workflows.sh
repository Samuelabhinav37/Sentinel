#!/usr/bin/env bash
# Deploys every committed n8n workflow via the public REST API (an n8n API
# key, not the account password -- Settings -> n8n API in the UI). Looks up
# each workflow by name to decide create-vs-update, since the public API
# treats `id` as read-only on create (the server always generates a fresh
# one) -- there's no PUT-by-name upsert, so this script does the lookup
# itself. Safe to re-run.
#
# Usage: N8N_URL=http://100.90.159.33:5678 N8N_API_KEY=... ./deploy-workflows.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${N8N_URL:?set N8N_URL, e.g. http://100.90.159.33:5678}"
: "${N8N_API_KEY:?set N8N_API_KEY, from Settings -> n8n API in the n8n UI}"

for wf in workflows/*.json; do
  name=$(python3 -c "import json; print(json.load(open('$wf'))['name'])")

  # Strip id/active -- both are read-only on create, and active needs its
  # own /activate call regardless of create or update.
  body=$(python3 -c "
import json
d = json.load(open('$wf'))
d.pop('id', None)
d.pop('active', None)
print(json.dumps(d))
")

  existing_id=$(curl -s -H "X-N8N-API-KEY: ${N8N_API_KEY}" "${N8N_URL}/api/v1/workflows" \
    | python3 -c "
import json,sys
d = json.load(sys.stdin)
match = [w['id'] for w in d.get('data', []) if w['name'] == '$name']
print(match[0] if match else '')
")

  if [ -n "$existing_id" ]; then
    wf_id="$existing_id"
    curl -s -H "X-N8N-API-KEY: ${N8N_API_KEY}" -H "Content-Type: application/json" \
      -X PUT "${N8N_URL}/api/v1/workflows/${wf_id}" -d "$body" > /dev/null
    echo "$name -> updated ($wf_id)"
  else
    wf_id=$(curl -s -H "X-N8N-API-KEY: ${N8N_API_KEY}" -H "Content-Type: application/json" \
      -X POST "${N8N_URL}/api/v1/workflows" -d "$body" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
    echo "$name -> created ($wf_id)"
  fi

  curl -s -H "X-N8N-API-KEY: ${N8N_API_KEY}" -X POST "${N8N_URL}/api/v1/workflows/${wf_id}/activate" > /dev/null
  echo "$name -> activated"
done
