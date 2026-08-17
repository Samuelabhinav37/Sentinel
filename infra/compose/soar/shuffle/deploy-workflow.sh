#!/usr/bin/env bash
# Deploys sentinel-auto-respond.json via Shuffle's API (a Shuffle API key,
# from Settings in the UI -- unlike n8n's, it's shown in plaintext
# permanently, not a one-time reveal). Looks up by name to decide
# create-vs-update, matching infra/compose/soar/n8n/deploy-workflows.sh's
# pattern, since Shuffle's create endpoint also doesn't support upsert.
#
# The committed file has placeholder url/headers values (the real ones
# contain the responder's shared-secret token) -- pass the real values as
# env vars and this script substitutes them before deploying.
#
# Usage:
#   SHUFFLE_URL=http://100.90.159.33:3001 SHUFFLE_API_KEY=... \
#   RESPONDER_URL=http://100.100.197.117:8088/respond/kill-process \
#   RESPONDER_TOKEN=... \
#   ./deploy-workflow.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${SHUFFLE_URL:?set SHUFFLE_URL, e.g. http://100.90.159.33:3001}"
: "${SHUFFLE_API_KEY:?set SHUFFLE_API_KEY, from Settings in the Shuffle UI}"
: "${RESPONDER_URL:?set RESPONDER_URL, e.g. http://100.100.197.117:8088/respond/kill-process}"
: "${RESPONDER_TOKEN:?set RESPONDER_TOKEN, from infra/compose/wazuh/.env on sentinel-wazuh}"

body=$(python3 -c "
import json, os
d = json.load(open('sentinel-auto-respond.json'))
for a in d['actions']:
    for p in a.get('parameters', []):
        if p['name'] == 'url':
            p['value'] = os.environ['RESPONDER_URL']
        if p['name'] == 'headers':
            p['value'] = 'Content-Type: application/json\nX-Responder-Token: ' + os.environ['RESPONDER_TOKEN']
print(json.dumps(d))
")

existing_id=$(curl -s "${SHUFFLE_URL}/api/v1/workflows?authorization=${SHUFFLE_API_KEY}" -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
  | python3 -c "
import json,sys
d = json.load(sys.stdin)
match = [w['id'] for w in d if w['name'] == 'Sentinel Auto-Respond']
print(match[0] if match else '')
")

if [ -n "$existing_id" ]; then
  curl -s "${SHUFFLE_URL}/api/v1/workflows/${existing_id}?authorization=${SHUFFLE_API_KEY}" \
    -H "Authorization: Bearer ${SHUFFLE_API_KEY}" -H "Content-Type: application/json" \
    -X PUT -d "$body" > /dev/null
  echo "Sentinel Auto-Respond -> updated (${existing_id})"
else
  echo "$body" > /dev/null
  echo "No existing workflow found -- Shuffle's create-from-scratch flow needs the visual"
  echo "editor for a first import (see docs/build-log.md for why: webhook trigger ids and"
  echo "the workflow's 'start' node aren't reliably settable via a raw POST). Build it once"
  echo "in the UI (Webhook -> Http POST), then re-run this script to keep it updated."
  exit 1
fi
