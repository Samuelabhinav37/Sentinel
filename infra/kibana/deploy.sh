#!/usr/bin/env bash
# Deploys the "Sentinel SOC Overview" dashboard (MTTD trend, alert volume by
# rule, ATT&CK techniques that have actually fired, LLM triage severity
# breakdown, automated response outcomes) plus its 3 data views and 5
# visualizations, via Kibana's saved-objects import API.
#
# The NDJSON bundle was built as classic aggregation-based visualizations,
# not Lens -- their JSON schema is simple enough to hand-verify and diff in
# review, unlike Lens's internal representation. Regenerate it after editing
# anything in the Kibana UI with:
#   curl -u elastic:$ELASTIC_PASSWORD -H 'kbn-xsrf: true' -X POST \
#     "$KIBANA_URL/api/saved_objects/_export" -H 'Content-Type: application/json' \
#     -d '{"objects":[{"type":"dashboard","id":"a2beef5d-4c3d-4636-b436-6a17977bf416"}],"includeReferencesDeep":true}' \
#     -o sentinel-soc-overview.ndjson
#
# Safe to re-run: import uses overwrite semantics for objects with matching
# ids, so this updates in place rather than duplicating.
#
# Usage: KIBANA_URL=http://100.103.246.10:5601 ELASTIC_PASSWORD=... ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${KIBANA_URL:?set KIBANA_URL, e.g. http://100.103.246.10:5601}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"

curl -sf -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -X POST \
  "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
  -F "file=@sentinel-soc-overview.ndjson" \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('success:', d.get('success'))
print('imported:', d.get('successCount'), 'objects')
if d.get('errors'):
    print('errors:', json.dumps(d['errors'], indent=2))
"
