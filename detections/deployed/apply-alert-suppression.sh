#!/usr/bin/env bash
# Collapses duplicate alerts from a single real-world action into one.
# auditd telemetry logs one event per execve, so a single attacker action
# that crosses a privilege boundary (e.g. `sudo cat /etc/shadow`) produces
# several distinct alerts -- one for the shell, one for sudo, one for the
# process sudo execs -- all on the same host within the same second (see
# docs/build-log.md: the /etc/shadow rule fired 4x for one atomic test).
#
# group_by host.name alone is a deliberate tradeoff: it collapses that
# intra-event-chain duplication, but it also means two genuinely unrelated
# firings of the *same rule* on the *same host* within the suppression
# window collapse into one alert too. For this project's single-host lab
# scope that's the right trade; a multi-host production deployment would
# likely want a tighter group_by (e.g. + process.parent.pid) or a shorter
# duration.
#
# Safe to re-run: PATCH replaces the rule's alert_suppression each time.
# Usage: KIBANA_URL=http://100.103.246.10:5601 ELASTIC_PASSWORD=... ./apply-alert-suppression.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${KIBANA_URL:?set KIBANA_URL, e.g. http://100.103.246.10:5601}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"

for rule in *.json; do
  rid=$(python3 -c "import json; print(json.load(open('$rule'))['rule_id'])")
  resp=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -X PATCH \
    "${KIBANA_URL}/api/detection_engine/rules" \
    -H 'Content-Type: application/json' \
    -d "{
      \"rule_id\": \"${rid}\",
      \"alert_suppression\": {
        \"group_by\": [\"host.name\"],
        \"duration\": { \"value\": 5, \"unit\": \"m\" },
        \"missing_fields_strategy\": \"suppress\"
      }
    }")
  name=$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name', d.get('message')))")
  echo "$rid -> $name"
done
