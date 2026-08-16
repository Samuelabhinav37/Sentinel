#!/usr/bin/env bash
# The single command for the whole detection-rule layer: deploys every rule,
# then re-attaches the push action and re-applies alert suppression to every
# rule. All three steps every time, in this order, on purpose -- deploy.sh's
# PUT replaces a rule's entire body, which silently wipes actions and
# alert_suppression if you only re-run deploy.sh (a real bug this project
# hit once already; see docs/build-log.md). Running the three scripts
# separately and forgetting the last two is exactly the mistake this script
# exists to make impossible.
#
# Usage:
#   KIBANA_URL=http://100.103.246.10:5601 \
#   ELASTIC_PASSWORD=... \
#   CONNECTOR_ID=<id from create-push-connector.sh> \
#   ./deploy-all.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${KIBANA_URL:?set KIBANA_URL, e.g. http://100.103.246.10:5601}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"
: "${CONNECTOR_ID:?set CONNECTOR_ID to the id printed by create-push-connector.sh}"

echo "== 1/3: deploying rules =="
./deploy.sh

echo "== 2/3: attaching push actions =="
./attach-push-actions.sh

echo "== 3/3: applying alert suppression =="
./apply-alert-suppression.sh

echo "== done: $(ls *.json | wc -l | tr -d ' ') rules deployed, actioned, and suppressed =="
