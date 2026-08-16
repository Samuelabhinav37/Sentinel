#!/usr/bin/env bash
# The one command for a full software-layer redeploy: index templates,
# every Sigma rule (+ push actions + alert suppression, in the order that
# doesn't wipe them), and every n8n workflow. Run this after any change to
# detections/, infra/elasticsearch/index-templates/, or
# infra/compose/soar/n8n/workflows/.
#
# Scope, deliberately: this assumes the VMs already exist and their Docker
# Compose stacks are already running (terraform apply + the per-service
# compose deploys are a separate, much less frequent, much higher-blast-
# radius operation that stays a conscious manual step, not something a
# routine redeploy command should ever silently bundle in).
#
# Usage:
#   ELASTIC_URL=http://100.103.246.10:9200 \
#   KIBANA_URL=http://100.103.246.10:5601 \
#   ELASTIC_PASSWORD=... \
#   CONNECTOR_ID=<id from detections/deployed/create-push-connector.sh> \
#   N8N_URL=http://100.90.159.33:5678 \
#   N8N_API_KEY=... \
#   ./scripts/redeploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."

: "${ELASTIC_URL:?set ELASTIC_URL, e.g. http://100.103.246.10:9200}"
: "${KIBANA_URL:?set KIBANA_URL, e.g. http://100.103.246.10:5601}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"
: "${CONNECTOR_ID:?set CONNECTOR_ID to the id printed by detections/deployed/create-push-connector.sh}"
: "${N8N_URL:?set N8N_URL, e.g. http://100.90.159.33:5678}"
: "${N8N_API_KEY:?set N8N_API_KEY, from Settings -> n8n API in the n8n UI}"

echo "###### index templates ######"
(cd infra/elasticsearch/index-templates && ELASTIC_URL="$ELASTIC_URL" ELASTIC_PASSWORD="$ELASTIC_PASSWORD" ./deploy.sh)

echo "###### detection rules + push actions + alert suppression ######"
(cd detections/deployed && KIBANA_URL="$KIBANA_URL" ELASTIC_PASSWORD="$ELASTIC_PASSWORD" CONNECTOR_ID="$CONNECTOR_ID" ./deploy-all.sh)

echo "###### n8n workflows ######"
(cd infra/compose/soar/n8n && N8N_URL="$N8N_URL" N8N_API_KEY="$N8N_API_KEY" ./deploy-workflows.sh)

echo "###### redeploy complete ######"
