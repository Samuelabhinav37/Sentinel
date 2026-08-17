#!/usr/bin/env bash
# Deploys Shuffle SOAR (pinned to v2.2.1) onto a fresh host.
# Run from anywhere; clones into /opt/sentinel/Shuffle.
#
# Set LAB_MODE=1 to also apply docker-compose.lab.yml (a much smaller
# OpenSearch heap -- see docs/deployment-profiles.md). Unset/0 keeps the
# full-deployment sizing, matching every environment this project has
# actually been validated against so far.
set -euo pipefail

SHUFFLE_DIR=/opt/sentinel/Shuffle
TAG=v2.2.1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

sudo mkdir -p /opt/sentinel
sudo chown "$(whoami)":"$(whoami)" /opt/sentinel

if [ ! -d "$SHUFFLE_DIR" ]; then
  git clone https://github.com/Shuffle/Shuffle.git "$SHUFFLE_DIR"
fi

cd "$SHUFFLE_DIR"
git checkout "$TAG"

# Permanent bug fix, not a sizing choice -- always applied. Upstream's
# orborus service is given BASE_URL=http://${OUTER_HOSTNAME}:5001, which is
# unreachable via hairpin NAT from orborus's own Docker network back to its
# own host; without this override, workflow triggers report success but
# nothing ever actually executes. See docs/build-log.md Phase 25.
cp "$SCRIPT_DIR/docker-compose.override.yml" "$SHUFFLE_DIR/docker-compose.override.yml"

sudo chown -R 1000:1000 "$SHUFFLE_DIR/shuffle-database"
sudo mkdir -p /opt/sentinel/shuffle-files

if [ ! -f .env ]; then
  echo "Copy $(dirname "$0")/.env.example to $SHUFFLE_DIR/.env, fill in real values" \
       "(especially SHUFFLE_OPENSEARCH_PASSWORD and OUTER_HOSTNAME), then re-run."
  exit 1
fi

sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-elasticsearch.conf > /dev/null

if [ "${LAB_MODE:-0}" = "1" ]; then
  cp "$SCRIPT_DIR/docker-compose.lab.yml" "$SHUFFLE_DIR/docker-compose.lab.yml"
  sudo docker compose -f docker-compose.yml -f docker-compose.override.yml -f docker-compose.lab.yml up -d
else
  sudo docker compose up -d
fi
echo "Shuffle starting. Frontend will be reachable at https://\${OUTER_HOSTNAME}:\${FRONTEND_PORT_HTTPS}"
