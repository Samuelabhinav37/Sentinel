#!/usr/bin/env bash
# Deploys Shuffle SOAR (pinned to v2.2.1) onto a fresh host.
# Run from anywhere; clones into /opt/sentinel/Shuffle.
set -euo pipefail

SHUFFLE_DIR=/opt/sentinel/Shuffle
TAG=v2.2.1

sudo mkdir -p /opt/sentinel
sudo chown "$(whoami)":"$(whoami)" /opt/sentinel

if [ ! -d "$SHUFFLE_DIR" ]; then
  git clone https://github.com/Shuffle/Shuffle.git "$SHUFFLE_DIR"
fi

cd "$SHUFFLE_DIR"
git checkout "$TAG"

sudo chown -R 1000:1000 "$SHUFFLE_DIR/shuffle-database"
sudo mkdir -p /opt/sentinel/shuffle-files

if [ ! -f .env ]; then
  echo "Copy $(dirname "$0")/.env.example to $SHUFFLE_DIR/.env, fill in real values" \
       "(especially SHUFFLE_OPENSEARCH_PASSWORD and OUTER_HOSTNAME), then re-run."
  exit 1
fi

sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-elasticsearch.conf > /dev/null

sudo docker compose up -d
echo "Shuffle starting. Frontend will be reachable at https://\${OUTER_HOSTNAME}:\${FRONTEND_PORT_HTTPS}"
