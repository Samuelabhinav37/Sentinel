#!/usr/bin/env bash
# ONE-TIME, HUMAN-RUN migration onto ILM-managed rollover aliases for
# auditbeat-linux, sentinel-triage, sentinel-response-actions, and
# winlogbeat-ecs. NOT part of scripts/redeploy.sh -- this mutates live index
# names (reindex + delete the old index), which is a different risk class
# than routine template/rule redeploys.
#
# Prerequisite: deploy the ILM policies and updated index templates FIRST
# (infra/elasticsearch/ilm-policies/deploy.sh, then
# infra/elasticsearch/index-templates/deploy.sh) -- the index_patterns
# already accept both the old plain names and the new rollover naming
# (<name>-000001, etc.), so the new indices this script creates pick up
# index.lifecycle.name / index.lifecycle.rollover_alias automatically.
#
# What this does, per target:
#   - auditbeat-linux, sentinel-triage, sentinel-response-actions: these
#     already hold live data as a single ever-growing plain index. Reindex
#     into "<name>-000001", verify the doc count matches, delete the old
#     plain index, then create an alias "<name>" -> "<name>-000001" with
#     is_write_index=true. Elasticsearch has no in-place rename, so the
#     reindex is unavoidable; this pauses the one Docker Compose service
#     that writes to each target before reindexing, to avoid losing writes
#     that land between the reindex snapshot and the old index's deletion.
#   - winlogbeat-ecs: no live data yet (Windows target is parked, see
#     README's Roadmap) -- just creates the empty "winlogbeat-ecs-000001"
#     index aliased as "winlogbeat-ecs" so the very first write from
#     winlogbeat lands on a rollover-managed index instead of a plain one.
#     Safe/idempotent to run before the Windows target ever exists.
#
# Safety: aborts before deleting anything if post-reindex doc counts don't
# match, or if the target is already an alias (migration already ran).
#
# Usage:
#   ELASTIC_URL=http://100.103.246.10:9200 \
#   ELASTIC_PASSWORD=... \
#   ./bootstrap-rollover-migration.sh
#
# Run from the VM (or anywhere with `docker compose` access to
# infra/compose/wazuh/auditbeat.yml) so the auditbeat pause/resume works;
# if run remotely, skip that step by hand instead (pause the container
# yourself, or accept the small write-loss race window on a lab system).
set -euo pipefail

: "${ELASTIC_URL:?set ELASTIC_URL, e.g. http://100.103.246.10:9200}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"

AUTH=(-u "elastic:${ELASTIC_PASSWORD}")
AUDITBEAT_COMPOSE="$(cd "$(dirname "$0")/../../compose/wazuh" && pwd)/auditbeat.yml"

es() { curl -sf "${AUTH[@]}" "$@"; }

target_kind() {
  # prints "alias", "index", or "absent" for a given name
  local name="$1"
  if es -o /dev/null -w '' "${ELASTIC_URL}/_alias/${name}" 2>/dev/null; then
    echo "alias"
  elif es -o /dev/null -w '' "${ELASTIC_URL}/${name}" 2>/dev/null; then
    echo "index"
  else
    echo "absent"
  fi
}

doc_count() {
  es "${ELASTIC_URL}/$1/_count" | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])"
}

migrate_existing_index() {
  local name="$1" pause_cmd="$2" resume_cmd="$3"
  local kind
  kind="$(target_kind "$name")"

  if [[ "$kind" == "alias" ]]; then
    echo "[$name] already an alias -- migration already ran, skipping."
    return
  fi
  if [[ "$kind" == "absent" ]]; then
    echo "[$name] no existing index found -- nothing to migrate (bootstrapping fresh instead)."
    bootstrap_fresh "$name"
    return
  fi

  echo "[$name] found as a plain index. Migrating to rollover alias..."
  [[ -n "$pause_cmd" ]] && { echo "[$name] pausing writer: $pause_cmd"; eval "$pause_cmd"; }

  local before after
  before="$(doc_count "$name")"
  echo "[$name] source doc count: $before"

  echo "[$name] reindexing $name -> ${name}-000001..."
  es -X POST "${ELASTIC_URL}/_reindex?wait_for_completion=true" \
    -H 'Content-Type: application/json' \
    -d "{\"source\": {\"index\": \"${name}\"}, \"dest\": {\"index\": \"${name}-000001\"}}" > /dev/null

  after="$(doc_count "${name}-000001")"
  echo "[$name] destination doc count: $after"

  if [[ "$before" != "$after" ]]; then
    echo "[$name] ABORT: doc count mismatch ($before vs $after) -- NOT deleting the old index. Investigate before re-running." >&2
    [[ -n "$resume_cmd" ]] && eval "$resume_cmd"
    exit 1
  fi

  echo "[$name] counts match. Deleting old plain index and creating alias..."
  es -X DELETE "${ELASTIC_URL}/${name}" > /dev/null
  es -X POST "${ELASTIC_URL}/_aliases" \
    -H 'Content-Type: application/json' \
    -d "{\"actions\": [{\"add\": {\"index\": \"${name}-000001\", \"alias\": \"${name}\", \"is_write_index\": true}}]}" > /dev/null

  [[ -n "$resume_cmd" ]] && { echo "[$name] resuming writer: $resume_cmd"; eval "$resume_cmd"; }
  echo "[$name] done -- now writing through the '${name}' rollover alias."
}

bootstrap_fresh() {
  local name="$1"
  local kind
  kind="$(target_kind "$name")"
  if [[ "$kind" != "absent" ]]; then
    echo "[$name] already exists ($kind) -- skipping fresh bootstrap."
    return
  fi
  echo "[$name] creating empty ${name}-000001 aliased as ${name} (is_write_index=true)..."
  es -X PUT "${ELASTIC_URL}/${name}-000001" \
    -H 'Content-Type: application/json' \
    -d "{\"aliases\": {\"${name}\": {\"is_write_index\": true}}}" > /dev/null
  echo "[$name] done."
}

migrate_existing_index "auditbeat-linux" \
  "docker compose -f '$AUDITBEAT_COMPOSE' stop auditbeat" \
  "docker compose -f '$AUDITBEAT_COMPOSE' start auditbeat"

# sentinel-triage / sentinel-response-actions are written by n8n's HTTP
# calls (and, for the latter, the responder), not one single Docker Compose
# service -- no automatic pause here. On a lab-volume alert rate the race
# window is small; pause the n8n workflows by hand first if you want it
# airtight.
migrate_existing_index "sentinel-triage" "" ""
migrate_existing_index "sentinel-response-actions" "" ""

bootstrap_fresh "winlogbeat-ecs"

echo "Migration complete."
