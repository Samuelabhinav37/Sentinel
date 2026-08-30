#!/usr/bin/env bash
# End-to-end pipeline demo driver for the multi-cloud attack targets.
#
# For each target host and each selected Sigma rule it:
#   1. stamps T0 (UTC),
#   2. fires the rule's trigger command over `tailscale ssh`,
#   3. polls Elasticsearch until the Kibana detection alert appears  -> T1, MTTD,
#   4. polls sentinel-triage for the n8n triage verdict (single- or dual-model;
#      records triage_secondary / cross_check_agreement when the deployed
#      workflow is the dual-model one),
#   5. polls sentinel-response-actions for the bounded responder outcome,
#   6. fires the negative-control command and confirms no new alert within one
#      rule interval.
#
# It only ever READS from Elasticsearch (and, if configured, the MCP read tools).
# It never triggers the SOAR response itself - the live pipeline does that on its
# own when the triage gate opens.
#
# Output: demo-runs/<UTC-timestamp>/ with events.jsonl, and per (host,rule)
# alert.json / triage.json / response.json, plus a summary.md that is the raw
# material for the detections/tests/validation.yml rows and any writeup.
#
# Usage:
#   TARGETS="sentinel-target-aws sentinel-target-azure" \
#   ELASTIC_URL=http://sentinel-elastic:9200 \
#   ELASTIC_PASSWORD=... \
#   ./scripts/run-e2e-demo.sh
#
# Optional env:
#   RULES="crontab_enum base64_decode_exec"   which rules to run (default: those two)
#   SSH_USER=ubuntu                            remote user for tailscale ssh
#   SSH_CMD="tailscale ssh"                    override the ssh transport
#   POLL_TIMEOUT=600  POLL_INTERVAL=15         alert/triage/response poll bounds (seconds)
#   MCP_URL=http://sentinel-soar:8090  MCP_TOKEN=...   also cross-check via MCP read tools
#
# Secrets (ELASTIC_PASSWORD, MCP_TOKEN) are read from the environment only and
# are never echoed or written to the evidence bundle.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${TARGETS:?set TARGETS, space-separated Tailscale hostnames}"
: "${ELASTIC_URL:?set ELASTIC_URL, e.g. http://sentinel-elastic:9200}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD (elastic superuser)}"

SSH_USER="${SSH_USER:-ubuntu}"
SSH_CMD="${SSH_CMD:-tailscale ssh}"
RULES="${RULES:-crontab_enum base64_decode_exec}"
POLL_TIMEOUT="${POLL_TIMEOUT:-600}"
POLL_INTERVAL="${POLL_INTERVAL:-15}"
MCP_URL="${MCP_URL:-}"
MCP_TOKEN="${MCP_TOKEN:-}"

for bin in curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing required tool: $bin" >&2; exit 1; }
done

RUN_DIR="demo-runs/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN_DIR"
EVENTS="$RUN_DIR/events.jsonl"
SUMMARY="$RUN_DIR/summary.md"

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Append one structured line to events.jsonl. Args: stage host rule detail
log_event() {
  jq -cn \
    --arg ts "$(now_iso)" --arg stage "$1" --arg host "$2" \
    --arg rule "$3" --arg detail "$4" \
    '{ts:$ts,stage:$stage,host:$host,rule:$rule,detail:$detail}' >> "$EVENTS"
  echo "[$(now_iso)] $1 host=$2 rule=$3 $4"
}

# Rule metadata. Sets RULE_ID / RULE_TECHNIQUE / RULE_NAME_MATCH / TRIGGER_CMD /
# NEGCTL_CMD. rule_id values are the real ones from detections/tests/validation.yml.
rule_meta() {
  case "$1" in
    crontab_enum)
      RULE_ID="403ed92c-b7ec-4edd-9947-5b535ee12d46"
      RULE_TECHNIQUE="T1007"
      RULE_NAME_MATCH="rontab"
      TRIGGER_CMD="crontab -l || true"
      NEGCTL_CMD="EDITOR=/bin/true crontab -e </dev/null || true"
      ;;
    base64_decode_exec)
      RULE_ID="bbd6e18e-8106-40fe-a150-f4bcfbf3c9ca"
      RULE_TECHNIQUE="T1059.004"
      RULE_NAME_MATCH="ase64"
      TRIGGER_CMD="echo aWQ= | base64 -d | bash"
      NEGCTL_CMD="base64 -w 0 /etc/hostname >/dev/null"
      ;;
    netcat_revshell)
      # Opt-in: leaves a live PID (~300s) so the responder has something real to
      # kill. Connects to a TEST-NET-1 address (RFC 5737) that never answers.
      RULE_ID="7f734ed0-4f47-46c0-837f-6ee62505abd9"
      RULE_TECHNIQUE="T1059"
      RULE_NAME_MATCH="etcat"
      TRIGGER_CMD="setsid nc -w 300 192.0.2.1 4444 >/dev/null 2>&1 & echo backgrounded pid \$!"
      NEGCTL_CMD="nc -h >/dev/null 2>&1 || true"
      ;;
    *)
      echo "unknown rule key: $1 (known: crontab_enum base64_decode_exec netcat_revshell)" >&2
      return 1
      ;;
  esac
}

es() {
  # $1 = path (starts with /), $2 = JSON request body
  curl -sS --max-time 30 -u "elastic:${ELASTIC_PASSWORD}" \
    -H 'Content-Type: application/json' "${ELASTIC_URL}$1" -d "$2"
}

mcp() {
  # $1 = tool path, $2 = JSON body. No-op unless MCP_URL + MCP_TOKEN are set.
  [ -n "$MCP_URL" ] && [ -n "$MCP_TOKEN" ] || return 0
  curl -sS --max-time 30 -H "X-MCP-Token: ${MCP_TOKEN}" \
    -H 'Content-Type: application/json' "${MCP_URL}$1" -d "$2" || true
}

# Poll .alerts-security for an alert on this host, newer than $t0, whose rule
# name contains RULE_NAME_MATCH. Echoes the raw hit JSON on success.
poll_alert() {
  local host="$1" t0="$2" match="$3" deadline hit name
  deadline=$(( $(date +%s) + POLL_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    hit="$(es "/.alerts-security.alerts-default*/_search" "{
      \"size\": 5,
      \"sort\": [{\"@timestamp\": \"desc\"}],
      \"query\": {\"bool\": {\"filter\": [
        {\"term\": {\"kibana.alert.rule.tags\": \"sentinel-sigma\"}},
        {\"term\": {\"host.name\": \"${host}\"}},
        {\"range\": {\"@timestamp\": {\"gte\": \"${t0}\"}}}
      ]}}}" | jq -c --arg m "$match" \
        '[.hits.hits[] | select((._source["kibana.alert.rule.name"] // ._source.kibana.alert.rule.name // "") | test($m))][0] // empty')"
    if [ -n "$hit" ]; then
      name="$(printf '%s' "$hit" | jq -r '._source["kibana.alert.rule.name"] // ._source.kibana.alert.rule.name // "?"')"
      printf '%s' "$hit"
      echo "  matched alert: ${name}" >&2
      return 0
    fi
    sleep "$POLL_INTERVAL"
  done
  return 1
}

# Poll sentinel-triage for the -push doc for this host newer than $t0.
poll_triage() {
  local host="$1" t0="$2" deadline doc
  deadline=$(( $(date +%s) + POLL_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    doc="$(es "/sentinel-triage/_search" "{
      \"size\": 1,
      \"sort\": [{\"@timestamp\": \"desc\"}],
      \"query\": {\"bool\": {\"filter\": [
        {\"term\": {\"triage_source\": \"push\"}},
        {\"term\": {\"alert.host.name\": \"${host}\"}},
        {\"range\": {\"@timestamp\": {\"gte\": \"${t0}\"}}}
      ]}}}" | jq -c '.hits.hits[0]._source // empty')"
    [ -n "$doc" ] && { printf '%s' "$doc"; return 0; }
    sleep "$POLL_INTERVAL"
  done
  return 1
}

# Poll sentinel-response-actions for a doc for this alert_id newer than $t0.
poll_response() {
  local alert_id="$1" t0="$2" deadline doc
  deadline=$(( $(date +%s) + POLL_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    doc="$(es "/sentinel-response-actions/_search" "{
      \"size\": 1,
      \"sort\": [{\"@timestamp\": \"desc\"}],
      \"query\": {\"bool\": {\"filter\": [
        {\"term\": {\"alert_id\": \"${alert_id}\"}},
        {\"range\": {\"@timestamp\": {\"gte\": \"${t0}\"}}}
      ]}}}" | jq -c '.hits.hits[0]._source // empty')"
    [ -n "$doc" ] && { printf '%s' "$doc"; return 0; }
    sleep "$POLL_INTERVAL"
  done
  return 1
}

run_one() {
  local host="$1" rule_key="$2" pair_dir t0 alert alert_id mttd triage response
  rule_meta "$rule_key"
  pair_dir="$RUN_DIR/${host}__${rule_key}"
  mkdir -p "$pair_dir"

  t0="$(now_iso)"
  log_event trigger "$host" "$rule_key" "T0=$t0 technique=$RULE_TECHNIQUE"
  # shellcheck disable=SC2029  # deliberate client-side expansion of the trigger
  $SSH_CMD "${SSH_USER}@${host}" "$TRIGGER_CMD" > "$pair_dir/trigger.out" 2>&1 || true

  if ! alert="$(poll_alert "$host" "$t0" "$RULE_NAME_MATCH")"; then
    log_event alert-timeout "$host" "$rule_key" "no alert within ${POLL_TIMEOUT}s"
    return 1
  fi
  printf '%s\n' "$alert" | jq '.' > "$pair_dir/alert.json"
  local t1
  t1="$(printf '%s' "$alert" | jq -r '._source["kibana.alert.start"] // ._source.kibana.alert.start // ._source["@timestamp"]')"
  mttd=$(( $(date -u -d "$t1" +%s) - $(date -u -d "$t0" +%s) ))
  alert_id="$(printf '%s' "$alert" | jq -r '._source["kibana.alert.uuid"] // ._source.kibana.alert.uuid // ._id')"
  log_event alert "$host" "$rule_key" "T1=$t1 mttd_seconds=$mttd alert_id=$alert_id"

  if triage="$(poll_triage "$host" "$t0")"; then
    printf '%s\n' "$triage" | jq '.' > "$pair_dir/triage.json"
    local sev fp agree
    sev="$(printf '%s' "$triage" | jq -r '.triage.severity // "?"')"
    fp="$(printf '%s' "$triage" | jq -r '.triage.false_positive_likelihood // "?"')"
    agree="$(printf '%s' "$triage" | jq -r 'if has("cross_check_agreement") then (.cross_check_agreement|tostring) else "n/a (single-model)" end')"
    log_event triage "$host" "$rule_key" "severity=$sev fp_likelihood=$fp cross_check_agreement=$agree"
  else
    log_event triage-timeout "$host" "$rule_key" "no triage doc within ${POLL_TIMEOUT}s"
  fi

  if response="$(poll_response "$alert_id" "$t0")"; then
    printf '%s\n' "$response" | jq '.' > "$pair_dir/response.json"
    local result comm rpid
    result="$(printf '%s' "$response" | jq -r '.result // "?"')"
    comm="$(printf '%s' "$response" | jq -r '.comm // "?"')"
    rpid="$(printf '%s' "$response" | jq -r '.requested_pid // "?"')"
    log_event response "$host" "$rule_key" "result=$result comm=$comm requested_pid=$rpid"
  else
    log_event response-none "$host" "$rule_key" "no response-action doc (expected when the trigger left no live PID)"
  fi

  mcp "/get_alert_context" "{\"alert_id\": \"${alert_id}\"}" > "$pair_dir/mcp_alert_context.json" 2>/dev/null || true

  # Negative control: benign use of the same tool, must NOT raise a new alert.
  local nc_t0 nc_hit
  nc_t0="$(now_iso)"
  log_event negctl-trigger "$host" "$rule_key" "T0=$nc_t0"
  # shellcheck disable=SC2029
  $SSH_CMD "${SSH_USER}@${host}" "$NEGCTL_CMD" > "$pair_dir/negctl.out" 2>&1 || true
  sleep "$POLL_INTERVAL"
  if nc_hit="$(poll_alert "$host" "$nc_t0" "$RULE_NAME_MATCH")" && [ -n "$nc_hit" ]; then
    log_event negctl-FAIL "$host" "$rule_key" "negative control raised an alert - false positive"
    printf '%s\n' "$nc_hit" | jq '.' > "$pair_dir/negctl_alert.json"
  else
    log_event negctl-ok "$host" "$rule_key" "no alert from benign use within one poll window"
  fi

  {
    echo "## ${host} / ${rule_key} (${RULE_TECHNIQUE})"
    echo
    echo "- rule_id: \`${RULE_ID}\`"
    echo "- trigger: \`${TRIGGER_CMD}\`"
    echo "- T0: ${t0}"
    echo "- T1 (alert start): ${t1:-n/a}"
    echo "- MTTD: ${mttd:-n/a} s"
    echo "- alert_id: \`${alert_id}\`"
    [ -f "$pair_dir/triage.json" ] && echo "- triage: $(jq -c '{severity:.triage.severity,fp:.triage.false_positive_likelihood,cross_check_agreement:(.cross_check_agreement // "n/a")}' "$pair_dir/triage.json")"
    [ -f "$pair_dir/response.json" ] && echo "- response: $(jq -c '{result,comm,requested_pid,reason}' "$pair_dir/response.json")"
    echo "- negative control: \`${NEGCTL_CMD}\` -> see events.jsonl (negctl-ok / negctl-FAIL)"
    echo
  } >> "$SUMMARY"
}

{
  echo "# Sentinel end-to-end demo run"
  echo
  echo "- started: $(now_iso)"
  echo "- targets: ${TARGETS}"
  echo "- rules: ${RULES}"
  echo "- elastic: ${ELASTIC_URL}"
  echo
} > "$SUMMARY"

rc=0
for host in $TARGETS; do
  for rule_key in $RULES; do
    run_one "$host" "$rule_key" || rc=1
  done
done

echo
echo "evidence bundle: $RUN_DIR"
echo "  events.jsonl  - one line per pipeline stage"
echo "  summary.md    - per (host,rule) rollup; backs the validation.yml rows"
exit "$rc"
