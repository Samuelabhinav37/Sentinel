# End-to-end demo runbook

The ordered capture list for the multi-cloud pipeline demo: attack on a cloud
target → Sigma rule fires → Elastic alert → n8n triage → response gate → Shuffle
→ bounded one-PID kill via `responder.py`.

This is a **Phase B** procedure — it needs the AWS + Azure targets actually
applied and the OCI stack live. Phase A (the Terraform, the `target` role, the
scripts, this doc) ships first with `terraform validate` only.

## Prerequisites

- OCI stack live and reachable over Tailscale (Elastic, Kibana, n8n, Shuffle,
  responder, MCP).
- For the dual-model triage stages (5, 6): the `feat/hardening-ci-tests-response`
  branch merged and redeployed (`scripts/redeploy.sh`). Against the single-model
  workflow on `main`, stage 5 shows only `triage` (no `triage_secondary` /
  `cross_check_agreement`) and stage 6's Cross-Check Gate node is absent — capture
  what's there and note it.
- Targets applied: `scripts/setup-cloud-creds.sh`, then
  `terraform -chdir=infra/aws apply` and `terraform -chdir=infra/azure apply`.
- Both targets show online in the Tailscale admin console and are shipping
  `auditbeat-linux` docs (check Kibana Discover, filter `host.name`).

## Running the driver

```
TARGETS="sentinel-target-aws sentinel-target-azure" \
ELASTIC_URL=http://sentinel-elastic:9200 \
ELASTIC_PASSWORD=... \
MCP_URL=http://sentinel-soar:8090 MCP_TOKEN=... \
./scripts/run-e2e-demo.sh
```

Writes `demo-runs/<UTC-timestamp>/` (gitignored): `events.jsonl` (one line per
stage), per-`(host,rule)` `alert.json` / `triage.json` / `response.json`, and
`summary.md` (the raw material for the `detections/tests/validation.yml` rows).

Default rules: `crontab_enum` (T1007, `crontab -l`) and `base64_decode_exec`
(T1059.004, `echo aWQ= | base64 -d | bash`). Both exit immediately, so there is
usually **no live PID** to kill — expect the response stage to record "no
response-action doc" or a `rejected: process not found`. For a killable
demonstration, add `RULES="... netcat_revshell"` — it backgrounds
`nc -w 300 192.0.2.1 4444` (RFC 5737 test address, never connects) so a real PID
is alive when the responder fires. Decide which rule carries the kill before the
run.

## Screenshot capture order

Claude drives Chrome (`mcp__claude-in-chrome__*`) to capture each screen as the
driver progresses; save PNGs alongside `demo-runs/<ts>/`.

| # | Screen | Expected state |
|---|---|---|
| 1 | **AWS Console** → EC2 → Instances | `sentinel-target-aws` running; note region, instance type `t3.small`, public IP. |
| 2 | **Azure Portal** → Virtual machines | `sentinel-target-azure` running; note size `Standard_B2s`, resource group `sentinel`. |
| 3 | **Tailscale admin** → Machines (`login.tailscale.com/admin/machines`) | Both `sentinel-target-aws` and `sentinel-target-azure` online, recent "last seen". |
| 4 | **Kibana** → Discover, index `auditbeat-linux` | `execve` docs with `host.name` = each target — telemetry is flowing before any attack. |
| 5 | **Kibana** → Security → Alerts | One alert per cloud, `host.name` = the target, rule = the fired Sigma rule (e.g. "Base64 Decode and Execute"), within ~5 min of T0. |
| 6 | **Kibana** → Discover, index `sentinel-triage` | The `<alert_id>-push` doc: `triage.severity`, `triage.false_positive_likelihood`, `mttd_seconds`; with the dual-model workflow also `triage_secondary` and `cross_check_agreement: true`. |
| 7 | **n8n** → Executions → `sentinel-llm-triage-push` | The run for this alert: Call Ollama (+ Claude, dual-model) → Parse → Write to Elasticsearch → Check Response Gate → Call Shuffle Response. |
| 8 | **Shuffle** → the "Sentinel Auto-Respond" workflow → Runs | The execution triggered by n8n: received `pid` / `reason` / `alert_id`, called the responder. |
| 9 | **Kibana** → Discover, index `sentinel-response-actions` | The doc for this `alert_id`: `action`, `requested_pid`, `comm`, `result` (`killed` for the netcat demo; `rejected` / `process not found` for the trivial rules), `reason`. |
| 10 | **Terminal** — `tailscale ssh ubuntu@<target>` then `ps -p <pid>` | For the killable demo: the PID is gone. For the trivial rules: show the process already exited (nothing to kill) — this is the honest outcome, capture it as-is. |
| 11 | **Kibana** → the "Sentinel SOC Overview" dashboard (and/or the ATT&CK Navigator layer from `detections/scripts/build_attack_navigator.py`) | The new alerts and the covered techniques reflected. |
| 12 | **Kibana** → Discover, `sentinel-triage`, negative-control window | No new alert from the benign negative-control command (`base64 -w 0 …`, `EDITOR=/bin/true crontab -e`) — precision, not just recall. |

## After the run

1. Add `true_positive` rows to `detections/tests/validation.yml` for each
   `(target, rule)` pair, using the **real** measured values from
   `demo-runs/<ts>/summary.md`: `mttd_seconds`, both timestamps, the triage
   verdict, and the negative-control result. Never invent MTTD.
2. `python detections/scripts/validate_rules.py` and `sigma check` — still green.
3. `terraform -chdir=infra/aws destroy` and `terraform -chdir=infra/azure destroy`
   the targets to stop the (few-dollars) burn. The full stacks are untouched.
