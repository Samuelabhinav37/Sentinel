# Sentinel build log — 2026-08-15

A detailed, chronological account of the first real build session on Sentinel, the
detection/correlation/response component of a larger code-driven SOC project (alongside
Axon and PRISM). Written to be source material for a blog post later — kept factual and
in order, including the mistakes, not just the clean version.

## Starting point

This wasn't a from-scratch project. On 2026-08-04 the infrastructure had already been
built once by hand: an OCI VCN, a compute instance, Docker, Tailscale, and a working Wazuh
install, all via click-ops through the OCI console (screenshots of every step exist in
`SOC Detection/` — VCN wizard, security lists, ingress rules, instance creation, Wazuh
login page working). That earlier work proved the concept end to end, but it wasn't
reproducible or version-controlled.

Decision made at the start of this session: tear down that manual instance and rebuild
everything as Terraform, with detections tracked as Sigma rules in git and validated in
CI. The manual security list configuration was worth keeping as a reference — notably, it
only opened SSH (22/tcp) and Tailscale (41641/udp) to the public internet, with every
dashboard (Wazuh, and later Kibana/Shuffle/n8n) reachable only over the Tailscale mesh.
That pattern was carried forward into the Terraform rebuild.

## Repo and architecture decisions

Repo: `github.com/Samuelabhinav37/Sentinel`, scaffolded at `~/Projects/sentinel`.

Core framing decision, made explicitly to avoid the project reading as "installed a lot
of tools": **one SIEM runs live** (Elastic). Splunk is treated as a Sigma compile target
only, to prove detection portability, not as a second system to operate. Security Onion
was dropped from the original plan in favor of running Suricata and Zeek directly — Onion
bundles more services than needed per host.

Repo layout: `infra/` (Terraform), `detections/rules/` (Sigma), `detections/tests/`
(attack-emulation-to-rule mapping, for closing the detection loop later),
`detections/deployed/` (the actual payloads pushed to live SIEM detection engines),
`pipelines/n8n/`, `soar/shuffle/`, `docs/`.

## Phase 1 — Terraform scaffold and first apply attempt

Wrote Terraform for: a VCN mirroring the original security list (SSH + Tailscale only),
and three Ampere A1 (`VM.Standard.A1.Flex`) instances on the OCI Always Free tier — one
each for Elastic, Wazuh, and Shuffle/n8n, sized to fit the free-tier ceiling of 4 OCPU /
24GB total. Reused a single Terraform module (`infra/modules/instance`) for all three,
parameterized by role, with cloud-init installing Docker and joining Tailscale.

First `terraform apply`: the networking layer (VCN, internet gateway, route table,
security list, subnet) created fine. All three compute instances failed with
`500 InternalError, Out of host capacity` — Ampere A1 is a well-known capacity bottleneck
for new OCI free-tier signups; the pool is heavily oversubscribed in many regions
(`us-chicago-1` in this case). Not a configuration problem, a genuine hardware
availability issue on Oracle's side.

First response: wrote a PowerShell retry loop to reattempt `terraform apply` every 3
minutes for up to ~6 hours, running in the background.

## Phase 2 — pivot to paid trial credit

Before the retry loop found capacity, it came out that the OCI account still had trial
credit available (~$243.28, ~15 days remaining) rather than being Always-Free-only. That
changes the capacity problem entirely: paid shapes draw from a completely different,
much deeper capacity pool than the free A1 tier, so switching shapes sidesteps the
capacity issue rather than waiting it out.

Decision: keep 3 separate VMs (one per role, for a more realistic architecture story) but
move to `VM.Standard.E4.Flex` (AMD EPYC, paid) instead of `A1.Flex`. Sized up since paid
capacity isn't free-tier-constrained: Elastic 4 OCPU/32GB, Wazuh 2 OCPU/16GB, Shuffle+n8n
2 OCPU/16GB (8 OCPU/64GB total).

First apply attempt on the new shape failed differently: `404 NotAuthorizedOrNotFound` on
`LaunchInstance`. Root cause: the OCI tenancy was still on the **Free Tier plan type** —
paid, non-Always-Free shapes are blocked by a service limit of 0 until the account is
upgraded to Pay As You Go (a separate step from having trial credit; upgrading doesn't
spend the credit early or trigger immediate billing). Walked through finding the upgrade
button in Billing & Cost Management, confirmed upgrade was "in progress" (a propagation
delay, not an error), waited, retried, and the apply succeeded:

- `sentinel-elastic` — 164.152.20.126
- `sentinel-wazuh` — 64.181.217.27
- `sentinel-soar` — 147.224.211.62

## Cost management

Before spending accelerated, did real pricing research rather than guessing:
`VM.Standard.E4.Flex` runs $0.0255/OCPU-hour + $0.0015/GB-hour. At 8 OCPU/64GB total that's
~$0.30/hr, ~$7.20/day, ~$108 over the full 15-day trial window if left running
continuously — nearly half the remaining balance, so worth managing actively.

Two concrete controls put in place:
1. **OCI Budget alert**: two-tier alert (75% and 100% of a $193 threshold — the current
   balance minus a $50 buffer), so a real email notification fires well before the trial
   credit runs low, rather than relying on anyone remembering to check.
2. **Stop-when-idle habit**: OCI only bills OCPU/memory while an instance is *running* —
   stopping (not terminating) an instance halts compute billing immediately, leaving only
   the boot volume's small storage cost (~$1.275/month per 50GB volume). Worth doing
   between work sessions.

## Phase 3 — a critical bug caught before it caused damage

While later adding a fourth VM (see Phase 6), `terraform plan` unexpectedly showed
**"3 to add, 0 to change, 3 to destroy"** — for what should have been a no-op against the
three already-deployed, already-configured VMs. Investigated instead of applying blindly.

Root cause: OCI's Terraform provider treats any change to an instance's `metadata`
(which includes `user_data`, i.e. the cloud-init script) as force-replace, because there
is no API to push updated `user_data` to an already-running instance — cloud-init only
ever executes once, at first boot. Earlier in the session (see Phase 4) the cloud-init
template had been edited to fix a real bug, which is exactly the kind of change that
looks like configuration drift to Terraform. Since the instances were already live and
manually configured well beyond what cloud-init did, applying "cleanly" here would have
destroyed and recreated all three VMs — including the Docker installs, Elastic, Wazuh,
Suricata, Zeek, and Shuffle/n8n deployments, and their data volumes.

Fix: added `lifecycle { ignore_changes = [metadata] }` to both the reusable instance
module and the standalone Windows resource. Template edits after first boot now simply
don't affect already-running instances — which is the correct behavior, since cloud-init
wouldn't re-run them anyway. This is the single highest-value catch of the session: a
plan that looked routine would have wiped out everything already built.

## Phase 4 — deploying the Elastic stack

`docker-compose.yml` for a single-node Elasticsearch 9.2.1 + Kibana 9.2.1, with security
enabled but HTTP TLS disabled (justified because the node is reachable only over
Tailscale — trading certificate complexity for basic auth without actually exposing
anything). A one-shot `setup` container bootstraps the `kibana_system` password via the
Elasticsearch security API once the node reports healthy.

Deployed and verified live: cluster status green, Kibana reachable at
`http://100.103.246.10:5601` over Tailscale, confirmed by curling the Tailscale IP from
this machine (not just localhost on the VM, to prove the actual access path works).

## Phase 5 — Wazuh, and a real cloud-init bug

Attempted to check Docker on the freshly-provisioned VMs and found `docker: command not
found` on all three, despite `cloud-init status` reporting `done`. Investigated the
cloud-init output log directly: the Docker apt repository line was hardcoded
`arch=arm64` — a leftover from the original `A1.Flex` (ARM) design, never updated when
the shape moved to `E4.Flex` (x86_64/amd64). `apt-get install docker-ce` silently failed
with no matching packages, and cloud-init's `runcmd` doesn't halt on an individual step
failing, so it reported success anyway. Fixed by detecting the architecture at runtime
via `dpkg --print-architecture` instead of hardcoding it, then manually re-ran the fixed
install steps over SSH on all three already-running VMs (the template fix alone wouldn't
retroactively apply — see Phase 3 for why not re-provisioning was the right call here).

Wazuh itself: deployed via the official `wazuh-docker` repo (pinned to `v4.14.7`,
single-node), rather than hand-writing config for a stack this security-sensitive.
Standard prerequisites: generate indexer TLS certs via the shipped
`generate-indexer-certs.yml`, raise `vm.max_map_count` to 262144 for the OpenSearch-based
indexer.

Before first boot, replaced the well-known default demo credentials
(`SecretPassword` / `kibanaserver` / `MyS3cr37P450r.*-`) with real generated passwords —
worth doing even on a Tailscale-only host, since a security project running its own SIEM
on known public defaults is a bad look regardless of exposure. This required generating
matching bcrypt hashes using the indexer image's *own* `hash.sh` tool (`docker run
wazuh/wazuh-indexer:4.14.7 bash .../hash.sh -p <password>`) so they'd actually validate —
a plain hash generated elsewhere wouldn't necessarily match OpenSearch's expected bcrypt
parameters. Wrote this up as a reusable `set-passwords.sh` script rather than a one-off
manual fix, so the procedure is repeatable.

Deployed and verified: indexer cluster green, manager core services running (analysisd,
remoted, logcollector, etc.), dashboard reachable over Tailscale at
`https://100.100.197.117`.

### Suricata and Zeek

Added as separate containers (`sensors.yml`) in host network mode against `ens3` (the
VM's primary interface), rather than trying to fold them into the Wazuh compose stack.

Suricata (`jasonish/suricata`) started but logged a warning: no rule files matched, zero
rules loaded — the image ships without a ruleset by default. Fixed by adding a one-shot
`suricata-update` service sharing a named volume with the main Suricata container,
matching the same "setup container runs first" pattern used for Elastic's password
bootstrap. After the fix, `suricata-update` pulled and enabled 52,311 Emerging Threats
rules.

Zeek (`zeek/zeek`) configured with `LogAscii::use_json=T` for JSON-formatted logs and a
minimal `local.zeek` site policy loading standard protocol-logging scripts (software
detection, known-hosts/services, SSL cert tracking).

To actually get this data into Wazuh: added six new `<localfile>` entries to
`wazuh_manager.conf` (`eve.json`, plus Zeek's `conn.log`, `dns.log`, `http.log`,
`ssl.log`, `weird.log`), each as `json` format, and bind-mounted the shared sensor-log
directory into the manager container read-only. Verified via `ossec.log` that the
logcollector was actively analyzing all six files — full pipeline confirmed working, not
just assumed.

## Phase 6 — Shuffle SOAR and n8n, and two more real bugs

Shuffle: official repo (`github.com/Shuffle/Shuffle`, pinned to `v2.2.1`), following their
documented prerequisites (`chown -R 1000:1000 shuffle-database`, `vm.max_map_count`). Their
`docker-compose.yml` requires several environment variables with no shipped defaults or
example file (`BACKEND_HOSTNAME`, `OUTER_HOSTNAME`, `SHUFFLE_FILE_LOCATION`,
`SHUFFLE_APP_HOTLOAD_LOCATION`, `DB_LOCATION`, `FRONTEND_PORT`, etc.) — had to read the
compose file directly to reconstruct a working `.env`, since none was provided.

Two real bugs surfaced only after actually trying to run it:

1. OpenSearch 3.2.0 refuses to start without `OPENSEARCH_INITIAL_ADMIN_PASSWORD` set.
   Shuffle's compose file correctly wires this to `${SHUFFLE_OPENSEARCH_PASSWORD}`, but
   that variable isn't set anywhere by default, so it silently defaults to a blank string
   and OpenSearch loops forever logging "No custom admin password found." Fix: set a real
   generated password for it.
2. Once OpenSearch started, the Shuffle backend still couldn't connect —
   `tls: failed to verify certificate: x509: certificate is valid for
   node-0.example.com, localhost, not shuffle-opensearch`. OpenSearch's bundled demo TLS
   certificate is static (baked into the image, not regenerated per deployment), so it can
   never match a container hostname like `shuffle-opensearch`. This isn't documented
   anywhere in Shuffle's own compose file or install guide for this release. Found the fix
   via a targeted search rather than guessing: `SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true`,
   an undocumented env var the Go backend reads via `env_file: .env`.

Given the size of Shuffle's own upstream repo (frontend, backend, shuffle-apps,
python-apps — a full multi-hundred-file monorepo), chose not to vendor it into the
Sentinel repo. Instead wrote `infra/compose/soar/shuffle/deploy.sh` (clones the pinned
tag, sets prerequisites) plus a `.env.example` documenting both undocumented fixes above,
so the deployment is reproducible from git without duplicating someone else's codebase.

n8n: a single container, SQLite-backed (no separate database — this is a lab deployment),
basic auth enabled.

Deployed and verified: Shuffle frontend reachable at `https://100.90.159.33:3443`,
backend responding on `:5001`, n8n editor reachable at `http://100.90.159.33:5678`.

## Phase 7 — wiring the first Sigma rule into a live detection

The one existing Sigma rule (`detections/rules/proc_creation_win_encoded_powershell.yml`
— detects `powershell.exe -EncodedCommand`, tagged `T1059.001`/`T1027`) had already been
validated and converted to EQL/SPL in CI (`sigma convert -t eql -p ecs_windows`), but that
conversion had never been pushed into a live, running SIEM as an actual scheduled
detection.

Initializing Kibana's detection engine (`POST /api/detection_engine/index`) failed on the
first attempt: "Unable to create actions client because the Encrypted Saved Objects
plugin is missing encryption key." Kibana's alerting/detection-engine plugins require
`xpack.encryptedSavedObjects.encryptionKey` (and, for completeness,
`xpack.security.encryptionKey` and `xpack.reporting.encryptionKey`) to be set — generated
three random hex keys, wired them into the Kibana container's environment, recreated it.

With that fixed, created the actual detection rule via
`POST /api/detection_engine/rules`, using the same EQL query validated in CI, with the
`rule_id` matching the Sigma rule's own `id` field for traceability between the source
YAML and the live rule. Confirmed it's genuinely executing on schedule (every 5 minutes)
via the rule's `execution_summary`: status is `partial failure`, with a message
explaining no index matching `winlogbeat-*`/`logs-windows.*` exists yet. That's expected
and correct — it's not a bug, it's an honest signal that the detection pipeline works
end-to-end but nothing is currently feeding it Windows telemetry.

The deployed rule payload and a small `deploy.sh` (POSTs every JSON file in
`detections/deployed/` to a given Kibana URl) were committed to the repo, so the live
rule is reproducible from git rather than only existing as a one-off API call.

## Phase 8 — closing the telemetry gap (in progress)

To make the rule above actually fireable — and eventually validate it with Atomic Red
Team — a Windows endpoint shipping process-creation telemetry to Elastic is needed.
Explicitly chose **not** to install monitoring agents (Sysmon, Winlogbeat) on the
personal daily-driver Windows machine this session runs on; instead provisioned a
disposable Windows Server 2022 VM (`VM.Standard.E4.Flex`, 2 OCPU/8GB) for this purpose
only.

Before provisioning, looked up real E4.Flex pricing but could not find a confirmed
Windows-licensing surcharge figure — flagged that honestly rather than guessing, and
proceeded at the user's direction.

Provisioning required two rounds of fixing the Terraform: the `operating_system_version`
filter for the Windows image data source initially matched zero images (guessed
`"Windows Server 2022 Standard Edition"`; the real value, discovered via a temporary
debug output enumerating all available images, is `"Server 2022 Standard"` — no "Windows"
prefix, no "Edition" suffix). The instance was created successfully:
`sentinel-win-target` — 170.9.244.44.

The VM was mid-boot (joining Tailscale via a `cloudbase-init` PowerShell script that
installs and configures Tailscale) when work paused for this write-up. Remaining for a
future session: confirm Tailscale join, install Sysmon (SwiftOnSecurity config) and
Winlogbeat shipping to Elasticsearch, generate a real `-EncodedCommand` execution to
confirm the live detection rule actually fires end-to-end, then formalize that as an
Atomic Red Team validation entry in `detections/tests/validation.yml`.

## Current state (end of this session)

**Live infrastructure** (all reachable only via Tailscale, matching the original manual
setup's ingress design):

| Service | Host | Tailscale address |
|---|---|---|
| Kibana | sentinel-elastic | `http://100.103.246.10:5601` |
| Wazuh dashboard | sentinel-wazuh | `https://100.100.197.117` |
| Suricata + Zeek | sentinel-wazuh | feeding Wazuh manager (verified ingesting) |
| Shuffle SOAR | sentinel-soar | `https://100.90.159.33:3443` |
| n8n | sentinel-soar | `http://100.90.159.33:5678` |
| Windows telemetry target | sentinel-win-target | joining Tailscale (in progress) |

**Detection-as-code**: one Sigma rule, validated and converted in CI to both Elastic EQL
and Splunk SPL, deployed live as a scheduled Kibana detection rule, currently unfed
pending the Windows telemetry endpoint above.

**Not yet done**: Sysmon/Winlogbeat on the Windows target; any Atomic Red Team validation
runs; the ATT&CK coverage matrix generator has code but only one rule to report on; the
n8n LLM triage pipeline hasn't been built; no second Sigma rule exists yet.

## Lessons worth writing about

- **A capacity error and an auth error can look similar but mean completely different
  things** — `Out of host capacity` (Ampere A1 oversubscription) needed patience/retry or
  a shape change; `404 NotAuthorizedOrNotFound` on the same API call, after switching
  shapes, needed an account-level upgrade, not a retry. Reading the actual error mattered
  more than pattern-matching "provisioning failed, try again."
- **Terraform can present a destructive plan for an update that shouldn't be
  destructive at all.** `user_data`/cloud-init being force-replace-only on OCI (and
  likely other providers) is a sharp edge worth knowing about *before* it happens, not
  after. `lifecycle { ignore_changes = [...] }` exists specifically for fields where a
  clean `terraform apply` would otherwise fight the reality that some resource attributes
  simply can't be updated in place.
- **"cloud-init status: done" is not proof anything actually worked.** cloud-init
  reports its own completion regardless of whether individual `runcmd` steps succeeded —
  worth explicitly verifying the thing you actually wanted (`docker --version`), not just
  the orchestration layer's own exit status.
- **Official docker-compose files from real projects still have gaps.** Wazuh's demo
  passwords needing the image's own hashing tool, and Shuffle's OpenSearch integration
  needing an undocumented skip-TLS-verify flag, were both things no amount of reading the
  compose file alone would have surfaced — they only showed up by actually running the
  stack and reading the failure.
- **A "partial failure" status on a live detection rule isn't automatically bad news.**
  The Kibana rule reporting no matching index is the system correctly telling the truth
  about its own state (no data source connected yet) rather than silently doing nothing
  or crashing.
