# Sentinel build log — 2026-08-15 onward

A detailed, chronological account of the build sessions on Sentinel, the
detection/correlation/response component of a larger code-driven SOC project (alongside
Axon and PRISM). Written to be source material for a blog post later — kept factual and
in order, including the mistakes, not just the clean version. Phases 1-8 are the first
session (initial infra + first detection); Phase 9 onward is a later session that
continued from where that one paused.

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

## Phase 9 — resuming, and diagnosing why the Windows VM never joined

Picked back up in a later session. `sentinel-win-target` had been mid-boot when the
previous session paused; checking `tailscale status` on the elastic VM showed it still
hadn't appeared almost 1.5 hours later — too long for a normal Windows first boot, and
long enough to stop assuming "still booting" and actually investigate. RDP being closed
wasn't a useful signal either way — port 3389 was never opened in the security list by
design (only SSH and Tailscale are public-facing), so a closed RDP port is expected
regardless of whether cloud-init succeeded.

With no SSH/RDP access to a box that isn't on the tailnet yet, the only way in was OCI's
serial console history. No `oci` CLI was installed locally, so the `oci` Python SDK was
installed instead and used directly (`CaptureConsoleHistory` + `GetConsoleHistoryContent`)
to pull the boot log. First attempt at reading it produced a wall of literal `\r\n` escape
sequences instead of real line breaks — the script had been `print()`-ing a raw Python
`bytes` object, which renders its `repr()` rather than the decoded text. Fixed by decoding
to UTF-8 before printing.

With readable output, the actual failure was clear: cloudbase-init ran the userdata script
fully, but the final step — `& "C:\Program Files\Tailscale\tailscale.exe" up ...` — failed
with "not recognized as the name of a cmdlet." The `msiexec` install one line above had
failed silently: `Start-Process -Wait` doesn't check the child process's exit code, so a
failed install and a successful one look identical to the calling script.

Rewrote `windows_target_userdata.ps1.tftpl` to actually verify success: up to 3
install attempts, polling for `tailscale.exe` to exist on disk before ever calling it, and
logging progress to `C:\Windows\Temp\sentinel-userdata.log` for easier diagnosis if it
ever fails again. Recreated the VM via `terraform apply -replace=oci_core_instance.windows_target`
(confirmed via `terraform plan` first that this touched only that one resource — the three
live core VMs were untouched, consistent with the `ignore_changes = [metadata]` fix from
Phase 3).

The recreated VM *still* didn't join Tailscale. Pulling the console log again (using the
now-fixed decode) showed real progress this time — the retry logic worked, catching a
transient `msiexec` exit `1618` ("another installation is already in progress," likely
racing a first-boot Windows service) and succeeding on the second attempt — but the final
`tailscale up --ssh` call itself failed outright: `500 Internal Server Error: The Tailscale
SSH server is not supported on windows`. The `--ssh` flag had been copied over from the
Linux VMs' cloud-init template without checking whether it applied to Windows; it doesn't
— Tailscale SSH is Linux/macOS-only. Removed the flag, recreated the VM a second time
(again confirmed via plan that only the Windows resource was touched).

Mid-way through waiting for that second rebuild to join the tailnet, the decision was made
to stop and fully tear the Windows VM down rather than keep iterating — the underlying
script bug was already found and fixed for whenever it's picked back up, so continuing to
debug the live instance wasn't adding value. Destroyed via
`terraform plan -destroy -target=oci_core_instance.windows_target` / `apply` (confirmed:
0 added, 0 changed, 1 destroyed — the other three VMs untouched). The corrected userdata
script stays in the repo, committed, ready to redeploy cleanly next time.

## Phase 10 — pivoting to the LLM triage pipeline and more detections

With the Windows telemetry thread deliberately paused, moved to two pieces of work that
don't depend on it: the n8n LLM-triage pipeline (the "LLM-augmented" half of the project's
pitch, not yet built at all) and more Sigma rules through the pipeline already proven in
Phase 7.

The one real decision needed up front: what powers the LLM triage step. Given the
project's stated goal of staying mostly open-source and the existing cost-consciousness
around the OCI trial credit, chose **self-hosted Ollama** over the Anthropic API — zero
marginal cost, keeps the whole stack self-contained, at the price of weaker triage quality
than a hosted frontier model.

## Phase 11 — deploying Ollama

Checked headroom on the SOAR VM before deciding where to run it: 4 vCPU, ~9.6GB available
RAM (out of 15GB, with Shuffle's OpenSearch container already using ~3.7GB), 28GB free
disk. Enough to co-locate Ollama alongside n8n and the existing Shuffle stack without
resizing or adding a fourth VM.

Added `ollama/ollama` to the n8n compose file, plus a one-shot `ollama-pull` bootstrap
container (`depends_on: condition: service_healthy` on the main Ollama service) to pull
`llama3.2:3b` once — the same "setup container runs first" pattern already used for
Suricata's rule updates and Kibana's password bootstrap in earlier phases. Chose the 3B
model specifically for CPU-inference latency, since there's no GPU on this box and triage
is a low-throughput, occasional workload rather than something needing to be fast at
scale. Verified with a real inference call via `docker exec sentinel-ollama ollama run
llama3.2:3b "..."` — got a correct response back.

## Phase 12 — building the n8n triage workflow, and several real n8n bugs

Designed the pipeline as: webhook trigger → build a triage prompt from the alert → call
Ollama → parse its JSON verdict → write the enriched result into a new `sentinel-triage`
Elasticsearch index → respond. Needed the `elastic` user's Elasticsearch password inside
n8n's environment; moved it VM-to-VM with a piped SSH command
(`ssh elastic-vm "grep ..." | ssh soar-vm "cat >> .env"`) so the plaintext value never
passed through anything visible — the same secret-handling discipline as earlier phases.

Wrote the workflow as a committed JSON file and imported it via `n8n import:workflow`
rather than hand-building it in the UI and leaving it undocumented. First import failed
with `SQLITE_CONSTRAINT: NOT NULL constraint failed: workflow_entity.id` — the workflow
JSON needs its own top-level `id` field, not just per-node `id`s; fixed by adding one.

Getting the webhook to actually respond surfaced a chain of real bugs:

1. Opening the n8n UI at all failed first: *"Your n8n server is configured to use a
   secure cookie, however you are either visiting this via an insecure URL..."* — n8n
   defaults to secure-only cookies, which don't work over plain HTTP on the private
   Tailscale mesh. Fixed with `N8N_SECURE_COOKIE=false` — the same TLS-vs-private-network
   tradeoff already made for Elasticsearch in Phase 4.
2. n8n then demanded a brand-new owner account through a `/setup` wizard — the
   `N8N_BASIC_AUTH_*` env vars from the original deployment turned out to be vestigial in
   this n8n release, superseded by n8n's own built-in user-management system. Created an
   owner account through the UI (unavoidable to type a password into a browser form for a
   one-time GUI setup step, unlike everything else in this project which has kept secrets
   out of the visible transcript).
3. This n8n version has a newer draft/publish workflow-versioning model, distinct from the
   classic single Active/Inactive toggle most n8n documentation assumes. CLI-imported
   workflows always land deactivated, and neither `n8n update:workflow --active=true` nor
   `n8n publish:workflow` reliably re-registered the webhook route after a container
   restart — despite the startup log claiming `Activated workflow "Sentinel LLM Triage"`.
4. Root-caused by reading the actual SQLite database directly rather than guessing further
   — which itself needed care, since n8n runs SQLite in WAL mode: copying just
   `database.sqlite` out of the container gave a stale, effectively empty view (0 rows in
   every table) until the `-wal`/`-shm` files were copied alongside it too. With a correct
   read, the real bug was visible in the `webhook_entity` table: the hand-authored Webhook
   node was missing a `webhookId` field that n8n normally auto-generates when a node is
   added through the UI. Without it, n8n registered a synthetic fallback route
   (`sentinel-llm-triage/alert%20webhook/sentinel-triage`) instead of the plain
   `/webhook/sentinel-triage` path actually being called — hence the persistent 404s.
   Added a generated UUID as the node's `webhookId`, and the webhook registered correctly
   and survived a restart.

With the trigger finally firing, a second, unrelated bug turned up in the workflow logic
itself: n8n's Webhook node wraps the real POST payload inside a `.body` field (alongside
`headers`/`params`/`query`), and the prompt-building code had been reading alert fields
from the top level — so every test fell through to "Unknown rule"/"unknown-host" defaults
instead of erroring, which made it look superficially like it was working. Fixed by
unwrapping `.body`. Verified the corrected pipeline end-to-end with `curl`: a realistic
alert payload in, a correctly-populated LLM triage verdict out, confirmed by a live
document-count check against the `sentinel-triage` Elasticsearch index.

## Phase 13 — a license wall, and a better redesign

The originally planned integration point — a native Kibana rule action calling n8n
through a Webhook connector — hit `403 Forbidden: Action type .webhook is disabled
because your basic license does not support it`. The generic Webhook connector type is
gated behind a paid Kibana license tier on this deployment; not something to work around
by paying for an upgrade on a cost-conscious project.

Redesigned around it rather than accepting the limitation: switched the workflow's trigger
from Kibana-push (Webhook) to n8n-pull (a Schedule Trigger polling Elasticsearch's
`.alerts-security.alerts-default*` index directly every 5 minutes for anything tagged
`sentinel-sigma` in the last 10 minutes). This needs no Kibana Action configuration at
all, sidesteps the license limitation entirely, and is arguably the more standard SOAR
integration pattern anyway. Made the Elasticsearch write idempotent by using the alert's
own `_id` as the triage document's ID (`PUT` instead of `POST`-with-autogenerated-id), so
re-polling the same alert across cycles overwrites rather than duplicates.

Verified via n8n's manual "Execute workflow": the schedule trigger, auth-header build, and
Elasticsearch query all succeeded; every downstream node correctly didn't run because zero
alerts matched — expected, since no Windows telemetry is live. Inspected the raw
Elasticsearch response directly to confirm this was a genuine, clean "no results" answer
(`_shards.successful: 1`, `hits.total.value: 0`) rather than a silently-broken query
that just happens to return nothing.

## Phase 14 — four more Sigma rules

Installed `sigma-cli` locally (it wasn't previously set up on this machine) to validate
rules before committing, matching the discipline established in Phase 7. Wrote four new
`process_creation` rules: LSASS memory dump via `comsvcs.dll`'s `MiniDump` export
(T1003.001), suspicious `certutil.exe` download/decode (T1105/T1140), scheduled-task
persistence via `schtasks.exe` (T1053.005), and Windows Defender disabled via
`Set-MpPreference` (T1562.001).

Hit the same "invalid ATT&CK tag" quirk from the very first session again — `attack.
defense-evasion` still fails `sigma check`'s validation against this environment's
live-fetched MITRE dataset. Confirmed it isn't a stale-cache problem by explicitly
clearing pysigma's ATT&CK cache and rechecking (same result). This time also found that
even a real, correctly-formatted *technique* tag can trip the same check —
`attack.t1562.001` is genuinely valid MITRE taxonomy but still gets flagged. The
difference that made it worth keeping anyway: `sigma check` treats this as a non-fatal
"issue" (exit code `0`), not a hard error, and the CI pipeline's own gate (a regex grep
for `attack\.t[0-9]{4}`) only cares about tag *format*, not whether sigma-cli's live MITRE
lookup happens to recognize it — so the tag was kept.

Converted all five rules (the original plus four new) to EQL and Splunk locally to mirror
CI exactly, then deployed to Kibana. Deploying surfaced a real, previously-unnoticed bug
in `deploy.sh`: it only ever `POST`ed, which creates a rule but 409s if the `rule_id`
already exists — meaning the script was never actually safe to rerun against an existing
rule despite that being its stated purpose. Fixed to try create first and fall back to
`PUT` (update) on a 409 conflict. Added `unvalidated` entries for all four new rules to
`detections/tests/validation.yml`, and regenerated the ATT&CK coverage layer — 2 covered
techniques became 7.

## Phase 15 — commit and push

Split the session's work into three separate commits rather than one — a Windows VM
cloud-init fix, the Ollama+n8n triage pipeline, and the Sigma rules plus the `deploy.sh`
idempotency fix — each with a message explaining the actual root cause behind the change,
not just a summary of the diff. Pushed to `main`.

## Phase 16 — deciding to stop fighting the Windows VM

After the fixed Windows VM was torn down (end of Phase 9), the plan was to redeploy it
once picked back up. Instead, after repeated Windows-VM boot friction across two
sessions, made the call to deviate from a live Windows VM entirely rather than keep
spending time/cost on cloud-init bootstrapping — and researched real alternatives
instead of guessing.

Checked what actually exists, not just what sounds plausible:

- **OTRF Security-Datasets ("Mordor")** — a library of real, pre-recorded attack
  telemetry mapped to ATT&CK, designed specifically for replaying into a SIEM to
  validate detections without live infrastructure. Checked its actual GitHub tree via
  the API rather than trusting a description: 165 Windows atomic datasets vs only 2
  for Linux (`sh_binary_padding_dd`, `sh_arp_cache`) and zero for macOS — confirmed this
  is a Windows-first resource, not evenly cross-platform.
- **AIT Log Data Set (AIT-LDS)**, Zenodo-hosted, ground-truth-annotated multi-host
  Linux attack simulations — a real option for Linux, though Sentinel already has three
  live Linux VMs with Wazuh agents, so running actual Atomic Red Team atomics against a
  disposable Linux box would give genuine telemetry with zero new infrastructure, which
  beats a static replay dataset for Linux specifically.
- **DetectionLab** — purpose-built for exactly this (Windows domain + Sysmon +
  Winlogbeat), but confirmed via its own GitHub activity that it's been unmaintained
  since 2023 (still weekly-CI-tested, so it currently builds, but a real staleness risk
  for a dependency).
- **macOS** — no viable free option found anywhere in the ecosystem. Red Team
  Automation (RTA) can generate real macOS telemetry, but only by actually running on
  macOS hardware; cloud macOS (AWS EC2 Mac) requires a 24-hour minimum dedicated-host
  allocation with real cost. Honest conclusion: macOS coverage is out of scope for this
  project unless a physical Mac becomes available to test on directly.

Decision: replay Mordor datasets for Windows now (fastest path to actually validating
the 5 deployed Sigma rules), treat live Atomic Red Team on a disposable Linux VM as the
better Linux option later, and drop macOS entirely rather than force a weak answer.

## Phase 17 — building the Mordor replay pipeline

Matched Mordor's dataset catalog against the 5 deployed rules by keyword-searching the
repo's file tree: found exact matches for two —
`credential_access/host/psh_lsass_memory_dump_comsvcs.zip` (T1003.001) and
`lateral_movement/host/schtask_create.zip` (T1053.005). No ready-made sample existed for
the encoded-PowerShell, certutil, or Defender-disabled rules.

Downloaded and inspected a sample file before writing any transform code, rather than
assuming its shape: Mordor datasets are raw Windows Event Log JSON (`NewProcessName`,
`CommandLine`, `EventID: 4688` for Security-log events; `Image`, `CommandLine`,
`EventID: 1` for Sysmon), not ECS — so a mapping layer was needed before this data could
mean anything to the ECS-based EQL queries the rules actually run.

Wrote `detections/scripts/replay_mordor_dataset.py`: unzips a dataset, maps the handful
of fields the rules query (`process.executable`, `process.command_line`, `host.name`,
`@timestamp`) into ECS-ish documents, and bulk-indexes them into Elasticsearch via the
`_bulk` API. Timestamps are stamped as "now" rather than preserved from the dataset's
original (multi-year-old) `TimeCreated` — the point of the replay is to exercise the
live rule schedule and the n8n polling window exactly as they'd see a real alert, not to
archive historical events.

## Phase 18 — four real bugs, found only by actually firing live alerts

Every mechanical test up to this point (single synthetic webhook calls, zero-result
schedule executions) had exercised the pipeline's plumbing without ever exercising its
actual detection logic end-to-end. Replaying real attack data immediately surfaced four
genuine, previously-invisible bugs — in order:

**1. EQL's `.caseless` isn't what it looks like.** The first replay attempt failed all
5 rules with `verification_exception: Unknown column [process.executable.caseless]`.
Traced it to dynamic mapping: my hand-rolled index had inferred `process.executable` as
`text` (with an auto `.keyword` sub-field), not `keyword` — this is exactly what
Winlogbeat's real ECS template would have prevented, so it would have hit real telemetry
too, not just this replay. Fixed with an explicit index template mapping the field as
`keyword`. That still didn't work — `.caseless` turned out not to be built-in EQL syntax
at all; it's a literal field name that Elastic Agent's official Windows integration
provides via its own component templates (a case-normalized runtime field), which
pysigma's `ecs_windows` pipeline assumes exists. Since this project uses plain
Winlogbeat, not Elastic Agent + Fleet, that field never existed. Fixed by adding it
explicitly as an Elasticsearch **runtime field** (`process.executable.caseless`,
computed via a Painless passthrough script) to the index template. This is arguably the
highest-value bug of the session — all 5 rules would have silently never fired against
real Windows telemetry either, for a reason that had nothing to do with the Sigma source
or the EQL conversion being wrong.

**2. n8n's Code node default silently drops items.** With the mapping fixed, rules
started generating real alerts — but only one ever got triaged per batch, with zero
errors logged. Root-caused by reading the workflow's stored JSON directly out of n8n's
SQLite database: both Code nodes (`Build Prompt`, `Parse Triage + Auth`) had been running
in n8n's default `runOnceForAllItems` mode, where `$input.first()` only ever looks at
item 0 — silently discarding every other item in the batch as valid-looking, no-error
behavior. A single-alert webhook test (session's earlier validation) could never have
caught this; it only showed up once multiple real alerts existed in one poll cycle.
Fixed by explicitly setting `"mode": "runOnceForEachItem"` on both nodes.

**3. Each-item mode has a different return shape.** Switching modes immediately broke
both nodes with `A 'json' property isn't an object` — `runOnceForAllItems` expects
`return [{ json: {...} }]` (an array of items), but `runOnceForEachItem` expects a single
`return { json: {...} }` (no array). Fixed both nodes' return statements.

**4. Sequential batch inference needs more timeout headroom.** With items now actually
processing one at a time, a batch of several items hit `ECONNABORTED` against Ollama at
the configured 120-second timeout — plausible under CPU-only inference with several
sequential calls, especially with a possible cold-start model reload after Ollama had
been idle. Bumped the HTTP Request timeout to 300 seconds.

**5. Dynamic date-detection locked in the wrong type from the very first test doc.**
Even with the above fixed, writes to `sentinel-triage` started failing with
`document_parsing_exception: failed to parse field [alert.winlog.event_data.TimeCreated]
of type [date]` — the index's dynamic mapping had inferred that nested field as `date`
from an early ad-hoc test document, and real Mordor data uses a different date-string
format that doesn't parse against whatever got locked in. Fixed with an index template
setting `"date_detection": false` for the `sentinel-triage*` pattern — the embedded raw
alert data doesn't need to be date-queryable, so treating those fields as safe untyped
values avoids this whole class of problem going forward.

## Phase 19 — clean end-to-end confirmation

After all five fixes, ran one final clean cycle: deleted and re-replayed the two Mordor
datasets, let the Kibana rules fire naturally on their own 5-minute schedule, and let
n8n's poller pick up the results on its own schedule — no manual triggering. Result: 4
real alerts (2× LSASS/comsvcs, 2× scheduled-task creation) generated by Kibana, all 4
picked up and correctly triaged by Ollama in a single execution with zero errors:

- 2× `severity: high` — "use of rundll32.exe to call the undocumented MiniDump export of
  comsvcs.dll against the LSASS process, a high-risk living-off-the-land technique"
- 2× `severity: medium` — correctly identified the `schtasks.exe /create` persistence
  behavior, one summary even correctly extracting the affected hostname
  (`WORKSTATION5.theshire.local`) from the raw alert data

This is the first time in the project that the full chain — detection rule fires on
real attack telemetry → alert lands in Elasticsearch → n8n polls it → a local LLM
produces an accurate, correctly-scoped triage verdict → result is written back — has
actually been observed working, rather than assumed to work from unit-level checks.

## Phase 20 — closing the loose ends: validation results and IaC for the index templates

Two follow-ups from the previous session's "not yet done" list.

First, updated `detections/tests/validation.yml`: the LSASS/comsvcs and scheduled-task
rules moved from `unvalidated` to `true_positive`, with notes pointing at the specific
Mordor sample used and the Phase 19 confirmation. Left `mttd_seconds` as `null` rather
than inventing a number — the replay script stamps `@timestamp` at replay time, not the
dataset's original event time, so a precise detect-latency figure isn't meaningful here.

Second, the two Elasticsearch index templates (`sentinel-windows-ecs`, `sentinel-triage`)
had only ever existed as ad-hoc `curl -X PUT` commands run by hand against the elastic
VM — real config, but not reproducible from the repo. Rather than reconstruct them from
memory, pulled the live definitions directly (`GET _index_template/<name>`) via SSH to
`sentinel-elastic` and committed those exact bodies to
`infra/elasticsearch/index-templates/`, plus a `deploy.sh` matching the idempotent-PUT
pattern already used by `detections/deployed/deploy.sh`.

Verifying the round-trip nearly caused a problem: `scp`'d the two new JSON files plus
`deploy.sh` into `/tmp` on the elastic VM to test-deploy them, but `/tmp` already had
several unrelated leftover files from earlier debugging sessions (`alerts_check.json`,
`final_triage.json`, `triage_check.json` — old query-result dumps, not template bodies).
`deploy.sh`'s `for template in *.json` glob picked up `alerts_check.json` too and tried
to `PUT` it as an index template body named `alerts_check`. It isn't a valid template
document, so Elasticsearch rejected it and `curl -sf` under `set -euo pipefail` aborted
the script before anything was written — confirmed after the fact with a `404` on
`_index_template/alerts_check`. No harm done, but it was a reminder not to run glob-based
deploy scripts against a directory shared with unrelated scratch files. Fixed by moving
the real template files into an isolated `/tmp/index-templates-verify/` directory,
re-running `deploy.sh` from there, and confirming both `PUT`s returned
`{"acknowledged":true}` with content identical to what was already live (Elasticsearch
doesn't bump `modified_date_millis` on a PUT with unchanged content, which is why that
field alone wasn't a reliable verification signal). Cleaned up the verification directory
afterward; the other unrelated leftover files in `/tmp` on `sentinel-elastic` were left
alone since deleting them wasn't part of this task.

## Phase 21 — cleaning up stray debug files, then a real bug in the last unvalidated rule

Before starting new work, swept `/tmp` on the live VMs for leftovers from earlier live
debugging (checked cron/systemd first to confirm nothing referenced them, then deleted):
five files on `sentinel-elastic` (old ad-hoc query-result dumps and the two Mordor
dataset zips, since those are re-downloadable and not meant to be committed), and ~44MB
of 7 stale `n8n_check*.sqlite` copies (plus WAL/SHM files) on `sentinel-soar` left over
from the SQLite-based debugging in Phase 18. `sentinel-wazuh` was already clean;
`sentinel-hub` is offline and wasn't reachable.

Then tackled the three Sigma rules with no matching Mordor sample (encoded PowerShell,
certutil download, Defender disabled). No live Windows target exists, so built
`detections/scripts/inject_synthetic_events.py`: hand-crafted ECS events matching the
exact shape `replay_mordor_dataset.py` produces, one positive event per rule plus a
benign negative control per rule (same tool, non-malicious flags), indexed into
`winlogbeat-synthetic-validation` so the live Kibana rules and n8n pipeline evaluate them
on their normal schedule — same methodology as the Mordor replay, just without genuine
recorded telemetry behind it. This is explicitly weaker evidence than the Mordor-replay
validation and is called out as such in `validation.yml`.

First live-fire attempt: certutil and Defender-disabled fired correctly (and neither
negative control did), but encoded PowerShell fired 0/1. Root-caused via `_eql/search`
run directly against the test index: the deployed query was
`process.command_line regex~ "(?i)-[e]{1}(nc(...)?)?\s"`. Two compounding bugs, found by
bisecting the query clause by clause:

1. Elasticsearch's EQL `regex~` operator performs a **full-string match**
   (`^pattern$`), not a substring search — and the `sigma-cli` `ecs_windows` EQL backend
   never wraps the compiled pattern in `.*...*` to compensate. Sigma's `|re` modifier
   means "matches anywhere in the field," so every Sigma rule converted through this
   backend with a `|re` modifier is silently broken against real data unless the deployed
   query is hand-wrapped. The other four rules use `like~`/`:` wildcard operators
   (`*text*`), which are unaffected — this backend gap only bites `regex~`.
2. The `(?i)` inline case-insensitivity flag isn't valid syntax for the Lucene automaton
   regex engine EQL's `regex~` runs on (it isn't real PCRE) — it gets matched as literal
   text, which never appears in a real command line, so it silently kills every match
   regardless of the anchoring fix. It's also redundant: confirmed via direct testing
   that `regex~` is already case-insensitive by default (an uppercase `-ENCODEDCOMMAND`
   variant matched a lowercase-only pattern once anchoring was fixed), so `(?i)` was never
   needed in the first place. (Briefly went down a dead end here — tried adding a
   `process.command_line.lowercase` runtime field, analogous to the existing `.caseless`
   field, to sidestep case-sensitivity entirely. That surfaced a third, unrelated
   limitation — `regex~` against a script-backed runtime field throws
   `Match flags not yet implemented [256]` in this Elasticsearch version — before the
   anchoring test above showed the runtime field wasn't needed at all. Reverted it.)

Fixed at the source: dropped the hand-embedded `(?i)` from
`detections/rules/proc_creation_win_encoded_powershell.yml`'s Sigma pattern (was never
valid to begin with), then re-ran `sigma-cli` to reconvert, then hand-wrapped the
compiled EQL pattern with `.*...*` when transcribing into
`detections/deployed/proc_creation_win_encoded_powershell.json` — the same kind of
manual backend-specific patch already applied for the `.caseless` field, since pysigma's
EQL backend doesn't know about either quirk. Redeployed, re-ran the synthetic events, and
confirmed exactly 3 alerts (one per rule) with zero false positives from the 3 negative
controls, all 3 correctly triaged by the n8n/Ollama pipeline.

All 5 deployed Sigma rules now have a `true_positive` validation.yml entry — two backed
by real replayed attack telemetry (Phase 19), three by synthetic events built for this
phase specifically because no Mordor sample exists for them. Cleaned up the test index
and temp files afterward.

## Phase 22 — Linux detection coverage, and the first genuinely live attack in this project

Everything validated so far — Mordor replay, synthetic events — was recorded or
synthetic telemetry, not a real attack run against a real host. This phase built actual
Linux host telemetry and ATT&CK coverage to close that gap, reusing `sentinel-wazuh`
(already live, running Suricata/Zeek) as both sensor host and attack target rather than
spinning up a new disposable VM.

**Telemetry**: deployed `auditbeat` (auditd module) as a Docker container on
`sentinel-wazuh` — `network_mode: host`, `pid: host`, `AUDIT_CONTROL`/`AUDIT_READ`
capabilities, watching `execve`/`execveat` — shipping into a new `auditbeat-linux` index
on the same `sentinel-elastic` cluster. No native `auditd` package or systemd service was
installed; auditbeat's own auditd module talks to the kernel audit netlink socket
directly, which turned out to matter later in this phase. First real event showed
auditd's PROCTITLE-record correlation working correctly out of the box — `process.args`,
`process.title` (full command line), `process.executable`, and `process.parent.pid` all
populate cleanly, unlike the raw `auditd.data.a0..aN` hex-encoded syscall arguments alone.
Committed the index template (`infra/elasticsearch/index-templates/sentinel-auditbeat-
linux.json`) as IaC before any real data landed under it, then deleted and let auditbeat
recreate the index so the explicit `keyword` mappings actually applied — Elasticsearch
index templates only affect index creation, not indices that already exist, which the
dynamic `text`-mapped index from the first test event was a reminder of.

**Detection rules**: wrote 5 Linux Sigma rules mirroring the existing Windows set by
ATT&CK technique — obfuscated `base64 -d` execution (T1059.004, analog of encoded
PowerShell), curl/wget download to a staging directory or piped to a shell (T1105, analog
of certutil), direct `/etc/shadow` access (T1003.008, analog of the LSASS dump rule), cron
persistence via a write to a system cron directory (T1053.003, analog of the scheduled-
task rule), and a defense-impairment rule analogous to Defender-disabled. No `ecs_linux`
pysigma pipeline exists (the installed `sigma-cli` only ships Windows/macOS/Kubernetes/
Zeek ECS pipelines), so all 5 were hand-converted to Kibana EQL directly against the real
auditbeat field shape — the same hand-patch precedent already established for the
`.caseless` field and the `regex~` anchoring fix. `sigma check` flagged `attack.t1562.001`
as an unrecognized ATT&CK ID; the bundled MITRE data in this pysigma install is missing
the entire T1562 family and also renames the `defense-evasion` tactic to
`defense-impairment` — a stale/nonstandard offline dataset, not a real problem with the
tag (the Windows Defender-disabled rule uses the identical real ATT&CK ID).

**Live Atomic Red Team execution — the actual point of this phase**: ran real attacker
commands against `sentinel-wazuh` over SSH, three sourced directly from the official
`atomic-red-team` GitHub catalog (base64-obfuscated `id` execution, `/etc/shadow` access,
cron.d persistence — matched by ATT&CK technique, with the exact GUIDs recorded in
`validation.yml`), two hand-run because the catalog has no Linux test for that technique
at all (T1105 has no Linux curl/wget test, only rsync/scp/sftp and Windows-only download
atomics; T1562 has no Linux test whatsoever). All 5 fired correctly, with **real measured
`mttd_seconds` for the first time in this project** (131–151 seconds for the first four;
previous Mordor/synthetic entries all recorded `null` since replayed timestamps don't
reflect genuine detection latency). Five paired negative controls (encode without decode,
a URL fetch with no output flag or shell pipe, a benign `/etc/passwd` read, a bare
`crontab -l`, and — after the rewrite below — nothing that touches the sensor containers)
were run afterward and confirmed silent across a full rule cycle.

The `/etc/shadow` and cron-persistence rules each fired more than once (4× and 2×) for a
single atomic test — not a bug. Both rules have no image filter, so they correctly caught
every process in the underlying privilege-escalation chain (the outer shell, `sudo`
itself, and the process `sudo` execs) that referenced the sensitive path on its command
line. Windows process-creation telemetry is roughly one event per user action; auditd
telemetry is one event per `execve`, so a single logical attacker action that crosses a
privilege boundary can legitimately produce multiple real alerts. Worth knowing before
treating alert *count* as a signal on this platform.

**A real design bug, found only by trying to actually test it**: the defense-impairment
rule was originally written like the Windows Defender-disabled rule — `auditctl -e 0` or
`systemctl stop auditd`. Attempting to run that live failed immediately: there is no
`auditctl` binary and no `auditd` systemd unit on `sentinel-wazuh`, because auditbeat runs
as a Docker container talking to the kernel directly rather than as a native auditd
service (deliberately, from earlier in this phase, to avoid two processes fighting over
the audit netlink socket). The rule's threat model didn't match the architecture it was
meant to protect. Rewrote it to detect the actual way this environment can be blinded —
`docker stop|kill|rm` against the project's own sensor containers (`sentinel-auditbeat`,
`sentinel-suricata`, `sentinel-zeek`) — redeployed, and validated live: `docker stop
sentinel-auditbeat`, confirmed the alert fired (74s MTTD), then `docker start
sentinel-auditbeat` immediately to restore the sensor. This is the same lesson as the
`.caseless` field and the `regex~` anchoring bug from earlier phases, generalized: a
detection rule is a claim about how a specific system actually works, and the only way to
find out it's wrong is to actually try to trigger it.

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
| Ollama (`llama3.2:3b`) | sentinel-soar | internal only (n8n → `ollama:11434`) |
| Windows telemetry target | — | torn down; fixed userdata script ready to redeploy |
| auditbeat (Linux telemetry) | sentinel-wazuh | Docker container, host network, feeding `auditbeat-linux` on sentinel-elastic |

**Detection-as-code**: 10 Sigma rules (5 Windows, 5 Linux), all deployed live as
scheduled Kibana detection rules. ATT&CK coverage: 12 techniques. All 10 are now
**confirmed firing correctly**. The 5 Windows rules were validated via a mix of real
replayed attack telemetry from OTRF Mordor (LSASS/comsvcs, scheduled-task creation) and
hand-built synthetic events (encoded PowerShell, certutil, Defender disabled — no Mordor
sample exists for these); the synthetic-event pass caught and fixed a real bug in the
encoded-PowerShell rule's `regex~` anchoring (see Phase 21). The 5 Linux rules were
validated with **genuinely live Atomic Red Team execution** against `sentinel-wazuh` (see
Phase 22) — three sourced from the official atomic-red-team catalog, two hand-run because
the catalog has no Linux test for that technique — and produced this project's first real
measured `mttd_seconds` values (74–151s). That same live-testing pass caught a real
architecture bug: a Linux defense-impairment rule modeled on `auditctl`/`systemctl` was
untestable because neither exists on a host where auditbeat runs as a Docker container
talking to the kernel directly; it was rewritten to detect `docker stop/kill/rm` against
the project's own sensor containers instead. Every rule's validation has an explicit
negative control confirming it doesn't fire on benign use of the same tool.

**LLM triage pipeline**: n8n polls Elasticsearch every 5 minutes for `sentinel-sigma`-
tagged alerts, has a self-hosted Ollama model assess severity/false-positive
likelihood/recommended action, and writes the result into a `sentinel-triage`
Elasticsearch index. **Confirmed working fully end-to-end against real alerts**,
including correct multi-item batch handling — 4 real alerts in one poll cycle, all 4
triaged accurately, zero errors.

**Replay tooling**: `detections/scripts/replay_mordor_dataset.py` plus two Elasticsearch
index templates (`sentinel-windows-ecs` for the `winlogbeat-*`/`logs-windows.*` pattern,
`sentinel-triage` for the triage output index) — both templates fix real mapping bugs
that would otherwise have surfaced again against genuine future Winlogbeat data, not
just this replay. Both templates are now committed as reproducible IaC under
`infra/elasticsearch/index-templates/` (pulled from the live cluster and verified via a
round-trip redeploy, see Phase 20), not just ad-hoc `curl` commands.

`detections/tests/validation.yml` now has all 10 rules as `true_positive` — the notes on
each entry are explicit about the strength of evidence behind it (real Mordor replay,
hand-built synthetic event, or genuinely live Atomic Red Team execution, weakest to
strongest), and the 5 Linux entries carry this project's first real measured
`mttd_seconds` values instead of `null`.

**Not yet done**: Sysmon/Winlogbeat on a live Windows target (VM currently torn down) and
a live Atomic Red Team run against it — the Windows side is still validated via replay/
synthetic events only, now that the Linux side has genuinely live coverage; a from-Kibana
push-based alternative to the n8n polling design, if the license is ever upgraded.

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
  the orchestration layer's own exit status. The same lesson showed up again with
  cloudbase-init on Windows: `Start-Process -Wait` doesn't check exit codes either, so a
  failed `msiexec` install looked identical to a successful one until the script tried to
  actually use the thing it was supposed to have installed.
- **Official docker-compose files from real projects still have gaps.** Wazuh's demo
  passwords needing the image's own hashing tool, and Shuffle's OpenSearch integration
  needing an undocumented skip-TLS-verify flag, were both things no amount of reading the
  compose file alone would have surfaced — they only showed up by actually running the
  stack and reading the failure.
- **A "partial failure" status on a live detection rule isn't automatically bad news.**
  The Kibana rule reporting no matching index is the system correctly telling the truth
  about its own state (no data source connected yet) rather than silently doing nothing
  or crashing.
- **A platform "just working" the first time doesn't mean the mechanism is understood.**
  The n8n webhook registered and responded correctly on the very first publish — then
  broke on the next container restart, and stayed broken through several plausible-looking
  fixes (`update:workflow --active=true`, `publish:workflow`, unpublish/republish via the
  UI) before the actual root cause (a missing `webhookId`, visible only by reading the raw
  SQLite tables) turned up. A workaround that happens to succeed once is not the same as
  a fix that's understood well enough to expect it to keep working.
- **SQLite's WAL mode means "just copy the .db file" can lie to you.** Reading only
  `database.sqlite` out of a running container showed 0 rows in every table, including
  ones known to have real data — the actual committed rows were sitting in the `-wal`
  sidecar file, invisible unless copied alongside the main file.
- **A paid-tier feature gate is a design constraint, not a bug to route around.** Hitting
  Kibana's licensed Webhook connector wall could have turned into a long detour trying to
  find a workaround; treating it as a hard boundary and redesigning the integration
  (push → pull) around it produced a cleaner, more standard architecture than the
  original plan would have.
- **Mechanical tests and real tests catch different bugs.** Every check before Phase 18
  (synthetic single-alert webhook calls, zero-result schedule executions returning clean
  empty responses) genuinely passed — and every single one of them would have missed all
  four bugs found by replaying real, multi-event attack data. "The pipeline runs without
  erroring" and "the pipeline produces correct results under realistic load" are different
  claims; only the second one is what actually matters, and only real data with more than
  one item in flight exposed the gap.
- **A field that "should just work" because it's `keyword`-typed can still not exist.**
  `.caseless` looked like standard EQL case-insensitivity syntax and even produced a
  plausible-sounding error ("Unknown column") that pointed toward a mapping problem —
  which was real, but fixing it wasn't enough. The deeper issue was that the field itself
  is a convention from a specific ingestion pipeline (Elastic Agent's Windows integration)
  that this project never installed, not a language feature. Worth checking what actually
  provides a field before assuming a syntax fix will make it resolve.
- **A no-code platform's "safe default" can be a silent data-loss default.** n8n's Code
  node defaulting to `runOnceForAllItems` never once threw an error while quietly
  processing only 25% of a 4-item batch — the exact kind of bug that looks like success
  in every log and every "it worked!" moment until multiple items are ever in flight at
  once.
- **A detection rule modeled on the wrong deployment mechanism will pass every check
  except the one that matters.** The Linux defense-impairment rule (`auditctl -e 0`,
  `systemctl stop auditd`) parsed cleanly, deployed cleanly, and ran on schedule without
  error — Kibana has no way to know the binary and the systemd unit it references don't
  exist on the target host. Only trying to actually execute the attacker action surfaced
  that auditbeat runs as a Docker container talking to the kernel directly, with neither.
  Synthetic events can't catch this class of bug either, since a hand-built event doesn't
  care whether the tool that would have produced it is even installed — only a live
  attempt against the real host does.
- **One logical attacker action can legitimately produce more than one real alert.**
  Windows process-creation telemetry is close to one event per user action; Linux auditd
  telemetry is one event per `execve`, so a command that crosses a privilege boundary
  (`sudo cat /etc/shadow`) generates a separate audit record for the shell, for `sudo`,
  and for the process `sudo` execs — and an image-agnostic rule correctly fires on all of
  them. Alert count isn't a reliable proxy for "number of attacker actions" across
  platforms with different telemetry granularity.
