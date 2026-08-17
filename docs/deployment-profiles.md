# Deployment profiles

Two profiles: **full** (the default, currently-running configuration —
what every phase of `docs/build-log.md` was validated against) and **lab**
(a smaller-footprint variant of the exact same architecture, for deploying
on more constrained infrastructure).

Nothing about the detection layer changes between profiles. Sigma rules,
EQL queries, the dashboard, alert suppression, and the response pipeline
are all built against ECS-normalized fields and don't know or care how big
the underlying cluster is. Only three things change: JVM/heap sizing on the
two bundled search backends, whether the optional network sensors run, and
the Terraform instance sizes.

## Why this exists

Real measured usage on the full profile, via `docker stats` on all three
VMs, for this project's actual (lab-scale) data volume:

| Service | Actual usage | Provisioned |
|---|---|---|
| Elasticsearch | ~13.4GB | 16GB limit, 12g heap |
| Kibana | ~0.8GB | 2GB limit |
| Wazuh manager | ~1.7GB | (16GB VM) |
| Wazuh indexer (OpenSearch) | ~1.6GB | 1g heap (already reasonably sized) |
| Wazuh dashboard | ~0.2GB | (16GB VM) |
| Suricata + Zeek | ~0.6GB combined | (16GB VM) |
| Shuffle OpenSearch | ~3.8GB | 3g heap |
| n8n + Ollama (idle) | ~0.5GB | (16GB VM) |

Total provisioned: **8 OCPU / 64GB across 3 VMs**. Total actual usage:
roughly a third of that, and almost all of the gap is Elasticsearch's
12g heap and Shuffle's 3g OpenSearch heap being sized for data volumes this
project's lab-scale event count never approaches -- not anything the
architecture inherently needs.

Also found in the course of measuring this: an unexplained `tenzir-node`
container running on sentinel-soar with no docker-compose project label,
not referenced by anything in this repo or Shuffle's registered app list,
publishing host ports directly (`0.0.0.0:1514`, colliding with Wazuh's own
agent-enrollment port). Predates this investigation and origin couldn't be
pinned down from available logs/history -- stopped (not removed) rather
than left running unexplained.

## What "lab" changes

1. **Elasticsearch heap**: `ES_JAVA_OPTS` and `mem_limit` in
   `infra/compose/elastic/docker-compose.yml` are now env-var-overridable,
   defaulting to the existing full-profile values if unset (so an existing
   deployment's `.env` needs no changes to keep working exactly as before).
   Set `ES_JAVA_OPTS=-Xms3g -Xmx3g` and `ES_MEM_LIMIT=4g` in `.env` for lab.

2. **Shuffle's OpenSearch heap**: a separate, explicitly-opt-in
   `infra/compose/soar/shuffle/docker-compose.lab.yml` (not auto-merged
   like `docker-compose.override.yml`, which is a permanent upstream bug
   fix -- see Phase 25 -- not a sizing choice). Reduces the heap from
   3072m/3072m to 512m/512m. Apply with `LAB_MODE=1 ./deploy.sh`.

3. **Suricata/Zeek network sensors**: already fully optional -- they're
   their own compose stack (`infra/compose/wazuh/sensors.yml`), deployed
   with a separate `docker compose -f sensors.yml up -d`. Skipping that
   command entirely is the lab-mode toggle; no code changes were needed.

4. **Terraform instance sizes**: `infra/terraform.tfvars.lab.example` --
   add its contents to your `terraform.tfvars` for right-sized VMs
   (2 OCPU/8GB, 1 OCPU/4GB, 1 OCPU/6GB instead of 4/32, 2/16, 2/16).

## What stays the same

- n8n, Ollama (`llama3.2:3b`), and the Wazuh indexer's heap were already
  reasonably sized for actual usage on measurement -- no changes.
- The responder, Shuffle workflow, dashboards, and every Sigma rule are
  identical in both profiles.
- `deploy.sh` scripts default to full-profile behavior; lab sizing is
  always an explicit opt-in (env var or a separate `-f` file), never a
  silent behavior change to an existing deployment.

## Using lab mode

```bash
# Elasticsearch: in infra/compose/elastic/.env
ES_JAVA_OPTS=-Xms3g -Xmx3g
ES_MEM_LIMIT=4g

# Shuffle
cd infra/compose/soar/shuffle && LAB_MODE=1 ./deploy.sh

# Wazuh: just don't deploy sensors.yml if network-layer detection isn't needed

# Terraform: append infra/terraform.tfvars.lab.example's contents to terraform.tfvars
```
