# Multi-cloud: the Azure and AWS roots

Sentinel's original Terraform (`infra/*.tf`) is entirely OCI-specific — `infra/modules/instance`
wraps `oci_core_instance` directly, with no abstraction layer to swap in. `infra/azure/` is a
second, complete implementation of the same architecture on Azure, proving the design ports
rather than just claiming it does.

`infra/aws/` is a third root. Unlike the Azure root it is **not** a full re-implementation of
the three-VM stack — it stands up a single lightweight Linux *attack-target* endpoint that
enrolls into the live OCI SIEM over Tailscale (see "The `target` role" below). `infra/azure/`
now carries the same kind of target alongside its full stack.

(An earlier pass built a full Azure-style stack on AWS, then removed it in favour of Azure —
nothing about the design changed, only the provider, and it was never applied against a real
account. AWS is back now deliberately, but scoped down: just the attack-target endpoint, not
a second full stack. OCI remains the one full live deployment.)

## Why a separate root, not one abstracted config

Terraform can't conditionally select between two providers' resource types in a single
`plan` the way application code can branch on a variable — `oci_core_instance` and
`azurerm_linux_virtual_machine` are different resource types with different schemas, so
"abstracting" them into one file means either a fragile `count`-gated mess referencing both
providers in every plan, or genuinely separate resource blocks. Given the live OCI deployment
(`infra/`) has to keep working untouched, the safer and clearer design is:

- **`infra/`** — OCI, unchanged. Still the live, deployed environment.
- **`infra/azure/`** — Azure, a fully separate root module with its own state, its own
  `terraform init`, and its own `terraform plan`/`apply`. It never reads or writes
  `infra/`'s state, so nothing done here can affect what's actually running.
- **`infra/aws/`** — AWS, another fully separate root with its own state. Scoped to one
  attack-target endpoint (`module "linux_target"`), not the full stack.

Each root has its own instance module: `infra/modules/instance` (OCI),
`infra/modules/instance-azure`, `infra/modules/instance-aws`. All three render the same
provider-agnostic cloud-init templates from `infra/modules/instance/cloud-init/`.

## What's shared vs. reimplemented

**Shared, not duplicated**: `infra/modules/instance-azure/main.tf` renders the exact same
`infra/modules/instance/cloud-init/base.yaml.tftpl` cloud-init template the OCI module uses
(`${path.module}/../instance/cloud-init/base.yaml.tftpl`). Cloud-init itself is
provider-agnostic — both OCI and Azure accept it as instance user-data (`custom_data` on
`azurerm_linux_virtual_machine`) — so the actual provisioning logic (Docker install,
Tailscale join) is identical across providers by construction, not by two people
maintaining two scripts in sync.

**Reimplemented per-provider** (necessarily, since the resource types differ):
- VNet/subnet/NSG vs. VCN/subnet/security-list vs. VPC/subnet/security-group —
  `infra/azure/network.tf` and `infra/aws/network.tf` mirror `infra/network.tf`'s ingress
  rules as closely as each provider's model allows: only SSH (22/tcp) and Tailscale
  (41641/udp) from the public internet, plus an ICMP allowance for path-MTU-discovery.
  One real deviation, called out where it's built: **Azure NSG rules can't filter ICMP by
  type/code**, so `protocol = "Icmp"` admits all ICMP types, not just type 3. **AWS security
  groups can** — `infra/aws/network.tf` scopes the ICMP rule to type 3 code 4 exactly as the
  OCI security list does (`from_port = 3`, `to_port = 4` on `protocol = "icmp"` is AWS's
  type/code encoding). So on this point AWS matches OCI and only Azure is broader, by
  construction rather than oversight.
- SSH access: OCI takes a raw public key in instance metadata; Azure's
  `azurerm_linux_virtual_machine` takes it the same way, via an inline `admin_ssh_key` block
  reading `var.ssh_public_key_path`. AWS needs a separate `aws_key_pair` resource (created in
  `infra/modules/instance-aws` from the same `var.ssh_public_key_path`) that the instance
  then references by name — one extra resource, same input.
- Sizing: OCI's `ocpus`/`memory_gb` (flexible shapes) don't map onto Azure's fixed VM sizes,
  so `infra/azure/variables.tf` uses `*_vm_size` strings instead (`elastic_vm_size`,
  `wazuh_vm_size`, `soar_vm_size`), with defaults chosen as a rough sizing match to the OCI
  root's defaults (`Standard_E4s_v5` — 4 vCPU/32 GiB, memory-optimized — for elastic;
  `Standard_D4s_v5` — 4 vCPU/16 GiB — for wazuh/soar) — not required to match exactly.
- Credentials: OCI's root takes explicit `tenancy_ocid`/`user_ocid`/`fingerprint`/
  `private_key_path` variables. Azure's provider instead uses the standard Azure credential
  chain — a cached `az login` session, or `ARM_SUBSCRIPTION_ID`/`ARM_TENANT_ID`/
  `ARM_CLIENT_ID`/`ARM_CLIENT_SECRET` env vars for a service principal — the established
  convention for Azure Terraform configs, so there's no custom credential variable to invent
  or keep in sync.
- Resource grouping: Azure requires every resource to live inside an `azurerm_resource_group`.
  `infra/azure/network.tf` creates one (`sentinel`) that everything else in the root is scoped
  under — OCI and AWS have no equivalent concept.

## The `target` role

`base.yaml.tftpl` (the cloud-init the three stack VMs use) installs Docker + Tailscale and
nothing else — per-role service stacks are brought up out of band. `target.yaml.tftpl` is a
second template, selected by the AWS and Azure instance modules when `role == "target"`:

- Same Docker + Tailscale install as the base template.
- Plus it drops `/opt/sentinel/target/{docker-compose.yml,auditbeat.yml}` and runs
  `docker compose up -d` at first boot, so the box ships process-creation telemetry the
  moment it joins the tailnet — no manual step. The sensor is the same
  `docker.elastic.co/beats/auditbeat:9.2.1` container, audit rule, and noise filtering as the
  hand-deployed one on `sentinel-wazuh`; a reference copy lives at `infra/compose/target/`
  (named `docker-compose.yml` so CI's compose-config job validates it).
- The two extra template inputs — `elastic_url`, `elastic_password` — are rendered into the
  sensor config. They reach the module as sensitive variables with empty-string defaults, so
  the `elastic`/`wazuh`/`soar` roles (which render `base.yaml.tftpl`) don't have to supply
  them. `elastic_password` lives only in the gitignored `terraform.tfvars`.

Telemetry lands in the existing `auditbeat-linux` rollover alias (already covered by
`infra/elasticsearch/index-templates/sentinel-auditbeat-linux.json` and the
`sentinel-telemetry-retention` ILM policy). Multiple hosts on one alias is fine — `host.name`
disambiguates — so no new index template or ILM policy was needed.

The OCI instance module (`infra/modules/instance`) is left untouched: still `base.yaml.tftpl`
only. There is no OCI Linux attack target — the OCI side already has `sentinel-wazuh` itself
and the Windows target for live-fire.

## Deliberately not duplicated

The disposable Windows telemetry target (`infra/windows_target.tf`) stays OCI-only. It's
explicitly a throwaway box for Sysmon/Atomic Red Team testing, not part of the core
three-VM SOC architecture this abstraction is proving out — duplicating it onto Azure or AWS
would be work with no real payoff. The Linux attack targets on AWS/Azure cover the
cross-cloud live-fire story; the Windows target covers the Windows-telemetry story.

## Using it

`scripts/setup-cloud-creds.sh` is a wizard that walks through cloud-CLI auth, fills both
`terraform.tfvars` files, and runs `init` + `plan` as a read-only readiness check (never
`apply`). By hand:

```
# Azure (full stack + a target)
cd infra/azure
cp terraform.tfvars.example terraform.tfvars   # tailscale_authkey, elastic_url, elastic_password, sizing/region
terraform init
terraform plan      # requires Azure credentials via the standard chain (az login or ARM_* vars)
terraform apply     # human-run only, same as the OCI root

# AWS (attack-target endpoint only)
cd infra/aws
cp terraform.tfvars.example terraform.tfvars   # tailscale_authkey, elastic_url, elastic_password, region
terraform init
terraform plan      # requires AWS credentials via the standard chain (env / ~/.aws / SSO)
terraform apply     # human-run only
```

`terraform validate` passes on all three roots with no cloud credentials present — verified.
`plan`/`apply` need real credentials and have **not** been run against a live AWS or Azure
account as part of this work. The modules are structurally complete and reuse provisioning
logic already proven live on OCI, but an actual deployment + an end-to-end demo run
(`scripts/run-e2e-demo.sh`, `docs/demo-runbook.md`) is the next real test — the same way every
other part of this project has ultimately been judged by firing something real at it.

### CI note

`.github/workflows/infra-ci.yml` (added on the `feat/hardening-ci-tests-response` branch) runs
`terraform validate` as one hardcoded step per root. When that branch and this one both land,
it needs a **third** step with `working-directory: infra/aws` alongside the existing `infra`
and `infra/azure` steps. `terraform fmt -check -recursive infra/` and the compose-config glob
already cover the new files.
