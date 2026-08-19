# Multi-cloud: the Azure root

Sentinel's original Terraform (`infra/*.tf`) is entirely OCI-specific — `infra/modules/instance`
wraps `oci_core_instance` directly, with no abstraction layer to swap in. `infra/azure/` is a
second, complete implementation of the same architecture on Azure, proving the design ports
rather than just claiming it does.

(An earlier pass built this same second implementation on AWS. It was replaced outright with
Azure per a later request — nothing about the design changed, only the provider. AWS was never
applied against a real account, so there was no live state to migrate.)

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

## What's shared vs. reimplemented

**Shared, not duplicated**: `infra/modules/instance-azure/main.tf` renders the exact same
`infra/modules/instance/cloud-init/base.yaml.tftpl` cloud-init template the OCI module uses
(`${path.module}/../instance/cloud-init/base.yaml.tftpl`). Cloud-init itself is
provider-agnostic — both OCI and Azure accept it as instance user-data (`custom_data` on
`azurerm_linux_virtual_machine`) — so the actual provisioning logic (Docker install,
Tailscale join) is identical across providers by construction, not by two people
maintaining two scripts in sync.

**Reimplemented per-provider** (necessarily, since the resource types differ):
- VNet/subnet/NSG vs. VCN/subnet/security-list — `infra/azure/network.tf` mirrors
  `infra/network.tf`'s ingress rules as closely as Azure's model allows: only SSH (22/tcp)
  and Tailscale (41641/udp) from the public internet, plus an ICMP allowance. One real
  deviation, called out where it's built: Azure NSG rules can't filter ICMP by type/code the
  way OCI's security lists (and AWS's security groups, in the earlier pass) do — `protocol =
  "Icmp"` admits all ICMP types, not just path-MTU-discovery (type 3). Slightly broader by
  construction, not by oversight.
- SSH access: OCI takes a raw public key in instance metadata; Azure's
  `azurerm_linux_virtual_machine` takes it the same way, via an inline `admin_ssh_key` block
  reading `var.ssh_public_key_path` — no separate key-pair resource to create and share, unlike
  AWS's `aws_key_pair`. This piece ends up closer to the OCI shape than the AWS one was.
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

## Deliberately not duplicated

The disposable Windows telemetry target (`infra/windows_target.tf`) stays OCI-only. It's
explicitly a throwaway box for Sysmon/Atomic Red Team testing, not part of the core
three-VM SOC architecture this abstraction is proving out — duplicating it onto Azure would
be work with no real payoff.

## Using it

```
cd infra/azure
cp terraform.tfvars.example terraform.tfvars   # fill in tailscale_authkey, adjust sizing/region
terraform init
terraform plan     # requires Azure credentials via the standard chain (az login or ARM_* vars)
terraform apply    # human-run only, same as the OCI root
```

`terraform validate` passes without any Azure credentials present — that's been verified.
`terraform plan`/`apply` require real Azure credentials and haven't been exercised against a
live Azure subscription as part of this work; the module is structurally complete and reuses
the same provisioning logic already proven live on OCI, but an actual Azure deployment is the
next real test of it, the same way every other part of this project has ultimately been judged
by firing something real at it rather than by configuration alone.
