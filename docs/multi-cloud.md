# Multi-cloud: the AWS root

Sentinel's original Terraform (`infra/*.tf`) is entirely OCI-specific — `infra/modules/instance`
wraps `oci_core_instance` directly, with no abstraction layer to swap in. `infra/aws/` is a
second, complete implementation of the same architecture on AWS, proving the design ports
rather than just claiming it does.

## Why a separate root, not one abstracted config

Terraform can't conditionally select between two providers' resource types in a single
`plan` the way application code can branch on a variable — `oci_core_instance` and
`aws_instance` are different resource types with different schemas, so "abstracting" them
into one file means either a fragile `count`-gated mess referencing both providers in every
plan, or genuinely separate resource blocks. Given the live OCI deployment (`infra/`) has to
keep working untouched, the safer and clearer design is:

- **`infra/`** — OCI, unchanged. Still the live, deployed environment.
- **`infra/aws/`** — AWS, a fully separate root module with its own state, its own
  `terraform init`, and its own `terraform plan`/`apply`. It never reads or writes
  `infra/`'s state, so nothing done here can affect what's actually running.

## What's shared vs. reimplemented

**Shared, not duplicated**: `infra/modules/instance-aws/main.tf` renders the exact same
`infra/modules/instance/cloud-init/base.yaml.tftpl` cloud-init template the OCI module uses
(`${path.module}/../instance/cloud-init/base.yaml.tftpl`). Cloud-init itself is
provider-agnostic — both OCI and AWS accept it as instance `user_data` — so the actual
provisioning logic (Docker install, Tailscale join) is identical across providers by
construction, not by two people maintaining two scripts in sync.

**Reimplemented per-provider** (necessarily, since the resource types differ):
- VPC/subnet/security-group vs. VCN/subnet/security-list — `infra/aws/network.tf` mirrors
  `infra/network.tf`'s exact ingress rules: only SSH (22/tcp) and Tailscale (41641/udp) from
  the public internet, plus the same path-MTU-discovery ICMP allowance. Nothing else is
  opened, matching the project's "minimal public ingress" design decision.
- SSH access: OCI takes a raw public key in instance metadata; AWS requires a named
  `aws_key_pair` resource first. `infra/aws/compute.tf` creates one `aws_key_pair` from the
  same `ssh_public_key_path` variable and shares it across all three instances, rather than
  creating (and duplicating) a key pair per VM.
- Sizing: OCI's `ocpus`/`memory_gb` (flexible shapes) don't map onto AWS's fixed instance
  types, so `infra/aws/variables.tf` uses `*_instance_type` strings instead
  (`elastic_instance_type`, `wazuh_instance_type`, `soar_instance_type`), with defaults
  chosen as a rough sizing match to the OCI root's defaults — not required to match exactly.
- Credentials: OCI's root takes explicit `tenancy_ocid`/`user_ocid`/`fingerprint`/
  `private_key_path` variables. AWS's provider instead uses the standard AWS credential
  chain (env vars, `~/.aws/credentials`, or an IAM role) — the established convention for
  AWS Terraform configs, so there's no custom credential variable to invent or keep in sync.

## Deliberately not duplicated

The disposable Windows telemetry target (`infra/windows_target.tf`) stays OCI-only. It's
explicitly a throwaway box for Sysmon/Atomic Red Team testing, not part of the core
three-VM SOC architecture this abstraction is proving out — duplicating it onto AWS would
be work with no real payoff.

## Using it

```
cd infra/aws
cp terraform.tfvars.example terraform.tfvars   # fill in tailscale_authkey, adjust sizing/region
terraform init
terraform plan     # requires AWS credentials via the standard chain
terraform apply    # human-run only, same as the OCI root
```

`terraform validate` passes without any AWS credentials present — that's been verified.
`terraform plan`/`apply` require real AWS credentials and haven't been exercised against a
live AWS account as part of this work; the module is structurally complete and reuses the
same provisioning logic already proven live on OCI, but an actual AWS deployment is the next
real test of it, the same way every other part of this project has ultimately been judged by
firing something real at it rather than by configuration alone.
