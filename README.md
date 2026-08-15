# Sentinel

Security Monitoring & Threat Analysis — the correlation & response brain of a code-driven,
LLM-augmented SOC.

Detections are written once as [Sigma](https://github.com/SigmaHQ/sigma) rules, tagged to
[MITRE ATT&CK](https://attack.mitre.org/), version-controlled, and validated in CI before
being compiled to whichever backend is live — Elastic is the primary running SIEM; Splunk
is a secondary compile target used to prove portability, not a second thing to operate.

Standalone-strength test: with Axon and PRISM removed, Sentinel is still a complete SOC —
detection, correlation, SOAR response, and an LLM triage pipeline, closing the loop against
its own attack emulation.

## Architecture

```
                        ┌─────────────────────┐
   Atomic Red Team ───▶ │   Monitored host(s)  │
                        │  (Sysmon + Wazuh agt)│
                        └──────────┬───────────┘
                                   │ telemetry
                                   ▼
   ┌───────────────────────────────────────────────────┐
   │ OCI VCN (Tailscale-only access beyond SSH)         │
   │                                                     │
   │  VM1: Elasticsearch + Kibana   (primary SIEM)      │
   │  VM2: Wazuh manager + Suricata/Zeek (sensors)      │
   │  VM3: Shuffle (SOAR) + n8n (LLM triage pipeline)   │
   └───────────────────────────────────────────────────┘
                                   │ alerts / webhooks
                                   ▼
                    Shuffle workflow ──▶ n8n ──▶ LLM triage,
                    auto incident report, tier-1 response
```

## Repo layout

- `infra/` — Terraform for OCI (VCN, security lists, Ampere A1 compute instances)
- `detections/rules/` — Sigma rules, one per file, each tagged with an ATT&CK technique ID
- `detections/tests/` — attack emulation mappings (Atomic Red Team technique → expected rule)
- `pipelines/n8n/` — exported n8n workflows (alert triage, incident report generation)
- `soar/shuffle/` — exported Shuffle workflows
- `docs/` — ATT&CK coverage matrix, MTTD/false-positive tracking, architecture notes

## Design decisions

- **One SIEM runs live** (Elastic). Splunk is a Sigma compile target only — this keeps the
  project's story "portable detections," not "installed a lot of tools."
- **Security Onion was dropped** in favor of Suricata + Zeek directly — SO is x86-heavy and
  bundles services beyond what fits the OCI free-tier ARM (Ampere A1) budget.
- **Public ingress is minimal**: only SSH (22/tcp) and Tailscale (41641/udp) are open on any
  security list. Kibana, the Wazuh dashboard, Shuffle, and n8n are reached only over Tailscale.
- **Every detection loop closes**: a Sigma rule isn't "done" until Atomic Red Team has fired
  the matching technique and the true/false-positive rate + time-to-detect is recorded in
  `docs/`.

## Status

Infra is being rebuilt from scratch in Terraform (an earlier manual/click-ops OCI setup with
Wazuh running was torn down in favor of this code-driven version).
