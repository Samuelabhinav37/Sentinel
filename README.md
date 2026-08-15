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

- `infra/` — Terraform for OCI (VCN, security lists, compute instances)
- `detections/rules/` — Sigma rules, one per file, each tagged with an ATT&CK technique ID
- `detections/tests/` — attack emulation mappings (Atomic Red Team technique → expected rule)
- `pipelines/n8n/` — exported n8n workflows (alert triage, incident report generation)
- `soar/shuffle/` — exported Shuffle workflows
- `docs/` — ATT&CK coverage matrix, MTTD/false-positive tracking, architecture notes

## Design decisions

- **One SIEM runs live** (Elastic). Splunk is a Sigma compile target only — this keeps the
  project's story "portable detections," not "installed a lot of tools."
- **Security Onion was dropped** in favor of Suricata + Zeek directly — SO bundles more
  services than this project needs to run per host.
- **Public ingress is minimal**: only SSH (22/tcp) and Tailscale (41641/udp) are open on any
  security list. Kibana, the Wazuh dashboard, Shuffle, and n8n are reached only over Tailscale.
- **Every detection loop closes**: a Sigma rule isn't "done" until Atomic Red Team has fired
  the matching technique and the true/false-positive rate + time-to-detect is recorded in
  `docs/`.

## Status

Infra is being rebuilt from scratch in Terraform (an earlier manual/click-ops OCI setup with
Wazuh running was torn down in favor of this code-driven version). Currently running on
`VM.Standard.E4.Flex` (paid, billed against a time-limited OCI trial) rather than the
Always Free `VM.Standard.A1.Flex` shape — free-tier Ampere A1 capacity was unavailable in
the home region at provisioning time. Plan to right-size back down to Always Free-eligible
shapes before the trial credit expires.

All three service stacks are deployed and verified live: Elastic (Elasticsearch + Kibana),
Wazuh (manager + indexer + dashboard) with Suricata and Zeek feeding it sensor telemetry,
and Shuffle SOAR + n8n. Everything is reachable only over Tailscale, per the ingress design
above. Not yet done: no Sigma rules are deployed as live detections in Elastic/Wazuh yet
(only the one example rule exists as source), no Atomic Red Team validation has run, and
the LLM triage pipeline in n8n hasn't been built.
