#!/usr/bin/env python3
"""Replay an OTRF Security-Datasets (Mordor) atomic dataset into Elasticsearch.

Mordor datasets are raw Windows Event Log JSON (one event per line, fields
like NewProcessName/CommandLine/EventID), not ECS. This maps the handful of
fields our Sigma-compiled EQL rules actually query (process.executable,
process.command_line, host.name, @timestamp) so the rules can evaluate
against real recorded attack telemetry without a live Windows endpoint.

Usage:
  ELASTIC_URL=http://100.103.246.10:9200 ELASTIC_PASSWORD=... \
    python3 replay_mordor_dataset.py <mordor.zip> [--index winlogbeat-mordor-replay]
"""
import argparse
import json
import os
import sys
import zipfile
from datetime import datetime, timezone

import urllib.request
import base64

# Windows Security-log process-creation events (4688) use these field names.
# Sysmon-channel events (EventID 1) use Image/CommandLine directly - handle both.
def to_ecs(raw):
    executable = raw.get("NewProcessName") or raw.get("Image")
    command_line = raw.get("CommandLine")
    if not executable or not command_line:
        return None

    # Stamped as "now" rather than the dataset's original (multi-year-old)
    # TimeCreated - the point of this replay is to exercise the live
    # detection rule schedule and the n8n polling pipeline exactly as they'd
    # see a real alert, not to archive historical events. Original time is
    # kept under winlog.event_data for reference.
    ts = datetime.now(timezone.utc).isoformat()

    host = (
        raw.get("SubjectDomainName")
        or raw.get("Computer")
        or raw.get("Hostname")
        or "mordor-replay-host"
    )

    return {
        "@timestamp": ts,
        "event": {"code": str(raw.get("EventID", "")), "category": ["process"]},
        "host": {"name": host},
        "process": {
            "executable": executable,
            "command_line": command_line,
        },
        "sentinel": {"source": "mordor-replay"},
        "winlog": {"event_data": raw},
    }


def iter_events(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            for line in z.read(name).decode("utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def bulk_index(es_url, es_password, index, docs):
    if not docs:
        print("no matching process-creation events found in this dataset")
        return

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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", help="path to a downloaded Mordor .zip file")
    parser.add_argument("--index", default="winlogbeat-mordor-replay")
    args = parser.parse_args()

    es_url = os.environ["ELASTIC_URL"]
    es_password = os.environ["ELASTIC_PASSWORD"]

    docs = [d for raw in iter_events(args.dataset) if (d := to_ecs(raw))]
    print(f"parsed {len(docs)} process-creation events from {args.dataset}")
    bulk_index(es_url, es_password, args.index, docs)


if __name__ == "__main__":
    main()
