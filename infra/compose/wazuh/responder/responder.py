#!/usr/bin/env python3
"""Minimal automated-response bridge for the Sentinel SOAR pipeline.

Shuffle has no SSH app hot-loaded locally (only http/Shuffle AI/Shuffle
Tools/Yara/Sigma/email), so this stdlib-only HTTP service is the bridge
between "a Shuffle workflow decided to act" and "a real action happens on
the host". Deliberately scoped to one safe, bounded, reversible-ish action
-- killing a single process by pid -- not network/host isolation, which
would be far higher blast radius and much harder to undo automatically.

Every request is checked against a shared-secret token (this endpoint has
real "kill an arbitrary process" power and is reachable over the Tailscale
mesh) and a protected-process allowlist, then logged to a local JSONL file
and to the sentinel-response-actions Elasticsearch index for the same
auditability every other part of this pipeline has.
"""
import base64
import json
import os
import signal
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESPONDER_TOKEN = os.environ["RESPONDER_TOKEN"]
ELASTIC_URL = os.environ["ELASTIC_URL"]
ELASTIC_PASSWORD = os.environ["ELASTIC_PASSWORD"]
LOG_PATH = "/var/log/sentinel-responder/actions.jsonl"

# Never kill these regardless of what a rule/LLM decided -- this project's
# own sensors, and core host services whose loss would be worse than
# whatever triggered the response in the first place.
PROTECTED_COMMS = {
    "systemd", "sshd", "dockerd", "containerd", "auditbeat",
    "wazuh-modulesd", "wazuh-agentd", "wazuh-execd", "wazuh-logcollector",
    "tailscaled", "docker-proxy", "runc", "init",
}


def read_comm(pid: int) -> str:
    # The container runs with pid: host, so its own /proc already reflects
    # the host's PID namespace -- no separate host mount needed.
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def log_action(entry: dict) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

    auth = base64.b64encode(f"elastic:{ELASTIC_PASSWORD}".encode()).decode()
    req = urllib.request.Request(
        f"{ELASTIC_URL}/sentinel-response-actions/_doc",
        data=json.dumps(entry).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"warning: failed to log action to Elasticsearch: {e}")


class Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != "/respond/kill-process":
            self._json(404, {"status": "error", "detail": "unknown endpoint"})
            return

        if self.headers.get("X-Responder-Token") != RESPONDER_TOKEN:
            self._json(401, {"status": "error", "detail": "unauthorized"})
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"status": "error", "detail": "invalid JSON"})
            return

        pid = body.get("pid")
        reason = body.get("reason", "")
        alert_id = body.get("alert_id", "")

        entry = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "kill-process",
            "requested_pid": pid,
            "reason": reason,
            "alert_id": alert_id,
        }

        # Some callers (e.g. Shuffle's variable substitution into a JSON
        # body template) can only produce a numeric *string*, not a JSON
        # number -- accept either rather than silently rejecting a
        # well-formed request over a caller-side typing quirk.
        if isinstance(pid, str) and pid.isdigit():
            pid = int(pid)

        if not isinstance(pid, int) or pid <= 1:
            entry["result"] = "rejected"
            entry["detail"] = "missing/invalid pid"
            log_action(entry)
            self._json(400, {"status": "error", "detail": "missing/invalid pid"})
            return

        comm = read_comm(pid)
        entry["comm"] = comm

        if not comm:
            entry["result"] = "rejected"
            entry["detail"] = "process not found"
            log_action(entry)
            self._json(404, {"status": "error", "detail": "process not found"})
            return

        if comm in PROTECTED_COMMS:
            entry["result"] = "rejected"
            entry["detail"] = "protected process"
            log_action(entry)
            self._json(403, {"status": "error", "detail": f"refusing to kill protected process '{comm}'"})
            return

        try:
            os.kill(pid, signal.SIGKILL)
            entry["result"] = "killed"
            log_action(entry)
            self._json(200, {"status": "killed", "pid": pid, "comm": comm})
        except ProcessLookupError:
            entry["result"] = "rejected"
            entry["detail"] = "process exited before kill"
            log_action(entry)
            self._json(404, {"status": "error", "detail": "process exited before kill"})

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8088), Handler)
    print("sentinel-responder listening on :8088")
    server.serve_forever()
