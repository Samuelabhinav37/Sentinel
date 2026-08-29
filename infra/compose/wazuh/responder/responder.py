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
from __future__ import annotations

import base64
import hmac
import json
import os
import signal
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Read with a fallback rather than a hard KeyError at import time, so the
# decision logic below can be imported and unit-tested without a full
# environment. `main()` still refuses to start the server if any of these
# is actually unset -- a misconfigured responder fails loud, it just fails
# at startup with a clear message instead of a bare KeyError on import.
REQUIRED_ENV = ("RESPONDER_TOKEN", "ELASTIC_URL", "ELASTIC_PASSWORD")
RESPONDER_TOKEN = os.environ.get("RESPONDER_TOKEN", "")
ELASTIC_URL = os.environ.get("ELASTIC_URL", "")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "")
LOG_PATH = os.environ.get("RESPONDER_LOG_PATH", "/var/log/sentinel-responder/actions.jsonl")

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


@dataclass
class KillDecision:
    """Outcome of evaluating a kill request, before any side effect runs.

    `log_detail` is what lands in the audit entry's `detail`; `client_detail`
    is what the HTTP caller sees -- they differ only for a protected process
    (the audit says "protected process", the caller is told which one)."""

    proceed: bool
    http_status: int
    log_detail: str
    client_detail: str
    comm: str | None = None
    pid: int | None = None


def evaluate_kill(raw_pid, *, read_comm_fn=read_comm, protected=PROTECTED_COMMS) -> KillDecision:
    """Decide whether a kill may proceed. Pure -- no os.kill, no logging.

    Mirrors exactly the checks the HTTP handler used to inline: a numeric
    string is coerced to int (some callers can only template a string),
    the pid must then be an int > 1, the process must exist, and its comm
    must not be on the protected allowlist."""
    pid = raw_pid
    if isinstance(pid, str) and pid.isdigit():
        pid = int(pid)
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return KillDecision(False, 400, "missing/invalid pid", "missing/invalid pid")
    comm = read_comm_fn(pid)
    if not comm:
        return KillDecision(False, 404, "process not found", "process not found", comm="", pid=pid)
    if comm in protected:
        return KillDecision(
            False, 403, "protected process",
            f"refusing to kill protected process '{comm}'", comm=comm, pid=pid,
        )
    return KillDecision(True, 200, "", "", comm=comm, pid=pid)


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

        if not hmac.compare_digest(self.headers.get("X-Responder-Token", ""), RESPONDER_TOKEN):
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

        decision = evaluate_kill(pid)
        if decision.comm is not None:
            entry["comm"] = decision.comm

        if not decision.proceed:
            entry["result"] = "rejected"
            entry["detail"] = decision.log_detail
            log_action(entry)
            self._json(decision.http_status, {"status": "error", "detail": decision.client_detail})
            return

        try:
            os.kill(decision.pid, signal.SIGKILL)
            entry["result"] = "killed"
            log_action(entry)
            self._json(200, {"status": "killed", "pid": decision.pid, "comm": decision.comm})
        except ProcessLookupError:
            entry["result"] = "rejected"
            entry["detail"] = "process exited before kill"
            log_action(entry)
            self._json(404, {"status": "error", "detail": "process exited before kill"})

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


def main() -> None:
    missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
    if missing:
        raise SystemExit(f"sentinel-responder: missing required env: {', '.join(missing)}")
    server = ThreadingHTTPServer(("0.0.0.0", 8088), Handler)
    print("sentinel-responder listening on :8088")
    server.serve_forever()


if __name__ == "__main__":
    main()
