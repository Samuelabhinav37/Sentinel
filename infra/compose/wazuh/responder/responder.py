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
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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

# Circuit breaker: at most MAX_KILLS successful kills in a trailing WINDOW.
# A dual-AI gate misfire, or an injection that somehow gets past both
# models, should not be able to walk a host process by process -- past the
# cap, every further request is rejected until the window clears and a
# human has looked. Counted from this service's own audit log.
RESPONDER_MAX_KILLS = int(os.environ.get("RESPONDER_MAX_KILLS", "3"))
RESPONDER_WINDOW_MINUTES = int(os.environ.get("RESPONDER_WINDOW_MINUTES", "60"))

# SIGKILL is delivered asynchronously; wait this long before the single
# post-kill re-check that decides "killed" vs "kill-unconfirmed".
RESPONDER_VERIFY_DELAY = float(os.environ.get("RESPONDER_VERIFY_DELAY", "0.2"))

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


def recent_kill_count(*, path: str | None = None, window_minutes: int | None = None,
                      now: datetime | None = None) -> int:
    """Kills fired (result "killed" or "kill-unconfirmed") recorded in the
    audit log within the trailing window. Tolerates a missing file and skips
    any line that isn't a JSON object with a parseable @timestamp; a naive
    timestamp is read as UTC."""
    path = LOG_PATH if path is None else path
    window_minutes = RESPONDER_WINDOW_MINUTES if window_minutes is None else window_minutes
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return 0
    count = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict) or entry.get("result") not in ("killed", "kill-unconfirmed"):
            continue
        try:
            when = datetime.fromisoformat(entry.get("@timestamp"))
        except (TypeError, ValueError):
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when >= cutoff:
            count += 1
    return count


def confirm_gone(pid: int, *, read_comm_fn=read_comm, delay: float | None = None) -> bool:
    """True once `pid` is no longer present. One re-check after a short
    delay, since SIGKILL delivery is asynchronous -- a process still there
    after that is reported as 'kill-unconfirmed' rather than 'killed'."""
    if not read_comm_fn(pid):
        return True
    time.sleep(RESPONDER_VERIFY_DELAY if delay is None else delay)
    return not read_comm_fn(pid)


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

        recent = recent_kill_count()
        if recent >= RESPONDER_MAX_KILLS:
            detail = (f"rate-limited: {recent} kill(s) in the last "
                      f"{RESPONDER_WINDOW_MINUTES}m, at the cap of {RESPONDER_MAX_KILLS} -- "
                      f"a human needs to review before automated response resumes")
            entry["result"] = "rejected"
            entry["detail"] = detail
            log_action(entry)
            self._json(429, {"status": "error", "detail": detail})
            return

        try:
            os.kill(decision.pid, signal.SIGKILL)
        except ProcessLookupError:
            entry["result"] = "rejected"
            entry["detail"] = "process exited before kill"
            log_action(entry)
            self._json(404, {"status": "error", "detail": "process exited before kill"})
            return

        if confirm_gone(decision.pid):
            entry["result"] = "killed"
            self._json(200, {"status": "killed", "pid": decision.pid, "comm": decision.comm})
        else:
            entry["result"] = "kill-unconfirmed"
            entry["detail"] = "process still present after SIGKILL"
            self._json(200, {"status": "kill-unconfirmed", "pid": decision.pid, "comm": decision.comm})
        log_action(entry)

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
