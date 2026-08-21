#!/usr/bin/env python3
"""Sentinel MCP server -- exposes Elastic/Wazuh/Shuffle/MISP (and, as it's
wired in, Velociraptor) over the Model Context Protocol so any MCP-speaking
agent reaches this SOC through one interface instead of one-off connectors.

Each tool is a thin wrapper over an HTTP call this project already makes
somewhere else (n8n's Elasticsearch writes, the Shuffle webhook, the Wazuh
dashboard's manager API) -- no new capability is introduced, just a common
front door. Auth is a shared-secret header, the same shape as
infra/compose/wazuh/responder/responder.py's X-Responder-Token, since this
endpoint is reachable over the Tailscale mesh and some tools (Shuffle
trigger, Wazuh agent control) have real effect.

search_index is deliberately allowlisted to known index patterns rather than
a raw passthrough to the whole cluster -- see ALLOWED_INDEX_PATTERNS below.

Every tool carries a ToolAnnotations hint (read-only vs. destructive vs.
open-world) so an MCP client's permission UI can tell "safe to auto-approve"
apart from "has real effect" without parsing docstrings.
"""
import base64
import fnmatch
import json
import os
import urllib.request
from pathlib import Path
from urllib.error import HTTPError

import uvicorn
from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

MCP_TOKEN = os.environ["MCP_TOKEN"]
ELASTIC_URL = os.environ["ELASTIC_URL"]
ELASTIC_PASSWORD = os.environ["ELASTIC_PASSWORD"]
WAZUH_API_URL = os.environ["WAZUH_API_URL"]
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ["WAZUH_API_PASSWORD"]
SHUFFLE_WEBHOOK_URL = os.environ["SHUFFLE_WEBHOOK_URL"]

# Optional -- unset until a real MISP instance/feed is available. Tools that
# need these return a clear "not configured" error rather than crashing.
MISP_URL = os.environ.get("MISP_URL", "")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")

# Bind-mounted read-only from the repo checkout on the host (see
# docker-compose.yml) -- read fresh on every call rather than baked into the
# image, so it's only as stale as this VM's last `git pull`.
ATTACK_COVERAGE_PATH = Path("/app/docs/attack_coverage.json")

# Alerts pattern matches what n8n's triage workflows already query
# (infra/compose/soar/n8n/workflows/llm-triage*.json); the rest are the
# indices this project's own pipeline writes to or ships telemetry into.
ALLOWED_INDEX_PATTERNS = [
    ".alerts-security.alerts-default*",
    "sentinel-triage",
    "sentinel-response-actions",
    "winlogbeat-*",
    "auditbeat-*",
]

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
READ_ONLY_OPEN_WORLD = ToolAnnotations(read_only_hint=True, open_world_hint=True)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)
ACTION_NON_DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False)


def _http_json(url: str, method: str = "GET", headers: dict | None = None, body: dict | None = None, timeout: int = 10) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers=headers or {},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _elastic_request(path: str, method: str = "GET", body: dict | None = None) -> dict:
    auth = base64.b64encode(f"elastic:{ELASTIC_PASSWORD}".encode()).decode()
    return _http_json(
        f"{ELASTIC_URL}/{path}", method,
        {"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        body,
    )


def _index_allowed(index_pattern: str) -> bool:
    return any(fnmatch.fnmatch(index_pattern, allowed) or index_pattern == allowed
               for allowed in ALLOWED_INDEX_PATTERNS)


def _range_query(query: str, from_time: str | None, to_time: str | None) -> dict:
    base = {"query_string": {"query": query}} if query else {"match_all": {}}
    if not from_time and not to_time:
        return base
    time_range = {}
    if from_time:
        time_range["gte"] = from_time
    if to_time:
        time_range["lte"] = to_time
    return {"bool": {"must": [base], "filter": [{"range": {"@timestamp": time_range}}]}}


def _response_actions_for(alert_id: str) -> dict:
    body = {"query": {"match": {"alert_id": alert_id}}, "size": 50}
    return _elastic_request("sentinel-response-actions/_search", "POST", body)


_wazuh_token_cache: dict[str, str] = {}


def _wazuh_token() -> str:
    # Wazuh's manager API issues short-lived JWTs from a Basic-auth login
    # call; cached in-process and refreshed on a 401 rather than re-login
    # on every tool call.
    if "token" in _wazuh_token_cache:
        return _wazuh_token_cache["token"]
    auth = base64.b64encode(f"{WAZUH_API_USER}:{WAZUH_API_PASSWORD}".encode()).decode()
    data = _http_json(f"{WAZUH_API_URL}/security/user/authenticate", "POST",
                       {"Authorization": f"Basic {auth}"})
    token = data["data"]["token"]
    _wazuh_token_cache["token"] = token
    return token


def _wazuh_request(path: str) -> dict:
    def _call(token: str) -> dict:
        return _http_json(f"{WAZUH_API_URL}/{path}", "GET", {"Authorization": f"Bearer {token}"})

    try:
        return _call(_wazuh_token())
    except HTTPError as e:
        if e.code == 401:
            _wazuh_token_cache.pop("token", None)
            return _call(_wazuh_token())
        raise


def _misp_headers() -> dict:
    return {"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}


mcp = MCPServer("sentinel")


@mcp.tool(annotations=READ_ONLY)
def search_alerts(query: str = "", size: int = 20, from_time: str | None = None, to_time: str | None = None) -> dict:
    """Search Kibana security alerts. `query` is a Lucene query string
    (empty matches all); `size` caps returned hits (default 20). Optional
    `from_time`/`to_time` (ISO8601) filter on @timestamp."""
    body = {"query": _range_query(query, from_time, to_time), "size": size}
    return _elastic_request(".alerts-security.alerts-default*/_search", "POST", body)


@mcp.tool(annotations=READ_ONLY)
def get_triage(alert_id: str) -> dict:
    """Fetch the LLM triage verdict for a given alert id from the
    sentinel-triage index."""
    return _elastic_request(f"sentinel-triage/_doc/{alert_id}")


@mcp.tool(annotations=READ_ONLY)
def search_index(index_pattern: str, query: str = "", size: int = 20, from_time: str | None = None, to_time: str | None = None) -> dict:
    """Search an allowlisted Sentinel index (sentinel-triage,
    sentinel-response-actions, winlogbeat-*, auditbeat-*, or the security
    alerts pattern). Rejects anything outside that allowlist. Optional
    `from_time`/`to_time` (ISO8601) filter on @timestamp."""
    if not _index_allowed(index_pattern):
        return {"error": f"index pattern '{index_pattern}' is not allowlisted", "allowed": ALLOWED_INDEX_PATTERNS}
    body = {"query": _range_query(query, from_time, to_time), "size": size}
    return _elastic_request(f"{index_pattern}/_search", "POST", body)


@mcp.tool(annotations=READ_ONLY)
def get_response_actions(alert_id: str) -> dict:
    """Look up automated response actions taken for a given alert id in
    sentinel-response-actions."""
    return _response_actions_for(alert_id)


@mcp.tool(annotations=READ_ONLY)
def get_alert_context(alert_id: str) -> dict:
    """Bundle everything Sentinel knows about one alert in a single call:
    the raw alert, both triage verdicts (the poll and push pipelines write
    distinct doc ids, alert_id and alert_id-push), and any response actions
    taken. Doesn't resolve a Wazuh agent from host.name -- use
    list_wazuh_agents/get_wazuh_agent_status with the returned host name if
    you need that."""
    alert_hits = _elastic_request(
        ".alerts-security.alerts-default*/_search", "POST",
        {"query": {"term": {"_id": alert_id}}, "size": 1},
    ).get("hits", {}).get("hits", [])
    alert = alert_hits[0]["_source"] if alert_hits else None

    def _try_triage(doc_id: str) -> dict | None:
        try:
            return _elastic_request(f"sentinel-triage/_doc/{doc_id}")
        except HTTPError as e:
            if e.code == 404:
                return None
            raise

    return {
        "alert_id": alert_id,
        "alert": alert,
        "triage_poll": _try_triage(alert_id),
        "triage_push": _try_triage(f"{alert_id}-push"),
        "response_actions": _response_actions_for(alert_id),
    }


@mcp.tool(annotations=DESTRUCTIVE)
def trigger_shuffle_response(pid: int, reason: str, alert_id: str) -> dict:
    """Trigger the Shuffle auto-response workflow to kill a process by pid,
    the same call n8n's Cross-Check Gate makes today. Shuffle and the
    responder still enforce the protected-process allowlist -- this does
    not bypass it."""
    body = {"pid": pid, "reason": reason, "alert_id": alert_id}
    req = urllib.request.Request(
        SHUFFLE_WEBHOOK_URL,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return {"status": resp.status, "body": resp.read().decode()}


@mcp.tool(annotations=READ_ONLY)
def list_wazuh_agents() -> dict:
    """List agents registered with the Wazuh manager (via its own manager
    API, not the Wazuh indexer -- see build-log for why)."""
    return _wazuh_request("agents")


@mcp.tool(annotations=READ_ONLY)
def get_wazuh_agent_status(agent_id: str) -> dict:
    """Get a single Wazuh agent's status/details by agent id."""
    return _wazuh_request(f"agents?agents_list={agent_id}")


@mcp.tool(annotations=READ_ONLY)
def get_agent_vulnerabilities(agent_id: str, severity: str | None = None) -> dict:
    """List vulnerabilities detected on a Wazuh agent (Vulnerability
    Detector module). Optional `severity` filter (Critical/High/Medium/Low)."""
    path = f"vulnerability/{agent_id}"
    if severity:
        path += f"?severity={severity}"
    return _wazuh_request(path)


@mcp.tool(annotations=READ_ONLY)
def get_agent_sca(agent_id: str) -> dict:
    """Get Security Configuration Assessment (SCA) policy results for a
    Wazuh agent -- pass/fail counts and compliance score per policy."""
    return _wazuh_request(f"sca/{agent_id}")


@mcp.tool(annotations=READ_ONLY)
def get_detection_coverage() -> dict:
    """Return this repo's ATT&CK Navigator coverage layer -- which
    techniques have a Sigma rule and which rule file(s) cover them. Read
    from a bind-mounted snapshot of docs/attack_coverage.json, refreshed by
    this VM's last `git pull`, not computed live against the cluster."""
    if not ATTACK_COVERAGE_PATH.exists():
        return {"error": f"{ATTACK_COVERAGE_PATH} not found -- is docs/ bind-mounted?"}
    layer = json.loads(ATTACK_COVERAGE_PATH.read_text(encoding="utf-8"))
    return {
        "layer": layer,
        "note": "snapshot of docs/attack_coverage.json as of this VM's last git pull, not live-computed",
    }


@mcp.tool(annotations=READ_ONLY_OPEN_WORLD)
def misp_search_ioc(indicator_type: str, value: str) -> dict:
    """Look up an indicator of compromise (e.g. indicator_type='ip-dst',
    value='1.2.3.4') against a MISP instance's restSearch API. Returns a
    'not_configured' error until MISP_URL/MISP_API_KEY are set."""
    if not MISP_URL or not MISP_API_KEY:
        return {"status": "not_configured", "detail": "MISP_URL/MISP_API_KEY are not set on this deployment"}
    body = {"returnFormat": "json", "type": indicator_type, "value": value}
    return _http_json(f"{MISP_URL}/attributes/restSearch", "POST", _misp_headers(), body)


@mcp.tool(annotations=READ_ONLY_OPEN_WORLD)
def misp_get_event(event_id: str) -> dict:
    """Fetch a single MISP event by id -- full context (attributes, tags,
    related objects), for deeper enrichment after misp_search_ioc finds a
    match. Returns a 'not_configured' error until MISP_URL/MISP_API_KEY are
    set."""
    if not MISP_URL or not MISP_API_KEY:
        return {"status": "not_configured", "detail": "MISP_URL/MISP_API_KEY are not set on this deployment"}
    return _http_json(f"{MISP_URL}/events/view/{event_id}", "GET", _misp_headers())


@mcp.tool(annotations=READ_ONLY)
def velociraptor_list_clients() -> dict:
    """List Velociraptor clients. Stubbed: the Velociraptor server is
    deployed (infra/compose/velociraptor), but no client is enrolled yet
    and this tool isn't wired to its gRPC/mTLS API (that needs the
    server-generated client cert, a human bootstrap step, plus a real gRPC
    client -- not worth building against nothing to test it against).
    Revisit once a client (e.g. the Windows target) is enrolled."""
    return {"status": "not_configured", "detail": "Velociraptor API integration not yet wired up -- server-only for now"}


@mcp.tool(annotations=ACTION_NON_DESTRUCTIVE)
def velociraptor_run_hunt(vql: str) -> dict:
    """Run a VQL hunt against enrolled Velociraptor clients. Stubbed for
    the same reason as velociraptor_list_clients."""
    return {"status": "not_configured", "detail": "Velociraptor API integration not yet wired up -- server-only for now"}


class TokenAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.headers.get("X-MCP-Token") != MCP_TOKEN:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


app = mcp.streamable_http_app()
app.add_middleware(TokenAuthMiddleware)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8090)
