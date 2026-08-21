#!/usr/bin/env python3
"""Sentinel MCP server -- exposes Elastic/Wazuh/Shuffle (and, as they're wired
in, MISP/Velociraptor) over the Model Context Protocol so any MCP-speaking
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
"""
import base64
import fnmatch
import json
import os
import urllib.request
from urllib.error import HTTPError

import uvicorn
from mcp.server import MCPServer
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


def _elastic_request(path: str, method: str = "GET", body: dict | None = None) -> dict:
    auth = base64.b64encode(f"elastic:{ELASTIC_PASSWORD}".encode()).decode()
    req = urllib.request.Request(
        f"{ELASTIC_URL}/{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _index_allowed(index_pattern: str) -> bool:
    return any(fnmatch.fnmatch(index_pattern, allowed) or index_pattern == allowed
               for allowed in ALLOWED_INDEX_PATTERNS)


_wazuh_token_cache: dict[str, str] = {}


def _wazuh_token() -> str:
    # Wazuh's manager API issues short-lived JWTs from a Basic-auth login
    # call; cached in-process and refreshed on a 401 rather than re-login
    # on every tool call.
    if "token" in _wazuh_token_cache:
        return _wazuh_token_cache["token"]
    auth = base64.b64encode(f"{WAZUH_API_USER}:{WAZUH_API_PASSWORD}".encode()).decode()
    req = urllib.request.Request(
        f"{WAZUH_API_URL}/security/user/authenticate",
        method="POST",
        headers={"Authorization": f"Basic {auth}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        token = json.loads(resp.read())["data"]["token"]
    _wazuh_token_cache["token"] = token
    return token


def _wazuh_request(path: str) -> dict:
    def _call(token: str) -> dict:
        req = urllib.request.Request(
            f"{WAZUH_API_URL}/{path}",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    try:
        return _call(_wazuh_token())
    except HTTPError as e:
        if e.code == 401:
            _wazuh_token_cache.pop("token", None)
            return _call(_wazuh_token())
        raise


mcp = MCPServer("sentinel")


@mcp.tool()
def search_alerts(query: str = "", size: int = 20) -> dict:
    """Search Kibana security alerts. `query` is a Lucene query string
    (empty matches all); `size` caps returned hits (default 20)."""
    body = {"query": {"query_string": {"query": query}} if query else {"match_all": {}}, "size": size}
    return _elastic_request(".alerts-security.alerts-default*/_search", "POST", body)


@mcp.tool()
def get_triage(alert_id: str) -> dict:
    """Fetch the LLM triage verdict for a given alert id from the
    sentinel-triage index."""
    return _elastic_request(f"sentinel-triage/_doc/{alert_id}")


@mcp.tool()
def search_index(index_pattern: str, query: str = "", size: int = 20) -> dict:
    """Search an allowlisted Sentinel index (sentinel-triage,
    sentinel-response-actions, winlogbeat-*, auditbeat-*, or the security
    alerts pattern). Rejects anything outside that allowlist."""
    if not _index_allowed(index_pattern):
        return {"error": f"index pattern '{index_pattern}' is not allowlisted", "allowed": ALLOWED_INDEX_PATTERNS}
    body = {"query": {"query_string": {"query": query}} if query else {"match_all": {}}, "size": size}
    return _elastic_request(f"{index_pattern}/_search", "POST", body)


@mcp.tool()
def get_response_actions(alert_id: str) -> dict:
    """Look up automated response actions taken for a given alert id in
    sentinel-response-actions."""
    body = {"query": {"match": {"alert_id": alert_id}}, "size": 50}
    return _elastic_request("sentinel-response-actions/_search", "POST", body)


@mcp.tool()
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


@mcp.tool()
def list_wazuh_agents() -> dict:
    """List agents registered with the Wazuh manager (via its own manager
    API, not the Wazuh indexer -- see build-log for why)."""
    return _wazuh_request("agents")


@mcp.tool()
def get_wazuh_agent_status(agent_id: str) -> dict:
    """Get a single Wazuh agent's status/details by agent id."""
    return _wazuh_request(f"agents?agents_list={agent_id}")


@mcp.tool()
def misp_search_ioc(indicator_type: str, value: str) -> dict:
    """Look up an indicator of compromise (e.g. indicator_type='ip-dst',
    value='1.2.3.4') against a MISP instance's restSearch API. Returns a
    'not_configured' error until MISP_URL/MISP_API_KEY are set."""
    if not MISP_URL or not MISP_API_KEY:
        return {"status": "not_configured", "detail": "MISP_URL/MISP_API_KEY are not set on this deployment"}
    body = {"returnFormat": "json", "type": indicator_type, "value": value}
    req = urllib.request.Request(
        f"{MISP_URL}/attributes/restSearch",
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Authorization": MISP_API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


@mcp.tool()
def velociraptor_list_clients() -> dict:
    """List Velociraptor clients. Stubbed: the Velociraptor server is
    deployed (infra/compose/velociraptor), but no client is enrolled yet
    and this tool isn't wired to its gRPC/mTLS API (that needs the
    server-generated client cert, a human bootstrap step, plus a real gRPC
    client -- not worth building against nothing to test it against).
    Revisit once a client (e.g. the Windows target) is enrolled."""
    return {"status": "not_configured", "detail": "Velociraptor API integration not yet wired up -- server-only for now"}


@mcp.tool()
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
