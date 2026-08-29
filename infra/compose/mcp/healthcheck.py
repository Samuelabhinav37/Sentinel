#!/usr/bin/env python3
"""Docker healthcheck for the MCP server. A 401 (missing/wrong X-MCP-Token)
still counts as healthy -- it's proof uvicorn is up and TokenAuthMiddleware
is running, not that this specific request's auth succeeded."""
import sys
import urllib.error
import urllib.request

try:
    urllib.request.urlopen("http://localhost:8090/mcp", timeout=3)
except urllib.error.HTTPError as e:
    sys.exit(0 if e.code == 401 else 1)
except Exception:
    sys.exit(1)
else:
    sys.exit(0)
