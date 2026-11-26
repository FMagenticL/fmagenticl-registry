#!/usr/bin/env python3
"""
External Surface Penetration & Security Auditor for FMagenticL v3.0.0
Probes live Cloudflare Pages endpoints on https://fmagenticl-registry.pages.dev.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.full_privacy_audit import scan_text

BASE_URL = "https://fmagenticl-registry.pages.dev"

ENDPOINTS = [
    ("GET", "/", None, 200),
    ("GET", "/registry.json", None, 200),
    ("GET", "/v1/snapshot.json", None, 200),
    ("GET", "/v1/keyring.json", None, 200),
    ("GET", "/v1/signatures/SIG-2026-0001.json", None, 200),
    ("GET", "/v1/health", None, 200),
    ("GET", "/llms.txt", None, 200),
    ("GET", "/.well-known/mcp.json", None, 200),
    ("GET", "/.well-known/agent.json", None, 200),
    ("HEAD", "/mcp", None, 200),
    ("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}), 200),
    ("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "fmagenticl_lookup_signature", "arguments": {"query": "SIG-2026-0001"}}}), 200),
    # Retired v2 write/legacy surfaces MUST return 404
    ("POST", "/v1/telemetry", "{bad json", 404),
    ("POST", "/v1/grievance", "{bad json", 404),
    ("GET", "/workarounds.json", None, 404),
    ("GET", "/non-existent-probe-test-404", None, 404),
]


def probe_endpoint(method: str, path: str, data: str = None) -> Tuple[int, Dict[str, str], str]:
    url = f"{BASE_URL}{path}"
    headers = {"User-Agent": "FMagenticL-Security-Audit/3.0", "Accept": "*/*"}
    body_bytes = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body_bytes = data.encode("utf-8")

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, f"CONNECTION_ERROR: {e}"


def main() -> int:
    failures = 0
    for method, path, payload, expected in ENDPOINTS:
        status, headers, body = probe_endpoint(method, path, payload)
        leaks = scan_text(body, f"{method} {path}")
        ok = (status == expected) and not leaks
        print(f"[{'PASS' if ok else 'FAIL'}] {method} {path} -> HTTP {status} (expected {expected}), leaks={len(leaks)}")
        if not ok:
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
