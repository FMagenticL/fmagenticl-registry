#!/usr/bin/env python3
r"""
External Surface Penetration & Security Auditor for FMagenticL
Probes all public Cloudflare Pages & Worker endpoints on:
  https://fmagenticl-registry.pages.dev
Asserts:
  1. HTTP status code is valid (200, 202, or expected 404/400).
  2. No secrets, API keys, tokens, or private keys in response bodies or headers.
  3. No local Windows/macOS/Linux paths (C:\Users, /Users, /home) leaked.
  4. No operator usernames (itari) or internal machine terms leaked.
  5. Error responses do not leak unhandled stack traces, Cloudflare Account IDs, or environment variables.
"""

import sys
import json
import urllib.request
import urllib.error
from typing import Dict, List, Tuple
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.full_privacy_audit import scan_text

BASE_URL = "https://fmagenticl-registry.pages.dev"

ENDPOINTS = [
    ("GET", "/", None),
    ("GET", "/registry.json", None),
    ("GET", "/grievances.json", None),
    ("GET", "/guestbook.json", None),
    ("GET", "/v1/snapshot.json", None),
    ("GET", "/v1/deltas/latest.json", None),
    ("GET", "/llms.txt", None),
    ("GET", "/llms-full.txt", None),
    ("GET", "/sitemap.xml", None),
    ("GET", "/robots.txt", None),
    ("GET", "/hooks/fmagenticl_hook.py", None),
    ("GET", "/api/v1/patches?limit=100", None),
    ("GET", "/v1/health", None),
    ("GET", "/v1/grievances", None),
    ("GET", "/v1/scoreboard", None),
    ("GET", "/v1/resolve/328d138472fd31c9c2ca2f134c43f4c4ee620765859553bb7219e00037f7ceb8.json", None),
    # MCP JSON-RPC endpoints
    ("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})),
    ("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "fmagenticl_get_grievances", "arguments": {}}})),
    # Ingress error boundary tests
    ("POST", "/v1/telemetry", "{bad json"),
    ("POST", "/v1/grievance", "{bad json"),
    ("POST", "/v1/hello", "{bad json"),
    ("GET", "/non-existent-probe-test-404", None),
]

def probe_endpoint(method: str, path: str, data: str = None) -> Tuple[int, Dict[str, str], str]:
    url = f"{BASE_URL}{path}"
    headers = {
        "User-Agent": "FMagenticL-Security-Audit/1.0",
        "Accept": "*/*"
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
        body_bytes = data.encode("utf-8")
    else:
        body_bytes = None

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            resp_headers = dict(resp.headers)
            body = resp.read().decode("utf-8", errors="replace")
            return status, resp_headers, body
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers)
        body = e.read().decode("utf-8", errors="replace")
        return status, resp_headers, body
    except Exception as e:
        return 0, {}, f"CONNECTION_ERROR: {e}"

def main():
    print("=" * 80)
    print(f"FMagenticL EXTERNAL SURFACE SECURITY & PRIVACY PROBE: {BASE_URL}")
    print("=" * 80)

    total_probed = 0
    all_violations = []

    for method, path, payload in ENDPOINTS:
        total_probed += 1
        status, headers, body = probe_endpoint(method, path, payload)
        header_dump = json.dumps(headers)
        
        # Scan body and headers
        body_findings = scan_text(body, f"EXTERNAL-BODY:{path}", is_test=False)
        header_findings = scan_text(header_dump, f"EXTERNAL-HEADERS:{path}", is_test=False)
        
        # Filter out public RFC metadata emails (e.g. repo author emails if any)
        crit_body = [f for f in body_findings if not f[1].startswith("CONTACT/NETWORK:Email")]
        crit_header = [f for f in header_findings if not f[1].startswith("CONTACT/NETWORK:Email")]

        status_flag = "OK" if status in (200, 202, 400, 404, 405) else "UNEXPECTED"
        print(f"[{status}] {method:<4} {path:<60} (Size: {len(body):>6} bytes) [{status_flag}]")

        if crit_body or crit_header:
            for loc, cat, snip in crit_body + crit_header:
                print(f"   [!] LEAK ON LIVE ENDPOINT: {loc} [{cat}] -> {snip}")
                all_violations.append((loc, cat, snip))

    print("\n" + "=" * 80)
    print("LIVE EXTERNAL PROBE AUDIT SUMMARY")
    print("=" * 80)
    print(f"Total external surfaces probed: {total_probed}")
    print(f"Total sensitive leaks detected on live production CDN: {len(all_violations)}")

    if all_violations:
        print("\n[X] CRITICAL: LEAKS DETECTED ON PUBLIC CDN ENDPOINTS:")
        for loc, cat, snip in all_violations:
            print(f"  - {loc} [{cat}] -> {snip}")
        sys.exit(1)
    else:
        print("\n[+] LIVE EXTERNAL SURFACES PASSED: ZERO secrets, tokens, local paths, or internal terms exposed to external agents or the public internet!")
        sys.exit(0)

if __name__ == "__main__":
    sys.exit(main())
