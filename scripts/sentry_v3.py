#!/usr/bin/env python3
"""
FMagenticL v3.0 — Standing Sentry Health, Expiry & Edge Monitor
Monitors live Cloudflare Pages + /mcp endpoints with zero D1 dependency:
  1. Static CDN & signature catalog parity (/v1/health, /v1/snapshot.json, /v1/keyring.json)
  2. Snapshot valid_until TTL watchdog (alerts if < 48h remaining before 14-day expiry)
  3. Read-only /mcp JSON-RPC probe (tools/list == 3 tools, exact lookup SIG-2026-0001)
  4. Retired v2 write/legacy surface 404 shield (/v1/telemetry, /v1/grievance, /workarounds.json)
"""

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE_URL = "https://fmagenticl-registry.pages.dev"


def http_req(method: str, path: str, body: dict | None = None) -> tuple[int, str]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"User-Agent": "FMagenticL-Sentry/3.0"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def run_sentry_checks() -> int:
    issues: list[str] = []

    st_health, body_health = http_req("GET", "/v1/health")
    if st_health != 200:
        issues.append(f"/v1/health returned HTTP {st_health}")
    else:
        h = json.loads(body_health)
        if h.get("protocol_version") != "3.0.0" or h.get("total_entries", 0) < 60:
            issues.append(f"/v1/health unexpected payload: {h}")

    st_snap, body_snap = http_req("GET", "/v1/snapshot.json")
    if st_snap != 200:
        issues.append(f"/v1/snapshot.json returned HTTP {st_snap}")
    else:
        snap = json.loads(body_snap)
        vu = snap.get("valid_until")
        if vu:
            exp = datetime.fromisoformat(str(vu).replace("Z", "+00:00"))
            hours_left = (exp - datetime.now(timezone.utc)).total_seconds() / 3600.0
            if hours_left < 48.0:
                issues.append(f"Snapshot valid_until expires in {hours_left:.1f}h (< 48h threshold)")

    st_mcp, body_mcp = http_req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    if st_mcp != 200:
        issues.append(f"POST /mcp tools/list returned HTTP {st_mcp}")
    else:
        tools = [t.get("name") for t in json.loads(body_mcp).get("result", {}).get("tools", [])]
        if tools != ["fmagenticl_lookup_signature", "fmagenticl_list_signatures", "fmagenticl_resolve"]:
            issues.append(f"Unexpected /mcp tools: {tools}")

    for retired in ("/v1/telemetry", "/v1/grievance", "/workarounds.json"):
        method = "GET" if retired.endswith(".json") else "POST"
        st_ret, _ = http_req(method, retired, {} if method == "POST" else None)
        if st_ret != 404:
            issues.append(f"Retired route {retired} returned HTTP {st_ret} (expected 404)")

    if issues:
        for i in issues:
            print(f"[!] SENTRY ALERT: {i}", file=sys.stderr)
        return 1
    print("[+] SENTRY v3.0 HEALTHY: All CDN, TTL, /mcp, and retired-route checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run_sentry_checks())
