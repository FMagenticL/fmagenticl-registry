#!/usr/bin/env python3
"""
FMagenticL - 90-Minute Standing Diagnostics & Analytics Engine (Honest Verification)
Runs:
  1. Live HTTP Edge Probing with TTFB measurement (/v1/health, /guestbook.json, /workarounds.json, /.well-known/agent-card.json)
  2. Read-only MCP JSON-RPC Probes (tools/list, tools/call fmagenticl_resolve)
  3. Workarounds SHA-256 Mutation Detection
  4. Live vs Local State Reconciliation (Reconciles live /v1/health with local dist/)
  5. Sentry Cycle Liveness / Missed-Cycle Detection (gap > 100 min)
  6. Cloudflare GraphQL Analytics & Traffic Accounting (Honest 5xx, no masking)
  7. Unique IP & Distinct Agent Node Audit (/mcp)
  8. Dynamic Health Evaluation: DEGRADED on any failure or recent 5xx, non-zero exit code
"""

import sys
import os
import json
import time
import hashlib
import urllib.request
import urllib.error
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(r"C:\Users\itari\Desktop\Antigravity Projects\Agentic Introspection Agent\fmagenticl")
SCRATCH_DIR = REPO_ROOT / "scratch"
SCRIPTS_DIR = REPO_ROOT / "scripts"
BASE_URL = "https://fmagenticl-registry.pages.dev"
SHA256_CACHE = SCRATCH_DIR / ".last_workarounds_sha256"
DAILY_TELEMETRY = REPO_ROOT / "daily_telemetry.md"


def probe_live_endpoints():
    endpoints = [
        "/v1/health",
        "/guestbook.json",
        "/workarounds.json",
        "/.well-known/agent-card.json",
    ]
    results = {}
    for ep in endpoints:
        url = BASE_URL + ep
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "FMagenticL-Sentry/2.0"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read()
                latency_ms = (time.perf_counter() - t0) * 1000.0
                results[ep] = {
                    "status": resp.getcode(),
                    "bytes": len(body),
                    "latency_ms": latency_ms,
                    "body": body,
                    "ok": resp.getcode() == 200,
                }
        except urllib.error.HTTPError as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            results[ep] = {"status": e.code, "bytes": 0, "latency_ms": latency_ms, "ok": False}
        except Exception as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            results[ep] = {"status": "ERROR", "error": str(e), "latency_ms": latency_ms, "ok": False}
    return results


def probe_mcp_protocol():
    url = BASE_URL + "/mcp"
    results = {}

    # 1. tools/list
    payload_list = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode("utf-8")
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(
            url,
            data=payload_list,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "User-Agent": "FMagenticL-Sentry/2.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            latency_ms = (time.perf_counter() - t0) * 1000.0
            tools = data.get("result", {}).get("tools", [])
            results["tools/list"] = {
                "ok": resp.getcode() == 200 and len(tools) > 0,
                "tool_count": len(tools),
                "latency_ms": latency_ms,
            }
    except Exception as e:
        results["tools/list"] = {"ok": False, "error": str(e), "latency_ms": (time.perf_counter() - t0) * 1000.0}

    # 2. tools/call fmagenticl_resolve
    payload_resolve = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "fmagenticl_resolve", "arguments": {"target": "pydantic"}},
    }).encode("utf-8")
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(
            url,
            data=payload_resolve,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "User-Agent": "FMagenticL-Sentry/2.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            latency_ms = (time.perf_counter() - t0) * 1000.0
            has_content = "result" in data and not data.get("error")
            results["tools/call:fmagenticl_resolve"] = {
                "ok": resp.getcode() == 200 and has_content,
                "latency_ms": latency_ms,
            }
    except Exception as e:
        results["tools/call:fmagenticl_resolve"] = {"ok": False, "error": str(e), "latency_ms": (time.perf_counter() - t0) * 1000.0}

    return results


def check_workarounds_mutation(raw_bytes: bytes) -> tuple[str, bool, str]:
    current_hash = hashlib.sha256(raw_bytes).hexdigest()
    changed = False
    old_hash = ""
    if SHA256_CACHE.exists():
        try:
            old_hash = SHA256_CACHE.read_text(encoding="utf-8").strip()
            if old_hash and old_hash != current_hash:
                changed = True
        except Exception:
            pass
    SHA256_CACHE.write_text(current_hash, encoding="utf-8")
    return current_hash, changed, old_hash


def check_liveness_gap() -> tuple[float | None, bool]:
    if not DAILY_TELEMETRY.exists():
        return None, False
    try:
        lines = DAILY_TELEMETRY.read_text(encoding="utf-8").splitlines()
        timestamps = []
        for l in lines:
            if l.startswith("## 🕒 Sentry Diagnostic Run — "):
                raw_ts = l.replace("## 🕒 Sentry Diagnostic Run — ", "").replace(" UTC", "").strip()
                try:
                    dt = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    timestamps.append(dt)
                except Exception:
                    pass
        if timestamps:
            last_ts = timestamps[-1]
            now = datetime.now(timezone.utc)
            gap_min = (now - last_ts).total_seconds() / 60.0
            # Missed cycle flag if gap > 100 minutes
            return gap_min, gap_min > 100.0
    except Exception:
        pass
    return None, False


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    now_utc = datetime.now(timezone.utc).isoformat()
    print("=" * 80)
    print(f"FMAGENTICL 90-MINUTE DIAGNOSTICS & ANALYTICS RUN (HONEST AUDIT) — {now_utc}")
    print("=" * 80)

    degraded_reasons = []

    # 0. Check Liveness Gap
    gap_min, gap_missed = check_liveness_gap()
    if gap_min is not None:
        gap_str = f"Last cycle was {gap_min:.1f} minutes ago."
        if gap_missed:
            gap_str += f" ⚠️ MISSED CYCLE FLAG: Gap exceeded 100-minute threshold!"
            degraded_reasons.append(f"Missed Sentry cycle (gap was {gap_min:.1f} min)")
        print(f"[0/5] Sentry Cadence Check: {gap_str}")

    # 1. Probe Live Endpoints & Latency
    print("\n[1/5] Probing Live Edge Endpoints with TTFB Latency...")
    probes = probe_live_endpoints()
    for ep, p in probes.items():
        if p.get("ok"):
            print(f"  {ep:<30} -> ✅ 200 OK ({p.get('bytes', 0):,} bytes, TTFB: {p.get('latency_ms', 0):.1f} ms)")
        else:
            print(f"  {ep:<30} -> ❌ {p.get('status')} (TTFB: {p.get('latency_ms', 0):.1f} ms)")
            degraded_reasons.append(f"Live endpoint probe failed: {ep} returned {p.get('status')}")

    # 2. Probe MCP Protocol
    print("\n[2/5] Probing MCP Protocol Endpoints (/mcp POST)...")
    mcp_probes = probe_mcp_protocol()
    for name, res in mcp_probes.items():
        if res.get("ok"):
            extra = f"tools={res.get('tool_count')}" if "tool_count" in res else "resolved"
            print(f"  POST /mcp {name:<25} -> ✅ 200 OK ({extra}, TTFB: {res.get('latency_ms', 0):.1f} ms)")
        else:
            print(f"  POST /mcp {name:<25} -> ❌ FAILED ({res.get('error', 'unknown error')})")
            degraded_reasons.append(f"MCP protocol probe failed: {name}")

    # 3. Workarounds SHA-256 Mutation Check
    wa_body = probes.get("/workarounds.json", {}).get("body", b"")
    if wa_body:
        cur_hash, changed, old_hash = check_workarounds_mutation(wa_body)
        if changed:
            print(f"\n[3/5] Workarounds Mutation Check: ⚠️ SHA-256 CHANGED ({old_hash[:12]}... -> {cur_hash[:12]}...)")
            degraded_reasons.append(f"Live workarounds.json SHA-256 changed unexpectedly ({old_hash[:8]} -> {cur_hash[:8]})")
        else:
            print(f"\n[3/5] Workarounds Mutation Check: ✅ Verified stable (SHA-256: {cur_hash[:16]}...)")

    # 4. Live vs Local State Reconciliation
    print("\n[4/5] Live vs Local State Reconciliation...")
    live_health_body = probes.get("/v1/health", {}).get("body", b"")
    live_health = json.loads(live_health_body.decode("utf-8")) if live_health_body else {}

    local_health_path = REPO_ROOT / "dist" / "v1" / "health"
    local_health = json.loads(local_health_path.read_text(encoding="utf-8")) if local_health_path.exists() else {}

    live_wa_cnt = live_health.get("verified_workarounds", "N/A")
    local_wa_cnt = local_health.get("verified_workarounds", "N/A")
    live_grv_cnt = live_health.get("total_grievances", "N/A")
    local_grv_cnt = local_health.get("total_grievances", "N/A")

    print(f"  Live  /v1/health: verified_workarounds={live_wa_cnt}, total_grievances={live_grv_cnt}, updated_at={live_health.get('updated_at')}")
    print(f"  Local dist/health: verified_workarounds={local_wa_cnt}, total_grievances={local_grv_cnt}, updated_at={local_health.get('updated_at')}")

    if live_wa_cnt != local_wa_cnt or live_grv_cnt != local_grv_cnt:
        print(f"  ⚠️ LIVE≠LOCAL DRIFT DETECTED: Live ({live_wa_cnt} WA / {live_grv_cnt} GRV) != Local ({local_wa_cnt} WA / {local_grv_cnt} GRV)")
        degraded_reasons.append(f"Live vs Local drift detected ({live_wa_cnt} live != {local_wa_cnt} local)")
    else:
        print(f"  ✅ Live and local distribution in exact parity ({live_grv_cnt} grievances / {live_wa_cnt} verified).")

    # 5. Cloudflare GraphQL Analytics & Traffic
    print("\n[5/5] Pulling Cloudflare GraphQL Zone Traffic...")
    cmd_cf = [sys.executable, str(SCRIPTS_DIR / "fetch_cf_analytics.py")]
    p2 = subprocess.run(cmd_cf, capture_output=True, text=True, encoding="utf-8")
    if p2.returncode == 0:
        print("  Cloudflare analytics updated in daily_telemetry.md.")
        for line in p2.stdout.splitlines():
            if line.startswith("- **") or line.startswith("### "):
                print(f"  {line}")
    else:
        print(f"  CF query warning: {p2.stderr[:200]}")
        degraded_reasons.append("Cloudflare GraphQL query failed")

    # Read latest summary
    summary_path = SCRATCH_DIR / "cf_latest_summary.json"
    recent_5xx = 0
    recent_504 = 0
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            recent = summary.get("recent", {})
            recent_5xx = recent.get("c_5xx_total", 0)
            recent_504 = recent.get("c_504", 0)
            d1_err = summary.get("d1", {}).get("error")
            if d1_err:
                degraded_reasons.append(f"D1 Database query error: {d1_err}")
            if recent_5xx > 0:
                degraded_reasons.append(f"Recent 4-hour window logged {recent_5xx} 5xx server errors (including {recent_504} 504 timeouts)")
        except Exception:
            pass

    # 6. Auditing Unique IPs & Agent Nodes on /mcp
    cmd_ips = [sys.executable, str(SCRATCH_DIR / "audit_unique_mcp_ips.py")]
    p3 = subprocess.run(cmd_ips, capture_output=True, text=True, encoding="utf-8")
    if p3.returncode == 0:
        print("\n  Distinct Nodes Audit:")
        for line in p3.stdout.splitlines():
            if "Total Distinct" in line or "/mcp Methods Breakdown" in line:
                print(f"  {line.strip()}")

    # Dynamic Health Banner
    print("\n" + "=" * 80)
    if not degraded_reasons:
        print("DIAGNOSTICS & TELEMETRY CYCLE COMPLETE — ALL ENDPOINTS GREEN (0 ERRORS)")
        print("=" * 80)
        sys.exit(0)
    else:
        print("DIAGNOSTICS & TELEMETRY CYCLE: DEGRADED STATUS REPORTED")
        print("DEGRADED REASONS:")
        for r in degraded_reasons:
            print(f"  - ❌ {r}")
        print("=" * 80)
        sys.exit(1)


if __name__ == "__main__":
    main()
